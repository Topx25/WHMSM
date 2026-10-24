<?php
/**
 * Safety Monitor Pro - Restore & Migrate.
 *
 * Brings accounts in from another server. It does NOT reimplement restoring: cPanel already ships a transfer
 * engine that knows how to rebuild an account, and reimplementing that is how migrations lose mailboxes. This
 * drives that engine and adds what it lacks - a readable source picker, a job that survives closing the page,
 * and an honest answer when an archive is in a format nothing here can read.
 *
 * Three routes, in order of how much cPanel already does for us:
 *   1. Live server, any panel cPanel knows      -> create_remote_root_transfer_session (it pushes its own
 *      pkgacct-* to the source and converts the account there).
 *   2. Local archive already in cPanel format   -> start_local_cpmove_restore.
 *   3. Local archive from another panel         -> convert to cpmove, then route 2. See smpro_mig_detect().
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

define('SMPRO_MIG_STATE', SMPRO_VARLIB . '/migrate.json');

/**
 * Source panels cPanel can migrate from. The keys are cPanel's own remote-type strings - anything not in
 * Whostmgr::Transfers::Session::Remotes is rejected by the API, so this list must stay in step with it.
 */
function smpro_mig_sources(): array {
    return [
        'cpanel'      => ['label' => 'cPanel / WHM', 'note' => 'Another cPanel server.'],
        'directadmin' => ['label' => 'DirectAdmin',  'note' => 'cPanel converts the account on the source server.'],
        'plesk'       => ['label' => 'Plesk',        'note' => 'cPanel converts the account on the source server.'],
        'ensim'       => ['label' => 'Ensim',        'note' => 'Legacy panel.'],
        'dsm'         => ['label' => 'DSM',          'note' => 'Legacy panel.'],
        'alabanza'    => ['label' => 'Alabanza',     'note' => 'Legacy panel.'],
        'sphera'      => ['label' => 'Sphera',       'note' => 'Legacy panel.'],
        'spectro'     => ['label' => 'Spectro',      'note' => 'Legacy panel.'],
    ];
}

/** Run a whmapi1 function. Returns ['ok'=>bool,'data'=>array,'error'=>string]. */
function smpro_mig_whm(string $fn, array $args = [], int $timeout = 60): array {
    $cmd = 'whmapi1 ' . escapeshellarg($fn);
    foreach ($args as $k => $v) $cmd .= ' ' . escapeshellarg($k . '=' . $v);
    $cmd .= ' --output=json';
    $raw = smpro_run($cmd, $timeout, ['stderr' => 'discard']);
    $j = json_decode($raw, true);
    if (!is_array($j)) return ['ok' => false, 'data' => [], 'error' => 'whmapi1 ' . $fn . ' returned no usable reply.'];
    // The envelope's result flag is the ground truth. A populated data block with result=0 is still a failure,
    // and reading only the data block is how a refusal renders as an empty-but-healthy answer.
    $ok = (int)($j['metadata']['result'] ?? 0) === 1;
    return ['ok' => $ok, 'data' => (array)($j['data'] ?? []),
            'error' => $ok ? '' : (string)($j['metadata']['reason'] ?? 'unknown error')];
}

/* ---------------- persisted job state ---------------- */

function smpro_mig_state(): array {
    $j = json_decode((string)@file_get_contents(SMPRO_MIG_STATE), true);
    return is_array($j) ? $j : [];
}

function smpro_mig_state_save(array $s): bool {
    $t = SMPRO_MIG_STATE . '.tmp';
    if (@file_put_contents($t, json_encode($s, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)) === false) return false;
    @chmod($t, 0600);
    return @rename($t, SMPRO_MIG_STATE);
}

/* ---------------- route 1: a live source server ---------------- */

/**
 * Open a transfer session against a live source server.
 * $auth is 'password' or 'sshkey'. The secret is passed straight to whmapi1 and is never written to state.
 */
function smpro_mig_connect(string $type, string $host, int $port, string $user, string $auth, string $secret): array {
    if (!isset(smpro_mig_sources()[$type])) return ['ok' => false, 'error' => 'Unsupported source panel: ' . $type];
    if (trim($host) === '')                 return ['ok' => false, 'error' => 'A source host is required.'];
    $args = ['host' => $host, 'user' => ($user !== '' ? $user : 'root'), 'port' => (string)($port > 0 ? $port : 22)];
    if ($type !== 'cpanel') $args['remote_server_type'] = $type;
    if ($auth === 'sshkey') { $args['authtype'] = 'key';      $args['sshkey_passphrase'] = $secret; }
    else                    { $args['authtype'] = 'password'; $args['password'] = $secret; }
    $r = smpro_mig_whm('create_remote_root_transfer_session', $args, 120);
    if (!$r['ok']) return ['ok' => false, 'error' => $r['error']];
    $sid = (string)($r['data']['transfer_session_id'] ?? '');
    if ($sid === '') return ['ok' => false, 'error' => 'The transfer session was created but no session id came back.'];
    smpro_mig_state_save(['session' => $sid, 'type' => $type, 'host' => $host, 'started' => time(), 'phase' => 'connected']);
    if (function_exists('smpro_audit')) smpro_audit('migrate_connect', ['type' => $type, 'host' => $host, 'session' => $sid]);
    return ['ok' => true, 'session' => $sid];
}

/** Ask the source what accounts it holds. */
function smpro_mig_analyze(string $sid): array {
    $r = smpro_mig_whm('analyze_transfer_session_remote', ['transfer_session_id' => $sid], 300);
    if (!$r['ok']) return ['ok' => false, 'accounts' => [], 'error' => $r['error']];
    $g = smpro_mig_whm('retrieve_transfer_session_remote_analysis', ['transfer_session_id' => $sid], 120);
    if (!$g['ok']) return ['ok' => false, 'accounts' => [], 'error' => $g['error']];
    return ['ok' => true, 'accounts' => (array)($g['data']['analysis'] ?? $g['data']), 'error' => ''];
}

/** Queue one account. localuser lets the operator land it under a different name to dodge a clash. */
function smpro_mig_enqueue(string $sid, string $user, string $localuser = '', array $opt = []): array {
    $args = ['transfer_session_id' => $sid, 'module' => 'AccountRemoteRoot',
             'user' => $user, 'localuser' => ($localuser !== '' ? $localuser : $user)];
    foreach (['skiphomedir', 'skipbwdata', 'skipsubdomains', 'overwrite_all_dbusers', 'shared_mysql_server', 'live_transfer'] as $k) {
        if (!empty($opt[$k])) $args[$k] = '1';
    }
    $r = smpro_mig_whm('enqueue_transfer_item', $args, 60);
    return ['ok' => $r['ok'], 'error' => $r['error']];
}

function smpro_mig_start(string $sid): array {
    $r = smpro_mig_whm('start_transfer_session', ['transfer_session_id' => $sid], 60);
    if ($r['ok']) {
        $s = smpro_mig_state(); $s['phase'] = 'running'; $s['run_started'] = time(); smpro_mig_state_save($s);
        if (function_exists('smpro_audit')) smpro_audit('migrate_start', ['session' => $sid]);
    }
    return ['ok' => $r['ok'], 'error' => $r['error']];
}

function smpro_mig_progress(string $sid): array {
    $r = smpro_mig_whm('get_transfer_session_state', ['transfer_session_id' => $sid], 30);
    return ['ok' => $r['ok'], 'state' => (array)$r['data'], 'error' => $r['error']];
}

function smpro_mig_abort(string $sid): array {
    $r = smpro_mig_whm('abort_transfer_session', ['transfer_session_id' => $sid], 60);
    if ($r['ok'] && function_exists('smpro_audit')) smpro_audit('migrate_abort', ['session' => $sid]);
    return ['ok' => $r['ok'], 'error' => $r['error']];
}

/* ---------------- routes 2 and 3: a local archive ---------------- */

/**
 * Work out which panel produced an archive.
 * Returns ['format','confidence','restorable','why'] with format 'cpanel'|'directadmin'|'plesk'|'unknown'.
 *
 * restorable=false is a real answer, not a failure. Handing an unrecognised archive to a restore because the
 * filename looked right is how an account comes back missing its mail: the restore reports success on whatever
 * subset it managed to read. Anything this cannot positively identify is refused, and it says why.
 */
function smpro_mig_detect(string $path): array {
    $no = function ($why) { return ['format' => 'unknown', 'confidence' => 'none', 'restorable' => false, 'why' => $why]; };
    if (!is_file($path) || !is_readable($path)) return $no('The file does not exist or cannot be read.');
    $list = smpro_run('tar tzf ' . escapeshellarg($path) . ' 2>/dev/null | head -n 400', 60, ['stderr' => 'discard']);
    if (trim($list) === '') return $no('This is not a readable gzipped tar archive.');

    // cPanel: a cpmove archive carries the account's cp/ metadata and a meta/ directory at the top level.
    if (preg_match('#(^|\n)(\./)?cpmove-[^/]+/#', $list)
        || (strpos($list, '/cp/') !== false && preg_match('#(^|\n)(\./)?[^/\n]+/meta/#', $list))) {
        return ['format' => 'cpanel', 'confidence' => 'high', 'restorable' => true,
                'why' => 'The archive carries cPanel account metadata, so cPanel can restore it directly.'];
    }
    // DirectAdmin puts the account definition in backup/user.conf.
    if (strpos($list, 'backup/user.conf') !== false) {
        return ['format' => 'directadmin', 'confidence' => 'likely', 'restorable' => false,
                'why' => 'This looks like a DirectAdmin backup. Converting one to cPanel format is not built yet, and '
                       . 'guessing at the layout risks restoring an account without its mail or databases. Use the '
                       . 'live-server route while the source is still reachable.'];
    }
    // Plesk migration dumps are described by XML rather than laid out as an account tree.
    if (strpos($list, 'dump.xml') !== false || strpos($list, 'backup_info') !== false) {
        return ['format' => 'plesk', 'confidence' => 'likely', 'restorable' => false,
                'why' => 'This looks like a Plesk backup. Converting one to cPanel format is not built yet. Use the '
                       . 'live-server route while the source is still reachable.'];
    }
    return $no('The archive is readable, but nothing in it identifies which panel produced it, so it is not being restored on a guess.');
}

/** Restore a cPanel-format archive that is already on this server. */
function smpro_mig_local_restore(string $path): array {
    $d = smpro_mig_detect($path);
    if ($d['format'] !== 'cpanel') return ['ok' => false, 'error' => $d['why'], 'detected' => $d];
    $r = smpro_mig_whm('start_local_cpmove_restore', ['cpmovepath' => $path], 120);
    if ($r['ok'] && function_exists('smpro_audit')) smpro_audit('migrate_local_restore', ['path' => $path]);
    return ['ok' => $r['ok'], 'error' => $r['error'], 'detected' => $d,
            'session' => (string)($r['data']['transfer_session_id'] ?? '')];
}
