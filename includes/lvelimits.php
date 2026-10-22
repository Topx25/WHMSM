<?php
/**
 * includes/lvelimits.php — "Resource Limit Is Reached" (HTTP 508 on CloudLinux): which accounts hit their LVE limits,
 * what is hitting them right now, and the ways out — end the hung PHP processes, lift the limits for a while (put
 * back automatically), or reset the account to its package limits. Every change backs /etc/container/ve.cfg up first,
 * is journalled, and is audited. Nothing here deletes a file of the account.
 *
 * Reads: lveinfo (history, JSON), /proc/lve/list (this second), lvectl list-user (limits), ps (processes).
 * Writes: lvectl set-user / delete-user, SIGTERM/SIGKILL to the account's own PHP processes.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

if (!defined('SMPRO_LV_LIFTS'))   define('SMPRO_LV_LIFTS', SMPRO_VARLIB . '/lve_lifts.json');
if (!defined('SMPRO_LV_BACKUPS')) define('SMPRO_LV_BACKUPS', SMPRO_VARLIB . '/backups/lve');
if (!defined('SMPRO_LV_VECFG'))   define('SMPRO_LV_VECFG', '/etc/container/ve.cfg');

/* ------------------------------------------------------------------ tools */

function smpro_lv_bin(string $name): string {
    foreach (['/usr/sbin/' . $name, '/usr/bin/' . $name] as $p) if (@is_executable($p)) return $p;
    return '';
}
/** CloudLinux LVE is on this server (lvectl present and the kernel exposes the LVE table). */
function smpro_lv_present(): bool { return smpro_lv_bin('lvectl') !== '' && @is_readable('/proc/lve/list'); }
function smpro_lv_run(string $cmd, int $t = 20): string { return function_exists('smpro_run') ? (string)smpro_run($cmd, $t) : (string)@shell_exec('timeout ' . $t . ' ' . $cmd . ' 2>/dev/null'); }

/** "1024M" / "1.0G" / "35.1M" / "0K" / "262144" (pages) -> MB. Pure. */
function smpro_lv_mb(string $v, bool $pages = false): int {
    $v = trim($v); if ($v === '' || $v === '-') return 0;
    if (preg_match('/^([\d.]+)\s*([KMGT]?)B?$/i', $v, $m)) {
        $n = (float)$m[1]; $u = strtoupper($m[2]);
        if ($u === '') return $pages ? (int)round($n * 4096 / 1048576) : (int)round($n / 1048576);
        return (int)round($n * ['K' => 1 / 1024, 'M' => 1, 'G' => 1024, 'T' => 1048576][$u]);
    }
    return 0;
}

/* ------------------------------------------------------------------ pure parsers */

/**
 * lveinfo --json rows -> [user => faults]. Reserved LVEs (numeric IDs even with --display-username) are skipped.
 * Keys per row: cpu_avg, cpu_max, cpu_lim (%), ep_max, ep_lim, ep_f, pmem_max, pmem_lim (MB), pmem_f, vmem_f,
 * nproc_max, nproc_lim, nproc_f, io_f, cpu_f (0 when the column is not reported), faults = sum.
 */
function smpro_lv_parse_faults(string $json): array {
    $d = json_decode($json, true); $out = [];
    if (!is_array($d) || !isset($d['data']) || !is_array($d['data'])) return $out;
    foreach ($d['data'] as $r) {
        $id = (string)($r['ID'] ?? ''); if ($id === '' || ctype_digit($id)) continue;
        $row = ['user' => $id,
                'cpu_avg' => (float)($r['aCPU'] ?? 0), 'cpu_max' => (float)($r['mCPU'] ?? 0), 'cpu_lim' => (float)($r['lCPU'] ?? 0),
                'ep_max' => (int)($r['mEP'] ?? 0), 'ep_lim' => (int)($r['lEP'] ?? 0), 'ep_f' => (int)($r['EPf'] ?? 0),
                'pmem_max' => (int)round((float)($r['mPMem'] ?? 0) / 1048576), 'pmem_lim' => (int)round((float)($r['lPMem'] ?? 0) / 1048576), 'pmem_f' => (int)($r['PMemF'] ?? 0),
                'vmem_f' => (int)($r['VMemF'] ?? 0),
                'nproc_max' => (int)($r['mNproc'] ?? 0), 'nproc_lim' => (int)($r['lNproc'] ?? 0), 'nproc_f' => (int)($r['NprocF'] ?? 0),
                'io_f' => (int)($r['IOf'] ?? 0) + (int)($r['IOPSf'] ?? 0), 'cpu_f' => (int)($r['CPUf'] ?? 0)];
        $row['faults'] = $row['ep_f'] + $row['pmem_f'] + $row['vmem_f'] + $row['nproc_f'] + $row['io_f'] + $row['cpu_f'];
        if ($row['faults'] === 0) continue;   // --by-fault still lists LVEs whose only fault kind is one we did not ask for; a row with nothing counted is noise
        $out[$id] = $row;
    }
    return $out;
}

/**
 * /proc/lve/list -> [uid => this second]. Header-driven, so a column added by CloudLinux does not shift the rest.
 * Keys: ep, lep, fep, nproc, lnproc, fnproc, memphy_mb, lmemphy_mb, fmemphy, lcpu. Pure.
 */
function smpro_lv_parse_proclist(string $txt): array {
    $lines = preg_split('/\r?\n/', trim($txt)); $out = [];
    if (count($lines) < 2) return $out;
    $hdr = preg_split('/\t+/', trim($lines[0])); $col = [];
    foreach ($hdr as $i => $h) { $h = trim($h); if ($h !== '') $col[$h] = $i; }
    // the first header cell is "N:LVE" (format version) - normalise
    foreach ($col as $h => $i) if (preg_match('/^\d+:LVE$/', $h)) { $col['LVE'] = $i; unset($col[$h]); }
    if (!isset($col['LVE'])) return $out;
    foreach (array_slice($lines, 1) as $l) {
        $c = preg_split('/\t/', $l); if (count($c) < 3) continue;
        $idf = trim((string)($c[$col['LVE']] ?? '')); if (!preg_match('/^\d+,(\d+)$/', $idf, $m)) continue;
        $uid = (int)$m[1]; if ($uid === 0 || $uid >= 4294967295) continue;
        $g = function (string $k) use ($c, $col): int { return isset($col[$k], $c[$col[$k]]) ? (int)$c[$col[$k]] : 0; };
        $out[$uid] = ['ep' => $g('EP'), 'lep' => $g('lEP'), 'fep' => $g('fEP'), 'nproc' => $g('NPROC'), 'lnproc' => $g('lNPROC'), 'fnproc' => $g('fNPROC'),
                      'memphy_mb' => (int)round($g('MEMPHY') * 4096 / 1048576), 'lmemphy_mb' => (int)round($g('lMEMPHY') * 4096 / 1048576), 'fmemphy' => $g('fMEMPHY'),
                      'lcpu' => $g('lCPU')];
    }
    return $out;
}

/** lvectl list-user table -> [user => limits]: speed (%), pmem_mb, vmem_mb, ep, nproc, io, iops. Pure. */
function smpro_lv_parse_limits(string $txt): array {
    $out = []; $cols = [];
    foreach (preg_split('/\r?\n/', trim($txt)) as $l) {
        $p = preg_split('/\s+/', trim($l)); if (count($p) < 5) continue;
        if ($p[0] === 'ID') { $cols = $p; continue; }
        if (!$cols) continue;
        $r = array_combine($cols, array_pad($p, count($cols), '')); if (!$r) continue;
        $out[$r['ID']] = ['speed' => (int)($r['SPEED'] ?? 0), 'pmem_mb' => smpro_lv_mb((string)($r['PMEM'] ?? '0')), 'vmem_mb' => smpro_lv_mb((string)($r['VMEM'] ?? '0')),
                          'ep' => (int)($r['EP'] ?? 0), 'nproc' => (int)($r['NPROC'] ?? 0), 'io' => (int)($r['IO'] ?? 0), 'iops' => (int)($r['IOPS'] ?? 0)];
    }
    return $out;
}

/** The lifted limits for one lift: double, with a floor on entry processes and a ceiling on CPU. Pure. */
function smpro_lv_lifted(array $cur): array {
    return ['ep' => max(40, (int)$cur['ep'] * 2), 'pmem_mb' => max(2048, (int)$cur['pmem_mb'] * 2), 'nproc' => max(200, (int)$cur['nproc'] * 2), 'speed' => min(400, max(200, (int)$cur['speed'] * 2))];
}

/** ps rows of one account: [pid, secs, cpu, rss_mb, cmd, kind]. kind: php | cron | other. Pure given the text. */
function smpro_lv_parse_ps(string $txt): array {
    $out = [];
    foreach (preg_split('/\r?\n/', trim($txt)) as $l) {
        if (!preg_match('/^\s*(\d+)\s+(\d+)\s+([\d.]+)\s+(\d+)\s+(.*)$/', $l, $m)) continue;
        $cmd = trim($m[5]);
        $kind = preg_match('#(^|/)(php|lsphp|php-cgi|php-fpm|php\d+)(\s|$|:)#', $cmd) || preg_match('/php-fpm: pool/', $cmd) ? 'php' : (preg_match('/wp-cron|cron\.php|artisan|\bcron\b/i', $cmd) ? 'cron' : 'other');
        $out[] = ['pid' => (int)$m[1], 'secs' => (int)$m[2], 'cpu' => (float)$m[3], 'rss_mb' => (int)round((int)$m[4] / 1024), 'cmd' => $cmd, 'kind' => $kind];
    }
    usort($out, fn($a, $b) => $b['secs'] <=> $a['secs']);
    return $out;
}

/* ------------------------------------------------------------------ reads */

/** History from lveinfo. ['ok'=>bool,'why'=>'', 'rows'=>[user=>...]] - a read that could not run says so. */
function smpro_lv_faults(string $period = '24h'): array {
    if (!in_array($period, ['1h', '24h', '7d'], true)) $period = '24h';
    $b = smpro_lv_bin('lveinfo');
    if ($b === '') return ['ok' => false, 'why' => 'lveinfo is not installed (lve-stats), so the limit history could not be read', 'rows' => []];
    // the fault columns for CPU, I/O and IOPS are NOT in lveinfo's default set: without --show-columns a CPU-throttled
    // account arrives with every printed counter at 0 and looks like it never hit anything
    $out = smpro_lv_run($b . ' --period=' . $period . ' --by-fault=any --display-username --limit=500 --json --show-columns=ID,aCPU,mCPU,lCPU,CPUf,aEP,mEP,lEP,EPf,aPMem,mPMem,lPMem,PMemF,VMemF,mNproc,lNproc,NprocF,IOf,IOPSf', 40);
    if (trim($out) === '') return ['ok' => false, 'why' => 'lveinfo gave no answer (is the lvestats service running?) - the history could not be read', 'rows' => []];
    $rows = smpro_lv_parse_faults($out);
    if (!$rows && strpos($out, '"success"') === false) return ['ok' => false, 'why' => 'lveinfo answered something that is not its JSON - the history could not be read', 'rows' => []];
    uasort($rows, fn($a, $b) => $b['faults'] <=> $a['faults']);
    return ['ok' => true, 'why' => '', 'rows' => $rows];
}
/** This second, by account name. */
function smpro_lv_now(): array {
    $raw = (string)@file_get_contents('/proc/lve/list'); $out = [];
    foreach (smpro_lv_parse_proclist($raw) as $uid => $r) {
        $pw = function_exists('posix_getpwuid') ? @posix_getpwuid($uid) : null; if (!is_array($pw)) continue;
        $out[(string)$pw['name']] = $r + ['uid' => $uid];
    }
    return $out;
}
function smpro_lv_limits(): array { $b = smpro_lv_bin('lvectl'); return $b === '' ? [] : smpro_lv_parse_limits(smpro_lv_run($b . ' list-user', 20)); }
/** Limits of one account: its own row, else the defaults row, else zeros. */
function smpro_lv_limits_of(string $user, ?array $all = null): array {
    $all = $all ?? smpro_lv_limits();
    return $all[$user] ?? $all['default'] ?? ['speed' => 0, 'pmem_mb' => 0, 'vmem_mb' => 0, 'ep' => 0, 'nproc' => 0, 'io' => 0, 'iops' => 0];
}
function smpro_lv_procs(string $user): array {
    if (!preg_match('/^[a-z0-9._-]{1,64}$/i', $user)) return [];
    return smpro_lv_parse_ps(smpro_lv_run('ps -u ' . escapeshellarg($user) . ' -o pid=,etimes=,pcpu=,rss=,args= 2>/dev/null', 10));
}
/** Has this account its own <lve id="UID"> entry in ve.cfg (custom limits) - or does it ride on the package/defaults? */
function smpro_lv_custom_cfg(int $uid): bool {
    $t = (string)@file_get_contents(SMPRO_LV_VECFG);
    return $t !== '' && preg_match('/<lve\s+id="' . $uid . '"/', $t) === 1;
}

/* ------------------------------------------------------------------ lifts journal */

function smpro_lv_lifts(): array { $j = json_decode((string)@file_get_contents(SMPRO_LV_LIFTS), true); return is_array($j) ? $j : []; }
function smpro_lv_lifts_save(array $j): bool { @is_dir(dirname(SMPRO_LV_LIFTS)) || @mkdir(dirname(SMPRO_LV_LIFTS), 0700, true); $ok = @file_put_contents(SMPRO_LV_LIFTS, json_encode($j, JSON_PRETTY_PRINT), LOCK_EX) !== false; @chmod(SMPRO_LV_LIFTS, 0600); return $ok; }
function smpro_lv_backup_cfg(): string {
    if (!@is_file(SMPRO_LV_VECFG)) return '';
    @is_dir(SMPRO_LV_BACKUPS) || @mkdir(SMPRO_LV_BACKUPS, 0700, true);
    $to = SMPRO_LV_BACKUPS . '/ve.cfg.' . date('Ymd_His') . '.' . substr(sha1((string)microtime(true)), 0, 6);
    if (!@copy(SMPRO_LV_VECFG, $to)) return ''; @chmod($to, 0600); return $to;
}

/* ------------------------------------------------------------------ actions */

function smpro_lv_ops(): array {
    $u = '/^[a-zA-Z0-9._-]{1,64}$/';
    return [
        'kill_hung' => ['label' => 'End the hung PHP processes', 'confirm' => 'End this account\'s PHP / cron processes that have run for more than 2 minutes? A web request that long is stuck, not serving a visitor; ending it frees the entry-process slots and the 508 clears at once. Files and data are not touched; the next visit starts fresh processes.', 'args' => ['user' => $u]],
        'lift'      => ['label' => 'Lift the limits', 'confirm' => 'Double this account\'s limits (entry processes, memory, processes, CPU) for the chosen time? They go back by themselves when the time is up - or earlier with "Put back". ve.cfg is backed up first.', 'args' => ['user' => $u, 'minutes' => '/^(15|60|240)$/']],
        'putback'   => ['label' => 'Put back', 'confirm' => 'Put this account\'s limits back to what they were before the lift, now?', 'args' => ['user' => $u]],
        'reset'     => ['label' => 'Reset to package limits', 'confirm' => 'Drop this account\'s custom LVE limits so it follows its package again? ve.cfg is backed up first; a lift in force is forgotten.', 'args' => ['user' => $u]],
    ];
}

/** @return array{ok:bool,msg:string,backup?:string} */
function smpro_lv_apply(string $op, array $args, string $actor = ''): array {
    $ops = smpro_lv_ops(); if (!isset($ops[$op])) return ['ok' => false, 'msg' => 'unknown action'];
    $a = [];
    foreach ($ops[$op]['args'] as $k => $pat) { $v = (string)($args[$k] ?? ''); if (!preg_match($pat, $v)) return ['ok' => false, 'msg' => 'refused: argument "' . $k . '" is not in the expected form']; $a[$k] = $v; }
    $user = $a['user'];
    $pw = function_exists('posix_getpwnam') ? @posix_getpwnam($user) : null;
    if (!is_array($pw) || (int)$pw['uid'] < 1000) return ['ok' => false, 'msg' => 'refused: not a hosting account'];
    $uid = (int)$pw['uid']; $ctl = smpro_lv_bin('lvectl');
    $r = ['ok' => false, 'msg' => ''];
    try {
        switch ($op) {
            case 'kill_hung':
                $min = 120; $victims = [];
                foreach (smpro_lv_procs($user) as $p) if (($p['kind'] === 'php' || $p['kind'] === 'cron') && $p['secs'] >= $min) $victims[] = $p;
                if (!$victims) { $r = ['ok' => false, 'msg' => 'no PHP or cron process of ' . $user . ' has run for 2 minutes or more right now - nothing to end. If the 508 persists, the limit is being hit by many SHORT requests: lift the limits or look at the traffic (Bot Guard).']; break; }
                $pids = array_column($victims, 'pid');
                foreach ($pids as $pid) @posix_kill($pid, 15);
                sleep(3);
                $left = 0; foreach ($pids as $pid) if (@posix_kill($pid, 0)) { @posix_kill($pid, 9); $left++; }
                smpro_audit('lve_kill_hung', ['user' => $user, 'pids' => $pids, 'forced' => $left, 'actor' => $actor]);
                $r = ['ok' => true, 'msg' => count($pids) . ' process(es) of ' . $user . ' ended' . ($left ? ' (' . $left . ' needed SIGKILL)' : '') . ': ' . implode(', ', array_map(fn($p) => 'pid ' . $p['pid'] . ' ' . substr($p['cmd'], 0, 40) . ' (' . intdiv($p['secs'], 60) . ' min)', array_slice($victims, 0, 5)))];
                break;
            case 'lift':
                if ($ctl === '') { $r = ['ok' => false, 'msg' => 'lvectl is not installed']; break; }
                $lifts = smpro_lv_lifts();
                $prev = isset($lifts[$user]['prev']) ? $lifts[$user]['prev'] : smpro_lv_limits_of($user);   // a second lift keeps the ORIGINAL to put back
                $custom = isset($lifts[$user]) ? (bool)$lifts[$user]['custom'] : smpro_lv_custom_cfg($uid);
                $new = smpro_lv_lifted($prev);
                $bk = smpro_lv_backup_cfg(); if ($bk === '') { $r = ['ok' => false, 'msg' => 'could not back up ' . SMPRO_LV_VECFG . ' - nothing changed']; break; }
                $o = smpro_lv_run($ctl . ' set-user ' . escapeshellarg($user) . ' --maxEntryProcs=' . $new['ep'] . ' --pmem=' . $new['pmem_mb'] . 'M --nproc=' . $new['nproc'] . ' --speed=' . $new['speed'] . '% 2>&1', 30);
                if (stripos($o, 'error') !== false) { $r = ['ok' => false, 'msg' => 'lvectl refused: ' . trim($o), 'backup' => $bk]; break; }
                $lifts[$user] = ['uid' => $uid, 'until' => time() + (int)$a['minutes'] * 60, 'prev' => $prev, 'new' => $new, 'custom' => $custom, 'by' => $actor, 'at' => time()];
                smpro_lv_lifts_save($lifts); smpro_lv_cron_sync();
                smpro_audit('lve_lift', ['user' => $user, 'minutes' => (int)$a['minutes'], 'prev' => $prev, 'new' => $new, 'actor' => $actor]);
                $r = ['ok' => true, 'msg' => $user . ': entry processes ' . $prev['ep'] . ' -> ' . $new['ep'] . ', memory ' . $prev['pmem_mb'] . ' -> ' . $new['pmem_mb'] . ' MB, processes ' . $prev['nproc'] . ' -> ' . $new['nproc'] . ', CPU ' . $prev['speed'] . '% -> ' . $new['speed'] . '% for ' . (int)$a['minutes'] . ' min; put back automatically at ' . date('H:i', $lifts[$user]['until']), 'backup' => $bk];
                break;
            case 'putback':
                $r = smpro_lv_putback($user, $actor, 'by the operator');
                break;
            case 'reset':
                if ($ctl === '') { $r = ['ok' => false, 'msg' => 'lvectl is not installed']; break; }
                $bk = smpro_lv_backup_cfg(); if ($bk === '') { $r = ['ok' => false, 'msg' => 'could not back up ' . SMPRO_LV_VECFG . ' - nothing changed']; break; }
                $o = smpro_lv_run($ctl . ' delete-user ' . escapeshellarg($user) . ' 2>&1', 30);
                if (stripos($o, 'error') !== false) { $r = ['ok' => false, 'msg' => 'lvectl refused: ' . trim($o), 'backup' => $bk]; break; }
                $lifts = smpro_lv_lifts(); unset($lifts[$user]); smpro_lv_lifts_save($lifts);
                smpro_audit('lve_reset', ['user' => $user, 'actor' => $actor]);
                $r = ['ok' => true, 'msg' => $user . ' follows its package limits again', 'backup' => $bk];
                break;
        }
    } catch (\Throwable $e) { $r = ['ok' => false, 'msg' => 'failed: ' . $e->getMessage()]; }
    return $r;
}

/** Put one lifted account back: its previous own limits, or the package when it had none. */
function smpro_lv_putback(string $user, string $actor = '', string $why = ''): array {
    $ctl = smpro_lv_bin('lvectl'); $lifts = smpro_lv_lifts();
    if (!isset($lifts[$user])) return ['ok' => false, 'msg' => $user . ' has no lift in force'];
    if ($ctl === '') return ['ok' => false, 'msg' => 'lvectl is not installed'];
    $L = $lifts[$user]; $p = (array)$L['prev'];
    $bk = smpro_lv_backup_cfg(); if ($bk === '') return ['ok' => false, 'msg' => 'could not back up ' . SMPRO_LV_VECFG . ' - the lift stays'];
    $cmd = !empty($L['custom'])
        ? $ctl . ' set-user ' . escapeshellarg($user) . ' --maxEntryProcs=' . (int)$p['ep'] . ' --pmem=' . (int)$p['pmem_mb'] . 'M --nproc=' . (int)$p['nproc'] . ' --speed=' . (int)$p['speed'] . '% 2>&1'
        : $ctl . ' delete-user ' . escapeshellarg($user) . ' 2>&1';
    $o = smpro_lv_run($cmd, 30);
    if (stripos($o, 'error') !== false) return ['ok' => false, 'msg' => 'lvectl refused: ' . trim($o) . ' - the lift stays', 'backup' => $bk];
    unset($lifts[$user]); smpro_lv_lifts_save($lifts); smpro_lv_cron_sync();
    smpro_audit('lve_putback', ['user' => $user, 'why' => $why, 'actor' => $actor]);
    return ['ok' => true, 'msg' => $user . ': limits put back (' . (!empty($L['custom']) ? 'its own previous values' : 'package limits') . ')' . ($why ? ' ' . $why : ''), 'backup' => $bk];
}

/** Expire lifts whose time is up. Returns the put-back results. Called by the cron tick and when the page is drawn. */
function smpro_lv_tick(int $now = 0): array {
    $now = $now ?: time(); $out = [];
    foreach (smpro_lv_lifts() as $user => $L) if ((int)($L['until'] ?? 0) <= $now) $out[$user] = smpro_lv_putback((string)$user, 'cron', 'time was up');
    return $out;
}

/** A 5-minute tick while any lift is in force; removed when none is. */
function smpro_lv_cron_sync(): bool {
    if (defined('SMPRO_TEST_SRC')) return true;
    $f = '/etc/cron.d/smpro-lvelimits';
    if (!smpro_lv_lifts()) { if (@is_file($f)) @unlink($f); return true; }
    $bin = SMPRO_BASE . '/bin/lve_tick.php'; if (!@is_file($bin)) return false;
    $php = function_exists('smpro_php_cli_bin') ? smpro_php_cli_bin() : (is_executable('/usr/local/cpanel/3rdparty/bin/php') ? '/usr/local/cpanel/3rdparty/bin/php' : 'php');
    $desired = "# Safety Monitor Pro — put lifted LVE limits back when their time is up (removed when no lift is in force)\n*/5 * * * * root timeout 120 $php $bin >/dev/null 2>&1\n";
    return function_exists('smpro_cron_install') ? smpro_cron_install($f, $desired) : (@file_put_contents($f, $desired) !== false && @chmod($f, 0644));
}

/* ------------------------------------------------------------------ the picture for the page */

/** [user => [domain, ...]] from cPanel's own /etc/userdomains (one read, cached). Used for search by site name. */
function smpro_lv_domains_map(): array {
    static $map = null; if ($map !== null) return $map;
    $map = [];
    foreach ((array)@file('/etc/userdomains', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $ln) {
        if (!preg_match('/^([^:\s]+):\s*([A-Za-z0-9._-]+)$/', trim((string)$ln), $m) || $m[1] === '*') continue;
        $map[$m[2]][] = strtolower($m[1]);
    }
    return $map;
}

/** Every cPanel account on this server, from cPanel's own /var/cpanel/users (the domain map as the fallback). */
function smpro_lv_accounts(): array {
    $out = [];
    foreach ((array)@scandir('/var/cpanel/users') as $n) if (preg_match('/^[a-z0-9][a-z0-9._-]{0,63}$/i', (string)$n) && $n !== 'system') $out[] = (string)$n;
    if (!$out) $out = array_keys(smpro_lv_domains_map());
    sort($out, SORT_STRING | SORT_FLAG_CASE);
    return array_values(array_unique($out));
}
/** Processes of EVERY account in one ps (not one ps per account): [user => rows as smpro_lv_parse_ps gives them]. */
function smpro_lv_procs_all(): array {
    $txt = smpro_lv_run('ps -eo user=,pid=,etimes=,pcpu=,rss=,args= 2>/dev/null', 20); $by = [];
    foreach (preg_split('/\r?\n/', trim($txt)) as $l) {
        if (!preg_match('/^\s*(\S+)\s+(\d+\s+\d+\s+[\d.]+\s+\d+\s+.*)$/', $l, $m)) continue;
        $u = $m[1]; if ($u === 'root' || preg_match('/^\d+$/', $u)) continue;
        $by[$u][] = $m[2];
    }
    $out = [];
    foreach ($by as $u => $lines) $out[$u] = smpro_lv_parse_ps(implode("\n", $lines));
    return $out;
}
/** A search term -> the account it names: an account name, or any domain of one (www. and case ignored). '' when none. */
function smpro_lv_resolve(string $q, ?array $map = null): string {
    $q = strtolower(trim($q)); $q = preg_replace('#^https?://#', '', $q); $q = preg_replace('#/.*$#', '', $q); $q = preg_replace('/^www\./', '', $q);
    if ($q === '' || !preg_match('/^[a-z0-9._-]{1,253}$/', $q)) return '';
    $map = $map ?? smpro_lv_domains_map();
    if (isset($map[$q])) return $q;
    foreach ($map as $u => $ds) foreach ($ds as $d) if ($d === $q || preg_replace('/^www\./', '', $d) === $q) return (string)$u;
    if (function_exists('posix_getpwnam') && is_array(@posix_getpwnam($q))) return $q;
    return '';
}

/**
 * The one thing to do for this row, in the words of the buttons. Pure.
 * @param array $f     history row (may be empty)   @param array|null $now  this second (may be null)
 * @param int   $hung  PHP/cron processes older than 2 min   @param bool $lift  a lift is in force
 */
function smpro_lv_advice(array $f, ?array $now, int $hung, bool $lift): array {
    $ep = (int)($f['ep_f'] ?? 0); $mem = (int)($f['pmem_f'] ?? 0) + (int)($f['vmem_f'] ?? 0); $np = (int)($f['nproc_f'] ?? 0);
    $cpu = (int)($f['cpu_f'] ?? 0); $io = (int)($f['io_f'] ?? 0);
    $atCeil = $now && (($now['lep'] > 0 && $now['ep'] >= $now['lep']) || ($now['lnproc'] > 0 && $now['nproc'] >= $now['lnproc']));
    if ($hung > 0) return ['kind' => 'kill', 'text' => 'Press "End the hung PHP processes": ' . $hung . ' request(s) of this account have run for 2+ minutes and hold the slots. The 508 clears the moment they are gone. Then open the process list to see WHICH script hangs and fix it at the source (a stuck wp-cron, a slow database, a remote call).'];
    if ($atCeil) return ['kind' => 'lift', 'text' => 'At its ceiling this second with no hung process - many SHORT requests are arriving at once. Press "Lift the limits x2" to get the site back up now, then look at Bot Guard for this domain (a crawler or a flood) and at Top Processes.'];
    if ($lift) return ['kind' => 'watch', 'text' => 'A lift is in force. If the site is fine now, leave it until the time is up ("Put back" ends it early). If it still hits 508 even lifted, the limit is not the problem: find the hanging script (process list) or the traffic (Bot Guard).'];
    if ($ep > 0 && $mem === 0) return ['kind' => 'traffic', 'text' => 'Entry processes were refused ' . $ep . ' time(s) but nothing hangs right now - bursts of short requests. Look at Bot Guard and Site Shield for this domain (crawlers and scanners are the usual cause). If the traffic is real, raise the entry-process limit in the package (WHM > LVE Manager) or press "Lift the limits x2" during the peak.'];
    if ($mem > 0) return ['kind' => 'memory', 'text' => 'Memory was refused ' . $mem . ' time(s): a heavy plugin, an import, or many processes at once. "Lift the limits x2" covers an import or a cleanup; a site that needs it every day needs a bigger package (WHM > LVE Manager), not a lift.'];
    if ($np > 0) return ['kind' => 'procs', 'text' => 'More processes than allowed ' . $np . ' time(s): cron jobs piling up or a script forking. Check the account\'s cron jobs (Compromise Check lists every line) and the process list.'];
    if ($cpu > 0 && $io === 0) return ['kind' => 'cpu', 'text' => 'CPU throttled ' . $cpu . ' time(s) - slow pages, not 508. Nothing to reset: find the heavy script in Top Processes; a lift only helps for a short peak.'];
    if ($io > 0) return ['kind' => 'io', 'text' => 'Disk I/O throttled ' . $io . ' time(s) - slow pages, not 508. Usually a backup, an import, or a crawler reading everything; check Bot Guard and the account\'s cron jobs. Nothing to reset.'];
    return ['kind' => 'none', 'text' => 'Nothing is hitting a limit for this account in this period.'];
}

/** Why the 508 happens for this row, in one line. Pure. */
function smpro_lv_explain(array $f, array $now): string {
    $parts = [];
    if (($f['ep_f'] ?? 0) > 0 || (($now['lep'] ?? 0) > 0 && ($now['ep'] ?? 0) >= $now['lep'])) $parts[] = 'too many requests running at once (' . (($f['ep_f'] ?? 0) > 0 ? 'the limit of ' . ($f['ep_lim'] ?: ($now['lep'] ?? '?')) . ' entry processes was refused ' . $f['ep_f'] . ' time(s)' : 'entry processes ' . ($now['ep'] ?? '?') . ' of ' . ($now['lep'] ?? '?') . ' this second') . ') - the usual cause is PHP requests that hang (a slow database, a stuck wp-cron, a remote call that never answers) or a bot flood';
    if (($f['pmem_f'] ?? 0) > 0 || ($f['vmem_f'] ?? 0) > 0) $parts[] = 'the site needed more memory than its limit (peak ' . ($f['pmem_max'] ?? '?') . ' of ' . ($f['pmem_lim'] ?? '?') . ' MB) - a heavy plugin, an import, or many processes at once';
    if (($f['nproc_f'] ?? 0) > 0) $parts[] = 'more processes than allowed (peak ' . ($f['nproc_max'] ?? '?') . ' of ' . ($f['nproc_lim'] ?? '?') . ') - cron jobs piling up, or a script forking';
    if (($f['cpu_f'] ?? 0) > 0 || (($f['cpu_lim'] ?? 0) > 0 && ($f['cpu_max'] ?? 0) >= $f['cpu_lim'] * 0.98)) $parts[] = 'CPU at its ceiling ' . (($f['cpu_f'] ?? 0) > 0 ? $f['cpu_f'] . ' time(s) ' : '') . '(peak ' . ($f['cpu_max'] ?? '?') . '% of ' . ($f['cpu_lim'] ?? '?') . '%) - throttled, not refused: pages get slow rather than 508, and a site that is slow for minutes at a time is usually a hung request or a crawler, not real visitors';
    if (($f['io_f'] ?? 0) > 0) $parts[] = 'disk I/O throttled - backups, imports or a crawler reading everything';
    return $parts ? implode('. ', $parts) . '.' : 'no limit was hit in this period.';
}
