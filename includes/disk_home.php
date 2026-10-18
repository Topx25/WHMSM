<?php
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }
/**
 * disk_home.php — move a cPanel account's home directory to another partition root
 * (e.g. /home -> /home2) with ZERO downtime (live rsync + delta), full reference rewrite,
 * generated-config rebuild, and reversibility (rollback / finalize).
 *
 * cPanel 11.x removed the old `rearrangeacct` script, so this reproduces its effect safely:
 *   1. rsync the homedir to the new root (live, then a --delete delta) — site stays up.
 *   2. usermod -d <newhome>  (the /etc/passwd homedir is cPanel's source of truth).
 *   3. rewrite the absolute paths in /var/cpanel/userdata/<user>/*  (documentroot/homedir/scriptalias).
 *   4. rebuild the GENERATED world (updateuserdomains, rebuildhttpdconf, php_fpm_config, cagefs, quotas)
 *      — this regenerates /etc/userdatadomains, httpd.conf and the php-fpm pools from the userdata above.
 * The old homedir is left ORPHANED (nothing references it) so the move is instantly reversible:
 *   - Finalize  = delete the orphaned old copy (reclaims the space on the old partition).
 *   - Rollback  = point everything back at the old copy and delete the new one.
 *
 * All heavy work runs in a DETACHED worker (bin/home_move.php) that survives the page closing.
 * The module polls home_move_status.
 */

/* ---------------- storage / state ---------------- */
function smpro_ds_home_dir(): string { $d = SMPRO_VARLIB . '/backups/home_move'; @is_dir($d) || @mkdir($d, 0700, true); return $d; }
// Job state is PER ACCOUNT so several moves can run at once during a batch without trampling each other.
// Called with no account it returns the legacy single-job file, which the single-move flow still uses.
function smpro_ds_home_job_path(string $acct = ''): string {
    $acct = preg_replace('/[^a-zA-Z0-9._-]/', '', $acct);
    return smpro_ds_home_dir() . ($acct === '' ? '/job.json' : '/job_' . $acct . '.json');
}
/* ---------------- batch (multi-account) move ---------------- */
function smpro_ds_home_batch_path(): string { return smpro_ds_home_dir() . '/batch.json'; }
function smpro_ds_home_batch_read(): array { $j = smpro_mnt_jread(smpro_ds_home_batch_path()); return is_array($j) ? $j : []; }
function smpro_ds_home_batch_write(array $b): void { $b['updated_at'] = time(); smpro_mnt_jwrite(smpro_ds_home_batch_path(), $b); }
// Recovery manifest (survives the move). PER ACCOUNT, because a batch runs several moves at once: a single
// shared file meant last-writer-wins, so after a batch only ONE account was still tracked as pending and the
// other moved accounts' old copies were orphaned with no way to reclaim or roll them back from the UI.
function smpro_ds_home_state_path(string $acct = ''): string {
    $acct = preg_replace('/[^a-zA-Z0-9._-]/', '', $acct);
    return smpro_ds_home_dir() . ($acct === '' ? '/state.json' : '/state_' . $acct . '.json');
}
/** Every account with a completed-but-not-finalised move — these are the ones still holding old copies. */
function smpro_ds_home_pending_all(): array {
    $out = [];
    foreach (glob(smpro_ds_home_dir() . '/state*.json') ?: [] as $f) {
        $j = smpro_mnt_jread($f);
        if (is_array($j) && !empty($j['user']) && ($j['status'] ?? '') === 'moved') $out[] = $j;
    }
    usort($out, fn($a, $b) => (int)($b['ts'] ?? 0) <=> (int)($a['ts'] ?? 0));
    return $out;
}
function smpro_ds_home_job_write(array $st, string $acct = ''): void { $st['updated_at'] = time(); smpro_mnt_jwrite(smpro_ds_home_job_path($acct), $st); }
function smpro_ds_home_job_read(string $acct = ''): array { $j = smpro_mnt_jread(smpro_ds_home_job_path($acct)); return is_array($j) ? $j : []; }
function smpro_ds_home_state_write(array $st, string $acct = ''): void { smpro_mnt_jwrite(smpro_ds_home_state_path($acct !== '' ? $acct : (string)($st['user'] ?? '')), $st); }
function smpro_ds_home_state_read(string $acct = ''): array { $j = smpro_mnt_jread(smpro_ds_home_state_path($acct)); return is_array($j) ? $j : []; }
/* ---------------- move history (kept after the job state is cleared; shown in Reports Center) ---------------- */
function smpro_ds_home_history_path(): string { return smpro_ds_home_dir() . '/history.json'; }
function smpro_ds_home_history(int $limit = 100): array {
    $h = smpro_mnt_jread(smpro_ds_home_history_path());
    if (!is_array($h)) return [];
    usort($h, fn($a, $b) => (int)($b['ts'] ?? 0) <=> (int)($a['ts'] ?? 0));
    return array_slice($h, 0, max(1, $limit));
}
/** Append one entry (move / finalize / rollback). Kept to 200 rows. */
function smpro_ds_home_history_add(array $e): void {
    $h = smpro_mnt_jread(smpro_ds_home_history_path());
    if (!is_array($h)) $h = [];
    $e['ts'] = $e['ts'] ?? time();
    $e['at'] = date('c', (int)$e['ts']);
    $h[] = $e;
    if (count($h) > 200) $h = array_slice($h, -200);
    smpro_mnt_jwrite(smpro_ds_home_history_path(), $h);
}
/** Interpreter for the detached move worker. cPanel's bundled PHP first, then whatever EA-PHP the server
 *  actually has — NEWEST first, discovered by glob. A hardcoded ea-php82 path used to sit in this list, which
 *  simply did not exist on a server built on any other branch; the move worker then fell through to a bare
 *  'php' that root's PATH may not resolve, and the job died with "worker did not start". */
function smpro_ds_home_php_bin(): string { return smpro_php_cli_bin(); }

/* ---------------- partition roots ---------------- */
/** Registered home-directory roots (cPanel) + free space, so the UI can offer valid targets. */
function smpro_ds_home_roots(): array {
    $roots = [];
    $api = function_exists('smpro_dom_whmapi') ? smpro_dom_whmapi() : '/usr/local/cpanel/bin/whmapi1';
    $out = (string)@shell_exec('timeout 20 ' . escapeshellarg($api) . ' get_homedir_roots --output=json 2>/dev/null');
    $j = json_decode($out, true);
    foreach ((array)($j['data']['payload'] ?? []) as $row) {
        $p = rtrim((string)($row['path'] ?? ''), '/'); if ($p === '') continue;
        $roots[$p] = true;
    }
    if (!$roots) $roots['/home'] = true;   // fallback: at least the default root
    $rows = [];
    foreach (array_keys($roots) as $p) {
        $df = (string)@shell_exec('df -PB1 ' . escapeshellarg($p) . ' 2>/dev/null | tail -1');
        $c  = preg_split('/\s+/', trim($df));
        $rows[] = ['path' => $p, 'device' => $c[0] ?? '', 'total' => (int)($c[1] ?? 0), 'used' => (int)($c[2] ?? 0), 'free' => (int)($c[3] ?? 0), 'mount' => $c[5] ?? ''];
    }
    return $rows;
}

/**
 * How many accounts may be copied AT THE SAME TIME without choking the server.
 * rsync on a big account is dominated by disk I/O and metadata work, not CPU — so the ceiling is deliberately
 * low and derived from what this machine can actually take: core count, whether the target disk is spinning
 * or solid-state, and how loaded the box already is. Running more parallel copies than this does NOT finish
 * sooner (the disk is the bottleneck) and it WILL slow customer sites, so the UI never offers more.
 */
function smpro_ds_home_capacity(string $troot = '/home'): array {
    $cores = (int)trim((string)@shell_exec('nproc 2>/dev/null')); if ($cores < 1) $cores = 1;
    $load1 = 0.0;
    $la = (string)@file_get_contents('/proc/loadavg');
    if ($la !== '') { $p = preg_split('/\s+/', trim($la)); $load1 = (float)($p[0] ?? 0); }
    // Is the filesystem behind the target on spinning rust? Parallel rsync is far more damaging there.
    $rot = null;
    $dev = trim((string)@shell_exec('df -P ' . escapeshellarg($troot) . ' 2>/dev/null | tail -1 | awk \'{print $1}\''));
    if ($dev !== '') {
        // Try the WHOLE device name first: md3 / dm-0 / nvme0n1 are real /sys/block entries and must not be
        // stripped (stripping md3 → md finds nothing, so RAID boxes silently reported "unknown"). Only if the
        // full name misses do we peel a partition suffix: nvme0n1p1 → nvme0n1, sda1 → sda.
        $base = preg_replace('#^/dev/#', '', $dev);
        $cands = [$base];
        if (preg_match('#^(.+?)p\d+$#', $base, $mm)) $cands[] = $mm[1];  // nvme0n1p1 → nvme0n1
        $cands[] = preg_replace('#\d+$#', '', $base);                     // sda1 → sda
        foreach ($cands as $cand) {
            if ($cand === '') continue;
            $f = '/sys/block/' . $cand . '/queue/rotational';
            if (@is_file($f)) { $rot = (trim((string)@file_get_contents($f)) === '1'); break; }
        }
        // An md array reports its own value, but if it is still unknown fall back to its first member disk.
        if ($rot === null && strpos($base, 'md') === 0) {
            foreach (glob('/sys/block/' . $base . '/slaves/*') ?: [] as $slave) {
                $sd = preg_replace('#\d+$#', '', basename($slave));
                $f = '/sys/block/' . $sd . '/queue/rotational';
                if (@is_file($f)) { $rot = (trim((string)@file_get_contents($f)) === '1'); break; }
            }
        }
    }
    // Baseline from cores, then a modest bump for solid-state, hard-capped — the disk is the real limit.
    $max = 2;
    if ($cores >= 8)  $max = 3;
    if ($cores >= 16) $max = 4;
    if ($rot === true) $max = min($max, 2);                             // spinning disk: seeking kills throughput
    elseif ($rot === false) $max = min(6, $max + 1);
    // Respect load the server is ALREADY carrying — customers come first.
    $busy = '';
    if ($load1 >= $cores * 0.75)      { $max = 1; $busy = 'the server is already busy (load ' . round($load1, 2) . ' on ' . $cores . ' cores), so only one at a time is offered'; }
    elseif ($load1 >= $cores * 0.40)  { $max = max(1, (int)floor($max / 2)); $busy = 'the server is moderately loaded (load ' . round($load1, 2) . '), so the limit was reduced'; }
    $rec = max(1, min($max, 2));                                        // recommended default stays conservative
    return ['max' => $max, 'recommended' => $rec, 'cores' => $cores, 'load1' => round($load1, 2),
            'rotational' => $rot, 'device' => $dev, 'note' => $busy];
}

/* ---------------- preflight (read-only) ---------------- */
/** Validate a proposed move. Returns ['ok'=>bool,'checks'=>[[label,ok,detail],...],'src'=>,'dst'=>,'account_bytes'=>,'free'=>]. */
function smpro_ds_home_preflight(string $user, string $troot): array {
    $checks = []; $ok = true;
    $add = function ($label, $pass, $detail = '') use (&$checks, &$ok) { $checks[] = ['label' => $label, 'ok' => (bool)$pass, 'detail' => $detail]; if (!$pass) $ok = false; };

    $user  = preg_replace('/[^a-zA-Z0-9._-]/', '', $user);
    $troot = rtrim($troot, '/');
    $add('Account is a real cPanel user (not system/root)', $user !== '' && function_exists('smpro_dom_user_protected') && !smpro_dom_user_protected($user), $user);
    $pw = $user !== '' ? posix_getpwnam($user) : false;
    if (!$pw) { $add('Account resolves in /etc/passwd', false, 'posix_getpwnam failed'); return ['ok' => false, 'checks' => $checks, 'src' => '', 'dst' => '']; }
    $src = rtrim($pw['dir'], '/');
    $curRoot = dirname($src);
    $dst = $troot . '/' . $user;
    $add('Current home is under a /home root', strpos($src, '/home') === 0, $src);
    $add('Target root differs from the current root', $troot !== '' && $troot !== $curRoot, 'current=' . $curRoot . ' target=' . $troot);
    $add('Target root exists and is a directory', is_dir($troot), $troot);

    $roots = array_column(smpro_ds_home_roots(), 'path');
    $add('Target is a registered cPanel home root', in_array($troot, $roots, true), 'roots: ' . implode(', ', $roots));

    $need = (int)trim((string)@shell_exec('timeout 60 du -sb ' . escapeshellarg($src) . ' 2>/dev/null | cut -f1'));
    $free = (int)trim((string)@shell_exec('df -PB1 ' . escapeshellarg($troot) . ' 2>/dev/null | tail -1 | awk \'{print $4}\''));
    $add('Target has room for the account (+20% margin)', $free > 0 && $need > 0 && ($need * 1.2) <= $free,
        'account=' . smpro_ds_home_h($need) . ' free=' . smpro_ds_home_h($free));

    if (is_dir($dst)) {
        $empty = trim((string)@shell_exec('ls -A ' . escapeshellarg($dst) . ' 2>/dev/null')) === '';
        $add('Target path is free (not an existing non-empty dir)', $empty, $dst . ($empty ? ' (empty)' : ' EXISTS'));
    } else {
        $add('Target path is free', true, $dst);
    }
    $running = smpro_ds_home_job_read();
    $add('No other home-move is in progress', empty($running['phase']) || !empty($running['done']) || ($running['user'] ?? '') === $user, (string)($running['user'] ?? ''));

    $srcFs = trim((string)@shell_exec('df -P ' . escapeshellarg($src) . ' 2>/dev/null | tail -1 | awk \'{print $1}\''));
    $dstFs = trim((string)@shell_exec('df -P ' . escapeshellarg($troot) . ' 2>/dev/null | tail -1 | awk \'{print $1}\''));

    return ['ok' => $ok, 'checks' => $checks, 'src' => $src, 'dst' => $dst, 'account_bytes' => $need, 'free' => $free,
            'cross_fs' => ($srcFs !== $dstFs), 'src_fs' => $srcFs, 'dst_fs' => $dstFs, 'user' => $user, 'target' => $troot];
}

function smpro_ds_home_h($b) { $b = (float)$b; $u = ['B','KB','MB','GB','TB']; $i = 0; while ($b >= 1024 && $i < 4) { $b /= 1024; $i++; } return round($b, $i > 1 ? 1 : 0) . ' ' . $u[$i]; }

/* ---------------- launch the detached worker ---------------- */
function smpro_ds_home_launch(string $mode, string $user, string $troot): array {
    $user  = preg_replace('/[^a-zA-Z0-9._-]/', '', $user);
    $troot = rtrim($troot, '/');
    // Single-flight WITHOUT holding the lock across the spawn. The worker grabs the very same lock as its
    // first act, so if we still held it here the worker would lose the race and exit silently = "no heartbeat"
    // (hit on a busy many-core box, where the spawned worker reaches the lock before this process unlocks).
    // So: test-and-release immediately, and let the WORKER own the lock for the duration of the job.
    $lockDir = defined('SMPRO_LOCKS') ? SMPRO_LOCKS : (SMPRO_VARLIB . '/locks');
    @is_dir($lockDir) || @mkdir($lockDir, 0700, true);
    $lf = @fopen($lockDir . '/home_move.lock', 'c');
    if ($lf) {
        if (!@flock($lf, LOCK_EX | LOCK_NB)) { @fclose($lf); return ['ok' => false, 'msg' => 'Another home-move is already running.']; }
        @flock($lf, LOCK_UN); @fclose($lf);          // release BEFORE spawning — the worker takes it from here
    }

    $worker = defined('SMPRO_ROOT') ? SMPRO_ROOT . '/bin/home_move.php' : (dirname(__DIR__) . '/bin/home_move.php');
    if (!@is_file($worker)) return ['ok' => false, 'msg' => 'Worker not found at ' . $worker . ' — reinstall/update the plugin.'];
    $php = smpro_ds_home_php_bin();
    if (!@is_executable($php) && $php !== 'php') return ['ok' => false, 'msg' => 'PHP CLI not executable: ' . $php];
    $hasSetsid = trim((string)@shell_exec('command -v setsid 2>/dev/null')) !== '';
    $hasNohup  = trim((string)@shell_exec('command -v nohup 2>/dev/null')) !== '';
    if (!$hasSetsid && !$hasNohup) return ['ok' => false, 'msg' => 'Neither setsid nor nohup is available, so the move cannot be run in the background.'];

    smpro_ds_home_job_write(['phase' => 'queued', 'pct' => 1, 'done' => false, 'mode' => $mode, 'user' => $user, 'target' => $troot,
        'msg' => 'Launching background worker…', 'heartbeat' => 0, 'launched_at' => time()]);

    $args = ' ' . escapeshellarg('--mode=' . $mode) . ' ' . escapeshellarg('--user=' . $user) . ' ' . escapeshellarg('--target=' . $troot);
    $cmd  = ($hasSetsid ? 'setsid ' : 'nohup ') . escapeshellarg($php) . ' ' . escapeshellarg($worker) . $args . ' >/dev/null 2>&1 </dev/null &';
    @shell_exec('PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin ' . $cmd);

    // confirm the worker actually came up (heartbeat). 20s — a loaded box can be slow to schedule the spawn.
    for ($i = 0; $i < 40; $i++) {
        usleep(500000);
        $j = smpro_ds_home_job_read();
        if (!empty($j['heartbeat']) || !empty($j['done'])) return ['ok' => true, 'msg' => 'Started.', 'phase' => (string)($j['phase'] ?? 'queued')];
    }
    // Still nothing: run a one-shot diagnostic so the admin gets a REAL reason instead of a guess.
    $diag = trim((string)@shell_exec('PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin '
        . escapeshellarg($php) . ' ' . escapeshellarg($worker) . ' --selftest 2>&1 | tail -3'));
    return ['ok' => false, 'msg' => 'The background worker did not start (no heartbeat).'
        . ($diag !== '' ? ' Worker said: ' . $diag : ' No output from the worker — check that ' . $php . ' can run ' . $worker . '.')];
}

/**
 * Watchdog cron — present ONLY while a move is unfinished, removed as soon as it completes. Runs every
 * minute; the worker's --watchdog decides whether anything actually needs restarting (it is a no-op unless
 * the job is stale AND no worker holds the lock). This is what makes an interrupted move resume by itself
 * even with the browser closed. Self-heals from the boot block in index.php.
 */
function smpro_ds_home_cron_sync() {
    // A test must never install a live cron. The shared writer refuses too, but a test that loads only
    // this file has no shared writer to refuse - function_exists() is false and the fallback writes
    // /etc/cron.d directly. The lab caught exactly that, restored the file, and went red at random.
    if (defined('SMPRO_TEST_SRC')) return true;
    $f = '/etc/cron.d/smpro-homemove';
    $worker = defined('SMPRO_BASE') ? SMPRO_BASE . '/bin/home_move.php' : (dirname(__DIR__) . '/bin/home_move.php');
    $j = smpro_ds_home_job_read();
    $active = !empty($j) && empty($j['done']) && !empty($j['phase']) && $j['phase'] !== 'idle';
    if (!$active || !@is_file($worker)) { if (@is_file($f)) @unlink($f); return; }
    $php   = smpro_ds_home_php_bin();
    $ld    = SMPRO_VARLIB . '/locks'; @is_dir($ld) || @mkdir($ld, 0700, true);
    $flock = @is_executable('/usr/bin/flock') ? '/usr/bin/flock' : 'flock';
    $desired = "# Safety Monitor Pro — resume an interrupted account move (auto-removed when the move finishes)\n"
             . "* * * * * root $flock -n " . $ld . "/home_move_wd.lock timeout 60 $php " . $worker . " --watchdog >/dev/null 2>&1\n";
    if (@is_file($f) && (string)@file_get_contents($f) === $desired) return;
    smpro_cron_install($f, $desired);   // verified write: 0644 + trailing newline, or it reports failure
}

/* ---------------- module dispatch ---------------- */
function smpro_ds_home_dispatch(string $act) {
    if ($act === 'home_roots') {
        return ['ok' => true, 'roots' => smpro_ds_home_roots()];
    }
    if ($act === 'preview_home_move') {
        $pf = smpro_ds_home_preflight((string)($_POST['hm_user'] ?? ''), (string)($_POST['hm_target'] ?? ''));
        return ['ok' => true, 'preflight' => $pf];
    }
    if ($act === 'home_move') {
        $user = (string)($_POST['hm_user'] ?? ''); $troot = (string)($_POST['hm_target'] ?? '');
        $pf = smpro_ds_home_preflight($user, $troot);
        if (empty($pf['ok'])) return ['ok' => false, 'msg' => 'Preflight failed — resolve the red items first.', 'preflight' => $pf];
        smpro_audit('disk_home_move_start', ['user' => $pf['user'], 'src' => $pf['src'], 'dst' => $pf['dst']]);
        return smpro_ds_home_launch('move', $pf['user'], $pf['target']);
    }
    if ($act === 'home_capacity') {
        return ['ok' => true, 'capacity' => smpro_ds_home_capacity((string)($_POST['hm_target'] ?? '/home'))];
    }
    if ($act === 'home_batch_start') {
        $troot = rtrim((string)($_POST['hm_target'] ?? ''), '/');
        $users = array_values(array_filter(array_map(
            fn($u) => preg_replace('/[^a-zA-Z0-9._-]/', '', (string)$u),
            (array)json_decode((string)($_POST['hm_users'] ?? '[]'), true) ?: []
        )));
        if (!$users) return ['ok' => false, 'msg' => 'Select at least one account.'];
        if (count($users) > 50) return ['ok' => false, 'msg' => 'Too many accounts in one batch (max 50).'];
        $cur = smpro_ds_home_batch_read();
        if ($cur && empty($cur['done'])) return ['ok' => false, 'msg' => 'A batch move is already running.'];
        $cap = smpro_ds_home_capacity($troot);
        $threads = max(1, min((int)($_POST['hm_threads'] ?? 1), (int)$cap['max']));
        // Pre-flight every account up front so obvious problems are reported BEFORE anything starts.
        $rows = []; $skipped = 0;
        foreach ($users as $u) {
            $pf = smpro_ds_home_preflight($u, $troot);
            if (empty($pf['ok'])) {
                $bad = [];
                foreach ((array)($pf['checks'] ?? []) as $c) if (empty($c['ok'])) $bad[] = (string)$c['label'];
                $rows[] = ['user' => $u, 'status' => 'skipped', 'msg' => 'Pre-flight failed: ' . implode('; ', array_slice($bad, 0, 2)), 'bytes' => (int)($pf['account_bytes'] ?? 0)];
                $skipped++;
            } else {
                $rows[] = ['user' => $u, 'status' => 'queued', 'msg' => '', 'bytes' => (int)($pf['account_bytes'] ?? 0)];
            }
        }
        if (!array_filter($rows, fn($r) => $r['status'] === 'queued')) {
            return ['ok' => false, 'msg' => 'None of the selected accounts passed pre-flight.', 'accounts' => $rows];
        }
        smpro_ds_home_batch_write(['target' => $troot, 'threads' => $threads, 'capacity' => $cap, 'accounts' => $rows,
            'phase' => 'queued', 'done' => false, 'cancelled' => false, 'started_at' => time(), 'heartbeat' => 0]);
        $worker = (defined('SMPRO_BASE') ? SMPRO_BASE : dirname(__DIR__)) . '/bin/home_move_batch.php';
        if (!@is_file($worker)) return ['ok' => false, 'msg' => 'Batch worker not found (bin/home_move_batch.php).'];
        $php = smpro_ds_home_php_bin();
        $launch = (trim((string)@shell_exec('command -v setsid 2>/dev/null')) !== '' ? 'setsid ' : 'nohup ')
            . escapeshellarg($php) . ' ' . escapeshellarg($worker) . ' >/dev/null 2>&1 </dev/null &';
        @shell_exec('PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin ' . $launch);
        smpro_audit('disk_home_batch_start', ['n' => count($rows), 'skipped' => $skipped, 'threads' => $threads, 'target' => $troot]);
        for ($i = 0; $i < 16; $i++) { usleep(400000); $b = smpro_ds_home_batch_read(); if (!empty($b['heartbeat'])) break; }
        return ['ok' => true, 'msg' => 'Batch started: ' . (count($rows) - $skipped) . ' account(s) queued, ' . $threads . ' at a time.' . ($skipped ? ' ' . $skipped . ' skipped by pre-flight.' : '')];
    }
    if ($act === 'home_batch_cancel') {
        $b = smpro_ds_home_batch_read();
        if (!$b || !empty($b['done'])) return ['ok' => false, 'msg' => 'No batch is running.'];
        $b['cancelled'] = true; smpro_ds_home_batch_write($b);
        smpro_audit('disk_home_batch_cancel', []);
        return ['ok' => true, 'msg' => 'Cancelling — accounts already copying will finish, nothing new will start.'];
    }
    if ($act === 'home_batch_status') {
        $b = smpro_ds_home_batch_read();
        if (!$b) return ['ok' => true, 'exists' => false];
        foreach ($b['accounts'] as $i => $a) {          // live percentage for the ones in flight
            if (($a['status'] ?? '') === 'running') {
                $j = smpro_ds_home_job_read((string)$a['user']);
                $b['accounts'][$i]['pct'] = (int)($j['pct'] ?? 0);
                $b['accounts'][$i]['phase'] = (string)($j['phase'] ?? '');
                $b['accounts'][$i]['live'] = (string)($j['msg'] ?? '');
            }
        }
        return ['ok' => true, 'exists' => true, 'batch' => $b];
    }
    if ($act === 'home_batch_clear') {
        @unlink(smpro_ds_home_batch_path());
        return ['ok' => true, 'msg' => 'Batch report cleared.'];
    }
    if ($act === 'home_move_verify') {
        // Evidence the admin can trust BEFORE deleting the old copy: is the account really switched over,
        // and is the site actually answering? Read-only.
        // A batch leaves SEVERAL accounts pending, so the caller says which one; with no account we fall back
        // to the only pending move (or the legacy single-move state).
        $st = smpro_ds_home_state_read(preg_replace('/[^a-zA-Z0-9._-]/', '', (string)($_POST['acct'] ?? '')));
        if (empty($st['user'])) { $all = smpro_ds_home_pending_all(); $st = count($all) === 1 ? $all[0] : []; }
        if (empty($st['user'])) return ['ok' => false, 'msg' => 'No completed move to verify.'];
        $u = (string)$st['user']; $dst = (string)($st['dst'] ?? ''); $src = (string)($st['src'] ?? '');
        $pw = @posix_getpwnam($u);
        $homeOk = $pw && rtrim($pw['dir'], '/') === rtrim($dst, '/');
        // no non-cache userdata file may still point at the old home
        $udOk = true;
        if ($src !== '') {
            $re = '#' . preg_quote($src, '#') . '(?=/|$|[\s:"\'])#m';
            foreach (glob('/var/cpanel/userdata/' . $u . '/*') ?: [] as $f) {
                if (!is_file($f) || substr($f, -6) === '.cache' || substr($f, -10) === 'cache.json') continue;
                if (preg_match($re, (string)@file_get_contents($f))) { $udOk = false; break; }
            }
        }
        $dom = '';
        $main = @file_get_contents('/var/cpanel/userdata/' . $u . '/main');
        if ($main && preg_match('/main_domain:\s*(\S+)/', $main, $m)) $dom = $m[1];
        $code = '';
        if ($dom !== '') $code = trim((string)@shell_exec('curl -sS -m 12 -o /dev/null -w \'%{http_code}\' -H ' . escapeshellarg('Host: ' . $dom) . ' http://127.0.0.1/ 2>/dev/null'));
        $siteOk = $code !== '' && (int)$code < 400;
        $allOk = $homeOk && $udOk && ($siteOk || $code === '');
        return ['ok' => true, 'verified' => $allOk, 'home_ok' => $homeOk, 'userdata_ok' => $udOk,
                'site_code' => $code, 'site_ok' => $siteOk, 'domain' => $dom, 'user' => $u, 'dst' => $dst];
    }
    if ($act === 'home_move_finalize' || $act === 'home_move_rollback') {
        // Which account — a batch leaves several pending at once.
        $st = smpro_ds_home_state_read(preg_replace('/[^a-zA-Z0-9._-]/', '', (string)($_POST['acct'] ?? '')));
        if (empty($st['user'])) { $all = smpro_ds_home_pending_all(); $st = count($all) === 1 ? $all[0] : []; }
        if (empty($st['user'])) return ['ok' => false, 'msg' => 'No completed move is pending finalize/rollback (say which account).'];
        $mode = $act === 'home_move_finalize' ? 'finalize' : 'rollback';
        smpro_audit('disk_home_' . $mode, ['user' => $st['user']]);
        return smpro_ds_home_launch($mode, (string)$st['user'], (string)($st['target_root'] ?? ''));
    }
    if ($act === 'home_move_status') {
        // With ?acct= it returns THAT account's job (used by the per-account "details" in a batch);
        // without it, the single ad-hoc move job.
        $acctQ = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)($_POST['acct'] ?? ''));
        $j = smpro_ds_home_job_read($acctQ); $st = smpro_ds_home_state_read();
        smpro_ds_home_cron_sync();   // install/remove the resume watchdog as the job starts/finishes
        $started = (int)($j['started_at'] ?? $j['launched_at'] ?? 0);
        return ['ok' => true, 'phase' => (string)($j['phase'] ?? 'idle'), 'pct' => (int)($j['pct'] ?? 0),
                'done' => !empty($j['done']), 'mode' => (string)($j['mode'] ?? ''), 'msg' => (string)($j['msg'] ?? ''),
                'account'  => (string)($j['account'] ?? $j['user'] ?? ''),
                'src' => (string)($j['src'] ?? ''), 'dst' => (string)($j['dst'] ?? ''),
                'started_at' => $started, 'started_h' => $started ? date('H:i', $started) : '',
                'elapsed_sec' => $started ? max(0, time() - $started) : 0,
                'bytes_done' => (int)($j['bytes_done'] ?? 0), 'bytes_total' => (int)($j['bytes_total'] ?? 0),
                'rate_bps' => (int)($j['rate_bps'] ?? 0), 'eta_sec' => isset($j['eta_sec']) ? (int)$j['eta_sec'] : null,
                'eta_at' => !empty($j['eta_sec']) ? date('H:i', time() + (int)$j['eta_sec']) : '',
                'resumed' => (int)($j['resumed'] ?? 0),
                'log' => array_slice((array)($j['log'] ?? []), -40),
                'files_done' => (int)($j['files_done'] ?? 0),
                'current_file' => (string)($j['current_file'] ?? ''),
                'recent_files' => array_slice((array)($j['recent_files'] ?? []), -12),
                'stale' => !empty($j['heartbeat']) && (time() - (int)$j['heartbeat']) > 180,
                'result' => $j['result'] ?? null,
                'pending' => !empty($st['user']) && ($st['status'] ?? '') === 'moved' ? ['user' => $st['user'], 'src' => $st['src'] ?? '', 'dst' => $st['dst'] ?? '', 'freeable' => $st['account_bytes'] ?? 0] : null];
    }
    return ['ok' => false, 'msg' => 'Unknown home action.'];
}
