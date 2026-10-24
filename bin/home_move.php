<?php
/**
 * bin/home_move.php - detached worker for the Disk/Storage "move home directory" feature.
 * Survives the page closing (ignore_user_abort + set_time_limit(0)). Reads --mode/--user/--target,
 * performs the phase, and streams progress into SMPRO_VARLIB/backups/home_move/job.json.
 * Modes: move | rollback | finalize.  See includes/disk_home.php for the design.
 */
define('SMPRO_BOOT', 1);   // MUST precede the requires - every include exits('forbidden') without it (that was the "no heartbeat" bug)
$root = dirname(__DIR__);
foreach (['defines', 'helpers', 'maintenance', 'domains', 'disk_home'] as $m) {   // domains.php: smpro_dom_user_protected / smpro_dom_whmapi used by preflight + roots
    $f = $root . '/includes/' . $m . '.php';
    if (is_file($f)) require $f;
}

@ignore_user_abort(true);
@set_time_limit(0);
@date_default_timezone_set(@date_default_timezone_get() ?: 'UTC');

/* ---- args ---- */
$mode = 'move'; $user = ''; $troot = ''; $selftest = false; $JOBK = '';   // $JOBK = per-account job key so batched moves never share one state file
foreach ($argv as $a) {
    if ($a === '--selftest')           $selftest = true;
    if (strpos($a, '--mode=') === 0)   $mode  = substr($a, 7);
    if (strpos($a, '--user=') === 0)   $user  = preg_replace('/[^a-zA-Z0-9._-]/', '', substr($a, 7));
    if (strpos($a, '--target=') === 0) $troot = rtrim(substr($a, 9), '/');
    if (strpos($a, '--job=') === 0)    $JOBK  = preg_replace('/[^a-zA-Z0-9._-]/', '', substr($a, 6));   // per-account job file (batch mode)
}
/* --selftest: print why the worker cannot run. The launcher calls this when no heartbeat arrives, so the
 * admin sees a REAL reason instead of a generic "did not start". Prints to stdout and exits. */
if ($selftest) {
    $lockDir = defined('SMPRO_LOCKS') ? SMPRO_LOCKS : (SMPRO_VARLIB . '/locks');
    echo 'php=' . PHP_VERSION . ' user=' . (function_exists('posix_geteuid') ? posix_geteuid() : '?') . "\n";
    echo 'varlib_writable=' . (is_writable(SMPRO_VARLIB) ? 'yes' : 'NO (' . SMPRO_VARLIB . ')') . "\n";
    $jd = smpro_ds_home_dir();
    echo 'jobdir=' . $jd . ' writable=' . (is_writable($jd) ? 'yes' : 'NO') . "\n";
    $t = @fopen($lockDir . '/home_move.lock', 'c');
    echo 'lock=' . ($t ? (@flock($t, LOCK_EX | LOCK_NB) ? 'free' : 'HELD BY ANOTHER JOB') : 'CANNOT OPEN') . "\n";
    foreach (['shell_exec', 'posix_getpwnam'] as $fn) if (!function_exists($fn)) echo 'MISSING PHP FUNCTION: ' . $fn . " (check disable_functions)\n";
    exit(0);
}
/* --watchdog (cron, every minute): if a job is unfinished but NO worker is alive, relaunch it so an
 * interrupted move (reboot / OOM / killed process) continues on its own without the admin doing anything.
 * "A worker is alive" == it holds the job lock, which it keeps for the whole run - so a free lock plus an
 * unfinished job is a reliable dead-worker signal. rsync resumes, and the move phase is resume-aware. */
if (in_array('--watchdog', $argv, true)) {
    $j = smpro_ds_home_job_read($GLOBALS['JOBK'] ?? '');
    if (empty($j) || !empty($j['done'])) exit(0);                       // nothing running / already finished
    if ((time() - (int)($j['heartbeat'] ?? 0)) < 180) exit(0);          // still beating - leave it alone
    if (function_exists('smpro_ctl_disabled') && smpro_ctl_disabled()) { $j['msg'] = 'Paused: the plugin is Disabled - the move resumes when it is enabled again'; smpro_ds_home_job_write($j); exit(0); }   // a watchdog never relaunches rsync + rm -rf under the global switch
    $lockDir = defined('SMPRO_LOCKS') ? SMPRO_LOCKS : (SMPRO_VARLIB . '/locks');
    $t = @fopen($lockDir . '/home_move.lock', 'c');
    if ($t && !@flock($t, LOCK_EX | LOCK_NB)) exit(0);                  // a worker still owns it -> alive
    if ($t) { @flock($t, LOCK_UN); @fclose($t); }
    $wmode = (string)($j['mode'] ?? 'move'); $wuser = (string)($j['user'] ?? ''); $wtar = (string)($j['target'] ?? '');
    if ($wuser === '' || !in_array($wmode, ['move', 'rollback', 'finalize'], true)) exit(0);
    $j['msg'] = 'Worker stopped unexpectedly — resuming automatically…'; $j['heartbeat'] = time();
    $j['resumed'] = (int)($j['resumed'] ?? 0) + 1;
    smpro_ds_home_job_write($j);
    $php = smpro_ds_home_php_bin();
    $self = __FILE__;
    $launch = (trim((string)@shell_exec('command -v setsid 2>/dev/null')) !== '' ? 'setsid ' : 'nohup ')
        . escapeshellarg($php) . ' ' . escapeshellarg($self)
        . ' ' . escapeshellarg('--mode=' . $wmode) . ' ' . escapeshellarg('--user=' . $wuser) . ' ' . escapeshellarg('--target=' . $wtar)
        . ' >/dev/null 2>&1 </dev/null &';
    @shell_exec('PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin ' . $launch);
    exit(0);
}
if (!in_array($mode, ['move', 'rollback', 'finalize'], true) || $user === '') { exit(2); }

/* ---- progress helpers (defined BEFORE the lock so a lock failure can still be REPORTED, not silent) ---- */
$JOB = ['phase' => 'starting', 'pct' => 2, 'done' => false, 'mode' => $mode, 'user' => $user, 'target' => $troot, 'heartbeat' => time(), 'launched_at' => time(), 'msg' => 'Worker started'];
/**
 * Append one human-readable step to the job's activity log. The card renders this as a plain, readable
 * timeline - the admin should never have to look at raw job data to know what the move is doing. Repeated
 * progress ticks for the SAME phase replace the last line instead of flooding it.
 */
function jlog($phase, $msg, $replace = false) {
    global $JOB;
    if (!isset($JOB['log']) || !is_array($JOB['log'])) $JOB['log'] = [];
    $n = count($JOB['log']);
    if ($replace && $n && ($JOB['log'][$n - 1]['phase'] ?? '') === $phase) {
        $JOB['log'][$n - 1]['msg'] = $msg; $JOB['log'][$n - 1]['ts'] = time();
    } else {
        $JOB['log'][] = ['ts' => time(), 'phase' => $phase, 'msg' => $msg];
        if (count($JOB['log']) > 60) $JOB['log'] = array_slice($JOB['log'], -60);
    }
}
function jp($phase, $pct, $msg) { global $JOB; $JOB['phase'] = $phase; $JOB['pct'] = $pct; $JOB['msg'] = $msg; $JOB['heartbeat'] = time();
    // a progress tick inside the same phase updates that line; a new phase starts a new line
    jlog($phase, $msg, ($GLOBALS['JLAST'] ?? '') === $phase);
    $GLOBALS['JLAST'] = $phase;
    smpro_ds_home_job_write($JOB, $GLOBALS['JOBK'] ?? ''); }
function jdone($ok, $msg, $extra = []) { global $JOB; $JOB['phase'] = $ok ? 'done' : 'error'; $JOB['pct'] = 100; $JOB['done'] = true; $JOB['msg'] = $msg; $JOB['heartbeat'] = time(); $JOB['result'] = array_merge(['ok' => $ok, 'msg' => $msg], $extra);
    jlog($ok ? 'done' : 'error', $msg);
    smpro_ds_home_job_write($JOB, $GLOBALS['JOBK'] ?? ''); }
jp('starting', 2, 'Worker started');   // heartbeat FIRST - the launcher is waiting on exactly this

/* ---- single-flight lock (worker side; held for the whole job) ---- */
$lockDir = defined('SMPRO_LOCKS') ? SMPRO_LOCKS : (SMPRO_VARLIB . '/locks');
@is_dir($lockDir) || @mkdir($lockDir, 0700, true);
// The lock is PER ACCOUNT in batch mode ($JOBK set) so several accounts can move concurrently; a single
// ad-hoc move keeps the global lock so it stays mutually exclusive with other ad-hoc moves.
$lockFile = $lockDir . ($JOBK !== '' ? '/home_move_' . $JOBK . '.lock' : '/home_move.lock');
$lf = @fopen($lockFile, 'c');
if ($lf && !@flock($lf, LOCK_EX | LOCK_NB)) { jdone(false, 'A move for this account is already running — this one was not started.'); exit(0); }

/* crash safety net */
register_shutdown_function(function () {
    $e = error_get_last();
    if ($e && in_array($e['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) {
        $j = smpro_ds_home_job_read($GLOBALS['JOBK'] ?? '');
        if (empty($j['done'])) { $j['phase'] = 'error'; $j['done'] = true; $j['pct'] = 100; $j['msg'] = 'Worker crashed: ' . $e['message']; $j['result'] = ['ok' => false, 'msg' => 'Worker crashed: ' . $e['message']]; smpro_ds_home_job_write($j); }
    }
});

function hm_sh($cmd, $t = 0) { return (string)@shell_exec(($t ? 'timeout ' . (int)$t . ' ' : '') . $cmd . ' 2>&1'); }
function hm_bytes_h($b) { $b = (float)$b; $u = ['B','KB','MB','GB','TB']; $i = 0; while ($b >= 1024 && $i < 4) { $b /= 1024; $i++; } return round($b, $i > 1 ? 1 : 0) . ' ' . $u[$i]; }
function hm_dur_h($s) {
    $s = (int)$s; if ($s < 0) return '';
    if ($s < 60) return $s . 's';
    if ($s < 3600) return floor($s / 60) . 'm ' . ($s % 60) . 's';
    return floor($s / 3600) . 'h ' . floor(($s % 3600) / 60) . 'm';
}
/**
 * Run an rsync with LIVE progress. Uses --info=progress2 (cumulative bytes) and computes the percentage
 * against the KNOWN total from preflight, so the figure is meaningful from the first second instead of
 * tracking rsync's own still-growing file list. Non-blocking reads keep the heartbeat alive during the
 * long file-list scan of a huge account (1.6M+ files), so the watchdog never mistakes it for dead.
 * $lo/$hi map this pass onto a slice of the overall 0-100 progress bar.
 */
function hm_rsync_progress($cmd, $totalBytes, $label, $lo, $hi) {
    global $JOB;
    $desc = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $proc = @proc_open($cmd, $desc, $pipes);
    if (!is_resource($proc)) { hm_sh($cmd, 0); return; }          // fallback: plain run, no progress
    @stream_set_blocking($pipes[1], false); @stream_set_blocking($pipes[2], false);
    $buf = ''; $lastUi = 0; $startedPass = time();
    $lastProgress = ''; $pending = '';
    // Rolling file view: with millions of files we must never store the whole list - keep a running COUNT
    // plus the most recent handful of names, which is what the admin actually wants to see.
    if (!isset($JOB['files_done'])) $JOB['files_done'] = 0;
    // Carry the list ACROSS passes: this runs once for the bulk copy and again for the delta. The delta
    // normally transfers nothing, so starting empty here wiped the names the bulk pass had collected.
    $recent = (isset($JOB['recent_files']) && is_array($JOB['recent_files'])) ? $JOB['recent_files'] : [];
    while (true) {
        $st = @proc_get_status($proc);
        $chunk = (string)@stream_get_contents($pipes[1]);
        @stream_get_contents($pipes[2]);
        if ($chunk !== '') {
            // rsync separates progress updates with \r and file names with \n - normalise, then process whole
            // lines only, holding any partial tail back so a file name is never cut in half.
            $pending .= str_replace("\r", "\n", $chunk);
            $lines = explode("\n", $pending);
            $pending = array_pop($lines);
            foreach ($lines as $ln) {
                $ln = trim($ln);
                if ($ln === '') continue;
                // rsync writes the unit in EITHER case (kB/s and MB/s both occur) and appends "(xfr#N, to-chk=...)"
                // on the final line - match case-insensitively and treat any xfr/to-chk line as progress, or a
                // progress line gets mistaken for a file name (it did: "0 0% 0.00kB/s" was counted as a file).
                if (preg_match('/([\d,]+)\s+(\d+)%\s+([\d.]+)\s*([KMGT]?)B\/s/i', $ln) || strpos($ln, 'to-chk=') !== false || strpos($ln, 'xfr#') !== false) { $lastProgress = $ln; continue; }
                // rsync chatter we must not mistake for a file name
                if (preg_match('/^(sending|receiving) incremental file list$/', $ln)) continue;
                if (preg_match('/^(sent|total size|created directory|building file list|delta-transmission)/i', $ln)) continue;
                if (preg_match('/^(rsync|IO error|file has vanished|skipping|deleting)/i', $ln)) continue;   // '--delete' prints "deleting <file>" - that is a removal, not a transfer
                if (substr($ln, -1) === '/') { $JOB['current_file'] = $ln; continue; }   // a directory, not a transfer
                $JOB['files_done']++;
                $JOB['current_file'] = $ln;
                $recent[] = $ln;
                if (count($recent) > 12) array_shift($recent);
            }
            if (strlen($pending) > 4096) $pending = substr($pending, -4096);
        }
        if (time() - $lastUi >= 2) {
            $lastUi = time();
            $done = 0.0; $rate = 0.0;
            // rsync --info=progress2:  "  12,345,678  34%  120.50MB/s    0:01:23"
            if ($lastProgress !== '' && preg_match('/([\d,]+)\s+(\d+)%\s+([\d.]+)\s*([KMGT]?)B\/s/i', $lastProgress, $p)) {
                $done = (float)str_replace(',', '', $p[1]);
                $mult = ['' => 1, 'K' => 1024, 'M' => 1048576, 'G' => 1073741824, 'T' => 1099511627776];
                $rate = (float)$p[3] * ($mult[strtoupper($p[4])] ?? 1);   // rsync may print kB/s or MB/s
            }
            $JOB['recent_files'] = $recent;
            $frac = ($totalBytes > 0 && $done > 0) ? min(1.0, $done / $totalBytes) : 0.0;
            $eta  = ($rate > 0 && $totalBytes > $done) ? (int)(($totalBytes - $done) / $rate) : null;
            $JOB['bytes_done'] = max((int)($JOB['bytes_done'] ?? 0), (int)$done);   // high-water mark: the delta pass transfers ~0 and must not reset the figure to zero
            $JOB['bytes_total'] = (int)$totalBytes;
            $JOB['rate_bps'] = (int)$rate;   $JOB['eta_sec'] = $eta;
            $JOB['pass_elapsed'] = time() - $startedPass;
            jp($JOB['phase'], (int)round($lo + ($hi - $lo) * $frac),
                $label . ' — ' . hm_bytes_h($done) . ' of ' . hm_bytes_h($totalBytes)
                . ($rate > 0 ? ' · ' . hm_bytes_h($rate) . '/s' : '')
                . ($eta !== null ? ' · about ' . hm_dur_h($eta) . ' left' : ''));
        }
        if (empty($st['running'])) break;
        usleep(400000);
    }
    @fclose($pipes[1]); @fclose($pipes[2]); @proc_close($proc);
    // Final flush - a fast pass can finish between two UI ticks, which previously left the file list empty
    // even though thousands of files had been counted.
    $JOB['recent_files'] = $recent;
    $JOB['current_file'] = '';
    smpro_ds_home_job_write($JOB, $GLOBALS['JOBK'] ?? '');
}
function hm_http_ok($domain) {
    if ($domain === '') return null;
    $code = trim((string)@shell_exec('curl -sS -m 12 -o /dev/null -w \'%{http_code}\' -H ' . escapeshellarg('Host: ' . $domain) . ' http://127.0.0.1/ 2>/dev/null'));
    return $code !== '' ? $code : null;
}
/** Primary domain for an account (for the HTTP up-check), from userdata/main or /etc/userdatadomains. */
function hm_primary_domain($user) {
    $main = @file_get_contents('/var/cpanel/userdata/' . $user . '/main');
    if ($main && preg_match('/main_domain:\s*(\S+)/', $main, $m)) return $m[1];
    $line = (string)@shell_exec('grep -m1 ' . escapeshellarg('==' . $user . '==') . ' /etc/userdatadomains 2>/dev/null');
    if (preg_match('/^([^:]+):/', trim($line), $m)) return $m[1];
    return '';
}
/** Boundary-safe rewrite of a homedir path inside the cPanel userdata tree ( /home/u -> /home2/u only at a path boundary). */
function hm_rewrite_userdata($user, $src, $dst) {
    $dir = '/var/cpanel/userdata/' . $user;
    $re = '#' . preg_quote($src, '#') . '(?=/|$|[\s:"\'])#m';
    $n = 0;
    foreach (glob($dir . '/*') ?: [] as $f) {
        if (!is_file($f)) continue;
        $c = (string)@file_get_contents($f);
        if (strpos($c, $src) === false) continue;
        $nc = preg_replace($re, $dst, $c);
        if ($nc !== null && $nc !== $c && @file_put_contents($f, $nc, LOCK_EX) !== false) $n++;
    }
    return $n;
}
/** Rebuild every generated config that derives from passwd + userdata. Returns a log string. */
function hm_rebuild($user) {
    $log = '';
    // Narrate each rebuild step into the activity log - this stage used to be one long silent pause.
    $step = function ($label) { jp('rebuild', 82, $label); };
    $step('Updating the domain map (updateuserdomains)…');
    // NB: do NOT run `userdata_update --reload` here - it regenerates the userdata from httpd.conf.datastore
    // (the OLD path) and reverts the documentroot/homedir rewrite. rebuildhttpdconf regenerates httpd.conf +
    // the datastore FROM userdata (the correct direction), which is all we need.
    $log .= "[updateuserdomains]\n"   . hm_sh('/usr/local/cpanel/scripts/updateuserdomains', 120);
    $step('Rebuilding the web-server configuration…');
    $log .= "[rebuildhttpdconf]\n"    . hm_sh('/usr/local/cpanel/scripts/rebuildhttpdconf', 180);
    $step('Checking the web-server configuration is valid…');
    $cfgOut = hm_sh('/usr/sbin/apachectl -t || /usr/local/apache/bin/httpd -t', 30);
    $log .= "[httpd -t]\n" . $cfgOut;
    jp('rebuild', 84, stripos($cfgOut, 'Syntax OK') !== false ? 'Web-server configuration is valid' : 'Web-server configuration reported: ' . trim(mb_substr($cfgOut, 0, 90)));
    $step('Reloading the web server…');
    $log .= "[restart httpd]\n"       . hm_sh('/usr/local/cpanel/scripts/restartsrv_httpd', 180);
    if (@is_file('/usr/local/cpanel/scripts/php_fpm_config')) {
        $step('Rebuilding the PHP-FPM pools…');
        $log .= "[php_fpm rebuild]\n" . hm_sh('/usr/local/cpanel/scripts/php_fpm_config --rebuild', 300);
        $step('Reloading PHP-FPM…');
        $log .= "[restart fpm]\n"     . hm_sh('/usr/local/cpanel/scripts/restartsrv_apache_php_fpm', 180);
    }
    if (trim(hm_sh('command -v cagefsctl')) !== '') { $step('Remounting CageFS for the account…'); $log .= "[cagefs remount]\n" . hm_sh('cagefsctl --remount ' . escapeshellarg($user), 300); }
    // quotas are per-filesystem; re-apply best-effort so the moved account is accounted on the new fs
    if (@is_file('/usr/local/cpanel/scripts/fixquotas')) { $step('Re-applying disk quotas…'); $log .= "[fixquotas]\n" . hm_sh('/usr/local/cpanel/scripts/fixquotas', 300); }
    return $log;
}

$pw = posix_getpwnam($user);
if (!$pw) { jdone(false, 'Account not found in /etc/passwd.'); exit; }

/* ================= MOVE ================= */
if ($mode === 'move') {
    // RESUME-AWARE: a previous attempt may have died (reboot/OOM/kill) after the cutover. If the account is
    // ALREADY on the target, re-running the copy would be wrong - pick up from the rebuild instead. rsync
    // itself is resumable, so an interrupted copy simply continues where it stopped.
    $prev = smpro_ds_home_state_read($user);
    $resumed = !empty($prev['user']) && $prev['user'] === $user && ($prev['status'] ?? '') === 'moving';
    $alreadyFlipped = rtrim($pw['dir'], '/') === rtrim($troot, '/') . '/' . $user;

    if (!$alreadyFlipped) {
        $pf = smpro_ds_home_preflight($user, $troot);
        if (empty($pf['ok'])) { jdone(false, 'Preflight failed at worker start — aborted (no changes made).'); exit; }
        $src = $pf['src']; $dst = $pf['dst']; $total = (int)($pf['account_bytes'] ?? 0);
    } else {
        $src = (string)($prev['src'] ?? ''); $dst = rtrim($troot, '/') . '/' . $user; $total = (int)($prev['account_bytes'] ?? 0);
        if ($src === '') { jdone(false, 'The account is already on ' . $troot . ' but there is no move record to finish — nothing to do.'); exit; }
    }
    $uid = (int)$pw['uid']; $gid = (int)$pw['gid'];
    $domain = hm_primary_domain($user);
    $httpBefore = hm_http_ok($domain);
    $JOB['started_at'] = (int)($prev['ts'] ?? time());
    $JOB['account'] = $user; $JOB['src'] = $src; $JOB['dst'] = $dst; $JOB['bytes_total'] = $total;
    $JOB['resumed'] = $resumed ? 1 : 0;

    if (!$alreadyFlipped) {
        // PREFLIGHT: rsync is what actually performs the move. It ships with cPanel, but a hardened or
        // minimal build can be missing it - and without this check the job would start, flip to the "Copying"
        // phase, run a command that does not exist, and report progress for a copy that never happened. Fail
        // BEFORE anything is touched, while the account is still entirely untouched and safe.
        $rsyncBin = trim((string)@shell_exec('command -v rsync 2>/dev/null'));
        if ($rsyncBin === '' || !@is_executable($rsyncBin)) {
            jdone(false, 'rsync is not installed on this server, so the account cannot be copied. Nothing was changed — the account is exactly as it was. Install rsync (dnf/yum/apt install rsync), then start the move again.');
            exit(1);
        }
        // --partial keeps a half-copied large file so an interrupted run resumes it instead of restarting it.
        $RS = 'rsync -aHAXS --numeric-ids --partial --info=progress2 --out-format=%n ';   // --out-format prints each transferred file so the details view can show them
        $JOB['phase'] = 'rsync';
        jp('rsync', 8, 'Copying ' . $user . ' to ' . $troot . ($resumed ? ' (resuming)' : '') . ' — the site stays up');
        @mkdir($dst, 0711, true); @chown($dst, $uid); @chgrp($dst, $gid);
        hm_rsync_progress($RS . escapeshellarg($src . '/') . ' ' . escapeshellarg($dst . '/'),
            $total, 'Copying ' . $user . ' to ' . $troot, 8, 55);

        $JOB['phase'] = 'delta';
        jp('delta', 55, 'Syncing final changes for ' . $user . ' (delta pass)…');
        hm_rsync_progress($RS . '--delete ' . escapeshellarg($src . '/') . ' ' . escapeshellarg($dst . '/'),
            $total, 'Final delta for ' . $user, 55, 68);
    } else {
        jp('rebuild', 78, 'Resuming the switch for ' . $user . ' (data already copied)…');
    }

    // record the recovery manifest BEFORE flipping anything (keep the ORIGINAL start time across a resume)
    $udBak = smpro_ds_home_dir() . '/' . $user . '.userdata.bak';
    if (!$alreadyFlipped || !is_dir($udBak)) {
        hm_sh('rm -rf ' . escapeshellarg($udBak) . '; cp -a /var/cpanel/userdata/' . escapeshellarg($user) . ' ' . escapeshellarg($udBak));
    }
    smpro_ds_home_state_write(['user' => $user, 'src' => $src, 'dst' => $dst, 'target_root' => $troot, 'oldhome' => $src,
        'userdata_backup' => $udBak, 'account_bytes' => $total, 'status' => 'moving', 'ts' => (int)($prev['ts'] ?? time())]);

    $nrw = 0;
    if (!$alreadyFlipped) {
        jp('flip', 70, 'Switching ' . $user . ' to the new home directory…');
        $um = hm_sh('/usr/sbin/usermod -d ' . escapeshellarg($dst) . ' ' . escapeshellarg($user), 60);
    }
    $nrw = hm_rewrite_userdata($user, $src, $dst);   // idempotent: a no-op if already rewritten

    jp('rebuild', 80, 'Rebuilding web/PHP/quota configuration for ' . $user . '…');
    $rlog = hm_rebuild($user);
    @file_put_contents(smpro_ds_home_dir() . '/' . $user . '.rebuild.log', $rlog, LOCK_EX);

    // CATCH-UP: between the delta pass and the moment the rebuild finished, the site was still LIVE on the OLD
    // path, so anything it wrote then (uploads, orders, sessions, cache) exists only there and would be lost when
    // the old copy is deleted at "Reclaim space". Copy those stragglers forward now that traffic is on the new
    // path. --update keeps files the site has ALREADY written to the new home (never clobber newer data), and
    // there is deliberately no --delete here (this pass must only ever add).
    jp('catchup', 90, 'Copying anything ' . $user . ' wrote during the switch…');
    hm_sh('rsync -aHAXS --numeric-ids --update ' . escapeshellarg($src . '/') . ' ' . escapeshellarg($dst . '/'), 0);

    jp('verify', 95, 'Verifying the account and site…');
    clearstatcache(); $pw2 = posix_getpwnam($user);
    $okHome = $pw2 && rtrim($pw2['dir'], '/') === $dst;
    $okDoc  = is_dir($dst . '/public_html') || is_dir($dst);
    $cfg    = trim(hm_sh('/usr/sbin/apachectl -t || /usr/local/apache/bin/httpd -t', 30));
    $cfgOk  = stripos($cfg, 'Syntax OK') !== false || $cfg === '';
    // Confirm the rewrite SURVIVED the rebuild (no non-cache userdata file still points at the old home) -
    // this is what catches a userdata_update-style revert regression.
    $udOk = true; $reSrc = '#' . preg_quote($src, '#') . '(?=/|$|[\s:"\'])#m';
    foreach (glob('/var/cpanel/userdata/' . $user . '/*') ?: [] as $f) {
        if (!is_file($f) || substr($f, -6) === '.cache' || substr($f, -10) === 'cache.json') continue;
        if (preg_match($reSrc, (string)@file_get_contents($f))) { $udOk = false; break; }
    }
    $httpAfter = hm_http_ok($domain);
    $siteOk = $httpAfter === null || $httpBefore === null || (int)$httpAfter < 500;

    if ($okHome && $okDoc && $cfgOk && $udOk && $siteOk) {
        $st = smpro_ds_home_state_read($user); $st['status'] = 'moved'; smpro_ds_home_state_write($st, $user);
        smpro_ds_home_history_add(['event' => 'move', 'user' => $user, 'src' => $src, 'dst' => $dst, 'bytes' => $total,
            'http_before' => $httpBefore, 'http_after' => $httpAfter, 'duration' => max(0, time() - (int)($JOB['started_at'] ?? time())),
            'resumed' => (int)($JOB['resumed'] ?? 0), 'ok' => true]);
        jdone(true, 'Moved ' . $user . ' to ' . $dst . '. Site check: HTTP ' . ($httpAfter ?? 'n/a') . ' (was ' . ($httpBefore ?? 'n/a') . '). The old copy at ' . $src . ' is kept — press "Reclaim space" to delete it, or "Roll back" to undo.',
            ['user' => $user, 'src' => $src, 'dst' => $dst, 'userdata_files_rewritten' => $nrw, 'http_before' => $httpBefore, 'http_after' => $httpAfter, 'freeable' => (int)($pf['account_bytes'] ?? 0)]);
    } else {
        jdone(false, 'Move completed with WARNINGS (homedir=' . ($okHome ? 'ok' : 'FAIL') . ', docroot=' . ($okDoc ? 'ok' : 'FAIL') . ', userdata=' . ($udOk ? 'ok' : 'STILL POINTS AT OLD PATH') . ', apache=' . ($cfgOk ? 'ok' : trim($cfg)) . ', site HTTP=' . ($httpAfter ?? 'n/a') . '). Review, then Roll back if needed.',
            ['user' => $user, 'src' => $src, 'dst' => $dst, 'http_after' => $httpAfter]);
    }
    exit;
}

/* ================= ROLLBACK ================= */
if ($mode === 'rollback') {
    $st = smpro_ds_home_state_read($user);
    if (empty($st['user']) || $st['user'] !== $user) { jdone(false, 'No matching move to roll back.'); exit; }
    $src = (string)$st['src']; $dst = (string)$st['dst']; $udBak = (string)($st['userdata_backup'] ?? '');
    jp('flip', 20, 'Pointing the account back to ' . $src . '…');
    hm_sh('/usr/sbin/usermod -d ' . escapeshellarg($src) . ' ' . escapeshellarg($user), 60);
    if ($udBak !== '' && is_dir($udBak)) {
        hm_sh('rm -rf /var/cpanel/userdata/' . escapeshellarg($user) . '; cp -a ' . escapeshellarg($udBak) . ' /var/cpanel/userdata/' . escapeshellarg($user));
    }
    jp('rebuild', 55, 'Rebuilding configuration…');
    hm_rebuild($user);
    clearstatcache(); $pw2 = posix_getpwnam($user); $okHome = $pw2 && rtrim($pw2['dir'], '/') === $src;
    jp('cleanup', 88, 'Removing the copied data on the new partition…');
    if ($okHome && $dst !== '' && $dst !== $src && is_dir($dst)) hm_sh('rm -rf ' . escapeshellarg($dst), 0);
    if ($okHome) { @unlink(smpro_ds_home_state_path($user)); if ($udBak) hm_sh('rm -rf ' . escapeshellarg($udBak)); }
    smpro_ds_home_history_add(['event' => 'rollback', 'user' => $user, 'src' => $src, 'dst' => $dst, 'ok' => (bool)$okHome,
        'bytes' => (int)($st['account_bytes'] ?? 0)]);
    jdone($okHome, $okHome ? 'Rolled back — ' . $user . ' is on ' . $src . ' again and the copy was removed.' : 'Rollback problem: homedir is ' . ($pw2['dir'] ?? '?') . '. Left the copy in place for safety.',
        ['user' => $user, 'home' => $pw2['dir'] ?? '']);
    exit;
}

/* ================= FINALIZE (delete the orphaned old copy) ================= */
if ($mode === 'finalize') {
    $st = smpro_ds_home_state_read($user);
    if (empty($st['user']) || $st['user'] !== $user) { jdone(false, 'No matching move to finalize.'); exit; }
    clearstatcache(); $pw2 = posix_getpwnam($user);
    if (!$pw2 || rtrim($pw2['dir'], '/') !== (string)$st['dst']) { jdone(false, 'Safety stop: the account is not on the moved target, so the old copy was NOT deleted.'); exit; }
    $src = (string)$st['src'];
    jp('cleanup', 30, 'Deleting the old copy at ' . $src . ' to reclaim space…');
    if ($src !== '' && $src !== (string)$st['dst'] && is_dir($src)) hm_sh('rm -rf ' . escapeshellarg($src), 0);
    @unlink(smpro_ds_home_state_path($user));
    if (!empty($st['userdata_backup'])) hm_sh('rm -rf ' . escapeshellarg((string)$st['userdata_backup']));
    smpro_ds_home_history_add(['event' => 'finalize', 'user' => $user, 'src' => $src, 'dst' => (string)$st['dst'],
        'bytes' => (int)($st['account_bytes'] ?? 0), 'ok' => true]);
    jdone(true, 'Reclaimed the space from the old home at ' . $src . '. The move is complete.', ['user' => $user, 'freed' => $src]);
    exit;
}
