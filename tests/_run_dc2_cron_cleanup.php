<?php
/**
 * One-off: repair the five schedules on this server, then end the processes they left behind.
 * Repair first — killing first would leave the old schedule to rebuild them within minutes.
 */
define('SMPRO_BOOT', 1);
$A = '/usr/local/cpanel/whostmgr/docroot/cgi/addons/smpro';
foreach (['defines','env','mmdb','helpers','pkg','secret','intrusion','croncheck','croncheck_fix','wpcron_fix'] as $f) {
    $p = "$A/includes/$f.php"; if (is_file($p)) require_once $p;
}

$before = smpro_cc_stuck(60);
$la = sys_getloadavg();
printf("before: load %.2f  ·  %d stuck processes across %d accounts\n\n", $la[0], $before['total'], count($before['accounts']));

/* ---------- 1. the schedules ---------- */
echo "=== repairing schedules ===\n";
$repaired = [];
foreach (array_keys($before['accounts']) as $user) {
    $script = '/home/' . $user . '/public_html/wp-cron.php';
    $r = smpro_ccf_repair($user, $script, 10, 300, false);
    if (!empty($r['ok'])) {
        $repaired[$user] = $r['backup'];
        printf("  %-14s replaced %d entries  ·  copy: %s\n", $user, (int)$r['replaced'], basename((string)$r['backup']));
    } else {
        printf("  %-14s NOT CHANGED — %s\n", $user, (string)($r['error'] ?? 'unknown'));
    }
}

/* ---------- 2. confirm before touching any process ---------- */
echo "\n=== confirming the schedules took ===\n";
$allClean = true;
foreach (array_keys($before['accounts']) as $user) {
    $d = smpro_cc_duplicates($user);
    $lines = smpro_cc_crontab($user);
    $wp = 0; $guarded = 0;
    foreach ($lines as $l) {
        if (stripos($l, 'wp-cron.php') === false) continue;
        $wp++;
        $g = smpro_cc_line_guarded($l);
        if ($g['lock'] && $g['limit']) $guarded++;
    }
    $ok = ($wp === 1 && $guarded === 1 && !$d);
    if (!$ok) $allClean = false;
    printf("  %-14s entries=%d guarded=%d duplicates=%s  %s\n", $user, $wp, $guarded, $d ? 'yes' : 'no', $ok ? 'ok' : 'NOT AS EXPECTED');
}
if (!$allClean) {
    echo "\nA schedule is not as expected, so no process is being touched. Review the accounts above first.\n";
    exit(1);
}

/* ---------- 3. the processes ---------- */
echo "\n=== ending the stuck processes ===\n";
$now = smpro_cc_stuck(60);              // fresh list, never the one read before the repairs
$killed = 0; $refused = 0;
foreach ($now['accounts'] as $user => $a) {
    $n = 0;
    foreach ($a['pids'] as $p) {
        $pid = (int)$p['pid'];
        if ($pid < 2) { $refused++; continue; }
        // Confirm, at this moment, that the process is still that account's scheduled job. A pid can be reused,
        // and acting on a stale list is how the wrong process gets ended.
        $cmd = trim((string)@file_get_contents("/proc/$pid/cmdline"));
        $st  = @stat("/proc/$pid");
        $own = $st ? (function_exists('posix_getpwuid') ? (posix_getpwuid($st['uid'])['name'] ?? '') : '') : '';
        if ($cmd === '' || stripos(str_replace("\0", ' ', $cmd), 'wp-cron.php') === false || ($own !== '' && $own !== $user)) { $refused++; continue; }
        $r = function_exists('smpro_tp_kill') ? smpro_tp_kill($pid, true) : ['ok' => false, 'msg' => 'killer unavailable'];
        if (!empty($r['ok'])) { $killed++; $n++; } else { $refused++; }
    }
    printf("  %-14s ended %d of %d\n", $user, $n, count($a['pids']));
}
printf("\nended %d, refused %d\n", $killed, $refused);

/* ---------- 4. where it stands ---------- */
sleep(5);
$after = smpro_cc_stuck(60);
$la2 = sys_getloadavg();
printf("\nafter: load %.2f  ·  %d stuck processes remaining\n", $la2[0], $after['total']);
echo "\nLoad average is an average over minutes — it falls gradually, not at once. Check again in fifteen.\n";
if ($repaired) {
    echo "\nTo put a schedule back:\n";
    foreach ($repaired as $u => $b) echo "  $u  ->  $b\n";
}
