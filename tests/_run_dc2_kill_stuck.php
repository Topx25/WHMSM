<?php
/**
 * End the stuck wp-cron processes on this server. The schedules were repaired first, so nothing rebuilds them.
 *
 * The guards are applied here rather than borrowed: the killer used by the Top Processes page lives in a page
 * module, which is only loaded when that page is requested, so a script like this never has it — and asking for
 * it with function_exists made a missing dependency look exactly like a refusal to act. Every process below is
 * checked against /proc at the moment it is ended, which is the check that actually matters: a pid can be reused,
 * and acting on a list read even seconds earlier is how the wrong process gets stopped.
 */
define('SMPRO_BOOT', 1);
$A = '/usr/local/cpanel/whostmgr/docroot/cgi/addons/smpro';
foreach (['defines','env','mmdb','helpers','pkg','secret','croncheck'] as $f) {
    $p = "$A/includes/$f.php"; if (is_file($p)) require_once $p;
}

$la = sys_getloadavg();
$s  = smpro_cc_stuck(60);
printf("before: load %.2f  ·  %d stuck processes across %d accounts\n\n", $la[0], $s['total'], count($s['accounts']));

$ended = 0; $skipped = []; $mine = getmypid();
foreach ($s['accounts'] as $user => $a) {
    $n = 0;
    foreach ($a['pids'] as $p) {
        $pid = (int)$p['pid'];
        if ($pid < 2 || $pid === $mine) { $skipped['self or system pid'] = ($skipped['self or system pid'] ?? 0) + 1; continue; }
        if (!is_dir("/proc/$pid"))       { $skipped['already gone'] = ($skipped['already gone'] ?? 0) + 1; continue; }

        $cmd = str_replace("\0", ' ', (string)@file_get_contents("/proc/$pid/cmdline"));
        if (stripos($cmd, 'wp-cron.php') === false) { $skipped['no longer that job'] = ($skipped['no longer that job'] ?? 0) + 1; continue; }

        $st = @stat("/proc/$pid");
        if (!$st) { $skipped['could not read owner'] = ($skipped['could not read owner'] ?? 0) + 1; continue; }
        if ((int)$st['uid'] === 0) { $skipped['root-owned'] = ($skipped['root-owned'] ?? 0) + 1; continue; }
        $own = function_exists('posix_getpwuid') ? (posix_getpwuid((int)$st['uid'])['name'] ?? '') : '';
        if ($own !== $user) { $skipped['owner changed'] = ($skipped['owner changed'] ?? 0) + 1; continue; }

        @posix_kill($pid, 15);                       // ask first
        $n++; $ended++;
    }
    printf("  %-14s signalled %d of %d\n", $user, $n, count($a['pids']));
}

sleep(4);
// Anything still there after being asked politely gets stopped. Re-checked from /proc again, not from the list.
$forced = 0;
foreach ($s['accounts'] as $user => $a) {
    foreach ($a['pids'] as $p) {
        $pid = (int)$p['pid'];
        if ($pid < 2 || !is_dir("/proc/$pid")) continue;
        $cmd = str_replace("\0", ' ', (string)@file_get_contents("/proc/$pid/cmdline"));
        if (stripos($cmd, 'wp-cron.php') === false) continue;
        $st = @stat("/proc/$pid"); if (!$st || (int)$st['uid'] === 0) continue;
        $own = function_exists('posix_getpwuid') ? (posix_getpwuid((int)$st['uid'])['name'] ?? '') : '';
        if ($own !== $user) continue;
        @posix_kill($pid, 9);
        $forced++;
    }
}

printf("\nsignalled %d, of which %d needed stopping outright\n", $ended, $forced);
foreach ($skipped as $why => $n) printf("  skipped %-24s %d\n", $why, $n);

sleep(4);
$after = smpro_cc_stuck(60);
$la2 = sys_getloadavg();
printf("\nafter: load %.2f  ·  %d remaining\n", $la2[0], $after['total']);
if (!empty($after['accounts'])) {
    foreach ($after['accounts'] as $u => $a) printf("  still there: %-14s %d\n", $u, $a['n']);
}
echo "\nLoad average is a rolling average over minutes — it comes down gradually. Worth another look in fifteen.\n";
