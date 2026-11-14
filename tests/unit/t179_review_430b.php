<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
require_once SMPRO_BASE . '/includes/lvelimits.php';
/**
 * t179 - round 430, actions that change the server: an account is removed only behind a backup known to be good,
 * a "lift" never lowers a limit, the automatic reboot is not planned once and then never again, held alerts are
 * not thrown away with a failed send.
 */
$src = fn($p) => str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $p));

/* ---------- lift ---------- */
is_eq(smpro_lv_lifted(['ep' => 0, 'pmem_mb' => 0, 'nproc' => 0, 'speed' => 800]), ['ep' => 0, 'pmem_mb' => 0, 'nproc' => 0, 'speed' => 800], 'L1: "no limit" and a CPU figure above the ceiling are left as they are');
is_eq(smpro_lv_lifted(['ep' => 20, 'pmem_mb' => 1024, 'nproc' => 100, 'speed' => 100]), ['ep' => 40, 'pmem_mb' => 2048, 'nproc' => 200, 'speed' => 200], 'L2: ordinary limits double, with the floors');
is_eq(smpro_lv_lifted(['ep' => 100, 'pmem_mb' => 4096, 'nproc' => 300, 'speed' => 300]), ['ep' => 200, 'pmem_mb' => 8192, 'nproc' => 600, 'speed' => 400], 'L3: CPU stops at the ceiling');
foreach ([[0, 0, 0, 800], [5, 100, 10, 50], [500, 9000, 900, 400], [1, 1, 1, 1]] as $c) {
    $cur = ['ep' => $c[0], 'pmem_mb' => $c[1], 'nproc' => $c[2], 'speed' => $c[3]]; $n = smpro_lv_lifted($cur); $low = false;
    foreach ($cur as $k => $v) if ($v > 0 && $n[$k] < $v) $low = true;
    foreach ($cur as $k => $v) if ($v === 0 && $k !== 'speed' && $n[$k] !== 0) $low = true;
    ok(!$low, 'L4: a lift never lowers (' . implode('/', $c) . ')');
}

/* ---------- terminate with backup ---------- */
$dm = $src('includes/domains.php');
has($dm, "\$ok = (\$pkgRc === 0 && \$file !== '' && is_file(\$file) && filesize(\$file) > 1024);", 'T1: a backup counts only when the packaging run ended without error');
has($dm, "'gzip -t ' . escapeshellarg(\$file)", 'T2: ...and the archive reads to its end');
ok(strpos($dm, "@unlink('/backup/cpmove-' . \$user . '.tar.gz');   // drop any STALE archive") === false, 'T3: an earlier archive is no longer deleted before the new one exists');
has($dm, "if (\$aside !== '' && !@file_exists(\$arc)) @rename(\$aside, \$arc);", 'T4: it is put back when the run fails');
has($dm, 'if [ "$RC" != "0" ] || [ ! -s "$F" ] || ! gzip -t "$F" >/dev/null 2>&1; then', 'T5: the background job has the same gate');
ok(strpos($dm, 'if ! ls /backup/cpmove-"$U".tar.gz >/dev/null 2>&1; then') === false, 'T6: "the file is there" is no longer the gate');
$i = strpos($dm, 'gzip -t "$F"'); $j = strpos($dm, 'removeacct user="$U"');
ok($i !== false && $j !== false && $i < $j, 'T7: the check comes before the account is removed');
has($dm, "FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) return ['code' => 0, 'title' => ''];", 'T8: the HTTP probe is not aimed at an inside address');
has($dm, "| { head -c 262144; echo; tail -c 24; }", 'T9: and reads a page up to a limit');

/* ---------- the rest ---------- */
has($src('includes/sysupd.php'), "time() - \$up > (int)\$s['reboot_planned_at']) {", 'R1: the "planned once" note ends when the server has restarted since');
$dg = $src('includes/digest.php');
has($dg, "return ['ok' => false, 'skip' => 'not delivered', 'kept' => count(\$back)];", 'D1: held alerts that nothing took go back to the queue');
$i = strpos($dg, "if (!\$sent) {"); $j = strrpos($dg, "@unlink(\$taken);");
ok($i !== false && $j !== false && $i < $j, 'D2: before the taken file is removed');
$tu = $src('includes/tuning.php');
is_eq(substr_count($tu, "smpro_tun_sh('csf -r', 20)"), 0, 'U1: a firewall reload is not cut off at 20 seconds');
has($tu, "The web server was NOT reloaded: its configuration test failed with the restored files", 'U2: a restore says so when the web server refused the restored files');
