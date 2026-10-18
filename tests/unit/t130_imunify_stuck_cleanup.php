<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
require_once SMPRO_BASE . '/includes/imclean.php';
/** t130 - files Imunify360 left as "found" are handed to Imunify's own cleanup: only real files inside the
 *  owner's home, never a database row, never before Imunify had its own chance, never outside the operator's
 *  Imunify choice, and only reported in Dry-Run. */
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/imclean.php'));
has($src, "if (\$act !== 'cleanup') return", 'S1: acts only when Imunify itself is set to clean');
has($src, "smpro_ctl_dry_run()", 'S2: Dry-Run only reports');
has($src, "time() - (int)\$c['last_run'] < 3600", 'S3: at most once an hour');
has($src, "' malware malicious cleanup --items '", "S4: uses Imunify's own cleanup, never a delete");
hasnt($src, 'unlink(', 'S4: SM Pro deletes nothing here');
$nt = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/notify.php'));
has($nt, "smpro_imc_auto(\$items)", 'S5: the alert cycle hands stuck files over before counting');
$mod = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/imunify360-reports.php'));
has($mod, "foreach (smpro_imc_stuck(is_array(\$mj) ? (\$mj['items'] ?? []) : [], 0) as \$path => \$ids) foreach (\$ids as \$i) if (isset(\$want[\$i])) { \$ok[] = \$i; \$okFiles[\$path] = true; }", 'S6: the button sends only ids Imunify lists as found');

// selection, on the lab with a real account home
$u = 'simstore';
if (function_exists('smpro_user_home') && is_dir((string)smpro_user_home($u)) && function_exists('posix_geteuid') && posix_geteuid() === 0) {
    $home = rtrim((string)realpath(smpro_user_home($u)), '/');
    $in = "$home/t130_" . getmypid() . '.php'; file_put_contents($in, '<?php //');
    $ln = "$home/t130_link_" . getmypid() . '.php'; @symlink('/etc/hostname', $ln);
    $out = sys_get_temp_dir() . '/t130_out_' . getmypid() . '.php'; file_put_contents($out, 'x');
    $old = time() - 7200; $new = time() - 60;
    $items = [
        ['id' => 1, 'status' => 'found', 'resource_type' => 'file', 'file' => $in, 'username' => $u, 'detected' => $old],
        ['id' => 2, 'status' => 'found', 'resource_type' => 'file', 'file' => $in, 'username' => $u, 'detected' => $old],
        ['id' => 3, 'status' => 'found', 'resource_type' => 'file', 'file' => $in, 'username' => $u, 'detected' => $new],
        ['id' => 4, 'status' => 'cleanup_done', 'resource_type' => 'file', 'file' => $in, 'username' => $u, 'detected' => $old],
        ['id' => 5, 'status' => 'found', 'resource_type' => 'db', 'file' => $in, 'username' => $u, 'detected' => $old],
        ['id' => 6, 'status' => 'found', 'resource_type' => 'file', 'file' => $out, 'username' => $u, 'detected' => $old],
        ['id' => 7, 'status' => 'found', 'resource_type' => 'file', 'file' => $ln, 'username' => $u, 'detected' => $old],
        ['id' => 8, 'status' => 'found', 'resource_type' => 'file', 'file' => "$home/t130_gone.php", 'username' => $u, 'detected' => $old],
    ];
    is_eq(smpro_imc_stuck($items), [$in => [1, 2]], 'L1: only found files on disk inside the home, waiting an hour, all their ids');
    is_eq(array_keys(smpro_imc_stuck($items, 0)), [$in], 'L2: the button sees new finds too, still nothing outside the home');
    @unlink($in); @unlink($ln); @unlink($out);
}
