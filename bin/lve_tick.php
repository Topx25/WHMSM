<?php
/**
 * bin/lve_tick.php — puts lifted LVE limits back when their time is up (see includes/lvelimits.php). Installed as
 * /etc/cron.d/smpro-lvelimits only while a lift is in force; exits 0 always.
 */
define('SMPRO_BOOT', 1);
$base = dirname(__DIR__);
foreach (['defines', 'env', 'mmdb', 'helpers', 'secret', 'license', 'lvelimits'] as $m) {
    $f = $base . '/includes/' . $m . '.php';
    if (is_file($f)) require_once $f;
}
try {
    if (function_exists('smpro_lv_tick')) foreach (smpro_lv_tick() as $u => $r) fwrite(STDOUT, $u . ': ' . $r['msg'] . "\n");
    if (function_exists('smpro_lv_cron_sync')) smpro_lv_cron_sync();
} catch (\Throwable $e) {
    if (function_exists('smpro_soft_fail')) smpro_soft_fail('lve_tick', $e);
}
exit(0);
