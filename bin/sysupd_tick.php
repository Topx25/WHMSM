<?php
/**
 * bin/sysupd_tick.php - every 30 minutes: check for updates when the check is due; in automatic mode, apply at the
 * chosen hour (once a day, packages only, never a reboot). The check runs whatever the mode: "manual" means
 * shown and told, not unseen.
 */
define('SMPRO_BOOT', 1);
$base = dirname(__DIR__);
foreach (['defines', 'env', 'mmdb', 'helpers', 'secret', 'license', 'notify', 'sysupd'] as $m) {
    $f = $base . '/includes/' . $m . '.php';
    if (is_file($f)) require_once $f;
}
if (function_exists('smpro_lic_heartbeat')) { @smpro_lic_heartbeat(); }
if (!function_exists('smpro_su_tick')) exit;
@set_time_limit(3400);
try {
    smpro_su_tick();
} catch (\Throwable $e) {
    if (function_exists('smpro_worker_fatal')) smpro_worker_fatal('sysupd_tick', $e);
    else @error_log('smpro sysupd_tick: ' . $e->getMessage());
}
