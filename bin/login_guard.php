<?php
/**
 * bin/login_guard.php - per-minute worker (installed as /etc/cron.d/smpro-login-guard while enabled).
 * Auto-blocks FOREIGN (non-Arab) source IPs that brute-force cPanel/WHM logins. Arab + local IPs are
 * never blocked; allowlist honoured; deduped; capped; every block audited. See smpro_login_guard_run().
 */
define('SMPRO_BOOT', 1);
$base = dirname(__DIR__);
foreach (['defines', 'mmdb', 'helpers', 'secret', 'license', 'intrusion', 'notify', 'cooler', 'tgbot'] as $m) {
    $f = $base . '/includes/' . $m . '.php';
    if (is_file($f)) require $f;
}
if (function_exists('smpro_lic_heartbeat')) { @smpro_lic_heartbeat(); }                 // keep the license fresh (so renewal wakes the plugin)
if (function_exists('smpro_ctl_disabled') && smpro_ctl_disabled()) exit;                 // disabled / license-dormant -> do nothing
if (function_exists('smpro_login_guard_run')) { try { smpro_login_guard_run(false); } catch (\Throwable $e) { if (function_exists('smpro_worker_fatal')) smpro_worker_fatal(__FILE__, $e); else @error_log('smpro worker fatal in ' . basename(__FILE__) . ': ' . $e->getMessage()); } }
