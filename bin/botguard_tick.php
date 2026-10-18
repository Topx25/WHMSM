<?php
/**
 * bin/botguard_tick.php — Bot Guard worker (installed as /etc/cron.d/smpro-botguard while Bot Guard is enabled).
 * Verifies crawlers, gray-lists attackers, auto-blocks past the threshold. See includes/botguard.php.
 */
define('SMPRO_BOOT', 1);
$base = dirname(__DIR__);
foreach (['defines', 'mmdb', 'helpers', 'secret', 'license', 'intrusion', 'notify', 'fwallow', 'botguard'] as $m) {
    $f = $base . '/includes/' . $m . '.php';
    if (is_file($f)) require_once $f;
}
if (function_exists('smpro_lic_heartbeat')) { @smpro_lic_heartbeat(); }
if (function_exists('smpro_ctl_disabled') && smpro_ctl_disabled()) exit;
if (function_exists('smpro_bg_run')) { try { smpro_bg_run(false); } catch (\Throwable $e) { if (function_exists('smpro_worker_fatal')) smpro_worker_fatal(__FILE__, $e); else @error_log('smpro worker fatal in ' . basename(__FILE__) . ': ' . $e->getMessage()); } }
