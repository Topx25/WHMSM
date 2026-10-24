<?php
/**
 * bin/cooler_tick.php - per-minute load-guard worker (installed as /etc/cron.d/smpro-cooler
 * only while the guard is enabled). Reverts any expired throttle, then enforces the load ceiling.
 */
define('SMPRO_BOOT', 1);
$base = dirname(__DIR__);
foreach (['defines', 'helpers', 'secret', 'license', 'intrusion', 'notify', 'cooler', 'load_investigate', 'tgbot'] as $m) {
    $f = $base . '/includes/' . $m . '.php';
    if (is_file($f)) require $f;
}
if (function_exists('smpro_ctl_disabled') && smpro_ctl_disabled()) exit;   // disabled / license-dormant -> do nothing
if (function_exists('smpro_cool_tick'))       { try { smpro_cool_tick(); }       catch (\Throwable $e) { if (function_exists('smpro_worker_fatal')) smpro_worker_fatal(__FILE__, $e); else @error_log('smpro worker fatal in ' . basename(__FILE__) . ': ' . $e->getMessage()); } }
if (function_exists('smpro_cool_guard_tick')) { try { smpro_cool_guard_tick(); } catch (\Throwable $e) { if (function_exists('smpro_worker_fatal')) smpro_worker_fatal(__FILE__, $e); else @error_log('smpro worker fatal in ' . basename(__FILE__) . ': ' . $e->getMessage()); } }
