<?php
/**
 * bin/learn_tick.php — every ten minutes: Learned Defense notes processes a file scan cannot see, and hunts the
 * whole server after a new lesson (or once a day). Reports only; see includes/learn.php.
 */
define('SMPRO_BOOT', 1);
$base = dirname(__DIR__);
foreach (['defines', 'env', 'mmdb', 'helpers', 'secret', 'license', 'learn'] as $m) {
    $f = $base . '/includes/' . $m . '.php';
    if (is_file($f)) require_once $f;
}
if (!function_exists('smpro_lr_tick')) exit;
if (function_exists('smpro_ctl_disabled') && smpro_ctl_disabled()) exit;
@set_time_limit(580);
try { smpro_lr_tick(); } catch (\Throwable $e) { if (function_exists('smpro_log_append')) @smpro_log_append('learn', 'tick failed: ' . $e->getMessage()); }
