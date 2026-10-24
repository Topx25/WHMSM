<?php
/**
 * bin/compcheck_tick.php - every ten minutes: run the scheduled Compromise Check when its slot is due.
 * The plan (when, what, whom to tell) lives in smpro_cx_sched_cfg(); the cron line is only the heartbeat.
 */
define('SMPRO_BOOT', 1);
$base = dirname(__DIR__);
foreach (['defines', 'env', 'mmdb', 'helpers', 'secret', 'license', 'notify', 'compcheck', 'ccfix'] as $m) {
    $f = $base . '/includes/' . $m . '.php';
    if (is_file($f)) require_once $f;
}
if (function_exists('smpro_lic_heartbeat')) { @smpro_lic_heartbeat(); }
if (!function_exists('smpro_cx_due')) exit;
if (function_exists('smpro_ctl_disabled') && smpro_ctl_disabled()) exit;   // the global switch covers the scheduled scan too
@set_time_limit(580);
try {
    $c = smpro_cx_sched_cfg();
    if (!smpro_cx_due($c)) exit;
    smpro_cx_run_scheduled($c);
} catch (\Throwable $e) {
    if (function_exists('smpro_worker_fatal')) smpro_worker_fatal('compcheck_tick', $e);
    else @error_log('smpro compcheck_tick: ' . $e->getMessage());
}
