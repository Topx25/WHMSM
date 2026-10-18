<?php
/**
 * bin/hwsample.php — hardware workload sampler. Run every 5 minutes from /etc/cron.d/smpro-hwsample.
 * Folds one CPU / memory / swap / disk-busy / disk-space reading into the current hour's bucket so
 * the "does the hardware match the load?" report has real 7-day peaks. Cheap and read-only.
 */
define('SMPRO_BOOT', 1);
$base = dirname(__DIR__);
foreach (['defines', 'helpers', 'secret', 'license', 'diskio', 'dbhealth', 'benchmark', 'benchdiag'] as $m) {
    $f = $base . '/includes/' . $m . '.php';
    if (is_file($f)) require $f;
}
if (function_exists('smpro_ctl_disabled') && smpro_ctl_disabled()) exit;
@set_time_limit(60);
if (function_exists('smpro_bd_sample_run')) { try { smpro_bd_sample_run(); } catch (\Throwable $e) { if (function_exists('smpro_worker_fatal')) smpro_worker_fatal(__FILE__, $e); else @error_log('smpro worker fatal in ' . basename(__FILE__) . ': ' . $e->getMessage()); } }
