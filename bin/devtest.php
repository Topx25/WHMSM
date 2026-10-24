<?php
/**
 * bin/devtest.php - single-device benchmark worker. Spawned detached by smpro_bd_devtest_start()
 * so testing one disk (or CPU / RAM / PHP / MySQL) survives the page being closed.
 * Physical-disk tests are strictly READ-ONLY - never writes to a raw device.
 * Usage: php devtest.php <kind> [target]
 */
define('SMPRO_BOOT', 1);
$base = dirname(__DIR__);
foreach (['defines', 'helpers', 'secret', 'license', 'dbhealth', 'benchmark', 'benchdiag'] as $m) {
    $f = $base . '/includes/' . $m . '.php';
    if (is_file($f)) require $f;
}
if (function_exists('smpro_ctl_disabled') && smpro_ctl_disabled()) exit;
@ignore_user_abort(true);
@set_time_limit(600);
$kind   = isset($argv[1]) ? preg_replace('/[^a-z]/', '', strtolower((string)$argv[1])) : '';
$target = isset($argv[2]) ? preg_replace('/[^A-Za-z0-9]/', '', (string)$argv[2]) : '';
if (function_exists('smpro_bd_run_devtest')) {
    try { smpro_bd_run_devtest($kind, $target); }
    catch (\Throwable $e) {
        if (function_exists('smpro_bd_state_write')) smpro_bd_state_write(['status' => 'error', 'msg' => 'Device test crashed: ' . $e->getMessage(), 'finished' => time()]);
    }
}
