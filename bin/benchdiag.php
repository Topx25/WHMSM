<?php
/**
 * bin/benchdiag.php - Benchmark & Diagnostics worker. Spawned detached by smpro_bd_start() so the full suite
 * (CPU/RAM/disk + PHP + MySQL) keeps running - and is saved to the report history - even if the admin closes
 * the page. Writes progress + partial results to the state file as it goes.
 * Usage: php benchdiag.php <disk-mount>
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
$mount = isset($argv[1]) ? preg_replace('#[^A-Za-z0-9/_.\-]#', '', (string)$argv[1]) : '';
if (function_exists('smpro_bd_run_all')) {
    try { smpro_bd_run_all($mount); }
    catch (\Throwable $e) {
        if (function_exists('smpro_bd_state_write')) smpro_bd_state_write(['status' => 'error', 'msg' => 'Benchmark crashed: ' . $e->getMessage(), 'finished' => time()]);
    }
}
