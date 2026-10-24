<?php
/**
 * bin/benchmark.php - Hardware benchmark worker. Spawned detached by smpro_bm_start() so the CPU/RAM/disk tests keep
 * running (and results are saved) even if the admin closes the page. Writes progress + results to the state file.
 * Usage: php benchmark.php <disk-mount>
 */
define('SMPRO_BOOT', 1);
$base = dirname(__DIR__);
foreach (['defines', 'helpers', 'secret', 'license', 'benchmark'] as $m) {
    $f = $base . '/includes/' . $m . '.php';
    if (is_file($f)) require $f;
}
if (function_exists('smpro_ctl_disabled') && smpro_ctl_disabled()) exit;
@ignore_user_abort(true);
@set_time_limit(300);
$mount = isset($argv[1]) ? preg_replace('#[^A-Za-z0-9/_.\-]#', '', (string)$argv[1]) : '';
if (function_exists('smpro_bm_run')) { try { smpro_bm_run($mount); } catch (\Throwable $e) { if (function_exists('smpro_bm_state_write')) smpro_bm_state_write(['status' => 'error', 'msg' => 'Benchmark crashed: ' . $e->getMessage(), 'finished' => time()]); } }
