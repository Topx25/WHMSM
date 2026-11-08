<?php
/**
 * bin/sitewatch.php - Site Watch worker.
 *   tick - the cron (every 15 minutes): start the scheduled check when it is due, send report digests, prune
 *   job  - a check started from the page (detached; finishes when the page is closed)
 */
define('SMPRO_BOOT', 1);
$base = dirname(__DIR__);
foreach (['defines', 'mmdb', 'helpers', 'secret', 'license', 'notify', 'domains', 'investigate', 'sdbulk', 'fileaudit', 'sitewatch'] as $m) {
    $f = $base . '/includes/' . $m . '.php';
    if (is_file($f)) require_once $f;
}
if (PHP_SAPI !== 'cli') exit;
if (function_exists('smpro_ctl_disabled') && smpro_ctl_disabled()) exit;
if (!function_exists('smpro_sw_tick')) exit;
@ini_set('memory_limit', '768M'); @set_time_limit(0);
$kind = (string)($argv[1] ?? 'tick');
$lk = @fopen(smpro_sw_path('worker.lock'), 'c');
if (!$lk || !@flock($lk, LOCK_EX | LOCK_NB)) exit;   // one worker at a time
try {
    if ($kind === 'job') smpro_sw_run_job();
    elseif ($kind === 'tick') smpro_sw_tick();
} catch (\Throwable $e) {
    $j = smpro_sw_load('job.json'); $j['running'] = false; $j['error'] = $e->getMessage(); smpro_sw_save('job.json', $j);
}
