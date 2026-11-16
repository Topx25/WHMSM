<?php
/**
 * bin/sitedoctor_bulk.php - Site Doctor worker for every site at once.
 *   scan  - probe every site, diagnose the failing ones (started from the page)
 *   fix   - fix the sites the operator ticked (started from the page)
 *   daily - the daily cron: scan, then (only with the automatic switch on) apply the safe fixes; purge 7-day backups
 * Detached from the page, so it finishes when the page is closed.
 */
define('SMPRO_BOOT', 1);
$base = dirname(__DIR__);
foreach (['defines', 'mmdb', 'helpers', 'secret', 'license', 'domains', 'investigate', 'sdbulk'] as $m) {
    $f = $base . '/includes/' . $m . '.php';
    if (is_file($f)) require_once $f;
}
if (PHP_SAPI !== 'cli') exit;
if (function_exists('smpro_ctl_disabled') && smpro_ctl_disabled()) exit;
if (!function_exists('smpro_sdb_run_job')) exit;
@ini_set('memory_limit', '512M'); @set_time_limit(0);
$kind = (string)($argv[1] ?? 'scan');
if ($kind === 'diag') {   // one site, for the scan that started this process; no worker lock (the scan holds it)
    $dom = strtolower(preg_replace('/[^A-Za-z0-9.-]/', '', (string)($argv[2] ?? '')));
    $p = json_decode((string)base64_decode((string)($argv[3] ?? ''), true), true);
    if ($dom === '' || !is_array($p) || !function_exists('smpro_sdb_diag')) exit(2);
    try { $row = smpro_sdb_diag($dom, $p); }
    catch (\Throwable $e) { $row = ['cause' => 'The detailed check of this site failed: ' . mb_substr($e->getMessage(), 0, 160) . '. The scan went on to the next site.', 'fixes' => [], 'advice' => 'Click the site name to examine it alone.', 'diag_failed' => 1]; }
    echo "\n__SDB__" . json_encode($row, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    exit(0);
}
if (!in_array($kind, ['scan', 'resume', 'fix', 'daily'], true)) exit(2);
$lk = @fopen(smpro_sdb_path('worker.lock'), 'c');
if (!$lk || !@flock($lk, LOCK_EX | LOCK_NB)) exit;   // one worker at a time
if ($kind === 'daily') {
    $cfg = smpro_sdb_cfg();
    if (!$cfg['scan_daily'] && !$cfg['auto']) { smpro_sdb_purge(); exit; }
    smpro_sdb_save('job.json', ['kind' => 'daily', 'domains' => [], 'running' => true, 'started' => time(), 'done' => 0, 'total' => 0, 'pid' => getmypid()]);
}
try { smpro_sdb_run_job($kind); }
catch (\Throwable $e) { $j = smpro_sdb_load('job.json'); $j['running'] = false; $j['error'] = $e->getMessage(); smpro_sdb_save('job.json', $j); }
