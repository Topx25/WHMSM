<?php
/**
 * bin/cleanscan.php — detached worker for the per-account disk-cleanup scan.
 * Runs to completion even if the admin closes the page; the finished report waits for them on return.
 * The only thing that stops it is an explicit cancel from the UI (which sets cancelled=1 in the job file).
 */
define('SMPRO_BOOT', 1);   // MUST precede the requires — every include exits('forbidden') without it
$root = dirname(__DIR__);
foreach (['defines', 'helpers', 'maintenance', 'disk_scan'] as $m) {
    $f = $root . '/includes/' . $m . '.php';
    if (is_file($f)) require $f;
}
@ignore_user_abort(true);
@set_time_limit(0);

$acct = '';
foreach ($argv as $a) if (strpos($a, '--user=') === 0) $acct = preg_replace('/[^a-zA-Z0-9._-]/', '', substr($a, 7));
if ($acct === '' || !is_dir(smpro_user_home($acct))) exit(2);

if (function_exists('smpro_ctl_disabled') && smpro_ctl_disabled()) exit(0);

/* single-flight per account */
$lockDir = defined('SMPRO_LOCKS') ? SMPRO_LOCKS : (SMPRO_VARLIB . '/locks');
@is_dir($lockDir) || @mkdir($lockDir, 0700, true);
$lf = @fopen($lockDir . '/cleanscan_' . $acct . '.lock', 'c');

$job = smpro_ds_scan_read($acct);
$job['account'] = $acct; $job['phase'] = 'scanning'; $job['done'] = false;
$job['heartbeat'] = time(); $job['msg'] = 'Scanning ' . $acct . ' for large files, archives, logs and cache…';
if (empty($job['started_at'])) $job['started_at'] = time();
smpro_ds_scan_write($acct, $job);   // heartbeat FIRST — the launcher waits on exactly this

if ($lf && !@flock($lf, LOCK_EX | LOCK_NB)) {
    $job['done'] = true; $job['phase'] = 'error'; $job['msg'] = 'Another scan for this account is already running.';
    smpro_ds_scan_write($acct, $job); exit(0);
}

register_shutdown_function(function () use ($acct) {
    $e = error_get_last();
    if ($e && in_array($e['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) {
        $j = smpro_ds_scan_read($acct);
        if (empty($j['done'])) { $j['done'] = true; $j['phase'] = 'error'; $j['msg'] = 'Scan crashed: ' . $e['message']; smpro_ds_scan_write($acct, $j); }
    }
});

$res = smpro_ds_cleanscan($acct);

// Honour an explicit cancel that arrived while we were scanning — the admin's cancel wins, and we do NOT
// overwrite it with a finished report.
$now = smpro_ds_scan_read($acct);
if (!empty($now['cancelled'])) { if (function_exists('smpro_audit')) smpro_audit('disk_cleanscan', ['account' => $acct, 'cancelled' => 1]); exit(0); }

$job = $now ?: $job;
$job['account'] = $acct;
$job['done'] = true;
$job['finished_at'] = time();
$job['heartbeat'] = time();
if (!empty($res['err'])) { $job['phase'] = 'error'; $job['msg'] = (string)$res['err']; $job['result'] = null; }
else {
    $job['phase'] = 'done';
    $job['result'] = $res;
    $job['counts'] = ['large' => count($res['large'] ?? []), 'arch' => count($res['arch'] ?? []),
                      'logs' => count($res['logs'] ?? []), 'cache' => count($res['cache'] ?? [])];
    $tot = 0;
    foreach (['large', 'arch', 'logs'] as $k) foreach ((array)($res[$k] ?? []) as $it) $tot += (int)($it['size'] ?? 0);
    foreach ((array)($res['cache'] ?? []) as $it) $tot += (int)($it['size'] ?? 0);
    $job['reclaimable'] = $tot;
    $job['msg'] = 'Scan finished — ' . array_sum($job['counts']) . ' item(s), ' . smpro_ds_humb($tot) . ' reclaimable.';
}
smpro_ds_scan_write($acct, $job);
if (function_exists('smpro_audit')) smpro_audit('disk_cleanscan', ['account' => $acct, 'items' => array_sum($job['counts'] ?? []), 'bytes' => (int)($job['reclaimable'] ?? 0)]);
