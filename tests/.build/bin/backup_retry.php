<?php
/**
 * bin/backup_retry.php — auto-retry failed JetBackup jobs until they complete.
 *
 * Run by cron (installed/removed from the Backup Monitor page). For each backup
 * job that is NOT running and whose last run did not complete
 * (last_completed < last_run), it calls runBackupJobManually, up to MAX attempts.
 * A successful completion resets that job's counter. State + log under
 * /var/lib/smpro. Bounded, idempotent, safe to run repeatedly.
 */

// honor the master switch / license-dormancy (disable ALL functions when the plugin is disabled or the license stopped >48h)
define('SMPRO_BOOT', 1);
foreach (['defines', 'env', 'mmdb', 'helpers', 'secret', 'license'] as $m) { $f = dirname(__DIR__) . '/includes/' . $m . '.php'; if (is_file($f)) @require_once $f; }
if (function_exists('smpro_ctl_disabled') && smpro_ctl_disabled()) exit;
// graduated degradation: shed this heavy/optional worker once the license server has been unreachable for a while (grace phase >= 2)
if (function_exists('smpro_lic_grace_phase') && smpro_lic_grace_phase() >= 2) exit;

define('SMPRO_BM_MAX', 5);                                   // give up after this many retries per failure cycle
$statePath = '/var/lib/smpro/state/backup_retry.json';
$logPath   = '/var/log/smpro/backup_retry.log';
$bin = '/usr/bin/jetbackup5api';
if (!is_executable($bin)) { fwrite(STDERR, "jetbackup5api not found\n"); exit(1); }

function jb($func, $data = '') {
    global $bin;
    $out = (string)@shell_exec('timeout 120 ' . $bin . ' -F ' . escapeshellarg($func) . ' -O json' . ($data !== '' ? ' -D ' . escapeshellarg($data) : '') . ' 2>/dev/null');
    $j = json_decode($out, true);
    return is_array($j) ? $j : [];
}
function bm_log($m) { global $logPath; @is_dir(dirname($logPath)) || @mkdir(dirname($logPath), 0700, true); @file_put_contents($logPath, date('c') . ' ' . $m . "\n", FILE_APPEND | LOCK_EX); }

$state = is_file($statePath) ? json_decode((string)@file_get_contents($statePath), true) : [];
if (!is_array($state)) $state = [];

$list = jb('listBackupJobs');
$jobs = $list['data']['jobs'] ?? $list['data'] ?? [];
if (!is_array($jobs)) { exit(0); }

$now = time();
foreach ($jobs as $j) {
    $id = (string)($j['_id'] ?? ''); if ($id === '') continue;
    $full = jb('getBackupJob', '_id=' . $id)['data'] ?? $j;
    if (!empty($full['running'])) continue;                  // currently running — leave it
    $lr = strtotime((string)($full['last_run'] ?? '')) ?: 0;
    $lc = strtotime((string)($full['last_completed'] ?? '')) ?: 0;
    $name = (string)($full['name'] ?? $id);

    $failed = $lr > 0 && $lc < $lr;                          // last run started but never completed
    if (!$failed) {                                          // success → clear any retry state
        if (isset($state[$id])) { bm_log("OK '$name' completed — clearing retry state"); unset($state[$id]); }
        continue;
    }
    // Only retry a given failed run once per run-timestamp cycle, capped at MAX.
    $rec = $state[$id] ?? ['attempts' => 0, 'for_run' => 0];
    if ((int)($rec['for_run'] ?? 0) !== $lr) { $rec = ['attempts' => 0, 'for_run' => $lr]; }   // a newer failed run resets the counter
    if ((int)$rec['attempts'] >= SMPRO_BM_MAX) { continue; } // exhausted — stop hammering

    jb('runBackupJobManually', '_id=' . $id);
    $rec['attempts'] = (int)$rec['attempts'] + 1;
    $rec['last_retry'] = date('c'); $rec['name'] = $name;
    $state[$id] = $rec;
    bm_log("RETRY '$name' (job $id) — attempt {$rec['attempts']}/" . SMPRO_BM_MAX);
}

@is_dir(dirname($statePath)) || @mkdir(dirname($statePath), 0700, true);
@file_put_contents($statePath, json_encode($state, JSON_UNESCAPED_SLASHES), LOCK_EX);
@chmod($statePath, 0600);
