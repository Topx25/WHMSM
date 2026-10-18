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
foreach (['defines', 'env', 'mmdb', 'helpers', 'secret', 'license', 'notify'] as $m) { $f = dirname(__DIR__) . '/includes/' . $m . '.php'; if (is_file($f)) @require_once $f; }
if (function_exists('smpro_ctl_disabled') && smpro_ctl_disabled()) exit;
if (function_exists('smpro_ctl_dry_run') && smpro_ctl_dry_run()) exit;   // global Dry-Run: this worker only acts, so it stays home
// graduated degradation: shed this heavy/optional worker once the license server has been unreachable for a while (grace phase >= 2)
if (function_exists('smpro_lic_grace_phase') && smpro_lic_grace_phase() >= 2) exit;

define('SMPRO_BM_MAX', 5);                                   // give up after this many retries per rolling window
define('SMPRO_BM_WINDOW', 6 * 3600);                        // …within this window; a genuinely new failure later gets a fresh budget
$statePath = '/var/lib/smpro/state/backup_retry.json';
$logPath   = '/var/log/smpro/backup_retry.log';
$bin = '/usr/bin/jetbackup5api';
if (!is_executable($bin)) { fwrite(STDERR, "jetbackup5api not found\n"); exit(1); }

function jb($func, $data = '') {
    global $bin;
    $out = (string)@shell_exec('timeout 120 ' . $bin . ' -F ' . escapeshellarg($func) . ' -O json' . ($data !== '' ? ' -D ' . escapeshellarg($data) : '') . ' 2>/dev/null');
    $j = json_decode($out, true);
    if (!is_array($j)) { $GLOBALS['jbErr'] = 'no readable response for "' . $func . '"'; return []; }
    // success=0 replies (expired licence, disabled API) carry error text in 'data'. Reading 'data' unconditionally
    // turned a hard API failure into an empty job list, i.e. "nothing to retry" — silently, forever.
    if (array_key_exists('success', $j) && (int)$j['success'] !== 1) {
        $m = trim((string)($j['message'] ?? $j['error'] ?? ''));
        if ($m === '' && isset($j['data']) && is_string($j['data'])) $m = trim($j['data']);
        $GLOBALS['jbErr'] = ($m !== '' ? $m : 'API call "' . $func . '" failed');
        return [];
    }
    return $j;
}
function bm_log($m) { global $logPath; @is_dir(dirname($logPath)) || @mkdir(dirname($logPath), 0700, true); @file_put_contents($logPath, date('c') . ' ' . $m . "\n", FILE_APPEND | LOCK_EX); }

$state = is_file($statePath) ? json_decode((string)@file_get_contents($statePath), true) : [];
if (!is_array($state)) $state = [];

$GLOBALS['jbErr'] = '';
$list = jb('listBackupJobs');
// An API error must be logged, not treated as "no jobs to retry" — a silent exit(0) every 20 min is exactly how
// a broken JetBackup licence stayed invisible while auto-retry appeared to be running.
if ($GLOBALS['jbErr'] !== '') { bm_log('ERROR JetBackup API unavailable: ' . $GLOBALS['jbErr'] . ' — no jobs could be read, nothing retried'); exit(0); }
$jobs = $list['data']['jobs'] ?? $list['data'] ?? [];
if (!is_array($jobs)) { exit(0); }

$now = time(); $bmT0 = time();
$bmSave = function () use (&$state, $statePath) { @is_dir(dirname($statePath)) || @mkdir(dirname($statePath), 0700, true); @file_put_contents($statePath, json_encode($state, JSON_UNESCAPED_SLASHES), LOCK_EX); @chmod($statePath, 0600); };
foreach ($jobs as $j) {
    if (time() - $bmT0 > 420) { bm_log('deadline reached - remaining jobs wait for the next tick'); break; }   // inside the cron's timeout, so the counter below is always written
    $id = (string)($j['_id'] ?? ''); if ($id === '') continue;
    $full = jb('getBackupJob', '_id=' . $id)['data'] ?? $j;
    if (!empty($full['running'])) continue;                  // currently running — leave it
    // JetBackup's 'state' is NOT the enabled flag — a live, enabled job reports state:0 alongside a separate
    // 'disabled' field. Keying off state made the retry worker skip EVERY job, so auto-retry silently never ran.
    if (!empty($full['disabled'])) continue;   // job is disabled — never auto-retry or it re-runs forever
    $lr = (is_numeric($full['last_run'] ?? '') ? (int)($full['last_run'] ?? 0) : (strtotime((string)($full['last_run'] ?? '')) ?: 0));
    $lc = (is_numeric($full['last_completed'] ?? '') ? (int)($full['last_completed'] ?? 0) : (strtotime((string)($full['last_completed'] ?? '')) ?: 0));
    $name = (string)($full['name'] ?? $id);

    $failed = $lr > 0 && $lc < $lr;                          // last run started but never completed
    if (!$failed) {                                          // success → clear any retry state
        if (isset($state[$id])) { bm_log("OK '$name' completed — clearing retry state"); unset($state[$id]); }
        continue;
    }
    // Cap retries per ROLLING WINDOW, not per run-timestamp. Each retry launches a NEW run with a
    // new last_run, so keying the counter on $lr reset it every tick → a permanently-failing job was
    // re-run every cron interval forever. Now: at most SMPRO_BM_MAX retries per SMPRO_BM_WINDOW; a
    // genuinely new failure after the window elapses gets a fresh budget.
    $rec = $state[$id] ?? ['attempts' => 0, 'window' => 0];
    if ((int)($rec['window'] ?? 0) === 0 || ($now - (int)$rec['window']) > SMPRO_BM_WINDOW) {
        $rec = ['attempts' => 0, 'window' => $now];         // start a fresh retry window
    }
    if ((int)$rec['attempts'] >= SMPRO_BM_MAX) {            // exhausted for this window — stop hammering
        // Tell the admin once per window that auto-retry gave up (previously it just went quiet).
        if (empty($rec['exhausted_notified']) && function_exists('smpro_notify')) {
            smpro_notify('backup_failed', 'Auto-retry exhausted: backup job "' . $name . '"',
                'SM Pro retried this failed JetBackup job ' . SMPRO_BM_MAX . ' time(s) and it still did not complete.'
                . "\nOpen Backup Monitor to investigate (destination full / unreachable, permissions, or the job config).",
                ['severity' => 'high']);
            $rec['exhausted_notified'] = 1;
            $state[$id] = $rec;
            bm_log("EXHAUSTED '$name' (job $id) — notified admin");
        }
        continue;
    }

    $rec['attempts'] = (int)$rec['attempts'] + 1;              // counted BEFORE the launch: a kill mid-call must not reset it
    $rec['last_retry'] = date('c'); $rec['name'] = $name;
    $state[$id] = $rec; $bmSave();
    jb('runBackupJobManually', '_id=' . $id);
    bm_log("RETRY '$name' (job $id) — attempt {$rec['attempts']}/" . SMPRO_BM_MAX);
}

@is_dir(dirname($statePath)) || @mkdir(dirname($statePath), 0700, true);
@file_put_contents($statePath, json_encode($state, JSON_UNESCAPED_SLASHES), LOCK_EX);
@chmod($statePath, 0600);
