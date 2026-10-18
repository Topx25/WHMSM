<?php
/**
 * bin/tmp_expand.php — detached worker for the "Double /tmp capacity" loopback path.
 * Spawned by smpro_ds_tmp_launch_worker() (setsid, </dev/null). Acquires the single-flight flock,
 * ignore_user_abort + no time limit (each shell op is externally timeout-bounded), writes an immediate
 * heartbeat so the handler can confirm launch, re-detects UNDER LOCK (TOCTOU), runs the swap, and
 * GUARANTEES /tmp is mounted (or fully rolled back) independent of the HTTP request lifetime.
 * Usage: php bin/tmp_expand.php --job=<id>
 */
define('SMPRO_BOOT', 1);
$base = dirname(__DIR__);
require $base . '/includes/defines.php';
require $base . '/includes/helpers.php';
require $base . '/includes/maintenance.php'; // shared smpro_mnt_* helpers
require $base . '/includes/disk_tmp.php';   // the smpro_ds_tmp_* helpers (section A2-tmp)

@ignore_user_abort(true);
@set_time_limit(0);                          // per-command `timeout N` bounds each op

// --- parse --job=<id> (server-generated; sanitized) ---
$job = 'tmpexpand';
foreach ($argv as $a) { if (strpos($a, '--job=') === 0) $job = preg_replace('/[^a-z0-9]/', '', substr($a, 6)) ?: 'tmpexpand'; }

if (!function_exists('smpro_ds_tmp_expand_loop')) { fwrite(STDERR, "tmp_expand helpers missing\n"); exit(1); }

// --- single-flight lock (handler already refused if held; re-assert here) ---
$lockDir = function_exists('smpro_mnt_locks_dir') ? smpro_mnt_locks_dir() : (defined('SMPRO_LOCKS') ? SMPRO_LOCKS : '/var/lib/smpro/locks');
@is_dir($lockDir) || @mkdir($lockDir, 0700, true);
$fh = @fopen($lockDir . '/tmp_expand.lock', 'c');    // 'c' => never truncate; we never unlink the lock inode
if (!$fh || !@flock($fh, LOCK_EX | LOCK_NB)) { fwrite(STDERR, "another tmp_expand is running\n"); exit(1); }

// --- heartbeat immediately so the handler's ~5s launch check succeeds ---
smpro_ds_tmp_job_write(['phase' => 'prestage', 'pct' => 2, 'done' => false, 'msg' => 'Worker started', 'heartbeat' => time()]);

// --- crash safety net: on shutdown, if we died inside the sensitive window with /tmp bare, run the ladder ---
register_shutdown_function(function () use ($fh) {
    $man = smpro_ds_tmp_load();
    if (is_array($man) && in_array(($man['phase'] ?? ''), ['swap_detached', 'swap_mounted'], true)) {
        if (trim((string)@shell_exec('findmnt -no TARGET /tmp 2>/dev/null')) !== '/tmp') {
            $log = [];
            smpro_ds_tmp_rollback_loop((string)$man['phase'], smpro_ds_tmp_detect(), $log);   // guarantee /tmp mounted
        }
    }
    @flock($fh, LOCK_UN); @fclose($fh);
});

try {
    // Re-detect + re-plan UNDER LOCK: backing could have changed between preview and now.
    $d = smpro_ds_tmp_detect();
    $p = smpro_ds_tmp_plan($d);
    if ($p['refuse'] || !$p['safe'] || $p['backing'] !== 'loop') {
        $res = ['ok' => false, 'msg' => 'Refused under lock: ' . ($p['reason'] ?: 'not a safe loop expansion') . '.'];
        smpro_ds_tmp_job_write(['phase' => 'failed', 'pct' => 100, 'done' => true, 'msg' => $res['msg'], 'result' => $res, 'heartbeat' => time()]);
        exit(0);
    }
    $log = [];
    $res = smpro_ds_tmp_expand_loop($p, $log);
    smpro_ds_tmp_job_write([
        'phase'  => !empty($res['ok']) ? 'done' : (!empty($res['critical']) ? 'failed' : 'rolled_back'),
        'pct'    => 100, 'done' => true, 'msg' => $res['msg'] ?? '', 'result' => $res, 'log' => $log, 'heartbeat' => time(),
    ]);
    if (function_exists('smpro_audit')) {
        @smpro_audit('ds_tmp_expand', ['backing' => 'loop', 'from' => $res['from'] ?? 0, 'to' => $res['to'] ?? 0, 'ok' => !empty($res['ok']), 'rolled_back' => !empty($res['rolled_back']), 'critical' => !empty($res['critical'])]);
        @smpro_audit('disk_fix', ['action' => 'tmp_expand', 'ok' => !empty($res['ok']), 'msg' => $res['msg'] ?? '']);
    }
} catch (\Throwable $e) {
    // Ensure /tmp is mounted no matter what, then report.
    $man = smpro_ds_tmp_load();
    if (is_array($man) && in_array(($man['phase'] ?? ''), ['swap_detached', 'swap_mounted'], true)) {
        $log = []; smpro_ds_tmp_rollback_loop((string)$man['phase'], smpro_ds_tmp_detect(), $log);
    }
    $res = ['ok' => false, 'critical' => true, 'msg' => 'Worker crashed: ' . $e->getMessage()];
    smpro_ds_tmp_job_write(['phase' => 'failed', 'pct' => 100, 'done' => true, 'msg' => $res['msg'], 'result' => $res, 'heartbeat' => time()]);
    if (function_exists('smpro_audit')) @smpro_audit('ds_tmp_expand', ['backing' => 'loop', 'ok' => false, 'critical' => true]);
}
exit(0);