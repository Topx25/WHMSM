<?php
/**
 * bin/fileaudit_tick.php - every minute: make the file-change evidence exist (auditd rules), collect it from the
 * kernel's log into the plugin's own store with the address joined, and prune what is older than the retention.
 *
 * NOT gated on smpro_ctl_disabled(): the history of a server whose plugin was switched off is exactly the
 * history somebody will ask for. Turning the feature off is its own switch (smpro_fa_cfg), and that switch also
 * removes the rules, so "off" means off in the kernel too.
 */
define('SMPRO_BOOT', 1);
$base = dirname(__DIR__);
foreach (['defines', 'env', 'helpers', 'secret', 'license', 'fileaudit'] as $m) {
    $f = $base . '/includes/' . $m . '.php';
    if (is_file($f)) require_once $f;
}
if (function_exists('smpro_lic_heartbeat')) { @smpro_lic_heartbeat(); }
if (!function_exists('smpro_fa_run')) exit;
@set_time_limit(110);
try {
    $r = smpro_fa_run();
    if (function_exists('smpro_audit') && ((int)$r['records'] > 0 || !$r['ok'] || !empty($r['provision']['did']))) {
        @smpro_audit('fileaudit_tick', ['ok' => $r['ok'] ? 1 : 0, 'records' => (int)$r['records'], 'why' => (string)$r['why'],
                                        'did' => (array)($r['provision']['did'] ?? [])]);
    }
} catch (\Throwable $e) {
    if (function_exists('smpro_worker_fatal')) smpro_worker_fatal('fileaudit_tick', $e);
    else @error_log('smpro fileaudit_tick: ' . $e->getMessage());
}
