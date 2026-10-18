<?php
/**
 * bin/autopurge.php — Auto-Purge Scheduler worker. Installed as /etc/cron.d/smpro-autopurge ONLY while a
 * cadence is chosen. Fixed mode fires on the interval; smart mode fires hourly (:07) and lets smpro_mnt_decide()
 * choose. `--run-now` performs one immediate purge (the UI "Run now" button, launched detached).
 */
define('SMPRO_BOOT', 1);
$base = dirname(__DIR__);
// Require the FULL set so smpro_ctl_disabled() can see license-dormant / tamper-lock / sync-stop, and the
// notifier is available for the smart "reclaim ineffective" alert.
foreach (['defines', 'helpers', 'secret', 'license', 'intrusion', 'notify', 'maintenance', 'tgbot'] as $m) {
    $f = $base . '/includes/' . $m . '.php';
    if (is_file($f)) require $f;
}
// GLOBAL GATE first — admin-disabled / tamper-lock / license-dormant / sync-stop => do nothing (parity with
// bin/cooler_tick.php line 12). Without this a dormant/tamper-locked/Disabled server would still auto-delete.
if (function_exists('smpro_ctl_disabled') && smpro_ctl_disabled()) exit;

$runNow = in_array('--run-now', (array)($argv ?? []), true);
if ($runNow) {
    // Run-now still honors Dry-Run: a monitor-only box never gets a surprise purge.
    if (function_exists('smpro_ctl_dry_run') && smpro_ctl_dry_run()) exit;
    if (function_exists('smpro_mnt_purge')) { try { smpro_mnt_purge(true, false); } catch (\Throwable $e) { if (function_exists('smpro_worker_fatal')) smpro_worker_fatal(__FILE__, $e); else @error_log('smpro worker fatal in ' . basename(__FILE__) . ': ' . $e->getMessage()); } }
    exit;
}
// Scheduled tick (fixed => run; smart => decide). tick() honors cfg.enabled + Dry-Run internally.
if (function_exists('smpro_mnt_tick')) { try { smpro_mnt_tick(); } catch (\Throwable $e) { if (function_exists('smpro_worker_fatal')) smpro_worker_fatal(__FILE__, $e); else @error_log('smpro worker fatal in ' . basename(__FILE__) . ': ' . $e->getMessage()); } }
