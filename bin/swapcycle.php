<?php
/**
 * bin/swapcycle.php — Auto Swap-Cycle worker. Installed as /etc/cron.d/smpro-swapcycle ONLY while the feature
 * is enabled; fires every 5 min. Cycles swap (swapoff -a && swapon -a) to drain idle pages back to RAM when
 * swap usage crosses the admin threshold — but ONLY if the OOM safety gate passes (free RAM >= 1.5x swap-in-use
 * and >= 25% RAM free). If the gate is not met it SKIPS; it never forces an unsafe swapoff.
 */
define('SMPRO_BOOT', 1);
$base = dirname(__DIR__);
foreach (['defines', 'helpers', 'secret', 'license', 'notify', 'maintenance'] as $m) {
    $f = $base . '/includes/' . $m . '.php';
    if (is_file($f)) require $f;
}
// GLOBAL GATE — admin-disabled / tamper-lock / license-dormant / sync-stop => do nothing.
if (function_exists('smpro_ctl_disabled') && smpro_ctl_disabled()) exit;
// A monitor-only (Dry-Run) box never gets a surprise swap cycle.
if (function_exists('smpro_ctl_dry_run') && smpro_ctl_dry_run()) exit;
@ignore_user_abort(true);
@set_time_limit(280);
if (function_exists('smpro_swapcycle_run')) { try { smpro_swapcycle_run(); } catch (\Throwable $e) { if (function_exists('smpro_worker_fatal')) smpro_worker_fatal(__FILE__, $e); else @error_log('smpro worker fatal in ' . basename(__FILE__) . ': ' . $e->getMessage()); } }
