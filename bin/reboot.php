<?php
/**
 * bin/reboot.php - Scheduled-reboot worker. Installed as a one-shot /etc/cron.d/smpro-reboot at the admin's chosen
 * time. It RE-VERIFIES pre-reboot readiness and ABORTS (with a notification) if a critical check fails - so a
 * scheduled reboot can never take the server down into a kernel where LVE / network / boot would be broken.
 */
define('SMPRO_BOOT', 1);
$base = dirname(__DIR__);
foreach (['defines', 'helpers', 'secret', 'license', 'notify', 'tgbot', 'reboot'] as $m) {
    $f = $base . '/includes/' . $m . '.php';
    if (is_file($f)) require $f;
}
// GLOBAL GATE - admin-disabled / tamper-lock / license-dormant / sync-stop => never reboot.
// A monitor-only (Dry-Run) box never gets a surprise reboot.
// Either way the reboot that was announced is not going to happen, and that is said: it used to end here in
// silence, with "Reboot scheduled" as the last thing anybody was told.
$smproOff = (function_exists('smpro_ctl_disabled') && smpro_ctl_disabled()) ? 'the plugin is switched off or locked'
          : ((function_exists('smpro_ctl_dry_run') && smpro_ctl_dry_run()) ? 'the plugin is in Dry-Run (monitor only) mode' : '');
if ($smproOff !== '') {
    $sc = function_exists('smpro_reboot_sched') ? smpro_reboot_sched() : [];
    if (!empty($sc['enabled']) && (int)($sc['at'] ?? 0) > 0 && time() >= (int)$sc['at'] - 90) {
        if (function_exists('smpro_audit')) @smpro_audit('reboot_aborted', ['fail' => [$smproOff]]);
        if (function_exists('smpro_notify')) @smpro_notify('reboot_aborted', 'Scheduled reboot NOT performed', 'The scheduled reboot of this server was not performed because ' . $smproOff . '. Nothing was restarted. Schedule it again when that has changed.', ['severity' => 'warning'], true);
        if (function_exists('smpro_reboot_clear')) smpro_reboot_clear();
    }
    exit;
}
@ignore_user_abort(true);
@set_time_limit(120);
if (function_exists('smpro_reboot_run')) { try { smpro_reboot_run(); } catch (\Throwable $e) { if (function_exists('smpro_worker_fatal')) smpro_worker_fatal(__FILE__, $e); else @error_log('smpro worker fatal in ' . basename(__FILE__) . ': ' . $e->getMessage()); } }
