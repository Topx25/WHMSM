<?php
/**
 * bin/hub_worker.php - Multi-Server member worker (cron, every minute).
 * Lets a Member server pull + run its hub's plugin-scoped commands and refresh the
 * pairing-invitation cache even when no admin is browsing the panel. Exits instantly
 * if the plugin is disabled or this server isn't an active (Ultra, not-turned-off) member.
 */
define('SMPRO_BOOT', 1);
$base = dirname(__DIR__);
foreach (['defines','env','mmdb','helpers','secret','license','intrusion','auth','csrf','ai','notify','profiles','update','integrity','reports','investigate','digest','tuning','tgbot','cooler','hub'] as $f) {
    $inc = "$base/includes/$f.php"; if (is_file($inc)) @require_once $inc;
}
if (function_exists('smpro_ctl_disabled') && smpro_ctl_disabled()) exit;
// graduated degradation: shed this optional worker once the license server has been unreachable for a while (grace phase >= 2)
if (function_exists('smpro_lic_grace_phase') && smpro_lic_grace_phase() >= 2) exit;
if (function_exists('smpro_hub_active') && smpro_hub_active() && function_exists('smpro_hub_member_tick')) {
    try {
        $r = smpro_hub_member_tick(true);
        // a hub is actively viewing this server -> fast-poll for ~50s so the remote panel feels live
        if (!empty($r['live']) && function_exists('smpro_hub_live_loop')) smpro_hub_live_loop();
        // if THIS server is a hub, refresh the fleet cache so the Dashboard shows members' status with no lag.
        // Also refresh when a fleet cache EXISTS even with zero active links, so revoking the LAST member clears
        // the Dashboard instead of leaving a ghost entry forever.
        if (function_exists('smpro_hub_fleet')) {
            $hubActive = false;
            foreach (smpro_hub_links('hub') as $L) { if (($L['status'] ?? '') === 'active') { $hubActive = true; break; } }
            if ($hubActive || is_file(SMPRO_VARLIB . '/hub/fleet.json')) smpro_hub_fleet();
        }
    } catch (\Throwable $e) {
        // don't die silently - a thrown E2E/auth failure or worker bug must leave a forensic trail
        if (function_exists('smpro_log_append')) smpro_log_append(SMPRO_VARLOG . '/hub_worker.log', date('c') . ' ERROR: ' . $e->getMessage() . "\n", 2097152, 2); else @file_put_contents(SMPRO_VARLOG . '/hub_worker.log', date('c') . ' ERROR: ' . $e->getMessage() . "\n", FILE_APPEND | LOCK_EX);
        if (function_exists('smpro_audit')) smpro_audit('hub_worker_error', ['msg' => mb_substr($e->getMessage(), 0, 200)]);
    }
}
