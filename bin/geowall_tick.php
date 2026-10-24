<?php
/**
 * bin/geowall_tick.php - the country wall's dead man's switch, and its recovery after a reboot.
 *
 * Two jobs, and both of them exist because the wall it looks after can lock the operator out of their own server
 * with no way back except the hosting provider's console:
 *
 *   1. If nothing has confirmed the panel is still reachable within the configured window, take the wall DOWN.
 *      That is the difference between a feature somebody can try and a feature nobody dares turn on.
 *   2. A reboot clears ipset and iptables. Put the wall back, from the configuration and the address it was
 *      armed from - because "on in the settings, absent in the kernel" is the exact state the whole feature
 *      exists to make impossible.
 */
define('SMPRO_BOOT', 1);
$base = dirname(__DIR__);
foreach (['defines', 'mmdb', 'helpers', 'secret', 'license', 'geologin', 'notify', 'geowall'] as $m) {
    $f = $base . '/includes/' . $m . '.php';
    if (is_file($f)) require_once $f;
}

if (function_exists('smpro_lic_heartbeat')) { @smpro_lic_heartbeat(); }
// NOTE: deliberately NOT gated on smpro_ctl_disabled(). If the plugin is switched off while a wall is up, the
// wall must still come down - leaving a DROP rule behind after the thing that manages it has been disabled is
// how a server becomes unreachable with nothing left on it that knows why.
if (!function_exists('smpro_gw_deadman')) exit;

try {
    $r = smpro_gw_deadman();
    if (($r['action'] ?? '') !== 'none' && function_exists('smpro_audit')) {
        @smpro_audit('geowall_tick', ['action' => (string)$r['action'], 'why' => (string)$r['why']]);
    }
} catch (\Throwable $e) {
    // A worker that throws while a DROP rule is live must not simply die quietly: the rule stays and nothing is
    // watching it. Take the wall down and record why - an open door is recoverable, a locked-out operator is not.
    if (function_exists('smpro_gw_remove')) { @smpro_gw_remove(); }
    if (function_exists('smpro_gw_record')) { @smpro_gw_record('tick_failed', 'the watcher failed (' . $e->getMessage() . ') — the wall was taken down rather than left unwatched'); }
    if (function_exists('smpro_worker_fatal')) smpro_worker_fatal('geowall_tick', $e);
}
