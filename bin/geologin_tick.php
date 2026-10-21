<?php
/**
 * bin/geologin_tick.php — Country Login Lock worker.
 *
 * WHY THIS FILE EXISTS.
 *
 * The lock could be armed, saved and shown as ARMED, and it could never act. smpro_gl_run() was reachable from
 * exactly one place — the "Check the last hour" button — and that button sends dryrun=1, because a check must
 * never write. Nothing installed a cron. So there was no path, anywhere, by which a rule could be written: an
 * operator armed the lock, signed in from a country not on their list, and nothing happened, while the panel
 * said ARMED. csf.deny held zero of its rules and always would have.
 *
 * That is the failure this product exists to prevent, in the product itself: something that reports it is working
 * while doing nothing. A feature that cannot act must not describe itself as armed.
 *
 * Installed as /etc/cron.d/smpro-geologin while the lock is on, and REMOVED when it is turned off.
 */
define('SMPRO_BOOT', 1);
$base = dirname(__DIR__);
foreach (['defines', 'mmdb', 'helpers', 'secret', 'license', 'fwallow', 'notify', 'netkind', 'botguard', 'siteshield', 'geologin', 'intrusion', 'geohulk'] as $m) {
    $f = $base . '/includes/' . $m . '.php';
    if (is_file($f)) require_once $f;
}

if (function_exists('smpro_lic_heartbeat')) { @smpro_lic_heartbeat(); }
if (function_exists('smpro_ctl_disabled') && smpro_ctl_disabled()) exit;
if (!function_exists('smpro_gl_run') || !function_exists('smpro_gl_cfg')) exit;

$cfg = smpro_gl_cfg();
if (empty($cfg['enabled'])) exit;          // the cron should already be gone; never act if it is not

// The kernel set and its rule are put back from the state file every run (after `csf -r` or a reboot the kernel
// has forgotten them); csfpost.sh calls this with --restore right after CSF reloads, and stops there.
// The VPN / hosting lists: fetched daily, and put back into their kernel sets after a CSF reload (which empties every set).
if (function_exists('smpro_nk_update')) { try { smpro_nk_update(); smpro_nk_ensure_sets(); } catch (\Throwable $e) { if (function_exists('smpro_soft_fail')) smpro_soft_fail('netkind', $e); } }
// Site Shields follow the lists: a changed list (or a new operator address) rewrites their includes, one graceful reload.
if (function_exists('smpro_ss_refresh')) { try { smpro_ss_refresh(); } catch (\Throwable $e) { if (function_exists('smpro_soft_fail')) smpro_soft_fail('siteshield', $e); } }
if (function_exists('smpro_gl_use_set') && smpro_gl_use_set()) {
    try {
        // A lock armed before the kernel set existed still has its old csf.deny lines (one per port per address):
        // move them over once, here, so every server gets the relief without anyone pressing Save.
        if (smpro_gs_legacy_count(SMPRO_GL_DENY) > 0) smpro_gl_set_up($cfg);
        else smpro_gs_restore(smpro_gl_ports_for($cfg));
    } catch (\Throwable $e) { if (function_exists('smpro_soft_fail')) smpro_soft_fail('geologin_set_restore', $e); }
}
if (in_array('--restore', (array)($argv ?? []), true)) exit;

try {
    // Three passes, twenty seconds apart, inside the one-minute cron: an address that got in is acted on within
    // ~20 s instead of up to two minutes. Each pass is one tail of the login feed - cheap - and the passes stop
    // early when the minute is nearly over so the next cron run never overlaps (flock -n would skip it).
    $t0 = time();
    for ($pass = 0; $pass < 3; $pass++) {
        if ($pass > 0) { if (time() - $t0 > 45) break; sleep(20); }
        // NOT forced to dry run. The saved setting decides - which is the whole difference between this and the
        // button on the page.
        $r = smpro_gl_run(false);
        if (empty($r['ok']) && function_exists('smpro_audit')) {
            // A run that could not read the log is recorded. "Could not look" and "nothing happened" are different
            // facts and a silent worker makes them identical.
            @smpro_audit('geologin_tick_blind', ['msg' => (string)($r['msg'] ?? '')]);
            break;
        }
        // The door wall follows the same list; keep it in step (cheap when nothing changed).
        if ($pass === 0 && function_exists('smpro_gh_sync')) { try { smpro_gh_sync(); } catch (\Throwable $e) { if (function_exists('smpro_soft_fail')) smpro_soft_fail('geohulk_sync', $e); } }
    }
} catch (\Throwable $e) {
    if (function_exists('smpro_worker_fatal')) smpro_worker_fatal('geologin_tick', $e);
    elseif (function_exists('smpro_soft_fail')) smpro_soft_fail('geologin_tick', $e);
}
