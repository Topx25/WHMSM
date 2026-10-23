<?php
/**
 * bin/cron_sync.php — put every enabled feature's scheduled run back in place.
 *
 * WHY THIS EXISTS.
 *
 * Nine features install their own /etc/cron.d entry, and each did it in exactly one place: the moment its
 * settings were saved. Nothing ever called them again. Two consequences, both found on a live server:
 *
 *   - A feature that gains a worker in a later release never gets scheduled for the operator who enabled it
 *     BEFORE that release. They upgrade, the setting still says on, and nothing runs — until they happen to open
 *     the page and press Save for an unrelated reason. Country Login Lock spent a release in exactly that state:
 *     armed, saved, displayed as ARMED, with no schedule and no way to act.
 *   - A cron file lost to an upcp, a cleanup or a half-finished uninstall never comes back. The feature keeps
 *     reporting itself as on.
 *
 * Run from bin/register.sh, which runs after every install and every self-update. Each sync reads its OWN saved
 * setting and installs or REMOVES accordingly, so this is idempotent and never turns anything on: a feature that
 * is off has its cron removed, exactly as if its page had been saved.
 */
define('SMPRO_BOOT', 1);
$base = dirname(__DIR__);
foreach (['defines', 'mmdb', 'helpers', 'secret', 'license',
          'notify', 'botguard', 'geologin', 'bfrules', 'maintenance', 'reboot', 'svcmon', 'spqueue',
          'fwallow', 'disk_home', 'benchdiag', 'geowall', 'loginfeed', 'evidence', 'hub', 'compcheck', 'ccfix', 'loadhist', 'cooler', 'tgbot', 'update', 'intrusion', 'backupmon', 'evship', 'fileaudit', 'learn', 'sysupd', 'slmaint', 'lvelimits', 'trustfeed'] as $m) {
    $f = $base . '/includes/' . $m . '.php';
    if (is_file($f)) require_once $f;
}

$quiet = in_array('--quiet', $argv, true);
$done = []; $failed = []; $absent = [];

foreach ([
    'notifications'      => 'smpro_ntf_cron_sync',
    'bot guard'          => 'smpro_bg_cron_sync',
    'country login lock' => 'smpro_gl_cron_sync',
    'break-in rules'     => 'smpro_bfr_cron_sync',
    'maintenance'        => 'smpro_mnt_cron_sync',
    'swap cycle'         => 'smpro_swapcycle_cron_sync',
    'scheduled reboot'   => 'smpro_reboot_cron_sync',
    'service monitor'    => 'smpro_svcmon_cron_sync',
    'site protection'    => 'smpro_spq_cron_sync',
    // Found by the regression, not by memory: three more installers existed and this list did not know
    // about them. That is the whole reason r30 discovers them from the tree instead of trusting this list.
    'allow-list sync'    => 'smpro_fw_allow_cron_sync',
    'home disk scan'     => 'smpro_ds_home_cron_sync',
    'hardware sampling'  => 'smpro_bd_sample_cron_sync',
    // The country wall's watcher is the one entry here that must NEVER be missed: it is what takes the wall
    // down when the operator can no longer reach the panel.
    'country wall'       => 'smpro_gw_cron_sync',
    // The evidence journal is not a feature that can be off: it is what makes the others answerable
    // afterwards, and a server whose plugin was switched off is exactly the one whose history is wanted.
    'evidence journal'   => 'smpro_ev_cron_sync',
    'evidence shipping'  => 'smpro_ev_ship_cron_sync',
    // Who changed which file, through which door, from which address. Made by the kernel (auditd), collected
    // every minute because the raw log rotates away in minutes on a busy server.
    'file changes'       => 'smpro_fa_cron_sync',
    // The scheduled Compromise Check: a ten-minute heartbeat while the plan is on, removed when it is off.
    'compromise check'   => 'smpro_cx_cron_sync',
    // System updates: always scheduled - "manual" means the operator presses the button, not that nobody looks.
    'system updates'     => 'smpro_su_cron_sync',
    // Lifted LVE limits go back when their time is up; the tick exists only while a lift is in force.
    'lve lifts'          => 'smpro_lv_cron_sync',
    // The signed trusted-bots list from the licence server, every six hours.
    'trusted bots list'  => 'smpro_tf_cron_sync',
    // One load sample a minute so "Load - last 24 hours" is 24 hours, not the moments somebody had the page open.
    'load history'       => 'smpro_lo_cron_sync',
    // These six were installed only from their own Save button or from the page's self-heal and were never put
    // back after an update that wiped /etc/cron.d.
    'load guard'         => 'smpro_cool_cron_sync',
    'telegram bot'       => 'smpro_tg_cron_sync',
    'hub worker'         => 'smpro_hub_cron_sync',
    'update check'       => 'smpro_upd_cron_sync',
    'login guard'        => 'smpro_lg_cron_sync',
    'backup auto-retry'  => 'smpro_bm_cron_sync',
    // Learned Defense: the hidden-process check and the hunt after every new lesson.
    'learned defense'    => 'smpro_lr_cron_sync',
] as $label => $fn) {
    if (!function_exists($fn)) { $absent[] = $label; continue; }
    try {
        // Several of these return void; only an explicit false is a failure.
        $r = $fn();
        if ($r === false) $failed[] = $label; else $done[] = $label;
    } catch (\Throwable $e) {
        $failed[] = $label . ' (' . $e->getMessage() . ')';
    }
}

// Not a cron: the real visitor behind Cloudflare, server-wide (includes/frontlogs.php). Checked here because this runs
// after every install and update; it tests nginx before keeping anything and reverts on a failed test.
if (!function_exists('smpro_cf_realip_sync')) { $fl = $base . '/includes/frontlogs.php'; if (is_file($fl)) require_once $fl; }
if (function_exists('smpro_cf_realip_sync')) { try { if (smpro_cf_realip_sync() === false) $failed[] = 'cloudflare real visitor address'; else $done[] = 'cloudflare real visitor address'; } catch (\Throwable $e) { $failed[] = 'cloudflare real visitor address (' . $e->getMessage() . ')'; } }

if (function_exists('smpro_audit')) {
    @smpro_audit('cron_sync', ['synced' => count($done), 'failed' => $failed, 'not_installed' => $absent]);
}
if (!$quiet) {
    echo 'cron sync: ' . count($done) . " feature(s) checked\n";
    if ($failed) echo '  could not sync: ' . implode(', ', $failed) . "\n";
    if ($absent) echo '  not in this build: ' . implode(', ', $absent) . "\n";
}
// Never fail the installer over a cron: the plugin is still usable, and register.sh reports warnings.
exit(0);
