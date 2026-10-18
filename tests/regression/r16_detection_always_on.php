<?php
/**
 * r16_detection_always_on.php — the detection worker is scheduled while the plugin is enabled, full stop.
 *
 * 2026-09-08: on a production server, a cPanel account was taken over with a stolen password and its site replaced
 * with SEO spam through File Manager from a foreign address — the exact case smpro_fm_foreign_writes() exists for.
 * Nothing fired. The worker that runs every detector (bin/notify_check.php via /etc/cron.d/smpro-notify) was only
 * installed when the admin toggled "Auto-checks" on the Notifications page or enabled intrusion auto-block; there,
 * neither had ever been touched. Every page read as clean because no check had ever run.
 *
 *   D1 smpro_ntf_cron_wanted() is true whenever the plugin is not disabled (and false when it is)
 *   D2 the Notifications "off" toggle no longer unlinks the cron and says why
 *   D3 the boot self-heal still calls smpro_ntf_cron_sync (so a missing cron comes back within minutes)
 */
require __DIR__ . '/../support/bootstrap.php';
require SMPRO_BASE . '/tests/support/plugin_funcs.php';
smpro_plugin_funcs('includes/helpers.php');
smpro_plugin_funcs_except('includes/notify.php', ['smpro_ntf_cron_install']);

ok(function_exists('smpro_ntf_cron_wanted'), 'D1: smpro_ntf_cron_wanted loaded');
smpro_ctl_save(['mode' => 'enabled', 'reenable_at' => 0]);
ok(smpro_ntf_cron_wanted(), 'D1: wanted while enabled — regardless of intrusion emergency/auto_block');
smpro_ctl_save(['mode' => 'dryrun', 'reenable_at' => 0]);
ok(smpro_ntf_cron_wanted(), 'D1: wanted in Dry-Run too (detection runs, actions are recorded)');
smpro_ctl_save(['mode' => 'disabled', 'reenable_at' => 0]);
ok(!smpro_ntf_cron_wanted(), 'D1: not wanted when the plugin is disabled');
smpro_ctl_save(['mode' => 'enabled', 'reenable_at' => 0]);

$src = (string)file_get_contents(SMPRO_BASE . '/includes/notify.php');
hasnt($src, "if (!empty(\$in['emergency']) || !empty(\$in['auto_block'])) return true;\n    return false;", 'D1: the old toggle-gated rule is gone');
$mod = (string)file_get_contents(SMPRO_BASE . '/modules/notifications.php');
hasnt($mod, '@unlink(SMPRO_NTF_CRON)', 'D2: the page never unlinks the detection cron');
has($mod, 'Detection keeps running every 15 min', 'D2: turning "off" says detection keeps running and how to stop messages');
$idx = (string)file_get_contents(SMPRO_BASE . '/index.php');
has($idx, "smpro_ntf_cron_sync()", 'D3: boot self-heal re-installs the detection cron');
