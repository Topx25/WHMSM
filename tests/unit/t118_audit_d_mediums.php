<?php
require __DIR__ . '/../support/bootstrap.php';
/** t118 - unattended-behaviour audit, medium findings: slot claimed before the scan, data survives a kill/purge, Telegram never replays, retry counter persisted first, CF header only from Cloudflare, csf.deny rewrites locked, no re-arm under Disabled/Dry-Run, MariaDB tmp untouched. */
$r = fn($f) => str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $f));
has($r('bin/compcheck_tick.php'), "smpro_ctl_disabled()) exit;", 'M2: the scheduled scan honours Disabled');
has($r('includes/ccfix.php'), "if (!\$force) { \$c['last_run'] = time(); smpro_cx_sched_save(\$c); }", 'M2: the slot is claimed before the scan');
$lic = $r('includes/license.php');
has($lic, "\$rm = 'sleep 3; rm -rf ' . escapeshellarg(\$base)", 'M4: a tamper-kill removes code only');
hasnt($lic, "rm -rf ' . escapeshellarg(\$vl)", 'M4: ...never the data directory');
has($r('includes/update.php'), "foreach (['quarantine', 'backups', 'emergency.json', 'detections'] as \$k)", 'M4: the purge sets the customers\' data aside');
$tg = $r('includes/tgbot.php');
has($tg, "smpro_tg_state_save(['offset' => \$offset]); \$cfg['offset'] = \$offset;\n        try { \$reply = smpro_tg_handle(\$text); }", 'M5: the offset is committed before a command runs');
has($tg, "register_shutdown_function(function () { @unlink(SMPRO_TG_LOCK); });", 'M5: the stamp is released on every exit');
$br = $r('bin/backup_retry.php');
has($br, "\$state[\$id] = \$rec; \$bmSave();\n    jb('runBackupJobManually', '_id=' . \$id);", 'M6: the counter is written before the launch');
has($br, "if (time() - \$bmT0 > 420)", 'M6: ...with a deadline inside the cron timeout');
has($r('includes/intrusion.php'), "smpro_ip_is_external(\$real) && smpro_ip_is_cloudflare(\$conn)) \$cur['ip'] = \$real;", 'M8: a client header is believed only from a Cloudflare edge');
$g = $r('includes/geologin.php');
is_eq(substr_count($g, "smpro_csf_deny_lock() : null;"), 2, 'M10: both csf.deny rewriters take the lock');
has($r('includes/helpers.php'), "function smpro_csf_deny_lock() {", 'M10: the lock exists');
has($r('includes/geowall.php'), "if (!smpro_gw_live() && !((function_exists('smpro_ctl_disabled') && smpro_ctl_disabled())", 'M11: the wall is not re-armed under Disabled / Dry-Run');
has($r('bin/home_move.php'), "a watchdog never relaunches rsync + rm -rf under the global switch", 'M11: the home-move watchdog pauses while Disabled');
is_eq(substr_count($r('includes/maintenance.php'), "-not -ipath '*mariadb*'"), 2, 'L1: MariaDB private tmp is excluded in the run and the preview');
