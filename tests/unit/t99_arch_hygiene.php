<?php
require __DIR__ . '/../support/bootstrap.php';
/** t99 - architecture audit, first batch: no double-declared function, no per-request cron install, no API on the render path, no overlapping cron. */
$ix = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/index.php'));
is_eq(substr_count($ix, 'smpro_page_fatal_guard();'), 1, 'U1: the fatal guard is installed once');
ok(preg_match('/if \(!\$__liteReq && \$__selfhealDue\) \{.*?smpro_login_guard_install_cron\(\).*?\n\}/s', $ix) === 1, 'U1: the login-guard cron install sits inside the 3-minute self-heal block, not on every request');
$fa = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/forensics-audit.php'));
hasnt($fa, 'function smpro_fa_account_of(', 'U2: the module no longer declares smpro_fa_account_of (includes/fileaudit.php owns that name)');
has($fa, 'function smpro_fx_file_owner(', 'U2: ...it is smpro_fx_file_owner now'); hasnt($fa, 'smpro_fa_account_of(', 'U2: ...and no caller in the module is left behind');
$lm = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/login-monitor.php'));
hasnt($lm, "cphulk_status", 'U3: Login Monitor does not call whmapi1 cphulk_status on render');
foreach (['includes/ccfix.php' => 'compcheck', 'includes/cooler.php' => 'cooler', 'includes/hub.php' => 'hub', 'includes/tgbot.php' => 'tgbot-cron'] as $f => $lock) {
    $s = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $f));
    has($s, '/' . $lock . '.lock timeout ', 'U4: ' . $f . ' cron line runs under flock -n with a timeout');
}
$sq = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/spqueue.php'));
hasnt($sq, "|| true)", 'U5: no always-true condition in spqueue');

/* ---------- U6: one atomic JSON writer; the six orphan crons are cron_sync-able ---------- */
require_once SMPRO_BASE . '/includes/helpers.php';
$f = $GLOBALS['__sandbox'] . '/js/a.json';
ok(smpro_json_save($f, ['a' => 1]), 'U6: save'); is_eq(smpro_json_load($f), ['a' => 1], 'U6: load'); ok(!glob($f . '.tmp.*'), 'U6: no temp file left behind');
is_eq(smpro_json_load($GLOBALS['__sandbox'] . '/js/none.json', ['d' => 1]), ['d' => 1], 'U6: default when missing');
$h = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/helpers.php'));
has($h, "function smpro_ctl_save(\$c) { smpro_json_save(", 'U6: control state is written atomically'); has($h, "function smpro_fw_self_state_save(\$s) { smpro_json_save(", 'U6: so is the self-allow state');
$cs = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/bin/cron_sync.php'));
foreach (['smpro_cool_cron_sync', 'smpro_tg_cron_sync', 'smpro_hub_cron_sync', 'smpro_upd_cron_sync', 'smpro_lg_cron_sync', 'smpro_bm_cron_sync'] as $fn) has($cs, $fn, 'U6: cron_sync covers ' . $fn);
$bm = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/backup-monitor.php'));
hasnt($bm, "@file_put_contents(SMPRO_BM_CRON", 'U6: the backup page no longer writes /etc/cron.d itself');
require_once SMPRO_BASE . '/includes/backupmon.php';
ok(function_exists('smpro_bm_cron_sync') && smpro_bm_cron_sync() === true, 'U6: the backup cron sync is a no-op under test');
