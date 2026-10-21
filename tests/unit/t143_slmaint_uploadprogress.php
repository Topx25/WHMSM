<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
if (!defined('SMPRO_VARLIB')) define('SMPRO_VARLIB', sys_get_temp_dir() . '/t143_varlib_' . getmypid());
require_once SMPRO_BASE . '/includes/slmaint.php';
/** t143 - Safety Lock meets the panel's own maintenance: locks are lifted for cPanel's PHP hooks and upcp and put
 *  back on exactly the recorded list, a release never stays open past the limit, another product's lock is named
 *  and not touched; and session.upload_progress is a Security Health check with Apply and Undo. */
$sl = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/slmaint.php'));
$sq = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/spqueue.php'));
$su = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/sysupd.php'));
$sh = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/shharden.php'));
$cs = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/bin/cron_sync.php'));
$bn = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/bin/sl_maint.php'));
hasnt($sl, '/home/', 'N1: no path from any server');
hasnt($sl, 'efadh', 'N1: no customer name');

// the hook pair, sorted before and after cPanel's own, in every folder that carries cPanel's hook
has($sl, "'005-smpro-safetylock-release' => 'release', '995-smpro-safetylock-relock' => 'relock'", 'H1: release sorts before 009-phpconf.pl, relock after');
has($sl, "glob(\$base . '/multi_pkgs/transaction/*/009-phpconf.pl')", 'H2: the folders are found by cPanel\'s own hook, never assumed');
has($sl, "['/scripts/preupcp' => 'release', '/scripts/postupcp' => 'relock']", 'H3: the same pair around upcp');
has($sl, "if (\$has) \$cur = preg_replace('/^.*' . preg_quote(SMPRO_SLM_MARK, '/') . '.*\\n?/m', '', \$cur);", 'H4: one marked line in postupcp, other products\' lines untouched');
has($sl, "if (defined('SMPRO_TEST_SRC')) return ['ok' => true, 'msg' => 'test: hooks are never installed'];", 'H5: a test never installs hooks');
has($bn, 'exit(0);', 'H6: the hook script always exits 0 - a failing hook must never stop cPanel\'s update');
has($sq, "if (function_exists('smpro_slm_hooks_sync')) { try { smpro_slm_hooks_sync(); }", 'H7: Site Protection\'s cron sync installs the hooks');
has($cs, "'sysupd', 'slmaint']", 'H8: cron_sync loads the module');

// release / relock on a fixture: exactly what was lifted is put back, permanent unlocks are left alone
$vl = SMPRO_VARLIB; @mkdir($vl . '/php_harden', 0700, true);
$rec = ['at' => time(), 'why' => 'test', 'files' => ['/tmp/t143/a', '/tmp/t143/b']];
smpro_slm_rec_save($rec);
is_eq(smpro_slm_rec()['files'], ['/tmp/t143/a', '/tmp/t143/b'], 'R1: the record is written and read');
$st = smpro_slm_status(); is_eq($st['released'], 2, 'R2: status says how many are released');
has($sl, "\$list = array_values(array_unique(array_merge((array)(\$rec['files'] ?? []), \$files)));", 'R3: a second release during the same maintenance extends the record, never loses it');
has($sl, "if (function_exists('smpro_ph_perm_has') && smpro_ph_perm_has(\$p)) continue; if (is_file(\$p) && !is_link(\$p)) \$again[] = \$p;", 'R4: relock skips permanently-unlocked files and links');
has($sl, "if (time() - (int)(\$rec['at'] ?? 0) < SMPRO_SLM_MAXAGE) return 0;", 'R5: the dead-man closes a release only past the limit');
has($sq, "if (function_exists('smpro_slm_deadman')) { try { smpro_slm_deadman(); }", 'R6: the minute worker runs the dead-man');
is_eq(SMPRO_SLM_MAXAGE, 7200, 'R7: two hours');
@unlink(SMPRO_SLM_REC);
is_eq(smpro_slm_relock('test'), ['ok' => true, 'relocked' => 0, 'msg' => 'nothing was released'], 'R8: relock with no record is a no-op that says so');

// System updates lifts the locks around its own run, and names an immutable file it cannot lift
has($su, "\$rel = function_exists('smpro_slm_release') ? smpro_slm_release('the system update') : null;", 'U1: the update lifts Safety Lock before dnf');
has($su, "if (\$rel && function_exists('smpro_slm_relock')) { \$rl = smpro_slm_relock('the system update');", 'U2: and puts it back after');
$d = smpro_su_diagnose_t143("The system failed to lock the immutable (+i) file \"/home/x/public_html/.htaccess\" because Operation not permitted");
ok($d !== null && $d['kind'] === 'immutable' && empty($d['auto']), 'U3: an immutable file is diagnosed and sent to the product that locked it, not forced');
function smpro_su_diagnose_t143(string $o) { require_once SMPRO_BASE . '/includes/sysupd.php'; return smpro_su_diagnose($o); }

// session.upload_progress
has($sh, "'php_uploadprogress' => ['PHP session.upload_progress Off', 'smpro_shh_fix_php_uploadprogress'],", 'P1: the fix is registered with Undo');
has($sh, "smpro_sh_mk('PHP session.upload_progress'", 'P2: the check is a Security Health card');
has($sh, "echo ini_get(\"session.upload_progress.enabled\");", 'P3: the state is read from each build\'s own binary (the ini line is usually commented)');
has($sh, "\$undo[] = ['file', \$f, \$bak];", 'P4: each php.ini is kept first and Undo restores it');
has($sh, "session.upload_progress.enabled = Off", 'P5: the directive written is the one PHP documents');
@exec('rm -rf ' . escapeshellarg(SMPRO_VARLIB));
