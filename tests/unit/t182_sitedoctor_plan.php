<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
require_once SMPRO_BASE . '/includes/investigate.php';
require_once SMPRO_BASE . '/includes/sdbulk.php';
/**
 * t182 - Site Doctor, all sites: one plan per failing site. The table showed one list of repairs and the fix ran
 * another; unlocking files was offered as a repair; a WordPress without its database was blamed on a plugin; the
 * core restore refused in the very case it was offered for; one bad site ended the whole scan.
 */
$src = fn($p) => str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $p));
$fx = fn(string $a, string $l, string $p = '') => ['action' => $a, 'label' => $l, 'path' => $p];

/* ---------- unlocking is a preparation, not a repair ---------- */
$p = smpro_sdb_plan(['docroot' => '/nonexistent/x', 'fixes' => [$fx('unharden', 'Un-harden 1 locked file(s)')], 'hardened' => ['a' => 1]], ['kind' => 'blank', 'text' => 'The page is blank.', 'code' => 200]);
is_eq($p['fixes'], [], 'P1: unlocking alone is not offered as a repair');
ok(strpos($p['advice'], 'unlocking them alone does not repair') !== false, 'P2: and the row says why there is nothing to run');
$p = smpro_sdb_plan(['docroot' => '/nonexistent/x', 'fixes' => [$fx('disable_plugin', 'Disable x', '/nonexistent/x/wp-content/plugins/x'), $fx('unharden', 'Un-harden 1 locked file(s)')]], ['kind' => 'php_fatal', 'text' => 'A PHP fatal error is printed on the page.', 'code' => 500]);
is_eq(array_column($p['fixes'], 'action'), ['unharden', 'disable_plugin'], 'P3: with a real repair, unlocking goes first');
ok($p['fixes'][0]['prep'] === true && $p['fixes'][1]['prep'] === false, 'P4: ...marked as the preparation it is');
ok($p['fixes'][1]['auto'] === true && $p['fixes'][0]['auto'] === false, 'P5: each repair says whether automatic fixing may run it');

/* ---------- nothing to run = a sentence, never an empty promise ---------- */
$p = smpro_sdb_plan(['docroot' => '/nonexistent/x', 'fixes' => []], ['kind' => 'http_500', 'text' => 'The server answers 500.', 'code' => 500]);
ok($p['fixes'] === [] && $p['advice'] !== '', 'N1: a site with no known repair says so');
$p = smpro_sdb_plan(['docroot' => sys_get_temp_dir() . '/smpro_t182_empty_' . getmypid(), 'fixes' => []], ['kind' => 'http_403', 'text' => 'The home page answers 403.', 'code' => 403]);
ok($p['advice'] !== '', 'N2: so does an empty web root');

/* ---------- 508: the Resource Limits repairs ---------- */
$p = smpro_sdb_plan(['docroot' => '/nonexistent/x', 'user' => 'someacct', 'fixes' => [$fx('disable_plugin', 'Disable x', '/p'), $fx('unharden', 'Un-harden')]], ['kind' => 'limit_508', 'text' => 'The account hit its resource limit (508).', 'code' => 508]);
ok(!in_array('disable_plugin', array_column($p['fixes'], 'action'), true) && !in_array('unharden', array_column($p['fixes'], 'action'), true), 'L1: at a resource limit the site code is not what gets repaired');
if (smpro_sdb_lve()) is_eq(array_column($p['fixes'], 'action'), ['lve_kill_hung', 'lve_lift'], 'L2: the two limit repairs are offered, stuck processes first');
else ok($p['fixes'] === [] && strpos($p['advice'], 'no per-account limit tool') !== false, 'L2: without per-account limits the row says so');
ok(smpro_sdb_auto_allowed('lve_kill_hung') && !smpro_sdb_auto_allowed('lve_lift'), 'L3: ending stuck processes may be automatic, raising limits never is');
$sb = $src('includes/sdbulk.php');
has($sb, "smpro_lv_apply('lift', ['user' => \$user, 'minutes' => '60'], 'site-doctor')", 'L4: the lift runs through the Resource Limits engine (its backup, its automatic put-back)');

/* ---------- the database ---------- */
is_eq(smpro_sdb_db_check('/nonexistent/x'), '', 'D1: no wp-config = nothing to say about a database');
has($sb, "\$cause = 'The database refuses the details in wp-config.php: ' . \$why", 'D2: a refused database is named as the cause');
has($sb, "!in_array((string)(\$f['action'] ?? ''), ['disable_plugin', 'disable_theme', 'unharden'], true)", 'D3: and the plugin that only tripped over it is not offered for switching off');
has($sb, "Call to a member function (get_row|get_var|get_results", 'D4: the tell-tale "on null" call is what triggers the check');

/* ---------- shown = done ---------- */
has($sb, "\$plan = smpro_sdb_plan(\$res, \$before);", 'S1: the fix builds the same plan the table showed');
has($sb, "    \$fixes = \$plan['fixes'];", 'S2: and runs exactly its repairs');
has($sb, "\$row = array_merge(\$row, smpro_sdb_diag_child(\$dom, \$p));", 'S3: the scan stores that plan');

/* ---------- the core restore ---------- */
has($sb, "if (\$ver === '' && is_file(\$doc . '/wp-includes/version.php')) return ['ok' => false,", 'C1: only an unreadable version file is refused');
ok(strpos($sb, "    if (\$ver === '') return ['ok' => false, 'msg' => 'the installed WordPress version could not be read") === false, 'C2: a MISSING version file no longer blocks the restore it is offered for');

/* ---------- one bad site does not end the scan; a long scan goes on by itself ---------- */
has($sb, "'timeout 240 ' . escapeshellarg(\$php) . ' ' . escapeshellarg(\$bin) . ' diag '", 'R1: each failing site is examined in its own process with a time limit');
has($sb, "The scan went on to the next site.", 'R2: a site whose examination did not finish gets a line saying so');
has($sb, "' resume') . ' >/dev/null 2>&1 </dev/null &'", 'R3: a scan cut by its time limit starts its own continuation');
has($sb, "(int)(\$j['round'] ?? 0) < 15", 'R4: a bounded number of times');
$bn = $src('bin/sitedoctor_bulk.php');
$i = strpos($bn, "if (\$kind === 'diag') {"); $j = strpos($bn, "@flock(\$lk, LOCK_EX | LOCK_NB)");
ok($i !== false && $j !== false && $i < $j, 'R5: the per-site process does not wait for the lock its parent holds');

/* ---------- the page ---------- */
$ui = $src('includes/sdbulk_ui.php');
ok(strpos($ui, 'by hand only') === false && strpos($ui, 'none known') === false, 'U1: the two unclear phrases are gone');
has($ui, "(canFix?'<input type=\"checkbox\" class=\"sdbChk\"", 'U2: a tick box only where ticking runs something');
has($ui, "'safe for automatic fixing':'runs when you tick this site'", 'U3: each repair says how it is run');
has($ui, "<b>No repair to run.</b>", 'U4: a row with nothing to run says so, with the reason');
has($ui, "can be repaired by automatic fixing, ", 'U5: the failing sites are counted in three plain groups');
