<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
/**
 * t189 - what an uninstall left behind, and a home move that could not be trusted half-way.
 *  - immutable locks on account files stayed after the product (and the only pages that release them) was gone
 *  - the crawler rule, the panel half of the country wall and the sender block kept enforcing unmanaged
 *  - home move: an interrupted copy could not be continued, the switch was never checked, a roll-back threw away
 *    every domain added since the move, "Reclaim space" brought deleted files back, scheduled jobs kept the old path
 *  - automatic brute-force rules had no idea of the operator's address when run by the scheduler
 *  - an AI decision button named a finding by number alone
 */
$src = fn($p) => str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $p));

/* ---------- uninstall ---------- */
// the real attribute tools, not the suite's stand-ins: this file sets and reads a real lock on a file of its own
putenv('PATH=/usr/bin:/bin:/usr/sbin:/sbin' . PATH_SEPARATOR . (string)getenv('PATH'));
require_once SMPRO_BASE . '/includes/phlock.php';
ok(function_exists('smpro_ph_release_all'), 'U0: one step releases what this product locked');
@mkdir(SMPRO_PH_STATE, 0700, true);
is_eq(smpro_ph_release_all('test'), ['accounts' => 0, 'released' => 0, 'skipped' => [], 'stuck' => []], 'U1: with no lock records nothing is done and nothing is said');

$ghost = 'zzt189gone' . (getmypid() % 1000);
file_put_contents(SMPRO_PH_STATE . '/' . $ghost . '.json', json_encode(['user' => $ghost, 'status' => 'locked', 'protected_files' => [['path' => '/home/' . $ghost . '/public_html/index.php']]]));
file_put_contents(SMPRO_PH_STATE . '/empty' . (getmypid() % 1000) . '.json', json_encode(['status' => 'unlocked', 'protected_files' => []]));
file_put_contents(SMPRO_PH_STATE . '/bad name;.json', json_encode(['protected_files' => [['path' => '/etc/hostname']]]));
$r = smpro_ph_release_all('test');
is_eq($r['skipped'], [$ghost], 'U2: a record of an account that no longer exists is named, a record with nothing locked is not');
is_eq($r['released'], 0, 'U3: ...and nothing is counted as released');

$isRoot = function_exists('posix_geteuid') && posix_geteuid() === 0 && stripos(PHP_OS, 'WIN') !== 0;
$me = $isRoot ? (posix_getpwuid(0)['name'] ?? '') : '';
$home = $me !== '' ? smpro_user_home($me) : '';
$lockable = false;
if ($home !== '' && smpro_ph_has('chattr') && smpro_ph_has('lsattr')) {
    $f1 = $home . '/.smpro_t189_a_' . getmypid(); $f2 = $home . '/.smpro_t189_b_' . getmypid(); $out = sys_get_temp_dir() . '/smpro_t189_out_' . getmypid();
    file_put_contents($f1, 'a'); file_put_contents($f2, 'b'); file_put_contents($out, 'c');
    $l = smpro_ph_chattr_many('+i', [$f1, $out]);
    $lockable = in_array($f1, $l['changed'], true) && in_array($out, $l['changed'], true);
    if ($lockable) {
        file_put_contents(SMPRO_PH_STATE . '/' . $me . '.json', json_encode(['user' => $me, 'status' => 'temporary_unlock', 'unlock_until' => date('c', time() + 600),
            'protected_files' => [['path' => $f1], ['path' => $out]], 'pending_relock' => ['files' => [$f2], 'dirs' => []]]));
        $r = smpro_ph_release_all('test');
        ok($r['released'] === 1 && $r['accounts'] === 1, 'U4: the lock inside the account is released and counted once (' . json_encode([$r['released'], $r['accounts']]) . ')');
        ok(!smpro_ph_locked($f1), 'U5: the file really is no longer immutable');
        ok(smpro_ph_locked($out), 'U6: a path OUTSIDE the home of the record\'s account is not touched, whatever the record says');
        $m = smpro_ph_load($me);
        ok(($m['status'] ?? '') === 'unlocked' && !isset($m['pending_relock']) && !empty($m['released_at_uninstall']), 'U7: the record says what is true now and no relock is left waiting');
        ok(@file_put_contents($f1, 'changed') !== false, 'U8: the owner can change the file again');
    }
    smpro_ph_chattr_many('-i', [$f1, $out]);
    @unlink($f1); @unlink($f2); @unlink($out); @unlink(SMPRO_PH_STATE . '/' . $me . '.json');
}
if (!$lockable) tap_skip('U4-U8: a real lock set and released', 'needs root, chattr and a filesystem that keeps the attribute');

$up = $src('includes/update.php');
$tn = substr($up, (int)strpos($up, 'function smpro_teardown_network('), 9000);
has($tn, '$lr = smpro_ph_release_all($by);', 'T1: an uninstall releases the file locks');
has($tn, "could NOT be released - clear them by hand with chattr -i: ", 'T2: a lock that stayed is named, with the way to clear it');
has($tn, "if (!defined('SMPRO_TEST_SRC') && \$cf !== '' && function_exists('smpro_cr_httpd_run') && @is_file(\$cf) && !is_link(\$cf)) {", 'T3: the crawler rule leaves the web server');
has($tn, "function_exists('smpro_gw_panel_live') && function_exists('smpro_gw_panel_remove') && smpro_gw_panel_live()", 'T4: the web-server half of the wall goes even when the kernel half is already down');
has($tn, "function_exists('smpro_mb_uninstall') && smpro_mb_installed()", 'T5: the sender block leaves the mail server');
has($tn, "'Tuning settings applied from this product stay in force (remove the file to go back to the defaults): '", 'T6: settings that stay are named');
ok(strpos($tn, '$lr = smpro_ph_release_all($by);') < strpos($tn, "@smpro_audit('teardown_network'"), 'T7: all of it is in the record of the teardown');
has($src('bin/teardown.php'), "'geohulk', 'hgbridge', 'ph_ignore', 'phlock', 'update'", 'T8: the shell uninstaller\'s worker loads what the release needs');
$t = smpro_teardown_network_safe();
ok(is_array($t), 'T9: the teardown still runs on a machine with nothing to take down');
function smpro_teardown_network_safe() {
    require_once SMPRO_BASE . '/includes/update.php';
    try { return smpro_teardown_network('test'); } catch (\Throwable $e) { return null; }
}

/* ---------- home move ---------- */
$hm = $src('bin/home_move.php'); $dh = $src('includes/disk_home.php');
has($dh, "&& in_array((string)(\$own['status'] ?? ''), ['copying', 'moving'], true);", 'H1: the account\'s own unfinished copy is not "in the way"');
has($hm, "'account_bytes' => \$total, 'status' => 'copying', 'ts' => (int)(\$prev['ts'] ?? time())]);", 'H2: the copy is recorded when it starts');
has($hm, "in_array((string)(\$prev['status'] ?? ''), ['copying', 'moving'], true);", 'H3: an interrupted copy is continued');
$i = strpos($hm, "if (!\$pwf || rtrim((string)\$pwf['dir'], '/') !== rtrim(\$dst, '/')) {"); $j = strpos($hm, '$nrw = hm_rewrite_userdata($user, $src, $dst);');
ok($i !== false && $j !== false && $i < $j, 'H4: the switch is checked BEFORE any record is rewritten');
has($hm, "\$stf['flipped_at'] = time();", 'H5: the moment of the switch is kept');
$i = strpos($hm, 'hm_rewrite_userdata($user, $dst, $src);'); $j = strpos($hm, "cp -a ' . escapeshellarg(\$udBak)", (int)$i);
ok($i !== false && $j !== false && $i < $j, 'H6: a roll-back rewrites the records back; the move-time copy is only the fallback');
is_eq(substr_count($hm, "-newermt ' . escapeshellarg('@' . \$since) . ' -print0 | rsync -aHAXS --numeric-ids --update --from0 --files-from=- ./ "), 2, 'H7: roll-back and reclaim carry over only what was written since the switch');
has($hm, 'function hm_cron_rewrite($user, $from, $to) {', 'H8: scheduled jobs follow the account');
is_eq(substr_count($hm, 'hm_cron_rewrite($user, ') - substr_count($hm, 'function hm_cron_rewrite($user, '), 3, 'H9: ...at the switch, at a roll-back and at reclaim');
has($hm, "if (@file_put_contents(\$keep . '/' . \$user . '-crontab-' . date('Ymd_His'), \$c) === false) return -1;", 'H10: the previous job list is kept first, or nothing is changed');
// the same pattern the worker uses, on a job list
$from = '/home/acct'; $to = '/home2/acct';
$re = '#' . preg_quote($from, '#') . '(?=/|$|[\s:;"\'])#m';
$cron = "MAILTO=\"\"\n*/5 * * * * /usr/bin/php /home/acct/public_html/cron.php\n0 1 * * * cd /home/acct; ./run.sh\n0 2 * * * tar cf /backup/x.tar \"/home/acct\"\n0 3 * * * /home/acct2/bin/job\n0 4 * * * ls /home/acct";
$new = preg_replace($re, $to, $cron, -1, $n);
is_eq($n, 4, 'H11: every mention of the old home is changed');
has($new, '/home/acct2/bin/job', 'H12: ...and an account whose name only BEGINS the same way is left alone');
hasnt(str_replace('/home/acct2/', '', $new), '/home/acct', 'H13: no line keeps the old path');
has($hm, "' settings file(s) of the account still name the old path and need the new one ('", 'H14: settings files that still name the old path are listed at reclaim');

/* ---------- brute-force rules under the scheduler ---------- */
$bf = $src('includes/bfrules.php');
has($bf, "if (function_exists('smpro_fw_self_state')) foreach (array_keys((array)smpro_fw_self_state()) as \$sip)", 'B1: the addresses the operator was seen working from count as his own in every run');
has($bf, "if (isset(\$mine[\$ip])) { \$out['refused'][] = ['ip' => \$ip, 'why' => \$ip === \$myIp ? 'this is your own address' : 'an address the operator works from']; continue; }", 'B2: none of them is blocked by a rule');
ok(strpos($bf, "\$myIp = '';\n    \$myIp = ") === false, 'B3: the leftover double assignment is gone');

/* ---------- Forensics: AI decision ---------- */
$fa = $src('modules/forensics-audit.php');
has($fa, "data-title=\"'+esc(d.title)+'\" data-act=\"'+esc(d.act||'')+'\"", 'F1: a decision carries the finding it was made for');
has($fa, "if(F0&&(F0.account!==acct||F0.title!==(b.getAttribute('data-title')||'')||(F0.act||'')!==(b.getAttribute('data-act')||''))){", 'F2: a button acts only when the row is still that finding');
