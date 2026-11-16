<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
/**
 * t184 - round 434, operations that delete or change data: a customer's file is taken out of its account
 * without root following a path, the mail queue is emptied for exactly one sender, a database is not cleaned
 * behind a backup that is not whole, and the log trim keeps the product's own history.
 */
$src = fn($p) => str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $p));

/* ---------- taking a file out of an account ---------- */
ok(function_exists('smpro_acct_take'), 'T0: there is one place that moves a customer file into a root-only store');
is_eq(smpro_acct_take('no-such-account-zz', '/nonexistent/a', '/nonexistent/b'), false, 'T1: an unknown account is refused');
$hp = $src('includes/helpers.php');
has($hp, "(\$st['mode'] & 0170000) !== 0100000 || (int)\$st['uid'] !== \$uid", 'T2: only a plain file that belongs to the account is taken');
has($hp, "\$s2['ino'] === \$st['ino'] && \$s2['dev'] === \$st['dev']) { @chmod(\$to, 0600); clearstatcache(true, \$to); return true; }", 'T3: what arrived is checked to be the file that was looked at');
has($hp, "@rename(\$to, \$from);   // not the file that was checked: back where it came from, at once", 'T4: anything else is put straight back');
has($hp, "if (!smpro_acct_rm(\$user, \$from) || @file_exists(\$from)) { @unlink(\$to); return false; }", 'T5: across filesystems the delete is done as the account');
if (stripos(PHP_OS, 'WIN') !== 0 && function_exists('posix_geteuid') && posix_geteuid() === 0 && is_array(@posix_getpwnam('nobody'))) {
    $d = sys_get_temp_dir() . '/smpro_t184_' . getmypid(); @mkdir($d, 0755, true);
    $f = $d . '/mine.txt'; file_put_contents($f, "x\n"); @chown($f, 'nobody');
    $g = $d . '/roots.txt'; file_put_contents($g, "y\n");
    ok(!smpro_acct_take('nobody', $g, $d . '/out1') && is_file($g), 'T6: a file of another owner is left where it is');
    ok(smpro_acct_take('nobody', $f, $d . '/out2') && !file_exists($f) && is_file($d . '/out2'), 'T7: the account\'s own file is moved');
    clearstatcache();
    is_eq(fileperms($d . '/out2') & 0777, 0600, 'T8: and the copy in the store is root-only');
    @symlink($g, $d . '/link.txt');
    ok(!smpro_acct_take('nobody', $d . '/link.txt', $d . '/out3') && is_file($g), 'T9: a link is never followed');
    foreach (['out1', 'out2', 'out3', 'roots.txt', 'link.txt', 'mine.txt'] as $x) @unlink($d . '/' . $x); @rmdir($d);
} else {
    tap_skip('T6-T9: real moves', 'needs root on Linux with the user nobody');
}
foreach (['modules/disk-storage.php' => 'disk delete', 'modules/spam-phishing.php' => 'phishing quarantine', 'modules/forensics-audit.php' => 'forensics delete'] as $file => $what) {
    $s = $src($file);
    ok(strpos($s, 'smpro_acct_take(') !== false, 'U: ' . $what . ' goes through it');
}
ok(strpos($src('modules/disk-storage.php'), "@rename(\$f, \$bak) || (@copy(\$f, \$bak) && @unlink(\$f))") === false, 'U4: the by-path move is gone from disk delete');
ok(strpos($src('modules/forensics-audit.php'), "\$deleted = @unlink(\$file);") === false, 'U5: and the by-path unlink from forensics delete');

/* ---------- the mail queue ---------- */
$sp = $src('modules/spam-phishing.php');
ok(strpos($sp, 'grep -F $esc') === false, 'Q1: the queue is no longer searched for the address as a piece of text');
has($sp, "strtolower(\$qm[2]) === \$sender) \$ids[] = \$qm[1];", 'Q2: a message is removed only when its sender IS the address');
$line = fn(string $id, string $from) => ' 25m  2.9K ' . $id . ' <' . $from . '>';
$pick = function (array $lines, string $sender): array { $ids = [];
    foreach ($lines as $ql) if (preg_match('/^\s*\S+\s+\S+\s+([0-9A-Za-z]{6}-[0-9A-Za-z]{6,11}-[0-9A-Za-z]{2,4})\s+<([^>]*)>/', $ql, $qm) && strtolower($qm[2]) === $sender) $ids[] = $qm[1];
    return $ids; };
$q = [$line('1abcDE-000123-AB', 'admin@site.test'), $line('1abcDF-000124-CD', 'webadmin@site.test'), $line('1abcDG-000125-EF', 'admin@site.test.au'), $line('1abcDH-000126-GH', 'Admin@Site.test'), '          someone@else.test'];
is_eq($pick($q, 'admin@site.test'), ['1abcDE-000123-AB', '1abcDH-000126-GH'], 'Q3: only that sender, not addresses that merely contain it');

/* ---------- database clean-up ---------- */
$db = $src('modules/database-cleanup.php');
has($db, "set -o pipefail; timeout 600 ", 'D1: every part of the dump pipe must end well');
has($db, "if (!preg_match('/__SMRC__=0\\s*\$/', \$dout)) {", 'D2: a dump that did not finish is not a backup');
has($db, "(int)\$wrote !== strlen((string)\$orig) || (int)@filesize(\$bak) !== strlen((string)\$orig)", 'D3: the copy of a row must be whole before the row is changed');
$i = strpos($db, "nothing was changed.', 'backup' => '']; }"); $j = strpos($db, "\$hex = bin2hex(\$clean);");
ok($i !== false && $j !== false && $i < $j, 'D4: ...and that check comes before the UPDATE');

/* ---------- log trim ---------- */
foreach (['modules/disk-storage.php', 'includes/maintenance.php'] as $file) has($src($file), "find /var/log -type f -not -path '/var/log/smpro/*' ", 'G: ' . basename($file) . ' keeps this product\'s own log history');
