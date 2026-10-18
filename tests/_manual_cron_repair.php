<?php
/**
 * Manual check for the crontab repair. Runs against a THROWAWAY lab account only.
 * Installs a schedule shaped like the real broken one, repairs it, and verifies that what should survive did.
 */
define('SMPRO_BOOT', 1);
$A = '/opt/smpro-testlab/src';
foreach (['defines', 'env', 'mmdb', 'helpers'] as $f) { $p = "$A/includes/$f.php"; if (is_file($p)) require_once $p; }
require_once "$A/includes/croncheck.php";
require_once "$A/includes/croncheck_fix.php";

$user = $argv[1] ?? '';
if ($user === '' || !is_file('/var/cpanel/users/' . $user)) { fwrite(STDERR, "usage: <lab account>\n"); exit(2); }

$root   = '/home/' . $user . '/public_html';
$script = $root . '/wp-cron.php';

echo "account: $user\n\n";
$original = smpro_ccf_read_raw($user);
$hadCrontab = !empty($original['ok']);
$saved = $hadCrontab ? $original['lines'] : [];

/* A schedule shaped like the real one: the same file twice, written two different ways, plus lines that must
   survive untouched — a comment, an environment line, and an unrelated job. */
$fixture = [
    'MAILTO=""',
    '# nightly database tidy — unrelated, must survive',
    '17 4 * * * /usr/local/bin/php ' . $root . '/tools/tidy.php',
    '',
    '35 11,23 * * * cd ' . $root . '; /usr/bin/php -q wp-cron.php >/dev/null 2>&1',
    '8,38 * * * * cd ' . $root . ' && /usr/local/bin/php ' . $script,
];
$w = smpro_ccf_write($user, $fixture);
if (empty($w['ok'])) { echo "could not install the fixture: " . $w['error'] . "\n"; exit(1); }
echo "fixture installed (" . count($fixture) . " lines)\n";

echo "\n--- detector sees ---\n";
$d = smpro_cc_duplicates($user);
echo "  same script scheduled twice: " . ($d ? 'YES (' . count(reset($d)) . ' entries)' : 'no') . "\n";

echo "\n--- dry run ---\n";
$dry = smpro_ccf_repair($user, $script, 10, 300, true);
echo "  would replace: " . ($dry['replaced'] ?? 0) . " entr(y/ies)\n";
echo "  would keep   : " . ($dry['kept'] ?? 0) . " other line(s)\n";
echo "  new entry    : " . ($dry['new_line'] ?? '-') . "\n";

echo "\n--- repair ---\n";
$r = smpro_ccf_repair($user, $script, 10, 300, false);
echo "  ok=" . (!empty($r['ok']) ? 'yes' : 'NO — ' . ($r['error'] ?? '')) . "  replaced=" . ($r['replaced'] ?? 0) . "\n";
echo "  copy: " . ($r['backup'] ?? '-') . "\n";

echo "\n--- what the account has now ---\n";
$after = smpro_ccf_read_raw($user);
foreach ($after['lines'] as $l) echo "  " . $l . "\n";

echo "\n--- checks ---\n";
$now = $after['lines'];
$wp = 0; foreach ($now as $l) { if (trim($l) !== '' && $l[0] !== '#' && stripos($l, 'wp-cron.php') !== false) $wp++; }
$chk = [
  'exactly one wp-cron entry'        => $wp === 1,
  'it locks'                         => (bool)preg_grep('/flock/', $now),
  'it has a time limit'              => (bool)preg_grep('/timeout /', $now),
  'the unrelated job survived'       => (bool)preg_grep('/tidy\.php/', $now),
  'the comment survived'             => (bool)preg_grep('/nightly database tidy/', $now),
  'MAILTO survived'                  => (bool)preg_grep('/^MAILTO=/', $now),
  'duplicates now report clean'      => !smpro_cc_duplicates($user),
];
$fail = 0;
foreach ($chk as $name => $pass) { printf("  %-32s %s\n", $name, $pass ? 'ok' : 'FAILED'); if (!$pass) $fail++; }

echo "\n--- undo ---\n";
$u = smpro_ccf_undo($user, (string)($r['backup'] ?? ''));
echo "  ok=" . (!empty($u['ok']) ? 'yes' : 'NO — ' . ($u['error'] ?? '')) . "\n";
$back = smpro_ccf_read_raw($user);
$fx = array_values(array_filter($fixture, fn($l) => trim($l) !== ''));
$bk = array_values(array_filter($back['lines'], fn($l) => trim($l) !== ''));
$restored = empty(array_diff($fx, $bk));   // every non-blank fixture line is back
printf("  %-32s %s\n", 'fixture came back', $restored ? 'ok' : 'FAILED');
if (!$restored) $fail++;

echo "\n--- refusing a copy from outside the account ---\n";
$bad = smpro_ccf_undo($user, '/etc/passwd');
printf("  %-32s %s\n", 'refused', empty($bad['ok']) ? 'ok — ' . $bad['error'] : 'ALLOWED (BAD)');
if (!empty($bad['ok'])) $fail++;

/* leave the account as it was found */
if ($hadCrontab) smpro_ccf_write($user, $saved);
else smpro_run('crontab -r -u ' . escapeshellarg($user), 10, ['stderr' => 'discard']);
echo "\naccount restored to how it was found.\n";
echo $fail ? "\n$fail CHECK(S) FAILED\n" : "\nall checks passed\n";
exit($fail ? 1 : 0);
