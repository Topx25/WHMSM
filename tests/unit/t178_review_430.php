<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
require_once SMPRO_BASE . '/includes/intrusion.php';
require_once SMPRO_BASE . '/includes/fileaudit.php';
/**
 * t178 - round 430: a guard's note "already blocked" is checked against the firewall, and one account cannot fill
 * the disk with its own file-change records.
 */
$src = fn($p) => str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $p));

/* ---------- is an earlier block still in force ---------- */
// an address the firewall of the machine running this does NOT hold (a test server's deny list has real entries)
$free = ''; $book = smpro_im_blocked_load();
for ($k = 1; $k < 250 && $free === ''; $k++) { $c = '198.51.100.' . $k; if (!smpro_csf_denied($c) && !isset($book[$c])) $free = $c; }
ok($free !== '', 'F0: an address that is not blocked here was found');
ok(smpro_im_block_in_force($free, time() - 600), 'F1: a note younger than a day is trusted as it is');
ok(!smpro_im_block_in_force($free, time() - 3 * 86400), 'F2: an old note for an address the firewall no longer holds is not');
ok(!smpro_im_block_in_force($free, 0), 'F3: a note with no time is checked, not trusted');

$im = $src('includes/intrusion.php');
has($im, "(empty(\$done[\$ip]['failed']) ? smpro_im_block_in_force((string)\$ip, (int)(\$done[\$ip]['ts'] ?? 0)) : time() - (int)(\$done[\$ip]['ts'] ?? 0) < 3600)", 'F4: Login Guard skips an address only while its block is in force');
$bg = $src('includes/botguard.php');
$i = strpos($bg, "!smpro_im_block_in_force((string)\$ip, (int)(\$b['decided_at'] ?? 0))"); $j = strpos($bg, "if (\$b['status'] === 'blocked') { \$bots[\$ip] = \$b; continue; }");
ok($i !== false && $j !== false && $i < $j, 'F5: Bot Guard drops its note before the "already blocked" skip');
has($src('includes/tgbot.php'), "if (!empty(\$r['ok']) && function_exists('smpro_im_blocked_forget')) smpro_im_blocked_forget(\$arg);", 'F6: an unblock from Telegram clears the block book too');

/* ---------- the day file has a ceiling ---------- */
$fa = $src('includes/fileaudit.php');
has($fa, "if ((int)@filesize(\$f) > 67108864) {", 'C1: a day file stops at its ceiling');
has($fa, "smpro_audit('fileaudit_day_full'", 'C2: that it stopped is written down');
has($fa, "@unlink(\$f . '.full');", 'C3: the marker goes with the day file when it is pruned');
if (defined('SMPRO_FA_DIR') && @is_dir(dirname(SMPRO_FA_DIR)) && stripos(PHP_OS, 'WIN') !== 0 && function_exists('smpro_fa_store')) {
    $acct = 't178acct' . getmypid(); $ts = time();
    $f = smpro_fa_dir() . '/' . $acct . '/' . gmdate('Y-m-d', $ts) . '.jsonl';
    ok(smpro_fa_store(['account' => $acct, 'ts' => $ts, 'path' => '/x', 'op' => 'created']), 'C4: a record is stored below the ceiling');
    $fh = fopen($f, 'r+'); ftruncate($fh, 67108865); fclose($fh);
    ok(!smpro_fa_store(['account' => $acct, 'ts' => $ts, 'path' => '/y', 'op' => 'created']), 'C5: and refused above it');
    ok(is_file($f . '.full'), 'C6: with the marker left beside the file');
    @unlink($f); @unlink($f . '.full'); @rmdir(dirname($f));
} else {
    tap_skip('C4-C6: the ceiling on a real file', 'needs the evidence folder on Linux');
}
