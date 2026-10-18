<?php
require __DIR__ . '/../support/bootstrap.php';
/**
 * r27_keep_original.php — nothing on a customer site is cleaned, stripped or deleted without the original
 * being kept first.
 *
 * A cleaned file cannot be un-cleaned, and the file being changed is usually also the evidence of how the
 * account was entered. On 2026-09-15 three shops carried 12,590-byte index.php files that were malware with the
 * shop's own 453-byte bootstrap appended at the end: deleting them would have taken three shops offline, and
 * stripping them without a copy would have destroyed the only record of what the attacker ran. A fourth site had
 * been truncated to ZERO bytes by someone else's cleanup with no backup anywhere — it served the panel's default
 * page while looking "up", and nothing on the server could reconstruct it.
 */

require_once SMPRO_BASE . '/includes/investigate.php';
ok(function_exists('smpro_inv_keep_original'), 'R1: there is one place that keeps an original');

$inv = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/investigate.php'));

/* ---------- R2: the only path that deletes a customer file keeps it first ---------- */
// Releasing php-harden's exec-deny block rewrites the customer's .htaccess, and deletes it outright when the
// strip leaves it empty. Both branches destroy the file; the copy must be taken before either runs.
$i = strpos($inv, 'smpro_inv_keep_original($safe, $c,');
$j = strpos($inv, '@unlink($safe);');
ok($i !== false, 'R2: the exec-deny release keeps the original');
ok($j !== false && $i !== false && $i < $j, 'R2: and keeps it BEFORE the delete, not after');

/* ---------- R3: a backup that could not be written is recorded, never silently skipped ---------- */
has($inv, "original_keep_failed", 'R3: a failed keep is written to the audit trail');
has($inv, "'sha256' => hash('sha256'", 'R3: what was kept is identified by hash, so it can be matched later');

/* ---------- R4: the store is root-only ---------- */
has($inv, '@mkdir($dir, 0700, true)', 'R4: the store directory is root-only');
has($inv, '@chmod($dest, 0600)', 'R4: and so is each kept file');

/* ---------- R5: it actually works ---------- */
$tmp = sys_get_temp_dir() . '/smpro_r27_' . getmypid() . '.txt';
file_put_contents($tmp, "original content\n");
$kept = smpro_inv_keep_original($tmp, null, 'r27 self-test');
ok($kept !== '' && is_file($kept), 'R5: a copy is written');
is_eq((string)@file_get_contents($kept), "original content\n", 'R5: and it is the original, byte for byte');
is_eq(fileperms($kept) & 0777, (stripos(PHP_OS, 'WIN') === 0 ? fileperms($kept) & 0777 : 0600),
      'R5: root-only (POSIX modes only — Windows cannot express 0600)');
@unlink($tmp); @unlink($kept);

/* ---------- R6: quarantine already backs up before it touches anything — keep it that way ---------- */
$im = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/intrusion.php'));
$a = strpos($im, "@copy(\$file, \$dest . '.bak')");
$b = strpos($im, '@rename($file, $dest)');   // beta291: the rename is guarded by !is_link() on the same line
ok($a !== false && $b !== false && $a < $b, 'R6: quarantine copies the file before it moves it');
has($im, "'error' => 'no-backup'",
    'R6: and refuses to stub a file in place when no verified backup exists');
