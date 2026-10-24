<?php
/**
 * bin/memo_refresh.php <key> - re-run one memoised shell command in the background (see smpro_memo_cmd) and
 * store its output. Started by a page that served a stale value; nothing else calls it. The command comes from
 * the root-only cache dir, never from the argument.
 */
define('SMPRO_BOOT', 1);
$base = dirname(__DIR__);
foreach (['defines', 'helpers'] as $m) { $f = $base . '/includes/' . $m . '.php'; if (is_file($f)) require_once $f; }
$key = preg_replace('/[^a-zA-Z0-9_.-]/', '', (string)($argv[1] ?? ''));
if ($key === '' || !defined('SMPRO_CACHE')) exit(1);
$cf = SMPRO_CACHE . '/memo_' . $key . '.cmd';
$j = @is_file($cf) ? json_decode((string)@file_get_contents($cf), true) : null;
if (!is_array($j) || (string)($j['cmd'] ?? '') === '') exit(1);
$t = max(1, (int)($j['t'] ?? 60));
$v = (string)@shell_exec('timeout ' . $t . ' sh -c ' . escapeshellarg((string)$j['cmd']) . ' 2>/dev/null');
$f = SMPRO_CACHE . '/memo_' . $key . '.json';
if (@file_put_contents($f . '.tmp', json_encode(['v' => $v], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE), LOCK_EX) !== false) { @chmod($f . '.tmp', 0600); @rename($f . '.tmp', $f); }
@unlink($cf);
