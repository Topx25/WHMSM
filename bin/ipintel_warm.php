<?php
/**
 * bin/ipintel_warm.php - fetch ASN / provider for the addresses a page asked about, behind the page.
 * A render hands the list over through SMPRO_CACHE/ipintel_want.json and shows the local GeoIP country at once;
 * this worker does the whois round trip (one bulk query) and the next render reads the full answer from the cache.
 * Single-flight through a lock; nothing here takes input from anywhere but that file.
 */
define('SMPRO_BOOT', 1);
$base = dirname(__DIR__);
foreach (['defines', 'env', 'mmdb', 'helpers'] as $m) { $f = $base . '/includes/' . $m . '.php'; if (is_file($f)) require_once $f; }
if (!function_exists('smpro_ip_intel_bulk')) exit;
$lockDir = defined('SMPRO_LOCKS') ? SMPRO_LOCKS : (SMPRO_VARLIB . '/locks'); @is_dir($lockDir) || @mkdir($lockDir, 0700, true);
$lk = @fopen($lockDir . '/ipintel_warm.lock', 'c'); if (!$lk || !@flock($lk, LOCK_EX | LOCK_NB)) exit;
$want = SMPRO_CACHE . '/ipintel_want.json';
for ($round = 0; $round < 3; $round++) {
    $list = @is_file($want) ? json_decode((string)@file_get_contents($want), true) : [];
    if (!is_array($list) || !$list) break;
    @unlink($want);
    $cache = &smpro_ip_cache();
    foreach ($list as $ip) if (isset($cache[$ip]) && (string)($cache[$ip]['source'] ?? '') === 'GeoIP (whois pending)') unset($cache[$ip]);   // let the bulk call see them as missing
    try { smpro_ip_intel_bulk(array_values(array_filter(array_map('strval', $list), fn($ip) => filter_var($ip, FILTER_VALIDATE_IP)))); } catch (\Throwable $e) { if (function_exists('smpro_soft_fail')) smpro_soft_fail('ipintel_warm', $e); }
}
@flock($lk, LOCK_UN); @fclose($lk);
