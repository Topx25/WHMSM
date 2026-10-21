<?php
/**
 * bin/php2shell_probe.php — reads the standing of every PHP build against the PHP core release of 2026-10-21 and
 * writes it to the cache the Security Health card reads. Run detached by the card on a cache miss and by the
 * System updates worker after every check, so a page never waits on rpm, dnf or whmapi1.
 */
define('SMPRO_BOOT', 1);
$base = dirname(__DIR__);
foreach (['defines', 'env', 'mmdb', 'helpers', 'secret', 'license', 'shharden'] as $m) {
    $f = $base . '/includes/' . $m . '.php';
    if (is_file($f)) require_once $f;
}
if (!function_exists('smpro_shh_php2shell_probe_write')) exit;
@set_time_limit(300);
try { smpro_shh_php2shell_probe_write(); } catch (\Throwable $e) { if (function_exists('smpro_soft_fail')) smpro_soft_fail('php2shell_probe', $e); }
