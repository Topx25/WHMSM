<?php
require __DIR__ . '/../support/bootstrap.php';
/**
 * t87_audit_no_whois_per_row.php — a page never waits on one whois call per address.
 *
 * Account Audit "opened with difficulty" on a busy server. Its break-in grouping asked the shared IP helper for
 * every offender; for each address not yet cached that helper ran a whois with a 4-second timeout, up to forty
 * per request, and rewrote the whole cache file after each one. The page now warms the cache with ONE bulk call
 * (14-second cap for the whole set), reads local databases only per row, and the cache is written once at exit.
 */
$br = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/breakin.php'));
has($br, "\$r = smpro_ip_intel(\$ip, false);", 'U1: the page wrapper never enables per-address network lookups');
$aa = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/account-audit.php'));
has($aa, "smpro_ip_intel_bulk(array_column(\$aaBrute, 'ip'), true)", 'U2: offenders are warmed with one bulk call before grouping');
has($aa, 'smpro-timing account-audit', 'U3: the page prints where its time went, so a slow server can be diagnosed from the HTML');
$h = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/helpers.php'));
has($h, 'function smpro_ip_cache_dirty(', 'U4: the cache is flushed once at shutdown');
has($h, "\$save = function () { smpro_ip_cache_dirty(); };", 'U4: not rewritten per address');
$posDef = strpos($h, 'function smpro_ip_cache_dirty('); $posUse = strpos($h, 'function smpro_ip_intel(');
ok($posDef !== false && $posUse !== false && $posDef < $posUse, 'U4: defined before its first use');
