<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
if (!defined('SMPRO_VARLIB')) define('SMPRO_VARLIB', sys_get_temp_dir() . '/t136_varlib_' . getmypid());
require_once SMPRO_BASE . '/includes/netkind.php';
/** t136 - VPN / hosting network kind: published prefix lists are validated whole, refreshed daily, looked up in the
 *  kernel or in PHP; an address in no list, a private address, or a server with no list yet is "unknown", never
 *  "a VPN"; the Country Login Lock reports such sign-ins by default and blocks only when told to. */
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/netkind.php'));
preg_match_all('#https?://[a-z0-9./@_-]+#i', $src, $urls);
is_eq(count(array_unique(array_map(fn($u) => parse_url($u, PHP_URL_HOST), $urls[0]))), 2, 'N1: the lists come from published sources only (two hosts, a mirror of the same list)');
hasnt($src, 'HETZNER', 'N2: no provider is named in the code - the lists are data that updates');
hasnt($src, 'AMAZON', 'N2: not one');

// the validator
$good = implode("\n", array_map(fn($i) => '203.0.' . intdiv($i, 256) . '.' . ($i % 256) . '/32', range(0, 599))) . "\n";
ok(is_array(smpro_nk_validate($good)) && count(smpro_nk_validate($good)) === 600, 'V1: a list of valid prefixes is accepted');
is_eq(smpro_nk_validate("1.2.3.4/24\n<html>error</html>\n"), null, 'V2: one bad line refuses the whole list (an error page is never a list)');
is_eq(smpro_nk_validate("1.2.3.4/24\n5.6.7.8\n"), null, 'V3: a list too short to be real is refused (a stub or a truncated download)');
is_eq(smpro_nk_validate(str_repeat("300.1.1.1/8\n", 600)), null, 'V4: an impossible octet is refused');
is_eq(smpro_nk_validate(str_repeat("1.1.1.1/33\n", 600)), null, 'V4: an impossible prefix length is refused');

// the pure-PHP lookup
@mkdir(smpro_nk_dir(), 0700, true);
file_put_contents(smpro_nk_file('vpn'), "198.51.100.0/24\n203.0.113.64/26\n");
file_put_contents(smpro_nk_file('hosting'), "192.0.2.0/25\n");
is_eq(smpro_nk_kind('198.51.100.7'), 'vpn', 'L1: an address inside a VPN prefix is a VPN');
is_eq(smpro_nk_kind('203.0.113.100'), 'vpn', 'L1: inside the /26');
is_eq(smpro_nk_kind('203.0.113.1'), '', 'L2: just outside the /26 is unknown');
is_eq(smpro_nk_kind('192.0.2.9'), 'hosting', 'L1: a hosting range');
is_eq(smpro_nk_kind('192.0.2.200'), '', 'L2: outside it is unknown');
is_eq(smpro_nk_kind('10.0.0.5'), '', 'L3: a private address is never a kind');
is_eq(smpro_nk_kind('2001:db8::1'), '', 'L3: IPv6 is unknown (the lists are IPv4)');
ok(smpro_nk_ready(), 'L4: ready once both lists are on disk');
@unlink(smpro_nk_file('hosting'));
ok(!smpro_nk_ready(), 'L4: not ready with one list missing');

// the lock's wiring
$gl = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/geologin.php'));
has($gl, "'netkind'    => 'report',", 'W1: report-only by default');
has($gl, "if (!\$foreign && \$nk === '') continue;", 'W2: an allowed country on an ordinary network is still allowed');
has($gl, "if (!\$foreign && \$nkMode === 'report') {", 'W3: in report mode an allowed-country VPN sign-in is said, not acted on');
has($gl, "\$nk = (\$nkMode !== 'off' && function_exists('smpro_nk_kind')) ? smpro_nk_kind(\$ip) : '';", 'W4: "off" never asks');
$tick = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/bin/geologin_tick.php'));
has($tick, "smpro_nk_update(); smpro_nk_ensure_sets();", 'W5: the worker refreshes the lists daily and puts the sets back after a CSF reload');
@exec('rm -rf ' . escapeshellarg(SMPRO_VARLIB));
