<?php
/**
 * t30_firewall_region.php — proves the Phase-3 STUB + RECORDER pattern, and covers three
 * security-critical intrusion behaviors:
 *   U35  smpro_im_region_status   — the Arab-exclusion auto-block gate (stub ip_intel + ip_is_datacenter)
 *   U40  smpro_im_is_bareip_host  — bare-IP / rDNS host detection (stub server_ips)
 *   S14  smpro_im_block_ip guards — NEVER block the server / private / invalid IP; csf recorder stays EMPTY
 *
 * Mechanism: smpro_test_install_stubs() defines the seam callees FIRST, then we require the .build
 * copy (whose seam functions are wrapped in `if(!function_exists)`), so our stubs win while every
 * other function is the real code. The csf PATH shim records any real firewall call — we assert it
 * was never invoked for a refused block (the "blocker not called" proof).
 */
require __DIR__ . '/../support/bootstrap.php';

smpro_test_install_stubs(['server_ips' => ['203.0.113.50' => 1]]);
require SMPRO_TEST_BUILD . '/includes/helpers.php';     // seams wrapped -> stubs win; ip_is_external etc. real
require SMPRO_TEST_BUILD . '/includes/intrusion.php';   // region_status / block_ip / is_bareip_host / in_cfg (real)

// caution_regions is now operator-configured (ships empty). Set the Arab list explicitly so this test exercises
// the tier-2 caution behaviour through the configurable mechanism (before any smpro_in_cfg() statics it).
@is_dir(dirname(SMPRO_IN_CFG)) || @mkdir(dirname(SMPRO_IN_CFG), 0700, true);
@file_put_contents(SMPRO_IN_CFG, json_encode(['protect_regions' => ['EG','SA'], 'caution_regions' => ['AE','KW','QA','BH','OM','JO','LB','SY','IQ','YE','PS','DZ','MA','TN','LY','SD','MR','SO','DJ','KM']]));

ok(function_exists('smpro_im_region_status'), 'region_status loaded; stubs installed');

/* ---------- U35 — region gate (the auto-block Arab-exclusion heart) ---------- */
$region = function ($ip, $intel) {
    smpro_stub_set('ip_intel', [$ip => $intel]);
    return smpro_im_region_status($ip);
};
is_eq($region('198.51.100.1', ['country' => 'EG', 'datacenter' => false]), 'core_protected', 'U35 EG residential -> core_protected (never auto-blocked)');
is_eq($region('198.51.100.2', ['country' => 'SA', 'datacenter' => false]), 'core_protected', 'U35 SA residential -> core_protected');
is_eq($region('198.51.100.3', ['country' => 'AE', 'datacenter' => false]), 'arab_caution',   'U35 AE residential -> arab_caution (blocked only at 3x)');
is_eq($region('198.51.100.4', ['country' => 'US', 'datacenter' => false]), 'normal',          'U35 US residential -> normal');
is_eq($region('198.51.100.5', ['country' => 'EG', 'datacenter' => true]),  'normal',          'U35 EG DATACENTER -> normal (hosting is fair game in any country)');
is_eq($region('198.51.100.6', ['country' => '',   'datacenter' => false]), 'normal',          'U35 unknown geo -> normal');
is_eq(smpro_im_region_status('not-an-ip'), 'normal', 'U35 invalid IP -> normal');

/* ---------- U40 — bare-IP / rDNS host detection ---------- */
is_eq(smpro_im_is_bareip_host('203.0.113.50'), true,  'U40 literal server IP host -> true');
is_eq(smpro_im_is_bareip_host(strtolower((string) php_uname('n'))), true, 'U40 server hostname -> true');
is_eq(smpro_im_is_bareip_host('203.0.113.50.cprapid.com'), true, 'U40 host CONTAINING a server IP -> true');
is_eq(smpro_im_is_bareip_host('50.113.0.203.clients.example.com'), true, 'U40 reversed-octet rDNS of a server IP -> true');
is_eq(smpro_im_is_bareip_host('shop.example.com'), false, 'U40 normal domain -> false');
is_eq(smpro_im_is_bareip_host(''), false, 'U40 empty host -> false');

/* ---------- S14 — never-block-self (the csf recorder must stay EMPTY) ---------- */
smpro_test_rec_reset('csf');
$srv = smpro_im_block_ip('203.0.113.50');
is_eq($srv['ok'], false, 'S14 block_ip(server IP) -> refused');
has($srv['msg'], 'server IP', 'S14 block_ip(server IP) -> reason names server IP');

$priv = smpro_im_block_ip('10.0.0.0');
is_eq($priv['ok'], false, 'S14 block_ip(private 10.x) -> refused');
has($priv['msg'], 'private', 'S14 block_ip(private) -> reason names private/local');

$lo = smpro_im_block_ip('127.0.0.1');
is_eq($lo['ok'], false, 'S14 block_ip(loopback) -> refused');

$bad = smpro_im_block_ip('not-an-ip');
is_eq($bad['ok'], false, 'S14 block_ip(invalid) -> refused');
has($bad['msg'], 'invalid', 'S14 block_ip(invalid) -> reason names invalid');

ok(smpro_test_rec_empty('csf'), 'S14 csf was NEVER invoked for any refused block (recorder empty — the blocker-not-called proof)');
