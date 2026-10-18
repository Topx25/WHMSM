<?php
require __DIR__ . '/../support/bootstrap.php';
require SMPRO_BASE . '/includes/helpers.php';
require SMPRO_BASE . '/includes/intrusion.php';   // smpro_cc_is_arab now delegates to smpro_im_trusted_regions() (config-driven)
// The "22 Arab CCs" are no longer hardcoded — they come from the region config. Seed home ∪ caution = the 22-set
// so these value/drift assertions still hold, now validating the config→function mapping (before in_cfg statics).
@is_dir(dirname(SMPRO_IN_CFG)) || @mkdir(dirname(SMPRO_IN_CFG), 0700, true);
@file_put_contents(SMPRO_IN_CFG, json_encode(['protect_regions' => ['EG','SA'], 'caution_regions' => ['AE','KW','QA','BH','OM','JO','LB','SY','IQ','YE','PS','DZ','MA','TN','LY','SD','MR','SO','DJ','KM']]));

/* =====================================================================
 * t10_helpers_geoip.php — GeoIP / IP-classification pure helpers
 * Targets (includes/helpers.php):
 *   smpro_cc_is_arab / smpro_is_arab_cc  (U45 — values + drift guard)
 *   smpro_ip_is_external                 (U47)
 *   smpro_ip_is_datacenter               (U48 — takes an intel ARRAY)
 *   smpro_ip_parse_cymru                 (U49)
 * SKIP: smpro_geo_foreign (U46) — calls smpro_ip_intel (network/shell + cache),
 *       needs a stub → Phase 3.
 * All expected values derived directly from the source.
 * ===================================================================== */

/* ---------------------------------------------------------------------
 * U45 — smpro_cc_is_arab  (source line ~472)
 * arab list: EG SA AE KW QA BH OM JO LB SY IQ YE PS DZ MA TN LY SD MR SO DJ KM
 * Behaviour: in_array(strtoupper((string)$cc), $arab, true)
 * ------------------------------------------------------------------- */
ok(smpro_cc_is_arab('EG'),  'cc_is_arab: EG (home core) -> true');
ok(smpro_cc_is_arab('sa'),  'cc_is_arab: lowercase sa -> true (upcased)');
ok(smpro_cc_is_arab('SA'),  'cc_is_arab: SA -> true');
nok(smpro_cc_is_arab('US'), 'cc_is_arab: US -> false');
nok(smpro_cc_is_arab(''),   'cc_is_arab: empty string -> false');
nok(smpro_cc_is_arab('XX'), 'cc_is_arab: unknown XX -> false');
// strtoupper((string)null) === '' so null is a guarded, non-arab input (no warning)
nok(smpro_cc_is_arab(null), 'cc_is_arab: null -> false (cast to "")');

/* U45 — smpro_is_arab_cc  (source line ~597) — same 22-set, different order */
ok(smpro_is_arab_cc('EG'),  'is_arab_cc: EG -> true');
ok(smpro_is_arab_cc('sa'),  'is_arab_cc: lowercase sa -> true');
nok(smpro_is_arab_cc('US'), 'is_arab_cc: US -> false');
nok(smpro_is_arab_cc(''),   'is_arab_cc: empty -> false');

/* U45 — DRIFT GUARD: both functions MUST agree on every code across the
 * full Arab-League list + a few non-Arab controls. If anyone edits one
 * list and not the other, this fails. */
$arab_full = ['EG','SA','AE','KW','QA','BH','OM','JO','LB','SY','IQ','YE',
              'PS','DZ','MA','TN','LY','SD','MR','SO','DJ','KM'];
$controls  = ['US','GB','FR','DE','IL','IR','TR','XX',''];

$drift_ok = true;
foreach ($arab_full as $cc) {
    if (!smpro_cc_is_arab($cc)) { $drift_ok = false; }
    if (!smpro_is_arab_cc($cc)) { $drift_ok = false; }
}
ok($drift_ok, 'drift guard: both fns return true for all 22 Arab CCs');

$pair_match = true;
foreach (array_merge($arab_full, $controls) as $cc) {
    if (smpro_cc_is_arab($cc) !== smpro_is_arab_cc($cc)) { $pair_match = false; }
}
ok($pair_match, 'drift guard: cc_is_arab === is_arab_cc for every tested CC (no list drift)');

// list length sanity — exactly 22 distinct Arab-League codes
$count_arab = 0;
foreach ($arab_full as $cc) { if (smpro_cc_is_arab($cc)) { $count_arab++; } }
is_eq($count_arab, 22, 'drift guard: exactly 22 Arab CCs recognised');

/* ---------------------------------------------------------------------
 * U47 — smpro_ip_is_external  (source line ~247)
 * (bool) filter_var($ip, FILTER_VALIDATE_IP, NO_PRIV_RANGE | NO_RES_RANGE)
 * ------------------------------------------------------------------- */
ok(smpro_ip_is_external('8.8.8.8'),        'ip_is_external: 8.8.8.8 (public) -> true');
ok(smpro_ip_is_external('1.1.1.1'),        'ip_is_external: 1.1.1.1 (public) -> true');
nok(smpro_ip_is_external('10.0.0.1'),      'ip_is_external: 10.0.0.1 (private) -> false');
nok(smpro_ip_is_external('192.168.1.1'),   'ip_is_external: 192.168.1.1 (private) -> false');
nok(smpro_ip_is_external('172.16.0.1'),    'ip_is_external: 172.16.0.1 (private) -> false');
nok(smpro_ip_is_external('127.0.0.1'),     'ip_is_external: 127.0.0.1 (loopback/reserved) -> false');
nok(smpro_ip_is_external('::1'),           'ip_is_external: ::1 (IPv6 loopback) -> false');
nok(smpro_ip_is_external('169.254.0.1'),   'ip_is_external: 169.254.x (link-local) -> false');
nok(smpro_ip_is_external('notanip'),       'ip_is_external: garbage string -> false');
nok(smpro_ip_is_external(''),              'ip_is_external: empty string -> false');
// return type is strictly bool (cast), not the validated string
is_eq(smpro_ip_is_external('8.8.8.8'), true,  'ip_is_external: returns strict bool true');
is_eq(smpro_ip_is_external('notanip'), false, 'ip_is_external: returns strict bool false');

/* ---------------------------------------------------------------------
 * U48 — smpro_ip_is_datacenter  (source line ~260)
 * Takes an INTEL ARRAY: $hay = strtoupper(provider . ' ' . asn).
 * Keyword list (substr match on $hay): GOOGLE AMAZON AWS AZURE MICROSOFT
 *   DIGITALOCEAN OVH HETZNER LINODE VULTR ALIBABA TENCENT CONTABO LEASEWEB
 *   SCALEWAY ORACLE M247 CHOOPA RACKSPACE GODADDY IONOS SELECTEL CLOUD
 *   HOSTING SERVER DATACENTER 'DATA CENTER' COLO VPS 'DIGITAL OCEAN'
 *   CLOUDFLARE FASTLY LIMESTONE PSYCHZ QUADRANET HOSTWINDS NAMECHEAP
 * Empty intel ($hay === ' ') -> false (the security-relevant guard).
 * NOTE: source signature is an array, NOT a bare string.
 * ------------------------------------------------------------------- */
ok(smpro_ip_is_datacenter(['provider' => 'DigitalOcean, LLC']), 'ip_is_datacenter: provider DigitalOcean -> true');
ok(smpro_ip_is_datacenter(['provider' => 'AMAZON-02']),         'ip_is_datacenter: provider AMAZON-02 -> true');
ok(smpro_ip_is_datacenter(['provider' => 'Google LLC']),        'ip_is_datacenter: provider Google -> true');
ok(smpro_ip_is_datacenter(['provider' => 'Hetzner Online GmbH']), 'ip_is_datacenter: Hetzner -> true');
ok(smpro_ip_is_datacenter(['provider' => 'OVH SAS']),           'ip_is_datacenter: OVH -> true');
ok(smpro_ip_is_datacenter(['provider' => 'Some Cloud Hosting']),'ip_is_datacenter: generic "Cloud Hosting" -> true');
ok(smpro_ip_is_datacenter(['provider' => 'cheap VPS hosting']), 'ip_is_datacenter: standalone "VPS" keyword -> true');
// word-boundary fix (#1): "VPS"/"COLO"/"SERVER" embedded inside a longer word no longer false-matches
nok(smpro_ip_is_datacenter(['provider' => 'OBSERVER MEDIA']), 'ip_is_datacenter: "OBSERVER" -> false (SERVER not a bare substring)');
// ASN-only match: AS15169 is Google but the keyword list matches the org text,
// NOT the numeric ASN. 'AS15169' upcased contains no keyword -> false.
nok(smpro_ip_is_datacenter(['asn' => 'AS15169']),               'ip_is_datacenter: asn AS15169 alone (no org text) -> false');
// but provider keyword still wins when asn carries the org name as text
ok(smpro_ip_is_datacenter(['asn' => 'AS16509 AMAZON']),         'ip_is_datacenter: asn text containing AMAZON -> true');
nok(smpro_ip_is_datacenter(['provider' => 'Vodafone Egypt']),   'ip_is_datacenter: Vodafone (residential ISP) -> false');
nok(smpro_ip_is_datacenter(['provider' => 'Telecom Egypt']),    'ip_is_datacenter: Telecom Egypt -> false');
nok(smpro_ip_is_datacenter(['provider' => '']),                 'ip_is_datacenter: empty provider -> false');
nok(smpro_ip_is_datacenter([]),                                 'ip_is_datacenter: empty intel array ($hay=" ") -> false');
// case-insensitivity (source upcases the haystack)
ok(smpro_ip_is_datacenter(['provider' => 'digitalocean']),      'ip_is_datacenter: lowercase digitalocean -> true (upcased)');

/* ---------------------------------------------------------------------
 * U49 — smpro_ip_parse_cymru  (source line ~250)
 * Team Cymru verbose line: AS | IP | Prefix | CC | Registry | Allocated | AS Name
 * Skips: '' / lines containing 'AS Name' / 'Bulk mode' / no '|'.
 * On a line with >=7 pipe-fields returns:
 *   ['asn'=>'AS'.$p[0], 'country'=>$p[3], 'provider'=>$p[6], 'source'=>'Team Cymru whois']
 * Header / empty / no-match -> [].
 * ------------------------------------------------------------------- */
$cymru = [
    'Bulk mode; whois.cymru.com [2025-01-01 00:00:00 +0000]',
    'AS      | IP               | BGP Prefix          | CC | Registry | Allocated  | AS Name',
    '15169   | 8.8.8.8          | 8.8.8.0/24          | US | arin     | 2000-03-30 | GOOGLE, US',
];
$got = smpro_ip_parse_cymru($cymru);
is_eq($got, [
    'asn'      => 'AS15169',
    'country'  => 'US',
    'provider' => 'GOOGLE, US',
    'source'   => 'Team Cymru whois',
], 'ip_parse_cymru: parses verbose data line -> [asn,country,provider,source]');

// header-only / noise input -> [] (the 'AS Name' header line is skipped)
$hdr_only = [
    'Bulk mode; whois.cymru.com [2025-01-01 00:00:00 +0000]',
    'AS      | IP | BGP Prefix | CC | Registry | Allocated | AS Name',
];
is_eq(smpro_ip_parse_cymru($hdr_only), [], 'ip_parse_cymru: only Bulk-mode + AS Name header -> []');

// empty input -> []
is_eq(smpro_ip_parse_cymru([]), [], 'ip_parse_cymru: empty array -> []');

// lines without a pipe are skipped -> []
is_eq(smpro_ip_parse_cymru(['no pipe here', '   ', '']), [], 'ip_parse_cymru: no-pipe / blank lines -> []');

// a line with fewer than 7 fields is skipped (count(p) < 7)
is_eq(smpro_ip_parse_cymru(['15169 | 8.8.8.8 | US']), [], 'ip_parse_cymru: <7 pipe fields -> []');

// first valid data line wins; the AS field is trimmed and AS-prefixed
$cymru2 = [
    '14618 | 3.3.3.3 | 3.0.0.0/9 | US | arin | 2010-01-01 | AMAZON-AES, US',
];
$got2 = smpro_ip_parse_cymru($cymru2);
is_eq($got2['asn'], 'AS14618',        'ip_parse_cymru: AS field trimmed + AS-prefixed');
is_eq($got2['country'], 'US',          'ip_parse_cymru: country = field[3] trimmed');
is_eq($got2['provider'], 'AMAZON-AES, US', 'ip_parse_cymru: provider = field[6] trimmed');
is_eq($got2['source'], 'Team Cymru whois', 'ip_parse_cymru: source label is constant');

// the parsed provider feeds smpro_ip_is_datacenter — end-to-end sanity
ok(smpro_ip_is_datacenter($got2), 'integration: parsed AMAZON provider classified as datacenter');

/* ---------------------------------------------------------------------
 * SKIPPED (need stubs / fixtures — Phase 3, no-stub phase here)
 * ------------------------------------------------------------------- */
tap_skip('smpro_geo_foreign — needs stub (Phase 3)', 'calls smpro_ip_intel (network whois + shell + disk cache); not pure');
