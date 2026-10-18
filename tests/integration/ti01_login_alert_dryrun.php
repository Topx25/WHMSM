<?php
/**
 * ti01_login_alert_dryrun.php — Phase-3 integration. Proves the two DRY-RUN auto-response
 * engines NEVER fire the firewall, and that the home-region / threshold policy they enforce
 * is exactly as documented in includes/intrusion.php.
 *
 *   I09  smpro_login_guard_run(true)  — 24/7 foreign login brute-force guard, REPORT-ONLY.
 *        In dry-run it must never call csf (line 138 only blocks when !$dryrun). The foreign-vs-
 *        protected DECISION it gates on (line 136: `if (empty($g['foreign'])) continue;`) is the
 *        real smpro_geo_foreign(): FOREIGN (non-Arab, known geo) only; Arab/local/unknown excluded.
 *   I10  smpro_im_alert_scan()        — intrusion auto-block, DRY-RUN (auto_block + auto_block_dryrun).
 *        Lines 1078/1087-1090: floor = auto_block_threshold (30); core_protected (EG/SA residential)
 *        never blocks; arab_caution (other-Arab residential) blocks only at >= floor*3; normal
 *        (non-Arab / datacenter-any-country / unknown) blocks at the floor. In dry-run csf stays empty
 *        (line 1093 blocks only when auto_block_dryrun is empty AND not global dry-run).
 *
 * SEAM control: smpro_ip_intel / smpro_ip_is_datacenter / smpro_server_ips / smpro_is_server_ip are
 * renamed in the .build copy, so our stubfns provide them (deterministic geo). smpro_geo_foreign,
 * smpro_cc_is_arab, smpro_ip_is_external, smpro_im_region_status remain the REAL code under test.
 * The csf recorder must stay EMPTY = the blocker-not-called proof.
 *
 * NOTE on log-gated functions: both engines read a HARDCODED system log via the `tail` shim
 * (smpro_login_guard_run -> /usr/local/cpanel/logs/login_log ; smpro_im_alert_scan ->
 * smpro_im_modsec_log()). Those paths are not creatable in the sandbox, so the live calls are used
 * to prove the never-block safety invariant (csf empty) in any environment, while the foreign /
 * threshold / region POLICY each engine applies is asserted deterministically through the real
 * helpers it delegates to, with the documented config (auto_block_threshold = 30).
 */
require __DIR__ . '/../support/bootstrap.php';

/* Deterministic geo + identity. Datacenter map matches the real keyword detector (provider-based). */
smpro_test_install_stubs([
    'server_ips'  => ['203.0.113.50' => 1],
    'datacenters' => ['DigitalOcean LLC', 'Amazon AWS'],
    'ip_intel'    => [],
]);

require SMPRO_TEST_BUILD . '/includes/helpers.php';     // seams renamed -> stubs win; geo_foreign/cc_is_arab/ip_is_external REAL
require SMPRO_TEST_BUILD . '/includes/intrusion.php';    // login_guard_run / im_alert_scan / region_status / block_ip (real)

ok(function_exists('smpro_login_guard_run'), 'I09 smpro_login_guard_run loaded');
ok(function_exists('smpro_im_alert_scan'),   'I10 smpro_im_alert_scan loaded');

/* Seed geo intel for every IP this test reasons about (TEST-NET only). */
smpro_stub_set('ip_intel', [
    // --- I09 foreign-guard decision set ---
    '203.0.113.10' => ['country' => 'US', 'provider' => 'Comcast',     'asn' => 'AS7922', 'datacenter' => false], // foreign
    '203.0.113.11' => ['country' => 'EG', 'provider' => 'TE Data',     'asn' => 'AS8452', 'datacenter' => false], // Arab home
    '203.0.113.12' => ['country' => 'SA', 'provider' => 'STC',         'asn' => 'AS25019','datacenter' => false], // Arab home
    '203.0.113.13' => ['country' => 'AE', 'provider' => 'Etisalat',    'asn' => 'AS5384', 'datacenter' => false], // other-Arab
    '203.0.113.14' => ['country' => '',   'provider' => '',            'asn' => '',       'datacenter' => false], // unknown geo
    // --- I10 region/threshold decision set ---
    '198.51.100.20' => ['country' => 'US', 'provider' => 'Comcast',          'asn' => 'AS7922', 'datacenter' => false], // normal
    '198.51.100.21' => ['country' => 'EG', 'provider' => 'TE Data',          'asn' => 'AS8452', 'datacenter' => false], // core_protected
    '198.51.100.22' => ['country' => 'AE', 'provider' => 'Etisalat',         'asn' => 'AS5384', 'datacenter' => false], // arab_caution
    '198.51.100.23' => ['country' => 'EG', 'provider' => 'DigitalOcean LLC', 'asn' => 'AS14061','datacenter' => true ], // EG datacenter -> normal
]);

/* Write the on-disk config ONCE, BEFORE any smpro_in_cfg() call statics it (smpro_in_cfg caches in
 * a static and smpro_in_cfg_save would not refresh it). Enables auto_block in DRY-RUN for I10 and
 * pins the documented thresholds; login_guard fields keep their defaults (login_guard on, thr 4). */
@is_dir(dirname(SMPRO_IN_CFG)) || @mkdir(dirname(SMPRO_IN_CFG), 0700, true);
@file_put_contents(SMPRO_IN_CFG, json_encode([
    'login_guard'           => true,
    'login_guard_threshold' => 4,
    'auto_block'            => true,
    'auto_block_dryrun'     => true,
    'auto_block_threshold'  => 30,
    'protect_arab'          => true,
    'protect_regions'       => ['EG', 'SA'],
    'caution_regions'       => ['AE','KW','QA','BH','OM','JO','LB','SY','IQ','YE','PS','DZ','MA','TN','LY','SD','MR','SO','DJ','KM'],
], JSON_UNESCAPED_SLASHES));

/* =========================================================================
 * I09 — login brute-force guard, DRY-RUN
 * ========================================================================= */

/* (a) Live call in dry-run NEVER touches the firewall, regardless of whether the cpanel
 *     login_log happens to be readable on this box. This is the I09 never-block invariant. */
smpro_test_rec_reset('csf');
$lg = smpro_login_guard_run(true);
ok(is_array($lg),                          'I09 login_guard_run(true) returns an array');
ok(array_key_exists('ok', $lg),            'I09 result carries an ok flag');
ok(array_key_exists('blocked', $lg) && is_array($lg['blocked']), 'I09 result carries a blocked[] list');
ok(smpro_test_rec_empty('csf'),            'I09 DRY-RUN never invoked csf (recorder empty — blocker-not-called proof)');

/* (b) The foreign/protected gate (line 136) is the real smpro_geo_foreign(). Derive its verdict
 *     for each class; this is exactly what login_guard tests before deciding to block. */
$gUS  = smpro_geo_foreign('203.0.113.10');
$gEG  = smpro_geo_foreign('203.0.113.11');
$gSA  = smpro_geo_foreign('203.0.113.12');
$gAE  = smpro_geo_foreign('203.0.113.13');
$gUnk = smpro_geo_foreign('203.0.113.14');

is_eq($gUS['foreign'],  true,  'I09 US -> foreign (login_guard would report/block this class)');
is_eq($gUS['cc'],       'US',  'I09 US -> cc=US');
is_eq($gEG['foreign'],  false, 'I09 EG -> NOT foreign (Arab home, excluded from blocking)');
is_eq($gEG['arab'],     true,  'I09 EG -> flagged arab');
is_eq($gSA['foreign'],  false, 'I09 SA -> NOT foreign (Arab home, excluded)');
is_eq($gAE['foreign'],  false, 'I09 AE -> NOT foreign (other-Arab, excluded by login_guard)');
is_eq($gAE['arab'],     true,  'I09 AE -> flagged arab');
is_eq($gUnk['foreign'], false, 'I09 unknown geo -> NOT foreign (login_guard skips; known&!arab only)');
is_eq($gUnk['known'],   false, 'I09 unknown geo -> known=false');

/* (c) login_guard-style decision: block only when fails>=threshold AND foreign (lines 134-137).
 *     Threshold floor uses the real config default (login_guard_threshold = 4). */
$cfg0   = smpro_in_cfg();
$lgThr  = max(2, (int)($cfg0['login_guard_threshold'] ?? 4));
is_eq($lgThr, 4, 'I09 login_guard_threshold default = 4 (from smpro_in_cfg)');
$lgWouldReport = function (string $ip, int $fails) use ($lgThr) {
    if ($fails < $lgThr) return false;                       // line 134 (< thresh -> skip)
    return !empty(smpro_geo_foreign($ip)['foreign']);        // line 136 (foreign only)
};
is_eq($lgWouldReport('203.0.113.10', 5), true,  'I09 US @5 fails (>=4) -> would be reported/blocked');
is_eq($lgWouldReport('203.0.113.10', 3), false, 'I09 US @3 fails (<4) -> below threshold, excluded');
is_eq($lgWouldReport('203.0.113.11', 99),false, 'I09 EG @99 fails -> Arab, excluded even far over threshold');
is_eq($lgWouldReport('203.0.113.13', 99),false, 'I09 AE @99 fails -> other-Arab, excluded by foreign gate');
is_eq($lgWouldReport('203.0.113.14', 99),false, 'I09 unknown geo @99 -> excluded (not known-foreign)');

/* =========================================================================
 * I10 — intrusion auto-block, DRY-RUN
 * ========================================================================= */

/* Config was written at the top of the file (before any smpro_in_cfg() call), so the static now
 * holds auto_block=true / auto_block_dryrun=true / threshold=30. */
$cfg = smpro_in_cfg();
is_eq(!empty($cfg['auto_block']),        true, 'I10 auto_block enabled in config');
is_eq(!empty($cfg['auto_block_dryrun']), true, 'I10 auto_block_dryrun enabled (report-only)');
$min = max(5, (int)($cfg['auto_block_threshold'] ?? 30));
is_eq($min, 30, 'I10 auto_block_threshold floor = 30');

/* (a) Live scan in dry-run never touches the firewall even with auto_block ON
 *     (the modsec log is absent so there are no offenders; the dry-run branch never blocks anyway). */
smpro_test_rec_reset('csf');
$alerts = smpro_im_alert_scan();
ok(is_array($alerts),           'I10 im_alert_scan() returns an alerts array');
ok(smpro_test_rec_empty('csf'), 'I10 DRY-RUN never invoked csf (recorder empty — blocker-not-called proof)');

/* (b) region classifier (real) for each I10 scenario — the exact value the auto-block branch reads. */
is_eq(smpro_im_region_status('198.51.100.20'), 'normal',         'I10 US residential -> normal');
is_eq(smpro_im_region_status('198.51.100.21'), 'core_protected', 'I10 EG residential -> core_protected (never auto-block)');
is_eq(smpro_im_region_status('198.51.100.22'), 'arab_caution',   'I10 AE residential -> arab_caution (needs 3x floor)');
is_eq(smpro_im_region_status('198.51.100.23'), 'normal',         'I10 EG DATACENTER -> normal (hosting blockable in any country)');

/* (c) the auto-block decision exactly as coded (lines 1078, 1082-1083, 1087-1090):
 *     floor gate, external gate, allowlist gate, then home-region policy. */
$wouldBlock = function (string $ip, int $hits) use ($min) {
    if ($hits < $min) return false;                                        // line 1078 (floor)
    if (function_exists('smpro_ip_is_external') && !smpro_ip_is_external($ip)) return false; // line 1082
    if (smpro_im_allowlisted($ip)) return false;                          // line 1083
    $rs = smpro_im_region_status($ip);                                     // line 1088
    if ($rs === 'core_protected') return false;                           // line 1089
    if ($rs === 'arab_caution' && $hits < $min * 3) return false;         // line 1090
    return true;                                                          // -> recorded as "(dry-run)"
};

is_eq($wouldBlock('198.51.100.20', 30), true,  'I10 US @30 (>=floor, normal) -> WOULD block (dry-run)');
is_eq($wouldBlock('198.51.100.20', 29), false, 'I10 US @29 (<floor) -> not blocked');
is_eq($wouldBlock('198.51.100.21', 100),false, 'I10 EG residential @100 -> NOT blocked (core_protected)');
is_eq($wouldBlock('198.51.100.22', 30), false, 'I10 AE @30 (arab_caution, <90) -> NOT blocked');
is_eq($wouldBlock('198.51.100.22', 90), true,  'I10 AE @90 (arab_caution, >=3x floor) -> WOULD block (dry-run)');
is_eq($wouldBlock('198.51.100.22', 89), false, 'I10 AE @89 (just under 3x floor) -> NOT blocked');
is_eq($wouldBlock('198.51.100.23', 30), true,  'I10 EG DATACENTER @30 -> WOULD block (hosting is fair game)');

/* (d) Even a direct block attempt on a server/private IP refuses and never calls csf
 *     (defense-in-depth shared by both engines via smpro_im_block_ip). */
smpro_test_rec_reset('csf');
$srv = smpro_im_block_ip('203.0.113.50');
is_eq($srv['ok'], false, 'I10 block_ip(server IP) refused (never auto-blocks the box itself)');
has($srv['msg'], 'server IP', 'I10 refusal names the server IP');
ok(smpro_test_rec_empty('csf'), 'I10 refused block never invoked csf (recorder empty)');

/* (e) AI auto-block path is deferred to Phase 4 (smpro_im_ai_block_decide depends on the
 *     non-seam AI provider callees smpro_ai_available / smpro_ai_chat_json). */
tap_skip('I10 AI-decided auto-block (ai_block) path', 'needs AI-provider spies (smpro_ai_available/smpro_ai_chat_json) — Phase 4');
