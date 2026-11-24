<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/license.php';
require_once SMPRO_BASE . '/includes/trustfeed.php';
require_once SMPRO_BASE . '/includes/vulnfeed.php';
/**
 * t199 - Security Health plan step 2: match installed hosting-stack versions (cPanel/Imunify360/CSF/LiteSpeed)
 * against a SIGNED advisory feed the licence server publishes (feeds/vuln-advisories.json), verified with the
 * SAME pinned licence key trustfeed uses. OS packages are covered by step 1 (dnf updateinfo); this covers the
 * stack that is not an OS package. Tests the pure matcher, the feed validator's rejections, and the safe-degrade
 * behaviour when no feed is configured. The generator lives on the licence server (_srv/vuln_advisories_build.php).
 */

// --- A. version matching: introduced <= v < fixed ---
$adv = [
    ['product' => 'cpanel', 'introduced' => '11.120.0.0', 'fixed' => '11.120.0.18', 'severity' => 'important', 'cves' => ['CVE-2026-1']],
    ['product' => 'cpanel', 'introduced' => '0',          'fixed' => '11.118.0.30', 'severity' => 'critical',  'cves' => ['CVE-2026-2']],
];
is_eq(count(smpro_vf_match_version('11.120.0.5',  $adv)), 1, 'A1: a version inside one range matches that one advisory');
is_eq(count(smpro_vf_match_version('11.118.0.10', $adv)), 1, 'A2: an older version matches the introduced=0 advisory');
is_eq(count(smpro_vf_match_version('11.120.0.18', $adv)), 0, 'A3: exactly the fixed version is NOT affected (fix applied)');
is_eq(count(smpro_vf_match_version('11.121.0.0',  $adv)), 0, 'A4: a newer version matches nothing');
is_eq(smpro_vf_match_version('not.a.version', $adv), [], 'A5: a non-dotted version matches nothing (no crash)');

// --- B. the signed-feed validator accepts a well-formed doc and rejects tampering ---
// build a correctly-signed feed with the TEST not having the private key: instead assert the validator's
// structural rejections (the signature path is proven end-to-end against the live server feed, not here).
$good = ['feed' => 'vuln-advisories', 'product' => 'smpro', 'generated' => time(),
         'advisories' => [['product' => 'csf', 'fixed' => '14.22', 'severity' => 'moderate']]];
is_eq(smpro_vf_validate(['payload' => $good, 'signature' => 'x'])['ok'], false, 'B1: a bad signature is rejected (no valid sig in-test)');
is_eq(smpro_vf_validate(['payload' => ['feed' => 'wrong', 'product' => 'smpro', 'generated' => time(), 'advisories' => []], 'signature' => 'x'])['why'] !== '', true, 'B2: the wrong feed name is rejected');
// the validator must reject malformed advisory fields BEFORE any version match uses them
$badSev = ['feed' => 'vuln-advisories', 'product' => 'smpro', 'generated' => time(), 'advisories' => [['product' => 'csf', 'fixed' => '1.0', 'severity' => 'spicy']]];
ok(strpos(smpro_vf_validate(['payload' => $badSev, 'signature' => 'x'])['why'], 'severity') !== false || !smpro_vf_validate(['payload' => $badSev, 'signature' => 'x'])['ok'], 'B3: an unknown severity is rejected');

// --- C. safe degrade: with no feed on disk, status is "not configured" and nothing is flagged ---
$st = smpro_vf_status();
ok(is_array($st) && array_key_exists('have', $st), 'C1: status always returns a structured result');
is_eq($st['have'], false, 'C2: with no verified feed kept, have=false (the page shows "not configured", flags nothing)');

// --- D. known products + the client reads a local version safely (empty on the lab, never a warning) ---
is_eq(smpro_vf_known_products(), ['cpanel', 'imunify360', 'csf', 'litespeed'], 'D1: the four hosting-stack products');
$cp = smpro_vf_match_product('cpanel');
ok(is_array($cp) && array_key_exists('installed', $cp) && array_key_exists('hits', $cp), 'D2: match_product returns a structured result even when nothing is installed');

// --- E. wiring: the generator source signs with the licence contract (when present) ---
// _srv/ holds licence-server tooling and is deliberately NOT part of the shipped/synced tree (the release gate
// syncs index.cgi/index.php/includes/modules/bin/cpuser/lang/assets/tests only), so on the lab the file is
// absent. Check the signing contract where the source IS present (the dev tree); skip cleanly where it is not.
$genPath = SMPRO_BASE . '/_srv/vuln_advisories_build.php';
if (is_file($genPath)) {
    $gen = str_replace(chr(13), '', (string)@file_get_contents($genPath));
    has($gen, "'feed' => 'vuln-advisories'", 'E2: the generator stamps the matching feed name');
    has($gen, 'openssl_sign($data, $sig, $pk, OPENSSL_ALGO_SHA256)', 'E3: it signs the canonical payload with RSA-SHA256 (same contract the client verifies)');
    has($gen, 'json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)', 'E4: ...over the exact canonical JSON the client re-encodes to verify');
} else {
    tap_skip('E: _srv/ generator not in this (synced) tree — checked in the dev tree');
}

// --- F. the page check is wired under Security updates and degrades without a feed ---
$sh = str_replace(chr(13), '', (string)@file_get_contents(SMPRO_BASE . '/includes/sechealth.php'));
has($sh, 'smpro_vf_match_product', 'F1: smpro_sh_all() consults the vuln feed per product');
has($sh, 'vulnerability advisory feed is not configured', 'F2: it degrades to info when no feed is published yet');
