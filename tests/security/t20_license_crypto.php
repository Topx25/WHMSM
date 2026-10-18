<?php
/**
 * t20_license_crypto.php — the anti-piracy CROWN JEWEL: the license-verdict crypto that makes
 * a hand-edited / copied / MITM'd / replayed license fail. Threat model = the ROOT licensee is
 * the adversary (per project rule). Catalog U10-U14, U20, S01-S04, S12 + authorize replay.
 *
 * Method: inject a TEST RSA public key (smpro_test_keypair) before requiring the .build copy of
 * license.php (whose SMPRO_LIC_PUBKEY define is made re-definable by make_build.sh), then sign
 * payloads with the matching TEST private key — exactly as the real license server does. Server
 * IP + fingerprint are the box's REAL values (read via the plugin's own functions) so the binding
 * checks exercise the genuine code path. Every expected value derives from license.php:67-76/424-436/786-799.
 */
require __DIR__ . '/../support/bootstrap.php';
require SMPRO_BASE . '/tests/support/lic_sign.php';

$kp = smpro_test_keypair();
define('SMPRO_LIC_PUBKEY', $kp['pub']);          // injected BEFORE the include (guard skips the real key)
require SMPRO_TEST_BUILD . '/includes/license.php';

ok(defined('SMPRO_LIC_PUBKEY'), 'TEST public key injected into .build license.php');

$ip = smpro_lic_server_ip();
$fp = smpro_lic_fingerprint();
ok($ip !== '' && $fp !== '', 'real server ip + fingerprint resolved on the test box');

$base = [
    'status' => 'active', 'bound_ip' => $ip, 'fingerprint' => $fp,
    'expires_at' => '', 'issued_at' => date('c'),
    'feat_key' => 'FEATKEY-123', 'pair_key' => 'PAIRKEY-ABC',
];
$set = function ($block, $extra = []) { $GLOBALS['_smpro_lic_state'] = array_merge(['raw' => ['license' => $block], 'key' => 'TESTKEY'], $extra); };

/* ---------- U10 / S03 — signature verification ---------- */
$blk = smpro_test_sign_block($base);
is_eq(smpro_lic_verify_signature($blk), true, 'U10 verify_signature: valid TEST-signed block -> true');

$tamper = $blk; $tamper['payload']['status'] = 'pwned';        // mutate AFTER signing
is_eq(smpro_lic_verify_signature($tamper), false, 'U10 verify_signature: mutated payload -> false');
is_eq(smpro_lic_verify_signature(['payload' => $base, 'signature' => '']), false, 'U10 verify_signature: empty signature -> false');
is_eq(smpro_lic_verify_signature(['payload' => $base, 'signature' => base64_encode('garbage')]), false, 'U10 verify_signature: garbage signature -> false');
is_eq(smpro_lic_verify_signature('not-an-array'), false, 'U10 verify_signature: non-array -> false');

$foreign = smpro_test_new_keypair();                          // MITM: signed by a DIFFERENT key
$mitm = smpro_test_sign_block($base, $foreign['priv']);
is_eq(smpro_lic_verify_signature($mitm), false, 'S03 verify_signature: block signed by a foreign key -> false');

/* ---------- U11 / S01 / S02 — verify_state (binding + tamper) ---------- */
$set($blk);
is_eq(smpro_lic_verify_state(smpro_lic_state()), [true, ''], 'U11 verify_state: valid bound signed state -> [true, expiry]');

$edited = $blk; $edited['payload']['expires_at'] = '2099-01-01';   // edit after signing -> sig breaks
$set($edited);
is_eq(smpro_lic_verify_state(smpro_lic_state()), [false, ''], 'S01 verify_state: hand-edited payload (sig broken) -> [false]');

$set(['payload' => $base, 'signature' => base64_encode('AAAA')]);  // unsigned/forged block
is_eq(smpro_lic_verify_state(smpro_lic_state()), [false, ''], 'S01 verify_state: forged block -> [false]');

$wrongIp = smpro_test_sign_block(array_merge($base, ['bound_ip' => '203.0.113.7']));
$set($wrongIp);
is_eq(smpro_lic_verify_state(smpro_lic_state()), [false, ''], 'S02 verify_state: valid verdict bound to ANOTHER ip (copied box) -> [false]');

$wrongFp = smpro_test_sign_block(array_merge($base, ['fingerprint' => str_repeat('b', 64)]));
$set($wrongFp);
is_eq(smpro_lic_verify_state(smpro_lic_state()), [false, ''], 'S02 verify_state: wrong fingerprint (cloned box) -> [false]');

$susp = smpro_test_sign_block(array_merge($base, ['status' => 'suspended']));
$set($susp);
is_eq(smpro_lic_verify_state(smpro_lic_state()), [false, ''], 'U11 verify_state: non-active status -> [false]');

$exp = smpro_test_sign_block(array_merge($base, ['expires_at' => '2099-12-31']));
$set($exp);
is_eq(smpro_lic_verify_state(smpro_lic_state()), [true, '2099-12-31'], 'U11 verify_state: returns the SIGNED expiry (not a mutable field)');

/* ---------- U13 — expired (monotonic clock) ---------- */
is_eq(smpro_lic_expired(''), false, 'U13 expired: empty -> false');
is_eq(smpro_lic_expired('0'), false, 'U13 expired: "0" -> false');
is_eq(smpro_lic_expired('2000-01-01'), true, 'U13 expired: past date -> true');
is_eq(smpro_lic_expired(date('c', time() + 86400)), false, 'U13 expired: future date -> false');

/* ---------- U20 / S12 — feature & pair keys come ONLY from the signed verdict ---------- */
$set($blk);
is_eq(smpro_lic_feat_key(), 'FEATKEY-123', 'U20 feat_key: read from signed verdict');
is_eq(smpro_lic_pair_key(), 'PAIRKEY-ABC', 'U20 pair_key: read from signed verdict');
$set(['payload' => $base, 'signature' => base64_encode('AAAA')]);   // unsigned
is_eq(smpro_lic_feat_key(), '', 'S12 feat_key: forged/unsigned state -> "" (cracked build cannot fabricate)');
is_eq(smpro_lic_pair_key(), '', 'S12 pair_key: forged/unsigned state -> ""');

/* ---------- U14 — pairing equation (Smpro_Rollup::sample) ---------- */
$set($blk);                                   // pair_key = PAIRKEY-ABC
$mac = 'AA:BB:CC:DD:EE:FF';
$now = smpro_lic_now();
$t = (int) floor($now / 3600);
$ctx = hash('sha256', strtolower(trim($mac)) . '|' . strtolower(trim((string) php_uname('n'))));
$expected = substr(hash_hmac('sha256', 'beat|' . $t . '|' . $ctx, 'PAIRKEY-ABC'), 0, 20);
is_eq(Smpro_Rollup::sample($mac), $expected, 'U14 pairing: Smpro_Rollup::sample matches independent reimpl (K, hour t, ctx=MAC|host)');
is_eq(strlen(Smpro_Rollup::sample($mac)), 20, 'U14 pairing: beacon is 20 hex chars');
is_eq(Smpro_Rollup::sample($mac), Smpro_Rollup::sample($mac), 'U14 pairing: stable within the same hour');
$GLOBALS['_smpro_lic_state'] = [];
is_eq(Smpro_Rollup::sample($mac), '', 'U14 pairing: no pair_key -> empty beacon (unbound/first boot)');

/* ---------- U17 — monotonic now() / hwm ---------- */
ok(smpro_lic_now() >= time(), 'U17 now(): never earlier than wall clock');
smpro_lic_hwm_bump(time() + 5 * 86400);                          // absurd future (> +24h) is ignored
ok(smpro_lic_now() <= time() + 86400, 'U17 hwm_bump: absurd future timestamp ignored (anti clock-jump)');

/* ---------- U12 / S04 — authorize: replay / relay / action-binding ---------- */
$nonce = bin2hex(random_bytes(8));
$ap = array_merge($base, ['action' => 'restart_service', 'nonce' => $nonce]);
$j = ['ok' => true, 'license' => smpro_test_sign_block($ap)];
is_eq(smpro_lic_verify_authorization('restart_service', $nonce, 200, $j), true, 'U12 authorize: valid live authorization -> true');
is_eq(smpro_lic_verify_authorization('restart_service', 'OTHERNONCE', 200, $j), false, 'S04 authorize: replay with different nonce -> false');
is_eq(smpro_lic_verify_authorization('delete_everything', $nonce, 200, $j), false, 'S04 authorize: action mismatch -> false');
is_eq(smpro_lic_verify_authorization('restart_service', $nonce, 500, $j), false, 'S04 authorize: non-authoritative (HTTP 500) -> false');
$j2 = $j; $j2['ok'] = false;
is_eq(smpro_lic_verify_authorization('restart_service', $nonce, 200, $j2), false, 'S04 authorize: ok=false -> false');
$jip = ['ok' => true, 'license' => smpro_test_sign_block(array_merge($ap, ['bound_ip' => '203.0.113.9']))];
is_eq(smpro_lic_verify_authorization('restart_service', $nonce, 200, $jip), false, 'S04 authorize: bound to another server -> false');
