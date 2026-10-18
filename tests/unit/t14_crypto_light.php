<?php
require __DIR__ . '/../support/bootstrap.php';

/**
 * t14_crypto_light — pure crypto-ish helpers from includes/secret.php, csrf.php, update.php.
 *  smpro_secret_enc / smpro_secret_dec  (U25)
 *  smpro_csrf_generate / smpro_csrf_verify (U72)
 *  smpro_upd_is_gzip (U27)
 *  smpro_upd_cfg     (U28)
 *
 * All targets are deterministic given args + the per-process sandbox key files
 * (which secret/csrf create on first use under SMPRO_VARLIB / SMPRO_CACHE — safe).
 * csrf needs smpro_current_actor() (auth.php) — pure (reads env/posix, no net/shell).
 */
require SMPRO_BASE . '/includes/auth.php';   // smpro_current_actor() — helper for csrf
require SMPRO_BASE . '/includes/secret.php';
require SMPRO_BASE . '/includes/csrf.php';
require SMPRO_BASE . '/includes/update.php';

/* ============================================================ *
 *  U25 — smpro_secret_enc / smpro_secret_dec
 * ============================================================ */

// round-trip: dec(enc('tok')) === 'tok'
$tok = 'super-secret-token-123';
$enc = smpro_secret_enc($tok);
like($enc, '/^enc:v1:/', 'enc() output carries the enc:v1: prefix');
isnt_eq($enc, $tok, 'enc() output differs from the plaintext');
is_eq(smpro_secret_dec($enc), $tok, 'dec(enc(tok)) === tok (round-trip)');

// round-trip for a few more shapes (incl. non-ascii / longer)
foreach (['x', 'AbCdEf0123', 'with spaces & symbols !@#$%^', str_repeat('Z', 200), "utf8-\xc3\xa9\xc3\xbc"] as $i => $p) {
    is_eq(smpro_secret_dec(smpro_secret_enc($p)), $p, "round-trip case #$i preserves the value exactly");
}

// non-deterministic IV: two encrypts of the same plaintext differ, but both decrypt back
$e1 = smpro_secret_enc($tok);
$e2 = smpro_secret_enc($tok);
isnt_eq($e1, $e2, 'two encryptions of the same plaintext differ (random IV)');
is_eq(smpro_secret_dec($e1), $tok, 'first ciphertext decrypts back to tok');
is_eq(smpro_secret_dec($e2), $tok, 'second ciphertext decrypts back to tok');

// already-encrypted passthrough on enc(): enc(enc(x)) === enc(x)
is_eq(smpro_secret_enc($enc), $enc, 'enc() is a passthrough for an already enc:v1: value');

// empty-string passthrough on enc() (guard: $plain === '')
is_eq(smpro_secret_enc(''), '', 'enc("") returns "" unchanged');

// plaintext / legacy passthrough on dec() (no enc:v1: prefix)
is_eq(smpro_secret_dec('plain-legacy-value'), 'plain-legacy-value', 'dec() passes through a non-prefixed (legacy) value');
is_eq(smpro_secret_dec(''), '', 'dec("") returns "" (no prefix → passthrough)');

// tamper a byte of the ciphertext body -> GCM auth fails -> dec returns ''
$body  = substr($enc, 7);                 // base64 of iv|tag|ct
$raw   = base64_decode($body, true);
ok(is_string($raw) && strlen($raw) >= 29, 'decoded enc blob is >= 29 bytes (iv12+tag16+ct>=1)');
// flip a bit deep in the ciphertext region (offset 28 = start of ct)
$flip          = $raw;
$flip[28]      = $flip[28] ^ "\x01";
$tampered      = 'enc:v1:' . base64_encode($flip);
isnt_eq($tampered, $enc, 'tampered token string differs from the original');
is_eq(smpro_secret_dec($tampered), '', 'dec() of a byte-tampered ciphertext returns "" (GCM auth fail)');

// tamper the IV region -> also fails auth -> ''
$flip2      = $raw;
$flip2[0]   = $flip2[0] ^ "\x01";
is_eq(smpro_secret_dec('enc:v1:' . base64_encode($flip2)), '', 'dec() of an IV-tampered ciphertext returns ""');

// prefixed but too-short blob (< 29 bytes) -> '' (length guard)
is_eq(smpro_secret_dec('enc:v1:' . base64_encode('short')), '', 'dec() of a prefixed-but-too-short blob returns ""');

// prefixed but non-base64 garbage -> base64_decode strict fails -> '' (not a warning)
is_eq(smpro_secret_dec('enc:v1:@@@not-base64@@@'), '', 'dec() of prefixed non-base64 garbage returns ""');

// smpro_secret_is_enc classifier
ok(smpro_secret_is_enc($enc), 'is_enc() true for an enc:v1: value');
nok(smpro_secret_is_enc('plain'), 'is_enc() false for a plaintext value');

/* ============================================================ *
 *  U72 — smpro_csrf_generate / smpro_csrf_verify
 * ============================================================ */

// lifetime constant is exactly 1 hour
is_eq(SMPRO_CSRF_TTL, 3600, 'CSRF TTL constant is 3600 (1 hour)');

// happy path: verify(action, generate(action)) === true
$act = 'license';
$t   = smpro_csrf_generate($act);
ok(smpro_csrf_verify($act, $t), 'verify(action, generate(action)) === true');

// token format: ts.nonce.sig (3 dot-separated parts)
$parts = explode('.', $t);
is_eq(count($parts), 3, 'generated token has exactly 3 dot-separated parts (ts.nonce.sig)');
ok(ctype_digit($parts[0]), 'token part 1 (ts) is all digits');
ok(ctype_xdigit($parts[1]), 'token part 2 (nonce) is hex');
ok(ctype_xdigit($parts[2]), 'token part 3 (sig) is hex (hmac-sha256)');

// wrong action -> false (token is action-bound)
nok(smpro_csrf_verify('different_action', $t), 'verify() false for a token issued for a different action');

// action normalisation: generate strips/normalises [^a-z0-9_-]; "License!" -> "license"
$tNorm = smpro_csrf_generate('License!');
ok(smpro_csrf_verify('license', $tNorm), 'verify() honours generate()s lowercase+strip normalisation');
ok(smpro_csrf_verify('LICENSE', $tNorm), 'verify() normalises the action the same way (case-insensitive)');

// tampered signature -> false
$badSig = $parts[0] . '.' . $parts[1] . '.' . 'deadbeef';
nok(smpro_csrf_verify($act, $badSig), 'verify() false when the signature is replaced');

// tampered timestamp (re-signs nothing) -> false (sig no longer matches ts)
$badTs = ((int)$parts[0] - 10) . '.' . $parts[1] . '.' . $parts[2];
nok(smpro_csrf_verify($act, $badTs), 'verify() false when the ts is altered (sig is bound to ts)');

// tampered nonce -> false
$badNonce = $parts[0] . '.' . 'ffffffffffffffff' . '.' . $parts[2];
nok(smpro_csrf_verify($act, $badNonce), 'verify() false when the nonce is altered');

// expired: ts older than TTL -> false. Forge a correctly-signed token with an old ts
// using the same recipe as generate() (same secret + actor), so ONLY the age fails it.
$oldTs   = time() - SMPRO_CSRF_TTL - 5;          // just past the 1h window
$nonce   = bin2hex(random_bytes(8));
$actNorm = preg_replace('/[^a-z0-9_\-]/', '', strtolower($act));
$actor   = smpro_current_actor();
$sigOld  = hash_hmac('sha256', "$actNorm|$actor|" . SMPRO_CPSESS . "|$oldTs|$nonce", smpro_csrf_secret());
$expired = "$oldTs.$nonce.$sigOld";
nok(smpro_csrf_verify($act, $expired), 'verify() false for a correctly-signed but expired (> TTL) token');

// a token right at the edge but still inside TTL verifies (age == TTL is allowed; > TTL fails)
$edgeTs  = time() - SMPRO_CSRF_TTL;              // exactly TTL old → (time-ts) == TTL, not > TTL
$nonce2  = bin2hex(random_bytes(8));
$sigEdge = hash_hmac('sha256', "$actNorm|$actor|" . SMPRO_CPSESS . "|$edgeTs|$nonce2", smpro_csrf_secret());
ok(smpro_csrf_verify($act, "$edgeTs.$nonce2.$sigEdge"), 'verify() true for a token exactly TTL seconds old (boundary, not yet > TTL)');

// malformed tokens -> false (count != 3, empty, non-digit ts, non-hex nonce)
nok(smpro_csrf_verify($act, ''), 'verify() false for an empty token');
nok(smpro_csrf_verify($act, 'a.b'), 'verify() false for a 2-part token');
nok(smpro_csrf_verify($act, 'a.b.c.d'), 'verify() false for a 4-part token');
nok(smpro_csrf_verify($act, 'notanumber.' . $parts[1] . '.' . $parts[2]), 'verify() false when ts is non-numeric');
nok(smpro_csrf_verify($act, $parts[0] . '.zzzz.' . $parts[2]), 'verify() false when nonce is non-hex');

/* ============================================================ *
 *  U27 — smpro_upd_is_gzip  (magic-byte sniff of a FILE)
 * ============================================================ */

$dir = SMPRO_VARLIB . '/t14';
@mkdir($dir, 0700, true);

$fGz = $dir . '/a.gz';
file_put_contents($fGz, "\x1f\x8b\x08\x00rest-of-stream");
ok(smpro_upd_is_gzip($fGz), 'is_gzip() true for a file starting with the gzip magic 1f 8b');

$fZip = $dir . '/a.zip';
file_put_contents($fZip, "PK\x03\x04rest");
nok(smpro_upd_is_gzip($fZip), 'is_gzip() false for a PK.. (zip) file');

$fEmpty = $dir . '/empty.bin';
file_put_contents($fEmpty, '');
nok(smpro_upd_is_gzip($fEmpty), 'is_gzip() false for an empty file (0 bytes read)');

$fOne = $dir . '/one.bin';
file_put_contents($fOne, "\x1f");
nok(smpro_upd_is_gzip($fOne), 'is_gzip() false for a 1-byte file (needs exactly 2 magic bytes)');

$fOnlyFirst = $dir . '/firstonly.bin';
file_put_contents($fOnlyFirst, "\x1f\x00");
nok(smpro_upd_is_gzip($fOnlyFirst), 'is_gzip() false when only the first magic byte matches');

$fOnlySecond = $dir . '/secondonly.bin';
file_put_contents($fOnlySecond, "\x00\x8b");
nok(smpro_upd_is_gzip($fOnlySecond), 'is_gzip() false when only the second magic byte matches');

// missing file: @file_get_contents returns false -> '' -> strlen 0 -> false, no warning (the @ suppresses)
is_eq(smpro_upd_is_gzip($dir . '/does-not-exist.bin'), false, 'is_gzip() false for a non-existent file (suppressed read)');

/* ============================================================ *
 *  U28 — smpro_upd_cfg  (no file -> documented defaults)
 * ============================================================ */

// SMPRO_UPD_CFG points inside the sandbox VARLIB and does not exist yet → pure defaults.
ok(!is_file(SMPRO_UPD_CFG), 'precondition: update.json does not exist in the sandbox');
$cfg = smpro_upd_cfg();
is_eq($cfg, [
    'auto'        => false,
    'last_check'  => 0,
    'last_apply'  => 0,
    'last_result' => '',
    'latest'      => '',
    'channel'     => 'stable',
], 'cfg() returns the exact documented defaults when no file exists');
// individual keys (explicit, in case the deep array compare ever drifts)
is_eq($cfg['auto'], false, 'default auto === false');
is_eq($cfg['last_check'], 0, 'default last_check === 0');
is_eq($cfg['last_apply'], 0, 'default last_apply === 0');
is_eq($cfg['last_result'], '', 'default last_result === ""');
is_eq($cfg['latest'], '', 'default latest === ""');
is_eq($cfg['channel'], 'stable', 'default channel === stable');

// when a partial file exists, defaults FILL only the missing keys (array union $d + defaults).
// $d takes precedence for keys it defines; defaults supply the rest.
@is_dir(dirname(SMPRO_UPD_CFG)) || @mkdir(dirname(SMPRO_UPD_CFG), 0700, true);
file_put_contents(SMPRO_UPD_CFG, json_encode(['auto' => true, 'latest' => '1.0.200', 'extra' => 'kept']));
$cfg2 = smpro_upd_cfg();
is_eq($cfg2['auto'], true, 'file value wins over the default (auto=true)');
is_eq($cfg2['latest'], '1.0.200', 'file value wins over the default (latest)');
is_eq($cfg2['last_check'], 0, 'missing key is filled from the default (last_check=0)');
is_eq($cfg2['extra'], 'kept', 'an extra key present in the file is preserved');

// a corrupt / non-array JSON body -> treated as [] -> pure defaults again
file_put_contents(SMPRO_UPD_CFG, 'not-json{');
$cfg3 = smpro_upd_cfg();
is_eq($cfg3, [
    'auto'        => false,
    'last_check'  => 0,
    'last_apply'  => 0,
    'last_result' => '',
    'latest'      => '',
    'channel'     => 'stable',
], 'cfg() falls back to defaults when the file is not valid JSON');

/* ---- targets intentionally NOT tested here (need stubs/fixtures — Phase 3) ---- */
tap_skip('smpro_upd_check — needs stub (Phase 3)', 'calls smpro_lic_api() over the network');
tap_skip('smpro_upd_apply — needs stub (Phase 3)', 'shells out to curl/tar/cp and verifies RSA signatures');
tap_skip('smpro_upd_auto — needs stub (Phase 3)', 'drives check/apply + license calls');
