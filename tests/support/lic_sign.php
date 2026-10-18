<?php
/**
 * lic_sign.php — TEST RSA keypair + a signer that mirrors the plugin's EXACT verdict format.
 *
 * The plugin verifies a license block with:
 *   openssl_verify(json_encode($payload, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES),
 *                  base64_decode($block['signature']), SMPRO_LIC_PUBKEY, OPENSSL_ALGO_SHA256) === 1
 * (license.php:67-76). So a crypto test:
 *   1) defines SMPRO_LIC_PUBKEY = smpro_test_keypair()['pub']  (before requiring the .build copy)
 *   2) builds a payload, signs it here with the matching TEST private key
 *   3) asserts the plugin's verify_* accepts it, and that any tamper/rebind makes it fail.
 * The TEST keypair is generated once and cached under tests/fixtures/lic_keys/ (TEST-only; the
 * real private key is never on this box).
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

/** Persisted TEST keypair (RSA-2048). Returns ['priv'=>pem,'pub'=>pem]. */
function smpro_test_keypair(): array {
    $dir = SMPRO_BASE . '/tests/fixtures/lic_keys';
    @is_dir($dir) || @mkdir($dir, 0700, true);
    $pp = $dir . '/test_priv.pem';
    $up = $dir . '/test_pub.pem';
    if (!is_file($pp) || !is_file($up)) {
        $kp = smpro_test_new_keypair();
        file_put_contents($pp, $kp['priv']); @chmod($pp, 0600);
        file_put_contents($up, $kp['pub']);
    }
    return ['priv' => (string)file_get_contents($pp), 'pub' => (string)file_get_contents($up)];
}

/** A fresh, throwaway RSA-2048 keypair (e.g. to simulate a MITM/foreign signer). */
function smpro_test_new_keypair(): array {
    $r = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    if ($r === false) throw new \RuntimeException('openssl_pkey_new failed: ' . openssl_error_string());
    openssl_pkey_export($r, $priv);
    $det = openssl_pkey_get_details($r);
    return ['priv' => (string)$priv, 'pub' => (string)$det['key']];
}

/** Sign a payload array into a license block exactly as the license server does. */
function smpro_test_sign_block(array $payload, ?string $privPem = null): array {
    if ($privPem === null) { $kp = smpro_test_keypair(); $privPem = $kp['priv']; }
    $pk = openssl_pkey_get_private($privPem);
    if ($pk === false) throw new \RuntimeException('bad private key');
    $data = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    $sig = '';
    openssl_sign($data, $sig, $pk, OPENSSL_ALGO_SHA256);
    return ['payload' => $payload, 'signature' => base64_encode($sig)];
}
