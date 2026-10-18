<?php
/**
 * secret.php — encrypt sensitive config values at rest (Telegram/WhatsApp/Pushbullet tokens, SMTP pass).
 * AES-256-GCM with a per-server key file (0600). Values are stored as "enc:v1:<base64(iv|tag|ct)>".
 * Decrypt is passthrough for non-prefixed (plaintext/legacy) values so migration is seamless.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

define('SMPRO_SECRET_KEY_FILE', SMPRO_VARLIB . '/.secret.key');

function smpro_secret_key(): string {
    static $k = null; if ($k !== null) return $k;
    $f = SMPRO_SECRET_KEY_FILE;
    if (is_readable($f)) { $d = base64_decode(trim((string)@file_get_contents($f)), true); if (is_string($d) && strlen($d) === 32) return $k = $d; }
    $k = random_bytes(32);
    @is_dir(dirname($f)) || @mkdir(dirname($f), 0700, true);
    $um = umask(077); @file_put_contents($f, base64_encode($k), LOCK_EX); umask($um); @chmod($f, 0600);   // born 0600: no window where another local user can read it
    return $k;
}
function smpro_secret_enc(string $plain): string {
    if ($plain === '' || !function_exists('openssl_encrypt')) return $plain;
    if (strpos($plain, 'enc:v1:') === 0) return $plain;                  // already encrypted
    $iv = random_bytes(12); $tag = '';
    $ct = openssl_encrypt($plain, 'aes-256-gcm', smpro_secret_key(), OPENSSL_RAW_DATA, $iv, $tag, 'smpro', 16);
    return $ct === false ? $plain : ('enc:v1:' . base64_encode($iv . $tag . $ct));
}
function smpro_secret_dec(string $val): string {
    if (strpos($val, 'enc:v1:') !== 0) return $val;                       // plaintext/legacy passthrough
    if (!function_exists('openssl_decrypt')) return '';
    $blob = base64_decode(substr($val, 7), true); if (!is_string($blob) || strlen($blob) < 29) return '';
    $p = openssl_decrypt(substr($blob, 28), 'aes-256-gcm', smpro_secret_key(), OPENSSL_RAW_DATA, substr($blob, 0, 12), substr($blob, 12, 16), 'smpro');
    return $p === false ? '' : $p;
}
function smpro_secret_is_enc(string $val): bool { return strpos($val, 'enc:v1:') === 0; }

/* tiny nested get/set for config secret fields (path = array of keys) */
function smpro_secret_get(array $a, array $path) { foreach ($path as $k) { if (!is_array($a) || !array_key_exists($k, $a)) return null; $a = $a[$k]; } return $a; }
function smpro_secret_set(array &$a, array $path, $v): void { $r = &$a; foreach ($path as $k) { if (!is_array($r)) $r = []; if (!array_key_exists($k, $r)) $r[$k] = []; $r = &$r[$k]; } $r = $v; }
