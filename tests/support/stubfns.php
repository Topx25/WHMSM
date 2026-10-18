<?php
/**
 * stubfns.php — PHP-level seam stubs (first-definition-wins).
 *
 * The plugin's `tests/.build` copy wraps a handful of side-effecting "callee" functions
 * (e.g. smpro_lic_server_ip, smpro_ip_intel, smpro_self_uninstall) in `if(!function_exists())`.
 * A test that needs to control such a callee calls smpro_test_install_stubs([...]) BEFORE
 * requiring the .build include — so our stub is defined first and the real one is skipped.
 *
 * Phase 0 does NOT call this (mmdb.php has no seams), so nothing here is active by default;
 * requiring real `includes/*` is therefore safe (no redeclare). Integration phases require
 * from `tests/.build` and opt in.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

$GLOBALS['__stub'] = $GLOBALS['__stub'] ?? [];

/** Set/override a stubbed value the seam functions return. */
function smpro_stub_set($key, $val) { $GLOBALS['__stub'][$key] = $val; }
/** Read a stubbed value (with default). */
function smpro_stub_get($key, $default = null) { return $GLOBALS['__stub'][$key] ?? $default; }

/**
 * Define the seam functions (idempotent, function_exists-guarded). Seed values via $vals.
 * Extend this set as integration phases require more seams; each MUST be guarded so it only
 * "wins" when the real defining file is the wrapped .build copy.
 */
function smpro_test_install_stubs(array $vals = []) {
    foreach ($vals as $k => $v) smpro_stub_set($k, $v);

    if (!function_exists('smpro_lic_server_ip')) {
        function smpro_lic_server_ip() { return smpro_stub_get('server_ip', '192.0.2.10'); }
    }
    if (!function_exists('smpro_lic_fingerprint')) {
        function smpro_lic_fingerprint() { return smpro_stub_get('fingerprint', str_repeat('a', 64)); }
    }
    // server identity — smpro_server_ips() returns a MAP (ip => meta); is_bareip_host uses array_keys()
    if (!function_exists('smpro_server_ips')) {
        function smpro_server_ips() { return smpro_stub_get('server_ips', ['192.0.2.10' => 1]); }
    }
    if (!function_exists('smpro_is_server_ip')) {
        function smpro_is_server_ip($ip) { return array_key_exists((string)$ip, smpro_stub_get('server_ips', ['192.0.2.10' => 1])); }
    }
    // geo/asn intel — keyed by IP; real signature is ($ip, $cap=true) and the result carries 'country'
    if (!function_exists('smpro_ip_intel')) {
        function smpro_ip_intel($ip, $cap = true) {
            $m = smpro_stub_get('ip_intel', []);
            return $m[$ip] ?? ['country' => '', 'asn' => '', 'provider' => '', 'datacenter' => false];
        }
    }
    // datacenter test — real takes the intel ARRAY; honor an explicit 'datacenter' flag, else match provider keyword
    if (!function_exists('smpro_ip_is_datacenter')) {
        function smpro_ip_is_datacenter($intel) {
            if (is_array($intel) && array_key_exists('datacenter', $intel)) return (bool)$intel['datacenter'];
            $p = is_array($intel) ? (string)($intel['provider'] ?? '') : (string)$intel;
            return in_array($p, smpro_stub_get('datacenters', []), true);
        }
    }
}
