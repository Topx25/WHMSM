<?php
/**
 * Safety Monitor Pro (smpro)
 * defines.php — single source of truth for paths/names.
 * Renaming for production = change values here only.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

// --- Identity ---
define('SMPRO_NAME',        'Safety Monitor Pro');
define('SMPRO_SLUG',        'smpro');
define('SMPRO_VERSION',     '1.1.10-beta368');

/* Safety Lock — the account-side page. These five names are read by bin/register_cpuser.sh, which finds them
 * by TEXT in this file. They were left behind when the account side was merged into this build: the files all
 * shipped, the installer ran, and it stopped with "SMPRO_CPS_SLUG came back empty" - so the page could never
 * be installed from a release, on any server. */
define('SMPRO_CPS_SLUG',    'safetylock');                      // dir + dynamicui_<slug>.conf + feature flag
define('SMPRO_CPS_NAME',    'Safety Lock');                    // what the account holder sees in cPanel
define('SMPRO_CPS_VENDOR',  'HostGuard');                      // /usr/local/cpanel/bin/admin/<Vendor>/
define('SMPRO_CPS_ADMIN',   'SafetyLock');                     // .../<Vendor>/<Module> — the root helper
define('SMPRO_CPS_GROUP',   'security');                       // which cPanel section it appears in
define('SMPRO_FN_PREFIX',   'smpro_');

// --- Brand ---
define('SMPRO_BRAND_COMPANY', 'HostGuard.org');            // parent brand — shown as "by HostGuard.org"
define('SMPRO_BRAND_TAGLINE', 'A HostGuard.org product');  // footer credit line
define('SMPRO_BRAND_URL',     'https://hostguard.org');    // brand site — the company name links here everywhere

// --- Code paths (inside WHM docroot) ---
define('SMPRO_BASE',        __DIR__ . '/..');               // .../cgi/addons/smpro
define('SMPRO_INCLUDES',    SMPRO_BASE . '/includes');
define('SMPRO_MODULES',     SMPRO_BASE . '/modules');
define('SMPRO_ASSETS_URL',  'index.cgi?asset=');            // assets served through router (no direct guess)

// --- Data paths (OUTSIDE web root) ---
// Guarded, so a harness can redirect state to a sandbox BEFORE booting the real include chain. The render
// smoke test (tests/support/render_one.php) boots every include exactly as index.php does and renders a page
// for real — the only way to catch a TypeError or an undefined variable inside a render path, which no
// source-text test can see. It must not write to the live state directories while doing it. Nothing in
// production pre-defines these, so the values below are what every server actually runs with.
if (!defined('SMPRO_VARLIB'))    define('SMPRO_VARLIB',    '/var/lib/smpro');
if (!defined('SMPRO_VARLOG'))    define('SMPRO_VARLOG',    '/var/log/smpro');
if (!defined('SMPRO_DB'))        define('SMPRO_DB',        SMPRO_VARLIB . '/smpro.db');
if (!defined('SMPRO_CACHE'))     define('SMPRO_CACHE',     SMPRO_VARLIB . '/cache');
if (!defined('SMPRO_LOCKS'))     define('SMPRO_LOCKS',     SMPRO_VARLIB . '/locks');

// --- Audit log ---
if (!defined('SMPRO_AUDIT_LOG')) define('SMPRO_AUDIT_LOG', SMPRO_VARLOG . '/audit.log');

// --- Resource limits (per plan §20/§28) ---
define('SMPRO_SCAN_NICE',          19);
define('SMPRO_SCAN_IONICE_CLASS',  3);
define('SMPRO_TIMEOUT_QUICK',      5);
define('SMPRO_TIMEOUT_NORMAL',     60);

// --- cPanel session prefix (passed from index.cgi) ---
define('SMPRO_CPSESS', getenv('SM_CPANEL_PREFIX') ?: '');

/* ---- extension polyfills: mbstring and posix are SEPARATE packages on ea-php / distro php. A worker that reached one
 *      mb_substr() on a box without them died with "undefined function", and the catch block died the same way. ---- */
if (!function_exists('mb_substr')) {
    function mb_substr($s, $start, $length = null, $encoding = null) { return $length === null ? substr((string)$s, (int)$start) : substr((string)$s, (int)$start, (int)$length); }
    function mb_strlen($s, $encoding = null) { return strlen((string)$s); }
    function mb_strpos($h, $n, $offset = 0, $encoding = null) { return strpos((string)$h, (string)$n, (int)$offset); }
    function mb_strtolower($s, $encoding = null) { return strtolower((string)$s); }
    function mb_strtoupper($s, $encoding = null) { return strtoupper((string)$s); }
    function mb_strcut($s, $start, $length = null, $encoding = null) { return $length === null ? substr((string)$s, (int)$start) : substr((string)$s, (int)$start, (int)$length); }
    function mb_check_encoding($s = null, $encoding = null) { return $s === null || preg_match('//u', (string)$s) === 1; }
    function mb_encode_mimeheader($s, $charset = 'UTF-8', $transfer = 'B', $linefeed = "\r\n", $indent = 0) { return preg_match('/[^\x20-\x7e]/', (string)$s) ? '=?UTF-8?B?' . base64_encode((string)$s) . '?=' : (string)$s; }
    function mb_decode_mimeheader($s) { return preg_replace_callback('/=\?([^?]+)\?([BbQq])\?([^?]*)\?=/', fn($m) => strtoupper($m[2]) === 'B' ? (string)base64_decode($m[3]) : quoted_printable_decode(str_replace('_', ' ', $m[3])), (string)$s); }
}
if (!function_exists('posix_getpwnam')) {
    function posix_getpwnam($name) {
        if (!preg_match('/^[a-zA-Z0-9._-]{1,64}$/', (string)$name)) return false;
        $l = trim((string)@shell_exec('getent passwd ' . escapeshellarg((string)$name) . ' 2>/dev/null'));
        $p = $l === '' ? [] : explode(':', $l); if (count($p) < 7) return false;
        return ['name' => $p[0], 'passwd' => $p[1], 'uid' => (int)$p[2], 'gid' => (int)$p[3], 'gecos' => $p[4], 'dir' => $p[5], 'shell' => $p[6]];
    }
    function posix_getpwuid($uid) {
        $l = trim((string)@shell_exec('getent passwd ' . (int)$uid . ' 2>/dev/null'));
        $p = $l === '' ? [] : explode(':', $l); if (count($p) < 7) return false;
        return ['name' => $p[0], 'passwd' => $p[1], 'uid' => (int)$p[2], 'gid' => (int)$p[3], 'gecos' => $p[4], 'dir' => $p[5], 'shell' => $p[6]];
    }
    function posix_geteuid() { return (int)trim((string)@shell_exec('id -u 2>/dev/null')); }
    function posix_kill($pid, $sig) { return trim((string)@shell_exec('kill -' . (int)$sig . ' ' . (int)$pid . ' >/dev/null 2>&1; echo $?')) === '0'; }
}
