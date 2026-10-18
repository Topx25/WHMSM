<?php
/**
 * bootstrap.php — first line of EVERY test file: require __DIR__.'/../support/bootstrap.php';
 *
 * Responsibilities (in order):
 *   1. define SMPRO_BOOT (satisfies every include's `if(!defined('SMPRO_BOOT'))` guard).
 *   2. Locate the plugin source root (this tree's parent) and the optional .build copy.
 *   3. Create a per-process sandbox and define the full SMPRO_* constant set REDIRECTED to it,
 *      mirroring defines.php — so includes that only READ constants never touch /var/lib/smpro.
 *      (We never require the real defines.php in unit tests → no "already defined" collision.)
 *   4. Install an error handler that records warnings/notices and a shutdown handler that adds
 *      an automatic "no fatal" + "no warnings" assertion and prints the TAP plan LAST.
 *   5. Prepend the stub PATH so any exec() the code-under-test attempts hits recording shims,
 *      never the real csf/kill/systemctl/sendmail/curl.
 *   6. Load tap/assert/sandbox/stubfns helpers.
 *
 * Deprecations are reported as diagnostics, not failures, unless SMPRO_TEST_STRICT=1.
 */
if (defined('SMPRO_BOOT')) { /* already bootstrapped in this process */ }
else { define('SMPRO_BOOT', 1); }

error_reporting(E_ALL);

$__sup = __DIR__;                       // .../tests/support
$__tests = dirname($__sup);             // .../tests
$__root = dirname($__tests);            // plugin source root
$__build = $__tests . '/.build';        // patched harness copy (integration phases)

if (!defined('SMPRO_TEST_SRC'))   define('SMPRO_TEST_SRC', $__root);
if (!defined('SMPRO_TEST_BUILD')) define('SMPRO_TEST_BUILD', is_dir($__build) ? $__build : $__root);

require $__sup . '/sandbox.php';
$__sandbox = smpro_test_mksandbox();
putenv('SMPRO_TEST_REC=' . $__sandbox . '/rec');
$GLOBALS['__sandbox'] = $__sandbox;

/* --- SMPRO_* constants, REDIRECTED to the sandbox (mirrors defines.php) --- */
if (!defined('SMPRO_NAME'))       define('SMPRO_NAME', 'Safety Monitor Pro');
if (!defined('SMPRO_SLUG'))       define('SMPRO_SLUG', 'smpro');
if (!defined('SMPRO_VERSION'))    define('SMPRO_VERSION', '1.0.199');
if (!defined('SMPRO_FN_PREFIX'))  define('SMPRO_FN_PREFIX', 'smpro_');
if (!defined('SMPRO_BASE'))       define('SMPRO_BASE', SMPRO_TEST_SRC);          // read-only: source + integrity.json
if (!defined('SMPRO_INCLUDES'))   define('SMPRO_INCLUDES', SMPRO_BASE . '/includes');
if (!defined('SMPRO_MODULES'))    define('SMPRO_MODULES', SMPRO_BASE . '/modules');
if (!defined('SMPRO_ASSETS_URL')) define('SMPRO_ASSETS_URL', 'index.cgi?asset=');
if (!defined('SMPRO_VARLIB'))     define('SMPRO_VARLIB', $__sandbox . '/varlib');  // <-- sandbox, not /var/lib/smpro
if (!defined('SMPRO_VARLOG'))     define('SMPRO_VARLOG', $__sandbox . '/varlog');
if (!defined('SMPRO_DB'))         define('SMPRO_DB', SMPRO_VARLIB . '/smpro.db');
if (!defined('SMPRO_CACHE'))      define('SMPRO_CACHE', SMPRO_VARLIB . '/cache');
if (!defined('SMPRO_LOCKS'))      define('SMPRO_LOCKS', SMPRO_VARLIB . '/locks');
if (!defined('SMPRO_AUDIT_LOG'))  define('SMPRO_AUDIT_LOG', SMPRO_VARLOG . '/audit.log');
if (!defined('SMPRO_SCAN_NICE'))          define('SMPRO_SCAN_NICE', 19);
if (!defined('SMPRO_SCAN_IONICE_CLASS'))  define('SMPRO_SCAN_IONICE_CLASS', 3);
if (!defined('SMPRO_TIMEOUT_QUICK'))      define('SMPRO_TIMEOUT_QUICK', 5);
if (!defined('SMPRO_TIMEOUT_NORMAL'))     define('SMPRO_TIMEOUT_NORMAL', 60);
if (!defined('SMPRO_CPSESS'))     define('SMPRO_CPSESS', '');

/* --- stub PATH: recording shims shadow real dangerous binaries --- */
$__stubpath = $__sup . '/stub_path';
if (is_dir($__stubpath)) {
    putenv('PATH=' . $__stubpath . PATH_SEPARATOR . getenv('PATH'));
}

/* --- warning capture --- */
$GLOBALS['__warns'] = [];
$GLOBALS['__suppress_warn'] = false;
$__strict = getenv('SMPRO_TEST_STRICT') === '1';
set_error_handler(function ($no, $str, $file, $line) use ($__strict) {
    if (!(error_reporting() & $no)) return false;           // respect @-suppression and the active level
    $soft = ($no === E_DEPRECATED || $no === E_USER_DEPRECATED || $no === E_STRICT);
    $GLOBALS['__warns'][] = [
        'fail' => $soft ? $__strict : true,
        'msg'  => '[' . $no . '] ' . $str . ' @ ' . basename($file) . ':' . $line,
    ];
    return true;
});

require $__sup . '/tap.php';
require $__sup . '/assert.php';
require $__sup . '/stubfns.php';

/* --- shutdown: auto "no fatal" + "no warnings" assertions, then the plan line --- */
register_shutdown_function(function () {
    $fatal = error_get_last();
    if ($fatal && in_array($fatal['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_RECOVERABLE_ERROR], true)) {
        tap_result(false, 'no fatal error', $fatal['message'] . ' @ ' . basename($fatal['file']) . ':' . $fatal['line']);
    }
    $warns = $GLOBALS['__warns'] ?? [];
    $hard  = array_values(array_filter($warns, fn($w) => $w['fail']));
    $soft  = array_values(array_filter($warns, fn($w) => !$w['fail']));
    if ($soft) tap_diag(count($soft) . ' deprecation(s): ' . implode(' | ', array_column($soft, 'msg')));
    if (empty($GLOBALS['__suppress_warn'])) {
        tap_result(empty($hard), 'no PHP warnings/notices',
            $hard ? implode("\n", array_column($hard, 'msg')) : '');
    }
    tap_done();
});
