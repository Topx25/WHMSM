<?php
/**
 * render_one.php — boot the REAL include chain and render ONE page, in an isolated process.
 *
 * WHY THIS EXISTS. Every other test in this suite either calls a pure function or asserts on source text,
 * because the lab has no WHM license and the router refuses to render there. That left the entire render path
 * untested, and twice it shipped a page that died on a customer's server while the lab stayed green:
 *   • 1.1.8 — index.cgi carried CRLF line endings; the shebang could not be executed; HTTP 500 on every page.
 *   • 1.1.10-beta184 — smpro_aa_bf_render() declared `array $back` while the caller passes a string; the
 *     Break-in Report tab died with a TypeError the moment it was opened.
 * Neither is visible to a grep. Both are caught the instant the page is actually rendered.
 *
 * WHAT IT DOES. Requires the same includes index.php requires, in the same order, with the same constants —
 * but with the data paths pointed at a sandbox and the stub PATH prepended, so nothing it runs can touch the
 * host's state, firewall, or mail. Then it renders one module the way the router does (output buffered, GET
 * only, never POST) and reports what happened. The module's own output is discarded; only its size is kept.
 *
 * IT DOES NOT bypass the licence. It never requires index.php, so the licence gate — which lives in the router,
 * not in the modules — is simply not on this path. There is no code here that a production install can reach.
 *
 * USAGE   php tests/support/render_one.php <module-id> [query-string] [sandbox-dir]
 * OUTPUT  exactly one marker line, last:
 *           RENDER_OK <bytes> warnings=<n>
 *           RENDER_FATAL <type>: <message> @ <file>:<line>
 *         preceded by one "WARN <message> @ <file>:<line>" line per distinct diagnostic.
 * EXIT    0 on a clean render, 1 on a fatal.
 */

$argvv   = $_SERVER['argv'] ?? [];
$id      = (string)($argvv[1] ?? '');
$qs      = (string)($argvv[2] ?? '');
$sandbox = (string)($argvv[3] ?? (rtrim(sys_get_temp_dir(), '/\\') . '/smpro_render_' . getmypid()));

if (!preg_match('/^[a-z0-9_-]+$/', $id)) { fwrite(STDERR, "usage: render_one.php <module-id> [query] [sandbox]\n"); exit(2); }

/* ---- 1. stub PATH first: before any include can exec() anything ---- */
$stub = __DIR__ . '/stub_path';
if (is_dir($stub)) putenv('PATH=' . $stub . PATH_SEPARATOR . getenv('PATH'));
putenv('SMPRO_TEST_REC=' . $sandbox . '/rec');

/* ---- 2. sandbox the state directories BEFORE defines.php runs (its data paths are guarded) ---- */
foreach (['', '/varlib', '/varlog', '/varlib/cache', '/varlib/locks', '/varlib/license', '/varlib/geoip', '/rec'] as $d) @mkdir($sandbox . $d, 0700, true);
define('SMPRO_BOOT', 1);
define('SMPRO_VARLIB',    $sandbox . '/varlib');
define('SMPRO_VARLOG',    $sandbox . '/varlog');
define('SMPRO_DB',        SMPRO_VARLIB . '/smpro.db');
define('SMPRO_CACHE',     SMPRO_VARLIB . '/cache');
define('SMPRO_LOCKS',     SMPRO_VARLIB . '/locks');
define('SMPRO_AUDIT_LOG', SMPRO_VARLOG . '/audit.log');

/* ---- 3. a GET request for this page, nothing else ---- */
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['SCRIPT_NAME']    = '/cgi/addons/smpro/index.cgi';
$_SERVER['REQUEST_URI']    = '/cgi/addons/smpro/index.cgi?page=' . $id . ($qs !== '' ? '&' . $qs : '');
$_SERVER['REMOTE_ADDR']    = '127.0.0.1';
$_SERVER['HTTP_USER_AGENT'] = 'smpro-render-smoke';
$_POST = [];
$_GET = [];
if ($qs !== '') parse_str($qs, $_GET);
$_GET['page'] = $id;

/* ---- 4. collect diagnostics; report a fatal as a marker instead of a silent empty page ---- */
$GLOBALS['__warn'] = [];
$GLOBALS['__done'] = false;
set_error_handler(function ($no, $str, $file, $line) {
    // Respect the @ operator. A custom handler is called even for suppressed diagnostics, and this code
    // suppresses deliberately (a filesize() on a log that does not exist yet is not a defect). Reporting those
    // would bury the diagnostics that matter under noise the author already decided was expected.
    if (!(error_reporting() & $no)) return true;
    // Deprecations from PHP-version drift are noise here; everything else is a real diagnostic.
    if ($no === E_DEPRECATED || $no === E_USER_DEPRECATED) return true;
    $k = $str . ' @ ' . basename((string)$file) . ':' . (int)$line;
    $GLOBALS['__warn'][$k] = ($GLOBALS['__warn'][$k] ?? 0) + 1;
    return true;   // never let a notice become output
});
register_shutdown_function(function () {
    while (ob_get_level() > 0) ob_end_clean();          // a module that exit()s mid-render must not print its buffer
    foreach (array_keys($GLOBALS['__warn']) as $w) echo 'WARN ' . $w . "\n";
    $e = error_get_last();
    if ($e && in_array((int)$e['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR], true)) {
        echo 'RENDER_FATAL ' . str_replace("\n", ' ', (string)$e['message']) . ' @ ' . basename((string)$e['file']) . ':' . (int)$e['line'] . "\n";
        exit(1);
    }
    if (empty($GLOBALS['__done'])) { echo "RENDER_FATAL render did not complete (the page exited before finishing)\n"; exit(1); }
});

/* ---- 5. boot exactly what index.php boots, in its order (read from index.php so the two cannot drift) ---- */
$root = dirname(__DIR__, 2);
$idx  = (string)@file_get_contents($root . '/index.php');
if ($idx === '') { echo "RENDER_FATAL index.php unreadable\n"; exit(1); }
preg_match_all("#^require __DIR__ \. '/includes/([a-z0-9_-]+)\.php';#mi", $idx, $m);
if (count($m[1]) < 20) { echo 'RENDER_FATAL could not read the boot list from index.php (found ' . count($m[1]) . ")\n"; exit(1); }
foreach ($m[1] as $inc) { $f = $root . '/includes/' . $inc . '.php'; if (is_file($f)) require_once $f; }

/* ---- 6. render the module the way the router does ---- */
// __selftest is not a page: it proves this harness can still SEE a failure. A detector that cannot fail is not
// a detector, and the whole point of this file is to fail when a render path breaks. tests/ is never packaged,
// so this branch exists on no server.
if ($id === '__selftest') {
    ob_start();
    (function (array $mustBeArray) { return $mustBeArray; })('a string, deliberately');   // TypeError, exactly like the one that shipped
    ob_end_clean();
    echo "RENDER_FATAL selftest did not throw" . PHP_EOL; $GLOBALS['__done'] = true; exit(1);
}
$mod = $root . '/modules/' . $id . '.php';
if (!is_file($mod)) { echo 'RENDER_FATAL no such module: ' . $id . "\n"; exit(1); }
$bytes = 0;
try {
    ob_start();
    require $mod;
    $bytes = strlen((string)ob_get_clean());
} catch (\Throwable $t) {
    while (ob_get_level() > 0) ob_end_clean();
    foreach (array_keys($GLOBALS['__warn']) as $w) echo 'WARN ' . $w . "\n";
    echo 'RENDER_FATAL ' . get_class($t) . ': ' . str_replace("\n", ' ', $t->getMessage()) . ' @ ' . basename($t->getFile()) . ':' . $t->getLine() . "\n";
    $GLOBALS['__done'] = true;   // the shutdown handler must not report a second, misleading failure
    exit(1);
}
$GLOBALS['__done'] = true;
foreach (array_keys($GLOBALS['__warn']) as $w) echo 'WARN ' . $w . "\n";
echo 'RENDER_OK ' . $bytes . ' warnings=' . count($GLOBALS['__warn']) . "\n";
exit(0);
