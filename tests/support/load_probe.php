<?php
/**
 * load_probe.php — minimal, TAP-free loader used to test whether ONE plugin file loads
 * cleanly under the harness env. Sets SMPRO_BOOT + sandboxed SMPRO_* constants, requires the
 * file given as argv[1] (optionally preloading helpers via argv[2]='helpers'), and:
 *   - prints "LOAD_OK" + exit 0 on a clean load
 *   - prints the warning/notice to STDERR + exit 7 on a warning
 *   - lets PHP exit non-zero on a fatal (the parent treats no-LOAD_OK as failure)
 * Deprecations are ignored (load-time only). Used by t03_load.php (one child per file).
 */
define('SMPRO_BOOT', 1);
error_reporting(E_ALL);
$warns = [];
set_error_handler(function ($no, $str, $file, $line) use (&$warns) {
    if (!(error_reporting() & $no)) return false;
    if ($no === E_DEPRECATED || $no === E_USER_DEPRECATED || $no === E_STRICT) return true;
    $warns[] = "[$no] $str @ " . basename($file) . ":$line";
    return true;
});

$root = dirname(dirname(__DIR__));                 // support -> tests -> plugin root
$sb = rtrim(sys_get_temp_dir(), '/\\') . '/smpro_probe_' . getmypid() . '_' . bin2hex(random_bytes(3));
foreach (['', '/cache', '/locks', '/license', '/hub', '/geoip'] as $d) @mkdir($sb . $d, 0700, true);
register_shutdown_function(function () use ($sb) {
    foreach (array_reverse(glob($sb . '/*') ?: []) as $p) { is_dir($p) ? @rmdir($p) : @unlink($p); }
    @rmdir($sb);
});

define('SMPRO_NAME', 'Safety Monitor Pro');
define('SMPRO_SLUG', 'smpro');
define('SMPRO_VERSION', '1.0.199');
define('SMPRO_FN_PREFIX', 'smpro_');
define('SMPRO_BASE', $root);
define('SMPRO_INCLUDES', $root . '/includes');
define('SMPRO_MODULES', $root . '/modules');
define('SMPRO_ASSETS_URL', 'index.cgi?asset=');
define('SMPRO_VARLIB', $sb);
define('SMPRO_VARLOG', $sb);
define('SMPRO_DB', $sb . '/smpro.db');
define('SMPRO_CACHE', $sb . '/cache');
define('SMPRO_LOCKS', $sb . '/locks');
define('SMPRO_AUDIT_LOG', $sb . '/audit.log');
define('SMPRO_SCAN_NICE', 19);
define('SMPRO_SCAN_IONICE_CLASS', 3);
define('SMPRO_TIMEOUT_QUICK', 5);
define('SMPRO_TIMEOUT_NORMAL', 60);
define('SMPRO_CPSESS', '');

if (($argv[2] ?? '') === 'helpers' && is_file(SMPRO_INCLUDES . '/helpers.php')) {
    require SMPRO_INCLUDES . '/helpers.php';
}
$f = $argv[1] ?? '';
if ($f === '' || !is_file($f)) { fwrite(STDERR, "no such file: $f"); exit(2); }
require $f;

if ($warns) { fwrite(STDERR, implode("\n", $warns)); exit(7); }
fwrite(STDOUT, "LOAD_OK\n");
exit(0);
