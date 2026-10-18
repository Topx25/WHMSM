<?php
/**
 * smpro_test.php — the ONLY entry point. Run as:
 *   /opt/cpanel/ea-php82/root/usr/bin/php tests/smpro_test.php [--layers ...] [--on-box] [--with-db] [--junit out/junit.xml] [--tap] [--filter str]
 *
 * Before running anything it enforces a non-negotiable safety posture so the lab is
 * "depend-on-it" AND physically incapable of running on production:
 *   1. Must be PHP CLI (the default `php` is a CGI wrapper with no STDOUT).
 *   2. Required extensions present.
 *   3. PRODUCTION LOCKOUT: /var/cpanel/mainip MUST be the TEST box IP, else abort loudly.
 *   4. Ensure the stub PATH exists (recording shims shadow csf/kill/systemctl/...).
 *   5. Print the active containment banner, then hand off to run.php.
 */
if (!defined('SMPRO_BOOT')) define('SMPRO_BOOT', 1);

/** IPs on which this suite is allowed to run. ONLY the TEST box. Production can never match. */
const SMPRO_TEST_ALLOWED_IPS = ['167.233.29.168'];

function die_unsafe($msg) {
    fwrite(STDERR, "\n*** SMPRO TEST LAB ABORTED ***\n" . $msg . "\n\n");
    exit(3);
}

/* 1. CLI only */
if (PHP_SAPI !== 'cli') die_unsafe("Not running under PHP CLI (SAPI=" . PHP_SAPI . "). Use /opt/cpanel/ea-php82/root/usr/bin/php — the default `php` is the CGI wrapper and produces no STDOUT.");

/* 2. PHP version + extensions */
if (PHP_VERSION_ID < 80000) die_unsafe("PHP >= 8.0 required, got " . PHP_VERSION);
$need = ['openssl', 'curl', 'json', 'mbstring'];
$argvStr = implode(' ', $argv);
if (strpos($argvStr, '--with-db') !== false) $need[] = 'sqlite3';
foreach ($need as $ext) if (!extension_loaded($ext)) die_unsafe("Required PHP extension missing: $ext");

/* 3. PRODUCTION LOCKOUT — the standing rule "never on production" enforced in code */
$mainipFile = '/var/cpanel/mainip';
$mainip = is_readable($mainipFile) ? trim((string)@file_get_contents($mainipFile)) : '';
if ($mainip === '') die_unsafe("Cannot read $mainipFile to verify this is the TEST box. Refusing to run (production safety).");
if (!in_array($mainip, SMPRO_TEST_ALLOWED_IPS, true)) {
    die_unsafe("This host's main IP is {$mainip}, which is NOT an allowed TEST IP (" . implode(', ', SMPRO_TEST_ALLOWED_IPS) . ").\n" .
               "The SM Pro test lab refuses to run anywhere but the designated TEST server. (Production is forbidden.)");
}

/* 4. Ensure the stub PATH (recording shims) exists */
$stub = __DIR__ . '/support/stub_path';
$mk   = __DIR__ . '/support/make_stubs.sh';
if (is_file($mk)) { @exec('sh ' . escapeshellarg($mk) . ' 2>&1', $o, $rc); }   // always refresh shims (picks up new ones)
if (!is_file($stub . '/csf')) {
    die_unsafe("Stub PATH not initialised ($stub/csf missing) and make_stubs.sh did not create it. Cannot guarantee csf/kill are shimmed.");
}
@chmod($stub, 0755);
foreach (glob($stub . '/*') ?: [] as $s) @chmod($s, 0755);

/* 4b. Refresh tests/.build (pubkey-swappable harness copy) so crypto tests run against current source */
$mkb = __DIR__ . '/support/make_build.sh';
if (is_file($mkb)) { @exec('sh ' . escapeshellarg($mkb) . ' 2>&1', $bo, $brc); }

/* 5. Banner */
$sapiPhp = PHP_BINARY;
fwrite(STDOUT, "Safety Monitor Pro — automated test lab\n");
fwrite(STDOUT, "  php       : $sapiPhp (" . PHP_VERSION . ")\n");
fwrite(STDOUT, "  host IP   : $mainip  (allowed TEST box ✓)\n");
fwrite(STDOUT, "  src root  : " . dirname(__DIR__) . "\n");
fwrite(STDOUT, "  stub PATH : $stub  (csf/kill/systemctl/sendmail/curl shimmed)\n");
fwrite(STDOUT, "  sandbox   : per-process under " . sys_get_temp_dir() . "/smpro_t_*  (no /var/lib/smpro writes)\n\n");

/* SAFETY NET: a few plugin functions write the HARDCODED real /etc/csf/csf.deny (path is not
 * sandboxable). Snapshot it and, on exit, restore it if any test mutated it — so the lab can NEVER
 * leave real firewall state changed even if a test reaches that write path. (csf itself is a recording
 * shim, so only the file is ever touched, never live iptables.) */
$csfDeny = '/etc/csf/csf.deny';
$csfSnap = is_file($csfDeny) ? @file_get_contents($csfDeny) : null;
if ($csfSnap !== false && $csfSnap !== null) {
    register_shutdown_function(function () use ($csfDeny, $csfSnap) {
        if (@file_get_contents($csfDeny) !== $csfSnap) {
            @file_put_contents($csfDeny, $csfSnap, LOCK_EX);
            fwrite(STDERR, "\n*** SMPRO TEST LAB: /etc/csf/csf.deny was modified by a test and has been RESTORED. A test must not write the real csf.deny. ***\n");
        }
    });
}

/* SAFETY NET #2: the live CGI render smoke spawns the real index.php, whose top-level calls install
 * crons to the HARDCODED /etc/cron.d. We neutralize those in the sandbox, but snapshot + restore the
 * real smpro crons on exit as a backstop so a test can never repoint or drop the live plugin's crons. */
$cronSnap = [];
foreach (glob('/etc/cron.d/smpro-*') ?: [] as $cf) $cronSnap[$cf] = @file_get_contents($cf);
register_shutdown_function(function () use ($cronSnap) {
    $changed = false;
    foreach ($cronSnap as $cf => $content) {
        if (@file_get_contents($cf) !== $content) { @file_put_contents($cf, $content); $changed = true; }
    }
    foreach (glob('/etc/cron.d/smpro-*') ?: [] as $cf) {
        if (!array_key_exists($cf, $cronSnap)) { @unlink($cf); $changed = true; }
    }
    if ($changed) fwrite(STDERR, "\n*** SMPRO TEST LAB: /etc/cron.d/smpro-* was modified by a test and has been RESTORED. ***\n");
});

/* hand off to the engine */
$GLOBALS['SMPRO_RUN_OPTS'] = null;   // run.php parses $argv itself
require __DIR__ . '/run.php';
