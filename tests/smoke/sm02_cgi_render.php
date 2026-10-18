<?php
/**
 * sm02_cgi_render.php — LIVE CGI render smoke (SM05/SM06/SM09-SM13). Spawns the REAL front controller
 * (index.php) out-of-process for a set of read-only pages and asserts each renders HTML with NO PHP
 * fatal/parse error — the only place the full boot→gate→route→render pipeline actually executes.
 *
 * SAFETY (this is the riskiest test, hence --on-box only):
 *  - runs against a SANDBOXED copy (tests/support/make_cgi_sandbox.sh): data dirs redirected to a temp tree,
 *    the cron-install / hub-tick side effects neutralized (they write the REAL /etc/cron.d), terms pre-accepted.
 *  - child PATH is poisoned (stub_path first) so any exec hits a recording shim, never a real tool.
 *  - it SNAPSHOTS /etc/cron.d/smpro-* before/after and asserts they are UNCHANGED (no real-cron mutation).
 *  - sandboxes are removed on exit.
 */
require __DIR__ . '/../support/bootstrap.php';

$mk = SMPRO_BASE . '/tests/support/make_cgi_sandbox.sh';
ok(is_file($mk), 'make_cgi_sandbox.sh present');

$stub = SMPRO_BASE . '/tests/support/stub_path';
$php  = PHP_BINARY;

/** Build a sandbox; returns its path (last line of the helper output). */
$build = function ($mode) use ($mk) {
    $out = []; $rc = 0;
    @exec('sh ' . escapeshellarg($mk) . ' ' . escapeshellarg($mode) . ' 2>/dev/null', $out, $rc);
    $sb = trim((string)end($out));
    return ($rc === 0 && $sb !== '' && is_dir($sb)) ? $sb : '';
};

/** Spawn the sandboxed index.php for one page. Returns [exit, stdout, stderr]. */
$cgi = function ($sb, $query) use ($php, $stub) {
    $env = $_ENV;
    $env['QUERY_STRING'] = $query;
    $env['REQUEST_METHOD'] = 'GET';
    $env['PATH'] = $stub . PATH_SEPARATOR . (getenv('PATH') ?: '/usr/bin:/bin');
    $desc = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $p = @proc_open([$php, $sb . '/plugin/index.php'], $desc, $pipes, $sb . '/plugin', $env);
    if (!is_resource($p)) return [-1, '', 'proc_open failed'];
    stream_set_blocking($pipes[1], false); stream_set_blocking($pipes[2], false);
    $out = ''; $err = ''; $t0 = microtime(true); $exit = null;
    while (true) {
        $st = proc_get_status($p);
        $out .= stream_get_contents($pipes[1]); $err .= stream_get_contents($pipes[2]);
        if (!$st['running']) { $exit = $st['exitcode']; break; }
        if (microtime(true) - $t0 > 20) { proc_terminate($p, 9); $exit = 124; usleep(80000); break; }
        usleep(10000);
    }
    $out .= stream_get_contents($pipes[1]); $err .= stream_get_contents($pipes[2]);
    fclose($pipes[1]); fclose($pipes[2]); proc_close($p);
    return [$exit, $out, $err];
};

// CONTENT signature (filenames + body) — NOT `ls -la`, so a benign mtime change can't false-positive;
// only a real content/target change (or a new/removed cron) trips it.
$cronSig = function () { $h = ''; foreach (glob('/etc/cron.d/smpro-*') ?: [] as $f) $h .= basename($f) . ':' . md5((string)@file_get_contents($f)) . ';'; return md5($h); };
$assertRender = function ($label, $r) {
    [$exit, $out, $err] = $r;
    nok($exit === 124, "$label: did not hang (no timeout)");
    is_eq(preg_match('/(Fatal error|Parse error|Uncaught)/i', $err), 0, "$label: no PHP fatal/parse error on stderr");
    ok(strlen($out) > 200 && (stripos($out, '<html') !== false || stripos($out, '<!doctype') !== false), "$label: rendered an HTML page (" . strlen($out) . " bytes)");
};

$sbOff = $build('off');
$sbOn  = $build('on');
ok($sbOff !== '', 'enforce-off CGI sandbox built');
ok($sbOn !== '', 'enforce-on CGI sandbox built');
register_shutdown_function(function () use ($sbOff, $sbOn) {
    foreach ([$sbOff, $sbOn] as $sb) if ($sb && strpos($sb, 'smpro_cgi.') !== false) smpro_test_rmrf($sb);
});

$cronBefore = $cronSig();

if ($sbOff !== '') {
    /* SM06/SM09-SM13: every read-only page renders cleanly with the gate disabled */
    foreach (['dashboard', 'intrusion-monitor', 'load-monitor', 'firewall-status', 'network', 'site-doctor', 'updates', 'license'] as $page) {
        $assertRender('render ' . $page, $cgi($sbOff, 'page=' . $page));
    }
}

if ($sbOn !== '') {
    /* SM05 / B2: with enforcement ON and NO valid license, the License page MUST stay reachable (not 403/fatal),
       and any other page is gated to the License page — never a crash. (curl is shimmed → no real network.) */
    $lic = $cgi($sbOn, 'page=license');
    $assertRender('B2 enforce-on ?page=license', $lic);
    has($lic[1], 'icense', 'SM05/B2: License page renders its content under enforcement (recovery path reachable)');

    $gated = $cgi($sbOn, 'page=dashboard');
    nok($gated[0] === 124, 'B2 enforce-on ?page=dashboard: did not hang');
    is_eq(preg_match('/(Fatal error|Parse error|Uncaught)/i', $gated[2]), 0, 'B2 enforce-on gated dashboard: no fatal (clean license-gate redirect, not a brick)');
}

is_eq($cronSig(), $cronBefore, 'SAFETY: /etc/cron.d/smpro-* UNCHANGED by the CGI render smoke (no real-cron mutation)');
