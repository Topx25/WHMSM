<?php
/**
 * r04_lint_and_switches.php — Phase-4 REGRESSION (lock documented past bugs shut).
 *
 *   R22  shell-injection STATIC LINT — scan every includes/*.php + modules/*.php + bin/*.php
 *        source file and assert ZERO statements pass a RAW superglobal ($_GET/$_POST/$_REQUEST/
 *        $_COOKIE) directly into a shell sink (shell_exec/exec/system/popen/proc_open/passthru)
 *        on the same call without escapeshellarg/escapeshellcmd/(int)/intval. This is a real,
 *        high-value guard: a future edit that pipes user input into a shell would reopen a
 *        command-injection bug and this lint would go red. It is deliberately CONSERVATIVE
 *        (token-based; flags only a superglobal token literally inside the sink-call argument)
 *        so it never false-positives on the existing "read into a sanitized var first" style.
 *
 *   R20  disabled master-switch — smpro_ctl_disabled() must be TRUE when control mode is
 *        'disabled' (the bin/* crons exit early on it, e.g. cooler_tick.php line 12). We seed
 *        the sandbox SMPRO_VARLIB/control.json and assert the gate actually closes / opens.
 *
 * SAFETY: pure source-text analysis + a JSON file in the sandbox VARLIB. No exec, no net, no csf.
 */
require __DIR__ . '/../support/bootstrap.php';

/* ============================================================================
 * R22 — shell-injection static lint (conservative, token_get_all based)
 * ==========================================================================*/

/**
 * Return a list of "file:line sink" findings where a raw superglobal is used
 * literally inside a shell-sink call argument with no escaping on the same call.
 */
function r04_lint_file($path) {
    $sinks    = ['shell_exec', 'exec', 'system', 'popen', 'proc_open', 'passthru'];
    $supers   = ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE'];
    $escapers = ['escapeshellarg', 'escapeshellcmd', 'intval'];

    $src  = (string) @file_get_contents($path);
    if ($src === '') return [];
    $toks = @token_get_all($src);
    $n    = count($toks);
    $findings = [];

    for ($i = 0; $i < $n; $i++) {
        $t = $toks[$i];
        if (!is_array($t) || $t[0] !== T_STRING) continue;
        if (!in_array(strtolower($t[1]), $sinks, true)) continue;

        // Skip method/static calls and the `function exec(){}` declaration token —
        // only a free function call ` exec(` is a shell sink.
        $j = $i - 1;
        while ($j >= 0 && is_array($toks[$j])
            && in_array($toks[$j][0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) $j--;
        if ($j >= 0 && is_array($toks[$j]) && in_array($toks[$j][0],
                [T_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION, T_NULLSAFE_OBJECT_OPERATOR], true)) continue;

        // Must be immediately followed by `(` to be a call.
        $k = $i + 1;
        while ($k < $n && is_array($toks[$k])
            && in_array($toks[$k][0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) $k++;
        if ($k >= $n || $toks[$k] !== '(') continue;

        // Capture the balanced argument-list tokens (the call's own parens only).
        $depth = 0; $arg = []; $line = (int) $t[2];
        for ($m = $k; $m < $n; $m++) {
            $tt = $toks[$m];
            if ($tt === '(') { $depth++; if ($depth === 1) continue; }
            elseif ($tt === ')') { $depth--; if ($depth === 0) break; }
            $arg[] = $tt;
        }

        $hasSuper = $hasEsc = $hasCast = false;
        foreach ($arg as $a) {
            if (is_array($a) && $a[0] === T_VARIABLE && in_array($a[1], $supers, true)) $hasSuper = true;
            if (is_array($a) && $a[0] === T_STRING && in_array(strtolower($a[1]), $escapers, true)) $hasEsc = true;
            if (is_array($a) && $a[0] === T_INT_CAST) $hasCast = true;
        }
        if ($hasSuper && !$hasEsc && !$hasCast) {
            $findings[] = basename($path) . ':' . $line . ' (sink=' . $t[1] . ')';
        }
    }
    return $findings;
}

$dirs  = [SMPRO_BASE . '/includes', SMPRO_BASE . '/modules', SMPRO_BASE . '/bin'];
$files = [];
foreach ($dirs as $d) foreach ((array) glob($d . '/*.php') as $f) $files[] = $f;

ok(count($files) > 0, 'R22 lint: found PHP source files to scan (' . count($files) . ')');
ok(count($files) >= 60, 'R22 lint: scanned the full source surface (>=60 files: includes+modules+bin)');

$all = [];
foreach ($files as $f) $all = array_merge($all, r04_lint_file($f));

is_eq($all, [], 'R22 ZERO raw-superglobal-into-shell-sink statements across all source');

/* Self-test the linter on a synthetic snippet so a future "always returns []" bug
 * (e.g. token logic broken) can't make R22 pass vacuously. Written to the sandbox only. */
$bad = SMPRO_VARLIB . '/r04_bad_sample.php';
@file_put_contents($bad, "<?php\n\$x = shell_exec('grep ' . \$_GET['q']);\n");
$good = SMPRO_VARLIB . '/r04_good_sample.php';
@file_put_contents($good, "<?php\n\$x = shell_exec('grep ' . escapeshellarg(\$_GET['q']));\n\$y = exec('id -u ' . (int)\$_POST['uid']);\n");

ok(count(r04_lint_file($bad)) === 1,  'R22 linter self-test: DETECTS a raw $_GET inside shell_exec (not vacuous)');
has(r04_lint_file($bad)[0], 'sink=shell_exec', 'R22 linter self-test: names the offending sink');
is_eq(r04_lint_file($good), [],            'R22 linter self-test: escapeshellarg + (int) are correctly treated as safe');
@unlink($bad); @unlink($good);

/* ============================================================================
 * R20 — disabled master-switch gate (the bin/* crons exit on smpro_ctl_disabled())
 * ==========================================================================*/

require SMPRO_TEST_BUILD . '/includes/helpers.php';   // defines smpro_ctl_get/mode/disabled + smpro_ctl_file

ok(function_exists('smpro_ctl_disabled'), 'R20 smpro_ctl_disabled() loaded from helpers');
is_eq(smpro_ctl_file(), SMPRO_VARLIB . '/control.json', 'R20 control file resolves into the sandbox VARLIB');

/** Seed control.json with a given mode (reenable_at=0 so auto-reenable can never flip it). */
$seed = function ($mode, $reenable_at = 0) {
    @mkdir(SMPRO_VARLIB, 0700, true);
    @file_put_contents(SMPRO_VARLIB . '/control.json',
        json_encode(['mode' => $mode, 'reenable_at' => $reenable_at, 'updated_at' => time(), 'actor' => 'r04']));
};

/* default / no file → enabled, gate OPEN (crons run) */
@unlink(SMPRO_VARLIB . '/control.json');
is_eq(smpro_ctl_mode(), 'enabled', 'R20 no control.json -> mode defaults to enabled');
is_eq(smpro_ctl_disabled(), false, 'R20 enabled (default) -> gate OPEN (crons run)');

/* dryrun → still not "disabled" (monitor-only is a different state) */
$seed('dryrun');
is_eq(smpro_ctl_mode(), 'dryrun', 'R20 dryrun mode read back from control.json');
is_eq(smpro_ctl_disabled(), false, 'R20 dryrun -> NOT disabled (gate stays open; only autopilot is off)');
is_eq(smpro_ctl_dry_run(), true,  'R20 dryrun -> dry_run() true');

/* disabled → gate CLOSED (the documented master switch; bin crons exit) */
$seed('disabled');
is_eq(smpro_ctl_mode(), 'disabled',  'R20 disabled mode read back from control.json');
is_eq(smpro_ctl_disabled(), true,    'R20 disabled -> smpro_ctl_disabled() TRUE (bin crons gate to exit)');
is_eq(smpro_ctl_dry_run(), false,    'R20 disabled -> dry_run() false (it is a full stop, not monitor-only)');

/* an UNKNOWN mode falls back to enabled (no accidental disable / no accidental run-amok) */
$seed('bogus-mode');
is_eq(smpro_ctl_mode(), 'enabled',   'R20 invalid mode value -> sanitized back to enabled');
is_eq(smpro_ctl_disabled(), false,   'R20 invalid mode -> gate OPEN (fails safe to enabled, not stuck-off)');

/* re-enable after disable is honored (reversible master switch, no lingering stop) */
$seed('disabled');
is_eq(smpro_ctl_disabled(), true,  'R20 re-disable -> closed again');
$seed('enabled');
is_eq(smpro_ctl_disabled(), false, 'R20 flip back to enabled -> gate OPEN again (reversible)');
