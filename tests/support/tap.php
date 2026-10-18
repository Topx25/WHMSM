<?php
/**
 * tap.php — TAP v13 emitter for a single child test process.
 *
 * Each test file runs in its OWN ea-php82 process (constant-collision isolation),
 * prints TAP to STDOUT, and tests/run.php aggregates the children.
 *
 * We do NOT print the plan line here; bootstrap.php's shutdown handler prints
 * "1..N" last (after the auto "no fatal / no warnings" assertions), so the plan
 * always matches the real assertion count even if the test body dies early.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

if (!isset($GLOBALS['__tap'])) $GLOBALS['__tap'] = ['n' => 0, 'fail' => 0, 'skip' => 0];

/** Emit a TAP diagnostic block ("# ..." lines). */
function tap_diag($msg) {
    foreach (explode("\n", rtrim((string)$msg, "\n")) as $l) {
        fwrite(STDOUT, '# ' . $l . "\n");
    }
}

/** Core result line. $ok bool, $name short label, $diag optional multi-line detail on failure. */
function tap_result($ok, $name, $diag = '') {
    $t = &$GLOBALS['__tap'];
    $t['n']++;
    $name = trim(str_replace(["\r", "\n"], ' ', (string)$name));
    fwrite(STDOUT, ($ok ? 'ok ' : 'not ok ') . $t['n'] . ' - ' . $name . "\n");
    if (!$ok) {
        $t['fail']++;
        if ($diag !== '') tap_diag($diag);
    }
    return (bool)$ok;
}

/** A skipped test still counts in the plan but never fails. */
function tap_skip($name, $why = '') {
    $t = &$GLOBALS['__tap'];
    $t['n']++;
    $t['skip']++;
    $name = trim(str_replace(["\r", "\n"], ' ', (string)$name));
    fwrite(STDOUT, 'ok ' . $t['n'] . ' - ' . $name . ' # SKIP ' . $why . "\n");
}

/** Print the trailing plan line. Called once, by bootstrap's shutdown handler. */
function tap_done() {
    if (!empty($GLOBALS['__tap_done'])) return;
    $GLOBALS['__tap_done'] = true;
    fwrite(STDOUT, '1..' . $GLOBALS['__tap']['n'] . "\n");
}
