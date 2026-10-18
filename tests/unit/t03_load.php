<?php
/**
 * t03_load.php — every includes/*.php must LOAD cleanly under the harness (require, not just
 * lint). Each include is probed in its OWN child process (load_probe.php): first standalone,
 * and if that fails, again with helpers.php preloaded. A file that loads only WITH helpers is
 * reported as such (informs which unit tests must preload helpers). This is also a permanent
 * regression guard: a future include that breaks standalone-loadability turns this red.
 */
require __DIR__ . '/../support/bootstrap.php';

$probe = SMPRO_BASE . '/tests/support/load_probe.php';
ok(is_file($probe), 'load_probe.php present');

$files = glob(SMPRO_BASE . '/includes/*.php') ?: [];
sort($files);
ok(count($files) > 0, 'found includes to probe (' . count($files) . ')');

$php = escapeshellarg(PHP_BINARY);
foreach ($files as $f) {
    $rel = 'includes/' . basename($f);

    // defines.php is the constant SOURCE — the harness supplies those constants, so tests never
    // require it; re-requiring it here would (correctly) warn "already defined". Skip by design.
    if (basename($f) === 'defines.php') { tap_skip("load $rel", 'constant source — never required by tests'); continue; }

    $out = []; $rc = 0;
    @exec($php . ' ' . escapeshellarg($probe) . ' ' . escapeshellarg($f) . ' 2>&1', $out, $rc);
    if ($rc === 0 && in_array('LOAD_OK', $out, true)) {
        tap_result(true, "load $rel (standalone)");
        continue;
    }

    // retry with helpers preloaded
    $out2 = []; $rc2 = 0;
    @exec($php . ' ' . escapeshellarg($probe) . ' ' . escapeshellarg($f) . ' helpers 2>&1', $out2, $rc2);
    if ($rc2 === 0 && in_array('LOAD_OK', $out2, true)) {
        tap_result(true, "load $rel (needs helpers preloaded)");
        continue;
    }

    tap_result(false, "load $rel", "standalone: " . implode(' | ', array_slice($out, 0, 4))
        . "\nwith helpers: " . implode(' | ', array_slice($out2, 0, 4)));
}
