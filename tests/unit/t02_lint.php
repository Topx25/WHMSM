<?php
/**
 * t02_lint.php — `php -l` (syntax check) on EVERY plugin source file. Pure static check
 * (no code executes), so it is safe in the default hermetic run. This is the broad
 * "the whole tree parses" baseline; the same test, run on the obfuscated build in Phase 5,
 * is the YAK-breakage gate before a release is promoted.
 */
require __DIR__ . '/../support/bootstrap.php';

$php = PHP_BINARY;
$files = [];
foreach (['includes', 'modules', 'bin'] as $d) {
    foreach (glob(SMPRO_BASE . '/' . $d . '/*.php') ?: [] as $f) $files[] = $f;
}
if (is_file(SMPRO_BASE . '/index.php')) $files[] = SMPRO_BASE . '/index.php';
sort($files);

ok(count($files) > 0, 'found plugin source files to lint (' . count($files) . ')');

foreach ($files as $f) {
    $rel = str_replace(SMPRO_BASE . '/', '', $f);
    $out = []; $rc = 0;
    @exec(escapeshellarg($php) . ' -l ' . escapeshellarg($f) . ' 2>&1', $out, $rc);
    tap_result($rc === 0, 'php -l ' . $rel, $rc === 0 ? '' : implode("\n", $out));
}
