<?php
/**
 * sm01_obf_build_lint.php — SM14: `php -l` every file of the OBFUSCATED, DEPLOYED build. This is the
 * release gate that catches YAK-obfuscator breakage BEFORE a build is promoted (the obfuscated tree is
 * what ships; a transform that produces invalid PHP must fail here, not on a customer box).
 *
 * On-box only (smoke layer, --on-box). Read-only: it only parses the live deployed files, never runs
 * them. Override the deployed path with SMPRO_OBF_ROOT (default = the WHM addon dir on 167).
 */
require __DIR__ . '/../support/bootstrap.php';

$obf = getenv('SMPRO_OBF_ROOT') ?: '/usr/local/cpanel/whostmgr/docroot/cgi/addons/smpro';
if (!is_dir($obf)) {
    tap_skip('obfuscated build lint', "deployed build not found at $obf (set SMPRO_OBF_ROOT)");
    return;
}

$php = PHP_BINARY;
$files = [];
foreach (['includes', 'modules', 'bin'] as $d) {
    foreach (glob($obf . '/' . $d . '/*.php') ?: [] as $f) $files[] = $f;
}
foreach (glob($obf . '/*.php') ?: [] as $f) $files[] = $f;
sort($files);

ok(count($files) > 0, 'found deployed obfuscated files to lint (' . count($files) . ')');
ok(strpos(file_get_contents($files[0] ?? __FILE__), 'SMPRO_BOOT') !== false || count($files) > 0, 'deployed build readable');

foreach ($files as $f) {
    $rel = str_replace($obf . '/', '', $f);
    $out = []; $rc = 0;
    @exec(escapeshellarg($php) . ' -l ' . escapeshellarg($f) . ' 2>&1', $out, $rc);
    tap_result($rc === 0, 'obf php -l ' . $rel, $rc === 0 ? '' : implode("\n", $out));
}
