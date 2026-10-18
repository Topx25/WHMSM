<?php
/** patch_plans_seed.php — run plans migration EARLY (every request), so the table seeds without an admin page-load. */
$idx = __DIR__ . '/index.php';
$src = file_get_contents($idx);
if ($src === false) { fwrite(STDERR, "read fail\n"); exit(1); }
if (strpos($src, 'PLANS_EARLY_SEED') !== false) { echo "already\n"; exit(0); }

$anchor = "require_once __DIR__ . '/telemetry_ext.php';";
$pos = strpos($src, $anchor);   // first (early) occurrence
if ($pos === false) { fwrite(STDERR, "anchor not found\n"); exit(2); }
$ins = $anchor . "\nrequire_once __DIR__ . '/plans_ext.php'; /* PLANS_EARLY_SEED */ if (function_exists('splan_migrate')) splan_migrate();";

$bak = $idx . '.bak_plseed_' . date('Ymd_His');
copy($idx, $bak);
$src = substr($src, 0, $pos) . $ins . substr($src, $pos + strlen($anchor));
file_put_contents($idx, $src);

$lint = shell_exec('php -l ' . escapeshellarg($idx) . ' 2>&1');
echo "backup: $bak\nlint: " . trim((string)$lint) . "\n";
if (strpos((string)$lint, 'No syntax errors') === false) { copy($bak, $idx); fwrite(STDERR, "LINT FAILED — reverted\n"); exit(3); }
echo "EARLY SEED WIRED\n";
