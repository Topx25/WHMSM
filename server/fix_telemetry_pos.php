<?php
/**
 * fix_telemetry_pos.php — telemetry_ext.php was required AFTER the /api/check dispatch (too late;
 * json_response exits first). Add an EARLY require before the API dispatch block so the helpers
 * exist when api_activate_or_check runs. Idempotent + backup + lint-guard.
 */
$idx = __DIR__ . '/index.php';
$src = file_get_contents($idx);
if ($src === false) { fwrite(STDERR, "cannot read\n"); exit(1); }

$early = "require_once __DIR__ . '/telemetry_ext.php';";
$anchor = "if (in_array(\$path, ['/api/activate', '/api/check'], true) && (\$_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {";

if (substr_count($src, $anchor) !== 1) { fwrite(STDERR, "anchor count != 1\n"); exit(2); }

$insert = "// telemetry helpers must load BEFORE the /api/check dispatch (handler exits via json_response)\n" . $early . "\n";
if (strpos($src, $insert) !== false) { echo "already fixed\n"; exit(0); }

$bak = $idx . '.bak_telfix_' . date('Ymd_His');
copy($idx, $bak);
$src = str_replace($anchor, $insert . $anchor, $src);
file_put_contents($idx, $src);

$lint = shell_exec('php -l ' . escapeshellarg($idx) . ' 2>&1');
echo "backup: $bak\nlint: " . trim((string)$lint) . "\n";
if (strpos((string)$lint, 'No syntax errors') === false) { copy($bak, $idx); fwrite(STDERR, "LINT FAILED — reverted\n"); exit(3); }
echo "FIXED OK\n";
