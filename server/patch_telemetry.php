<?php
/**
 * patch_telemetry.php — wires telemetry_ext.php into public/index.php (Phase A).
 * Idempotent + safe: backs up first, requires EXACTLY one match per anchor, aborts otherwise.
 * Run:  php patch_telemetry.php   (from the public/ dir on the license server)
 */
$idx = __DIR__ . '/index.php';
$src = file_get_contents($idx);
if ($src === false) { fwrite(STDERR, "cannot read index.php\n"); exit(1); }

if (strpos($src, "telemetry_ext.php") !== false) { echo "already patched — nothing to do\n"; exit(0); }

$reqAnchor = "require_once __DIR__ . '/authorize_ext.php';";
$okBlock =
"    log_event(\$licenseKey, \$mode, 'ok', 'License valid', \$ctx);\n\n" .
"    json_response([\n" .
"        'ok' => true,\n" .
"        'status' => 'active',\n" .
"        'license' => \$signed,\n" .
"    ]);";

$okReplace =
"    log_event(\$licenseKey, \$mode, 'ok', 'License valid', \$ctx);\n\n" .
"    if (function_exists('smlic_telemetry_ingest')) smlic_telemetry_ingest(\$licenseKey, \$data, \$serverIp, \$hostname);\n" .
"    \$smResp = ['ok' => true, 'status' => 'active', 'license' => \$signed];\n" .
"    if (function_exists('smlic_command_pop')) { \$smCmd = smlic_command_pop(\$licenseKey); if (\$smCmd) \$smResp['command'] = \$smCmd; }\n" .
"    json_response(\$smResp);";

if (substr_count($src, $reqAnchor) !== 1) { fwrite(STDERR, "require anchor count != 1\n"); exit(2); }
if (substr_count($src, $okBlock) !== 1)   { fwrite(STDERR, "ok-block anchor count != 1\n"); exit(3); }

$bak = $idx . '.bak_telemetry_' . date('Ymd_His');
copy($idx, $bak);

$src = str_replace($reqAnchor, $reqAnchor . "\nrequire_once __DIR__ . '/telemetry_ext.php';", $src);
$src = str_replace($okBlock, $okReplace, $src);
file_put_contents($idx, $src);

$lint = shell_exec('php -l ' . escapeshellarg($idx) . ' 2>&1');
echo "backup: $bak\n";
echo "lint: " . trim((string)$lint) . "\n";
if (strpos((string)$lint, 'No syntax errors') === false) {
    copy($bak, $idx);
    fwrite(STDERR, "LINT FAILED — restored from backup\n"); exit(4);
}
echo "PATCHED OK\n";
