<?php
// Idempotent patcher: wires /api/authorize into the license server's index.php.
$f = '/opt/aitech-license-server/public/index.php';
$src = file_get_contents($f);
if ($src === false) { fwrite(STDERR, "cannot read $f\n"); exit(2); }
if (strpos($src, 'api_authorize') !== false) { echo "already patched\n"; exit(0); }

$anchor = "if (\$path === '/api/check' && (\$_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {\n    api_activate_or_check('check');\n}";
if (strpos($src, $anchor) === false) { fwrite(STDERR, "anchor not found — aborting\n"); exit(3); }

$inject = $anchor . "\n\n"
    . "require_once __DIR__ . '/authorize_ext.php';\n"
    . "if (\$path === '/api/authorize' && (\$_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {\n"
    . "    api_authorize();\n"
    . "}\n";

$out = str_replace($anchor, $inject, $src);
if (file_put_contents($f, $out) === false) { fwrite(STDERR, "write failed\n"); exit(4); }
echo "patched OK\n";
