<?php
/* one-shot: wire the /api/download route into the license server's index.php (idempotent). */
$f = '/opt/aitech-license-server/public/index.php';
$s = file_get_contents($f);
if ($s === false) { fwrite(STDERR, "cannot read $f\n"); exit(1); }

if (strpos($s, "/api/download") !== false) { echo "already wired — no change\n"; exit(0); }

$anchor = "if (\$path === '/api/authorize' && (\$_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {\n    api_authorize();\n}";
$inject = $anchor . "\n\nrequire_once __DIR__ . '/download_ext.php';\nif (\$path === '/api/download' && (\$_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {\n    api_download();\n}";

$n = str_replace($anchor, $inject, $s, $c);
if ($c !== 1) { fwrite(STDERR, "anchor not found (matches=$c) — aborting\n"); exit(2); }

if (file_put_contents($f, $n) === false) { fwrite(STDERR, "cannot write $f\n"); exit(3); }
echo "patched ok\n";
