<?php
/** patch_servers.php — wire servers_ext.php (Servers tab) into index.php. Backup + lint-guard + idempotent. */
$idx = __DIR__ . '/index.php';
$src = file_get_contents($idx);
if ($src === false) { fwrite(STDERR, "cannot read index.php\n"); exit(1); }
if (strpos($src, 'servers_ext.php') !== false) { echo "already patched\n"; exit(0); }

$routeAnchor = "    if (function_exists('pext_route') && pext_route(\$path)) { exit; }";
$routeNew = "    require_once __DIR__ . '/servers_ext.php';\n"
          . "    if (function_exists('srv_route') && srv_route(\$path)) { exit; }\n"
          . $routeAnchor;
$navAnchor = "        echo '<a href=\"/logs\">Logs</a>';";
$navNew = "        echo '<a href=\"/servers\">Servers</a>';\n" . $navAnchor;

if (substr_count($src, $routeAnchor) !== 1) { fwrite(STDERR, "route anchor != 1\n"); exit(2); }
if (substr_count($src, $navAnchor) !== 1)   { fwrite(STDERR, "nav anchor != 1\n"); exit(3); }

$bak = $idx . '.bak_servers_' . date('Ymd_His');
copy($idx, $bak);
$src = str_replace($routeAnchor, $routeNew, $src);
$src = str_replace($navAnchor, $navNew, $src);
file_put_contents($idx, $src);

$lint = shell_exec('php -l ' . escapeshellarg($idx) . ' 2>&1');
echo "backup: $bak\nlint: " . trim((string)$lint) . "\n";
if (strpos((string)$lint, 'No syntax errors') === false) { copy($bak, $idx); fwrite(STDERR, "LINT FAILED — reverted\n"); exit(4); }
echo "PATCHED OK\n";
