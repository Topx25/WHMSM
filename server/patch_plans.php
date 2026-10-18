<?php
/** patch_plans.php — wire plans_ext.php + unify the nav to SM-only. Backup + lint + idempotent. */
$idx = __DIR__ . '/index.php';
$src = file_get_contents($idx);
if ($src === false) { fwrite(STDERR, "read fail\n"); exit(1); }
if (strpos($src, 'plans_ext.php') !== false) { echo "already patched\n"; exit(0); }

$wireAnchor = "    require_once __DIR__ . '/servers_ext.php';\n    if (function_exists('srv_route') && srv_route(\$path)) { exit; }";
$wireNew = "    require_once __DIR__ . '/servers_ext.php';\n"
         . "    require_once __DIR__ . '/plans_ext.php';\n"
         . "    if (function_exists('splan_migrate')) splan_migrate();\n"
         . "    if (function_exists('srv_route') && srv_route(\$path)) { exit; }\n"
         . "    if (function_exists('splan_route') && splan_route(\$path)) { exit; }";

$navAnchor = "        echo '<a href=\"/licenses/create\">Create License</a>';\n"
           . "        echo '<a href=\"/licenses/create-v2\">Create License v2</a>';\n"
           . "        echo '<a href=\"/licenses/create-safety-v2\">Safety Serial</a>';\n"
           . "        echo '<a href=\"/licenses/activate-sm\">SM Activation</a>';\n"
           . "        echo '<a href=\"/licenses/plans-v2\">Safety Plans</a>';";
$navNew = "        echo '<a href=\"/licenses/new\">Create License</a>';\n"
        . "        echo '<a href=\"/plans\">Plans</a>';";

foreach (['wire'=>$wireAnchor, 'nav'=>$navAnchor] as $n => $a) if (substr_count($src, $a) !== 1) { fwrite(STDERR, "$n anchor != 1\n"); exit(2); }

$bak = $idx . '.bak_plans_' . date('Ymd_His');
copy($idx, $bak);
$src = str_replace($wireAnchor, $wireNew, $src);
$src = str_replace($navAnchor, $navNew, $src);
file_put_contents($idx, $src);

$lint = shell_exec('php -l ' . escapeshellarg($idx) . ' 2>&1');
echo "backup: $bak\nlint: " . trim((string)$lint) . "\n";
if (strpos((string)$lint, 'No syntax errors') === false) { copy($bak, $idx); fwrite(STDERR, "LINT FAILED — reverted\n"); exit(3); }
echo "PLANS WIRED OK\n";
