<?php
// Adds the origin watch to the licence server: one new file + three one-line hooks. Backup first, lint before swap.
$pub = '/opt/aitech-license-server/public'; $f = $pub . '/index.php'; $ts = date('Ymd_His');
$bk = '/opt/aitech-license-server/_backups/originwatch_' . $ts; @mkdir($bk, 0700, true);
if (!copy($f, $bk . '/index.php')) { echo "backup failed\n"; exit(1); }
$s = file_get_contents($f); $o = $s;
if (strpos($s, 'smlic_origin_watch') !== false) { echo "already applied\n"; exit(0); }
$edits = [
    ["    if (function_exists('smlic_pair_verify')) smlic_pair_verify(\$lic, \$data, \$serverIp, \$hostname, \$fingerprint);",
     "\n    if (function_exists('smlic_origin_watch')) { try { smlic_origin_watch(\$licenseKey, (int)\$lic['id']); } catch (\\Throwable \$e) {} }   // report-only: one licence checking in from two places", 'after-line'],
    ["    log_event(\$licenseKey, 'license-check', 'ok', 'License valid', \$ctx);",
     "\n    if (function_exists('smlic_origin_watch')) { try { smlic_origin_watch(\$licenseKey, (int)\$lic['id']); } catch (\\Throwable \$e) {} }", 'after'],
    ["require_once __DIR__ . '/plans_ext.php'; /* PLANS_EARLY_SEED */",
     "\$__ow = __DIR__ . '/originwatch_ext.php'; if (is_file(\$__ow)) require_once \$__ow;\n", 'before'],
];
foreach ($edits as [$a, $b, $how]) {
    $c = substr_count($s, $a); if ($c !== 1) { echo "anchor count $c for: " . substr($a, 0, 60) . "\n"; exit(1); }
    if ($how === 'before') $s = str_replace($a, $b . $a, $s);
    elseif ($how === 'after') $s = str_replace($a, $a . $b, $s);
    else { $p = strpos($s, $a); $e = strpos($s, "\n", $p); $s = substr($s, 0, $e) . $b . substr($s, $e); }
}
$tmp = $f . '.ow-new'; file_put_contents($tmp, $s);
exec('php -l ' . escapeshellarg($tmp) . ' 2>&1', $out, $rc); if ($rc !== 0) { unlink($tmp); echo "lint failed: " . implode(' ', $out) . "\n"; exit(1); }
exec('php -l ' . escapeshellarg($argv[1]) . ' 2>&1', $out2, $rc2); if ($rc2 !== 0) { unlink($tmp); echo "ext lint failed\n"; exit(1); }
$st = stat($f); chown($tmp, $st['uid']); chgrp($tmp, $st['gid']); chmod($tmp, $st['mode'] & 0777);
$ext = $pub . '/originwatch_ext.php'; copy($argv[1], $ext); chown($ext, $st['uid']); chgrp($ext, $st['gid']); chmod($ext, 0644);
rename($tmp, $f);
echo "applied; backup $bk; index.php lines " . substr_count($o, "\n") . " -> " . substr_count($s, "\n") . "\n";
