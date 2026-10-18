<?php
/** patch_dupbind.php — refuse binding a 2nd serial to the same IP+hostname. Patches download_ext.php + index.php. */
function pf($file, $anchor, $insert) {
    $s = file_get_contents($file); if ($s === false) return "READ FAIL $file";
    if (strpos($s, 'smlic_server_taken(') !== false) return "already patched $file";
    if (substr_count($s, $anchor) !== 1) return "anchor != 1 in $file";
    $bak = $file . '.bak_dup_' . date('Ymd_His'); copy($file, $bak);
    $s = str_replace($anchor, $insert, $s);
    file_put_contents($file, $s);
    $lint = shell_exec('php -l ' . escapeshellarg($file) . ' 2>&1');
    if (strpos((string)$lint, 'No syntax errors') === false) { copy($bak, $file); return "LINT FAIL $file: " . trim((string)$lint); }
    return "OK $file (bak $bak)";
}
$dir = __DIR__;

// download_ext.php — bind on first download
$dlAnchor = "    if (\$notBound) {\n        \$st = db()->prepare(\"UPDATE licenses SET status='active', bound_ip=?, bound_hostname=?, bound_fingerprint=?, activated_at=COALESCE(activated_at, NOW()), last_check_at=NOW() WHERE id=?\");";
$dlGuard = "    if (\$notBound) {\n"
  . "        if (function_exists('smlic_server_taken') && (\$smOther = smlic_server_taken(\$licenseKey, \$serverIp, \$hostname))) {\n"
  . "            log_event(\$licenseKey, 'download', 'dup_binding', 'Server already bound to ' . \$smOther, \$ctx);\n"
  . "            json_response(['ok' => false, 'status' => 'dup_binding', 'message' => 'This server (IP + hostname) is already licensed under another serial. One license per server.'], 409);\n"
  . "        }\n"
  . "        \$st = db()->prepare(\"UPDATE licenses SET status='active', bound_ip=?, bound_hostname=?, bound_fingerprint=?, activated_at=COALESCE(activated_at, NOW()), last_check_at=NOW() WHERE id=?\");";
echo pf($dir . '/download_ext.php', $dlAnchor, $dlGuard) . "\n";

// index.php — activate binding
$acAnchor = "    if (\$mode === 'activate') {\n        \$notBound = empty(\$lic['bound_ip']) && empty(\$lic['bound_fingerprint']);\n\n        if (\$notBound) {";
$acGuard = "    if (\$mode === 'activate') {\n        \$notBound = empty(\$lic['bound_ip']) && empty(\$lic['bound_fingerprint']);\n\n        if (\$notBound) {\n"
  . "            if (function_exists('smlic_server_taken') && (\$smOther = smlic_server_taken(\$licenseKey, \$serverIp, \$hostname))) {\n"
  . "                log_event(\$licenseKey, \$mode, 'dup_binding', 'Server already bound to ' . \$smOther, \$ctx);\n"
  . "                json_response(['ok' => false, 'status' => 'dup_binding', 'message' => 'This server (IP + hostname) is already licensed under another serial. One license per server.'], 409);\n"
  . "            }";
echo pf($dir . '/index.php', $acAnchor, $acGuard) . "\n";
