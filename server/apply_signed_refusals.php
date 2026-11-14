<?php
// Licence server: sign the refusals of the check/activate endpoint, and say so inside the signed verdict.
// Three small insertions in public/index.php. The file is copied to _backups first and linted before the swap.
//   1. json_response(): a refusal sent while a licence check is being answered gets a signed "verdict" block
//      (payload: license_key, fingerprint, status, kind "negative", issued_at). Older plugins ignore the field.
//   2. api_activate_or_check(): remembers which key and machine the answer is for.
//   3. license_payload(): the signed verdict carries signs_negative=true, so a plugin knows an unsigned refusal
//      is not this server speaking.
$pub = '/opt/aitech-license-server/public'; $f = $pub . '/index.php';
$bk = '/opt/aitech-license-server/_backups/signed_refusals_' . date('Ymd_His'); @mkdir($bk, 0700, true);
if (!copy($f, $bk . '/index.php')) { echo "backup failed\n"; exit(1); }
$s = file_get_contents($f); $before = substr_count($s, "\n");
if (strpos($s, 'smlic_neg_ctx') !== false) { echo "already applied\n"; exit(0); }

$a = "function json_response(array \$data, int \$code = 200): never {\n";
if (substr_count($s, $a) !== 1) { echo "anchor 1 not found once\n"; exit(1); }
$s = str_replace($a, $a
    . "    // a refusal of a licence check is signed, so the plugin can tell it from a look-alike answer\n"
    . "    if (!empty(\$GLOBALS['smlic_neg_ctx']) && empty(\$data['ok']) && isset(\$data['status']) && !isset(\$data['verdict'])) {\n"
    . "        try {\n"
    . "            \$data['verdict'] = sign_payload(['kind' => 'negative', 'license_key' => (string)\$GLOBALS['smlic_neg_ctx']['license_key'],\n"
    . "                'fingerprint' => (string)\$GLOBALS['smlic_neg_ctx']['fingerprint'], 'status' => (string)\$data['status'], 'issued_at' => date('c')]);\n"
    . "        } catch (\\Throwable \$e) { /* unsigned, as before */ }\n"
    . "    }\n", $s);

$h = strpos($s, "function api_activate_or_check(string \$mode): never {");
$a = "    if (\$licenseKey === '' || \$serverIp === '' || \$fingerprint === '') {";
$p = $h === false ? false : strpos($s, $a, $h);
if ($p === false || $p - $h > 1500) { echo "anchor 2 not found\n"; exit(1); }
$s = substr($s, 0, $p)
   . "    if (\$licenseKey !== '' && \$fingerprint !== '') \$GLOBALS['smlic_neg_ctx'] = ['license_key' => \$licenseKey, 'fingerprint' => \$fingerprint];   // refusals below are signed for this key + machine\n"
   . substr($s, $p);

$h = strpos($s, "function license_payload(array \$lic, string \$serverIp, string \$hostname, string \$fingerprint): array {");
$a = "        'issued_at' => date('c'),\n";
$p = $h === false ? false : strpos($s, $a, $h);
if ($p === false || $p - $h > 2000) { echo "anchor 3 not found\n"; exit(1); }
$s = substr($s, 0, $p + strlen($a)) . "        'signs_negative' => true,                                                              // this server signs its refusals (\"verdict\")\n" . substr($s, $p + strlen($a));

$tmp = $f . '.sr-new'; file_put_contents($tmp, $s);
exec('php -l ' . escapeshellarg($tmp) . ' 2>&1', $out, $rc); if ($rc !== 0) { unlink($tmp); echo "lint failed: " . implode(' ', $out) . "\n"; exit(1); }
$st = stat($f); chown($tmp, $st['uid']); chgrp($tmp, $st['gid']); chmod($tmp, $st['mode'] & 0777);
rename($tmp, $f);
echo "applied; backup $bk; index.php lines $before -> " . substr_count($s, "\n") . "\n";
