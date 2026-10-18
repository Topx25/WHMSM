<?php
// Idempotent: make api_activate_or_check fingerprint-authoritative with IP auto-rebind.
$f = '/opt/aitech-license-server/public/index.php';
$src = file_get_contents($f);
if ($src === false) { fwrite(STDERR, "cannot read\n"); exit(2); }
if (strpos($src, 'ip_rebind') !== false) { echo "already patched\n"; exit(0); }

$anchor = "    \$ipMatches = hash_equals((string)\$lic['bound_ip'], \$serverIp);\n"
        . "    \$fpMatches = hash_equals((string)\$lic['bound_fingerprint'], \$fingerprint);\n\n"
        . "    if (!\$ipMatches || !\$fpMatches) {\n"
        . "        log_event(\$licenseKey, \$mode, 'binding_mismatch', 'IP or fingerprint mismatch', \$ctx);\n"
        . "        json_response([\n"
        . "            'ok' => false,\n"
        . "            'status' => 'binding_mismatch',\n"
        . "            'message' => 'License is already bound to another server. Contact support.',\n"
        . "            'bound_ip' => \$lic['bound_ip'],\n"
        . "        ], 403);\n"
        . "    }";
if (strpos($src, $anchor) === false) { fwrite(STDERR, "anchor not found\n"); exit(3); }

$repl = "    // Fingerprint = authoritative binding (stable behind Cloudflare / on IP change).\n"
      . "    // IP auto-rebinds when the same machine reports a new origin IP. Only a DIFFERENT machine is rejected.\n"
      . "    if (!hash_equals((string)\$lic['bound_fingerprint'], \$fingerprint)) {\n"
      . "        log_event(\$licenseKey, \$mode, 'binding_mismatch', 'Fingerprint mismatch (different machine)', \$ctx);\n"
      . "        json_response([\n"
      . "            'ok' => false,\n"
      . "            'status' => 'binding_mismatch',\n"
      . "            'message' => 'License is bound to a different machine. Contact support.',\n"
      . "            'bound_ip' => \$lic['bound_ip'],\n"
      . "        ], 403);\n"
      . "    }\n"
      . "    if (!hash_equals((string)\$lic['bound_ip'], \$serverIp) || !hash_equals((string)(\$lic['bound_hostname'] ?? ''), \$hostname)) {\n"
      . "        \$rid = (int)\$lic['id'];\n"
      . "        \$rs = db()->prepare(\"UPDATE licenses SET bound_ip=?, bound_hostname=? WHERE id=?\");\n"
      . "        \$rs->bind_param('ssi', \$serverIp, \$hostname, \$rid); \$rs->execute();\n"
      . "        log_event(\$licenseKey, \$mode, 'ip_rebind', 'Origin IP/hostname updated for same fingerprint (Cloudflare/IP change): ' . \$lic['bound_ip'] . ' -> ' . \$serverIp, \$ctx);\n"
      . "        \$lic = license_find(\$licenseKey);\n"
      . "    }";

$out = str_replace($anchor, $repl, $src);
if ($out === $src) { fwrite(STDERR, "no change\n"); exit(4); }
if (file_put_contents($f, $out) === false) { fwrite(STDERR, "write failed\n"); exit(5); }
echo "binding patched OK\n";
