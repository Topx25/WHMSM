<?php
/* Add an editable "Server binding" section (Bound IP / hostname / fingerprint + status) to the
 * /licenses/edit page in panel_ext.php. Idempotent. */
$f = '/opt/aitech-license-server/public/panel_ext.php';
$s = file_get_contents($f);
if ($s === false) { fwrite(STDERR, "read fail\n"); exit(1); }
if (strpos($s, 'Server binding') !== false) { echo "already patched\n"; exit(0); }

/* A) extend the UPDATE to persist bound_ip / bound_hostname / bound_fingerprint */
$a1 = '        $stmt = db()->prepare("UPDATE licenses SET client_name=?, client_email=?, plan=?, edition=?, product_code=?, status=?, max_servers=?, expires_at=?, notes=?, features=? WHERE id=?");' . "\n"
    . '        $stmt->bind_param(\'ssssssisssi\', $clientName, $clientEmail, $plan, $edition, $product, $status, $maxServers, $expiresAt, $notes, $featuresJson, $id);';
$b1 = '        $bIp  = trim((string)($_POST[\'bound_ip\'] ?? \'\'));          $bIp   = $bIp   === \'\' ? null : $bIp;' . "\n"
    . '        $bHost = trim((string)($_POST[\'bound_hostname\'] ?? \'\'));    $bHost = $bHost === \'\' ? null : $bHost;' . "\n"
    . '        $bFp  = trim((string)($_POST[\'bound_fingerprint\'] ?? \'\'));  $bFp   = $bFp   === \'\' ? null : $bFp;' . "\n"
    . '        $stmt = db()->prepare("UPDATE licenses SET client_name=?, client_email=?, plan=?, edition=?, product_code=?, status=?, max_servers=?, expires_at=?, notes=?, features=?, bound_ip=?, bound_hostname=?, bound_fingerprint=? WHERE id=?");' . "\n"
    . '        $stmt->bind_param(\'ssssssissssssi\', $clientName, $clientEmail, $plan, $edition, $product, $status, $maxServers, $expiresAt, $notes, $featuresJson, $bIp, $bHost, $bFp, $id);';
$s = str_replace($a1, $b1, $s, $c1);
if ($c1 !== 1) { fwrite(STDERR, "A anchor matched $c1\n"); exit(2); }

/* B) render an editable binding section just before the Save button */
$a2 = "    echo '<div style=\"margin-top:14px\"><button type=\"submit\" class=\"ok\">&#128190; Save changes</button> <a class=\"btn\" href=\"/licenses\">Cancel</a></div>';";
$b2 = "    echo '<div class=\"pext-sections\"><div class=\"pext-sechd\"><b>&#128279; Server binding (who may download / run)</b></div>';\n"
    . "    echo '<p style=\"color:#475569;font-size:13px;margin:4px 0 8px\">Auto by default: the FIRST download from the licensed server binds it to that server&#39;s IP + hostname + hardware fingerprint (the fingerprint is the real lock). Set these only to move/correct a binding. To let a NEW server download, <b>clear all three</b> (or use Reset IP) and it re-binds on next download. An IP without a fingerprint will NOT allow download.</p>';\n"
    . "    echo '<div class=\"pext-grid\" style=\"display:grid;grid-template-columns:repeat(2,1fr);gap:12px\">';\n"
    . "    echo '<label>Bound IP<input name=\"bound_ip\" value=\"' . \$v('bound_ip') . '\" placeholder=\"(auto on first download)\"></label>';\n"
    . "    echo '<label>Bound hostname<input name=\"bound_hostname\" value=\"' . \$v('bound_hostname') . '\"></label>';\n"
    . "    echo '<label style=\"grid-column:1/-1\">Bound fingerprint (sha256)<input name=\"bound_fingerprint\" value=\"' . \$v('bound_fingerprint') . '\" placeholder=\"(auto on first download)\"></label>';\n"
    . "    echo '</div>';\n"
    . "    echo '<p style=\"color:#64748b;font-size:12.5px;margin-top:6px\">Status: <b>' . \$v('status') . '</b> &middot; Activated: ' . (\$v('activated_at') ?: '&mdash;') . '</p>';\n"
    . "    echo '</div>';\n"
    . $a2;
$s = str_replace($a2, $b2, $s, $c2);
if ($c2 !== 1) { fwrite(STDERR, "B anchor matched $c2\n"); exit(3); }

file_put_contents($f, $s);
echo "patched ok (binding section added)\n";
