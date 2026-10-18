<?php
/* Production touch-ups (idempotent):
 *   B) audit-log the reset_download admin action in index.php
 *   C) show "Downloads: N / 1" + a Reset-download button on the /licenses/edit page (panel_ext.php)
 */
$changed = 0;

/* ---- B) index.php : log_event on reset_download ---- */
$f1 = '/opt/aitech-license-server/public/index.php';
$s1 = file_get_contents($f1);
if ($s1 === false) { fwrite(STDERR, "cannot read $f1\n"); exit(1); }
if (strpos($s1, "Admin reset the single-download") === false) {
    $a = "            \$st = db()->prepare(\"DELETE FROM license_logs WHERE license_key=? AND action='download' AND result='ok'\");\n" .
         "            \$st->bind_param('s', \$key); \$st->execute();\n" .
         "        }";
    $b = "            \$st = db()->prepare(\"DELETE FROM license_logs WHERE license_key=? AND action='download' AND result='ok'\");\n" .
         "            \$st->bind_param('s', \$key); \$st->execute();\n" .
         "            log_event(\$key, 'reset_download', 'ok', 'Admin reset the single-download allowance', []);\n" .
         "        }";
    $n = str_replace($a, $b, $s1, $c);
    if ($c !== 1) { fwrite(STDERR, "B: anchor matched $c (expected 1) — aborting\n"); exit(2); }
    file_put_contents($f1, $n); $changed++; echo "B applied\n";
} else { echo "B already present\n"; }

/* ---- C) panel_ext.php : downloads info + reset button on edit page ---- */
$f2 = '/opt/aitech-license-server/public/panel_ext.php';
$s2 = file_get_contents($f2);
if ($s2 === false) { fwrite(STDERR, "cannot read $f2\n"); exit(1); }
if (strpos($s2, 'Reset download allowance') === false) {
    $anchor = "    echo '<p style=\"color:#64748b;font-weight:800\">Key <code>' . h((string)\$lic['license_key']) . '</code></p>';";
    $inject = $anchor . "\n" .
        "    \$dlc = 0;\n" .
        "    if (\$dq = db()->prepare(\"SELECT COUNT(*) FROM license_logs WHERE license_key=? AND action='download' AND result='ok'\")) {\n" .
        "        \$dq->bind_param('s', \$lic['license_key']); \$dq->execute(); \$dq->bind_result(\$dlc); \$dq->fetch(); \$dq->close(); \$dlc = (int)\$dlc;\n" .
        "    }\n" .
        "    echo '<p style=\"color:#0f2657;font-weight:800;margin:-4px 0 6px\">Downloads: <b>' . \$dlc . ' / 1</b> ' . (\$dlc >= 1 ? '<span class=\"badge suspended\">used</span>' : '<span class=\"badge active\">available</span>') . '</p>';\n" .
        "    echo '<form method=\"post\" action=\"/licenses/action\" style=\"margin:0 0 12px\"><input type=\"hidden\" name=\"csrf\" value=\"' . h(csrf_token()) . '\"><input type=\"hidden\" name=\"id\" value=\"' . (int)\$lic['id'] . '\">';\n" .
        "    echo '<button name=\"do\" value=\"reset_download\"' . (\$dlc >= 1 ? '' : ' disabled') . ' onclick=\"return confirm(\\'Allow this license to be downloaded again?\\')\">&#8635; Reset download allowance</button></form>';";
    $n = str_replace($anchor, $inject, $s2, $c);
    if ($c !== 1) { fwrite(STDERR, "C: anchor matched $c (expected 1) — aborting\n"); exit(3); }
    file_put_contents($f2, $n); $changed++; echo "C applied\n";
} else { echo "C already present\n"; }

echo "done ($changed file(s) changed)\n";
