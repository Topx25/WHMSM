<?php
/* Adds a "Downloads" column + "Reset DL" button to the Licenses admin page, and a
 * reset_download action to page_license_action(). Idempotent. Run once on the server. */
$f = '/opt/aitech-license-server/public/index.php';
$s = file_get_contents($f);
if ($s === false) { fwrite(STDERR, "cannot read $f\n"); exit(1); }
if (strpos($s, 'reset_download') !== false) { echo "already patched — no change\n"; exit(0); }

$edits = [];

// 1) licenses query → also compute per-license successful-download count
$edits[] = [
  '$rows = db()->query("SELECT * FROM licenses ORDER BY id DESC LIMIT 500")->fetch_all(MYSQLI_ASSOC);',
  '$rows = db()->query("SELECT l.*, (SELECT COUNT(*) FROM license_logs g WHERE g.license_key=l.license_key AND g.action=\'download\' AND g.result=\'ok\') AS download_count FROM licenses l ORDER BY l.id DESC LIMIT 500")->fetch_all(MYSQLI_ASSOC);',
];

// 2) header: add a Downloads column before Actions
$edits[] = [
  '<th>Expires</th><th>Actions</th>',
  '<th>Expires</th><th>Downloads</th><th>Actions</th>',
];

// 3) body: render the Downloads cell right before the Actions cell
$edits[] = [
  "        echo '<td class=\"actions\">';",
  "        \$dlc = (int)(\$r['download_count'] ?? 0);\n" .
  "        echo '<td>' . \$dlc . ' / 1' . (\$dlc >= 1 ? ' <span class=\"badge suspended\">used</span>' : '') . '</td>';\n" .
  "        echo '<td class=\"actions\">';",
];

// 4) add the Reset DL button after the Reset IP button
$edits[] = [
  "        echo '<button name=\"do\" value=\"reset\">Reset IP</button> ';",
  "        echo '<button name=\"do\" value=\"reset\">Reset IP</button> ';\n" .
  "        echo '<button name=\"do\" value=\"reset_download\" onclick=\"return confirm(\\'Allow this license to be downloaded again?\\')\">Reset DL</button> ';",
];

// 5) handler: add reset_download branch before the delete branch
$edits[] = [
  "    } elseif (\$do === 'delete') {\n        db()->query(\"DELETE FROM licenses WHERE id=\$id\");\n    }",
  "    } elseif (\$do === 'reset_download') {\n" .
  "        \$kr = db()->query(\"SELECT license_key FROM licenses WHERE id=\$id\");\n" .
  "        \$key = \$kr ? (string)(\$kr->fetch_row()[0] ?? '') : '';\n" .
  "        if (\$key !== '') {\n" .
  "            \$st = db()->prepare(\"DELETE FROM license_logs WHERE license_key=? AND action='download' AND result='ok'\");\n" .
  "            \$st->bind_param('s', \$key); \$st->execute();\n" .
  "        }\n" .
  "    } elseif (\$do === 'delete') {\n        db()->query(\"DELETE FROM licenses WHERE id=\$id\");\n    }",
];

foreach ($edits as $i => $e) {
    $n = str_replace($e[0], $e[1], $s, $c);
    if ($c !== 1) { fwrite(STDERR, "edit #" . ($i + 1) . " anchor matched $c times (expected 1) — aborting, no write\n"); exit(2); }
    $s = $n;
}

if (file_put_contents($f, $s) === false) { fwrite(STDERR, "cannot write $f\n"); exit(3); }
echo "patched ok (5 edits)\n";
