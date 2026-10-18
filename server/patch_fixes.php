<?php
/** patch_fixes.php — global keygen prefix AITECH→SM + richer source-linked dashboard stats. Backup+lint. */
$idx = __DIR__ . '/index.php';
$src = file_get_contents($idx);
if ($src === false) { fwrite(STDERR, "read fail\n"); exit(1); }

$bak = $idx . '.bak_fixes_' . date('Ymd_His'); copy($idx, $bak);
$did = [];

// 1) default key prefix AITECH-RKH → SM
$a1 = "return 'AITECH-RKH-' . date('Y') . '-' . implode('-', \$parts);";
$n1 = "return 'SM-' . date('Y') . '-' . implode('-', \$parts);";
if (strpos($src, $a1) !== false) { $src = str_replace($a1, $n1, $src); $did[] = 'keygen'; }

// 2) dashboard: add Reporting Servers + Trials stat cards (real DB counts)
$a2 = "    echo '<div class=\"stat\"><div class=\"num\">' . \$stats['suspended'] . '</div><div class=\"label\">Suspended</div></div>';\n    echo '</section>';";
if (strpos($src, $a2) !== false && strpos($src, 'Reporting Servers') === false) {
    $n2 = "    echo '<div class=\"stat\"><div class=\"num\">' . \$stats['suspended'] . '</div><div class=\"label\">Suspended</div></div>';\n"
        . "    echo '<div class=\"stat\"><div class=\"num\">' . ((\$q=@db()->query(\"SELECT COUNT(*) c FROM license_telemetry\"))?(int)\$q->fetch_assoc()['c']:0) . '</div><div class=\"label\">Reporting Servers</div></div>';\n"
        . "    echo '<div class=\"stat\"><div class=\"num\">' . ((\$q=@db()->query(\"SELECT COUNT(*) c FROM licenses WHERE plan='free_trial'\"))?(int)\$q->fetch_assoc()['c']:0) . '</div><div class=\"label\">Trials</div></div>';\n"
        . "    echo '</section>';";
    $src = str_replace($a2, $n2, $src); $did[] = 'dashboard';
}

file_put_contents($idx, $src);
$lint = shell_exec('php -l ' . escapeshellarg($idx) . ' 2>&1');
echo "backup: $bak\ndid: " . implode(',', $did) . "\nlint: " . trim((string)$lint) . "\n";
if (strpos((string)$lint, 'No syntax errors') === false) { copy($bak, $idx); fwrite(STDERR, "LINT FAILED — reverted\n"); exit(2); }
echo "FIXES OK\n";
