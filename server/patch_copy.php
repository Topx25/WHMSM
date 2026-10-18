<?php
/** patch_copy.php — global click-to-copy for license keys + make the Licenses list keys copyable. */
$idx = __DIR__ . '/index.php';
$s = file_get_contents($idx);
if ($s === false) { fwrite(STDERR, "read fail\n"); exit(1); }
$bak = $idx . '.bak_copy_' . date('Ymd_His'); copy($idx, $bak);
$did = [];

if (strpos($s, 'COPYKEY-GLOBAL') === false) {
    $a = "    echo '</div></body></html>';";
    if (substr_count($s, $a) === 1) {
        $ins = "    echo '<script>/* COPYKEY-GLOBAL */document.addEventListener(\"click\",function(e){var c=e.target.closest(\".copykey\");if(!c)return;var t=c.getAttribute(\"data-k\")||c.textContent;if(navigator.clipboard)navigator.clipboard.writeText(t);var o=c.textContent;c.textContent=\"\\u2713 copied\";c.style.color=\"#16a34a\";setTimeout(function(){c.textContent=o;c.style.color=\"\";},1000);});</script>';\n" . $a;
        $s = str_replace($a, $ins, $s); $did[] = 'global-copy';
    }
}
// Licenses list: add copykey class to the key <code> cell (fallback uses textContent, no data-k needed)
$lk = "<code>' . h(\$r['license_key']) . '</code>";
if (strpos($s, $lk) !== false) {
    $s = str_replace($lk, "<code class=\"copykey\" style=\"cursor:pointer\" title=\"Click to copy\">' . h(\$r['license_key']) . '</code>", $s);
    $did[] = 'list-key';
}
file_put_contents($idx, $s);
$lint = shell_exec('php -l ' . escapeshellarg($idx) . ' 2>&1');
echo "backup: $bak\ndid: " . implode(',', $did) . "\nlint: " . trim((string)$lint) . "\n";
if (strpos((string)$lint, 'No syntax errors') === false) { copy($bak, $idx); fwrite(STDERR, "LINT FAILED — reverted\n"); exit(2); }
echo "COPY OK\n";
