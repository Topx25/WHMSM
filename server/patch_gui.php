<?php
/** patch_gui.php — GUI/UX polish: active sidebar link + refinements, injected in layout_end (additive). */
$idx = __DIR__ . '/index.php';
$src = file_get_contents($idx);
if ($src === false) { fwrite(STDERR, "read fail\n"); exit(1); }
if (strpos($src, 'SMPRO-GUI-POLISH') !== false) { echo "already polished\n"; exit(0); }

$anchor = "    echo '</div></body></html>';";
if (substr_count($src, $anchor) !== 1) { fwrite(STDERR, "anchor != 1\n"); exit(2); }

$inject = "    echo '<style>/* SMPRO-GUI-POLISH */"
  . ".nav a{transition:background .12s,border-color .12s}"
  . ".nav a.active{background:#1a2740;color:#fff;border-left-color:#3b5bdb}"
  . ".nav a i,.nav a svg{margin-right:2px}"
  . ".hero{display:flex;align-items:center;justify-content:space-between;gap:14px;flex-wrap:wrap}"
  . ".card{transition:box-shadow .15s}.card:hover{box-shadow:0 10px 28px rgba(15,23,42,.08)}"
  . "td small{display:block;color:#94a3b8;font-size:11px;margin-top:2px}"
  . "table{border-radius:10px;overflow:hidden}"
  . ".wrap>.card:last-child{background:transparent;border:0;box-shadow:none;color:#94a3b8;font-size:12px;padding:8px}"
  . "::-webkit-scrollbar{width:9px;height:9px}::-webkit-scrollbar-thumb{background:#c7d0e0;border-radius:6px}.nav::-webkit-scrollbar-thumb{background:#2a3a5c}"
  . "</style>'; "
  . "echo '<script>(function(){var p=location.pathname.replace(/\\/+\$/,\"\")||\"/\";var best=null,bl=-1;document.querySelectorAll(\".nav a\").forEach(function(a){var h=(a.getAttribute(\"href\")||\"\").replace(/\\/+\$/,\"\")||\"/\";if(h===p||(h!==\"/\"&&p.indexOf(h)===0)){if(h.length>bl){bl=h.length;best=a;}}});if(best)best.classList.add(\"active\");})();</script>';\n";

$bak = $idx . '.bak_gui_' . date('Ymd_His');
copy($idx, $bak);
$src = str_replace($anchor, $inject . $anchor, $src);
file_put_contents($idx, $src);

$lint = shell_exec('php -l ' . escapeshellarg($idx) . ' 2>&1');
echo "backup: $bak\nlint: " . trim((string)$lint) . "\n";
if (strpos((string)$lint, 'No syntax errors') === false) { copy($bak, $idx); fwrite(STDERR, "LINT FAILED — reverted\n"); exit(3); }
echo "POLISHED OK\n";
