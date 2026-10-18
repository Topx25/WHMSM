<?php
/** patch_redesign.php — replace the panel CSS block with the modern dark-sidebar theme. Backup + lint + idempotent. */
$idx = __DIR__ . '/index.php';
$src = file_get_contents($idx);
if ($src === false) { fwrite(STDERR, "read fail\n"); exit(1); }
if (strpos($src, 'SMPRO-REDESIGN') !== false) { echo "already redesigned\n"; exit(0); }

$css = '<style>/* SMPRO-REDESIGN */
*{box-sizing:border-box}
body{margin:0;font:14px/1.6 -apple-system,Segoe UI,Roboto,Arial,sans-serif;background:#f4f6fb;color:#1f2733}
a{color:#3b5bdb;text-decoration:none}
h1,h2,h3{color:#0f1b33}
.nav{position:fixed;top:0;left:0;width:236px;height:100vh;background:#10182b;display:flex;flex-direction:column;gap:2px;padding:62px 12px 16px;overflow:auto;z-index:30}
.nav::before{content:"Safety Monitor \00B7 License";position:fixed;top:0;left:0;width:236px;height:50px;display:flex;align-items:center;padding:0 16px;font-weight:800;color:#fff;background:#0c1322;font-size:14px;border-bottom:1px solid #1d2740}
.nav a{color:#cfd8ef;padding:9px 12px;border-radius:9px;font-size:13.5px;font-weight:600;border-left:3px solid transparent}
.nav a:hover{background:#1a2740;color:#fff}
.nav a[href="/logout"]{margin-top:auto;color:#f3a9a9}
.nav a[href="/public.pem"]{color:#9fb0d6}
.wrap{margin-left:236px;padding:22px 28px;max-width:1500px}
.hero{background:#fff;border:1px solid #e6eaf1;border-radius:14px;padding:18px 22px;margin-bottom:18px}
.hero h1{margin:0;font-size:22px;font-weight:800}
.hero p{margin:4px 0 0;color:#6b7686;font-size:13px}
.card{background:#fff;border:1px solid #e6eaf1;border-radius:14px;padding:18px 20px;margin-bottom:16px;box-shadow:0 6px 20px rgba(15,23,42,.05)}
.card h2{margin:0 0 14px;font-size:16px;font-weight:800}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.03em;color:#6b7686;font-weight:700;padding:9px 10px;border-bottom:2px solid #eef1f6}
td{padding:10px;border-bottom:1px solid #eef1f6;vertical-align:top}
tr:hover td{background:#fafbff}
button,.btn{display:inline-flex;align-items:center;gap:6px;background:#3b5bdb;color:#fff;border:0;border-radius:9px;padding:8px 13px;font-size:13px;font-weight:700;cursor:pointer;text-decoration:none}
button:hover,.btn:hover{background:#2f49b0}
button.danger,.btn.danger{background:#d93b3b}button.danger:hover{background:#b91c1c}
button.ok,.btn.ok{background:#1f9d55}
label{display:block;font-weight:700;color:#0f2657;font-size:13px;margin-bottom:4px}
input,select,textarea{padding:9px 12px;border:1px solid #d8dee9;border-radius:9px;font-size:14px;background:#fff;color:#1f2733;width:100%}
.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.badge{display:inline-block;font-size:11px;font-weight:700;padding:2px 9px;border-radius:20px;background:#eef2f7;color:#475569}
.badge.active{background:#e9f8ef;color:#1f9d55}.badge.suspended{background:#fdecec;color:#d93b3b}.badge.expired{background:#fdf6e7;color:#c47f17}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-bottom:16px}
.stat{background:#fff;border:1px solid #e6eaf1;border-radius:14px;padding:16px 18px}
.stat .num{font-size:30px;font-weight:800}
.stat .label{color:#6b7686;font-size:12px;margin-top:2px}
code{background:#f1f5f9;padding:1px 6px;border-radius:6px;font-size:12px}
small{color:#6b7686}
@media(max-width:860px){.nav{position:static;width:auto;height:auto;flex-direction:row;flex-wrap:wrap;padding:8px}.nav::before{display:none}.wrap{margin-left:0;padding:14px}}
</style>';

$a = strpos($src, "echo '<style>");
if ($a === false) { fwrite(STDERR, "style start not found\n"); exit(2); }
$marker = "</style>';";
$b = strpos($src, $marker, $a);
if ($b === false) { fwrite(STDERR, "style end not found\n"); exit(3); }
$new = "echo '" . $css . "';";

$bak = $idx . '.bak_redesign_' . date('Ymd_His');
copy($idx, $bak);
$src = substr($src, 0, $a) . $new . substr($src, $b + strlen($marker));
file_put_contents($idx, $src);

$lint = shell_exec('php -l ' . escapeshellarg($idx) . ' 2>&1');
echo "backup: $bak\nlint: " . trim((string)$lint) . "\n";
if (strpos((string)$lint, 'No syntax errors') === false) { copy($bak, $idx); fwrite(STDERR, "LINT FAILED — reverted\n"); exit(4); }
echo "REDESIGNED OK\n";
