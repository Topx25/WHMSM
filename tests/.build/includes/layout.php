<?php
/**
 * layout.php — central page shell with a FIXED, SHARED sidebar that appears
 * on every page. Driven by includes/menu.php. Local CSS/JS only, no CDN.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

function smpro_layout_header($title = '') {
    $cp       = SMPRO_CPSESS;
    $whm_home = ($cp ?: '') . '/';   // WHM home = session root (/cpsessXXXX/)

    // Active menu item resolved from the current request (alias-aware).
    $req    = isset($_GET['page']) ? preg_replace('/[^a-z0-9_\-]/', '', strtolower($_GET['page'])) : 'dashboard';
    $item   = smpro_menu_resolve($req);
    $active = $item['id'] ?? 'dashboard';
    ?>
<!doctype html>
<html lang="en">
<head>
<script>/* apply saved prefs before paint (no flash) */(function(){try{var d=document.documentElement;
if(localStorage.getItem('smpro_theme')==='dark')d.setAttribute('data-theme','dark');
var _nv=localStorage.getItem('smpro_nav');if(_nv==='rail'||_nv==='hidden')d.classList.add('nav-rail');
}catch(e){}})();</script>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= smpro_h($title ? "$title — " . SMPRO_NAME : SMPRO_NAME) ?></title>
<style>
:root{--bg:#f4f6fb;--card:#fff;--ink:#1f2733;--muted:#6b7686;--line:#e6eaf1;
--good:#1f9d55;--good-bg:#e9f8ef;--warn:#c47f17;--warn-bg:#fdf6e7;--dang:#d93b3b;--dang-bg:#fdecec;
--brand:#3b5bdb;--brand-bg:#eef2ff;--side:#10182b;--side-ink:#cfd8ef;--sidew:248px;--toph:52px;}
*{box-sizing:border-box}
body{margin:0;font:14px/1.5 -apple-system,Segoe UI,Roboto,Arial,sans-serif;background:var(--bg);color:var(--ink)}
a{color:inherit}
/* Topbar (fixed) */
.smpro-top{position:fixed;top:0;left:0;right:0;height:var(--toph);z-index:30;display:flex;align-items:center;gap:12px;
 background:var(--side);color:#fff;padding:0 16px;border-bottom:1px solid #1d2740}
.smpro-top .burger{display:none;background:#23304d;border:0;color:#fff;font-size:18px;line-height:1;padding:6px 10px;border-radius:8px;cursor:pointer}
.smpro-top .tag{font-size:11px;background:#23304d;padding:2px 8px;border-radius:20px;color:var(--side-ink)}
.smpro-top .sp{flex:1}
.smpro-health{display:flex;gap:7px;align-items:center;margin-left:6px}
.sh-chip{display:inline-flex;align-items:center;gap:5px;background:#23304d;border:1px solid #2f3e5e;border-radius:20px;padding:3px 10px;font-size:12px;color:#cdd6ea;line-height:1.4}
.sh-chip i{font-style:normal;font-size:11px;opacity:.9}
.sh-chip span{font-size:9.5px;text-transform:uppercase;letter-spacing:.04em;opacity:.65}
.sh-chip b{font-weight:800;font-variant-numeric:tabular-nums}
.sh-chip.ok{background:#16341f;border-color:#1f7a4d}.sh-chip.ok b,.sh-chip.ok i,.sh-chip.ok span{color:#5fe0a6}
.sh-chip.elev{background:#3a2a16;border-color:#b06012}.sh-chip.elev b,.sh-chip.elev i,.sh-chip.elev span{color:#fdba74}
.sh-chip.warn{background:#3a3416;border-color:#b07d12}.sh-chip.warn b{color:#fcd34d}.sh-chip.warn i,.sh-chip.warn span{color:#fcd34d;opacity:.9}
.sh-chip.crit{background:#4a1d1d;border-color:#dc2626;animation:shpulse 1.5s ease-in-out infinite}.sh-chip.crit b,.sh-chip.crit i,.sh-chip.crit span{color:#fca5a5}
.sh-chip.na b{color:#6b7a99}
@keyframes shpulse{0%,100%{box-shadow:0 0 0 0 rgba(220,38,38,0)}50%{box-shadow:0 0 0 3px rgba(220,38,38,.3)}}
@media(max-width:1024px){.smpro-health .sh-chip span{display:none}}
@media(max-width:720px){.smpro-health{display:none}}
.smpro-top a{color:var(--side-ink);text-decoration:none;font-size:13px;padding:6px 10px;border-radius:6px}
.smpro-top a:hover{background:#23304d;color:#fff}
/* Sidebar (fixed, shared) */
.smpro-side{position:fixed;top:var(--toph);bottom:0;left:0;width:var(--sidew);z-index:25;overflow-y:auto;
 background:var(--side);color:var(--side-ink);padding:10px 0 30px;border-right:1px solid #1d2740}
.smpro-brand{padding:12px 18px 8px;border-bottom:1px solid #1d2740;margin-bottom:6px}
.smpro-brand b{display:block;color:#fff;font-size:14px}
.smpro-brand span{font-size:11px;color:#8895b3}
.smpro-sec{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:#7b88a8;padding:14px 18px 6px}
.smpro-link{display:flex;align-items:center;gap:10px;padding:9px 18px;text-decoration:none;color:var(--side-ink);font-size:13px;border-left:3px solid transparent}
.smpro-link:hover{background:#1a2540;color:#fff}
.smpro-link.active{background:#1d2952;color:#fff;border-left-color:var(--brand)}
.smpro-link i{width:18px;text-align:center;font-style:normal;opacity:.85}
.smpro-link .soon{margin-left:auto;font-size:9px;font-style:normal;background:#2a3858;color:#9fb0d6;padding:1px 6px;border-radius:10px;text-transform:uppercase}
.smpro-link.locked{opacity:.5}.smpro-link.locked:hover{opacity:.8}
.smpro-link .smpro-lock{margin-left:auto;font-style:normal;font-size:11px;opacity:.85}
/* Content */
.smpro-main{margin-left:var(--sidew);padding-top:var(--toph)}
.wrap{max-width:1800px;margin:18px auto;padding:0 28px}
@media(min-width:1500px){.wrap{padding:0 40px}}
.h{margin:0 0 4px;font-size:20px}
.sub{color:var(--muted);margin:0 0 18px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px}
.card .lbl{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
.card .val{font-size:26px;font-weight:700;margin:6px 0 2px}
.card .meta{font-size:12px;color:var(--muted)}
.pill{display:inline-block;font-size:11px;font-weight:700;padding:3px 10px;border-radius:20px}
.pill.good{background:var(--good-bg);color:var(--good)}.pill.warn{background:var(--warn-bg);color:var(--warn)}.pill.danger{background:var(--dang-bg);color:var(--dang)}
.bar{height:8px;border-radius:8px;background:#eef1f6;overflow:hidden;margin-top:10px}
.bar>i{display:block;height:100%;border-radius:8px}
.bar>i.good{background:var(--good)}.bar>i.warn{background:var(--warn)}.bar>i.danger{background:var(--dang)}
.foot{margin:24px 0 40px;padding:14px 16px;background:#fff;border:1px solid var(--line);border-radius:12px;color:var(--muted);font-size:12px}
.foot b{color:var(--good)}
.smpro-ovl{display:none;position:fixed;inset:var(--toph) 0 0 0;background:rgba(8,12,22,.5);z-index:24}
/* Responsive: sidebar becomes a drawer */
@media(max-width:860px){
 .smpro-side{transform:translateX(-100%);transition:transform .2s ease;box-shadow:2px 0 18px rgba(0,0,0,.3)}
 body.smpro-open .smpro-side{transform:none}
 body.smpro-open .smpro-ovl{display:block}
 .smpro-main{margin-left:0}
 .smpro-top .burger{display:inline-block}
 .smpro-top a.hide-sm{display:none}
}
/* ---- universal UI/UX polish (additive, safe across all pages) ---- */
.card{transition:box-shadow .18s ease,border-color .18s ease}
.card:hover{box-shadow:0 6px 20px rgba(15,23,42,.07)}
button,.tp-btn,.fa-lnk,.lnk,a.tp-btn,input,select,textarea{transition:background .15s,border-color .15s,color .15s,box-shadow .15s}
button:active,.tp-btn:active{transform:translateY(1px)}
input:focus,select:focus,textarea:focus,.tp-in:focus,.tp-sel:focus{outline:none;border-color:var(--brand);box-shadow:0 0 0 3px var(--brand-bg)}
.smpro-link{transition:background .15s,color .15s,border-color .15s}
button:focus-visible,a:focus-visible,input:focus-visible,select:focus-visible{outline:2px solid var(--brand);outline-offset:1px}
tbody tr{transition:background .12s}
::-webkit-scrollbar{width:11px;height:11px}::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:#cbd5e1;border-radius:8px;border:2px solid #f4f6fb}::-webkit-scrollbar-thumb:hover{background:#94a3b8}
*{scrollbar-width:thin;scrollbar-color:#cbd5e1 transparent}
/* ---- header control icons (sidebar toggle / theme / language) ---- */
.smpro-ctl{display:inline-flex;align-items:center;justify-content:center;width:32px;height:32px;background:#23304d;border:1px solid #2f3e5e;color:#cdd6ea;border-radius:9px;cursor:pointer;font-size:15px;line-height:1;padding:0}
.smpro-ctl:hover{background:#2d3d61;color:#fff}
.smpro-ctl.lang{font-size:12px;font-weight:800;letter-spacing:.02em}
/* ---- collapsible sidebar (desktop) ---- */
.smpro-side,.smpro-main{transition:transform .2s ease,margin .2s ease}
.smpro-top .burger{display:inline-flex;align-items:center;justify-content:center}
html.nav-collapsed .smpro-side{transform:translateX(-100%)}
html.nav-collapsed .smpro-main{margin-left:0}
/* ---- RTL (Arabic) ---- */
html[dir=rtl] .smpro-side{left:auto;right:0;border-right:0;border-left:1px solid #1d2740}
html[dir=rtl] .smpro-main{margin-left:0;margin-right:var(--sidew)}
html[dir=rtl].nav-collapsed .smpro-side{transform:translateX(100%)}
html[dir=rtl].nav-collapsed .smpro-main{margin-right:0}
html[dir=rtl] .smpro-link{border-left:0;border-right:3px solid transparent}
html[dir=rtl] .smpro-link.active{border-right-color:var(--brand)}
html[dir=rtl] .smpro-link .soon,html[dir=rtl] .smpro-link .smpro-lock{margin-left:0;margin-right:auto}
html[dir=rtl] .sm-licbtn,html[dir=rtl] .sm-expbtn{margin-left:0;margin-right:auto}
@media(max-width:860px){html[dir=rtl] .smpro-side{transform:translateX(100%)}html[dir=rtl] .smpro-main{margin-right:0}html[dir=rtl] body.smpro-open .smpro-side{transform:none}}
/* ---- dark theme ---- */
html[data-theme=dark]{--bg:#0e1626;--card:#162032;--ink:#e7ecf6;--muted:#94a3bd;--line:#27324a;
 --good-bg:#102619;--warn-bg:#2a2410;--dang-bg:#2c1517;--brand-bg:#1b2747;}
html[data-theme=dark] body{background:#0e1626}
html[data-theme=dark] .card,html[data-theme=dark] .sm-aiout,html[data-theme=dark] .foot{background:#152033;border-color:#27324a;color:var(--ink)}
html[data-theme=dark] .smpro-table th{background:#1a2740 !important;color:#9fb0d6}
html[data-theme=dark] .smpro-table td,html[data-theme=dark] .smpro-table th{border-color:#27324a}
html[data-theme=dark] .db-tablewrap thead th,html[data-theme=dark] thead th{background:#1a2740}
html[data-theme=dark] input,html[data-theme=dark] select,html[data-theme=dark] textarea,html[data-theme=dark] .tp-in,html[data-theme=dark] .tp-sel{background:#0f1a2e;border-color:#2b3850;color:var(--ink)}
html[data-theme=dark] code,html[data-theme=dark] .mono{background:#0f1a2e;color:#cbd5e1}
html[data-theme=dark] .bar{background:#23314c}
html[data-theme=dark] ::-webkit-scrollbar-thumb{background:#33405c;border-color:#0e1626}
/* ---- comprehensive dark surfaces across ALL module styles (class-prefix based) ---- */
html[data-theme=dark] .smpro-main{color:var(--ink)}
html[data-theme=dark] .smpro-main h1,html[data-theme=dark] .smpro-main h2,html[data-theme=dark] .smpro-main h3,html[data-theme=dark] .smpro-main h4,html[data-theme=dark] .h{color:var(--ink)}
/* surfaces (cards / kpis / boxes / panels / bars / menus / cells / rows / charts / tables wrappers) */
html[data-theme=dark] [class*="kpi"],html[data-theme=dark] [class*="card"],html[data-theme=dark] [class*="-box"],html[data-theme=dark] [class*="panel"],html[data-theme=dark] [class*="-bar"],html[data-theme=dark] [class*="-menu"],html[data-theme=dark] [class*="-cell"],html[data-theme=dark] [class*="-rec"],html[data-theme=dark] [class*="-row"],html[data-theme=dark] [class*="-per"],html[data-theme=dark] [class*="chart"],html[data-theme=dark] [class*="spark"],html[data-theme=dark] [class*="tablewrap"],html[data-theme=dark] [class*="-sc"],html[data-theme=dark] [class*="-ioc"]{background:#152033 !important;border-color:#27324a !important}
/* section headers / toolbars get a slightly lighter slate */
html[data-theme=dark] [class*="head"],html[data-theme=dark] [class*="toolbar"],html[data-theme=dark] [class*="-hd"]{background:#1a2740 !important;border-color:#27324a !important;color:#cdd9f0 !important}
/* muted/secondary text */
html[data-theme=dark] .meta,html[data-theme=dark] .sub,html[data-theme=dark] .muted,html[data-theme=dark] [class*="meta"],html[data-theme=dark] [class*="-note"],html[data-theme=dark] [class*="-empty"],html[data-theme=dark] [class*="-sub"],html[data-theme=dark] small{color:#93a3bd !important}
/* tables everywhere */
html[data-theme=dark] table{background:transparent}
html[data-theme=dark] table th{background:#1a2740 !important;color:#9fb0d6 !important}
html[data-theme=dark] table td,html[data-theme=dark] table th{border-color:#27324a !important}
html[data-theme=dark] tbody tr:hover{background:#192540}
/* form controls */
html[data-theme=dark] input,html[data-theme=dark] select,html[data-theme=dark] textarea{background:#0f1a2e !important;color:var(--ink) !important;border-color:#2b3850 !important}
html[data-theme=dark] input::placeholder,html[data-theme=dark] textarea::placeholder{color:#5d6b86}
/* buttons / pills / links used across modules (keep brand/danger ones colored) */
html[data-theme=dark] [class*="-btn"]:not(.primary):not(.danger),html[data-theme=dark] [class*="-mini"]:not(.fixdb):not(.clean):not(.insp):not(.trash1),html[data-theme=dark] [class*="-lnk"],html[data-theme=dark] .tp-btn:not(.primary){background:#1c2840 !important;color:#cdd9f0 !important;border-color:#33415e !important}
/* code / monospace value boxes */
html[data-theme=dark] code,html[data-theme=dark] .mono{background:#0f1a2e;color:#cbd5e1}
/* keep the already-dark preview/snippet boxes as-is; just soften borders */
html[data-theme=dark] [class*="prev"],html[data-theme=dark] [class*="snip"]{border-color:#27324a}
/* AI assistant + alert bars text legibility */
html[data-theme=dark] .sm-aiout,html[data-theme=dark] .sm-aiout *{color:var(--ink)}
html[data-theme=dark] .sm-aibar{background:#152033 !important}
@media(prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}
/* ---- sidebar rail (icon-only collapse) — desktop only; mobile keeps the drawer ---- */
@media(min-width:861px){
 html.nav-rail{--sidew:66px}
 html.nav-rail .smpro-side{width:66px;overflow:visible;padding-top:8px}
 html.nav-rail .smpro-brand{display:none}
 html.nav-rail .smpro-sec{justify-content:center;padding:6px 0;margin:6px 12px 2px;border-top:1px solid #1d2740}
 html.nav-rail .smpro-sec span[data-i18n],html.nav-rail .smpro-secchev{display:none}
 html.nav-rail .smpro-secitems{display:block!important}
 html.nav-rail .smpro-link{justify-content:center;padding:11px 0;gap:0;border-left-width:0}
 html.nav-rail .smpro-link i{width:auto;font-size:18px;opacity:.95}
 html.nav-rail .smpro-link span[data-i18n],html.nav-rail .smpro-link .soon,html.nav-rail .smpro-link .smpro-lock{display:none}
 html.nav-rail .smpro-link.active{background:#1d2952;box-shadow:inset 3px 0 0 var(--brand)}
 html[dir=rtl].nav-rail .smpro-link.active{box-shadow:inset -3px 0 0 var(--brand)}
}
/* ---- skeleton shimmer (reusable: window.smproSkel(el,n) / .sm-skel > .skl) ---- */
.sm-skel{display:flex;flex-direction:column;gap:9px;margin-top:10px}
.skl{height:11px;border-radius:6px;background:linear-gradient(90deg,var(--line) 25%,#dfe5ef 37%,var(--line) 63%);background-size:400% 100%;animation:sklsh 1.4s ease infinite}
.skl.w40{width:40%}.skl.w55{width:55%}.skl.w72{width:72%}.skl.w90{width:90%}
@keyframes sklsh{0%{background-position:100% 0}100%{background-position:0 0}}
html[data-theme=dark] .skl{background:linear-gradient(90deg,#1c2740 25%,#26344f 37%,#1c2740 63%);background-size:400% 100%}
html[data-theme=dark] .spark{background:transparent!important;border:0!important}
</style>
</head>
<body>
<?php if (!empty($GLOBALS['SMPRO_LIC_GATE'])): /* license gate forced this render to the License page — sync the URL */ ?>
<script>try{if(window.history&&history.replaceState)history.replaceState(null,'','index.cgi?page=license');}catch(e){}</script>
<?php endif; ?>
<div class="smpro-top">
  <button class="burger" id="smproBurger" aria-label="Menu">&#9776;</button>
  <b style="font-size:15px">&#128737; <?= smpro_h(SMPRO_NAME) ?></b>
  <?php
    // live header health: Load / CPU / RAM / Temp (instant values; CPU + live updates via poll)
    $hLoad = function_exists('smpro_loadavg') ? smpro_loadavg()['1m'] : 0;
    $hCores = function_exists('smpro_cpu_cores') ? max(1, smpro_cpu_cores()) : 1;
    $hRam  = function_exists('smpro_memory') ? (float)smpro_memory()['percent'] : 0;
    $hTemp = function_exists('smpro_cpu_temp') ? smpro_cpu_temp() : null;
    $hLoadPct = round($hLoad / $hCores * 100);
    $hCls = function ($v, $w, $c) { return $v >= $c ? 'crit' : ($v >= $w ? 'warn' : 'ok'); };
    // Load chip coloured by ABSOLUTE 1-min load (admin spec), mapped to chip vocab.
    $shLoadCls = ['good' => 'ok', 'elev' => 'elev', 'warn' => 'warn', 'danger' => 'crit'][smpro_load_cls($hLoad)];
  ?>
  <div class="smpro-health" id="smproHealth" title="Live server health">
    <a class="sh-chip <?= $shLoadCls ?>" id="shLoadChip" href="index.cgi?page=load-monitor" style="cursor:pointer;text-decoration:none" title="1-minute load average. Colour: &le;10 green · &le;25 orange · &le;30 yellow · &gt;30 red — open Server Health &amp; System"><i>&#9889;</i><span data-i18n>load</span><b id="shLoad"><?= number_format($hLoad, 2) ?></b><i id="shLoadPct" style="opacity:.65;font-style:normal">· <?= (int)$hLoadPct ?>%</i></a>
    <a class="sh-chip" id="shCpuChip" href="index.cgi?page=top-processes" style="cursor:pointer;text-decoration:none" title="Top CPU processes"><i>&#128202;</i><span data-i18n>cpu</span><b id="shCpu">…</b></a>
    <span class="sh-chip <?= $hCls($hRam, 75, 90) ?>" id="shRamChip"><i>&#129518;</i><span data-i18n>ram</span><b id="shRam"><?= round($hRam) ?>%</b></span>
    <span class="sh-chip <?= $hTemp !== null ? $hCls($hTemp, 70, 82) : 'na' ?>" id="shTempChip"><i>&#127777;</i><span data-i18n>temp</span><b id="shTemp"><?= $hTemp !== null ? round($hTemp) . '°' : '—' ?></b></span>
  </div>
  <span class="sp"></span>
  <button class="smpro-ctl" id="smproTheme" type="button" title="Light / Dark">&#127769;</button>
  <a href="index.cgi?page=dashboard" class="hide-sm" data-i18n>Dashboard</a>
  <a href="index.cgi?page=<?= smpro_h($active) ?>" class="hide-sm" data-i18n>Refresh</a>
  <a href="<?= smpro_h($whm_home) ?>" class="hide-sm" data-i18n>WHM Home</a>
</div>
<script>
(function(){
  var poll, fails=0;
  function cls(v,w,c){return v>=c?'crit':(v>=w?'warn':'ok');}
  function lcls(v){return v>30?'crit':(v>25?'warn':(v>10?'elev':'ok'));}  // absolute load bands (admin spec)
  function setChip(id,val,txt,kls){var b=document.getElementById(id);if(!b)return;b.textContent=txt;var chip=b.closest('.sh-chip');if(chip)chip.className='sh-chip '+kls;}
  function tick(){
    fetch('index.cgi?format=json&metric=server',{cache:'no-store'}).then(function(r){return r.json();}).then(function(j){
      if(!j||j.license_required){clearInterval(poll);return;}
      var d=j.data; if(!d)return; fails=0;
      var loadPct=d.cores?Math.round(d.load['1m']/d.cores*100):0;
      setChip('shLoad', d.load['1m'], (d.load['1m']).toFixed(2), lcls(d.load['1m']));
      var lp=document.getElementById('shLoadPct'); if(lp) lp.textContent='· '+loadPct+'%';
      if(d.cpu) setChip('shCpu', d.cpu.pct, Math.round(d.cpu.pct)+'%', cls(d.cpu.pct,60,85));
      if(d.ram) setChip('shRam', d.ram.pct, Math.round(d.ram.pct)+'%', cls(d.ram.pct,75,90));
      setChip('shTemp', d.temp, (d.temp!=null?Math.round(d.temp)+'°':'—'), d.temp!=null?cls(d.temp,70,82):'na');
    }).catch(function(){ if(++fails>5)clearInterval(poll); });
  }
  if(document.getElementById('smproHealth')){ tick(); poll=setInterval(tick,5000); }
})();
</script>
<?php smpro_menu_render($active); ?>
<div class="smpro-ovl" id="smproOvl"></div>
<div class="smpro-main">
<div class="wrap">
<?php
// Licensing: soft warning when the plugin is not licensed on this server (hard-gate is opt-in in index.php).
if (function_exists('smpro_lic_is_valid') && !smpro_lic_is_valid() && (($GLOBALS['page'] ?? '') !== 'license')):
    $smLicSt = function_exists('smpro_lic_state') ? smpro_lic_state() : [];
?>
<div class="sm-licbar">
  <span class="sm-licico">&#128273;</span>
  <b><?= empty($smLicSt['key']) ? 'This copy of ' . smpro_h(SMPRO_NAME) . ' is not activated' : 'Your license is not valid' ?></b>
  <span class="sm-licsub"><?= empty($smLicSt['key']) ? 'Enter your license key to activate.' : smpro_h($smLicSt['message'] ?? 'Re-check or re-activate your license.') ?></span>
  <a class="sm-licbtn" href="index.cgi?page=license">Open License &#8594;</a>
</div>
<style>
.sm-licbar{display:flex;align-items:center;gap:10px;flex-wrap:wrap;background:#fef2f2;border:1px solid #fecaca;border-left:4px solid var(--dang);border-radius:12px;margin:0 0 14px;padding:10px 14px;font-size:13px;color:#991b1b}
.sm-licico{font-size:16px}.sm-licsub{color:#b91c1c;opacity:.9}
.sm-licbtn{margin-left:auto;background:var(--dang);color:#fff;text-decoration:none;font-weight:700;padding:7px 13px;border-radius:9px}
</style>
<?php endif; ?>
<?php
// CONNECTION-LOSS ladder banner (opted-in licenses only): takes precedence over the generic grace banner.
$smSyncShown = false;
$smSyncB = function_exists('smpro_lic_sync_banner') ? smpro_lic_sync_banner() : null;
if ($smSyncB && (($GLOBALS['page'] ?? '') !== 'license')):
    $smSyncShown = true;
?>
<div class="sm-gracebar sm-grace-<?= $smSyncB[0] === 'crit' ? 'crit' : 'info' ?>">
  <span class="sm-licico"><?= $smSyncB[0] === 'crit' ? '&#9888;' : '&#9432;' ?></span>
  <b><?= smpro_h($smSyncB[1]) ?></b> <span style="opacity:.85"><?= smpro_h($smSyncB[2]) ?></span>
  <a class="sm-licbtn" href="index.cgi?page=license" title="Open License — it re-checks the connection">Retry now</a>
</div>
<?php endif; ?>
<?php
// GRADUATED DEGRADATION: while the license server is unreachable, is_valid() stays TRUE through the 48h grace,
// but we escalate a banner (and shed heavy background work elsewhere) so a prolonged outage / deliberate
// blackhole is felt well before the hard lock. Phase is measured from the SIGNED last-contact (unforgeable).
$smGph = function_exists('smpro_lic_grace_phase') ? smpro_lic_grace_phase() : 0;
if (!$smSyncShown && $smGph >= 1 && (($GLOBALS['page'] ?? '') !== 'license')):
    $smGRem  = function_exists('smpro_lic_grace_remaining') ? smpro_lic_grace_remaining() : 0;
    $smGhrs  = (int)ceil($smGRem / 3600);
    $smGcls  = $smGph >= 3 ? 'crit' : ($smGph >= 2 ? 'warn' : 'info');
    $smGicon = $smGph >= 3 ? '&#9888;' : ($smGph >= 2 ? '&#9888;' : '&#9432;');
    $smGmsg  = $smGph >= 3
        ? 'License server unreachable — the plugin will fully stop in ~' . $smGhrs . 'h unless the connection is restored. Some heavy features are paused now.'
        : ($smGph >= 2
            ? 'License server unreachable for a while — some heavy features are paused. The plugin will stop in ~' . $smGhrs . 'h if the outage continues.'
            : 'License server temporarily unreachable — the plugin is running in a grace period.');
?>
<div class="sm-gracebar sm-grace-<?= $smGcls ?>">
  <span class="sm-licico"><?= $smGicon ?></span>
  <b><?= smpro_h($smGmsg) ?></b>
  <a class="sm-licbtn" href="index.cgi?page=license">License &#8594;</a>
</div>
<style>
.sm-gracebar{display:flex;align-items:center;gap:10px;flex-wrap:wrap;border-radius:12px;margin:0 0 14px;padding:10px 14px;font-size:13px}
.sm-grace-info{background:#eff6ff;border:1px solid #bfdbfe;border-left:4px solid #3b82f6;color:#1e40af}
.sm-grace-warn{background:#fffbeb;border:1px solid #fde68a;border-left:4px solid var(--warn);color:#7c5e16}
.sm-grace-crit{background:#fef2f2;border:1px solid #fecaca;border-left:4px solid var(--dang);color:#991b1b;animation:smGracePulse 1.6s ease-in-out infinite}
.sm-gracebar .sm-licbtn{margin-left:auto}
@keyframes smGracePulse{0%,100%{box-shadow:0 0 0 0 rgba(220,38,38,0)}50%{box-shadow:0 0 0 3px rgba(220,38,38,.18)}}
</style>
<?php endif; ?>
<?php
// Mandatory expiry reminder: valid license expiring within 3 days → always-visible banner.
if (function_exists('smpro_lic_is_valid') && smpro_lic_is_valid() && (($GLOBALS['page'] ?? '') !== 'license')):
    $smExp = trim((string)((function_exists('smpro_lic_state') ? smpro_lic_state() : [])['expiry'] ?? ''));
    $smExpTs = $smExp !== '' ? (is_numeric($smExp) ? (int)$smExp : strtotime($smExp)) : 0;
    $smRem = $smExpTs ? $smExpTs - time() : 0;
    if ($smExpTs && $smRem > 0 && $smRem <= 3 * 86400):
        $smDays = max(1, (int)ceil($smRem / 86400));
?>
<div class="sm-expbar">
  <span class="sm-licico">&#9203;</span>
  <b>License expires in ~<?= $smDays ?> day<?= $smDays > 1 ? 's' : '' ?></b>
  <span class="sm-expsub">Renew before <?= smpro_h($smExp) ?> — the plugin locks when the license expires.</span>
  <a class="sm-expbtn" href="index.cgi?page=license">License &#8594;</a>
</div>
<style>
.sm-expbar{display:flex;align-items:center;gap:10px;flex-wrap:wrap;background:#fffbeb;border:1px solid #fde68a;border-left:4px solid var(--warn);border-radius:12px;margin:0 0 14px;padding:10px 14px;font-size:13px;color:#7c5e16}
.sm-expsub{color:#92702a}.sm-expbtn{margin-left:auto;background:var(--warn,#d97706);color:#fff;text-decoration:none;font-weight:700;padding:7px 13px;border-radius:9px}
</style>
<?php endif; endif; ?>
<?php
// Multi-Server: a hub has invited THIS server — show a banner everywhere until handled (cheap cached read).
if (function_exists('smpro_hub_invites_cached') && (($GLOBALS['page'] ?? '') !== 'multi-server')):
    $smInv = smpro_hub_invites_cached();
    if ($smInv): $smInv0 = $smInv[0];
?>
<div class="sm-hubbar">
  <span class="sm-licico">&#128225;</span>
  <b><?= count($smInv) > 1 ? (count($smInv) . ' servers want') : ('“' . smpro_h($smInv0['hub_label'] ?: 'A hub') . '” wants') ?> to manage this server</b>
  <span class="sm-hubsub">Review the pairing request<?= count($smInv) > 1 ? 's' : '' ?> and choose what to allow — or decline.</span>
  <a class="sm-hubbtn" href="index.cgi?page=multi-server">Review &#8594;</a>
</div>
<style>
.sm-hubbar{display:flex;align-items:center;gap:10px;flex-wrap:wrap;background:var(--brand-bg,#eef2ff);border:1px solid #c7d2fe;border-left:4px solid var(--brand);border-radius:12px;margin:0 0 14px;padding:10px 14px;font-size:13px;color:#1e3a8a}
.sm-hubsub{color:#3749a6;opacity:.9}.sm-hubbtn{margin-left:auto;background:var(--brand);color:#fff;text-decoration:none;font-weight:700;padding:7px 13px;border-radius:9px}
</style>
<?php endif; endif; ?>
<?php
// Critical: an attack whose SOURCE is the server's own/local IP (possible local compromise) → always-visible bar.
if (function_exists('smpro_im_selfattack_recent') && (($GLOBALS['page'] ?? '') !== 'license')):
    $smSelf = smpro_im_selfattack_recent(6);
    if ($smSelf):
        $smSelfN = array_sum(array_map(fn($x) => (int)$x['n'], $smSelf));
?>
<div class="sm-selfbar">
  <span class="sm-licico">&#128680;</span>
  <b>Attack from the server's own / local IP detected</b>
  <span class="sm-selfsub"><?= count($smSelf) ?> local source(s), <?= $smSelfN ?> event(s) in the last 6h — a process on this server may be compromised and attacking hosted sites.</span>
  <button type="button" class="sm-selfinfo" onclick="var m=document.getElementById('smSelfMore');m.classList.toggle('open');this.classList.toggle('on');this.textContent=m.classList.contains('open')?'Hide info':'More info';">More info</button>
  <a class="sm-selfbtn" href="index.cgi?page=intrusion-monitor&amp;tab=live">Investigate &#8594;</a>
  <div id="smSelfMore" class="sm-selfmore">
    <div class="sm-selfwhat">A process running <b>on this server itself</b> (local / loopback source) is generating web attacks against hosted sites — a strong sign of a compromised account, script, or cron on the box (not an outside attacker you can simply firewall). Locate the source process/account in <b>Forensics&nbsp;/&nbsp;Audit</b> and <b>Top&nbsp;Processes</b>, then clean or isolate it.</div>
    <table class="sm-selftbl"><thead><tr><th>Local source IP</th><th>Events</th><th>Domains hit</th><th>Attack type</th><th>Last seen</th></tr></thead><tbody>
    <?php foreach ($smSelf as $s): ?>
      <tr><td style="font-family:ui-monospace,Consolas,monospace"><?= smpro_h((string)$s['ip']) ?></td><td><?= (int)$s['n'] ?></td><td><?= (int)$s['domains'] ?></td><td><?= smpro_h((string)$s['kind']) ?></td><td><?= !empty($s['last']) ? smpro_h(date('Y-m-d H:i', (int)$s['last'])) : '&mdash;' ?></td></tr>
    <?php endforeach; ?>
    </tbody></table>
    <div class="sm-selfact">Next: <a href="index.cgi?page=forensics-audit">Forensics / Audit</a> &middot; <a href="index.cgi?page=top-processes">Top Processes</a></div>
  </div>
</div>
<style>
.sm-selfbar{display:flex;align-items:center;gap:10px;flex-wrap:wrap;background:#fef2f2;border:1px solid #fecaca;border-left:4px solid var(--dang);border-radius:12px;margin:0 0 14px;padding:10px 14px;font-size:13px;color:#991b1b}
.sm-selfsub{color:#b91c1c;opacity:.9}
.sm-selfinfo{margin-left:auto;background:#fff;color:var(--dang);border:1px solid #fecaca;font-weight:700;padding:6px 12px;border-radius:9px;cursor:pointer;font-size:12.5px}
.sm-selfinfo.on{background:var(--dang);color:#fff}
.sm-selfbtn{background:var(--dang);color:#fff;text-decoration:none;font-weight:700;padding:7px 13px;border-radius:9px}
.sm-selfmore{display:none;flex-basis:100%;width:100%;margin-top:8px;background:#fff;border:1px solid #fecaca;border-radius:10px;padding:10px 12px}
.sm-selfmore.open{display:block}
.sm-selfwhat{color:#7f1d1d;font-size:12.5px;margin-bottom:8px;line-height:1.6}
.sm-selftbl{width:100%;border-collapse:collapse;font-size:12.5px}
.sm-selftbl th{text-align:left;color:#b91c1c;font-weight:700;padding:5px 8px;border-bottom:1px solid #fde2e2;font-size:11px;text-transform:uppercase;letter-spacing:.02em}
.sm-selftbl td{padding:5px 8px;border-bottom:1px solid #fdeaea;color:#7f1d1d}
.sm-selfact{margin-top:8px;font-size:12.5px}.sm-selfact a{color:var(--dang);font-weight:700}
</style>
<?php endif; endif; ?>
<?php
// Non-blocking environment warnings: components that are missing on this host.
// Each only disables its own feature — the rest of the plugin works normally.
$smMissing = function_exists('smpro_missing_capabilities') ? smpro_missing_capabilities() : [];
if ($smMissing):
?>
<div class="sm-envbar" id="smEnvBar" data-sig="<?= smpro_h(substr(md5(implode(',', array_column($smMissing, 'key'))), 0, 8)) ?>">
  <div class="sm-envhead">
    <span class="sm-envico">&#9888;</span>
    <b><?= count($smMissing) ?> optional component<?= count($smMissing) > 1 ? 's' : '' ?> not detected</b>
    <span class="sm-envsub">features below are disabled until you install them — everything else works</span>
    <button class="sm-envtoggle" id="smEnvToggle" type="button">Details &#9662;</button>
    <button class="sm-envx" id="smEnvDismiss" type="button" title="Hide until next change">&times;</button>
  </div>
  <div class="sm-envbody" id="smEnvBody" hidden>
    <?php $smEnvTok = function_exists('smpro_csrf_generate') ? smpro_csrf_generate('env_install') : ''; ?>
    <?php foreach ($smMissing as $m): ?>
      <div class="sm-envrow" data-comp="<?= smpro_h($m['key']) ?>">
        <span class="sm-envname"><?= $m['label'] ?></span>
        <span class="sm-envaff"><?= $m['affects'] ?></span>
        <span class="sm-envhint"><?= $m['hint'] ?>
          <?php if (!empty($m['doc'])): ?> <a href="<?= smpro_h($m['doc']) ?>" target="_blank" rel="noopener" class="sm-envdoc">install guide &#8599;</a><?php endif; ?>
        </span>
        <span class="sm-envact">
          <?php if (!empty($m['installable'])): ?>
            <button class="sm-envbtn" type="button" data-comp="<?= smpro_h($m['key']) ?>">&#11015; Install now</button>
          <?php else: ?>
            <span class="sm-envmanual">vendor install</span>
          <?php endif; ?>
        </span>
      </div>
    <?php endforeach; ?>
  </div>
</div>
<script>var SM_ENV_TOK=<?= json_encode($smEnvTok) ?>;</script>
<style>
.sm-envbar{background:#fffbeb;border:1px solid #fde68a;border-left:4px solid var(--warn);border-radius:12px;margin:0 0 14px;font-size:13px;color:#7c5e16}
.sm-envhead{display:flex;align-items:center;gap:10px;padding:10px 14px;flex-wrap:wrap}
.sm-envico{font-size:16px}.sm-envhead b{color:#92400e}
.sm-envsub{color:#a07c2a;font-size:12px}@media(max-width:680px){.sm-envsub{display:none}}
.sm-envtoggle{margin-left:auto;background:#fff;border:1px solid #fde68a;border-radius:8px;padding:4px 10px;font-size:12px;font-weight:700;color:#92400e;cursor:pointer}
.sm-envx{background:none;border:0;color:#b8932f;font-size:20px;line-height:1;cursor:pointer;padding:0 4px}
.sm-envbody{border-top:1px solid #fde68a;padding:6px 14px 12px}
.sm-envrow{display:grid;grid-template-columns:160px 1fr 150px;gap:2px 14px;padding:9px 0;border-bottom:1px dashed #fce6b5;align-items:start}
.sm-envrow:last-child{border-bottom:0}
.sm-envname{font-weight:800;color:#92400e;grid-row:1/3}
.sm-envaff{color:#7c5e16}.sm-envhint{grid-column:2;color:#a07c2a;font-size:12px}
.sm-envdoc{color:#3b5bdb;text-decoration:none;font-weight:600}
.sm-envact{grid-column:3;grid-row:1/3;text-align:right}
.sm-envbtn{background:var(--good);color:#fff;border:0;border-radius:8px;padding:6px 12px;font-size:12px;font-weight:700;cursor:pointer}
.sm-envbtn:disabled{opacity:.6;cursor:default}
.sm-envmanual{font-size:11px;color:#a07c2a;font-style:italic}
.sm-envres{display:block;font-size:11px;margin-top:4px}
@media(max-width:560px){.sm-envrow{grid-template-columns:1fr}.sm-envname,.sm-envhint,.sm-envact{grid-column:1;grid-row:auto;text-align:left}}
</style>
<script>
(function(){
  var bar=document.getElementById('smEnvBar');if(!bar)return;
  var sig=bar.getAttribute('data-sig');
  try{ if(localStorage.getItem('smEnvDismiss')===sig){bar.style.display='none';} }catch(e){}
  var body=document.getElementById('smEnvBody'),tg=document.getElementById('smEnvToggle');
  if(tg)tg.addEventListener('click',function(){var h=body.hasAttribute('hidden');if(h)body.removeAttribute('hidden');else body.setAttribute('hidden','');tg.innerHTML=h?'Details &#9652;':'Details &#9662;';});
  var x=document.getElementById('smEnvDismiss');
  if(x)x.addEventListener('click',function(){bar.style.display='none';try{localStorage.setItem('smEnvDismiss',sig);}catch(e){}});
  // Install-now buttons (package-manager components)
  bar.addEventListener('click',function(e){
    var b=e.target.closest('.sm-envbtn');if(!b)return;
    var comp=b.getAttribute('data-comp');
    if(!confirm('Install "'+comp+'" now via the server package manager?\n\nThis runs apt/dnf install on this server.'))return;
    var old=b.innerHTML,row=b.closest('.sm-envrow');
    b.disabled=true;b.innerHTML='⏳ Installing…';
    var res=row.querySelector('.sm-envres');if(!res){res=document.createElement('span');res.className='sm-envres';b.parentNode.appendChild(res);}
    res.textContent='';
    var fd=new URLSearchParams();fd.set('component',comp);fd.set('smpro_csrf',SM_ENV_TOK);
    fetch('index.cgi?env_install=1&format=json',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'})
      .then(function(r){return r.json();}).then(function(j){
        if(j&&j.ok){b.innerHTML='✅ Installed';res.style.color='#15803d';res.textContent=j.msg||'';setTimeout(function(){location.reload();},1400);}
        else{b.disabled=false;b.innerHTML=old;res.style.color='#b42318';res.textContent='⚠ '+((j&&j.msg)||'Install failed');}
      }).catch(function(){b.disabled=false;b.innerHTML=old;res.style.color='#b42318';res.textContent='⚠ Request failed';});
  });
})();
</script>
<?php endif; ?>
<?php if (function_exists('smpro_ai_available') && smpro_ai_available()): ?>
<div class="sm-aibar">
  <span class="sm-aibarlbl">&#129302; AI</span>
  <button class="sm-aibtn think" id="smAiThink" type="button">&#129504; Think (advice)</button>
  <button class="sm-aibtn decide" id="smAiDecide" type="button">&#9889; Decide &amp; act</button>
  <span class="sm-aibarhint">&#129504; Think = advice only · &#9889; Decide &amp; act = AI picks the actions, you click to apply</span>
</div>
<div class="sm-aiout" id="smAiOut" hidden></div>
<style>
.sm-aibar{display:flex;align-items:center;gap:10px;flex-wrap:wrap;background:linear-gradient(90deg,#faf5ff,#eef2ff);border:1px solid #e7dbfa;border-radius:12px;padding:9px 14px;margin:0 0 14px}
.sm-aibarlbl{font-weight:800;color:#7c3aed}
.sm-aibar .sm-aibtn{border:1px solid var(--line);border-radius:9px;padding:7px 13px;font-size:12px;font-weight:700;cursor:pointer;background:#fff;color:var(--ink)}.sm-aibtn[disabled]{opacity:.5}
.sm-aibtn.think{border-color:#c4a7f0;color:#7c3aed}.sm-aibtn.think:hover{background:#7c3aed;color:#fff}
.sm-aibtn.decide{border-color:#86c79b;color:#16864a}.sm-aibtn.decide:hover{background:#16864a;color:#fff}
.sm-aibarhint{font-size:11px;color:var(--muted);margin-left:auto}@media(max-width:680px){.sm-aibarhint{display:none}}
.sm-aiout{background:#fff;border:1px solid var(--line);border-radius:12px;padding:14px 16px;margin:0 0 14px;font-size:13px;line-height:1.6;color:#1f2733}
.sm-aiout h3{font-size:14px;color:#7c3aed;margin:12px 0 6px}.sm-aiout ul{margin:6px 0 10px;padding-left:20px}.sm-aiout li{margin:3px 0}.sm-aiout code{background:#f1f5f9;padding:1px 5px;border-radius:5px;font-family:ui-monospace,Consolas,monospace;font-size:12px;word-break:break-all}
.sm-aiouthd{display:flex;align-items:center;gap:8px;margin:-4px 0 8px;font-weight:700}.sm-aiouthd .meta{font-size:11px;font-weight:400}.sm-aiouthd .x{margin-left:auto;cursor:pointer;color:var(--muted);border:none;background:none;font-size:18px;line-height:1}
.sm-aierr{color:var(--dang);background:var(--dang-bg);padding:10px;border-radius:8px;font-size:12px}
.sm-aihint{color:var(--muted);font-size:12px}
.sm-decwrap{display:flex;flex-direction:column;gap:8px}
.sm-dec{border:1px solid var(--line);border-radius:10px;padding:9px 12px;background:#fbfcff}
.sm-dec-h{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.sm-dec-t{font-size:12px;color:var(--muted);font-family:ui-monospace,Consolas,monospace}
.sm-dec-w{font-size:12px;color:#475569;margin-top:5px}
.sm-decbtn{border:1px solid var(--line);border-radius:8px;padding:6px 13px;font-size:12px;font-weight:700;cursor:pointer;background:#fff;color:var(--ink)}
.sm-decbtn:disabled{opacity:.7;cursor:default}
.sm-decbtn.danger{border-color:#f3c4c4;color:var(--dang)}.sm-decbtn.danger:hover{background:var(--dang);color:#fff}
.sm-decbtn.warn{border-color:#f0d9a7;color:#a16207}.sm-decbtn.warn:hover{background:var(--warn);color:#fff}
.sm-decbtn.good{border-color:#bfe6cd;color:var(--good)}.sm-decbtn.good:hover{background:var(--good);color:#fff}
.sm-decbtn.ghost{border-color:#c9d4ff;color:var(--brand)}.sm-decbtn.ghost:hover{background:var(--brand);color:#fff}
.sm-dec-rb{margin-top:7px;font-size:12px;padding:7px 10px;border-radius:8px}
.sm-dec-rb.ok{background:var(--good-bg);color:#14532d}.sm-dec-rb.err{background:var(--dang-bg);color:var(--dang)}
</style>
<?php endif; ?>
<?php
}

function smpro_layout_footer() {
    ?>
<div class="foot">
  <b><?= smpro_h(SMPRO_NAME) ?></b> <span style="opacity:.7">v<?= smpro_h(SMPRO_VERSION) ?></span>
  <div style="margin-top:6px;opacity:.7">Last updated <?= smpro_h(date('Y-m-d H:i:s')) ?> · live server data.</div>
</div>
<?php if (function_exists('smpro_account_datalist')) smpro_account_datalist(); ?>
</div><!-- /wrap -->
</div><!-- /smpro-main -->
<div id="smTopLoad" class="sm-toploader" hidden><span></span></div>
<style>
.sm-toploader{position:fixed;top:0;left:0;right:0;height:3px;z-index:2000;background:rgba(124,58,237,.16);pointer-events:none;overflow:hidden}
.sm-toploader span{display:block;height:100%;width:40%;background:linear-gradient(90deg,#7c3aed,#4f46e5);animation:smtop 1s ease-in-out infinite}
@keyframes smtop{0%{margin-left:-40%}100%{margin-left:100%}}
@media print{.sm-toploader{display:none !important}}
/* ===== SMPRO modern buttons — global, emitted last so it unifies every module ===== */
.tp-btn,.btn,.fa-lnk{border-radius:10px;font-weight:600;letter-spacing:.005em;display:inline-flex;align-items:center;justify-content:center;gap:6px;white-space:nowrap;transition:transform .12s ease,box-shadow .16s ease,filter .16s ease,background .16s ease,border-color .16s ease}
.tp-btn,.btn{padding:8px 14px;font-size:13px;line-height:1.2;cursor:pointer}
.tp-btn:hover,.btn:hover{transform:translateY(-1px);box-shadow:0 6px 16px rgba(2,8,23,.13);filter:brightness(1.02)}
.tp-btn:active,.btn:active{transform:translateY(0);box-shadow:0 1px 3px rgba(2,8,23,.16)}
.tp-btn:focus-visible,.btn:focus-visible,.fa-lnk:focus-visible{outline:none;box-shadow:0 0 0 3px rgba(59,130,246,.35)}
.tp-btn[disabled],.btn[disabled],.tp-btn:disabled,.btn:disabled{opacity:.55;cursor:default;transform:none !important;box-shadow:none !important;filter:none}
.fa-lnk{padding:4px 10px;font-size:11px;cursor:pointer}
.fa-lnk:hover{transform:translateY(-1px);box-shadow:0 3px 9px rgba(2,8,23,.12)}
.btn-success,.btn-danger,.btn-warning,.btn-primary,.dsFix,.tp-btn.danger{box-shadow:0 2px 6px rgba(2,8,23,.10)}
.btn-success:hover,.btn-danger:hover,.btn-warning:hover,.btn-primary:hover,.dsFix:hover,.tp-btn.danger:hover{box-shadow:0 8px 20px rgba(2,8,23,.18)}
@media print{.tp-btn,.btn,.fa-lnk{box-shadow:none !important;transform:none !important}}
/* ===== Unified button colours — one look per STATE, applied to button variant classes only ===== */
/* PRIMARY (single brand colour for main actions) */
.btn-primary,.dsFix,.btn.primary,.tp-btn.primary{background:var(--brand) !important;color:#fff !important;border-color:var(--brand) !important}
/* SUCCESS = green */
.btn-success,.btn.success,.tp-btn.success{background:var(--good) !important;color:#fff !important;border-color:var(--good) !important}
/* DANGER = red (outline → fills on hover) */
.btn-danger,.tp-btn.danger,.dcDel,.dcClear,.btn.danger{background:#fff !important;color:var(--dang) !important;border-color:#f0c5c5 !important}
.btn-danger:hover,.tp-btn.danger:hover,.dcDel:hover,.dcClear:hover,.btn.danger:hover{background:var(--dang) !important;color:#fff !important;border-color:var(--dang) !important}
/* WARNING = amber */
.btn-warning,.btn.warning,.tp-btn.warning{background:#fff !important;color:#9a6700 !important;border-color:#f0d8b8 !important}
.btn-warning:hover,.btn.warning:hover,.tp-btn.warning:hover{background:#f59e0b !important;color:#fff !important;border-color:#f59e0b !important}
/* reusable inline scan progress bar (use inside a result/output area while a scan runs) */
.sm-scanbar{height:6px;border-radius:6px;background:rgba(124,58,237,.14);overflow:hidden;margin:8px 0}
.sm-scanbar span{display:block;height:100%;width:35%;border-radius:6px;background:linear-gradient(90deg,#7c3aed,#4f46e5);animation:smscan 1.1s ease-in-out infinite}
@keyframes smscan{0%{margin-left:-35%}100%{margin-left:100%}}
.sm-scanning{display:inline-flex;align-items:center;gap:8px;color:#64748b;font-size:12.5px}
.sm-scanning::before{content:"";width:13px;height:13px;border:2px solid #cbd5e1;border-top-color:#7c3aed;border-radius:50%;animation:smspin .7s linear infinite}
@keyframes smspin{to{transform:rotate(360deg)}}
</style>
<script>
(function(){
  // Universal non-blocking progress bar: shows for EVERY scan/action — page-load scans (navigation)
  // and AJAX scans/applies/tests — while excluding the frequent background pollers so it never flickers.
  var bar=document.getElementById('smTopLoad'); if(!bar)return;
  var n=0;
  function show(){n++;bar.hidden=false;} function dec(){n=Math.max(0,n-1);if(n===0)bar.hidden=true;} function hideAll(){n=0;bar.hidden=true;}

  // 1) Any AJAX request shows the bar (debounced 180ms so fast calls don't flash), except known pollers.
  if(window.fetch){var _f=window.fetch;
    var BG=/live=1|metric=|cool_action=status|cool_action=sources/;   // 3s status/metric polls — no bar
    window.fetch=function(input){
      var url=(typeof input==='string')?input:((input&&input.url)||'');
      if(BG.test(url)) return _f.apply(this,arguments);
      var shown=false, armed=setTimeout(function(){shown=true;show();},180);
      function fin(){clearTimeout(armed);if(shown)dec();}
      var p; try{p=_f.apply(this,arguments);}catch(e){fin();throw e;}
      return p.then(function(r){fin();return r;},function(e){fin();throw e;});
    };
  }
  // 2) Navigation-based scans (full page reload, e.g. Re-scan / opening a scan page).
  document.addEventListener('click',function(e){
    var el=e.target.closest&&e.target.closest('a,[data-scan]'); if(!el)return;
    if(el.hasAttribute('data-scan')){show();return;}
    var href=el.getAttribute('href')||'';
    if(href&&!/^#|^javascript:|^mailto:|^tel:/i.test(href)&&el.target!=='_blank'&&/index\.cgi|[?&]page=/.test(href))show();
  });
  document.addEventListener('submit',function(e){var f=e.target;if(f&&f.tagName==='FORM')show();});
  window.addEventListener('pageshow',hideAll); window.addEventListener('pagehide',hideAll);
})();
</script>
<!-- Global action modal: nice confirm + success card, reusable by every module. -->
<div id="smModalRoot"></div>
<style>
.sm-modal-ov{position:fixed;inset:0;background:rgba(15,23,42,.45);display:flex;align-items:center;justify-content:center;z-index:3000;padding:20px}
.sm-modal{background:#fff;border-radius:16px;max-width:440px;width:100%;box-shadow:0 20px 60px rgba(15,23,42,.3);overflow:hidden;animation:smpop .16s ease}
@keyframes smpop{from{transform:scale(.96);opacity:0}to{transform:scale(1);opacity:1}}
.sm-modal-ic{width:62px;height:62px;border-radius:50%;display:flex;align-items:center;justify-content:center;margin:22px auto 0;font-size:30px;font-weight:700}
.sm-modal-ic.ok{background:#e9f8ef;color:#16a34a}.sm-modal-ic.warn{background:#fef3c7;color:#b45309}.sm-modal-ic.err{background:#fee2e2;color:#dc2626}.sm-modal-ic.ask{background:#eef2ff;color:#4f46e5}
.sm-modal-b{padding:14px 24px 4px;text-align:center}
.sm-modal-t{font-size:17px;font-weight:800;color:#0f2657;margin:0 0 6px}
.sm-modal-m{font-size:13px;color:#475569;line-height:1.6;white-space:pre-wrap;max-height:240px;overflow:auto;text-align:left}
.sm-modal-f{display:flex;gap:10px;justify-content:center;padding:16px 24px 22px}
.sm-modal-btn{border:1px solid var(--line);border-radius:10px;padding:9px 20px;font-size:13px;font-weight:700;cursor:pointer;background:#fff;color:var(--ink)}
.sm-modal-btn.primary{background:#16a34a;color:#fff;border-color:#16a34a}.sm-modal-btn.danger{background:var(--dang);color:#fff;border-color:var(--dang)}
.la-done,.sm-done-chip{display:inline-block;font-size:11.5px;font-weight:800;padding:3px 10px;border-radius:20px;background:#e9f8ef;color:#16a34a;white-space:nowrap}
.la-done.allow{background:#eef2ff;color:#4f46e5}
</style>
<script>
(function(){
  function esc(s){var e=document.createElement('div');e.textContent=(s==null?'':String(s));return e.innerHTML;}
  window.smEsc=esc;
  function close(){var r=document.getElementById('smModalRoot');if(r)r.innerHTML='';}
  window.smModalClose=close;
  function build(o){
    var icc={ok:'&#10003;',warn:'&#9888;',err:'&#10006;',ask:'?'}[o.icon||'ok'];
    document.getElementById('smModalRoot').innerHTML=
      '<div class="sm-modal-ov"><div class="sm-modal" role="dialog" aria-modal="true">'
      +'<div class="sm-modal-ic '+(o.icon||'ok')+'">'+icc+'</div>'
      +'<div class="sm-modal-b"><div class="sm-modal-t">'+esc(o.title||'')+'</div>'
      +(o.message?'<div class="sm-modal-m">'+esc(o.message)+'</div>':'')+'</div>'
      +'<div class="sm-modal-f" id="smModalF"></div></div></div>';
  }
  window.smDone=function(o){o=o||{};build({icon:o.icon||'ok',title:o.title||'Done',message:o.message||''});
    var f=document.getElementById('smModalF'),b=document.createElement('button');
    b.className='sm-modal-btn primary';b.textContent=o.okText||'OK';
    b.addEventListener('click',function(){close();if(o.onClose)o.onClose();});f.appendChild(b);b.focus();};
  window.smConfirm=function(o){o=o||{};build({icon:o.icon||'ask',title:o.title||'Are you sure?',message:o.message||''});
    var f=document.getElementById('smModalF');
    var c=document.createElement('button');c.className='sm-modal-btn';c.textContent=o.cancelText||'Cancel';c.addEventListener('click',close);
    var k=document.createElement('button');k.className='sm-modal-btn '+(o.danger?'danger':'primary');k.textContent=o.confirmText||'Confirm';
    k.addEventListener('click',function(){close();if(o.onConfirm)o.onConfirm();});
    f.appendChild(c);f.appendChild(k);k.focus();};
})();
</script>
<!-- Generic popover styling (reused by the per-table column show/hide control). -->
<style>
.la-tabgearwrap{position:relative;display:inline-flex;align-items:center}
.la-tabgear{border:1px solid #cbd5e1;background:#fff;border-radius:8px;min-width:30px;height:30px;padding:0 10px;cursor:pointer;color:var(--muted);font-size:12px;font-weight:700;line-height:1;display:inline-flex;align-items:center;gap:5px}
.la-tabgear:hover{color:var(--brand);border-color:var(--brand)}
.la-tabpop{position:absolute;top:115%;right:0;z-index:60;background:#fff;border:1px solid var(--line);border-radius:10px;box-shadow:0 12px 32px rgba(15,23,42,.18);padding:8px;min-width:200px;max-height:340px;overflow:auto}
.la-tabpop .hd{font-size:11px;font-weight:800;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;padding:2px 8px 6px;display:flex;justify-content:space-between;align-items:center}
.la-tabpop .hd a{font-weight:700;color:var(--brand);text-decoration:none;font-size:11px}
.la-tabpop label{display:flex;align-items:center;gap:8px;padding:5px 8px;border-radius:7px;font-size:13px;color:var(--ink);cursor:pointer;white-space:nowrap}
.la-tabpop label:hover{background:var(--brand-bg)}
/* ── universal table enhancements (sort + column borders + resize handle) — applied to every .smpro-table ── */
.smpro-table th[data-sort]{cursor:pointer;user-select:none}
.smpro-table th[data-sort]:hover{color:var(--brand)}
.smpro-table th.sorted-asc::after{content:" \25B2";font-size:8px}
.smpro-table th.sorted-desc::after{content:" \25BC";font-size:8px}
.smpro-table th,.smpro-table td{border-right:1px solid var(--line)}
.smpro-table th:last-child,.smpro-table td:last-child{border-right:0}
.sm-colresize{position:absolute;top:0;right:-3px;width:8px;height:100%;cursor:col-resize;user-select:none;z-index:2}
.sm-colresize:hover{background:var(--brand);opacity:.3}
body.sm-resizing{cursor:col-resize!important;user-select:none}
.smpro-table td{overflow:hidden;text-overflow:ellipsis}
html[data-theme=dark] .smpro-table th,html[data-theme=dark] .smpro-table td{border-right-color:#27324a}
</style>
<!-- Universal table engine: click-to-sort, draggable column resize, ⚙ column show/hide. Auto-runs on every .smpro-table. -->
<script>
(function(){
  function headerCells(t){var hr=t.tHead&&t.tHead.rows[0];return hr?hr.cells:null;}
  function isActionTh(th){var x=(th.textContent||'').trim().toLowerCase();return x===''||x==='action'||x==='actions'||x==='#'||!!th.querySelector('input,button');}
  function ensureId(t){if(!t.id){window.__smTblN=(window.__smTblN||0)+1;t.id='smtbl'+window.__smTblN;}return t.id;}
  // ---- sorting ----
  function cval(c,type){if(!c)return type==='num'?0:'';var v=c.getAttribute('data-val');if(v==null)v=c.textContent.trim();return type==='num'?(parseFloat((''+v).replace(/[^0-9.\-]/g,''))||0):(''+v).toLowerCase();}
  function doSort(t,th){var tb=t.tBodies[0];if(!tb)return;var idx=Array.prototype.indexOf.call(th.parentNode.children,th),type=th.getAttribute('data-sort')||'str',dir=th.getAttribute('data-dir')||'asc';
    var rows=Array.prototype.slice.call(tb.querySelectorAll('tr')).filter(function(r){return r.parentNode===tb&&r.querySelector('td');});
    rows.sort(function(a,b){var x=cval(a.children[idx],type),y=cval(b.children[idx],type);return (x<y?-1:x>y?1:0)*(dir==='asc'?1:-1);});
    rows.forEach(function(r){tb.appendChild(r);});}
  window.smReapplySort=function(t){if(!t)return;var th=t.querySelector('thead th[data-sort][data-dir]');if(th)doSort(t,th);};
  function bindSort(t){var ths=headerCells(t);if(!ths)return;
    for(var i=0;i<ths.length;i++){var th=ths[i];if(!th.hasAttribute('data-sort')){if(isActionTh(th))continue;th.setAttribute('data-sort',th.classList.contains('num')?'num':'str');}}
    Array.prototype.forEach.call(t.querySelectorAll('thead th[data-sort]'),function(th){if(th.dataset.smSortBound)return;th.dataset.smSortBound='1';
      th.addEventListener('click',function(e){if(e.target.classList.contains('sm-colresize'))return;var dir=th.getAttribute('data-dir')==='asc'?'desc':'asc';
        Array.prototype.forEach.call(t.querySelectorAll('th[data-sort]'),function(o){o.removeAttribute('data-dir');o.classList.remove('sorted-asc','sorted-desc');});
        th.setAttribute('data-dir',dir);th.classList.add(dir==='asc'?'sorted-asc':'sorted-desc');doSort(t,th);});});}
  // ---- draggable column resize (widths persist per table) ----
  function makeResizable(t){var hr=t.tHead&&t.tHead.rows[0];if(!hr)return;var ths=hr.cells;if(ths.length<2)return;var key='smcolw:'+t.id;
    function lock(){if(t.dataset.smFixed)return;t.dataset.smFixed='1';var ws=[],i;for(i=0;i<ths.length;i++)ws[i]=ths[i].offsetWidth;t.style.width=t.offsetWidth+'px';t.style.tableLayout='fixed';for(i=0;i<ths.length;i++)ths[i].style.width=ws[i]+'px';}
    function restore(){try{var s=JSON.parse(localStorage.getItem(key)||'null');if(s&&s.length===ths.length){lock();var tot=0,i;for(i=0;i<ths.length;i++){ths[i].style.width=s[i]+'px';tot+=s[i];}t.style.width=tot+'px';}}catch(e){}}
    function persist(){try{var a=[],i;for(i=0;i<ths.length;i++)a[i]=ths[i].offsetWidth;localStorage.setItem(key,JSON.stringify(a));}catch(e){}}
    for(var i=0;i<ths.length-1;i++){(function(th){th.style.position='relative';var h=document.createElement('span');h.className='sm-colresize';h.title='Drag to resize';th.appendChild(h);
      h.addEventListener('mousedown',function(e){e.preventDefault();e.stopPropagation();lock();var sx=e.clientX,sw=th.offsetWidth,stw=t.offsetWidth;document.body.classList.add('sm-resizing');
        function mv(ev){var w=Math.max(36,sw+(ev.clientX-sx));th.style.width=w+'px';t.style.width=(stw+(w-sw))+'px';}
        function up(){document.removeEventListener('mousemove',mv);document.removeEventListener('mouseup',up);document.body.classList.remove('sm-resizing');persist();}
        document.addEventListener('mousemove',mv);document.addEventListener('mouseup',up);});})(ths[i]);}
    setTimeout(restore,1200);}
  // ---- ⚙ column show/hide (hides via injected <style> nth-child so it survives live re-renders) ----
  function makeColumnToggle(t){var hr=t.tHead&&t.tHead.rows[0];if(!hr)return;var ths=hr.cells;if(ths.length<2)return;var ckey='smcolhide:'+t.id;
    var hidden=[];try{hidden=JSON.parse(localStorage.getItem(ckey)||'[]')||[];}catch(e){}
    var st=document.createElement('style');document.head.appendChild(st);
    function apply(){var css='';hidden.forEach(function(i){var n=i+1;css+='#'+t.id+' th:nth-child('+n+'),#'+t.id+' td:nth-child('+n+'){display:none}';});st.textContent=css;}
    function persist(){try{localStorage.setItem(ckey,JSON.stringify(hidden));}catch(e){}}
    var wrap=document.createElement('span');wrap.className='la-tabgearwrap';
    var btn=document.createElement('button');btn.type='button';btn.className='la-tabgear';btn.title='Show / hide columns';btn.innerHTML='&#9881; Columns';
    var pop=document.createElement('div');pop.className='la-tabpop';pop.hidden=true;
    var hd=document.createElement('div');hd.className='hd';hd.innerHTML='<span>Show columns</span>';
    var all=document.createElement('a');all.href='#';all.textContent='Show all';all.addEventListener('click',function(e){e.preventDefault();hidden=[];persist();apply();Array.prototype.forEach.call(pop.querySelectorAll('input'),function(c){c.checked=true;});});
    hd.appendChild(all);pop.appendChild(hd);
    for(var i=0;i<ths.length;i++){(function(idx){var label=(ths[idx].textContent||'').trim();if(!label)return;
      var row=document.createElement('label');var cb=document.createElement('input');cb.type='checkbox';cb.checked=hidden.indexOf(idx)<0;
      cb.addEventListener('change',function(){var k=hidden.indexOf(idx);if(cb.checked){if(k>=0)hidden.splice(k,1);}else{if(k<0)hidden.push(idx);}persist();apply();});
      row.appendChild(cb);row.appendChild(document.createTextNode(' '+label));pop.appendChild(row);})(i);}
    btn.addEventListener('click',function(e){e.stopPropagation();pop.hidden=!pop.hidden;});
    pop.addEventListener('click',function(e){e.stopPropagation();});
    document.addEventListener('click',function(){pop.hidden=true;});
    wrap.appendChild(btn);wrap.appendChild(pop);
    var scroll=t.closest('.la-scroll')||t;
    var bar=document.createElement('div');bar.style.cssText='display:flex;justify-content:flex-end;margin:0 0 6px';bar.appendChild(wrap);
    if(scroll.parentNode)scroll.parentNode.insertBefore(bar,scroll);
    apply();}
  function enhance(t){if(t.dataset.smEnh)return;t.dataset.smEnh='1';ensureId(t);var ths=headerCells(t);var n=ths?ths.length:0;
    bindSort(t);
    if(n>=4&&!t.classList.contains('no-enhance')){makeResizable(t);makeColumnToggle(t);}}
  window.smEnhanceTables=function(root){Array.prototype.forEach.call((root||document).querySelectorAll('table.smpro-table'),enhance);};
  window.imReapplySort=window.imReapplySort||window.smReapplySort;   // back-compat alias for intrusion live feed
  function init(){window.smEnhanceTables(document);}
  if(document.readyState!=='loading')init();else document.addEventListener('DOMContentLoaded',init);
})();
</script>
<?php if (function_exists('smpro_ai_available') && smpro_ai_available()):
    $smAiTok = smpro_csrf_generate('ai_assist');
    $smAiCtx = preg_replace('/[^a-z0-9_\-]/', '', strtolower((string)($_GET['page'] ?? 'dashboard'))) ?: 'dashboard';
?>
<script>
(function(){
  var TOK=<?= json_encode($smAiTok) ?>, CTX=<?= json_encode($smAiCtx) ?>;
  var out=document.getElementById('smAiOut'),bT=document.getElementById('smAiThink'),bD=document.getElementById('smAiDecide');
  if(!out)return;
  function md(t){var e=document.createElement('div');e.textContent=t;var h=e.innerHTML;
    h=h.replace(/^#{1,3} (.*)$/gm,'<h3>$1</h3>').replace(/\*\*([^*]+)\*\*/g,'<b>$1</b>').replace(/`([^`]+)`/g,'<code>$1</code>');
    h=h.replace(/^\s*[-*\d.]+ (.*)$/gm,'<li>$1</li>').replace(/(<li>[\s\S]*?<\/li>)/g,'<ul>$1</ul>');
    return h.replace(/\n{2,}/g,'<br><br>').replace(/\n/g,'<br>');}
  function head(title){return '<div class="sm-aiouthd"><b>&#129302; '+title+'</b><span class="meta" id="smAiM"></span><button class="x" id="smAiClose" type="button">&times;</button></div>';}
  function bindClose(){var c=document.getElementById('smAiClose');if(c)c.addEventListener('click',function(){out.hidden=true;});}
  function skel(){return '<div class="sm-skel"><div class="skl w55"></div><div class="skl w90"></div><div class="skl w72"></div><div class="skl w90"></div><div class="skl w40"></div></div>';}
  window.smproSkel=function(el,n){if(!el)return;var ws=['w55','w90','w72','w40','w90'],h='<div class="sm-skel">';for(var i=0;i<(n||4);i++)h+='<div class="skl '+ws[i%ws.length]+'"></div>';el.innerHTML=h+'</div>';};
  function run(mode,q){
    out.hidden=false; out.innerHTML=head(mode==='think'?'Analysis':'Recommended decisions')+'<div class="sm-aihint">&#129302; '+(mode==='think'?'Analyzing this section…':'Working out the best decisions…')+'</div>'+skel(); bindClose();
    bT.disabled=true;bD.disabled=true; out.scrollIntoView({behavior:'smooth',block:'nearest'});
    var fd=new URLSearchParams();fd.set('q',q);fd.set('ctx',CTX);fd.set('smpro_csrf',TOK);
    fetch('index.cgi?ai_assist=1&format=json',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString()})
      .then(function(r){return r.json();}).then(function(j){
        bT.disabled=false;bD.disabled=false;
        out.innerHTML=head(mode==='think'?'Analysis':'Recommended decisions')+(j&&j.ok?md(j.text||'(empty)'):'<div class="sm-aierr">'+((j&&j.error)||'AI request failed')+'</div>'); bindClose();
        var m=document.getElementById('smAiM');if(m&&j&&j.ok)m.textContent=(j.provider||'')+' · '+(j.model||'');
      }).catch(function(){bT.disabled=false;bD.disabled=false;out.innerHTML=head('Error')+'<div class="sm-aierr">Request failed.</div>';bindClose();});
  }
  if(bT)bT.addEventListener('click',function(){run('think','Analyze the current state of the \"'+CTX+'\" section on this cPanel/WHM server: what is happening, the top risks, and what they mean. Be concise and concrete.');});

  // Recommend decisions → structured, EXECUTABLE action buttons (Block/Delete/Clean/Suspend…).
  function esc(s){var e=document.createElement('div');e.textContent=(s==null?'':String(s));return e.innerHTML;}
  function runDecide(){
    out.hidden=false; out.innerHTML=head('Recommended decisions')+'<div class="sm-aihint">&#129302; Reading live data &amp; working out executable decisions…</div>'+skel(); bindClose();
    bT.disabled=true;bD.disabled=true; out.scrollIntoView({behavior:'smooth',block:'nearest'});
    var fd=new URLSearchParams();fd.set('mode','decide');fd.set('q','decide');fd.set('ctx',CTX);fd.set('smpro_csrf',TOK);
    fetch('index.cgi?ai_assist=1&format=json',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString()})
      .then(function(r){return r.json();}).then(function(j){
        bT.disabled=false;bD.disabled=false;
        if(!j||!j.ok){out.innerHTML=head('Recommended decisions')+'<div class="sm-aierr">'+esc((j&&j.error)||'AI request failed')+'</div>';bindClose();return;}
        var h=head('Recommended decisions');
        if(j.summary)h+='<div style="margin:0 0 8px">'+esc(j.summary)+'</div>';
        var ds=j.decisions||[];
        if(!ds.length){h+='<div class="sm-aihint" style="position:static">'+esc(j.note||'No actions recommended right now.')+'</div>';out.innerHTML=h;bindClose();
          var m0=document.getElementById('smAiM');if(m0&&j.provider)m0.textContent=(j.provider||'')+' · '+(j.model||'');return;}
        h+='<div class="sm-decwrap">';
        ds.forEach(function(d,i){
          h+='<div class="sm-dec" data-i="'+i+'"><div class="sm-dec-h"><button type="button" class="sm-decbtn '+esc((d.exec&&d.exec.cls)||'ghost')+'" data-i="'+i+'">'+esc(d.label||d.action)+'</button>'
            +'<span class="sm-dec-t">'+esc(d.target||'')+'</span></div>'
            +(d.why?'<div class="sm-dec-w">'+esc(d.why)+'</div>':'')+'<div class="sm-dec-r" id="smDecR'+i+'"></div></div>';
        });
        h+='</div>';
        out.innerHTML=h; bindClose();
        var m=document.getElementById('smAiM');if(m&&j.provider)m.textContent=(j.provider||'')+' · '+(j.model||'');
        window.__smDecs=ds;
      }).catch(function(){bT.disabled=false;bD.disabled=false;out.innerHTML=head('Error')+'<div class="sm-aierr">Request failed.</div>';bindClose();});
  }
  if(bD)bD.addEventListener('click',runDecide);

  // Execute a decision button: confirm → POST exec.fields to exec.url (or navigate).
  if(out)out.addEventListener('click',function(e){
    var b=e.target.closest('.sm-decbtn');if(!b)return;
    var ds=window.__smDecs||[];var d=ds[+b.getAttribute('data-i')];if(!d||!d.exec)return;
    var x=d.exec, res=document.getElementById('smDecR'+b.getAttribute('data-i'));
    if(x.nav){window.location.href=x.nav;return;}
    if(x.confirm&&!confirm(x.confirm))return;
    var old=b.innerHTML;b.disabled=true;b.innerHTML='⏳ Working…';
    var fd=new URLSearchParams();Object.keys(x.fields||{}).forEach(function(k){fd.set(k,x.fields[k]);});
    fetch(x.url,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'})
      .then(function(r){return r.json();}).then(function(j){
        var ok=j&&(j.ok===true||(j.results&&j.results.some&&j.results.some(function(r){return r.ok;})));
        var msg=j&&j.msg?j.msg:(j&&j.results&&j.results[0]?(j.results[0].msg||''):'');
        if(j&&j.results&&!msg){var f=j.results.filter(function(r){return !r.ok;});if(f.length)msg=f.map(function(r){return r.ip+': '+r.msg;}).join('; ');}
        b.innerHTML=ok?'✅ Done':old;b.disabled=ok?true:false;
        if(res)res.innerHTML='<div class="sm-dec-rb '+(ok?'ok':'err')+'">'+(ok?'✅ ':'⚠ ')+esc(msg||(ok?'Executed.':'Failed.'))+'</div>';
      }).catch(function(){b.disabled=false;b.innerHTML=old;if(res)res.innerHTML='<div class="sm-dec-rb err">⚠ Request failed.</div>';});
  });
})();
</script>
<?php endif; ?>
<script>
(function(){
  var d=document.documentElement, body=document.body;
  /* ---- sidebar: desktop = collapse (persisted) · mobile = drawer ---- */
  var b=document.getElementById('smproBurger'),o=document.getElementById('smproOvl');
  function isMobile(){return window.matchMedia('(max-width:860px)').matches;}
  if(b)b.addEventListener('click',function(){
    if(isMobile()){ body.classList.toggle('smpro-open'); return; }
    var rail=!d.classList.contains('nav-rail');
    d.classList.toggle('nav-rail',rail);
    try{localStorage.setItem('smpro_nav',rail?'rail':'full');}catch(e){}
    smproRailTitles(rail);
  });
  function smproRailTitles(on){try{document.querySelectorAll('.smpro-side .smpro-link').forEach(function(a){var s=a.querySelector('span[data-i18n]');if(!s)return;if(on)a.setAttribute('title',s.textContent.trim());else a.removeAttribute('title');});}catch(e){}}
  smproRailTitles(d.classList.contains('nav-rail'));
  if(o)o.addEventListener('click',function(){body.classList.remove('smpro-open');});

  /* ---- theme: light / dark ---- */
  var tb=document.getElementById('smproTheme');
  function syncTheme(){ if(tb) tb.innerHTML = d.getAttribute('data-theme')==='dark' ? '&#9728;&#65039;' : '&#127769;'; }
  syncTheme();
  if(tb)tb.addEventListener('click',function(){
    var dark=d.getAttribute('data-theme')!=='dark';
    if(dark)d.setAttribute('data-theme','dark');else d.removeAttribute('data-theme');
    try{localStorage.setItem('smpro_theme',dark?'dark':'light');}catch(e){}
    syncTheme();
  });

  /* language switcher removed — the plugin renders in English (its source language) on every page */
  try{ if(localStorage.getItem('smpro_lang'))localStorage.removeItem('smpro_lang'); }catch(e){}
  d.setAttribute('dir','ltr'); d.setAttribute('lang','en');
})();
</script>
<?php if (empty($GLOBALS['SMPRO_LIC_GATE']) && function_exists('smpro_fw_self_should_prompt') && smpro_fw_self_should_prompt()):
  $smSelfIp = smpro_admin_ip(); $smSelfTok = function_exists('smpro_csrf_generate') ? smpro_csrf_generate('fw_self') : ''; ?>
<style>
#smSelfModal{position:fixed;inset:0;z-index:99999;display:none;align-items:center;justify-content:center;background:rgba(8,15,30,.55);backdrop-filter:blur(2px);font-family:inherit}
#smSelfModal.show{display:flex}
#smSelfModal .sm-card{background:#fff;color:#0f1b33;width:min(440px,92vw);border-radius:16px;box-shadow:0 24px 70px rgba(0,0,0,.4);overflow:hidden;animation:smPop .18s ease-out}
@keyframes smPop{from{transform:translateY(10px) scale(.97);opacity:0}to{transform:none;opacity:1}}
#smSelfModal .sm-hd{display:flex;align-items:center;gap:10px;padding:16px 18px;background:linear-gradient(135deg,#3b5bdb,#2a3f9e);color:#fff}
#smSelfModal .sm-hd .sm-ic{font-size:22px}#smSelfModal .sm-hd b{font-size:15px}
#smSelfModal .sm-bd{padding:16px 18px;font-size:14px;line-height:1.6}
#smSelfModal .sm-ip{display:inline-block;font-family:monospace;font-weight:800;background:#eef2ff;color:#2a3f9e;padding:2px 9px;border-radius:7px}
#smSelfModal .sm-ft{display:flex;gap:10px;justify-content:flex-end;padding:0 18px 18px}
#smSelfModal button{border:0;border-radius:10px;padding:10px 18px;font-size:13.5px;font-weight:700;cursor:pointer}
#smSelfModal .sm-ok{background:#16a34a;color:#fff}#smSelfModal .sm-ok:hover{background:#15803d}
#smSelfModal .sm-no{background:#eef1f6;color:#475569}#smSelfModal .sm-no:hover{background:#e2e8f0}
#smSelfModal .sm-msg{margin-top:10px;font-size:13px;font-weight:700;display:none}
</style>
<div id="smSelfModal" role="dialog" aria-modal="true">
  <div class="sm-card">
    <div class="sm-hd"><span class="sm-ic">&#128737;</span><b>Safety Monitor Pro — Firewall</b></div>
    <div class="sm-bd">
      Your admin IP <span class="sm-ip" id="smSelfIpTxt"></span> is <b>not</b> on the firewall allow-list.<br>
      Add it to the CSF allow-list (<b>full allow — never blocked</b>) so the firewall can never lock you out?
      <div class="sm-msg" id="smSelfMsg"></div>
    </div>
    <div class="sm-ft">
      <button class="sm-no" id="smSelfNo">Cancel</button>
      <button class="sm-ok" id="smSelfYes">&#9989; Allow my IP</button>
    </div>
  </div>
</div>
<script>
/* RULE: on entry, offer (styled modal) to allow-list the admin's own IP (full allow / never block) */
(function(){
  var ip=<?= json_encode($smSelfIp) ?>, tok=<?= json_encode($smSelfTok) ?>;
  if(!ip||!tok) return;
  try{ if(sessionStorage.getItem('smpro_selfip_'+ip)) return; }catch(e){}
  var modal=document.getElementById('smSelfModal'); if(!modal) return;
  document.getElementById('smSelfIpTxt').textContent=ip;
  function close(){ modal.classList.remove('show'); }
  function send(act){
    try{ sessionStorage.setItem('smpro_selfip_'+ip,'1'); }catch(e){}
    var fd=new URLSearchParams(); fd.set('smpro_csrf',tok);
    if(act==='dismiss'){ close(); }
    else { var y=document.getElementById('smSelfYes'); y.disabled=true; y.textContent='⏳ Adding…'; }
    fetch('index.cgi?fw_self='+act,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'})
      .then(function(r){return r.json();}).then(function(j){
        if(act!=='dismiss'){ var m=document.getElementById('smSelfMsg'); m.style.display='block';
          m.style.color=(j&&j.ok)?'#16a34a':'#dc2626'; m.textContent=(j&&j.ok?'✅ ':'⚠ ')+((j&&j.msg)||'Done');
          setTimeout(close,1400); }
      }).catch(function(){ if(act!=='dismiss'){var m=document.getElementById('smSelfMsg');m.style.display='block';m.style.color='#dc2626';m.textContent='⚠ Request failed';} });
  }
  document.getElementById('smSelfYes').addEventListener('click',function(){ send('add'); });
  document.getElementById('smSelfNo').addEventListener('click',function(){ send('dismiss'); });
  setTimeout(function(){ modal.classList.add('show'); }, 900);
})();
</script>
<?php endif; ?>
</body>
</html>
<?php
}

/** Shared placeholder for menu items not built yet (keeps menu fully usable). */
function smpro_render_placeholder($item) {
    smpro_layout_header($item['label']);
    echo '<h1 class="h">' . smpro_h($item['label']) . '</h1>';
    echo '<p class="sub">This module is part of Safety Monitor Pro and is scheduled for an upcoming phase.</p>';
    echo '<div class="card"><div class="lbl">Status</div><div class="val" style="font-size:18px">Planned</div>'
       . '<div class="meta" style="margin-top:6px">Route <code>?page=' . smpro_h($item['id']) . '</code> is registered and reachable. '
       . 'The shared menu is active on every page. Pick this module next and it will read live data here.</div></div>';
    smpro_layout_footer();
}

/** A section whose feature is not included in the active license. */
function smpro_render_locked($item) {
    smpro_layout_header($item['label']);
    echo '<div style="max-width:620px;margin:30px auto;text-align:center">';
    echo '<div style="font-size:46px">&#128274;</div>';
    echo '<h1 class="h" style="margin:8px 0">' . smpro_h($item['label']) . ' is locked</h1>';
    echo '<p class="sub">This section is not included in your current license' . (function_exists('smpro_lic_state') && !empty(smpro_lic_state()['plan']) ? ' (' . smpro_h(smpro_lic_state()['plan']) . ' plan)' : '') . '. '
       . 'Upgrade or activate a license that includes the <code>' . smpro_h($item['feature'] ?? '') . '</code> feature to use it.</p>';
    echo '<a class="tp-btn primary" style="display:inline-block;margin-top:10px;background:var(--brand);color:#fff;border:0;padding:11px 20px;border-radius:10px;text-decoration:none;font-weight:700" href="index.cgi?page=license">&#128273; Open License</a>';
    echo '</div>';
    smpro_layout_footer();
}
