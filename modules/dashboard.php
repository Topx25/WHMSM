<?php
/**
 * modules/dashboard.php — LIVE dashboard.
 * Initial render uses real values; JS then polls ?format=json every 2s and
 * updates the numbers in place (real-time, no page reload, light /proc reads).
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

$m = smpro_collect_metrics();
$attn = function_exists('smpro_dash_attention') ? smpro_dash_attention($m) : [];
smpro_audit('dashboard_view', ['pressure' => $m['pressure']]);
// Keep the Security & Health score honest: refresh the cached Server Tune-up hardening posture in the background
// (throttled, detached — never scans inline) so the score reflects open hardening items, not just acute issues.
if (function_exists('smpro_tun_posture_refresh_async')) { try { smpro_tun_posture_refresh_async(); } catch (\Throwable $e) { if (function_exists('smpro_soft_fail')) smpro_soft_fail(basename(__FILE__) . ':' . __LINE__, $e); } }

smpro_layout_header('Dashboard');
?>
<h1 class="h">System Overview
  <span class="live" id="smLive"><i></i> LIVE <span id="smClock"><?= smpro_h($m['ts']) ?></span></span>
</h1>
<p class="sub">Real-time server status from <code><?= smpro_h($m['host']) ?></code> — auto-updating every 5s. No heavy scans, no changes.</p>

<?php
  $uc  = function_exists('smpro_upd_cfg') ? smpro_upd_cfg() : [];
  $uCur = defined('SMPRO_VERSION') ? SMPRO_VERSION : '?';
  $uLatest = (string)($uc['latest'] ?? '');
  $uNew = $uLatest !== '' && version_compare($uLatest, $uCur, '>');
?>
<p class="sub" style="margin-top:-4px">
  Version <b><?= smpro_h($uCur) ?></b>
  · Latest available <b><?= smpro_h($uLatest !== '' ? $uLatest : '—') ?></b>
  <?php if ($uNew): ?>
    <a href="index.cgi?page=updates" style="margin-left:6px;background:#f59e0b;color:#fff;border-radius:6px;padding:2px 9px;text-decoration:none;font-weight:800">&#8593; Update available — v<?= smpro_h($uLatest) ?></a>
  <?php else: ?>
    <span style="margin-left:6px;color:#16a34a;font-weight:700">&#10003; up to date</span>
  <?php endif; ?>
  <span style="color:var(--muted);font-size:11.5px;margin-left:6px">checked daily</span>
</p>

<?php if (function_exists('smpro_insight_render')) echo smpro_insight_render($m); ?>

<?php if (function_exists('smpro_score_render')) smpro_score_render($m, $attn); ?>

<?php
// Managed servers (Hub) — show every linked member's live status right on the main dashboard.
if (function_exists('smpro_hub_active') && smpro_hub_active() && function_exists('smpro_hub_fleet_cached')):
  $dfleet = smpro_hub_fleet_cached();
  if ($dfleet):
?>
<?php $dprob = 0; foreach ($dfleet as $F) if (smpro_hub_snap_issues($F['snap'])) $dprob++; ?>
<div class="card" style="margin:6px 0 16px">
  <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px;flex-wrap:wrap">
    <b style="font-size:15px">&#127760; Managed servers</b>
    <span class="meta"><?= count($dfleet) ?> linked</span>
    <?php if ($dprob): ?><span class="df-attn">&#9888; <?= $dprob ?> need attention</span><?php else: ?><span class="df-ok">&#10003; all healthy</span><?php endif; ?>
    <a href="index.cgi?page=multi-server" class="lnk" style="margin-left:auto">Open Hub &rarr;</a>
  </div>
  <div class="df-grid">
    <?php foreach ($dfleet as $F): $L=$F['link']; $s=$F['snap']; $nm=$L['member_host'] ?: ('Server #'.(int)($L['link_id'] ?? 0)); $mon=(($L['mode']??'control')==='monitor'); $iss=smpro_hub_snap_issues($s); ?>
    <a class="df-card<?= $iss?' df-bad':'' ?>" href="index.cgi?page=multi-server" title="Open the Hub to manage this server">
      <div class="df-h"><b><?= smpro_h($nm) ?></b> <span class="df-pill <?= $mon?'mon':'ctl' ?>"><?= $mon?'monitor':'control' ?></span></div>
      <?php if ($iss): ?><div class="df-iss">&#9888; <?= smpro_h(implode(' · ', $iss)) ?></div><?php endif; ?>
      <?php if (!$s): ?><div class="meta">waiting for first report…</div>
      <?php else: $ld=is_array($s['load']??null)?($s['load']['1m']??'?'):($s['load']??'?'); ?>
        <div class="df-row"><span>load <b><?= smpro_h(is_numeric($ld)?round((float)$ld,2):$ld) ?></b></span><span>cpu <b><?= isset($s['cpu'])&&$s['cpu']!==null?round((float)$s['cpu']).'%':'?' ?></b></span><span>ram <b><?= isset($s['mem'])&&$s['mem']!==null?round((float)$s['mem']).'%':'?' ?></b></span><span>disk <b><?= isset($s['disk'])&&$s['disk']!==null?round((float)$s['disk']).'%':'?' ?></b></span></div>
        <div class="meta" style="margin-top:4px">v<?= smpro_h($s['version']??'?') ?><?= isset($s['uptime'])?' · up '.smpro_h($s['uptime']):'' ?><?= !empty($s['svc_failed'])?' · <span style="color:var(--dang)">'.(int)$s['svc_failed'].' failed</span>':'' ?><?= !empty($s['rebooted'])?' · <span style="color:var(--dang)">&#8635; reboot</span>':'' ?></div>
      <?php endif; ?>
    </a>
    <?php endforeach; ?>
  </div>
</div>
<style>
.df-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(215px,1fr));gap:10px}
.df-card{display:block;border:1px solid var(--line);border-radius:11px;padding:11px 12px;background:var(--card);color:inherit;text-decoration:none}
.df-card:hover{border-color:var(--brand)}
.df-h{display:flex;gap:6px;align-items:center;margin-bottom:6px;font-size:13.5px}
.df-row{display:flex;gap:12px;flex-wrap:wrap;font-size:12px;color:var(--muted)}
.df-row b{color:var(--ink)}
.df-pill{font-size:9.5px;font-weight:700;padding:1px 7px;border-radius:7px;text-transform:uppercase}
.df-pill.mon{background:var(--warn-bg);color:var(--warn)}.df-pill.ctl{background:var(--brand-bg);color:var(--brand)}
.df-attn{font-size:11.5px;font-weight:800;color:var(--dang);background:var(--dang-bg);padding:2px 10px;border-radius:20px}
.df-ok{font-size:11.5px;font-weight:700;color:var(--good);background:var(--good-bg);padding:2px 10px;border-radius:20px}
.df-card.df-bad{border-color:var(--dang);box-shadow:0 0 0 1px var(--dang) inset}
.df-iss{font-size:11.5px;color:var(--dang);font-weight:600;margin:4px 0 2px}
</style>
<?php endif; endif; ?>

<div id="smAttn" class="attn-wrap"<?= $attn ? '' : ' hidden' ?>>
  <div class="attn-hd">&#128226; Needs attention <span class="attn-n" id="smAttnN"><?= count($attn) ?></span></div>
  <div class="attn-list" id="smAttnList"><?php
    foreach ($attn as $x) {
      echo '<a class="attn-item attn-' . smpro_h($x['sev']) . '" href="index.cgi?page=' . smpro_h($x['page']) . '">'
         . '<span class="attn-ic">' . $x['icon'] . '</span><span class="attn-tx"><b>' . smpro_h($x['title']) . '</b>'
         . '<span class="attn-d">' . smpro_h($x['detail']) . '</span></span><span class="attn-go">&#8594;</span></a>';
    }
  ?></div>
</div>

<?php
// Service status — headline Running/Down tiles; the Down tile deep-links into the Service Manager drill-in.
if (function_exists('smpro_svc_scan_cached')):
  [$svcRows, $svcTs, $svcCached] = smpro_svc_scan_cached(60);
  $svcUp = 0; $svcInst = 0; $svcDown = 0;
  foreach ((array)$svcRows as $rr) { if (!empty($rr['installed'])) $svcInst++; if (!empty($rr['active'])) $svcUp++; if (!empty($rr['down'])) $svcDown++; }
  $svmCfg = function_exists('smpro_svcmon_cfg') ? smpro_svcmon_cfg() : ['enabled'=>false,'monitor'=>[]];
?>
<div class="dsvc">
  <a class="dsvc-c good" href="index.cgi?page=cpanel-services" title="Open the Service Manager">
    <span class="dsvc-ic">&#10003;</span>
    <span class="dsvc-b"><span class="dsvc-n"><?= (int)$svcUp ?></span><span class="dsvc-l">Services running</span><span class="dsvc-s">of <?= (int)$svcInst ?> installed</span></span>
  </a>
  <a class="dsvc-c <?= $svcDown ? 'bad' : 'good' ?>" href="index.cgi?page=cpanel-services<?= $svcDown ? '#svcDown' : '' ?>" title="<?= $svcDown ? 'View and fix the stopped services' : 'All services are up' ?>">
    <span class="dsvc-ic"><?= $svcDown ? '&#9888;' : '&#10003;' ?></span>
    <span class="dsvc-b"><span class="dsvc-n"><?= (int)$svcDown ?></span><span class="dsvc-l"><?= $svcDown ? 'Services down' : 'None down' ?></span><span class="dsvc-s"><?= $svcDown ? 'Click to view &amp; fix &rarr;' : 'all up' ?></span></span>
  </a>
  <a class="dsvc-c mon <?= $svmCfg['enabled'] ? 'on' : 'off' ?>" href="index.cgi?page=cpanel-services#svcMon" title="Service Monitor settings">
    <span class="dsvc-ic">&#128737;</span>
    <span class="dsvc-b"><span class="dsvc-l">Auto-monitor</span><span class="dsvc-n2"><?= $svmCfg['enabled'] ? 'ON' : 'OFF' ?></span><span class="dsvc-s"><?= $svmCfg['enabled'] ? ('watching ' . count($svmCfg['monitor']) . ' · manage &rarr;') : 'turn on &rarr;' ?></span></span>
  </a>
</div>
<?php endif; ?>

<!-- KPI row (matches HostGuard product mockup) -->
<div class="dkpi">
  <div class="dkpi-c">
    <div class="dkpi-l">CPU usage</div>
    <div class="dkpi-v"><span data-k="cpu.pct"><?= smpro_h($m['cpu']['pct']) ?></span><span class="dkpi-u">%</span></div>
    <div class="dkpi-s"><span class="trend" data-trend="cpu"></span> <span data-k="cores"><?= (int)$m['cores'] ?></span> cores</div>
    <div class="bar"><i data-bar="cpu" class="<?= $m['cpu']['status'] ?>" style="width:<?= min(100,$m['cpu']['pct']) ?>%"></i></div>
  </div>
  <div class="dkpi-c">
    <div class="dkpi-l">Memory</div>
    <div class="dkpi-v"><span data-k="ram.pct"><?= smpro_h($m['ram']['pct']) ?></span><span class="dkpi-u">%</span></div>
    <div class="dkpi-s"><span data-k="ram.used"><?= smpro_h($m['ram']['used']) ?></span> / <span data-k="ram.total"><?= smpro_h($m['ram']['total']) ?></span></div>
    <div class="bar"><i data-bar="ram" class="<?= $m['ram']['status'] ?>" style="width:<?= min(100,$m['ram']['pct']) ?>%"></i></div>
  </div>
  <div class="dkpi-c">
    <div class="dkpi-l">Disk usage</div>
    <div class="dkpi-v"><span data-k="disk.pct"><?= smpro_h($m['disk']['pct']) ?></span><span class="dkpi-u">%</span></div>
    <div class="dkpi-s"><span data-k="disk.used"><?= smpro_h($m['disk']['used']) ?></span> / <span data-k="disk.total"><?= smpro_h($m['disk']['total']) ?></span> used</div>
    <div class="bar"><i data-bar="disk" class="<?= $m['disk']['status'] ?>" style="width:<?= min(100,$m['disk']['pct']) ?>%"></i></div>
  </div>
  <div class="dkpi-c">
    <div class="dkpi-l">Uptime</div>
    <div class="dkpi-v dkpi-v-sm"><span data-k="uptime"><?= smpro_h($m['uptime']) ?></span></div>
    <div class="dkpi-s"><span class="pill" data-k="health.pill"><?= smpro_h($m['health_label']) ?></span></div>
  </div>
</div>

<!-- CPU load chart + server-health panel -->
<div class="drow2">
  <div class="card dchart">
    <div class="dchart-hd"><span class="dkpi-l">CPU load</span><span class="meta">live · last ~10 min · every 5s</span></div>
    <div class="dchart-wrap">
      <div class="dchart-y"><span>100</span><span>50</span><span>0</span></div>
      <svg class="dchart-svg" viewBox="0 0 100 24" preserveAspectRatio="none" data-spark="cpu"><defs><linearGradient id="cpuFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#3b82f6" stop-opacity="0.34"/><stop offset="1" stop-color="#3b82f6" stop-opacity="0"/></linearGradient></defs><polygon class="dchart-area" points="" fill="url(#cpuFill)" stroke="none"/><polyline points="" fill="none" stroke-width="0.7" stroke-linejoin="round" stroke-linecap="round"/></svg>
    </div>
  </div>
  <div class="card dhealth">
    <div class="dkpi-l">Server health — load pressure</div>
    <div class="val" style="margin-top:6px"><span data-k="pressure"><?= smpro_h($m['pressure']) ?></span>% <span style="font-size:13px;color:var(--muted);font-weight:400">of <span data-k="cores"><?= (int)$m['cores'] ?></span> cores</span></div>
    <div class="bar"><i data-bar="pressure" class="<?= $m['health'] ?>" style="width:<?= min(100,$m['pressure']) ?>%"></i></div>
    <div class="meta" style="margin-top:10px">Load&nbsp;avg&nbsp; 1m <b data-k="load.1m"><?= smpro_h($m['load']['1m']) ?></b> · 5m <b data-k="load.5m"><?= smpro_h($m['load']['5m']) ?></b> · 15m <b data-k="load.15m"><?= smpro_h($m['load']['15m']) ?></b></div>
    <div class="meta" style="margin-top:6px">Processes <b data-k="procs"><?= (int)$m['procs'] ?></b> · Swap <b data-k="swap.pct"><?= smpro_h($m['swap']['pct']) ?></b>% (<span data-k="swap.used_mb"><?= smpro_h($m['swap']['used_mb']) ?></span>/<span data-k="swap.total_mb"><?= smpro_h($m['swap']['total_mb']) ?></span> MB)</div>
    <div class="bar" style="margin-top:8px"><i data-bar="swap" class="<?= $m['swap']['status'] ?>" style="width:<?= min(100,$m['swap']['pct']) ?>%"></i></div>
    <div class="meta" style="margin-top:6px"><span data-k="disk.free"><?= smpro_h($m['disk']['free']) ?></span> disk free</div>
  </div>
</div>

<?php if (function_exists('smpro_sc_render')) smpro_sc_render(); ?>

<?php if (function_exists('smpro_dash_sections')): $secs = smpro_dash_sections($m); ?>
<div class="lbl" style="margin:18px 0 8px">Sections <span class="meta" style="font-weight:400;font-size:11.5px">— summary of each area, click to open</span></div>
<div class="sec-grid">
  <?php foreach ($secs as $c): ?>
    <a class="sec-card sec-<?= smpro_h($c['tone'] ?: 'none') ?>" href="index.cgi?page=<?= smpro_h($c['page']) ?>">
      <div class="sec-top"><span class="sec-ic"><?= $c['icon'] ?></span><span class="sec-lbl"><?= $c['label'] ?></span><span class="sec-go">&#8594;</span></div>
      <div class="sec-stat"><?= $c['stat'] ?></div>
      <div class="sec-sub"><?= $c['sub'] ?></div>
    </a>
  <?php endforeach; ?>
</div>
<?php endif; ?>

<style>
.live{font-size:11px;font-weight:700;color:var(--good);background:var(--good-bg);padding:3px 10px;border-radius:20px;vertical-align:middle;margin-left:8px}
.live i{display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--good);margin-right:5px;animation:smpulse 1.2s infinite}
.live.stale{color:var(--muted);background:var(--card)}.live.stale i{background:var(--muted);animation:none}
@keyframes smpulse{0%,100%{opacity:1}50%{opacity:.25}}
[data-k]{transition:color .25s}
.flash{color:var(--brand)!important}
.dash-load.good{color:var(--good)}.dash-load.elev{color:#f97316}.dash-load.warn{color:var(--warn)}.dash-load.danger{color:var(--dang)}
.dash-loadpill{font-weight:800;padding:1px 8px;border-radius:20px}
.dash-loadpill.good{background:var(--good-bg);color:var(--good)}.dash-loadpill.elev{background:rgba(249,115,22,.15);color:#f97316}.dash-loadpill.warn{background:var(--warn-bg);color:var(--warn)}.dash-loadpill.danger{background:var(--dang-bg);color:var(--dang)}
.attn-wrap{margin-bottom:14px;border-radius:14px;border:1px solid #fed7aa;background:var(--warn-bg);padding:12px 14px}
.attn-hd{font-weight:800;color:#9a3412;font-size:13px;margin-bottom:8px}
.attn-n{display:inline-block;min-width:18px;text-align:center;background:#ea580c;color:#fff;border-radius:20px;font-size:11px;padding:1px 7px;margin-left:4px}
.attn-list{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:8px}
.attn-item{display:flex;align-items:center;gap:10px;text-decoration:none;border-radius:10px;padding:9px 11px;background:var(--card);border:1px solid #fde6c8;color:var(--ink);transition:.15s}
.attn-item:hover{transform:translateY(-1px);box-shadow:0 3px 12px rgba(234,88,12,.14)}
.attn-item.attn-critical{border-left:4px solid #dc2626}.attn-item.attn-warn{border-left:4px solid #f59e0b}.attn-item.attn-info{border-left:4px solid #0ea5e9}
.attn-ic{font-size:18px}.attn-tx{display:flex;flex-direction:column;line-height:1.3;flex:1}.attn-tx b{font-size:13px}.attn-d{font-size:11.5px;color:#64748b}
.attn-go{color:#ea580c;font-weight:900}
.sec-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:10px}
.sec-card{display:block;text-decoration:none;color:var(--ink);background:var(--card);border:1px solid var(--line);border-radius:14px;padding:13px 15px;transition:.15s}
.sec-card:hover{border-color:var(--brand);box-shadow:0 4px 16px rgba(124,58,237,.12);transform:translateY(-2px)}
.sec-top{display:flex;align-items:center;gap:8px;margin-bottom:8px}
.sec-ic{font-size:17px}.sec-lbl{font-weight:700;font-size:13px}.sec-go{margin-left:auto;color:var(--muted);font-weight:900}
.sec-card:hover .sec-go{color:var(--brand)}
.sec-stat{font-size:20px;font-weight:800;line-height:1.1}.sec-sub{font-size:11.5px;color:var(--muted);margin-top:3px}
.sec-card.sec-good .sec-stat{color:#16a34a}.sec-card.sec-warn{border-left:4px solid #f59e0b}.sec-card.sec-warn .sec-stat{color:#b45309}
.sec-card.sec-crit{border-left:4px solid #dc2626}.sec-card.sec-crit .sec-stat{color:#dc2626}
.spark{width:100%;height:24px;margin-top:8px;display:block}
/* service status tiles */
.dsvc{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:6px 0 14px}
@media(max-width:700px){.dsvc{grid-template-columns:1fr}}
.dsvc-c{display:flex;align-items:center;gap:14px;text-decoration:none;color:var(--ink);background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px 16px;transition:.15s}
.dsvc-c:hover{transform:translateY(-2px);box-shadow:0 4px 16px rgba(0,0,0,.08)}
.dsvc-c.good{border-left:5px solid var(--good)}
.dsvc-c.bad{border-left:5px solid var(--dang)}
.dsvc-c.mon.on{border-left:5px solid var(--brand)}.dsvc-c.mon.off{border-left:5px solid var(--line)}
.dsvc-ic{font-size:24px;width:46px;height:46px;flex:none;display:flex;align-items:center;justify-content:center;border-radius:12px;background:var(--brand-bg);color:var(--brand)}
.dsvc-c.good .dsvc-ic{background:var(--good-bg);color:var(--good)}
.dsvc-c.bad .dsvc-ic{background:var(--dang-bg);color:var(--dang)}
.dsvc-b{display:flex;flex-direction:column;line-height:1.2}
.dsvc-n{font-size:26px;font-weight:800}
.dsvc-n2{font-size:17px;font-weight:800;margin-top:1px}
.dsvc-c.mon.on .dsvc-n2{color:var(--brand)}.dsvc-c.mon.off .dsvc-n2{color:var(--muted)}
.dsvc-l{font-weight:700;font-size:13px;margin-top:1px}
.dsvc-s{font-size:11px;color:var(--muted);margin-top:1px}
/* KPI row + CPU chart (HostGuard mockup layout) */
.dkpi{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:12px}
.dkpi-c{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px 16px}
.dkpi-l{font-size:10.5px;letter-spacing:.05em;text-transform:uppercase;color:var(--muted);font-weight:700}
.dkpi-v{font-size:30px;font-weight:800;line-height:1.1;margin-top:7px;color:var(--ink);font-variant-numeric:tabular-nums}
.dkpi-v-sm{font-size:19px}
.dkpi-u{font-size:16px;color:var(--muted);font-weight:700;margin-left:1px}
.dkpi-s{font-size:11.5px;color:var(--muted);margin-top:6px}
.dkpi-c .bar{margin-top:11px}
.drow2{display:grid;grid-template-columns:2fr 1fr;gap:12px;margin-bottom:14px}
.dchart-hd{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:12px}
.dchart-wrap{position:relative;height:150px;padding-left:28px}
.dchart-wrap::before{content:"";position:absolute;left:28px;right:0;top:0;bottom:0;background-image:linear-gradient(var(--line) 1px,transparent 1px);background-size:100% 75px;opacity:.5;pointer-events:none}
.dchart-svg{width:100%;height:150px;display:block;position:relative}
.dchart-y{position:absolute;left:0;top:-5px;bottom:-5px;width:24px;display:flex;flex-direction:column;justify-content:space-between;font-size:9.5px;color:var(--muted);text-align:right;font-variant-numeric:tabular-nums}
@media(max-width:820px){.dkpi{grid-template-columns:repeat(2,1fr)}.drow2{grid-template-columns:1fr}}
.trend{font-size:10.5px;font-weight:700;padding:1px 6px;border-radius:10px;vertical-align:middle}
.trend.up{color:var(--dang);background:var(--dang-bg)}
.trend.down{color:var(--good);background:var(--good-bg)}
.trend.flat{color:var(--muted);background:var(--card)}
</style>
<script>
(function(){
  var URL='index.cgi?page=dashboard&format=json&metric=server';
  var live=document.getElementById('smLive');
  // ---- rolling history + sparklines (client-side, persisted ~10min) ----
  var HK='smpro_hist_v1',HMAX=40,HWIN=15;
  var hist=(function(){try{var j=JSON.parse(localStorage.getItem(HK)||'{}');if(j&&j.t&&(Date.now()-j.t)<600000&&j.d)return j.d;}catch(e){}return{cpu:[],ram:[],disk:[],swap:[]};})();
  function saveHist(){try{localStorage.setItem(HK,JSON.stringify({t:Date.now(),d:hist}));}catch(e){}}
  function pushHist(d){
    var mp={cpu:d.cpu&&d.cpu.pct,ram:d.ram&&d.ram.pct,disk:d.disk&&d.disk.pct,swap:d.swap&&d.swap.pct};
    Object.keys(mp).forEach(function(k){var v=parseFloat(mp[k]);if(isNaN(v))return;(hist[k]=hist[k]||[]).push(v);if(hist[k].length>HMAX)hist[k].shift();});
    saveHist();
  }
  function spk(a){if(!a||a.length<2)return '';var n=a.length,W=100,H=24,p=3;return a.map(function(v,i){var x=(i/(n-1))*W;var y=H-p-(Math.max(0,Math.min(100,v))/100)*(H-2*p);return x.toFixed(1)+','+y.toFixed(1);}).join(' ');}
  function spkCol(k){var b=document.querySelector('[data-bar="'+k+'"]');var c=b?b.className:'';if(c.indexOf('danger')>=0)return '#d93b3b';if(c.indexOf('warn')>=0)return '#c47f17';if(c.indexOf('elev')>=0)return '#f97316';return '#1f9d55';}
  function drawSparks(){['cpu','ram','disk','swap'].forEach(function(k){
    var pl=document.querySelector('[data-spark="'+k+'"] polyline');if(pl){var lnp=spk(hist[k]);pl.setAttribute('points',lnp);pl.setAttribute('stroke',spkCol(k));var pg=document.querySelector('[data-spark="'+k+'"] polygon');if(pg)pg.setAttribute('points',lnp?('0,24 '+lnp+' 100,24'):'');}
    var tr=document.querySelector('[data-trend="'+k+'"]');if(!tr)return;var a=hist[k]||[];
    if(a.length<HWIN+1){tr.textContent='';tr.className='trend';return;}
    var dl=a[a.length-1]-a[a.length-1-HWIN];
    if(Math.abs(dl)<1){tr.textContent='steady';tr.className='trend flat';}
    else{tr.textContent=(dl>0?'▲ ':'▼ ')+Math.abs(Math.round(dl))+'%';tr.className='trend '+(dl>0?'up':'down');}
  });}
  function set(k,v){
    document.querySelectorAll('[data-k="'+k+'"]').forEach(function(el){
      if(el.textContent!==String(v)){el.textContent=v;el.classList.add('flash');setTimeout(function(){el.classList.remove('flash');},300);}
    });
  }
  function bar(name,pct,status){
    var el=document.querySelector('[data-bar="'+name+'"]');
    if(el){el.style.width=Math.min(100,pct)+'%';el.className=status;}
  }
  function apply(d){
    set('uptime',d.uptime);set('cores',d.cores);set('procs',d.procs);
    set('pressure',d.pressure);set('load.1m',d.load['1m']);set('load.5m',d.load['5m']);set('load.15m',d.load['15m']);
    set('cpu.pct',d.cpu.pct);set('ram.pct',d.ram.pct);set('ram.used',d.ram.used);set('ram.total',d.ram.total);
    set('disk.pct',d.disk.pct);set('disk.used',d.disk.used);set('disk.total',d.disk.total);set('disk.free',d.disk.free);
    set('swap.pct',d.swap.pct);set('swap.used_mb',d.swap.used_mb);set('swap.total_mb',d.swap.total_mb);
    bar('pressure',d.pressure,d.health);bar('cpu',d.cpu.pct,d.cpu.status);bar('ram',d.ram.pct,d.ram.status);
    bar('disk',d.disk.pct,d.disk.status);bar('swap',d.swap.pct,d.swap.status);
    var pill=document.querySelector('[data-k="health.pill"]');if(pill){pill.textContent=d.health_label;pill.className='pill '+d.health;}
    var _lc=(d.load&&d.load['1m']>30)?'danger':(d.load&&d.load['1m']>25?'warn':(d.load&&d.load['1m']>10?'elev':'good'));
    var dl=document.getElementById('dashLoadV');if(dl)dl.className='val dash-load '+_lc;
    var dlp=document.getElementById('dashLoadPill');if(dlp)dlp.className='dash-loadpill '+_lc;
    var c=document.getElementById('smClock');if(c)c.textContent=d.ts;
    pushHist(d);drawSparks();
    if(live)live.classList.remove('stale');
  }
  function esc(s){var e=document.createElement('div');e.textContent=(s==null?'':String(s));return e.innerHTML;}
  function renderAttn(list){
    var w=document.getElementById('smAttn');if(!w)return;
    if(!list||!list.length){w.hidden=true;return;}
    w.hidden=false;
    var n=document.getElementById('smAttnN');if(n)n.textContent=list.length;
    var html='';
    list.forEach(function(x){
      html+='<a class="attn-item attn-'+esc(x.sev)+'" href="index.cgi?page='+esc(x.page)+'">'
          +'<span class="attn-ic">'+(x.icon||'')+'</span><span class="attn-tx"><b>'+esc(x.title)+'</b>'
          +'<span class="attn-d">'+esc(x.detail)+'</span></span><span class="attn-go">&#8594;</span></a>';
    });
    document.getElementById('smAttnList').innerHTML=html;
  }
  function tick(){
    if(document.hidden)return; // pause when tab not visible
    fetch(URL,{cache:'no-store'}).then(function(r){return r.json();})
      .then(function(j){if(j&&j.ok&&j.data){apply(j.data);renderAttn(j.attention);}})
      .catch(function(){if(live)live.classList.add('stale');});
  }
  drawSparks();          // paint whatever history we already have, before the first poll
  tick();                // refresh immediately on load (don't wait for the first interval)
  setInterval(tick,5000);  // 5s (was 2s) — each poll is a full PHP-CLI request; 5s stays "live" while cutting server load ~60%
  document.addEventListener('visibilitychange',function(){if(!document.hidden)tick();});
})();
</script>
<?php
smpro_layout_footer();
