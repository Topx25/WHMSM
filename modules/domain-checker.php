<?php
/**
 * modules/domain-checker.php - Domain Checker.
 * Lists every hosted domain with its owner + account status (fast, server-side), then deep-checks
 * each domain on demand (live DNS A record vs this server's IPs, + WHOIS expiry) via ?domchk=1.
 * Multi-select + per-row Suspend / Terminate of the owning cPanel account (root, CSRF, confirmed).
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

$domains   = smpro_dom_list();
$serverIps = smpro_dom_server_ips();
$csrf      = smpro_csrf_generate('domchk');
$suspended = 0; foreach ($domains as $d) if (!empty($d['suspended'])) $suspended++;
smpro_audit('domain_checker_view', ['domains' => count($domains)]);
smpro_layout_header('Domain Checker');
?>
<script>var DC_CSRF=<?= json_encode($csrf) ?>,DC_SERVER_IPS=<?= json_encode(array_values($serverIps)) ?>;</script>
<div class="svc-kicker">Security &amp; Access</div>
<h1 class="h" style="margin:2px 0 4px">&#127760; Domain Checker</h1>
<p class="sub">Every domain hosted on this server with its owner, account status, registrar expiry, and the live IP it points to — so you can spot <b>expired</b> domains and domains that <b>resolve to another server</b>. This server's IP(s): <code><?= smpro_h(implode(', ', $serverIps) ?: 'unknown') ?></code>.</p>

<div class="fw-kpis" style="grid-template-columns:repeat(4,minmax(0,1fr))">
  <a class="fw-kpi brand" href="#dc-table" data-go="dc-table"><div class="l">Domains</div><div class="v"><?= count($domains) ?></div><div class="s">hosted on this server</div></a>
  <a class="fw-kpi warn" href="#dc-table" data-go="dc-table"><div class="l">Point elsewhere</div><div class="v" id="dcMismatchN">—</div><div class="s">resolve to another IP · after a scan</div></a>
  <a class="fw-kpi dang" href="#dc-table" data-go="dc-table"><div class="l">Expired</div><div class="v" id="dcExpiredN">—</div><div class="s">registrar expiry passed · after a scan</div></a>
  <a class="fw-kpi <?= $suspended ? 'warn' : 'muted' ?>" href="#dc-table" data-go="dc-table"><div class="l">Suspended accts</div><div class="v"><?= (int)$suspended ?></div><div class="s">owning account suspended</div></a>
</div>
<nav class="fw-nav" id="dcNav"><a href="#dc-tools" data-go="dc-tools">&#128270; Scan &amp; export</a><a href="#dc-table" data-go="dc-table">&#127760; Domains</a><span class="sp"></span><button type="button" class="fw-navx" id="dcOpenAll">expand all</button><button type="button" class="fw-navx" id="dcCloseAll">collapse all</button></nav>
<div class="card dc-tools" id="dc-tools">
  <button type="button" class="btn" id="dcCheckAll" style="background:var(--brand);color:#fff">&#128270; Check all domains</button>
  <button type="button" class="btn" id="dcExport" style="background:#217346;color:#fff">&#128190; Export CSV</button>
  <button type="button" class="btn" id="dcCopy" style="background:#475569;color:#fff">&#128203; Copy list</button>
  <span id="dcProg" class="meta"></span>
</div>

<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:10px">
  <input type="text" id="dcSearch" placeholder="Filter by domain or user…" style="flex:1;min-width:200px;padding:7px 11px;border:1px solid var(--line);border-radius:9px;font-size:13px">
  <label style="display:inline-flex;align-items:center;gap:5px;font-size:12.5px;background:var(--card);border:1px solid var(--line);border-radius:9px;padding:6px 10px;cursor:pointer"><input type="radio" name="dcFilter" value="all" checked> All</label>
  <label style="display:inline-flex;align-items:center;gap:5px;font-size:12.5px;background:var(--card);border:1px solid var(--line);border-radius:9px;padding:6px 10px;cursor:pointer"><input type="radio" name="dcFilter" value="mismatch"> Point elsewhere</label>
  <label style="display:inline-flex;align-items:center;gap:5px;font-size:12.5px;background:var(--card);border:1px solid var(--line);border-radius:9px;padding:6px 10px;cursor:pointer"><input type="radio" name="dcFilter" value="expired"> Expired</label>
  <label style="display:inline-flex;align-items:center;gap:5px;font-size:12.5px;background:var(--card);border:1px solid var(--line);border-radius:9px;padding:6px 10px;cursor:pointer"><input type="radio" name="dcFilter" value="suspended"> Suspended</label>
</div>

<div id="dcScanBanner" style="display:none"></div>

<div class="card" id="dcBulkBar" style="display:none;align-items:center;gap:10px;margin-bottom:10px;background:var(--warn-bg);border:1px solid #fed7aa">
  <b id="dcSelN" style="font-size:13px">0 selected</b>
  <span class="meta">Actions apply to the owning cPanel account (all its domains).</span>
  <div style="margin-left:auto;display:flex;gap:8px">
    <button type="button" class="btn" style="padding:5px 12px;font-size:12.5px;background:#b45309;color:#fff" onclick="dcBulk('suspend')">&#9208; Suspend selected</button>
    <button type="button" class="btn" style="padding:5px 12px;font-size:12.5px;background:#b91c1c;color:#fff" onclick="dcBulk('terminate')">&#128465; Terminate selected</button>
  </div>
</div>

<style>
/* ---- overview strip / navigator / collapsible cards (pattern: firewall-status.php) ---- */
/* .fw-kpis / .fw-nav / .fw-collapse / pager styles: shared, in includes/layout.php */
.dc-hd{display:flex;align-items:center;gap:10px;padding:12px 16px;border-bottom:1px solid var(--line);font-weight:700;font-size:14px}.dc-hd .meta{margin-left:auto;font-weight:400;font-size:12px}
.dc-tools{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:12px}
@media print{.fw-nav{display:none!important}}
#dcTbl{width:100%;border-collapse:separate;border-spacing:0;font-size:13px}
#dcTbl thead th{position:sticky;top:0;z-index:2;background:var(--card);color:#334155;font-weight:700;font-size:11.5px;text-transform:uppercase;letter-spacing:.02em;
  padding:10px 12px;text-align:left;border-bottom:2px solid #d8e0ec;white-space:nowrap}
#dcTbl thead th.sortable{cursor:pointer;user-select:none}
#dcTbl thead th.sortable:hover{background:var(--card)}
#dcTbl thead th{position:relative}
.dc-resz{position:absolute;top:0;right:0;width:7px;height:100%;cursor:col-resize;z-index:3;user-select:none}
.dc-resz:hover,.dc-resz.drag{background:rgba(59,91,219,.35)}
body.dc-resizing{cursor:col-resize!important;user-select:none!important}
#dcTbl td{overflow:hidden}
#dcTbl thead th .arr{opacity:.35;font-size:10px;margin-left:3px}
#dcTbl thead th[data-dir=asc] .arr,#dcTbl thead th[data-dir=desc] .arr{opacity:1;color:var(--brand)}
#dcTbl tbody td{padding:10px 12px;vertical-align:top;border-bottom:1px solid #eef1f6;line-height:1.5}
#dcTbl tbody tr:nth-child(even){background:var(--card)}
#dcTbl tbody tr:hover{background:var(--brand-bg)}
#dcTbl tbody tr.dc-act{opacity:.45}
#dcTbl td.col-actions{text-align:right;white-space:nowrap}
#dcTbl td.col-actions .btn{padding:4px 9px;font-size:12px;margin-left:3px}
#dcTbl .col-dns{max-width:230px;word-break:break-word}
#dcTbl .col-site{max-width:170px;word-break:break-word}
#dcWrap{overflow-x:auto;border-radius:12px}
</style>
<div class="card" id="dc-table" style="padding:0;margin-bottom:14px"><div class="dc-hd"><b>&#127760; Domains</b><span class="meta"><?= count($domains) ?> rows · sort by clicking a column · drag a border to resize</span></div>
<div id="dcWrap" data-nopage="1">
<?php if (!$domains): ?>
  <p class="meta" style="padding:16px">No domains found (is this a cPanel/WHM server, running as root?).</p>
<?php else: ?>
<table id="dcTbl">
  <thead><tr>
    <th style="text-align:center;width:34px"><input type="checkbox" id="dcAll"></th>
    <th class="sortable" data-sort="domain">Domain<span class="arr">&#8645;</span></th>
    <th class="sortable" data-sort="user">User<span class="arr">&#8645;</span></th>
    <th class="sortable" data-sort="type">Type<span class="arr">&#8645;</span></th>
    <th class="sortable" data-sort="account">Account<span class="arr">&#8645;</span></th>
    <th class="sortable" data-sort="expiry">Expiry<span class="arr">&#8645;</span></th>
    <th>Points to</th>
    <th class="sortable" data-sort="match" style="text-align:center">Match<span class="arr">&#8645;</span></th>
    <th class="sortable" data-sort="site">Site<span class="arr">&#8645;</span></th>
    <th>DNS (nameservers)</th>
    <th style="text-align:right">Actions</th>
  </tr></thead>
  <tbody id="dcBody">
  <?php foreach ($domains as $d): $u = $d['user']; $susp = !empty($d['suspended']); ?>
    <tr data-domain="<?= smpro_h($d['domain']) ?>" data-user="<?= smpro_h($u) ?>" data-type="<?= smpro_h($d['type']) ?>" data-susp="<?= $susp ? '1' : '0' ?>" data-match="" data-expired="" data-expts="" data-http="">
      <td style="text-align:center"><input type="checkbox" class="dcChk"></td>
      <td style="font-weight:600"><?= smpro_h($d['domain']) ?></td>
      <td><code><?= smpro_h($u) ?></code></td>
      <td style="color:#64748b"><?= smpro_h($d['type']) ?></td>
      <td><?php if ($susp): ?><span style="color:#b45309;font-weight:700">suspended</span><?php else: ?><span style="color:#16a34a">active</span><?php endif; ?></td>
      <td class="dcExp" style="color:#94a3b8">—</td>
      <td class="dcIp" style="color:#94a3b8">—</td>
      <td class="dcMatch" style="text-align:center;color:#94a3b8">—</td>
      <td class="dcHttp col-site" style="color:#94a3b8">—</td>
      <td class="dcNs col-dns" style="color:#94a3b8">—</td>
      <td class="col-actions">
        <button type="button" class="btn dcCheckBtn" title="Deep-check DNS + WHOIS">&#128270;</button>
        <?php if (!$susp): ?><button type="button" class="btn" style="background:#b45309;color:#fff" onclick="dcSuspend(this)" title="Suspend account">&#9208;</button><?php endif; ?>
        <button type="button" class="btn" style="background:#b91c1c;color:#fff" onclick="dcTerminate(this)" title="Terminate account">&#128465;</button>
      </td>
    </tr>
  <?php endforeach; ?>
  </tbody>
</table>
<?php endif; ?>
</div></div>

<!-- Two-step Terminate confirmation modal -->
<div id="dcModal" style="display:none;position:fixed;inset:0;background:rgba(15,27,51,.6);z-index:99999;align-items:center;justify-content:center;padding:16px">
  <div style="background:var(--card);border-radius:16px;max-width:500px;width:100%;box-shadow:0 24px 70px rgba(0,0,0,.35);overflow:hidden;font-family:inherit">
    <!-- Step 1 -->
    <div id="dcM1">
      <div style="background:linear-gradient(135deg,#dc2626,#b91c1c);color:#fff;padding:18px 22px;display:flex;align-items:center;gap:12px">
        <span style="font-size:30px;line-height:1">&#9888;</span>
        <div><div style="font-size:18px;font-weight:800">Terminate account</div><div style="font-size:12px;opacity:.9">Step 1 of 2 — warning</div></div>
      </div>
      <div style="padding:22px">
        <p style="margin:0 0 14px;font-size:14.5px;color:#0f1b33">You are about to <b style="color:#b91c1c">permanently terminate</b> the account <code id="dcM1User" style="background:var(--card);padding:2px 7px;border-radius:6px"></code>.</p>
        <div style="background:var(--dang-bg);border:1px solid #fecaca;border-radius:11px;padding:13px 15px;font-size:13px;color:#7f1d1d;line-height:1.6">
          This removes the cPanel account and <b>ALL</b> of its content:
          <div style="margin-top:7px;display:flex;flex-wrap:wrap;gap:6px">
            <span style="background:var(--card);border:1px solid #fecaca;border-radius:6px;padding:2px 8px">&#127760; All domains</span>
            <span style="background:var(--card);border:1px solid #fecaca;border-radius:6px;padding:2px 8px">&#128193; Website files</span>
            <span style="background:var(--card);border:1px solid #fecaca;border-radius:6px;padding:2px 8px">&#128231; Email accounts</span>
            <span style="background:var(--card);border:1px solid #fecaca;border-radius:6px;padding:2px 8px">&#128190; Databases</span>
          </div>
          <div style="margin-top:9px;font-weight:800">&#9888; This action cannot be undone.</div>
        </div>
      </div>
      <div style="padding:0 22px 20px;display:flex;gap:10px;justify-content:flex-end">
        <button type="button" class="btn" onclick="dcModalClose()" style="padding:8px 16px">Cancel</button>
        <button type="button" class="btn" onclick="dcModalStep2()" style="padding:8px 16px;background:#b45309;color:#fff;font-weight:700">I understand, continue &rarr;</button>
      </div>
    </div>
    <!-- Step 2 -->
    <div id="dcM2" style="display:none">
      <div style="background:linear-gradient(135deg,#991b1b,#7f1d1d);color:#fff;padding:18px 22px;display:flex;align-items:center;gap:12px">
        <span style="font-size:30px;line-height:1">&#128465;</span>
        <div><div style="font-size:18px;font-weight:800">Final confirmation</div><div style="font-size:12px;opacity:.9">Step 2 of 2 — confirm &amp; backup</div></div>
      </div>
      <div style="padding:22px">
        <p style="margin:0 0 14px;font-size:14.5px;color:#0f1b33">Confirm you really want to delete <code id="dcM2User" style="background:var(--card);padding:2px 7px;border-radius:6px"></code>. <b style="color:#b91c1c">There is no recovery after this.</b></p>
        <label style="display:flex;align-items:flex-start;gap:10px;background:var(--brand-bg);border:1px solid #bfdbfe;border-radius:11px;padding:13px 15px;font-size:13px;cursor:pointer;margin-bottom:14px;line-height:1.55">
          <input type="checkbox" id="dcBackupChk" checked style="margin-top:3px;width:16px;height:16px;flex:none">
          <span><b>Create a full backup of the account first</b> &mdash; a complete <code>pkgacct</code> archive saved to <code>/backup/</code> (files, email, databases, DNS, settings). <b>Recommended</b>: you can fully restore the account later from this archive.</span>
        </label>
        <p style="margin:0 0 7px;font-size:13px;color:#475569">Type <b style="letter-spacing:.05em">TERMINATE</b> below to enable the button:</p>
        <input type="text" id="dcConfirmInput" autocomplete="off" spellcheck="false" placeholder="TERMINATE" style="width:100%;padding:10px 12px;border:2px solid #fecaca;border-radius:10px;font-size:15px;letter-spacing:.08em;box-sizing:border-box;text-align:center;font-weight:700">
        <div id="dcM2Msg" style="margin-top:10px;font-size:13px;color:#475569"></div>
      </div>
      <div style="padding:0 22px 20px;display:flex;gap:10px;justify-content:flex-end">
        <button type="button" class="btn" onclick="dcModalClose()" style="padding:8px 16px">Cancel</button>
        <button type="button" class="btn" id="dcTermGo" disabled onclick="dcModalConfirm()" style="padding:8px 16px;background:#b91c1c;color:#fff;font-weight:800;opacity:.45;cursor:not-allowed">&#128465; Terminate now</button>
      </div>
    </div>
  </div>
</div>

<script>(function(){
  function P(id){return document.getElementById(id);}
  function esc(s){return (s==null?'':String(s)).replace(/[&<>"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
  function call(extra){var fd=new URLSearchParams();fd.set('smpro_csrf',DC_CSRF);Object.keys(extra).forEach(function(k){fd.set(k,extra[k]);});
    return fetch('index.cgi?domchk=1',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'}).then(function(r){return r.json();});}
  function fmtDate(ts){if(!ts)return '';var d=new Date(ts*1000);return d.toISOString().slice(0,10);}
  var rows=[].slice.call(document.querySelectorAll('tr[data-domain]'));
  var dcChecked=false;

  // ---- localStorage state - persists check results across page navigations ----
  var DC_STATE_KEY='dc_state_v2';
  var dcState={v:2,scanId:null,scanDone:false,total:0,since:0,results:{},savedAt:0};
  function saveState(){try{dcState.savedAt=Math.floor(Date.now()/1000);localStorage.setItem(DC_STATE_KEY,JSON.stringify(dcState));}catch(e){}}
  function loadState(){try{var s=JSON.parse(localStorage.getItem(DC_STATE_KEY)||'{}');if(s&&s.v===2){dcState=s;return true;}}catch(e){}return false;}
  function clearState(){dcState={v:2,scanId:null,scanDone:false,total:0,since:0,results:{},savedAt:0};try{localStorage.removeItem(DC_STATE_KEY);}catch(e){}}

  // ---- scan banner ----
  var dcBanner=P('dcScanBanner');
  function setBannerRunning(done,total){
    if(!dcBanner)return;
    var pct=total>0?Math.round(done/total*100):0;
    dcBanner.style.cssText='display:flex;align-items:center;gap:10px;padding:10px 14px;border:1px solid #93c5fd;border-radius:10px;margin-bottom:10px;font-size:13.5px;font-weight:600;background:var(--brand-bg);color:#1e40af;flex-wrap:wrap';
    dcBanner.innerHTML='<span>&#9203; Background scan running — '+done+' / '+total+' ('+pct+'%)</span>'
      +'<span style="font-size:12px;font-weight:400;color:#3b5bdb">Results are saved automatically. You can navigate away and return.</span>'
      +'<button type="button" class="btn" style="margin-left:auto;font-size:12px;padding:4px 10px" onclick="dcClearAndRescan()">&#8635; Re-scan</button>';
  }
  function setBannerDone(done,total,ts){
    if(!dcBanner)return;
    var ago=ts?Math.round((Math.floor(Date.now()/1000)-ts)/60)+'m ago':'';
    dcBanner.style.cssText='display:flex;align-items:center;gap:10px;padding:10px 14px;border:1px solid #86efac;border-radius:10px;margin-bottom:10px;font-size:13.5px;font-weight:600;background:var(--good-bg);color:#166534;flex-wrap:wrap';
    dcBanner.innerHTML='<span>&#10003; Scan complete — '+done+' domains checked'+(ago?' &middot; '+ago:'')+'</span>'
      +'<button type="button" class="btn" style="margin-left:auto;font-size:12px;padding:4px 10px" onclick="dcClearAndRescan()">&#8635; Re-scan</button>';
  }
  function setBannerRestored(done,total,ts){
    if(!dcBanner)return;
    var ago=ts?Math.round((Math.floor(Date.now()/1000)-ts)/60)+'m ago':'';
    var continueBtn=(!dcState.scanDone&&dcState.scanId)?'<button type="button" class="btn" style="font-size:12px;padding:4px 10px;background:var(--brand);color:#fff" onclick="dcResumeOrRescan()">&#9654; Continue scan</button>':'';
    dcBanner.style.cssText='display:flex;align-items:center;gap:10px;padding:10px 14px;border:1px solid #fcd34d;border-radius:10px;margin-bottom:10px;font-size:13.5px;font-weight:600;background:var(--warn-bg);color:#92400e;flex-wrap:wrap';
    dcBanner.innerHTML='<span>&#8629; Restored '+done+' results from last scan'+(ago?' &middot; '+ago:'')+'</span>'
      +continueBtn+'<button type="button" class="btn" style="margin-left:auto;font-size:12px;padding:4px 10px" onclick="dcClearAndRescan()">&#8635; Re-scan</button>';
  }
  function hideBanner(){if(dcBanner)dcBanner.style.display='none';}

  var dcActiveFilter='all';

  function renderCheck(tr,j,skipSave){
    var dom=tr.getAttribute('data-domain');
    var ipCell=tr.querySelector('.dcIp'),mCell=tr.querySelector('.dcMatch'),eCell=tr.querySelector('.dcExp');
    if(!j||!j.ok){ipCell.innerHTML='<span style="color:#b91c1c">check failed</span>';return;}
    if(!skipSave){dcState.results[dom]=j;saveState();}
    // points-to
    var ips=(j.ips||[]);
    ipCell.innerHTML = ips.length ? esc(ips.join(', '))+(j.cdn?' <span style="font-size:10px;color:#0369a1">('+esc(j.cdn)+')</span>':'') : '<span style="color:#b45309">no A record</span>';
    // match
    tr.setAttribute('data-match', j.match?'1':'0');
    if(j.match){mCell.innerHTML='<span style="color:#16a34a;font-weight:700">&#10003; yes</span>';}
    else if(j.cdn){mCell.innerHTML='<span style="color:#0369a1;font-weight:700" title="Behind '+esc(j.cdn)+' — origin may still be this server">CDN</span>';}
    else{mCell.innerHTML='<span style="color:#b91c1c;font-weight:800">&#10007; elsewhere</span>';}
    // expiry
    tr.setAttribute('data-expired', j.expired?'1':'0');
    tr.setAttribute('data-expts', j.unregistered?'1':(j.expiry_ts||''));
    if(j.unregistered){
      eCell.innerHTML='<span style="color:#b91c1c;font-weight:800" title="WHOIS reports this domain is not registered — likely expired/dropped">NOT REGISTERED</span>';
    } else if(j.parked){
      eCell.innerHTML='<span style="color:#b91c1c;font-weight:800" title="Nameservers point to a domain-parking service ('+esc(j.park_provider||'')+') — domain is parked/inactive">PARKED'+(j.park_provider?' ('+esc(j.park_provider)+')':'')+'</span>';
    } else if(j.expiry_ts){
      var clr=j.expired?'#b91c1c':(j.expiring?'#b45309':'#16a34a');
      var lbl=j.expired?' (EXPIRED)':(j.expiring?' (soon)':'');
      eCell.innerHTML='<span style="color:'+clr+';font-weight:'+(j.expired?'800':'600')+'">'+fmtDate(j.expiry_ts)+lbl+'</span>';
    } else { eCell.innerHTML='<span style="color:#94a3b8" title="'+esc(j.whois_err||'')+'">unknown</span>'; }
    // site (HTTP) status + title
    var hCell=tr.querySelector('.dcHttp');
    if(hCell){
      var c=j.http_code||0,hc='#6b7686',ht='no response';
      if(c>=200&&c<300){hc='#16a34a';ht=c+' OK';}
      else if(c>=300&&c<400){hc='#0369a1';ht=c+' redirect';}
      else if(c>=400){hc='#b91c1c';ht=c+' error';}
      tr.setAttribute('data-http', c||0);
      hCell.innerHTML='<span style="color:'+hc+';font-weight:700">'+esc(ht)+'</span>'+(j.http_title?'<br><small style="color:#64748b">'+esc(j.http_title)+'</small>':'');
    }
    // DNS / nameservers
    var nCell=tr.querySelector('.dcNs');
    if(nCell){
      var ns=(j.ns||[]);
      if(!ns.length){nCell.innerHTML='<span style="color:#b45309">no NS</span>';}
      else{
        var prov='';var joined=ns.join(' ').toLowerCase();
        if(joined.indexOf('cloudflare')>-1)prov='Cloudflare';
        else if(joined.indexOf('awsdns')>-1)prov='AWS Route53';
        else if(joined.indexOf('googledomains')>-1||joined.indexOf('google.com')>-1)prov='Google';
        else if(joined.indexOf('godaddy')>-1||joined.indexOf('domaincontrol')>-1)prov='GoDaddy';
        nCell.innerHTML='<small style="color:#475569;word-break:break-all">'+esc(ns.join(', '))+'</small>'+(prov?' <span style="font-size:10px;color:#0369a1;font-weight:700">('+esc(prov)+')</span>':'');
      }
    }
    updateCounts();
  }
  function updateCounts(){
    var mm=0,ex=0;rows.forEach(function(tr){if(tr.getAttribute('data-match')==='0')mm++;if(tr.getAttribute('data-expired')==='1')ex++;});
    P('dcMismatchN').textContent=mm;P('dcExpiredN').textContent=ex;
  }
  function checkOne(tr){
    var dom=tr.getAttribute('data-domain'),btn=tr.querySelector('.dcCheckBtn');
    var o=btn.innerHTML;btn.disabled=true;btn.innerHTML='&#8987;';
    return call({dc_action:'check',domain:dom}).then(function(j){btn.disabled=false;btn.innerHTML=o;renderCheck(tr,j);})
      .catch(function(){btn.disabled=false;btn.innerHTML=o;tr.querySelector('.dcIp').innerHTML='<span style="color:#b91c1c">error</span>';});
  }
  document.addEventListener('click',function(e){var b=e.target.closest('.dcCheckBtn');if(b){var tr=b.closest('tr[data-domain]');if(tr)checkOne(tr);}});

  // ---- background scan - starts a server-side worker that checks every domain, polls progress ----
  var dcPollIv=null;
  function stopScanPoll(){if(dcPollIv){clearInterval(dcPollIv);dcPollIv=null;}}
  function startScanPoll(scanId){
    stopScanPoll();
    dcPollIv=setInterval(function(){
      call({dc_action:'scanstatus',scan_id:scanId,since:String(dcState.since)}).then(function(j){
        if(!j||!j.ok)return;
        var nr=j.new_results||{};
        Object.keys(nr).forEach(function(dom){
          var tr=null;for(var i=0;i<rows.length;i++){if(rows[i].getAttribute('data-domain')===dom){tr=rows[i];break;}}
          if(tr)renderCheck(tr,nr[dom]);
        });
        dcState.since=j.done||dcState.since;
        if(j.status==='done'||j.status==='stalled'){
          dcState.scanDone=(j.status==='done');
          saveState();stopScanPoll();
          var b=P('dcCheckAll');b.disabled=false;b.innerHTML='&#128270; Check all domains';
          if(j.status==='done'){dcChecked=true;setBannerDone(j.done,j.total,j.ts||0);P('dcProg').textContent='';}
          else{setBannerRestored(j.done,j.total,j.ts||0);P('dcProg').textContent='Scan stalled — click Re-scan to retry.';}
        } else {
          saveState();setBannerRunning(j.done,j.total);P('dcProg').textContent=j.done+' / '+j.total+' scanned';
          if(dcActiveFilter==='mismatch'||dcActiveFilter==='expired')applyFilter();
        }
      }).catch(function(){});
    },3000);
  }

  window.dcStartBgscan=function(){
    stopScanPoll();dcChecked=false;
    var b=P('dcCheckAll');b.disabled=true;b.innerHTML='&#9203; Starting scan…';P('dcProg').textContent='';
    rows.forEach(function(tr){
      ['dcIp','dcMatch','dcExp','dcHttp','dcNs'].forEach(function(cls){var c=tr.querySelector('.'+cls);if(c)c.innerHTML='<span style="color:#94a3b8">—</span>';});
      tr.removeAttribute('data-match');tr.removeAttribute('data-expired');tr.removeAttribute('data-expts');tr.removeAttribute('data-http');
    });
    clearState();hideBanner();
    call({dc_action:'bgscan'}).then(function(j){
      if(!j||!j.ok){b.disabled=false;b.innerHTML='&#128270; Check all domains';smToast('&#10007; '+(j&&j.msg||'Could not start scan'),'err');return;}
      dcState.scanId=j.scan_id;dcState.total=j.total;dcState.since=0;saveState();
      b.innerHTML='&#9203; Scanning…';
      setBannerRunning(0,j.total);P('dcProg').textContent='0 / '+j.total+' scanned';
      startScanPoll(j.scan_id);
    }).catch(function(){b.disabled=false;b.innerHTML='&#128270; Check all domains';smToast('&#10007; Request failed.','err');});
  };
  window.dcClearAndRescan=function(){clearState();window.dcStartBgscan();};
  window.dcResumeOrRescan=function(){
    if(dcState.scanId&&!dcState.scanDone){
      var b=P('dcCheckAll');b.disabled=true;b.innerHTML='&#9203; Scanning…';
      setBannerRunning(dcState.since,dcState.total);P('dcProg').textContent=dcState.since+' / '+dcState.total+' scanned';
      startScanPoll(dcState.scanId);
    } else {window.dcStartBgscan();}
  };

  // ---- restore state on page load ----
  (function initState(){
    if(!loadState())return;
    var keys=Object.keys(dcState.results);if(!keys.length)return;
    var restored=0;
    rows.forEach(function(tr){var r=dcState.results[tr.getAttribute('data-domain')];if(r){renderCheck(tr,r,true);restored++;}});
    if(!restored)return;
    if(restored>=rows.length&&dcState.scanDone)dcChecked=true;
    if(!dcState.scanDone&&dcState.scanId){
      setBannerRestored(dcState.since,dcState.total,dcState.savedAt);
    } else if(dcState.scanDone){
      setBannerDone(keys.length,dcState.total,dcState.savedAt);dcChecked=true;
    } else {
      setBannerRestored(restored,dcState.total||restored,dcState.savedAt);
    }
  })();

  P('dcCheckAll').addEventListener('click',function(){window.dcStartBgscan();});

  // ---- CSV export (only visible/filtered rows; UTF-8 BOM for Excel) ----
  P('dcExport').addEventListener('click',function(){
    var hdr=['Domain','User','Type','Account','Expiry','Points to','Match','Site','Title','Nameservers'];
    function cell(v){return '"'+String(v==null?'':v).replace(/"/g,'""').replace(/\s+/g,' ').trim()+'"';}
    var lines=[hdr.map(cell).join(',')];
    rows.forEach(function(tr){
      if(tr.style.display==='none')return;
      var t=function(sel){var e=tr.querySelector(sel);return e?e.innerText:'';};
      var siteCell=tr.querySelector('.dcHttp'),site='',title='';
      if(siteCell){var parts=siteCell.innerText.split('\n');site=parts[0]||'';title=parts.slice(1).join(' ')||'';}
      lines.push([
        tr.getAttribute('data-domain'), tr.getAttribute('data-user'),
        t('td:nth-child(4)'), t('td:nth-child(5)'), t('.dcExp'), t('.dcIp'), t('.dcMatch'), site, title, t('.dcNs')
      ].map(cell).join(','));
    });
    if(lines.length<2){smToast('Nothing to export for the current filter.','info');return;}
    var blob=new Blob(['﻿'+lines.join('\n')],{type:'text/csv;charset=utf-8;'});
    var a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='domains-'+(new Date().toISOString().slice(0,10))+'.csv';
    document.body.appendChild(a);a.click();document.body.removeChild(a);
    smToast('&#10003; Exported '+(lines.length-1)+' filtered domain(s) to CSV.','ok');
  });

  // ---- Copy the filtered domain list to clipboard (quick extract) ----
  function visibleRows(){return rows.filter(function(tr){return tr.style.display!=='none';});}
  P('dcCopy').addEventListener('click',function(){
    var list=visibleRows().map(function(tr){return tr.getAttribute('data-domain');});
    if(!list.length){smToast('No domains in the current filter.','info');return;}
    var text=list.join('\n');
    function ok(){smToast('&#10003; Copied '+list.length+' filtered domain(s) to clipboard.','ok');}
    if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(text).then(ok,function(){fallback();});}
    else fallback();
    function fallback(){var ta=document.createElement('textarea');ta.value=text;ta.style.position='fixed';ta.style.opacity='0';document.body.appendChild(ta);ta.select();try{document.execCommand('copy');ok();}catch(e){smToast('Copy failed — select manually.','err');}document.body.removeChild(ta);}
  });

  // ---- filters + search ----
  function applyFilter(){
    var q=(P('dcSearch').value||'').toLowerCase().trim();
    var f=(document.querySelector('input[name=dcFilter]:checked')||{}).value||'all';
    dcActiveFilter=f;
    if((f==='mismatch'||f==='expired')&&!dcChecked){
      P('dcProg').textContent='Starting scan to apply this filter…';
      window.dcStartBgscan();
      return;
    }
    rows.forEach(function(tr){
      var dom=tr.getAttribute('data-domain'),usr=tr.getAttribute('data-user');
      var textOk=!q||dom.indexOf(q)>-1||usr.toLowerCase().indexOf(q)>-1;
      var fOk=true;
      if(f==='mismatch')fOk=tr.getAttribute('data-match')==='0';
      else if(f==='expired')fOk=tr.getAttribute('data-expired')==='1';
      else if(f==='suspended')fOk=tr.getAttribute('data-susp')==='1';
      tr.style.display=(textOk&&fOk)?'':'none';
    });
    var n=rows.filter(function(tr){return tr.style.display!=='none';}).length;
    var filtered=(f!=='all')||q!=='';
    P('dcExport').innerHTML='&#128190; Export CSV'+(filtered?' ('+n+')':'');
    P('dcCopy').innerHTML='&#128203; Copy list'+(filtered?' ('+n+')':'');
  }
  P('dcSearch').addEventListener('input',applyFilter);
  [].slice.call(document.querySelectorAll('input[name=dcFilter]')).forEach(function(r){r.addEventListener('change',applyFilter);});


  // ---- column sorting ----
  var sortDir={};
  function rowKey(tr,key){
    if(key==='expiry')return parseInt(tr.getAttribute('data-expts')||'0',10)||0;
    if(key==='site')return parseInt(tr.getAttribute('data-http')||'0',10)||0;
    if(key==='account')return tr.getAttribute('data-susp')==='1'?1:0;
    if(key==='match'){var m=tr.getAttribute('data-match')||'';return m==='1'?1:(m===''?2:3);}
    if(key==='type')return tr.getAttribute('data-type')||'';
    if(key==='user')return (tr.getAttribute('data-user')||'').toLowerCase();
    return (tr.getAttribute('data-domain')||'');
  }
  function dcSort(key,th){
    var dir=sortDir[key]==='asc'?'desc':'asc';sortDir={};sortDir[key]=dir;
    [].slice.call(document.querySelectorAll('#dcTbl thead th')).forEach(function(h){h.removeAttribute('data-dir');});
    if(th)th.setAttribute('data-dir',dir);
    var body=P('dcBody');
    rows.slice().sort(function(a,b){
      var ka=rowKey(a,key),kb=rowKey(b,key),c;
      if(typeof ka==='number')c=ka-kb;else c=String(ka).localeCompare(String(kb));
      return dir==='asc'?c:-c;
    }).forEach(function(tr){body.appendChild(tr);});
  }
  [].slice.call(document.querySelectorAll('#dcTbl thead th.sortable')).forEach(function(th){
    th.addEventListener('click',function(){dcSort(th.getAttribute('data-sort'),th);});
  });

  // ---- draggable column borders (resizable columns; widths persist in localStorage) ----
  (function(){
    var tbl=P('dcTbl'); if(!tbl)return;
    var ths=[].slice.call(tbl.querySelectorAll('thead th'));
    function loadW(){try{return JSON.parse(localStorage.getItem('dc_colw_v1'))||[];}catch(e){return [];}}
    function saveW(){try{localStorage.setItem('dc_colw_v1',JSON.stringify(ths.map(function(t){return Math.round(t.getBoundingClientRect().width);})));}catch(e){}}
    var saved=loadW();
    ths.forEach(function(th,idx){ var w=saved[idx]||Math.round(th.getBoundingClientRect().width); th.style.width=w+'px'; });
    tbl.style.tableLayout='fixed';
    ths.forEach(function(th,idx){
      if(idx===ths.length-1)return;                          // no handle on the last column
      var h=document.createElement('span');h.className='dc-resz';th.appendChild(h);
      h.addEventListener('click',function(e){e.stopPropagation();});   // don't trigger sort
      h.addEventListener('mousedown',function(e){
        e.preventDefault();e.stopPropagation();
        var startX=e.clientX, startW=th.getBoundingClientRect().width;
        h.classList.add('drag');document.body.classList.add('dc-resizing');
        function mv(ev){ th.style.width=Math.max(40,startW+(ev.clientX-startX))+'px'; }
        function up(){document.removeEventListener('mousemove',mv);document.removeEventListener('mouseup',up);
          h.classList.remove('drag');document.body.classList.remove('dc-resizing');saveW();}
        document.addEventListener('mousemove',mv);document.addEventListener('mouseup',up);
      });
    });
  })();

  // ---- selection ----
  function selectedRows(){return rows.filter(function(tr){var c=tr.querySelector('.dcChk');return c&&c.checked&&tr.style.display!=='none';});}
  function refreshSel(){var n=selectedRows().length;P('dcSelN').textContent=n+' selected';P('dcBulkBar').style.display=n?'flex':'none';}
  document.addEventListener('change',function(e){if(e.target.classList&&e.target.classList.contains('dcChk'))refreshSel();});
  P('dcAll').addEventListener('change',function(){var on=this.checked;rows.forEach(function(tr){if(tr.style.display!=='none'){var c=tr.querySelector('.dcChk');if(c)c.checked=on;}});refreshSel();});

  // ---- actions ----
  window.dcSuspend=function(btn){var tr=btn.closest('tr[data-domain]');var user=tr.getAttribute('data-user');
    if(!confirm('Suspend account "'+user+'"?\n\nThis suspends the WHOLE cPanel account and ALL its domains. It is reversible from WHM.'))return;
    btn.disabled=true;call({dc_action:'suspend',user:user,reason:'Suspended via SM Pro Domain Checker'}).then(function(j){
      alert(j&&j.msg?j.msg:(j&&j.ok?'Suspended':'Failed'));
      if(j&&j.ok){tr.setAttribute('data-susp','1');tr.querySelector('td:nth-child(5)').innerHTML='<span style="color:#b45309;font-weight:700">suspended</span>';btn.style.display='none';}
      else btn.disabled=false;
    }).catch(function(){btn.disabled=false;alert('Request failed.');});};

  // ---- Terminate: styled two-step modal (warning -> confirm + optional /backup/ archive) ----
  var dcTermTr=null;
  window.dcTerminate=function(btn){dcTermTr=btn.closest('tr[data-domain]');var user=dcTermTr.getAttribute('data-user');
    P('dcM1User').textContent=user;P('dcM2User').textContent=user;
    P('dcM1').style.display='';P('dcM2').style.display='none';
    P('dcConfirmInput').value='';P('dcM2Msg').textContent='';P('dcBackupChk').checked=true;
    var go=P('dcTermGo');go.disabled=true;go.style.opacity='.45';go.style.cursor='not-allowed';
    P('dcModal').style.display='flex';};
  window.dcModalClose=function(){P('dcModal').style.display='none';dcTermTr=null;};
  window.dcModalStep2=function(){P('dcM1').style.display='none';P('dcM2').style.display='';setTimeout(function(){P('dcConfirmInput').focus();},50);};
  P('dcConfirmInput').addEventListener('input',function(){var ok=this.value.trim()==='TERMINATE';var go=P('dcTermGo');go.disabled=!ok;go.style.opacity=ok?'1':'.45';go.style.cursor=ok?'pointer':'not-allowed';});
  window.dcModalConfirm=function(){
    if(!dcTermTr)return;var user=dcTermTr.getAttribute('data-user');var backup=P('dcBackupChk').checked;var tr=dcTermTr;
    var go=P('dcTermGo');go.disabled=true;go.style.opacity='.6';
    P('dcM2Msg').innerHTML='&#9203; Starting background task…';
    var body={dc_action:'terminatebg',user:user,confirm:'TERMINATE'};if(backup)body.backup='1';
    call(body).then(function(j){
      if(j&&j.ok&&j.job){
        dcModalClose();
        smToast('&#9203; '+(j.msg||('Terminating '+user+' in background…'))+' You can keep working — it runs as a task.','info',6000);
        tr.style.opacity='.55';tr.setAttribute('data-job',j.job);tr.querySelectorAll('button').forEach(function(b){b.disabled=true;});
        var st=tr.querySelector('.dcExp');if(st)st.innerHTML='<span style="color:#b45309;font-weight:700" title="Background task running">&#9203; terminating…</span>';
        dcPollJob(j.job,user,tr,backup);
      } else { go.disabled=false;go.style.opacity='1';P('dcM2Msg').innerHTML='<span style="color:#b91c1c">&#10007; '+esc((j&&j.msg)||'Could not start')+'</span>'; }
    }).catch(function(){go.disabled=false;go.style.opacity='1';P('dcM2Msg').innerHTML='<span style="color:#b91c1c">Request failed.</span>';});};

  // Poll a background terminate job (every 5s) - non-blocking; UI stays fully usable.
  function dcPollJob(id,user,tr,backup){
    var tries=0,max=300;   // up to ~25 min
    var iv=setInterval(function(){
      tries++;
      call({dc_action:'jobstatus',job:id}).then(function(j){
        if(j&&j.ok){
          var st=tr.querySelector('.dcExp');
          if(j.status==='done'){clearInterval(iv);tr.style.opacity='.4';if(st)st.innerHTML='<span style="color:#b91c1c;font-weight:800">terminated</span>';smToast('&#10003; '+(j.msg||(user+' terminated.')),'ok');}
          else if(j.status==='failed'){clearInterval(iv);tr.style.opacity='1';tr.querySelectorAll('button').forEach(function(b){b.disabled=false;});if(st)st.innerHTML='<span style="color:#b91c1c">task failed</span>';smToast('&#10007; '+user+': '+(j.msg||'terminate failed'),'err');}
          else if(st&&j.phase){st.innerHTML='<span style="color:#b45309;font-weight:700" title="'+esc(j.msg||'')+'">&#9203; '+esc(j.phase)+'…</span>';}
        }
      }).catch(function(){});
      if(tries>=max)clearInterval(iv);
    },5000);
  }

  window.dcBulk=function(kind){
    var sel=selectedRows();if(!sel.length){alert('Select at least one domain.');return;}
    // dedupe by owning account
    var users={};sel.forEach(function(tr){users[tr.getAttribute('data-user')]=1;});
    var list=Object.keys(users);
    var verb=kind==='terminate'?'TERMINATE (permanently remove)':'suspend';
    if(!confirm(verb+' '+list.length+' account(s)?\n\n'+list.join(', ')+'\n\nActions apply to whole accounts (all their domains).'+(kind==='terminate'?'\n\nTERMINATION CANNOT BE UNDONE.':'')))return;
    var bulkBackup=false;
    if(kind==='terminate'){
      var t=prompt('Type TERMINATE to permanently remove '+list.length+' account(s):');if(t!=='TERMINATE'){alert('Cancelled.');return;}
      // Backing up is the DEFAULT. Never let Cancel/Escape silently choose "delete without backup" - Escape is
      // the universal "get me out of here", so it must select the SAFE option, matching the single-account
      // modal whose backup checkbox is checked by default. Skipping the backup now requires typing NOBACKUP.
      bulkBackup=true;
      var sk=prompt('Each account will be FULLY BACKED UP to /backup/ before deletion (safer, slower).\n\nLeave this empty to keep the backups.\nTo delete WITHOUT any backup, type: NOBACKUP');
      if(sk===null){alert('Cancelled — nothing was deleted.');return;}   // Escape/Cancel = abort, never "delete unsafely"
      if(sk.trim().toUpperCase()==='NOBACKUP'){
        if(!confirm('Last check: delete '+list.length+' account(s) with NO backup at all?\n\nThere will be no way to recover them.'))return;
        bulkBackup=false;
      }
    }
    var i=0,okc=0,failc=0;var log=[];
    function step(){
      if(i>=list.length){alert(verb+' done.\n\nOK: '+okc+'  Failed: '+failc+(log.length?'\n\n'+log.join('\n'):''));location.reload();return;}
      var user=list[i++];var body={dc_action:kind,user:user};if(kind==='terminate'){body.confirm='TERMINATE';if(bulkBackup)body.backup='1';}else body.reason='Bulk action via SM Pro Domain Checker';
      P('dcSelN').textContent='Processing '+user+' ('+i+'/'+list.length+')…';
      call(body).then(function(j){if(j&&j.ok)okc++;else{failc++;log.push(user+': '+((j&&j.msg)||'failed'));}step();})
        .catch(function(){failc++;log.push(user+': request error');step();});
    }
    step();
  };
})();</script>
<script>
(function(){
  /* collapsible section cards + sticky navigator (pattern: modules/firewall-status.php). The header of every
     card is a real toggle (role=button, keyboard), the open/closed choice is remembered per section. */
  var KEY='smpro:domain-checker:open', HSEL='.smpro-main .card > .dc-hd', PFX='dc', open={};
  try{ open=JSON.parse(localStorage.getItem(KEY)||'{}')||{}; }catch(err){ open={}; }
  function remember(){ try{ localStorage.setItem(KEY, JSON.stringify(open)); }catch(err){} }
  function toggleOf(card){ for(var i=0;i<card.children.length;i++){ if(card.children[i].classList.contains('fw-toggle')) return card.children[i]; } return null; }
  function setOpen(card,on){ var th=toggleOf(card); if(!th) return; card.classList.toggle('fw-open',on); th.setAttribute('aria-expanded',on?'true':'false'); open[th.getAttribute('data-fold')]=on; }
  function openCard(id,scroll){ var card=document.getElementById(id); if(!card) return;
    if(toggleOf(card)&&!card.classList.contains('fw-open')){ setOpen(card,true); remember(); }
    if(scroll){ card.style.scrollMarginTop='120px'; card.scrollIntoView({behavior:'smooth',block:'start'}); } }
  function init(){
    if(!document.getElementById(PFX+'Nav')) return;   /* only on a page that carries this navigator */
    var heads=document.querySelectorAll(HSEL), i;
    for(i=0;i<heads.length;i++){ (function(th,idx){
      var card=th.parentElement; if(!card||th.classList.contains('fw-toggle')) return;
      var body=document.createElement('div'); body.className='fw-collapse';
      while(th.nextSibling){ body.appendChild(th.nextSibling); }
      card.appendChild(body);
      th.classList.add('fw-toggle');
      if(!th.querySelector('.fw-chev')) th.insertAdjacentHTML('afterbegin','<span class="fw-chev">&#9656;</span> ');
      var lab=th.querySelector('b');
      var id=((lab?lab.textContent:th.textContent)||'').replace(/\s+/g,' ').replace(/^\s+|\s+$/g,'').slice(0,60) || ('card'+idx);
      th.setAttribute('data-fold',id);
      var isOpen=Object.prototype.hasOwnProperty.call(open,id)?!!open[id]:true;
      card.classList.toggle('fw-open',isOpen);
      th.setAttribute('role','button'); th.setAttribute('tabindex','0'); th.style.cursor='pointer'; th.setAttribute('aria-expanded',isOpen?'true':'false');
      function toggle(){ setOpen(card,!card.classList.contains('fw-open')); remember(); }
      th.addEventListener('click',function(e){ if(e.target.closest('a,button,input,select,label,textarea,details,summary')) return; toggle(); });
      th.addEventListener('keydown',function(e){ if(e.target!==th) return; if(e.key===' '||e.key==='Enter'||e.key==='Spacebar'){ e.preventDefault(); toggle(); } });
    })(heads[i],i); }
    var gos=document.querySelectorAll('.fw-nav [data-go], .fw-kpis [data-go]');
    for(i=0;i<gos.length;i++){ (function(a){ a.addEventListener('click',function(e){ e.preventDefault(); var id=a.getAttribute('data-go'); openCard(id,true);
      var ch=document.querySelectorAll('.fw-nav a'); for(var j=0;j<ch.length;j++) ch[j].classList.toggle('on', ch[j].getAttribute('data-go')===id);
      try{ history.replaceState(null,'','#'+id); }catch(err){} }); })(gos[i]); }
    function all(on){ var cs=document.querySelectorAll('.smpro-main .card'); for(var j=0;j<cs.length;j++){ if(toggleOf(cs[j])) setOpen(cs[j],on); } remember(); }
    var oa=document.getElementById(PFX+'OpenAll'), ca=document.getElementById(PFX+'CloseAll');
    if(oa) oa.addEventListener('click',function(){ all(true); });
    if(ca) ca.addEventListener('click',function(){ all(false); });
    if(location.hash && document.getElementById(location.hash.slice(1))) setTimeout(function(){ openCard(location.hash.slice(1), true); },150);

  }
  window[PFX+'OpenCard']=openCard;
  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',init); else init();
})();
</script>
<?php
smpro_layout_footer();
