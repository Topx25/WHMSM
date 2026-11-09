<?php
/**
 * modules/site-watch.php - Site Watch: per-site history of who changed what, what ran, what changed in the database;
 * report rules (sites -> numbers, level, when); fix & protect. Engine: includes/sitewatch.php.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }
foreach (['sdbulk', 'fileaudit', 'sitewatch'] as $m) { $f = SMPRO_BASE . '/includes/' . $m . '.php'; if (is_file($f)) require_once $f; }
$reqMethod = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));
$J = fn($x) => json_encode($x, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);

/* ---- read-only JSON (root) ---- */
if (isset($_GET['sw_state']) || isset($_GET['sw_site'])) {
    smpro_require_root(); header('Content-Type: application/json');
    if (isset($_GET['sw_site'])) {
        $d = smpro_sw_key((string)$_GET['sw_site']);
        echo $J(['ok' => true, 'domain' => $d, 'state' => smpro_sw_load('sites/' . $d . '/state.json'), 'events' => smpro_sw_events($d, 300),
                 'db' => smpro_sw_load('sites/' . $d . '/db.json'), 'plan' => smpro_sw_plan($d), 'fixes' => array_slice(smpro_sw_load('sites/' . $d . '/fixes.json'), 0, 30)]); exit;
    }
    $rows = []; $cut = time() - 86400;
    foreach (array_keys(smpro_sdb_targets()) as $d) {
        $st = smpro_sw_load('sites/' . $d . '/state.json'); if (!$st) { $rows[] = ['domain' => $d, 'risk' => 'unchecked']; continue; }
        $ev = array_values(array_filter(smpro_sw_events($d, 60), fn($e) => $e['ts'] >= $cut && smpro_sw_event_live($e)));
        usort($ev, fn($a, $b) => smpro_sw_rank($b['sev']) <=> smpro_sw_rank($a['sev']));
        $rows[] = ['domain' => $d, 'user' => $st['user'] ?? '', 'risk' => $st['risk'] ?? 'clean', 'checked_at' => $st['checked_at'] ?? 0, 'top' => $ev[0]['title'] ?? '',
                   'n24' => count($ev), 'newphp' => count(array_filter(($st['new24'] ?? []), 'smpro_sw_is_php')), 'db' => count(array_filter($ev, fn($e) => strpos($e['kind'], 'db_') === 0 || $e['kind'] === 'new_admin')),
                   'checks' => $st['checks'] ?? []];
    }
    echo $J(['ok' => true, 'cfg' => smpro_sw_cfg(), 'job' => smpro_sw_job(), 'rows' => $rows]); exit;
}
/* ---- actions (POST + CSRF + root) ---- */
if ($reqMethod === 'POST' && in_array(($_POST['sw_action'] ?? ''), ['check', 'cfg', 'rule_add', 'rule_del', 'rule_test', 'fix', 'fix_safe', 'undo'], true)) {
    smpro_require_valid_csrf('sw_action'); smpro_require_root(); header('Content-Type: application/json');
    $a = $_POST['sw_action']; $list = fn($k) => array_values(array_filter(array_map('trim', preg_split('/[\s,;]+/', (string)($_POST[$k] ?? '')))));
    if ($a === 'check') { echo $J(smpro_sw_start($list('domains'), true)); exit; }
    if ($a === 'cfg') {
        $c = smpro_sw_cfg_save(['auto' => ($_POST['auto'] ?? '') === '1', 'scope' => (string)($_POST['scope'] ?? 'all'), 'sites' => $list('sites'), 'files_min' => (int)($_POST['files_min'] ?? 60),
            'db_min' => (int)($_POST['db_min'] ?? 1440), 'keep_days' => (int)($_POST['keep_days'] ?? 90), 'protect' => $list('protect'),
            'alerts' => array_map(fn($k) => in_array($k, $list('alerts'), true), array_combine(array_keys(smpro_sw_cfg()['alerts']), array_keys(smpro_sw_cfg()['alerts'])))]);
        smpro_audit('sitewatch_cfg', ['auto' => $c['auto'], 'scope' => $c['scope'], 'protect' => count($c['protect'])]);
        echo $J(['ok' => true, 'msg' => 'Saved.', 'cfg' => $c]); exit;
    }
    if ($a === 'rule_add') {
        $to = $list('to'); $ch = array_values(array_intersect($list('channels'), ['whatsapp', 'telegram', 'email']));
        $sites = ($_POST['sites_mode'] ?? '') === 'all' ? '*' : array_map('smpro_sw_key', $list('sites'));
        if (!$to || !$ch || ($sites !== '*' && !$sites)) { echo $J(['ok' => false, 'msg' => 'Pick the sites, at least one number/address and a channel.']); exit; }
        $c = smpro_sw_cfg(); $c['rules'][] = ['sites' => $sites, 'to' => $to, 'channels' => $ch, 'level' => in_array($_POST['level'] ?? '', ['critical', 'warning', 'info'], true) ? $_POST['level'] : 'critical',
            'when' => in_array($_POST['when'] ?? '', ['instant', 'daily', 'weekly', 'instant_daily'], true) ? $_POST['when'] : 'instant'];
        smpro_sw_cfg_save(['rules' => $c['rules']]); smpro_audit('sitewatch_rule_add', ['sites' => is_array($sites) ? count($sites) : 'all', 'to' => count($to)]);
        echo $J(['ok' => true, 'msg' => 'Rule saved.']); exit;
    }
    if ($a === 'rule_del') { $c = smpro_sw_cfg(); array_splice($c['rules'], (int)($_POST['i'] ?? -1), 1); smpro_sw_cfg_save(['rules' => $c['rules']]); echo $J(['ok' => true, 'msg' => 'Rule removed.']); exit; }
    if ($a === 'rule_test') {
        $r = smpro_sw_cfg()['rules'][(int)($_POST['i'] ?? -1)] ?? null; if (!$r) { echo $J(['ok' => false, 'msg' => 'No such rule.']); exit; }
        $out = []; foreach ($r['to'] as $to) foreach ($r['channels'] as $ch) { [$ok, $d] = smpro_sw_send($ch, $to, 'Site Watch test', "Site Watch test message from " . gethostname()); $out[] = $ch . ' ' . $to . ': ' . ($ok ? 'sent' : 'failed - ' . $d); }
        echo $J(['ok' => true, 'msg' => implode("\n", $out)]); exit;
    }
    if ($a === 'fix') { echo $J(smpro_sw_fix((string)($_POST['domain'] ?? ''), (string)($_POST['act'] ?? ''), (string)($_POST['arg'] ?? ''))); exit; }
    if ($a === 'fix_safe') { echo $J(smpro_sw_fix_safe((string)($_POST['domain'] ?? ''), 'manual')); exit; }
    if ($a === 'undo') { echo $J(function_exists('smpro_inv_undo') ? smpro_inv_undo((string)($_POST['id'] ?? '')) : ['ok' => false]); exit; }
}

$csrf = smpro_csrf_generate('sw_action');
smpro_audit('sitewatch_view', []);
smpro_layout_header('Site Watch');
$doms = array_keys(function_exists('smpro_sdb_targets') ? smpro_sdb_targets() : []);
?>
<script>var SW_CSRF=<?= json_encode($csrf) ?>;</script>
<datalist id="swDoms"><?php foreach ($doms as $d) echo '<option value="' . smpro_h($d) . '">'; ?></datalist>
<div class="svc-kicker">Security</div>
<h1 class="h" style="margin:2px 0 4px">&#128065; Site Watch</h1>
<p class="sub">Who uploaded or changed which file, what ran on the site, what changed in its database — per site. Then fix it or lock it down; every change is backed up first and can be undone.</p>

<div class="card sw-c sw-bar">
  <div class="sw-bar-l">
    <div class="sw-h">Check now</div>
    <div class="sw-row">
      <select id="swWhat" title="What to check"><option value="one">One site</option><option value="prot">The auto-protected sites</option><option value="scope">All watched sites</option></select>
      <input type="text" id="swOne" list="swDoms" placeholder="type or pick a site" style="min-width:220px">
      <button class="sd-go sw-g" id="swCheck" type="button">&#9654; Check now</button>
    </div>
  </div>
  <div class="sw-bar-r">
    <div id="swJob" class="sw-mut">No check running.</div>
    <div class="sw-prog" id="swProgW" style="display:none"><div id="swProg"></div></div>
  </div>
</div>

<div class="card sw-c">
  <div class="sw-row" style="justify-content:space-between"><div class="sw-h" style="margin:0">Settings</div><span class="sw-mut" id="swDirty"></span></div>
  <div class="sw-grid">
    <section class="sw-panel">
      <label class="sw-sw"><span class="sw-tg"><input type="checkbox" id="swAuto"><i></i></span> Automatic checks</label>
      <p class="sw-help">Checks run in the background on a schedule.</p>
      <label class="sw-f">Which sites<select id="swScope"><option value="all">All sites</option><option value="list">Only the sites below</option></select></label>
      <label class="sw-f" id="swSitesW">Sites<input type="text" id="swSites" list="swDoms" placeholder="domain names, comma separated"></label>
      <div class="sw-3">
        <label class="sw-f">Files<select id="swFiles"><option value="15">every 15 min</option><option value="60">every hour</option><option value="360">every 6 h</option></select></label>
        <label class="sw-f">Database<select id="swDb"><option value="360">every 6 h</option><option value="1440">daily</option></select></label>
        <label class="sw-f">History<select id="swKeep"><option value="30">30 days</option><option value="90">90 days</option><option value="180">180 days</option></select></label>
      </div>
    </section>
    <section class="sw-panel sw-prot">
      <label class="sw-sw"><span class="sw-tg"><input type="checkbox" id="swProtOn"><i></i></span> Automatic protection</label>
      <p class="sw-help">When a Critical event is found on these sites, the safe steps run at once (quarantine the file, block who ran it, no PHP in uploads). Database edits always wait for you. Other sites are watched and reported only.</p>
      <label class="sw-f">Protected sites <span class="sw-mut" id="swProtN"></span><input type="text" id="swProt" list="swDoms" placeholder="domain names, comma separated"></label>
    </section>
    <section class="sw-panel">
      <div class="sw-sw">Instant alerts</div>
      <p class="sw-help">Sent at once to the report rules below, for these Critical events.</p>
      <div class="sw-chips">
        <label><input type="checkbox" class="swAl" value="upload_php"> PHP in uploads</label>
        <label><input type="checkbox" class="swAl" value="shell_run"> Injected file run</label>
        <label><input type="checkbox" class="swAl" value="new_admin"> New admin</label>
        <label><input type="checkbox" class="swAl" value="db_inject"> Script in database</label>
        <label><input type="checkbox" class="swAl" value="htaccess"> .htaccess change</label>
      </div>
    </section>
  </div>
  <div class="sw-row" style="justify-content:flex-end;margin-top:10px"><button class="sd-go" id="swSave" type="button">Save settings</button></div>
</div>

<div class="sw-k" id="swKpi"></div>

<div class="card sw-c">
  <div class="sw-row"><select id="swF"><option value="att">Needs attention</option><option value="all">All sites</option></select><input type="text" id="swQ" placeholder="Filter by domain or account"><label class="sw-sw"><input type="checkbox" id="swHide" checked> Hide clean sites</label><select id="swPer"><option value="25">25 per page</option><option value="50" selected>50 per page</option><option value="100">100 per page</option></select><span id="swPager" class="sw-row" style="margin-left:auto"></span></div>
  <div style="overflow-x:auto"><table class="tbl"><thead><tr><th>Site</th><th>Account</th><th>Auto-protect</th><th>Risk</th><th>Last 24 h</th><th>New PHP</th><th>Database</th><th>Checked</th><th></th></tr></thead><tbody id="swRows"></tbody></table></div>
</div>

<div class="card sw-c" id="swSite" style="display:none"></div>

<div class="card sw-c">
  <b>Who gets the reports</b> <span class="sw-mut">— which sites, which numbers, from which level, how often. A site can be in several rules; the same event never goes twice to the same number.</span>
  <div style="overflow-x:auto"><table class="tbl"><thead><tr><th>Sites</th><th>Send to</th><th>Channel</th><th>From level</th><th>When</th><th></th></tr></thead><tbody id="swRules"></tbody></table></div>
  <div class="sw-panel" style="margin-top:10px">
    <div class="sw-sw">New rule</div>
    <div class="sw-rule">
      <label class="sw-f">Sites<select id="rMode"><option value="list">These sites</option><option value="all">All sites</option></select></label>
      <label class="sw-f" id="rSitesW">Which<input type="text" id="rSites" list="swDoms" placeholder="domain names, comma separated"></label>
      <label class="sw-f">Send to<input type="text" id="rTo" placeholder="numbers / chat ids / e-mails, comma separated"></label>
      <div class="sw-f">Channel<div class="sw-chips"><label><input type="checkbox" class="rCh" value="whatsapp" checked> WhatsApp</label><label><input type="checkbox" class="rCh" value="telegram"> Telegram</label><label><input type="checkbox" class="rCh" value="email"> E-mail</label></div></div>
      <label class="sw-f">From level<select id="rLevel"><option value="critical">Critical only</option><option value="warning">Warning and above</option><option value="info">Everything</option></select></label>
      <label class="sw-f">When<select id="rWhen"><option value="instant">Instantly</option><option value="daily">Daily summary</option><option value="weekly">Weekly report</option><option value="instant_daily">Instantly + daily summary</option></select></label>
    </div>
    <div class="sw-row" style="justify-content:flex-end"><button class="sd-go sw-g" id="rAdd" type="button">+ Add rule</button></div>
  </div>
  <p class="sw-mut" style="font-size:12px;margin:6px 0 0">WhatsApp numbers in international form without + (e.g. 2010xxxxxxxx); the WhatsApp gateway of the Notifications page is used.</p>
</div>
<style>
.svc-kicker{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--brand);font-weight:800}
.sw-c{padding:14px;margin-bottom:14px}.sw-row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:4px 0}.sw-row input[type=text],.sw-row select{border:1px solid var(--line);border-radius:9px;padding:7px 9px}
.sw-prot{padding:8px;border:1px solid #bbf7d0;background:#f7fef9;border-radius:10px}.sw-sw{font-weight:700;display:inline-flex;gap:6px;align-items:center}.sw-mut{color:#64748b;font-size:13px}
.sd-go{border:none;background:var(--brand);color:#fff;border-radius:10px;padding:8px 16px;font-weight:700;cursor:pointer}.sd-go.sw-g{background:#059669}.sd-go.sw-o{background:#fff;color:#0f172a;border:1px solid var(--line)}
.sw-k{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:14px}.sw-k div{background:#fff;border:1px solid var(--line);border-radius:12px;padding:10px}.sw-k b{font-size:22px;display:block}
.pl{display:inline-block;border-radius:20px;padding:1px 8px;font-size:12px;font-weight:700}.pr{background:#fee2e2;color:#991b1b}.pa{background:#fef3c7;color:#92400e}.pg{background:#dcfce7;color:#166534}.ps{background:#e2e8f0;color:#334155}
.sw-tl{border-left:2px solid var(--line);margin-left:6px;padding-left:14px}.sw-ev{padding:6px 0 10px}.sw-ev small{color:#64748b}.mono{font-family:ui-monospace,Consolas,monospace;font-size:12px}
.sw-h{font-weight:800;font-size:15px;margin-bottom:6px}
.sw-bar{display:flex;gap:16px;justify-content:space-between;align-items:center;flex-wrap:wrap}.sw-bar-r{flex:1;min-width:260px;max-width:520px}
.sw-prog{height:8px;background:#e2e8f0;border-radius:6px;overflow:hidden;margin-top:6px}.sw-prog>div{height:100%;width:0;background:#059669;transition:width .4s}
.sw-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-top:8px}.sw-panel{border:1px solid var(--line);border-radius:12px;padding:12px;background:#fff}
.sw-panel.sw-prot{border-color:#bbf7d0;background:#f7fef9}.sw-help{color:#64748b;font-size:12px;margin:4px 0 8px}
.sw-f{display:flex;flex-direction:column;gap:4px;font-size:12px;font-weight:700;color:#475569;margin-bottom:8px}.sw-f input[type=text],.sw-f select{border:1px solid var(--line);border-radius:9px;padding:7px 9px;font-weight:400;font-size:13px;color:#0f172a}
.sw-3{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}.sw-chips{display:flex;flex-wrap:wrap;gap:6px}.sw-chips label{border:1px solid var(--line);border-radius:20px;padding:4px 10px;font-size:13px;font-weight:600;color:#0f172a;cursor:pointer;display:inline-flex;gap:5px;align-items:center}
.sw-rule{display:grid;grid-template-columns:150px 1fr 1fr;gap:8px 12px;margin-top:8px}
.sw-tg{position:relative;width:36px;height:20px;display:inline-block}.sw-tg input{opacity:0;width:0;height:0}.sw-tg i{position:absolute;inset:0;background:#cbd5e1;border-radius:20px;transition:.2s}.sw-tg i:before{content:"";position:absolute;width:16px;height:16px;left:2px;top:2px;background:#fff;border-radius:50%;transition:.2s}
.sw-tg input:checked+i{background:#059669}.sw-tg input:checked+i:before{transform:translateX(16px)}.sw-tg input:focus-visible+i{outline:2px solid var(--brand);outline-offset:2px}
.sw-k div{cursor:pointer}.sw-k div:hover{border-color:var(--brand)}.sd-go:disabled{opacity:.5;cursor:default}
@media(max-width:1000px){.sw-grid,.sw-rule{grid-template-columns:1fr}}
.sw-2{display:grid;grid-template-columns:1.4fr 1fr;gap:14px}@media(max-width:900px){.sw-2,.sw-k{grid-template-columns:1fr}}
</style>
<script>
(function(){
  var S=null,tm=null,PG=1,$=function(i){return document.getElementById(i);};
  function e(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
  function post(d){var f=new URLSearchParams();f.set('smpro_csrf',SW_CSRF);Object.keys(d).forEach(function(k){f.set(k,d[k]);});return fetch('index.cgi?page=site-watch',{method:'POST',body:f,credentials:'same-origin'}).then(function(r){return r.json();});}
  function pill(r){return {critical:'<span class="pl pr">Critical</span>',warning:'<span class="pl pa">Warning</span>',clean:'<span class="pl pg">Clean</span>',unchecked:'<span class="pl ps">Not checked</span>'}[r]||e(r);}
  function ago(t){if(!t)return '—';var s=Math.round(Date.now()/1000-t);return s<3600?Math.round(s/60)+' min ago':s<86400?Math.round(s/3600)+' h ago':Math.round(s/86400)+' d ago';}
  function load(){fetch('index.cgi?page=site-watch&sw_state=1',{cache:'no-store',credentials:'same-origin'}).then(function(r){return r.json();}).then(function(j){var first=!S;S=j;if(first){fillCfg();vis();}draw();clearTimeout(tm);if(j.job&&j.job.running)tm=setTimeout(load,4000);});}
  function fillCfg(){var c=S.cfg;$('swAuto').checked=!!c.auto;$('swScope').value=c.scope;$('swSites').value=(c.sites||[]).join(', ');$('swFiles').value=String(c.files_min);$('swDb').value=String(c.db_min);$('swKeep').value=String(c.keep_days);
    $('swProtOn').checked=(c.protect||[]).length>0;$('swProt').value=(c.protect||[]).join(', ');[].forEach.call(document.querySelectorAll('.swAl'),function(x){x.checked=!!c.alerts[x.value];});}
  function draw(){
    var jb=S.job||{},rs=S.rows||[],c=S.cfg;
    $('swProgW').style.display=jb.running?'':'none';if(jb.running)$('swProg').style.width=Math.round(100*(jb.done||0)/Math.max(1,jb.total||1))+'%';
    $('swJob').textContent=jb.running?('Checking '+(jb.done||0)+' of '+(jb.total||0)+(jb.current?' — now: '+jb.current:'')+' · you can close this page'):(jb.finished?'Last check finished '+ago(jb.finished)+'.':'No check running.');
    $('swCheck').disabled=!!jb.running; $('swProtN').textContent=(c.protect||[]).length+' of '+rs.length;
    var cr=rs.filter(function(r){return r.risk==='critical';}).length,wa=rs.filter(function(r){return r.risk==='warning';}).length,np=rs.reduce(function(a,r){return a+(r.newphp||0);},0),db=rs.reduce(function(a,r){return a+(r.db?1:0);},0),cl=rs.filter(function(r){return r.risk==='clean';}).length;
    $('swKpi').innerHTML='<div data-k="crit"><b style="color:#dc2626">'+cr+'</b>Critical sites</div><div data-k="warn"><b style="color:#b45309">'+wa+'</b>Warnings</div><div data-k="new"><b>'+np+'</b>New PHP files (last check)</div><div data-k="db"><b style="color:#dc2626">'+db+'</b>Database changes (24 h)</div><div data-k="clean"><b>'+cl+'</b>Clean sites</div>';
    var f=$('swF').value,q=$('swQ').value.toLowerCase(),hide=$('swHide').checked,h='';
    var list=rs.slice().sort(function(a,b){var o={critical:0,warning:1,unchecked:2,clean:3};return (o[a.risk]-o[b.risk])||(a.domain<b.domain?-1:1);}).filter(function(r){
      if(hide&&r.risk==='clean')return false; if(f==='att'&&r.risk!=='critical'&&r.risk!=='warning')return false; if(q&&(r.domain+' '+(r.user||'')).toLowerCase().indexOf(q)<0)return false; return true;});
    var per=+$('swPer').value,pages=Math.max(1,Math.ceil(list.length/per));if(PG>pages)PG=pages;
    var ph='<span class="sw-mut">'+(list.length?((PG-1)*per+1)+'–'+Math.min(PG*per,list.length)+' of '+list.length:'0')+'</span> ';
    if(pages>1){ph+='<button class="sd-go sw-o swPg" data-p="'+Math.max(1,PG-1)+'"'+(PG===1?' disabled':'')+'>‹ Prev</button>';
      for(var p=1;p<=pages;p++){if(p===1||p===pages||Math.abs(p-PG)<=2)ph+='<button class="sd-go swPg'+(p===PG?'':' sw-o')+'" data-p="'+p+'">'+p+'</button>';else if(Math.abs(p-PG)===3)ph+='<span class="sw-mut">…</span>';}
      ph+='<button class="sd-go sw-o swPg" data-p="'+Math.min(pages,PG+1)+'"'+(PG===pages?' disabled':'')+'>Next ›</button>';}
    $('swPager').innerHTML=ph;
    list.slice((PG-1)*per,PG*per).forEach(function(r){
      var pr=(c.protect||[]).indexOf(r.domain)>=0;
      h+='<tr><td><b>'+e(r.domain)+'</b></td><td>'+e(r.user||'')+'</td><td>'+(pr?'<span class="pl pg">On</span>':'<span class="pl ps">Watch only</span>')+'</td><td>'+pill(r.risk)+'</td><td>'+e(r.top||'')+'</td><td>'+(r.newphp?'<span class="pl pa">'+r.newphp+'</span>':'0')+'</td><td>'+(r.db?'<span class="pl pr">'+r.db+'</span>':'—')+'</td><td>'+ago(r.checked_at)+'</td><td><a href="#" class="swOpen" data-d="'+e(r.domain)+'">Open</a></td></tr>';
    });
    $('swRows').innerHTML=h||'<tr><td colspan="9" class="sw-mut">Nothing to show'+(rs.some(function(r){return r.risk==='unchecked';})?' — press "Check now" for the first check.':'.')+'</td></tr>';
    var rh='';(c.rules||[]).forEach(function(r,i){rh+='<tr><td>'+(r.sites==='*'?'<span class="pl ps">All sites</span>':e(r.sites.join(', ')))+'</td><td class="mono">'+e(r.to.join(', '))+'</td><td>'+e(r.channels.join(' + '))+'</td><td>'+e(r.level)+'</td><td>'+e(r.when)+'</td><td><a href="#" data-t="'+i+'" class="rT">Test</a> · <a href="#" data-x="'+i+'" class="rX">Delete</a></td></tr>';});
    $('swRules').innerHTML=rh||'<tr><td colspan="6" class="sw-mut">No rules yet — nothing is sent.</td></tr>';
  }
  function site(d){fetch('index.cgi?page=site-watch&sw_site='+encodeURIComponent(d),{cache:'no-store',credentials:'same-origin'}).then(function(r){return r.json();}).then(function(j){
    var st=j.state||{},h='<div class="sw-row" style="justify-content:space-between"><div><h2 class="h" style="margin:0">'+e(d)+' '+pill(st.risk||'unchecked')+'</h2><span class="sw-mut">Account '+e(st.user||'')+' · '+e(st.docroot||'')+' · '+(st.files_n||0)+' code files · checked '+ago(st.checked_at)+'</span></div>'
      +'<div class="sw-row"><button class="sd-go" data-act="checkone">Check this site now</button><a class="sd-go sw-o" href="index.cgi?page=site-doctor&target='+encodeURIComponent(d)+'">Site Doctor</a></div></div>';
    var plan=j.plan||[];
    h+='<div class="card" style="margin:10px 0;padding:12px;border-color:#bbf7d0;background:#f7fef9"><div class="sw-row" style="justify-content:space-between"><b>Fix &amp; protect</b>'+(plan.some(function(s){return s.safe;})?'<button class="sd-go sw-g" data-act="fixsafe">Fix all safe steps ('+plan.filter(function(s){return s.safe;}).length+')</button>':'')+'</div>';
    h+=plan.length?'<table class="tbl">'+plan.map(function(s,i){return '<tr><td>'+e(s.label)+'</td><td>'+(s.safe?'<span class="pl pg">Safe</span>':'<span class="pl pa">By hand</span>')+'</td><td>'+(s.action!=='advice'?'<button class="sd-go'+(s.safe?'':' sw-o')+'" style="padding:4px 10px" data-fix="'+i+'">'+(s.safe?'Fix':'Review &amp; fix')+'</button>':'')+'</td></tr>';}).join('')+'</table>':'<span class="sw-mut">Nothing to fix right now.</span>';
    if((j.fixes||[]).length)h+='<div style="margin-top:8px"><b style="font-size:13px">Done</b>'+j.fixes.map(function(x){return '<div class="sw-mut">'+new Date(x.ts*1000).toLocaleString()+' — '+e(x.msg)+(x.undo_id?' <a href="#" data-undo="'+e(x.undo_id)+'">Undo</a>':'')+'</div>';}).join('')+'</div>';
    h+='</div><div class="sw-2"><div class="sw-tl">';
    (j.events||[]).slice(0,120).forEach(function(v){var dd=v.data||{},w=dd.who||{},col={critical:'#dc2626',warning:'#f59e0b',info:'#94a3b8'}[v.sev];
      h+='<div class="sw-ev"><small>'+new Date(v.ts*1000).toLocaleString()+'</small> <span style="color:'+col+';font-weight:800">●</span> <b>'+e(v.title)+'</b>'+(v.resolved?' <span class="pl pg">resolved</span>':'')
       +(w.door?'<br><small>Door: <b>'+e(w.door)+'</b>'+(w.login?' · '+e(w.login):'')+(w.ip?' · from '+e(w.ip):'')+' · '+e(w.how||'')+'</small>':'')
       +(dd.ran&&dd.ran.runs?'<br><small>Run '+dd.ran.runs+'x from '+e(dd.ran.ips.join(', '))+'</small>':'')+(dd.ips?'<br><small>From '+e(dd.ips.join(', '))+'</small>':'')
       +(dd.login&&v.kind==='new_admin'?'<br><small>'+e(dd.email||'')+' · registered '+e(dd.registered||'')+'</small>':'')
       +(dd.steps?'<br><small>'+dd.steps.map(e).join('<br>')+'</small>':'')+'</div>';});
    if(!(j.events||[]).length)h+='<span class="sw-mut">No events yet.</span>';
    h+='</div><div>';
    var nw=(st.new24||[]).filter(function(p){return /\.(php\d?|phtml|phar)$/i.test(p);});
    h+='<div class="card" style="padding:10px;margin-bottom:10px"><b>New PHP files (last check)</b>'+(nw.length?nw.slice(0,40).map(function(p){return '<div class="mono">'+e(p)+'</div>';}).join(''):'<div class="sw-mut">None</div>')+'</div>';
    var db=j.db||{};h+='<div class="card" style="padding:10px;margin-bottom:10px"><b>Database</b>'+(db.ts?'<div class="sw-mut">Snapshot '+new Date(db.ts*1000).toLocaleString()+'</div><div>Administrators: '+e(Object.keys(db.admins||{}).join(', '))+'</div><div>Injected posts: '+(db.inj_posts||[]).length+' · options: '+(db.inj_options||[]).length+'</div>':'<div class="sw-mut">Not a WordPress site, or not checked yet.</div>')+'</div>';
    h+='<div class="card" style="padding:10px"><b>Security checks</b>'+(st.checks||[]).map(function(c){return '<div>'+({fail:'<span class="pl pr">Fail</span>',warn:'<span class="pl pa">Warn</span>',ok:'<span class="pl pg">OK</span>',info:'<span class="pl ps">Info</span>'}[c[0]])+' '+e(c[1])+'</div>';}).join('')+'</div></div></div>';
    var box=$('swSite');box.innerHTML=h;box.style.display='';box.scrollIntoView({behavior:'smooth'});
    box.onclick=function(ev){var b=ev.target.closest('[data-fix],[data-act],[data-undo]');if(!b)return;ev.preventDefault();
      if(b.dataset.act==='checkone'){post({sw_action:'check',domains:d}).then(function(x){alert(x.msg);load();});return;}
      if(b.dataset.act==='fixsafe'){if(!confirm('Run every safe step on '+d+'? Each one is backed up and can be undone.'))return;post({sw_action:'fix_safe',domain:d}).then(function(x){alert((x.steps||[]).join('\n')||'Nothing done.');site(d);});return;}
      if(b.dataset.undo){post({sw_action:'undo',id:b.dataset.undo}).then(function(x){alert(x.msg||'');site(d);});return;}
      var s=plan[+b.dataset.fix];if(!confirm(s.label+'?'+(s.safe?'':'\n\nThis is a by-hand step: read it carefully.')))return;post({sw_action:'fix',domain:d,act:s.action,arg:s.arg}).then(function(x){alert(x.msg||'');site(d);});};
  });}
  $('swSave').onclick=function(){post({sw_action:'cfg',auto:$('swAuto').checked?'1':'0',scope:$('swScope').value,sites:$('swSites').value,files_min:$('swFiles').value,db_min:$('swDb').value,keep_days:$('swKeep').value,
    protect:$('swProtOn').checked?$('swProt').value:'',alerts:[].filter.call(document.querySelectorAll('.swAl'),function(x){return x.checked;}).map(function(x){return x.value;}).join(',')}).then(function(j){$('swJob').textContent=j.msg||'';$('swDirty').textContent='Saved';S=null;load();});};
  function vis(){$('swSitesW').style.display=$('swScope').value==='list'?'':'none';$('swProt').disabled=!$('swProtOn').checked;$('rSitesW').style.display=$('rMode').value==='all'?'none':'';}
  ['swAuto','swScope','swSites','swFiles','swDb','swKeep','swProtOn','swProt'].forEach(function(id){$(id).addEventListener('change',function(){vis();$('swDirty').textContent='Unsaved changes';});});
  [].forEach.call(document.querySelectorAll('.swAl'),function(x){x.addEventListener('change',function(){$('swDirty').textContent='Unsaved changes';});});
  $('rMode').addEventListener('change',vis);
  $('swKpi').onclick=function(ev){var k=ev.target.closest('div[data-k]');if(!k)return;$('swF').value=k.dataset.k==='clean'?'all':'att';$('swHide').checked=k.dataset.k!=='clean';PG=1;draw();};
  $('swWhat').onchange=function(){$('swOne').style.display=this.value==='one'?'':'none';};
  $('swCheck').onclick=function(){var w=$('swWhat').value,d='';
    if(w==='one'){d=$('swOne').value.trim();if(!d){alert('Type the site to check.');return;}}
    else if(w==='prot'){d=(S.cfg.protect||[]).join(',');if(!d){alert('No auto-protected site is selected.');return;}}
    else if(!confirm('Check every watched site ('+(S.cfg.scope==='list'?(S.cfg.sites||[]).length:S.rows.length)+')? It runs in the background.'))return;
    post({sw_action:'check',domains:d}).then(function(j){$('swJob').textContent=j.msg||'';setTimeout(load,1500);});};
  $('rAdd').onclick=function(){post({sw_action:'rule_add',sites_mode:$('rMode').value,sites:$('rSites').value,to:$('rTo').value,channels:[].filter.call(document.querySelectorAll('.rCh'),function(x){return x.checked;}).map(function(x){return x.value;}).join(','),level:$('rLevel').value,when:$('rWhen').value}).then(function(j){alert(j.msg);load();});};
  $('swRules').onclick=function(ev){var a=ev.target.closest('a');if(!a)return;ev.preventDefault();if(a.className==='rT')post({sw_action:'rule_test',i:a.dataset.t}).then(function(j){alert(j.msg);});else if(confirm('Delete this rule?'))post({sw_action:'rule_del',i:a.dataset.x}).then(function(){load();});};
  $('swRows').onclick=function(ev){var a=ev.target.closest('a.swOpen');if(!a)return;ev.preventDefault();site(a.dataset.d);};
  var rst=function(){PG=1;draw();};
  $('swF').onchange=rst;$('swQ').oninput=rst;$('swHide').onchange=rst;$('swPer').onchange=rst;
  $('swPager').onclick=function(ev){var b=ev.target.closest('.swPg');if(!b||b.disabled)return;PG=+b.dataset.p;draw();$('swPager').scrollIntoView({block:'nearest'});};
  load();
})();
</script>
<?php smpro_layout_footer();
