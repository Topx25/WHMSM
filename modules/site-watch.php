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
        $ev = array_values(array_filter(smpro_sw_events($d, 60), fn($e) => $e['ts'] >= $cut && empty($e['resolved'])));
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

<div class="card sw-c">
  <div class="sw-row">
    <label class="sw-sw"><input type="checkbox" id="swAuto"> Automatic checks</label>
    <select id="swScope"><option value="all">All sites</option><option value="list">Only these sites:</option></select>
    <input type="text" id="swSites" list="swDoms" placeholder="domain names, comma separated" style="min-width:240px">
    <select id="swFiles"><option value="15">Files every 15 min</option><option value="60">Files every hour</option><option value="360">Files every 6 h</option></select>
    <select id="swDb"><option value="360">Database every 6 h</option><option value="1440">Database daily</option></select>
    <select id="swKeep"><option value="30">Keep 30 days</option><option value="90">Keep 90 days</option><option value="180">Keep 180 days</option></select>
  </div>
  <div class="sw-row sw-prot">
    <label class="sw-sw"><input type="checkbox" id="swProtOn"> Automatic protection</label><span class="sw-mut">only on these sites:</span>
    <input type="text" id="swProt" list="swDoms" placeholder="pick sites" style="min-width:320px"><span class="sw-mut" id="swProtN"></span>
    <span class="sw-mut">Other sites are watched and reported only.</span>
  </div>
  <div class="sw-row"><span class="sw-mut">Instant alerts on:</span>
    <label><input type="checkbox" class="swAl" value="upload_php"> PHP in uploads</label><label><input type="checkbox" class="swAl" value="shell_run"> Injected file run</label>
    <label><input type="checkbox" class="swAl" value="new_admin"> New admin</label><label><input type="checkbox" class="swAl" value="db_inject"> Script in database</label>
    <label><input type="checkbox" class="swAl" value="htaccess"> .htaccess change</label>
    <button class="sd-go" id="swSave" type="button">Save</button><button class="sd-go sw-g" id="swCheck" type="button">Check now</button>
  </div>
  <div id="swJob" class="sw-mut" style="margin-top:6px"></div>
</div>

<div class="sw-k" id="swKpi"></div>

<div class="card sw-c">
  <div class="sw-row"><select id="swF"><option value="att">Needs attention</option><option value="all">All sites</option></select><input type="text" id="swQ" placeholder="Filter by domain or account"><label class="sw-sw"><input type="checkbox" id="swHide" checked> Hide clean sites</label></div>
  <div style="overflow-x:auto"><table class="tbl"><thead><tr><th>Site</th><th>Account</th><th>Auto-protect</th><th>Risk</th><th>Last 24 h</th><th>New PHP</th><th>Database</th><th>Checked</th><th></th></tr></thead><tbody id="swRows"></tbody></table></div>
</div>

<div class="card sw-c" id="swSite" style="display:none"></div>

<div class="card sw-c">
  <b>Who gets the reports</b> <span class="sw-mut">— which sites, which numbers, from which level, how often. A site can be in several rules; the same event never goes twice to the same number.</span>
  <div style="overflow-x:auto"><table class="tbl"><thead><tr><th>Sites</th><th>Send to</th><th>Channel</th><th>From level</th><th>When</th><th></th></tr></thead><tbody id="swRules"></tbody></table></div>
  <div class="sw-row" style="margin-top:8px">
    <select id="rMode"><option value="list">These sites:</option><option value="all">All sites</option></select>
    <input type="text" id="rSites" list="swDoms" placeholder="domain names, comma separated" style="min-width:220px">
    <input type="text" id="rTo" placeholder="Numbers / chat ids / e-mails, comma separated" style="min-width:260px">
    <label><input type="checkbox" class="rCh" value="whatsapp" checked> WhatsApp</label><label><input type="checkbox" class="rCh" value="telegram"> Telegram</label><label><input type="checkbox" class="rCh" value="email"> E-mail</label>
    <select id="rLevel"><option value="critical">Critical only</option><option value="warning">Warning and above</option><option value="info">Everything</option></select>
    <select id="rWhen"><option value="instant">Instantly</option><option value="daily">Daily summary</option><option value="weekly">Weekly report</option><option value="instant_daily">Instantly + daily summary</option></select>
    <button class="sd-go sw-g" id="rAdd" type="button">Add rule</button>
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
.sw-2{display:grid;grid-template-columns:1.4fr 1fr;gap:14px}@media(max-width:900px){.sw-2,.sw-k{grid-template-columns:1fr}}
</style>
<script>
(function(){
  var S=null,tm=null,$=function(i){return document.getElementById(i);};
  function e(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
  function post(d){var f=new URLSearchParams();f.set('smpro_csrf',SW_CSRF);Object.keys(d).forEach(function(k){f.set(k,d[k]);});return fetch('index.cgi?page=site-watch',{method:'POST',body:f,credentials:'same-origin'}).then(function(r){return r.json();});}
  function pill(r){return {critical:'<span class="pl pr">Critical</span>',warning:'<span class="pl pa">Warning</span>',clean:'<span class="pl pg">Clean</span>',unchecked:'<span class="pl ps">Not checked</span>'}[r]||e(r);}
  function ago(t){if(!t)return '—';var s=Math.round(Date.now()/1000-t);return s<3600?Math.round(s/60)+' min ago':s<86400?Math.round(s/3600)+' h ago':Math.round(s/86400)+' d ago';}
  function load(){fetch('index.cgi?page=site-watch&sw_state=1',{cache:'no-store',credentials:'same-origin'}).then(function(r){return r.json();}).then(function(j){var first=!S;S=j;if(first)fillCfg();draw();clearTimeout(tm);if(j.job&&j.job.running)tm=setTimeout(load,4000);});}
  function fillCfg(){var c=S.cfg;$('swAuto').checked=!!c.auto;$('swScope').value=c.scope;$('swSites').value=(c.sites||[]).join(', ');$('swFiles').value=String(c.files_min);$('swDb').value=String(c.db_min);$('swKeep').value=String(c.keep_days);
    $('swProtOn').checked=(c.protect||[]).length>0;$('swProt').value=(c.protect||[]).join(', ');[].forEach.call(document.querySelectorAll('.swAl'),function(x){x.checked=!!c.alerts[x.value];});}
  function draw(){
    var jb=S.job||{},rs=S.rows||[],c=S.cfg;
    $('swJob').textContent=jb.running?('Checking '+(jb.done||0)+' of '+(jb.total||0)+(jb.current?' — now: '+jb.current:'')+' · you can close this page'):(jb.finished?'Last check finished '+ago(jb.finished):'');
    $('swCheck').disabled=!!jb.running; $('swProtN').textContent=(c.protect||[]).length+' of '+rs.length;
    var cr=rs.filter(function(r){return r.risk==='critical';}).length,wa=rs.filter(function(r){return r.risk==='warning';}).length,np=rs.reduce(function(a,r){return a+(r.newphp||0);},0),db=rs.reduce(function(a,r){return a+(r.db?1:0);},0),cl=rs.filter(function(r){return r.risk==='clean';}).length;
    $('swKpi').innerHTML='<div><b style="color:#dc2626">'+cr+'</b>Critical sites</div><div><b style="color:#b45309">'+wa+'</b>Warnings</div><div><b>'+np+'</b>New PHP files (last check)</div><div><b style="color:#dc2626">'+db+'</b>Database changes (24 h)</div><div><b>'+cl+'</b>Clean sites</div>';
    var f=$('swF').value,q=$('swQ').value.toLowerCase(),hide=$('swHide').checked,h='';
    rs.slice().sort(function(a,b){var o={critical:0,warning:1,unchecked:2,clean:3};return o[a.risk]-o[b.risk];}).forEach(function(r){
      if(hide&&r.risk==='clean')return; if(f==='att'&&r.risk!=='critical'&&r.risk!=='warning')return; if(q&&(r.domain+' '+(r.user||'')).toLowerCase().indexOf(q)<0)return;
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
    protect:$('swProtOn').checked?$('swProt').value:'',alerts:[].filter.call(document.querySelectorAll('.swAl'),function(x){return x.checked;}).map(function(x){return x.value;}).join(',')}).then(function(j){$('swJob').textContent=j.msg||'';S=null;load();});};
  $('swCheck').onclick=function(){post({sw_action:'check',domains:''}).then(function(j){$('swJob').textContent=j.msg||'';setTimeout(load,1500);});};
  $('rAdd').onclick=function(){post({sw_action:'rule_add',sites_mode:$('rMode').value,sites:$('rSites').value,to:$('rTo').value,channels:[].filter.call(document.querySelectorAll('.rCh'),function(x){return x.checked;}).map(function(x){return x.value;}).join(','),level:$('rLevel').value,when:$('rWhen').value}).then(function(j){alert(j.msg);load();});};
  $('swRules').onclick=function(ev){var a=ev.target.closest('a');if(!a)return;ev.preventDefault();if(a.className==='rT')post({sw_action:'rule_test',i:a.dataset.t}).then(function(j){alert(j.msg);});else if(confirm('Delete this rule?'))post({sw_action:'rule_del',i:a.dataset.x}).then(function(){load();});};
  $('swRows').onclick=function(ev){var a=ev.target.closest('a.swOpen');if(!a)return;ev.preventDefault();site(a.dataset.d);};
  $('swF').onchange=draw;$('swQ').oninput=draw;$('swHide').onchange=draw;
  load();
})();
</script>
<?php smpro_layout_footer();
