<?php
/**
 * modules/database-health.php — MySQL / MariaDB slowness & health (LIVE page).
 * Everything on this page refreshes in place from index.cgi?...&metric=dbhealth&full=1 —
 * the markup is rendered by the shared smpro_dbh_*_html() helpers in includes/dbhealth.php,
 * so the first paint and every live refresh come from exactly the same code.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

/* ---- POST actions (JSON, root + CSRF) ---- */
$reqMethod = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));
if ($reqMethod === 'POST' && ($_POST['dbh_action'] ?? '') !== '') {
    header('Content-Type: application/json');                 // FIRST, so CSRF/root failures return JSON
    smpro_require_valid_csrf('dbh_action'); smpro_require_root();
    $act = (string)$_POST['dbh_action'];
    if ($act === 'kill')   { echo json_encode(smpro_dbh_kill_query((int)($_POST['id'] ?? 0)), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit; }
    if ($act === 'fix')    { echo json_encode(smpro_dbh_apply(preg_replace('/[^a-z_]/', '', strtolower((string)($_POST['fix'] ?? '')))), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit; }
    if ($act === 'rec')    { echo json_encode(smpro_dbh_apply_rec(preg_replace('/[^a-z_]/', '', strtolower((string)($_POST['key'] ?? '')))), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit; }
    if ($act === 'revert') { echo json_encode(smpro_dbh_revert(preg_replace('/[^a-z_:]/', '', strtolower((string)($_POST['which'] ?? '')))), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit; }
    echo json_encode(['ok' => false, 'msg' => 'Unknown action.']); exit;
}

smpro_layout_header('Database Health');

$state = smpro_dbh_state();
if (empty($state['ok'])) {
    ?>
    <h1 class="h">Database Health <span class="sub" style="font-weight:400">MySQL / MariaDB</span></h1>
    <div class="card" style="margin-top:14px;border-left:4px solid var(--warn);display:flex;gap:14px;align-items:flex-start">
      <div style="font-size:26px">&#128190;</div>
      <div>
        <b style="font-size:15px"><?= $state['reason'] === 'auth' ? 'Cannot read MySQL as root' : 'No local MySQL / MariaDB detected' ?></b>
        <p class="sub" style="margin:6px 0 0"><?= smpro_h($state['msg'] ?? '') ?></p>
      </div>
    </div>
    <?php
    smpro_layout_footer();
    return;
}

$R    = smpro_dbh_report();
$rec  = smpro_dbh_recommend();
$srv  = $R['server']; $k = $R['kpis'];
smpro_audit('dbhealth_view', ['score' => $R['score'], 'findings' => count($R['findings']), 'rec' => count($rec)]);
?>
<div style="display:flex;justify-content:space-between;align-items:flex-start;gap:14px;flex-wrap:wrap">
  <div>
    <h1 class="h">Database Health
      <span class="live" id="dbhLive"><i></i> LIVE <span id="dbhClock"><?= smpro_h($R['ts']) ?></span></span>
    </h1>
    <p class="sub"><b><?= smpro_h($srv['flavor']) ?> <?= smpro_h(preg_replace('/-.*$/', '', $srv['version'])) ?></b> · uptime <?= smpro_h($k['uptime_h']) ?> · <?= (int)$srv['cores'] ?> cores · buffer pool <?= smpro_h(smpro_dbh_bytes_h($k['buffer_pool'])) ?><?= ((float)$srv['ram_bytes'] > 0) ? ' of ' . smpro_h(smpro_dbh_bytes_h($srv['ram_bytes'])) . ' RAM' : '' ?>. Everything below refreshes by itself — no page reload.</p>
  </div>
  <div class="dbh-topright">
    <div class="dbh-verdict <?= smpro_h($R['verdict_cls']) ?>" id="dbhVerdict">
      <div class="dbh-score" id="dbhScore"><?= (int)$R['score'] ?></div>
      <div class="dbh-vlabel"><span id="dbhVerdictTx"><?= smpro_h($R['verdict']) ?></span><span id="dbhCounts"><?= (int)$R['counts']['high'] + (int)$R['counts']['critical'] ?> high · <?= (int)$R['counts']['medium'] ?> med · <?= (int)$R['counts']['low'] ?> low</span></div>
    </div>
    <div class="dbh-ctl">
      <select class="tp-sel" id="dbhInt" title="refresh interval">
        <option value="3000">3s</option><option value="5000" selected>5s</option><option value="10000">10s</option><option value="30000">30s</option>
      </select>
      <button class="tp-btn" id="dbhPause" type="button">Pause</button>
    </div>
  </div>
</div>

<div class="grid dbh-kpis" id="dbhKpis" style="margin:14px 0"><?= smpro_dbh_kpis_html($R) ?></div>

<?php if ($R['warm']): ?>
<div class="dbh-note">&#8987; MySQL has been up for under an hour, so rate-based checks are still warming up and may under-report.</div>
<?php endif; ?>

<?php
/* Undersized buffer-pool callout — shown only while the 'bp_undersized' finding (includes/dbhealth.php)
   is present: the pool is at/near the shipped default or a fraction of this machine's RAM. */
$bpUndersized = false;
foreach ($R['findings'] as $f) { if (($f['id'] ?? '') === 'bp_undersized') { $bpUndersized = true; break; } }
if ($bpUndersized): ?>
<div class="dbh-note">&#9888;&#65039; The InnoDB buffer pool (<?= smpro_h(smpro_dbh_bytes_h($k['buffer_pool'])) ?>) is a small fraction of this server's RAM<?= ((float)$srv['ram_bytes'] > 0) ? ' (' . smpro_h(smpro_dbh_bytes_h($srv['ram_bytes'])) . ')' : '' ?> — raising it is usually the single biggest MySQL speed win. See the HIGH finding below; the suggested value is a starting point to review, not to apply blindly.</div>
<?php endif; ?>

<!-- Ways to improve — values computed from THIS server's RAM / cores / data size -->
<div class="card" style="padding:0;overflow:hidden;margin-bottom:14px;border-top:3px solid var(--brand)">
  <div class="dbh-head"><b>&#128640; Ways to improve</b><span class="meta">tuned to this server's own RAM, cores and data size — apply live, or copy the my.cnf block to make it permanent</span>
    <span class="dbh-livemeta"><b id="dbhRecN"><?= count($rec) ?></b> suggestion(s)</span></div>
  <div id="dbhRec"><?= smpro_dbh_recommend_html($rec) ?></div>
</div>

<div class="dbh-safe">&#128737;&#65039; <b>About every fix on this page:</b> it changes a live MySQL <em>tuning number</em> with <span class="mono">SET GLOBAL</span> — it takes effect immediately, touches <b>no data</b> and deletes nothing, so <b>there is nothing to back up</b>. Each one is fully reversible: it reverts by itself on the next MySQL restart, and you get an <b>Undo</b> that restores the previous value instantly.</div>

<!-- Utilization & configuration -->
<div class="card" style="padding:0;overflow:hidden;margin-bottom:14px">
  <div class="dbh-head"><b>&#128202; Utilization &amp; configuration</b><span class="meta">what each MySQL resource is set to, how much of it you're using, and the value to aim for</span></div>
  <div class="smpro-tablewrap" id="dbhCfg"><?= smpro_dbh_config_html($R) ?></div>
</div>

<!-- Findings -->
<div class="card" style="padding:0;overflow:hidden;margin-bottom:14px">
  <div class="dbh-head"><b>&#128269; Findings</b><span class="meta">live — ranked by impact</span><span class="dbh-livemeta"><b id="dbhFN"><?= count($R['findings']) ?></b> issue(s)</span></div>
  <div id="dbhFindings"><?= smpro_dbh_findings_html($R) ?></div>
</div>

<?php
/* MyISAM hot-table list — only when the "myisam_locks" finding above is present and the (cached ~1h) list is non-empty.
   Names the exact tables that finding recommends converting, each with a copy-ready ALTER TABLE hint. */
$myisamPresent = false;
foreach ($R['findings'] as $f) { if (($f['id'] ?? '') === 'myisam_locks') { $myisamPresent = true; break; } }
$myisamRows = $myisamPresent ? smpro_dbh_myisam_tables() : [];
if ($myisamPresent && $myisamRows): ?>
<!-- MyISAM tables behind the table-lock finding above -->
<div class="card" style="padding:0;overflow:hidden;margin-bottom:14px">
  <div class="dbh-head"><b>&#128204; MyISAM tables to convert</b><span class="meta">the tables behind the table-lock finding above — convert each to InnoDB (row-level locking)</span><span class="dbh-livemeta"><b><?= count($myisamRows) ?></b> table(s)</span></div>
  <div class="smpro-tablewrap">
    <table class="smpro-table">
      <thead><tr><th>Table</th><th class="num">Size</th><th>Convert with</th></tr></thead>
      <tbody>
      <?php foreach ($myisamRows as $t): ?>
        <tr>
          <td class="mono"><?= smpro_h($t['schema'] . '.' . $t['table']) ?></td>
          <td class="num mono"><?= smpro_h(number_format((float)$t['mb'], 1)) ?> MB</td>
          <td class="mono"><?= smpro_h('ALTER TABLE `' . $t['schema'] . '`.`' . $t['table'] . '` ENGINE=InnoDB;') ?></td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
  </div>
</div>
<?php endif; ?>

<!-- Queries running now -->
<div class="card" style="padding:0;overflow:hidden">
  <div class="dbh-head"><b>&#9889; Queries running now</b><span class="meta">idle (Sleep) connections hidden · statements redacted · you can kill a stuck query</span>
    <span class="dbh-livemeta">active: <b id="dbhActive">—</b> · longest: <b id="dbhLongest">—</b></span></div>
  <div class="smpro-tablewrap">
    <table class="smpro-table" id="dbhProc">
      <thead><tr><th class="num">Thread</th><th>User</th><th>DB</th><th class="num">Time</th><th>Command / State</th><th>Statement</th><th></th></tr></thead>
      <tbody id="dbhProcBody"><tr><td colspan="7" style="color:var(--muted);padding:14px">Loading…</td></tr></tbody>
    </table>
  </div>
</div>

<style>
/* Base primitives — the shared layout only adds sort/border enhancements to .smpro-table, so each
   page declares the base look itself (otherwise tables render as bare, cramped browser defaults). */
.smpro-tablewrap{overflow-x:auto}
.smpro-table{width:100%;border-collapse:collapse;font-size:12.5px}
.smpro-table th,.smpro-table td{padding:9px 12px;text-align:left;border-bottom:1px solid var(--line);white-space:nowrap;vertical-align:middle}
.smpro-table th{font-size:11px;text-transform:uppercase;letter-spacing:.03em;color:var(--muted);font-weight:800}
.smpro-table td.num,.smpro-table th.num{text-align:right;font-variant-numeric:tabular-nums}
.smpro-table tbody tr:hover{background:var(--brand-bg)}
.smpro-table tbody tr:last-child td{border-bottom:none}
.mono{font-family:ui-monospace,Consolas,monospace}
.meta{color:var(--muted)}
.b{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:20px;white-space:nowrap}
.b.green{background:var(--good-bg);color:var(--good)}.b.orange{background:var(--warn-bg);color:var(--warn)}
.b.red{background:var(--dang-bg);color:var(--dang)}.b.blue{background:var(--brand-bg);color:var(--brand)}
.b.gray{background:var(--bg);color:var(--muted)}
.live{font-size:11px;font-weight:700;color:var(--good);background:var(--good-bg);padding:3px 10px;border-radius:20px;margin-left:10px;display:inline-flex;align-items:center;gap:6px;vertical-align:middle}
.live i{width:7px;height:7px;border-radius:50%;background:var(--good);display:inline-block;animation:dbhpulse 1.4s infinite}
@keyframes dbhpulse{0%,100%{opacity:1}50%{opacity:.25}}
.dbh-topright{display:flex;flex-direction:column;gap:8px;align-items:flex-end}
.dbh-ctl{display:flex;gap:8px}
.dbh-verdict{display:flex;align-items:center;gap:12px;padding:10px 16px;border-radius:14px;border:1px solid var(--line)}
.dbh-verdict.good{background:var(--good-bg)}.dbh-verdict.warn{background:var(--warn-bg)}.dbh-verdict.dang{background:var(--dang-bg)}
.dbh-score{font-size:30px;font-weight:800;line-height:1}
.dbh-verdict.good .dbh-score{color:var(--good)}.dbh-verdict.warn .dbh-score{color:var(--warn)}.dbh-verdict.dang .dbh-score{color:var(--dang)}
.dbh-vlabel{font-weight:800;font-size:14px;display:flex;flex-direction:column}
.dbh-vlabel span+span{font-weight:600;font-size:11px;color:var(--muted);margin-top:2px}
.dbh-kpis .val{font-size:20px}
.dbh-note{background:var(--warn-bg);color:#8a6516;border:1px solid var(--line);border-radius:12px;padding:10px 14px;font-size:12.5px;margin-bottom:14px}
html[data-theme=dark] .dbh-note{color:#fdba74}
.dbh-head{display:flex;align-items:center;gap:10px;padding:12px 16px;border-bottom:1px solid var(--line);flex-wrap:wrap}
.dbh-head .meta{color:var(--muted);font-size:12px}
.dbh-livemeta{margin-left:auto;font-size:12px;color:var(--muted)}.dbh-livemeta b{color:var(--ink)}
.dbh-findings{display:flex;flex-direction:column}
.dbh-f{padding:13px 16px;border-bottom:1px solid var(--line);border-left:3px solid transparent}
.dbh-f:last-child{border-bottom:none}
.dbh-f.dbh-red{border-left-color:var(--dang)}.dbh-f.dbh-orange{border-left-color:var(--warn)}.dbh-f.dbh-blue{border-left-color:var(--brand)}
.dbh-frow{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.dbh-sev{flex:none}
.dbh-ftitle{font-size:14px;flex:1;min-width:200px}
.dbh-eqv{font-family:ui-monospace,Consolas,monospace;font-size:12px;color:var(--muted);margin:7px 0 0;line-height:1.55}
.dbh-detail{font-size:12.5px;margin-top:6px;line-height:1.6;opacity:.9}
.dbh-rec{font-size:12.5px;margin-top:7px;line-height:1.6;background:var(--brand-bg);border-radius:9px;padding:8px 11px}
.dbh-rec span{font-weight:800;color:var(--brand);margin-right:4px}
.dbh-fix,.dbh-recapply{border-color:#bcd0ff!important;color:var(--brand);background:var(--brand-bg);white-space:nowrap}
.dbh-fix:hover,.dbh-recapply:hover{background:#dde6ff}
.dbh-fix:disabled,.dbh-recapply:disabled{opacity:.6;cursor:default}
.dbh-target{color:var(--brand);font-weight:700}
.dbh-cfg td,.dbh-rectbl td{vertical-align:top}
.dbh-cfg td.dbh-ideal{white-space:normal;max-width:240px;font-size:12px;line-height:1.5}
.dbh-cfg td.dbh-what,.dbh-rectbl td.dbh-what{white-space:normal;max-width:360px;color:var(--muted);font-size:12px;line-height:1.55}
.dbh-bar{height:5px;background:var(--line);border-radius:4px;overflow:hidden;margin-top:5px;max-width:160px}
.dbh-bar span{display:block;height:100%}
.dbh-bar span.green{background:var(--good)}.dbh-bar span.orange{background:var(--warn)}.dbh-bar span.red{background:var(--dang)}
.dbh-safe{background:var(--good-bg);border:1px solid var(--line);border-left:4px solid var(--good);border-radius:12px;padding:11px 14px;font-size:12.5px;line-height:1.6;margin-bottom:14px}
.dbh-safe .mono,.dbh-snip .mono{font-family:ui-monospace,Consolas,monospace;font-size:11.5px}
.dbh-snip{padding:12px 16px;border-top:1px solid var(--line)}
.dbh-sniphd{font-size:12px;color:var(--muted);margin-bottom:6px}
.dbh-snip pre{background:#0f172a;color:#e5e7eb;border-radius:10px;padding:11px 13px;font-size:12px;overflow-x:auto;margin:0;font-family:ui-monospace,Consolas,monospace}
.dbh-applied{display:inline-flex;align-items:center;gap:8px}
.dbh-okpill{color:var(--good);font-weight:700;font-size:12px}
.dbh-undo{border-color:var(--line)!important;font-size:11px;padding:4px 9px}
#dbhProc td.st{color:var(--muted);font-size:11.5px}
#dbhProc td.qy{max-width:460px;overflow:hidden;text-overflow:ellipsis;font-family:ui-monospace,Consolas,monospace;font-size:11.5px}
.dbh-kill{border-color:#f3c4c4!important;color:#b91c1c;background:var(--dang-bg);font-size:11px;padding:4px 9px}
.live.stale{color:var(--muted)}.live.stale i{background:var(--muted);animation:none}
</style>
<script>
(function(){
  if (window.__dbhInit) return; window.__dbhInit = 1;
  var CSRF = <?= json_encode(smpro_csrf_generate('dbh_action'), JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE) ?>;
  var live=document.getElementById('dbhLive'), timer=null, paused=false, holdUntil=0;
  function $(id){return document.getElementById(id);}
  function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
  function dur(s){s=+s||0;if(s<60)return s+'s';var m=(s/60)|0;if(m<60)return m+'m'+(s%60)+'s';var h=(m/60)|0;return h+'h'+(m%60)+'m';}
  function timeCls(t){t=+t||0;return t>=60?'red':t>=15?'orange':'green';}
  function post(p){var b=new URLSearchParams();b.set('smpro_csrf',CSRF);for(var kk in p)b.set(kk,p[kk]);
    return fetch('index.cgi?page=database-health',{method:'POST',cache:'no-store',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:b.toString()}).then(function(r){return r.json();});}
  /* after an action, stop auto-refresh briefly so the ✅/Undo control is not wiped away */
  function hold(ms){holdUntil=Date.now()+(ms||25000);}

  function renderProc(d){
    if(d.db_ok===false){$('dbhProcBody').innerHTML='<tr><td colspan="7" style="padding:14px;color:var(--muted)">'+esc(d.msg||'Database not reachable.')+'</td></tr>';return;}
    $('dbhActive').textContent=(d.active!=null?d.active:'—');
    $('dbhLongest').textContent=(d.longest?dur(d.longest):'—');
    var rows=(d.proc||[]).filter(function(r){return (r.command||'').toLowerCase()!=='sleep';});
    if(!rows.length){$('dbhProcBody').innerHTML='<tr><td colspan="7" style="padding:14px;color:var(--good)">✓ Nothing but idle connections — no active queries right now.</td></tr>';return;}
    $('dbhProcBody').innerHTML=rows.map(function(r){
      var sys=['system user','event_scheduler','unauthenticated user',''].indexOf((r.user||'').toLowerCase())>=0;
      var canKill=!sys && (r.info||'')!=='';
      return '<tr><td class="num">'+r.id+'</td><td>'+esc(r.user)+'</td><td>'+esc(r.db||'—')+'</td>'
        +'<td class="num"><span class="b '+timeCls(r.time)+'">'+dur(r.time)+'</span></td>'
        +'<td>'+esc(r.command)+(r.state?'<div class="st">'+esc(r.state)+'</div>':'')+'</td>'
        +'<td class="qy" title="'+esc(r.info)+'">'+esc(r.info||'—')+'</td>'
        +'<td>'+(canKill?'<button class="tp-btn dbh-kill" type="button" data-id="'+r.id+'">⚡ Kill</button>':'')+'</td></tr>';
    }).join('');
  }
  function renderFull(d){
    if(!d.html)return;
    if(Date.now()<holdUntil)return;                 // an action is showing its result — don't clobber it
    $('dbhKpis').innerHTML=d.html.kpis;
    $('dbhCfg').innerHTML=d.html.config;
    $('dbhFindings').innerHTML=d.html.findings;
    $('dbhRec').innerHTML=d.html.rec;
    $('dbhFN').textContent=(d.fcount!=null?d.fcount:'');
    $('dbhRecN').textContent=(d.rec_count!=null?d.rec_count:'');
    if(d.score!=null)$('dbhScore').textContent=d.score;
    if(d.verdict)$('dbhVerdictTx').textContent=d.verdict;
    if(d.counts)$('dbhCounts').textContent=((d.counts.high||0)+(d.counts.critical||0))+' high · '+(d.counts.medium||0)+' med · '+(d.counts.low||0)+' low';
    if(d.verdict_cls){var v=$('dbhVerdict');v.className='dbh-verdict '+d.verdict_cls;}
  }
  function tick(){
    if(paused||document.hidden)return;
    fetch('index.cgi?page=database-health&format=json&metric=dbhealth&full=1',{cache:'no-store'})
      .then(function(r){return r.json();})
      .then(function(j){ if(!j||!j.ok)return; renderProc(j); renderFull(j);
        var c=$('dbhClock'); if(c&&j.ts)c.textContent=j.ts; if(live)live.classList.remove('stale'); })
      .catch(function(){ if(live)live.classList.add('stale'); });
  }
  function schedule(){ if(timer)clearInterval(timer); timer=setInterval(tick, +$('dbhInt').value||5000); }

  /* ---- delegated actions: the content is re-rendered on every refresh, so bind once on the document ---- */
  function swapForUndo(btn, j, fallbackWhich, label){
    var wrap=document.createElement('span'); wrap.className='dbh-applied';
    wrap.innerHTML='<span class="dbh-okpill">✅ applied'+(j.from&&j.to?(' · '+esc(j.from)+' → '+esc(j.to)):'')+'</span> <button class="tp-btn dbh-undo" type="button" data-which="'+esc(j.undo||fallbackWhich)+'">↩ Undo</button>';
    btn.replaceWith(wrap);
  }
  document.addEventListener('click', function(e){
    var b;
    if ((b=e.target.closest('.dbh-recapply'))) {
      var key=b.getAttribute('data-key'), orig=b.innerHTML;
      if(!confirm('Apply the recommended value for '+key+' now?\n\nIt is applied live with SET GLOBAL — no restart, no data touched, nothing to back up. You can Undo it right after.\n\nContinue?'))return;
      b.disabled=true;b.innerHTML='⏳';hold(60000);
      post({dbh_action:'rec',key:key}).then(function(j){
        if(j&&j.ok){alert(j.msg||'Applied.');swapForUndo(b,j,'rec:'+key);}
        else{b.innerHTML=orig;b.disabled=false;hold(0);alert('⚠ '+((j&&j.msg)||'Could not apply.'));}
      }).catch(function(){b.innerHTML=orig;b.disabled=false;hold(0);alert('⚠ Network error.');});
      return;
    }
    if ((b=e.target.closest('.dbh-fix'))) {
      var fix=b.getAttribute('data-fix'), o2=b.innerHTML;
      if(!confirm('Apply this fix now?\n\nIt is a LIVE MySQL tuning change (SET GLOBAL): immediate, touches NO data, deletes nothing — nothing to back up. You can Undo it right after.\n\nContinue?'))return;
      b.disabled=true;b.innerHTML='⏳';hold(60000);
      post({dbh_action:'fix',fix:fix}).then(function(j){
        if(j&&j.ok){alert(j.msg||'Applied.');swapForUndo(b,j,fix);}
        else{b.innerHTML=o2;b.disabled=false;hold(0);alert('⚠ '+((j&&j.msg)||'Could not apply.'));}
      }).catch(function(){b.innerHTML=o2;b.disabled=false;hold(0);alert('⚠ Network error.');});
      return;
    }
    if ((b=e.target.closest('.dbh-undo'))) {
      var which=b.getAttribute('data-which');
      if(!confirm('Undo this change — restore the previous value?'))return;
      b.disabled=true;b.textContent='⏳';hold(30000);
      post({dbh_action:'revert',which:which}).then(function(r){
        alert((r&&r.msg)||'Reverted.');
        if(r&&r.ok){b.textContent='↩ undone';hold(0);setTimeout(tick,600);}else{b.textContent='↩ Undo';b.disabled=false;}
      }).catch(function(){b.textContent='↩ Undo';b.disabled=false;alert('⚠ Network error.');});
      return;
    }
    if ((b=e.target.closest('.dbh-kill'))) {
      var id=b.getAttribute('data-id');
      if(!confirm('Kill the running query on thread '+id+'?\n\nThis sends KILL QUERY — it aborts the current statement but keeps the connection open. Use it only for a query that is clearly stuck.'))return;
      b.disabled=true;b.textContent='⏳';
      post({dbh_action:'kill',id:id}).then(function(j){
        if(j&&j.ok){b.textContent='✅';setTimeout(tick,600);}
        else{b.disabled=false;b.textContent='⚡ Kill';alert('⚠ '+((j&&j.msg)||'Could not kill.'));}
      }).catch(function(){b.disabled=false;b.textContent='⚡ Kill';alert('⚠ Network error.');});
    }
  });

  $('dbhInt').addEventListener('change',schedule);
  $('dbhPause').addEventListener('click',function(){paused=!paused;this.textContent=paused?'Resume':'Pause';
    if(live)live.classList.toggle('stale',paused); if(!paused)tick();});
  document.addEventListener('visibilitychange',function(){if(!document.hidden)tick();});
  tick(); schedule();
})();
</script>
<?php
smpro_layout_footer();
