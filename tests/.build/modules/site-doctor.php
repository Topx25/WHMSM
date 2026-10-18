<?php
/**
 * modules/site-doctor.php — Site Doctor: diagnose WHY a site is failing (500/blank/down) and
 * apply a SAFE, REVERSIBLE fix (incl. AI-driven). Engine: includes/investigate.php.
 * Every fix is backup-first (rename, never delete), path-whitelisted to the account docroot,
 * hardening-aware (clears chattr +i, re-locks after), and one-click undoable.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

$reqMethod = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));

/* ---- diagnose (GET JSON) ---- */
if (($_GET['sd_investigate'] ?? '') === '1') {
    header('Content-Type: application/json');
    $r = smpro_inv_run((string)($_GET['target'] ?? ''));
    smpro_audit('sitedoctor_investigate', ['target'=>(string)($_GET['target'] ?? ''),'ok'=>!empty($r['ok'])]);
    echo json_encode($r, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE); exit;
}
/* ---- fix / undo / ai-fix / ai-verdict (POST + CSRF + root) ---- */
if ($reqMethod === 'POST' && in_array(($_POST['sd_action'] ?? ''), ['fix','undo','fixit','ai_fix','ai'], true)) {
    smpro_require_valid_csrf('sd_action'); smpro_require_root();
    header('Content-Type: application/json');
    $act = $_POST['sd_action'];
    if ($act === 'fix')      { echo json_encode(smpro_inv_fix((string)($_POST['act'] ?? ''), (string)($_POST['target'] ?? ''), (string)($_POST['path'] ?? '')), JSON_UNESCAPED_SLASHES); exit; }
    if ($act === 'undo')     { echo json_encode(smpro_inv_undo((string)($_POST['id'] ?? '')), JSON_UNESCAPED_SLASHES); exit; }
    if ($act === 'fixit')    { echo json_encode(smpro_inv_fixit((string)($_POST['target'] ?? '')), JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE); exit; }   // deterministic
    if ($act === 'ai_fix')   { echo json_encode(smpro_inv_ai_plan((string)($_POST['target'] ?? '')), JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE); exit; }  // AI takes over + executes
    if ($act === 'ai') {
        if (!function_exists('smpro_ai_available') || !smpro_ai_available()) { echo json_encode(['ok'=>false,'error'=>'No AI provider configured.']); exit; }
        $res = smpro_inv_run((string)($_POST['target'] ?? '')); if (empty($res['ok'])) { echo json_encode(['ok'=>false,'error'=>$res['msg'] ?? 'resolve failed']); exit; }
        $ev = "Site: " . $res['domain'] . " (account " . $res['user'] . ", PHP " . ($res['phpver'] ?: '?') . ", HTTP " . $res['http']['code'] . ")\n";
        foreach ($res['fatals'] as $f) $ev .= "FATAL: " . $f['msg'] . "\n";
        if (!empty($res['recent'])) { $ev .= "Recently changed:\n"; foreach (array_slice($res['recent'], 0, 10) as $c) $ev .= "  " . $c['time'] . " " . $c['path'] . "\n"; }
        $sys = "You are a senior cPanel/WHM hosting support engineer. Given diagnostic evidence for a failing website, state the SINGLE most likely root cause in one sentence, then numbered concrete fix steps (safest first). Be specific and short.";
        $r = smpro_ai_chat($sys, function_exists('smpro_ai_redact') ? smpro_ai_redact($ev) : $ev, ['max_tokens'=>600,'context'=>'sitedoctor']);
        echo json_encode(['ok'=>!empty($r['ok']),'text'=>$r['text'] ?? '','error'=>$r['error'] ?? '','provider'=>$r['provider'] ?? ''], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE); exit;
    }
}

$csrf = smpro_csrf_generate('sd_action');
$aiReady = function_exists('smpro_ai_available') && smpro_ai_available();
$qtarget = smpro_h($_GET['target'] ?? '');
smpro_audit('sitedoctor_view', []);
smpro_layout_header('Site Doctor');
?>
<script>var SD_CSRF=<?= json_encode($csrf) ?>;</script>
<div class="svc-kicker">Diagnose &amp; fix</div>
<h1 class="h" style="margin:2px 0 4px">&#129658; Site Doctor</h1>
<p class="sub" data-i18n>Find out why a site is failing — 500 / blank page / errors — and fix it safely. Enter a domain or cPanel account; every fix is reversible.</p>

<div class="sd-search">
  <form id="sdForm" onsubmit="return false">
    <input type="text" id="sdTarget" class="sd-in" value="<?= $qtarget ?>" placeholder="domain.com  or  cPanel account…" autocomplete="off" autofocus>
    <button class="sd-go" id="sdGo" type="submit">&#128270; Diagnose</button>
  </form>
</div>
<div id="sdOut" class="sd-out"></div>

<style>
.svc-kicker{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--brand);font-weight:800}
.sd-search{margin:14px 0 6px}.sd-search form{display:flex;gap:8px;max-width:560px}
.sd-in{flex:1;border:1px solid var(--line);border-radius:11px;padding:12px 15px;font-size:15px}
.sd-go{border:none;background:var(--brand);color:#fff;border-radius:11px;padding:12px 20px;font-size:14px;font-weight:700;cursor:pointer;white-space:nowrap}
.sd-go:disabled{opacity:.6}
.sd-out{margin-top:16px;width:100%}
.sd-card{background:var(--card);border:1px solid var(--line);border-radius:16px;overflow:hidden;box-shadow:0 8px 28px rgba(15,23,42,.06)}
.sd-hero{display:flex;align-items:center;gap:16px;padding:18px 20px;border-bottom:1px solid var(--line)}
.sd-http{width:72px;height:72px;border-radius:16px;display:flex;flex-direction:column;align-items:center;justify-content:center;font-size:22px;font-weight:800;flex-shrink:0;color:#fff;line-height:1}
.sd-http small{font-size:9px;font-weight:600;opacity:.85;margin-top:2px;text-transform:uppercase}
.sd-http.ok{background:var(--good)}.sd-http.bad{background:var(--dang)}.sd-http.warn{background:#d97706}.sd-http.na{background:#94a3b8}
.sd-hmeta{flex:1;min-width:0}.sd-dom{font-size:20px;font-weight:800;word-break:break-all}.sd-facts{color:var(--muted);font-size:13px;margin-top:4px}
.sd-facts .chip{display:inline-block;background:#f1f5f9;border-radius:8px;padding:2px 9px;margin:2px 4px 0 0;font-size:12px;color:#475569}
.sd-cause{padding:16px 20px;display:flex;gap:14px;align-items:flex-start}
.sd-cause.bad{background:var(--dang-bg)}.sd-cause.good{background:var(--good-bg)}
.sd-cause .ci{font-size:24px;line-height:1}.sd-cause .ct{flex:1}.sd-cause b{display:block;margin-bottom:4px;font-size:15px}
/* clean diagnosis card (DNS / redirect-loop) */
.sd-card2{border:1px solid var(--line);border-left:4px solid var(--dang);border-radius:12px;overflow:hidden;margin:2px 0}
.sd-card2.bad{border-left-color:var(--dang)}
.sd-card2 .c2h{display:flex;gap:13px;align-items:flex-start;padding:15px 18px;background:var(--dang-bg)}
.sd-card2 .c2ic{font-size:26px;line-height:1;flex-shrink:0}
.sd-card2 .c2t{flex:1;min-width:0}.sd-card2 .c2t b{display:block;font-size:15px;color:#1d2327;margin-bottom:3px}
.sd-card2 .c2sub{font-size:12.5px;color:var(--muted);line-height:1.5}
.sd-card2 .c2body{padding:14px 18px;background:var(--card)}
.sd-card2 .c2plan-t{font-size:12px;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:.03em;margin-bottom:8px}
.sd-plan{margin:0;padding:0;list-style:none;counter-reset:sp}
.sd-plan li{counter-increment:sp;position:relative;padding:7px 0 7px 32px;font-size:13.5px;color:var(--ink);border-bottom:1px dashed var(--line)}
.sd-plan li:last-child{border-bottom:0}
.sd-plan li::before{content:counter(sp);position:absolute;left:0;top:6px;width:21px;height:21px;border-radius:50%;background:var(--brand);color:#fff;font-size:11px;font-weight:700;display:flex;align-items:center;justify-content:center}
.sd-plan li b{font-weight:700}.sd-plan .sd-plan-w{display:block;font-size:11.5px;color:var(--muted);margin-top:1px}
.sd-card2 .c2note{margin-top:10px;font-size:12px;color:var(--muted);background:var(--bg);border-radius:8px;padding:8px 11px}
.sd-card2 code{background:var(--bg);padding:1px 6px;border-radius:5px;font-size:12px}
.sd-fixrow{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}
.sd-fixbtn{border:none;border-radius:10px;padding:10px 16px;font-size:13px;font-weight:700;cursor:pointer;color:#fff}
.sd-fixbtn.go{background:var(--good)}.sd-fixbtn.ai{background:var(--brand)}.sd-fixbtn:disabled{opacity:.6}
.sd-sec{padding:15px 20px;border-top:1px solid var(--line)}.sd-sec h4{margin:0;font-size:13px;display:flex;align-items:center;gap:7px;cursor:pointer;user-select:none}
.sd-sec h4::before{content:"\25B8";font-size:11px;color:var(--muted);transition:transform .15s;display:inline-block}
.sd-sec:not(.collapsed) h4{margin-bottom:9px}
.sd-sec:not(.collapsed) h4::before{transform:rotate(90deg)}
.sd-sec.collapsed > :not(h4){display:none}
.sd-scroll{max-height:240px;overflow:auto;border:1px solid var(--line);border-radius:10px}
.sd-tbl{width:100%;border-collapse:collapse;font-size:12px}.sd-tbl th,.sd-tbl td{padding:8px 11px;text-align:left;border-bottom:1px solid var(--line)}
.sd-tbl th{font-size:10.5px;text-transform:uppercase;color:var(--muted);background:#fafbfe;position:sticky;top:0}
.sd-tbl tr:last-child td{border-bottom:none}
.sd-mono{font-family:ui-monospace,Consolas,monospace;font-size:11px;word-break:break-all}
.sd-pre{background:#0f172a;color:#e2e8f0;padding:11px;border-radius:9px;overflow:auto;max-height:180px;font-size:11px;margin:0}
.sd-code{background:#f7f9fc;border:1px solid var(--line);border-radius:9px;padding:11px 13px;font-family:ui-monospace,Consolas,monospace;font-size:11.5px;line-height:1.6;color:#334155;max-height:200px;overflow:auto;white-space:nowrap}
.sd-disk{max-width:420px}
.sd-bar{height:10px;border-radius:6px;background:#eef1f6;overflow:hidden}
.sd-fill{display:block;height:100%;border-radius:6px;background:var(--good)}.sd-fill.warn{background:#d97706}.sd-fill.bad{background:var(--dang)}
.sd-diskmeta{font-size:13px;color:var(--muted);margin-top:7px}.sd-diskmeta b{color:var(--ink);font-size:15px}
.sd-foot{display:flex;gap:10px;align-items:center;flex-wrap:wrap;padding:14px 20px;border-top:1px solid var(--line)}
.sd-ghost{border:1px solid var(--line);background:#fff;border-radius:9px;padding:9px 14px;font-size:12.5px;cursor:pointer;font-weight:600;color:var(--ink)}
.sd-ghost:hover{border-color:var(--brand);color:var(--brand)}
.sd-badge{display:inline-block;font-size:11px;font-weight:700;padding:2px 9px;border-radius:20px;background:#f1f5f9;color:#475569}
.sd-badge.crit{background:var(--dang-bg);color:#b91c1c}
.sd-undo{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:6px 0;border-bottom:1px solid var(--line);font-size:12.5px}.sd-undo:last-child{border-bottom:none}
.sd-aiout{padding:0 20px 16px}
.sd-empty{padding:26px;text-align:center;color:var(--muted)}
.sd-scan{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));background:var(--card);border-bottom:1px solid var(--line)}
.sd-fact{padding:11px 16px;border-top:1px solid var(--line);border-right:1px solid var(--line)}
.sd-fact.wide{grid-column:1/-1;border-right:0}
.sd-fact .k{display:block;font-size:10.5px;text-transform:uppercase;letter-spacing:.03em;color:var(--muted);margin-bottom:3px}
.sd-fact b{font-size:13.5px}
.sd-prog{padding:14px 16px;background:#f7f9fc;border-radius:11px;margin-top:6px}
.sd-progtop{display:flex;justify-content:space-between;align-items:center;font-size:13px;margin-bottom:8px}
.sd-progpct{font-weight:800;color:var(--brand)}
.sd-progbar{height:8px;border-radius:5px;background:#e6eaf1;overflow:hidden;margin-bottom:12px}
.sd-progbar span{display:block;height:100%;width:0;background:var(--brand);border-radius:5px;transition:width .4s ease}
.sd-steps{display:flex;flex-direction:column;gap:6px}
.sd-step{display:flex;align-items:flex-start;gap:9px;font-size:12.5px;color:var(--ink)}
.sd-step .sd-stepic{flex-shrink:0;width:18px;text-align:center}
.sd-step.ok .sd-stepic{color:var(--good)}.sd-step.bad .sd-stepic{color:var(--dang)}.sd-step.run .sd-stepic{color:var(--brand)}
.sd-verify{margin-top:12px;padding:9px 12px;border-radius:9px;font-weight:700;font-size:13px}
.sd-verify.ok{background:var(--good-bg);color:var(--good)}.sd-verify.bad{background:var(--warn-bg);color:#92702a}
</style>
<script>
(function(){
  var form=document.getElementById('sdForm'),inp=document.getElementById('sdTarget'),out=document.getElementById('sdOut');
  function esc(s){return (s==null?'':String(s)).replace(/[&<>"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
  function httpCls(c){c=+c;return !c?'na':(c>=500?'bad':(c>=400?'warn':'ok'));}
  function post(act,extra){var fd=new URLSearchParams();fd.set('sd_action',act);fd.set('smpro_csrf',SD_CSRF);Object.keys(extra||{}).forEach(function(k){fd.set(k,extra[k]);});
    return fetch('index.cgi?page=site-doctor',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'}).then(function(r){return r.json();});}
  // professional progress panel: animates planned steps, then fills real results from the response
  function progress(title,plan){
    var ao=document.getElementById('sdAiOut');
    ao.innerHTML='<div class="sd-prog"><div class="sd-progtop"><b>'+title+'</b><span class="sd-progpct" id="sdPct">0%</span></div>'
      +'<div class="sd-progbar"><span id="sdFill"></span></div><div class="sd-steps" id="sdSteps">'
      +plan.map(function(s,i){return '<div class="sd-step" id="sdStp'+i+'"><span class="sd-stepic">○</span><span>'+esc(s)+'</span></div>';}).join('')+'</div></div>';
    ao.scrollIntoView({behavior:'smooth',block:'nearest'});
    var i=0,fill=document.getElementById('sdFill'),pct=document.getElementById('sdPct');
    var tm=setInterval(function(){ if(i<plan.length){var st=document.getElementById('sdStp'+i);if(st){st.className='sd-step run';st.querySelector('.sd-stepic').textContent='⏳';} i++; var p=Math.min(90,Math.round(i/plan.length*90)); fill.style.width=p+'%'; pct.textContent=p+'%'; } else clearInterval(tm); },550);
    return {done:function(steps,okfix,hb,ha,extra){ clearInterval(tm); fill.style.width='100%'; pct.textContent='100%';
      var box=document.getElementById('sdSteps');
      box.innerHTML=(steps&&steps.length?steps:plan).map(function(s){var ok=(''+s).indexOf('✓')===0,bad=(''+s).indexOf('✗')===0;
        return '<div class="sd-step '+(ok?'ok':(bad?'bad':'ok'))+'"><span class="sd-stepic">'+(bad?'✗':'✓')+'</span><span>'+esc((''+s).replace(/^[✓✗]\s*/,''))+'</span></div>';}).join('');
      var p=document.querySelector('.sd-prog');
      if(typeof ha!=='undefined')p.insertAdjacentHTML('beforeend','<div class="sd-verify '+(okfix?'ok':'bad')+'">'+(okfix?'✅ Verified by curl — site is UP':'⚠ Verified by curl — still failing')+' (HTTP '+esc(hb)+' → '+esc(ha)+')</div>');
      if(extra)p.insertAdjacentHTML('beforeend',extra);
    }};
  }
  function render(j,t){
    var h='<div class="sd-card"><div class="sd-hero"><div class="sd-http '+httpCls(j.http.code)+'">'+(j.http.code||'—')+'<small>HTTP</small></div>'
      +'<div class="sd-hmeta"><div class="sd-dom">'+esc(j.domain||j.user)+'</div><div class="sd-facts">'
      +'<span class="chip">account '+esc(j.user)+'</span>'+(j.phpver?'<span class="chip">PHP '+esc(j.phpver)+'</span>':'')
      +(j.detect&&j.detect.platform?'<span class="chip">'+esc(j.detect.platform)+(j.detect.multisite?' multisite':'')+'</span>':'')
      +(j.detect&&j.detect.multilingual?'<span class="chip">🌐 '+esc(j.detect.multilingual)+'</span>':'')
      +(j.detect&&j.detect.installs>1?'<span class="chip">'+j.detect.installs+' installs</span>':'')
      +'<span class="chip">'+esc(j.docroot||'')+'</span></div></div></div>';
    // ---- Scan summary (always visible) ----
    var dt=j.detect||{};
    var logsrc=[]; if(j.logtail&&j.logtail.length)logsrc.push('site error_log'); if(j.serverlogs&&j.serverlogs.length)logsrc.push(j.serverlogs.length+' server-log lines');
    var ml=dt.multilingual?dt.multilingual:'none detected';
    window.__sdFixes=j.fixes||[];
    var wpv=j.wp||{},isWP=(dt.platform==='WordPress'),domTip=(dt.sites&&dt.sites.length)?dt.sites.join('\n'):'';
    h+='<div class="sd-scan">'
      +'<div class="sd-fact"><span class="k">Platform</span><b>'+esc(dt.platform||'unknown')+(dt.version?' '+esc(dt.version):'')+(dt.multisite?' · multisite':'')+(dt.debug?' · <span style="color:#d97706">DEBUG on</span>':'')+'</b></div>'
      +'<div class="sd-fact" title="'+esc(domTip)+'"><span class="k">Account topology</span><b>'+(isWP?(dt.installs||0)+' WP install(s) · ':'')+((dt.sites&&dt.sites.length)||1)+' domain(s)</b><div style="font-size:11px;color:var(--muted)">hover for list</div></div>'
      +'<div class="sd-fact"><span class="k">PHP / Database</span><b>'+esc(j.phpver||'?')+(wpv.db&&wpv.db.version?' · MySQL '+esc((''+wpv.db.version).split("-")[0]):'')+'</b></div>';
    if(isWP){
      h+='<div class="sd-fact"><span class="k">Active theme</span><b>'+esc(wpv.theme||'—')+'</b></div>'
        +'<div class="sd-fact"><span class="k">Plugins</span><b>'+(dt.plugins||0)+' installed</b></div>'
        +'<div class="sd-fact"><span class="k">Multilingual</span><b>'+esc(ml)+'</b></div>';
    } else if(dt.env){
      var ev=dt.env,evp=function(k,lbl){return (k in ev)?'<div class="sd-fact"><span class="k">'+lbl+'</span><b'+((''+ev[k]).indexOf('MISSING')>=0?' style="color:var(--dang)"':'')+'>'+esc(ev[k])+'</b></div>':'';};
      h+=evp('APP_ENV','App env')+evp('APP_DEBUG','Debug')+evp('DB_CONNECTION','DB driver')+evp('APP_KEY','App key')+evp('vendor','vendor/')+evp('(.env)','.env');
    }
    h+='<div class="sd-fact"><span class="k">Logs read</span><b>'+(logsrc.length?esc(logsrc.join(' · ')):'—')+'</b></div>';
    // STEP 0 — domain / DNS validity (shown first: is the domain even pointed at this server?)
    var dns=j.dns||null;
    if(dns){var dc=(dns.state==='ok')?'var(--good)':(dns.state==='proxied'?'#d97706':'var(--dang)');
      var dlabel=(dns.state==='ok'?'✓ points here':(dns.state==='proxied'?'via Cloudflare/CDN':(dns.state==='nxdomain'?'✗ does not resolve':'✗ points elsewhere')));
      h+='<div class="sd-fact wide" title="'+esc(dns.note||'')+'"><span class="k">Domain &amp; DNS (step 1)</span><b style="color:'+dc+'">'+esc((dns.ips&&dns.ips.length?dns.ips.join(', '):'no A record'))+' — '+esc(dlabel)+'</b><div style="font-size:11px;color:var(--muted)">'+esc(dns.note||'')+'</div></div>';}
    // HTTP + redirect chain
    var ht=j.http||{};
    if(ht.first){var rtxt='HTTP '+ht.first; if(ht.hops>0)rtxt+=' → '+(ht.loop?'redirect LOOP ('+ht.hops+'+ hops)':(ht.final+' after '+ht.hops+' redirect(s)'));
      h+='<div class="sd-fact wide"><span class="k">HTTP / redirects</span><b style="color:'+(ht.loop?'var(--dang)':(ht.final>=200&&ht.final<400?'var(--good)':'var(--dang)'))+'">'+esc(rtxt)+'</b>'+(ht.final_url&&ht.final_url!==ht.url?'<div style="font-size:11px;color:var(--muted)">ends at: '+esc(ht.final_url)+'</div>':'')+'</div>';}
    h+=(dt.sites&&dt.sites.length?'<div class="sd-fact wide"><span class="k">Related domains ('+dt.sites.length+')</span><b style="font-weight:400;font-size:12.5px">'+dt.sites.map(esc).join(' · ')+'</b></div>':'')
      +(j.selfhealers&&Object.keys(j.selfhealers).length?'<div class="sd-fact wide"><span class="k">⚠ Self-healer detected</span><b style="color:var(--dang)">'+Object.keys(j.selfhealers).map(function(p){return esc(p.split("/").pop());}).join(', ')+' — reverts fixes; disabled first</b></div>':'')
      +'</div>';
    var lc=j.live_cause||null, fixes=j.fixes||[], hasFix=fixes.length>0;
    var stale=(j.fatals&&j.fatals[0]&&!j.fatals[0].target_exists&&j.fatals[0].fix_target)?j.fatals[0]:null;
    var autobtn='<button class="sd-fixbtn go" data-fixit>&#128295; Fix it</button> <button class="sd-fixbtn ai" data-aifix>&#129302; AI Fix</button>';
    function planSteps(pre,post){var li=(pre||[]).concat(fixes.map(function(f){return esc(f.label);})).concat(post||[]);return '<ol class="sd-plan">'+li.map(function(s){return '<li>'+s+'</li>';}).join('')+'</ol>';}
    if(j.status==='dns'){
      h+='<div class="sd-card2 bad"><div class="c2h"><span class="c2ic">&#127760;</span><div class="c2t"><b>Domain is not pointed at this server</b><span class="c2sub">'+esc((dns&&dns.ips&&dns.ips.length?dns.ips.join(', '):'no DNS record')+' (server '+((dns&&dns.server_ip)||'?')+')')+'</span></div></div>'
        +'<div class="c2body"><ol class="sd-plan"><li>Set the <b>A record</b> for <code>'+esc(dns?dns.domain:'')+'</code> → <code>'+esc((dns&&dns.server_ip)||'this server')+'</code></li>'
        +'<li>Wait for DNS to propagate</li><li><b>Re-scan</b></li></ol></div></div>';
    } else if(j.status==='redirect_loop'){
      h+='<div class="sd-card2 bad"><div class="c2h"><span class="c2ic">&#128257;</span><div class="c2t"><b>Redirect loop (HTTP '+(ht.first||301)+')</b><span class="c2sub">Too many redirects — the site bounces between http/https.</span></div></div>'
        +'<div class="c2body">'+(hasFix
          ? '<div class="c2plan-t">Fix it (reversible, stops at first that works):</div>'+planSteps(['Unlock locked files'],['Verify'])
          : '<div class="c2note">Use <b>AI Fix</b> — it inspects Site URL, .htaccess &amp; SSL plugin.</div>')
        +'<div class="sd-fixrow">'+autobtn+'</div></div></div>';
    } else if(j.status==='up'&&!hasFix){
      h+='<div class="sd-cause good"><span class="ci">&#10003;</span><div class="ct"><b>Site is UP (HTTP '+j.http.code+')</b>No active error with a fixable cause.'
        +(stale?' A previously-broken '+esc(stale.component||'component')+' was already disabled.':'')+'</div></div>';
    } else if(hasFix){
      var f0=fixes[0];
      h+='<div class="sd-cause '+(j.status==='up'?'good':'bad')+'"><span class="ci">'+(j.status==='up'?'&#9888;':'&#9888;')+'</span><div class="ct">'
        +'<b>'+(j.status==='up'?'Issue found (site still responding)':'Likely cause found')+'</b>'
        +esc((lc&&lc.kind)||(f0.why)||'')+(lc&&lc.component?' <span class="sd-badge crit">'+esc(lc.component)+'</span>':'')
        +'<div style="margin-top:5px;color:var(--muted)">Recommended fix: <b>'+esc(f0.label)+'</b> (reversible)</div>'
        +'<div class="sd-fixrow">'+autobtn+'</div></div></div>';
    } else {
      var tf=(j.fatals&&j.fatals[0])||null;
      h+='<div class="sd-cause bad"><span class="ci">&#9888;</span><div class="ct"><b>Site is failing'+(j.http.code?' (HTTP '+j.http.code+')':'')+'</b>'
        +(tf?('Latest error: '+esc((tf.msg||'').slice(0,200))+(tf.kind?' <span style="color:var(--muted)">('+esc(tf.kind)+')</span>':'')):(stale?'A previously-broken '+esc(stale.component||'component')+' was already disabled, but it is still failing — the cause is elsewhere.':'No PHP fatal in the logs — likely a config/DB/server issue (see Recent log lines below).'))
        +'<div style="margin-top:6px;color:var(--muted)">Click below — it applies a fix if possible, otherwise gives a precise AI diagnosis from these errors.</div><div class="sd-fixrow">'+autobtn+'</div></div></div>';
    }
    if(j.components&&j.components.length){h+='<div class="sd-sec"><h4>&#129513; Theme &amp; plugin health</h4><div class="sd-scroll"><table class="sd-tbl"><thead><tr><th>Type</th><th>Name</th><th>Severity</th><th>Errors</th><th></th></tr></thead><tbody>';
      j.components.forEach(function(c){var active=(j.wp&&j.wp.theme&&c.type==="theme"&&c.name===j.wp.theme);
        h+='<tr><td>'+esc(c.type)+'</td><td><b>'+esc(c.name)+'</b>'+(active?' <span class="sd-badge" style="background:var(--brand-bg);color:var(--brand)">active</span>':'')+'</td>'
          +'<td><span class="sd-badge'+(c.sev==="critical"?" crit":"")+'"'+(c.sev==="warning"?' style="background:var(--warn-bg);color:#92702a"':'')+'>'+esc(c.sev)+'</span></td><td>'+c.count+'</td>'
          +'<td>'+(c.exists&&c.sev==="critical"?'<button class="sd-ghost" data-fix data-act="'+(c.type==="theme"?"disable_theme":"disable_plugin")+'" data-path="'+esc(c.path)+'">Disable</button>':'')+'</td></tr>';});
      h+='</tbody></table></div><div style="font-size:11px;color:var(--muted);margin-top:6px">Critical = PHP fatal (breaks the site) · Warning/Notice = noisy not fatal. Disable offered for critical only.</div></div>';}
    if(j.fatals&&j.fatals.length){h+='<div class="sd-sec collapsed"><h4>&#128308; PHP fatal / parse errors</h4><div class="sd-scroll"><table class="sd-tbl"><thead><tr><th>Time</th><th>Error</th><th>File</th></tr></thead><tbody>';
      j.fatals.forEach(function(f){var res=f.fix_target&&!f.target_exists;h+='<tr'+(res?' style="opacity:.6"':'')+'><td>'+esc(f.ts?new Date(f.ts*1000).toLocaleString():'')+'</td><td>'+(res?'<span class="sd-badge" style="background:var(--good-bg);color:var(--good)">resolved</span> ':'')+esc((f.msg||'').slice(0,240))+'</td><td class="sd-mono">'+esc(f.file||'')+'</td></tr>';});h+='</tbody></table></div></div>';}
    if(j.recent&&j.recent.length){h+='<div class="sd-sec collapsed"><h4>&#128221; Recently changed (48h)</h4><div class="sd-scroll"><table class="sd-tbl"><thead><tr><th>Modified</th><th>File</th></tr></thead><tbody>';
      j.recent.forEach(function(c){h+='<tr><td>'+esc(c.time)+'</td><td class="sd-mono">'+esc(c.path)+'</td></tr>';});h+='</tbody></table></div></div>';}
    if(j.wp){var w=j.wp;var dbok=w.db&&w.db.connected;h+='<div class="sd-sec collapsed"><h4>&#127760; WordPress / Database</h4><div class="sd-code">'
      +'DB: '+(dbok?'<span style="color:var(--good)">connected</span>':'<span style="color:var(--dang)">NOT CONNECTED'+(w.db&&w.db.error?' — '+esc(w.db.error):'')+'</span>')+'<br>'
      +'siteurl: '+esc(w.siteurl||'?')+'<br>home: '+esc(w.home||'?')+'<br>expected: '+esc(w.expected||'?')
      +(w.url_mismatch?'<br><span style="color:var(--dang)">&#9888; URL points to a path that does not exist on disk — regenerates the wrong .htaccess</span>':'')
      +'</div></div>';}
    if(j.hardened&&Object.keys(j.hardened).length){h+='<div class="sd-sec collapsed"><h4>&#128274; Hardened / locked files <span style="color:var(--muted);font-weight:400;font-size:11px">(block WordPress self-repair — un-hardened first by Fix)</span></h4><div class="sd-code">'+Object.keys(j.hardened).map(function(p){return esc(p)+' &mdash; '+esc(j.hardened[p]);}).join('<br>')+'</div></div>';}
    if(j.logtail&&j.logtail.length){h+='<div class="sd-sec collapsed"><h4>&#128203; Site error_log</h4><div class="sd-code">'+j.logtail.map(esc).join('<br>')+'</div></div>';}
    if(j.serverlogs&&j.serverlogs.length){h+='<div class="sd-sec collapsed"><h4>&#128421; Server logs (apache / litespeed / suexec / domlog / modsec)</h4><div class="sd-code">'+j.serverlogs.map(esc).join('<br>')+'</div></div>';}
    if(j.htaccess){h+='<div class="sd-sec collapsed"><h4>&#9881; .htaccess <span style="color:var(--muted);font-weight:400;font-size:11px">edited '+esc(j.htaccess.mtime)+'</span></h4>';
      if(j.htaccess.issues&&j.htaccess.issues.length)j.htaccess.issues.forEach(function(is){h+='<div style="background:var(--warn-bg);color:#92702a;border-radius:8px;padding:8px 11px;margin-bottom:8px;font-size:12.5px">&#9888; '+esc(is)+'</div>';});
      h+='<div class="sd-code">'+esc(j.htaccess.head).replace(/\n/g,'<br>')+'</div></div>';}
    if(j.disk){var d=j.disk,gb=function(mb){return mb>=1024?(mb/1024).toFixed(1)+' GB':mb+' MB';};
      var pc=Math.min(100,d.pct||0),pcls=pc>=90?'bad':(pc>=75?'warn':'ok');
      h+='<div class="sd-sec collapsed"><h4>&#128190; Disk usage</h4><div class="sd-disk">'
        +'<div class="sd-bar"><span class="sd-fill '+pcls+'" style="width:'+pc+'%"></span></div>'
        +'<div class="sd-diskmeta"><b>'+gb(d.used_mb)+'</b>'+(d.limit_mb?' of '+gb(d.limit_mb)+' ('+pc+'%)':' used')+' &middot; '+(d.inodes||0).toLocaleString()+' files</div>'
        +'</div></div>';}
    if(j.undo&&j.undo.length){h+='<div class="sd-sec collapsed"><h4>&#8635; Applied fixes (undo)</h4>';
      j.undo.forEach(function(u){h+='<div class="sd-undo"><span class="sd-mono">'+esc(u.action)+' · '+esc((u.from||"").split("/").pop())+(u.hardened?' <span class="sd-badge">was hardened</span>':'')+'</span><button class="sd-ghost" data-undo="'+esc(u.id)+'">Undo</button></div>';});h+='</div>';}
    h+='<div class="sd-foot"><button class="sd-ghost" data-ai>&#129302; AI verdict</button><button class="sd-ghost" data-rerun>&#8635; Re-scan</button></div><div class="sd-aiout" id="sdAiOut"></div></div>';
    out.innerHTML=h;
  }
  function run(t){ out.innerHTML='<div class="sd-card"><div class="sd-empty">&#128270; Diagnosing '+esc(t)+'… reading logs &amp; recent changes</div></div>';
    fetch('index.cgi?page=site-doctor&sd_investigate=1&target='+encodeURIComponent(t),{cache:'no-store'}).then(function(r){return r.json();}).then(function(j){
      if(!j||!j.ok){out.innerHTML='<div class="sd-card"><div class="sd-empty"><b style="color:var(--dang)">'+esc((j&&j.msg)||'Investigation failed')+'</b></div></div>';return;}
      render(j,t);
    }).catch(function(){out.innerHTML='<div class="sd-card"><div class="sd-empty"><b style="color:var(--dang)">Request failed.</b></div></div>';});}
  form.addEventListener('submit',function(){var t=(inp.value||'').trim();if(t){history.replaceState(0,'','index.cgi?page=site-doctor&target='+encodeURIComponent(t));run(t);}});
  out.addEventListener('click',function(e){
    var t=(inp.value||'').trim();
    var hd=e.target.closest('.sd-sec h4');   // collapse/expand info sections
    if(hd){var sec=hd.closest('.sd-sec');if(sec)sec.classList.toggle('collapsed');return;}
    var fx=e.target.closest('[data-fix]');
    if(fx){if(!confirm('Apply this fix on '+t+'?\n\nThe broken folder is renamed (disabled) — fully reversible via Undo. Hardening (if any) is handled automatically.'))return;
      fx.disabled=true;var ot=fx.innerHTML;fx.innerHTML='&#9203; Fixing…';
      post('fix',{act:fx.getAttribute('data-act'),target:t,path:fx.getAttribute('data-path')}).then(function(k){alert((k&&k.ok)?('✅ '+k.msg):('⚠ '+((k&&k.msg)||'fix failed')));run(t);}).catch(function(){fx.disabled=false;fx.innerHTML=ot;alert('Request failed.');});return;}
    var ft=e.target.closest('[data-fixit]');
    if(ft){if(!confirm('Fix '+t+' with the known scenario fixes?\n\nApplies the deterministic fixes in order, then verifies with curl. All reversible. If still failing, use AI Fix.'))return;
      ft.disabled=true;var ot=ft.innerHTML;ft.innerHTML='&#9203; Fixing…';
      var plan=(window.__sdFixes||[]).map(function(f){return f.label;}); if(!plan.length)plan=['Apply scenario fixes']; plan.push('Verify with curl');
      var pg=progress('🔧 Applying scenario fixes',plan);
      post('fixit',{target:t}).then(function(k){
        ft.disabled=false;ft.innerHTML=ot;
        pg.done((k&&k.steps)||[], k&&k.ok, k&&k.http_before, k&&k.http_after, (k&&k.escalate)?'<div style="margin-top:10px"><button class="sd-fixbtn ai" data-aifix>&#129302; Hand over to AI Fix</button></div>':'');
        if(k&&k.ok)setTimeout(function(){run(t);},1800);
      }).catch(function(){ft.disabled=false;ft.innerHTML=ot;pg.done(['✗ Request failed'],false);});return;}
    var af=e.target.closest('[data-aifix]');
    if(af){if(!confirm('Hand over to AI Fix for '+t+'?\n\nThe AI reads ALL the evidence (logs inside+outside the site, DB, platform) plus what Fix-it already tried, decides a plan, and EXECUTES it itself (reversible).'))return;
      af.disabled=true;var ot=af.innerHTML;af.innerHTML='&#129302; Working…';
      var pg=progress('🤖 AI Fix',['Reading logs (inside + server), DB & platform','AI deciding the fix plan','Applying the plan (reversible)','Verifying with curl']);
      post('ai_fix',{target:t}).then(function(k){
        af.disabled=false;af.innerHTML=ot;
        if(k&&k.verdict){var ao=document.getElementById('sdAiOut'); // planner fell back to diagnosis
          if(ao)ao.innerHTML='<div style="background:var(--brand-bg);border-radius:11px;padding:13px 15px;white-space:pre-wrap;font-size:13px;margin-top:4px"><b class="sd-badge" style="background:#fff">&#129302; Diagnosis'+(k.provider?' ('+esc(k.provider)+')':'')+'</b><div style="margin-top:8px;color:var(--muted)">'+esc(k.msg||'')+'</div><div style="margin-top:8px">'+esc(k.verdict)+'</div></div>';
          return;}
        var extra=(k&&k.cause)?'<div style="margin-top:8px;color:var(--muted);font-size:12.5px">Cause: '+esc(k.cause)+(k.provider?' · '+esc(k.provider):'')+'</div>':'';
        pg.done((k&&k.steps)||[], k&&k.ok, k&&k.http_before, k&&k.http_after, extra);
        if(k&&k.ok)setTimeout(function(){run(t);},1800);
      }).catch(function(){af.disabled=false;af.innerHTML=ot;var ao=document.getElementById('sdAiOut');if(ao)ao.innerHTML='<div class="sd-badge crit">Request failed.</div>';});return;}
    var ub=e.target.closest('[data-undo]');
    if(ub){if(!confirm('Undo this fix (restore the original folder)?'))return;
      post('undo',{id:ub.getAttribute('data-undo')}).then(function(k){alert((k&&k.ok)?('✅ '+k.msg):('⚠ '+((k&&k.msg)||'undo failed')));run(t);}).catch(function(){alert('Request failed.');});return;}
    if(e.target.closest('[data-rerun]')){run(t);return;}
    var ai=e.target.closest('[data-ai]');
    if(ai){var ao=document.getElementById('sdAiOut');ai.disabled=true;var ot=ai.innerHTML;ai.innerHTML='&#129302; Thinking…';ao.innerHTML='<div style="color:var(--muted);padding-top:6px">reviewing evidence…</div>';
      post('ai',{target:t}).then(function(k){ai.disabled=false;ai.innerHTML=ot;
        if(!k||!k.ok){ao.innerHTML='<div class="sd-badge crit">'+esc((k&&k.error)||'AI unavailable')+'</div>';return;}
        ao.innerHTML='<div style="background:var(--brand-bg);border-radius:11px;padding:13px 15px;white-space:pre-wrap;font-size:13px"><b class="sd-badge" style="background:#fff">&#129302; AI verdict'+(k.provider?' ('+esc(k.provider)+')':'')+'</b><div style="margin-top:8px">'+esc(k.text||'')+'</div></div>';
      }).catch(function(){ai.disabled=false;ai.innerHTML=ot;ao.innerHTML='<div class="sd-badge crit">failed</div>';});return;}
  });
  if((inp.value||'').trim())run(inp.value.trim());
})();
</script>
<?php
smpro_layout_footer();
