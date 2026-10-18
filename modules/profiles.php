<?php
/**
 * modules/profiles.php — Protection Profiles (Settings).
 * Apply a whole-plugin protection posture (Medium / Maximum / AI / Custom) in one click,
 * adapted to this server. Every apply previews the exact changes first and snapshots the
 * current settings to a server-named, dated ARCHIVE entry so you can always roll back.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

$reqMethod = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));

if ($reqMethod === 'POST' && ($_POST['pf_action'] ?? '') !== '') {
    smpro_require_valid_csrf('pf_action'); smpro_require_root();
    header('Content-Type: application/json');
    $act = preg_replace('/[^a-z_]/', '', strtolower((string)$_POST['pf_action']));
    $key = preg_replace('/[^0-9A-Za-z_]/', '', (string)($_POST['key'] ?? ''));

    if ($act === 'preview') {
        $t = smpro_prof_resolve($key);
        echo json_encode(['ok'=>true,'label'=>$t['label'] ?? $key,'desc'=>$t['desc'] ?? '','diff'=>smpro_prof_diff($key)], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE); exit;
    }
    if ($act === 'apply')      { echo json_encode(smpro_prof_apply($key), JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE); exit; }
    if ($act === 'auto_setup') { echo json_encode(smpro_prof_apply(smpro_prof_recommended_key(), 'auto-setup'), JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE); exit; }
    if ($act === 'restore')    { echo json_encode(smpro_prof_apply($key, 'restore'), JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE); exit; }
    if ($act === 'save_current') {
        $name = trim((string)($_POST['name'] ?? '')) ?: ('Custom — ' . date('Y-m-d H:i'));
        $id = smpro_prof_store($name, smpro_prof_current(), 'saved');
        smpro_audit('profile_save', ['name'=>$name]);
        echo json_encode(['ok'=>true,'id'=>$id], JSON_UNESCAPED_SLASHES); exit;
    }
    if ($act === 'ai_generate') {
        $r = smpro_prof_ai_generate();
        if (empty($r['ok'])) { echo json_encode(['ok'=>false,'msg'=>$r['msg'] ?? 'AI failed'], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE); exit; }
        $id = smpro_prof_store('AI profile — ' . date('Y-m-d H:i') . ($r['provider']?' ('.$r['provider'].')':''), $r['profile'], 'ai');
        echo json_encode(['ok'=>true,'id'=>$id,'desc'=>$r['profile']['desc'] ?? '','diff'=>smpro_prof_diff($id)], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE); exit;
    }
    echo json_encode(['ok'=>false,'msg'=>'unknown action']); exit;
}

$csrf = smpro_csrf_generate('pf_action');
$env  = smpro_prof_env();
$active = smpro_prof_active();
$builtin = smpro_prof_builtin();
$idx = smpro_prof_index();
smpro_audit('profile_view', []);
smpro_layout_header('Protection Profiles');
?>
<script>var PF_CSRF=<?= json_encode($csrf) ?>;</script>
<div class="svc-kicker">Settings</div>
<h1 class="h" style="margin:2px 0 4px" data-i18n>Protection Profiles</h1>
<p class="sub" data-i18n>Apply a whole-plugin protection posture in one click — adapted to this server. Every apply previews the exact changes and saves a dated rollback point.</p>

<div class="pf-env">
  <div><span class="l" data-i18n>Server</span><b><?= smpro_h($env['hostname']) ?></b></div>
  <div><span class="l" data-i18n>Cores / RAM</span><b><?= (int)$env['cores'] ?> · <?= smpro_h($env['ram_gb']) ?>GB</b></div>
  <div><span class="l" data-i18n>Hosted sites</span><b><?= (int)$env['sites'] ?></b></div>
  <div><span class="l">Imunify</span><b class="<?= $env['imunify']?'y':'n' ?>"><?= $env['imunify']?'yes':'no' ?></b></div>
  <div><span class="l">CSF</span><b class="<?= $env['csf']?'y':'n' ?>"><?= $env['csf']?'yes':'no' ?></b></div>
  <div><span class="l">Cloudflare</span><b class="<?= $env['cloudflare']?'y':'n' ?>"><?= $env['cloudflare']?'yes':'no' ?></b></div>
  <div><span class="l">AI</span><b class="<?= $env['ai']?'y':'n' ?>"><?= $env['ai']?'ready':'no' ?></b></div>
  <div><span class="l" data-i18n>Active profile</span><b><?= $active ? smpro_h($active['label'] ?? $active['key'] ?? '') : '<span class="meta">none set</span>' ?></b></div>
</div>

<div style="margin:14px 0;display:flex;gap:8px;flex-wrap:wrap;align-items:center">
  <button class="pf-btn primary" id="pfAuto" type="button">&#128640; <span data-i18n>Auto-setup this server (recommended)</span></button>
  <span class="meta" data-i18n>Detects the environment and applies the recommended Medium profile, tuned to your cores / sites.</span>
</div>

<div class="pf-grid">
  <?php foreach ($builtin as $k => $p): ?>
  <div class="pf-card <?= $k==='maximum'?'max':'' ?>">
    <h3><?= $k==='maximum'?'&#128680; ':'&#128737; ' ?><?= smpro_h($p['label']) ?></h3>
    <p class="meta"><?= smpro_h($p['desc']) ?></p>
    <div class="pf-row"><button class="pf-btn" data-prev="<?= $k ?>" type="button" data-i18n>Preview &amp; Apply</button></div>
  </div>
  <?php endforeach; ?>
  <div class="pf-card ai">
    <h3>&#129302; <span data-i18n>AI Profile</span></h3>
    <p class="meta" data-i18n>The AI inspects this server (resources, Imunify/CSF/Cloudflare, sites, attack volume) and tailors the safest effective settings.</p>
    <div class="pf-row"><button class="pf-btn" id="pfAi" type="button" <?= $env['ai']?'':'disabled title="Configure an AI provider first"' ?> data-i18n>Generate with AI</button></div>
  </div>
  <div class="pf-card">
    <h3>&#128190; <span data-i18n>Save current as profile</span></h3>
    <p class="meta" data-i18n>Snapshot your current settings (Profile 1) so you can return to them later.</p>
    <div class="pf-row"><input type="text" id="pfName" class="pf-in" placeholder="Profile name"><button class="pf-btn" id="pfSave" type="button" data-i18n>Save</button></div>
  </div>
</div>

<div id="pfPreview" class="card" hidden style="margin:14px 0;padding:16px 18px;border-left:4px solid var(--brand)"></div>

<div class="tp-th" style="margin-top:18px"><b data-i18n>Archive &amp; saved profiles</b><span class="meta" style="margin-left:auto" data-i18n>a rollback point is saved automatically before every apply</span></div>
<div class="pf-scroll"><table class="smpro-table">
  <thead><tr><th data-i18n>Name</th><th data-i18n>Type</th><th data-i18n>Date</th><th></th></tr></thead><tbody>
  <?php if (!$idx): ?><tr><td colspan="4" class="pf-empty" data-i18n>No saved profiles yet.</td></tr><?php endif; ?>
  <?php foreach (array_slice($idx,0,200) as $r): ?>
    <tr><td><?= smpro_h($r['name'] ?? '') ?></td>
      <td><span class="b <?= ($r['kind']??'')==='ai'?'ai':(($r['kind']??'')==='archive'?'arc':'sv') ?>"><?= smpro_h($r['kind'] ?? '') ?></span></td>
      <td class="meta"><?= smpro_h($r['at'] ?? '') ?></td>
      <td><button class="pf-btn sm" data-prev="<?= smpro_h($r['id']) ?>" type="button" data-i18n>Preview &amp; Restore</button></td></tr>
  <?php endforeach; ?>
  </tbody></table></div>

<details class="pf-help" style="margin-top:16px">
  <summary data-i18n>What does each profile change? (and how it is applied)</summary>
  <div class="meta" style="margin-top:8px;line-height:1.8">
    <b>Medium</b> — alerts on; attacker auto-block in <b>dry-run</b>; Emergency off; balanced thresholds. Lowest risk. <b>Recommended default.</b><br>
    <b>Maximum</b> — auto-block <b>enforced</b> (+AI if available); <b>Emergency on</b> (hardens & quarantines web-shells); sensitive thresholds. For high-threat servers.<br>
    <b>AI Profile</b> — generated from this server's environment with a written rationale.<br>
    <b>Custom (Profile 1)</b> — your saved settings.<br>
    A profile controls the Intrusion Monitor automation + alert thresholds, <b>adapted to your cores/sites</b>. It never touches your Cloudflare/AI tokens, IP allowlist, breach-exclude paths, or the License. Before any apply, your current settings are archived as <i>&lt;server&gt; — &lt;date&gt;</i> for one-click restore.
  </div>
</details>

<style>
.pf-env{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:14px 0}
@media(max-width:760px){.pf-env{grid-template-columns:repeat(2,1fr)}}
.pf-env>div{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:10px 14px;display:flex;flex-direction:column;gap:2px}
.pf-env .l{font-size:11px;color:var(--muted);text-transform:uppercase;font-weight:700}.pf-env b{font-size:15px}
.pf-env b.y{color:var(--good)}.pf-env b.n{color:var(--muted)}
.pf-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px}@media(max-width:760px){.pf-grid{grid-template-columns:1fr}}
.pf-card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px 18px;display:flex;flex-direction:column}
.pf-card.max{border-left:4px solid var(--dang)}.pf-card.ai{border-left:4px solid var(--brand)}
.pf-card h3{margin:0 0 6px;font-size:16px}.pf-card .meta{flex:1}.pf-row{margin-top:12px;display:flex;gap:8px;align-items:center}
.pf-btn{border:1px solid var(--line);background:var(--card);color:var(--ink);border-radius:9px;padding:8px 14px;font-size:13px;cursor:pointer;font-weight:600}
.pf-btn.primary{background:var(--brand);color:#fff;border-color:var(--brand)}.pf-btn.sm{padding:5px 10px;font-size:12px}.pf-btn[disabled]{opacity:.5;cursor:not-allowed}
.pf-in{border:1px solid var(--line);border-radius:9px;padding:7px 11px;font-size:13px}
.pf-scroll{max-height:380px;overflow:auto}.smpro-table{width:100%;border-collapse:collapse;font-size:13px}
.smpro-table th,.smpro-table td{padding:8px 12px;text-align:left;border-bottom:1px solid var(--line)}.smpro-table th{font-size:11px;text-transform:uppercase;color:var(--muted)}
.tp-th{display:flex;align-items:center;gap:10px;padding:8px 2px}.pf-empty{padding:16px;text-align:center;color:var(--muted)}
.b{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:20px;background:var(--card);color:#475569}.b.ai{background:var(--brand-bg);color:var(--brand)}.b.arc{background:var(--warn-bg);color:#92702a}.b.sv{background:var(--good-bg);color:var(--good)}
.pf-diff{width:100%;border-collapse:collapse;font-size:13px;margin-top:8px}.pf-diff td,.pf-diff th{padding:5px 10px;border-bottom:1px solid var(--line);text-align:left}
.pf-from{color:var(--muted)}.pf-to{color:var(--brand);font-weight:700}
.pf-set{font-weight:600}
.pf-info{display:inline-flex;align-items:center;justify-content:center;width:17px;height:17px;border-radius:50%;border:1px solid var(--brand);background:var(--brand-bg,#eef2ff);color:var(--brand);font-size:11px;font-weight:800;font-style:italic;cursor:pointer;line-height:1;vertical-align:middle;padding:0}
.pf-info:hover{background:var(--brand);color:#fff}
.pf-balloon{margin:6px 0 2px;padding:9px 12px;background:#0f2657;color:#eaf0ff;border-radius:10px;font-size:12.5px;line-height:1.6;max-width:520px;box-shadow:0 6px 18px rgba(15,38,87,.18);position:relative}
.pf-balloon::before{content:"";position:absolute;top:-6px;left:14px;border:6px solid transparent;border-top:0;border-bottom-color:#0f2657}
.svc-kicker{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--brand);font-weight:700}.meta{color:var(--muted)}
</style>
<script>
(function(){
  function esc(s){return (s==null?'':String(s)).replace(/[&<>"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
  var pv=document.getElementById('pfPreview');
  function post(act,extra){var fd=new URLSearchParams();fd.set('pf_action',act);fd.set('smpro_csrf',PF_CSRF);for(var k in (extra||{}))fd.set(k,extra[k]);
    return fetch('index.cgi?page=profiles',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'}).then(function(r){return r.json();});}
  function showPreview(key,j,restore){
    var d=j.diff||[];
    var html='<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap"><b>'+esc(j.label||key)+'</b>';
    html+='<button class="pf-btn primary" id="pfConfirm" style="margin-left:auto">'+(restore?'Restore now':'Apply now')+'</button><button class="pf-btn" id="pfCancel">Cancel</button></div>';
    if(j.desc)html+='<p class="meta" style="margin:8px 0">'+esc(j.desc)+'</p>';
    if(!d.length)html+='<div class="meta">No changes — this profile matches your current settings.</div>';
    else{html+='<table class="pf-diff"><thead><tr><th>What changes</th><th>Now</th><th>→ Will be</th></tr></thead><tbody>';
      d.forEach(function(x,i){html+='<tr><td><span class="pf-set">'+esc(x.label)+'</span>';
        if(x.help)html+=' <button type="button" class="pf-info" data-bk="pfb_'+i+'" title="What is this?">i</button><div class="pf-balloon" id="pfb_'+i+'" hidden>'+esc(x.help)+'</div>';
        html+='</td><td class="pf-from">'+esc(x.from)+'</td><td class="pf-to">'+esc(x.to)+'</td></tr>';});
      html+='</tbody></table><p class="meta" style="margin-top:8px">&#128190; A backup of your current profile is saved automatically before anything is changed — one-click restore from the archive below.</p>';}
    pv.innerHTML=html;pv.hidden=false;pv.scrollIntoView({behavior:'smooth',block:'nearest'});
    document.getElementById('pfCancel').onclick=function(){pv.hidden=true;};
    document.getElementById('pfConfirm').onclick=function(){this.disabled=true;this.textContent='💾 Backing up, then applying…';
      post('apply',{key:key}).then(function(r){if(r&&r.ok){var bk=r.backup_name?('<div class="meta" style="margin-top:6px">&#128190; Backup saved: <b>'+esc(r.backup_name)+'</b></div>'):'';pv.innerHTML='<b style="color:var(--good)">&#10003; '+esc(r.msg||'Applied')+'</b> — reload to refresh.'+bk;setTimeout(function(){location.reload();},1200);}else pv.innerHTML='<b style="color:var(--dang)">'+esc((r&&r.msg)||'Apply failed')+'</b>';}).catch(function(){pv.innerHTML='<b style="color:var(--dang)">Request failed.</b>';});};
  }
  document.addEventListener('click',function(e){
    var inf=e.target.closest('.pf-info');if(inf){var b=document.getElementById(inf.getAttribute('data-bk'));if(b)b.hidden=!b.hidden;e.preventDefault();return;}
    var p=e.target.closest('[data-prev]');if(p){var key=p.getAttribute('data-prev');post('preview',{key:key}).then(function(j){if(j&&j.ok)showPreview(key,j,p.classList.contains('sm'));else alert('Preview failed.');});return;}
  });
  var auto=document.getElementById('pfAuto');if(auto)auto.addEventListener('click',function(){if(!confirm('Auto-setup applies the recommended Medium profile (tuned to this server). Continue? Your current settings are archived first.'))return;
    auto.disabled=true;post('auto_setup',{}).then(function(r){if(r&&r.ok){alert('Applied: '+(r.msg||''));location.reload();}else{alert((r&&r.msg)||'Failed');auto.disabled=false;}});});
  var ai=document.getElementById('pfAi');if(ai)ai.addEventListener('click',function(){ai.disabled=true;var ot=ai.innerHTML;ai.innerHTML='&#129302; Analysing…';
    post('ai_generate',{}).then(function(j){ai.disabled=false;ai.innerHTML=ot;if(j&&j.ok)showPreview(j.id,{label:'AI profile',desc:j.desc,diff:j.diff},false);else alert((j&&j.msg)||'AI failed');}).catch(function(){ai.disabled=false;ai.innerHTML=ot;alert('AI request failed');});});
  var sv=document.getElementById('pfSave');if(sv)sv.addEventListener('click',function(){var n=document.getElementById('pfName').value;
    post('save_current',{name:n}).then(function(r){if(r&&r.ok){alert('Saved.');location.reload();}else alert('Save failed');});});
})();
</script>
<?php
smpro_layout_footer();
