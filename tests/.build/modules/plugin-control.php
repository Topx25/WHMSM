<?php
/**
 * modules/plugin-control.php — master Enable / Dry-Run / Disable switch for the whole plugin.
 *   Enabled  : normal operation (monitor + take automatic actions).
 *   Dry-Run  : monitor + alert, but DO NOT take any automatic action (auto-block, auto-fix, throttle, auto-update).
 *   Disabled : the plugin stops — pages show a notice and the background worker does nothing.
 * Disabling can carry a scheduled re-enable date/time (auto turns back on then). State: SMPRO_VARLIB/control.json.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

$reqMethod = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));
if ($reqMethod === 'POST' && ($_POST['pc_action'] ?? '') === 'save') {
    smpro_require_valid_csrf('pc_action'); smpro_require_root();
    header('Content-Type: application/json');
    $mode = in_array(($_POST['mode'] ?? ''), ['enabled','dryrun','disabled'], true) ? $_POST['mode'] : 'enabled';
    $reAt = 0;
    if ($mode === 'disabled') {
        $re = trim((string)($_POST['reenable_at'] ?? ''));
        if ($re !== '') { $t = strtotime($re); if ($t && $t > time()) $reAt = $t; }
    }
    $c = smpro_ctl_get();
    $c['mode'] = $mode; $c['reenable_at'] = $reAt; $c['updated_at'] = time(); $c['actor'] = smpro_current_actor();
    smpro_ctl_save($c);
    smpro_audit('plugin_control', ['mode' => $mode, 'reenable_at' => $reAt, 'by' => smpro_current_actor()]);
    echo json_encode(['ok' => true, 'mode' => $mode, 'reenable_at' => $reAt ? date('Y-m-d H:i', $reAt) : '']); exit;
}
if ($reqMethod === 'POST' && ($_POST['pc_action'] ?? '') === 'uninstall') {
    smpro_require_valid_csrf('pc_action'); smpro_require_root();
    header('Content-Type: application/json');
    if (strtoupper(trim((string)($_POST['confirm'] ?? ''))) !== 'UNINSTALL') { echo json_encode(['ok' => false, 'msg' => 'Type UNINSTALL to confirm.']); exit; }
    $purge = !empty($_POST['purge']);
    $done  = function_exists('smpro_plugin_uninstall') ? smpro_plugin_uninstall($purge) : ['uninstall unavailable'];
    echo json_encode(['ok' => true, 'purge' => $purge, 'done' => $done]); exit;
}

$ctl  = smpro_ctl_get();
$csrf = smpro_csrf_generate('pc_action');
$mode = $ctl['mode'];
$reAtStr = (int)$ctl['reenable_at'] > 0 ? date('Y-m-d\TH:i', (int)$ctl['reenable_at']) : '';
smpro_audit('plugin_control_view', ['mode' => $mode]);
smpro_layout_header('Plugin Control');
$badge = ['enabled'=>['#16a34a','&#9679; Enabled — full operation'],'dryrun'=>['#b45309','&#9679; Dry-Run — monitoring only'],'disabled'=>['#dc2626','&#9679; Disabled — stopped']][$mode] ?? ['#16a34a','Enabled'];
?>
<script>var PC_CSRF=<?= json_encode($csrf) ?>;</script>
<div class="svc-kicker">Settings</div>
<h1 class="h" style="margin:2px 0 4px">&#9211; Plugin Control</h1>
<p class="sub">Master switch for <b><?= smpro_h(SMPRO_NAME) ?></b> — turn the whole plugin on, run it safely in monitor-only mode, or stop it (with an optional automatic restart time).</p>

<div class="card" style="max-width:680px;padding:20px 22px">
  <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px">
    <b>Current state:</b> <span id="pcState" style="font-weight:800;color:<?= $badge[0] ?>"><?= $badge[1] ?></span>
    <?php if ($mode === 'disabled' && $reAtStr): ?><span class="meta">· auto-restart at <?= smpro_h(date('Y-m-d H:i', (int)$ctl['reenable_at'])) ?></span><?php endif; ?>
  </div>

  <label class="pc-opt <?= $mode==='enabled'?'on':'' ?>">
    <input type="radio" name="pc_mode" value="enabled" <?= $mode==='enabled'?'checked':'' ?>>
    <div><b>&#9989; Enabled</b><div class="meta">Normal operation — monitors the server AND takes automatic actions (auto-block attackers, auto-fixes, load guard, auto-update).</div></div>
  </label>
  <label class="pc-opt <?= $mode==='dryrun'?'on':'' ?>">
    <input type="radio" name="pc_mode" value="dryrun" <?= $mode==='dryrun'?'checked':'' ?>>
    <div><b>&#129517; Dry-Run (monitor only)</b><div class="meta">Keeps watching and still sends alerts, but performs <b>no automatic actions</b> — it only logs what it <i>would</i> have done. Safe for testing.</div></div>
  </label>
  <label class="pc-opt <?= $mode==='disabled'?'on':'' ?>">
    <input type="radio" name="pc_mode" value="disabled" <?= $mode==='disabled'?'checked':'' ?>>
    <div><b>&#9940; Disabled</b><div class="meta">Stops the plugin completely — all pages show a notice and the background worker does nothing until re-enabled.</div></div>
  </label>

  <div id="pcReWrap" style="margin-top:6px;<?= $mode==='disabled'?'':'display:none' ?>">
    <label class="l" style="font-size:12px;color:var(--muted);display:block;margin-bottom:4px">Automatic restart (optional) — turn back on at:</label>
    <input type="datetime-local" id="pcReAt" class="tp-in" value="<?= smpro_h($reAtStr) ?>" style="max-width:240px">
    <div class="meta" style="margin-top:4px">Leave blank to stay disabled until you turn it back on manually.</div>
  </div>

  <div id="pcMsg" class="meta" style="margin:14px 2px 0;min-height:20px"></div>
  <div style="margin-top:12px"><button class="btn" id="pcSave" style="background:var(--brand);color:#fff">&#128190; Apply</button></div>
</div>

<div class="card pc-danger" style="max-width:680px;padding:18px 22px;margin-top:18px">
  <b style="color:var(--dang);font-size:14px">&#9888; Danger zone — uninstall</b>
  <p class="sub" style="margin:6px 0 12px">Removes <b><?= smpro_h(SMPRO_NAME) ?></b> from this server: unregisters the WHM menu entry, deletes its cron jobs, and removes the plugin files. This does <b>not</b> touch your cPanel accounts or websites.</p>
  <label style="display:flex;gap:8px;align-items:flex-start;font-size:13px;margin-bottom:10px;cursor:pointer">
    <input type="checkbox" id="pcPurge" style="margin-top:2px">
    <span>Also delete all plugin <b>data &amp; logs</b> (settings, license activation, reports). Leave unchecked to keep them in case you reinstall.</span>
  </label>
  <label class="l" style="font-size:12px;color:var(--muted);display:block;margin-bottom:4px">Type <b>UNINSTALL</b> to confirm:</label>
  <input type="text" id="pcConfirm" class="tp-in" placeholder="UNINSTALL" autocomplete="off" spellcheck="false" style="max-width:240px">
  <div id="pcUnMsg" class="meta" style="margin:12px 2px 0;min-height:20px"></div>
  <div style="margin-top:12px"><button class="btn" id="pcUninstall" style="background:var(--dang);color:#fff">&#128465; Uninstall plugin</button></div>
</div>

<style>
.pc-opt{display:flex;gap:12px;align-items:flex-start;border:1px solid var(--line);border-radius:11px;padding:13px 15px;margin-bottom:10px;cursor:pointer;transition:border-color .15s,background .15s}
.pc-danger{border-color:var(--dang)}
.pc-opt:hover{background:rgba(148,163,184,.05)}
.pc-opt.on{border-color:var(--brand);background:rgba(59,91,219,.05)}
.pc-opt input{margin-top:3px}
.pc-opt b{font-size:14px}
</style>
<script>(function(){
  function P(id){return document.getElementById(id);}
  document.querySelectorAll('input[name=pc_mode]').forEach(function(r){r.addEventListener('change',function(){
    document.querySelectorAll('.pc-opt').forEach(function(o){o.classList.remove('on');});
    this.closest('.pc-opt').classList.add('on');
    P('pcReWrap').style.display = this.value==='disabled' ? '' : 'none';
  });});
  P('pcSave').addEventListener('click',function(){
    var mode=(document.querySelector('input[name=pc_mode]:checked')||{}).value||'enabled';
    if(mode==='disabled' && !confirm('Disable the plugin now? It will stop all monitoring and automatic protection until re-enabled.'))return;
    var b=this,o=b.innerHTML;b.disabled=true;b.innerHTML='Saving…';
    var fd=new URLSearchParams();fd.set('smpro_csrf',PC_CSRF);fd.set('pc_action','save');fd.set('mode',mode);
    fd.set('reenable_at', mode==='disabled' ? (P('pcReAt').value||'') : '');
    fetch('index.cgi?page=plugin-control',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'})
      .then(function(r){return r.json();}).then(function(j){b.disabled=false;b.innerHTML=o;
        if(j&&j.ok){P('pcMsg').style.color='#16a34a';P('pcMsg').textContent='✅ Saved — mode: '+j.mode+(j.reenable_at?(' · auto-restart '+j.reenable_at):'');setTimeout(function(){location.reload();},900);}
        else{P('pcMsg').style.color='#dc2626';P('pcMsg').textContent='⚠ '+((j&&j.msg)||'Failed');}})
      .catch(function(){b.disabled=false;b.innerHTML=o;P('pcMsg').style.color='#dc2626';P('pcMsg').textContent='⚠ Request failed';});
  });
  var unb=P('pcUninstall'); if(unb)unb.addEventListener('click',function(){
    var conf=(P('pcConfirm').value||'').trim().toUpperCase();
    if(conf!=='UNINSTALL'){P('pcUnMsg').style.color='#dc2626';P('pcUnMsg').textContent='⚠ Type UNINSTALL to confirm.';return;}
    var purge=P('pcPurge').checked;
    if(!confirm('Uninstall '+<?= json_encode(SMPRO_NAME) ?>+' from this server now?'+(purge?' This will ALSO delete all data, logs, settings and license activation — this cannot be undone.':' (Data & logs will be kept.)')))return;
    var b=this,o=b.innerHTML;b.disabled=true;b.innerHTML='Uninstalling…';
    var fd=new URLSearchParams();fd.set('smpro_csrf',PC_CSRF);fd.set('pc_action','uninstall');fd.set('confirm',conf);fd.set('purge',purge?'1':'');
    fetch('index.cgi?page=plugin-control',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'})
      .then(function(r){return r.json();}).then(function(j){
        if(j&&j.ok){P('pcUnMsg').style.color='#16a34a';P('pcUnMsg').innerHTML='✅ Uninstalled: '+(j.done||[]).join(' · ')+'<br>The WHM menu entry will disappear shortly. You can close this page.';}
        else{b.disabled=false;b.innerHTML=o;P('pcUnMsg').style.color='#dc2626';P('pcUnMsg').textContent='⚠ '+((j&&j.msg)||'Failed');}})
      .catch(function(){b.disabled=false;b.innerHTML=o;P('pcUnMsg').style.color='#dc2626';P('pcUnMsg').textContent='⚠ Request failed';});
  });
})();</script>
<?php
smpro_layout_footer();
