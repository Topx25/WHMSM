<?php
/**
 * modules/updates.php - in-plugin updates (check + apply + auto-update).
 * GET renders status; all actions go through the ?update=1 endpoint (POST + CSRF + root).
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

if (function_exists('smpro_upd_install_cron')) smpro_upd_install_cron();   // ensure the daily background check is scheduled
$cfg  = smpro_upd_cfg();
$csrf = smpro_csrf_generate('update');
$cur  = defined('SMPRO_VERSION') ? SMPRO_VERSION : '?';
$lastChk = !empty($cfg['last_check']) ? date('Y-m-d H:i', (int)$cfg['last_check']) : 'never';
$lastRes = (string)($cfg['last_result'] ?? '');
smpro_audit('updates_view', ['current' => $cur, 'auto' => !empty($cfg['auto'])]);
smpro_layout_header('Updates');
?>
<script>var UPD_CSRF=<?= json_encode($csrf) ?>;</script>
<div class="svc-kicker">Maintenance</div>
<h1 class="h" style="margin:2px 0 4px">&#8635; Updates</h1>
<p class="sub">Pull new builds of <b><?= smpro_h(SMPRO_NAME) ?></b> securely (gated by your license + this server's hardware fingerprint). Enable auto-update to apply new versions automatically.</p>

<style>
.upd-card{max-width:700px;padding:20px 22px}
.upd-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}
.upd-box{display:flex;flex-direction:column;gap:5px;border:1px solid var(--line);border-radius:11px;padding:13px 15px;background:var(--card)}
.upd-box .l{font-size:11px;text-transform:uppercase;letter-spacing:.03em;color:var(--muted);font-weight:700}
.upd-box b{font-size:18px;font-weight:800}
.upd-actions{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-top:18px}
.upd-actions .btn{padding:10px 16px}
.upd-sep{height:1px;background:var(--line);margin:20px 0}
.upd-auto{display:flex;align-items:flex-start;gap:12px}
.upd-note{color:#64748b;font-size:12.5px;margin-top:14px;line-height:1.6}
.upd-seg{display:inline-flex;border:1px solid var(--line);border-radius:10px;overflow:hidden}
.upd-seg .seg{background:var(--card);border:0;padding:8px 16px;font-size:13px;font-weight:700;color:var(--muted);cursor:pointer}
.upd-seg .seg.on{background:var(--brand);color:#fff}
.upd-seg .seg+.seg{border-left:1px solid var(--line)}
@media(max-width:560px){.upd-grid{grid-template-columns:1fr}}
</style>
<div class="card upd-card">
  <div class="upd-grid">
    <div class="upd-box"><span class="l">Installed version</span><b id="updCur"><?= smpro_h($cur) ?></b></div>
    <div class="upd-box"><span class="l">Latest available</span><b id="updLatest"><?= smpro_h((string)($cfg['latest'] ?? '') ?: '—') ?></b></div>
    <div class="upd-box"><span class="l">Last checked</span><b id="updLastChk" style="font-size:15px"><?= smpro_h($lastChk) ?></b></div>
    <div class="upd-box"><span class="l">Last result</span><b id="updLastRes" style="font-size:15px"><?= smpro_h($lastRes ?: '—') ?></b></div>
  </div>

  <div id="updMsg" class="meta" style="margin:14px 2px 0;min-height:20px"></div>

  <div class="upd-actions">
    <button class="btn" id="updCheck">&#128269; Check for updates</button>
    <button class="btn" id="updApply" style="background:#16a34a;color:#fff;display:none">&#8681; Update now</button>
    <button class="btn" id="updForce" style="background:transparent;border:1px solid var(--line);color:var(--muted)" title="Re-install the latest build from your update channel right now — even if it matches your installed version. For recovering a broken install or pulling a re-published build without waiting for the daily check.">&#8635; Force update</button>
  </div>
  <p class="upd-note" style="margin-top:8px"><b>Force update</b> re-installs the latest build from your current channel immediately, even if the version already matches — useful right after a release or to repair a partial install. The package signature is still verified and the current build is backed up first.</p>

  <div class="upd-sep"></div>

  <?php $ch = ($cfg['channel'] ?? 'stable') === 'beta' ? 'beta' : 'stable'; ?>
  <div class="upd-chan">
    <div class="l" style="font-size:11px;text-transform:uppercase;letter-spacing:.03em;color:var(--muted);font-weight:700;margin-bottom:7px">Update channel</div>
    <div class="upd-seg" id="updChan">
      <button type="button" class="seg<?= $ch === 'stable' ? ' on' : '' ?>" data-ch="stable">&#9679; Stable</button>
      <button type="button" class="seg<?= $ch === 'beta' ? ' on' : '' ?>" data-ch="beta">&#129514; Beta (test)</button>
    </div>
    <p class="upd-note" style="margin-top:8px"><b>Stable</b> = the tested production release (recommended). <b>Beta</b> = early builds with new features under test — may be less stable, and once on a beta you stay on it until a newer stable catches up. Same license key either way.</p>
  </div>

  <div class="upd-sep"></div>

  <label class="sw upd-auto">
    <input type="checkbox" id="updAuto" <?= !empty($cfg['auto']) ? 'checked' : '' ?>>
    <span class="track"></span><span class="lbl">Auto-update — apply new versions automatically (checked daily by the background worker)</span><span class="st"></span>
  </label>
  <p class="upd-note">Every update backs up the current install first, verifies the package SHA-256, then swaps the files and re-registers the WHM plugin. Your data, settings and license are untouched, and the change is reversible.</p>
</div>

<script>(function(){
  function P(id){return document.getElementById(id);}
  function post(action,extra){var fd=new URLSearchParams();fd.set('smpro_csrf',UPD_CSRF);fd.set('upd_action',action);
    if(extra)Object.keys(extra).forEach(function(k){fd.set(k,extra[k]);});
    return fetch('index.cgi?update=1',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'}).then(function(r){return r.json();});}
  function msg(t,c){var m=P('updMsg');m.innerHTML=t;m.style.color=c||'';}
  function e(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}   /* escape server-supplied fields before innerHTML */

  P('updCheck').addEventListener('click',function(){var b=this;b.disabled=true;var o=b.innerHTML;b.innerHTML='Checking…';msg('Checking for updates…');
    post('check').then(function(j){b.disabled=false;b.innerHTML=o;
      if(!j||!j.ok){P('updLastChk').textContent='just now';P('updLastRes').textContent='Check failed';msg('&#10007; '+e((j&&j.message)||'Check failed'),'#b91c1c');return;}
      P('updLatest').textContent=j.latest||'—';P('updLastChk').textContent='just now';P('updLastRes').textContent=j.result||(j.available?'Update available: '+j.latest:'Up to date');
      if(j.available){msg('&#10003; Version <b>'+e(j.latest)+'</b> is available (you have '+e(j.current)+').'+(j.notes?'<div style="margin-top:6px">'+e(j.notes)+'</div>':''),'#047857');P('updApply').style.display='';}
      else{msg('&#10003; You are on the latest version ('+e(j.current)+').','#047857');P('updApply').style.display='none';}
    }).catch(function(){b.disabled=false;b.innerHTML=o;msg('&#10007; Request failed.','#b91c1c');});});

  P('updApply').addEventListener('click',function(){if(!confirm('Download and install the new version now? The current build is backed up first and the change is reversible.'))return;
    var b=this;b.disabled=true;var o=b.innerHTML;b.innerHTML='Updating…';msg('Downloading + applying update… do not close this page.');
    post('apply').then(function(j){b.disabled=false;b.innerHTML=o;
      if(j&&j.ok){msg('&#10003; Updated to <b>'+e(j.to||'latest')+'</b>. Reload the page to load the new version.','#047857');P('updCur').textContent=j.to||'';P('updApply').style.display='none';P('updLastRes').textContent='updated to '+(j.to||'latest');}
      else{msg('&#10007; '+e((j&&j.message)||'Update failed'),'#b91c1c');}
    }).catch(function(){b.disabled=false;b.innerHTML=o;msg('&#10007; Update request failed.','#b91c1c');});});

  P('updForce').addEventListener('click',function(){
    if(!confirm('Force-install the latest build from your update channel now?\n\nThis re-applies the current channel release even if it already matches your installed version (used to recover a broken install or re-pull a re-published build). The package signature is still verified, the current build is backed up first, and the change is reversible.'))return;
    var b=this;b.disabled=true;var o=b.innerHTML;b.innerHTML='Updating…';msg('Downloading + re-applying the current channel build… do not close this page.');
    post('force').then(function(j){b.disabled=false;b.innerHTML=o;
      if(j&&j.ok){msg('&#10003; Installed <b>'+e(j.to||'latest')+'</b>. Reload the page to load the new build.','#047857');if(j.to)P('updCur').textContent=j.to;P('updApply').style.display='none';P('updLastRes').textContent='forced update to '+(j.to||'latest');}
      else{msg('&#10007; '+e((j&&j.message)||'Force update failed'),'#b91c1c');}
    }).catch(function(){b.disabled=false;b.innerHTML=o;msg('&#10007; Force update request failed.','#b91c1c');});});

  P('updAuto').addEventListener('change',function(){var on=this.checked;post('auto',{on:on?'1':''}).then(function(j){msg(on?'Auto-update enabled.':'Auto-update disabled.','#475569');}).catch(function(){});});

  Array.prototype.forEach.call(document.querySelectorAll('#updChan .seg'),function(b){
    b.addEventListener('click',function(){
      var ch=b.getAttribute('data-ch');
      if(ch==='beta'&&!confirm('Switch to the BETA channel?\n\nYou will receive early test builds with new features that may be less stable. Once on a beta you stay on it until a newer stable release catches up. Same license key. Reversible.'))return;
      post('channel',{channel:ch}).then(function(j){
        if(j&&j.ok){document.querySelectorAll('#updChan .seg').forEach(function(x){x.classList.toggle('on',x.getAttribute('data-ch')===j.channel);});
          msg('Update channel set to <b>'+j.channel+'</b>. Click "Check for updates" to pull from it.','#475569');}
        else msg('&#10007; '+e((j&&j.msg)||'Could not change channel'),'#b91c1c');
      }).catch(function(){msg('&#10007; Request failed.','#b91c1c');});
    });
  });
})();</script>
<?php
smpro_layout_footer();
