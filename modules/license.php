<?php
/**
 * modules/license.php — License activation & status (AITECH_LICENSE). The endpoint hosts live in
 * SMPRO_LIC_BASE / SMPRO_LIC_BASE_FALLBACK (includes/license.php) — never name one here.
 * GET renders status (refreshing a stale cache). All mutations go through the
 * ?license=1 endpoint in index.php (POST + CSRF + root).
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

// Warm the cached verdict WITHOUT blocking the render — the old blocking check could hang the page
// ~20-40s during a license-server outage (exactly when admins open this page). The detached refresh
// updates the state for the next load; this render shows the current cached verdict.
if (function_exists('smpro_lic_refresh_async')) smpro_lic_refresh_async(); else smpro_lic_refresh_if_stale();
$s     = smpro_lic_state();
$valid = smpro_lic_is_valid();
$key   = (string)($s['key'] ?? '');
$csrf  = smpro_csrf_generate('license');

$state = $key === '' ? 'none' : ($valid ? 'active' : 'invalid');
$badge = ['active'=>['good','&#10003; Active'], 'invalid'=>['dang','&#10007; Not valid'], 'none'=>['muted','&#9679; Not activated']][$state];
$maskKey = $key === '' ? '' : (mb_strlen($key) > 10 ? mb_substr($key,0,4) . str_repeat('•',6) . mb_substr($key,-4) : $key);

smpro_audit('license_view', ['state' => $state]);
smpro_layout_header('License');
?>
<?php if (!empty($GLOBALS['SMPRO_LIC_UNREACHABLE']) || (function_exists('smpro_lic_is_unreachable') && smpro_lic_is_unreachable())): ?>
<div class="card" style="border-left:4px solid #e53935;background:rgba(229,57,53,.08);padding:14px 16px;margin-bottom:14px">
  <b style="color:#c62828">&#9888; <?= smpro_h(smpro_lic_support_message()) ?></b>
</div>
<?php endif; ?>
<div class="svc-kicker">Activation</div>
<h1 class="h" style="margin:2px 0 4px">License</h1>
<p class="sub">Activate <b><?= smpro_h(SMPRO_NAME) ?></b> with your license key. The license is bound to this server's main IP and a hardware fingerprint; it re-checks automatically.</p>

<script>var LIC_CSRF=<?= json_encode($csrf) ?>;</script>

<div class="card lic-status lic-<?= $state ?>">
  <div class="lic-badge <?= $badge[0] ?>"><?= $badge[1] ?></div>
  <div class="lic-grid">
    <div><span class="l">Status</span><b id="licStatusTxt"><?= smpro_h(ucfirst((string)($s['status'] ?? ($state==='none'?'not activated':'unknown')))) ?></b></div>
    <div><span class="l">Plan</span><b><?= smpro_h(ucfirst((string)($s['plan'] ?? ''))) ?: '—' ?></b></div>
    <div><span class="l">Product</span><b><?= smpro_h(smpro_lic_product_name($s['product'] ?? '')) ?: '—' ?></b></div>
    <div><span class="l">Expiry</span><b class="<?= smpro_lic_expired($s['expiry'] ?? '')?'lic-exp':'' ?>"><?= smpro_h($s['expiry'] ?? '') ?: 'no expiry' ?></b></div>
    <div><span class="l">Licensed to</span><b><?= smpro_h(smpro_lic_owner_display()) ?: '—' ?></b></div>
    <div><span class="l">Key</span><b class="mono"><?= smpro_h($maskKey) ?: '—' ?></b></div>
    <div><span class="l">Features</span><b><?= !empty($s['features']) ? count($s['features']).' enabled' : '—' ?></b></div>
    <div><span class="l">Bound to</span><b class="mono"><?= smpro_h(($s['bound_ip'] ?? '') ?: '—') ?><?= !empty($s['bound_hostname'])?' <span class="meta">('.smpro_h($s['bound_hostname']).')</span>':'' ?></b></div>
    <div><span class="l">Signature</span><b><?= !empty($s['sig_verified']) ? '<span class="lic-ok">&#10003; verified (RSA)</span>' : ($key!==''?'<span class="lic-warn">not verified</span>':'—') ?></b></div>
    <div><span class="l">Last check</span><b><?= !empty($s['last_check']) ? smpro_h(date('Y-m-d H:i', (int)$s['last_check'])) : '—' ?><?= !empty($s['unreachable'])?' <span class="lic-warn">server unreachable</span>':'' ?></b></div>
  </div>
  <?php if (!empty($s['features'])): ?><div class="lic-feats"><?php foreach (array_slice($s['features'],0,30) as $ft): ?><span class="lic-feat"><?= smpro_h($ft) ?></span><?php endforeach; ?></div><?php endif; ?>
  <?php if (!empty($s['message'])): ?><div class="lic-msg"><?= smpro_h($s['message']) ?></div><?php endif; ?>
</div>

<div class="card">
  <h3 class="lic-h">&#128273; <?= $state==='active' ? 'Manage license' : 'Activate this server' ?></h3>
  <div class="lic-form">
    <label class="lic-fld">License key
      <input class="tp-in" id="licKey" type="text" placeholder="<?= $key !== '' ? smpro_h($maskKey) . ' — type a key to change' : 'SM-2026-XXXX-XXXX-XXXX-XXXX' ?>" value="" autocomplete="off" spellcheck="false">
    </label>
    <div class="lic-actions">
      <button class="tp-btn primary" id="licActivate" type="button">&#9889; <?= $state==='active'?'Re-activate':'Activate' ?></button>
      <?php if ($key !== ''): ?>
      <button class="tp-btn" id="licCheck" type="button">&#128260; Re-check now</button>
      <button class="tp-btn lic-danger" id="licDeactivate" type="button">&#128465; Remove from this server</button>
      <?php endif; ?>
    </div>
    <div class="lic-result" id="licResult"></div>
  </div>
</div>

<style>
.svc-kicker{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--brand);font-weight:800}
.lic-status{position:relative;border-top:3px solid var(--line)}
.lic-status.lic-active{border-top-color:var(--good)}.lic-status.lic-invalid{border-top-color:var(--dang)}
.lic-badge{display:inline-block;font-weight:800;font-size:13px;padding:4px 12px;border-radius:20px;margin-bottom:12px}
.lic-badge.good{background:var(--good-bg);color:var(--good)}.lic-badge.dang{background:var(--dang-bg);color:var(--dang)}.lic-badge.muted{background:var(--card);color:#475569}
.lic-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}@media(max-width:760px){.lic-grid{grid-template-columns:1fr 1fr}}
.lic-grid>div{display:flex;flex-direction:column;gap:3px}
.lic-grid .l{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);font-weight:700}
.lic-grid b{font-size:14px}.lic-exp{color:var(--dang)}
.lic-grid .meta{color:var(--muted);font-weight:400;font-size:12px}
.lic-ok{color:var(--good);font-weight:800}
.lic-warn{font-size:11px;color:#b45309;font-weight:700}
.lic-feats{display:flex;flex-wrap:wrap;gap:6px;margin-top:14px}
.lic-feat{font-size:11px;font-weight:700;background:var(--good-bg);color:var(--good);border-radius:20px;padding:3px 10px}
.lic-msg{margin-top:12px;padding:9px 12px;background:var(--warn-bg);border:1px solid #fde68a;border-radius:9px;font-size:13px;color:#7c5e16}
.lic-h{margin:0 0 12px;font-size:15px}
.lic-form{display:flex;flex-direction:column;gap:12px;max-width:560px}
.lic-fld{display:flex;flex-direction:column;gap:6px;font-size:11px;text-transform:uppercase;color:var(--muted);font-weight:700}
.tp-in{border:1px solid var(--line);border-radius:9px;padding:11px 13px;font-size:14px;font-family:ui-monospace,Consolas,monospace}
.lic-actions{display:flex;gap:10px;flex-wrap:wrap}
.tp-btn{border:1px solid var(--line);border-radius:9px;padding:10px 16px;font-size:13px;font-weight:700;cursor:pointer;background:var(--card);color:var(--ink)}
.tp-btn.lic-danger{border-color:#fca5a5;background:var(--dang-bg);color:var(--dang)}
.lic-result{font-size:13px;min-height:18px}
.lic-result.ok{color:var(--good)}.lic-result.err{color:var(--dang)}
.mono{font-family:ui-monospace,Consolas,monospace;word-break:break-all}
.lic-id b{font-size:12.5px}
</style>
<script>
(function(){
  function post(action,extra){
    var fd=new URLSearchParams();fd.set('smpro_csrf',LIC_CSRF);fd.set('lic_action',action);
    if(extra)Object.keys(extra).forEach(function(k){fd.set(k,extra[k]);});
    return fetch('index.cgi?license=1',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'}).then(function(r){return r.json();});
  }
  var res=document.getElementById('licResult');
  function say(ok,msg){res.className='lic-result '+(ok?'ok':'err');res.textContent=(ok?'✅ ':'⚠ ')+msg;}
  function run(btn,action,extra,working){
    var all=document.querySelectorAll('.lic-actions .tp-btn');all.forEach(function(b){b.disabled=true;});
    var old=btn.innerHTML;btn.innerHTML='⏳ '+working;
    post(action,extra).then(function(j){
      all.forEach(function(b){b.disabled=false;});btn.innerHTML=old;
      if(!j){say(false,'No response from server.');return;}
      var ok=!!(j.valid||j.ok);
      say(ok,(j.message||(ok?'License is valid.':'License is not valid.'))+(j.status?' ['+j.status+']':'')+(j.expiry?' · expires '+j.expiry:''));
      setTimeout(function(){location.reload();},900);
    }).catch(function(){all.forEach(function(b){b.disabled=false;});btn.innerHTML=old;say(false,'Request failed.');});
  }
  var a=document.getElementById('licActivate');
  if(a)a.addEventListener('click',function(){var k=(document.getElementById('licKey').value||'').trim();if(!k){say(false,'Enter a license key.');return;}run(a,'activate',{key:k},'Activating…');});
  var c=document.getElementById('licCheck');
  if(c)c.addEventListener('click',function(){run(c,'check',null,'Checking…');});
  var d=document.getElementById('licDeactivate');
  if(d)d.addEventListener('click',function(){if(!confirm('Remove the license from this server? The plugin will be unlicensed until you activate again.'))return;run(d,'deactivate',null,'Removing…');});
})();
</script>
<?php
smpro_layout_footer();
