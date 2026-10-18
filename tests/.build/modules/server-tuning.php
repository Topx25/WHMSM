<?php
/**
 * modules/server-tuning.php — Server Tune-up: scan engines, recommend perf/security improvements,
 * back up configs (timestamped), and record a profile of applied changes. Apply via ?tuning=1.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

$scan = smpro_tun_scan();
$csrf = smpro_csrf_generate('tuning');
$byEngine = [];
foreach ($scan['recs'] as $r) $byEngine[$r['engine']][] = $r;
$autoIds = array_keys(smpro_tun_apply_map());
$sc = smpro_tun_score($scan['recs']);
$scW = ['high' => 10, 'medium' => 6, 'low' => 3];
$sevColor = ['high' => '#b91c1c', 'medium' => '#b45309', 'low' => '#0f766e'];
smpro_audit('tuning_view', ['recs' => count($scan['recs'])]);
smpro_layout_header('Server Tune-up');
?>
<script>var TUN_CSRF=<?= json_encode($csrf) ?>,TUN_SCORE=<?= (int)$sc['score'] ?>,TUN_H=<?= (int)$sc['high'] ?>,TUN_M=<?= (int)$sc['medium'] ?>,TUN_L=<?= (int)$sc['low'] ?>,TUN_CIRC=188.5;</script>
<div class="svc-kicker">Performance &amp; Security</div>
<h1 class="h" style="margin:2px 0 4px">&#128295; Server Tune-up</h1>
<p class="sub">Scans your server engines (<?= smpro_h(implode(', ', array_map(fn($e) => $e['label'], $scan['engines']))) ?>) and recommends performance &amp; security improvements. Every apply backs up the config first and records a profile. <b><?= (int)$scan['cores'] ?></b> cores · <b><?= round($scan['ram_mb'] / 1024) ?></b> GB RAM.</p>

<?php $scClr = $sc['score'] >= 85 ? '#16a34a' : ($sc['score'] >= 70 ? '#0ea5b7' : ($sc['score'] >= 50 ? '#b45309' : '#b91c1c')); $scCirc = 188.5; $scOff = $scCirc * (1 - $sc['score'] / 100); ?>
<div class="card" id="tunScoreCard" style="display:flex;align-items:center;gap:16px;margin-bottom:12px">
  <div style="position:relative;width:74px;height:74px;flex:none">
    <svg width="74" height="74" viewBox="0 0 72 72"><circle cx="36" cy="36" r="30" fill="none" stroke="rgba(148,163,184,.25)" stroke-width="7"/><circle id="tunRing" cx="36" cy="36" r="30" fill="none" stroke="<?= $scClr ?>" stroke-width="7" stroke-linecap="round" stroke-dasharray="<?= $scCirc ?>" stroke-dashoffset="<?= round($scOff, 1) ?>" transform="rotate(-90 36 36)" style="transition:stroke-dashoffset .6s ease,stroke .3s"/></svg>
    <div id="tunScoreN" style="position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:21px;font-weight:800;color:#0f1b33"><?= (int)$sc['score'] ?></div>
  </div>
  <div style="flex:1;min-width:0">
    <div style="font-size:14px;font-weight:800;color:#0f1b33">Optimization score &middot; <span id="tunGrade"><?= smpro_h($sc['grade']) ?></span></div>
    <div class="meta" id="tunBreak"><?= (int)$sc['high'] ?> high &middot; <?= (int)$sc['medium'] ?> medium &middot; <?= (int)$sc['low'] ?> low open</div>
    <div class="meta" style="font-size:11px">Apply an optimization &rarr; it disappears here and the score rises.</div>
  </div>
</div>
<div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px">
  <a class="btn" href="index.cgi?page=server-tuning" data-scan>&#128260; Re-scan</a>
  <button class="btn" id="tunBackup">&#128190; Back up all configs now</button>
  <span id="tunMsg" class="meta" style="align-self:center"></span>
</div>

<?php $targets = smpro_tun_targets(); ?>
<div class="card" style="margin-bottom:12px">
  <h2 style="margin:0 0 4px">&#129518; AI optimization</h2>
  <p class="sub" style="margin:0 0 10px">Pick what to optimize. The AI reads this server (engines, versions, cores/RAM, hosted sites, current settings) and proposes the best, safest changes for each. Anything that could lock you out or take a site/service offline is flagged with a clear warning.</p>
  <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:10px">
    <label style="display:inline-flex;align-items:center;gap:6px;font-weight:700;font-size:13px;background:#eef2ff;border:1px solid #c7d2fe;border-radius:9px;padding:6px 11px;cursor:pointer">
      <input type="checkbox" id="tgtAll"> Select all</label>
    <?php foreach ($targets as $tk => $tl): ?>
      <label style="display:inline-flex;align-items:center;gap:6px;font-size:13px;background:#fff;border:1px solid var(--line);border-radius:9px;padding:6px 11px;cursor:pointer">
        <input type="checkbox" class="tgtChk" value="<?= smpro_h($tk) ?>"> <?= smpro_h($tl) ?></label>
    <?php endforeach; ?>
  </div>
  <button class="btn" id="tunAi" style="background:var(--brand);color:#fff">&#9889; Analyze &amp; optimize selected (AI)</button>
  <span id="tunAiMsg" class="meta" style="margin-left:10px"></span>
  <div id="tunAiOut" style="margin-top:12px"></div>
</div>

<?php if (!$scan['recs']): ?>
  <div class="card"><b style="color:#047857">&#10003; No issues found — your engines are well configured.</b></div>
<?php else: foreach ($byEngine as $eng => $recs): $lbl = $scan['engines'][$eng]['label'] ?? $eng; ?>
  <div class="card" style="margin-bottom:12px" data-engine="<?= smpro_h($eng) ?>">
    <h2 style="margin:0 0 8px"><?= smpro_h($lbl) ?> <span class="meta" style="font-weight:600" data-engcount>(<?= count($recs) ?>)</span></h2>
    <?php foreach ($recs as $r): $auto = in_array($r['id'], $autoIds, true); ?>
      <div data-rec="<?= smpro_h($r['id']) ?>" data-sev="<?= smpro_h($r['sev']) ?>" data-w="<?= (int)($scW[$r['sev']] ?? 4) ?>" style="border-left:4px solid <?= $sevColor[$r['sev']] ?? '#64748b' ?>;padding:8px 12px;margin-bottom:8px;background:rgba(255,255,255,.45);border-radius:8px">
        <div style="display:flex;justify-content:space-between;gap:8px;align-items:center">
          <b><?= smpro_h($r['title']) ?></b>
          <span style="font-size:10.5px;font-weight:900;color:<?= $r['type'] === 'security' ? '#b91c1c' : '#0369a1' ?>"><?= strtoupper($r['type']) ?> · <?= strtoupper($r['sev']) ?></span>
        </div>
        <div style="font-size:12.5px;color:#475569;margin:4px 0"><?= smpro_h($r['rationale']) ?></div>
        <div style="font-size:12px"><span style="color:#94a3b8">now:</span> <code><?= smpro_h($r['current'] ?: '—') ?></code> &#8594; <span style="color:#16a34a">recommended:</span> <code><?= smpro_h($r['recommended']) ?></code></div>
        <?php if (!empty($r['access_risk'])): ?><div style="margin-top:6px;background:#fef2f2;border:1px solid #fecaca;color:#b91c1c;border-radius:8px;padding:6px 10px;font-size:12px">&#9888; <b>Can make the server/SSH inaccessible.</b> <?= smpro_h($r['warn'] ?? '') ?></div><?php endif; ?>
        <div style="margin-top:6px">
          <?php if ($r['id'] === 'csf_install'): ?>
            <div style="font-size:11.5px;color:#475569;margin-bottom:6px">Installs the <code>cpanel-csf</code> package: <code>dnf install cpanel-csf</code> (AlmaLinux/CloudLinux/Rocky) or <code>apt install cpanel-csf</code> (Ubuntu) — <b>not</b> <code>csf</code>.</div>
            <button class="btn" style="padding:4px 10px;font-size:12px;background:#16a34a;color:#fff" onclick="tunInstallCsf(this)">&#11015; Install CSF now</button>
          <?php elseif ($auto): ?>
            <button class="btn" style="padding:4px 10px;font-size:12px;background:#16a34a;color:#fff" onclick="tunApply('<?= smpro_h($r['id']) ?>',this)">Apply (backup first)</button>
          <?php else: ?>
            <span style="font-size:11.5px;color:#b45309">&#9888; cPanel-managed — apply via WHM (advisory)</span>
          <?php endif; ?>
        </div>
      </div>
    <?php endforeach; ?>
  </div>
<?php endforeach; endif; ?>

<div class="card" style="margin-bottom:12px"><h3 style="margin:0 0 8px">&#128190; Config backups (by date)</h3>
  <?php $bks = smpro_tun_backups(); if (!$bks): ?><p class="meta">No backups yet — click “Back up all configs now”.</p>
  <?php else: ?><table style="width:100%"><tr><th style="text-align:left">When</th><th style="text-align:left">Files</th></tr>
    <?php foreach ($bks as $b): ?><tr><td><?= smpro_h(date('Y-m-d H:i', (int)$b['ts'])) ?></td><td style="font-size:12px;color:#475569"><?= smpro_h(implode(', ', array_map('basename', $b['files']))) ?></td></tr><?php endforeach; ?>
  </table><?php endif; ?>
</div>

<div class="card"><h3 style="margin:0 0 8px">&#128203; Applied profiles (what was changed)</h3>
  <?php $profs = smpro_tun_profiles(); if (!$profs): ?><p class="meta">No changes applied yet.</p>
  <?php else: foreach ($profs as $p): ?>
    <div style="border-bottom:1px solid rgba(148,163,184,.25);padding:6px 0"><b><?= smpro_h(date('Y-m-d H:i', (int)$p['ts'])) ?></b>
      <?php foreach ($p['changes'] as $ch): ?><div style="font-size:12.5px;color:#475569">&#8226; [<?= smpro_h($ch['engine']) ?>] <?= smpro_h($ch['change']) ?> <span style="color:#94a3b8">(was: <?= smpro_h($ch['from'] ?: '—') ?>)</span></div><?php endforeach; ?>
    </div>
  <?php endforeach; endif; ?>
</div>

<script>(function(){
  function P(id){return document.getElementById(id);}
  function call(extra){var fd=new URLSearchParams();fd.set('smpro_csrf',TUN_CSRF);Object.keys(extra).forEach(function(k){fd.set(k,extra[k]);});
    return fetch('index.cgi?tuning=1',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'}).then(function(r){return r.json();});}
  function msg(t,c){P('tunMsg').innerHTML=t;P('tunMsg').style.color=c||'#475569';}
  P('tunBackup').addEventListener('click',function(){var b=this;b.disabled=true;msg('Backing up…');call({tun_action:'backup'}).then(function(j){b.disabled=false;if(j&&j.ok){msg('&#10003; Backed up '+(j.files||0)+' config file(s). Reload to see it.','#047857');}else{msg('Backup failed','#b91c1c');}});});
  function tunScoreRender(){var n=P('tunScoreN');if(n)n.textContent=TUN_SCORE;var ring=P('tunRing');var clr=TUN_SCORE>=85?'#16a34a':(TUN_SCORE>=70?'#0ea5b7':(TUN_SCORE>=50?'#b45309':'#b91c1c'));if(ring){ring.setAttribute('stroke-dashoffset',(TUN_CIRC*(1-TUN_SCORE/100)).toFixed(1));ring.setAttribute('stroke',clr);}var g=P('tunGrade');if(g)g.textContent=TUN_SCORE>=85?'A':(TUN_SCORE>=70?'B':(TUN_SCORE>=50?'C':'D'));var b=P('tunBreak');if(b)b.textContent=TUN_H+' high · '+TUN_M+' medium · '+TUN_L+' low open';}
  function tunBump(card){if(!card)return;var w=+(card.getAttribute('data-w')||0),sev=card.getAttribute('data-sev');TUN_SCORE=Math.min(100,TUN_SCORE+w);if(sev==='high')TUN_H=Math.max(0,TUN_H-1);else if(sev==='medium')TUN_M=Math.max(0,TUN_M-1);else TUN_L=Math.max(0,TUN_L-1);tunScoreRender();var eng=card.closest('[data-engine]');card.style.transition='opacity .35s ease,transform .35s ease';card.style.opacity='0';card.style.transform='translateX(10px)';setTimeout(function(){card.parentNode&&card.remove();if(eng){var left=eng.querySelectorAll('[data-rec]').length;var cnt=eng.querySelector('[data-engcount]');if(cnt)cnt.textContent='('+left+')';if(!left)eng.remove();}},370);}
  window.tunApply=function(id,btn){if(!confirm('Apply this change? The current config is backed up first and recorded as a profile.'))return;btn.disabled=true;btn.textContent='Applying…';
    call({tun_action:'apply',rec:id}).then(function(j){if(j&&j.ok){msg('&#10003; '+(j.applied||'applied')+(j.note?' — '+j.note:''),'#047857');tunBump(btn.closest('[data-rec]'));}else{btn.textContent='Apply (backup first)';btn.disabled=false;msg('✗ '+((j&&j.msg)||'failed'),'#b91c1c');}});};

  function esc(s){return (s==null?'':String(s)).replace(/[&<>"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
  window.tunInstallCsf=function(btn){if(!confirm('Install CSF now? It installs the cpanel-csf package and starts in TESTING mode (it does NOT block anything yet — nothing is locked out).'))return;
    btn.disabled=true;var o=btn.innerHTML;btn.innerHTML='Installing… (up to ~1 min)';msg('Installing cpanel-csf…');
    call({tun_action:'install',target:'csf'}).then(function(j){btn.disabled=false;btn.innerHTML=o;
      if(j&&j.ok){btn.style.display='none';msg('&#10003; '+esc(j.msg||'CSF installed'),'#047857');}
      else{msg('&#10007; '+esc((j&&j.msg)||'install failed')+(j&&j.cmd?(' — manual: '+esc(j.cmd)):''),'#b91c1c');}
    }).catch(function(){btn.disabled=false;btn.innerHTML=o;msg('Request failed.','#b91c1c');});};
  var chks=[].slice.call(document.querySelectorAll('.tgtChk'));
  var all=P('tgtAll'); if(all)all.addEventListener('change',function(){chks.forEach(function(c){c.checked=all.checked;});});
  function selected(){return chks.filter(function(c){return c.checked;}).map(function(c){return c.value;});}
  var sev={high:'#b91c1c',medium:'#b45309',low:'#0f766e'};
  function aimsg(t,c){P('tunAiMsg').innerHTML=t;P('tunAiMsg').style.color=c||'#475569';}
  P('tunAi').addEventListener('click',function(){var t=selected();if(!t.length){aimsg('Select at least one target above.','#b45309');return;}
    var b=this;b.disabled=true;var o=b.innerHTML;b.innerHTML='&#129518; Analysing this server…';aimsg('');
    P('tunAiOut').innerHTML='<div class="sm-scanbar"><span></span></div><div class="sm-scanning">Reading engines, versions, cores/RAM &amp; current settings…</div>';
    call({tun_action:'aioptimize',targets:t.join(',')}).then(function(j){b.disabled=false;b.innerHTML=o;
      if(!j||!j.ok){aimsg('✗ '+((j&&j.msg)||'AI failed'),'#b91c1c');return;}
      aimsg('✓ '+j.count+' recommendation(s)'+(j.provider?' · '+esc(j.provider):''),'#047857');
      var html='';
      j.recs.forEach(function(r){
        html+='<div style="border-left:4px solid '+(sev[r.sev]||'#64748b')+';padding:8px 12px;margin-bottom:8px;background:rgba(255,255,255,.55);border-radius:8px">';
        html+='<div style="display:flex;justify-content:space-between;gap:8px;align-items:center"><b>'+esc(r.title)+'</b><span style="font-size:10.5px;font-weight:900;color:'+(r.type==="security"?"#b91c1c":"#0369a1")+'">'+esc((r.engine||"").toUpperCase())+' · '+esc((r.sev||"").toUpperCase())+'</span></div>';
        if(r.rationale)html+='<div style="font-size:12.5px;color:#475569;margin:4px 0">'+esc(r.rationale)+'</div>';
        if(r.current||r.recommended)html+='<div style="font-size:12px"><span style="color:#94a3b8">now:</span> <code>'+esc(r.current||"—")+'</code> &#8594; <span style="color:#16a34a">recommended:</span> <code>'+esc(r.recommended||"")+'</code></div>';
        if(r.access_risk)html+='<div style="margin-top:6px;background:#fef2f2;border:1px solid #fecaca;color:#b91c1c;border-radius:8px;padding:6px 10px;font-size:12px">&#9888; <b>Can make the server/SSH inaccessible.</b> '+esc(r.warn||"")+'</div>';
        html+='<div style="font-size:11px;color:#94a3b8;margin-top:5px">AI suggestion — review &amp; apply via WHM. Not auto-changed.</div>';
        html+='</div>';
      });
      P('tunAiOut').innerHTML=html||'<p class="meta">No suggestions.</p>';
    }).catch(function(){b.disabled=false;b.innerHTML=o;aimsg('Request failed.','#b91c1c');});});
})();</script>
<?php
smpro_layout_footer();
