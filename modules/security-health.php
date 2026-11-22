<?php
/**
 * modules/security-health.php - interactive security posture scan + safe apply.
 * Each check shows Risk / Recommended action / Validation / Evidence.
 * Fixable checks expose an "Apply Fix" (POST+CSRF+root): config is backed up,
 * SSH changes are validated with `sshd -t` BEFORE reload (no lock-out) and
 * auto-reverted on failure. Service-restart fixes warn about downtime.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

// The checks and appliers live in includes/sechealth.php (shared with the scheduled scan worker).
require_once __DIR__ . '/../includes/sechealth.php';

/* ---- POST: apply a fix (CSRF + root) ---- */
$reqMethod = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));
if ($reqMethod === 'POST' && ($_POST['sh_apply'] ?? '') !== '') {
    smpro_require_valid_csrf('sh_apply');
    smpro_require_root();
    $id = preg_replace('/[^a-z_]/', '', (string)$_POST['sh_apply']);
    $spec = smpro_sh_fixspec()[$id] ?? null;
    if (!$spec) { echo json_encode(['ok' => false, 'msg' => 'unknown fix']); exit; }
    @ignore_user_abort(true); @set_time_limit(600);   // a started fix finishes even if the page is closed
    if ($spec['type'] === 'shh') [$ok, $msg] = smpro_shh_apply($id);
    elseif ($spec['type'] === 'sshd') [$ok, $msg] = smpro_sh_apply_sshd($spec['key'], $spec['val']);
    elseif ($spec['type'] === 'mycnf') [$ok, $msg] = smpro_sh_apply_mycnf($spec['key'], $spec['val']);
    else { $ok = false; $msg = 'unsupported'; }
    if ($ok && function_exists('smpro_cache_bust')) smpro_cache_bust('sh_scan');   // reload shows the fix's effect immediately
    smpro_audit('security_health_apply', ['fix' => $id, 'ok' => $ok, 'actor' => smpro_current_actor()]);
    echo json_encode(['ok' => $ok, 'msg' => $msg], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

/* ---- POST: undo one hardening fix (or every one), or apply every safe open fix at once ---- */
if ($reqMethod === 'POST' && (($_POST['sh_undo'] ?? '') !== '' || ($_POST['sh_apply_all'] ?? '') !== '')) {
    smpro_require_valid_csrf('sh_apply');
    smpro_require_root();
    @ignore_user_abort(true); @set_time_limit(900);
    if (($_POST['sh_undo'] ?? '') !== '') {
        $id = preg_replace('/[^a-z_]/', '', (string)$_POST['sh_undo']);
        [$ok, $msg] = smpro_shh_undo($id === 'all' ? '' : $id);
        smpro_audit('security_health_undo', ['fix' => $id, 'ok' => $ok, 'actor' => smpro_current_actor()]);
    } else {
        // only fixes whose check is open right now, and never the ones marked danger (lock-out / DB restart)
        $spec = smpro_sh_fixspec(); $open = [];
        foreach (smpro_sh_all() as $checks) foreach ($checks as $c) if ($c['fix'] !== '' && isset($spec[$c['fix']]) && empty($spec[$c['fix']]['danger']) && $c['fix'] !== 'ssh_rootlogin') $open[$c['fix']] = true;
        $done = []; $bad = [];
        foreach (array_keys($open) as $id) {
            $s = $spec[$id];
            [$ok1, $m1] = $s['type'] === 'shh' ? smpro_shh_apply($id) : ($s['type'] === 'sshd' ? smpro_sh_apply_sshd($s['key'], $s['val']) : [false, 'skipped']);
            if ($ok1) $done[] = $id; else $bad[] = $id . ': ' . $m1;
        }
        $ok = !$bad; $msg = $open ? count($done) . ' fix(es) applied' . ($bad ? '; not applied: ' . implode(' | ', $bad) : '') : 'Nothing to apply — every safe fix is already in place.';
        smpro_audit('security_health_apply_all', ['done' => $done, 'failed' => count($bad), 'actor' => smpro_current_actor()]);
    }
    if (function_exists('smpro_cache_bust')) smpro_cache_bust('sh_scan');
    echo json_encode(['ok' => $ok, 'msg' => $msg], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

/** A PHP ini setting as reported by every interpreter that ACTUALLY serves websites, keyed by version.
 *  A bare `php` resolves to cPanel's own bundled build (/usr/local/bin/php). That interpreter serves no
 *  customer site and is not what MultiPHP INI Editor hardens, so reading it answered the wrong question on
 *  every cPanel server - it could report a hardened box as unhardened, or an unhardened box as fine, purely
 *  by coincidence. Falls back to whatever `php` exists only when no EA-PHP is installed. Empty array = no
 *  interpreter could be read, which the caller must render as "unknown", never as a pass. */
// smpro_sh_all() runs php -i twice + recursive Apache-config greps + ss/sshd/mysql probes - too heavy for
// every render (incl. the post-Apply reload). Cache it; the apply handler busts the cache so a fix shows
// its effect immediately on reload.
$cats = smpro_cache_through('sh_scan', 120, fn() => smpro_sh_all());
$total = 0; $okN = 0; $infoN = 0; $warnN = 0; $critN = 0;
foreach ($cats as $checks) foreach ($checks as $c) { $total++;
    if ($c['status']==='ok') $okN++; elseif ($c['status']==='info') $infoN++; elseif ($c['status']==='warning') $warnN++; elseif ($c['status']==='critical') $critN++; }
$score = max(0, 100 - $warnN * 3 - $critN * 12);
$risk = $critN > 0 ? ['Critical', 'danger'] : ($warnN >= 5 ? ['Warning', 'warn'] : ($warnN > 0 ? ['Review', 'warn'] : ['Good', 'good']));

smpro_audit('security_health_view', ['score' => $score, 'warnings' => $warnN, 'critical' => $critN]);

smpro_layout_header('Security Health');
$fixspec = smpro_sh_fixspec();
function smpro_sh_badge($s) { $m = ['ok'=>['good','OK'],'info'=>['blue','INFO'],'warning'=>['warn','WARNING'],'critical'=>['danger','CRITICAL']]; [$c,$t]=$m[$s]??['gray',strtoupper($s)]; return '<span class="shb '.$c.'">'.$t.'</span>'; }
?>
<h1 class="h">Security Health</h1>
<p class="sub">Interactive security posture scan. Click any check for the risk, recommended action, validation steps and evidence. Fixable items can be applied safely.</p>

<div class="card sh-note">&#9889; <b>Interactive fixes:</b> applying a fix backs up the config first, and SSH changes are validated with <code>sshd -t</code> before reload (no lock-out, existing sessions kept). Service-restart fixes are shown as manual commands and clearly warn about downtime.</div>

<?php
// overview strip + navigator: one chip per category; the Critical / Warnings tiles open the first category holding one
$shCatId = function ($cat) { return 'sh-cat-' . trim(preg_replace('/[^a-z0-9]+/', '-', strtolower($cat)), '-'); };
$shFirst = ['critical' => '', 'warning' => '']; $shCatN = ['critical' => [], 'warning' => []];
foreach ($cats as $shCat => $shChecks) foreach ($shChecks as $shC) {
    if (!isset($shFirst[$shC['status']])) continue;
    if ($shFirst[$shC['status']] === '') $shFirst[$shC['status']] = $shCatId($shCat);
    $shCatN[$shC['status']][$shCat] = ($shCatN[$shC['status']][$shCat] ?? 0) + 1;
}
$shFirstCat = $cats ? $shCatId(array_key_first($cats)) : '';
$shKpis = [
  [$shFirstCat,                            'Security Score', (int)$score . '/100',                 $score >= 80 ? 'good' : ($score >= 60 ? 'warn' : 'dang'), '100 − 3/warning − 12/critical'],
  [$shFirstCat,                            'Overall Risk',   $risk[0],                             $risk[1] === 'danger' ? 'dang' : $risk[1],               $critN ? 'critical findings present' : ($warnN ? 'warnings to review' : 'nothing open')],
  [$shFirst['critical'] ?: $shFirstCat,    'Critical',       (string)(int)$critN,                  $critN ? 'dang' : 'good',                                 $critN ? count($shCatN['critical']) . ' categor' . (count($shCatN['critical']) === 1 ? 'y' : 'ies') : 'none'],
  [$shFirst['warning'] ?: $shFirstCat,     'Warnings',       (string)(int)$warnN,                  $warnN ? 'warn' : 'good',                                 $warnN ? count($shCatN['warning']) . ' categor' . (count($shCatN['warning']) === 1 ? 'y' : 'ies') : 'none'],
  [$shFirstCat,                            'OK / Info',      (int)$okN . ' / ' . (int)$infoN,      'brand',                                                  'passed / informational'],
  [$shFirstCat,                            'Total Checks',   (string)(int)$total,                  'muted',                                                  count($cats) . ' categories · cached 2 min'],
];
?>
<div class="fw-kpis">
  <?php foreach ($shKpis as $k): ?>
  <a class="fw-kpi <?= $k[3] ?>" href="#<?= smpro_h($k[0]) ?>" data-go="<?= smpro_h($k[0]) ?>"><div class="l"><?= smpro_h($k[1]) ?></div><div class="v"><?= smpro_h($k[2]) ?></div><div class="s"><?= smpro_h($k[4]) ?></div></a>
  <?php endforeach; ?>
</div>
<nav class="fw-nav" id="shNav"><?php foreach ($cats as $shCat => $shChecks): ?><a href="#<?= smpro_h($shCatId($shCat)) ?>" data-go="<?= smpro_h($shCatId($shCat)) ?>"><?= smpro_h($shCat) ?><?php if (!empty($shCatN['critical'][$shCat])): ?> <span class="shb danger"><?= (int)$shCatN['critical'][$shCat] ?></span><?php elseif (!empty($shCatN['warning'][$shCat])): ?> <span class="shb warn"><?= (int)$shCatN['warning'][$shCat] ?></span><?php endif; ?></a><?php endforeach; ?><span class="sp"></span><button type="button" class="fw-navx" id="shOpenAll">expand all</button><button type="button" class="fw-navx" id="shCloseAll">collapse all</button></nav>
<?php
$shUndoable = smpro_shh_undoable();
$shUndoMap = ['Kernel network & info-leak settings' => 'kernel_harden', '/dev/shm noexec' => 'shm_noexec', 'PHP allow_url_include' => 'php_urlinclude',
              'CSF/LFD attack detection' => 'csf_harden', 'Outgoing mail caps' => 'mail_caps', 'Imunify360 protection settings' => 'imunify_harden'];
$shSafeOpen = 0; foreach ($cats as $shChecks) foreach ($shChecks as $shC) if ($shC['fix'] !== '' && isset($fixspec[$shC['fix']]) && empty($fixspec[$shC['fix']]['danger']) && $shC['fix'] !== 'ssh_rootlogin') $shSafeOpen++;
?>
<div class="card sh-bulk">
  <div><b>Server hardening</b> &mdash; <?= $shSafeOpen ? (int)$shSafeOpen . ' safe fix(es) open.' : 'every safe fix is in place.' ?> Each change is backed up and can be undone one by one or all together. Root key-only SSH and database restarts are never applied in bulk.</div>
  <div class="sh-bulkbtns">
    <button type="button" class="sh-applybtn" id="shApplyAll"<?= $shSafeOpen ? '' : ' disabled' ?>>&#9889; Apply all safe fixes<?= $shSafeOpen ? ' (' . (int)$shSafeOpen . ')' : '' ?></button>
    <?php if ($shUndoable): ?><button type="button" class="sh-act" id="shUndoAll">&#8630; Roll back all (<?= count($shUndoable) ?>)</button><?php endif; ?>
  </div>
</div>
<script>var SH_CSRF=<?= json_encode(smpro_csrf_generate('sh_apply')) ?>;</script>

<div class="sh-cats">
  <?php foreach ($cats as $cat => $checks): ?>
  <div class="card sh-cat" id="<?= smpro_h($shCatId($cat)) ?>">
    <div class="sh-cathead"><b><?= smpro_h($cat) ?></b><span class="sh-n"><?= count($checks) ?></span><?php if (!empty($shCatN['critical'][$cat])): ?><span class="shb danger"><?= (int)$shCatN['critical'][$cat] ?> critical</span><?php endif; ?><?php if (!empty($shCatN['warning'][$cat])): ?><span class="shb warn"><?= (int)$shCatN['warning'][$cat] ?> warn</span><?php endif; ?></div>
    <?php foreach ($checks as $i => $c): $tid = 'sh-' . md5($cat . $i); $applyable = $c['fix'] !== '' && isset($fixspec[$c['fix']]); ?>
      <div class="sh-check <?= $c['status'] ?>">
        <div class="sh-row" data-t="<?= $tid ?>">
          <?= smpro_sh_badge($c['status']) ?>
          <div class="sh-title"><?= smpro_h($c['title']) ?><div class="sh-finding"><?= smpro_h($c['finding']) ?></div></div>
          <?php /* the row button only OPENS the panel; it says "Fix" only when a one-click fix really sits inside, "How to fix" when the panel holds instructions only */ ?>
          <button class="sh-act" type="button" data-t="<?= $tid ?>"<?= $applyable ? ' data-hasfix="1"' : '' ?>><?= $c['status']==='ok'?'Details':($c['status']==='info'?'Review':($applyable?'&#9889; Fix':'How to fix')) ?></button>
        </div>
        <div class="sh-detail" id="<?= $tid ?>">
          <div class="sh-kv"><span>Risk</span><?= smpro_h($c['risk']) ?></div>
          <div class="sh-rec"><span>Recommended action</span><?= smpro_h($c['rec']) ?></div>
          <div class="sh-kv"><span>Validation</span>Re-run Security Health after any change to confirm the status flips to OK.</div>
          <?php if ($c['manual'] !== ''): ?><div class="sh-cmd"><span>Manual command</span><code><?= smpro_h($c['manual']) ?></code></div><?php endif; ?>
          <?php if ($c['evidence'] !== ''): ?><div class="sh-ev"><button type="button" class="sh-evbtn" data-t="<?= $tid ?>-ev">Evidence</button><pre id="<?= $tid ?>-ev" class="sh-evbox"><?= smpro_h(trim($c['evidence'])) ?></pre></div><?php endif; ?>
          <?php if ($applyable): ?>
            <div class="sh-apply">
              <button type="button" class="sh-applybtn<?= !empty($fixspec[$c['fix']]['danger'])?' danger':'' ?>" data-fix="<?= smpro_h($c['fix']) ?>" data-risk="<?= smpro_h($fixspec[$c['fix']]['risk']) ?>" data-desc="<?= smpro_h($fixspec[$c['fix']]['key'].' = '.$fixspec[$c['fix']]['val']) ?>">&#9889; Apply this fix</button>
              <span class="sh-applynote"><?= smpro_h($fixspec[$c['fix']]['risk']) ?></span>
            </div>
          <?php endif; ?>
          <?php $shUid = $shUndoMap[$c['title']] ?? ''; if ($shUid !== '' && isset($shUndoable[$shUid])): ?>
            <div class="sh-apply"><button type="button" class="sh-act" data-undo="<?= smpro_h($shUid) ?>">&#8630; Undo this change</button><span class="sh-applynote">Puts back the exact previous state saved when the fix was applied.</span></div>
          <?php endif; ?>
        </div>
      </div>
    <?php endforeach; ?>
  </div>
  <?php endforeach; ?>
</div>

<style>
.sh-note{background:var(--brand-bg);color:#26408b;font-size:13px;margin-bottom:14px;border-left:4px solid var(--brand);line-height:1.6}
.sh-score{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:14px}
@media(max-width:1100px){.sh-score{grid-template-columns:repeat(3,1fr)}}@media(max-width:600px){.sh-score{grid-template-columns:repeat(2,1fr)}}
.sh-sc{padding:14px 16px}.sh-sc .lbl{font-size:11px;color:var(--muted);text-transform:uppercase;font-weight:700}.sh-sc .v{font-size:24px;font-weight:800;margin-top:6px}
.sh-cats{display:grid;grid-template-columns:1fr 1fr;gap:14px}@media(max-width:900px){.sh-cats{grid-template-columns:1fr}}
.sh-cat{padding:0;overflow:hidden}
.sh-cathead{padding:12px 16px;border-bottom:1px solid var(--line);font-weight:700;font-size:14px}.sh-cathead .meta{color:var(--muted);font-weight:400;font-size:12px}
.sh-check{border-bottom:1px solid var(--line)}.sh-check:last-child{border-bottom:0}
.sh-row{display:flex;align-items:flex-start;gap:10px;padding:11px 16px;cursor:pointer}.sh-row:hover{background:var(--card)}
.sh-check.warning .sh-row{background:var(--card)}.sh-check.critical .sh-row{background:var(--dang-bg)}
.sh-title{flex:1;font-size:13px;font-weight:600}.sh-finding{font-weight:400;color:var(--muted);font-size:12px;margin-top:2px}
.sh-act{font-size:11px;font-weight:600;border:1px solid var(--line);background:var(--card);border-radius:7px;padding:4px 12px;cursor:pointer;color:var(--brand);white-space:nowrap}.sh-act:hover{background:var(--brand-bg)}
.sh-detail{display:none;padding:4px 16px 14px}.sh-detail.open{display:block}
.sh-kv,.sh-rec,.sh-cmd{font-size:12px;line-height:1.6;margin-top:9px}
.sh-kv span,.sh-rec span,.sh-cmd span{display:block;font-size:10px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);font-weight:700;margin-bottom:1px}
.sh-rec{background:var(--card);border:1px solid var(--line);border-left:3px solid var(--brand);border-radius:8px;padding:9px 11px}.sh-rec span{color:var(--brand)}
.sh-cmd code{display:block;background:#0f172a;color:#e5e7eb;border-radius:8px;padding:9px 11px;font-size:12px;white-space:pre-wrap;word-break:break-word}
.sh-evbtn{font-size:11px;font-weight:600;border:1px solid var(--line);background:var(--card);border-radius:7px;padding:3px 10px;cursor:pointer;color:var(--brand);margin-top:9px}
.sh-evbox{display:none;background:#0f172a;color:#e5e7eb;border-radius:8px;padding:10px;font-size:11px;white-space:pre-wrap;word-break:break-word;margin-top:6px}
.sh-evbox.open{display:block}
.sh-apply{margin-top:10px;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.sh-applybtn{font-size:12px;font-weight:700;border:0;border-radius:8px;padding:8px 14px;cursor:pointer;background:var(--good);color:#fff}.sh-applybtn:hover{filter:brightness(.95)}
.sh-applybtn.danger{background:var(--dang)}
.sh-applynote{font-size:11px;color:var(--muted)}
.sh-bulk{display:flex;gap:14px;align-items:center;justify-content:space-between;flex-wrap:wrap;font-size:13px;margin-bottom:14px}
.sh-bulkbtns{display:flex;gap:8px;flex-wrap:wrap}.sh-applybtn[disabled]{opacity:.5;cursor:default}
.shb{display:inline-block;font-size:10px;font-weight:800;padding:2px 8px;border-radius:20px;min-width:64px;text-align:center;margin-top:1px}
.shb.good{background:var(--good-bg);color:var(--good)}.shb.blue{background:var(--brand-bg);color:var(--brand)}.shb.warn{background:var(--warn-bg);color:var(--warn)}.shb.danger{background:var(--dang-bg);color:var(--dang)}
.pill{display:inline-block;font-size:12px;font-weight:700;padding:3px 12px;border-radius:20px}
.pill.good{background:var(--good-bg);color:var(--good)}.pill.warn{background:var(--warn-bg);color:var(--warn)}.pill.danger{background:var(--dang-bg);color:var(--dang)}
.meta{color:var(--muted)}
/* ---- overview strip / navigator / collapsible cards (pattern: firewall-status.php) ---- */
/* .fw-kpis / .fw-nav / .fw-collapse / pager styles: shared, in includes/layout.php */
.sh-cathead{cursor:pointer}.sh-cathead .sh-n{font-size:11.5px;font-weight:800;padding:1px 8px;border-radius:999px;background:var(--brand-bg);color:var(--brand);margin-left:4px}
.sh-cathead .shb{margin-left:4px;min-width:0}
@media print{.fw-nav{display:none!important}}
.sh-applybtn.sh-flash{box-shadow:0 0 0 4px var(--brand-bg);outline:2px solid var(--brand)}
</style>
<script>
(function(){
  function toggle(tid){var d=document.getElementById(tid);if(!d)return;d.classList.toggle('open');
    var b=document.querySelector('.sh-act[data-t="'+tid+'"]');if(b){if(b.dataset.lbl===undefined)b.dataset.lbl=b.textContent;b.textContent=d.classList.contains('open')?'Hide':b.dataset.lbl;
      /* a "Fix" row opened: bring the one-click Apply button into view and flash it, so the next click is the fix itself */
      if(b.dataset.hasfix&&d.classList.contains('open')){var ap=d.querySelector('.sh-applybtn');if(ap){ap.scrollIntoView({behavior:'smooth',block:'center'});ap.classList.add('sh-flash');setTimeout(function(){ap.classList.remove('sh-flash');},1800);}}}}
  document.addEventListener('click',function(e){
    var ev=e.target.closest('.sh-evbtn');if(ev){var x=document.getElementById(ev.getAttribute('data-t'));if(x)x.classList.toggle('open');return;}
    var ap=e.target.closest('.sh-applybtn');if(ap){applyFix(ap);return;}
    var row=e.target.closest('[data-t]');if(row&&!e.target.closest('.sh-evbtn')&&!e.target.closest('.sh-applybtn'))toggle(row.getAttribute('data-t'));});
  function shPost(field,val,btn,label,confirmTxt){
    if(!confirm(confirmTxt))return;
    btn.disabled=true;var t0=btn.textContent;btn.textContent=label;
    var fd=new URLSearchParams();fd.set(field,val);fd.set('smpro_csrf',SH_CSRF);
    fetch('index.cgi?page=security-health',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'})
      .then(function(r){return r.json();}).then(function(j){alert(((j&&j.ok)?'Done: ':'Not complete: ')+((j&&j.msg)||'error')+'\n\nReloading to re-scan…');location.reload();})
      .catch(function(){btn.disabled=false;btn.textContent=t0;alert('Failed (network/permission). A started change still finishes on the server; reload in a minute.');});
  }
  document.addEventListener('click',function(e){
    var b=e.target.closest&&e.target.closest('[data-undo],#shApplyAll,#shUndoAll');if(!b)return;
    if(b.id==='shApplyAll')shPost('sh_apply_all','1',b,'Applying…','Apply every safe fix that is open now?\n\nEach change is backed up first and can be undone. Fixes that can lock you out or restart the database are NOT included.');
    else if(b.id==='shUndoAll')shPost('sh_undo','all',b,'Rolling back…','Put back every server-hardening change made from this page, newest first?');
    else shPost('sh_undo',b.getAttribute('data-undo'),b,'Undoing…','Put back the previous state of this setting?');
  });
  function applyFix(btn){
    var fix=btn.getAttribute('data-fix'),risk=btn.getAttribute('data-risk'),desc=btn.getAttribute('data-desc');
    if(!confirm('Apply fix: '+desc+'\n\n'+risk+'\n\nA backup is taken first. Continue?'))return;
    btn.disabled=true;btn.textContent='Applying…';
    var fd=new URLSearchParams();fd.set('sh_apply',fix);fd.set('smpro_csrf',SH_CSRF);
    fetch('index.cgi?page=security-health',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'})
      .then(function(r){return r.json();}).then(function(j){
        btn.disabled=false;
        if(j&&j.ok){btn.textContent='✓ Applied';btn.style.background='var(--good)';alert('Applied: '+(j.msg||'')+'\n\nReloading to re-scan…');location.reload();}
        else{btn.textContent='⚠ Failed';btn.classList.add('danger');alert('Not applied: '+((j&&j.msg)||'error'));}
      }).catch(function(){btn.disabled=false;btn.textContent='⚠ Failed';alert('Failed (network/permission).');});
  }
})();
</script>
<script>
(function(){
  /* collapsible section cards + sticky navigator (pattern: modules/firewall-status.php). The header of every
     card is a real toggle (role=button, keyboard), the open/closed choice is remembered per section. */
  var KEY='smpro:security-health:open', HSEL='.smpro-main .card > .sh-cathead', PFX='sh', open={};
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
