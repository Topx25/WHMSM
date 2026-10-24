<?php
/**
 * modules/server-tuning.php - Server Tune-up: scan engines, recommend perf/security improvements,
 * back up configs (timestamped), and record a profile of applied changes. Apply via ?tuning=1.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

/* ---------- Hide "Server Information" (cPanel "Server Status Viewer", feature key `serverstatus`) from customer
 *            cPanel - the page that lists server name, OS, cPanel/Apache/MySQL/PHP versions and the IP. This is
 *            what Feature Manager toggles; we set serverstatus=0 in every feature list. Reversible; each list is
 *            backed up first. Unknown keys in a feature list are ignored by cPanel, so this can never break it. ---------- */
function smpro_cphide_dir() { return '/var/cpanel/features'; }
function smpro_cphide_lists() {
    $out = [];
    foreach (glob(smpro_cphide_dir() . '/*') ?: [] as $f) {
        if (!is_file($f)) continue;
        $b = basename($f);
        if ($b === '' || $b[0] === '.' || $b === 'disabled' || substr($b, -1) === '~' || strpos($b, '.smprobak') !== false) continue;
        $out[] = $f;                                            // a real feature list (skip the special "disabled" file + backups/dotfiles)
    }
    return $out;
}
function smpro_cphide_status() {
    if (!is_dir(smpro_cphide_dir())) return ['available' => false, 'total' => 0, 'hidden' => 0, 'all_hidden' => false];
    $lists = smpro_cphide_lists(); $hidden = 0;
    foreach ($lists as $f) if (preg_match('/^serverstatus=0\s*$/m', (string)@file_get_contents($f))) $hidden++;
    return ['available' => true, 'total' => count($lists), 'hidden' => $hidden, 'all_hidden' => ($lists && $hidden === count($lists))];
}
function smpro_cphide_apply($hide) {
    if (!is_dir(smpro_cphide_dir())) return ['ok' => false, 'msg' => 'This is not a cPanel server (no /var/cpanel/features).'];
    $lists = smpro_cphide_lists();
    if (!$lists) return ['ok' => false, 'msg' => 'No cPanel feature lists were found.'];
    $val = $hide ? '0' : '1'; $changed = 0;
    $bakdir = (defined('SMPRO_VARLIB') ? SMPRO_VARLIB : '/var/lib/smpro') . '/cphide_bak/' . date('Ymd_His');
    @is_dir($bakdir) || @mkdir($bakdir, 0700, true);
    foreach ($lists as $f) {
        $c = (string)@file_get_contents($f);
        @copy($f, $bakdir . '/' . basename($f));               // back up the original first
        if (preg_match('/^serverstatus=[01]\s*$/m', $c)) $nc = preg_replace('/^serverstatus=[01]\s*$/m', 'serverstatus=' . $val, $c, 1);
        else $nc = ($c === '' ? '' : rtrim($c, "\r\n") . "\n") . 'serverstatus=' . $val . "\n";
        if ($nc !== $c && @file_put_contents($f, $nc, LOCK_EX) !== false) { @chmod($f, 0644); $changed++; }
    }
    smpro_audit('cphide_serverinfo', ['hide' => $hide ? 1 : 0, 'changed' => $changed, 'lists' => count($lists), 'actor' => smpro_current_actor()]);
    return ['ok' => true, 'changed' => $changed, 'total' => count($lists), 'backup' => $bakdir,
            'msg' => ($hide ? 'Server Information is now HIDDEN from customer cPanel.' : 'Server Information is now VISIBLE in customer cPanel.')
                   . ' Updated ' . $changed . ' of ' . count($lists) . ' feature list(s) — it takes effect on the customer\'s next cPanel page load. Originals backed up.'];
}

$reqMethod = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));
if ($reqMethod === 'POST' && ($_POST['cphide_action'] ?? '') !== '') {
    smpro_require_valid_csrf('tuning'); smpro_require_root();
    header('Content-Type: application/json');
    $a = (string)$_POST['cphide_action'];
    if ($a === 'hide' || $a === 'show') { echo json_encode(smpro_cphide_apply($a === 'hide'), JSON_UNESCAPED_SLASHES); exit; }
    echo json_encode(['ok' => false, 'msg' => 'bad action']); exit;
}

// smpro_tun_scan() is a heavy probe stack (imunify config show, whmapi1, sshd -T, httpd -M x2, php -r x3,
// getent, cagefsctl...). Cache it off the render path; the ?tuning=1 handler busts the cache after any apply/
// restore so the posture reloads fresh.
// A stale copy is shown AT ONCE and refreshed by a detached worker (job 'rescan'); the operator waited twelve seconds
// at every fifth-minute visit before. Only a server with no scan yet (first visit, or right after an apply busted the
// cache) computes inline, because then there is nothing honest to show.
$scan = smpro_cache_through('tun_scan', 300, fn() => smpro_tun_scan(), false);
$scanAge = 0; $scanRefreshing = false;
if ($scan === null) $scan = smpro_cache_through('tun_scan', 300, fn() => smpro_tun_scan());
else {
    $ctf = SMPRO_CACHE . '/ct_tun_scan.json'; $ctj = @is_file($ctf) ? json_decode((string)@file_get_contents($ctf), true) : null;
    $scanAge = time() - (int)($ctj['ts'] ?? time());
    if ($scanAge >= 300) { $rs = smpro_tun_job_start('rescan', []); $scanRefreshing = !empty($rs['ok']); }
}
$csrf = smpro_csrf_generate('tuning');
$byEngine = [];
foreach ($scan['recs'] as $r) $byEngine[$r['engine']][] = $r;
$autoIds = array_keys(smpro_tun_apply_map());
$sc = smpro_tun_score($scan['recs']);
$scW = ['high' => 10, 'medium' => 6, 'low' => 3];
$sevColor = ['high' => '#b91c1c', 'medium' => '#b45309', 'low' => '#0f766e'];
$engLbls = ['access' => "\xF0\x9F\x94\x92 Access Isolation & Jailing"];   // labels for synthetic (non-engine) rec groups
smpro_audit('tuning_view', ['recs' => count($scan['recs'])]);
$aiJob = function_exists('smpro_tun_job_read') ? smpro_tun_job_read('aioptimize') : ['status' => 'idle', 'updated_at' => 0];
$saJob = function_exists('smpro_tun_job_read') ? smpro_tun_job_read('secadvisor') : ['status' => 'idle', 'updated_at' => 0];
$applyJob = function_exists('smpro_tun_job_read') ? smpro_tun_job_read('applyall') : ['status' => 'idle', 'updated_at' => 0];
smpro_layout_header('Server Tune-up');
?>
<script>var TUN_CSRF=<?= json_encode($csrf) ?>,TUN_SCORE=<?= (int)$sc['score'] ?>,TUN_H=<?= (int)$sc['high'] ?>,TUN_M=<?= (int)$sc['medium'] ?>,TUN_L=<?= (int)$sc['low'] ?>,TUN_CIRC=188.5,
AI_JOB=<?= json_encode($aiJob, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE) ?>,SA_JOB=<?= json_encode($saJob, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE) ?>,APPLY_JOB=<?= json_encode($applyJob, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE) ?>;</script>
<div class="svc-kicker">Performance &amp; Security</div>
<h1 class="h" style="margin:2px 0 4px">&#128295; Server Tune-up</h1>
<?php if ($scanRefreshing): ?><div class="card" style="border-left:4px solid var(--brand);padding:8px 14px;margin-bottom:10px;font-size:12.5px">&#8635; This posture is from <b><?= $scanAge >= 3600 ? floor($scanAge / 3600) . ' h ' . floor(($scanAge % 3600) / 60) . ' min' : floor($scanAge / 60) . ' min' ?></b> ago; a fresh scan is running in the background - reload in about a minute for the new one.</div><?php endif; ?>
<p class="sub">Scans your server engines (<?= smpro_h(implode(', ', array_map(fn($e) => $e['label'], $scan['engines']))) ?>) and recommends performance &amp; security improvements. Every apply backs up the config first and records a profile. <b><?= (int)$scan['cores'] ?></b> cores · <b><?= round($scan['ram_mb'] / 1024) ?></b> GB RAM.</p>

<?php $cph = smpro_cphide_status(); if ($cph['available']): ?>
<div class="card cph-card" style="margin-bottom:12px;border-left:4px solid <?= $cph['all_hidden'] ? 'var(--good)' : 'var(--line)' ?>">
  <div class="cph-row">
    <div class="cph-main">
      <b>&#128274; Hide server information from customer cPanel</b>
      <div class="meta cph-desc">Removes the <b>Server Information</b> page (server name, OS, cPanel / Apache / MySQL / PHP versions, IP) from your customers' cPanel — so a customer or an attacker can't read your stack. Applies to all cPanel accounts (via every feature list), reversible, and each list is backed up first.</div>
      <div class="cph-state" id="cphState"><?php
        if ($cph['all_hidden']) echo '<span class="b" style="background:var(--good-bg);color:var(--good)">&#10003; Hidden on all ' . (int)$cph['total'] . ' feature list(s)</span>';
        elseif ($cph['hidden'] > 0) echo '<span class="b" style="background:var(--warn-bg);color:var(--warn)">Hidden on ' . (int)$cph['hidden'] . ' of ' . (int)$cph['total'] . ' — apply to cover the rest</span>';
        else echo '<span class="b" style="background:var(--card);color:var(--muted);border:1px solid var(--line)">Currently VISIBLE to customers on all ' . (int)$cph['total'] . ' feature list(s)</span>';
      ?></div>
    </div>
    <div class="cph-btns">
      <button class="tp-btn primary" id="cphHide" type="button" <?= $cph['all_hidden'] ? 'disabled' : '' ?>>&#128274; Hide it</button>
      <button class="tp-btn" id="cphShow" type="button" <?= $cph['hidden'] == 0 ? 'disabled' : '' ?>>Show it again</button>
    </div>
  </div>
  <div id="cphMsg" class="meta cph-msg"></div>
</div>
<script>(function(){
  function cp(action){var m=document.getElementById('cphMsg');if(m){m.textContent='Working…';m.style.color='';}
    var fd=new URLSearchParams();fd.set('cphide_action',action);fd.set('smpro_csrf',window.TUN_CSRF||'');
    return fetch('index.cgi?page=server-tuning',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'}).then(function(r){return r.json();});}
  function done(j,btn,o){var m=document.getElementById('cphMsg');if(m){m.innerHTML=(j&&j.ok?'✓ ':'✗ ')+String((j&&j.msg)||'Failed').replace(/[&<>]/g,'');m.style.color=(j&&j.ok)?'var(--good)':'var(--dang)';}if(j&&j.ok){setTimeout(function(){location.reload();},1900);}else{btn.disabled=false;btn.innerHTML=o;}}
  var h=document.getElementById('cphHide'),s=document.getElementById('cphShow');
  if(h)h.addEventListener('click',function(){if(!confirm('Hide the Server Information page from ALL customer cPanel accounts?\n\nReversible — each feature list is backed up first.'))return;var o=h.innerHTML;h.disabled=true;h.innerHTML='…';cp('hide').then(function(j){done(j,h,o);}).catch(function(){h.disabled=false;h.innerHTML=o;});});
  if(s)s.addEventListener('click',function(){if(!confirm('Show the Server Information page in customer cPanel again?'))return;var o=s.innerHTML;s.disabled=true;s.innerHTML='…';cp('show').then(function(j){done(j,s,o);}).catch(function(){s.disabled=false;s.innerHTML=o;});});
})();</script>
<style>
.cph-card .cph-row{display:flex;align-items:center;gap:16px;flex-wrap:wrap}
.cph-main{flex:1;min-width:240px}
.cph-desc{margin-top:3px;line-height:1.5}
.cph-state{margin-top:8px}
.cph-btns{display:flex;gap:8px;flex-wrap:wrap}
.cph-msg{margin-top:8px;min-height:16px}
</style>
<?php endif; ?>

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
    <label style="display:inline-flex;align-items:center;gap:6px;font-weight:700;font-size:13px;background:var(--brand-bg);border:1px solid #c7d2fe;border-radius:9px;padding:6px 11px;cursor:pointer">
      <input type="checkbox" id="tgtAll"> Select all</label>
    <?php foreach ($targets as $tk => $tl): ?>
      <label style="display:inline-flex;align-items:center;gap:6px;font-size:13px;background:var(--card);border:1px solid var(--line);border-radius:9px;padding:6px 11px;cursor:pointer">
        <input type="checkbox" class="tgtChk" value="<?= smpro_h($tk) ?>"> <?= smpro_h($tl) ?></label>
    <?php endforeach; ?>
  </div>
  <button class="btn" id="tunAi" style="background:var(--brand);color:#fff">&#9889; Analyze &amp; optimize selected (AI)</button>
  <span id="tunAiMsg" class="meta" style="margin-left:10px"></span>
  <div id="tunAiUpd" class="meta" style="margin-top:6px;font-size:11px"></div>
  <div id="tunApplyProg"></div>
  <div id="tunAiOut" style="margin-top:12px"></div>
</div>

<div class="card" style="margin-bottom:12px" id="tunSaCard">
  <h2 style="margin:0 0 4px">&#128272; cPanel Security Advisor</h2>
  <p class="sub" style="margin:0 0 10px">Fetches WHM's built-in Security Advisor scan. Items that Tune-up can fix automatically (SSH hardening, etc.) show an Apply button; others link to WHM &rsaquo; Security Advisor.</p>
  <button class="btn" id="tunSaScan">&#128270; Scan Security Advisor</button>
  <span id="tunSaMsg" class="meta" style="margin-left:10px"></span>
  <div id="tunSaUpd" class="meta" style="margin-top:6px;font-size:11px"></div>
  <div id="tunSaOut" style="margin-top:12px"></div>
</div>

<?php if (!$scan['recs']): ?>
  <div class="card"><b style="color:#047857">&#10003; No issues found — your engines are well configured.</b></div>
<?php else: foreach ($byEngine as $eng => $recs): $lbl = $scan['engines'][$eng]['label'] ?? ($engLbls[$eng] ?? $eng); ?>
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
        <?php if (!empty($r['access_risk'])): ?><div style="margin-top:6px;background:var(--dang-bg);border:1px solid #fecaca;color:#b91c1c;border-radius:8px;padding:6px 10px;font-size:12px">&#9888; <b>Can make the server/SSH inaccessible.</b> <?= smpro_h($r['warn'] ?? '') ?></div>
        <?php elseif (!empty($r['warn'])): ?><div style="margin-top:6px;background:var(--warn-bg);border:1px solid #f0d8b8;color:#8a5a00;border-radius:8px;padding:6px 10px;font-size:12px">&#9888; <?= smpro_h($r['warn']) ?></div><?php endif; ?>
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
  <?php $bks = smpro_tun_backups(); if (!$bks): ?><p class="meta">No backups yet — click "Back up all configs now".</p>
  <?php else: ?><table style="width:100%;border-collapse:collapse">
    <tr><th style="text-align:left;padding:5px 8px;font-size:11px;text-transform:uppercase;color:#94a3b8">When</th><th style="text-align:left;padding:5px 8px;font-size:11px;text-transform:uppercase;color:#94a3b8">Files backed up</th><th style="padding:5px 8px"></th></tr>
    <?php foreach ($bks as $b):
      $isPreRestore = strpos($b['id'], '_pre') !== false;
    ?><tr style="border-top:1px solid var(--line)">
      <td style="padding:6px 8px;white-space:nowrap;font-size:13px"><?= smpro_h(date('Y-m-d H:i', (int)$b['ts'])) ?><?php if ($isPreRestore): ?> <span class="meta" style="font-size:10px">(pre-restore safeguard)</span><?php endif; ?></td>
      <td style="padding:6px 8px;font-size:12px;color:#475569"><?= smpro_h(implode(', ', array_map('basename', $b['files']))) ?></td>
      <td style="padding:6px 8px;text-align:right"><?php if (!$isPreRestore && $b['files']): ?><button class="btn" style="padding:3px 10px;font-size:12px" onclick="tunRestore('<?= smpro_h($b['id']) ?>',this)">&#8635; Restore</button><?php endif; ?></td>
    </tr><?php endforeach; ?>
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
  window.tunRestore=function(id,btn){
    if(!confirm('Restore configs from backup '+id+'?\n\nThe current config will be saved as a safeguard backup first, then overwritten with the selected snapshot. CSF will be reloaded if its config was included.'))return;
    btn.disabled=true;var o=btn.innerHTML;btn.innerHTML='&#8635; Restoring…';msg('Restoring…');
    call({tun_action:'restore',bk_id:id}).then(function(j){btn.disabled=false;btn.innerHTML=o;
      if(j&&j.ok){msg('&#10003; '+esc(j.msg||'Restored'),'#047857');}
      else{msg('&#10007; '+esc((j&&j.msg)||'Restore failed'),'#b91c1c');}
    }).catch(function(){btn.disabled=false;btn.innerHTML=o;msg('Request failed.','#b91c1c');});};
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
  function tunFmtTs(t){if(!t)return '';try{return new Date(t*1000).toLocaleString();}catch(e){return '';}}
  function aiUpd(t){var el=P('tunAiUpd');if(el)el.textContent=t?('Last updated: '+tunFmtTs(t)):'';}
  var AI_LBL='&#9889; Analyze &amp; optimize selected (AI)';
  function aiRender(j){
    if(!j||!j.ok){aimsg('✗ '+((j&&j.msg)||'AI failed'),'#b91c1c');P('tunAiOut').innerHTML='';return;}
    aimsg('✓ '+j.count+' recommendation(s)'+(j.provider?' · '+esc(j.provider):''),'#047857');
    var applyable=[],html='';(j.recs||[]).forEach(function(r){
      var canApply=r.apply_id&&!r.access_risk;if(canApply)applyable.push(r.apply_id);
      html+='<div data-ai-rec="'+esc(r.apply_id||'')+'" style="border-left:4px solid '+(sev[r.sev]||'#64748b')+';padding:8px 12px;margin-bottom:8px;background:rgba(255,255,255,.55);border-radius:8px">';
      html+='<div style="display:flex;justify-content:space-between;gap:8px;align-items:center"><b>'+esc(r.title)+'</b><span style="font-size:10.5px;font-weight:900;color:'+(r.type==="security"?"#b91c1c":"#0369a1")+'">'+esc((r.engine||"").toUpperCase())+' · '+esc((r.sev||"").toUpperCase())+'</span></div>';
      if(r.rationale)html+='<div style="font-size:12.5px;color:#475569;margin:4px 0">'+esc(r.rationale)+'</div>';
      if(r.current||r.recommended)html+='<div style="font-size:12px"><span style="color:#94a3b8">now:</span> <code>'+esc(r.current||"—")+'</code> &#8594; <span style="color:#16a34a">recommended:</span> <code>'+esc(r.recommended||"")+'</code></div>';
      if(r.access_risk)html+='<div style="margin-top:6px;background:var(--dang-bg);border:1px solid #fecaca;color:#b91c1c;border-radius:8px;padding:6px 10px;font-size:12px">&#9888; <b>Can make the server/SSH inaccessible.</b> '+esc(r.warn||"")+'</div>';
      html+='<div style="margin-top:6px">';
      if(canApply)html+='<button class="btn" style="padding:4px 10px;font-size:12px;background:#16a34a;color:#fff" onclick="aiApplyOne(&quot;'+esc(r.apply_id)+'&quot;,this,0)">&#9654; Apply (backup first)</button>';
      else if(r.apply_id&&r.access_risk)html+='<button class="btn" style="padding:4px 10px;font-size:12px;background:#b45309;color:#fff" onclick="aiApplyOne(&quot;'+esc(r.apply_id)+'&quot;,this,1)">&#9888; Apply this one (access-risk)</button> <span style="font-size:11px;color:#b45309">Not included in “Apply all”</span>';
      else html+='<span style="font-size:11px;color:#94a3b8">Advisory — apply via WHM (no safe one-click for this)</span>';
      html+='</div></div>';
    });
    var bar='';if(applyable.length)bar='<div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;flex-wrap:wrap"><button class="btn" id="aiApplyAll" style="background:#16a34a;color:#fff" data-ids="'+esc(applyable.join(','))+'">&#9889; Apply all '+applyable.length+' safe suggestion(s) — backup first</button><span class="meta" style="font-size:11px">Access-risk changes (SSH/firewall) are excluded — apply those individually.</span></div>';
    P('tunAiOut').innerHTML=bar+(html||'<p class="meta">No suggestions.</p>');
    var ab=P('aiApplyAll');if(ab)ab.addEventListener('click',function(){aiApplyAll(this);});
  }
  window.aiApplyOne=function(id,btn,risky){
    if(!confirm('Apply this change?'+(risky?'\n\n⚠ ACCESS-RISK — confirm key-based SSH login works before you apply this.':'')+'\n\nAll configs are backed up first; restore any time from the Config Backups table below.'))return;
    btn.disabled=true;var o=btn.innerHTML;btn.innerHTML='Applying…';
    call({tun_action:'apply',rec:id}).then(function(j){
      if(j&&j.ok){btn.innerHTML='&#10003; '+esc(j.applied||'applied');btn.style.background='#0f766e';msg('&#10003; Applied '+esc(id)+(j.note?' — '+esc(j.note):''),'#047857');}
      else{btn.disabled=false;btn.innerHTML=o;msg('✗ '+esc((j&&j.msg)||'failed'),'#b91c1c');}
    }).catch(function(){btn.disabled=false;btn.innerHTML=o;msg('Request failed.','#b91c1c');});};
  var applyIv=null;
  function applyProgUi(p){var el=P('tunApplyProg');if(!el)return;
    var done=(p&&p.done)||0,total=(p&&p.total)||0,cur=(p&&p.current)||'';var pct=total?Math.round(done/total*100):0;
    el.innerHTML='<div style="margin:10px 0;padding:10px 12px;background:var(--brand-bg);border-radius:10px"><div style="font-size:12px;font-weight:700;color:#26408b">Applying '+done+' / '+total+(cur?' — '+esc(cur):'')+'</div><div style="height:8px;background:var(--line);border-radius:6px;overflow:hidden;margin-top:6px"><div style="height:100%;width:'+pct+'%;background:#16a34a;transition:width .3s"></div></div><div class="meta" style="font-size:11px;margin-top:4px">Running in the background — you can leave this page; it keeps going and the result is saved.</div></div>';}
  function applyMarkDone(j){var pe=P('tunApplyProg');if(pe)pe.innerHTML='';
    msg((j&&j.ok?'&#10003; ':'&#9888; ')+esc((j&&j.msg)||'Apply-all finished'),(j&&j.ok)?'#047857':'#b45309');
    ((j&&j.applied)||[]).forEach(function(a){var el=document.querySelector('[data-ai-rec="'+a.id+'"]');if(el){el.style.opacity='.55';var bb=el.querySelector('button');if(bb){bb.disabled=true;bb.innerHTML='&#10003; applied';bb.style.background='#0f766e';}}});}
  function applyPoll(btn,lbl){if(applyIv)clearInterval(applyIv);
    applyIv=setInterval(function(){call({tun_action:'applyallstatus'}).then(function(st){
      if(st&&st.status==='running'){applyProgUi(st.progress);return;}
      clearInterval(applyIv);applyIv=null;if(btn){btn.disabled=false;if(lbl)btn.innerHTML=lbl;}
      applyMarkDone(st&&st.result);
    }).catch(function(){});},2000);}
  window.aiApplyAll=function(btn){
    var ids=btn.getAttribute('data-ids')||'';if(!ids)return;
    if(!confirm('Apply all safe AI suggestions now?\n\nAll configs are backed up FIRST (one snapshot), then each safe change is applied and Apache is config-tested with automatic rollback on failure. Access-risk changes (SSH/firewall) are NOT included. Runs in the background — you can leave the page. Reversible from the Config Backups table below.'))return;
    var o=btn.innerHTML;btn.disabled=true;btn.innerHTML='&#129518; Starting…';
    call({tun_action:'applyallstart',ids:ids}).then(function(r){
      if(!r||!r.ok){btn.disabled=false;btn.innerHTML=o;msg('✗ '+((r&&r.msg)||'could not start'),'#b91c1c');return;}
      applyProgUi({done:0,total:0,current:'Backing up all configs…'});applyPoll(btn,o);
    }).catch(function(){btn.disabled=false;btn.innerHTML=o;msg('Request failed.','#b91c1c');});};
  // resume the apply-all progress if a job was running when the page was (re)loaded
  if(APPLY_JOB&&APPLY_JOB.status==='running'){applyProgUi(APPLY_JOB.progress);applyPoll(null,null);}
  else if(APPLY_JOB&&(APPLY_JOB.status==='done'||APPLY_JOB.status==='error')&&APPLY_JOB.result&&APPLY_JOB.updated_at&&(Date.now()/1000-APPLY_JOB.updated_at)<120)applyMarkDone(APPLY_JOB.result);
  var aiIv=null;
  function aiRunUi(){var b=P('tunAi');b.disabled=true;b.innerHTML='&#129518; Running in background…';P('tunAiOut').innerHTML='<div class="sm-scanbar"><span></span></div><div class="sm-scanning">Analysing in the background — you can close this page and come back; the result is saved.</div>';}
  function aiPoll(){if(aiIv)clearInterval(aiIv);aiIv=setInterval(function(){call({tun_action:'aioptimizestatus'}).then(function(st){
    if(st&&st.status==='running'){if(st.started_at&&(Date.now()/1000-st.started_at)>210){clearInterval(aiIv);aiIv=null;var b=P('tunAi');b.disabled=false;b.innerHTML=AI_LBL;aimsg('&#9888; Taking too long — the scan may have failed. Try again.','#b45309');P('tunAiOut').innerHTML='';}return;}
    if(!st)return;clearInterval(aiIv);aiIv=null;var b=P('tunAi');b.disabled=false;b.innerHTML=AI_LBL;aiUpd(st.updated_at);
    if(st.status==='done'&&st.result)aiRender(st.result);else aimsg('✗ '+((st.result&&st.result.msg)||'Scan failed'),'#b91c1c');
  }).catch(function(){});},3000);}
  P('tunAi').addEventListener('click',function(){var t=selected();if(!t.length){aimsg('Select at least one target above.','#b45309');return;}
    aimsg('');aiRunUi();
    call({tun_action:'aioptimizestart',targets:t.join(',')}).then(function(r){
      if(!r||!r.ok){var b=P('tunAi');b.disabled=false;b.innerHTML=AI_LBL;aimsg('✗ '+((r&&r.msg)||'could not start'),'#b91c1c');P('tunAiOut').innerHTML='';return;}
      aiPoll();
    }).catch(function(){var b=P('tunAi');b.disabled=false;b.innerHTML=AI_LBL;aimsg('Request failed.','#b91c1c');});});
  // restore last result / resume polling on load
  if(AI_JOB&&AI_JOB.updated_at)aiUpd(AI_JOB.updated_at);
  if(AI_JOB&&AI_JOB.status==='running'){aiRunUi();aiPoll();}
  else if(AI_JOB&&AI_JOB.status==='done'&&AI_JOB.result)aiRender(AI_JOB.result);
  else if(AI_JOB&&AI_JOB.status==='error'&&AI_JOB.result)aimsg('✗ '+((AI_JOB.result&&AI_JOB.result.msg)||'Last scan failed'),'#b91c1c');

  // Security Advisor - every item has an Apply button; backend handles 9 advisory types automatically.
  var sevClrSa={fatal:'#b91c1c',warn:'#b45309',info:'#0369a1'};
  // Normalize advisory key the same way the backend does (strip class path, drop non-alnum incl. underscores)
  function saNorm(id){var p=id.split('::');return p[p.length-1].toUpperCase().replace(/[^A-Z0-9]/g,'');}
  // SSH-access advisories -> show the lockout warning (substring match on normalized key)
  function saIsSshRisk(n){return n.indexOf('ROOTLOGIN')>-1||n.indexOf('PASSWORDAUTH')>-1||(n.indexOf('SSH')>-1&&n.indexOf('PASSWORD')>-1);}
  window.tunSaApply=function(rawId,btn){
    if(!confirm('Apply this Security Advisor fix?\n\nA config backup is created automatically before any change, and you can restore it from the Config Backups table below at any time.'))return;
    btn.disabled=true;var o=btn.innerHTML;btn.innerHTML='Applying…';
    call({tun_action:'secadvisorapply',sa_id:rawId}).then(function(j){
      if(j&&j.ok){
        msg('&#10003; '+(j.applied||'applied')+(j.note?' — '+j.note:''),'#047857');
        var card=btn.closest('[data-sa-rec]');
        if(card){card.style.transition='opacity .35s';card.style.opacity='0';setTimeout(function(){card.remove();},370);}
        // nudge user to reload backup list
        setTimeout(function(){var bkNote=P('tunMsg');if(bkNote&&bkNote.innerHTML.indexOf('Backed up')===-1)msg(bkNote.innerHTML+' (Reload to see new backup in the list below)');},600);
      }else if(j&&j.manual){
        btn.innerHTML=o;btn.disabled=false;
        msg('&#9888; '+esc(j.msg||'Manual step required — see WHM › Security › Security Advisor.'),'#b45309');
      }else{
        btn.innerHTML=o;btn.disabled=false;
        msg('&#10007; '+esc((j&&j.msg)||'Apply failed'),'#b91c1c');
      }
    }).catch(function(){btn.innerHTML=o;btn.disabled=false;msg('Request failed.','#b91c1c');});};
  function saUpd(t){var el=P('tunSaUpd');if(el)el.textContent=t?('Last updated: '+tunFmtTs(t)):'';}
  var SA_LBL='&#128270; Scan Security Advisor';
  function saRender(j){var saMsg=P('tunSaMsg'),saOut=P('tunSaOut');
    if(!j||!j.ok){saMsg.style.color='#b91c1c';saMsg.innerHTML='&#10007; '+esc((j&&j.msg)||'Failed');saOut.innerHTML='';return;}
    if(!j.count){saOut.innerHTML='<p style="color:#047857;margin:0">&#10003; All Security Advisor checks pass — no recommendations.</p>';saMsg.innerHTML='&#10003; All clear';saMsg.style.color='#047857';return;}
    var html='';(j.recs||[]).forEach(function(r){
      var clr=sevClrSa[r.type]||'#64748b';var normId=saNorm(r.id);
      html+='<div data-sa-rec="'+esc(r.id)+'" style="border-left:4px solid '+clr+';padding:8px 12px;margin-bottom:8px;background:rgba(255,255,255,.45);border-radius:8px">';
      html+='<div style="display:flex;justify-content:space-between;gap:8px;align-items:center"><b>'+esc(r.title)+'</b>';
      html+='<span style="font-size:10.5px;font-weight:900;color:'+clr+'">'+esc(r.type.toUpperCase())+(r.category?' · '+esc(r.category):'')+'</span></div>';
      if(r.advice)html+='<div style="font-size:12.5px;color:#475569;margin:4px 0">'+esc(r.advice)+'</div>';
      if(saIsSshRisk(normId))html+='<div style="margin:6px 0;background:var(--dang-bg);border:1px solid #fecaca;color:#b91c1c;border-radius:8px;padding:5px 9px;font-size:12px">&#9888; <b>Can lock you out of SSH.</b> Confirm key-based login works before applying.</div>';
      html+='<div style="margin-top:6px"><button class="btn" style="padding:4px 10px;font-size:12px;background:#16a34a;color:#fff" onclick="tunSaApply(&quot;'+esc(r.id)+'&quot;,this)">&#9654; Apply (backup first)</button> <span style="font-size:11px;color:#64748b">Auto-applied — config backed up before change</span></div></div>';
    });
    saOut.innerHTML=html;saMsg.innerHTML=j.count+' recommendation(s)';saMsg.style.color='#b45309';
  }
  var saIv=null;
  function saRunUi(){var b=P('tunSaScan');b.disabled=true;b.innerHTML='&#128270; Running in background…';P('tunSaMsg').innerHTML='';P('tunSaOut').innerHTML='<div class="sm-scanbar"><span></span></div><div class="sm-scanning">Fetching Security Advisor in the background — you can close this page; the result is saved.</div>';}
  function saPoll(){if(saIv)clearInterval(saIv);saIv=setInterval(function(){call({tun_action:'secadvisorstatus'}).then(function(st){
    if(st&&st.status==='running'){if(st.started_at&&(Date.now()/1000-st.started_at)>210){clearInterval(saIv);saIv=null;var b=P('tunSaScan');b.disabled=false;b.innerHTML=SA_LBL;P('tunSaMsg').style.color='#b45309';P('tunSaMsg').innerHTML='&#9888; Taking too long — the scan may have failed. Try again.';P('tunSaOut').innerHTML='';}return;}
    if(!st)return;clearInterval(saIv);saIv=null;var b=P('tunSaScan');b.disabled=false;b.innerHTML=SA_LBL;saUpd(st.updated_at);
    if(st.status==='done'&&st.result)saRender(st.result);else{P('tunSaMsg').style.color='#b91c1c';P('tunSaMsg').innerHTML='&#10007; '+esc((st.result&&st.result.msg)||'Scan failed');}
  }).catch(function(){});},3000);}
  var saBtn=P('tunSaScan');
  if(saBtn)saBtn.addEventListener('click',function(){saRunUi();
    call({tun_action:'secadvisorstart'}).then(function(r){
      if(!r||!r.ok){var b=P('tunSaScan');b.disabled=false;b.innerHTML=SA_LBL;P('tunSaMsg').style.color='#b91c1c';P('tunSaMsg').innerHTML='✗ '+esc((r&&r.msg)||'could not start');P('tunSaOut').innerHTML='';return;}
      saPoll();
    }).catch(function(){var b=P('tunSaScan');b.disabled=false;b.innerHTML=SA_LBL;P('tunSaMsg').innerHTML='Request failed.';P('tunSaMsg').style.color='#b91c1c';});});
  // restore last result / resume polling on load
  if(SA_JOB&&SA_JOB.updated_at)saUpd(SA_JOB.updated_at);
  if(SA_JOB&&SA_JOB.status==='running'){saRunUi();saPoll();}
  else if(SA_JOB&&SA_JOB.status==='done'&&SA_JOB.result)saRender(SA_JOB.result);
  else if(SA_JOB&&SA_JOB.status==='error'&&SA_JOB.result){P('tunSaMsg').style.color='#b91c1c';P('tunSaMsg').innerHTML='✗ '+esc((SA_JOB.result&&SA_JOB.result.msg)||'Last scan failed');}
})();</script>
<?php
smpro_layout_footer();
