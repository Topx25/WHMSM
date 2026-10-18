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
    $oldMode = (string)($c['mode'] ?? 'enabled');
    $c['mode'] = $mode; $c['reenable_at'] = $reAt; $c['updated_at'] = time(); $c['actor'] = smpro_current_actor();
    smpro_ctl_save($c);
    // Alert when the master switch changes — a guard being stood down must never be silent. Force-sent.
    if ($mode !== $oldMode && function_exists('smpro_notify')) {
        $label = ['enabled' => 'ENABLED (full protection)', 'dryrun' => 'DRY-RUN (detect only, no auto-actions)', 'disabled' => 'DISABLED (no protection)'][$mode] ?? $mode;
        smpro_notify('plugin_mode_change', 'SM Pro protection mode → ' . $mode,
            'Changed from "' . $oldMode . '" to "' . $label . '" by ' . smpro_current_actor()
            . ($reAt ? "\nAuto re-enable at: " . date('Y-m-d H:i', $reAt) : ''),
            ['severity' => $mode === 'enabled' ? 'info' : 'high'], true);
    }
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

if ($reqMethod === 'POST' && ($_POST['pc_action'] ?? '') === 'cpuser') {
    smpro_require_valid_csrf('pc_action'); smpro_require_root();
    header('Content-Type: application/json');
    $on = ($_POST['on'] ?? '') === '1';
    $r  = smpro_pc_cpuser_set($on);
    echo json_encode($r, JSON_UNESCAPED_SLASHES); exit;
}

/**
 * Turn the account-side page on or off for this server.
 *
 * The switch is a file rather than a config key because the thing that reads it is a shell script run from the
 * updater, and a shell script asking a PHP config loader for one boolean is a dependency that breaks in exactly
 * the situation this must survive — a half-finished update.
 *
 * The registration script is then run immediately instead of waiting for the next update, and its OUTPUT is
 * returned. It is the only thing that actually knows whether cPanel accepted the entry, and an operator who
 * clicked a switch deserves the answer now rather than a green toggle and a page that may not be there.
 */
function smpro_pc_cpuser_set($on) {
    $flag = SMPRO_VARLIB . '/cpuser_enabled';
    @is_dir(SMPRO_VARLIB) || @mkdir(SMPRO_VARLIB, 0700, true);

    if ($on) {
        if (@file_put_contents($flag, date('c') . "
") === false) {
            return ['ok' => false, 'msg' => 'Could not write the switch file at ' . $flag . '. Nothing changed.'];
        }
    } else {
        @unlink($flag);
        if (is_file($flag)) return ['ok' => false, 'msg' => 'Could not remove the switch file at ' . $flag . '. Nothing changed.'];
    }

    $script = SMPRO_BASE . '/bin/register_cpuser.sh';
    if (!is_file($script)) {
        return ['ok' => false, 'on' => $on,
                'msg' => 'The switch was saved but bin/register_cpuser.sh is missing from this build, so nothing was installed or removed.'];
    }
    $out = []; $rc = 0;
    @exec('bash ' . escapeshellarg($script) . ' 2>&1', $out, $rc);
    $txt = trim(preg_replace('/\[[0-9;]*m/', '', implode("
", $out)));

    smpro_audit('cpuser_plugin', ['on' => $on ? 1 : 0, 'rc' => $rc]);

    // Read the ground truth back rather than trusting the exit code.
    $slug  = defined('SMPRO_CPS_SLUG') ? SMPRO_CPS_SLUG : 'siteprotection';
    $themes = 0;
    foreach (glob('/usr/local/cpanel/base/frontend/*', GLOB_ONLYDIR) ?: [] as $t) {
        if (is_file($t . '/' . $slug . '/index.live.php') && is_file($t . '/dynamicui/dynamicui_' . $slug . '.conf')) $themes++;
    }

    if ($on) {
        return ['ok' => $themes > 0, 'on' => true, 'themes' => $themes, 'detail' => $txt,
                'msg' => $themes > 0
                    ? 'Your customers now see it in cPanel under Security (' . $themes . ' theme(s)). You can still withhold it per package in Feature Manager.'
                    : 'It did NOT install — nothing appeared in any theme, so no customer can see it. See the detail below.'];
    }
    return ['ok' => $themes === 0, 'on' => false, 'themes' => $themes, 'detail' => $txt,
            'msg' => $themes === 0
                ? 'Removed from cPanel. Your customers no longer see it.'
                : 'The switch is off but it is STILL present in ' . $themes . ' theme(s) — your customers can still see it.'];
}

$ctl  = smpro_ctl_get();
$csrf = smpro_csrf_generate('pc_action');
$envCsrf = smpro_csrf_generate('env_install');   // Diagnostics self-test one-click installs reuse the env_install endpoint
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

<?php
/* Diagnostics — at-a-glance self-test of optional integrations, so a degraded feature is visible here instead of
   being discovered only when a page looks empty. Read-only status + one-click install (reuses the env_install endpoint). */
$diagCaps = function_exists('smpro_capabilities') ? smpro_capabilities() : [];
$diagMgr  = function_exists('smpro_pkg_mgr') ? smpro_pkg_mgr() : '';
$diagOk = 0; $diagMiss = 0;
foreach ($diagCaps as $dc) { if (!empty($dc[1])) $diagOk++; else $diagMiss++; }
?>
<?php
$cpuserOn = is_file(SMPRO_VARLIB . '/cpuser_enabled');
$cpuserSlug = defined('SMPRO_CPS_SLUG') ? SMPRO_CPS_SLUG : 'siteprotection';
$cpuserName = defined('SMPRO_CPS_NAME') ? SMPRO_CPS_NAME : 'Site Protection';
$cpuserThemes = 0;
foreach (glob('/usr/local/cpanel/base/frontend/*', GLOB_ONLYDIR) ?: [] as $t) {
    if (is_file($t . '/' . $cpuserSlug . '/index.live.php')) $cpuserThemes++;
}
?>
<div class="card" style="max-width:680px;padding:18px 22px;margin-top:18px">
  <div class="svc-kicker">Account side</div>
  <b style="font-size:14px">&#128100; Give your customers <?= smpro_h($cpuserName) ?> in their cPanel</b>
  <p class="sub" style="margin:6px 0 12px">
    A page inside each customer's own cPanel that protects the files their site runs on: it blocks code from
    running in upload folders, makes the key files read-only, and lets them ask this server to lock those files
    properly &mdash; which this plugin then does for them, because only the server can.
    <b>Off by default</b>, because putting something in front of your customers is your decision, not an update's.
    Once on, every update keeps it in place by itself.
  </p>
  <div class="pc-diagrow">
    <span class="pc-dot <?= $cpuserOn ? 'ok' : 'miss' ?>"><?= $cpuserOn ? '&#10003;' : '&#10007;' ?></span>
    <div class="pc-diagtx">
      <b><?= $cpuserOn ? 'On' : 'Off' ?></b>
      <div class="meta">
        <?php if ($cpuserOn && $cpuserThemes > 0): ?>
          Installed in <?= (int)$cpuserThemes ?> theme(s). Withhold it from a package in WHM &rsaquo; Feature Manager.
        <?php elseif ($cpuserOn): ?>
          The switch is on but it is not installed in any theme &mdash; your customers cannot see it. Switch it off and on again to retry.
        <?php else: ?>
          Nothing is in your customers' cPanel. Turning this on installs it now and keeps it installed.
        <?php endif; ?>
      </div>
    </div>
    <div class="pc-diagact">
      <button class="btn" id="pcCpuser" type="button" data-on="<?= $cpuserOn ? '1' : '0' ?>"
        style="<?= $cpuserOn ? '' : 'background:var(--brand);color:#fff;' ?>padding:6px 13px;font-size:12px">
        <?= $cpuserOn ? 'Turn off' : 'Turn on' ?>
      </button>
    </div>
  </div>
  <div id="pcCpuserMsg" class="meta" style="font-size:12px;margin-top:8px"></div>
</div>

<?php
/* Account-side plugins — what the customer sees inside cPanel. Nothing else in WHM reports this, and a second
   lock manager already installed is the one thing that must be known before shipping our own. */
$cps = function_exists('smpro_cps_scan') ? smpro_cps_scan() : ['plugins' => [], 'ok' => false, 'why' => 'The scan is unavailable in this build.'];
$cpsOthers = array_values(array_filter($cps['plugins'], fn($p) => empty($p['ours'])));
?>
<div class="card" style="max-width:680px;padding:18px 22px;margin-top:18px">
  <div class="svc-kicker">Account side</div>
  <b style="font-size:14px">&#128100; Plugins your customers see inside cPanel</b>
  <p class="sub" style="margin:6px 0 12px">
    <?php if (!empty($cps['why'])): ?>
      <b>This list is incomplete.</b> <?= smpro_h($cps['why']) ?> Treat it as "not fully checked", not as "none installed".
    <?php elseif (!$cpsOthers): ?>
      Nothing else is installed. Every place cPanel loads account-side plugins from was read, and only ours is there.
    <?php else: ?>
      <b><?= count($cpsOthers) ?></b> found besides ours. Listed so you know what your customers already have &mdash;
      no judgement is made about them here.
    <?php endif; ?>
  </p>
  <?php foreach ($cpsOthers as $p): ?>
    <div class="pc-diagrow">
      <span class="pc-dot <?= !empty($p['admin_bins']) ? 'miss' : 'ok' ?>"><?= !empty($p['admin_bins']) ? '&#9679;' : '&#9675;' ?></span>
      <div class="pc-diagtx">
        <b><?= smpro_h($p['name']) ?></b>
        <div class="meta"><?= smpro_h(smpro_cps_describe($p)) ?></div>
        <div class="meta pc-dhint" style="font-family:ui-monospace,Consolas,monospace"><?= smpro_h($p['path']) ?><?= $p['runnable'] ? ' &middot; ' . smpro_h(implode(', ', array_slice($p['runnable'], 0, 6))) : '' ?></div>
        <?php foreach ($p['admin_bins'] as $b): ?>
          <div class="meta pc-dhint" style="font-family:ui-monospace,Consolas,monospace">root helper: <?= smpro_h($b['path']) ?> (<?= smpro_h($b['mode']) ?><?= $b['conf'] !== '' ? ', ' . smpro_h($b['conf']) : '' ?>)</div>
        <?php endforeach; ?>
      </div>
      <div class="pc-diagact"><span class="pc-dstat <?= !empty($p['admin_bins']) ? 'miss' : 'ok' ?>"><?= !empty($p['admin_bins']) ? 'has root helper' : 'account only' ?></span></div>
    </div>
  <?php endforeach; ?>
</div>

<div class="card" style="max-width:680px;padding:18px 22px;margin-top:18px">
  <div class="svc-kicker">Diagnostics</div>
  <b style="font-size:14px">&#129514; System self-test — optional integrations</b>
  <p class="sub" style="margin:6px 0 12px"><b><?= (int)$diagOk ?></b> active · <b><?= (int)$diagMiss ?></b> missing. A missing tool only disables the specific feature it powers — the plugin keeps working without it, with a built-in fallback where possible.</p>
  <div class="pc-diag">
  <?php foreach ($diagCaps as $dk => $dcap):
      $present = !empty($dcap[1]); $pkg = (string)($dcap[4] ?? '');
      $installable = !$present && $pkg !== '' && $diagMgr !== '';
  ?>
    <div class="pc-diagrow">
      <span class="pc-dot <?= $present ? 'ok' : 'miss' ?>"><?= $present ? '&#10003;' : '&#10007;' ?></span>
      <div class="pc-diagtx">
        <b><?= $dcap[0] ?? smpro_h($dk) ?></b>
        <div class="meta"><?= $dcap[2] ?? '' ?></div>
        <?php if (!$present): ?><div class="meta pc-dhint"><?= $dcap[3] ?? '' ?></div><?php endif; ?>
      </div>
      <div class="pc-diagact">
        <?php if ($present): ?><span class="pc-dstat ok">Active</span>
        <?php elseif ($installable): ?><button class="btn pc-dinstall" type="button" data-cap="<?= smpro_h($dk) ?>" style="background:var(--brand);color:#fff;padding:6px 13px;font-size:12px">&#8681; Install</button>
        <?php else: ?><span class="pc-dstat miss">Not installed</span><?php endif; ?>
      </div>
    </div>
  <?php endforeach; ?>
  </div>
</div>
<style>
.pc-diag{display:flex;flex-direction:column}
.pc-diagrow{display:flex;gap:12px;align-items:flex-start;padding:11px 2px;border-bottom:1px solid var(--line)}
.pc-diagrow:last-child{border-bottom:0}
.pc-dot{flex:0 0 22px;width:22px;height:22px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:800;margin-top:1px}
.pc-dot.ok{background:rgba(22,163,74,.12);color:#16a34a}
.pc-dot.miss{background:rgba(220,38,38,.10);color:#dc2626}
.pc-diagtx{flex:1;min-width:0}.pc-diagtx b{font-size:13.5px}
.pc-dhint{margin-top:3px;opacity:.85}
.pc-diagact{flex:0 0 auto;align-self:center;text-align:right}
.pc-dstat{font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:.03em}
.pc-dstat.ok{color:#16a34a}.pc-dstat.miss{color:var(--muted)}
</style>
<script>(function(){
  var EI_CSRF=<?= json_encode($envCsrf) ?>;
  document.querySelectorAll('.pc-dinstall').forEach(function(b){b.addEventListener('click',function(){
    var cap=b.getAttribute('data-cap'),o=b.innerHTML; b.disabled=true; b.innerHTML='Installing…';
    var fd=new URLSearchParams(); fd.set('smpro_csrf',EI_CSRF); fd.set('component',cap);
    fetch('index.cgi?env_install=1',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'})
      .then(function(r){return r.json();}).then(function(j){
        var row=b.closest('.pc-diagrow');
        if(j&&j.ok){ b.outerHTML='<span class="pc-dstat ok">Installed</span>'; if(row){var d=row.querySelector('.pc-dot'); if(d){d.className='pc-dot ok'; d.innerHTML='✓';}} }
        else { b.disabled=false; b.innerHTML=o; alert((j&&j.msg)||'Install failed — check the server has a package manager and network.'); }
      }).catch(function(){ b.disabled=false; b.innerHTML=o; alert('Request failed'); });
  });});
})();</script>

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
  var cpb=P('pcCpuser'); if(cpb)cpb.addEventListener('click',function(){
    var on=cpb.getAttribute('data-on')==='1', msg=P('pcCpuserMsg');
    if(on){ if(!confirm('Turn OFF Safety Lock for your customers?\n\nIt is removed from cPanel and nobody will see it. Anything already locked stays locked — this removes the page, not the protection.'))return; }
    else  { if(!confirm('Turn ON Safety Lock?\n\nA new entry appears in EVERY customer cPanel on this server, under Security. You can withhold it from individual packages afterwards in Feature Manager.'))return; }
    var o=cpb.innerHTML; cpb.disabled=true; cpb.innerHTML='⏳ working…'; msg.textContent='';
    var fd=new URLSearchParams(); fd.set('smpro_csrf',PC_CSRF); fd.set('pc_action','cpuser'); fd.set('on',on?'0':'1');
    fetch('index.cgi?page=plugin-control',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'})
      .then(function(r){return r.json();})
      .then(function(j){
        msg.textContent=(j&&j.msg)||'No answer from the server.';
        msg.style.color=(j&&j.ok)?'var(--good)':'var(--dang)';
        // The detail is the installer's own words — shown on failure, because that is where the reason is.
        if(j&&!j.ok&&j.detail){var d=document.createElement('pre');d.style.cssText='white-space:pre-wrap;font-size:11px;margin:6px 0 0;color:var(--muted)';d.textContent=j.detail;msg.appendChild(d);}
        setTimeout(function(){location.reload();}, (j&&j.ok)?1200:6000);
      })
      .catch(function(){cpb.disabled=false;cpb.innerHTML=o;msg.textContent='The request failed — nothing was changed.';msg.style.color='var(--dang)';});
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
