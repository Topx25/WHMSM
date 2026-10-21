<?php
/**
 * modules/system-updates.php — what is pending on this server (packages, cPanel, kernel), when it was last looked
 * at, what was applied and how it went; the mode (manual / automatic), Check now, Update now, Repair downloads.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }
require_once __DIR__ . '/../includes/sysupd.php';
smpro_require_root();

$act = (string)($_POST['su_action'] ?? '');
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $act !== '') {
    smpro_require_valid_csrf('su_action');
    header('Content-Type: application/json');
    $out = ['ok' => false, 'msg' => 'Unknown action.'];
    if ($act === 'settings') {
        $c = smpro_su_cfg_save(['mode' => (string)($_POST['mode'] ?? 'manual') === 'auto' ? 'auto' : 'manual', 'hour' => (int)($_POST['hour'] ?? 4), 'check_hours' => (int)($_POST['check_hours'] ?? 6),
                                 'cpanel_auto' => !empty($_POST['cpanel_auto']), 'notify_new' => !empty($_POST['notify_new']), 'notify_result' => !empty($_POST['notify_result']), 'notify_problem' => !empty($_POST['notify_problem'])]);
        $cron = smpro_su_cron_sync();
        smpro_audit('sysupd_settings', ['mode' => $c['mode'], 'hour' => $c['hour'], 'check_hours' => $c['check_hours'], 'cpanel_auto' => $c['cpanel_auto'] ? 1 : 0]);
        $out = ['ok' => true, 'msg' => 'Saved. Mode: ' . ($c['mode'] === 'auto' ? 'automatic at ' . sprintf('%02d:00', $c['hour']) . ' server time (packages' . ($c['cpanel_auto'] ? ' + cPanel' : '') . ', never a reboot)' : 'manual - you are told, you press Update now') . '. Check every ' . $c['check_hours'] . ' h.' . ($cron ? '' : ' WARNING: the cron line could not be written.')];
    } elseif ($act === 'check') {
        $s = smpro_su_check(false);
        $out = ['ok' => (bool)$s['check_ok'], 'msg' => $s['check_ok'] ? count($s['pending']) . ' package update(s) pending' . (!empty($s['cpanel']['behind']) ? '; cPanel ' . $s['cpanel']['current'] . ' -> ' . $s['cpanel']['latest'] : (isset($s['cpanel']['behind']) ? '; cPanel is current' : '')) : 'COULD NOT CHECK: ' . $s['check_err'] . ($s['problems'] ? ' - ' . $s['problems'][0]['what'] : '')];
    } elseif ($act === 'apply') {
        @set_time_limit(3500);
        $r = smpro_su_apply(smpro_current_actor() ?: 'operator', !empty($_POST['cpanel']));
        $out = ['ok' => $r['ok'], 'msg' => $r['msg']];
    } elseif ($act === 'repair') {
        $s = smpro_su_state(); $d = $s['problems'][0] ?? null;
        [$ok, $what] = smpro_su_repair(is_array($d) && !empty($d['auto']) ? $d : null);
        smpro_audit('sysupd_repair', ['ok' => $ok ? 1 : 0, 'what' => $what]);
        if ($ok) { $s2 = smpro_su_check(false); $what .= '; re-check: ' . ($s2['check_ok'] ? count($s2['pending']) . ' pending' : 'still failing - ' . $s2['check_err']); }
        $out = ['ok' => $ok, 'msg' => $what];
    } elseif ($act === 'putback') {
        [$ok, $msg] = smpro_su_php_putback((string)($_POST['vhost'] ?? ''), (string)($_POST['version'] ?? ''), (int)!empty($_POST['fpm']));
        if ($ok) { $s = smpro_su_state(); smpro_su_php_watch($s, 'put back', false); smpro_su_state_save($s); }
        $out = ['ok' => $ok, 'msg' => $msg];
    } elseif ($act === 'log') {
        $out = ['ok' => true, 'log' => is_file(SMPRO_SU_LOG) ? substr((string)@file_get_contents(SMPRO_SU_LOG), -60000) : '(no apply has run yet)'];
    }
    echo json_encode($out, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

$cfg = smpro_su_cfg(); $s = smpro_su_state(); $csrf = smpro_csrf_generate('su_action');
$cronOk = is_file(SMPRO_SU_CRON) || defined('SMPRO_TEST_SRC');
$dry = function_exists('smpro_ctl_dry_run') && smpro_ctl_dry_run();
$kinds = []; foreach ((array)$s['pending'] as $x) $kinds[$x['kind']] = ($kinds[$x['kind']] ?? 0) + 1; arsort($kinds);
$KL = ['kernel' => ['Kernel', '#b91c1c'], 'php' => ['PHP', '#7c3aed'], 'web' => ['Web server', '#0369a1'], 'mail' => ['Mail', '#b45309'], 'db' => ['Database', '#0f766e'], 'security' => ['Security', '#be123c'], 'panel' => ['Panel', '#1d4ed8'], 'base' => ['Base system', '#475569'], 'other' => ['Other', '#64748b']];
$ago = function ($ts) { $ts = (int)$ts; if ($ts <= 0) return 'never'; $d = time() - $ts; if ($d < 3600) return intdiv($d, 60) . ' min ago'; if ($d < 86400) return intdiv($d, 3600) . ' h ago'; return intdiv($d, 86400) . ' d ago'; };
$cp = (array)$s['cpanel']; $kn = (array)$s['kernel']; $la = (array)$s['last_apply'];
smpro_layout_header('System updates');
?>
<style>
.su-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;margin:12px 0}
.su-tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.su-tile .n{font-size:22px;font-weight:700;line-height:1.2}.su-tile .l{color:var(--muted);font-size:12.5px;margin-top:4px}
.su-chip{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11.5px;font-weight:600}
.su-tbl td,.su-tbl th{font-size:12.5px}
.su-log{white-space:pre-wrap;font-family:monospace;font-size:11.5px;max-height:360px;overflow:auto;background:var(--card2,rgba(0,0,0,.03));padding:10px;border-radius:8px}
.su-res{margin:8px 0;padding:8px 12px;border-radius:8px;font-size:12.5px}.su-res.ok{background:#eafaf0;color:#166534}.su-res.bad{background:#fdecec;color:#991b1b}
</style>
<div class="card" style="padding:0;overflow:hidden">
  <div class="fa-head"><b>&#8635; System updates</b> <span class="meta">packages (dnf), cPanel's build, the kernel - looked at every <?= (int)$cfg['check_hours'] ?> h; <?= $cfg['mode'] === 'auto' ? 'applied automatically at ' . sprintf('%02d:00', $cfg['hour']) . ' server time' : 'applied when you press the button' ?>; never a reboot</span>
    <?php if (!$cronOk): ?><span class="b red" style="margin-left:8px">worker not scheduled - save the settings once</span><?php endif; ?>
    <?php if ($dry): ?><span class="b orange" style="margin-left:8px">Dry-Run: nothing is applied</span><?php endif; ?></div>
  <div style="padding:12px 16px">
    <div class="su-grid">
      <div class="su-tile"><div class="n" style="color:<?= $s['check_ok'] === false ? 'var(--dang)' : ($s['pending'] ? 'var(--warn)' : 'var(--good)') ?>"><?= $s['check_ok'] === null ? '—' : ($s['check_ok'] === false ? 'could not check' : count($s['pending'])) ?></div><div class="l"><?= $s['check_ok'] === false ? smpro_h($s['check_err']) : 'package update(s) pending' ?> &middot; checked <?= smpro_h($ago($s['last_check'])) ?></div></div>
      <div class="su-tile"><div class="n" style="color:<?= !empty($cp['behind']) ? 'var(--warn)' : (isset($cp['behind']) ? 'var(--good)' : 'var(--muted)') ?>"><?= smpro_h((string)($cp['current'] ?? trim((string)@file_get_contents('/usr/local/cpanel/version')))) ?></div><div class="l">cPanel, tier <?= smpro_h((string)($cp['tier'] ?? '?')) ?> &middot; <?= !empty($cp['behind']) ? 'behind: ' . smpro_h($cp['latest']) . ' is out' : (isset($cp['behind']) ? 'current' : ($cp['err'] ?? 'not checked yet')) ?></div></div>
      <div class="su-tile"><div class="n" style="color:<?= !empty($kn['reboot_pending']) ? 'var(--warn)' : 'var(--good)' ?>"><?= !empty($kn['reboot_pending']) ? 'reboot pending' : 'kernel current' ?></div><div class="l">running <?= smpro_h((string)($kn['running'] ?? '')) ?><?= !empty($kn['installed']) ? ' &middot; on disk ' . smpro_h($kn['installed']) : '' ?><?= !empty($kn['livepatch']) ? ' &middot; live-patched to ' . smpro_h($kn['livepatch']) . ' (KernelCare)' : '' ?></div></div>
      <div class="su-tile"><div class="n" style="color:<?= $la ? ($la['ok'] ? 'var(--good)' : 'var(--dang)') : 'var(--muted)' ?>"><?= $la ? ($la['ok'] ? 'applied' : 'FAILED') : 'never applied' ?></div><div class="l"><?= $la ? smpro_h($ago($la['at'])) . ' by ' . smpro_h((string)$la['by']) . ' &middot; ' . (int)$la['updated'] . ' package(s)' : 'by this product' ?></div></div>
    </div>
    <?php if ($s['problems']): ?>
    <div class="fa-note" style="background:var(--dang-bg);color:var(--dang)"><b>Problem:</b> <?= smpro_h($s['problems'][0]['what']) ?><?= !empty($s['problems'][0]['repair']) ? ' &mdash; repair this product can do: ' . smpro_h($s['problems'][0]['repair']) : ' &mdash; no automatic repair for this kind; the output is in the log below' ?></div>
    <?php endif; ?>
    <?php if ($la && ($la['services']['restarted'] ?? []) || ($la['services']['down'] ?? [])): ?>
    <div class="fa-note" style="background:var(--warn-bg);color:var(--warn)">After the last update: <?= !empty($la['services']['restarted']) ? 'restarted ' . smpro_h(implode(', ', $la['services']['restarted'])) . '. ' : '' ?><?= !empty($la['services']['down']) ? '<b>STILL DOWN: ' . smpro_h(implode(', ', $la['services']['down'])) . '</b>' : '' ?></div>
    <?php endif; ?>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin:10px 0">
      <button class="tp-btn" type="button" data-su="check">&#8635; Check now</button>
      <button class="tp-btn primary" type="button" data-su="apply"<?= $s['pending'] && !$dry ? '' : ' disabled' ?> data-confirm="Apply <?= count((array)$s['pending']) ?> package update(s) now? Services are checked afterwards; a kernel is installed to disk only - no reboot.">&#9654; Update now</button>
      <button class="tp-btn" type="button" data-su="apply" data-cpanel="1"<?= $dry ? ' disabled' : '' ?> data-confirm="Run cPanel's own updater (upcp) as well? This can take several minutes and restarts cPanel services.">&#9654; Update packages + cPanel</button>
      <button class="tp-btn" type="button" data-su="repair" data-confirm="Repair downloads: clean the package cache, rebuild the metadata, and fix a stale lock or damaged rpm database if that is what the last error said?">&#128295; Repair downloads</button>
      <button class="fa-lnk" type="button" data-su="log">show last apply log</button>
      <span class="meta" id="suMsg"></span>
    </div>
    <div id="suLog" class="su-log" style="display:none"></div>

    <?php if ($s['pending']): ?>
    <div class="meta" style="margin:6px 0">By kind: <?php foreach ($kinds as $k => $n): [$kl, $kc] = $KL[$k] ?? [$k, '#64748b']; ?><span class="su-chip" style="background:<?= $kc ?>22;color:<?= $kc ?>;margin-right:4px"><?= smpro_h($kl) ?> <?= (int)$n ?></span><?php endforeach; ?></div>
    <div style="overflow:auto;max-height:420px"><table class="smpro-table su-tbl" style="margin:0"><thead><tr><th>Package</th><th>Kind</th><th>New version</th><th>Repository</th></tr></thead><tbody>
      <?php foreach ((array)$s['pending'] as $x): [$kl, $kc] = $KL[$x['kind']] ?? [$x['kind'], '#64748b']; ?>
      <tr><td class="mono"><?= smpro_h($x['name']) ?></td><td><span class="su-chip" style="background:<?= $kc ?>22;color:<?= $kc ?>"><?= smpro_h($kl) ?></span></td><td class="mono"><?= smpro_h($x['version']) ?></td><td class="meta"><?= smpro_h($x['repo']) ?></td></tr>
      <?php endforeach; ?>
    </tbody></table></div>
    <?php elseif ($s['check_ok']): ?>
    <div class="fa-empty" style="color:var(--good)">Every package is current<?= !empty($cp['behind']) ? ' &mdash; only cPanel itself has a newer build (its nightly job installs it, or press "Update packages + cPanel")' : '' ?>.</div>
    <?php elseif ($s['check_ok'] === null): ?>
    <div class="fa-empty">Not checked yet &mdash; press Check now (the worker also checks every <?= (int)$cfg['check_hours'] ?> h once the settings are saved).</div>
    <?php endif; ?>
  </div>
</div>

<?php $pc = (array)($s['php_changes'] ?? []); $snap = (array)($s['php_snapshot'] ?? []); ?>
<div class="card" style="margin-top:14px">
  <div class="fa-head"><b>PHP version changes</b> <span class="meta">every domain's PHP version and FPM setting are photographed at every check and around every update; a change is listed here with the way back (<?= count($snap) ?> domain(s) in the last photograph<?= !empty($s['php_snapshot_at']) ? ', ' . smpro_h(date('Y-m-d H:i', (int)$s['php_snapshot_at'])) : '' ?>)</span></div>
  <?php if (!$pc): ?><div class="fa-empty" style="color:var(--good)">No domain changed its PHP version since the first photograph.</div>
  <?php else: ?><div style="overflow:auto;max-height:360px"><table class="smpro-table su-tbl" style="margin:0"><thead><tr><th>When</th><th>Domain</th><th>Before</th><th>After</th><th></th></tr></thead><tbody>
    <?php foreach ($pc as $ev): foreach ((array)$ev['changes'] as $h => $c): $cur = $snap[$h] ?? null; $same = $cur && $cur['v'] === $c['before']['v'] && $cur['fpm'] === $c['before']['fpm']; ?>
    <tr><td style="white-space:nowrap"><?= smpro_h(date('m-d H:i', (int)$ev['at'])) ?><div class="meta"><?= smpro_h($ev['why']) ?></div></td><td class="mono"><?= smpro_h($h) ?></td>
      <td class="mono"><?= smpro_h($c['before']['v']) ?><?= $c['before']['fpm'] ? ' +FPM' : '' ?></td><td class="mono"><?= smpro_h($c['after']['v']) ?><?= $c['after']['fpm'] ? ' +FPM' : '' ?></td>
      <td><?php if ($same): ?><span class="meta">already back</span><?php else: ?><button type="button" class="fa-lnk" data-su="putback" data-vhost="<?= smpro_h($h) ?>" data-version="<?= smpro_h($c['before']['v']) ?>" data-fpm="<?= (int)$c['before']['fpm'] ?>" data-confirm="Put <?= smpro_h($h) ?> back on <?= smpro_h($c['before']['v']) ?><?= $c['before']['fpm'] ? ' with FPM' : ' without FPM' ?>? cPanel rewrites the handler and the result is read back.">Put back</button><?php endif; ?></td></tr>
    <?php endforeach; endforeach; ?>
  </tbody></table></div><?php endif; ?>
</div>

<div class="card" style="margin-top:14px">
  <div class="fa-head"><b>Settings</b> <span class="meta">the check always runs; the mode decides who presses the button</span></div>
  <form id="suForm" style="padding:12px 16px;display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px">
    <label>Mode<br><select name="mode" class="tp-sel"><option value="manual"<?= $cfg['mode'] === 'manual' ? ' selected' : '' ?>>manual - tell me, I press Update now</option><option value="auto"<?= $cfg['mode'] === 'auto' ? ' selected' : '' ?>>automatic - apply at the hour below (never reboots)</option></select></label>
    <label>Hour (server time, automatic mode)<br><select name="hour" class="tp-sel"><?php for ($h = 0; $h < 24; $h++): ?><option value="<?= $h ?>"<?= $h === $cfg['hour'] ? ' selected' : '' ?>><?= sprintf('%02d:00', $h) ?></option><?php endfor; ?></select></label>
    <label>Check every<br><select name="check_hours" class="tp-sel"><?php foreach ([1, 3, 6, 12, 24] as $h): ?><option value="<?= $h ?>"<?= $h === $cfg['check_hours'] ? ' selected' : '' ?>><?= $h ?> hour<?= $h > 1 ? 's' : '' ?></option><?php endforeach; ?></select></label>
    <label class="lm-chkl"><input type="checkbox" name="cpanel_auto" value="1"<?= $cfg['cpanel_auto'] ? ' checked' : '' ?>> in automatic mode, run cPanel's updater (upcp) too</label>
    <label class="lm-chkl"><input type="checkbox" name="notify_new" value="1"<?= $cfg['notify_new'] ? ' checked' : '' ?>> tell me when new updates appear</label>
    <label class="lm-chkl"><input type="checkbox" name="notify_result" value="1"<?= $cfg['notify_result'] ? ' checked' : '' ?>> tell me after each automatic apply</label>
    <label class="lm-chkl"><input type="checkbox" name="notify_problem" value="1"<?= $cfg['notify_problem'] ? ' checked' : '' ?>> tell me when a check or download breaks (with the diagnosis)</label>
    <div style="grid-column:1/-1"><button class="tp-btn primary" type="submit">Save</button> <span class="meta" id="suSet"></span></div>
  </form>
  <div class="meta" style="padding:0 16px 12px;font-size:12px">Repairs this product does by itself when a download breaks: clean the package cache and rebuild the metadata; move aside a stale package-manager lock (only when its process is gone or older than 30 minutes); rebuild a damaged rpm database (a copy is kept first); when ONE repository will not answer, update everything else and name the one that is down. A full disk, a package conflict or a failed install script are reported with the tool's own words - they need a person.</div>
</div>
<script>
(function(){
  var CSRF=<?= json_encode($csrf) ?>;
  function post(fd,cb){fd.set('smpro_csrf',CSRF);fetch('index.cgi?page=system-updates',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'}).then(function(r){return r.json();}).then(cb).catch(function(){cb({ok:false,msg:'The request did not complete (an update can take minutes - reload the page and look at the log).'});});}
  document.querySelectorAll('[data-su]').forEach(function(b){b.addEventListener('click',function(){
    var a=b.getAttribute('data-su'); if(b.dataset.confirm && !confirm(b.dataset.confirm)) return;
    var m=document.getElementById('suMsg'); m.textContent=(a==='apply'?'Updating… (this can take several minutes; the page waits)':a==='repair'?'Repairing…':a==='check'?'Checking…':'');
    document.querySelectorAll('[data-su]').forEach(function(x){x.disabled=true;});
    var fd=new URLSearchParams(); fd.set('su_action',a); if(b.dataset.cpanel) fd.set('cpanel','1'); if(a==='putback'){fd.set('vhost',b.dataset.vhost);fd.set('version',b.dataset.version);fd.set('fpm',b.dataset.fpm);}
    post(fd,function(r){ document.querySelectorAll('[data-su]').forEach(function(x){x.disabled=false;});
      if(a==='log'){var l=document.getElementById('suLog'); l.style.display='block'; l.textContent=r.log||''; m.textContent=''; return;}
      m.textContent=r.msg||''; m.className='meta '+(r.ok?'':'');
      var res=document.createElement('div'); res.className='su-res '+(r.ok?'ok':'bad'); res.textContent=(r.ok?'Done: ':'Not done: ')+(r.msg||''); m.parentNode.insertAdjacentElement('afterend',res);
      if(r.ok && a!=='log') setTimeout(function(){location.reload();},1500);
    });
  });});
  document.getElementById('suForm').addEventListener('submit',function(e){e.preventDefault(); var fd=new URLSearchParams(new FormData(e.target)); fd.set('su_action','settings'); post(fd,function(r){document.getElementById('suSet').textContent=r.msg||''; if(r.ok) setTimeout(function(){location.reload();},1200);});});
})();
</script>
<?php smpro_layout_footer();
