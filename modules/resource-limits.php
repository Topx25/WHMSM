<?php
/**
 * modules/resource-limits.php — "Resource Limit Is Reached" (HTTP 508): which accounts hit their CloudLinux LVE
 * limits, what is hitting them this second, and the ways out. Engine: includes/lvelimits.php. Every action backs
 * ve.cfg up first and is audited; a lift puts itself back when its time is up.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }
require_once SMPRO_INCLUDES . '/lvelimits.php';
smpro_require_root();

$reqMethod = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));
if ($reqMethod === 'POST' && ($_POST['lv_action'] ?? '') === 'fix') {
    header('Content-Type: application/json');
    smpro_require_valid_csrf('lv_fix');
    @ignore_user_abort(true); @set_time_limit(120);   // a started action finishes even if the page is closed
    $op = (string)($_POST['op'] ?? ''); $args = [];
    foreach ((array)($_POST['args'] ?? []) as $k => $v) if (preg_match('/^[a-z_]{1,20}$/', (string)$k)) $args[$k] = (string)$v;
    echo json_encode(smpro_lv_apply($op, $args, smpro_current_actor()), JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

$period = (string)($_GET['period'] ?? '24h'); if (!in_array($period, ['1h', '24h', '7d'], true)) $period = '24h';
$csrf = smpro_csrf_generate('lv_fix');
$OPS = smpro_lv_ops();
smpro_layout_header('Resource Limit Reached');

if (!smpro_lv_present()) { ?>
<h1 class="h">Resource Limit Reached <span class="sub" style="font-weight:400">CloudLinux LVE</span></h1>
<div class="card" style="margin-top:14px;border-left:4px solid var(--warn);display:flex;gap:14px;align-items:flex-start">
  <div style="font-size:26px">&#9201;</div>
  <div><b style="font-size:15px">This server has no CloudLinux LVE</b>
    <p class="sub" style="margin:6px 0 0">The "Resource Limit Is Reached" page (HTTP 508) is produced by CloudLinux's per-account limits (LVE). lvectl or /proc/lve/list is not here, so there is nothing to read or reset on this server. On a plain cPanel server the same symptom (a site that stops answering under load) is handled from Server Health &amp; System and Top Processes.</p></div>
</div>
<?php smpro_layout_footer(); return; }

$expired = smpro_lv_tick();                       // lifts whose time is up go back even when no cron ran
$hist = smpro_lv_faults($period);
$now = smpro_lv_now();
$limits = smpro_lv_limits();
$lifts = smpro_lv_lifts();

/* the rows: every account that hit a limit in the period, is at its ceiling this second, or has a lift in force */
$users = array_keys($hist['rows']);
foreach ($now as $u => $n) if (($n['lep'] > 0 && $n['ep'] >= $n['lep']) || ($n['lmemphy_mb'] > 0 && $n['memphy_mb'] >= $n['lmemphy_mb'] * 0.95) || ($n['lnproc'] > 0 && $n['nproc'] >= $n['lnproc'])) $users[] = $u;
foreach (array_keys($lifts) as $u) $users[] = $u;
$users = array_values(array_unique($users));
$hitNow = 0; foreach ($users as $u) { $n = $now[$u] ?? null; if ($n && (($n['lep'] > 0 && $n['ep'] >= $n['lep']) || ($n['lnproc'] > 0 && $n['nproc'] >= $n['lnproc']))) $hitNow++; }
$totalFaults = 0; foreach ($hist['rows'] as $r) $totalFaults += $r['faults'];
smpro_audit('resource_limits_view', ['period' => $period, 'accounts' => count($users), 'faults' => $totalFaults, 'now' => $hitNow, 'lifts' => count($lifts)]);
?>
<style>
.lv-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px;margin:12px 0}
.lv-kpi{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 14px}.lv-kpi .v{font-size:24px;font-weight:800;line-height:1.1}.lv-kpi .l{font-size:12px;color:var(--muted)}
.lv-kpi.bad .v{color:var(--dang)}.lv-kpi.warn .v{color:var(--warn)}.lv-kpi.good .v{color:var(--good)}
.lv-tbl{width:100%;border-collapse:collapse;font-size:13px}.lv-tbl th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);padding:8px;border-bottom:1px solid var(--line)}
.lv-tbl td{padding:9px 8px;border-bottom:1px solid var(--line);vertical-align:top}.lv-tbl tr:last-child td{border-bottom:0}
.lv-u{font-weight:800;font-size:13.5px}.lv-chip{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:999px;margin:0 4px 4px 0}
.lv-chip.ep{background:var(--dang-bg);color:var(--dang)}.lv-chip.mem{background:var(--warn-bg);color:var(--warn)}.lv-chip.np{background:var(--brand-bg);color:var(--brand)}.lv-chip.cpu{background:var(--bg);color:var(--text)}.lv-chip.io{background:var(--bg);color:var(--muted)}.lv-chip.lift{background:var(--good-bg);color:var(--good)}
.lv-why{font-size:12px;color:var(--muted);line-height:1.5;margin-top:3px}
.lv-now{font-size:12.5px;line-height:1.6;font-variant-numeric:tabular-nums}.lv-now b.hit{color:var(--dang)}
.lv-acts{display:flex;flex-wrap:wrap;gap:6px;align-items:center}
.lv-btn{font-size:12px;font-weight:700;padding:5px 11px;border-radius:8px;border:1px solid var(--brand);background:transparent;color:var(--brand);cursor:pointer}.lv-btn:hover{background:var(--brand-bg)}.lv-btn[disabled]{opacity:.5;cursor:default}
.lv-btn.dang{border-color:var(--dang);color:var(--dang)}.lv-btn.dang:hover{background:var(--dang-bg)}
.lv-sel{font-size:12px;padding:4px 6px;border-radius:7px;border:1px solid var(--line);background:var(--card);color:var(--text)}
.lv-res{font-size:12px;margin-top:6px;padding:6px 10px;border-radius:6px}.lv-res.ok{background:var(--good-bg);color:var(--good)}.lv-res.bad{background:var(--dang-bg);color:var(--dang)}
.lv-procs{margin-top:6px;font-size:11.5px}.lv-procs summary{cursor:pointer;color:var(--brand);font-weight:600}.lv-procs table{width:100%;border-collapse:collapse;margin-top:4px}.lv-procs td{padding:2px 6px;border-bottom:1px dashed var(--line);font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11px;word-break:break-all}
.lv-procs tr.old td{color:var(--dang)}
.lv-note{background:var(--bg);border-left:3px solid var(--brand);padding:8px 12px;border-radius:0 8px 8px 0;font-size:12.5px;line-height:1.6;margin:12px 0}
.lv-warn{background:var(--warn-bg);color:var(--warn);padding:8px 12px;border-radius:8px;font-size:12.5px;margin:10px 0}
.lv-bar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:10px 0}
</style>

<h1 class="h">Resource Limit Reached <span class="sub" style="font-weight:400">which accounts hit their CloudLinux limits, and the way out</span></h1>
<p class="sub">A visitor sees <i>"Resource Limit Is Reached - The website is temporarily unable to service your request as it exceeded resource limit"</i> when the account's LVE refuses a new request: usually every allowed <b>entry process</b> is busy (hung PHP requests, a stuck cron, a bot flood), sometimes the <b>memory</b> or <b>process</b> ceiling. This page shows who hit which limit, what is running this second, and three ways out - each backed up and audited.</p>

<div class="lv-bar">
  <form method="get" style="display:inline-flex;gap:6px;align-items:center"><input type="hidden" name="page" value="resource-limits"><label class="sub" for="lvP">Period</label>
    <select class="lv-sel" id="lvP" name="period" onchange="this.form.submit()"><?php foreach (['1h' => 'last hour', '24h' => 'last 24 hours', '7d' => 'last 7 days'] as $k => $v): ?><option value="<?= $k ?>"<?= $k === $period ? ' selected' : '' ?>><?= $v ?></option><?php endforeach; ?></select></form>
  <input class="lv-sel" id="lvF" type="search" placeholder="filter: account" style="min-width:200px">
</div>

<div class="lv-kpis">
  <div class="lv-kpi <?= $hitNow ? 'bad' : 'good' ?>"><div class="v"><?= $hitNow ?></div><div class="l">at a ceiling this second (508 right now)</div></div>
  <div class="lv-kpi <?= count($hist['rows']) ? 'warn' : 'good' ?>"><div class="v"><?= $hist['ok'] ? count($hist['rows']) : '?' ?></div><div class="l">accounts that hit a limit (<?= smpro_h($period) ?>)</div></div>
  <div class="lv-kpi"><div class="v"><?= $hist['ok'] ? $totalFaults : '?' ?></div><div class="l">refused / throttled events (<?= smpro_h($period) ?>)</div></div>
  <div class="lv-kpi <?= $lifts ? 'warn' : '' ?>"><div class="v"><?= count($lifts) ?></div><div class="l">lifts in force (go back by themselves)</div></div>
</div>
<?php if (!$hist['ok']): ?><div class="lv-warn">&#9888; History could not be read: <?= smpro_h($hist['why']) ?>. The "this second" column below is read from the kernel and is still true.</div><?php endif; ?>
<?php foreach ($expired as $u => $r): ?><div class="lv-res <?= $r['ok'] ? 'ok' : 'bad' ?>">Lift expired: <?= smpro_h($r['msg']) ?></div><?php endforeach; ?>

<div class="card" style="margin-top:8px">
<?php if (!$users): ?>
  <div class="sub" style="padding:12px">No account hit a limit in the <?= smpro_h($period) ?> period and none is at a ceiling this second<?= $hist['ok'] ? '' : ' (as far as the kernel table shows; the history could not be read)' ?>.</div>
<?php else: ?>
  <div class="smpro-tablewrap"><table class="lv-tbl" id="lvTbl"><thead><tr><th>Account</th><th>What was hit (<?= smpro_h($period) ?>)</th><th>This second</th><th>Limits</th><th>Actions</th></tr></thead><tbody>
  <?php foreach ($users as $u): $f = $hist['rows'][$u] ?? []; $n = $now[$u] ?? null; $L = smpro_lv_limits_of($u, $limits); $lift = $lifts[$u] ?? null;
        $procs = smpro_lv_procs($u); $hung = 0; foreach ($procs as $p) if (($p['kind'] === 'php' || $p['kind'] === 'cron') && $p['secs'] >= 120) $hung++;
        $epHit = $n && $n['lep'] > 0 && $n['ep'] >= $n['lep']; ?>
    <tr data-u="<?= smpro_h($u) ?>">
      <td><div class="lv-u"><?= smpro_h($u) ?></div><?php if ($lift): ?><span class="lv-chip lift">lifted until <?= date('H:i', (int)$lift['until']) ?></span><?php endif; ?>
        <div class="lv-why" style="font-size:11.5px"><a href="index.cgi?page=user-investigation&amp;user=<?= smpro_h($u) ?>&amp;win=1">investigate &#8250;</a> &middot; <a href="index.cgi?page=load-monitor">overload investigator &#8250;</a></div></td>
      <td>
        <?php if ($f): ?>
          <?php if ($f['ep_f']): ?><span class="lv-chip ep">entry processes &times;<?= (int)$f['ep_f'] ?></span><?php endif; ?>
          <?php if ($f['pmem_f'] || $f['vmem_f']): ?><span class="lv-chip mem">memory &times;<?= (int)$f['pmem_f'] + (int)$f['vmem_f'] ?></span><?php endif; ?>
          <?php if ($f['nproc_f']): ?><span class="lv-chip np">processes &times;<?= (int)$f['nproc_f'] ?></span><?php endif; ?>
          <?php if ($f['cpu_f'] || ($f['cpu_lim'] > 0 && $f['cpu_max'] >= $f['cpu_lim'] * 0.98)): ?><span class="lv-chip cpu">CPU throttled<?= $f['cpu_f'] ? ' &times;' . (int)$f['cpu_f'] : '' ?></span><?php endif; ?>
          <?php if ($f['io_f']): ?><span class="lv-chip io">I/O throttled &times;<?= (int)$f['io_f'] ?></span><?php endif; ?>
        <?php elseif ($lift): ?><span class="sub">nothing in this period</span><?php else: ?><span class="lv-chip ep">at a ceiling now</span><?php endif; ?>
        <div class="lv-why"><?= smpro_h(smpro_lv_explain($f, $n ?? [])) ?></div>
      </td>
      <td class="lv-now"><?php if ($n): ?>
        entry processes <b class="<?= $epHit ? 'hit' : '' ?>"><?= (int)$n['ep'] ?> / <?= (int)$n['lep'] ?: '&infin;' ?></b><br>
        memory <b class="<?= $n['lmemphy_mb'] > 0 && $n['memphy_mb'] >= $n['lmemphy_mb'] * 0.95 ? 'hit' : '' ?>"><?= (int)$n['memphy_mb'] ?> / <?= (int)$n['lmemphy_mb'] ?: '&infin;' ?> MB</b><br>
        processes <b class="<?= $n['lnproc'] > 0 && $n['nproc'] >= $n['lnproc'] ? 'hit' : '' ?>"><?= (int)$n['nproc'] ?> / <?= (int)$n['lnproc'] ?: '&infin;' ?></b><br>
        <span class="sub">refused since boot: <?= (int)$n['fep'] ?> ep &middot; <?= (int)$n['fmemphy'] ?> mem &middot; <?= (int)$n['fnproc'] ?> proc</span>
        <?php else: ?><span class="sub">idle - no process in its LVE right now</span><?php endif; ?>
        <?php if ($procs): ?><details class="lv-procs"><summary><?= count($procs) ?> process(es)<?= $hung ? ', ' . $hung . ' hung for 2+ min' : '' ?></summary><table>
          <?php foreach (array_slice($procs, 0, 25) as $p): ?><tr class="<?= ($p['kind'] !== 'other' && $p['secs'] >= 120) ? 'old' : '' ?>"><td><?= (int)$p['pid'] ?></td><td><?= $p['secs'] >= 3600 ? intdiv($p['secs'], 3600) . 'h' . intdiv($p['secs'] % 3600, 60) . 'm' : ($p['secs'] >= 60 ? intdiv($p['secs'], 60) . 'm' . ($p['secs'] % 60) . 's' : $p['secs'] . 's') ?></td><td><?= (int)$p['rss_mb'] ?>M</td><td><?= smpro_h(substr($p['cmd'], 0, 110)) ?></td></tr><?php endforeach; ?>
        </table></details><?php endif; ?>
      </td>
      <td class="lv-now">CPU <?= (int)$L['speed'] ?>% &middot; mem <?= (int)$L['pmem_mb'] ?> MB<br>entry <?= (int)$L['ep'] ?> &middot; proc <?= (int)$L['nproc'] ?><br>I/O <?= (int)$L['io'] ?> KB/s<?php if ($lift): ?><br><span class="sub">before the lift: entry <?= (int)$lift['prev']['ep'] ?> &middot; mem <?= (int)$lift['prev']['pmem_mb'] ?> MB</span><?php endif; ?></td>
      <td>
        <div class="lv-acts">
          <button type="button" class="lv-btn dang" data-op="kill_hung" data-args="<?= smpro_h(json_encode(['user' => $u])) ?>" data-confirm="<?= smpro_h($OPS['kill_hung']['confirm']) ?>"<?= $hung ? '' : ' title="no PHP/cron process of this account has run 2+ minutes right now"' ?>><?= smpro_h($OPS['kill_hung']['label']) ?><?= $hung ? ' (' . $hung . ')' : '' ?></button>
        </div>
        <div class="lv-acts" style="margin-top:6px">
          <?php if ($lift): ?>
            <button type="button" class="lv-btn" data-op="putback" data-args="<?= smpro_h(json_encode(['user' => $u])) ?>" data-confirm="<?= smpro_h($OPS['putback']['confirm']) ?>"><?= smpro_h($OPS['putback']['label']) ?> now</button>
          <?php else: ?>
            <select class="lv-sel lv-min"><option value="15">15 min</option><option value="60" selected>1 hour</option><option value="240">4 hours</option></select>
            <button type="button" class="lv-btn" data-op="lift" data-args="<?= smpro_h(json_encode(['user' => $u])) ?>" data-confirm="<?= smpro_h($OPS['lift']['confirm']) ?>"><?= smpro_h($OPS['lift']['label']) ?> &times;2</button>
          <?php endif; ?>
          <button type="button" class="lv-btn" data-op="reset" data-args="<?= smpro_h(json_encode(['user' => $u])) ?>" data-confirm="<?= smpro_h($OPS['reset']['confirm']) ?>"><?= smpro_h($OPS['reset']['label']) ?></button>
        </div>
        <div class="sub" style="font-size:11px;margin-top:4px">ve.cfg backed up first &middot; audited</div>
      </td>
    </tr>
  <?php endforeach; ?>
  </tbody></table></div>
<?php endif; ?>
</div>

<div class="lv-note">
  <b>What each button does.</b><br>
  <b>End the hung PHP processes</b> - sends TERM (then KILL) to this account's PHP and cron processes that have run for 2+ minutes. A web request that old is not serving anyone; ending it frees the entry-process slots and the 508 clears at once. Nothing on disk is touched. If none is hung, the limit is being hit by many short requests - look at the traffic (Bot Guard) or lift the limits.<br>
  <b>Lift the limits &times;2</b> - doubles entry processes (at least 40), memory (at least 2 GB), processes and CPU (at most 400%) for 15 min / 1 h / 4 h, then puts the previous values back by itself (a 5-minute cron while a lift is in force, and again when this page is opened). Use it to get a site through a sale, an import or a cleanup.<br>
  <b>Put back</b> - ends a lift early. <b>Reset to package limits</b> - drops the account's custom LVE entry so it follows its package again (the fix when a limit was lowered by hand long ago).<br>
  Permanent higher limits belong in WHM &gt; CloudLinux LVE Manager (per package or per user); this page is for the moment the site is down.
</div>

<script>
(function(){
  var CSRF = <?= json_encode($csrf) ?>;
  document.getElementById('lvF').addEventListener('input', function(){ var q=this.value.toLowerCase(); document.querySelectorAll('#lvTbl tbody tr').forEach(function(tr){ tr.style.display = (tr.getAttribute('data-u')||'').toLowerCase().indexOf(q)>=0 ? '' : 'none'; }); });
  document.querySelectorAll('.lv-btn[data-op]').forEach(function(b){
    b.addEventListener('click', function(){
      if (!confirm(b.getAttribute('data-confirm') || 'Apply?')) return;
      b.disabled = true; var old = b.innerHTML; b.textContent = 'working…';
      /* url-encoded on purpose: index.cgi reads POST bodies with parse_str and refuses multipart */
      var fd = new URLSearchParams(); fd.append('lv_action','fix'); fd.append('smpro_csrf', CSRF); fd.append('op', b.getAttribute('data-op'));
      var args = {}; try { args = JSON.parse(b.getAttribute('data-args')||'{}'); } catch(e){}
      if (b.getAttribute('data-op') === 'lift') { var s = b.parentNode.querySelector('.lv-min'); args.minutes = s ? s.value : '60'; }
      Object.keys(args).forEach(function(k){ fd.append('args['+k+']', args[k]); });
      fetch('index.cgi?page=resource-limits', {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:fd.toString(), credentials:'same-origin'}).then(function(r){ return r.json(); }).then(function(j){
        var res = document.createElement('div'); res.className = 'lv-res ' + (j.ok ? 'ok' : 'bad');
        res.textContent = (j.ok ? 'Done: ' : 'Not done: ') + (j.msg || '') + (j.backup ? '  [backup: ' + j.backup + ']' : '');
        b.closest('td').appendChild(res);
        if (j.ok) { b.textContent = 'done'; setTimeout(function(){ location.reload(); }, 2500); } else { b.disabled = false; b.innerHTML = old; }
      }).catch(function(){ b.disabled = false; b.innerHTML = old; alert('The request did not complete. Reload the page and look at the row again.'); });
    });
  });
})();
</script>
<?php smpro_layout_footer();
