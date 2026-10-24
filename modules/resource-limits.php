<?php
/**
 * modules/resource-limits.php - "Resource Limit Is Reached" (HTTP 508): which accounts hit their CloudLinux LVE
 * limits, what is hitting them this second, and the ways out. Engine: includes/lvelimits.php. Every action backs
 * ve.cfg up first and is audited; a lift puts itself back when its time is up.
 * The table is the page's own: search by account OR domain, paging, multi-select with a bulk bar - the shared
 * auto-pager is kept off it (data-nopage) so there is exactly one search box and one pager.
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
$q = trim((string)($_GET['q'] ?? ''));
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
$doms = smpro_lv_domains_map();
$kstate = smpro_lv_kernel_state();

/* the rows: EVERY account on the server - the ones that hit a limit in the period first, then the ones at a ceiling
   this second, then lifted ones, then the calm ones (a calm account is a row that says it hit nothing, so the operator
   can search any site and see its state and processes). Processes come from ONE ps for the whole server. */
$atCeil = function (?array $n): bool { return $n && (($n['lep'] > 0 && $n['ep'] >= $n['lep']) || ($n['lmemphy_mb'] > 0 && $n['memphy_mb'] >= $n['lmemphy_mb'] * 0.95) || ($n['lnproc'] > 0 && $n['nproc'] >= $n['lnproc'])); };
$allAcct = smpro_lv_accounts();
$rank = [];
foreach ($allAcct as $u) $rank[$u] = (isset($hist['rows'][$u]) ? 0 : ($atCeil($now[$u] ?? null) ? 1 : (isset($lifts[$u]) ? 2 : 3)));
foreach (array_keys($hist['rows']) as $u) if (!isset($rank[$u])) $rank[$u] = 0;     // an LVE id that is not in /var/cpanel/users is still shown
foreach ($now as $u => $n) if (!isset($rank[$u]) && $atCeil($n)) $rank[$u] = 1;
foreach (array_keys($lifts) as $u) if (!isset($rank[$u])) $rank[$u] = 2;
$lookedUp = $q !== '' ? smpro_lv_resolve($q, $doms) : ''; if ($lookedUp !== '') $rank[$lookedUp] = -1;   // the searched one first
uksort($rank, function ($a, $b) use ($rank, $hist) { return ($rank[$a] <=> $rank[$b]) ?: ((int)($hist['rows'][$b]['faults'] ?? 0) <=> (int)($hist['rows'][$a]['faults'] ?? 0)) ?: strcasecmp($a, $b); });
$users = array_keys($rank);
$procsAll = smpro_lv_procs_all();
$hitNow = 0; foreach ($users as $u) { $n = $now[$u] ?? null; if ($n && (($n['lep'] > 0 && $n['ep'] >= $n['lep']) || ($n['lnproc'] > 0 && $n['nproc'] >= $n['lnproc']))) $hitNow++; }
$totalFaults = 0; foreach ($hist['rows'] as $r) $totalFaults += $r['faults'];
$calm = 0; foreach ($rank as $u => $r) if ($r === 3) $calm++;
smpro_audit('resource_limits_view', ['period' => $period, 'accounts' => count($users), 'hit' => count($hist['rows']), 'faults' => $totalFaults, 'now' => $hitNow, 'lifts' => count($lifts)]);
$fmtAge = function (int $s): string { return $s >= 3600 ? intdiv($s, 3600) . 'h' . intdiv($s % 3600, 60) . 'm' : ($s >= 60 ? intdiv($s, 60) . 'm' . ($s % 60) . 's' : $s . 's'); };
?>
<style>
.lv-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px;margin:12px 0}
.lv-kpi{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 14px}.lv-kpi .v{font-size:24px;font-weight:800;line-height:1.1}.lv-kpi .l{font-size:12px;color:var(--muted)}
.lv-kpi.bad .v{color:var(--dang)}.lv-kpi.warn .v{color:var(--warn)}.lv-kpi.good .v{color:var(--good)}
.lv-tbl{width:100%;border-collapse:collapse;font-size:13px}.lv-tbl th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);padding:8px;border-bottom:1px solid var(--line)}
.lv-tbl td{padding:9px 8px;border-bottom:1px solid var(--line);vertical-align:top}.lv-tbl tr:last-child td{border-bottom:0}.lv-tbl tr.hide{display:none}.lv-tbl tr.sel td{background:var(--brand-bg)}
.lv-u{font-weight:800;font-size:13.5px}.lv-dom{font-size:11.5px;color:var(--muted);word-break:break-all}
.lv-chip{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:999px;margin:0 4px 4px 0}
.lv-chip.ep{background:var(--dang-bg);color:var(--dang)}.lv-chip.mem{background:var(--warn-bg);color:var(--warn)}.lv-chip.np{background:var(--brand-bg);color:var(--brand)}.lv-chip.cpu{background:var(--bg);color:var(--text)}.lv-chip.io{background:var(--bg);color:var(--muted)}.lv-chip.lift{background:var(--good-bg);color:var(--good)}.lv-chip.calm{background:var(--good-bg);color:var(--good);font-weight:600}
.lv-why{font-size:12px;color:var(--muted);line-height:1.5;margin-top:3px}
.lv-todo{font-size:12.3px;line-height:1.5;margin-top:6px;padding:6px 9px;border-radius:7px;background:var(--bg);border-left:3px solid var(--brand)}.lv-todo b{color:var(--brand)}
.lv-todo.kill{border-left-color:var(--dang)}.lv-todo.kill b{color:var(--dang)}.lv-todo.lift{border-left-color:var(--warn)}.lv-todo.lift b{color:var(--warn)}.lv-todo.none,.lv-todo.cpu,.lv-todo.io{border-left-color:var(--line)}.lv-todo.none b,.lv-todo.cpu b,.lv-todo.io b{color:var(--muted)}
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
.lv-bulk{display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:8px 10px;border:1px solid var(--line);border-radius:10px;background:var(--card);margin:0 0 8px}.lv-bulk .n{font-weight:800;color:var(--brand)}
.lv-pg{display:flex;gap:8px;align-items:center;justify-content:flex-end;padding:8px;font-size:12px;color:var(--muted)}.lv-pg button{font-size:12px;padding:3px 10px;border-radius:7px;border:1px solid var(--line);background:var(--card);color:var(--text);cursor:pointer}.lv-pg button[disabled]{opacity:.4;cursor:default}
.lv-bulklog{font-size:12px;margin-top:6px;max-height:220px;overflow:auto;font-family:ui-monospace,Menlo,Consolas,monospace;white-space:pre-wrap}
</style>

<h1 class="h">Resource Limit Reached <span class="sub" style="font-weight:400">which accounts hit their CloudLinux limits, and the way out</span></h1>
<p class="sub">A visitor sees <i>"Resource Limit Is Reached - The website is temporarily unable to service your request as it exceeded resource limit"</i> when the account's LVE refuses a new request: usually every allowed <b>entry process</b> is busy (hung PHP requests, a stuck cron, a bot flood), sometimes the <b>memory</b> or <b>process</b> ceiling. Each row says which limit, why, what runs this second, and the one thing to do - in the words of the buttons.</p>

<div class="lv-kpis">
  <div class="lv-kpi <?= $hitNow ? 'bad' : 'good' ?>"><div class="v"><?= $hitNow ?></div><div class="l">at a ceiling this second (508 right now)</div></div>
  <div class="lv-kpi <?= count($hist['rows']) ? 'warn' : 'good' ?>"><div class="v"><?= $hist['ok'] ? count($hist['rows']) : '?' ?></div><div class="l">accounts that hit a limit (<?= smpro_h($period) ?>)</div></div>
  <div class="lv-kpi"><div class="v"><?= $hist['ok'] ? $totalFaults : '?' ?></div><div class="l">refused / throttled events (<?= smpro_h($period) ?>)</div></div>
  <div class="lv-kpi <?= $lifts ? 'warn' : '' ?>"><div class="v"><?= count($lifts) ?></div><div class="l">lifts in force (go back by themselves)</div></div>
  <div class="lv-kpi good"><div class="v"><?= $calm ?></div><div class="l">calm accounts (of <?= count($users) ?> on the server) - listed too, below the others</div></div>
</div>
<?php if ($q !== '' && $lookedUp === ''): ?><div class="lv-warn">&#9888; "<?= smpro_h($q) ?>" is not an account on this server and no account owns that domain (checked cPanel's own domain list).</div><?php endif; ?>
<?php if ($q !== '' && $lookedUp !== '' && !isset($hist['rows'][$lookedUp]) && !isset($lifts[$lookedUp])): ?><div class="lv-res ok">"<?= smpro_h($q) ?>" belongs to account <b><?= smpro_h($lookedUp) ?></b>, which hit NO limit in the <?= smpro_h($period) ?> period - its row is shown first so you can see what runs now; a 508 on this site right now would come from something else (a PHP error page, the handler, Site Shield). Try the 7-day period to be sure.</div><?php endif; ?>
<?php if ($kstate['broken']): ?><div class="lv-warn" style="background:var(--dang-bg);color:var(--dang)"><b>&#9888; The LVE kernel module is refusing to enforce limits on this server</b> - <?= (int)$kstate['n'] ?> kernel errors in the last 2 hours (last: <code><?= smpro_h($kstate['last']) ?></code>). <?= smpro_h($kstate['why']) ?>. Until then every "Lift" and "Reset" fails with "Can't setup lve ... error code -2", and NEW processes may be running outside their limits - the numbers in "This second" can be lower than the truth.</div><?php elseif (!empty($kstate['module']['mismatch'])): ?><div class="lv-warn">&#9888; The LVE kernel module was updated on disk (<?= smpro_h($kstate['module']['disk']) ?>) but <?= smpro_h($kstate['module']['loaded']) ?> is still loaded - limits keep working on the old one, but a reboot is pending to load the new one.</div><?php elseif ($kstate['n'] > 0): ?><div class="lv-warn">&#9888; <?= (int)$kstate['n'] ?> LVE kernel error(s) in the last 2 hours (last: <code><?= smpro_h($kstate['last']) ?></code>) - if a lift is refused, this is why.</div><?php endif; ?>
<?php if (!$hist['ok']): ?><div class="lv-warn">&#9888; History could not be read: <?= smpro_h($hist['why']) ?>. The "this second" column below is read from the kernel and is still true.</div><?php endif; ?>
<?php foreach ($expired as $u => $r): ?><div class="lv-res <?= $r['ok'] ? 'ok' : 'bad' ?>">Lift expired: <?= smpro_h($r['msg']) ?></div><?php endforeach; ?>

<div class="lv-bar">
  <form method="get" style="display:inline-flex;gap:6px;align-items:center"><input type="hidden" name="page" value="resource-limits"><label class="sub" for="lvP">Period</label>
    <select class="lv-sel" id="lvP" name="period" onchange="this.form.submit()"><?php foreach (['1h' => 'last hour', '24h' => 'last 24 hours', '7d' => 'last 7 days'] as $k => $v): ?><option value="<?= $k ?>"<?= $k === $period ? ' selected' : '' ?>><?= $v ?></option><?php endforeach; ?></select></form>
  <input class="lv-sel" id="lvF" type="search" placeholder="search: account or domain (example.com) - Enter looks it up server-wide" style="min-width:300px" value="<?= smpro_h($q) ?>">
  <select class="lv-sel" id="lvV"><option value="">every account</option><option value="hit">hit a limit (<?= smpro_h($period) ?>)</option><option value="calm">calm - hit nothing</option><option value="ep">entry processes</option><option value="mem">memory</option><option value="np">processes</option><option value="cpu">CPU</option><option value="io">I/O</option><option value="lift">lifted</option><option value="hung">hung processes now</option></select>
  <select class="lv-sel" id="lvS"><option value="25">25 / page</option><option value="50">50 / page</option><option value="100">100 / page</option></select>
  <span class="sub" id="lvCount"></span>
</div>

<div class="lv-bulk" id="lvBulk" style="display:none">
  <span><span class="n" id="lvSelN">0</span> selected</span>
  <button type="button" class="lv-btn dang" data-bop="kill_hung"><?= smpro_h($OPS['kill_hung']['label']) ?></button>
  <select class="lv-sel" id="lvBulkMin"><option value="15">15 min</option><option value="60" selected>1 hour</option><option value="240">4 hours</option></select>
  <button type="button" class="lv-btn" data-bop="lift"><?= smpro_h($OPS['lift']['label']) ?> &times;2</button>
  <button type="button" class="lv-btn" data-bop="putback"><?= smpro_h($OPS['putback']['label']) ?></button>
  <button type="button" class="lv-btn" data-bop="reset"><?= smpro_h($OPS['reset']['label']) ?></button>
  <button type="button" class="lv-btn" id="lvSelNone" style="border-color:var(--line);color:var(--muted)">clear selection</button>
  <span class="sub" style="font-size:11px">one account at a time, in order; every step backs up and is audited; the log appears below</span>
  <div class="lv-bulklog" id="lvBulkLog" style="flex-basis:100%;display:none"></div>
</div>

<div class="card" style="margin-top:8px" data-nopage="1">
<?php if (!$users): ?>
  <div class="sub" style="padding:12px">No cPanel account was found on this server (nothing in /var/cpanel/users and no domain map).</div>
<?php else: ?>
  <div class="smpro-tablewrap"><table class="lv-tbl" id="lvTbl"><thead><tr><th><input type="checkbox" id="lvAll" title="select every account shown on this page"></th><th>Account</th><th>What was hit (<?= smpro_h($period) ?>) and what to do</th><th>This second</th><th>Limits</th><th>Actions</th></tr></thead><tbody>
  <?php foreach ($users as $u): $f = $hist['rows'][$u] ?? []; $n = $now[$u] ?? null; $L = smpro_lv_limits_of($u, $limits); $lift = $lifts[$u] ?? null;
        $procs = $procsAll[$u] ?? []; $hung = 0; foreach ($procs as $p) if (($p['kind'] === 'php' || $p['kind'] === 'cron') && $p['secs'] >= 120) $hung++;
        $epHit = $n && $n['lep'] > 0 && $n['ep'] >= $n['lep'];
        $ud = $doms[$u] ?? []; $adv = smpro_lv_advice($f, $n, $hung, (bool)$lift);
        $kinds = [$f ? 'hit' : 'calm']; if (!empty($f['ep_f'])) $kinds[] = 'ep'; if (!empty($f['pmem_f']) || !empty($f['vmem_f'])) $kinds[] = 'mem'; if (!empty($f['nproc_f'])) $kinds[] = 'np'; if (!empty($f['cpu_f'])) $kinds[] = 'cpu'; if (!empty($f['io_f'])) $kinds[] = 'io'; if ($lift) $kinds[] = 'lift'; if ($hung) $kinds[] = 'hung'; if ($epHit) $kinds[] = 'ep';
        $needle = strtolower($u . ' ' . implode(' ', $ud)); ?>
    <tr data-u="<?= smpro_h($u) ?>" data-s="<?= smpro_h($needle) ?>" data-k="<?= smpro_h(implode(' ', array_unique($kinds))) ?>" data-lift="<?= $lift ? 1 : 0 ?>" data-hung="<?= (int)$hung ?>">
      <td><input type="checkbox" class="lvSel" value="<?= smpro_h($u) ?>"></td>
      <td><div class="lv-u"><?= smpro_h($u) ?></div>
        <?php if ($ud): ?><div class="lv-dom"><?= smpro_h(implode(', ', array_slice($ud, 0, 4))) ?><?= count($ud) > 4 ? ' +' . (count($ud) - 4) . ' more' : '' ?></div><?php endif; ?>
        <?php if ($lift): ?><span class="lv-chip lift">lifted until <?= date('H:i', (int)$lift['until']) ?></span><?php endif; ?>
        <div class="lv-why" style="font-size:11.5px"><a href="index.cgi?page=user-investigation&amp;user=<?= smpro_h($u) ?>&amp;win=1">investigate &#8250;</a> &middot; <a href="index.cgi?page=top-processes">top processes &#8250;</a><?php if ($ud): ?> &middot; <a href="index.cgi?page=bot-guard">bot guard &#8250;</a><?php endif; ?></div></td>
      <td>
        <?php if ($f): ?>
          <?php if ($f['ep_f']): ?><span class="lv-chip ep">entry processes &times;<?= (int)$f['ep_f'] ?></span><?php endif; ?>
          <?php if ($f['pmem_f'] || $f['vmem_f']): ?><span class="lv-chip mem">memory &times;<?= (int)$f['pmem_f'] + (int)$f['vmem_f'] ?></span><?php endif; ?>
          <?php if ($f['nproc_f']): ?><span class="lv-chip np">processes &times;<?= (int)$f['nproc_f'] ?></span><?php endif; ?>
          <?php if ($f['cpu_f'] || ($f['cpu_lim'] > 0 && $f['cpu_max'] >= $f['cpu_lim'] * 0.98)): ?><span class="lv-chip cpu">CPU throttled<?= $f['cpu_f'] ? ' &times;' . (int)$f['cpu_f'] : '' ?></span><?php endif; ?>
          <?php if ($f['io_f']): ?><span class="lv-chip io">I/O throttled &times;<?= (int)$f['io_f'] ?></span><?php endif; ?>
        <?php elseif ($lift): ?><span class="sub">nothing in this period</span><?php elseif ($epHit || $atCeil($n)): ?><span class="lv-chip ep">at a ceiling now</span><?php else: ?><span class="lv-chip calm">no limit hit (<?= smpro_h($period) ?>)</span><?php endif; ?>
        <div class="lv-why"><?= smpro_h(smpro_lv_explain($f, $n ?? [])) ?></div>
        <div class="lv-todo <?= smpro_h($adv['kind']) ?>"><b>What to do:</b> <?= smpro_h($adv['text']) ?></div>
      </td>
      <td class="lv-now"><?php if ($n): ?>
        entry processes <b class="<?= $epHit ? 'hit' : '' ?>"><?= (int)$n['ep'] ?> / <?= (int)$n['lep'] ?: '&infin;' ?></b><br>
        memory <b class="<?= $n['lmemphy_mb'] > 0 && $n['memphy_mb'] >= $n['lmemphy_mb'] * 0.95 ? 'hit' : '' ?>"><?= (int)$n['memphy_mb'] ?> / <?= (int)$n['lmemphy_mb'] ?: '&infin;' ?> MB</b><br>
        processes <b class="<?= $n['lnproc'] > 0 && $n['nproc'] >= $n['lnproc'] ? 'hit' : '' ?>"><?= (int)$n['nproc'] ?> / <?= (int)$n['lnproc'] ?: '&infin;' ?></b><br>
        <span class="sub">refused since boot: <?= (int)$n['fep'] ?> ep &middot; <?= (int)$n['fmemphy'] ?> mem &middot; <?= (int)$n['fnproc'] ?> proc</span>
        <?php else: ?><span class="sub">idle - no process in its LVE right now</span><?php endif; ?>
        <?php if ($procs): ?><details class="lv-procs"><summary><?= count($procs) ?> process(es)<?= $hung ? ', ' . $hung . ' hung for 2+ min' : '' ?></summary><table>
          <?php foreach (array_slice($procs, 0, 25) as $p): ?><tr class="<?= ($p['kind'] !== 'other' && $p['secs'] >= 120) ? 'old' : '' ?>"><td><?= (int)$p['pid'] ?></td><td><?= $fmtAge((int)$p['secs']) ?></td><td><?= (int)$p['rss_mb'] ?>M</td><td><?= smpro_h(substr($p['cmd'], 0, 110)) ?></td></tr><?php endforeach; ?>
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
  <div class="lv-pg"><button type="button" id="lvPrev">&#8249; prev</button><span id="lvPgTx"></span><button type="button" id="lvNext">next &#8250;</button></div>
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
  var rows = Array.prototype.slice.call(document.querySelectorAll('#lvTbl tbody tr'));
  var F = document.getElementById('lvF'), V = document.getElementById('lvV'), S = document.getElementById('lvS'), page = 0;
  /* ---- search (account or domain) + kind filter + paging, all over the rows the server rendered ---- */
  function visible(){ var q = (F.value||'').toLowerCase().trim(), k = V.value; return rows.filter(function(tr){
      if (q && (tr.getAttribute('data-s')||'').indexOf(q) < 0) return false;
      if (k && (' ' + (tr.getAttribute('data-k')||'') + ' ').indexOf(' ' + k + ' ') < 0) return false;
      return true; }); }
  function draw(){ var vis = visible(), size = parseInt(S.value, 10) || 25, pages = Math.max(1, Math.ceil(vis.length / size));
    if (page >= pages) page = pages - 1; if (page < 0) page = 0;
    rows.forEach(function(tr){ tr.classList.add('hide'); });
    vis.slice(page * size, (page + 1) * size).forEach(function(tr){ tr.classList.remove('hide'); });
    document.getElementById('lvCount').textContent = vis.length + ' of ' + rows.length + ' listed account(s)' + (vis.length ? ' · showing ' + (page * size + 1) + '–' + Math.min(vis.length, (page + 1) * size) : ((F.value||'').trim() ? ' · not in this list - press Enter to look it up across every account on the server' : ''));
    var tx = document.getElementById('lvPgTx'); if (tx) tx.textContent = 'page ' + (page + 1) + ' / ' + pages;
    var pv = document.getElementById('lvPrev'), nx = document.getElementById('lvNext'); if (pv) pv.disabled = page <= 0; if (nx) nx.disabled = page >= pages - 1;
    var all = document.getElementById('lvAll'); if (all) all.checked = false; }
  if (F) { F.addEventListener('keydown', function(e){ if (e.key === 'Enter') { e.preventDefault(); var u = new URL(location.href); u.searchParams.set('page','resource-limits'); u.searchParams.set('period', document.getElementById('lvP').value); if ((F.value||'').trim()) u.searchParams.set('q', F.value.trim()); else u.searchParams.delete('q'); location.href = u.toString(); } });
    F.addEventListener('input', function(){ page = 0; draw(); }); V.addEventListener('change', function(){ page = 0; draw(); }); S.addEventListener('change', function(){ page = 0; draw(); }); }
  var pv = document.getElementById('lvPrev'), nx = document.getElementById('lvNext');
  if (pv) pv.addEventListener('click', function(){ page--; draw(); }); if (nx) nx.addEventListener('click', function(){ page++; draw(); });
  try { var qs = new URLSearchParams(location.search); if (qs.get('q') && F) F.value = qs.get('q'); } catch(e){}
  if (rows.length) draw();
  /* ---- one request, url-encoded on purpose: index.cgi reads POST bodies with parse_str and refuses multipart ---- */
  function run(op, args){ var fd = new URLSearchParams(); fd.append('lv_action','fix'); fd.append('smpro_csrf', CSRF); fd.append('op', op);
    Object.keys(args).forEach(function(k){ fd.append('args['+k+']', args[k]); });
    return fetch('index.cgi?page=resource-limits', {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:fd.toString(), credentials:'same-origin'}).then(function(r){ return r.json(); }); }
  /* ---- row buttons ---- */
  document.querySelectorAll('.lv-btn[data-op]').forEach(function(b){
    b.addEventListener('click', function(){
      if (!confirm(b.getAttribute('data-confirm') || 'Apply?')) return;
      b.disabled = true; var old = b.innerHTML; b.textContent = 'working…';
      var args = {}; try { args = JSON.parse(b.getAttribute('data-args')||'{}'); } catch(e){}
      if (b.getAttribute('data-op') === 'lift') { var s = b.parentNode.querySelector('.lv-min'); args.minutes = s ? s.value : '60'; }
      run(b.getAttribute('data-op'), args).then(function(j){
        var res = document.createElement('div'); res.className = 'lv-res ' + (j.ok ? 'ok' : 'bad');
        res.textContent = (j.ok ? 'Done: ' : 'Not done: ') + (j.msg || '') + (j.backup ? '  [backup: ' + j.backup + ']' : '');
        b.closest('td').appendChild(res);
        if (j.ok) { b.textContent = 'done'; setTimeout(function(){ location.reload(); }, 2500); } else { b.disabled = false; b.innerHTML = old; }
      }).catch(function(){ b.disabled = false; b.innerHTML = old; alert('The request did not complete. Reload the page and look at the row again.'); });
    });
  });
  /* ---- multi-select + bulk bar: the selected accounts, one after another, with a log line each ---- */
  function selected(){ return Array.prototype.slice.call(document.querySelectorAll('.lvSel:checked')).map(function(c){ return c.value; }); }
  function refreshSel(){ var n = selected().length; document.getElementById('lvSelN').textContent = n; document.getElementById('lvBulk').style.display = n ? '' : 'none';
    rows.forEach(function(tr){ var c = tr.querySelector('.lvSel'); tr.classList.toggle('sel', !!(c && c.checked)); }); }
  document.addEventListener('change', function(e){ if (e.target.classList && e.target.classList.contains('lvSel')) refreshSel(); });
  var all = document.getElementById('lvAll'); if (all) all.addEventListener('change', function(){ rows.forEach(function(tr){ if (!tr.classList.contains('hide')) { var c = tr.querySelector('.lvSel'); if (c) c.checked = all.checked; } }); refreshSel(); });
  var none = document.getElementById('lvSelNone'); if (none) none.addEventListener('click', function(){ rows.forEach(function(tr){ var c = tr.querySelector('.lvSel'); if (c) c.checked = false; }); refreshSel(); });
  var CONFIRM = <?= json_encode(array_map(fn($o) => $o['confirm'], $OPS)) ?>;
  document.querySelectorAll('.lv-btn[data-bop]').forEach(function(b){
    b.addEventListener('click', function(){
      var users = selected(), op = b.getAttribute('data-bop'); if (!users.length) return;
      if (!confirm('Run on ' + users.length + ' account(s), one after another?\n\n' + (CONFIRM[op] || ''))) return;
      var log = document.getElementById('lvBulkLog'); log.style.display = ''; log.textContent = '';
      var bar = document.querySelectorAll('.lv-btn[data-bop]'); bar.forEach(function(x){ x.disabled = true; });
      var i = 0, okN = 0, badN = 0;
      (function next(){ if (i >= users.length) { log.textContent += '\n' + okN + ' done, ' + badN + ' not done.' + (okN ? ' Reloading…' : ''); bar.forEach(function(x){ x.disabled = false; }); if (okN) setTimeout(function(){ location.reload(); }, 3000); return; }
        var u = users[i++]; var args = {user: u}; if (op === 'lift') args.minutes = document.getElementById('lvBulkMin').value;
        log.textContent += u + ': working…\n';
        run(op, args).then(function(j){ if (j.ok) okN++; else badN++; log.textContent = log.textContent.replace(u + ': working…\n', u + ': ' + (j.ok ? 'done - ' : 'NOT done - ') + (j.msg || '') + '\n'); log.scrollTop = log.scrollHeight; next(); })
          .catch(function(){ badN++; log.textContent = log.textContent.replace(u + ': working…\n', u + ': NOT done - the request did not complete\n'); next(); });
      })();
    });
  });
})();
</script>
<?php smpro_layout_footer();
