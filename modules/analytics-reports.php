<?php
/**
 * modules/analytics-reports.php — Analytics / Change-Log dashboard (read-only).
 * Admin/analyst view: every CHANGE made on the server (IP blocks, service
 * controls, security fixes, report actions) plus security events — across all
 * sections, filterable by time period and change type, with CSV/HTML/PDF export.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

require_once SMPRO_BASE . '/includes/analytics.php';   // smpro_ar_du / smpro_ar_sh / smpro_ar_reports: shared with the notify worker, which keeps the counts warm
function smpro_ar_bytes($b) { $u = ['B','KB','MB','GB','TB']; $b = (float)$b; $i = 0; while ($b >= 1024 && $i < 4) { $b /= 1024; $i++; } return round($b, $i ? 1 : 0) . ' ' . $u[$i]; }
function smpro_ar_label($a) {
    static $map = [
        'dashboard_view'=>'Dashboard viewed','server_health_view'=>'Server Health viewed','top_processes_view'=>'Top Processes viewed',
        'account_audit_view'=>'Account Audit viewed','account_audit_report_delete'=>'Audit report deleted',
        'login_monitor_view'=>'Login Monitor viewed','login_correlation_view'=>'Login Correlation viewed','firewall_status_view'=>'Firewall Status viewed',
        'security_health_view'=>'Security Health scanned','security_health_apply'=>'Security fix applied','analytics_reports_view'=>'Analytics viewed','cpanel_services_view'=>'Services viewed',
        'firewall_unblock'=>'IP unblocked (Firewall)','login_monitor_csf_block'=>'IP blocked','login_monitor_csf_allow'=>'IP allow-listed','login_monitor_csf_unblock'=>'IP unblocked',
        'login_correlation_csf_block'=>'IP blocked','login_correlation_csf_allow'=>'IP allow-listed','login_correlation_csf_unblock'=>'IP unblocked',
        'login_correlation_hide'=>'Result hidden','login_correlation_unhide'=>'Result restored',
        'cpanel_service_restart'=>'Service restarted','cpanel_service_start'=>'Service started','cpanel_service_stop'=>'Service stopped',
        'csrf_failed'=>'Security token rejected','access_denied'=>'Access denied','root_required_denied'=>'Root required (denied)',
    ];
    return $map[$a] ?? ucfirst(str_replace(['_', '-'], ' ', $a));
}
/** Change kind: view / firewall / service / fix / report / security / other. */
function smpro_ar_kind($a) {
    if (substr($a, -5) === '_view') return 'view';
    if (strpos($a,'block')!==false || strpos($a,'allow')!==false || strpos($a,'unblock')!==false || strpos($a,'firewall_')!==false) return 'firewall';
    if (strpos($a,'service_')!==false) return 'service';
    if (strpos($a,'_apply')!==false) return 'fix';
    if (strpos($a,'report')!==false || strpos($a,'hide')!==false) return 'report';
    if (strpos($a,'csrf')!==false || strpos($a,'denied')!==false) return 'security';
    return 'other';
}
function smpro_ar_target($e) { $d = $e['details'] ?? []; foreach (['ip','svc','fix','id','user'] as $k) if (!empty($d[$k])) return (string)$d[$k]; if (!empty($d['ids']) && is_array($d['ids'])) return implode(', ', array_slice($d['ids'],0,3)) . (count($d['ids'])>3?' +'.(count($d['ids'])-3):''); return ''; }
function smpro_ar_result($e) { $d = $e['details'] ?? []; if (array_key_exists('ok',$d)) return $d['ok'] ? 'ok' : 'fail'; if (!empty($d['deleted'])) return 'ok'; return ''; }

/* ---------- operational reports (spam / attacks / brute-force / imunify / backup) ---------- */
// Run through `sh -c` so a pipeline that BEGINS with a brace group — `{ cat a; zcat b; } | grep | tail` from the
// rotation-aware reader — is valid. Without the explicit shell, `timeout 14 { … }` is a sh syntax error, and
// EVERY counter silently returned 0 (a monitor reporting "all clear" unconditionally).

/* ---------- filters ---------- */
$KINDS = ['all'=>'All changes','firewall'=>'Firewall / IP actions','service'=>'Service controls','fix'=>'Security fixes','report'=>'Report actions','security'=>'Security events','view'=>'Page views'];
$kindColor = ['firewall'=>'#d93b3b','service'=>'#3b5bdb','fix'=>'#1f9d55','report'=>'#c47f17','security'=>'#9333ea','view'=>'#94a3b8','other'=>'#64748b'];
$days = (int)($_GET['days'] ?? 7); if (!in_array($days, [1,7,14,30,90], true)) $days = 7;
$hasRange = preg_match('/^\d{4}-\d{2}-\d{2}$/', (string)($_GET['from'] ?? '')) && preg_match('/^\d{4}-\d{2}-\d{2}$/', (string)($_GET['to'] ?? ''));
if ($hasRange) { $from = $_GET['from']; $to = $_GET['to']; $fromTs = strtotime($from.' 00:00:00'); $toTs = strtotime($to.' 23:59:59'); }
else { $toTs = time(); $fromTs = $toTs - $days*86400; $from = date('Y-m-d',$fromTs); $to = date('Y-m-d',$toTs); }
$cat = (string)($_GET['cat'] ?? 'all'); if (!isset($KINDS[$cat])) $cat = 'all';
$fmt = (string)($_GET['format'] ?? '');

/* ---------- parse audit events (time filter) ---------- */
$tailN = min(120000, max(10000, $days * 4000));
$all = [];
if (is_readable(SMPRO_AUDIT_LOG)) foreach (explode("\n", (string)@shell_exec('tail -n ' . $tailN . ' ' . escapeshellarg(SMPRO_AUDIT_LOG) . ' 2>/dev/null')) as $l) {
    $j = json_decode(trim($l), true); if (!is_array($j) || empty($j['action'])) continue;
    $ts = strtotime((string)($j['timestamp'] ?? '')); if (!$ts || $ts < $fromTs || $ts > $toTs) continue;
    $j['_ts'] = $ts; $j['_kind'] = smpro_ar_kind($j['action']); $all[] = $j;
}
/* the change log: everything that changed state (all sections), minus page views */
$logFilter = fn($e) => $cat === 'all' ? $e['_kind'] !== 'view' : $e['_kind'] === $cat;
$log = array_values(array_filter($all, $logFilter));
usort($log, fn($a, $b) => $b['_ts'] <=> $a['_ts']);

/* ---------- export (filtered change log) ---------- */
if (in_array($fmt, ['csv','html','pdf'], true)) {
    if ($fmt === 'csv') {
        $fh = fopen('php://output', 'w');
        smpro_fputcsv($fh, ['time','change','kind','target','result','actor']);
        foreach ($log as $e) smpro_fputcsv($fh, [date('Y-m-d H:i:s',$e['_ts']), smpro_ar_label($e['action']), $e['_kind'], smpro_ar_target($e), smpro_ar_result($e) ?: '-', $e['actor'] ?? 'root']);
        fclose($fh);
    } else { smpro_ar_report($log, $from, $to, $KINDS[$cat], $fmt === 'pdf'); }
    exit;
}

/* ---------- metrics over ALL events in range (admin KPIs) ---------- */
$kc = ['firewall'=>0,'service'=>0,'fix'=>0,'report'=>0,'security'=>0,'view'=>0,'other'=>0];
$byType = []; $failed = 0;
foreach ($all as $e) { $kc[$e['_kind']]++; if ($e['_kind'] !== 'view') { $byType[$e['action']] = ($byType[$e['action']] ?? 0) + 1; if (smpro_ar_result($e) === 'fail') $failed++; } }
arsort($byType);
$totalChanges = $kc['firewall'] + $kc['service'] + $kc['fix'] + $kc['report'] + $kc['security'] + $kc['other'];

/* trend: changes per bucket */
$spanH = ($toTs - $fromTs) / 3600; $chart = []; $hourly = $spanH <= 26;
if ($hourly) { for ($i=23;$i>=0;$i--){ $t=$toTs-$i*3600; $chart[date('Y-m-d H',$t)]=['label'=>date('H',$t),'n'=>0]; } }
else { $st=max($fromTs,$toTs-30*86400); for($t=strtotime(date('Y-m-d',$st));$t<=$toTs;$t+=86400)$chart[date('Y-m-d',$t)]=['label'=>date('m-d',$t),'n'=>0]; }
foreach ($log as $e) { $k = $hourly ? date('Y-m-d H',$e['_ts']) : date('Y-m-d',$e['_ts']); if (isset($chart[$k])) $chart[$k]['n']++; }
$chartMax = max(1, max(array_map(fn($c)=>$c['n'],$chart ?: [['n'=>1]])));

/* secondary state metadata */
$root = SMPRO_VARLIB;
$repIdx = is_file($root.'/reports/index.json') ? (json_decode((string)@file_get_contents($root.'/reports/index.json'), true) ?: []) : [];
$ipc = is_file($root.'/cache/ipintel.json') ? (json_decode((string)@file_get_contents($root.'/cache/ipintel.json'), true) ?: []) : [];
$totalBytes = smpro_ar_du($root) + smpro_ar_du(SMPRO_VARLOG);
$builtMods = 0; foreach (smpro_menu() as $items) foreach ($items as $it) if (!empty($it['built'])) $builtMods++;
$reports = smpro_ar_reports($fromTs, $toTs);
$repMax  = max(1, max(array_map(fn($r)=>(int)$r['n'], $reports)));

smpro_audit('analytics_reports_view', ['days'=>$days,'cat'=>$cat,'changes'=>$totalChanges]);
smpro_layout_header('Analytics Reports');
$expQs = fn($f) => 'index.cgi?page=analytics-reports&format=' . $f . '&days=' . $days . '&from=' . urlencode($from) . '&to=' . urlencode($to) . '&cat=' . urlencode($cat);
function smpro_ar_kbadge($k) { static $m=['firewall'=>['red','Firewall'],'service'=>['blue','Service'],'fix'=>['green','Fix'],'report'=>['orange','Report'],'security'=>['purple','Security'],'view'=>['gray','View'],'other'=>['gray','Other']]; [$c,$t]=$m[$k]??['gray',$k]; return '<span class="kb '.$c.'">'.$t.'</span>'; }
?>
<style>
/* critical layout CSS emitted BEFORE content so the grids never flash unstyled/stacked (FOUC fix) */
.ar-cards{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin:14px 0}
.ar-reports{display:grid;grid-template-columns:repeat(5,1fr);gap:12px}
.ar-chart{display:flex;gap:8px;align-items:flex-end;height:184px;overflow-x:auto}
.ar-two{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin:14px 0}
@media(max-width:1100px){.ar-cards{grid-template-columns:repeat(3,1fr)}}
@media(max-width:1000px){.ar-reports{grid-template-columns:repeat(3,1fr)}}
@media(max-width:900px){.ar-two{grid-template-columns:1fr}}
@media(max-width:600px){.ar-cards{grid-template-columns:repeat(2,1fr)}.ar-reports{grid-template-columns:repeat(2,1fr)}}
</style>
<div class="svc-kicker">Reports</div>
<h1 class="h" style="margin:2px 0 4px">Analytics &amp; Change Log</h1>
<p class="sub">Every change made on the server across all sections — IP blocks, service controls, security fixes, report actions and security events. Filterable &amp; exportable.</p>

<form method="get" action="index.cgi" class="card ar-filters">
  <input type="hidden" name="page" value="analytics-reports">
  <label class="ar-fld">Time range<select class="tp-sel" name="days" id="arDays">
    <?php foreach ([1=>'Last 24 hours',7=>'Last 7 days',14=>'Last 14 days',30=>'Last 30 days',90=>'Last 90 days'] as $k=>$v): ?><option value="<?= $k ?>"<?= $days===$k?' selected':'' ?>><?= $v ?></option><?php endforeach; ?>
  </select></label>
  <label class="ar-fld">From<input class="tp-in" type="date" name="from" id="arFrom" value="<?= smpro_h($from) ?>"></label>
  <label class="ar-fld">To<input class="tp-in" type="date" name="to" id="arTo" value="<?= smpro_h($to) ?>"></label>
  <label class="ar-fld">Change type<select class="tp-sel" name="cat">
    <?php foreach ($KINDS as $k=>$v): ?><option value="<?= smpro_h($k) ?>"<?= $cat===$k?' selected':'' ?>><?= smpro_h($v) ?></option><?php endforeach; ?>
  </select></label>
  <button class="tp-btn primary" type="submit">Apply</button>
  <div class="ar-export"><button class="tp-btn green" type="button" id="arExportBtn">Export ▾</button>
    <div class="ar-menu" id="arExportMenu"><a href="<?= smpro_h($expQs('csv')) ?>">CSV</a><a href="<?= smpro_h($expQs('html')) ?>">HTML</a><a target="_blank" href="<?= smpro_h($expQs('pdf')) ?>">PDF (print)</a></div>
  </div>
</form>

<div class="ar-cards">
  <div class="card ar-c"><div class="lbl">Total changes</div><div class="v"><?= (int)$totalChanges ?></div><div class="meta"><?= smpro_h($from) ?> → <?= smpro_h($to) ?></div></div>
  <div class="card ar-c"><div class="lbl">Firewall / IP actions</div><div class="v" style="color:var(--dang)"><?= (int)$kc['firewall'] ?></div><div class="meta">blocks · allows · unblocks</div></div>
  <div class="card ar-c"><div class="lbl">Service controls</div><div class="v" style="color:var(--brand)"><?= (int)$kc['service'] ?></div><div class="meta">restart · start · stop</div></div>
  <div class="card ar-c"><div class="lbl">Security fixes</div><div class="v" style="color:var(--good)"><?= (int)$kc['fix'] ?></div><div class="meta">applied</div></div>
  <div class="card ar-c"><div class="lbl">Security events</div><div class="v" style="color:<?= $kc['security']?'#9333ea':'var(--good)' ?>"><?= (int)$kc['security'] ?></div><div class="meta">denied · token rejects</div></div>
  <div class="card ar-c"><div class="lbl">Failed actions</div><div class="v" style="color:<?= $failed?'var(--dang)':'var(--good)' ?>"><?= (int)$failed ?></div><div class="meta">need review</div></div>
</div>

<div class="card" style="margin-bottom:14px">
  <div class="ar-head" style="border:0;padding:0 0 10px">Changes over time <span class="meta"><?= $hourly?'last 24 hours':'by day' ?> · <?= smpro_h($KINDS[$cat]) ?></span></div>
  <div class="ar-chart">
    <?php foreach ($chart as $b): ?><div class="ar-col" title="<?= smpro_h($b['label']) ?>: <?= (int)$b['n'] ?>"><div class="ar-colbar" style="height:<?= max(4,round(sqrt($b['n']/$chartMax)*130)) ?>px"></div><div class="ar-coln"><?= (int)$b['n'] ?></div><div class="ar-cold"><?= smpro_h($b['label']) ?></div></div><?php endforeach; ?>
  </div>
</div>

<!-- Security & operations reports (stacked) -->
<div class="card" style="margin-bottom:14px">
  <div class="ar-head" style="border:0;padding:0 0 10px">Security &amp; operations reports <span class="meta">spam · web attacks · brute-force · Imunify · backups — for <?= smpro_h($from) ?> → <?= smpro_h($to) ?> (Imunify / backups show current state)</span></div>
  <div class="ar-reports">
    <?php foreach ($reports as $r): ?>
      <a class="ar-rep <?= smpro_h($r['sev']) ?>" href="index.cgi?page=<?= smpro_h($r['page']) ?>">
        <div class="ar-rep-top"><span class="ar-rep-ic"><?= $r['icon'] ?></span><span class="ar-rep-t"><?= smpro_h($r['title']) ?></span></div>
        <div class="ar-rep-n"><?= (int)$r['n'] ?></div>
        <div class="ar-rep-note"><?= smpro_h($r['note']) ?></div>
      </a>
    <?php endforeach; ?>
  </div>
  <div class="ar-chart" style="margin-top:14px">
    <?php foreach ($reports as $r): ?>
      <div class="ar-col" title="<?= smpro_h($r['title']) ?>: <?= (int)$r['n'] ?>"><div class="ar-colbar sev-<?= smpro_h($r['sev']) ?>" style="height:<?= max(4,round(sqrt((int)$r['n']/$repMax)*130)) ?>px"></div><div class="ar-coln"><?= (int)$r['n'] ?></div><div class="ar-cold"><?= smpro_h($r['title']) ?></div></div>
    <?php endforeach; ?>
  </div>
</div>

<!-- Changes by Type (full width) -->
<div class="card" style="padding:0;overflow:hidden;margin-bottom:14px">
  <div class="ar-head">Changes by Type</div>
  <div class="smpro-tablewrap"><table class="smpro-table"><tbody>
    <?php if (!$byType): ?><tr><td class="ar-empty">No changes in range.</td></tr>
    <?php else: $mx=max($byType); foreach (array_slice($byType,0,12,true) as $a=>$n): $k=smpro_ar_kind($a); ?>
      <tr><td style="width:60%"><?= smpro_h(smpro_ar_label($a)) ?><div class="bar" style="margin-top:5px"><i style="width:<?= max(3,round($n/$mx*100)) ?>%;background:<?= $kindColor[$k] ?>"></i></div></td><td class="num"><b><?= (int)$n ?></b></td></tr>
    <?php endforeach; endif; ?>
  </tbody></table></div>
</div>

<!-- Changes by Category (full width) -->
<div class="card" style="padding:0;overflow:hidden;margin-bottom:14px">
  <div class="ar-head">Changes by Category</div>
  <div style="padding:16px;display:flex;gap:18px;align-items:center;flex-wrap:wrap">
    <?php $deg=0;$grad=[];$ct=max(1,$totalChanges); foreach (['firewall','service','fix','report','security','other'] as $k){ $n=$kc[$k]; if($n<=0)continue; $sl=$n/$ct*360; $grad[]=$kindColor[$k].' '.round($deg,1).'deg '.round($deg+$sl,1).'deg'; $deg+=$sl; } $g=$grad?'conic-gradient('.implode(',',$grad).')':'#eef1f6'; ?>
    <div class="ar-donut" style="background:<?= $g ?>"><div class="ar-donuthole"><b><?= (int)$totalChanges ?></b><span>changes</span></div></div>
    <div class="ar-legend">
      <?php foreach (['firewall'=>'Firewall','service'=>'Service','fix'=>'Fixes','report'=>'Reports','security'=>'Security','other'=>'Other'] as $k=>$lbl): if($kc[$k]<=0)continue; ?>
        <div><span class="ar-dot" style="background:<?= $kindColor[$k] ?>"></span><?= $lbl ?> <b><?= (int)$kc[$k] ?></b> <span class="meta">(<?= round($kc[$k]/$ct*100) ?>%)</span></div>
      <?php endforeach; ?>
      <?php if (!$totalChanges): ?><div class="meta">No changes. Page views in range: <?= (int)$kc['view'] ?>.</div><?php endif; ?>
    </div>
  </div>
</div>

<div class="card ar-strip">
  <div><span>Storage</span><b><?= smpro_ar_bytes($totalBytes) ?></b></div>
  <div><span>Saved reports</span><b><?= count($repIdx) ?></b></div>
  <div><span>Cached IPs</span><b><?= count($ipc) ?></b></div>
  <div><span>Hidden IPs</span><b><?= count(smpro_hidden_ips()) ?></b></div>
  <div><span>Page views (range)</span><b><?= (int)$kc['view'] ?></b></div>
  <div><span>Active modules</span><b><?= (int)$builtMods ?></b></div>
</div>

<!-- Change Log: grouped by type + collapsed, at the very end -->
<?php
  $logGroups = [];
  foreach (array_slice($log, 0, 1500) as $e) { $logGroups[$e['_kind'] ?: 'other'][] = $e; }
  $kindOrder = ['firewall','service','fix','report','security','other'];
  uksort($logGroups, fn($a,$b) => (array_search($a,$kindOrder) <=> array_search($b,$kindOrder)));
?>
<details class="ar-acc" style="margin-top:14px">
  <summary>
    <span>&#128203; Change Log</span>
    <span class="ar-cnt"><?= count($log) ?> changes · grouped by type · newest first</span>
    <span class="ar-arw">&#9656;</span>
  </summary>
  <div class="ar-accbody">
    <?php if (!$log): ?><p class="meta" style="padding:8px 2px">No changes recorded in this range/type.</p><?php endif; ?>
    <?php foreach ($logGroups as $kind=>$rows): ?>
      <details class="ar-grp">
        <summary><?= smpro_ar_kbadge($kind) ?> <span class="ar-grp-n"><?= count($rows) ?> change(s)</span><span class="ar-arw">&#9656;</span></summary>
        <div class="smpro-tablewrap"><table class="smpro-table"><thead><tr><th>Time</th><th>Change</th><th>Target</th><th>Result</th><th>By</th></tr></thead><tbody>
          <?php foreach (array_slice($rows, 0, 200) as $e): $res = smpro_ar_result($e); ?>
            <tr>
              <td class="mono"><?= smpro_h(date('M j, H:i:s', $e['_ts'])) ?></td>
              <td><?= smpro_h(smpro_ar_label($e['action'])) ?></td>
              <td class="mono"><?= smpro_ar_target($e)!==''?smpro_h(smpro_ar_target($e)):'<span class="meta">—</span>' ?></td>
              <td><?= $res==='ok'?'<span class="kb green">✓ ok</span>':($res==='fail'?'<span class="kb red">✗ failed</span>':'<span class="meta">—</span>') ?></td>
              <td class="mono"><?= smpro_h($e['actor'] ?? 'root') ?></td>
            </tr>
          <?php endforeach; ?>
        </tbody></table></div>
      </details>
    <?php endforeach; ?>
  </div>
</details>

<style>
.svc-kicker{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--brand);font-weight:800}
.ar-filters{display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap;margin:14px 0;position:relative}
.ar-fld{display:flex;flex-direction:column;gap:4px;font-size:11px;text-transform:uppercase;letter-spacing:.03em;color:var(--muted);font-weight:700}
.tp-sel,.tp-in{border:1px solid var(--line);border-radius:9px;padding:8px 11px;font-size:13px}
.tp-btn{border:1px solid var(--line);border-radius:9px;padding:9px 16px;font-size:13px;font-weight:600;cursor:pointer;text-decoration:none;color:var(--ink)}.tp-btn.green{background:var(--good);color:#fff;border-color:var(--good)}
.ar-export{position:relative}.ar-menu{display:none;position:absolute;right:0;top:calc(100% + 4px);background:var(--card);border:1px solid var(--line);border-radius:10px;box-shadow:0 12px 28px rgba(15,23,42,.12);z-index:5;min-width:130px;overflow:hidden}
.ar-export.open .ar-menu{display:block}.ar-menu a{display:block;padding:9px 14px;font-size:13px;color:var(--ink);text-decoration:none}.ar-menu a:hover{background:var(--brand-bg);color:var(--brand)}
.ar-cards{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin:14px 0}
@media(max-width:1100px){.ar-cards{grid-template-columns:repeat(3,1fr)}}@media(max-width:600px){.ar-cards{grid-template-columns:repeat(2,1fr)}}
.ar-c{padding:15px 17px;position:relative;overflow:hidden;transition:box-shadow .15s,transform .15s,border-color .15s}
.ar-c::before{content:"";position:absolute;left:0;right:0;top:0;height:3px;background:var(--brand);opacity:.7}
.ar-c:hover{transform:translateY(-2px);box-shadow:0 10px 26px rgba(2,8,23,.10)}
.ar-c .lbl{font-size:11px;color:var(--muted);text-transform:uppercase;font-weight:700;letter-spacing:.03em}.ar-c .v{font-size:25px;font-weight:800;margin-top:5px;line-height:1.1;font-variant-numeric:tabular-nums}.ar-c .meta{font-size:11px;color:var(--muted);margin-top:2px}
/* operational report tiles */
.ar-reports{display:grid;grid-template-columns:repeat(5,1fr);gap:12px}
@media(max-width:1000px){.ar-reports{grid-template-columns:repeat(3,1fr)}}@media(max-width:600px){.ar-reports{grid-template-columns:repeat(2,1fr)}}
.ar-rep{display:block;border:1px solid var(--line);border-radius:11px;padding:12px 13px;text-decoration:none;color:var(--ink);transition:box-shadow .15s,border-color .15s;border-left-width:4px}
.ar-rep:hover{box-shadow:0 10px 26px rgba(2,8,23,.10);transform:translateY(-2px)}
.ar-rep.ok{border-left-color:#1f9d55}.ar-rep.warn{border-left-color:#f59e0b}.ar-rep.crit{border-left-color:#dc2626}
.ar-rep-top{display:flex;align-items:center;gap:7px}.ar-rep-ic{font-size:16px}.ar-rep-t{font-weight:700;font-size:13px}
.ar-rep-n{font-size:26px;font-weight:800;margin:4px 0 2px}
.ar-rep.ok .ar-rep-n{color:#16a34a}.ar-rep.warn .ar-rep-n{color:#b45309}.ar-rep.crit .ar-rep-n{color:#dc2626}
.ar-rep-note{font-size:11.5px;color:var(--muted);line-height:1.4}
.ar-colbar.sev-ok{background:#1f9d55}.ar-colbar.sev-warn{background:#f59e0b}.ar-colbar.sev-crit{background:#dc2626}
/* grouped, collapsible change log */
.ar-acc{border:1px solid var(--line);border-radius:12px;overflow:hidden;background:var(--card,#fff)}
.ar-acc>summary,.ar-grp>summary{list-style:none;cursor:pointer;display:flex;align-items:center;gap:8px;padding:13px 16px;font-weight:700;user-select:none}
.ar-acc>summary::-webkit-details-marker,.ar-grp>summary::-webkit-details-marker{display:none}
.ar-acc>summary:hover,.ar-grp>summary:hover{background:rgba(148,163,184,.07)}
.ar-arw{margin-left:auto;transition:transform .18s;color:var(--muted);font-size:12px}
details[open]>summary .ar-arw{transform:rotate(90deg)}
.ar-cnt,.ar-grp-n{font-weight:500;font-size:12px;color:var(--muted)}
.ar-accbody{padding:4px 14px 14px}
.ar-grp{border:1px solid var(--line);border-radius:10px;margin-top:8px;overflow:hidden}
.ar-grp>summary{padding:10px 12px;font-size:13px;background:rgba(148,163,184,.05)}
.ar-chart{display:flex;gap:8px;align-items:flex-end;height:184px;padding:10px 6px 0;overflow-x:auto}
.ar-col{flex:1;min-width:26px;display:flex;flex-direction:column;align-items:center;justify-content:flex-end;height:100%}
.ar-colbar{width:82%;max-width:48px;background:linear-gradient(180deg,#5b8dff,#3b5bdb);border-radius:8px 8px 0 0;min-height:4px;transition:filter .15s}
.ar-col:hover .ar-colbar{filter:brightness(1.12)}
.ar-coln{font-size:11px;font-weight:800;margin-top:5px}.ar-cold{font-size:9.5px;color:var(--muted);margin-top:2px;white-space:nowrap}
.ar-head{padding:12px 16px;border-bottom:1px solid var(--line);font-weight:700;font-size:14px}.ar-head .meta{font-weight:400;font-size:12px;color:var(--muted)}
.ar-logwrap{max-height:460px;overflow:auto}.ar-logwrap thead th{position:sticky;top:0;background:var(--card);z-index:1;box-shadow:inset 0 -1px 0 var(--line)}
.ar-two{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin:14px 0}@media(max-width:900px){.ar-two{grid-template-columns:1fr}}
.ar-donut{width:130px;height:130px;border-radius:50%;display:grid;place-items:center}.ar-donuthole{width:84px;height:84px;border-radius:50%;background:var(--card);display:flex;flex-direction:column;align-items:center;justify-content:center}
.ar-donuthole b{font-size:22px;font-weight:800}.ar-donuthole span{font-size:11px;color:var(--muted)}
.ar-legend{font-size:13px;line-height:2}.ar-dot{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:7px}
.bar{height:7px;border-radius:8px;background:var(--card);overflow:hidden}.bar>i{display:block;height:100%;border-radius:8px;background:var(--brand)}
.smpro-tablewrap{overflow-x:auto}.smpro-table{width:100%;border-collapse:collapse;font-size:13px}
.smpro-table th,.smpro-table td{padding:8px 14px;text-align:left;border-bottom:1px solid var(--line)}.smpro-table tr:last-child td{border-bottom:0}
.smpro-table th{font-size:11px;text-transform:uppercase;color:var(--muted)}.smpro-table td.num{text-align:right}
.mono{font-family:ui-monospace,Consolas,monospace;font-size:12px}
.ar-empty{padding:18px;color:var(--muted);text-align:center}
.ar-strip{display:flex;flex-wrap:wrap;gap:24px;padding:14px 18px}
.ar-strip div span{display:block;font-size:11px;color:var(--muted);text-transform:uppercase}.ar-strip div b{font-size:18px;font-weight:800}
.kb{display:inline-block;font-size:10px;font-weight:800;padding:2px 8px;border-radius:20px}
.kb.red{background:var(--dang-bg);color:var(--dang)}.kb.blue{background:var(--brand-bg);color:var(--brand)}.kb.green{background:var(--good-bg);color:var(--good)}.kb.orange{background:var(--warn-bg);color:var(--warn)}.kb.purple{background:var(--brand-bg);color:#9333ea}.kb.gray{background:var(--card);color:#475569}
.meta{color:var(--muted)}
</style>
<script>
(function(){var d=document.getElementById('arDays');if(d)d.addEventListener('change',function(){var n=parseInt(this.value,10)||7,to=new Date(),fr=new Date(Date.now()-n*86400000);function f(x){return x.getFullYear()+'-'+String(x.getMonth()+1).padStart(2,'0')+'-'+String(x.getDate()).padStart(2,'0');}document.getElementById('arTo').value=f(to);document.getElementById('arFrom').value=f(fr);});
var b=document.getElementById('arExportBtn');if(b){var box=b.closest('.ar-export');b.addEventListener('click',function(e){e.stopPropagation();box.classList.toggle('open');});document.addEventListener('click',function(){box.classList.remove('open');});}})();
</script>
<?php
smpro_layout_footer();

function smpro_ar_report($log, $from, $to, $catLabel, $print) {
    $h = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $byKind = [];
    foreach ($log as $e) $byKind[$e['_kind']] = ($byKind[$e['_kind']] ?? 0) + 1;
    arsort($byKind);
    echo "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Change Log Report</title><style>
*{box-sizing:border-box}body{font:13px/1.5 -apple-system,Segoe UI,Arial,sans-serif;color:#1f2733;margin:0;padding:28px}h1{font-size:20px;margin:0 0 4px}.muted{color:#6b7686;font-size:12px;margin:0 0 16px}h2{font-size:14px;margin:18px 0 8px}
table{width:100%;border-collapse:collapse;font-size:12px;margin-bottom:8px}th,td{border:1px solid #e6eaf1;padding:6px 9px;text-align:left}th{background:var(--bg);text-transform:uppercase;font-size:10px;color:#475569}.brand{color:#3b5bdb;font-weight:700;float:right}td.n{text-align:right}</style></head><body>";
    echo "<div class=\"brand\">&#128737; Safety Monitor Pro</div><h1>Change Log Report</h1>";
    echo "<p class=\"muted\">Period " . $h($from) . " → " . $h($to) . " · " . $h($catLabel) . " · " . count($log) . " changes · generated " . $h(date('Y-m-d H:i:s')) . "</p>";
    echo "<h2>By type</h2><table><thead><tr><th>Kind</th><th>Changes</th></tr></thead><tbody>";
    foreach ($byKind as $k => $n) echo "<tr><td>" . $h(ucfirst($k)) . "</td><td class=\"n\">" . (int)$n . "</td></tr>";
    echo "</tbody></table><h2>Changes (" . count($log) . ")</h2><table><thead><tr><th>Time</th><th>Change</th><th>Type</th><th>Target</th><th>Result</th><th>By</th></tr></thead><tbody>";
    if (!$log) echo "<tr><td colspan=\"6\" style=\"text-align:center;color:#6b7686\">No changes.</td></tr>";
    foreach ($log as $e) echo "<tr><td>" . $h(date('Y-m-d H:i:s',$e['_ts'])) . "</td><td>" . $h(smpro_ar_label($e['action'])) . "</td><td>" . $h($e['_kind']) . "</td><td>" . $h(smpro_ar_target($e)) . "</td><td>" . $h(smpro_ar_result($e) ?: '-') . "</td><td>" . $h($e['actor'] ?? 'root') . "</td></tr>";
    echo "</tbody></table>";
    if ($print) echo "<script>window.onload=function(){setTimeout(function(){window.print();},300);};</script>";
    echo "</body></html>";
}
