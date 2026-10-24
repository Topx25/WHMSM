<?php
/**
 * modules/benchmark.php - Benchmark & Diagnostics hub.
 * Opens on a LIVE hardware panel (CPU/RAM/swap/load/temp + per-disk I/O and temperature, refreshed
 * every couple of seconds), then the machine's specs, a full benchmark run with a verdict against
 * what this hardware SHOULD do, hardware health (SMART/RAID/ECC), kernel+software troubleshooting,
 * and a saved report history.
 *
 * The page render only touches cheap sources; SMART, the dmesg scan and the EA-PHP probe are cached
 * and refreshed by the JSON poll (smpro_bd_live_payload), so the page opens instantly on any server.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

/* ---- POST: start a run, apply a safe kernel fix, or undo one (JSON, root + CSRF) ---- */
$reqMethod = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));
if ($reqMethod === 'POST' && ($_POST['bd_action'] ?? '') !== '') {
    header('Content-Type: application/json');
    smpro_require_valid_csrf('bd_action'); smpro_require_root();
    $act = (string)$_POST['bd_action'];
    if ($act === 'start')  { echo json_encode(smpro_bd_start((string)($_POST['mount'] ?? '')), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit; }
    if ($act === 'devtest'){ echo json_encode(smpro_bd_devtest_start((string)($_POST['kind'] ?? ''), (string)($_POST['target'] ?? '')), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit; }
    if ($act === 'grow')   { echo json_encode(smpro_bd_grow_apply((string)($_POST['dev'] ?? ''), (string)($_POST['confirm'] ?? '')), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit; }
    if ($act === 'fix')    { echo json_encode(smpro_bd_apply_sysctl(preg_replace('/[^a-z0-9_.]/', '', strtolower((string)($_POST['key'] ?? ''))), ''), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit; }
    if ($act === 'revert') { echo json_encode(smpro_bd_revert(preg_replace('/[^a-z0-9_.:]/', '', strtolower((string)($_POST['which'] ?? '')))), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit; }
    echo json_encode(['ok' => false, 'msg' => 'Unknown action.']); exit;
}

smpro_layout_header('Benchmark & Diagnostics');

$inv     = function_exists('smpro_bm_inventory') ? smpro_bm_inventory(false) : [];
$bst     = smpro_bd_state();
$bmMount = function_exists('smpro_bm_disk_mount') ? smpro_bm_disk_mount() : '';
$kern    = smpro_bd_kernel_info();
$hist    = smpro_bd_history();
$m0      = function_exists('smpro_collect_metrics') ? smpro_collect_metrics() : [];
$hw0     = smpro_bd_hw_health_cached(false);     // cache-only - never blocks this render
$diag0   = smpro_bd_diagnose_cached(false);      // cache-only
smpro_audit('benchdiag_view', ['runs' => count($hist)]);

$sevCls   = ['critical' => 'red', 'high' => 'red', 'medium' => 'orange', 'low' => 'blue'];
$sevLabel = ['critical' => 'CRITICAL', 'high' => 'HIGH', 'medium' => 'MEDIUM', 'low' => 'LOW'];
$pcls = function ($p) { $p = (float)$p; return $p >= 90 ? 'red' : ($p >= 70 ? 'orange' : 'green'); };
?>
<div style="display:flex;justify-content:space-between;align-items:flex-start;gap:14px;flex-wrap:wrap">
  <div>
    <h1 class="h">Benchmark &amp; Diagnostics
      <span class="live" id="bdLive"><i></i> LIVE <span id="bdClock"><?= smpro_h($m0['ts'] ?? '') ?></span></span>
    </h1>
    <p class="sub">Live hardware readings, a full benchmark measured against what this hardware <em>should</em> do, hardware health, and kernel/software troubleshooting. <b><?= smpro_h($kern['os'] ?: 'Linux') ?></b> · kernel <span class="mono"><?= smpro_h($kern['release']) ?></span></p>
  </div>
  <div class="bd-ctl">
    <select class="tp-sel" id="bdInt" title="refresh interval">
      <option value="2000" selected>2s</option><option value="5000">5s</option><option value="10000">10s</option>
    </select>
    <button class="tp-btn" id="bdPause" type="button">Pause</button>
  </div>
</div>
<?php
$bdSevN = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];
if (is_array($diag0)) foreach ($diag0 as $f) { $s = (string)($f['sev'] ?? 'low'); if (isset($bdSevN[$s])) $bdSevN[$s]++; }
$bdDiagN = is_array($diag0) ? count($diag0) : null;
$bdHwV   = is_array($hw0) ? (string)($hw0['verdict'] ?? '') : '';
$bdPress = (float)($m0['pressure'] ?? 0); $bdPc = $pcls($bdPress);
$bdSt    = (string)($bst['status'] ?? 'idle');
$bdKpis  = [
  ['bd-live',    'Live load',       (string)($m0['load']['1m'] ?? '—') . ' / ' . (string)($m0['load']['5m'] ?? '—'), $bdPc === 'red' ? 'dang' : ($bdPc === 'orange' ? 'warn' : 'good'),
                 'pressure ' . $bdPress . '% · CPU ' . (float)($m0['cpu']['pct'] ?? 0) . '% · RAM ' . (float)($m0['ram']['pct'] ?? 0) . '%'],
  ['bd-health',  'Hardware health', $bdHwV !== '' ? $bdHwV : 'reading…', $bdHwV === 'Healthy' ? 'good' : ($bdHwV === 'Failing' ? 'dang' : ($bdHwV !== '' ? 'warn' : 'muted')),
                 is_array($hw0) ? count($hw0['findings'] ?? []) . ' finding(s) · SMART · RAID · ECC' : 'SMART · RAID · ECC'],
  ['bd-trouble', 'Diagnosis',       $bdDiagN === null ? 'running…' : $bdDiagN . ' finding' . ($bdDiagN === 1 ? '' : 's'),
                 $bdDiagN === null ? 'muted' : (($bdSevN['critical'] + $bdSevN['high']) > 0 ? 'dang' : ($bdSevN['medium'] > 0 ? 'warn' : 'good')),
                 $bdDiagN === null ? 'kernel · software · PHP' : ($bdSevN['critical'] + $bdSevN['high']) . ' critical/high · ' . $bdSevN['medium'] . ' medium · ' . $bdSevN['low'] . ' low'],
  ['bd-run',     'Benchmark',       $bdSt === 'done' ? 'done' : ($bdSt === 'running' ? 'running' : 'idle'), $bdSt === 'done' ? 'good' : ($bdSt === 'running' ? 'warn' : 'muted'),
                 $bdSt === 'running' ? (string)($bst['step'] ?? '') . ' · ' . (int)($bst['pct'] ?? 0) . '%' : 'CPU · RAM · disk · PHP · MySQL'],
  ['bd-reports', 'Last run',        isset($hist[0]['date']) ? (string)$hist[0]['date'] : 'never', isset($hist[0]) ? 'brand' : 'muted', count($hist) . ' saved report(s)'],
  ['bd-inv',     'This server',     count($inv['disks'] ?? []) . ' disk(s) · ' . (string)($inv['ram']['total_gb'] ?? 0) . ' GB', 'brand', (string)($inv['cpu']['model'] ?? '…')],
];
?>
<div class="fw-kpis">
  <?php foreach ($bdKpis as $k): ?>
  <a class="fw-kpi <?= $k[3] ?>" href="#<?= $k[0] ?>" data-go="<?= $k[0] ?>"><div class="l"><?= smpro_h($k[1]) ?></div><div class="v"><?= smpro_h($k[2]) ?></div><div class="s"><?= smpro_h($k[4]) ?></div></a>
  <?php endforeach; ?>
</div>
<nav class="fw-nav" id="bdNav"><a href="#bd-live" data-go="bd-live">&#128225; Live</a><a href="#bd-score" data-go="bd-score">&#127942; Score</a><a href="#bd-fit" data-go="bd-fit">&#9878; Fit</a><a href="#bd-storage" data-go="bd-storage">&#128190; Storage</a><a href="#bd-wear" data-go="bd-wear">Wear</a><a href="#bd-ruler" data-go="bd-ruler">Ruler</a><a href="#bd-array" data-go="bd-array">Array</a><a href="#bd-chg" data-go="bd-chg">Changes</a><a href="#bd-inv" data-go="bd-inv">Server</a><a href="#bd-run" data-go="bd-run">&#127937; Run</a><a href="#bd-perf" data-go="bd-perf">Performance</a><a href="#bd-faster" data-go="bd-faster">Faster</a><a href="#bd-health" data-go="bd-health">&#129505; Health</a><a href="#bd-trouble" data-go="bd-trouble">&#128295; Troubleshoot</a><a href="#bd-reports" data-go="bd-reports">&#128202; Reports</a><span class="sp"></span><button type="button" class="fw-navx" id="bdOpenAll">expand all</button><button type="button" class="fw-navx" id="bdCloseAll">collapse all</button></nav>

<!-- ============ LIVE hardware readings ============ -->
<div class="card" id="bd-live" style="padding:0;overflow:hidden;margin:14px 0;border-top:3px solid var(--good)">
  <button class="bd-head" type="button" aria-expanded="true" aria-controls="bd-live-b"><span class="bd-chev">&#9654;</span><span class="bd-ic">&#128225;</span><b>Live hardware</b><span class="meta">real-time — updates by itself, no refresh</span>
    <span class="dbh-livemeta">uptime <b id="bdUp"><?= smpro_h($m0['uptime'] ?? '—') ?></b> · <b id="bdProcs"><?= (int)($m0['procs'] ?? 0) ?></b> processes</span></button>
  <div class="bd-gauges" id="bdGauges">
    <div class="bd-g"><div class="bd-gk">CPU</div><div class="bd-gv"><span class="b <?= $pcls($m0['cpu']['pct'] ?? 0) ?>" id="bdCpu"><?= (float)($m0['cpu']['pct'] ?? 0) ?>%</span></div>
      <div class="bd-bar"><span id="bdCpuBar" class="<?= $pcls($m0['cpu']['pct'] ?? 0) ?>" style="width:<?= min(100,(float)($m0['cpu']['pct'] ?? 0)) ?>%"></span></div>
      <div class="bd-gs"><span id="bdCores"><?= (int)($m0['cores'] ?? 0) ?></span> cores · temp <span id="bdTemp"><?= $m0['temp'] ? smpro_h($m0['temp']) . '&deg;C' : '—' ?></span></div></div>
    <div class="bd-g"><div class="bd-gk">Memory</div><div class="bd-gv"><span class="b <?= $pcls($m0['ram']['pct'] ?? 0) ?>" id="bdRam"><?= (float)($m0['ram']['pct'] ?? 0) ?>%</span></div>
      <div class="bd-bar"><span id="bdRamBar" class="<?= $pcls($m0['ram']['pct'] ?? 0) ?>" style="width:<?= min(100,(float)($m0['ram']['pct'] ?? 0)) ?>%"></span></div>
      <div class="bd-gs"><span id="bdRamTx"><?= smpro_h(($m0['ram']['used'] ?? '') . ' / ' . ($m0['ram']['total'] ?? '')) ?></span></div></div>
    <div class="bd-g"><div class="bd-gk">Swap</div><div class="bd-gv"><span class="b <?= $pcls($m0['swap']['pct'] ?? 0) ?>" id="bdSwap"><?= (float)($m0['swap']['pct'] ?? 0) ?>%</span></div>
      <div class="bd-bar"><span id="bdSwapBar" class="<?= $pcls($m0['swap']['pct'] ?? 0) ?>" style="width:<?= min(100,(float)($m0['swap']['pct'] ?? 0)) ?>%"></span></div>
      <div class="bd-gs"><span id="bdSwapTx"><?= (int)($m0['swap']['used_mb'] ?? 0) ?> / <?= (int)($m0['swap']['total_mb'] ?? 0) ?> MB</span></div></div>
    <div class="bd-g"><div class="bd-gk">Load</div><div class="bd-gv"><span class="b <?= $pcls($m0['pressure'] ?? 0) ?>" id="bdLoad"><?= smpro_h(($m0['load']['1m'] ?? 0) . ' / ' . ($m0['load']['5m'] ?? 0) . ' / ' . ($m0['load']['15m'] ?? 0)) ?></span></div>
      <div class="bd-bar"><span id="bdLoadBar" class="<?= $pcls($m0['pressure'] ?? 0) ?>" style="width:<?= min(100,(float)($m0['pressure'] ?? 0)) ?>%"></span></div>
      <div class="bd-gs">pressure <span id="bdPress"><?= (float)($m0['pressure'] ?? 0) ?></span>% of capacity</div></div>
  </div>
  <div class="bd-subhd">&#128190; Disk activity &amp; temperature — live</div>
  <div class="smpro-tablewrap"><table class="smpro-table" id="bdDiskTbl">
    <thead><tr><th>Device</th><th class="num">Read</th><th class="num">Write</th><th class="num">IOPS</th><th>Busy</th><th class="num">Temp</th></tr></thead>
    <tbody id="bdDiskBody"><tr><td colspan="6" style="color:var(--muted);padding:12px">Reading disks…</td></tr></tbody>
  </table></div>
</div>

<?php $SC = smpro_bd_hw_score(); $FIT = smpro_bd_workload_fit(); ?>
<!-- ============ hardware score ============ -->
<div class="card" id="bd-score" style="padding:0;overflow:hidden;margin:14px 0">
  <button class="bd-head" type="button" aria-expanded="true" aria-controls="bd-score-b"><span class="bd-chev">&#9654;</span><span class="bd-ic">&#127942;</span><b>Hardware score</b>
    <span class="meta">performance 35% · health 35% · headroom 15% · configuration 15%</span>
    <span class="dbh-livemeta"><span class="b <?= $SC['band'][0]==='good'?'green':($SC['band'][0]==='warn'?'orange':($SC['band'][0]==='dang'?'red':'gray')) ?>"><?= smpro_h($SC['band'][1]) ?></span></span></button>
  <div class="bd-score">
    <?php
      // A provisional score must not read as a confident pass, so the ring goes neutral until
      // enough of the assessment is actually measured.
      $ringCol = $SC['coverage'] < 60 ? 'var(--muted)'
               : ($SC['band'][0] === 'good' ? 'var(--good)' : ($SC['band'][0] === 'warn' ? 'var(--warn)' : 'var(--dang)'));
    ?>
    <div class="bd-ring<?= $SC['coverage'] < 100 ? ' partial' : '' ?>" style="background:conic-gradient(<?= $ringCol ?> 0 <?= (int)($SC['score'] ?? 0) ?>%, var(--line) <?= (int)($SC['score'] ?? 0) ?>% 100%)">
      <div class="in"><div><div class="n"><?= $SC['score'] === null ? '—' : (int)$SC['score'] ?></div>
        <div class="k"><?= $SC['coverage'] < 100 ? 'Provisional' : 'Score' ?></div></div></div>
    </div>
    <div class="bd-brk">
      <?php foreach ($SC['parts'] as $k => $v):
        $col = $v === null ? 'var(--line)' : ($v >= 80 ? 'var(--good)' : ($v >= 55 ? 'var(--warn)' : 'var(--dang)')); ?>
        <div class="bd-brow"><span class="bl"><?= smpro_h(ucfirst($k)) ?> <span class="meta">(<?= (int)$SC['weights'][$k] ?>%)</span></span>
          <span class="bd-bar"><span style="width:<?= (int)($v ?? 0) ?>%;background:<?= $col ?>"></span></span>
          <span class="bv"><?= $v === null ? '—' : (int)$v ?></span></div>
      <?php endforeach; ?>
      <?php if ($SC['coverage'] < 100 && $SC['score'] !== null): ?>
        <div class="bd-partial">
          <b>This score covers only <?= (int)$SC['coverage'] ?>% of the assessment.</b>
          It is calculated from the parts that have been measured
          (<?= smpro_h(implode(', ', array_map('ucfirst', array_diff(array_keys($SC['weights']), $SC['missing'])))) ?>)
          — the rest is not counted at all, so treat it as provisional rather than a verdict on the machine.
          <div style="margin-top:6px">To complete it: <?= smpro_h(implode(' · ', $SC['todo'])) ?>.</div>
        </div>
      <?php endif; ?>
      <div class="meta" style="margin-top:8px;line-height:1.6">A dash means that part has not been measured yet.
      Weighting is health-heavy on purpose: a failing disk should sink the score even on a fast machine.</div>
    </div>
  </div>
</div>

<!-- ============ workload fit ============ -->
<div class="card" id="bd-fit" style="padding:0;overflow:hidden;margin:14px 0">
  <button class="bd-head" type="button" aria-expanded="true" aria-controls="bd-fit-b"><span class="bd-chev">&#9654;</span><span class="bd-ic">&#9878;</span><b>Does the hardware match the load?</b>
    <span class="meta">peak vs installed capacity<?= $FIT['stats']['hours'] ? ' · ' . (int)$FIT['stats']['hours'] . 'h of history, ' . number_format((int)$FIT['stats']['samples']) . ' samples' : '' ?></span></button>
  <div style="padding:4px 16px">
    <?php foreach ($FIT['rows'] as $r): $pk = $r['peak'] === null ? 0 : (float)$r['peak'];
      $col = $r['tier'] === 'dang' ? 'var(--dang)' : ($r['tier'] === 'warn' ? 'var(--warn)' : 'var(--good)'); ?>
      <div class="bd-fitrow">
        <div class="bd-fitk"><b><?= smpro_h($r['label']) ?></b><span><?= smpro_h($r['cap']) ?></span></div>
        <div>
          <div class="bd-rail"><i style="width:<?= min(100,max(1,$pk)) ?>%;background:<?= $col ?>"></i>
            <em><?= $r['peak'] === null ? 'no data yet' : 'peak ' . $r['peak'] . '%' ?><?= $r['avg'] !== null ? ' · typical ' . $r['avg'] . '%' : '' ?><?= $r['now'] !== null ? ' · now ' . round($r['now']) . '%' : '' ?></em></div>
          <div class="bd-fitn"><?= smpro_h($r['note']) ?></div>
        </div>
      </div>
    <?php endforeach; ?>
  </div>
  <div class="bd-verdictbox <?= $FIT['verdict'][0] === 'good' ? 'ok' : 'warn' ?>">
    <span class="vi"><?= $FIT['verdict'][0] === 'good' ? '&#9989;' : ($FIT['verdict'][0] === 'warm' ? '&#8987;' : '&#9888;') ?></span>
    <div><b><?= smpro_h($FIT['verdict'][1]) ?></b><br><?= smpro_h($FIT['verdict'][2]) ?></div>
  </div>
</div>

<!-- ============ storage layout + per-device testing ============ -->
<div class="card" id="bd-storage" style="padding:0;overflow:hidden;margin:14px 0">
  <button class="bd-head" type="button" aria-expanded="true" aria-controls="bd-storage-b"><span class="bd-chev">&#9654;</span><span class="bd-ic">&#128190;</span><b>Storage layout &amp; per-device testing</b>
    <span class="meta">drive types, sizes, RAID level — test one drive at a time, read-only</span></button>
  <div id="bdStor"><?= smpro_bd_storage_html() ?></div>
  <div class="bd-safe">&#128274; <b>Physical drives are tested read-only.</b>
    <details class="gl-fold" style="display:inline-block;vertical-align:top"><summary><span class="fw-chev gl-chev">&#9656;</span>How this works</summary>A single disk is measured with
    sequential read (O_DIRECT) and random-read IOPS straight from the device — nothing is ever written to a raw disk,
    because that would destroy the filesystem on it. <b>RAID arrays are never tested or modified</b>: benchmarking an
    array writes through to every member, and altering one risks your data and the machine's ability to boot.</details></div>
</div>

<!-- ============ drive lifetime, wear, health & performance ============ -->
<div class="card" id="bd-wear" style="padding:0;overflow:hidden;margin:14px 0">
  <button class="bd-head" type="button" aria-expanded="true" aria-controls="bd-wear-b"><span class="bd-chev">&#9654;</span><span class="bd-ic">&#129503;</span><b>Drive lifetime &amp; wear</b>
    <span class="meta">hours run, data written / read since manufacture, health % and performance %</span></button>
  <div id="bdLife"><?= smpro_bd_life_html() ?></div>
</div>

<!-- ============ where the numbers land (grade ruler) ============ -->
<div class="card" id="bd-ruler" style="padding:0;overflow:hidden;margin:14px 0">
  <button class="bd-head" type="button" aria-expanded="false" aria-controls="bdRuler" style="width:100%;text-align:left;font-family:inherit;font-size:inherit;color:var(--ink);background:var(--card);border:0;border-bottom:1px solid var(--line);cursor:pointer">
    <span class="bd-chev">&#9654;</span><span class="bd-ic">&#128200;</span><b>What speed this server actually needs</b>
    <span class="meta">the grade scale, with your drives plotted on it</span>
  </button>
  <div id="bdRuler" hidden><div id="bdRulerBody"><?= smpro_bd_ruler_html() ?></div></div>
</div>

<!-- ============ array I/O path ============ -->
<div class="card" id="bd-array" style="padding:0;overflow:hidden;margin:14px 0">
  <button class="bd-head" type="button" aria-expanded="true" aria-controls="bd-array-b"><span class="bd-chev">&#9654;</span><span class="bd-ic">&#128256;</span><b>How reads and writes travel through the array</b>
    <span class="meta">an array is only as fast as the path the data must take</span></button>
  <div id="bdPath"><?= smpro_bd_path_html() ?></div>
  <div class="bd-safe" style="background:var(--bg);border-left-color:var(--line)"><b>By array type.</b>
    RAID 1 — write = slowest member, read up to N×. RAID 0 — both scale ≈ N×, but one lost disk loses everything.
    RAID 10 — read ≈ N×, write ≈ N/2×. RAID 5/6 — reads are fast, but every small write costs a read-modify-write
    cycle, so random writes fall well below what the members suggest.</div>
</div>

<!-- ============ storage changes ============ -->
<?php $OPS = smpro_bd_storage_ops(); $GROW = $OPS['growable']; ?>
<div class="card" id="bd-chg" style="padding:0;overflow:hidden;margin:14px 0">
  <button class="bd-head" type="button" aria-expanded="false" aria-controls="bdChg" style="width:100%;text-align:left;font-family:inherit;font-size:inherit;color:var(--ink);background:var(--card);border:0;border-bottom:1px solid var(--line);cursor:pointer">
    <span class="bd-chev">&#9654;</span><span class="bd-ic">&#128208;</span><b>Storage changes</b>
    <span class="meta">offered only where the operation is safe</span>
    <span class="dbh-livemeta"><span class="b <?= $GROW ? 'orange' : 'gray' ?>"><?= $GROW ? count($GROW) . ' filesystem(s) can grow' : 'Nothing available on this server' ?></span></span>
  </button>
  <div id="bdChg" hidden>
    <div class="bd-tiles">
      <div class="bd-tile"><div class="k">Grow a filesystem</div>
        <div class="v" style="<?= $GROW ? '' : 'color:var(--muted)' ?>"><?= $GROW ? 'Available' : 'Unavailable' ?></div>
        <div class="s"><?= $GROW ? 'A block device is larger than the filesystem on it — there is room to grow into.' : 'No unallocated space behind any filesystem — nothing to grow into.' ?></div></div>
      <div class="bd-tile"><div class="k">Shrink a filesystem</div><div class="v" style="color:var(--muted)">Never offered</div>
        <div class="s">Requires unmounting and risks data loss — do it from rescue mode, not a web panel.</div></div>
      <div class="bd-tile"><div class="k">RAID level / members</div><div class="v" style="color:var(--muted)">Never offered</div>
        <div class="s">Can destroy the array and leave the server unbootable.</div></div>
    </div>
    <?php foreach ($GROW as $g): ?>
      <div class="bd-oprow">
        <span class="ot"><b>Grow <?= smpro_h($g['mount']) ?> — <?= smpro_h(smpro_bd_kb_h($g['fs_bytes'] / 1024)) ?> &rarr; <?= smpro_h(smpro_bd_kb_h($g['dev_bytes'] / 1024)) ?></b>
          <span><?= smpro_h($g['stack']) ?> · gains <?= smpro_h(smpro_bd_kb_h($g['gain_bytes'] / 1024)) ?> · runs online, stays mounted</span></span>
        <button class="tp-btn bd-grow" type="button" data-dev="<?= smpro_h($g['name']) ?>" data-mount="<?= smpro_h($g['mount']) ?>"
          data-from="<?= smpro_h(smpro_bd_kb_h($g['fs_bytes'] / 1024)) ?>" data-to="<?= smpro_h(smpro_bd_kb_h($g['dev_bytes'] / 1024)) ?>"
          data-fs="<?= smpro_h($g['fs']) ?>" data-cmd="<?= smpro_h($g['cmd']) ?>">Grow filesystem…</button>
      </div>
    <?php endforeach; ?>

    <?php if (!empty($OPS['blocked'])): ?>
      <div class="bd-ghd" style="cursor:default"><span>Everything else — and exactly why it is not offered</span>
        <span class="rt"><?= count($OPS['blocked']) ?> filesystem(s)</span></div>
      <?php foreach ($OPS['blocked'] as $b): ?>
        <div class="bd-blocked">
          <div class="bh"><b class="mono"><?= smpro_h($b['mount'] !== '' ? $b['mount'] : $b['dev']) ?></b>
            <span class="b gray">Not offered</span>
            <span class="meta"><?= smpro_h($b['stack']) ?></span></div>
          <div class="bw"><?= smpro_h($b['why']) ?></div>
          <div class="bd-fitn"><?= smpro_h($b['detail']) ?></div>
          <div class="bm-manual"><span>Do it yourself</span> <span class="mono"><?= smpro_h($b['manual']) ?></span></div>
        </div>
      <?php endforeach; ?>
    <?php endif; ?>
    <div class="bd-safe" style="background:var(--bg);border-left-color:var(--line)"><b>Every storage change passes two
      warnings</b> — a risk disclosure, then a final confirmation that requires the device name to be typed. The server
      re-validates that the filesystem is genuinely growable at the moment you confirm; it never trusts what the page sent.</div>
  </div>
</div>

<!-- ============ specs ============ -->
<div class="card" id="bd-inv" style="padding:0;overflow:hidden;margin:14px 0">
  <button class="bd-head" type="button" aria-expanded="true" aria-controls="bd-inv-b"><span class="bd-chev">&#9654;</span><span class="bd-ic">&#128187;</span><b>This server</b><span class="meta">hardware inventory</span></button>
  <div style="padding:12px 16px"><div class="bm-inv" id="bmInv">
    <div class="bm-invcard"><div class="bm-invk">&#129504; CPU</div><div class="bm-invv"><b><?= smpro_h($inv['cpu']['model'] ?? '…') ?></b></div><div class="bm-invs"><?= (int)($inv['cpu']['cores'] ?? ($m0['cores'] ?? 0)) ?> threads</div></div>
    <div class="bm-invcard"><div class="bm-invk">&#129518; RAM</div><div class="bm-invv"><b><?= smpro_h($inv['ram']['total_gb'] ?? 0) ?> GB</b></div><div class="bm-invs">total memory</div></div>
    <div class="bm-invcard"><div class="bm-invk">&#128190; Storage</div><div class="bm-invv"><b><?= count($inv['disks'] ?? []) ?> disk(s)</b></div><div class="bm-invs">&nbsp;</div></div>
    <div class="bm-invcard"><div class="bm-invk">&#127959; Platform</div><div class="bm-invv"><b><?= ($inv['virt'] ?? '') === 'none' ? 'Bare metal' : smpro_h(ucfirst((string)($inv['virt'] ?? ''))) ?></b></div><div class="bm-invs">&nbsp;</div></div>
  </div></div>
</div>

<!-- ============ run the benchmark ============ -->
<div class="card" id="bd-run" style="padding:0;overflow:hidden;margin:14px 0;border-top:3px solid var(--brand)">
  <button class="bd-head" type="button" aria-expanded="true" aria-controls="bd-run-b"><span class="bd-chev">&#9654;</span><span class="bd-ic">&#127937;</span><b>Full benchmark</b><span class="meta">CPU · RAM · disk · PHP · MySQL — runs in the background, saved to Reports</span></button>
  <div style="padding:12px 16px">
    <div class="bm-run">
      <button class="tp-btn primary" id="bdRun" type="button">&#127937; Run full benchmark</button>
      <span class="meta">Writes ~1&nbsp;GB on <b><?= smpro_h($bmMount ?: 'no eligible mount') ?></b> (removed after) and runs a MySQL test on a TEMPORARY table. ~40–90s; you can leave the page.</span>
    </div>
    <div class="bm-prog" id="bdProg" style="display:none"><div class="dc-scanprog"><span></span></div><div class="bm-progtxt" id="bdProgTxt">Starting…</div></div>
    <div class="bm-results" id="bdResults"<?= ($bst['status'] ?? '') === 'done' ? '' : ' style="display:none"' ?>></div>
  </div>
</div>

<?php
$lastRes = (($bst['status'] ?? '') === 'done' && !empty($bst['results'])) ? $bst['results'] : (isset($hist[0]['results']) ? $hist[0]['results'] : []);
$assess  = $lastRes ? smpro_bd_assess($lastRes) : null;
$rateCls = ['excellent' => 'green', 'good' => 'green', 'below' => 'orange', 'poor' => 'red', 'unknown' => 'gray'];
$rateTxt = ['excellent' => 'Excellent', 'good' => 'As expected', 'below' => 'Below expected', 'poor' => 'Poor', 'unknown' => '—'];
if ($assess && $assess['groups']): ?>
<div class="card" id="bd-perf" style="padding:0;overflow:hidden;margin:14px 0">
  <button class="bd-head" type="button" aria-expanded="true" aria-controls="bd-perf-b"><span class="bd-chev">&#9654;</span><span class="bd-ic">&#128200;</span><b>Performance vs what this hardware should do</b><span class="meta">each result compared against the normal range for the hardware detected here</span></button>
  <?php foreach ($assess['groups'] as $g): ?>
    <div class="bd-ag">
      <div class="bd-aghd"><span class="bd-ic"><?= $g['icon'] ?></span><b><?= smpro_h($g['title']) ?></b><span class="bd-tested">tested: <?= smpro_h($g['tested']) ?></span></div>
      <div class="smpro-tablewrap"><table class="smpro-table bd-atbl">
        <thead><tr><th>Measurement</th><th class="num">This server</th><th>What is normal</th><th>Verdict</th></tr></thead>
        <tbody><?php foreach ($g['rows'] as $row): ?>
          <tr><td><b><?= smpro_h($row['label']) ?></b></td><td class="num mono"><?= smpro_h($row['value']) ?></td>
          <td class="bd-expect"><?= smpro_h($row['expect']) ?></td>
          <td><span class="b <?= $rateCls[$row['rating']] ?? 'gray' ?>"><?= smpro_h($row['rating_txt'] !== '' ? $row['rating_txt'] : ($rateTxt[$row['rating']] ?? '')) ?></span></td></tr>
        <?php endforeach; ?></tbody>
      </table></div>
    </div>
  <?php endforeach; ?>
</div>
<?php if (!empty($assess['upgrades'])): ?>
<div class="card" id="bd-faster" style="padding:0;overflow:hidden;margin:14px 0;border-top:3px solid var(--warn)">
  <button class="bd-head" type="button" aria-expanded="true" aria-controls="bd-faster-b"><span class="bd-chev">&#9654;</span><span class="bd-ic">&#128295;</span><b>How to make it faster</b><span class="meta">what to change — and where the hardware is the limit, exactly what to replace it with</span></button>
  <?php foreach ($assess['upgrades'] as $u): ?>
    <div class="bd-up bd-<?= ($u['sev'] === 'high' ? 'red' : 'orange') ?>">
      <div class="bd-frow"><span class="b <?= $u['sev'] === 'high' ? 'red' : 'orange' ?>"><?= strtoupper(smpro_h($u['sev'])) ?></span>
        <span class="bd-area"><?= smpro_h($u['what']) ?></span><b class="bd-ftitle"><?= smpro_h($u['title']) ?></b></div>
      <div class="bd-detail"><?= smpro_h($u['detail']) ?></div>
      <div class="bd-spec"><span>&#128295; Recommended</span> <?= smpro_h($u['spec']) ?></div>
    </div>
  <?php endforeach; ?>
</div>
<?php endif; endif; ?>

<!-- ============ hardware health (cached; filled/refreshed by the poll) ============ -->
<div class="card" id="bd-health" style="padding:0;overflow:hidden;margin:14px 0">
  <button class="bd-head" type="button" aria-expanded="true" aria-controls="bd-health-b"><span class="bd-chev">&#9654;</span><span class="bd-ic">&#129505;</span><b>Hardware health</b><span class="meta">SMART disk health &amp; wear · RAID · ECC memory</span>
    <span class="b gray" id="bdHwVerdict" style="margin-left:auto"><?= smpro_h(is_array($hw0) ? ($hw0['verdict'] ?? '…') : '…') ?></span></button>
  <div id="bdHw"><?= smpro_bd_hw_html($hw0) ?></div>
</div>

<!-- ============ troubleshooting (cached; filled/refreshed by the poll) ============ -->
<div class="card" id="bd-trouble" style="padding:0;overflow:hidden;margin:14px 0">
  <button class="bd-head" type="button" aria-expanded="true" aria-controls="bd-trouble-b"><span class="bd-chev">&#9654;</span><span class="bd-ic">&#128295;</span><b>Troubleshooting — kernel &amp; software</b><span class="meta">kernel tunables, kernel-log errors, PHP posture</span>
    <span class="dbh-livemeta"><b id="bdDiagN"><?= is_array($diag0) ? count($diag0) : 0 ?></b> finding(s)</span></button>
  <div class="bd-safe">&#128737;&#65039; <b>About the one-click fixes:</b> a fix changes a kernel <em>tuning number</em> — applied instantly with <span class="mono">sysctl -w</span> and written to our own <span class="mono"><?= smpro_h(SMPRO_BD_SYSCTL) ?></span> so it survives a reboot. No data is touched and nothing is deleted, so <b>there is nothing to back up</b>, and every fix has a one-click <b>Undo</b>.</div>
  <div id="bdDiag"><?= smpro_bd_diag_html($diag0) ?></div>
</div>

<!-- ============ reports ============ -->
<div class="card" id="bd-reports" style="padding:0;overflow:hidden;margin:14px 0">
  <button class="bd-head" type="button" aria-expanded="true" aria-controls="bd-reports-b"><span class="bd-chev">&#9654;</span><span class="bd-ic">&#128202;</span><b>Reports — previous runs</b><span class="meta">compare over time (last <?= count($hist) ?>)</span></button>
  <?php if (!$hist): ?>
    <div style="padding:20px 16px;color:var(--muted)">No runs saved yet — press <b>Run full benchmark</b> and the result is stored here.</div>
  <?php else: ?>
  <div class="smpro-tablewrap"><table class="smpro-table">
    <thead><tr><th>When</th><th class="num">CPU 1-core</th><th class="num">CPU all</th><th class="num">RAM read</th><th class="num">Disk write</th><th class="num">Disk read</th><th class="num">PHP int ops</th><th class="num">MySQL q/s</th><th class="num">MySQL ins/s</th></tr></thead>
    <tbody>
    <?php foreach ($hist as $i => $h): $r = $h['results'] ?? []; $mb = function ($v) { return $v === null || $v === '' ? '—' : ($v >= 1024 ? round($v / 1024, 2) . ' GB/s' : round($v) . ' MB/s'); }; ?>
      <tr<?= $i === 0 ? ' class="bd-latest"' : '' ?>>
        <td class="mono"><?= smpro_h($h['date'] ?? '') ?><?= $i === 0 ? ' <span class="b green">latest</span>' : '' ?></td>
        <td class="num mono"><?= $mb($r['cpu']['single_mbs'] ?? null) ?></td>
        <td class="num mono"><?= $mb($r['cpu']['multi_mbs'] ?? null) ?></td>
        <td class="num mono"><?= $mb($r['ram']['read_mbs'] ?? null) ?></td>
        <td class="num mono"><?= $mb($r['disk']['write_mbs'] ?? null) ?></td>
        <td class="num mono"><?= $mb($r['disk']['read_mbs'] ?? null) ?></td>
        <td class="num mono"><?= isset($r['php']['int_ops_sec']) ? number_format((int)$r['php']['int_ops_sec']) : '—' ?></td>
        <td class="num mono"><?= !empty($r['mysql']['query_ops_sec']) ? number_format((int)$r['mysql']['query_ops_sec']) : '—' ?></td>
        <td class="num mono"><?= !empty($r['mysql']['insert_rows_sec']) ? number_format((int)$r['mysql']['insert_rows_sec']) : '—' ?></td>
      </tr>
    <?php endforeach; ?>
    </tbody>
  </table></div>
  <?php endif; ?>
</div>

<!-- two-step confirmation for a storage change -->
<div class="ds-modal" id="growModal" role="dialog" aria-modal="true" aria-labelledby="gmTitle" hidden>
  <div class="ds-modal-card">
    <div id="gmStep1">
      <div class="ds-modal-head"><span class="bd-ic">&#128721;</span><b id="gmTitle">This changes a live filesystem</b>
        <span class="gm-step">Step 1 of 2</span></div>
      <div class="ds-modal-body">
        <p class="meta" style="margin:0">You are about to modify storage on a production server. Even an operation
        considered safe belongs to the class of change that can end a server.</p>
        <ul class="gm-risks">
          <li><span class="ri">!</span><span><b>Your data can be lost.</b> If it is interrupted — power cut, kernel panic,
            an I/O error on a tired disk — the filesystem can be left inconsistent and files unrecoverable.</span></li>
          <li><span class="ri">!</span><span><b>The server may not boot again.</b> If the affected filesystem is needed at
            boot, a failed change can leave the machine unable to start, requiring rescue-mode recovery by hand.</span></li>
          <li><span class="ri">!</span><span><b>Take a verified backup first</b> — not one you assume works; one you have
            confirmed you can restore from.</span></li>
        </ul>
        <div class="gm-spec">
          <div class="sh">Exactly what will be done, and what it affects</div>
          <dl>
            <dt>Operation</dt><dd>Grow <b id="gmFs"></b> on <span class="mono" id="gmMount"></span> — <b id="gmFrom"></b> &rarr; <b id="gmTo"></b></dd>
            <dt>Command</dt><dd class="mono" id="gmCmd"></dd>
            <dt>While mounted</dt><dd>Yes — grows online; the filesystem stays mounted and sites keep serving</dd>
            <dt>Effect on data</dt><dd>Files are not moved or rewritten; only the filesystem's size metadata changes</dd>
            <dt>Effect on server</dt><dd>Brief extra I/O on that device. No reboot, no service restart</dd>
            <dt>Reversible</dt><dd><b style="color:var(--dang)">No</b> — a mounted filesystem cannot be shrunk back</dd>
            <dt>If it fails</dt><dd>The filesystem may need <span class="mono">fsck</span> from rescue mode; accounts offline until repaired</dd>
          </dl>
        </div>
      </div>
      <div class="ds-modal-foot"><span class="gm-lg">&#128274; Logged to the audit trail</span>
        <button class="tp-btn" data-gmclose>Cancel</button>
        <button class="tp-btn danger" id="gmNext">I understand the risk — continue</button></div>
    </div>
    <div id="gmStep2" hidden>
      <div class="ds-modal-head"><span class="bd-ic">&#9888;</span><b>Data corruption is possible</b>
        <span class="gm-step">Step 2 of 2</span></div>
      <div class="ds-modal-body">
        <p class="meta" style="margin:0">This is the last point at which you can stop. Once started the operation runs to
        completion and <b>cannot be cancelled</b>. If it is interrupted part-way the filesystem can be left corrupted and
        some files permanently damaged — even though progress appeared normal.</p>
        <ul class="gm-risks">
          <li><span class="ri ok">&#10003;</span><span>A <b>restore-tested</b> backup exists, stored somewhere other than this device.</span></li>
          <li><span class="ri ok">&#10003;</span><span>The server is quiet — no backup, restore or heavy import running.</span></li>
          <li><span class="ri ok">&#10003;</span><span>Nothing is scheduled that could reboot the machine mid-operation.</span></li>
        </ul>
        <div class="gm-conf">
          <label>Type <b class="mono" id="gmName"></b> to confirm which filesystem is being changed:</label>
          <input id="gmInput" type="text" placeholder="device name" autocomplete="off" spellcheck="false">
        </div>
      </div>
      <div class="ds-modal-foot"><button class="tp-btn" id="gmBack">&larr; Back</button><span class="gm-lg"></span>
        <button class="tp-btn" data-gmclose>Cancel</button>
        <button class="tp-btn btn-danger" id="gmGo" disabled>Grow the filesystem</button></div>
    </div>
  </div>
</div>

<style>
/* score + workload fit */
.bd-score{display:flex;gap:20px;align-items:center;flex-wrap:wrap;padding:16px}
.bd-ring{width:112px;height:112px;border-radius:50%;flex:none;display:grid;place-items:center}
.bd-ring .in{width:88px;height:88px;border-radius:50%;background:var(--card);display:grid;place-items:center;text-align:center}
.bd-ring .n{font-size:28px;font-weight:800;line-height:1;font-variant-numeric:tabular-nums}
.bd-ring .k{font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);font-weight:800;margin-top:2px}
.bd-brk{flex:1;min-width:260px;display:flex;flex-direction:column;gap:8px}
.bd-ring.partial{opacity:.92}
.bd-ring.partial .k{color:var(--warn);font-weight:800}
.bd-partial{margin-top:9px;background:var(--warn-bg);border:1px solid var(--line);border-left:3px solid var(--warn);
  border-radius:9px;padding:9px 12px;font-size:12.5px;line-height:1.6}
.bd-partial b{color:var(--ink)}
.bd-brow{display:grid;grid-template-columns:150px 1fr 40px;gap:11px;align-items:center;font-size:12.5px}
.bd-brow .bl{color:var(--muted);font-weight:600}
.bd-bar{height:7px;border-radius:5px;background:var(--line);overflow:hidden}
.bd-bar span{display:block;height:100%;border-radius:5px}
.bd-brow .bv{text-align:right;font-weight:700;font-variant-numeric:tabular-nums}
.bd-fitrow{display:grid;grid-template-columns:130px 1fr;gap:13px;padding:11px 0;border-bottom:1px solid var(--line)}
.bd-fitrow:last-child{border-bottom:none}
.bd-fitk b{display:block;font-size:12.5px}
.bd-fitk span{display:block;color:var(--muted);font-size:11.5px}
.bd-rail{position:relative;height:24px;border-radius:7px;background:var(--line);overflow:hidden}
.bd-rail i{position:absolute;left:0;top:0;bottom:0;border-radius:7px}
.bd-rail em{position:absolute;inset:0;display:flex;align-items:center;padding:0 10px;font-style:normal;
  font-size:11.5px;font-weight:700;color:var(--ink);font-variant-numeric:tabular-nums}
.bd-fitn{font-size:11.5px;color:var(--muted);margin-top:5px;line-height:1.55}
.bd-verdictbox{display:flex;gap:12px;padding:13px 16px;border-top:1px solid var(--line);font-size:13px;line-height:1.6}
.bd-verdictbox.ok{background:var(--good-bg)}.bd-verdictbox.warn{background:var(--warn-bg)}
.bd-verdictbox .vi{font-size:18px}
.bd-oprow{display:flex;gap:14px;align-items:center;padding:13px 16px;flex-wrap:wrap;border-top:1px solid var(--line)}
.bd-oprow .ot{flex:1;min-width:240px}
.bd-oprow .ot b{display:block;font-size:13px}
.bd-oprow .ot span{display:block;color:var(--muted);font-size:11.5px;margin-top:2px}
.bd-blocked{padding:13px 16px;border-bottom:1px solid var(--line);border-left:3px solid var(--line)}
.bd-blocked:last-child{border-bottom:none}
.bd-blocked .bh{display:flex;align-items:center;gap:10px;flex-wrap:wrap;font-size:13px}
.bd-blocked .bh .meta{font-size:11.5px}
.bd-blocked .bw{font-size:12.5px;font-weight:600;margin-top:6px}
.bm-manual{font-size:12px;margin-top:8px;background:var(--bg);border:1px solid var(--line);border-radius:9px;
  padding:8px 11px;line-height:1.6;word-break:break-word}
.bm-manual span:first-child{font-weight:800;color:var(--muted);text-transform:uppercase;font-size:10.5px;
  letter-spacing:.05em;margin-right:6px}
/* grow dialog - the plugin's ds-modal pattern */
.ds-modal{position:fixed;inset:0;background:rgba(15,19,32,.55);display:grid;place-items:center;padding:20px;z-index:60}
.ds-modal[hidden]{display:none}
.ds-modal-card{width:min(580px,100%);max-height:92vh;overflow:auto;background:var(--card);border:1px solid var(--line);
  border-radius:14px;box-shadow:0 20px 50px rgba(15,19,32,.28)}
.ds-modal-head{display:flex;align-items:center;gap:10px;padding:14px 18px;border-bottom:1px solid var(--line)}
.ds-modal-head b{font-size:15px}
.gm-step{margin-left:auto;font-size:11px;color:var(--muted);background:var(--bg);border:1px solid var(--line);
  border-radius:20px;padding:3px 10px;white-space:nowrap}
.ds-modal-body{padding:16px 18px;font-size:13px;line-height:1.65}
.ds-modal-foot{display:flex;gap:9px;align-items:center;padding:13px 18px;border-top:1px solid var(--line);flex-wrap:wrap}
.gm-lg{margin-right:auto;font-size:11.5px;color:var(--muted)}
.gm-risks{margin:13px 0 0;padding:0;list-style:none;display:flex;flex-direction:column;gap:9px}
.gm-risks li{display:flex;gap:9px;font-size:12.5px;line-height:1.6;color:var(--muted)}
.gm-risks li b{color:var(--ink)}
.gm-risks .ri{width:17px;height:17px;border-radius:6px;flex:none;margin-top:1px;display:grid;place-items:center;
  background:var(--dang-bg);color:var(--dang);font-size:10px;font-weight:800}
.gm-risks .ri.ok{background:var(--good-bg);color:var(--good)}
.gm-spec{margin-top:14px;border:1px solid var(--line);border-radius:11px;overflow:hidden}
.gm-spec .sh{padding:8px 12px;background:var(--bg);border-bottom:1px solid var(--line);font-size:11px;
  font-weight:800;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
.gm-spec dl{margin:0;display:grid;grid-template-columns:auto 1fr}
.gm-spec dt{padding:9px 12px;color:var(--muted);font-size:12px;border-bottom:1px solid var(--line);white-space:nowrap}
.gm-spec dd{padding:9px 12px;margin:0;font-size:12.5px;border-bottom:1px solid var(--line)}
.gm-spec dt:last-of-type,.gm-spec dd:last-of-type{border-bottom:none}
.gm-conf{margin-top:15px;padding-top:13px;border-top:1px solid var(--line)}
.gm-conf label{display:block;font-size:12.5px;color:var(--muted);margin-bottom:7px}
.gm-conf input{width:100%;font-family:ui-monospace,Consolas,monospace;font-size:13px;padding:9px 12px;
  border:1px solid var(--line);border-radius:9px;background:var(--bg);color:var(--ink)}
.gm-conf input:focus{outline:none;border-color:var(--dang)}
.gm-conf input.ok{border-color:var(--good)}
/* Base primitives. The shared layout only adds sort/border ENHANCEMENTS to .smpro-table - the base
   look (full width, padding, header style, badges, live pill) is declared per page, as every other
   module does. Without this the tables fall back to bare browser defaults (shrink-to-fit, no padding). */
.smpro-tablewrap{overflow-x:auto}
.smpro-table{width:100%;border-collapse:collapse;font-size:12.5px}
.smpro-table th,.smpro-table td{padding:9px 12px;text-align:left;border-bottom:1px solid var(--line);white-space:nowrap;vertical-align:middle}
.smpro-table th{font-size:11px;text-transform:uppercase;letter-spacing:.03em;color:var(--muted);font-weight:800}
.smpro-table td.num,.smpro-table th.num{text-align:right;font-variant-numeric:tabular-nums}
.smpro-table tbody tr:hover{background:var(--brand-bg)}
.smpro-table tbody tr:last-child td{border-bottom:none}
.mono{font-family:ui-monospace,Consolas,monospace}
.meta{color:var(--muted)}
.b{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:20px;white-space:nowrap}
.b.green{background:var(--good-bg);color:var(--good)}.b.orange{background:var(--warn-bg);color:var(--warn)}
.b.red{background:var(--dang-bg);color:var(--dang)}.b.blue{background:var(--brand-bg);color:var(--brand)}
.b.gray{background:var(--bg);color:var(--muted)}
.live{font-size:11px;font-weight:700;color:var(--good);background:var(--good-bg);padding:3px 10px;border-radius:20px;margin-left:10px;display:inline-flex;align-items:center;gap:6px;vertical-align:middle}
.live i{width:7px;height:7px;border-radius:50%;background:var(--good);display:inline-block;animation:bdpulse 1.4s infinite}
@keyframes bdpulse{0%,100%{opacity:1}50%{opacity:.25}}
.live.stale{color:var(--muted);background:var(--bg)}.live.stale i{background:var(--muted);animation:none}
/* inline utilisation bar that sits ON the same line as its % (the stacked version looked broken) */
.bd-ibar{display:inline-block;width:88px;height:7px;border-radius:5px;background:var(--line);overflow:hidden;vertical-align:middle;margin-right:8px}
.bd-ibar span{display:block;height:100%;transition:width .4s ease}
.bd-ibar span.green{background:var(--good)}.bd-ibar span.orange{background:var(--warn)}.bd-ibar span.red{background:var(--dang)}
/* storage layout + per-device rows */
.bd-tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px;padding:14px 16px}
.bd-tile{border:1px solid var(--line);border-radius:11px;padding:11px 13px;background:var(--card)}
.bd-tile .k{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);font-weight:800}
.bd-tile .v{font-size:15px;font-weight:700;margin-top:4px}
.bd-tile .s{font-size:11.5px;color:var(--muted);margin-top:3px;line-height:1.5}
.bd-ghd{width:100%;font-family:inherit;text-align:left;cursor:pointer;border:0;border-top:1px solid var(--line);
  border-bottom:1px solid var(--line);padding:9px 16px;background:var(--bg);font-size:10.5px;font-weight:800;
  letter-spacing:.07em;text-transform:uppercase;color:var(--muted);display:flex;align-items:center;gap:9px}
.bd-ghd:hover{background:var(--brand-bg);color:var(--brand)}
.bd-ghd:focus-visible{outline:2px solid var(--brand);outline-offset:-2px}
.bd-ghd .rt{margin-left:auto;text-transform:none;letter-spacing:0;font-weight:600;font-size:11px;
  display:flex;align-items:center;gap:8px}
.bd-chev{font-size:11px;color:var(--muted);transition:transform .16s ease;display:inline-block;flex:none}
[aria-expanded="true"] .bd-chev{transform:rotate(90deg)}
@media (prefers-reduced-motion:reduce){.bd-chev{transition:none}}
.bd-row{display:grid;gap:14px;align-items:center;padding:13px 16px;border-bottom:1px solid var(--line);
  border-left:3px solid transparent;grid-template-columns:minmax(230px,1.6fr) 110px minmax(180px,1.2fr) 110px auto}
.bd-row:last-child{border-bottom:none}
.bd-row:hover{background:var(--brand-bg)}
.bd-row.bd-warnrow{border-left-color:var(--warn);background:linear-gradient(90deg,var(--warn-bg),transparent 55%)}
.bd-row.bd-dangrow{border-left-color:var(--dang);background:linear-gradient(90deg,var(--dang-bg),transparent 55%)}
.bd-row.bd-runrow{border-left-color:var(--brand)}
.bd-dv b{display:block;font-size:13px}
.bd-dv span{display:block;color:var(--muted);font-size:11.5px;margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.bd-mini{font-size:12px;color:var(--muted);font-variant-numeric:tabular-nums}
.bd-mini b{color:var(--ink);font-weight:600}
.bd-out{font-size:12px;font-variant-numeric:tabular-nums}
.bd-act{display:flex;justify-content:flex-end}
.bd-prg{height:6px;border-radius:5px;background:var(--line);overflow:hidden}
.bd-prg i{display:block;height:100%;width:60%;background:var(--brand);border-radius:5px}
.bd-prgt{font-size:11.5px;color:var(--brand);font-weight:600;margin-top:5px}
/* grade ruler */
.bd-ruler{padding:16px;background:var(--bg)}
.bd-rhd{display:flex;align-items:baseline;gap:9px;flex-wrap:wrap;margin-bottom:18px}
.bd-rhd b{font-size:13px}
.bd-segs{display:flex;height:10px;border-radius:5px;overflow:hidden}
.bd-segs i{display:block;position:relative}
.bd-segs i::after{content:attr(data-l);position:absolute;top:16px;left:0;font-size:10px;font-weight:700;
  color:var(--muted);white-space:nowrap}
.bd-marks{position:relative;height:70px;margin-top:32px}
.bd-mk{position:absolute;top:0;transform:translateX(-50%);text-align:center;width:92px}
.bd-mk .stem{width:1px;height:14px;background:var(--line);margin:0 auto 5px}
.bd-mk .dot{width:8px;height:8px;border-radius:50%;margin:0 auto 6px}
.bd-mk .nm{font-size:11.5px;font-weight:700}
.bd-mk .vl{font-size:10.5px;color:var(--muted);margin-top:2px;font-variant-numeric:tabular-nums}
.bd-mk.lo{top:36px}
/* io path */
.bd-path{padding:14px 16px;border-bottom:1px solid var(--line)}
.bd-path:last-child{border-bottom:none}
.bd-phd{display:flex;align-items:center;gap:10px;margin-bottom:11px;flex-wrap:wrap}
.bd-phd b{font-size:13px}
.bd-flow{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:9px}
.bd-fk{font-size:10.5px;font-weight:800;letter-spacing:.06em;text-transform:uppercase;width:44px;flex:none}
.bd-fk.w{color:var(--dang)}.bd-fk.r{color:var(--brand)}
.bd-nd{border:1px solid var(--line);border-radius:9px;padding:6px 11px;background:var(--card);font-size:12px;
  font-family:ui-monospace,Consolas,monospace;white-space:nowrap}
.bd-nd.arr{background:var(--bg);font-weight:700}
.bd-nd.slow{border-color:var(--warn);background:var(--warn-bg);color:var(--warn);font-weight:700}
.bd-nd.res{border-color:#bcd0ff;background:var(--brand-bg);color:var(--brand);font-weight:700}
.bd-ar{color:var(--muted);flex:none}
.bd-fork{display:flex;flex-direction:column;gap:6px}
.bd-vd{margin-top:4px;padding:9px 12px;border-radius:9px;background:var(--brand-bg);font-size:12.5px;line-height:1.6}
.bd-vd.alert{background:var(--warn-bg)}
.bd-vd b{color:var(--ink)}
.bd-ctl{display:flex;gap:8px}
.bd-head{display:flex;align-items:center;gap:10px;padding:12px 16px;border-bottom:1px solid var(--line);flex-wrap:wrap}
.bd-head .meta{color:var(--muted);font-size:12px}
.card>button.bd-head{width:100%;text-align:left;font-family:inherit;font-size:inherit;color:var(--ink);background:var(--card);border:0;border-bottom:1px solid var(--line);cursor:pointer}
.card>button.bd-head:hover{background:var(--brand-bg)}.card>button.bd-head:focus-visible{outline:2px solid var(--brand);outline-offset:-2px}
/* ---- overview strip / navigator (pattern: firewall-status.php) ---- */
/* .fw-kpis / .fw-nav / .fw-collapse / pager styles: shared, in includes/layout.php */
.bd-safe .gl-fold>summary{font-size:12.5px}
.bd-ic{font-size:16px}
.dbh-livemeta{margin-left:auto;font-size:12px;color:var(--muted)}.dbh-livemeta b{color:var(--ink)}
.bd-gauges{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;padding:14px 16px}
.bd-g{border:1px solid var(--line);border-radius:12px;padding:11px 13px;background:var(--card)}
.bd-gk{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);font-weight:800}
.bd-gv{font-size:19px;font-weight:800;margin:5px 0 7px}
.bd-gv .b{font-size:16px;padding:3px 10px}
.bd-bar{height:6px;background:var(--line);border-radius:4px;overflow:hidden}
.bd-bar span{display:block;height:100%;transition:width .4s ease}
.bd-bar span.green{background:var(--good)}.bd-bar span.orange{background:var(--warn)}.bd-bar span.red{background:var(--dang)}
.bd-gs{font-size:11px;color:var(--muted);margin-top:6px}
.bd-subhd{padding:10px 16px;border-top:1px solid var(--line);font-weight:700;font-size:12.5px;background:var(--bg)}
.bd-findings{display:flex;flex-direction:column}
.bd-f{padding:13px 16px;border-bottom:1px solid var(--line);border-left:3px solid transparent}
.bd-f:last-child{border-bottom:none}
.bd-f.bd-red{border-left-color:var(--dang)}.bd-f.bd-orange{border-left-color:var(--warn)}.bd-f.bd-blue{border-left-color:var(--brand)}
.bd-frow{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.bd-area{font-size:11px;color:var(--muted);font-weight:700;text-transform:uppercase;letter-spacing:.03em}
.bd-ftitle{font-size:14px;flex:1;min-width:200px}
.bd-ev{font-family:ui-monospace,Consolas,monospace;font-size:11.5px;color:var(--muted);margin-top:7px;line-height:1.55;word-break:break-word}
.bd-detail{font-size:12.5px;margin-top:6px;line-height:1.6;opacity:.9}
.bd-rec{font-size:12.5px;margin-top:7px;line-height:1.6;background:var(--brand-bg);border-radius:9px;padding:8px 11px}
.bd-rec span{font-weight:800;color:var(--brand);margin-right:4px}
.bd-fix{border-color:#bcd0ff!important;color:var(--brand);background:var(--brand-bg);white-space:nowrap;text-decoration:none;display:inline-block}
.bd-fix:hover{background:#dde6ff}.bd-fix:disabled{opacity:.6;cursor:default}
.bd-safe{background:var(--good-bg);border-bottom:1px solid var(--line);border-left:4px solid var(--good);padding:11px 15px;font-size:12.5px;line-height:1.6}
.bd-safe .mono{font-family:ui-monospace,Consolas,monospace;font-size:11.5px}
.bd-applied{display:inline-flex;align-items:center;gap:8px}
.bd-okpill{color:var(--good);font-weight:700;font-size:12px}
.bd-undo{border-color:var(--line)!important;font-size:11px;padding:4px 9px}
.bd-latest td{background:var(--brand-bg)}
.bd-ag{border-bottom:1px solid var(--line)}.bd-ag:last-child{border-bottom:none}
.bd-aghd{display:flex;align-items:center;gap:9px;padding:11px 16px;background:var(--bg);flex-wrap:wrap}
.bd-tested{font-size:11.5px;color:var(--muted);font-family:ui-monospace,Consolas,monospace}
.bd-atbl td.bd-expect{white-space:normal;max-width:420px;color:var(--muted);font-size:12px;line-height:1.55}
.bd-up{padding:13px 16px;border-bottom:1px solid var(--line);border-left:3px solid transparent}
.bd-up:last-child{border-bottom:none}
.bd-up.bd-red{border-left-color:var(--dang)}.bd-up.bd-orange{border-left-color:var(--warn)}
.bd-spec{font-size:12.5px;margin-top:8px;line-height:1.65;background:var(--warn-bg);border-radius:9px;padding:9px 12px}
.bd-spec span{font-weight:800;color:#8a6516;margin-right:4px}
html[data-theme=dark] .bd-spec span{color:#fdba74}
.bd-eccrow{padding:11px 16px;border-top:1px solid var(--line);font-size:12.5px}
.bm-inv{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:10px}
.bm-invcard{border:1px solid var(--line);border-radius:11px;padding:10px 12px;background:var(--card)}
.bm-invk{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);font-weight:800;margin-bottom:3px}
.bm-invv{font-size:13px}.bm-invv b{font-size:13px}
.bm-invs{font-size:11px;color:var(--muted);margin-top:3px;line-height:1.5}
.bm-disk{display:inline-block;background:var(--brand-bg);border-radius:6px;padding:1px 6px;margin:2px 3px 0 0;white-space:nowrap}
.bm-run{display:flex;gap:12px;align-items:center;flex-wrap:wrap}
.bm-run .meta{flex:1;min-width:240px;font-size:11.5px;line-height:1.5}
.bm-prog{margin-top:12px}.bm-progtxt{font-size:12px;color:var(--muted);margin-top:5px;font-weight:700}
.bm-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(215px,1fr));gap:12px;margin-top:12px}
.bm-rc{border:1px solid var(--line);border-radius:12px;padding:12px 14px;background:var(--card)}
.bm-rt{font-size:12px;font-weight:800;margin-bottom:8px}
.bm-rrow{display:flex;justify-content:space-between;gap:10px;font-size:12.5px;padding:4px 0;border-bottom:1px solid var(--line)}
.bm-rrow:last-child{border-bottom:none}.bm-rrow b{font-family:ui-monospace,Consolas,monospace}
.live.stale{color:var(--muted)}.live.stale i{background:var(--muted);animation:none}
</style>
<script>
(function(){
  if (window.__bdInit) return; window.__bdInit = 1;
  var CSRF = <?= json_encode(smpro_csrf_generate('bd_action'), JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE) ?>;
  var timer=null, paused=false, holdUntil=0, live=document.getElementById('bdLive');
  function $(id){return document.getElementById(id);}
  function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
  function mbs(v){return v==null?'—':(v>=1024?(v/1024).toFixed(2)+' GB/s':Math.round(v)+' MB/s');}
  function num(v){return v==null?'—':Number(v).toLocaleString();}
  function pcls(p){p=+p||0;return p>=90?'red':(p>=70?'orange':'green');}
  function post(p){var b=new URLSearchParams();b.set('smpro_csrf',CSRF);for(var k in p)b.set(k,p[k]);
    return fetch('index.cgi?page=benchmark',{method:'POST',cache:'no-store',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:b.toString()}).then(function(r){return r.json();});}
  function hold(ms){holdUntil=Date.now()+(ms||25000);}
  /* the storage block is re-rendered by the poll - remember which groups the admin had open */
  function openState(){
    var s={}; Array.prototype.forEach.call(document.querySelectorAll('#bdStor button[aria-controls]'),function(b){
      s[b.getAttribute('aria-controls')]=b.getAttribute('aria-expanded')==='true'; }); return s;
  }
  function restoreState(s){
    Array.prototype.forEach.call(document.querySelectorAll('#bdStor button[aria-controls]'),function(b){
      var id=b.getAttribute('aria-controls'); if(!(id in s))return;
      b.setAttribute('aria-expanded',s[id]?'true':'false');
      var body=document.getElementById(id); if(body)body.hidden=!s[id];
    });
  }
  function setBar(id,pct,cls){var e=$(id);if(!e)return;e.style.width=Math.min(100,Math.max(0,+pct||0))+'%';e.className=cls;}

  /* ---- live hardware gauges ---- */
  function renderLive(m){
    if(!m)return;
    var c=+(m.cpu&&m.cpu.pct)||0, r=+(m.ram&&m.ram.pct)||0, s=+(m.swap&&m.swap.pct)||0, p=+m.pressure||0;
    $('bdCpu').textContent=c+'%'; $('bdCpu').className='b '+pcls(c); setBar('bdCpuBar',c,pcls(c));
    $('bdRam').textContent=r+'%'; $('bdRam').className='b '+pcls(r); setBar('bdRamBar',r,pcls(r));
    $('bdSwap').textContent=s+'%';$('bdSwap').className='b '+pcls(s); setBar('bdSwapBar',s,pcls(s));
    if(m.load)$('bdLoad').textContent=m.load['1m']+' / '+m.load['5m']+' / '+m.load['15m'];
    $('bdLoad').className='b '+pcls(p); setBar('bdLoadBar',p,pcls(p));
    $('bdPress').textContent=p;
    if(m.ram)$('bdRamTx').textContent=(m.ram.used||'')+' / '+(m.ram.total||'');
    if(m.swap)$('bdSwapTx').textContent=(m.swap.used_mb||0)+' / '+(m.swap.total_mb||0)+' MB';
    $('bdCores').textContent=m.cores||0;
    $('bdTemp').innerHTML=m.temp?(m.temp+'&deg;C'):'—';
    $('bdUp').textContent=m.uptime||'—';
    $('bdProcs').textContent=m.procs||0;
    if(m.ts)$('bdClock').textContent=m.ts;
  }
  function renderDisks(ds){
    var tb=$('bdDiskBody'); if(!tb)return;
    if(!ds||!ds.length){tb.innerHTML='<tr><td colspan="6" style="color:var(--muted);padding:12px">No per-disk counters available.</td></tr>';return;}
    tb.innerHTML=ds.map(function(d){
      var u=+d.util||0, tt=d.temp_tier;
      var tcls=tt==='danger'?'red':(tt==='warn'?'orange':'green');
      return '<tr><td class="mono"><b>'+esc(d.dev)+'</b></td>'
        +'<td class="num mono">'+mbs((+d.r_kbs||0)/1024)+'</td>'
        +'<td class="num mono">'+mbs((+d.w_kbs||0)/1024)+'</td>'
        +'<td class="num mono">'+num(Math.round((+d.r_iops||0)+(+d.w_iops||0)))+'</td>'
        +'<td><span class="bd-ibar"><span class="'+(u>=85?'red':(u>=60?'orange':'green'))+'" style="width:'+Math.min(100,u)+'%"></span></span>'
        +'<span class="meta">'+u+'%</span></td>'
        +'<td class="num mono">'+(d.temp!=null?('<span class="b '+tcls+'">'+d.temp+'°C</span>'):'—')+'</td></tr>';
    }).join('');
  }
  function invCard(k,v,s){return '<div class="bm-invcard"><div class="bm-invk">'+k+'</div><div class="bm-invv"><b>'+v+'</b></div><div class="bm-invs">'+s+'</div></div>';}
  function renderInv(inv){
    var box=$('bmInv'); if(!box||!inv)return;
    var cpu=inv.cpu||{},ram=inv.ram||{},disks=inv.disks||[];
    var cs=(cpu.cores||0)+' threads'+(cpu.sockets?' · '+cpu.sockets+' socket(s)':'')+(cpu.mhz_max?' · up to '+Math.round(cpu.mhz_max)+' MHz':'')+(cpu.l3?' · L3 '+esc(cpu.l3):'');
    var rs=(ram.type?esc(ram.type):'type n/a')+(ram.speed?' · '+ram.speed+' MT/s':'')+(ram.modules?' · '+ram.modules+' module(s)':'');
    var ds=''; for(var i=0;i<Math.min(disks.length,4);i++){var d=disks[i];ds+='<span class="bm-disk">'+esc(d.name)+' '+esc(d.size)+' '+(d.ssd?'SSD':'HDD')+(d.tran?' '+esc(String(d.tran).toUpperCase()):'')+'</span> ';}
    var pv=inv.virt==='none'?'Bare metal':(inv.virt?esc(inv.virt.charAt(0).toUpperCase()+inv.virt.slice(1)):'—');
    box.innerHTML=invCard('&#129504; CPU',esc(cpu.model||'—'),cs)+invCard('&#129518; RAM',(ram.total_gb||0)+' GB',rs)
      +invCard('&#128190; Storage',disks.length+' disk(s)',ds||'—')+invCard('&#127959; Platform',pv,inv.virt==='none'?'physical server':(inv.virt?'virtualized ('+esc(inv.virt)+')':'—'));
  }
  function stepName(s){return {starting:'Starting…',cpu:'Testing CPU (AES-256)…',ram:'Testing RAM bandwidth…',disk:'Testing disk read/write…',php:'Testing PHP throughput…',mysql:'Testing MySQL…',done:'Done'}[s]||s;}
  function renderResults(r){
    if(!r) return ''; var h='<div class="bm-grid">';
    if(r.cpu){h+='<div class="bm-rc"><div class="bm-rt">&#129504; CPU · AES-256</div>'
      +'<div class="bm-rrow"><span>Single core</span><b>'+mbs(r.cpu.single_mbs)+'</b></div>'
      +'<div class="bm-rrow"><span>All '+(r.cpu.cores||'')+' threads</span><b>'+mbs(r.cpu.multi_mbs)+'</b></div>'
      +(r.cpu.scaling?'<div class="bm-rrow"><span>Parallel scaling</span><b>'+r.cpu.scaling+'×</b></div>':'')+'</div>';}
    if(r.ram){h+='<div class="bm-rc"><div class="bm-rt">&#129518; RAM bandwidth</div>'
      +(r.ram.err?'<div class="bm-rrow"><span>—</span><b>'+esc(r.ram.err)+'</b></div>'
       :'<div class="bm-rrow"><span>Write</span><b>'+mbs(r.ram.write_mbs)+'</b></div><div class="bm-rrow"><span>Read</span><b>'+mbs(r.ram.read_mbs)+'</b></div>')+'</div>';}
    if(r.disk){h+='<div class="bm-rc"><div class="bm-rt">&#128190; Disk'+(r.disk.mount?' ('+esc(r.disk.mount)+')':'')+'</div>'
      +(r.disk.err?'<div class="bm-rrow"><span>—</span><b>'+esc(r.disk.err)+'</b></div>'
       :'<div class="bm-rrow"><span>Seq write</span><b>'+mbs(r.disk.write_mbs)+'</b></div><div class="bm-rrow"><span>Seq read</span><b>'+mbs(r.disk.read_mbs)+'</b></div>'
        +'<div class="bm-rrow"><span>Random 4K IOPS</span><b>'+(r.disk.iops!=null?num(r.disk.iops):'— (fio)')+'</b></div>')+'</div>';}
    if(r.php){h+='<div class="bm-rc"><div class="bm-rt">&#128295; PHP '+esc(r.php.php_version||'')+'</div>'
      +'<div class="bm-rrow"><span>Integer ops</span><b>'+num(r.php.int_ops_sec)+'/s</b></div>'
      +'<div class="bm-rrow"><span>Hash (md5)</span><b>'+num(r.php.hash_ops_sec)+'/s</b></div>'
      +'<div class="bm-rrow"><span>Array + sort</span><b>'+num(r.php.array_ops_sec)+'/s</b></div></div>';}
    if(r.mysql){h+='<div class="bm-rc"><div class="bm-rt">&#128044; MySQL</div>'
      +(r.mysql.err?'<div class="bm-rrow"><span>—</span><b>'+esc(r.mysql.err)+'</b></div>'
       :'<div class="bm-rrow"><span>Connect latency</span><b>'+(r.mysql.connect_ms!=null?r.mysql.connect_ms+' ms':'—')+'</b></div>'
        +'<div class="bm-rrow"><span>Query throughput</span><b>'+num(r.mysql.query_ops_sec)+'/s</b></div>'
        +'<div class="bm-rrow"><span>InnoDB inserts</span><b>'+num(r.mysql.insert_rows_sec)+'/s</b></div>')+'</div>';}
    return h+'</div>';
  }
  function show(st){
    var prog=$('bdProg'),pt=$('bdProgTxt'),rr=$('bdResults'),run=$('bdRun'); if(!st)return;
    if(st.status==='running'){prog.style.display='';pt.textContent=stepName(st.step)+' ('+(st.pct||0)+'%)';run.disabled=true;run.textContent='⏳ Benchmarking…';
      if(st.results&&Object.keys(st.results).length){rr.style.display='';rr.innerHTML=renderResults(st.results);}}
    else if(st.status==='done'){prog.style.display='none';run.disabled=false;run.innerHTML='&#127937; Run full benchmark again';
      rr.style.display='';rr.innerHTML=renderResults(st.results)+'<div class="meta" style="margin-top:8px">Finished '+(st.finished?new Date(st.finished*1000).toLocaleString():'')+' · saved to Reports. <a href="index.cgi?page=benchmark">Reload</a> to see the full comparison.</div>';}
    else if(st.status==='error'){prog.style.display='none';run.disabled=false;run.innerHTML='&#127937; Run full benchmark';
      rr.style.display='';rr.innerHTML='<div class="db-box" style="color:var(--dang)">⚠ '+esc(st.msg||'Benchmark failed')+'</div>';}
  }
  function tick(){
    if(paused||document.hidden)return;
    fetch('index.cgi?page=benchmark&format=json&metric=benchdiag',{cache:'no-store'})
      .then(function(r){return r.json();})
      .then(function(j){
        if(!j||!j.ok)return;
        renderLive(j.live); renderDisks(j.disks); renderInv(j.inv); show(j.bench);
        if(Date.now()>=holdUntil){
          if(j.stor_html){var so=openState();$('bdStor').innerHTML=j.stor_html;restoreState(so);}
          if(j.ruler_html)$('bdRulerBody').innerHTML=j.ruler_html;
          if(j.path_html)$('bdPath').innerHTML=j.path_html;
          if(j.life_html)$('bdLife').innerHTML=j.life_html;
          if(j.hw_html){$('bdHw').innerHTML=j.hw_html;}
          if(j.diag_html){$('bdDiag').innerHTML=j.diag_html;}
          if(j.diag_n!=null)$('bdDiagN').textContent=j.diag_n;
          if(j.hw_verdict){var v=$('bdHwVerdict');v.textContent=j.hw_verdict;
            v.className='b '+(j.hw_verdict==='Healthy'?'green':(j.hw_verdict==='Failing'?'red':'orange'));}
        }
        if(live)live.classList.remove('stale');
      })
      .catch(function(){if(live)live.classList.add('stale');});
  }
  function schedule(){if(timer)clearInterval(timer);timer=setInterval(tick,+$('bdInt').value||2000);}

  $('bdRun').addEventListener('click',function(){
    var run=this;
    if(!confirm('Run the full benchmark now?\n\nIt tests CPU, RAM, disk (writes ~1 GB then removes it), PHP and MySQL (a TEMPORARY table that is auto-dropped). It briefly loads the server, runs in the background (~40–90s), and the result is saved to Reports — you can leave the page.'))return;
    run.disabled=true; run.textContent='⏳ Starting…';
    post({bd_action:'start'}).then(function(j){
      if(j&&j.ok){setTimeout(tick,900);}
      else{run.disabled=false;run.innerHTML='&#127937; Run full benchmark';alert((j&&j.msg)||'Could not start.');}
    }).catch(function(){run.disabled=false;run.innerHTML='&#127937; Run full benchmark';alert('⚠ Network error.');});
  });

  /* delegated - the troubleshooting list is re-rendered by the poll */
  document.addEventListener('click',function(e){
    var b;
    /* Collapsible section headers. Scoped to '#bdStor ...' this only worked for the re-rendered storage block -
       the page's other collapsibles ("What speed this server actually needs", "Storage changes") sit OUTSIDE
       that element, so clicking them did nothing at all. Match any collapsible header on the page. */
    if((b=e.target.closest('button[aria-controls]'))){
      var open=b.getAttribute('aria-expanded')==='true', body=document.getElementById(b.getAttribute('aria-controls'));
      b.setAttribute('aria-expanded',open?'false':'true'); if(body)body.hidden=open; return;
    }
    /* "test it" link in the Drive-lifetime table -> reveal the Physical drives section and scroll to it */
    if((b=e.target.closest('.bd-jumptest'))){ e.preventDefault();
      var pb=document.querySelector('[aria-controls="bdDrives"]'), body=document.getElementById('bdDrives');
      if(pb)pb.setAttribute('aria-expanded','true'); if(body){body.hidden=false; body.scrollIntoView({behavior:'smooth',block:'center'});}
      return;
    }
    /* grow a filesystem - opens the two-step confirmation */
    if((b=e.target.closest('.bd-grow'))){ growOpen(b); return; }
    /* test one device */
    if((b=e.target.closest('.bd-devtest'))){
      var kind=b.getAttribute('data-kind'), target=b.getAttribute('data-target')||'', orig=b.innerHTML;
      if(kind==='disk'&&!confirm('Test '+target+' now?\n\nThe drive is read ONLY — sequential read plus random-read IOPS straight from the device. Nothing is written to it. It runs in the background (~10-30s) and briefly loads that disk.\n\nContinue?'))return;
      b.disabled=true; b.innerHTML='⏳';
      post({bd_action:'devtest',kind:kind,target:target}).then(function(j){
        if(j&&j.ok){setTimeout(tick,700);}
        else{b.disabled=false;b.innerHTML=orig;alert('⚠ '+((j&&j.msg)||'Could not start.'));}
      }).catch(function(){b.disabled=false;b.innerHTML=orig;alert('⚠ Network error.');});
      return;
    }
    if((b=e.target.closest('button.bd-fix[data-key]'))){
      var key=b.getAttribute('data-key'), orig=b.innerHTML;
      if(!confirm('Apply this kernel setting now?\n\n'+key+'\n\nIt applies instantly (sysctl -w) and is written to our own drop-in so it survives a reboot. It changes a kernel TUNING NUMBER only — no data touched, nothing deleted, nothing to back up. You can Undo it right after.\n\nContinue?'))return;
      b.disabled=true;b.innerHTML='⏳ applying…';hold(60000);
      post({bd_action:'fix',key:key}).then(function(j){
        if(j&&j.ok){alert(j.msg||'Applied.');
          var w=document.createElement('span');w.className='bd-applied';
          w.innerHTML='<span class="bd-okpill">✅ applied'+(j.from&&j.to?(' · '+esc(j.from)+' → '+esc(j.to)):'')+'</span> <button class="tp-btn bd-undo" type="button" data-which="'+esc(j.undo||('sysctl:'+key))+'">↩ Undo</button>';
          b.replaceWith(w);
        } else {b.innerHTML=orig;b.disabled=false;hold(0);alert('⚠ '+((j&&j.msg)||'Could not apply.'));}
      }).catch(function(){b.innerHTML=orig;b.disabled=false;hold(0);alert('⚠ Network error.');});
      return;
    }
    if((b=e.target.closest('.bd-undo'))){
      var which=b.getAttribute('data-which');
      if(!confirm('Undo — restore the previous value?'))return;
      b.disabled=true;b.textContent='⏳';hold(30000);
      post({bd_action:'revert',which:which}).then(function(r){
        alert((r&&r.msg)||'Reverted.');
        if(r&&r.ok){b.textContent='↩ undone';hold(0);setTimeout(tick,700);}else{b.textContent='↩ Undo';b.disabled=false;}
      }).catch(function(){b.textContent='↩ Undo';b.disabled=false;alert('⚠ Network error.');});
    }
  });

  /* ---- two-step storage-change confirmation ---- */
  var gm=$('growModal'), gmDev='', gmLast=null;
  function gmStep(n){ $('gmStep1').hidden=(n!==1); $('gmStep2').hidden=(n!==2);
    if(n===2){ var i=$('gmInput'); i.value=''; i.classList.remove('ok'); $('gmGo').disabled=true;
      $('gmGo').textContent='Grow the filesystem'; setTimeout(function(){i.focus();},60); } }
  function growOpen(btn){
    gmDev=btn.getAttribute('data-dev'); gmLast=btn;
    $('gmFs').textContent=(btn.getAttribute('data-fs')||'').toUpperCase();
    $('gmMount').textContent=btn.getAttribute('data-mount')||'';
    $('gmFrom').textContent=btn.getAttribute('data-from')||'';
    $('gmTo').textContent=btn.getAttribute('data-to')||'';
    $('gmCmd').textContent=btn.getAttribute('data-cmd')||'';
    $('gmName').textContent=gmDev;
    gm.hidden=false; gmStep(1); hold(120000);
    setTimeout(function(){$('gmNext').focus();},110);
  }
  function gmClose(){ gm.hidden=true; hold(0); if(gmLast)gmLast.focus(); }
  $('gmNext').addEventListener('click',function(){gmStep(2);});
  $('gmBack').addEventListener('click',function(){gmStep(1);});
  Array.prototype.forEach.call(document.querySelectorAll('[data-gmclose]'),function(b){b.addEventListener('click',gmClose);});
  gm.addEventListener('mousedown',function(e){if(e.target===gm)gmClose();});
  document.addEventListener('keydown',function(e){if(e.key==='Escape'&&!gm.hidden)gmClose();});
  $('gmInput').addEventListener('input',function(){
    var ok=this.value.trim()===gmDev; $('gmGo').disabled=!ok; this.classList.toggle('ok',ok);
  });
  $('gmGo').addEventListener('click',function(){
    var go=this; go.disabled=true; go.textContent='Growing…'; hold(300000);
    post({bd_action:'grow',dev:gmDev,confirm:$('gmInput').value.trim()}).then(function(j){
      alert((j&&j.msg)||'Done.');
      if(j&&j.ok){ go.textContent='✓ Completed'; setTimeout(function(){gmClose();location.reload();},900); }
      else { go.disabled=false; go.textContent='Grow the filesystem'; hold(0); }
    }).catch(function(){ go.disabled=false; go.textContent='Grow the filesystem'; hold(0); alert('⚠ Network error.'); });
  });

  $('bdInt').addEventListener('change',schedule);
  $('bdPause').addEventListener('click',function(){paused=!paused;this.textContent=paused?'Resume':'Pause';
    if(live)live.classList.toggle('stale',paused); if(!paused)tick();});
  document.addEventListener('visibilitychange',function(){if(!document.hidden)tick();});
  tick(); schedule();
})();
</script>
<script>
(function(){
  /* collapsible cards (a11y toggle: button.bd-head[aria-expanded][aria-controls]) + sticky navigator.
     The page's delegated click handler already flips aria-expanded and body.hidden for ANY
     button[aria-controls]; this only wraps the bodies, remembers the choice, and drives the chips. */
  var KEY='smpro:benchmark:open', open={};
  try{ open=JSON.parse(localStorage.getItem(KEY)||'{}')||{}; }catch(err){ open={}; }
  function remember(){ try{ localStorage.setItem(KEY, JSON.stringify(open)); }catch(err){} }
  function headOf(card){ for(var i=0;i<card.children.length;i++){ var ch=card.children[i]; if(ch.tagName==='BUTTON'&&ch.classList.contains('bd-head')&&ch.hasAttribute('aria-controls')) return ch; } return null; }
  function keyOf(card,b){ return card.id||b.getAttribute('aria-controls'); }
  function setOpen(card,on){ var b=headOf(card); if(!b) return; var body=document.getElementById(b.getAttribute('aria-controls'));
    b.setAttribute('aria-expanded',on?'true':'false'); if(body) body.hidden=!on; open[keyOf(card,b)]=on; }
  function openCard(id,scroll){ var card=document.getElementById(id); if(!card) return; var b=headOf(card);
    if(b&&b.getAttribute('aria-expanded')!=='true'){ setOpen(card,true); remember(); }
    if(scroll){ card.style.scrollMarginTop='120px'; card.scrollIntoView({behavior:'smooth',block:'start'}); } }
  var cards=document.querySelectorAll('.smpro-main .card'), i;
  for(i=0;i<cards.length;i++){ var card=cards[i], b=headOf(card); if(!b) continue;
    var cid=b.getAttribute('aria-controls'), body=document.getElementById(cid);
    if(!body){ body=document.createElement('div'); body.id=cid; while(b.nextSibling){ body.appendChild(b.nextSibling); } card.appendChild(body); }
    var k=keyOf(card,b), on=Object.prototype.hasOwnProperty.call(open,k)?!!open[k]:(b.getAttribute('aria-expanded')==='true');
    b.setAttribute('aria-expanded',on?'true':'false'); body.hidden=!on; }
  document.addEventListener('click',function(e){
    var b=e.target.closest('button.bd-head[aria-controls]');
    if(b&&b.parentElement&&b.parentElement.classList.contains('card')){ open[keyOf(b.parentElement,b)]=b.getAttribute('aria-expanded')==='true'; remember(); return; }
    if(e.target.closest('.bd-jumptest')) openCard('bd-storage',false);   /* the drives table lives inside the storage card */
  });
  var gos=document.querySelectorAll('.fw-nav [data-go], .fw-kpis [data-go]');
  for(i=0;i<gos.length;i++){ (function(a){ a.addEventListener('click',function(e){ e.preventDefault(); var id=a.getAttribute('data-go'); openCard(id,true);
    var ch=document.querySelectorAll('.fw-nav a'); for(var j=0;j<ch.length;j++) ch[j].classList.toggle('on', ch[j].getAttribute('data-go')===id);
    try{ history.replaceState(null,'','#'+id); }catch(err){} }); })(gos[i]); }
  function all(on){ for(var j=0;j<cards.length;j++){ if(headOf(cards[j])) setOpen(cards[j],on); } remember(); }
  var oa=document.getElementById('bdOpenAll'), ca=document.getElementById('bdCloseAll');
  if(oa) oa.addEventListener('click',function(){ all(true); });
  if(ca) ca.addEventListener('click',function(){ all(false); });
  if(location.hash && document.getElementById(location.hash.slice(1))) setTimeout(function(){ openCard(location.hash.slice(1), true); },150);
  window.bdOpenCard=openCard;
})();
</script>
<?php
smpro_layout_footer();
