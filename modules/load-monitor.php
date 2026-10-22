<?php
/**
 * modules/load-monitor.php — Load Monitor (live).
 * A full, organised view of server load: load averages + pressure, per-core CPU,
 * memory & swap detail, disk usage, and the top processes by CPU and by memory,
 * plus a live load sparkline and a hardware summary. Read-only; self-contained
 * JSON endpoint (?page=load-monitor&live=1) polled every few seconds.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

/* ---------------- collectors ---------------- */
function smpro_lo_stat() {
    $r = [];
    foreach (file('/proc/stat') ?: [] as $l) if (preg_match('/^(cpu\d*)\s+(.+)/', $l, $m)) $r[$m[1]] = array_map('intval', preg_split('/\s+/', trim($m[2])));
    return $r;
}
function smpro_lo_meminfo() {
    $mi = [];
    foreach (file('/proc/meminfo', FILE_IGNORE_NEW_LINES) ?: [] as $l) { $p = explode(':', $l, 2); if (count($p) === 2) $mi[trim($p[0])] = (int)filter_var($p[1], FILTER_SANITIZE_NUMBER_INT); }
    return $mi;
}
function smpro_lo_ps($sort, $n = 8) {
    $sort = $sort === 'mem' ? '-pmem' : '-pcpu';
    $self = function_exists('getmypid') ? (int)getmypid() : 0;
    $raw = (string)@shell_exec('timeout 8 ps -eo pid,user:20,pcpu,pmem,comm --sort=' . $sort . ' 2>/dev/null | head -n ' . ($n + 6));
    $rows = []; $i = 0;
    foreach (explode("\n", trim($raw)) as $l) {
        if ($i++ === 0) continue;
        if (!preg_match('/^\s*(\d+)\s+(\S+)\s+([\d.]+)\s+([\d.]+)\s+(.+)$/', $l, $m)) continue;
        $pid = (int)$m[1]; $cmd = trim($m[5]);
        if ($cmd === 'ps' || $pid === $self) continue;   // hide the monitoring command itself (inflated %CPU artifact)
        $rows[] = ['pid' => $pid, 'user' => $m[2], 'cpu' => (float)$m[3], 'mem' => (float)$m[4], 'cmd' => $cmd];
        if (count($rows) >= $n) break;
    }
    return $rows;
}
function smpro_lo_live() {
    $s1 = smpro_lo_stat(); usleep(750000); $s2 = smpro_lo_stat();   // longer window = stable per-core % (not transient 100%)
    $cores = []; $cpuPct = 0;
    foreach ($s2 as $cpu => $b) {
        if (!isset($s1[$cpu])) continue;
        $a = $s1[$cpu];
        $idle = (($b[3] ?? 0) + ($b[4] ?? 0)) - (($a[3] ?? 0) + ($a[4] ?? 0));
        $tot = array_sum($b) - array_sum($a);
        $p = $tot > 0 ? round((1 - $idle / $tot) * 100, 1) : 0;
        if ($cpu === 'cpu') $cpuPct = $p; else $cores[] = ['cpu' => $cpu, 'pct' => $p];
    }
    $mi = smpro_lo_meminfo();
    $memTotal = $mi['MemTotal'] ?? 0; $memAvail = $mi['MemAvailable'] ?? ($mi['MemFree'] ?? 0); $memUsed = max(0, $memTotal - $memAvail);
    $swapTotal = $mi['SwapTotal'] ?? 0; $swapUsed = max(0, $swapTotal - ($mi['SwapFree'] ?? 0));
    $la = preg_split('/\s+/', trim((string)@file_get_contents('/proc/loadavg')));
    $nproc = max(1, count($cores) ?: (int)trim((string)@shell_exec('nproc 2>/dev/null')));
    $up = (int)(float)(explode(' ', (string)@file_get_contents('/proc/uptime'))[0] ?? 0);
    $procs = (int)trim((string)@shell_exec('ps -e --no-headers 2>/dev/null | wc -l'));
    $fs = [];
    foreach (explode("\n", (string)@shell_exec("df -P -B1 -x tmpfs -x devtmpfs -x overlay 2>/dev/null")) as $i => $l) {
        if ($i === 0) continue;
        if (!preg_match('/^(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)%\s+(\S.*)$/', trim($l), $m)) continue;
        $fs[] = ['dev' => $m[1], 'total' => (int)$m[2], 'used' => (int)$m[3], 'pct' => (int)$m[5], 'mount' => $m[6]];
    }
    usort($fs, fn($a, $b) => $b['pct'] <=> $a['pct']);
    $l1 = (float)($la[0] ?? 0);
    return [
        'ts' => date('H:i:s'),
        'load' => ['1m' => round($l1, 2), '5m' => round((float)($la[1] ?? 0), 2), '15m' => round((float)($la[2] ?? 0), 2),
                   'pressure' => round($l1 / $nproc * 100, 1), 'cores' => $nproc, 'running' => (int)(explode('/', $la[3] ?? '0/0')[0])],
        'cpu_pct' => $cpuPct, 'cores' => $cores,
        'mem' => ['total' => $memTotal * 1024, 'used' => $memUsed * 1024, 'avail' => $memAvail * 1024,
                  'cached' => ($mi['Cached'] ?? 0) * 1024, 'buffers' => ($mi['Buffers'] ?? 0) * 1024,
                  'pct' => $memTotal ? round($memUsed / $memTotal * 100, 1) : 0],
        'swap' => ['total' => $swapTotal * 1024, 'used' => $swapUsed * 1024, 'pct' => $swapTotal ? round($swapUsed / $swapTotal * 100, 1) : 0],
        'procs' => $procs, 'uptime' => $up, 'fs' => $fs,
        'top_cpu' => smpro_lo_ps('cpu', 8), 'top_mem' => smpro_lo_ps('mem', 8),
    ];
}
function smpro_lo_human($b) { $b = (float)$b; $u = ['B','KB','MB','GB','TB']; $i = 0; while ($b >= 1024 && $i < 4) { $b /= 1024; $i++; } return ($i ? round($b, 1) : (int)$b) . ' ' . $u[$i]; }
function smpro_lo_dur($s) { $d = intdiv($s, 86400); $h = intdiv($s % 86400, 3600); $m = intdiv($s % 3600, 60); return ($d ? $d . 'd ' : '') . $h . 'h ' . $m . 'm'; }

/* ---------------- hardware & platform static facts (merged from the old Hardware page, cached ~1h) ---------------- */
if (!defined('SMPRO_HW_CACHE')) define('SMPRO_HW_CACHE', SMPRO_VARLIB . '/cache/hardware.json');
function smpro_hw_dmi($name) { $f = '/sys/class/dmi/id/' . $name; return is_readable($f) ? trim((string)@file_get_contents($f)) : ''; }
function smpro_hw_cmd($cmd, $t = 8) { return trim((string)@shell_exec('timeout ' . $t . ' ' . $cmd . ' 2>/dev/null')); }
function smpro_hw_static() {
    if (is_file(SMPRO_HW_CACHE) && (time() - (int)@filemtime(SMPRO_HW_CACHE)) < 3600) { $j = json_decode((string)@file_get_contents(SMPRO_HW_CACHE), true); if (is_array($j)) return $j; }
    $cpuModel = '';
    foreach (file('/proc/cpuinfo', FILE_IGNORE_NEW_LINES) ?: [] as $l) { if (stripos($l, 'model name') === 0) { $cpuModel = trim(explode(':', $l, 2)[1] ?? ''); break; } }
    $lscpu = []; foreach (explode("\n", smpro_hw_cmd('lscpu')) as $l) { $p = explode(':', $l, 2); if (count($p) === 2) $lscpu[trim($p[0])] = trim($p[1]); }
    $memTotalKb = (int)filter_var(trim((string)(explode(':', (string)@shell_exec("grep MemTotal /proc/meminfo"), 2)[1] ?? '0')), FILTER_SANITIZE_NUMBER_INT);
    $os = '';
    if (is_readable('/etc/os-release')) foreach (file('/etc/os-release', FILE_IGNORE_NEW_LINES) ?: [] as $l) if (strpos($l, 'PRETTY_NAME=') === 0) $os = trim(str_replace(['PRETTY_NAME=', '"'], '', $l));
    $clRel = is_readable('/etc/redhat-release') ? trim((string)@file_get_contents('/etc/redhat-release')) : '';
    $cpver = is_readable('/usr/local/cpanel/version') ? trim((string)@file_get_contents('/usr/local/cpanel/version')) : '';
    $disks = [];
    foreach (explode("\n", smpro_hw_cmd("lsblk -dn -o NAME,SIZE,MODEL,ROTA,TYPE 2>/dev/null")) as $l) { if (!preg_match('/^(\S+)\s+(\S+)\s+(.*?)\s+(\d)\s+(\S+)$/', trim($l), $m)) continue; if ($m[5] !== 'disk') continue; $disks[] = ['name'=>$m[1],'size'=>$m[2],'model'=>trim($m[3]) ?: '—','type'=>$m[4] === '0' ? 'SSD/NVMe' : 'HDD']; }
    $nics = [];
    foreach (explode("\n", smpro_hw_cmd("ip -br -4 addr show 2>/dev/null")) as $l) { if (!preg_match('/^(\S+)\s+(\S+)\s+(.*)$/', trim($l), $m)) continue; if ($m[1] === 'lo') continue; $nics[] = ['name'=>$m[1],'state'=>$m[2],'ip'=>trim($m[3]) ?: '—']; }
    $data = ['hostname'=>gethostname(),'cpu_model'=>$cpuModel ?: ($lscpu['Model name'] ?? '—'),'sockets'=>$lscpu['Socket(s)'] ?? '1','cores_per_socket'=>$lscpu['Core(s) per socket'] ?? '','threads_per_core'=>$lscpu['Thread(s) per core'] ?? '',
        'cpus'=>(int)(smpro_hw_cmd('nproc') ?: ($lscpu['CPU(s)'] ?? 0)),'cpu_mhz'=>$lscpu['CPU MHz'] ?? ($lscpu['CPU max MHz'] ?? ''),'cache_l3'=>$lscpu['L3 cache'] ?? '','arch'=>php_uname('m'),
        'virt'=>smpro_hw_cmd('systemd-detect-virt') ?: ($lscpu['Hypervisor vendor'] ?? 'bare metal'),'os'=>$os ?: php_uname('s'),'distro'=>$clRel,'kernel'=>php_uname('r'),'cpanel'=>$cpver,
        'sys_vendor'=>smpro_hw_dmi('sys_vendor'),'product'=>smpro_hw_dmi('product_name'),'board'=>trim(smpro_hw_dmi('board_vendor').' '.smpro_hw_dmi('board_name')),
        'bios'=>trim(smpro_hw_dmi('bios_vendor').' '.smpro_hw_dmi('bios_version').' ('.smpro_hw_dmi('bios_date').')'),'mem_total_gb'=>$memTotalKb ? round($memTotalKb/1048576,1) : 0,'disks'=>$disks,'nics'=>$nics,'collected'=>date('Y-m-d H:i')];
    @is_dir(dirname(SMPRO_HW_CACHE)) || @mkdir(dirname(SMPRO_HW_CACHE), 0700, true);
    @file_put_contents(SMPRO_HW_CACHE, json_encode($data, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE), LOCK_EX);
    return $data;
}

/* ---------------- persistent 24h load history (survives reload / other browsers) ---------------- */
require_once SMPRO_INCLUDES . '/loadhist.php';   // the 24 h ring: fed by cron every minute, topped up by this page's poll

/* ---------------- live JSON endpoint ---------------- */
if (isset($_GET['live'])) {
    header('Content-Type: application/json');
    $L = smpro_lo_live();
    $hist = smpro_lo_hist_tick(is_array($L['load'] ?? null) ? ($L['load']['1m'] ?? 0) : 0);
    $health = function_exists('smpro_sv_snapshot') ? smpro_sv_snapshot() : null;   // one request feeds both the live cards and the health ring
    echo json_encode(['ok' => true, 'live' => $L, 'hist' => $hist, 'health' => $health], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

/* ---------------- render ---------------- */
// smpro_lo_live() blocks 0.75s on a two-point CPU sample. The page self-polls ?live=1 every 3s (which calls
// smpro_lo_live() fresh), so cache the RENDER sample briefly — first paint is instant, the poll keeps it live.
$L = smpro_cache_through('lo_live_render', 5, fn() => smpro_lo_live());
// hardware summary
$cpuModel = '';
foreach (file('/proc/cpuinfo', FILE_IGNORE_NEW_LINES) ?: [] as $l) { if (stripos($l, 'model name') === 0) { $cpuModel = trim(explode(':', $l, 2)[1] ?? ''); break; } }
$nproc = $L['load']['cores'];
$press = $L['load']['pressure'];
$verdict = $press >= 100 ? ['CRITICAL', 'danger'] : ($press >= 70 ? ['HIGH', 'warn'] : ['HEALTHY', 'good']);
$loadCls = smpro_load_cls($L['load']['1m']);   // load NUMBER colour = ABSOLUTE 1m load (admin spec)
$loadBar = ['good' => 'var(--good)', 'elev' => '#f97316', 'warn' => 'var(--warn)', 'danger' => 'var(--dang)'][$loadCls];

$hw = smpro_hw_static();
$d  = function_exists('smpro_sv_snapshot') ? smpro_sv_snapshot() : null;   // server-health score (merged in)
smpro_audit('load_monitor_view', ['pressure' => $press]);
smpro_layout_header('Server Health & System');
?>
<div class="svc-kicker">Server Monitoring</div>
<div style="display:flex;justify-content:space-between;align-items:flex-start;gap:14px;flex-wrap:wrap">
  <div><h1 class="h" style="margin:2px 0 4px" data-i18n>Server Health &amp; System <span class="lo-live" id="loLive">&#9679; LIVE</span></h1>
    <p class="sub" data-i18n>Server health score, live load &amp; pressure, per-core CPU, memory &amp; swap, disk, heaviest processes — plus full hardware &amp; platform details. Auto-refreshing.</p></div>
  <div style="display:flex;gap:10px;align-items:center"><span class="pill <?= $verdict[1] ?>" id="loVerdict"><?= $verdict[0] ?></span>
    <label class="lo-pause"><input type="checkbox" id="loPause"> Pause</label></div>
</div>

<?php if ($d): ?>
<!-- Server Health score (merged from Server Health) -->
<div class="card sv-hero <?= smpro_h($d['cls']) ?>" id="lo-hero">
  <div class="sv-donut">
    <svg viewBox="0 0 120 120" width="132" height="132">
      <circle cx="60" cy="60" r="52" fill="none" stroke="#e9edf5" stroke-width="12"></circle>
      <circle id="svRing" cx="60" cy="60" r="52" fill="none" stroke-width="12" stroke-linecap="round" transform="rotate(-90 60 60)" stroke-dasharray="<?= 2*M_PI*52 ?>" stroke-dashoffset="<?= 2*M_PI*52*(1-$d['score']/100) ?>"></circle>
      <text x="60" y="58" text-anchor="middle" class="sv-num" id="svScore"><?= (int)$d['score'] ?></text>
      <text x="60" y="76" text-anchor="middle" class="sv-sub">/100</text>
    </svg>
  </div>
  <div class="sv-state">
    <div class="sv-statelbl" data-i18n>Server Health Score</div>
    <div class="sv-status"><span class="pill <?= smpro_h($d['cls']) ?>" id="svStatus"><?= smpro_h($d['status']) ?></span> <span class="sv-title" id="svTitle"><?= smpro_h($d['status_title']) ?></span></div>
    <p class="sv-expl" id="svExpl"><?= smpro_h($d['cause']) ?> 1m <b><?= smpro_h($d['load']['1m']['v']) ?></b>, 5m <b><?= smpro_h($d['load']['5m']['v']) ?></b>, 15m <b><?= smpro_h($d['load']['15m']['v']) ?></b> on <?= (int)$d['cores'] ?> cores. Effective pressure: <b><?= smpro_h($d['eff']) ?>%</b>.</p>
  </div>
</div>
<?php endif; ?>

<!-- KPIs -->
<div class="lo-kpis">
  <div class="lo-kpi span2">
    <div class="lo-kl">Load average · 1 / 5 / 15 min</div>
    <div class="lo-load" id="loLoad"><b id="loLoadV" class="lo-v <?= $loadCls ?>"><?= $L['load']['1m'] ?></b> / <?= $L['load']['5m'] ?> / <?= $L['load']['15m'] ?> <span id="loLoadPct" class="lo-vpill <?= $loadCls ?>"><?= (int)round($press) ?>%</span></div>
    <div class="lo-bar"><i id="loPressBar" style="width:<?= min(100, $press) ?>%;background:<?= $loadBar ?>"></i></div>
    <div class="lo-kmeta"><span id="loPress"><?= $press ?></span>% pressure · <?= (int)$nproc ?> cores · <b id="loRunning"><?= $L['load']['running'] ?></b> running</div>
  </div>
  <div class="lo-kpi"><div class="lo-gauge"><svg viewBox="0 0 36 36"><path class="bg" d="M18 2 a16 16 0 1 1 0 32 a16 16 0 1 1 0 -32"/><path class="fg" id="gCpu" d="M18 2 a16 16 0 1 1 0 32 a16 16 0 1 1 0 -32"/></svg><div class="lo-gv"><b id="kCpu"><?= $L['cpu_pct'] ?></b>%</div></div><div class="lo-kl">CPU</div></div>
  <div class="lo-kpi"><div class="lo-gauge"><svg viewBox="0 0 36 36"><path class="bg" d="M18 2 a16 16 0 1 1 0 32 a16 16 0 1 1 0 -32"/><path class="fg" id="gMem" d="M18 2 a16 16 0 1 1 0 32 a16 16 0 1 1 0 -32"/></svg><div class="lo-gv"><b id="kMem"><?= $L['mem']['pct'] ?></b>%</div></div><div class="lo-kl">RAM</div></div>
  <div class="lo-kpi"><div class="lo-gauge"><svg viewBox="0 0 36 36"><path class="bg" d="M18 2 a16 16 0 1 1 0 32 a16 16 0 1 1 0 -32"/><path class="fg" id="gSwap" d="M18 2 a16 16 0 1 1 0 32 a16 16 0 1 1 0 -32"/></svg><div class="lo-gv"><b id="kSwap"><?= $L['swap']['pct'] ?></b>%</div></div><div class="lo-kl">Swap</div></div>
</div>

<p class="meta" style="font-size:11.5px;margin:-2px 0 12px" data-i18n>CPU % is an instantaneous snapshot — short php-cgi bursts can momentarily read 100%. <b>Load Average</b> (above) is the authoritative health metric: <?= number_format($L['load']['pressure'],0) ?>% of <?= (int)$nproc ?> cores used over time.</p>

<?php
// overview strip: one tile per section, each a link to the card it comes from (values are the render sample)
$loFsMax = null;
foreach ($L['fs'] as $f) { if ($loFsMax === null || (float)$f['pct'] > (float)$loFsMax['pct']) $loFsMax = $f; }
$loHealthCls = $d ? ($d['cls'] === 'danger' ? 'dang' : ($d['cls'] === 'attn' ? 'warn' : $d['cls'])) : 'muted';
$loFsCls = $loFsMax ? ((int)$loFsMax['pct'] >= 90 ? 'dang' : ((int)$loFsMax['pct'] >= 75 ? 'warn' : 'good')) : 'muted';
$loKpis = [
  ['lo-hero',   'Health score', $d ? (int)$d['score'] . '/100' : 'n/a',            $loHealthCls,                                     $d ? $d['status'] : 'snapshot unavailable'],
  ['lo-live',   'Pressure',     (int)round($press) . '%',                           $verdict[1] === 'danger' ? 'dang' : $verdict[1],   $verdict[0] . ' · load ' . $L['load']['1m'] . ' on ' . (int)$nproc . ' cores'],
  ['lo-topcpu', 'Processes',    number_format((int)$L['procs']),                    'brand',                                           $L['load']['running'] . ' running'],
  ['lo-mem',    'Memory',       $L['mem']['pct'] . '%',                             (float)$L['mem']['pct'] >= 90 ? 'dang' : ((float)$L['mem']['pct'] >= 75 ? 'warn' : 'good'), smpro_lo_human($L['mem']['used']) . ' of ' . smpro_lo_human($L['mem']['total']) . ' · swap ' . $L['swap']['pct'] . '%'],
  ['lo-fs',     'Fullest disk', $loFsMax ? (int)$loFsMax['pct'] . '%' : 'n/a',      $loFsCls,                                          $loFsMax ? $loFsMax['mount'] . ' · ' . smpro_lo_human($loFsMax['used']) . ' used' : 'no mounts'],
  ['lo-hw',     'Platform',     (int)$hw['cpus'] . ' CPU · ' . $hw['mem_total_gb'] . ' GB', 'brand',                                  trim($hw['virt'] . ' · up ' . smpro_lo_dur($L['uptime']), ' ·'), 'lo-vs'],
];
?>
<div class="fw-kpis">
  <?php foreach ($loKpis as $k): ?>
  <a class="fw-kpi <?= $k[3] ?><?= !empty($k[5]) ? ' ' . $k[5] : '' ?>" href="#<?= $k[0] ?>" data-go="<?= $k[0] ?>"><div class="l"><?= smpro_h($k[1]) ?></div><div class="v"><?= smpro_h($k[2]) ?></div><div class="s"><?= smpro_h($k[4]) ?></div></a>
  <?php endforeach; ?>
</div>
<nav class="fw-nav" id="loNav" data-keep-open="1"><a href="#lo-live" data-go="lo-live">&#128200; Live load</a><a href="#lo-hist" data-go="lo-hist">&#128197; 24 hours</a><a href="#lo-cores" data-go="lo-cores">Per-core</a><a href="#lo-mem" data-go="lo-mem">Memory</a><a href="#lo-topcpu" data-go="lo-topcpu">Top CPU</a><a href="#lo-topmem" data-go="lo-topmem">Top memory</a><a href="#lo-fs" data-go="lo-fs">&#128190; Disks</a><a href="#lo-hw" data-go="lo-hw">&#128421; Hardware</a><a href="#coolCard" data-go="coolCard">&#10052; Cooler</a><a href="#ovCard" data-go="ovCard">&#128269; Overload</a><span class="sp"></span><button type="button" class="fw-navx" id="loOpenAll">expand all</button><button type="button" class="fw-navx" id="loCloseAll">collapse all</button></nav>

<!-- load history sparkline -->
<div class="card" id="lo-live" style="margin-bottom:14px">
  <div class="lo-spark-h lo-hd"><b>Load (1-min) — live history</b><span class="meta" id="loSparkNow"></span></div>
  <svg id="loSpark" class="lo-spark" viewBox="0 0 600 80" preserveAspectRatio="none"><polyline id="loSparkLine" fill="none" stroke="var(--brand)" stroke-width="2" points=""></polyline></svg>
</div>

<!-- persistent 24h load history (server-side; survives reload) -->
<div class="card" id="lo-hist" style="margin-bottom:14px">
  <div class="lo-spark-h lo-hd"><b>Load — last 24 hours</b><span class="meta" id="loHistMeta"></span></div>
  <svg id="loHist" class="lo-spark" viewBox="0 0 600 90" preserveAspectRatio="none" style="height:90px">
    <line x1="0" y1="45" x2="600" y2="45" stroke="var(--line)" stroke-width="1" stroke-dasharray="3,3"></line>
    <polyline id="loHistLine" fill="none" stroke="var(--good)" stroke-width="1.5" points=""></polyline>
  </svg>
  <div class="meta" style="display:flex;justify-content:space-between;margin-top:2px"><span id="loHistFrom">-24h</span><span id="loHistPeak"></span><span>now</span></div>
</div>

<div class="lo-two">
  <!-- per-core -->
  <div class="card" id="lo-cores" style="padding:0;overflow:hidden">
    <div class="tp-th"><b>Per-core CPU</b><span class="meta"><?= (int)$nproc ?> logical CPUs</span></div>
    <div id="loCores" class="lo-cores">
      <?php foreach ($L['cores'] as $c): ?><div class="lo-core" data-cpu="<?= smpro_h($c['cpu']) ?>"><span class="lo-cn"><?= smpro_h(strtoupper($c['cpu'])) ?></span><div class="lo-bar sm"><i style="width:<?= (float)$c['pct'] ?>%"></i></div><span class="lo-cp"><?= $c['pct'] ?>%</span></div><?php endforeach; ?>
    </div>
  </div>
  <!-- memory detail -->
  <div class="card" id="lo-mem" style="padding:0;overflow:hidden">
    <div class="tp-th"><b>Memory &amp; Swap</b></div>
    <table class="smpro-table lo-kv">
      <tr><td>RAM total</td><td><b id="mTotal"><?= smpro_lo_human($L['mem']['total']) ?></b></td></tr>
      <tr><td>RAM used</td><td><span id="mUsed"><?= smpro_lo_human($L['mem']['used']) ?></span> (<span id="mPct"><?= $L['mem']['pct'] ?></span>%)</td></tr>
      <tr><td>RAM available</td><td id="mAvail"><?= smpro_lo_human($L['mem']['avail']) ?></td></tr>
      <tr><td>Cached</td><td id="mCached"><?= smpro_lo_human($L['mem']['cached']) ?></td></tr>
      <tr><td>Buffers</td><td id="mBuf"><?= smpro_lo_human($L['mem']['buffers']) ?></td></tr>
      <tr><td>Swap</td><td><span id="sUsed"><?= smpro_lo_human($L['swap']['used']) ?></span> / <?= smpro_lo_human($L['swap']['total']) ?> (<span id="sPct"><?= $L['swap']['pct'] ?></span>%)</td></tr>
      <tr><td>Uptime</td><td id="mUp"><?= smpro_lo_dur($L['uptime']) ?></td></tr>
      <tr><td>Processes</td><td id="mProcs"><?= number_format($L['procs']) ?></td></tr>
    </table>
  </div>
</div>

<div class="lo-two">
  <!-- top CPU -->
  <div class="card" id="lo-topcpu" style="padding:0;overflow:hidden">
    <div class="tp-th"><b>Top processes — CPU</b></div>
    <div class="lo-tw"><table class="smpro-table"><thead><tr><th>PID</th><th>User</th><th class="num">CPU%</th><th class="num">MEM%</th><th>Command</th></tr></thead><tbody id="loTopCpu">
      <?php foreach ($L['top_cpu'] as $p): ?><tr><td class="mono"><?= (int)$p['pid'] ?></td><td class="mono"><?= smpro_h($p['user']) ?></td><td class="num"><span class="b <?= $p['cpu']>=50?'red':($p['cpu']>=15?'orange':'gray') ?>"><?= $p['cpu'] ?></span></td><td class="num"><?= $p['mem'] ?></td><td class="mono lo-cmd"><?= smpro_h($p['cmd']) ?></td></tr><?php endforeach; ?>
    </tbody></table></div>
  </div>
  <!-- top MEM -->
  <div class="card" id="lo-topmem" style="padding:0;overflow:hidden">
    <div class="tp-th"><b>Top processes — Memory</b></div>
    <div class="lo-tw"><table class="smpro-table"><thead><tr><th>PID</th><th>User</th><th class="num">MEM%</th><th class="num">CPU%</th><th>Command</th></tr></thead><tbody id="loTopMem">
      <?php foreach ($L['top_mem'] as $p): ?><tr><td class="mono"><?= (int)$p['pid'] ?></td><td class="mono"><?= smpro_h($p['user']) ?></td><td class="num"><span class="b <?= $p['mem']>=20?'red':($p['mem']>=8?'orange':'gray') ?>"><?= $p['mem'] ?></span></td><td class="num"><?= $p['cpu'] ?></td><td class="mono lo-cmd"><?= smpro_h($p['cmd']) ?></td></tr><?php endforeach; ?>
    </tbody></table></div>
  </div>
</div>

<!-- disk -->
<div class="card" id="lo-fs" style="padding:0;overflow:hidden;margin-bottom:14px">
  <div class="tp-th"><b>Filesystems</b><span class="meta">live usage per mount</span></div>
  <div class="lo-tw"><table class="smpro-table"><thead><tr><th>Device</th><th>Mount</th><th class="num">Used</th><th class="num">Total</th><th style="width:170px">Usage</th></tr></thead><tbody id="loFs">
    <?php foreach ($L['fs'] as $f): ?><tr data-mount="<?= smpro_h($f['mount']) ?>"><td class="mono"><?= smpro_h($f['dev']) ?></td><td class="mono"><?= smpro_h($f['mount']) ?></td><td class="num used"><?= smpro_lo_human($f['used']) ?></td><td class="num"><?= smpro_lo_human($f['total']) ?></td><td><div class="lo-bar"><i class="fsb" style="width:<?= (int)$f['pct'] ?>%;background:<?= $f['pct']>=90?'var(--dang)':($f['pct']>=75?'var(--warn)':'var(--good)') ?>"></i></div><span class="fsp meta"><?= (int)$f['pct'] ?>%</span></td></tr><?php endforeach; ?>
  </tbody></table></div>
</div>

<!-- Hardware & Platform — collapsible (merged from the old Hardware page) -->
<?php
$loTemps = [];
foreach (glob('/sys/class/thermal/thermal_zone*/temp') ?: [] as $tf) { $tc = (int)trim((string)@file_get_contents($tf)); if ($tc <= 0) continue; $zd = dirname($tf); $loTemps[] = ['zone'=>trim((string)@file_get_contents($zd.'/type')) ?: basename($zd), 'c'=>round($tc/1000,1)]; }
?>
<details class="lo-fold" id="lo-hw">
  <summary><span class="lo-foldt">&#128421; <span data-i18n>Hardware &amp; Platform</span></span><span class="meta">full system details · click to expand</span><span class="lo-foldchev">&#9656;</span></summary>
  <div class="lo-foldbody">
    <?php if ($loTemps): ?>
    <div class="card" style="padding:0;overflow:hidden;margin-bottom:14px"><div class="tp-th lo-hwth"><b>&#127777; Thermals</b></div>
      <div class="hw-temps"><?php foreach ($loTemps as $t): ?><span class="hw-temp"><?= smpro_h($t['zone']) ?> <b><?= $t['c'] ?>&deg;C</b></span><?php endforeach; ?></div></div>
    <?php endif; ?>
    <div class="lo-two">
      <div class="card" style="padding:0;overflow:hidden">
        <div class="tp-th lo-hwth"><b>&#129518; Processor &amp; Memory</b></div>
        <table class="smpro-table lo-kv">
          <tr><td>CPU model</td><td><b><?= smpro_h($hw['cpu_model']) ?></b></td></tr>
          <tr><td>Topology</td><td><?= smpro_h($hw['sockets']) ?> socket(s) · <?= smpro_h($hw['cores_per_socket']) ?> core/socket · <?= smpro_h($hw['threads_per_core']) ?> thread/core · <b><?= (int)$hw['cpus'] ?></b> logical</td></tr>
          <?php if ($hw['cpu_mhz']): ?><tr><td>Frequency</td><td><?= smpro_h(round((float)$hw['cpu_mhz'])) ?> MHz<?= $hw['cache_l3']?' · L3 '.smpro_h($hw['cache_l3']):'' ?></td></tr><?php endif; ?>
          <tr><td>Architecture</td><td><?= smpro_h($hw['arch']) ?></td></tr>
          <tr><td>Virtualization</td><td><?= smpro_h($hw['virt']) ?></td></tr>
          <tr><td>Total memory</td><td><b><?= smpro_h($hw['mem_total_gb']) ?> GB</b></td></tr>
        </table>
      </div>
      <div class="card" style="padding:0;overflow:hidden">
        <div class="tp-th lo-hwth"><b>&#128421; Platform &amp; Firmware</b></div>
        <table class="smpro-table lo-kv">
          <tr><td>Hostname</td><td><b><?= smpro_h($hw['hostname']) ?></b></td></tr>
          <tr><td>Operating system</td><td><?= smpro_h($hw['os']) ?><?= $hw['distro']?' · '.smpro_h($hw['distro']):'' ?></td></tr>
          <tr><td>Kernel</td><td class="mono"><?= smpro_h($hw['kernel']) ?></td></tr>
          <?php if ($hw['cpanel']): ?><tr><td>cPanel &amp; WHM</td><td><?= smpro_h($hw['cpanel']) ?></td></tr><?php endif; ?>
          <?php if ($hw['sys_vendor']||$hw['product']): ?><tr><td>System</td><td><?= smpro_h(trim($hw['sys_vendor'].' '.$hw['product'])) ?: '—' ?></td></tr><?php endif; ?>
          <?php if ($hw['board']): ?><tr><td>Mainboard</td><td><?= smpro_h($hw['board']) ?></td></tr><?php endif; ?>
          <?php if (trim($hw['bios'],' ()')): ?><tr><td>BIOS</td><td><?= smpro_h($hw['bios']) ?></td></tr><?php endif; ?>
        </table>
      </div>
    </div>
    <div class="lo-two" style="margin-top:14px">
      <div class="card" style="padding:0;overflow:hidden">
        <div class="tp-th lo-hwth"><b>Storage devices</b></div>
        <div class="lo-tw"><table class="smpro-table"><thead><tr><th>Device</th><th>Model</th><th class="num">Size</th><th>Type</th></tr></thead><tbody>
          <?php if (!$hw['disks']): ?><tr><td colspan="4" class="meta" style="padding:14px">No block devices.</td></tr>
          <?php else: foreach ($hw['disks'] as $d): ?><tr><td class="mono"><?= smpro_h($d['name']) ?></td><td><?= smpro_h($d['model']) ?></td><td class="num"><?= smpro_h($d['size']) ?></td><td><span class="b gray"><?= smpro_h($d['type']) ?></span></td></tr><?php endforeach; endif; ?>
        </tbody></table></div>
      </div>
      <div class="card" style="padding:0;overflow:hidden">
        <div class="tp-th lo-hwth"><b>Network interfaces</b></div>
        <div class="lo-tw"><table class="smpro-table"><thead><tr><th>Interface</th><th>State</th><th>IPv4</th></tr></thead><tbody>
          <?php if (!$hw['nics']): ?><tr><td colspan="3" class="meta" style="padding:14px">No interfaces.</td></tr>
          <?php else: foreach ($hw['nics'] as $n): ?><tr><td class="mono"><?= smpro_h($n['name']) ?></td><td><span class="b <?= strtoupper($n['state'])==='UP'?'green':'gray' ?>"><?= smpro_h($n['state']) ?></span></td><td class="mono"><?= smpro_h($n['ip']) ?></td></tr><?php endforeach; endif; ?>
        </tbody></table></div>
      </div>
    </div>
    <p class="meta" style="font-size:11px;margin-top:10px">Hardware facts cached ~1h · collected <?= smpro_h($hw['collected']) ?>.</p>
  </div>
</details>

<style>
.svc-kicker{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--brand);font-weight:800}
.lo-live{font-size:11px;font-weight:800;color:var(--good);vertical-align:middle;margin-left:6px}.lo-live.off{color:var(--muted)}
.lo-pause{font-size:13px;display:flex;align-items:center;gap:6px;font-weight:600;color:var(--muted)}
.pill{display:inline-block;font-size:12px;font-weight:800;padding:4px 12px;border-radius:20px}
.pill.good{background:var(--good-bg);color:var(--good)}.pill.warn{background:var(--warn-bg);color:var(--warn)}.pill.danger{background:var(--dang-bg);color:var(--dang)}.pill.attn{background:var(--brand-bg);color:var(--brand)}
.sv-hero{display:flex;gap:24px;align-items:center;flex-wrap:wrap;border-left:5px solid var(--good);margin:14px 0;padding:18px 20px}
.sv-hero.good{border-left-color:var(--good)}.sv-hero.warn,.sv-hero.attn{border-left-color:var(--warn)}.sv-hero.danger{border-left-color:var(--dang)}
.sv-num{font-size:30px;font-weight:800;fill:var(--ink)}.sv-sub{font-size:12px;fill:var(--muted)}
#svRing{stroke:var(--good)}.sv-hero.warn #svRing,.sv-hero.attn #svRing{stroke:var(--warn)}.sv-hero.danger #svRing{stroke:var(--dang)}
.sv-state{flex:1;min-width:280px}.sv-statelbl{font-size:11px;text-transform:uppercase;color:var(--muted);font-weight:700;letter-spacing:.04em}
.sv-status{display:flex;align-items:center;gap:10px;margin:6px 0}.sv-title{font-size:20px;font-weight:700}
.sv-expl{color:var(--muted);font-size:13px;line-height:1.7;margin:6px 0 0}.sv-expl b{color:var(--ink)}
.lo-kpis{display:grid;grid-template-columns:2fr 1fr 1fr 1fr;gap:14px;margin:14px 0}@media(max-width:820px){.lo-kpis{grid-template-columns:1fr 1fr}.lo-kpi.span2{grid-column:1/-1}}
.lo-kpi{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px;text-align:center}
.lo-kpi.span2{text-align:left}
.lo-kl{font-size:11px;text-transform:uppercase;color:var(--muted);font-weight:700;margin-top:8px}
.lo-load{font-size:22px;font-weight:800;margin:4px 0}.lo-load b{color:var(--ink)}
.lo-v.good{color:var(--good)}.lo-v.elev{color:#f97316}.lo-v.warn{color:var(--warn)}.lo-v.danger{color:var(--dang)}
.lo-vpill{font-size:12px;font-weight:800;padding:2px 9px;border-radius:20px;vertical-align:middle;margin-left:4px}
.lo-vpill.good{background:var(--good-bg);color:var(--good)}.lo-vpill.elev{background:rgba(249,115,22,.15);color:#f97316}.lo-vpill.warn{background:var(--warn-bg);color:var(--warn)}.lo-vpill.danger{background:var(--dang-bg);color:var(--dang)}
.lo-kmeta{font-size:12px;color:var(--muted);margin-top:6px}
.lo-bar{height:8px;border-radius:8px;background:var(--card);overflow:hidden;margin:6px 0}.lo-bar>i{display:block;height:100%;border-radius:8px;background:var(--brand);transition:width .5s}
.lo-bar.sm{height:7px;margin:0}
.lo-gauge{position:relative;width:80px;height:80px;margin:0 auto}.lo-gauge svg{width:80px;height:80px;transform:rotate(-90deg)}
.lo-gauge path{fill:none;stroke-width:3.4;stroke-linecap:round}.lo-gauge .bg{stroke:#eef1f6}.lo-gauge .fg{stroke:var(--brand);stroke-dasharray:0,100;transition:stroke-dasharray .5s,stroke .5s}
.lo-gv{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:12px;color:var(--muted)}.lo-gv b{font-size:19px;color:var(--ink)}
.lo-spark-h{display:flex;align-items:center;gap:10px;margin-bottom:8px}.lo-spark-h .meta{margin-left:auto}
.lo-spark{width:100%;height:80px;background:var(--card);border:1px solid var(--line);border-radius:10px}
.lo-two{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px}@media(max-width:900px){.lo-two{grid-template-columns:1fr}}
.tp-th{display:flex;align-items:center;gap:10px;padding:12px 16px;border-bottom:1px solid var(--line);font-weight:700;font-size:14px}.tp-th .meta{margin-left:auto;color:var(--muted);font-size:12px}
.lo-cores{display:grid;grid-template-columns:1fr 1fr;gap:6px 18px;padding:14px 16px;max-height:320px;overflow:auto}@media(max-width:560px){.lo-cores{grid-template-columns:1fr}}
.lo-core{display:flex;align-items:center;gap:8px;font-size:11px}.lo-cn{width:46px;font-family:ui-monospace,Consolas,monospace;color:var(--muted)}.lo-cp{width:42px;text-align:right;font-weight:700}
.lo-tw{overflow:auto;max-height:340px}.lo-tw thead th{position:sticky;top:0;background:var(--card);z-index:1;box-shadow:inset 0 -1px 0 var(--line)}
.smpro-table{width:100%;border-collapse:collapse;font-size:12.5px}.smpro-table th,.smpro-table td{padding:8px 12px;text-align:left;border-bottom:1px solid var(--line);white-space:nowrap}
.smpro-table th{font-size:11px;text-transform:uppercase;color:var(--muted)}.smpro-table td.num,.smpro-table th.num{text-align:right}
.lo-kv{width:100%;table-layout:fixed}.lo-kv td{word-break:break-word}.lo-kv td:first-child{color:var(--muted);width:140px}
#coolCard>h2.lo-hd,#ovCard>h2.lo-hd{font-size:15px;margin:2px 0 6px}
.fw-kpi.lo-vs .v{font-size:15px;white-space:normal;line-height:1.3}
.lo-cmd{max-width:280px;overflow:hidden;text-overflow:ellipsis}
.lo-hw{display:flex;gap:18px;flex-wrap:wrap;align-items:center;font-size:13px}.lo-hw b{color:var(--muted);font-weight:700}.lo-hwlink{margin-left:auto;color:var(--brand);text-decoration:none;font-weight:600}
.mono{font-family:ui-monospace,Consolas,monospace}.meta{color:var(--muted)}
.b{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:20px}.b.red{background:var(--dang-bg);color:var(--dang)}.b.orange{background:var(--warn-bg);color:var(--warn)}.b.gray{background:var(--card);color:#475569}.b.green{background:var(--good-bg);color:var(--good)}
.lo-fold{border:1px solid var(--line);border-radius:14px;background:var(--card);margin-bottom:14px;overflow:hidden}
.lo-fold>summary{list-style:none;cursor:pointer;display:flex;align-items:center;gap:10px;padding:14px 16px;font-weight:700;font-size:14px;user-select:none}
.lo-fold>summary::-webkit-details-marker{display:none}
.lo-fold>summary .meta{margin-left:auto;font-weight:400}
.lo-foldchev{transition:transform .15s ease;color:var(--muted);font-size:11px;margin-left:6px}
.lo-fold[open]>summary{border-bottom:1px solid var(--line)}.lo-fold[open]>summary .lo-foldchev{transform:rotate(90deg)}
.lo-foldbody{padding:14px 16px}
.hw-temps{display:flex;gap:8px;flex-wrap:wrap;padding:12px 16px}.hw-temp{font-size:12px;background:var(--card);border-radius:20px;padding:5px 11px}
/* ---- overview strip / navigator / collapsible cards (pattern: firewall-status.php) ---- */
/* .fw-kpis / .fw-nav / .fw-collapse / pager styles: shared, in includes/layout.php */
.lo-hd{cursor:pointer}.card.fw-open>.lo-spark-h{margin-bottom:8px}.card>.lo-spark-h.fw-toggle{margin-bottom:0}
.card>h2.lo-hd{padding:0}
@media print{.fw-nav{display:none!important}}
</style>
<script>
(function(){
  function human(b){b=+b||0;var u=['B','KB','MB','GB','TB'],i=0;while(b>=1024&&i<4){b/=1024;i++;}return (i?b.toFixed(1):b)+' '+u[i];}
  function col(p){return p>=90?'var(--dang)':(p>=70?'var(--warn)':'var(--good)');}
  function esc(s){return String(s==null?'':s).replace(/[<>&]/g,function(c){return{'<':'&lt;','>':'&gt;','&':'&amp;'}[c];});}
  function gauge(id,v){var a=document.getElementById(id);if(a){a.style.strokeDasharray=Math.max(0,Math.min(100,v))+',100';a.style.stroke=col(v);}}
  var hist=[],paused=false;var pz=document.getElementById('loPause');if(pz)pz.addEventListener('change',function(){paused=this.checked;var lb=document.getElementById('loLive');if(lb){lb.classList.toggle('off',paused);lb.innerHTML=paused?'&#9679; PAUSED':'&#9679; LIVE';}});
  function rows(tb,arr,cpuFirst){var el=document.getElementById(tb);if(!el)return;el.innerHTML=arr.map(function(p){
    var a=cpuFirst?p.cpu:p.mem,b=cpuFirst?p.mem:p.cpu;var c=cpuFirst?(a>=50?'red':a>=15?'orange':'gray'):(a>=20?'red':a>=8?'orange':'gray');
    return '<tr><td class="mono">'+p.pid+'</td><td class="mono">'+esc(p.user)+'</td><td class="num"><span class="b '+c+'">'+a+'</span></td><td class="num">'+b+'</td><td class="mono lo-cmd">'+esc(p.cmd)+'</td></tr>';}).join('');}
  function lcls(x){return x>30?'danger':(x>25?'warn':(x>10?'elev':'good'));}  // absolute load bands (admin spec)
  function lbar(c){return c==='good'?'var(--good)':(c==='elev'?'#f97316':(c==='warn'?'var(--warn)':'var(--dang)'));}
  function apply(L){
    var lc=lcls(L.load['1m']);
    document.getElementById('loLoad').innerHTML='<b id="loLoadV" class="lo-v '+lc+'">'+L.load['1m']+'</b> / '+L.load['5m']+' / '+L.load['15m']+' <span id="loLoadPct" class="lo-vpill '+lc+'">'+Math.round(L.load.pressure)+'%</span>';
    document.getElementById('loPress').textContent=L.load.pressure;
    var pb=document.getElementById('loPressBar');if(pb){pb.style.width=Math.min(100,L.load.pressure)+'%';pb.style.background=lbar(lc);}
    document.getElementById('loRunning').textContent=L.load.running;
    var vEl=document.getElementById('loVerdict');var v=L.load.pressure>=100?['CRITICAL','danger']:(L.load.pressure>=70?['HIGH','warn']:['HEALTHY','good']);vEl.textContent=v[0];vEl.className='pill '+v[1];
    document.getElementById('kCpu').textContent=L.cpu_pct;gauge('gCpu',L.cpu_pct);
    document.getElementById('kMem').textContent=L.mem.pct;gauge('gMem',L.mem.pct);
    document.getElementById('kSwap').textContent=L.swap.pct;gauge('gSwap',L.swap.pct);
    // mem detail
    var set=function(id,v){var e=document.getElementById(id);if(e)e.textContent=v;};
    set('mTotal',human(L.mem.total));set('mUsed',human(L.mem.used));set('mPct',L.mem.pct);set('mAvail',human(L.mem.avail));
    set('mCached',human(L.mem.cached));set('mBuf',human(L.mem.buffers));set('sUsed',human(L.swap.used));set('sPct',L.swap.pct);set('mProcs',(L.procs||0).toLocaleString());
    // per-core
    var box=document.getElementById('loCores');
    (L.cores||[]).forEach(function(c){var r=box.querySelector('[data-cpu="'+c.cpu+'"]');if(!r){r=document.createElement('div');r.className='lo-core';r.setAttribute('data-cpu',c.cpu);r.innerHTML='<span class="lo-cn">'+c.cpu.toUpperCase()+'</span><div class="lo-bar sm"><i></i></div><span class="lo-cp"></span>';box.appendChild(r);}r.querySelector('i').style.width=c.pct+'%';r.querySelector('i').style.background=col(c.pct);r.querySelector('.lo-cp').textContent=c.pct+'%';});
    rows('loTopCpu',L.top_cpu||[],true);rows('loTopMem',L.top_mem||[],false);
    // fs
    var fb=document.getElementById('loFs');(L.fs||[]).forEach(function(f){var r=fb.querySelector('[data-mount="'+CSS.escape(f.mount)+'"]');if(!r)return;var bar=r.querySelector('.fsb');if(bar){bar.style.width=f.pct+'%';bar.style.background=f.pct>=90?'var(--dang)':(f.pct>=75?'var(--warn)':'var(--good)');}var p=r.querySelector('.fsp');if(p)p.textContent=f.pct+'%';var u=r.querySelector('.used');if(u)u.textContent=human(f.used);});
    // sparkline
    hist.push(L.load['1m']);if(hist.length>60)hist.shift();
    var mx=Math.max(1,Math.max.apply(null,hist));var pts=hist.map(function(v,i){return (i/(Math.max(1,hist.length-1))*600).toFixed(1)+','+(80-(v/mx)*74).toFixed(1);}).join(' ');
    var ln=document.getElementById('loSparkLine');if(ln)ln.setAttribute('points',pts);
    var sn=document.getElementById('loSparkNow');if(sn)sn.textContent='now '+L.load['1m']+' · peak '+mx.toFixed(2);
  }
  // persistent 24h history chart — hist is [[ts, load1], ...] from the server ring
  function drawHist(hist){
    if(!hist||!hist.length){return;}
    var mx=1; hist.forEach(function(p){if(p[1]>mx)mx=p[1];});
    var n=hist.length, pts=hist.map(function(p,i){return (i/Math.max(1,n-1)*600).toFixed(1)+','+(90-(p[1]/mx)*84).toFixed(1);}).join(' ');
    var ln=document.getElementById('loHistLine');if(ln)ln.setAttribute('points',pts);
    var span=(hist[n-1][0]-hist[0][0]); var hrs=Math.round(span/3600);
    var m=document.getElementById('loHistMeta');if(m)m.textContent=n+' samples · '+(hrs>0?hrs+'h':(Math.round(span/60)+' min'));
    var fr=document.getElementById('loHistFrom');if(fr)fr.textContent='-'+(hrs>0?hrs+'h':Math.max(1,Math.round(span/60))+' min');
    var pk=document.getElementById('loHistPeak');if(pk)pk.textContent='peak '+mx.toFixed(2);
  }
  apply(<?= json_encode($L, JSON_UNESCAPED_SLASHES|JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT|JSON_INVALID_UTF8_SUBSTITUTE) ?>);   /* HEX flags: top_cpu/top_mem cmd+user from ps are attacker-influenced */
  drawHist(<?= json_encode(smpro_lo_hist_read(), JSON_UNESCAPED_SLASHES|JSON_INVALID_UTF8_SUBSTITUTE) ?>);   // seed 24h chart from the server ring
  function tick(){if(paused)return;fetch('index.cgi?page=load-monitor&live=1',{cache:'no-store'}).then(function(r){return r.json();}).then(function(j){if(j&&j.ok){apply(j.live);drawHist(j.hist);if(j.health&&window.loApplyHealth)window.loApplyHealth(j.health);}}).catch(function(){});}
  setInterval(tick,3000);
})();
</script>
<script>
/* Server Health score — live (polls the shared serverhealth snapshot) */
(function(){var R=2*Math.PI*52,ring=document.getElementById('svRing');if(!ring)return;
  function apply(d){if(!d)return;var s=document.getElementById('svScore');if(s)s.textContent=d.score;ring.style.strokeDashoffset=R*(1-d.score/100);
    var st=document.getElementById('svStatus');if(st){st.textContent=d.status;st.className='pill '+d.cls;}
    var ti=document.getElementById('svTitle');if(ti)ti.textContent=d.status_title;
    var hero=document.querySelector('.sv-hero');if(hero)hero.className='card sv-hero '+d.cls;
    var ex=document.getElementById('svExpl');if(ex&&d.load)ex.innerHTML=d.cause+' 1m <b>'+d.load['1m'].v+'</b>, 5m <b>'+d.load['5m'].v+'</b>, 15m <b>'+d.load['15m'].v+'</b> on '+d.cores+' cores. Effective pressure: <b>'+d.eff+'%</b>.';}
  window.loApplyHealth=apply;   /* fed by the page's single live poller (beta363) - no second 3-second poll */
})();
</script>

<?php $coolCsrf = smpro_csrf_generate('cooler'); $coolSt = smpro_cool_status(); ?>
<div class="card" id="coolCard" style="margin-top:18px">
  <div class="svc-kicker">Load control</div>
  <h2 class="h lo-hd" style="margin:2px 0 4px"><b>&#10052;&#65039; Cooler mode</b></h2>
  <p class="sub">When something spikes the load, cool it down without killing it: the offending process is dropped to lowest CPU/IO priority<span id="coolCap"></span> for a chosen time, then automatically restored. Fully reversible.</p>
  <div style="background:#0f2a1c;border:1px solid #1f7a4d;color:#a7f3d0;border-radius:10px;padding:9px 12px;font-size:12px;margin:0 0 10px">
    &#128737; <b>Safe by design:</b> web server, database, mail, DNS, FTP, SSH, firewall &amp; cPanel services are <b>never throttled</b> (shown as &#128274; protected). It only lowers the priority of isolated runaway processes — it never kills a process, never stops a service, and never suspends a customer account.
  </div>

  <div id="coolStatus" class="meta" style="margin:8px 0;min-height:20px"></div>

  <?php $capM = $coolSt['cap'] ?? (!empty($coolSt['cpulimit']) ? 'cpulimit' : 'none'); if ($capM !== 'cpulimit'): ?>
  <div style="<?= $capM === 'builtin' ? 'background:#0b2536;border:1px solid #0e7490;color:#a5f3fc' : 'background:#3a2a0a;border:1px solid #a16207;color:#fde68a' ?>;border-radius:10px;padding:9px 12px;font-size:12px;margin:0 0 10px">
    <?php if ($capM === 'builtin'): ?>
      &#8505;&#65039; <b>CPU cap is active via built-in throttling</b> &mdash; no <code>cpulimit</code> needed. The Cooler and Auto&nbsp;Load&nbsp;Guard cut the load by pausing runaway processes in short duty cycles (fully reversible). For lower overhead you can install the native <code>cpulimit</code>:
    <?php else: ?>
      &#9888;&#65039; <b>CPU cap unavailable.</b> Install <code>cpulimit</code> to enable a hard CPU cap:
    <?php endif; ?>
    <button type="button" class="btn" id="cpulimitInstall" data-csrf="<?= smpro_h(smpro_csrf_generate('pkg')) ?>" style="margin-top:6px;background:#16a34a;color:#fff">&#11015;&#65039; Install cpulimit</button>
    <span id="cpulimitMsg" style="margin-left:8px"></span>
  </div>
  <?php endif; ?>

  <div id="coolPick">
    <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:10px">
      <label style="font-size:12.5px;color:#94a3b8">Duration
        <select id="coolMin" style="margin-left:4px">
          <option value="10">10 min</option><option value="15" selected>15 min</option><option value="30">30 min</option><option value="60">1 hour</option><option value="120">2 hours</option>
        </select>
      </label>
      <label style="font-size:12.5px;color:#94a3b8">CPU cap
        <select id="coolPct" style="margin-left:4px">
          <option value="10">10%</option><option value="20">20%</option><option value="30">30%</option><option value="40">40%</option><option value="50" selected>50%</option>
        </select>
      </label>
      <button type="button" class="btn" id="coolAuto" style="background:#0ea5e9;color:#fff">&#10052;&#65039; Cool the top hog</button>
      <button type="button" class="btn" id="coolRefresh">&#8635; Refresh sources</button>
      <button type="button" class="btn" id="coolStop" style="background:#b91c1c;color:#fff;display:none">&#9632; Stop cooling</button>
    </div>
    <table class="tbl" id="coolTbl" style="width:100%;font-size:13px"><thead><tr>
      <th style="width:28px"></th><th>PID</th><th>%CPU</th><th>%MEM</th><th>User</th><th>Command</th></tr></thead><tbody></tbody></table>
    <button type="button" class="btn" id="coolStart" style="margin-top:10px;background:#16a34a;color:#fff;display:none">&#10052;&#65039; Cool selected</button>
  </div>

  <div style="border-top:1px solid rgba(148,163,184,.25);margin-top:16px;padding-top:14px">
    <label class="sw" style="display:inline-flex;margin-bottom:8px">
      <input type="checkbox" id="grdEnabled" <?= !empty($coolSt['guard']['enabled']) ? 'checked' : '' ?>>
      <span class="track"></span><span class="lbl" style="font-weight:700">Auto load guard — keep the load under a ceiling</span><span class="st"></span>
    </label>
    <p class="sub" style="margin:0 0 10px">When the 1-minute load reaches the ceiling, the top CPU process(es) are automatically cooled for the set time, then restored. Runs every minute in the background.</p>
    <div style="display:flex;gap:14px;flex-wrap:wrap;align-items:flex-end;font-size:12.5px">
      <label style="color:#94a3b8">Load ceiling<br><input type="number" id="grdCeiling" min="1" max="2048" step="0.5" value="<?= (float)($coolSt['guard']['ceiling'] ?? 20) ?>" style="width:90px;margin-top:3px"></label>
      <label style="color:#94a3b8">Cool top N<br><input type="number" id="grdTopk" min="1" max="50" value="<?= (int)($coolSt['guard']['topk'] ?? 3) ?>" style="width:70px;margin-top:3px"></label>
      <label style="color:#94a3b8">Only if &ge; %CPU<br><input type="number" id="grdMinCpu" min="1" max="100" value="<?= (int)($coolSt['guard']['min_cpu'] ?? 25) ?>" style="width:80px;margin-top:3px"></label>
      <label style="color:#94a3b8">CPU cap %<br><select id="grdPct" style="width:90px;margin-top:3px"><?php $gp=(int)($coolSt['guard']['percent'] ?? 50); foreach([10,20,30,40,50] as $o) echo '<option value="'.$o.'"'.($gp==$o?' selected':'').'>'.$o.'%</option>'; ?></select></label>
      <label style="color:#94a3b8">Duration (min)<br><input type="number" id="grdMin" min="1" max="720" value="<?= (int)($coolSt['guard']['minutes'] ?? 15) ?>" style="width:90px;margin-top:3px"></label>
      <button type="button" class="btn" id="grdSave" style="background:#0f2657;color:#fff">Save guard</button>
    </div>
    <div id="grdMsg" class="meta" style="margin-top:8px;min-height:16px"></div>
  </div>
</div>
<script>(function(){
  var CSRF=<?= json_encode($coolCsrf) ?>, hasCpulimit=<?= $coolSt['cpulimit'] ? 'true':'false' ?>, capMethod=<?= json_encode($coolSt['cap'] ?? ($coolSt['cpulimit']?'cpulimit':'none')) ?>;
  function P(i){return document.getElementById(i);}
  (function(){var cli=P('cpulimitInstall');if(!cli)return;cli.addEventListener('click',function(){
    var m=P('cpulimitMsg');cli.disabled=true;cli.textContent='Installing...';if(m){m.style.color='';m.textContent='';}
    var fd=new URLSearchParams();fd.set('smpro_csrf',cli.getAttribute('data-csrf'));fd.set('tool','cpulimit');
    fetch('index.cgi?pkg=1',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'}).then(function(r){return r.json();}).then(function(j){
      if(j&&j.ok){cli.innerHTML='&#10003; Installed';if(m){m.style.color='#22c55e';m.textContent=(j.msg||'Installed')+' - reloading...';}setTimeout(function(){location.reload();},1200);}
      else{cli.disabled=false;cli.innerHTML='&#11015;&#65039; Install cpulimit';if(m){m.style.color='#f87171';m.textContent=(j&&j.msg)||'Install failed.';}}
    }).catch(function(){cli.disabled=false;cli.innerHTML='&#11015;&#65039; Install cpulimit';if(m){m.style.color='#f87171';m.textContent='Request failed.';}});
  });})();
  function post(action,extra){var fd=new URLSearchParams();fd.set('smpro_csrf',CSRF);fd.set('cool_action',action);
    if(extra)Object.keys(extra).forEach(function(k){fd.set(k,extra[k]);});
    return fetch('index.cgi?cooler=1',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'}).then(function(r){return r.json();});}
  function st(t,c){var m=P('coolStatus');m.innerHTML=t;m.style.color=c||'';}
  P('coolCap').textContent = (capMethod!=='none') ? ' (or a hard CPU % cap)' : '';

  function renderStatus(s){
    var g=(s&&s.guard)||{}, gtxt=g.enabled?(' · 🌡 Guard ON (ceiling '+g.ceiling+(s&&s.load1!=null?', load now '+s.load1:'')+')'):'';
    if(s&&s.active){
      var names=(s.targets||[]).map(function(t){return String(t.comm==null?'':t.comm).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];})+' ('+t.pid+')';}).join(', ');   /* escape ps comm before innerHTML */
      st('&#10052;&#65039; <b>Cooling active</b> — '+names+' · '+(s.percent>0&&s.cap&&s.cap!=='none'?('cap '+s.percent+'%'+(s.cap==='builtin'?' (built-in)':'')+' · '):'low-priority · ')+Math.ceil(s.remaining/60)+' min left.'+gtxt,'#0ea5e9');
      P('coolStop').style.display='';P('coolPick').style.opacity='.5';
    } else { st('Idle — nothing is being throttled.'+gtxt,'#64748b'); P('coolStop').style.display='none';P('coolPick').style.opacity='1'; }
  }
  function loadSources(){
    fetch('index.cgi?cooler=1&cool_action=sources',{cache:'no-store'}).then(function(r){return r.json();}).then(function(j){
      if(!j||!j.ok)return;var tb=P('coolTbl').querySelector('tbody');tb.innerHTML='';
      (j.procs||[]).forEach(function(p){var tr=document.createElement('tr');
        var chk=p.protected?'<span title="Critical service — never throttled" style="color:#16a34a">&#128274;</span>':'<input type="checkbox" class="coolChk" value="'+p.pid+'">';
        var tag=p.protected?' <span style="font-size:10px;color:#16a34a;font-weight:700">service · protected</span>'
               :(p.site_engine?' <span style="font-size:10px;color:#b45309;font-weight:700" title="A customer site’s PHP — auto-guard never touches it; throttle manually only if it is clearly stuck">site PHP</span>':'');
        var name=(''+p.comm).replace(/[<>]/g,'')+tag;
        tr.innerHTML='<td>'+chk+'</td><td>'+p.pid+'</td><td>'+p.cpu.toFixed(1)+'</td><td>'+p.mem.toFixed(1)+'</td><td>'+(''+p.user).replace(/[<>]/g,'')+'</td><td>'+name+'</td>';
        if(p.protected)tr.style.opacity='.6';
        tb.appendChild(tr);});
      P('coolStart').style.display=(j.procs&&j.procs.length)?'':'none';
    }).catch(function(){});
  }
  function refresh(){post('status').then(renderStatus).catch(function(){});}

  P('coolRefresh').addEventListener('click',loadSources);
  P('coolStart').addEventListener('click',function(){
    var pids=[].slice.call(document.querySelectorAll('.coolChk:checked')).map(function(c){return c.value;});
    if(!pids.length){st('Select at least one process first.','#b45309');return;}
    this.disabled=true;var b=this;post('start',{pids:pids.join(','),percent:P('coolPct').value,minutes:P('coolMin').value}).then(function(j){b.disabled=false;
      st((j&&j.ok?'&#10003; ':'&#10007; ')+((j&&j.msg)||''),j&&j.ok?'#047857':'#b91c1c');refresh();}).catch(function(){b.disabled=false;});});
  P('coolAuto').addEventListener('click',function(){this.disabled=true;var b=this;
    post('auto',{percent:P('coolPct').value,minutes:P('coolMin').value}).then(function(j){b.disabled=false;
      st((j&&j.ok?'&#10003; ':'&#10007; ')+((j&&j.msg)||''),j&&j.ok?'#047857':'#b91c1c');refresh();}).catch(function(){b.disabled=false;});});
  P('coolStop').addEventListener('click',function(){post('stop').then(function(j){st((j&&j.msg)||'stopped','#475569');refresh();}).catch(function(){});});
  P('grdSave').addEventListener('click',function(){var b=this;b.disabled=true;var m=P('grdMsg');
    var fd=new URLSearchParams();fd.set('smpro_csrf',CSRF);fd.set('cool_action','guard');
    fd.set('enabled',P('grdEnabled').checked?'1':'');fd.set('ceiling',P('grdCeiling').value);fd.set('topk',P('grdTopk').value);
    fd.set('min_cpu',P('grdMinCpu').value);fd.set('percent',P('grdPct').value);fd.set('minutes',P('grdMin').value);
    fetch('index.cgi?cooler=1',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'})
      .then(function(r){return r.text().then(function(t){return {st:r.status,t:t};});})
      .then(function(o){b.disabled=false;var j=null;try{j=JSON.parse(o.t);}catch(e){}
        if(j&&j.ok){m.innerHTML='&#10003; Guard '+(j.guard.enabled?('enabled — load kept under '+j.guard.ceiling):'disabled')+'.';m.style.color='#047857';refresh();}
        else{m.innerHTML='&#10007; HTTP '+o.st+' — '+((j&&(j.error||j.message||j.msg))||(o.t||'empty').slice(0,220));m.style.color='#b91c1c';}
      }).catch(function(e){b.disabled=false;m.innerHTML='&#10007; network: '+e;m.style.color='#b91c1c';});});

  renderStatus(<?= json_encode($coolSt, JSON_UNESCAPED_SLASHES|JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT|JSON_INVALID_UTF8_SUBSTITUTE) ?>);loadSources();setInterval(refresh,5000);   /* HEX flags: cooled targets[].comm from ps */
  /* folding is the shared card engine below (fw-toggle); the page's own fold script was removed in beta363 - it
     doubled every header's chevron and fought the shared one for the same cards */
})();</script>

<!-- ===== Overload Investigator ===== -->
<div class="card" id="ovCard" style="margin-top:18px">
  <div class="svc-kicker">Load control</div>
  <h2 class="h lo-hd" style="margin:2px 0 4px"><b>&#128269; Overload Investigator</b></h2>
  <p class="sub">Finds the real reason the load is high &mdash; including a per-user <b>swarm</b> of many small processes that per-process checks miss &mdash; and checks I/O-wait &amp; memory, not just CPU. Then it proposes concrete, ordered fixes you can apply.</p>
  <div style="display:flex;gap:8px;flex-wrap:wrap;margin:10px 0">
    <button class="btn" id="ovInv" type="button" style="background:var(--brand);color:#fff;border-color:var(--brand)">&#128269; Investigate the overload</button>
    <button class="btn" id="ovAi" type="button">&#129302; AI diagnosis</button>
    <button class="btn" id="ovPlan" type="button">&#9881;&#65039; Auto-handling plan</button>
    <button class="btn" id="ovRep" type="button">&#128202; Overload report</button>
  </div>
  <div id="ovOut" style="margin-top:10px;min-height:18px;color:var(--muted);font-size:13px">Click <b>Investigate the overload</b> to see what is driving the load right now.</div>
</div>
<script>(function(){
  var OVCSRF=<?= json_encode($coolCsrf) ?>;
  var O=document.getElementById('ovOut');
  if(!O)return;
  function esc(s){var d=document.createElement('div');d.textContent=(s==null?'':(''+s));return d.innerHTML;}
  function sev(s){return s==='do'?'var(--good)':(s==='fix'?'var(--brand)':'var(--muted)');}
  function busy(t){O.innerHTML='<span style="color:var(--muted)">'+esc(t)+'&hellip;</span>';}
  function err(t){O.innerHTML='<span style="color:var(--dang)">&#9888;&#65039; '+esc(t)+'</span>';}
  function h4(t){return '<div style="font-weight:700;color:var(--ink);margin:10px 0 4px">'+t+'</div>';}
  function getj(a){return fetch('index.cgi?cooler=1&cool_action='+a,{cache:'no-store',credentials:'same-origin'}).then(function(r){if(!r.ok)throw new Error('HTTP '+r.status);return r.json();});}
  function postj(a,ex){var fd=new URLSearchParams();fd.set('smpro_csrf',OVCSRF);fd.set('cool_action',a);if(ex)for(var k in ex)fd.set(k,ex[k]);
    return fetch('index.cgi?cooler=1',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store',credentials:'same-origin'}).then(function(r){if(!r.ok)throw new Error('HTTP '+r.status);return r.json();});}
  function apply(a,btn){
    if(!a)return;
    var conf,ex,act;
    if(a.type==='cool_user'){conf='Throttle ALL of "'+a.user+'" '+(a.comm||'')+' processes to a CPU cap (reversible)?';ex={user:a.user,comm:a.comm||'',percent:a.percent||20,minutes:a.minutes||15};act='cooluser';}
    else if(a.type==='cool_pid'){conf='Throttle PID '+a.pid+' to a CPU cap (reversible)?';ex={pids:a.pid,percent:a.percent||30,minutes:a.minutes||15};act='start';}
    else if(a.type==='link'){location.href='index.cgi?page='+encodeURIComponent(a.page||'reports-center');return;}
    else return;
    if(!confirm(conf))return;
    btn.disabled=true;var ot=btn.innerHTML;btn.innerHTML='&hellip;';
    postj(act,ex).then(function(j){alert((j&&j.ok?'✅ ':'⚠ ')+((j&&(j.msg||('Cooled '+(j.cooled||0)+' process(es).')))||'done'));btn.innerHTML=j&&j.ok?'&#10003; done':ot;btn.disabled=!(j&&j.ok);}).catch(function(e){btn.innerHTML=ot;btn.disabled=false;alert('Request failed: '+((e&&e.message)||e));});
  }
  function wireApply(cls,arr){Array.prototype.forEach.call(O.querySelectorAll(cls),function(b){b.addEventListener('click',function(){apply(arr[+b.getAttribute('data-i')],b);});});}
  function on(id,fn){var b=document.getElementById(id);if(b)b.addEventListener('click',fn);}

  on('ovInv',function(){busy('Investigating');getj('investigate').then(function(j){
    if(!j||!j.ok){err('Investigation failed.');return;}
    var ev=j.ev||{},d=j.diag||{},cpu=ev.cpu||{},mem=ev.mem||{},html='';
    var ok=(d.status==='healthy'),pbg=ok?'var(--good-bg)':'var(--warn-bg)',pbd=ok?'var(--good)':'var(--warn)',plbl=ok?'&#9989; Healthy &mdash; no overload':'&#9888;&#65039; Primary cause';
    html+='<div style="background:'+pbg+';border:1px solid '+pbd+';border-radius:10px;padding:10px 12px;margin-bottom:10px">'
      +'<b style="color:var(--ink)">'+plbl+'</b><br><span style="color:var(--ink)">'+esc(d.primary)+'</span>'
      +'<div style="margin-top:6px;font-size:12px;color:var(--muted)">load '+esc(d.load)+' on '+esc(d.cores)+' cores ('+esc(d.pct)+'% of capacity) &middot; CPU us '+esc(cpu.us)+'% sy '+esc(cpu.sy)+'% iowait '+esc(cpu.wa)+'% &middot; RAM '+esc(mem.used_pct)+'% swap '+esc(mem.swap_used_pct)+'%</div></div>';
    if(ev.swarms&&ev.swarms.length){html+=h4('&#9888;&#65039; Process swarms (many small processes from one account)')
      +'<table class="tbl" style="width:100%;max-width:760px"><thead><tr><th>User</th><th>Process</th><th>Count</th><th>Total&nbsp;%CPU</th></tr></thead><tbody>';
      ev.swarms.forEach(function(s){html+='<tr><td>'+esc(s.user)+'</td><td class="mono">'+esc(s.comm)+(s.wp_cron?' <span style="color:var(--warn)">(wp-cron)</span>':'')+'</td><td>'+esc(s.count)+'</td><td><b>'+esc(s.cpu)+'</b></td></tr>';});
      html+='</tbody></table>';}
    if(ev.top_users&&ev.top_users.length){html+=h4('Top users by TOTAL CPU (aggregate across all their processes)')
      +'<table class="tbl" style="width:100%;max-width:760px"><thead><tr><th>User</th><th>Total&nbsp;%CPU</th><th>Procs</th><th>Mostly</th></tr></thead><tbody>';
      ev.top_users.slice(0,6).forEach(function(u){html+='<tr><td>'+esc(u.user)+'</td><td>'+esc(u.cpu)+'</td><td>'+esc(u.procs)+'</td><td class="mono">'+esc(u.top_comm)+'</td></tr>';});
      html+='</tbody></table>';}
    if(d.suggestions&&d.suggestions.length){html+=h4('&#128161; Suggested solutions');
      d.suggestions.forEach(function(s,i){var isLink=s.action&&s.action.type==='link',canApply=s.action&&(s.action.type==='cool_user'||s.action.type==='cool_pid');
        html+='<div style="border:1px solid var(--line);border-radius:8px;padding:8px 10px;margin-bottom:6px">'
          +'<div style="display:flex;justify-content:space-between;align-items:center;gap:8px"><b style="color:'+sev(s.sev)+'">'+esc(s.title)+'</b>'
          +((canApply||isLink)?'<button class="btn ovA" type="button" data-i="'+i+'" style="font-size:11px;padding:3px 10px;white-space:nowrap;'+(canApply?'background:var(--good);color:#fff;border-color:var(--good)':'')+'">'+(isLink?'Open':'Apply')+'</button>':'')+'</div>'
          +'<div style="color:var(--muted);font-size:12px;margin-top:3px">'+esc(s.why)+'</div>'
          +'<div style="color:var(--ink);font-size:12px;margin-top:2px">&#8594; '+esc(s.how)+'</div></div>';});}
    O.innerHTML=html;wireApply('.ovA',d.suggestions||[]);
  }).catch(function(e){err('Request failed: '+((e&&e.message)||e));});});

  on('ovAi',function(){busy('Asking the AI to diagnose the load');postj('aidiagnose').then(function(j){
    if(!j||!j.ok){err((j&&j.error)||'AI diagnosis failed.');return;}
    O.innerHTML='<div style="font-size:12px;color:var(--muted);margin-bottom:6px">&#129302; '+esc(j.provider)+' &middot; '+esc(j.model)+'</div><div style="white-space:pre-wrap;color:var(--ink);font-size:13px;line-height:1.6">'+esc(j.text)+'</div>';
  }).catch(function(e){err('Request failed: '+((e&&e.message)||e));});});

  on('ovPlan',function(){busy('Building an automatic-handling plan');getj('autoplan').then(function(j){
    if(!j||!j.ok){err('Plan failed.');return;}
    var html=h4('&#9881;&#65039; Recommended handling')+'<div style="color:var(--muted);font-size:12px;margin-bottom:8px">'+esc(j.summary)+'</div>';
    (j.steps||[]).forEach(function(s,i){var canApply=s.action&&(s.action.type==='cool_user'||s.action.type==='cool_pid');
      html+='<div style="border-left:3px solid var(--brand);padding:6px 10px;margin-bottom:6px;background:var(--brand-bg);border-radius:0 8px 8px 0">'
        +'<div style="display:flex;justify-content:space-between;align-items:center;gap:8px"><b style="color:var(--ink)">'+esc(s.n)+'. '+esc(s.title)+'</b>'
        +(canApply?'<button class="btn ovS" type="button" data-i="'+i+'" style="font-size:11px;padding:3px 10px;white-space:nowrap;background:var(--good);color:#fff;border-color:var(--good)">Apply step</button>':'')+'</div>'
        +'<div style="color:var(--ink);font-size:12px;margin-top:2px">'+esc(s.detail)+'</div></div>';});
    O.innerHTML=html;var st=j.steps||[];Array.prototype.forEach.call(O.querySelectorAll('.ovS'),function(b){b.addEventListener('click',function(){apply(st[+b.getAttribute('data-i')].action,b);});});
  }).catch(function(e){err('Request failed: '+((e&&e.message)||e));});});

  on('ovRep',function(){busy('Loading the overload report');getj('report').then(function(j){
    if(!j||!j.ok){err('Report failed.');return;}
    if(!j.rows||!j.rows.length){O.innerHTML='<span style="color:var(--muted)">No overload episodes recorded yet. Episodes are logged automatically while the Auto Load Guard is enabled.</span>';return;}
    var html=h4('&#128202; Overload episodes (most recent first)')+'<table class="tbl" style="width:100%;max-width:760px"><thead><tr><th>When</th><th>Load</th><th>Top user</th><th>Likely cause</th></tr></thead><tbody>';
    j.rows.slice(0,50).forEach(function(r){var dt=new Date((r.ts||0)*1000);html+='<tr><td style="white-space:nowrap">'+esc(dt.toLocaleString())+'</td><td>'+esc(r.load)+'</td><td>'+esc(r.top_user||'&#8212;')+'</td><td style="color:var(--muted)">'+esc(r.cause)+'</td></tr>';});
    html+='</tbody></table>';O.innerHTML=html;
  }).catch(function(e){err('Request failed: '+((e&&e.message)||e));});});
})();</script>
<script>
(function(){
  /* collapsible section cards + sticky navigator (pattern: modules/firewall-status.php). The header of every
     card is a real toggle (role=button, keyboard), the open/closed choice is remembered per section. */
  var KEY='smpro:load-monitor:open', HSEL='.smpro-main .card > .tp-th:not(.lo-hwth), .smpro-main .card > .lo-hd', PFX='lo', open={};
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
    var hwd=document.getElementById('lo-hw');
    if(hwd){ var hg=document.querySelectorAll('[data-go="lo-hw"]'); for(var k=0;k<hg.length;k++){ hg[k].addEventListener('click',function(){ hwd.open=true; }); } }
  }
  window[PFX+'OpenCard']=openCard;
  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',init); else init();
})();
</script>
<?php
smpro_layout_footer();
