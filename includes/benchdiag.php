<?php
/**
 * includes/benchdiag.php - Benchmark & Diagnostics hub engine.
 *
 * Extends the hardware benchmark (includes/benchmark.php, smpro_bm_*) into a full
 * benchmark + troubleshooting suite that is portable to ANY server:
 *
 *   BENCHMARK  hardware (CPU/RAM/disk, reused from benchmark.php) + software/PHP
 *              (integer, hash and array throughput) + MySQL (connect latency,
 *              CPU-bound query throughput, InnoDB insert rate on a TEMPORARY table).
 *   DIAGNOSE   kernel (key sysctl values vs recommended, plus a dmesg scan for OOM
 *              kills, hung tasks, disk/filesystem errors, segfaults, conntrack/TCP
 *              exhaustion) and software/PHP (EA-PHP versions, OPcache, limits).
 *   REPORTS    every completed run is appended to a bounded history so you can
 *              compare this run against previous ones.
 *
 * Gather is read-only and time-bounded. The only writes are explicit, POST+CSRF+root
 * gated, reversible sysctl tunables (live `sysctl -w` + a persisted drop-in we own),
 * each with the previous value recorded so there is a real one-click Undo.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

if (!defined('SMPRO_BD_STATE'))   define('SMPRO_BD_STATE',   SMPRO_VARLIB . '/benchdiag_state.json');
if (!defined('SMPRO_BD_HISTORY')) define('SMPRO_BD_HISTORY', SMPRO_VARLIB . '/benchdiag_history.json');
if (!defined('SMPRO_BD_PREV'))    define('SMPRO_BD_PREV',    SMPRO_VARLIB . '/benchdiag_prev.json');
if (!defined('SMPRO_BD_SYSCTL'))  define('SMPRO_BD_SYSCTL',  '/etc/sysctl.d/99-smpro.conf');

function smpro_bd_sh($cmd, $t = 10) { return smpro_run((string)$cmd, (int)$t, ['stderr' => 'discard']); }
function smpro_bd_has($bin) { return trim((string)@shell_exec('command -v ' . escapeshellarg($bin) . ' 2>/dev/null')) !== ''; }

/* ---------------- run state (shared by the detached worker + the page poll) ---------------- */
function smpro_bd_state() {
    $d = @is_file(SMPRO_BD_STATE) ? json_decode((string)@file_get_contents(SMPRO_BD_STATE), true) : null;
    return is_array($d) ? $d : ['status' => 'idle'];
}
function smpro_bd_state_write($s) {
    $f = SMPRO_BD_STATE; @is_dir(dirname($f)) || @mkdir(dirname($f), 0700, true);
    $t = $f . '.tmp';
    if (@file_put_contents($t, json_encode($s, JSON_UNESCAPED_SLASHES), LOCK_EX) !== false) { @chmod($t, 0600); @rename($t, $f); }
}

/* ---------------- run history / reports ---------------- */
function smpro_bd_history() {
    $d = @is_file(SMPRO_BD_HISTORY) ? json_decode((string)@file_get_contents(SMPRO_BD_HISTORY), true) : null;
    return is_array($d) ? $d : [];
}
function smpro_bd_history_add(array $run, $keep = 20) {
    $h = smpro_bd_history();
    array_unshift($h, $run);
    if (count($h) > $keep) $h = array_slice($h, 0, $keep);
    $f = SMPRO_BD_HISTORY; @is_dir(dirname($f)) || @mkdir(dirname($f), 0700, true);
    $t = $f . '.tmp';
    if (@file_put_contents($t, json_encode($h, JSON_UNESCAPED_SLASHES), LOCK_EX) !== false) { @chmod($t, 0600); @rename($t, $f); }
}

/* ---------------- SOFTWARE / PHP benchmark (pure PHP, bounded ~2-4s) ---------------- */
function smpro_bd_php_bench() {
    $r = ['php_version' => PHP_VERSION];
    $t0 = microtime(true); $x = 0; for ($i = 0; $i < 3000000; $i++) { $x += $i % 7; }
    $r['int_ops_sec'] = (int)round(3000000 / max(0.001, microtime(true) - $t0));
    $t0 = microtime(true); for ($i = 0; $i < 200000; $i++) { $h = md5((string)$i); }
    $r['hash_ops_sec'] = (int)round(200000 / max(0.001, microtime(true) - $t0));
    $t0 = microtime(true); $a = []; for ($i = 0; $i < 300000; $i++) { $a[] = ($i * 7919) % 300000; } sort($a);
    $r['array_ops_sec'] = (int)round(300000 / max(0.001, microtime(true) - $t0));
    unset($a);
    return $r;
}

/* ---------------- MySQL benchmark (uses the dbhealth root access; TEMPORARY table only) ---------------- */
function smpro_bd_mysql_bench() {
    if (!function_exists('smpro_dbh_available') || !smpro_dbh_available()) return ['err' => 'No local MySQL/MariaDB reachable'];
    // 1) connect + round-trip latency (average of 5)
    $n = 5; $t0 = microtime(true);
    for ($i = 0; $i < $n; $i++) smpro_dbh_q('SELECT 1', 6);
    $connMs = round((microtime(true) - $t0) / $n * 1000, 1);
    // 2) CPU-bound query throughput via MySQL's own BENCHMARK()
    $iter = 2000000; $t0 = microtime(true);
    smpro_dbh_q("SELECT BENCHMARK($iter, MD5('smpro'))", 40);
    $el = microtime(true) - $t0;
    $qops = $el > 0.01 ? (int)round($iter / $el) : null;
    // 3) InnoDB write rate - TEMPORARY table (session-scoped, auto-dropped; no schema left behind)
    // `mysql -e` starts with NO default schema, so a bare CREATE TEMPORARY TABLE fails with "No database
    // selected" - give it a schema context. The table is TEMPORARY: session-private, never persisted into
    // that schema, and dropped automatically when this one-shot client connection ends.
    $rows = 2000; $batch = implode(',', array_fill(0, 100, "('smpro-bench-row')"));
    $sql = "USE mysql; CREATE TEMPORARY TABLE smpro_bench_tmp (id INT PRIMARY KEY AUTO_INCREMENT, v VARCHAR(64)) ENGINE=InnoDB;";
    for ($i = 0; $i < (int)($rows / 100); $i++) $sql .= "INSERT INTO smpro_bench_tmp (v) VALUES $batch;";
    $sql .= "SELECT COUNT(*) FROM smpro_bench_tmp;";
    $t0 = microtime(true); $out = smpro_dbh_q($sql, 40); $wel = microtime(true) - $t0;
    $lines = array_values(array_filter(array_map('trim', explode("\n", $out)), function ($x) { return $x !== ''; }));
    $cnt = $lines ? (int)end($lines) : 0;
    $ins = ($cnt === $rows && $wel > 0.001) ? (int)round($rows / $wel) : null;
    return ['connect_ms' => $connMs, 'query_ops_sec' => $qops, 'insert_rows_sec' => $ins, 'rows' => $rows];
}

/* ---------------- the full suite (worker body) ---------------- */
function smpro_bd_run_all($mount = '') {
    @ignore_user_abort(true); @set_time_limit(600);
    $started = (int)(smpro_bd_state()['started'] ?? time());
    $res = [];
    $step = function ($name, $pct) use ($started, &$res, $mount) {
        smpro_bd_state_write(['status' => 'running', 'step' => $name, 'pct' => $pct, 'started' => $started, 'mount' => $mount, 'results' => $res]);
    };
    $step('cpu', 8);
    if (function_exists('smpro_bm_cpu')) $res['cpu'] = smpro_bm_cpu();
    $step('ram', 28);
    if (function_exists('smpro_bm_ram')) $res['ram'] = smpro_bm_ram();
    $step('disk', 45);
    if (function_exists('smpro_bm_disk')) {
        $m = $mount !== '' ? $mount : (function_exists('smpro_bm_disk_mount') ? smpro_bm_disk_mount() : '/');
        $res['disk'] = smpro_bm_disk($m);
    }
    $step('php', 76);
    $res['php'] = smpro_bd_php_bench();
    $step('mysql', 88);
    $res['mysql'] = smpro_bd_mysql_bench();

    $inv = function_exists('smpro_bm_inventory') ? smpro_bm_inventory(true) : [];
    $run = ['ts' => time(), 'date' => date('Y-m-d H:i'), 'results' => $res,
            'cpu_model' => $inv['cpu']['model'] ?? '', 'cores' => $inv['cpu']['cores'] ?? 0,
            'version' => defined('SMPRO_VERSION') ? SMPRO_VERSION : ''];
    smpro_bd_history_add($run);
    smpro_bd_state_write(['status' => 'done', 'step' => 'done', 'pct' => 100, 'started' => $started,
                          'finished' => time(), 'mount' => $mount, 'results' => $res]);
    if (function_exists('smpro_audit')) @smpro_audit('benchdiag_run', ['mount' => $mount]);
    return $res;
}
/** Spawn the full suite as a DETACHED worker so it survives closing the page. */
function smpro_bd_start($mount = '') {
    $st = smpro_bd_state();
    if (($st['status'] ?? '') === 'running' && (time() - (int)($st['started'] ?? 0)) < 600)
        return ['ok' => false, 'msg' => 'A benchmark run is already in progress — results appear here when it finishes.'];
    $mount = preg_replace('#[^A-Za-z0-9/_.\-]#', '', (string)$mount);
    if (function_exists('smpro_bm_disk_mount')) $mount = smpro_bm_disk_mount($mount);
    smpro_bd_state_write(['status' => 'running', 'step' => 'starting', 'pct' => 2, 'started' => time(), 'mount' => $mount, 'results' => []]);
    $worker = SMPRO_BASE . '/bin/benchdiag.php';
    if (!@is_file($worker)) { smpro_bd_run_all($mount); return ['ok' => true, 'msg' => 'Benchmark complete.']; }
    $php = function_exists('smpro_bm_php_bin') ? smpro_bm_php_bin() : 'php';
    $pre = smpro_bd_has('setsid') ? 'setsid ' : 'nohup ';
    @shell_exec($pre . escapeshellarg($php) . ' ' . escapeshellarg($worker) . ' ' . escapeshellarg($mount) . ' >/dev/null 2>&1 </dev/null &');
    if (function_exists('smpro_audit')) @smpro_audit('benchdiag_start', ['mount' => $mount]);
    return ['ok' => true, 'msg' => 'Benchmark started — it runs in the background (you can leave this page) and is saved to Reports when it finishes.'];
}

/* ================= WHAT GOOD LOOKS LIKE: expected performance, comparison, upgrade advice ================= */

/** Whole disks with their class (rotational / SATA SSD / NVMe). */
function smpro_bd_disks() {
    $out = [];
    foreach (explode("\n", smpro_bd_sh('lsblk -dnP -o NAME,SIZE,ROTA,TRAN,MODEL', 8)) as $l) {
        if (trim($l) === '') continue; $kv = [];
        if (preg_match_all('/(\w+)="([^"]*)"/', $l, $mm, PREG_SET_ORDER)) foreach ($mm as $p) $kv[$p[1]] = $p[2];
        $n = $kv['NAME'] ?? ''; if ($n === '' || preg_match('/^(loop|sr|ram|zram)/', $n)) continue;
        $out[] = ['name' => $n, 'size' => $kv['SIZE'] ?? '', 'rota' => (($kv['ROTA'] ?? '1') === '1'),
                  'tran' => strtolower($kv['TRAN'] ?? ''), 'model' => trim($kv['MODEL'] ?? '')];
    }
    return $out;
}
/** Which physical disk backs a mount, and therefore what performance is REASONABLE to expect from it. */
function smpro_bd_mount_class($mount) {
    $disks = smpro_bd_disks();
    $dev = trim(smpro_bd_sh('df -P ' . escapeshellarg($mount !== '' ? $mount : '/') . " | awk 'NR==2{print \$1}'", 8));
    $base = $dev !== '' ? basename($dev) : '';
    $parent = '';
    if ($base !== '') {
        $pk = trim(smpro_bd_sh('lsblk -no PKNAME /dev/' . escapeshellarg($base) . ' 2>/dev/null | head -1', 8));
        $parent = $pk !== '' ? $pk : preg_replace('/p?\d+$/', '', $base);
    }
    $hit = null;
    foreach ($disks as $d) if ($parent !== '' && $d['name'] === $parent) { $hit = $d; break; }
    if (!$hit) {   // RAID/LVM or unresolved - fall back to the best class present
        foreach ($disks as $d) { if ($d['tran'] === 'nvme') { $hit = $d; break; } if (!$d['rota'] && !$hit) $hit = $d; }
        if (!$hit && $disks) $hit = $disks[0];
    }
    if (!$hit) return ['class' => 'unknown', 'label' => 'unknown storage', 'disk' => null];
    if ($hit['tran'] === 'nvme')  return ['class' => 'nvme', 'label' => 'NVMe SSD',  'disk' => $hit];
    if (!$hit['rota'])            return ['class' => 'ssd',  'label' => 'SATA/SAS SSD', 'disk' => $hit];
    return ['class' => 'hdd', 'label' => 'rotational hard disk (HDD)', 'disk' => $hit];
}
/** Expected bands per storage class: [good, acceptable] for seq write, seq read, random 4K IOPS. */
function smpro_bd_disk_expect($class) {
    $t = [
        'nvme'    => ['w' => [800, 400],  'r' => [1500, 700], 'i' => [80000, 30000], 'txt' => '800–3500 MB/s write · 1500–7000 MB/s read · 80k–500k IOPS'],
        'ssd'     => ['w' => [350, 150],  'r' => [400, 200],  'i' => [15000, 5000],  'txt' => '200–520 MB/s write · 300–560 MB/s read · 15k–90k IOPS'],
        'hdd'     => ['w' => [120, 60],   'r' => [150, 80],   'i' => [150, 70],      'txt' => '80–250 MB/s sequential · only ~100–200 random IOPS'],
        'unknown' => ['w' => [300, 100],  'r' => [400, 150],  'i' => [10000, 2000],  'txt' => 'depends on the underlying storage'],
    ];
    return $t[$class] ?? $t['unknown'];
}
/** higher-is-better rating against [good, acceptable]. */
function smpro_bd_rate($v, array $band) {
    if ($v === null || $v === '') return ['unknown', 'No result'];
    $v = (float)$v;
    if ($v >= $band[0]) return ['excellent', 'Excellent'];
    if ($v >= $band[1]) return ['good', 'As expected'];
    if ($v >= $band[1] * 0.5) return ['below', 'Below expected'];
    return ['poor', 'Poor'];
}
/** Does this CPU have AES-NI? (its absence makes the AES benchmark ~10x slower and HTTPS expensive) */
function smpro_bd_has_aesni() { return stripos((string)@file_get_contents('/proc/cpuinfo'), ' aes') !== false; }

/**
 * Turn raw benchmark numbers into: what was tested, what it scored, what is NORMAL for this
 * hardware, a verdict, and either a tuning action or a concrete hardware-replacement spec.
 */
function smpro_bd_assess(array $res) {
    $inv  = function_exists('smpro_bm_inventory') ? smpro_bm_inventory(false) : [];
    $out  = ['groups' => [], 'upgrades' => []];
    $mount = $res['disk']['mount'] ?? '';
    $mc   = smpro_bd_mount_class($mount);
    $exp  = smpro_bd_disk_expect($mc['class']);

    /* ---- CPU ---- (cheap fallbacks so this is right even when the cached inventory is cold) */
    $aes = smpro_bd_has_aesni();
    $cores = (int)($inv['cpu']['cores'] ?? 0);
    if ($cores < 1) $cores = function_exists('smpro_cpu_cores') ? (int)smpro_cpu_cores() : max(1, (int)trim(smpro_bd_sh('nproc', 5)));
    $model = (string)($inv['cpu']['model'] ?? '');
    if ($model === '' || $model === 'detecting…' || $model === '?')
        $model = trim(smpro_bd_sh("awk -F: '/model name/{print \$2; exit}' /proc/cpuinfo", 5)) ?: 'CPU';
    $virt = (string)($inv['virt'] ?? '');
    if ($virt === '') $virt = trim(smpro_bd_sh('systemd-detect-virt', 5)) ?: 'none';
    $isVm = ($virt !== 'none' && $virt !== '');
    $cpuBand = $aes ? [900, 400] : [120, 60];
    $g = ['title' => 'Processor', 'icon' => '&#129504;',
          'tested' => trim($model . ' · ' . $cores . ' threads' . ($aes ? ' · AES-NI present' : ' · NO AES-NI') . ($isVm ? ' · virtualized (' . $virt . ')' : '')),
          'rows' => []];
    if (isset($res['cpu'])) {
        $r = smpro_bd_rate($res['cpu']['single_mbs'] ?? null, $cpuBand);
        $g['rows'][] = ['label' => 'AES-256, single core', 'value' => ($res['cpu']['single_mbs'] ?? null) === null ? '—' : round($res['cpu']['single_mbs']) . ' MB/s',
            'expect' => $aes ? 'a modern server core does 900–2500 MB/s' : 'without AES-NI even a fast core only reaches ~60–150 MB/s',
            'rating' => $r[0], 'rating_txt' => $r[1]];
        $mr = smpro_bd_rate($res['cpu']['multi_mbs'] ?? null, [$cpuBand[0] * $cores * 0.6, $cpuBand[1] * $cores * 0.5]);
        $g['rows'][] = ['label' => 'AES-256, all cores', 'value' => ($res['cpu']['multi_mbs'] ?? null) === null ? '—' : round($res['cpu']['multi_mbs']) . ' MB/s',
            'expect' => 'should scale close to ' . $cores . '× the single-core figure',
            'rating' => $mr[0], 'rating_txt' => $mr[1]];
        if (isset($res['cpu']['scaling']))
            $g['rows'][] = ['label' => 'Parallel scaling', 'value' => $res['cpu']['scaling'] . '×',
                'expect' => 'close to the thread count; much lower means the cores are shared/throttled (common on oversold VPS)',
                'rating' => ($res['cpu']['scaling'] >= $cores * 0.6) ? 'good' : 'below', 'rating_txt' => ''];
        if (!$aes) $out['upgrades'][] = ['what' => 'CPU / instance type', 'sev' => 'high',
            'title' => 'This CPU has no AES-NI — encryption is done in software',
            'detail' => 'Every HTTPS connection, encrypted DB link and backup compression costs many times more CPU than it should. On any CPU made in the last decade this is hardware-accelerated.',
            'spec' => 'Move to a host/instance with a modern x86-64 CPU (Intel Xeon Scalable or AMD EPYC, 2017+). Any of them include AES-NI; expect roughly a 10× jump in the figure above and noticeably lower CPU under HTTPS load.'];
    }

    /* ---- RAM ---- */
    $ramTxt = 'RAM';
    if (isset($inv['ram'])) $ramTxt = ($inv['ram']['total_gb'] ?? 0) . ' GB'
        . (isset($inv['ram']['type']) ? ' ' . $inv['ram']['type'] : '')
        . (isset($inv['ram']['speed']) ? ' @ ' . (int)$inv['ram']['speed'] . ' MT/s' : '');
    $gr = ['title' => 'Memory', 'icon' => '&#129518;', 'tested' => $ramTxt, 'rows' => []];
    if (isset($res['ram']) && empty($res['ram']['err'])) {
        $rr = smpro_bd_rate($res['ram']['read_mbs'] ?? null, [4000, 1800]);
        $gr['rows'][] = ['label' => 'Read bandwidth', 'value' => ($res['ram']['read_mbs'] ?? null) === null ? '—' : round($res['ram']['read_mbs']) . ' MB/s',
            'expect' => 'DDR4 in dual channel typically gives 4000–12000 MB/s here', 'rating' => $rr[0], 'rating_txt' => $rr[1]];
        $rw = smpro_bd_rate($res['ram']['write_mbs'] ?? null, [3000, 1200]);
        $gr['rows'][] = ['label' => 'Write bandwidth', 'value' => ($res['ram']['write_mbs'] ?? null) === null ? '—' : round($res['ram']['write_mbs']) . ' MB/s',
            'expect' => 'usually 3000–9000 MB/s on a healthy DDR4 server', 'rating' => $rw[0], 'rating_txt' => $rw[1]];
        if ($rr[0] === 'below' || $rr[0] === 'poor') $out['upgrades'][] = ['what' => 'Memory configuration', 'sev' => 'medium',
            'title' => 'Memory bandwidth is below what this class of server should reach',
            'detail' => 'Usually one of: DIMMs populated in single channel (all sticks on one controller), a slower memory generation, or a virtual machine whose host is oversubscribed.',
            'spec' => 'Populate memory in matched pairs/quads so it runs in dual or quad channel, and prefer DDR4-3200 (or DDR5) modules. If this is a VM, the host is likely contended — a dedicated or higher-tier instance will fix it.'];
    }

    /* ---- DISK - the one that usually decides how the server feels ---- */
    $dsk = $mc['disk'];
    $gd = ['title' => 'Storage', 'icon' => '&#128190;',
           'tested' => ($dsk ? ('/dev/' . $dsk['name'] . ' · ' . $dsk['size'] . ($dsk['model'] !== '' ? ' · ' . $dsk['model'] : '')) : 'storage')
                       . ' · detected as ' . $mc['label'] . ($mount !== '' ? ' · tested on ' . $mount : ''), 'rows' => []];
    if (isset($res['disk']) && empty($res['disk']['err'])) {
        $w = smpro_bd_rate($res['disk']['write_mbs'] ?? null, $exp['w']);
        $gd['rows'][] = ['label' => 'Sequential write', 'value' => ($res['disk']['write_mbs'] ?? null) === null ? '—' : round($res['disk']['write_mbs']) . ' MB/s',
            'expect' => 'normal for ' . $mc['label'] . ': ' . $exp['txt'], 'rating' => $w[0], 'rating_txt' => $w[1]];
        $r = smpro_bd_rate($res['disk']['read_mbs'] ?? null, $exp['r']);
        $gd['rows'][] = ['label' => 'Sequential read', 'value' => ($res['disk']['read_mbs'] ?? null) === null ? '—' : round($res['disk']['read_mbs']) . ' MB/s',
            'expect' => 'normal for ' . $mc['label'], 'rating' => $r[0], 'rating_txt' => $r[1]];
        $io = smpro_bd_rate($res['disk']['iops'] ?? null, $exp['i']);
        $gd['rows'][] = ['label' => 'Random 4K IOPS', 'value' => ($res['disk']['iops'] ?? null) === null ? '— (install fio)' : number_format((int)$res['disk']['iops']),
            'expect' => 'THE number that decides how a busy cPanel/MySQL server feels — ' . ($mc['class'] === 'hdd' ? 'an HDD can only do ~100–200' : ($mc['class'] === 'nvme' ? 'NVMe should do 80k+' : 'a SATA SSD should do 15k+')),
            'rating' => $io[0], 'rating_txt' => $io[1]];
    }
    // storage upgrade advice - specific type, capacity and the properties that matter
    if ($mc['class'] === 'hdd') {
        $usedGb = (int)trim(smpro_bd_sh("df -PBG " . escapeshellarg($mount !== '' ? $mount : '/') . " | awk 'NR==2{gsub(/G/,\"\",\$3); print \$3}'", 8));
        $capGb  = max(480, (int)(ceil(max($usedGb * 2, 240) / 240) * 240));
        $out['upgrades'][] = ['what' => 'Storage — replace the disk', 'sev' => 'high',
            'title' => 'This server runs on a rotational hard disk (HDD) — that is the bottleneck',
            'detail' => 'An HDD delivers only ~100–200 random IOPS no matter how fast its sequential speed looks. A cPanel server with MySQL, mail and many small files is almost entirely random I/O, so the disk spends its time seeking while everything queues behind it. This is the single biggest hardware limit on this machine.',
            'spec' => $isVm
                ? 'This is a virtual machine (' . $virt . '), so the disk is provided by the host — ask your provider to move it to NVMe-backed storage or a higher-IOPS volume tier. Specify: NVMe/SSD-backed, at least ' . $capGb . ' GB (you are using about ' . max(1, $usedGb) . ' GB — allow 2× for growth, snapshots and temp space) and a guaranteed IOPS floor rather than a "burst" allowance. Expect random IOPS to go from ~150 to tens of thousands — a 100×+ improvement in exactly the metric that limits you.'
                : 'Replace with an NVMe SSD (PCIe 3.0 x4 or newer). Recommended: at least ' . $capGb . ' GB (you are using about ' . max(1, $usedGb) . ' GB — allow 2× for growth, snapshots and temp space), datacentre/enterprise class with power-loss protection, endurance of at least 0.5–1 DWPD (roughly ' . (int)($capGb * 0.5 * 365 * 3 / 1000) . ' TBW over 3 years) for a hosting workload, and ideally two of them in RAID 1 for redundancy. Expect random IOPS to go from ~150 to 80,000+ — that is a 300–500× improvement in exactly the metric that limits you.'];
    } elseif ($mc['class'] === 'ssd' && isset($res['disk']['iops']) && $res['disk']['iops'] !== null && $res['disk']['iops'] < 15000) {
        $out['upgrades'][] = ['what' => 'Storage — consider NVMe', 'sev' => 'medium',
            'title' => 'SATA SSD is fine, but it is capped by the SATA interface',
            'detail' => 'SATA tops out around 550 MB/s and typically tens of thousands of IOPS. NVMe talks straight to PCIe and removes that ceiling.',
            'spec' => $isVm
                ? 'This is a virtual machine (' . $virt . ') — the figure above reflects the host\'s storage tier, not a physical drive you own. If the server is I/O-bound, ask the provider for an NVMe-backed volume with a guaranteed IOPS floor.'
                : 'If this server is I/O-bound, move to an NVMe SSD (PCIe 3.0 x4 or better, enterprise class with power-loss protection, ≥1 DWPD). Typical gain: 3–10× sequential and 5–20× random IOPS over SATA.'];
    } elseif (isset($res['disk']['read_mbs']) && $res['disk']['read_mbs'] !== null && ($mc['class'] === 'nvme') && $res['disk']['read_mbs'] < $exp['r'][1]) {
        $out['upgrades'][] = ['what' => 'Storage — investigate', 'sev' => 'medium',
            'title' => 'NVMe hardware, but it is performing far below NVMe class',
            'detail' => 'The device should be several times faster than this. Common causes: the drive is thermally throttling, it is nearly full (SSDs slow down badly above ~90%), it is worn out, or the benchmark ran while another job saturated it.',
            'spec' => 'Check the drive temperature and wear in Hardware health below, free space above 20%, and re-run the benchmark when the server is quiet. If it stays slow and wear is high, replace the drive.'];
    }

    /* ---- PHP + MySQL ---- */
    $gp = ['title' => 'PHP', 'icon' => '&#128295;', 'tested' => 'PHP ' . ($res['php']['php_version'] ?? '?') . ' (the interpreter SM Pro runs under)', 'rows' => []];
    if (isset($res['php'])) {
        $pr = smpro_bd_rate($res['php']['int_ops_sec'] ?? null, [20000000, 9000000]);
        $gp['rows'][] = ['label' => 'Integer throughput', 'value' => number_format((int)($res['php']['int_ops_sec'] ?? 0)) . '/s',
            'expect' => 'a current server CPU on PHP 8 does 20–40 million/s', 'rating' => $pr[0], 'rating_txt' => $pr[1]];
        $hr = smpro_bd_rate($res['php']['hash_ops_sec'] ?? null, [2000000, 900000]);
        $gp['rows'][] = ['label' => 'Hash (md5) throughput', 'value' => number_format((int)($res['php']['hash_ops_sec'] ?? 0)) . '/s',
            'expect' => 'typically 2–5 million/s', 'rating' => $hr[0], 'rating_txt' => $hr[1]];
    }
    $gm = ['title' => 'MySQL', 'icon' => '&#128044;', 'tested' => 'the local database engine', 'rows' => []];
    if (isset($res['mysql']) && empty($res['mysql']['err'])) {
        $cr = smpro_bd_rate($res['mysql']['connect_ms'] ?? null, [0, 0]);   // lower-is-better, handled inline
        $cm = $res['mysql']['connect_ms'] ?? null;
        $gm['rows'][] = ['label' => 'Connect + round trip', 'value' => $cm === null ? '—' : $cm . ' ms',
            'expect' => 'under 20 ms is healthy; over 50 ms means the server is busy or DNS/socket resolution is slow',
            'rating' => $cm === null ? 'unknown' : ($cm <= 20 ? 'excellent' : ($cm <= 50 ? 'good' : 'below')), 'rating_txt' => ''];
        $qr = smpro_bd_rate($res['mysql']['query_ops_sec'] ?? null, [1000000, 400000]);
        $gm['rows'][] = ['label' => 'Query throughput (CPU-bound)', 'value' => number_format((int)($res['mysql']['query_ops_sec'] ?? 0)) . '/s',
            'expect' => 'tracks CPU speed; 1M+/s on a modern core', 'rating' => $qr[0], 'rating_txt' => $qr[1]];
        $ir = smpro_bd_rate($res['mysql']['insert_rows_sec'] ?? null, [10000, 3000]);
        $gm['rows'][] = ['label' => 'InnoDB insert rate', 'value' => ($res['mysql']['insert_rows_sec'] ?? null) === null ? '—' : number_format((int)$res['mysql']['insert_rows_sec']) . '/s',
            'expect' => 'this is a DISK test in disguise — it measures how fast InnoDB can commit. Under ~3000/s points at slow storage',
            'rating' => $ir[0], 'rating_txt' => $ir[1]];
        if (($res['mysql']['insert_rows_sec'] ?? 99999) < 3000)
            $out['upgrades'][] = ['what' => 'Storage (confirmed by the database)', 'sev' => 'high',
                'title' => 'MySQL write rate is low — the database is waiting on the disk',
                'detail' => 'The InnoDB insert benchmark measures commit/flush speed, so a low number is independent confirmation that storage — not CPU — is what limits this server.',
                'spec' => 'Prioritise the storage upgrade above. A datacentre NVMe SSD with power-loss protection typically takes this figure from a few hundred to tens of thousands of rows/s.'];
    }

    foreach ([$g, $gr, $gd, $gp, $gm] as $grp) if (!empty($grp['rows'])) $out['groups'][] = $grp;
    return $out;
}

/* ================= 7-DAY WORKLOAD SAMPLING =================
 * "Is the hardware bigger than the load?" can only be answered from history, so a tiny cron
 * appends one sample every 5 minutes into hourly buckets (max + mean). 168 buckets = 7 days,
 * a few KB on disk. Nothing here is heavy: one /proc read per resource. */
if (!defined('SMPRO_BD_HIST')) define('SMPRO_BD_HIST', SMPRO_VARLIB . '/hw_history.json');
function smpro_bd_hist_read() {
    $d = @is_file(SMPRO_BD_HIST) ? json_decode((string)@file_get_contents(SMPRO_BD_HIST), true) : null;
    return is_array($d) ? $d : [];
}
/** Fold one live sample into the current hour's bucket, then trim to 7 days. */
function smpro_bd_sample_run() {
    if (!function_exists('smpro_collect_metrics')) return false;
    $m = smpro_collect_metrics();
    $busy = 0;
    if (function_exists('smpro_ds_diskio')) foreach (smpro_ds_diskio() as $d) $busy = max($busy, (float)($d['util'] ?? 0));
    $vals = ['cpu' => (float)($m['cpu']['pct'] ?? 0), 'ram' => (float)($m['ram']['pct'] ?? 0),
             'swap' => (float)($m['swap']['pct'] ?? 0), 'busy' => $busy, 'space' => (float)($m['disk']['pct'] ?? 0)];
    $h = smpro_bd_hist_read(); $k = date('YmdH');
    $b = $h[$k] ?? ['n' => 0];
    foreach ($vals as $kk => $v) {
        $b[$kk . '_max'] = max((float)($b[$kk . '_max'] ?? 0), $v);
        $b[$kk . '_sum'] = (float)($b[$kk . '_sum'] ?? 0) + $v;
    }
    $b['n'] = (int)($b['n'] ?? 0) + 1;
    $h[$k] = $b;
    if (count($h) > 168) { ksort($h); $h = array_slice($h, -168, null, true); }
    $f = SMPRO_BD_HIST; @is_dir(dirname($f)) || @mkdir(dirname($f), 0700, true);
    $t = $f . '.tmp';
    if (@file_put_contents($t, json_encode($h, JSON_UNESCAPED_SLASHES), LOCK_EX) !== false) { @chmod($t, 0600); @rename($t, $f); }
    return true;
}
function smpro_bd_sample_cron_sync() {
    // A test must never install a live cron. The shared writer refuses too, but a test that loads only
    // this file has no shared writer to refuse - function_exists() is false and the fallback writes
    // /etc/cron.d directly. The lab caught exactly that, restored the file, and went red at random.
    if (defined('SMPRO_TEST_SRC')) return true;
    $f = '/etc/cron.d/smpro-hwsample';
    if (!is_file(SMPRO_BASE . '/bin/hwsample.php')) { if (is_file($f)) @unlink($f); return; }
    $php = smpro_php_cli_bin();   // canonical: cron's PATH may not resolve a bare `php`
    $ld = SMPRO_VARLIB . '/locks'; @is_dir($ld) || @mkdir($ld, 0700, true);
    $flock = is_executable('/usr/bin/flock') ? '/usr/bin/flock' : 'flock';
    $desired = "# Safety Monitor Pro — hardware workload sampling (7-day peaks for the hardware-fit report)\n"
             . "*/5 * * * * root $flock -n " . $ld . "/hwsample.cron.lock timeout 60 $php " . SMPRO_BASE . "/bin/hwsample.php >/dev/null 2>&1\n";
    if (is_file($f) && (string)@file_get_contents($f) === $desired) return;
    smpro_cron_install($f, $desired);   // verified write: 0644 + trailing newline, or it reports failure
}
/** Peak + typical per resource over the retained window. */
function smpro_bd_hist_stats() {
    $h = smpro_bd_hist_read();
    $keys = ['cpu', 'ram', 'swap', 'busy', 'space'];
    $out = []; $hours = 0; $samples = 0;
    foreach ($keys as $k) { $out[$k] = ['peak' => null, 'avg' => null, 'samples' => 0]; }
    if (!$h) return ['hours' => 0, 'samples' => 0] + $out;
    // Count ONLY buckets that actually recorded a metric. Buckets written by an older sampler that
    // lack the *_max keys must not masquerade as zero-usage samples - otherwise a box with plenty of
    // history but only legacy buckets shows a peak of 0 (or "no data"), which is exactly the bug this
    // fixes. A metric stays null until it has at least one real sample, then shows its true peak.
    foreach ($keys as $k) {
        $peak = null; $sum = 0; $n = 0;
        foreach ($h as $b) {
            if (!is_array($b) || !array_key_exists($k . '_max', $b)) continue;   // this bucket never sampled this metric
            $v = (float)$b[$k . '_max'];
            $peak = ($peak === null) ? $v : max($peak, $v);
            $sum += (float)($b[$k . '_sum'] ?? 0);
            $n   += (int)($b['n'] ?? 0);
        }
        $out[$k] = ['peak' => $peak === null ? null : round($peak, 1), 'avg' => $n ? round($sum / $n, 1) : null, 'samples' => $n];
        $samples = max($samples, $n);
        if ($n > 0) $hours = max($hours, count(array_filter($h, function ($b) use ($k) { return is_array($b) && array_key_exists($k . '_max', $b); })));
    }
    return ['hours' => $hours, 'samples' => $samples] + $out;
}

/* ================= WORKLOAD FIT + OVERALL HARDWARE SCORE ================= */
function smpro_bd_workload_fit() {
    $s = smpro_bd_hist_stats();
    $m = function_exists('smpro_collect_metrics') ? smpro_collect_metrics() : [];
    $inv = function_exists('smpro_bm_inventory') ? smpro_bm_inventory(false) : [];
    $cores = (int)($m['cores'] ?? 0); if ($cores < 1) $cores = max(1, (int)trim(smpro_bd_sh('nproc', 5)));
    $ramGb = (float)($inv['ram']['total_gb'] ?? 0);
    $warm = ($s['hours'] < 6);            // not enough history yet to call a peak a peak
    $row = function ($key, $label, $cap, $peak, $avg, $now, $note, $warnAt = 70, $dangAt = 88) {
        $p = $peak === null ? 0 : (float)$peak;
        $tier = $p >= $dangAt ? 'dang' : ($p >= $warnAt ? 'warn' : 'good');
        // Named explicitly, not via compact() - see the note in dbhealth.php: obfuscation renames the variables
        // but not the strings compact() looks them up by, so this silently returned an empty row in every build.
        return ['key' => $key, 'label' => $label, 'cap' => $cap, 'peak' => $peak,
                'avg' => $avg, 'now' => $now, 'note' => $note, 'tier' => $tier];
    };
    $rows = [];
    $rows[] = $row('cpu', 'Processor', $cores . ' threads', $s['cpu']['peak'], $s['cpu']['avg'], (float)($m['cpu']['pct'] ?? 0),
        'Load average ' . (($m['load']['1m'] ?? 0)) . ' against ' . $cores . ' threads.');
    // Capacity label: real total GB from inventory; if the inventory cache is cold, parse the live
    // total (e.g. "63.2G") rather than mislabelling the usage PERCENT as "GB".
    $ramCap = $ramGb ? ($ramGb . ' GB') : (preg_match('/([\d.]+)\s*G/i', (string)($m['ram']['total'] ?? ''), $mg) ? ($mg[1] . ' GB') : '—');
    $rows[] = $row('ram', 'Memory', $ramCap, $s['ram']['peak'], $s['ram']['avg'], (float)($m['ram']['pct'] ?? 0),
        'Now ' . ($m['ram']['used'] ?? '?') . ' of ' . ($m['ram']['total'] ?? '?') . '.');
    $rows[] = $row('busy', 'Storage speed', 'busiest disk', $s['busy']['peak'], $s['busy']['avg'], null,
        'How close the busiest disk gets to saturation.');
    $rows[] = $row('space', 'Storage space', ($m['disk']['total'] ?? ''), $s['space']['peak'], $s['space']['avg'], (float)($m['disk']['pct'] ?? 0),
        ($m['disk']['free'] ?? '') . ' free.', 75, 90);

    // verdict: is anything actually constrained?
    $tight = []; foreach ($rows as $r) if ($r['tier'] !== 'good') $tight[] = $r['label'];
    if ($warm) {
        $verdict = ['warm', 'Collecting history', 'Sampling started less than 6 hours ago, so these peaks are not yet meaningful. '
            . 'A sample is taken every 5 minutes; come back after a normal working day for a reliable answer.'];
    } elseif (!$tight) {
        $verdict = ['good', 'The hardware is comfortably ahead of your workload',
            'Every resource stays well inside its capacity even at peak, so a bigger server would buy nothing. '
            . 'If the machine ever feels slow, the cause is configuration or a single slow component — not a lack of hardware.'];
    } else {
        $verdict = ['warn', 'Under pressure: ' . implode(', ', $tight),
            'These resources reach a high share of capacity at peak. Fix the cause first (a slow disk, an unindexed query, '
            . 'a runaway account) — only add hardware once you know the demand is genuine.'];
    }
    return ['rows' => $rows, 'stats' => $s, 'warm' => $warm, 'verdict' => $verdict];
}
/** Composite 0-100: Performance 35 · Health 35 · Headroom 15 · Configuration 15. Health-heavy on purpose. */
function smpro_bd_hw_score() {
    $parts = [];
    // performance - from whatever devices have been measured
    $dev = smpro_bd_dev_results(); $pv = [];
    foreach ($dev as $k => $r) {
        if (strpos($k, 'disk:') !== 0) continue;
        $g = ($r['iops'] ?? null) !== null ? smpro_bd_grade_iops($r['iops']) : smpro_bd_grade_seq($r['read_mbs'] ?? null);
        $pv[] = ['excellent' => 100, 'verygood' => 85, 'good' => 70, 'poor' => 45, 'failing' => 15, 'unknown' => null][$g[0]] ?? null;
    }
    $pv = array_values(array_filter($pv, function ($x) { return $x !== null; }));
    $parts['performance'] = $pv ? (int)round(array_sum($pv) / count($pv)) : null;
    // health - SMART / RAID / ECC findings
    $hw = smpro_bd_hw_health_cached(false);
    if (is_array($hw)) {
        $h = 100;
        foreach (($hw['findings'] ?? []) as $f)
            $h -= ['critical' => 60, 'high' => 25, 'medium' => 10, 'low' => 3][$f['sev']] ?? 0;
        $parts['health'] = max(0, min(100, $h));
    } else $parts['health'] = null;
    // headroom - inverse of the worst peak
    $fit = smpro_bd_workload_fit();
    if (!$fit['warm']) {
        $worst = 0; foreach ($fit['rows'] as $r) $worst = max($worst, (float)($r['peak'] ?? 0));
        $parts['headroom'] = (int)round(max(0, min(100, 100 - $worst)));
    } else $parts['headroom'] = null;
    // configuration - kernel/software findings
    $diag = smpro_bd_diagnose_cached(false);
    if (is_array($diag)) {
        $c = 100;
        foreach ($diag as $f) $c -= ['critical' => 40, 'high' => 18, 'medium' => 8, 'low' => 3][$f['sev']] ?? 0;
        $parts['configuration'] = max(0, min(100, $c));
    } else $parts['configuration'] = null;

    $w = ['performance' => 35, 'health' => 35, 'headroom' => 15, 'configuration' => 15];
    $num = 0; $den = 0; $missing = [];
    foreach ($w as $k => $weight) {
        if ($parts[$k] !== null) { $num += $parts[$k] * $weight; $den += $weight; }
        else $missing[] = $k;
    }
    $score = $den ? (int)round($num / $den) : null;
    // Coverage matters as much as the number. Scoring only the parts we could measure and then
    // presenting the result as a finished verdict overstates it - half an assessment is not an
    // "Excellent" machine, it is an untested one. So the band carries the coverage, and below
    // ~60% the score is explicitly provisional rather than being given a confident grade.
    $total = array_sum($w);
    $coverage = (int)round($den / $total * 100);
    $how = ['performance' => 'test a drive', 'headroom' => 'let the sampler collect a few hours',
            'health' => 'install smartmontools', 'configuration' => 're-open this page'];
    $todo = [];
    foreach ($missing as $k) $todo[] = ucfirst($k) . ' — ' . ($how[$k] ?? 'not measured');
    if ($score === null)        $band = ['gray', 'Not assessed yet'];
    elseif ($coverage < 60)     $band = ['gray', 'Provisional · ' . $coverage . '% assessed'];
    else {
        $lbl = $score >= 90 ? ['good', 'Excellent'] : ($score >= 75 ? ['good', 'Healthy']
             : ($score >= 55 ? ['warn', 'Needs attention'] : ['dang', 'Poor']));
        $band = $coverage < 100 ? [$lbl[0], $lbl[1] . ' · ' . $coverage . '% assessed'] : $lbl;
    }
    return ['score' => $score, 'parts' => $parts, 'weights' => $w, 'band' => $band,
            'coverage' => $coverage, 'provisional' => ($coverage < 100), 'missing' => $missing, 'todo' => $todo];
}

/* ================= GROW A FILESYSTEM (the only storage change ever offered) =================
 * Detection only finds the safe case: a mounted ext4/xfs whose block device is materially LARGER
 * than the filesystem on it, i.e. there is unallocated room to grow INTO. Shrinking, RAID-level
 * changes and member replacement are never offered - they can destroy data or the boot. */
/**
 * Resolve the WHOLE storage stack behind a device, because "can this grow?" depends entirely on
 * what it is sitting on: a plain partition, an mdadm array, an LVM logical volume, a hardware-RAID
 * virtual disk, or a filesystem that manages its own pool (btrfs / ZFS). Read-only (lsblk + vgs).
 */
function smpro_bd_stack($devPath) {
    $st = ['dev' => $devPath, 'name' => basename($devPath), 'type' => '', 'chain' => [], 'disks' => [],
           'pttype' => '', 'is_lvm' => false, 'is_md' => false, 'is_hwraid' => false, 'md_level' => '', 'vg' => '', 'vg_free' => 0];
    $st['type'] = trim(smpro_bd_sh('lsblk -rno TYPE ' . escapeshellarg($devPath) . ' 2>/dev/null | head -1', 6));
    foreach (explode("\n", smpro_bd_sh('lsblk -rsn -o NAME,TYPE ' . escapeshellarg($devPath) . ' 2>/dev/null', 8)) as $l) {
        $p = preg_split('/\s+/', trim($l)); if (count($p) < 2 || $p[0] === '') continue;
        $st['chain'][] = ['name' => $p[0], 'type' => $p[1]];
        if ($p[1] === 'disk' && !in_array($p[0], $st['disks'], true)) $st['disks'][] = $p[0];
        if ($p[1] === 'lvm') $st['is_lvm'] = true;
        if (preg_match('/^raid(\d+)/', $p[1], $m)) { $st['is_md'] = true; $st['md_level'] = 'RAID ' . $m[1]; }
    }
    if ($st['type'] === 'lvm') $st['is_lvm'] = true;
    if (preg_match('/^raid/', $st['type'])) { $st['is_md'] = true; $st['md_level'] = strtoupper(str_replace('raid', 'RAID ', $st['type'])); }
    if ($st['disks']) $st['pttype'] = strtolower(trim(smpro_bd_sh('lsblk -rno PTTYPE /dev/' . escapeshellarg($st['disks'][0]) . ' 2>/dev/null | head -1', 6)));
    // hardware RAID: a "disk" that is really a controller's virtual disk
    foreach ($st['disks'] as $d) {
        $vm = strtolower(trim(smpro_bd_sh('lsblk -rno VENDOR,MODEL /dev/' . escapeshellarg($d) . ' 2>/dev/null | head -1', 6)));
        if (preg_match('/(megaraid|perc|logical volume|smartarray|smart array|avago|lsi|adaptec|3ware|hpsa)/', $vm)) $st['is_hwraid'] = true;
    }
    // LVM: is there free room left in the volume group?
    if ($st['is_lvm'] && smpro_bd_has('lvs')) {
        $vg = trim(smpro_bd_sh('lvs --noheadings -o vg_name ' . escapeshellarg($devPath) . ' 2>/dev/null | head -1', 8));
        $st['vg'] = trim($vg);
        if ($st['vg'] !== '' && smpro_bd_has('vgs'))
            $st['vg_free'] = (float)preg_replace('/[^0-9]/', '', trim(smpro_bd_sh('vgs --noheadings --units b -o vg_free ' . escapeshellarg($st['vg']) . ' 2>/dev/null', 8)));
    }
    return $st;
}
/** Unallocated bytes lying AFTER the last partition on a disk (needs parted; 0 if unknown). */
function smpro_bd_disk_tail_free($disk) {
    if (!smpro_bd_has('parted')) return 0;
    $raw = smpro_bd_sh('parted -sm /dev/' . escapeshellarg($disk) . ' unit B print free 2>/dev/null', 10);
    $best = 0;
    foreach (explode("\n", $raw) as $l) {
        $p = explode(':', trim($l));
        if (count($p) >= 5 && stripos($p[4], 'free') !== false) $best = max($best, (float)rtrim($p[3], 'B'));
    }
    return $best;
}
/**
 * Every mounted filesystem, classified: can it be grown online right now, or does a LOWER layer
 * have to be expanded first (and by what). We only ever OFFER the first case; everything else is
 * reported with the exact reason and the manual procedure, never executed.
 */
function smpro_bd_storage_ops() {
    $growable = []; $blocked = [];
    foreach (smpro_bd_mounts() as $devPath => $mi) {
        $fs = strtolower($mi['fs']);
        if (in_array($fs, ['tmpfs', 'devtmpfs', 'overlay', 'squashfs', 'iso9660', 'proc', 'sysfs'], true)) continue;
        if (strpos($devPath, '/dev/') !== 0) continue;
        $fsBytes = (float)$mi['size_kb'] * 1024;
        $devBytes = (float)trim(smpro_bd_sh('blockdev --getsize64 ' . escapeshellarg($devPath), 6));
        $st = smpro_bd_stack($devPath);
        $stackTxt = strtoupper($fs) . ' on ' . ($st['is_lvm'] ? 'LVM logical volume' : ($st['is_md'] ? ($st['md_level'] ?: 'mdadm array')
                  : ($st['type'] === 'part' ? 'partition' : ($st['type'] === 'disk' ? 'whole disk' : ($st['type'] ?: 'device')))))
                  . ' ' . $st['name']
                  . ($st['pttype'] !== '' ? ' · ' . strtoupper($st['pttype']) . ' table' : '')
                  . ($st['disks'] ? ' · on ' . implode(' + ', $st['disks']) : '')
                  . ($st['is_hwraid'] ? ' · hardware RAID controller' : '');
        $base = ['dev' => $devPath, 'name' => $st['name'], 'fs' => $fs, 'mount' => $mi['mount'],
                 'fs_bytes' => $fsBytes, 'dev_bytes' => $devBytes, 'stack' => $stackTxt, 'st' => $st];

        // 1) filesystems that manage their own pool - never touched with resize2fs/xfs_growfs
        if (in_array($fs, ['zfs', 'btrfs'], true)) {
            $blocked[] = $base + ['why' => strtoupper($fs) . ' manages its own storage pool',
                'detail' => 'Growing it is a pool operation, not a filesystem resize, and the wrong tool here would be destructive.',
                'manual' => $fs === 'btrfs' ? 'btrfs filesystem resize max ' . $mi['mount'] . ' (after adding a device with btrfs device add)'
                                            : 'zpool set autoexpand=on <pool> ; zpool online -e <pool> <device>'];
            continue;
        }
        // 2) only ext*/xfs can be grown online by this plugin
        if (!in_array($fs, ['ext2', 'ext3', 'ext4', 'xfs'], true)) {
            $blocked[] = $base + ['why' => 'Filesystem type ' . strtoupper($fs) . ' is not supported for online growth',
                'detail' => 'Only ext2/3/4 and XFS are grown here, because only those have a well-understood online-grow path.',
                'manual' => 'Consult the documentation for ' . strtoupper($fs) . '.'];
            continue;
        }
        if ($devBytes <= 0) continue;
        $slack = $devBytes - $fsBytes;

        // 3) the safe case: the block device is ALREADY larger than the filesystem
        if ($slack >= 1073741824 && $slack >= $devBytes * 0.02) {
            $growable[] = $base + ['gain_bytes' => $slack,
                'cmd' => ($fs === 'xfs') ? ('xfs_growfs ' . $mi['mount']) : ('resize2fs ' . $devPath)];
            continue;
        }

        // 4) no slack at this layer - is there room one layer down, and is it safe for us to take it?
        if ($st['is_md']) {
            $blocked[] = $base + ['why' => 'Sits on an mdadm ' . ($st['md_level'] ?: 'array') . ' that is already full',
                'detail' => 'Growing the array itself (mdadm --grow) reshapes data across every member disk. A reshape that is '
                          . 'interrupted can lose the whole array, so this plugin never performs one.',
                'manual' => 'Expand the members first, then: mdadm --grow /dev/' . $st['name'] . ' --size=max — from the console, with a verified backup.'];
        } elseif ($st['is_lvm']) {
            if ($st['vg_free'] > 1073741824) {
                $blocked[] = $base + ['why' => 'Its volume group has ' . smpro_bd_kb_h($st['vg_free'] / 1024) . ' free, but the logical volume must be extended first',
                    'detail' => 'This is a two-layer change: extend the LV, then grow the filesystem into it. The plugin only performs the '
                              . 'second half, so that a failure can never leave the volume layout inconsistent.',
                    'manual' => 'lvextend -l +100%FREE ' . $devPath . '  then  ' . ($fs === 'xfs' ? 'xfs_growfs ' . $mi['mount'] : 'resize2fs ' . $devPath)
                              . ' — after that, this page will offer the filesystem step itself.'];
            } else {
                $blocked[] = $base + ['why' => 'On LVM, and the volume group has no free space',
                    'detail' => 'There is nothing to grow into until a physical volume is added to the group.',
                    'manual' => 'Add a disk: pvcreate /dev/sdX ; vgextend ' . ($st['vg'] ?: '<vg>') . ' /dev/sdX ; then extend the LV.'];
            }
        } elseif ($st['is_hwraid']) {
            $blocked[] = $base + ['why' => 'Sits behind a hardware RAID controller',
                'detail' => 'The operating system only sees a virtual disk. Capacity has to be added on the controller first, and only '
                          . 'the controller knows whether that is safe.',
                'manual' => 'Expand the virtual disk in the RAID controller utility, then re-check this page.'];
        } elseif ($st['type'] === 'part') {
            $disk = $st['disks'][0] ?? '';
            $tail = $disk !== '' ? smpro_bd_disk_tail_free($disk) : 0;
            if ($tail > 1073741824) {
                $blocked[] = $base + ['why' => 'There is ' . smpro_bd_kb_h($tail / 1024) . ' unallocated after this partition — but the PARTITION must be resized first',
                    'detail' => 'Growing a partition rewrites the partition table. If that is interrupted or the table is misread, the disk can '
                              . 'become unbootable and the data unreachable — so the plugin never edits a partition table.'
                              . ($st['pttype'] === 'dos' ? ' This disk uses an MBR/DOS table, which also cannot address beyond 2 TB.' : ''),
                    'manual' => 'growpart /dev/' . $disk . ' <partition-number>  (or parted resizepart) from the console with a verified backup, '
                              . 'then this page will offer the filesystem step.'];
            } else {
                $blocked[] = $base + ['why' => 'No unallocated space left on ' . ($disk !== '' ? '/dev/' . $disk : 'the disk'),
                    'detail' => 'The partition already extends to the end of the device, so there is nothing to grow into.',
                    'manual' => 'Add a disk, or move data to a larger volume.'];
            }
        } else {
            $blocked[] = $base + ['why' => 'The filesystem already fills its device',
                'detail' => 'There is no unallocated space behind it.', 'manual' => 'Add capacity at the storage layer first.'];
        }
    }
    return ['growable' => $growable, 'blocked' => $blocked];
}
/** Back-compat: only the entries we are willing to act on. */
function smpro_bd_grow_candidates() { $o = smpro_bd_storage_ops(); return $o['growable']; }
/** Grow ONE filesystem online. Re-validates everything server-side; never trusts the client. */
function smpro_bd_grow_apply($devName, $confirm) {
    $devName = preg_replace('/[^A-Za-z0-9_.\-]/', '', (string)$devName);
    $cands = smpro_bd_grow_candidates(); $c = null;
    foreach ($cands as $x) if ($x['name'] === $devName) { $c = $x; break; }
    if (!$c) return ['ok' => false, 'msg' => 'That filesystem is not growable (re-checked on the server just now). Nothing was changed.'];
    if (trim((string)$confirm) !== $c['name'])
        return ['ok' => false, 'msg' => 'Confirmation did not match the device name. Nothing was changed.'];
    $beforeKb = 0; $mounts = smpro_bd_mounts();
    foreach ($mounts as $d => $mi) if ($d === $c['dev']) $beforeKb = (int)$mi['size_kb'];
    if (function_exists('smpro_audit')) smpro_audit('benchdiag_grow_start', ['dev' => $c['dev'], 'fs' => $c['fs'], 'mount' => $c['mount'], 'before_kb' => $beforeKb]);
    $cmd = ($c['fs'] === 'xfs')
        ? 'xfs_growfs ' . escapeshellarg($c['mount'])
        : 'resize2fs ' . escapeshellarg($c['dev']);
    $out = smpro_bd_sh($cmd, 900);
    // verify from a fresh df, not from the tool's own chatter
    $after = 0;
    foreach (explode("\n", smpro_bd_sh('df -Pk ' . escapeshellarg($c['mount']), 15)) as $i => $l) {
        if ($i === 0 || trim($l) === '') continue;
        $p = preg_split('/\s+/', trim($l)); if (count($p) >= 2) { $after = (int)$p[1]; break; }
    }
    $grew = ($after > $beforeKb);
    if (function_exists('smpro_audit')) smpro_audit('benchdiag_grow_done', ['dev' => $c['dev'], 'before_kb' => $beforeKb, 'after_kb' => $after, 'ok' => $grew]);
    return ['ok' => $grew, 'from' => smpro_bd_kb_h($beforeKb), 'to' => smpro_bd_kb_h($after),
        'msg' => $grew
            ? '✅ ' . smpro_h($c['mount']) . ' grew from ' . smpro_bd_kb_h($beforeKb) . ' to ' . smpro_bd_kb_h($after)
              . ". It stayed mounted throughout and no file was moved or rewritten — only the filesystem's size metadata changed."
            : 'The filesystem did not change size. Output: ' . trim(mb_substr($out, 0, 400))];
}

/* ================= STORAGE LAYOUT: drive types, sizes, RAID level, members, usage =================
 * Everything here is read-only: lsblk, /proc/mdstat and df. */

/** partition -> parent disk map (sda1->sda, nvme0n1p2->nvme0n1), built in one lsblk call. */
function smpro_bd_part_map() {
    static $m = null; if ($m !== null) return $m;
    $m = [];
    foreach (explode("\n", smpro_bd_sh('lsblk -nP -o NAME,PKNAME', 8)) as $l) {
        if (trim($l) === '') continue; $kv = [];
        if (preg_match_all('/(\w+)="([^"]*)"/', $l, $mm, PREG_SET_ORDER)) foreach ($mm as $p) $kv[$p[1]] = $p[2];
        if (!empty($kv['NAME']) && !empty($kv['PKNAME'])) $m[$kv['NAME']] = $kv['PKNAME'];
    }
    return $m;
}
/** mounted filesystems keyed by device path: type, size, used, use%, mount. */
function smpro_bd_mounts() {
    static $r = null; if ($r !== null) return $r;
    $r = [];
    foreach (explode("\n", smpro_bd_sh('df -PT', 10)) as $i => $l) {
        if ($i === 0 || trim($l) === '') continue;
        $p = preg_split('/\s+/', trim($l), 7);
        if (count($p) < 7 || strpos($p[0], '/dev/') !== 0) continue;
        $r[$p[0]] = ['fs' => $p[1], 'size_kb' => (int)$p[2], 'used_kb' => (int)$p[3],
                     'pct' => (int)rtrim($p[5], '%'), 'mount' => $p[6]];
    }
    return $r;
}
/** RAID arrays from /proc/mdstat: level, member DISKS (not partitions), health, plus fs/mount/usage. */
function smpro_bd_arrays() {
    $md = (string)@file_get_contents('/proc/mdstat');
    if (trim($md) === '') return [];
    $pmap = smpro_bd_part_map(); $mounts = smpro_bd_mounts();
    $out = []; $lines = explode("\n", $md);
    for ($i = 0; $i < count($lines); $i++) {
        if (!preg_match('/^(md\d+)\s*:\s*(\S+)\s+(raid\d+|linear|multipath)\s+(.*)$/', trim($lines[$i]), $m)) continue;
        $name = $m[1]; $level = strtoupper(str_replace('raid', 'RAID ', $m[3]));
        $members = [];
        foreach (preg_split('/\s+/', trim($m[4])) as $tok) {
            if (!preg_match('/^([A-Za-z0-9]+)\[\d+\]/', $tok, $mm)) continue;
            $part = $mm[1];
            $disk = $pmap[$part] ?? preg_replace('/(p?\d+)$/', '', $part);
            if ($disk !== '' && !in_array($disk, $members, true)) $members[] = $disk;
        }
        $state = ''; $degraded = false;
        for ($j = $i + 1; $j < min($i + 4, count($lines)); $j++) {
            if (preg_match('/\[([U_]+)\]/', $lines[$j], $sm)) { $state = $sm[1]; $degraded = strpos($sm[1], '_') !== false; break; }
        }
        $dev = '/dev/' . $name; $mi = $mounts[$dev] ?? null;
        $out[] = ['name' => $name, 'level' => $level, 'members' => $members, 'state' => $state,
                  'degraded' => $degraded, 'active' => (stripos($m[2], 'active') !== false),
                  'fs' => $mi['fs'] ?? '', 'mount' => $mi['mount'] ?? '',
                  'size_kb' => $mi['size_kb'] ?? 0, 'pct' => $mi['pct'] ?? null];
    }
    return $out;
}
/** Full layout: every physical drive (type/size/model) + every array, with a raw/usable summary. */
function smpro_bd_storage_layout() {
    $disks = smpro_bd_disks(); $arrays = smpro_bd_arrays(); $mounts = smpro_bd_mounts();
    $rawKb = 0;
    foreach ($disks as &$d) {
        $d['class'] = ($d['tran'] === 'nvme') ? 'nvme' : ($d['rota'] ? 'hdd' : 'ssd');
        $d['class_label'] = ['nvme' => 'NVMe SSD', 'ssd' => 'SATA/SAS SSD', 'hdd' => 'HDD ' . 'rotational'][$d['class']];
        $kb = (int)trim(smpro_bd_sh('lsblk -bdno SIZE /dev/' . escapeshellarg($d['name']) . ' 2>/dev/null', 6));
        $d['size_kb'] = (int)($kb / 1024); $rawKb += $d['size_kb'];
    }
    unset($d);
    $usableKb = 0; foreach ($arrays as $a) $usableKb += (int)$a['size_kb'];
    if (!$arrays) foreach ($mounts as $mi) $usableKb += (int)$mi['size_kb'];
    $freeKb = 0; foreach ($mounts as $mi) $freeKb += max(0, (int)$mi['size_kb'] - (int)$mi['used_kb']);
    return ['disks' => $disks, 'arrays' => $arrays,
            'raw_kb' => $rawKb, 'usable_kb' => $usableKb, 'free_kb' => $freeKb];
}

/* ================= GRADES: the 5 bands, applied to a measurement ================= */
function smpro_bd_grade_iops($iops) {
    if ($iops === null) return ['unknown', '—'];
    $v = (float)$iops;
    if ($v >= 80000) return ['excellent', 'Excellent'];
    if ($v >= 30000) return ['verygood',  'Very good'];
    if ($v >= 8000)  return ['good',      'Good'];
    if ($v >= 100)   return ['poor',      'Poor'];
    return ['failing', 'Failing'];
}
function smpro_bd_grade_seq($mbs) {
    if ($mbs === null) return ['unknown', '—'];
    $v = (float)$mbs;
    if ($v >= 1500) return ['excellent', 'Excellent'];
    if ($v >= 600)  return ['verygood',  'Very good'];
    if ($v >= 250)  return ['good',      'Good'];
    if ($v >= 80)   return ['poor',      'Poor'];
    return ['failing', 'Failing'];
}
function smpro_bd_grade_cls($g) {
    return ['excellent' => 'green', 'verygood' => 'green', 'good' => 'blue',
            'poor' => 'orange', 'failing' => 'red', 'unknown' => 'gray'][$g] ?? 'gray';
}
/** Log-scale position (0-100%) of an IOPS figure on the grade ruler (10 -> 500k). */
function smpro_bd_ruler_pos($iops) {
    $v = max(10, min(500000, (float)$iops));
    return round((log10($v) - 1) / (log10(500000) - 1) * 100, 1);
}

/* ================= PER-DEVICE TEST (physical disks are READ-ONLY tested) =================
 * A raw WRITE to a physical device would destroy the filesystem on it, so a single disk is
 * measured with strictly read-only probes: sequential read via dd O_DIRECT, and random-read
 * IOPS via fio on the raw device. A slow or dying disk shows up in reads too, and on a mirror
 * the slower member is what caps array writes - so this is enough to find the culprit.       */
if (!defined('SMPRO_BD_DEV')) define('SMPRO_BD_DEV', SMPRO_VARLIB . '/benchdiag_devices.json');
function smpro_bd_dev_results() {
    $d = @is_file(SMPRO_BD_DEV) ? json_decode((string)@file_get_contents(SMPRO_BD_DEV), true) : null;
    return is_array($d) ? $d : [];
}
function smpro_bd_dev_save($key, array $res) {
    $all = smpro_bd_dev_results(); $all[$key] = $res + ['ts' => time()];
    @is_dir(dirname(SMPRO_BD_DEV)) || @mkdir(dirname(SMPRO_BD_DEV), 0700, true);
    $t = SMPRO_BD_DEV . '.tmp';
    if (@file_put_contents($t, json_encode($all, JSON_UNESCAPED_SLASHES), LOCK_EX) !== false) { @chmod($t, 0600); @rename($t, SMPRO_BD_DEV); }
}
/** Read-only sequential read + random-read IOPS for ONE physical disk. Never writes. */
function smpro_bd_test_disk($dev) {
    $dev = preg_replace('/[^A-Za-z0-9]/', '', (string)$dev);
    if ($dev === '' || !@file_exists('/dev/' . $dev)) return ['err' => 'No such device'];
    $known = false; foreach (smpro_bd_disks() as $d) if ($d['name'] === $dev) { $known = true; break; }
    if (!$known) return ['err' => 'Not a whole physical disk'];
    $path = '/dev/' . $dev;
    // sequential read, O_DIRECT so the page cache cannot fake it
    $r = smpro_bm_dd_mbs('dd if=' . escapeshellarg($path) . ' of=/dev/null bs=1M count=1024 iflag=direct 2>&1', 120);
    if ($r === null) $r = smpro_bm_dd_mbs('dd if=' . escapeshellarg($path) . ' of=/dev/null bs=1M count=512 2>&1', 120);
    // random 4K read IOPS - read-only fio directly on the device
    $iops = null;
    if (smpro_bd_has('fio')) {
        $out = smpro_bd_sh('fio --name=r --filename=' . escapeshellarg($path) . ' --rw=randread --bs=4k --size=256M'
             . ' --numjobs=1 --runtime=6 --time_based --direct=1 --readonly --group_reporting --output-format=json', 40);
        $j = json_decode($out, true);
        $v = $j['jobs'][0]['read']['iops'] ?? null;
        if ($v !== null) $iops = (int)round($v);
    }
    return ['read_mbs' => $r, 'iops' => $iops, 'readonly' => true];
}
/** Run one device test synchronously and store it (called by the detached worker). */
function smpro_bd_run_devtest($kind, $target) {
    $kind = preg_replace('/[^a-z]/', '', strtolower((string)$kind));
    $res = [];
    if ($kind === 'disk')      { $res = smpro_bd_test_disk($target); $key = 'disk:' . preg_replace('/[^A-Za-z0-9]/', '', (string)$target); }
    elseif ($kind === 'cpu')   { $res = function_exists('smpro_bm_cpu') ? smpro_bm_cpu() : []; $key = 'cpu'; }
    elseif ($kind === 'ram')   { $res = function_exists('smpro_bm_ram') ? smpro_bm_ram() : []; $key = 'ram'; }
    elseif ($kind === 'php')   { $res = smpro_bd_php_bench(); $key = 'php'; }
    elseif ($kind === 'mysql') { $res = smpro_bd_mysql_bench(); $key = 'mysql'; }
    else return ['ok' => false, 'msg' => 'Unknown device.'];
    smpro_bd_dev_save($key, $res);
    smpro_bd_state_write(['status' => 'idle']);      // clear the per-device busy flag
    if (function_exists('smpro_audit')) @smpro_audit('benchdiag_devtest', ['kind' => $kind, 'target' => $target]);
    return ['ok' => true];
}
/** Spawn a single-device test detached. One at a time so tests never skew each other. */
function smpro_bd_devtest_start($kind, $target = '') {
    $st = smpro_bd_state();
    if (($st['status'] ?? '') === 'running' && (time() - (int)($st['started'] ?? 0)) < 600)
        return ['ok' => false, 'msg' => 'Another test is already running — only one runs at a time so results are not skewed.'];
    $kind = preg_replace('/[^a-z]/', '', strtolower((string)$kind));
    $target = preg_replace('/[^A-Za-z0-9]/', '', (string)$target);
    if (!in_array($kind, ['disk', 'cpu', 'ram', 'php', 'mysql'], true)) return ['ok' => false, 'msg' => 'Unknown device.'];
    smpro_bd_state_write(['status' => 'running', 'step' => $kind, 'dev' => $target, 'pct' => 5, 'started' => time(), 'results' => []]);
    $worker = SMPRO_BASE . '/bin/devtest.php';
    if (!@is_file($worker)) { smpro_bd_run_devtest($kind, $target); return ['ok' => true, 'msg' => 'Test complete.']; }
    $php = function_exists('smpro_bm_php_bin') ? smpro_bm_php_bin() : 'php';
    $pre = smpro_bd_has('setsid') ? 'setsid ' : 'nohup ';
    @shell_exec($pre . escapeshellarg($php) . ' ' . escapeshellarg($worker) . ' ' . escapeshellarg($kind) . ' ' . escapeshellarg($target) . ' >/dev/null 2>&1 </dev/null &');
    if (function_exists('smpro_audit')) @smpro_audit('benchdiag_devtest_start', ['kind' => $kind, 'target' => $target]);
    return ['ok' => true, 'msg' => 'Test started — it runs in the background and the result appears here.'];
}

/** Per-array read/write path analysis, using the per-disk read results as the member speeds. */
function smpro_bd_array_analysis() {
    $dev = smpro_bd_dev_results(); $out = [];
    foreach (smpro_bd_arrays() as $a) {
        $mem = [];
        foreach ($a['members'] as $mname) {
            $r = $dev['disk:' . $mname] ?? null;
            $mem[] = ['name' => $mname, 'read_mbs' => $r['read_mbs'] ?? null, 'iops' => $r['iops'] ?? null];
        }
        $known = array_values(array_filter(array_map(function ($m) { return $m['read_mbs']; }, $mem), function ($v) { return $v !== null; }));
        $slow = null; $slowest = null;
        foreach ($mem as $m) if ($m['read_mbs'] !== null && ($slowest === null || $m['read_mbs'] < $slowest)) { $slowest = $m['read_mbs']; $slow = $m['name']; }
        $lvl = $a['level'];
        $n = max(1, count($mem));
        if (stripos($lvl, 'RAID 1') !== false || stripos($lvl, 'RAID 10') !== false) {
            $wRule = 'every block is written to both mirrors, so write speed equals the SLOWEST member';
            $rRule = 'a read can be served by either member, so reads balance and approach ' . $n . '× a single disk';
            $wEff = $slowest; $rEff = $known ? array_sum($known) : null;
        } elseif (stripos($lvl, 'RAID 0') !== false) {
            $wRule = 'data is striped across all members, so both scale with the number of disks';
            $rRule = 'reads stripe across all members'; $wEff = $known ? array_sum($known) : null; $rEff = $wEff;
        } elseif (stripos($lvl, 'RAID 5') !== false || stripos($lvl, 'RAID 6') !== false) {
            $wRule = 'every small write costs a read-modify-write cycle, so random writes fall well below the members';
            $rRule = 'reads spread across the data disks'; $wEff = $slowest; $rEff = $known ? array_sum($known) * 0.8 : null;
        } else { $wRule = ''; $rRule = ''; $wEff = $slowest; $rEff = $known ? array_sum($known) : null; }
        // is one member dragging the array down?
        $drag = null;
        if (count($known) > 1 && $slowest !== null) {
            $fastest = max($known);
            if ($fastest > 0 && $slowest < $fastest * 0.7) $drag = ['name' => $slow, 'slow' => $slowest, 'fast' => $fastest];
        }
        $out[] = $a + ['members_detail' => $mem, 'w_rule' => $wRule, 'r_rule' => $rRule,
                       'w_eff' => $wEff, 'r_eff' => $rEff, 'slowest' => $slow, 'drag' => $drag,
                       'tested' => count($known), 'total_members' => count($mem)];
    }
    return $out;
}

/* ================= HARDWARE HEALTH (SMART / RAID / ECC memory) ================= */
function smpro_bd_smart_one($dev) {
    $raw = smpro_bd_sh('smartctl -H -A -i /dev/' . escapeshellarg($dev), 20);
    if (trim($raw) === '') $raw = smpro_bd_sh('smartctl -d sat -H -A -i /dev/' . escapeshellarg($dev), 20);
    if (trim($raw) === '') return null;
    $r = ['dev' => $dev, 'health' => '', 'attrs' => []];
    if (preg_match('/SMART overall-health self-assessment test result:\s*(\S+)/i', $raw, $m)) $r['health'] = strtoupper($m[1]);
    elseif (preg_match('/SMART Health Status:\s*(\S+)/i', $raw, $m)) $r['health'] = strtoupper($m[1]);
    $grab = function ($name) use ($raw) {
        if (preg_match('/^\s*\d+\s+' . preg_quote($name, '/') . '\s+.*?(\d+)\s*$/mi', $raw, $m)) return (int)$m[1];
        return null;
    };
    $r['realloc'] = $grab('Reallocated_Sector_Ct');
    $r['pending'] = $grab('Current_Pending_Sector');
    $r['uncorr']  = $grab('Offline_Uncorrectable');
    $r['hours']   = $grab('Power_On_Hours');
    // NVMe / modern SSD style fields
    if (preg_match('/Percentage Used:\s*(\d+)%/i', $raw, $m))               $r['used_pct'] = (int)$m[1];
    if (preg_match('/Media and Data Integrity Errors:\s*([\d,]+)/i', $raw, $m)) $r['media_err'] = (int)str_replace(',', '', $m[1]);
    if (preg_match('/Critical Warning:\s*(\S+)/i', $raw, $m))               $r['critical'] = $m[1];
    if (preg_match('/Power On Hours:\s*([\d,]+)/i', $raw, $m))              $r['hours'] = (int)str_replace(',', '', $m[1]);
    if (preg_match('/Temperature:\s*(\d+) Celsius/i', $raw, $m))            $r['temp'] = (int)$m[1];
    elseif (($t = $grab('Temperature_Celsius')) !== null)                   $r['temp'] = $t;
    if (($wl = $grab('Wear_Leveling_Count')) !== null && !isset($r['used_pct'])) $r['wear_left'] = $wl;
    if (preg_match('/Device Model:\s*(.+)/i', $raw, $m))                    $r['model'] = trim($m[1]);
    elseif (preg_match('/Model Number:\s*(.+)/i', $raw, $m))                $r['model'] = trim($m[1]);
    // ---- lifetime totals: bytes written / read since manufacture ----
    // NVMe: smartctl prints the human total in brackets, e.g. "Data Units Written: 12,345,678 [6.32 TB]".
    if (preg_match('/Data Units Written:.*\[([^\]]+)\]/i', $raw, $m)) $r['written_h'] = trim($m[1]);
    if (preg_match('/Data Units Read:.*\[([^\]]+)\]/i', $raw, $m))    $r['read_h']    = trim($m[1]);
    // ATA/SATA: Total_LBAs_Written / _Read attributes -> bytes via the logical sector size.
    $sec = 512; if (preg_match('/Sector Sizes?:\s*(\d+)\s*bytes logical/i', $raw, $m)) $sec = (int)$m[1];
    elseif (preg_match('/Logical block size:\s*(\d+)/i', $raw, $m)) $sec = (int)$m[1];
    if (!isset($r['written_h']) && ($lw = $grab('Total_LBAs_Written')) !== null && $lw > 0) $r['written_bytes'] = (float)$lw * $sec;
    if (!isset($r['read_h'])    && ($lr = $grab('Total_LBAs_Read'))    !== null && $lr > 0) $r['read_bytes']    = (float)$lr * $sec;
    // Host writes on some enterprise SSDs (in GiB)
    if (!isset($r['written_h']) && !isset($r['written_bytes']) && ($gw = $grab('Host_Writes_GiB')) !== null && $gw > 0) $r['written_bytes'] = (float)$gw * 1073741824;
    return $r;
}
/** Bytes -> "1.23 TB". */
function smpro_bd_bytes_h($b) {
    $b = (float)$b; if ($b <= 0) return '—';
    $u = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']; $i = 0;
    while ($b >= 1024 && $i < 5) { $b /= 1024; $i++; }
    return ($b >= 100 ? round($b) : round($b, 2)) . ' ' . $u[$i];
}
/** Health 0-100% for one drive, from its SMART wear + defect indicators. */
function smpro_bd_disk_health_pct($s) {
    $h = isset($s['used_pct']) ? max(0, 100 - (int)$s['used_pct']) : 100;   // SSD/NVMe wear is the primary signal
    if (!empty($s['pending']))  $h = min($h, 35);                            // unreadable sectors = failing
    if (!empty($s['realloc']))  $h -= min(50, (int)$s['realloc'] * 2);       // each remapped sector chips away
    if (!empty($s['uncorr']))   $h = min($h, 25);
    if (!empty($s['media_err'])) $h = min($h, 30);
    if (isset($s['critical']) && !preg_match('/^(0x00|0)$/i', trim((string)$s['critical']))) $h = min($h, 20);
    $ok = ($s['health'] ?? '') === '' || in_array($s['health'], ['PASSED', 'OK'], true);
    if (!$ok) $h = min($h, 8);                                               // SMART already says it is failing
    return max(0, min(100, (int)round($h)));
}
/** Performance 0-100% for one drive: its measured speed against what a HEALTHY drive of its class does. */
function smpro_bd_disk_perf_pct($dev, $class) {
    $r = smpro_bd_dev_results()['disk:' . $dev] ?? null;
    if (!$r) return null;                                                    // not tested yet
    $ref = ['nvme' => ['r' => 2500, 'i' => 200000], 'ssd' => ['r' => 480, 'i' => 40000], 'hdd' => ['r' => 190, 'i' => 150]][$class]
         ?? ['r' => 400, 'i' => 10000];
    $parts = [];
    if (($r['read_mbs'] ?? null) !== null) $parts[] = min(100, (float)$r['read_mbs'] / $ref['r'] * 100);
    if (($r['iops'] ?? null) !== null)     $parts[] = min(100, (float)$r['iops']    / $ref['i'] * 100);
    if (!$parts) return null;
    return (int)round(array_sum($parts) / count($parts));                    // read + random, averaged
}
function smpro_bd_hw_health() {
    $out = ['disks' => [], 'findings' => [], 'raid' => '', 'ecc' => null, 'smart_ok' => smpro_bd_has('smartctl')];
    $add = function ($sev, $title, $detail, $rec) use (&$out) {
        // Not compact() - obfuscation breaks it silently; see dbhealth.php.
        $out['findings'][] = ['sev' => $sev, 'title' => $title, 'detail' => $detail, 'rec' => $rec];
    };

    /* --- disks --- */
    if ($out['smart_ok']) {
        foreach (smpro_bd_disks() as $d) {
            $s = smpro_bd_smart_one($d['name']);
            if (!$s) continue;
            $s['size'] = $d['size']; $s['tran'] = $d['tran']; $s['rota'] = $d['rota'];
            $out['disks'][] = $s;
            $dn = '/dev/' . $d['name'];
            if ($s['health'] !== '' && $s['health'] !== 'PASSED' && $s['health'] !== 'OK')
                $add('critical', $dn . ' — SMART reports the drive as FAILING',
                     'The drive\'s own self-assessment has failed. Manufacturers only report this when failure is imminent or already occurring.',
                     'Replace this disk now. Verify your backups first, and if it is part of a RAID array replace it before a second disk goes.');
            if (!empty($s['pending']))
                $add('critical', $dn . ' — ' . $s['pending'] . ' pending (unreadable) sector(s)',
                     'Sectors that could not be read and are waiting to be reallocated. This is the strongest early warning of a dying disk and often means data is already unreadable.',
                     'Back up immediately and replace the disk. Do not ignore this one.');
            if (!empty($s['realloc']))
                $add($s['realloc'] > 50 ? 'high' : 'medium', $dn . ' — ' . $s['realloc'] . ' reallocated sector(s)',
                     'The drive has moved damaged sectors to spare area. A handful can be stable for years; a growing count means the surface is degrading.',
                     'Watch the count over time. If it grows, replace the disk. Make sure it is not the only copy of anything.');
            if (!empty($s['media_err']))
                $add('high', $dn . ' — ' . $s['media_err'] . ' media/data-integrity error(s)',
                     'The NVMe controller reported unrecoverable data errors.', 'Plan a replacement and verify backups.');
            if (isset($s['used_pct']) && $s['used_pct'] >= 80)
                $add($s['used_pct'] >= 90 ? 'high' : 'medium', $dn . ' — SSD is ' . $s['used_pct'] . '% through its rated write endurance',
                     'The flash has used most of its designed write life. Past 100% the drive may go read-only or fail.',
                     'Schedule a replacement. For a write-heavy hosting workload choose a higher-endurance (≥1 DWPD) datacentre SSD next time.');
            if (isset($s['temp']) && $s['temp'] >= 60)
                $add($s['temp'] >= 70 ? 'high' : 'medium', $dn . ' — running hot (' . $s['temp'] . '°C)',
                     'Sustained high temperature shortens flash life and makes SSDs throttle, which shows up as sudden slowness.',
                     'Improve airflow / check fans and dust. NVMe drives benefit from a heatsink.');
        }
    } else {
        $add('low', 'Disk health cannot be read — smartmontools is not installed',
             'Without smartctl the plugin cannot see reallocated sectors, pending sectors, SSD wear or drive temperature, so a failing disk gives no warning here.',
             'Install it: dnf install smartmontools (or yum/apt). It is read-only monitoring and safe on a production server.');
    }

    /* --- RAID --- */
    $md = (string)@file_get_contents('/proc/mdstat');
    if (trim($md) !== '' && strpos($md, 'md') !== false) {
        $out['raid'] = trim($md);
        if (preg_match_all('/\[([U_]+)\]/', $md, $mm)) {
            foreach ($mm[1] as $st) if (strpos($st, '_') !== false) {
                $add('critical', 'RAID array is DEGRADED [' . $st . ']',
                     'One or more member disks have dropped out of the array. You are running without redundancy — a second failure means data loss.',
                     'Identify the failed member (cat /proc/mdstat), replace it and rebuild the array as soon as possible.');
                break;
            }
        }
        if (stripos($md, 'recovery') !== false || stripos($md, 'resync') !== false)
            $add('medium', 'RAID array is rebuilding/resyncing',
                 'The array is rebuilding. Disk performance is reduced until it finishes, and redundancy is incomplete.',
                 'Let it finish before doing heavy maintenance; benchmark results taken now will be pessimistic.');
    }

    /* --- ECC memory --- */
    $ce = 0; $ue = 0; $seen = false;
    foreach (glob('/sys/devices/system/edac/mc/mc*/ce_count') ?: [] as $f) { $seen = true; $ce += (int)trim((string)@file_get_contents($f)); }
    foreach (glob('/sys/devices/system/edac/mc/mc*/ue_count') ?: [] as $f) { $ue += (int)trim((string)@file_get_contents($f)); }
    if ($seen) {
        $out['ecc'] = ['ce' => $ce, 'ue' => $ue];
        if ($ue > 0) $add('critical', 'Memory: ' . $ue . ' UNCORRECTABLE ECC error(s)',
            'RAM returned data the ECC could not repair. This corrupts whatever was in that memory — it causes random crashes and can silently damage data written to disk.',
            'Identify and replace the faulty DIMM (check the EDAC logs / dmesg for the slot), and run a memory test. Treat this as urgent.');
        elseif ($ce > 1000) $add('medium', 'Memory: ' . number_format($ce) . ' corrected ECC errors',
            'ECC has been silently correcting a large number of single-bit errors. Corrected errors are not dangerous by themselves, but a high and growing count usually precedes an uncorrectable one.',
            'Note which DIMM is reporting them and plan to replace it at the next maintenance window.');
    }

    $rank = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3];
    usort($out['findings'], function ($a, $b) use ($rank) { return ($rank[$a['sev']] ?? 9) <=> ($rank[$b['sev']] ?? 9); });
    $out['verdict'] = 'Healthy';
    foreach ($out['findings'] as $f) { if ($f['sev'] === 'critical') { $out['verdict'] = 'Failing'; break; } if ($f['sev'] === 'high') $out['verdict'] = 'Needs attention'; }
    return $out;
}

/* ================= DIAGNOSTICS ================= */

/* ---------------- kernel: sysctl posture ---------------- */
/** The portable sysctl targets we check. `fix`=true ⇒ safe + reversible ⇒ gets a one-click button. */
function smpro_bd_sysctl_targets() {
    return [
        ['key' => 'vm.swappiness',                'want' => 10,    'cmp' => 'lte', 'fix' => true,
         'label' => 'Swap aggressiveness',
         'why'  => 'How eagerly the kernel pushes memory out to swap. A high value makes a server with free RAM swap anyway, which shows up as random slowness.',
         'rec'  => 'Set to 10 so the kernel only swaps when it genuinely needs to.'],
        ['key' => 'net.core.somaxconn',           'want' => 1024,  'cmp' => 'gte', 'fix' => true,
         'label' => 'Socket accept backlog',
         'why'  => 'How many finished connections can queue waiting to be accepted. Too small and a traffic burst drops connections before your web server ever sees them.',
         'rec'  => 'Raise to at least 1024 on a public web server.'],
        ['key' => 'net.ipv4.tcp_max_syn_backlog', 'want' => 2048,  'cmp' => 'gte', 'fix' => true,
         'label' => 'SYN (half-open) backlog',
         'why'  => 'Queue for connections still completing the TCP handshake. Too small and legitimate visitors are dropped during bursts or a SYN flood.',
         'rec'  => 'Raise to at least 2048.'],
        ['key' => 'fs.file-max',                  'want' => 200000,'cmp' => 'gte', 'fix' => true,
         'label' => 'Max open files (system-wide)',
         'why'  => 'Every connection, log and file handle counts. Hitting this ceiling causes "too many open files" errors across services.',
         'rec'  => 'Raise to at least 200000 on a busy cPanel server.'],
        ['key' => 'net.ipv4.tcp_fin_timeout',     'want' => 30,    'cmp' => 'lte', 'fix' => true,
         'label' => 'TCP FIN timeout',
         'why'  => 'How long a closed connection sits in FIN-WAIT holding a port. A long timeout wastes ports on a busy server.',
         'rec'  => 'Lower to 30s to recycle ports faster.'],
    ];
}
function smpro_bd_sysctl_get($key) {
    $v = trim(smpro_bd_sh('sysctl -n ' . escapeshellarg($key), 5));
    return $v === '' ? null : $v;
}
function smpro_bd_kernel_findings() {
    $F = [];
    foreach (smpro_bd_sysctl_targets() as $t) {
        $cur = smpro_bd_sysctl_get($t['key']);
        if ($cur === null) continue;                       // not present on this kernel - skip silently
        $curN = (float)$cur; $want = (float)$t['want'];
        $bad = ($t['cmp'] === 'gte') ? ($curN < $want) : ($curN > $want);
        if (!$bad) continue;
        $F[] = ['sev' => 'medium', 'area' => 'kernel', 'id' => 'sysctl:' . $t['key'],
                'title' => $t['label'] . ' — ' . $t['key'] . ' is ' . $cur,
                'evidence' => $t['key'] . ' = ' . $cur . ' · recommended ' . ($t['cmp'] === 'gte' ? '≥ ' : '≤ ') . $t['want'],
                'detail' => $t['why'], 'rec' => $t['rec'],
                'fix' => $t['fix'] ? ['action' => 'sysctl', 'key' => $t['key'], 'to' => (string)$t['want'],
                                      'label' => 'Set to ' . $t['want'] . ' (live)'] : null];
    }
    return $F;
}

/* ---------------- kernel: dmesg health scan (advisory - these need investigation, not a toggle) ---------------- */
function smpro_bd_dmesg_findings() {
    $raw = smpro_bd_sh('dmesg -T 2>/dev/null | tail -n 4000', 12);
    if (trim($raw) === '') $raw = smpro_bd_sh('dmesg 2>/dev/null | tail -n 4000', 12);
    if (trim($raw) === '') return [];
    $pats = [
        ['re' => '/Out of memory: Kill|oom-kill|invoked oom-killer/i', 'sev' => 'high', 'id' => 'oom',
         'title' => 'Kernel OOM killer has killed processes',
         'detail' => 'The kernel ran out of memory and killed processes to survive. Whatever it killed (often MySQL or PHP workers) went down abruptly — this causes sudden outages and corrupted-looking behaviour.',
         'rec' => 'Find what consumes the RAM (Top Processes / Database Health buffer pool), add RAM or swap, and cap per-account memory. Check which process was killed in the log line.'],
        ['re' => '/blocked for more than \d+ seconds|hung_task/i', 'sev' => 'high', 'id' => 'hung',
         'title' => 'Tasks hung waiting on I/O',
         'detail' => 'A process was stuck in uninterruptible I/O for over two minutes. This is the kernel telling you storage is not keeping up (or a disk/controller is failing) — it is a classic cause of "the whole server froze".',
         'rec' => 'Check disk health and I/O load (Disk / Storage → Disk I/O busy%), and the disk benchmark below. If a specific device is implicated, check its SMART data.'],
        ['re' => '/I\/O error|critical medium error|blk_update_request.*error|ata\d+.*failed command/i', 'sev' => 'critical', 'id' => 'ioerr',
         'title' => 'Disk I/O errors reported by the kernel',
         'detail' => 'The kernel logged real read/write errors from a block device. This usually means a failing disk or cable/controller fault — data loss risk.',
         'rec' => 'Identify the device in the log line, check SMART immediately, and plan a replacement / verify your RAID and backups before it fails completely.'],
        ['re' => '/EXT4-fs error|XFS.*(corruption|error)|Remounting filesystem read-only/i', 'sev' => 'critical', 'id' => 'fserr',
         'title' => 'Filesystem errors',
         'detail' => 'The filesystem reported corruption, or was remounted read-only to protect itself. Sites and databases will fail to write.',
         'rec' => 'Check the affected filesystem, verify backups, and schedule a checked reboot / fsck (see Reboot readiness in Service Manager).'],
        ['re' => '/segfault at |general protection fault/i', 'sev' => 'medium', 'id' => 'segv',
         'title' => 'Processes crashing (segfault)',
         'detail' => 'One or more processes crashed with a segmentation fault. Repeated segfaults in a service (php, httpd, mysqld) point at a broken module/extension or bad memory.',
         'rec' => 'Identify the crashing binary in the log line; update or disable the offending extension/module. Persistent random segfaults across services can indicate failing RAM.'],
        ['re' => '/nf_conntrack: table full|conntrack table full/i', 'sev' => 'high', 'id' => 'conntrack',
         'title' => 'Connection-tracking table full — packets dropped',
         'detail' => 'The firewall connection-tracking table filled up, so the kernel started dropping new connections. Visitors see random timeouts even though the server looks idle.',
         'rec' => 'Raise net.netfilter.nf_conntrack_max (and the hashsize), and look for whatever is opening huge numbers of connections (a flood or a scraper).'],
        ['re' => '/TCP: out of memory|out of socket memory/i', 'sev' => 'high', 'id' => 'tcpmem',
         'title' => 'TCP ran out of socket memory',
         'detail' => 'The network stack could not allocate memory for sockets — connections get dropped under load.',
         'rec' => 'Raise net.ipv4.tcp_mem / net.core.rmem_max·wmem_max, and investigate the connection volume.'],
    ];
    $F = [];
    foreach ($pats as $p) {
        $n = preg_match_all($p['re'], $raw, $m);
        if (!$n) continue;
        // last matching line for context (trimmed, no payload leakage concerns - kernel text)
        $last = '';
        foreach (array_reverse(explode("\n", $raw)) as $l) { if (preg_match($p['re'], $l)) { $last = trim($l); break; } }
        $F[] = ['sev' => $p['sev'], 'area' => 'kernel', 'id' => 'dmesg:' . $p['id'],
                'title' => $p['title'] . ' (' . $n . ' event' . ($n === 1 ? '' : 's') . ' in the kernel log)',
                'evidence' => function_exists('mb_substr') ? mb_substr($last, 0, 220) : substr($last, 0, 220),
                'detail' => $p['detail'], 'rec' => $p['rec'], 'fix' => null];
    }
    return $F;
}

/* ---------------- software / PHP posture ---------------- */
function smpro_bd_php_info() {
    $out = ['ea' => [], 'default' => '', 'opcache' => null];
    foreach (glob('/opt/cpanel/ea-php*/root/usr/bin/php') ?: [] as $bin) {
        if (!@is_executable($bin)) continue;
        if (preg_match('#ea-php(\d+)#', $bin, $m)) {
            $v = trim(smpro_bd_sh(escapeshellarg($bin) . " -r 'echo PHP_VERSION;'", 8));
            $out['ea'][] = ['tag' => 'ea-php' . $m[1], 'bin' => $bin, 'version' => $v];
        }
    }
    // cPanel's own default handler version (best effort)
    $d = trim(smpro_bd_sh("/usr/local/cpanel/bin/whmapi1 --output=json php_get_system_default_version 2>/dev/null | sed -n 's/.*\"version\":\"\\([^\"]*\\)\".*/\\1/p'", 10));
    $out['default'] = $d;
    // OPcache posture of the default (or newest) EA-PHP
    $pick = '';
    foreach ($out['ea'] as $e) if ($d !== '' && $e['tag'] === $d) $pick = $e['bin'];
    if ($pick === '' && $out['ea']) $pick = $out['ea'][count($out['ea']) - 1]['bin'];
    if ($pick !== '') {
        $ini = smpro_bd_sh(escapeshellarg($pick) . " -r 'echo (int)ini_get(\"opcache.enable\"),\"|\",ini_get(\"opcache.memory_consumption\"),\"|\",ini_get(\"opcache.max_accelerated_files\"),\"|\",ini_get(\"memory_limit\"),\"|\",ini_get(\"max_execution_time\");'", 10);
        $p = explode('|', trim($ini));
        if (count($p) >= 5) $out['opcache'] = ['enabled' => (int)$p[0], 'memory_mb' => (int)$p[1], 'max_files' => (int)$p[2],
                                               'memory_limit' => $p[3], 'max_exec' => $p[4], 'bin' => $pick];
    }
    return $out;
}
function smpro_bd_php_findings() {
    $F = []; $i = smpro_bd_php_info();
    // End-of-life PHP versions still installed (portable list; 7.x and older are all EOL as of 2024+)
    $eol = [];
    foreach ($i['ea'] as $e) if (preg_match('/^(\d+)\.(\d+)/', $e['version'], $m) && ((int)$m[1] < 8 || ((int)$m[1] === 8 && (int)$m[2] < 1))) $eol[] = $e['tag'] . ' (' . $e['version'] . ')';
    if ($eol) {
        $F[] = ['sev' => 'medium', 'area' => 'software', 'id' => 'php_eol',
            'title' => count($eol) . ' end-of-life PHP version' . (count($eol) === 1 ? '' : 's') . ' installed',
            'evidence' => implode(', ', $eol),
            'detail' => 'These PHP versions no longer receive security fixes. Any account still running on them is exposed, and they are also markedly slower than current PHP.',
            'rec' => 'Move accounts to PHP 8.1+ (MultiPHP Manager), then remove the unused old versions. Newer PHP is both safer and significantly faster.', 'fix' => null];
    }
    if (is_array($i['opcache'])) {
        $o = $i['opcache'];
        if (empty($o['enabled'])) {
            $F[] = ['sev' => 'high', 'area' => 'software', 'id' => 'opcache_off',
                'title' => 'OPcache is OFF for the default PHP',
                'evidence' => 'opcache.enable=0 on ' . $o['bin'],
                'detail' => 'Without OPcache, PHP re-compiles every script on every single request. Turning it on is typically the single biggest, cheapest speed win on a PHP server — often 2-3x faster page generation.',
                'rec' => 'Enable OPcache for the server PHP. Server Tune-up has a one-click, reversible OPcache action.',
                'fix' => ['action' => 'link', 'page' => 'server-tuning', 'label' => 'Open Server Tune-up']];
        } elseif ((int)$o['memory_mb'] > 0 && (int)$o['memory_mb'] < 128) {
            $F[] = ['sev' => 'low', 'area' => 'software', 'id' => 'opcache_small',
                'title' => 'OPcache memory is small (' . (int)$o['memory_mb'] . 'M)',
                'evidence' => 'opcache.memory_consumption=' . (int)$o['memory_mb'] . 'M, max_accelerated_files=' . (int)$o['max_files'],
                'detail' => 'On a server with many sites the compiled-script cache fills up and starts evicting, so scripts get re-compiled anyway and you lose part of the benefit.',
                'rec' => 'Raise opcache.memory_consumption (e.g. 192-256M) and max_accelerated_files (e.g. 16000) for a busy multi-site server.', 'fix' => null];
        }
    }
    return $F;
}

/** All diagnostics, ranked. */
function smpro_bd_diagnose() {
    $F = array_merge(smpro_bd_kernel_findings(), smpro_bd_dmesg_findings(), smpro_bd_php_findings());
    $rank = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3];
    usort($F, function ($a, $b) use ($rank) { return ($rank[$a['sev']] ?? 9) <=> ($rank[$b['sev']] ?? 9); });
    return $F;
}
function smpro_bd_kernel_info() {
    return [
        'release' => trim(smpro_bd_sh('uname -r', 5)),
        'os'      => trim(smpro_bd_sh("sed -n 's/^PRETTY_NAME=\"\\(.*\\)\"/\\1/p' /etc/os-release", 5)),
        'uptime'  => trim(smpro_bd_sh("awk '{print int($1)}' /proc/uptime", 5)),
    ];
}

/* ================= LIVE payload + off-render caching =================
 * SMART (smartctl per disk), the dmesg scan and probing every EA-PHP binary are far too slow to run
 * on a page render - on a box with several disks and 8 PHP versions that is many seconds. They are
 * cached with a TTL and refreshed by the JSON poll, exactly like the hardware inventory. The page
 * render reads cache-only, so it opens instantly and then fills in. */
function smpro_bd_cache($key, $ttl, $compute, callable $producer) {
    $f = SMPRO_VARLIB . '/bd_' . preg_replace('/[^a-z0-9_]/', '', $key) . '.json';
    $d = @is_file($f) ? json_decode((string)@file_get_contents($f), true) : null;
    if (is_array($d) && array_key_exists('v', $d) && (time() - (int)($d['ts'] ?? 0)) < $ttl) return $d['v'];
    if (!$compute) return (is_array($d) && array_key_exists('v', $d)) ? $d['v'] : null;   // stale beats blocking
    $v = $producer();
    @is_dir(dirname($f)) || @mkdir(dirname($f), 0700, true);
    $t = $f . '.tmp';
    if (@file_put_contents($t, json_encode(['ts' => time(), 'v' => $v], JSON_UNESCAPED_SLASHES), LOCK_EX) !== false) { @chmod($t, 0600); @rename($t, $f); }
    return $v;
}
function smpro_bd_hw_health_cached($compute = true, $ttl = 300) { return smpro_bd_cache('hw',   $ttl, $compute, 'smpro_bd_hw_health'); }
function smpro_bd_diagnose_cached($compute = true, $ttl = 300)  { return smpro_bd_cache('diag', $ttl, $compute, 'smpro_bd_diagnose'); }

/** Everything the page polls for: live gauges, disks, inventory, run state, and the cached heavy sections. */
function smpro_bd_live_payload() {
    $out = ['bench' => smpro_bd_state()];
    if (function_exists('smpro_bm_inventory'))  $out['inv']  = smpro_bm_inventory(true);
    if (function_exists('smpro_collect_metrics')) $out['live'] = smpro_collect_metrics();
    if (function_exists('smpro_ds_diskio') && function_exists('smpro_ds_diskio_payload')) {
        $p = smpro_ds_diskio_payload(smpro_ds_diskio());
        $out['disks'] = $p['devices'] ?? [];
    }
    $hw   = smpro_bd_hw_health_cached(true);
    $diag = smpro_bd_diagnose_cached(true);
    $out['hw_html']    = is_array($hw)   ? smpro_bd_hw_html($hw)     : '';
    $out['diag_html']  = is_array($diag) ? smpro_bd_diag_html($diag) : '';
    $out['stor_html']  = smpro_bd_storage_html();      // drive list + per-device test state
    $out['ruler_html'] = smpro_bd_ruler_html();
    $out['path_html']  = smpro_bd_path_html();
    $out['life_html']  = smpro_bd_life_html();          // drive lifetime / wear / health% / performance%
    $out['hw_verdict'] = is_array($hw)   ? ($hw['verdict'] ?? '')    : '';
    $out['diag_n']     = is_array($diag) ? count($diag)              : 0;
    return $out;
}

/* ---------------- storage layout + per-device tests: rendered server-side, refreshed by the poll ---------------- */
function smpro_bd_kb_h($kb) {
    $b = (float)$kb * 1024; $u = ['KB','MB','GB','TB','PB']; $i = 0; $b /= 1024;
    while ($b >= 1024 && $i < 4) { $b /= 1024; $i++; }
    return ($b >= 100 ? round($b) : round($b, 1)) . ' ' . $u[$i];
}
function smpro_bd_storage_html() {
    $L = smpro_bd_storage_layout();
    $dev = smpro_bd_dev_results();
    $st = smpro_bd_state();
    $busyDev = (($st['status'] ?? '') === 'running') ? (string)($st['dev'] ?? '') : '';
    $busyKind = (($st['status'] ?? '') === 'running') ? (string)($st['step'] ?? '') : '';
    $anyBusy = ($st['status'] ?? '') === 'running';
    $h = '';

    /* summary tiles */
    $nA = count($L['arrays']); $lvls = [];
    foreach ($L['arrays'] as $a) $lvls[$a['level']] = ($lvls[$a['level']] ?? 0) + 1;
    $lvlTxt = [];
    foreach ($lvls as $lv => $c) $lvlTxt[] = ($c > 1 ? $c . ' × ' : '') . $lv;
    $h .= '<div class="bd-tiles">'
        . '<div class="bd-tile"><div class="k">Physical drives</div><div class="v">' . count($L['disks']) . ' · ' . smpro_bd_kb_h($L['raw_kb']) . ' raw</div><div class="s">'
        . implode(' + ', array_map(function ($c) { return $c; }, (function ($ds) {
              $n = []; foreach ($ds as $d) $n[$d['class_label']] = ($n[$d['class_label']] ?? 0) + 1;
              $o = []; foreach ($n as $k => $v) $o[] = $v . '× ' . $k; return $o; })($L['disks']))) . '</div></div>'
        . '<div class="bd-tile"><div class="k">Arrays</div><div class="v">' . ($nA ? smpro_h(implode(' · ', $lvlTxt)) : 'none') . '</div><div class="s">'
        . ($nA ? smpro_bd_kb_h($L['usable_kb']) . ' usable' : 'no software RAID detected') . '</div></div>'
        . '<div class="bd-tile"><div class="k">Free space</div><div class="v">' . smpro_bd_kb_h($L['free_kb']) . '</div><div class="s">across mounted filesystems</div></div>'
        . '</div>';

    /* physical drives - collapsed, with a summary that keeps any warning visible */
    $bad = 0; $rows = '';
    foreach ($L['disks'] as $d) {
        $r = $dev['disk:' . $d['name']] ?? null;
        $g = $r ? smpro_bd_grade_iops($r['iops'] ?? null) : ['unknown', '—'];
        if ($r && ($r['iops'] ?? null) === null) $g = smpro_bd_grade_seq($r['read_mbs'] ?? null);
        if (in_array($g[0], ['poor', 'failing'], true)) $bad++;
        $cls = $g[0] === 'failing' ? ' bd-dangrow' : ($g[0] === 'poor' ? ' bd-warnrow' : '');
        $isBusy = ($busyKind === 'disk' && $busyDev === $d['name']);
        if ($isBusy) $cls = ' bd-runrow';
        $out = $isBusy
            ? '<div class="bd-prg"><i></i></div><div class="bd-prgt">Reading device…</div>'
            : ($r ? (($r['read_mbs'] ?? null) !== null ? '<span class="mono">' . round($r['read_mbs']) . ' MB/s read</span>' : '<span class="meta">no result</span>')
                    . (($r['iops'] ?? null) !== null ? ' <span class="mono meta">· ' . number_format((int)$r['iops']) . ' IOPS</span>' : '')
                  : '<span class="meta" style="font-style:italic">Not tested yet</span>');
        $btn = $isBusy ? '<button class="tp-btn" disabled>Running</button>'
             : '<button class="tp-btn bd-devtest" type="button" data-kind="disk" data-target="' . smpro_h($d['name']) . '"' . ($anyBusy ? ' disabled' : '') . '>'
               . ($r ? 'Re-test' : 'Test') . '</button>';
        $rows .= '<div class="bd-row' . $cls . '">'
              . '<div class="bd-dv"><b class="mono">' . smpro_h($d['name']) . '</b><span>' . smpro_h(trim($d['model'] . ' · ' . $d['class_label'] . ' · ' . $d['size'])) . '</span></div>'
              . '<div class="bd-mini">' . smpro_h($d['size']) . '</div>'
              . '<div class="bd-out">' . $out . '</div>'
              . '<div><span class="b ' . smpro_bd_grade_cls($g[0]) . '">' . smpro_h($g[1]) . '</span></div>'
              . '<div class="bd-act">' . $btn . '</div></div>';
    }
    $h .= '<button class="bd-ghd" aria-expanded="false" aria-controls="bdDrives">'
        . '<span class="bd-chev">&#9654;</span><span>Physical drives</span>'
        . '<span class="rt">' . count($L['disks']) . ' drives · read-only test'
        . ($bad ? ' <span class="b red">' . $bad . ' need attention</span>' : '') . '</span></button>'
        . '<div id="bdDrives" hidden>' . $rows . '</div>';

    /* arrays - read-only */
    if ($L['arrays']) {
        $ar = '';
        foreach (smpro_bd_array_analysis() as $a) {
            $stTag = $a['degraded'] ? '<span class="b red">DEGRADED [' . smpro_h($a['state']) . ']</span>'
                                    : '<span class="b green">Clean' . ($a['state'] !== '' ? ' [' . smpro_h($a['state']) . ']' : '') . '</span>';
            $ar .= '<div class="bd-row' . ($a['degraded'] ? ' bd-dangrow' : '') . '">'
                . '<div class="bd-dv"><b class="mono">' . smpro_h($a['name']) . '</b><span>' . smpro_h($a['level'] . ' · ' . implode(' + ', $a['members']) . ($a['mount'] !== '' ? ' · mounted on ' . $a['mount'] : '')) . '</span></div>'
                . '<div class="bd-mini">' . ($a['size_kb'] ? smpro_bd_kb_h($a['size_kb']) : '—') . ($a['pct'] !== null ? ' · <b>' . (int)$a['pct'] . '%</b> used' : '') . '</div>'
                . '<div class="bd-out">' . $stTag . ' <span class="mono meta">' . smpro_h($a['fs']) . '</span></div>'
                . '<div><span class="b gray">Read-only</span></div>'
                . '<div class="bd-act"><button class="tp-btn" disabled title="Arrays are never tested or modified">No actions</button></div></div>';
        }
        $h .= '<button class="bd-ghd" aria-expanded="true" aria-controls="bdArrays">'
            . '<span class="bd-chev">&#9654;</span><span>RAID arrays</span>'
            . '<span class="rt">' . $nA . ' arrays <span class="b gray">&#128274; read-only — never tested or modified</span></span></button>'
            . '<div id="bdArrays">' . $ar . '</div>';
    }
    return $h;
}
/** Per-drive lifetime & wear: power-on time, bytes written/read since manufacture, health %, performance %. */
function smpro_bd_life_html() {
    if (!smpro_bd_has('smartctl'))
        return '<div style="padding:16px;color:var(--muted)">Install <span class="mono">smartmontools</span> '
             . '(<span class="mono">dnf install smartmontools</span>) to read drive lifetime, wear and health. It is read-only monitoring.</div>';
    $hw = smpro_bd_hw_health_cached(false);
    $smart = [];
    if (is_array($hw) && !empty($hw['disks'])) foreach ($hw['disks'] as $d) $smart[$d['dev']] = $d;
    $classOf = [];
    foreach (smpro_bd_disks() as $d) $classOf[$d['name']] = ($d['tran'] === 'nvme') ? 'nvme' : ($d['rota'] ? 'hdd' : 'ssd');

    $h = '<div class="smpro-tablewrap"><table class="smpro-table"><thead><tr>'
       . '<th>Drive</th><th>Type</th><th class="num">Powered on</th><th class="num">Written</th><th class="num">Read</th>'
       . '<th>Health</th><th>Performance</th></tr></thead><tbody>';
    $rows = 0;
    foreach (smpro_bd_disks() as $d) {
        $s = $smart[$d['name']] ?? null; if (!$s) continue;
        $rows++;
        $class = $classOf[$d['name']] ?? 'hdd';
        $hoursN = (int)($s['hours'] ?? 0);
        $onTxt = $hoursN > 0 ? number_format($hoursN) . ' h · ' . round($hoursN / 8760, 1) . ' yr' : '—';
        $wrote = isset($s['written_h']) ? $s['written_h'] : (isset($s['written_bytes']) ? smpro_bd_bytes_h($s['written_bytes']) : '—');
        $read  = isset($s['read_h'])    ? $s['read_h']    : (isset($s['read_bytes'])    ? smpro_bd_bytes_h($s['read_bytes'])    : '—');
        $wearNote = isset($s['used_pct']) ? (' <span class="meta">(' . (int)$s['used_pct'] . '% life used)</span>')
                  : (!empty($s['realloc']) ? ' <span class="meta">(' . (int)$s['realloc'] . ' reallocated)</span>' : '');
        $hp = smpro_bd_disk_health_pct($s);
        $hcls = $hp >= 80 ? 'green' : ($hp >= 50 ? 'orange' : 'red');
        $pp = smpro_bd_disk_perf_pct($d['name'], $class);
        $perf = $pp === null
            ? '<span class="meta">not tested — <a href="#" class="bd-jumptest">test it</a></span>'
            : '<span class="b ' . ($pp >= 80 ? 'green' : ($pp >= 50 ? 'orange' : 'red')) . '">' . $pp . '%</span>';
        $h .= '<tr><td class="mono"><b>' . smpro_h($d['name']) . '</b></td>'
            . '<td>' . smpro_h(['nvme' => 'NVMe SSD', 'ssd' => 'SATA SSD', 'hdd' => 'HDD'][$class] ?? $class) . '</td>'
            . '<td class="num mono">' . $onTxt . '</td>'
            . '<td class="num mono">' . smpro_h($wrote) . '</td>'
            . '<td class="num mono">' . smpro_h($read) . '</td>'
            . '<td><span class="b ' . $hcls . '">' . $hp . '%</span>' . $wearNote . '</td>'
            . '<td>' . $perf . '</td></tr>';
    }
    if (!$rows) return '<div style="padding:16px;color:var(--muted)">No SMART-capable drives detected (virtual disks and some RAID controllers do not expose it).</div>';
    $h .= '</tbody></table></div>';
    $h .= '<div class="bd-safe" style="background:var(--bg);border-left-color:var(--line)"><b>How these are derived.</b> '
        . '<b>Powered on</b> and the total <b>written</b> / <b>read</b> come straight from the drive\'s own SMART counters, accumulated since it was manufactured. '
        . '<b>Health %</b> is the drive\'s remaining life: on an SSD/NVMe it is 100 minus the wear the controller reports, reduced further by any reallocated or unreadable sectors; on an HDD it starts at 100% and drops with defect counts. '
        . '<b>Performance %</b> is the drive\'s last measured speed against what a healthy drive of its class should do — it only appears after you test the drive above.</div>';
    return $h;
}

/** The grade ruler: bands drawn to scale with each tested disk plotted on it. */
function smpro_bd_ruler_html() {
    $dev = smpro_bd_dev_results(); $marks = ''; $i = 0; $any = false;
    foreach (smpro_bd_disks() as $d) {
        $r = $dev['disk:' . $d['name']] ?? null; if (!$r) continue;
        $iops = $r['iops'] ?? null;
        if ($iops === null) continue;                       // the ruler is an IOPS scale
        $any = true;
        $pos = smpro_bd_ruler_pos($iops);
        $g = smpro_bd_grade_iops($iops);
        $col = ['excellent' => 'var(--good)', 'verygood' => 'var(--good)', 'good' => 'var(--brand)',
                'poor' => 'var(--warn)', 'failing' => 'var(--dang)'][$g[0]] ?? 'var(--muted)';
        $marks .= '<div class="bd-mk' . (($i++ % 2) ? ' lo' : '') . '" style="left:' . $pos . '%">'
               . '<div class="stem"></div><div class="dot" style="background:' . $col . '"></div>'
               . '<div class="nm mono">' . smpro_h($d['name']) . '</div>'
               . '<div class="vl mono">' . number_format((int)$iops) . '</div></div>';
    }
    if (!$any) return '<div class="bd-ruler"><div class="meta" style="padding:4px 0">Test a drive (and install <span class="mono">fio</span> for random IOPS) to see where it lands on the scale.</div></div>';
    return '<div class="bd-ruler">'
        . '<div class="bd-rhd"><b>Where those numbers land</b><span class="meta">random 4K IOPS — the figure that decides how a busy server feels · logarithmic</span></div>'
        . '<div class="bd-segs">'
        . '<i data-l="Failing" style="width:21%;background:var(--dang)"></i>'
        . '<i data-l="Poor" style="width:41%;background:var(--warn)"></i>'
        . '<i data-l="Good" style="width:12%;background:var(--brand)"></i>'
        . '<i data-l="Very good" style="width:9%;background:#37b47e"></i>'
        . '<i data-l="Excellent" style="width:17%;background:var(--good)"></i></div>'
        . '<div class="bd-marks">' . $marks . '</div>'
        . '<div class="bd-vd"><b>Read the bands in context.</b> They describe what the <i>server</i> needs, not what a device can reach — '
        . 'a 7,200 rpm disk can never pass <b>Good</b>, because ~180 IOPS is its mechanical ceiling. That is the whole argument for NVMe on a hosting '
        . 'server: not the sequential figure, but the random one. Thresholds — Excellent &ge; 80,000 · Very good 30,000–80,000 · Good 8,000–30,000 · '
        . 'Poor 100–8,000 · Failing &lt; 100.</div></div>';
}
/** Per-array read/write path, and whether one member is dragging the array down. */
function smpro_bd_path_html() {
    $an = smpro_bd_array_analysis();
    if (!$an) return '<div class="bd-pathwrap"><div class="meta" style="padding:14px 16px">No software RAID on this server — each filesystem sits directly on its drive.</div></div>';
    $h = '';
    foreach ($an as $a) {
        $mem = '';
        foreach ($a['members_detail'] as $m) {
            $slow = ($a['drag'] && $a['drag']['name'] === $m['name']);
            $mem .= '<span class="bd-nd' . ($slow ? ' slow' : '') . '">' . smpro_h($m['name'])
                 . ($m['read_mbs'] !== null ? ' · ' . round($m['read_mbs']) . ' MB/s' : ' · not tested')
                 . ($slow ? ' &larr; slowest' : '') . '</span>';
        }
        $h .= '<div class="bd-path"><div class="bd-phd"><b class="mono">' . smpro_h($a['name']) . '</b>'
            . '<span class="b ' . ($a['degraded'] ? 'red' : 'green') . '">' . smpro_h($a['level']) . '</span>'
            . '<span class="mono meta">' . smpro_h(implode(' + ', $a['members']) . ($a['mount'] !== '' ? ' → ' . $a['mount'] : '')) . '</span></div>'
            . '<div class="bd-flow"><span class="bd-fk w">Write</span><span class="bd-nd arr">' . smpro_h($a['name']) . '</span><span class="bd-ar">&rarr;</span>'
            . '<span class="bd-fork">' . $mem . '</span>'
            . ($a['w_eff'] !== null ? '<span class="bd-ar">=</span><span class="bd-nd ' . ($a['drag'] ? 'slow' : 'res') . '">' . round($a['w_eff']) . ' MB/s</span>' : '')
            . '</div>'
            . '<div class="bd-flow"><span class="bd-fk r">Read</span><span class="bd-nd arr">' . smpro_h($a['name']) . '</span><span class="bd-ar">&rarr;</span>'
            . '<span class="bd-nd">' . smpro_h(implode(' or ', $a['members'])) . '</span>'
            . ($a['r_eff'] !== null ? '<span class="bd-ar">=</span><span class="bd-nd res">up to ' . round($a['r_eff']) . ' MB/s</span>' : '')
            . '</div>';
        if ($a['tested'] < $a['total_members']) {
            $h .= '<div class="bd-vd">Test every member under <b>Physical drives</b> to complete this picture — '
                . $a['tested'] . ' of ' . $a['total_members'] . ' measured so far. ' . smpro_h($a['w_rule']) . '.</div>';
        } elseif ($a['drag']) {
            $pct = round($a['drag']['slow'] / max(1, $a['drag']['fast']) * 100);
            $h .= '<div class="bd-vd alert"><b>One member is holding this array back.</b> Because ' . smpro_h($a['w_rule'])
                . ', <b>' . smpro_h($a['drag']['name']) . '</b> at ' . round($a['drag']['slow']) . ' MB/s ('
                . $pct . '% of its fastest sibling) caps writes for the whole array'
                . ($a['mount'] !== '' ? ' — and therefore everything on <b>' . smpro_h($a['mount']) . '</b>' : '')
                . '. Re-test it while the server is quiet; if it stays slow, check its SMART data and plan a replacement.</div>';
        } else {
            $h .= '<div class="bd-vd">' . smpro_h(ucfirst($a['w_rule'])) . '; ' . smpro_h($a['r_rule']) . '. <b>Members are evenly matched.</b></div>';
        }
        $h .= '</div>';
    }
    return $h;
}

/* ---------------- shared HTML renderers (page render AND live refresh use these) ---------------- */
function smpro_bd_sevcls($s) { return ['critical' => 'red', 'high' => 'red', 'medium' => 'orange', 'low' => 'blue'][$s] ?? 'blue'; }
function smpro_bd_hw_html($hw) {
    if (!is_array($hw)) return '<div style="padding:16px;color:var(--muted)">Reading hardware health…</div>';
    $h = '';
    if (!empty($hw['disks'])) {
        $h .= '<div class="smpro-tablewrap"><table class="smpro-table"><thead><tr><th>Disk</th><th>Model</th><th class="num">Size</th><th>SMART</th><th class="num">Wear / reallocated</th><th class="num">Temp</th><th class="num">Power-on</th></tr></thead><tbody>';
        foreach ($hw['disks'] as $d) {
            $hOk  = (($d['health'] ?? '') === 'PASSED' || ($d['health'] ?? '') === 'OK' || ($d['health'] ?? '') === '');
            $wear = isset($d['used_pct']) ? ($d['used_pct'] . '% life used') : (isset($d['realloc']) ? ((int)$d['realloc'] . ' reallocated') : '—');
            $bad  = (isset($d['used_pct']) && $d['used_pct'] >= 80) || !empty($d['realloc']) || !empty($d['pending']);
            $h .= '<tr><td class="mono"><b>/dev/' . smpro_h($d['dev']) . '</b>' . (!empty($d['tran']) ? ' <span class="b blue">' . smpro_h(strtoupper($d['tran'])) . '</span>' : '') . '</td>'
                . '<td class="mono">' . smpro_h($d['model'] ?? '—') . '</td>'
                . '<td class="num mono">' . smpro_h($d['size'] ?? '') . '</td>'
                . '<td><span class="b ' . ($hOk ? 'green' : 'red') . '">' . smpro_h(($d['health'] ?? '') !== '' ? $d['health'] : 'n/a') . '</span>'
                . (!empty($d['pending']) ? ' <span class="b red">' . (int)$d['pending'] . ' pending</span>' : '') . '</td>'
                . '<td class="num mono">' . ($bad ? '<span class="b red">' . smpro_h($wear) . '</span>' : smpro_h($wear)) . '</td>'
                . '<td class="num mono">' . (isset($d['temp']) ? (int)$d['temp'] . '&deg;C' : '—') . '</td>'
                . '<td class="num mono">' . (isset($d['hours']) ? number_format((int)$d['hours']) . ' h' : '—') . '</td></tr>';
        }
        $h .= '</tbody></table></div>';
    }
    if (!empty($hw['ecc'])) {
        $ue = (int)$hw['ecc']['ue']; $ce = (int)$hw['ecc']['ce'];
        $h .= '<div class="bd-eccrow">&#129518; <b>ECC memory:</b> ' . number_format($ce) . ' corrected · ' . number_format($ue) . ' uncorrectable'
            . ($ue > 0 ? ' <span class="b red">action needed</span>' : ($ce === 0 ? ' <span class="b green">clean</span>' : '')) . '</div>';
    }
    if (!empty($hw['findings'])) {
        $lbl = ['critical' => 'CRITICAL', 'high' => 'HIGH', 'medium' => 'MEDIUM', 'low' => 'LOW'];
        $h .= '<div class="bd-findings">';
        foreach ($hw['findings'] as $f) {
            $c = smpro_bd_sevcls($f['sev']);
            $h .= '<div class="bd-f bd-' . $c . '"><div class="bd-frow"><span class="b ' . $c . '">' . ($lbl[$f['sev']] ?? '') . '</span>'
                . '<b class="bd-ftitle">' . smpro_h($f['title']) . '</b></div>'
                . '<div class="bd-detail">' . smpro_h($f['detail']) . '</div>'
                . '<div class="bd-rec"><span>&#128161; What to do</span> ' . smpro_h($f['rec']) . '</div></div>';
        }
        $h .= '</div>';
    } elseif (!empty($hw['disks'])) {
        $h .= '<div style="padding:16px;text-align:center;color:var(--good)"><b>&#10003; No hardware problems detected</b> — SMART is clean, no reallocated/pending sectors, RAID and memory look healthy.</div>';
    }
    return $h !== '' ? $h : '<div style="padding:16px;color:var(--muted)">No hardware health data available on this machine.</div>';
}
function smpro_bd_diag_html($diag) {
    if (!is_array($diag)) return '<div style="padding:16px;color:var(--muted)">Running diagnostics…</div>';
    if (!$diag) return '<div style="padding:22px 16px;text-align:center;color:var(--good)"><b>&#10003; No kernel or software problems detected.</b>'
        . '<div class="sub" style="margin-top:4px">Kernel tunables are at sane values, the kernel log is clean, and PHP looks healthy.</div></div>';
    $lbl = ['critical' => 'CRITICAL', 'high' => 'HIGH', 'medium' => 'MEDIUM', 'low' => 'LOW'];
    $icon = ['kernel' => '&#129504;', 'software' => '&#128295;', 'mysql' => '&#128044;'];
    $h = '<div class="bd-findings">';
    foreach ($diag as $f) {
        $c = smpro_bd_sevcls($f['sev']);
        $btn = '';
        if (!empty($f['fix']) && ($f['fix']['action'] ?? '') === 'sysctl')
            $btn = '<button class="tp-btn bd-fix" type="button" data-key="' . smpro_h($f['fix']['key']) . '">' . smpro_h($f['fix']['label']) . '</button>';
        elseif (!empty($f['fix']) && ($f['fix']['action'] ?? '') === 'link')
            $btn = '<a class="tp-btn bd-fix" href="index.cgi?page=' . smpro_h($f['fix']['page']) . '">' . smpro_h($f['fix']['label']) . '</a>';
        $h .= '<div class="bd-f bd-' . $c . '"><div class="bd-frow"><span class="b ' . $c . '">' . ($lbl[$f['sev']] ?? '') . '</span>'
            . '<span class="bd-area">' . ($icon[$f['area']] ?? '') . ' ' . smpro_h(ucfirst($f['area'])) . '</span>'
            . '<b class="bd-ftitle">' . smpro_h($f['title']) . '</b>' . $btn . '</div>'
            . '<div class="bd-ev">' . smpro_h($f['evidence']) . '</div>'
            . '<div class="bd-detail">' . smpro_h($f['detail']) . '</div>'
            . '<div class="bd-rec"><span>&#128161; Fix</span> ' . smpro_h($f['rec']) . '</div></div>';
    }
    return $h . '</div>';
}

/* ---------------- writes: reversible sysctl fixes (live + persisted drop-in) + undo ---------------- */
function smpro_bd_prev_read() { $d = @is_file(SMPRO_BD_PREV) ? json_decode((string)@file_get_contents(SMPRO_BD_PREV), true) : []; return is_array($d) ? $d : []; }
function smpro_bd_prev_write($k, $v) {
    $d = smpro_bd_prev_read(); $d[$k] = $v;
    @is_dir(dirname(SMPRO_BD_PREV)) || @mkdir(dirname(SMPRO_BD_PREV), 0700, true);
    if (@file_put_contents(SMPRO_BD_PREV, json_encode($d, JSON_UNESCAPED_SLASHES), LOCK_EX) !== false) @chmod(SMPRO_BD_PREV, 0600);
}
/** Write/replace one key in OUR OWN sysctl drop-in (never touches /etc/sysctl.conf or anyone else's file). */
function smpro_bd_sysctl_persist($key, $val, $remove = false) {
    $f = SMPRO_BD_SYSCTL;
    $lines = @is_file($f) ? explode("\n", (string)@file_get_contents($f)) : ['# Managed by Safety Monitor Pro — reversible kernel tunables.'];
    $out = []; $done = false;
    foreach ($lines as $l) {
        if (preg_match('/^\s*' . preg_quote($key, '/') . '\s*=/', $l)) {
            if ($remove) continue;
            $out[] = $key . ' = ' . $val; $done = true; continue;
        }
        $out[] = $l;
    }
    if (!$done && !$remove) $out[] = $key . ' = ' . $val;
    $body = rtrim(implode("\n", $out), "\n") . "\n";
    return @file_put_contents($f, $body, LOCK_EX) !== false;
}
/** Apply a recommended sysctl value live + persist it. Records the previous value for Undo. */
function smpro_bd_apply_sysctl($key, $to) {
    $ok_keys = [];
    foreach (smpro_bd_sysctl_targets() as $t) if (!empty($t['fix'])) $ok_keys[$t['key']] = (string)$t['want'];
    if (!isset($ok_keys[$key])) return ['ok' => false, 'msg' => 'That kernel setting is not in the safe, reversible list.'];
    $to = (string)$ok_keys[$key];                                  // always our vetted value, never client-supplied
    $prev = smpro_bd_sysctl_get($key);
    if ($prev === null) return ['ok' => false, 'msg' => 'This kernel does not expose ' . $key . '.'];
    smpro_bd_prev_write('sysctl:' . $key, $prev);
    smpro_bd_sh('sysctl -w ' . escapeshellarg($key . '=' . $to), 8);
    smpro_bd_sysctl_persist($key, $to);
    $now = smpro_bd_sysctl_get($key);
    $ok = ($now !== null && (float)$now === (float)$to);
    if (function_exists('smpro_audit')) smpro_audit('benchdiag_sysctl', ['key' => $key, 'from' => $prev, 'to' => $to, 'ok' => $ok]);
    return ['ok' => $ok, 'undo' => $ok ? 'sysctl:' . $key : '', 'from' => $prev, 'to' => $to,
        'msg' => $ok
            ? '✅ ' . $key . ' changed from ' . $prev . ' to ' . $to . ".\n\nIt took effect immediately (sysctl -w) and was written to " . SMPRO_BD_SYSCTL . ' so it survives a reboot. This is a kernel tuning number — it touches no data and deletes nothing, so there is nothing to back up. Press Undo to put it back to ' . $prev . '.'
            : 'Could not change ' . $key . ' (the kernel refused the value).'];
}
function smpro_bd_revert($which) {
    $p = smpro_bd_prev_read();
    if (empty($p[$which]) && !isset($p[$which])) return ['ok' => false, 'msg' => 'Nothing recorded to undo for this setting.'];
    if (strpos($which, 'sysctl:') !== 0) return ['ok' => false, 'msg' => 'Unknown setting.'];
    $key = substr($which, 7); $val = (string)$p[$which];
    smpro_bd_sh('sysctl -w ' . escapeshellarg($key . '=' . $val), 8);
    smpro_bd_sysctl_persist($key, $val, true);                     // drop our persisted override entirely
    $now = smpro_bd_sysctl_get($key);
    $ok = ($now !== null && (float)$now === (float)$val);
    if (function_exists('smpro_audit')) smpro_audit('benchdiag_sysctl_revert', ['key' => $key, 'to' => $val, 'ok' => $ok]);
    return ['ok' => $ok, 'msg' => $ok
        ? '↩ Restored ' . $key . ' to ' . $val . ' and removed our persisted override.'
        : 'Could not restore ' . $key . '.'];
}
