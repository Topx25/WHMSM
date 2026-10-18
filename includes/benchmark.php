<?php
/**
 * includes/benchmark.php — Hardware benchmark (CPU · RAM · Disk) + a live hardware inventory.
 * The benchmark runs as a DETACHED background worker (bin/benchmark.php) so it survives the admin closing the tab;
 * progress + results are written to a state file the page polls (index.php format=json&metric=benchmark). Every test
 * is bounded and uses tools that are always present (openssl, dd) with optional fio for random IOPS. Read inventory
 * is instant; the benchmark is admin-triggered + confirm-gated (it briefly loads CPU/RAM/disk).
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

if (!defined('SMPRO_BENCH_STATE')) define('SMPRO_BENCH_STATE', SMPRO_VARLIB . '/benchmark.json');

function smpro_bm_sh($cmd, $t = 8) { return smpro_run((string)$cmd, (int)$t, ['path' => true]); }
function smpro_bm_has($bin) { return trim((string)@shell_exec('command -v ' . escapeshellarg($bin) . ' 2>/dev/null')) !== ''; }

/* ---------------- hardware inventory (CACHED — hardware is static; computed off the page render) ----------------
 * The disk-storage render calls smpro_bm_inventory(false) = cache-only (never runs dmidecode/lscpu/lsblk, so the
 * page stays fast even on a busy server); the benchmark JSON poll calls smpro_bm_inventory(true) which computes +
 * caches it once (~24h). A cold cache returns a "detecting…" skeleton so the render never fatals. */
if (!defined('SMPRO_BM_INV')) define('SMPRO_BM_INV', SMPRO_VARLIB . '/hw_inventory.json');
function smpro_bm_inventory_default() {
    return ['cpu' => ['model' => 'detecting…', 'cores' => 0, 'tpc' => 0, 'sockets' => 0, 'mhz_max' => '', 'l3' => ''],
            'ram' => ['total_gb' => 0], 'disks' => [], 'virt' => '', 'has_fio' => false, 'has_dmidecode' => false, 'pending' => true];
}
function smpro_bm_inventory($compute = true, $ttl = 86400) {
    $f = SMPRO_BM_INV;
    $d = @is_file($f) ? json_decode((string)@file_get_contents($f), true) : null;
    if (is_array($d) && is_array($d['inv'] ?? null) && (time() - (int)($d['ts'] ?? 0)) < $ttl) return $d['inv'];
    if (!$compute) return smpro_bm_inventory_default();
    $inv = smpro_bm_inventory_compute();
    $t = $f . '.tmp'; @is_dir(dirname($f)) || @mkdir(dirname($f), 0700, true);
    if (@file_put_contents($t, json_encode(['ts' => time(), 'inv' => $inv], JSON_UNESCAPED_SLASHES), LOCK_EX) !== false) { @chmod($t, 0600); @rename($t, $f); }
    return $inv;
}
function smpro_bm_inventory_compute() {
    $lscpu = smpro_bm_sh('lscpu');
    $g = function ($k) use ($lscpu) { return preg_match('/^' . $k . ':\s*(.+)$/m', $lscpu, $m) ? trim($m[1]) : ''; };
    $cpu = ['model' => $g('Model name') ?: '?', 'cores' => (int)$g('CPU\(s\)'), 'tpc' => (int)$g('Thread\(s\) per core'),
            'sockets' => (int)$g('Socket\(s\)'), 'mhz_max' => $g('CPU max MHz') ?: $g('CPU MHz'), 'l3' => $g('L3 cache')];
    $ram = ['total_gb' => round(((int)trim(smpro_bm_sh("free -m | awk '/Mem:/{print \$2}'"))) / 1024, 1)];
    if (smpro_bm_has('dmidecode')) {
        $dmi = smpro_bm_sh('dmidecode -t memory', 5);
        if (preg_match('/\bType:\s*(DDR\w*)/', $dmi, $m)) $ram['type'] = $m[1];
        if (preg_match_all('/(?:Configured Memory Speed|Speed):\s*(\d+)\s*MT\/s/', $dmi, $mm)) { $sp = array_filter(array_map('intval', $mm[1])); if ($sp) $ram['speed'] = max($sp); }
        if (preg_match_all('/^\s*Size:\s*(\d+)\s*(?:GB|MB)/m', $dmi, $mm)) $ram['modules'] = count($mm[1]);
    }
    $disks = [];
    foreach (explode("\n", smpro_bm_sh('lsblk -dnP -o NAME,SIZE,ROTA,TRAN,MODEL 2>/dev/null')) as $l) {
        if (trim($l) === '') continue; $kv = [];
        if (preg_match_all('/(\w+)="([^"]*)"/', $l, $mm, PREG_SET_ORDER)) foreach ($mm as $p) $kv[$p[1]] = $p[2];
        $n = $kv['NAME'] ?? ''; if ($n === '' || preg_match('/^(loop|sr|ram)/', $n)) continue;
        $disks[] = ['name' => $n, 'model' => ($kv['MODEL'] ?? '') !== '' ? $kv['MODEL'] : '—', 'size' => $kv['SIZE'] ?? '',
                    'ssd' => (($kv['ROTA'] ?? '1') === '0'), 'tran' => $kv['TRAN'] ?? ''];
    }
    return ['cpu' => $cpu, 'ram' => $ram, 'disks' => $disks, 'virt' => trim(smpro_bm_sh('systemd-detect-virt 2>/dev/null')) ?: 'none',
            'has_fio' => smpro_bm_has('fio'), 'has_dmidecode' => smpro_bm_has('dmidecode')];
}

/* ---------------- benchmark state + start (detached) ---------------- */
function smpro_bm_state() { $d = @is_file(SMPRO_BENCH_STATE) ? json_decode((string)@file_get_contents(SMPRO_BENCH_STATE), true) : null; return is_array($d) ? $d : ['status' => 'idle']; }
function smpro_bm_state_write($s) {
    $f = SMPRO_BENCH_STATE; @is_dir(dirname($f)) || @mkdir(dirname($f), 0700, true);
    $t = $f . '.tmp'; if (@file_put_contents($t, json_encode($s, JSON_UNESCAPED_SLASHES), LOCK_EX) !== false) { @chmod($t, 0600); @rename($t, $f); }
}
function smpro_bm_php_bin() { return smpro_php_cli_bin(); }
/** Pick a real, writable mount with >=2GB free for the disk test (prefer /home, else /). */
function smpro_bm_disk_mount($want = '') {
    $cand = [];
    if ($want !== '' && is_dir($want)) $cand[] = $want;
    foreach (['/home', '/'] as $m) $cand[] = $m;
    foreach ($cand as $m) {
        if (!is_dir($m) || !is_writable($m)) continue;
        $availMb = (int)(((int)trim(smpro_bm_sh('df -Pk ' . escapeshellarg($m) . " | awk 'NR==2{print \$4}'"))) / 1024);
        if ($availMb >= 2200) return $m;
    }
    return '';
}
function smpro_bm_start($mount = '') {
    $st = smpro_bm_state();
    if (($st['status'] ?? '') === 'running' && (time() - (int)($st['started'] ?? 0)) < 300) return ['ok' => false, 'msg' => 'A benchmark is already running — results will appear when it finishes.'];
    $mount = smpro_bm_disk_mount(preg_replace('#[^A-Za-z0-9/_.\-]#', '', (string)$mount));
    smpro_bm_state_write(['status' => 'running', 'step' => 'starting', 'pct' => 2, 'started' => time(), 'mount' => $mount, 'results' => []]);
    $worker = SMPRO_BASE . '/bin/benchmark.php';
    if (!@is_file($worker)) { smpro_bm_run($mount); return ['ok' => true, 'msg' => 'Benchmark complete.']; }
    $pre = smpro_bm_has('setsid') ? 'setsid ' : 'nohup ';
    @shell_exec($pre . escapeshellarg(smpro_bm_php_bin()) . ' ' . escapeshellarg($worker) . ' ' . escapeshellarg($mount) . ' >/dev/null 2>&1 </dev/null &');
    if (function_exists('smpro_audit')) @smpro_audit('hw_benchmark_start', ['mount' => $mount]);
    return ['ok' => true, 'msg' => 'Benchmark started — it runs in the background (you can leave this page); results appear here when done.'];
}

/* ---------------- the tests (called by the worker) ---------------- */
/** Parse a dd/openssl "X MB/s" throughput. Returns MB/s. */
function smpro_bm_dd_mbs($cmd, $t = 90) {
    $out = smpro_bm_sh($cmd, $t);
    if (preg_match('/,\s*([0-9.]+)\s*(GB|MB|kB)\/s/', $out, $m)) { $v = (float)$m[1]; if ($m[2] === 'GB') $v *= 1024; elseif ($m[2] === 'kB') $v /= 1024; return round($v, 1); }
    return null;
}
/** openssl AES-256 throughput in MB/s ($multi>1 = aggregate across cores). openssl reports 1000s of bytes/s. */
function smpro_bm_openssl_mbs($multi) {
    if (!smpro_bm_has('openssl')) return null;
    $out = smpro_bm_sh('openssl speed ' . ($multi > 1 ? '-multi ' . (int)$multi . ' ' : '') . '-seconds 1 -evp aes-256-cbc', 30);
    foreach (explode("\n", $out) as $l) {
        $l = trim($l);
        if (stripos($l, 'aes-256-cbc') === 0) { $f = preg_split('/\s+/', $l); $last = (float)preg_replace('/[^0-9.]/', '', (string)end($f)); if ($last > 0) return round($last / 1000, 1); }   // OpenSSL 3.x labels it "AES-256-CBC" (uppercase)
    }
    return null;
}
function smpro_bm_cpu() {
    $cores = max(1, (int)trim(smpro_bm_sh('nproc')));
    $one = smpro_bm_openssl_mbs(1);
    $all = smpro_bm_openssl_mbs($cores);
    return ['single_mbs' => $one, 'multi_mbs' => $all, 'cores' => $cores, 'scaling' => ($one && $all) ? round($all / $one, 1) : null];
}
function smpro_bm_ram() {
    $shm = '/dev/shm'; if (!is_dir($shm) || !is_writable($shm)) return ['err' => 'no writable /dev/shm'];
    $availMb = (int)(((int)trim(smpro_bm_sh("df -Pk /dev/shm | awk 'NR==2{print \$4}'"))) / 1024);
    $size = max(256, min(2048, (int)($availMb * 0.4))); if ($size < 128) return ['err' => 'not enough free RAM (/dev/shm)'];
    $f = $shm . '/.smpro_bench' . getmypid();
    $w = smpro_bm_dd_mbs('dd if=/dev/zero of=' . escapeshellarg($f) . ' bs=1M count=' . $size . ' conv=fdatasync 2>&1', 30);
    $r = smpro_bm_dd_mbs('dd if=' . escapeshellarg($f) . ' of=/dev/null bs=1M 2>&1', 30);
    @unlink($f);
    return ['write_mbs' => $w, 'read_mbs' => $r, 'size_mb' => $size];
}
function smpro_bm_fio($dir) {
    if (!smpro_bm_has('fio')) return null;
    $out = smpro_bm_sh('fio --name=rr --directory=' . escapeshellarg($dir) . ' --rw=randread --bs=4k --size=256M --numjobs=1 --runtime=5 --time_based --direct=1 --group_reporting --output-format=json 2>/dev/null', 30);
    $j = json_decode($out, true);
    $iops = $j['jobs'][0]['read']['iops'] ?? null;
    return $iops !== null ? (int)round($iops) : null;
}
function smpro_bm_disk($mount) {
    if ($mount === '' || !is_dir($mount)) return ['err' => 'no mount with >=2GB free'];
    $dir = rtrim($mount, '/') . '/.smpro_bench'; @mkdir($dir, 0700, true); $f = $dir . '/tf'; $size = 1024;
    $w = smpro_bm_dd_mbs('dd if=/dev/zero of=' . escapeshellarg($f) . ' bs=1M count=' . $size . ' conv=fdatasync 2>&1', 120);
    $r = smpro_bm_dd_mbs('dd if=' . escapeshellarg($f) . ' of=/dev/null bs=1M iflag=direct 2>&1', 120);   // O_DIRECT = real disk read (bypass cache)
    if ($r === null) $r = smpro_bm_dd_mbs('dd if=' . escapeshellarg($f) . ' of=/dev/null bs=1M 2>&1', 120);  // fallback if the fs rejects O_DIRECT
    $iops = smpro_bm_fio($dir);
    @unlink($f); @rmdir($dir);
    return ['write_mbs' => $w, 'read_mbs' => $r, 'iops' => $iops, 'size_mb' => $size, 'mount' => $mount];
}
/** Worker body: run CPU → RAM → Disk, writing progress after each so the page can show it live. */
function smpro_bm_run($mount) {
    @ignore_user_abort(true); @set_time_limit(300);
    $started = (int)(smpro_bm_state()['started'] ?? time());
    $step = function ($name, $pct, $res = null) use ($started, $mount) {
        $s = ['status' => 'running', 'step' => $name, 'pct' => $pct, 'started' => $started, 'mount' => $mount, 'results' => is_array($res) ? $res : (smpro_bm_state()['results'] ?? [])];
        smpro_bm_state_write($s);
    };
    $res = [];
    $step('cpu', 12);       $res['cpu']  = smpro_bm_cpu();       $step('cpu', 45, $res);
    $step('ram', 50);       $res['ram']  = smpro_bm_ram();       $step('ram', 65, $res);
    $step('disk', 70);      $res['disk'] = smpro_bm_disk($mount); $step('disk', 96, $res);
    smpro_bm_state_write(['status' => 'done', 'step' => 'done', 'pct' => 100, 'started' => $started, 'finished' => time(), 'mount' => $mount, 'results' => $res]);
    if (function_exists('smpro_audit')) @smpro_audit('hw_benchmark', ['cpu_multi' => $res['cpu']['multi_mbs'] ?? 0, 'disk_w' => $res['disk']['write_mbs'] ?? 0]);
}
