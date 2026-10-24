<?php
/**
 * includes/diskio.php - live per-disk I/O (read/write throughput + BUSY%) + disk temperature (SMART).
 * Boot-loaded so the live JSON endpoint (index.php `format=json&metric=diskio`, polled by the Disk/Storage card
 * with NO page refresh - same mechanism as the dashboard) and the page render both share ONE implementation.
 * "Busy %" (io_ticks delta) is the real performance-impact signal - a disk at ~100% busy is the bottleneck even
 * at low MB/s. Temperatures are cached ~60s because smartctl is slow.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

/* one /proc/diskstats snapshot: name => {reads, sectors_read, writes, sectors_written, io_ticks_ms} */
function smpro_ds_diskstats_snap() {
    $out = [];
    foreach (explode("\n", (string)@file_get_contents('/proc/diskstats')) as $l) {
        $p = preg_split('/\s+/', trim($l)); if (count($p) < 14) continue;
        // fields: [2]=name [3]=reads [5]=sectors_read [7]=writes [9]=sectors_written [12]=ms doing I/O (io_ticks)
        $out[$p[2]] = ['r' => (float)$p[3], 'sr' => (float)$p[5], 'w' => (float)$p[7], 'sw' => (float)$p[9], 'io' => (float)$p[12]];
    }
    return $out;
}
/** Whole disks + RAID/LVM only - skip partitions and pseudo devices. */
function smpro_ds_dev_is_whole($n) {
    if (preg_match('/^(loop|ram|fd\d|sr\d|dm-name)/', $n)) return false;
    if (preg_match('/^(sd|vd|xvd|hd)[a-z]+$/', $n))  return true;   // whole SCSI/virtio/IDE disk (no trailing partition digit)
    if (preg_match('/^nvme\d+n\d+$/', $n))           return true;   // whole NVMe namespace (no pN partition)
    if (preg_match('/^md\d+$/', $n))                 return true;   // software-RAID array
    if (preg_match('/^dm-\d+$/', $n))                return true;   // LVM / device-mapper
    return false;
}
/** Per-device I/O: read/write kB/s, IOPS, and busy% with a health tier (ok<60 / warn 60-85 / danger>=85). */
function smpro_ds_diskio($interval = 0.8) {
    if (!@is_readable('/proc/diskstats')) return [];
    $a = smpro_ds_diskstats_snap();
    usleep((int)($interval * 1000000));
    $b = smpro_ds_diskstats_snap();
    $rows = [];
    foreach ($b as $n => $s2) {
        if (!smpro_ds_dev_is_whole($n)) continue;
        $s1 = $a[$n] ?? null; if (!$s1) continue;
        $rk = max(0, ($s2['sr'] - $s1['sr']) * 0.5 / $interval);      // sectors*512/1024 = kB
        $wk = max(0, ($s2['sw'] - $s1['sw']) * 0.5 / $interval);
        $ri = max(0, ($s2['r']  - $s1['r'])  / $interval);
        $wi = max(0, ($s2['w']  - $s1['w'])  / $interval);
        $util = max(0, min(100, ($s2['io'] - $s1['io']) / ($interval * 1000) * 100));
        $rows[] = ['dev' => $n, 'r_kbs' => $rk, 'w_kbs' => $wk, 'r_iops' => $ri, 'w_iops' => $wi, 'util' => round($util, 1),
                   'tier' => ($util >= 85 ? 'danger' : ($util >= 60 ? 'warn' : 'ok'))];
    }
    usort($rows, fn($x, $y) => $y['util'] <=> $x['util']);           // busiest first
    return $rows;
}
/* ---------- disk temperature (SMART / drivetemp) ---------- */
function smpro_ds_temp_tier($c) { if ($c === null) return null; if ($c >= 60) return 'danger'; if ($c >= 50) return 'warn'; return 'ok'; }
function smpro_ds_disk_temp_one($dev) {
    if (preg_match('/^(md|dm-)/', $dev)) return null;                       // RAID arrays / device-mapper have no sensor
    $path = '/dev/' . preg_replace('/[^a-z0-9]/', '', $dev);
    foreach (['smartctl -A ' . escapeshellarg($path), 'smartctl -A -d sat ' . escapeshellarg($path)] as $cmd) {
        $out = (string)@shell_exec('timeout 6 ' . $cmd . ' 2>/dev/null'); if ($out === '') continue;
        if (preg_match('/(?:Temperature|Current Drive Temperature):\s*(\d{1,3})\s*(?:Celsius|C\b)/i', $out, $m)) return (int)$m[1];   // NVMe / SCSI
        foreach (['Temperature_Celsius', 'Airflow_Temperature'] as $attr)  // ATA attr table: prefer 194 (drive temp) over 190 (airflow)
            foreach (explode("\n", $out) as $ln)
                if (strpos($ln, $attr) !== false) { $f = preg_split('/\s+/', trim($ln)); if (isset($f[9]) && ctype_digit((string)$f[9])) return (int)$f[9]; }
    }
    foreach (glob('/sys/block/' . $dev . '/device/hwmon/hwmon*/temp1_input') ?: [] as $hp) { $v = (int)trim((string)@file_get_contents($hp)); if ($v > 0) return (int)round($v / 1000); }   // kernel drivetemp
    return null;
}
/** Cached temps map {dev=>°C}. $ttl huge = cache-only (used by the page render so smartctl never blocks it). */
function smpro_ds_disktemps(array $devs, $ttl = 60) {
    $f = SMPRO_VARLIB . '/disktemp.json';
    $d = @is_file($f) ? json_decode((string)@file_get_contents($f), true) : null;
    if (is_array($d) && (time() - (int)($d['ts'] ?? 0)) < $ttl && isset($d['t']) && is_array($d['t'])) return $d['t'];
    if ($ttl === PHP_INT_MAX) return (is_array($d) && is_array($d['t'] ?? null)) ? $d['t'] : [];   // cache-only: never run smartctl
    $t = [];
    if (trim((string)@shell_exec('command -v smartctl 2>/dev/null')) !== '' || (glob('/sys/block/*/device/hwmon/hwmon*/temp1_input') ?: []))
        foreach ($devs as $dev) { $c = smpro_ds_disk_temp_one($dev); if ($c !== null) $t[$dev] = $c; }
    @is_dir(dirname($f)) || @mkdir(dirname($f), 0700, true);
    @file_put_contents($f . '.tmp', json_encode(['ts' => time(), 't' => $t]), LOCK_EX); @chmod($f . '.tmp', 0600); @rename($f . '.tmp', $f);
    return $t;
}
/** Live I/O + temps -> the payload shared by the page render AND the no-refresh live poll. $refreshTemps=false =
 *  cache-only (fast page render); the live poll passes true so smartctl runs in the background JSON request. */
function smpro_ds_diskio_payload(array $io, $refreshTemps = true): array {
    $temps = smpro_ds_disktemps(array_map(fn($d) => $d['dev'], $io), $refreshTemps ? 60 : PHP_INT_MAX);
    $worst = 'ok'; $devs = [];
    foreach ($io as $d) {
        if ($d['tier'] === 'danger') $worst = 'danger'; elseif ($d['tier'] === 'warn' && $worst !== 'danger') $worst = 'warn';
        $c = $temps[$d['dev']] ?? null;
        $devs[] = $d + ['temp' => $c, 'temp_tier' => smpro_ds_temp_tier($c)];
    }
    return ['worst' => $worst, 'devices' => $devs, 'has_temp' => !empty($temps)];
}
