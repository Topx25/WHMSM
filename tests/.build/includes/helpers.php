<?php
/**
 * helpers.php — read-only live collectors + small utilities.
 * Every function here READS system state only. No mutation, no restart.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

/** HTML-escape shortcut. */
function smpro_h($s) {
    return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/** Append a JSON line to the audit log. Best-effort, never fatal. */
function smpro_audit($action, array $details = []) {
    $line = json_encode([
        'timestamp' => date('c'),
        'level'     => 'INFO',
        'action'    => $action,
        'actor'     => smpro_actor(),
        'ip'        => $_SERVER['REMOTE_ADDR'] ?? 'cli',
        'details'   => $details,
    ], JSON_UNESCAPED_SLASHES);
    @file_put_contents(SMPRO_AUDIT_LOG, $line . "\n", FILE_APPEND | LOCK_EX);
}

/** Best-effort actor identity (WHM runs as root). */
function smpro_actor() {
    return $_ENV['REMOTE_USER'] ?? ($_SERVER['REMOTE_USER'] ?? (function_exists('posix_getpwuid') ? (posix_getpwuid(posix_geteuid())['name'] ?? 'root') : 'root'));
}

/* ----------------------------------------------------------------------
 * LIVE COLLECTORS (read-only)
 * -------------------------------------------------------------------- */

/** CPU core count. */
function smpro_cpu_cores() {
    $n = 0;
    foreach (@file('/proc/cpuinfo') ?: [] as $l) {
        if (strpos($l, 'processor') === 0) $n++;
    }
    return $n ?: 1;
}

/** Load averages from /proc/loadavg → [1m,5m,15m]. */
function smpro_loadavg() {
    $p = explode(' ', trim(@file_get_contents('/proc/loadavg')));
    return [
        '1m'  => (float)($p[0] ?? 0),
        '5m'  => (float)($p[1] ?? 0),
        '15m' => (float)($p[2] ?? 0),
    ];
}

/** Load-average colour band by ABSOLUTE 1-min value (admin spec, NOT pressure):
 *  <=10 good (green) · >10..25 elev (orange) · >25..30 warn (yellow) · >30 danger (red). */
function smpro_load_cls($v) {
    $v = (float)$v;
    if ($v > 30) return 'danger';
    if ($v > 25) return 'warn';
    if ($v > 10) return 'elev';
    return 'good';
}

/** System uptime in seconds. */
function smpro_uptime() {
    $p = explode(' ', trim(@file_get_contents('/proc/uptime')));
    return (int)($p[0] ?? 0);
}

/** Memory snapshot from /proc/meminfo (values in MB). */
function smpro_memory() {
    $m = [];
    foreach (@file('/proc/meminfo') ?: [] as $l) {
        if (preg_match('/^(\w+):\s+(\d+)/', $l, $x)) $m[$x[1]] = (int)$x[2]; // kB
    }
    $total = $m['MemTotal'] ?? 0;
    $avail = $m['MemAvailable'] ?? ($m['MemFree'] ?? 0);
    $used  = $total - $avail;
    return [
        'total_mb' => round($total / 1024),
        'used_mb'  => round($used / 1024),
        'free_mb'  => round($avail / 1024),
        'percent'  => $total ? round($used / $total * 100, 1) : 0,
        'swap_total_mb' => round(($m['SwapTotal'] ?? 0) / 1024),
        'swap_used_mb'  => round((($m['SwapTotal'] ?? 0) - ($m['SwapFree'] ?? 0)) / 1024),
    ];
}

/** Instant CPU utilization % via two /proc/stat samples (~120ms). */
function smpro_cpu_usage() {
    $a = smpro_cpu_stat_snapshot();
    usleep(120000);
    $b = smpro_cpu_stat_snapshot();
    $dt = $b['total'] - $a['total'];
    $di = $b['idle']  - $a['idle'];
    if ($dt <= 0) return 0.0;
    return round((1 - $di / $dt) * 100, 1);
}
function smpro_cpu_stat_snapshot() {
    foreach (@file('/proc/stat') ?: [] as $l) {
        if (strpos($l, 'cpu ') === 0) {
            $p = preg_split('/\s+/', trim($l));
            array_shift($p);
            $p = array_map('intval', $p);
            $idle  = ($p[3] ?? 0) + ($p[4] ?? 0); // idle + iowait
            $total = array_sum($p);
            return ['idle' => $idle, 'total' => $total];
        }
    }
    return ['idle' => 0, 'total' => 0];
}

/** Root filesystem disk usage. */
function smpro_disk_root() {
    $total = @disk_total_space('/') ?: 0;
    $free  = @disk_free_space('/') ?: 0;
    $used  = $total - $free;
    return [
        'total' => $total,
        'used'  => $used,
        'free'  => $free,
        'percent' => $total ? round($used / $total * 100, 1) : 0,
    ];
}

/** Process count (read-only, counts /proc/<pid> dirs). */
function smpro_process_count() {
    $n = 0;
    foreach (@scandir('/proc') ?: [] as $e) {
        if (ctype_digit($e)) $n++;
    }
    return $n;
}

/** Human-readable bytes. */
function smpro_bytes($b) {
    $u = ['B','KB','MB','GB','TB','PB'];
    $b = (float)$b; $i = 0;
    while ($b >= 1024 && $i < count($u) - 1) { $b /= 1024; $i++; }
    return round($b, $i ? 2 : 0) . ' ' . $u[$i];
}

/** Human-readable uptime. */
function smpro_dur($sec) {
    $d = intdiv($sec, 86400); $sec %= 86400;
    $h = intdiv($sec, 3600);  $sec %= 3600;
    $m = intdiv($sec, 60);
    return ($d ? "{$d}d " : '') . sprintf('%dh %dm', $h, $m);
}

/** Status color from a percentage (green<80, warn<90, danger). */
function smpro_status($pct) {
    if ($pct >= 90) return 'danger';
    if ($pct >= 80) return 'warn';
    return 'good';
}
/* LOAD pressure (load ÷ cores, %) verdict — the SINGLE source of truth for load colour, used everywhere
 * (dashboard, Server Health page, top bar, health score): warn ≥70%, danger ≥100%. Keep these thresholds
 * identical to smpro_sv_snapshot()/load-monitor verdict so the same load never shows two different colours. */
function smpro_load_status($pressure) {
    if ($pressure >= 100) return 'danger';
    if ($pressure >= 70)  return 'warn';
    return 'good';
}

/**
 * Centralized redaction (plan §11). Strips session tokens, auth tokens,
 * passwords and signed URLs from any text before display/export.
 */
function smpro_redact_sensitive($text) {
    $text = (string)$text;
    $text = preg_replace('#/cpsess\d+#', '/cpsess[REDACTED]', $text);
    $text = preg_replace('/\b(cpsess|access_token|refresh_token|auth_token|security_token|token|signature_v2|sign|api[_-]?key|apikey|secret)=([^&\s"\']+)/i', '$1=[REDACTED]', $text);
    $text = preg_replace('/\b(pass|passwd|password|pwd)=([^&\s"\']+)/i', '$1=[REDACTED]', $text);
    return $text;
}

/* ---- Server Health snapshot (matches the legacy dashboard score logic exactly) ---- */
if (!defined('SMPRO_SV_ABS_WARN')) define('SMPRO_SV_ABS_WARN', 15.0);   // legacy fallback only
/** Absolute load thresholds SCALED to core count — so a big server (e.g. 96 cores) is not
 *  flagged warning/danger at light load. Warn ≈ cores×0.5 (~50% pressure), danger ≈ cores×0.85. */
function smpro_sv_abs_warn($cores)   { $cores = max(1, (int)$cores); return max(6.0,  round($cores * 0.5,  1)); }
function smpro_sv_abs_danger($cores) { $cores = max(1, (int)$cores); return max(10.0, round($cores * 0.85, 1)); }
/** Color class for a 0–100 percentage: good(green) / attn(blue) / danger(red). */
function smpro_sv_col($pct) { if ($pct >= 90) return 'danger'; if ($pct >= 70) return 'attn'; return 'good'; }
/**
 * Full server-health snapshot. Health is driven by Load Averages PEAK pressure
 * across cores — identical formula to the legacy Safety Monitor dashboard.
 */
function smpro_sv_snapshot() {
    $m = smpro_collect_metrics();
    $cores = max(1, (int)$m['cores']); $load = $m['load'];
    $l1 = round((float)$load['1m'], 2); $l5 = round((float)$load['5m'], 2); $l15 = round((float)$load['15m'], 2);
    $peak = max($l1, $l5, $l15);
    $pressure = round(($peak / $cores) * 100, 1);
    $absWarn = smpro_sv_abs_warn($cores); $absDanger = smpro_sv_abs_danger($cores);

    if ($pressure >= 100 || $peak >= $absDanger) $level = 'danger';
    elseif ($pressure >= 70 || $peak >= $absWarn) $level = 'warning';
    else $level = 'good';

    if ($level === 'danger') { $score = max(0, min(59, 59 - (int)round(max(0, $pressure - 100) * 0.5))); $cause = 'Critical Load Averages detected.'; }
    elseif ($level === 'warning') {
        if ($pressure >= 70) { $score = max(60, 79 - (int)round(($pressure - 70) * 0.65)); $cause = 'Elevated Load Averages pressure.'; }
        else { $score = 78; $cause = 'High absolute Load Average detected.'; }
    } else { $score = max(80, 100 - (int)round($pressure * 0.25)); $cause = 'No critical Load Averages detected.'; }

    $title = $level === 'good' ? 'Optimal status' : ($level === 'warning' ? 'Warning status' : 'Danger status');
    $cls = $level === 'good' ? 'good' : ($level === 'warning' ? 'warn' : 'danger');

    $tp = smpro_top_processes(60);
    $tu = $tp['groups'][0] ?? null;
    $tup = $tu ? round($tu['cpu'] / $cores * 100, 1) : 0;
    $lp = [];
    foreach (['1m' => $l1, '5m' => $l5, '15m' => $l15] as $k => $v) $lp[$k] = ['v' => $v, 'p' => round($v / $cores * 100, 1)];

    return [
        'ts' => $m['ts'], 'host' => $m['host'], 'cores' => $cores,
        'score' => $score, 'status' => strtoupper($level), 'status_title' => $title, 'cause' => $cause, 'cls' => $cls,
        'eff' => $pressure, 'peak' => $peak, 'abs_warn' => (int)$absWarn, 'load' => $lp,
        'cpu' => ['p' => $m['cpu']['pct'], 'cls' => smpro_sv_col($m['cpu']['pct'])],
        'ram' => ['p' => $m['ram']['pct'], 'cls' => smpro_sv_col($m['ram']['pct']), 'used' => $m['ram']['used'], 'total' => $m['ram']['total']],
        'disk' => ['p' => $m['disk']['pct'], 'cls' => smpro_sv_col($m['disk']['pct']), 'used' => $m['disk']['used'], 'total' => $m['disk']['total'], 'free' => $m['disk']['free']],
        'swap' => ['p' => $m['swap']['pct'], 'cls' => smpro_sv_col($m['swap']['pct']), 'used_mb' => $m['swap']['used_mb'], 'total_mb' => $m['swap']['total_mb']],
        'procs' => $m['procs'],
        'top_user' => $tu ? ['user' => $tu['user'], 'cpu' => $tu['cpu'], 'pressure' => $tup, 'cls' => smpro_sv_col(min(100, $tup))] : null,
    ];
}

/* ----------------------------------------------------------------------
 * IP INTELLIGENCE (shared) — country / provider / ASN via Team Cymru whois,
 * cached on disk, with a per-request new-lookup cap. Plus datacenter/bot
 * detection (logins from cloud/hosting ranges are almost always automated).
 * -------------------------------------------------------------------- */
if (!defined('SMPRO_IPCACHE')) define('SMPRO_IPCACHE', SMPRO_VARLIB . '/cache/ipintel.json');
if (!defined('SMPRO_IPTTL'))   define('SMPRO_IPTTL', 30 * 86400);
if (!defined('SMPRO_IPMAXNEW')) define('SMPRO_IPMAXNEW', 40);

function &smpro_ip_cache() {
    static $c = null;
    if ($c === null) {
        $d = is_file(SMPRO_IPCACHE) ? json_decode((string)@file_get_contents(SMPRO_IPCACHE), true) : null;
        $c = is_array($d) ? $d : [];
    }
    return $c;
}
function smpro_ip_is_external($ip) {
    return (bool)filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
}
function smpro_ip_parse_cymru($lines) {
    foreach ($lines as $l) {
        $l = trim($l);
        if ($l === '' || stripos($l, 'AS Name') !== false || stripos($l, 'Bulk mode') !== false || strpos($l, '|') === false) continue;
        $p = array_map('trim', explode('|', $l));
        if (count($p) >= 7) return ['asn' => 'AS' . $p[0], 'country' => $p[3], 'provider' => $p[6], 'source' => 'Team Cymru whois'];
    }
    return [];
}
/** Is this IP's network a datacenter / cloud / hosting provider (=> likely bot)? */
function _smpro_disabled_smpro_ip_is_datacenter($intel) {
    $hay = strtoupper(($intel['provider'] ?? '') . ' ' . ($intel['asn'] ?? ''));
    if ($hay === ' ') return false;
    static $kw = ['GOOGLE','AMAZON','AWS','AZURE','MICROSOFT','DIGITALOCEAN','OVH','HETZNER','LINODE',
        'VULTR','ALIBABA','TENCENT','CONTABO','LEASEWEB','SCALEWAY','ORACLE','M247','CHOOPA','RACKSPACE',
        'GODADDY','IONOS','SELECTEL','CLOUD','HOSTING','SERVER','DATACENTER','DATA CENTER','COLO','VPS',
        'DIGITAL OCEAN','CLOUDFLARE','FASTLY','LIMESTONE','PSYCHZ','QUADRANET','HOSTWINDS','NAMECHEAP'];
    foreach ($kw as $k) if (strpos($hay, $k) !== false) return true;
    return false;
}
/** Resolve country/provider/ASN for an IP (cached). $cap=false skips new whois. */
/* ---- offline GeoIP (local MaxMind DB) — resolves COUNTRY with no network, so it works even when outbound
 *      whois/port-43 is blocked by the firewall (the usual reason Country shows "n/a" on a locked-down box). ---- */
function smpro_geoip_bin() {
    static $b = null;
    if ($b === null) $b = is_executable('/usr/bin/mmdblookup') ? '/usr/bin/mmdblookup' : (trim((string)@shell_exec('command -v mmdblookup 2>/dev/null')) ?: '');
    return $b;
}
function smpro_geoip_db($kind = 'Country', $fresh = false) {
    static $p = [];
    if (!$fresh && isset($p[$kind])) return $p[$kind];
    // OUR own downloaded copy (SMPRO_VARLIB/geoip) is searched FIRST so a fresh DB always beats a stale/absent
    // system DB — this is what makes country resolve on a box with no system GeoIP DB (e.g. dc2).
    foreach ([SMPRO_VARLIB . '/geoip', '/usr/share/GeoIP', '/var/lib/csf/Geo', '/usr/local/share/GeoIP', '/var/lib/GeoIP', '/usr/share/GeoIP2'] as $d)
        foreach (["GeoLite2-$kind.mmdb", "GeoIP2-$kind.mmdb", "dbip-$kind.mmdb"] as $f)
            if (is_file("$d/$f")) return $p[$kind] = "$d/$f";
    return $p[$kind] = '';
}
/** Offline 2-letter country code for an IP via the local MaxMind DB. '' if unavailable.
 *  Prefers the fast `mmdblookup` binary; falls back to the pure-PHP reader (includes/mmdb.php) when the binary
 *  is absent — so country still resolves on a box without libmaxminddb installed. */
function smpro_geoip_cc($ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return '';
    $db = smpro_geoip_db('Country') ?: smpro_geoip_db('City');
    if ($db === '') return '';
    $bin = smpro_geoip_bin();
    if ($bin !== '') {
        $out = (string)@shell_exec('timeout 4 ' . escapeshellarg($bin) . ' --file ' . escapeshellarg($db) . ' --ip ' . escapeshellarg($ip) . ' country iso_code 2>/dev/null');
        if (preg_match('/"([A-Za-z]{2})"/', $out, $m)) return strtoupper($m[1]);
    }
    return function_exists('smpro_mmdb_country') ? smpro_mmdb_country($db, $ip) : '';   // pure-PHP fallback
}
/** Offline ASN org/number via the local MaxMind ASN DB (if present). Returns ['asn'=>,'provider'=>] or [].
 *  Same mmdblookup-then-pure-PHP fallback as smpro_geoip_cc(). */
function smpro_geoip_asn($ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return [];
    $db = smpro_geoip_db('ASN');
    if ($db === '') return [];
    $bin = smpro_geoip_bin();
    if ($bin !== '') {
        $r = [];
        $n = (string)@shell_exec('timeout 4 ' . escapeshellarg($bin) . ' --file ' . escapeshellarg($db) . ' --ip ' . escapeshellarg($ip) . ' autonomous_system_number 2>/dev/null');
        if (preg_match('/(\d+)/', $n, $m)) $r['asn'] = 'AS' . $m[1];
        $o = (string)@shell_exec('timeout 4 ' . escapeshellarg($bin) . ' --file ' . escapeshellarg($db) . ' --ip ' . escapeshellarg($ip) . ' autonomous_system_organization 2>/dev/null');
        if (preg_match('/"([^"]+)"/', $o, $m)) $r['provider'] = trim($m[1]);
        if ($r) return $r;
    }
    return function_exists('smpro_mmdb_asn') ? smpro_mmdb_asn($db, $ip) : [];           // pure-PHP fallback
}
/** Candidate download URLs for a GeoIP DB kind, in fallback order. All no-key / https / curl-able (verified).
 *  date('Y-m') is built at runtime here (the DB-IP file is month-stamped). */
function smpro_geoip_sources($kind) {
    $mo = date('Y-m'); $pm = date('Y-m', strtotime('first day of last month'));
    if (strtolower($kind) === 'asn') return [
        'https://cdn.jsdelivr.net/npm/@ip-location-db/geolite2-asn-mmdb@latest/geolite2-asn.mmdb',      // combined v4+v6, no gzip
        'https://github.com/sapics/ip-location-db/releases/download/latest/geolite2-asn-ipv4.mmdb',     // 30x → needs follow
        "https://download.db-ip.com/free/dbip-asn-lite-$mo.mmdb.gz",
        "https://download.db-ip.com/free/dbip-asn-lite-$pm.mmdb.gz",
    ];
    return [
        "https://download.db-ip.com/free/dbip-country-lite-$mo.mmdb.gz",                                 // gzip, v4+v6, current month
        "https://download.db-ip.com/free/dbip-country-lite-$pm.mmdb.gz",                                 // prev-month fallback
        'https://cdn.jsdelivr.net/npm/@ip-location-db/dbip-country-mmdb/dbip-country-ipv4.mmdb',
        'https://github.com/sapics/ip-location-db/releases/download/latest/dbip-country-ipv4.mmdb',      // 30x → needs follow
        'https://cdn.jsdelivr.net/npm/@ip-location-db/geolite2-country-mmdb/geolite2-country-ipv4.mmdb',
    ];
}
/** Download a FRESH GeoIP DB from multiple free sources, validate it (pure-PHP reader, no mmdblookup needed),
 *  and atomically install it to SMPRO_VARLIB/geoip so it takes precedence over a stale/absent system DB.
 *  Returns ['ok'=>bool,'kind'=>,'source'=>,'bytes'=>,'msg'=>]. */
function smpro_geoip_update($kind = 'Country') {
    $kind = (strtolower($kind) === 'asn') ? 'ASN' : 'Country';
    $dir = SMPRO_VARLIB . '/geoip'; @is_dir($dir) || @mkdir($dir, 0755, true);
    $dest = "$dir/GeoLite2-$kind.mmdb";
    $marker = "\xab\xcd\xefMaxMind.com";
    // PRIMARY source = our LICENSED central delivery (we curate + keep it fresh from many mirrors,
    // gated by the license so it's a paid feature). Public mirrors stay as fallback so a server is
    // never left without a DB if our endpoint is unreachable or the license lapses.
    $lk   = (defined('SMPRO_LIC_BASE') && function_exists('smpro_lic_key')) ? trim((string) smpro_lic_key()) : '';
    $ours = ($lk !== '') ? [SMPRO_LIC_BASE . '/api/geoip?kind=' . strtolower($kind)] : [];
    foreach (array_merge($ours, smpro_geoip_sources($kind)) as $url) {
        $opts = ['timeout' => 90, 'follow' => true, 'maxbytes' => 80 * 1024 * 1024];   // cap download (anti-bomb)
        if ($lk !== '' && strpos($url, SMPRO_LIC_BASE . '/api/geoip') === 0) $opts['headers'] = ['X-License-Key: ' . $lk];   // authenticate to OUR endpoint (key stays in-process)
        $res = smpro_http($url, $opts);
        if (($res['code'] ?? 0) !== 200 || strlen($res['body']) < 50000) continue;
        $body = $res['body'];
        // gzip-bomb guard: cap the decompressed size (real DBs are ~30MB; reject anything wildly larger)
        if (substr($url, -3) === '.gz') { $d = @gzdecode($body, 96 * 1024 * 1024); if ($d === false || $d === '') continue; $body = $d; }
        if (strlen($body) < 100000 || strrpos($body, $marker) === false) continue;     // not a real mmdb
        // write to temp + validate WITH THE PURE-PHP READER (independent of mmdblookup)
        $tmp = $dest . '.tmp.' . getmypid();
        if (@file_put_contents($tmp, $body) === false) continue;
        @chmod($tmp, 0644);
        $valid = false;
        if (function_exists('smpro_mmdb_open')) {
            if ($kind === 'Country') $valid = (smpro_mmdb_country($tmp, '8.8.8.8') === 'US');
            else                     $valid = (bool)(smpro_mmdb_asn($tmp, '8.8.8.8'));
        } else { $valid = true; }                                                       // reader absent → trust marker check
        if (!$valid) { @unlink($tmp); continue; }
        if (!@rename($tmp, $dest)) { @unlink($tmp); continue; }                          // atomic install
        smpro_geoip_db($kind, true);                                                     // bust the path cache
        if (function_exists('smpro_in_cfg_save')) smpro_in_cfg_save(['geoip_last_update' => time()]);
        if (function_exists('smpro_audit')) smpro_audit('geoip_update', ['kind' => $kind, 'source' => $url, 'bytes' => strlen($body)]);
        return ['ok' => true, 'kind' => $kind, 'source' => $url, 'bytes' => strlen($body), 'msg' => "$kind DB updated (" . round(strlen($body)/1048576, 1) . " MB)"];
    }
    if (function_exists('smpro_audit')) smpro_audit('geoip_update', ['kind' => $kind, 'ok' => false]);
    return ['ok' => false, 'kind' => $kind, 'source' => '', 'bytes' => 0, 'msg' => "Could not download a $kind GeoIP database from any source."];
}
/** Throttled background refresh: pull Country+ASN when missing OR older than ~7 days. Cheap to call every cron tick. */
function smpro_geoip_auto_update() {
    $cfg = function_exists('smpro_in_cfg') ? smpro_in_cfg() : [];
    if (isset($cfg['geoip_auto_update']) && !$cfg['geoip_auto_update']) return;
    $missing = (smpro_geoip_db('Country') === '' || smpro_geoip_db('ASN') === '');
    $stale   = (time() - (int)($cfg['geoip_last_update'] ?? 0)) > 7 * 86400;
    if (!$missing && !$stale) return;
    foreach (['Country', 'ASN'] as $k) { try { smpro_geoip_update($k); } catch (\Throwable $e) {} }
}
/** HTTP request via the native curl extension so auth tokens/keys stay in this process's memory and never
 *  appear in the command line (shelling out to the `curl` binary leaks secrets via /proc/<pid>/cmdline,
 *  readable by other local users). TLS verification is ON. Returns ['code'=>int,'body'=>string,'error'=>string].
 *  $opts: method, headers[], body(string), timeout(int). Falls back to escaped shell curl only if the
 *  extension is missing (degraded — argv exposure — but functional). */
function smpro_http($url, array $opts = []) {
    $method  = strtoupper((string)($opts['method'] ?? 'GET'));
    $timeout = (int)($opts['timeout'] ?? 15);
    $headers = (array)($opts['headers'] ?? []);
    $body    = $opts['body'] ?? null;
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        $set = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => $timeout,
            CURLOPT_CONNECTTIMEOUT => max(3, min(10, $timeout)),
            CURLOPT_FOLLOWLOCATION => !empty($opts['follow']),   // opt-in (GeoIP CDN / GitHub-release URLs 30x-redirect)
            CURLOPT_MAXREDIRS      => 5,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_USERAGENT      => 'SafetyMonitorPro',
        ];
        if (!empty($opts['maxbytes'])) {                      // refuse oversized downloads (anti decompression/transfer bomb)
            $max = (int)$opts['maxbytes'];
            $set[CURLOPT_MAXFILESIZE] = $max;                                   // rejects when Content-Length exceeds the cap
            $set[CURLOPT_NOPROGRESS]  = false;
            $set[CURLOPT_PROGRESSFUNCTION] = function ($ch, $dlTotal, $dlNow) use ($max) { return ($dlNow > $max || $dlTotal > $max) ? 1 : 0; }; // abort if it grows past the cap mid-stream
        }
        if ($method === 'POST')      { $set[CURLOPT_POST] = true; if ($body !== null) $set[CURLOPT_POSTFIELDS] = $body; }
        elseif ($method !== 'GET')   { $set[CURLOPT_CUSTOMREQUEST] = $method; if ($body !== null) $set[CURLOPT_POSTFIELDS] = $body; }
        $hdr = '';
        if (!empty($opts['want_headers'])) $set[CURLOPT_HEADERFUNCTION] = function ($ch, $line) use (&$hdr) { $hdr .= $line; return strlen($line); };
        curl_setopt_array($ch, $set);
        $out = curl_exec($ch); $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE); $err = (string)curl_error($ch); curl_close($ch);
        return ['code' => $code, 'body' => ($out === false ? '' : (string)$out), 'error' => $err, 'hdr' => $hdr];
    }
    // degraded fallback: extension absent → shell curl (args fully escaped; only used if curl_init is missing)
    $cmd = 'curl -s -m ' . $timeout . (!empty($opts['follow']) ? ' -L' : '') . ' -X ' . escapeshellarg($method) . ' ' . escapeshellarg($url) . " -w '\\n%{http_code}'";
    foreach ($headers as $hh) $cmd .= ' -H ' . escapeshellarg($hh);
    if ($body !== null) $cmd .= ' --data-binary ' . escapeshellarg((string)$body);
    $raw = (string)@shell_exec($cmd . ' 2>/dev/null');
    $nl = strrpos($raw, "\n"); $code = $nl !== false ? (int)substr($raw, $nl + 1) : 0;
    return ['code' => $code, 'body' => $nl !== false ? substr($raw, 0, $nl) : $raw, 'error' => ''];
}
function _smpro_disabled_smpro_ip_intel($ip, $cap = true) {
    static $new = 0;
    $ip = trim((string)$ip);
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return ['ip' => $ip, 'country' => '', 'provider' => '', 'asn' => '', 'scope' => 'invalid'];
    if (!smpro_ip_is_external($ip)) return ['ip' => $ip, 'country' => 'LOCAL', 'provider' => 'Private/Reserved', 'asn' => '', 'scope' => 'local'];
    $cache = &smpro_ip_cache();
    $now = time();
    $save = function () use (&$cache) {
        $t = SMPRO_IPCACHE . '.tmp';
        @is_dir(dirname(SMPRO_IPCACHE)) || @mkdir(dirname(SMPRO_IPCACHE), 0700, true);
        @file_put_contents($t, json_encode($cache, JSON_UNESCAPED_SLASHES), LOCK_EX); @rename($t, SMPRO_IPCACHE); @chmod(SMPRO_IPCACHE, 0600);
    };
    if (isset($cache[$ip]) && ($now - (int)($cache[$ip]['cached_at'] ?? 0)) < SMPRO_IPTTL) {
        $r = $cache[$ip]; $r['scope'] = 'external';
        if ((($r['country'] ?? '') === '' || strtolower($r['country']) === 'n/a')) {     // backfill country offline for old network-only entries
            $cc = smpro_geoip_cc($ip); if ($cc !== '') { $cache[$ip]['country'] = $r['country'] = $cc; $save(); }
        }
        return $r;
    }
    // OFFLINE country FIRST — no network, no cap. This is what makes Country resolve behind egress firewalls.
    $cc = smpro_geoip_cc($ip);
    $intel = ['ip' => $ip, 'country' => ($cc !== '' ? $cc : 'n/a'), 'provider' => 'n/a', 'asn' => '', 'cached_at' => $now];
    if ($asn = smpro_geoip_asn($ip)) $intel = array_merge($intel, $asn);                  // offline provider/ASN if that DB exists
    // network whois (Team Cymru) enriches provider/ASN — only within the per-request cap
    if ($cap && $new < SMPRO_IPMAXNEW) {
        $new++;
        $raw = @shell_exec('timeout 4 whois -h whois.cymru.com ' . escapeshellarg(' -v ' . $ip) . ' 2>/dev/null');
        if ($raw) { $p = smpro_ip_parse_cymru(explode("\n", $raw)); if ($p) {
            if ((($p['country'] ?? '') === '' || strtolower((string)($p['country'] ?? '')) === 'n/a') && $cc !== '') $p['country'] = $cc;   // keep the offline country if whois lacks it
            $intel = array_merge($intel, $p);
        }}
    }
    $intel['scope'] = 'external';
    if ($cc !== '' || ($intel['provider'] !== 'n/a' && $intel['provider'] !== '')) {       // cache only when we learned something
        $store = $intel; unset($store['scope']); $cache[$ip] = $store; $save();
    }
    return $intel;
}

/** Arab countries (protected/trusted). EG+SA are the home core; the rest are still Arab (not "foreign"). */
function smpro_cc_is_arab($cc) {
    static $arab = ['EG','SA','AE','KW','QA','BH','OM','JO','LB','SY','IQ','YE','PS','DZ','MA','TN','LY','SD','MR','SO','DJ','KM'];
    return in_array(strtoupper((string)$cc), $arab, true);
}

/** Is an IP "foreign" = external + resolved to a NON-Arab country. Shared rule for
 *  login/spam/brute-force/intrusion. Returns ['foreign'=>bool,'cc'=>CC,'arab'=>bool,'local'=>bool,'known'=>bool]. */
function smpro_geo_foreign($ip) {
    $in  = function_exists('smpro_ip_intel') ? smpro_ip_intel($ip, false) : [];
    $cc  = strtoupper((string)($in['country'] ?? ''));
    $loc = (($in['scope'] ?? '') === 'local') || $cc === 'LOCAL' || (function_exists('smpro_ip_is_external') && !smpro_ip_is_external($ip));
    if ($loc) return ['foreign'=>false,'cc'=>'LOCAL','arab'=>false,'local'=>true,'known'=>true];
    $known = ($cc !== '' && $cc !== 'N/A' && $cc !== 'NA');
    $arab  = smpro_cc_is_arab($cc);
    return ['foreign'=>($known && !$arab), 'cc'=>$cc, 'arab'=>$arab, 'local'=>false, 'known'=>$known];
}

/**
 * Warm the IP cache for many IPs in ONE Team Cymru bulk whois call (fast).
 * Falls back to a few individual lookups if netcat is unavailable.
 */
function smpro_ip_intel_bulk($ips) {
    $cache = &smpro_ip_cache();
    $now = time();
    $need = [];
    foreach (array_unique($ips) as $ip) {
        if ($ip === '' || !smpro_ip_is_external($ip)) continue;
        if (isset($cache[$ip]) && ($now - (int)($cache[$ip]['cached_at'] ?? 0)) < SMPRO_IPTTL) continue;
        $need[] = $ip;
    }
    if (!$need) return;
    $need = array_slice($need, 0, 200);
    // Team Cymru bulk whois over a raw TCP socket via bash /dev/tcp (one round-trip
    // for all IPs). ncat's bulk mode is unreliable here, so we avoid it.
    $query = "begin\nverbose\n" . implode("\n", $need) . "\nend\n";
    $script = 'exec 3<>/dev/tcp/whois.cymru.com/43 || exit 1; printf %s ' . escapeshellarg($query) . ' >&3; cat <&3';
    $raw = (string)@shell_exec('timeout 14 bash -c ' . escapeshellarg($script) . ' 2>/dev/null');
    if (trim($raw) === '') {
        // whois/Team Cymru unreachable (e.g. outbound port 43 blocked) → warm COUNTRY offline from the local
        // MaxMind DB so the table + the Arab/EG-SA protection still work. Country-only here for speed.
        foreach (array_slice($need, 0, 80) as $ip) {
            if (isset($cache[$ip])) continue;
            $cc = smpro_geoip_cc($ip);
            if ($cc !== '') $cache[$ip] = ['ip'=>$ip,'country'=>$cc,'provider'=>'n/a','asn'=>'','source'=>'GeoIP (offline)','cached_at'=>$now];
        }
        $t = SMPRO_IPCACHE . '.tmp'; @is_dir(dirname(SMPRO_IPCACHE)) || @mkdir(dirname(SMPRO_IPCACHE), 0700, true);
        @file_put_contents($t, json_encode($cache, JSON_UNESCAPED_SLASHES), LOCK_EX); @rename($t, SMPRO_IPCACHE); @chmod(SMPRO_IPCACHE, 0600);
        return;
    }
    foreach (explode("\n", $raw) as $l) {
        $l = trim($l);
        if ($l === '' || stripos($l, 'Bulk mode') !== false || stripos($l, 'AS Name') !== false || strpos($l, '|') === false) continue;
        $p = array_map('trim', explode('|', $l)); // AS | IP | Prefix | CC | Registry | Allocated | AS Name
        if (count($p) >= 7 && filter_var($p[1], FILTER_VALIDATE_IP)) {
            $cache[$p[1]] = ['ip' => $p[1], 'asn' => 'AS' . $p[0], 'country' => $p[3], 'provider' => $p[6], 'source' => 'Team Cymru bulk', 'cached_at' => $now];
        }
    }
    $t = SMPRO_IPCACHE . '.tmp';
    @is_dir(dirname(SMPRO_IPCACHE)) || @mkdir(dirname(SMPRO_IPCACHE), 0700, true);
    @file_put_contents($t, json_encode($cache, JSON_UNESCAPED_SLASHES), LOCK_EX); @rename($t, SMPRO_IPCACHE); @chmod(SMPRO_IPCACHE, 0600);
}

/** Path to the csf binary, or '' if not installed. */
function smpro_csf_bin() {
    foreach (['/usr/sbin/csf', '/usr/local/csf/bin/csf'] as $b) if (is_executable($b)) return $b;
    return '';
}
/** Run a CSF action (block=-d / allow=-a / unblock=-dr). Immediate, no restart. Block/allow go through the
 *  VERIFIED helpers (never trust csf stdout); unblock removes from csf.deny robustly. */
function smpro_csf_do($action, $ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return ['ok' => false, 'msg' => 'invalid IP'];   // parity with the deny/allow helpers
    if ($action === 'block' && function_exists('smpro_csf_deny_add')) { $r = smpro_csf_deny_add($ip, 'smpro'); return ['ok'=>!empty($r['ok']), 'testing'=>!empty($r['testing']), 'recorded'=>!empty($r['recorded']), 'msg'=>(string)$r['msg']]; }
    if ($action === 'allow' && function_exists('smpro_csf_allow_add')) { $r = smpro_csf_allow_add($ip, 'smpro'); return ['ok'=>!empty($r['ok']), 'msg'=>(string)$r['msg']]; }
    $csf = smpro_csf_bin();
    if ($csf === '') return ['ok' => false, 'msg' => 'csf not found'];
    if ($action === 'unblock') {
        @shell_exec('timeout 25 ' . escapeshellarg($csf) . ' -dr ' . escapeshellarg($ip) . ' 2>&1');
        // also strip any direct csf.deny line we may have written when CSF was a no-op
        $f = '/etc/csf/csf.deny';
        if (is_file($f) && is_writable($f) && smpro_csf_denied($ip)) {
            $keep = array_filter(file($f, FILE_IGNORE_NEW_LINES) ?: [], fn($l) => !preg_match('/^' . preg_quote($ip, '/') . '(\s|$|\/|#)/', trim($l)));
            @file_put_contents($f, implode("\n", $keep) . "\n", LOCK_EX);
            if (!smpro_csf_testing()) @shell_exec('timeout 25 ' . escapeshellarg($csf) . ' -r >/dev/null 2>&1');
        }
        clearstatcache();
        return ['ok' => !smpro_csf_denied($ip), 'msg' => smpro_csf_denied($ip) ? ('could not remove ' . $ip) : ($ip . ' unblocked')];
    }
    $flag = $action === 'allow' ? '-a' : '-d';
    $out = (string)@shell_exec('timeout 25 ' . escapeshellarg($csf) . ' ' . $flag . ' ' . escapeshellarg($ip) . ' ' . escapeshellarg('smpro ' . date('Y-m-d H:i')) . ' 2>&1');
    return ['ok' => $out !== '' && stripos($out, 'error') === false, 'msg' => trim(mb_substr($out, 0, 160))];
}
/** Set of IPs already blocked by CSF (permanent csf.deny + temporary deny). */
function smpro_csf_blocked_set() {
    $set = [];
    if (is_readable('/etc/csf/csf.deny')) foreach (file('/etc/csf/csf.deny', FILE_IGNORE_NEW_LINES) ?: [] as $l) {
        $l = trim($l);
        if ($l === '' || $l[0] === '#') continue;
        if (preg_match('/^([0-9a-fA-F:.]+)/', $l, $m)) $set[$m[1]] = 'perm';
    }
    $csf = smpro_csf_bin();
    if ($csf !== '') foreach (explode("\n", (string)@shell_exec('timeout 5 ' . escapeshellarg($csf) . ' -t 2>/dev/null')) as $l)
        if (stripos($l, 'DENY') !== false && preg_match('/\b(\d{1,3}(?:\.\d{1,3}){3})\b/', $l, $m) && !isset($set[$m[1]])) $set[$m[1]] = 'temp';
    return $set;
}
/* ---- shared "hidden IPs" ignore-list (persisted, applies across modules) ---- */
if (!defined('SMPRO_HIDDEN_IPS')) define('SMPRO_HIDDEN_IPS', SMPRO_VARLIB . '/state/hidden_ips.json');
function smpro_hidden_ips() {
    static $s = null;
    if ($s === null) { $d = is_file(SMPRO_HIDDEN_IPS) ? json_decode((string)@file_get_contents(SMPRO_HIDDEN_IPS), true) : null; $s = is_array($d) ? $d : []; }
    return $s;
}
function smpro_hidden_ip_toggle($ip, $hide) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return false;
    $s = smpro_hidden_ips();
    if ($hide) $s[$ip] = ['at' => date('c'), 'by' => smpro_current_actor()];
    else unset($s[$ip]);
    @is_dir(dirname(SMPRO_HIDDEN_IPS)) || @mkdir(dirname(SMPRO_HIDDEN_IPS), 0700, true);
    $t = SMPRO_HIDDEN_IPS . '.tmp';
    @file_put_contents($t, json_encode($s, JSON_UNESCAPED_SLASHES), LOCK_EX); @rename($t, SMPRO_HIDDEN_IPS); @chmod(SMPRO_HIDDEN_IPS, 0600);
    // refresh the static cache
    $GLOBALS['__smpro_hidden_dirty'] = true;
    return true;
}

/** True for the 22 Arab-League country codes. */
function smpro_is_arab_cc($cc) {
    static $a = ['SA','EG','AE','KW','QA','BH','OM','JO','LB','IQ','SY','YE','PS','SD','LY','TN','DZ','MA','MR','SO','DJ','KM'];
    return in_array(strtoupper((string)$cc), $a, true);
}

/** Redact secrets from a command line before display/export. */
function smpro_redact_cmd($s) {
    // key=value or "key value" secrets
    $s = preg_replace('/(--?(?:password|passwd|pass|pwd|secret|token|api[_-]?key|auth[_-]?key|access[_-]?key))(=|\s+)\S+/i', '$1=***', $s);
    // mysql-style -p<password> (only when followed by non-space right after -p)
    $s = preg_replace('/(\s-p)(?=\S)\S+/', '$1***', $s);
    return $s;
}

/** Friendly service name guessed from a process/command name. */
function smpro_service_guess($comm) {
    static $map = [
        'mysqld' => 'MySQL/MariaDB', 'mariadbd' => 'MySQL/MariaDB', 'mysql' => 'MySQL client',
        'httpd' => 'Apache', 'apache2' => 'Apache', 'nginx' => 'Nginx', 'lsphp' => 'LiteSpeed PHP',
        'php-fpm' => 'PHP-FPM', 'php' => 'PHP', 'php-cgi' => 'PHP-CGI',
        'exim' => 'Exim (mail)', 'dovecot' => 'Dovecot (mail)', 'pure-ftpd' => 'FTP', 'proftpd' => 'FTP',
        'named' => 'DNS (BIND)', 'pdns_server' => 'PowerDNS', 'sshd' => 'SSH',
        'cpsrvd' => 'cPanel', 'cphulkd' => 'cPHulk', 'queueprocd' => 'cPanel queue', 'tailwatchd' => 'cPanel tailwatch',
        'imunify360' => 'Imunify360', 'ai-bolit' => 'Imunify scan', 'lfd' => 'CSF/LFD', 'csf' => 'CSF',
        'redis-server' => 'Redis', 'memcached' => 'Memcached', 'crond' => 'Cron', 'systemd' => 'systemd',
        'clamd' => 'ClamAV', 'spamd' => 'SpamAssassin',
    ];
    $c = strtolower(trim($comm));
    return $map[$c] ?? '';
}

/** Is this a real cPanel account? */
function smpro_is_cpanel_user($user) {
    return $user !== '' && preg_match('/^[a-zA-Z0-9._-]+$/', $user) && is_file('/var/cpanel/users/' . $user);
}

/** Per-user CPU risk based on pressure across cores. */
function smpro_proc_risk($cpu, $cores) {
    $pressure = $cores > 0 ? ($cpu / $cores) : $cpu;
    if ($cpu >= 300 || $pressure >= 8) return 'DANGER';
    if ($cpu >= 100 || $pressure >= 4) return 'WARNING';
    return 'GOOD';
}

/** Hide Safety Monitor's own scan noise from the listing. */
function smpro_proc_self_noise($comm, $args) {
    $c = strtolower($comm);
    if (in_array($c, ['ps', 'head', 'awk', 'sort', 'nice', 'timeout'], true)) return true;
    $a = strtolower($args);
    if (strpos($a, '/cgi/addons/smpro/') !== false) return true;
    if (strpos($a, 'smpro/index') !== false) return true;
    return false;
}

/**
 * Live process list (read-only via ps), with the same depth as the legacy page:
 * full usernames, PPID/STAT/ETIME/args, per-user groups, per-command rollup,
 * cPanel detection, risk scoring. No kill/renice/env exposure (plan §38).
 * Args are redacted before display/export.
 */
function smpro_top_processes($limit = 100) {
    $limit    = max(20, min(300, (int)$limit));
    $hideSelf = true;

    // user:48 keeps full usernames; comm:32 readable; COLUMNS=4096 avoids arg truncation.
    // Shell ordering is strict: the env assignment MUST come first, before timeout
    // and nice — neither of those can parse a leading VAR=val token.
    $ps = 'ps -eo user:48=,pid=,ppid=,comm:32=,pcpu=,pmem=,stat=,etime=,args= --sort=-pcpu';
    $wrapped = 'timeout ' . SMPRO_TIMEOUT_QUICK . ' ';
    if (is_executable('/usr/bin/nice')) $wrapped .= 'nice -n ' . SMPRO_SCAN_NICE . ' ';
    $cmd = 'COLUMNS=4096 ' . $wrapped . $ps . ' 2>/dev/null | head -n 800';
    $raw = @shell_exec($cmd);

    $cores = smpro_cpu_cores();
    $load  = smpro_loadavg();

    $rows = [];
    $hiddenSelf = 0;
    foreach (explode("\n", (string)$raw) as $line) {
        $line = trim($line);
        if ($line === '') continue;
        $p = preg_split('/\s+/', $line, 9);
        if (!$p || count($p) < 8) continue;

        $user = rtrim((string)$p[0]);
        $comm = (string)$p[3];
        $args = smpro_redact_cmd((string)($p[8] ?? ''));
        if ($user === '') continue;
        if ($hideSelf && smpro_proc_self_noise($comm, $args)) { $hiddenSelf++; continue; }

        $rows[] = [
            'user'      => $user,
            'pid'       => (int)$p[1],
            'ppid'      => (int)$p[2],
            'process'   => $comm,
            'cpu'       => round((float)$p[4], 1),
            'mem'       => round((float)$p[5], 1),
            'stat'      => (string)$p[6],
            'etime'     => (string)$p[7],
            'args'      => $args,
            'is_cpanel' => smpro_is_cpanel_user($user),
        ];
        if (count($rows) >= $limit) break;
    }

    // Group by user + roll up commands.
    $groups = [];
    $commands = [];
    foreach ($rows as $r) {
        $u = $r['user']; $cmdName = $r['process'];
        if (!isset($groups[$u])) {
            $groups[$u] = ['user' => $u, 'is_cpanel' => $r['is_cpanel'], 'cpu' => 0.0, 'mem' => 0.0,
                           'processes' => 0, 'top_process' => '', 'top_pid' => 0, 'top_cpu' => 0.0, '_cmds' => []];
        }
        $groups[$u]['cpu'] += $r['cpu'];
        $groups[$u]['mem'] += $r['mem'];
        $groups[$u]['processes']++;
        if ($r['cpu'] > $groups[$u]['top_cpu']) {
            $groups[$u]['top_cpu'] = $r['cpu']; $groups[$u]['top_process'] = $cmdName; $groups[$u]['top_pid'] = $r['pid'];
        }
        $groups[$u]['_cmds'][$cmdName] = ($groups[$u]['_cmds'][$cmdName] ?? 0) + 1;
        if (!isset($commands[$cmdName])) $commands[$cmdName] = ['command' => $cmdName, 'count' => 0, 'cpu' => 0.0];
        $commands[$cmdName]['count']++; $commands[$cmdName]['cpu'] += $r['cpu'];
    }
    foreach ($groups as &$g) {
        $g['cpu'] = round($g['cpu'], 1);
        $g['mem'] = round($g['mem'], 1);
        $g['pressure'] = round($cores > 0 ? $g['cpu'] / $cores : 0, 1);
        $g['risk'] = smpro_proc_risk($g['cpu'], $cores);
        arsort($g['_cmds']);
        $topName = array_key_first($g['_cmds']);
        $g['top_command_group'] = $topName !== null ? $topName . ' ×' . $g['_cmds'][$topName] : '';
        unset($g['_cmds'], $g['top_cpu']);
    }
    unset($g);
    $groups = array_values($groups);
    usort($groups, fn($a, $b) => $b['cpu'] <=> $a['cpu']);

    foreach ($commands as &$c) $c['cpu'] = round($c['cpu'], 1);
    unset($c);
    $commands = array_values($commands);
    usort($commands, fn($a, $b) => $b['cpu'] <=> $a['cpu']);

    return [
        'ts'          => date('H:i:s'),
        'time'        => date('Y-m-d H:i:s'),
        'cores'       => $cores,
        'load'        => $load,
        'load_disp'   => sprintf('%.2f / %.2f / %.2f', $load['1m'], $load['5m'], $load['15m']),
        'limit'       => $limit,
        'hidden_self' => $hiddenSelf,
        'total'       => count($rows),
        'users_count' => count($groups),
        'top_user'    => $groups[0] ?? null,
        'groups'      => $groups,
        'commands'    => array_slice($commands, 0, 16),
        'rows'        => $rows,
    ];
}

/**
 * Collect ALL live metrics in one shot. Shared by the HTML render and the
 * JSON polling endpoint so both always show identical, real-time values.
 */
/** Highest CPU/package temperature in °C (thermal zones → sensors), or null if no sensor. */
function smpro_cpu_temp() {
    $max = null;
    foreach (glob('/sys/class/thermal/thermal_zone*/temp') ?: [] as $f) {
        $v = (int)trim((string)@file_get_contents($f));
        if ($v > 0 && $v < 200000) { $c = $v / 1000; if ($max === null || $c > $max) $max = $c; }
    }
    if ($max !== null) return round($max, 1);
    $out = (string)@shell_exec('sensors 2>/dev/null');
    if ($out !== '') {
        // take the FIRST temperature after each label's colon (the live reading) — ignore (high=/crit=) thresholds
        foreach (explode("\n", $out) as $line) {
            if (preg_match('/:\s*[+]?(\d{2,3}(?:\.\d)?)\s*°C/u', $line, $m)) {
                $c = (float)$m[1];
                if ($c > 0 && $c < 150 && ($max === null || $c > $max)) $max = $c;
            }
        }
        if ($max !== null) return round($max, 1);
    }
    return null;
}
function smpro_collect_metrics() {
    $cores = smpro_cpu_cores();
    $load  = smpro_loadavg();
    $cpu   = smpro_cpu_usage();
    $mem   = smpro_memory();
    $disk  = smpro_disk_root();
    $procs = smpro_process_count();
    $up    = smpro_uptime();

    $pressure = $cores ? round($load['1m'] / $cores * 100, 1) : 0;
    $swap_pct = $mem['swap_total_mb'] ? round($mem['swap_used_mb'] / $mem['swap_total_mb'] * 100, 1) : 0;
    $health   = smpro_load_status($pressure);   // load uses the 70/100 rule (consistent w/ Server Health page)

    return [
        'ts'        => date('H:i:s'),
        'host'      => gethostname(),
        'cores'     => $cores,
        'load'      => $load,
        'pressure'  => $pressure,
        'health'    => $health,
        'health_label' => $health === 'good' ? 'GOOD' : ($health === 'warn' ? 'WARNING' : 'CRITICAL'),
        'cpu'       => ['pct' => $cpu, 'status' => smpro_status($cpu)],
        'ram'       => ['pct' => $mem['percent'], 'status' => smpro_status($mem['percent']),
                        'used' => smpro_bytes($mem['used_mb'] * 1048576), 'total' => smpro_bytes($mem['total_mb'] * 1048576)],
        'disk'      => ['pct' => $disk['percent'], 'status' => smpro_status($disk['percent']),
                        'used' => smpro_bytes($disk['used']), 'total' => smpro_bytes($disk['total']), 'free' => smpro_bytes($disk['free'])],
        'swap'      => ['pct' => $swap_pct, 'status' => smpro_status($swap_pct),
                        'used_mb' => $mem['swap_used_mb'], 'total_mb' => $mem['swap_total_mb']],
        'procs'     => $procs,
        'uptime'    => smpro_dur($up),
        'temp'      => smpro_cpu_temp(),
    ];
}

/** Set of THIS server's own IP addresses (bound IPs + cPanel main/additional). Cached. */
function _smpro_disabled_smpro_server_ips() {
    static $set = null;
    if ($set !== null) return $set;
    $set = [];
    foreach (explode("\n", (string)@shell_exec("ip -o addr show 2>/dev/null | awk '{print \$4}'")) as $l) {
        $ip = explode('/', trim($l))[0];
        if ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP)) $set[$ip] = 1;
    }
    $mi = is_readable('/var/cpanel/mainip') ? trim((string)@file_get_contents('/var/cpanel/mainip')) : '';
    if (filter_var($mi, FILTER_VALIDATE_IP)) $set[$mi] = 1;
    if (is_readable('/etc/ips')) foreach (file('/etc/ips', FILE_IGNORE_NEW_LINES) ?: [] as $l)
        if (preg_match('/^([0-9a-fA-F:.]+):/', trim($l), $m) && filter_var($m[1], FILTER_VALIDATE_IP)) $set[$m[1]] = 1;
    return $set;
}
/** True if $ip is loopback/localhost or one of this server's own IPs (never block these). */
function _smpro_disabled_smpro_is_server_ip($ip) {
    $ip = trim((string)$ip);
    if ($ip === '') return false;
    if ($ip === '::1' || $ip === '::' || strpos($ip, '127.') === 0) return true;
    return isset(smpro_server_ips()[$ip]);
}

/* ---- plugin master control: Enabled / Dry-Run / Disabled (+ auto re-enable date) ---- */
function smpro_ctl_file() { return SMPRO_VARLIB . '/control.json'; }
function smpro_ctl_save($c) { @is_dir(SMPRO_VARLIB) || @mkdir(SMPRO_VARLIB, 0700, true); @file_put_contents(smpro_ctl_file(), json_encode($c, JSON_UNESCAPED_SLASHES), LOCK_EX); }
/** Read control state, auto re-enabling if a scheduled re-enable time has passed. */
function smpro_ctl_get() {
    $f = smpro_ctl_file();
    $c = is_file($f) ? json_decode((string)@file_get_contents($f), true) : null;
    if (!is_array($c)) $c = [];
    $c += ['mode' => 'enabled', 'reenable_at' => 0, 'updated_at' => 0, 'actor' => ''];
    if (!in_array($c['mode'], ['enabled', 'dryrun', 'disabled'], true)) $c['mode'] = 'enabled';
    // auto re-enable: a scheduled restart time has arrived → flip back to enabled
    if ($c['mode'] === 'disabled' && (int)$c['reenable_at'] > 0 && time() >= (int)$c['reenable_at']) {
        $c['mode'] = 'enabled'; $c['reenable_at'] = 0; $c['updated_at'] = time(); $c['actor'] = 'auto-reenable';
        smpro_ctl_save($c);
        if (function_exists('smpro_audit')) smpro_audit('plugin_control', ['mode' => 'enabled', 'by' => 'auto-reenable']);
    }
    return $c;
}
function smpro_ctl_mode()     { return smpro_ctl_get()['mode']; }
function smpro_ctl_disabled() {
    if (smpro_ctl_get()['mode'] === 'disabled') return true;                 // admin manually disabled
    // flagged diagnostics marker (confirmed endpoint redirect) → IMMEDIATE full stop; cleared only by a server reset
    if (function_exists('smpro_lic_tlm_at') && smpro_lic_tlm_at() > 0) return true;
    // connection-loss SOFT stop (opted-in licenses only, reversible) → full stop; resumes the instant a fresh
    // signed exchange returns. NOT a tamper — must stay OUT of $smTamperLock so License/Plugin-Control stay reachable.
    if (function_exists('smpro_lic_sync_disabled') && smpro_lic_sync_disabled()) return true;
    // pairing REVERSIBLE stop (opt-in; signed pair_stop=true) — same soft, non-tamper, self-healing posture as sync.
    if (function_exists('smpro_lic_pair_stopped') && smpro_lic_pair_stopped()) return true;
    // license stopped (expired/suspended/revoked) for >48h → whole plugin dormant (all functions off; resumes on renewal)
    if (function_exists('smpro_lic_dormant') && smpro_lic_dormant()) return true;
    return false;
}
/** True when the plugin should MONITOR but NOT take automatic actions (auto-block, auto-fix, throttle, auto-update). */
function smpro_ctl_dry_run()  { return smpro_ctl_get()['mode'] === 'dryrun'; }

/* ---- admin self-IP firewall allow-list (offer to whitelist the operator's own IP) ---- */
/** The admin's connecting IP (X-Forwarded-For / X-Real-IP / REMOTE_ADDR; skips loopback). */
function smpro_admin_ip() {
    // WHM/cpsrvd is the direct peer (NOT behind a proxy/CDN), so REMOTE_ADDR is the real, unforgeable client IP.
    // Trust it first; only fall back to the forgeable X-Forwarded-For/X-Real-IP if REMOTE_ADDR is somehow absent.
    foreach (['REMOTE_ADDR','HTTP_X_FORWARDED_FOR','HTTP_X_REAL_IP'] as $k) {
        $v = trim((string)($_SERVER[$k] ?? '')); if ($v === '') continue;
        $v = trim(explode(',', $v)[0]);
        if (filter_var($v, FILTER_VALIDATE_IP) && $v !== '127.0.0.1' && $v !== '::1') return $v;
    }
    return '';
}
/** Is the IP already in csf.allow (full allow / never block)? */
function smpro_csf_allowlisted($ip) {
    if ($ip === '' || !is_readable('/etc/csf/csf.allow')) return false;
    foreach (file('/etc/csf/csf.allow', FILE_IGNORE_NEW_LINES) ?: [] as $l) {
        $l = trim($l); if ($l === '' || $l[0] === '#') continue;
        if (preg_match('/^' . preg_quote($ip, '/') . '(\s|$|\/|#)/', $l)) return true;
    }
    return false;
}
/**
 * Robustly add an IP to csf.allow (full allow / never block). Works whether CSF is enabled
 * or disabled (TESTING): tries `csf -a`, then VERIFIES against csf.allow, and if it didn't land
 * (e.g. CSF disabled = csf -a is a no-op) it appends to /etc/csf/csf.allow directly so the allow
 * applies as soon as CSF runs. Returns ['ok'=>bool,'already'=>bool,'msg'=>string]. Never trusts
 * csf's stdout for success — only the actual presence in csf.allow.
 */
function smpro_csf_allow_add($ip, $reason = '') {
    $ip = trim((string)$ip);
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return ['ok'=>false,'already'=>false,'msg'=>'invalid IP'];
    if (smpro_csf_allowlisted($ip)) return ['ok'=>true,'already'=>true,'msg'=>$ip . ' is already allow-listed (csf.allow).'];
    $reason = preg_replace('/[^A-Za-z0-9 ._\-\/:()]/', '', mb_substr((string)$reason, 0, 80)) ?: 'smpro';
    $csf = function_exists('smpro_im_csf_bin') ? smpro_im_csf_bin() : '';
    if ($csf !== '') @shell_exec('timeout 25 ' . escapeshellarg($csf) . ' -a ' . escapeshellarg($ip) . ' ' . escapeshellarg($reason) . ' 2>&1');
    clearstatcache();
    if (!smpro_csf_allowlisted($ip)) {                              // csf disabled / no-op → write the file directly
        $f = '/etc/csf/csf.allow';
        if (is_file($f) && is_writable($f)) @file_put_contents($f, $ip . ' # ' . $reason . ' - ' . date('D M j H:i:s Y') . "\n", FILE_APPEND | LOCK_EX);
        clearstatcache();
        if ($csf !== '' && smpro_csf_allowlisted($ip)) @shell_exec('timeout 25 ' . escapeshellarg($csf) . ' -r >/dev/null 2>&1');  // reload if CSF is enabled
    }
    $ok = smpro_csf_allowlisted($ip);
    return ['ok'=>$ok, 'already'=>false, 'msg'=>$ok ? ($ip . ' added to csf.allow (never block).') : ('could not write csf.allow for ' . $ip . '.')];
}
/** Is CSF in TESTING mode? Then `csf -d` writes csf.deny but does NOT load rules into iptables → NOT enforced. */
function smpro_csf_testing() {
    $f = '/etc/csf/csf.conf';
    return is_readable($f) && (bool)preg_match('/^\s*TESTING\s*=\s*"?1"?/m', (string)@file_get_contents($f));
}
/** Is the IP currently in csf.deny (permanent or temp)? Direct end-state read — the source of truth for "blocked". */
function smpro_csf_denied($ip) {
    $ip = trim((string)$ip);
    if ($ip === '') return false;
    clearstatcache();
    $set = function_exists('smpro_csf_blocked_set') ? smpro_csf_blocked_set() : [];
    return isset($set[$ip]);
}
/**
 * Robustly block an IP in CSF — the deny twin of smpro_csf_allow_add(). Tries `csf -d`, VERIFIES the IP
 * actually landed in csf.deny, falls back to a direct csf.deny write if csf was a no-op, and reloads CSF
 * when it is enforcing. NEVER trusts csf's stdout. Detects TESTING mode (recorded but NOT enforced).
 * Returns ['ok'=>bool ENFORCED, 'recorded'=>bool, 'testing'=>bool, 'already'=>bool, 'msg'=>string].
 */
function smpro_csf_deny_add($ip, $reason = '') {
    $ip = trim((string)$ip);
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return ['ok'=>false,'recorded'=>false,'testing'=>false,'already'=>false,'msg'=>'invalid IP'];
    $reason = preg_replace('/[^A-Za-z0-9 ._\-\/:()]/', '', mb_substr((string)$reason, 0, 80)) ?: 'smpro';   // parity w/ allow_add: no newlines into csf.deny
    $testing = smpro_csf_testing();
    $csf = smpro_csf_bin();
    $already = smpro_csf_denied($ip);
    if (!$already && $csf !== '')
        @shell_exec('timeout 25 ' . escapeshellarg($csf) . ' -d ' . escapeshellarg($ip) . ' ' . escapeshellarg(($reason !== '' ? $reason : 'smpro') . ' - ' . date('Y-m-d H:i')) . ' 2>&1');
    if (!smpro_csf_denied($ip)) {                                    // csf absent / no-op (e.g. disabled) → write csf.deny directly
        $f = '/etc/csf/csf.deny';
        if (is_file($f) && is_writable($f)) @file_put_contents($f, $ip . ' # ' . ($reason !== '' ? $reason : 'smpro') . ' - ' . date('D M j H:i:s Y') . "\n", FILE_APPEND | LOCK_EX);
        if ($csf !== '' && !$testing && smpro_csf_denied($ip)) @shell_exec('timeout 25 ' . escapeshellarg($csf) . ' -r >/dev/null 2>&1');   // reload only if enforcing
    }
    $recorded = smpro_csf_denied($ip);
    $enforced = $recorded && !$testing && $csf !== '';
    if (!$recorded) $msg = ($csf === '' ? 'No firewall (CSF) installed — cannot block ' . $ip . '.' : 'Could not write csf.deny for ' . $ip . '.');
    elseif ($testing) $msg = $ip . ' added to csf.deny, but CSF is in TESTING mode — NOT enforced. Set TESTING=0 (Server Tune-up) to actually block.';
    elseif ($csf === '') $msg = $ip . ' written to csf.deny — will apply once CSF is installed/running.';
    else $msg = ($already ? $ip . ' is already blocked in CSF.' : $ip . ' blocked in CSF (csf.deny).');
    return ['ok'=>$enforced, 'recorded'=>$recorded, 'testing'=>$testing, 'already'=>$already && $recorded, 'msg'=>$msg];
}
function smpro_fw_self_state() { $f = SMPRO_VARLIB . '/fw_self_allow.json'; $d = is_file($f) ? json_decode((string)@file_get_contents($f), true) : null; return is_array($d) ? $d : []; }
function smpro_fw_self_state_save($s) { @file_put_contents(SMPRO_VARLIB . '/fw_self_allow.json', json_encode($s, JSON_UNESCAPED_SLASHES), LOCK_EX); }
/** Offer to allow-list the admin's own IP? true when CSF is present, an IP is detected,
 *  it's not already in csf.allow, and it hasn't already been added. (Re-asks each session until added.) */
function smpro_fw_self_should_prompt() {
    if (!function_exists('smpro_im_csf_bin') || smpro_im_csf_bin() === '') return false;
    $ip = smpro_admin_ip(); if ($ip === '') return false;
    if (smpro_csf_allowlisted($ip)) return false;
    $st = smpro_fw_self_state();
    return (($st[$ip]['d'] ?? '') !== 'added');
}

/** All cPanel account usernames on this server (cached). Empty on a non-cPanel host. */
function smpro_cpanel_users() {
    static $u = null;
    if ($u !== null) return $u;
    $u = [];
    foreach (glob('/var/cpanel/users/*') ?: [] as $f) {
        $b = basename($f);
        if ($b !== '' && $b !== 'system' && preg_match('/^[a-zA-Z0-9._-]+$/', $b)) $u[] = $b;
    }
    sort($u);
    return $u;
}
/**
 * Emit the shared account autocomplete: a JS list of all cPanel users + a small
 * reliable typeahead widget (filters as you type, styled dropdown, keyboard nav).
 * Attaches to any input carrying  data-ac="accounts". Also keeps a native
 * <datalist id="smAccounts"> as a no-JS fallback.
 */
function smpro_account_datalist() {
    $users = smpro_cpanel_users();
    if (!$users) return;
    echo '<datalist id="smAccounts">';
    foreach ($users as $u) echo '<option value="' . smpro_h($u) . '">';
    echo '</datalist>';
    echo '<script>window.SM_ACCOUNTS=' . json_encode(array_values($users), JSON_UNESCAPED_SLASHES) . ';</script>';
    ?>
<style>
.sm-ac{position:absolute;z-index:9999;background:#fff;border:1px solid var(--line);border-radius:10px;box-shadow:0 14px 34px rgba(15,23,42,.16);max-height:300px;overflow:auto;padding:4px}
.sm-aci{padding:8px 11px;font-size:13px;cursor:pointer;font-family:ui-monospace,Consolas,monospace;border-radius:7px}
.sm-aci.on,.sm-aci:hover{background:var(--brand-bg);color:var(--brand)}
.sm-aci b{color:var(--brand);font-weight:800}
.sm-ac-empty{padding:9px 11px;font-size:12px;color:var(--muted)}
</style>
<script>
(function(){
  var ACC=window.SM_ACCOUNTS||[]; if(!ACC.length)return;
  function esc(s){return String(s).replace(/[&<>"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
  document.querySelectorAll('input[data-ac="accounts"]').forEach(function(inp){
    inp.setAttribute('autocomplete','off'); inp.removeAttribute('list');
    var box=document.createElement('div');box.className='sm-ac';box.style.display='none';document.body.appendChild(box);
    var idx=-1,items=[];
    function place(){var r=inp.getBoundingClientRect();box.style.left=(r.left+window.scrollX)+'px';box.style.top=(r.bottom+window.scrollY+3)+'px';box.style.minWidth=Math.max(220,r.width)+'px';}
    function render(){
      var q=(inp.value||'').toLowerCase().trim();
      items=ACC.filter(function(a){return q===''||a.toLowerCase().indexOf(q)>=0;});
      items.sort(function(a,b){var pa=a.toLowerCase().indexOf(q)===0?0:1,pb=b.toLowerCase().indexOf(q)===0?0:1;return pa-pb||a.localeCompare(b);});
      items=items.slice(0,14);
      if(!items.length){box.innerHTML='<div class="sm-ac-empty">No matching account</div>';place();box.style.display='block';return;}
      var re=q?new RegExp('('+q.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+')','ig'):null;
      box.innerHTML=items.map(function(a,i){var lbl=re?esc(a).replace(re,'<b>$1</b>'):esc(a);return '<div class="sm-aci'+(i===idx?' on':'')+'" data-v="'+esc(a)+'">'+lbl+'</div>';}).join('');
      place();box.style.display='block';
    }
    function close(){box.style.display='none';idx=-1;}
    function choose(v){inp.value=v;close();inp.dispatchEvent(new Event('change',{bubbles:true}));inp.focus();}
    inp.addEventListener('input',function(){idx=-1;render();});
    inp.addEventListener('focus',render);
    inp.addEventListener('keydown',function(e){
      if(box.style.display==='none'){if(e.key==='ArrowDown')render();return;}
      if(e.key==='ArrowDown'){idx=Math.min(items.length-1,idx+1);render();e.preventDefault();}
      else if(e.key==='ArrowUp'){idx=Math.max(0,idx-1);render();e.preventDefault();}
      else if(e.key==='Enter'){if(idx>=0&&items[idx]){choose(items[idx]);e.preventDefault();}else close();}
      else if(e.key==='Escape'){close();}
    });
    box.addEventListener('mousedown',function(e){var it=e.target.closest('.sm-aci');if(it){choose(it.getAttribute('data-v'));e.preventDefault();}});
    inp.addEventListener('blur',function(){setTimeout(close,160);});
    window.addEventListener('scroll',function(){if(box.style.display!=='none')place();},true);
    window.addEventListener('resize',function(){if(box.style.display!=='none')place();});
  });
})();
</script>
    <?php
}
