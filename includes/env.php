<?php
/**
 * env.php - environment & capability detection.
 *
 * The plugin adapts to whatever is present on the host. Optional components
 * (cPanel/WHM, Imunify360, CSF, Exim, JetBackup, chattr, curl, whois) are
 * detected here; anything missing is surfaced as a NON-blocking warning in the
 * page header (see layout.php) with a hint on how to enable it. Missing pieces
 * only disable the feature that needs them - they never break the rest.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

/** Is a binary available (by name on PATH, or absolute path)? Cached per request. */
function smpro_has_bin($name) {
    static $cache = [];
    if (isset($cache[$name])) return $cache[$name];
    if (strpos($name, '/') === 0) return $cache[$name] = is_executable($name);
    foreach (['/usr/local/cpanel/3rdparty/bin/', '/usr/sbin/', '/usr/bin/', '/usr/local/bin/', '/bin/', '/sbin/'] as $p)
        if (is_executable($p . $name)) return $cache[$name] = true;
    $out = []; $rc = 1; @exec('command -v ' . escapeshellarg($name) . ' 2>/dev/null', $out, $rc);
    return $cache[$name] = ($rc === 0 && !empty($out));
}

/** True on a cPanel/WHM server. */
function smpro_has_cpanel() { return is_dir('/usr/local/cpanel'); }

/** OS package manager on this host: 'apt' | 'dnf' | 'yum' | 'zypper' | ''. */
function smpro_pkg_mgr() {
    static $m = null;
    if ($m !== null) return $m;
    foreach (['dnf', 'apt-get', 'yum', 'zypper'] as $b) if (smpro_has_bin($b)) { $m = ($b === 'apt-get' ? 'apt' : $b); return $m; }
    return $m = '';
}

/**
 * Capability catalogue. key => [
 *   label, present(bool), affects, hint,
 *   pkg   => OS package name if it can be installed via the package manager (else ''),
 *   doc   => external install URL for vendor components (else '')
 * ].
 * Cached for the request. Used by the header warning banner.
 */
function smpro_capabilities() {
    static $caps = null;
    if ($caps !== null) return $caps;
    $caps = [
        'cpanel'    => ['cPanel &amp; WHM',         smpro_has_cpanel(),
                        'Account management, WHM integration, root-ACL auth',
                        'This plugin is built for cPanel/WHM servers. On a non-cPanel host, account-level features stay disabled.',
                        '', 'https://docs.cpanel.net/installation-guide/'],
        'imunify'   => ['Imunify360 / ImunifyAV',   smpro_has_bin('imunify360-agent'),
                        'Malware scanning · Forensics · Imunify360 reports',
                        'Install Imunify360 (paid) or the free ImunifyAV to populate malware detection.',
                        '', 'https://docs.imunify360.com/installation/'],
        'csf'       => ['CSF firewall',             smpro_has_bin('csf'),
                        'IP blocking (Login/Spam) · Firewall status',
                        'Install ConfigServer Security &amp; Firewall — the cPanel package is <code>cpanel-csf</code>.',
                        'cpanel-csf', 'https://docs.cpanel.net/knowledge-base/third-party/how-to-install-csf/'],
        'exim'      => ['Exim mail server',         smpro_has_bin('exim'),
                        'Spam &amp; mail-queue analysis · outbound blocking',
                        'cPanel ships Exim; if missing, install/enable it via WHM.',
                        '', ''],
        'jetbackup' => ['JetBackup 5',              smpro_has_bin('jetbackup5api'),
                        'Backup monitor &amp; auto-retry',
                        'Install JetBackup 5 (one-line installer).',
                        '', 'https://docs.jetbackup.com/v5.3/manual/gettingStarted/installation.html'],
        'chattr'    => ['chattr / lsattr',          smpro_has_bin('chattr') && smpro_has_bin('lsattr'),
                        'PHP Harden file locking (immutable bit)',
                        'Provided by the e2fsprogs package.',
                        'e2fsprogs', ''],
        'curl'      => ['curl',                     smpro_has_bin('curl'),
                        'AI providers · Telegram · Pushbullet · WhatsApp',
                        'Provided by the curl package.',
                        'curl', ''],
        'whois'     => ['whois',                    smpro_has_bin('whois'),
                        'IP country / provider intelligence',
                        'Provided by the whois package.',
                        'whois', ''],
        'geoip'     => ['MaxMind GeoIP (mmdblookup)', smpro_has_bin('mmdblookup'),
                        'Offline IP country + ASN / datacenter detection (Arab-exclusion + geo auto-block rules)',
                        'Provided by libmaxminddb (RPM) / mmdb-bin (Debian). A pure-PHP reader also ships as a fallback.',
                        'libmaxminddb', ''],
        'vnstat'    => ['vnStat',                   smpro_has_bin('vnstat'),
                        'Network traffic history (per-hour / day / month totals)',
                        'Provided by the vnstat package — historical upload/download totals.',
                        'vnstat', ''],
        'sensors'   => ['lm-sensors',               smpro_has_bin('sensors') || (bool)glob('/sys/class/thermal/thermal_zone*/temp'),
                        'CPU / board temperature in the header health bar',
                        'Provided by the lm-sensors package — reads hardware thermal sensors. (Virtual machines often expose no temperature sensor.)',
                        'lm-sensors', ''],
        'sysstat'   => ['sysstat (sar)',            smpro_has_bin('sar'),
                        'Outage &amp; resource history — load / memory / network timelines in Reports Center',
                        'Provided by the sysstat package; the collector service is enabled automatically so history accumulates.',
                        'sysstat', ''],
    ];
    return $caps;
}

/** List of missing capabilities (present === false), each w/ install metadata. */
function smpro_missing_capabilities() {
    $mgr = smpro_pkg_mgr();
    $out = [];
    foreach (smpro_capabilities() as $k => $c) {
        if (!empty($c[1])) continue;
        $pkg = $c[4] ?? '';
        $out[] = ['key' => $k, 'label' => $c[0], 'affects' => $c[2], 'hint' => $c[3],
                  'pkg' => $pkg, 'doc' => $c[5] ?? '',
                  'installable' => $pkg !== '' && $mgr !== ''];
    }
    return $out;
}

/** Install a capability's OS package via the detected package manager. Returns [ok, detail]. */
function smpro_env_install($key) {
    $caps = smpro_capabilities();
    if (!isset($caps[$key])) return [false, 'unknown component'];
    // CSF: use the dedicated installer (cpanel-csf package + firewalld handling + verification).
    if ($key === 'csf' && function_exists('smpro_tun_install_csf')) {
        $r = smpro_tun_install_csf();
        return [!empty($r['ok']), (string)($r['msg'] ?? ($r['ok'] ? 'installed' : 'install failed'))];
    }
    $pkg = $caps[$key][4] ?? '';
    if ($pkg === '') return [false, 'this component is not installable from here — use its vendor installer'];
    $mgr = smpro_pkg_mgr();
    if ($mgr === '') return [false, 'no supported package manager (apt/dnf/yum/zypper) found'];
    // package names differ between Debian (apt) and RPM (dnf/yum/zypper) for some components
    $aliases = [
        'sensors' => ['apt' => 'lm-sensors', 'dnf' => 'lm_sensors', 'yum' => 'lm_sensors', 'zypper' => 'sensors'],
        'geoip'   => ['apt' => 'mmdb-bin',   'dnf' => 'libmaxminddb', 'yum' => 'libmaxminddb', 'zypper' => 'libmaxminddb'],
    ];
    if (isset($aliases[$key][$mgr])) $pkg = $aliases[$key][$mgr];
    // the binary that proves success can differ from the package name
    $bins = ['sensors' => 'sensors', 'chattr' => 'chattr', 'imunify' => 'imunify360-agent', 'jetbackup' => 'jetbackup5api', 'csf' => 'csf', 'geoip' => 'mmdblookup', 'sysstat' => 'sar'];
    $bin  = $bins[$key] ?? $pkg;
    $pkgArg = escapeshellarg($pkg);
    switch ($mgr) {
        case 'apt':    $cmd = 'DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y ' . $pkgArg; break;
        case 'dnf':    $cmd = 'dnf install -y ' . $pkgArg; break;
        case 'yum':    $cmd = 'yum install -y ' . $pkgArg; break;
        case 'zypper': $cmd = 'zypper -n install ' . $pkgArg; break;
        default:       return [false, 'unsupported package manager'];
    }
    $out = (string)@shell_exec('timeout 240 ' . $cmd . ' 2>&1');
    // sysstat ships the sar binary but collects nothing until its timer/service is enabled - turn it on best-effort
    // (service name differs: Debian `sysstat`, RHEL adds `sysstat-collect.timer`); errors are harmless no-ops.
    if ($key === 'sysstat') @shell_exec('systemctl enable --now sysstat 2>/dev/null; systemctl enable --now sysstat-collect.timer 2>/dev/null; systemctl enable --now sysstat.service 2>/dev/null');
    $now = is_executable('/usr/bin/' . $bin) || is_executable('/usr/sbin/' . $bin) || is_executable('/bin/' . $bin)
        || (bool)@shell_exec('command -v ' . escapeshellarg($bin) . ' 2>/dev/null');
    if (function_exists('smpro_audit')) smpro_audit('env_install', ['component' => $key, 'pkg' => $pkg, 'mgr' => $mgr, 'ok' => $now]);
    return [$now, $now ? ($pkg . ' installed via ' . $mgr) : ('install failed via ' . $mgr . ': ' . trim(mb_substr($out, -200)))];
}

/** Quick boolean for a single capability, e.g. smpro_cap('imunify'). */
function smpro_cap($key) { $c = smpro_capabilities(); return !empty($c[$key][1]); }

/** Tools the plugin AUTO-INSTALLS (best-effort) at install/update so its features work out of the box.
 *  binary-on-PATH => capability key (whose package + per-distro alias smpro_env_install knows). */
function smpro_deps_required() {
    return ['mmdblookup' => 'geoip'];   // offline GeoIP (country + ASN); pure-PHP reader is the fallback if this fails
}
/**
 * Ensure required tooling is installed. Best-effort + throttled (once/24h via /var/lib/smpro/.deps_check) so it
 * self-provisions at install/update and self-heals on cron without hammering the package manager. No-op when all
 * tools are already present. Returns ['ok'=>bool,'installed'=>[],'msg'=>string]. NEVER fatal.
 */
function smpro_deps_ensure($force = false) {
    $missing = [];
    foreach (smpro_deps_required() as $bin => $cap) if (!smpro_has_bin($bin)) $missing[$bin] = $cap;
    if (!$missing) return ['ok' => true, 'installed' => [], 'msg' => 'all required tools present'];
    $stamp = SMPRO_VARLIB . '/.deps_check';
    if (!$force && is_file($stamp) && (time() - (int)@filemtime($stamp)) < 86400)
        return ['ok' => false, 'installed' => [], 'msg' => 'throttled (retry after 24h)'];
    @is_dir(SMPRO_VARLIB) || @mkdir(SMPRO_VARLIB, 0700, true);
    @touch($stamp);
    if (smpro_pkg_mgr() === '') return ['ok' => false, 'installed' => [], 'msg' => 'no supported package manager'];
    $done = []; $failed = [];
    foreach ($missing as $bin => $cap) { [$ok] = smpro_env_install($cap); if ($ok) $done[] = $bin; else $failed[] = $bin; }
    if (function_exists('smpro_audit')) smpro_audit('deps_ensure', ['installed' => $done, 'failed' => $failed]);
    return ['ok' => !empty($done), 'installed' => $done,
            'msg' => $done ? ('installed: ' . implode(',', $done)) : ('install failed: ' . implode(',', $failed) . ' — pure-PHP fallback in use')];
}
