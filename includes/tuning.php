<?php
/**
 * tuning.php — Server Tune-up: scan the installed engines (Apache/Nginx, MySQL/MariaDB, CSF firewall,
 * CloudLinux, Imunify, PHP) and recommend performance + security improvements. Every apply backs the
 * config up first (timestamped, listed), validates, rolls back on failure, and records a profile of
 * exactly what changed. Read scan = safe; apply = explicit per-item, with backup + validation.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

define('SMPRO_TUN_BK',   SMPRO_VARLIB . '/backups/tuning');     // timestamped config backups
define('SMPRO_TUN_PROF', SMPRO_VARLIB . '/tuning/profiles');    // applied-change profiles
define('SMPRO_TUN_POSTURE', SMPRO_VARLIB . '/tun_posture.json'); // cached SECURITY-posture summary → dashboard score (so the dashboard never runs this heavy scan itself)

/* Cache a lightweight security-posture summary from a scan's recs, so the dashboard Security & Health score can
 * reflect open hardening items WITHOUT running the heavy tune-up scan on every dashboard load. */
function smpro_tun_posture_cache_write(array $recs): void {
    $w = ['high' => 8, 'medium' => 4, 'low' => 2];
    $items = []; $pts = 0;
    foreach ($recs as $r) {
        if (($r['type'] ?? '') !== 'security') continue;              // only security findings affect the security score
        $p = $w[$r['sev'] ?? 'medium'] ?? 4; $pts += $p;
        $items[] = ['label' => (string)($r['title'] ?? 'Hardening item'), 'sev' => (string)($r['sev'] ?? 'medium'), 'pts' => $p];
    }
    if ($pts > 40) $pts = 40;                                         // cap tune-up's share of the 100-point score
    $out = ['ts' => time(), 'count' => count($items), 'pts' => $pts, 'items' => array_slice($items, 0, 8)];
    $f = SMPRO_TUN_POSTURE; @is_dir(dirname($f)) || @mkdir(dirname($f), 0700, true);
    if (@file_put_contents($f . '.tmp', json_encode($out, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), LOCK_EX) !== false) { @chmod($f . '.tmp', 0600); @rename($f . '.tmp', $f); }
}
function smpro_tun_posture_read(): array { $d = @is_file(SMPRO_TUN_POSTURE) ? json_decode((string)@file_get_contents(SMPRO_TUN_POSTURE), true) : null; return is_array($d) ? $d : []; }
/** If the cached posture is missing/stale (>6h), spawn a THROTTLED detached scan to refresh it. Keeps the dashboard light. */
function smpro_tun_posture_refresh_async(): void {
    $pd = smpro_tun_posture_read();
    if (!empty($pd['ts']) && (time() - (int)$pd['ts']) < 21600) return;             // fresh enough (<6h)
    $mark = SMPRO_VARLIB . '/tun_posture.spawn';
    if (is_file($mark) && (time() - (int)@filemtime($mark)) < 1800) return;         // throttle: at most one spawn / 30 min
    @touch($mark);
    if (function_exists('smpro_tun_job_start')) smpro_tun_job_start('posture', []);
}

// Force a full PATH (like smpro_dom_sh) so bare binaries such as `sshd` resolve to /usr/sbin under the minimal
// WHM-CGI PATH — otherwise `sshd -t` validation emits "command not found" and false-rolls-back a VALID config.
function smpro_tun_sh($cmd, $t = 8) { return smpro_run((string)$cmd, (int)$t, ['path' => true, 'stderr' => 'discard']); }
/** A version string changes at install/update time, not per page view: ten minutes between real calls. */
function smpro_tun_ver($cmd) { return function_exists('smpro_memo') ? (string)smpro_memo('tun_ver_' . sha1($cmd), 600, fn() => trim(smpro_tun_sh($cmd)) ?: null) : trim(smpro_tun_sh($cmd)); }
function smpro_tun_has($bin) { return trim(smpro_tun_sh('command -v ' . escapeshellarg($bin))) !== ''; }

/* ---------------- detect installed engines ---------------- */
function smpro_tun_detect(): array {
    $e = [];
    // web server
    if (smpro_tun_has('nginx')) $e['nginx'] = ['label' => 'Nginx', 'conf' => '/etc/nginx/nginx.conf', 'ver' => trim(smpro_tun_sh('nginx -v 2>&1'))];
    foreach (['/usr/local/apache/bin/httpd', '/usr/sbin/httpd', '/usr/sbin/apache2'] as $h) if (is_executable($h)) { $conf = ''; foreach (['/etc/apache2/conf/httpd.conf', '/usr/local/apache/conf/httpd.conf', '/etc/httpd/conf/httpd.conf'] as $c) if (is_file($c)) { $conf = $c; break; } $e['apache'] = ['label' => 'Apache', 'conf' => $conf, 'bin' => $h, 'ver' => trim(smpro_tun_sh(escapeshellarg($h) . ' -v 2>&1 | head -1'))]; break; }
    // db
    foreach (['mysqld', 'mariadbd'] as $d) if (smpro_tun_has($d)) { $e['mysql'] = ['label' => 'MySQL/MariaDB', 'conf' => smpro_tun_mycnf(), 'ver' => trim(smpro_tun_sh($d . ' --version 2>&1 | head -1'))]; break; }
    // firewall
    if (is_file('/etc/csf/csf.conf')) $e['csf'] = ['label' => 'CSF Firewall', 'conf' => '/etc/csf/csf.conf', 'ver' => smpro_tun_ver('csf -v 2>&1 | head -1')];
    // platform
    if (is_file('/etc/cloudlinux-release')) $e['cloudlinux'] = ['label' => 'CloudLinux', 'conf' => '', 'ver' => trim((string)@file_get_contents('/etc/cloudlinux-release'))];
    if (smpro_tun_has('imunify360-agent')) $e['imunify'] = ['label' => 'Imunify360', 'conf' => '', 'ver' => smpro_tun_ver('imunify360-agent version 2>&1 | head -1')];
    // ssh
    if (($sc = smpro_tun_ssh_conf()) !== '') $e['ssh'] = ['label' => 'SSH (sshd)', 'conf' => $sc, 'ver' => trim(smpro_tun_sh('ssh -V 2>&1 | head -1'))];
    // php (cPanel default)
    $php = trim(smpro_tun_sh("ls -d /opt/cpanel/ea-php*/root/usr/bin/php 2>/dev/null | tail -1"));
    if ($php !== '') $e['php'] = ['label' => 'PHP (cPanel)', 'conf' => '', 'bin' => $php, 'ver' => trim(smpro_tun_sh(escapeshellarg($php) . ' -r "echo PHP_VERSION;"'))];
    return $e;
}
function smpro_tun_mycnf(): string { foreach (['/etc/my.cnf', '/etc/mysql/my.cnf', '/etc/mysql/mariadb.cnf'] as $f) if (is_file($f)) return $f; return '/etc/my.cnf'; }
function smpro_tun_ssh_conf(): string { foreach (['/etc/ssh/sshd_config'] as $f) if (is_file($f)) return $f; return ''; }

/* Optimizable targets the user can pick (only those detected). 'http' is always offered (web-perf). */
function smpro_tun_targets(): array {
    $det = smpro_tun_detect(); $t = [];
    if (isset($det['mysql']))      $t['mysql']      = $det['mysql']['label'];
    if (isset($det['apache']))     $t['apache']     = 'Apache';
    if (isset($det['nginx']))      $t['nginx']      = 'Nginx';
    $t['csf']        = isset($det['csf']) ? 'CSF Firewall' : 'CSF Firewall (install)';
    if (isset($det['cloudlinux'])) $t['cloudlinux'] = 'CloudLinux';
    if (isset($det['imunify']))    $t['imunify']    = 'Imunify360';
    if (isset($det['ssh']))        $t['ssh']        = 'SSH';
    if (isset($det['php']))        $t['php']        = 'PHP';
    $t['http'] = 'HTTP performance';
    return $t;
}

/* ---------------- access-isolation helpers (jailshell / CageFS / symlink) ---------------- */
/** cPanel accounts on a FULL (non-jailed) login shell — these can browse the whole server outside their home.
 *  Returns [['user','shell','home'],…]. Skips root/system users (uid<1000) and non-/home homes. */
function smpro_tun_shell_users(): array {
    $out  = smpro_tun_sh('getent passwd 2>/dev/null', 15);
    $full = ['/bin/bash', '/bin/sh', '/usr/bin/bash', '/usr/bin/sh', '/bin/zsh', '/usr/bin/zsh', '/bin/ksh'];
    $rows = [];
    foreach (explode("\n", $out) as $ln) {
        $p = explode(':', $ln); if (count($p) < 7) continue;
        $user = $p[0]; $uid = (int)$p[2]; $home = $p[5]; $shell = $p[6];
        if ($uid < 1000) continue;                       // skip root + system accounts
        if (strpos($home, '/home') !== 0) continue;       // cPanel accounts live under /home*
        if (in_array($shell, $full, true)) $rows[] = ['user' => $user, 'shell' => $shell, 'home' => $home];
    }
    return $rows;
}
/** Locate cagefsctl (CloudLinux CageFS control), '' if absent. */
function smpro_tun_cagefsctl(): string { if (is_executable('/usr/sbin/cagefsctl')) return '/usr/sbin/cagefsctl'; return smpro_tun_has('cagefsctl') ? 'cagefsctl' : ''; }
/** Read a single WHM Tweak Setting value via whmapi1 get_tweaksetting. Returns the string value, or '' if unavailable/invalid key. */
function smpro_tun_tweak_get(string $key): string {
    $bin = smpro_tun_sa_bin(); if ($bin === '') return '';
    $out = smpro_tun_sh(escapeshellarg($bin) . ' --output=json get_tweaksetting key=' . escapeshellarg($key), 12);
    $j = json_decode($out, true);
    if (!is_array($j) || empty($j['metadata']['result'])) return '';
    return (string)($j['data']['tweaksetting']['value'] ?? '');
}

/* ---------------- scan → recommendations (read-only) ---------------- */
function smpro_tun_scan(): array {
    $det = smpro_tun_detect();
    $recs = [];
    $cores = (int)trim(smpro_tun_sh('nproc')) ?: 1;
    $ramMb = (int)trim(smpro_tun_sh("free -m | awk '/Mem:/{print \$2}'"));
    $rec = function ($engine, $id, $type, $sev, $title, $cur, $reco, $why, $accessRisk = false, $warn = '') use (&$recs) {
        $recs[] = ['engine' => $engine, 'id' => $id, 'type' => $type, 'sev' => $sev, 'title' => $title, 'current' => $cur,
                   'recommended' => $reco, 'rationale' => $why, 'access_risk' => (bool)$accessRisk, 'warn' => $warn];
    };

    if (isset($det['apache'])) {
        // read httpd.conf AND our cPanel-safe include drop-in, so applied directives are detected (parity with apply)
        $c = (string)@file_get_contents($det['apache']['conf']) . "\n" . (string)@file_get_contents('/etc/apache2/conf.d/includes/zz-smpro-tuning.conf');
        $get = fn($k) => (preg_match('/^\s*' . $k . '\s+(.+)$/im', $c, $m) ? trim($m[1]) : '');
        if (stripos($get('ServerTokens'), 'Prod') === false) $rec('apache', 'apache_tokens', 'security', 'medium', 'Apache exposes its version (ServerTokens)', $get('ServerTokens') ?: 'Full (default)', 'ServerTokens Prod', 'Hides Apache/OS version from attackers (banner grabbing).');
        if (stripos($get('ServerSignature'), 'Off') === false) $rec('apache', 'apache_sig', 'security', 'low', 'Apache ServerSignature on error pages', $get('ServerSignature') ?: 'On', 'ServerSignature Off', 'Stops leaking the server signature on error pages.');
        if ($get('KeepAlive') === '' || stripos($get('KeepAlive'), 'On') === false) $rec('apache', 'apache_keepalive', 'performance', 'medium', 'KeepAlive disabled', $get('KeepAlive') ?: 'Off', 'KeepAlive On (KeepAliveTimeout 5)', 'Reuses connections → fewer TCP handshakes, faster page loads.');
        if (!preg_match('/mod_deflate|deflate_module/i', smpro_tun_sh(escapeshellarg($det['apache']['bin']) . ' -M 2>&1'))) $rec('apache', 'apache_deflate', 'performance', 'medium', 'Compression (mod_deflate) not enabled', 'off', 'enable mod_deflate (gzip text/html/css/js)', 'Compresses responses → big bandwidth + load-time win.');
    }
    if (isset($det['nginx'])) {
        $c = (string)@file_get_contents($det['nginx']['conf']);
        if (!preg_match('/^\s*gzip\s+on/im', $c)) $rec('nginx', 'nginx_gzip', 'performance', 'medium', 'Nginx gzip not enabled', 'off', 'gzip on; gzip_types text/css application/javascript;', 'Compresses responses → faster, less bandwidth.');
        if (!preg_match('/server_tokens\s+off/i', $c)) $rec('nginx', 'nginx_tokens', 'security', 'low', 'Nginx exposes its version', 'on', 'server_tokens off;', 'Hides the Nginx version banner.');
        if (preg_match('/worker_processes\s+(\d+)/i', $c, $m) && (int)$m[1] !== $cores) $rec('nginx', 'nginx_workers', 'performance', 'low', 'worker_processes not matched to cores', $m[1], 'worker_processes auto; (= ' . $cores . ')', 'One worker per CPU core maximizes throughput.');
    }
    if (isset($det['mysql'])) {
        $c = (string)@file_get_contents($det['mysql']['conf']);
        $mget = fn($k) => (preg_match('/^\s*' . $k . '\s*=\s*(.+)$/im', $c, $m) ? trim($m[1]) : '');
        $bp = $mget('innodb_buffer_pool_size');
        $recoBp = max(1, (int)round($ramMb * 0.5 / 1024)) . 'G';
        if ($bp === '') $rec('mysql', 'mysql_bufferpool', 'performance', 'high', 'innodb_buffer_pool_size not set', 'default (128M)', $recoBp . ' (~50% of RAM)', 'The single biggest MySQL perf lever — caches data+indexes in RAM.');
        if (stripos($c, 'skip-name-resolve') === false && stripos($c, 'skip_name_resolve') === false) $rec('mysql', 'mysql_skipdns', 'performance', 'medium', 'skip-name-resolve not set', 'off', 'skip-name-resolve', 'Avoids a reverse-DNS lookup on every connection → faster connects.');
        if ($mget('slow_query_log') === '' ) $rec('mysql', 'mysql_slowlog', 'performance', 'low', 'Slow query log off', 'off', 'slow_query_log=1; long_query_time=2', 'Surfaces slow queries to optimize (diagnostic).');
        if (stripos($c, 'local_infile') === false && stripos($c, 'local-infile') === false) $rec('mysql', 'mysql_localinfile', 'security', 'medium', 'local_infile not disabled', 'on (default)', 'local-infile=0', 'Blocks LOAD DATA LOCAL abuse from a compromised app.');
    }
    if (!isset($det['csf'])) {
        $rec('csf', 'csf_install', 'security', 'medium', 'CSF firewall not installed', 'not installed', 'Install CSF via the cpanel-csf package', 'A host firewall (CSF/LFD) adds brute-force blocking, port control and login-failure protection. On cPanel, CSF installs as the cpanel-csf package (dnf/yum/apt) — note the package is "cpanel-csf", not "csf". This button installs it (and disables a conflicting firewalld). It starts in TESTING mode, so nothing is blocked until you enable it.');
    }
    if (isset($det['csf'])) {
        $c = (string)@file_get_contents('/etc/csf/csf.conf');
        $cget = fn($k) => (preg_match('/^\s*' . $k . '\s*=\s*"?([^"\n]*)"?/im', $c, $m) ? trim($m[1]) : '');
        if ($cget('TESTING') === '1') $rec('csf', 'csf_testing', 'security', 'high', 'CSF is in TESTING mode (not enforcing)', 'TESTING=1', 'TESTING=0', 'In testing mode the firewall does NOT actually block — enforcement is off.', true, 'Enforcing the firewall can lock you out if your own IP is not allowlisted. Make sure your IP is in csf.allow before applying.');
        if ($cget('SYNFLOOD') === '0' || $cget('SYNFLOOD') === '') $rec('csf', 'csf_synflood', 'security', 'medium', 'SYN-flood protection off', 'SYNFLOOD=0', 'SYNFLOOD=1 (SYNFLOOD_RATE 100/s)', 'Mitigates SYN-flood DoS attacks.');
        if ((int)$cget('CT_LIMIT') === 0) $rec('csf', 'csf_ct', 'security', 'low', 'Connection-tracking (CT_LIMIT) off', '0', 'CT_LIMIT=300', 'Blocks IPs opening too many concurrent connections (DoS).');
        if ($cget('LF_ALERT_TO') === '') $rec('csf', 'csf_alert', 'security', 'low', 'CSF/LFD alert email not set', 'empty', 'LF_ALERT_TO=admin@…', 'Get notified of brute-force/login-failure blocks.');
    }
    if (isset($det['imunify'])) {
        // config show is one big JSON line; the old grep-for-"false" matched unrelated keys → flagged forever. Read the actual PROACTIVE_DEFENSE mode.
        $pd = smpro_tun_sh('imunify360-agent config show 2>/dev/null', 15);
        $pdMode = preg_match('/"PROACTIVE_DEFENSE"\s*:\s*\{[^}]*"mode"\s*:\s*"([A-Za-z]+)"/', $pd, $mm) ? strtoupper($mm[1]) : '';
        if ($pdMode === '' || $pdMode === 'DISABLED') $rec('imunify', 'imunify_pad', 'security', 'medium', 'Imunify Proactive Defense not active', $pdMode ?: 'off', 'enable Proactive Defense (KILL)', 'Blocks malicious PHP execution in real time.');
    }
    if (isset($det['ssh'])) {
        $c = (string)@file_get_contents($det['ssh']['conf']);
        $eff = smpro_tun_sh('sshd -T 2>/dev/null; /usr/sbin/sshd -T 2>/dev/null', 10);   // effective merged config — reflects sshd_config.d drop-ins (parity with apply)
        $sget = function ($k) use ($c, $eff) { if ($eff !== '' && preg_match('/^' . strtolower($k) . '\s+(.+)$/im', $eff, $m)) return trim($m[1]); return preg_match('/^\s*' . $k . '\s+(.+)$/im', $c, $m) ? trim($m[1]) : ''; };
        $root = strtolower($sget('PermitRootLogin'));
        if ($root === '' || $root === 'yes') $rec('ssh', 'ssh_root', 'security', 'high', 'SSH allows direct root login', $root ?: 'yes (default)', 'PermitRootLogin prohibit-password', 'Stops password brute-force of the root account; keys still work.', true, 'If root is your ONLY way in and you have no SSH key / sudo user, this can lock you out. Set up a key or a sudo user first.');
        if (strtolower($sget('PasswordAuthentication')) !== 'no') $rec('ssh', 'ssh_passauth', 'security', 'medium', 'SSH password authentication enabled', $sget('PasswordAuthentication') ?: 'yes (default)', 'PasswordAuthentication no (keys only)', 'Eliminates password brute-force entirely — the #1 SSH attack.', true, 'Only disable AFTER confirming key-based login works, or you will be locked out.');
        $port = $sget('Port');
        if ($port === '' || $port === '22') $rec('ssh', 'ssh_port', 'security', 'low', 'SSH on the default port 22', $port ?: '22', 'a non-default high port (e.g. 2222)', 'Cuts automated scanner/brute-force noise dramatically.', true, 'Changing the port needs a matching firewall rule (CSF TCP_IN) FIRST, or you will be locked out. Keep your current session open while testing.');
        if (stripos($sget('X11Forwarding'), 'yes') !== false) $rec('ssh', 'ssh_x11', 'security', 'low', 'X11 forwarding enabled', 'yes', 'X11Forwarding no', 'Reduces SSH attack surface on a headless server.');
    }
    // HTTP performance roll-up (compression / keep-alive / HTTP-2) across whichever web server is present
    if (isset($det['nginx'])) {
        $c = (string)@file_get_contents($det['nginx']['conf']);
        if (!preg_match('/listen\s+443[^;]*http2/i', $c) && !preg_match('/^\s*http2\s+on/im', $c)) $rec('http', 'http_h2_nginx', 'performance', 'medium', 'HTTP/2 not enabled on Nginx TLS', 'http/1.1', 'listen 443 ssl http2;', 'HTTP/2 multiplexes requests on one connection → faster page loads.');
    }
    if (isset($det['apache'])) {
        if (!preg_match('/http2_module|mod_http2/i', smpro_tun_sh(escapeshellarg($det['apache']['bin']) . ' -M 2>&1'))) $rec('http', 'http_h2_apache', 'performance', 'medium', 'HTTP/2 (mod_http2) not enabled on Apache', 'off', 'enable mod_http2 + Protocols h2 http/1.1', 'HTTP/2 multiplexing speeds up modern browsers.');
    }
    if (isset($det['php'])) {
        $php = $det['php']['bin'];
        // escapeshellarg the WHOLE -r program (the old nested-quote form was malformed → always returned empty → opcache flagged forever)
        $ini = fn($k) => trim(smpro_tun_sh(escapeshellarg($php) . ' -r ' . escapeshellarg('echo (string)ini_get("' . $k . '");')));
        if ($ini('expose_php') === '1') $rec('php', 'php_expose', 'security', 'low', 'expose_php on (X-Powered-By leaks PHP version)', 'On', 'expose_php = Off', 'Hides the PHP version from response headers.');
        $oc = trim(smpro_tun_sh(escapeshellarg($php) . ' -r ' . escapeshellarg('echo (extension_loaded("Zend OPcache") && ini_get("opcache.enable")) ? "1" : "0";')));
        if ($oc !== '1') $rec('php', 'php_opcache', 'performance', 'high', 'OPcache disabled', 'off', 'opcache.enable=1', 'Caches compiled PHP bytecode — major speedup for every PHP app.');
    }

    /* ---- Access isolation / jailing (parity with WHM Security Advisor) ---- */
    $isCL     = is_file('/etc/cloudlinux-release');
    $symOwner = trim(smpro_tun_sh('sysctl -n fs.enforce_symlinksifowner 2>/dev/null'));   // CloudLinux SecureLinks (kernel symlink-owner enforcement)
    // Jail Apache = mod_ruid2 running each vhost as its owner WITH symlink protection. This one WHM tweak fixes
    // BOTH the symlink race-condition AND vhost-segmentation findings, so both recs point at the same fix.
    $jailOn   = isset($det['apache']) ? (smpro_tun_tweak_get('jailapache') === '1') : true;
    // 1) Symlink race-condition protection — protected by Jail Apache, CloudLinux SecureLinks, or CageFS.
    if (isset($det['apache']) && !$jailOn && !$isCL && $symOwner !== '1') {
        $rec('access', 'harden_symlink', 'security', 'high', 'Symlink race-condition protection is OFF',
            'not enforced', 'enable Jail Apache (mod_ruid2 symlink protection)',
            "Without it, a malicious account can win a symlink race to make Apache/PHP open ANOTHER account's files (its config, DB credentials, mailboxes). On cPanel this is fixed by enabling Jail Apache (mod_ruid2 runs each site as its owner and blocks cross-owner symlinks) — the same one-click fix as \"Apache vhosts are not segmented\" below. CloudLinux CageFS also protects against it.", false,
            "This enables Jail Apache — it rebuilds the Apache config and gracefully restarts it. Note, per cPanel: it can affect accessing Mailman through Apache.");
    }
    // 2) Apache vhosts not segmented (mod_ruid2 / Jail Apache)
    if (isset($det['apache']) && !$jailOn && !$isCL) {
        $rec('access', 'harden_ruid2', 'security', 'medium', 'Apache vhosts are not segmented (Jail Apache / mod_ruid2 off)',
            'runs as nobody/apache', 'enable mod_ruid2 + Jail Apache',
            "With Jail Apache (mod_ruid2), each website runs as its own cPanel user instead of one shared web user — so a single hacked site cannot read or write another account's files, and cross-account symlink attacks are blocked. This installs mod_ruid2 (if missing) and turns on Jail Apache.", false,
            "This rebuilds the Apache config and gracefully restarts it (no downtime expected). Note, per cPanel: enabling Jail Apache can affect accessing Mailman through Apache.");
    }
    // 3) cPanel accounts running outside the jail (full shell)
    $fullUsers = smpro_tun_shell_users();
    if ($fullUsers) {
        $names = implode(', ', array_slice(array_map(fn($u) => $u['user'], $fullUsers), 0, 8)) . (count($fullUsers) > 8 ? ' +' . (count($fullUsers) - 8) . ' more' : '');
        $rec('access', 'harden_jailshell', 'security', 'high', count($fullUsers) . ' account(s) have full shell access (not jailed)',
            $names, 'switch them to jailshell',
            "These cPanel accounts use a normal shell (/bin/bash) instead of cPanel's jailshell, so an SSH/terminal session can leave its home directory and browse the whole server. Switching them to jailshell confines each account to its own jail." . ($isCL ? ' For even stronger isolation, enable CloudLinux CageFS below.' : ' For stronger isolation, consider CloudLinux + CageFS.'), false,
            "Switches the listed accounts to /usr/local/cpanel/bin/jailshell (reversible per-account in WHM › Manage Shell Access). If a specific user legitimately needs a full shell, set it back for that user afterwards.");
    }
    // 4) CageFS (only meaningful on CloudLinux)
    if ($isCL && ($ctl = smpro_tun_cagefsctl()) !== '') {
        $enN = (int)trim(smpro_tun_sh(escapeshellarg($ctl) . ' --list-enabled 2>/dev/null | grep -c .'));
        $disN = (int)trim(smpro_tun_sh(escapeshellarg($ctl) . ' --list-disabled 2>/dev/null | grep -c .'));
        if ($disN > 0 || $enN === 0) {
            $rec('access', 'harden_cagefs', 'security', 'medium', 'CageFS is not enabled for all users',
                $enN . ' enabled / ' . $disN . ' not', 'cagefsctl --enable-all',
                "CageFS gives every account its own isolated virtual filesystem, so users cannot see each other's files, processes or the server's real configuration. Enabling it for all users is the recommended CloudLinux hardening.", false,
                'Runs cagefsctl --enable-all then --force-update. Reversible: cagefsctl --disable-all.');
        }
    } elseif ($isCL && smpro_tun_cagefsctl() === '') {
        $rec('access', 'harden_cagefs_install', 'security', 'low', 'CloudLinux present but CageFS not installed',
            'not installed', 'install + enable CageFS',
            'CageFS isolates each account in its own filesystem. Install it from WHM › CloudLinux™ Manager, then enable it for all users.', false,
            'Install is manual (WHM › CloudLinux). Once installed, this Advisor will offer a one-click "enable for all users".');
    }

    smpro_tun_posture_cache_write($recs);   // refresh the dashboard-score posture cache every time we scan
    return ['engines' => $det, 'recs' => $recs, 'cores' => $cores, 'ram_mb' => $ramMb];
}

/* ---------------- install CSF firewall (official cPanel method) ----------------
 * Per cPanel docs (docs.cpanel.net/.../how-to-install-csf): CSF is the package "cpanel-csf"
 * (NOT "csf") in the cpanel-plugins repo — `dnf/yum install cpanel-csf` (AlmaLinux/CloudLinux/Rocky)
 * or `apt install cpanel-csf` (Ubuntu). firewalld must be off first (CSF cannot coexist with it).
 * CSF starts in TESTING mode (does NOT block) so installing it cannot lock anyone out. */
function smpro_tun_install_csf(): array {
    if (is_file('/etc/csf/csf.conf') || is_file('/usr/sbin/csf')) return ['ok' => true, 'already' => true, 'msg' => 'CSF is already installed. ' . trim(smpro_tun_sh('csf -v 2>/dev/null | head -1'))];
    $log = [];
    // firewalld conflicts with CSF — stop & disable it first (reversible; CSF's own setup expects this)
    if (smpro_tun_has('firewall-cmd') && trim(smpro_tun_sh('systemctl is-active firewalld 2>/dev/null')) === 'active') {
        $log[] = '# systemctl stop/disable firewalld (CSF cannot run alongside firewalld)';
        $log[] = smpro_tun_sh('systemctl stop firewalld 2>&1; systemctl disable firewalld 2>&1', 60);
    }
    // install the cpanel-csf package
    if (smpro_tun_has('dnf') || smpro_tun_has('yum')) {
        $pm = smpro_tun_has('dnf') ? 'dnf' : 'yum';
        $log[] = "# $pm -y install cpanel-csf";
        $log[] = smpro_tun_sh($pm . ' -y install cpanel-csf 2>&1', 360);
    } elseif (smpro_tun_has('apt-get')) {
        $log[] = '# apt-get install cpanel-csf';
        smpro_tun_sh('apt-get update 2>&1', 120);
        $log[] = smpro_tun_sh('DEBIAN_FRONTEND=noninteractive apt-get -y install cpanel-csf 2>&1', 360);
    } else {
        return ['ok' => false, 'msg' => 'No supported package manager (dnf/yum/apt) found.'];
    }
    $ok = is_file('/etc/csf/csf.conf') || is_file('/usr/sbin/csf');
    if (function_exists('smpro_audit')) smpro_audit('tuning_install_csf', ['ok' => $ok]);
    return ['ok' => $ok,
            'msg' => $ok ? 'CSF installed (cpanel-csf). It starts in TESTING mode — it does NOT block yet, so nothing is locked out. Add your IP to csf.allow, verify, then set TESTING=0 (or toggle Testing off in WHM) to enforce.'
                         : 'cpanel-csf install did not complete — see the log. Reminder: the cPanel package is "cpanel-csf", not "csf".',
            'log' => mb_substr(implode("\n", array_filter($log)), -1800)];
}

/* ---------------- AI-driven optimization (advisory) ----------------
 * Collects a compact server profile (engines, versions, cores/RAM, current findings) and asks the
 * configured AI for the best, safest optimizations for the SELECTED targets only. AI output is
 * ADVISORY (shown with rationale + access-risk warnings) — it is never auto-written to a config. */
/* ===================== background jobs (AI optimization / Security Advisor) =====================
 * These two scans call an AI provider / whmapi1 and take 30-60s. Running them in the FOREGROUND meant
 * closing the page lost the result. smpro_tun_job_start() spawns a detached worker (bin/tun_worker.php)
 * that writes the result + timestamp to a state file; the page reads it on load ("Last updated …") and
 * polls while a job is running. Persisted per job under SMPRO_VARLIB/tuning/. */
function smpro_tun_job_file(string $job): string { $job = preg_replace('/[^a-z]/', '', $job); return SMPRO_VARLIB . '/tuning/' . ($job ?: 'x') . '.json'; }
function smpro_tun_job_read(string $job): array {
    $d = is_file($f = smpro_tun_job_file($job)) ? json_decode((string)@file_get_contents($f), true) : null;
    return is_array($d) ? $d : ['status' => 'idle', 'updated_at' => 0];
}
function smpro_tun_job_write(string $job, array $st): void {
    $f = smpro_tun_job_file($job); $dir = dirname($f); @is_dir($dir) || @mkdir($dir, 0700, true);
    $tmp = @tempnam($dir, 'tj'); if (!$tmp) return;
    @file_put_contents($tmp, json_encode($st, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)); @chmod($tmp, 0600); @rename($tmp, $f);
}
function smpro_tun_php_bin(): string { return smpro_php_cli_bin(); }
/** Run the job synchronously (invoked by bin/tun_worker.php in the background) — persists result + timestamp. */
function smpro_tun_job_run(string $job, array $args): void {
    $job = preg_replace('/[^a-z]/', '', $job);
    $started = (int)(smpro_tun_job_read($job)['started_at'] ?? 0) ?: time();
    smpro_tun_job_write($job, ['status' => 'running', 'started_at' => $started, 'updated_at' => time(), 'targets' => $args['targets'] ?? []]);
    try {
        if ($job === 'aioptimize' && function_exists('smpro_tun_ai_optimize'))    $res = smpro_tun_ai_optimize((array)($args['targets'] ?? []));
        elseif ($job === 'secadvisor' && function_exists('smpro_tun_secadvisor')) $res = smpro_tun_secadvisor();
        elseif ($job === 'applyall' && function_exists('smpro_tun_ai_apply_all')) $res = smpro_tun_ai_apply_all((array)($args['ids'] ?? []), 'applyall');   // writes progress into this job's state
        elseif ($job === 'posture')                                              { smpro_tun_scan(); $res = ['ok' => true]; }   // scan writes the dashboard posture cache as a side-effect
        elseif ($job === 'rescan')                                               { smpro_cache_bust('tun_scan'); smpro_cache_through('tun_scan', 300, fn() => smpro_tun_scan()); $res = ['ok' => true]; }   // refreshes the Tune-up page's own cache, off the render path
        else                                                                      $res = ['ok' => false, 'msg' => 'unknown job'];
    } catch (\Throwable $e) { $res = ['ok' => false, 'msg' => 'Scan crashed: ' . $e->getMessage()]; }
    smpro_tun_job_write($job, ['status' => (!empty($res['ok']) ? 'done' : 'error'), 'started_at' => $started, 'updated_at' => time(), 'targets' => $args['targets'] ?? [], 'result' => $res]);
    if (function_exists('smpro_audit')) @smpro_audit('tuning_job_' . $job, ['ok' => !empty($res['ok'])]);
}
/** Start the job in the BACKGROUND (detached) and return immediately. Won't double-spawn a fresh running job. */
function smpro_tun_job_start(string $job, array $args): array {
    $job = preg_replace('/[^a-z]/', '', $job); if (!in_array($job, ['aioptimize', 'secadvisor', 'applyall', 'posture', 'rescan'], true)) return ['ok' => false, 'msg' => 'unknown job'];
    $st = smpro_tun_job_read($job);
    if (($st['status'] ?? '') === 'running' && (time() - (int)($st['started_at'] ?? 0)) < 600)
        return ['ok' => true, 'started' => false, 'status' => 'running', 'started_at' => (int)($st['started_at'] ?? 0), 'msg' => 'A scan is already running in the background.'];
    smpro_tun_job_write($job, ['status' => 'running', 'started_at' => time(), 'updated_at' => time(), 'targets' => $args['targets'] ?? []]);
    $worker = SMPRO_BASE . '/bin/tun_worker.php';
    if (!is_file($worker)) { smpro_tun_job_run($job, $args); return ['ok' => true, 'started' => true, 'status' => 'done', 'msg' => 'Completed.']; }
    $pre  = trim((string)@shell_exec('command -v setsid 2>/dev/null')) !== '' ? 'setsid ' : 'nohup ';
    $argb = base64_encode(json_encode($args, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    @shell_exec($pre . escapeshellarg(smpro_tun_php_bin()) . ' ' . escapeshellarg($worker) . ' ' . escapeshellarg($job) . ' ' . escapeshellarg($argb) . ' >/dev/null 2>&1 </dev/null &');
    return ['ok' => true, 'started' => true, 'status' => 'running', 'started_at' => time(), 'msg' => 'Scan started in the background — you can leave this page and come back.'];
}

function smpro_tun_ai_optimize(array $targets): array {
    $targets = array_values(array_intersect(array_map('strval', $targets), array_keys(smpro_tun_targets())));
    if (!$targets) return ['ok' => false, 'msg' => 'Select at least one target to optimize.'];
    if (!function_exists('smpro_ai_available') || !smpro_ai_available()) return ['ok' => false, 'msg' => 'Configure an AI provider first (AI Providers page).'];

    $scan = smpro_tun_scan();
    $ctx = ['cores' => $scan['cores'], 'ram_mb' => $scan['ram_mb'], 'targets' => $targets, 'engines' => []];
    foreach ($scan['engines'] as $k => $e) $ctx['engines'][$k] = ['ver' => $e['ver'] ?? ''];
    $sites = function_exists('smpro_prof_env') ? (int)(smpro_prof_env()['sites'] ?? 0) : 0;
    $ctx['hosted_sites'] = $sites;
    $ctx['current_findings'] = [];
    foreach ($scan['recs'] as $r) if (in_array($r['engine'], $targets, true)) $ctx['current_findings'][] = ['engine' => $r['engine'], 'title' => $r['title'], 'current' => $r['current']];

    $sys = "You are a senior cPanel/WHM hosting performance + security engineer. Given a server profile, propose the BEST, SAFEST optimizations ONLY for the requested targets (" . implode(', ', $targets) . "). "
         . "Respond with STRICT JSON ONLY, no prose: {\"recs\":[{\"target\":\"mysql|apache|nginx|cloudlinux|imunify|ssh|php|http\",\"title\":string,\"current\":string,\"recommended\":string,\"rationale\":string,\"severity\":\"high|medium|low\",\"access_risk\":boolean,\"warn\":string,\"apply_id\":string}]}. "
         . "Set access_risk=true with a clear `warn` for ANYTHING that could lock out SSH/admin or take a site or service offline (SSH port/root-login/password-auth, firewall enforcement, disabling a service, binding changes). "
         . "For a rec that EXACTLY corresponds to one of these KNOWN, SAFE, one-click appliers, set \"apply_id\" to its key (otherwise omit apply_id — it stays advisory): "
         . "mysql_bufferpool(innodb_buffer_pool_size~=50% RAM), mysql_skipdns(skip-name-resolve), mysql_slowlog(slow query log), mysql_localinfile(disable local-infile), "
         . "apache_tokens(ServerTokens Prod), apache_sig(ServerSignature Off), apache_keepalive(KeepAlive on), http_h2_apache(enable HTTP/2), "
         . "php_expose(expose_php Off), php_opcache(enable OPcache), csf_synflood(SYN-flood protection), csf_ct(connection tracking), csf_alert(login-alert email), imunify_pad(Proactive Defense), ssh_x11(disable X11 forwarding), "
         . "ssh_root(PermitRootLogin), ssh_passauth(disable password auth), ssh_port(change SSH port), csf_testing(enable CSF blocking). The last four are access_risk=true and are NEVER applied in bulk. "
         . "Prefer reversible, non-disruptive changes tuned to the cores/RAM/site-count. Do not invent engines that are not present.";
    $user = "Server profile:\n" . json_encode($ctx, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    $r = smpro_ai_chat($sys, $user, ['max_tokens' => 1300, 'context' => 'server_tuning']);
    if (empty($r['ok'])) return ['ok' => false, 'msg' => $r['error'] ?? 'AI request failed'];
    $j = preg_match('/\{.*\}/s', (string)($r['text'] ?? ''), $m) ? json_decode($m[0], true) : null;
    if (!is_array($j) || empty($j['recs']) || !is_array($j['recs'])) return ['ok' => false, 'msg' => 'AI returned no usable recommendations.', 'raw' => mb_substr((string)($r['text'] ?? ''), 0, 200)];

    $out = [];
    foreach ($j['recs'] as $x) {
        if (!is_array($x)) continue;
        $tg = preg_replace('/[^a-z]/', '', strtolower((string)($x['target'] ?? '')));
        if (!in_array($tg, $targets, true)) continue;
        $sev = in_array(($x['severity'] ?? 'low'), ['high', 'medium', 'low'], true) ? $x['severity'] : 'low';
        $applyId = preg_replace('/[^a-z0-9_]/', '', strtolower((string)($x['apply_id'] ?? '')));
        if (!isset(smpro_tun_apply_map()[$applyId])) $applyId = '';               // only allow a REAL, known applier key
        $out[] = [
            'engine' => $tg, 'id' => 'ai_' . substr(sha1(($x['title'] ?? '') . count($out)), 0, 8),
            'type' => !empty($x['access_risk']) ? 'security' : 'performance', 'sev' => $sev,
            'title' => mb_substr((string)($x['title'] ?? 'AI suggestion'), 0, 140),
            'current' => mb_substr((string)($x['current'] ?? ''), 0, 140),
            'recommended' => mb_substr((string)($x['recommended'] ?? ''), 0, 220),
            'rationale' => mb_substr((string)($x['rationale'] ?? ''), 0, 420),
            'access_risk' => !empty($x['access_risk']), 'warn' => mb_substr((string)($x['warn'] ?? ''), 0, 320),
            'apply_id' => $applyId, 'ai' => true,
        ];
    }
    if (!$out) return ['ok' => false, 'msg' => 'AI did not return recommendations for the selected targets.'];
    if (function_exists('smpro_audit')) smpro_audit('tuning_ai_optimize', ['targets' => $targets, 'recs' => count($out)]);
    return ['ok' => true, 'recs' => $out, 'provider' => $r['provider'] ?? '', 'count' => count($out)];
}

/** Access-risk appliers that must NEVER be applied in bulk (SSH lockout / firewall-enforcement). Individual + confirm only. */
function smpro_tun_bulk_excluded(): array { return ['ssh_root', 'ssh_passauth', 'ssh_port', 'csf_testing']; }
/**
 * Apply the AI suggestions that map to KNOWN, TESTED, one-click appliers — in bulk. Takes ONE automatic backup of all
 * configs FIRST, then applies each via smpro_tun_apply() (which config-tests Apache and auto-rolls-back on failure).
 * Access-risk changes (SSH/CSF-enforcement) are EXCLUDED — they must be applied individually with the lockout warning.
 */
function smpro_tun_ai_apply_all(array $applyIds, string $progressJob = ''): array {
    $map = smpro_tun_apply_map(); $risky = smpro_tun_bulk_excluded();
    $ids = array_values(array_unique(array_filter(array_map(fn($i) => preg_replace('/[^a-z0-9_]/', '', strtolower((string)$i)), $applyIds), fn($i) => isset($map[$i]))));
    $skippedRisky = array_values(array_intersect($ids, $risky));
    $toApply = array_values(array_diff($ids, $risky));
    if (!$toApply) return ['ok' => false, 'msg' => 'No safe one-click changes to apply from these suggestions.' . ($skippedRisky ? ' ' . count($skippedRisky) . ' access-risk change(s) must be applied individually.' : ''), 'skipped_risky' => $skippedRisky];
    $total = count($toApply);
    // progress writer — merges a {done,total,current} block into the background-job state (no-op when run synchronously)
    $wp = function ($done, $current) use ($progressJob, $total) {
        if ($progressJob === '' || !function_exists('smpro_tun_job_read')) return;
        $st = smpro_tun_job_read($progressJob); $st['progress'] = ['done' => (int)$done, 'total' => (int)$total, 'current' => (string)$current]; $st['updated_at'] = time();
        smpro_tun_job_write($progressJob, $st);
    };
    $wp(0, 'Backing up all configs…');
    $backup = smpro_tun_backup_all();                                    // ONE auto-backup of all configs, before any change
    $applied = []; $failed = []; $i = 0;
    foreach ($toApply as $id) {
        $wp($i, $id); $i++;
        $r = smpro_tun_apply($id, true);                                 // skipBackup=true (we backed up once above)
        if (!empty($r['ok'])) $applied[] = ['id' => $id, 'applied' => $r['applied'] ?? $id, 'note' => $r['note'] ?? ''];
        else $failed[] = ['id' => $id, 'msg' => $r['msg'] ?? 'failed'];
    }
    $wp($total, '');
    if (function_exists('smpro_audit')) smpro_audit('tuning_ai_apply_all', ['applied' => count($applied), 'failed' => count($failed), 'backup' => $backup['id'] ?? '']);
    return ['ok' => !empty($applied), 'applied' => $applied, 'failed' => $failed, 'skipped_risky' => $skippedRisky, 'backup_id' => $backup['id'] ?? '',
            'msg' => 'Backed up all configs (' . ($backup['id'] ?? '') . '), then applied ' . count($applied) . ' change(s)' . ($failed ? ', ' . count($failed) . ' failed' : '') . ($skippedRisky ? '. ' . count($skippedRisky) . ' access-risk change(s) skipped — apply those individually.' : '.')];
}

/* ---------------- cPanel Security Advisor integration ----------------
 * Uses whmapi1 fetch_security_advice (the documented Security Advisor endpoint).
 * Schema: data.payload[] of { type:'mod_advice', module, advice:{key,summary,suggestion,type} }
 * where advice.type ∈ ADVISE_BAD|ADVISE_WARN|ADVISE_INFO|ADVISE_GOOD.
 * We surface BAD/WARN/INFO (GOOD = passing check, skipped) and map keys to apply handlers. */
function smpro_tun_secadvisor(): array {
    $bin = smpro_tun_sa_bin();
    if ($bin === '') return ['ok' => false, 'msg' => 'whmapi1 not found — must run on a cPanel/WHM server.'];

    // fetch_security_advice is current; securityadvisor_get_recommendations was an older/variant name (kept as fallback).
    $raw  = smpro_tun_sh(escapeshellarg($bin) . ' --output=json fetch_security_advice', 45);
    $json = json_decode($raw, true);
    $payload = $json['data']['payload'] ?? null;
    if (!is_array($payload)) {
        // Fallback to the legacy function name on older cPanel
        $raw2  = smpro_tun_sh(escapeshellarg($bin) . ' --output=json securityadvisor_get_recommendations', 45);
        $json2 = json_decode($raw2, true);
        if (is_array($json2['data']['advice'] ?? null)) {
            $payload = [];
            foreach ($json2['data']['advice'] as $a) if (is_array($a)) $payload[] = ['type' => 'mod_advice', 'module' => (string)($a['category'] ?? ''),
                'advice' => ['key' => (string)($a['id'] ?? ''), 'summary' => (string)($a['description'] ?? ''), 'suggestion' => (string)($a['advice'] ?? $a['solution'] ?? ''),
                'type' => 'ADVISE_' . strtoupper((string)($a['type'] ?? 'WARN'))]];
        }
    }
    if (!is_array($payload)) {
        $err = mb_substr(strip_tags((string)($json['metadata']['reason'] ?? $raw)), 0, 120);
        return ['ok' => false, 'msg' => 'Security Advisor unavailable: ' . ($err !== '' ? $err : 'no data') . '. (Requires a valid cPanel license + root.)'];
    }

    // advice.type → our severity bucket. GOOD = passing (skip).
    $sevOf = ['ADVISE_BAD' => 'high', 'ADVISE_WARN' => 'medium', 'ADVISE_INFO' => 'low'];
    $recs = [];
    foreach ($payload as $it) {
        if (!is_array($it) || (($it['type'] ?? '') !== 'mod_advice')) continue;   // skip mod_load errors
        $a = $it['advice'] ?? null;
        if (!is_array($a)) continue;
        $at = strtoupper((string)($a['type'] ?? ''));
        if (!isset($sevOf[$at])) continue;                                          // skip ADVISE_GOOD / unknown
        $module = (string)($it['module'] ?? '');
        $cat = ($module !== '' && preg_match('/Assessors::([A-Za-z0-9_]+)/', $module, $mm)) ? $mm[1] : '';
        $recs[] = [
            'id'       => (string)($a['key'] ?? ''),
            'type'     => ($at === 'ADVISE_BAD' ? 'fatal' : ($at === 'ADVISE_WARN' ? 'warn' : 'info')),
            'sev'      => $sevOf[$at],
            'title'    => mb_substr((string)($a['summary'] ?? ($a['key'] ?? 'Advisory')), 0, 220),
            'advice'   => mb_substr(strip_tags((string)($a['suggestion'] ?? '')), 0, 400),
            'category' => mb_substr($cat, 0, 60),
        ];
    }
    // Order by severity (high → low) for the UI
    $rank = ['high' => 0, 'medium' => 1, 'low' => 2];
    usort($recs, fn($x, $y) => ($rank[$x['sev']] ?? 9) <=> ($rank[$y['sev']] ?? 9));
    return ['ok' => true, 'recs' => $recs, 'count' => count($recs)];
}

/* --- SA: normalize raw advisory key for matching (strip class-path prefix, drop ALL non-alnum, uppercase).
 *   e.g. "SSH_direct_root_login_permitted" → "SSHDIRECTROOTLOGINPERMITTED" (so substring checks hit). --- */
function smpro_tun_sa_normalize(string $id): string {
    if (strpos($id, '::') !== false) { $p = explode('::', $id); $id = end($p); }
    return strtoupper(preg_replace('/[^A-Za-z0-9]/', '', $id));
}

/* --- SA: dispatch a fix for any raw advisory ID (backs up first, validates, records profile) --- */
function smpro_tun_sa_apply(string $rawId): array {
    $bk = smpro_tun_backup_all();   // always backup before touching anything
    $id  = smpro_tun_sa_normalize($rawId);

    // SSH hardening — substring match on normalized key (real cPanel keys: SSHDIRECTROOTLOGINPERMITTED, SSHPASSWORDAUTHENTICATIONENABLED…)
    if (strpos($id, 'ROOTLOGIN') !== false)
        return smpro_tun_sa_sshd('PermitRootLogin', 'prohibit-password', 'ssh_root', $bk['id']);
    if (strpos($id, 'PASSWORDAUTH') !== false || (strpos($id, 'SSH') !== false && strpos($id, 'PASSWORD') !== false))
        return smpro_tun_sa_sshd('PasswordAuthentication', 'no', 'ssh_passauth', $bk['id']);
    if (strpos($id, 'X11') !== false && strpos($id, 'FORWARD') !== false)
        return smpro_tun_sa_sshd('X11Forwarding', 'no', 'ssh_x11', $bk['id']);

    // cPHulkD brute-force protection
    if (strpos($id, 'CPHULK') !== false || strpos($id, 'BRUTEFORCE') !== false || $id === 'CPHULKD')
        return smpro_tun_sa_cphulk($bk['id']);

    // Apache ETag (inode leakage)
    if (strpos($id, 'ETAG') !== false)
        return smpro_tun_sa_apache_dir('FileETag MTime Size', 'FileETag', 'ETAG', 'FileETag MTime Size (inode excluded)', 'Hides inode from ETag — stops info leakage on load-balanced setups. Apache reloaded gracefully.', $bk['id']);

    // Apache mod_userdir
    if (strpos($id, 'USERDIR') !== false)
        return smpro_tun_sa_apache_dir('UserDir disabled', 'UserDir', 'APACHEMOD_USERDIR', 'UserDir disabled', 'Apache no longer serves ~/user home-directory URLs. Apache reloaded gracefully.', $bk['id']);

    // MySQL remote root
    if ($id === 'REMOTEROOT' || ($id === 'MYSQLROOTPASSWORD') || (strpos($id, 'MYSQL') !== false && strpos($id, 'ROOT') !== false))
        return smpro_tun_sa_mysql_remoteroot($bk['id']);

    // Email rate limiting
    if (strpos($id, 'MAXEMAIL') !== false || (strpos($id, 'EMAIL') !== false && strpos($id, 'HOUR') !== false))
        return smpro_tun_sa_maxemail($bk['id']);

    // Compiler access
    if (strpos($id, 'COMPILER') !== false)
        return smpro_tun_sa_compilers($bk['id']);

    // cPanel auto-update
    if (strpos($id, 'AUTOUPDATE') !== false || (strpos($id, 'UPDATE') !== false && strpos($id, 'CPANEL') !== false) || $id === 'UPDATES')
        return smpro_tun_sa_autoupdate($bk['id']);

    // Two-factor auth
    if (strpos($id, '2FA') !== false || strpos($id, 'TWOFACTOR') !== false || strpos($id, 'MFA') !== false)
        return smpro_tun_sa_twofactor($bk['id']);

    // ModSecurity
    if (strpos($id, 'MODSECURITY') !== false || strpos($id, 'MODSEC') !== false)
        return smpro_tun_sa_modsecurity($bk['id']);

    // Dynamic fallback — no hardcoded handler: re-fetch advisory from WHM and try its own 'function' field.
    return smpro_tun_sa_whm_dispatch($rawId, $id, $bk['id']);
}

/* --- SA: helper — locate whmapi1 binary --- */
function smpro_tun_sa_bin(): string {
    static $b = null;
    if ($b !== null) return $b;
    foreach (['/usr/local/cpanel/bin/whmapi1', '/usr/bin/whmapi1'] as $p) if (is_executable($p)) return ($b = $p);
    return ($b = (smpro_tun_has('whmapi1') ? 'whmapi1' : ''));
}

/* --- SA: dynamic WHM dispatch — substring-matches the normalized advisory key against a table of
 *   safe whmapi1 fixes. Keys/values come from this table (never the browser), so no injection risk.
 *   fetch_security_advice does NOT expose a per-advice 'function' field, so we map by key pattern. --- */
function smpro_tun_sa_whm_dispatch(string $rawId, string $normId, string $bkId): array {
    $bin = smpro_tun_sa_bin();
    if ($bin === '') return ['ok' => false, 'manual' => true, 'msg' => 'whmapi1 not available.', 'backup_id' => $bkId];

    // Each entry: [substring_to_match_in_normalized_key, whmapi1_function, [arg_key=>value,...], human_label]
    $table = [
        // Verified against Whostmgr/API/1/*.pm on cPanel 11.136. Four names used here previously do not exist
        // and answered "Unknown app": set_cphulk_config, compilerinstall, twofactorauth_set_policy,
        // modsec_enable_disable. COMPILER and MODSEC have NO whmapi1 equivalent at all, so they are not listed —
        // smpro_tun_sa_compilers() (set_compiler_access script) and smpro_tun_sa_modsecurity()
        // (modsec_set_setting + modsec_deploy_settings_changes) own those, and both run before this table.
        ['CPHULK',        'enable_cphulk',           [],                                                              'cPHulkD brute-force protection enabled'],
        ['BRUTEFORCE',    'enable_cphulk',           [],                                                              'Brute-force protection enabled'],
        ['CPANELUPDATE',  'set_cpanel_updates',      ['updates' => 'daily'],                                          'cPanel automatic updates enabled'],
        ['AUTOUPDATE',    'set_cpanel_updates',      ['updates' => 'daily'],                                          'cPanel automatic updates enabled'],
        ['TWOFACTOR',     'twofactorauth_enable_policy', [],                                                          'WHM two-factor auth enforced'],
        ['MAXEMAIL',      'set_tweaks',              ['maxemailsperhour' => '500'], 'Outbound email rate limit set (500/hr)'],
        ['EMAILPERHOUR',  'set_tweaks',              ['maxemailsperhour' => '500'], 'Outbound email rate limit set (500/hr)'],
        ['SYMLINK',       'set_tweaks',              ['jailapache' => '1'],                                           'Symlink race-condition protection enabled (Jail Apache / mod_ruid2)'],
        ['QUOTA',         'set_tweaks',              ['skipquotacheck' => '0'],                                       'Disk quota enforcement enabled'],
        ['REFERRER',      'set_tweaks',              ['referrerblanksafety' => '1', 'referrersafety' => '1'],         'Referrer security checks enabled'],
        ['COOKIEIPVALIDATION', 'set_tweaks',         ['cookieipvalidation' => 'strict'],                              'Cookie IP validation set to strict'],
    ];
    foreach ($table as $row) {
        [$needle, $fn, $args, $label] = $row;
        if (strpos($normId, $needle) === false) continue;
        // Tweak-setting fixes must go through set_tweaksetting (there is no set_tweaks fn); everything else via the generic caller.
        $r = ($fn === 'set_tweaks')
            ? smpro_tun_set_tweaksetting($bin, $args, $normId, $bkId, $label)
            : smpro_tun_sa_call_whm($bin, $fn, $args, $normId, $bkId);
        if (!empty($r['ok'])) { $r['applied'] = $label; return $r; }
        // matched but call failed → report the error (don't keep scanning for a weaker match)
        return $r + ['manual' => true];
    }

    // No automated fix found
    return ['ok' => false, 'manual' => true,
            'msg' => 'No automated fix for "' . $normId . '" — apply it in WHM › Security › Security Advisor.',
            'backup_id' => $bkId];
}

/* --- WHM Tweak Settings writer. cPanel's real function is `set_tweaksetting` (SINGULAR, one key/value per call);
 *   there is NO `set_tweaks` function — calling it returns result=0 and the fix silently fails. This loops over the
 *   given key=>value pairs, calling `set_tweaksetting key=<k> value=<v>` for each, and fails on the first error. --- */
function smpro_tun_set_tweaksetting(string $bin, array $kv, string $pid, string $bkId, string $label = ''): array {
    if ($bin === '') return ['ok' => false, 'msg' => 'whmapi1 not available.', 'manual' => true];
    $done = [];
    foreach ($kv as $k => $v) {
        if (!preg_match('/^[a-z0-9_]+$/i', (string)$k) || !is_scalar($v)) continue;
        $out = smpro_tun_sh(escapeshellarg($bin) . ' --output=json set_tweaksetting key=' . escapeshellarg((string)$k) . ' value=' . escapeshellarg((string)$v), 25);
        $j = json_decode($out, true);
        if (!is_array($j) || empty($j['metadata']['result'])) {
            $err = mb_substr(strip_tags((string)$out), 0, 140);
            return ['ok' => false, 'msg' => 'whmapi1 set_tweaksetting ' . $k . ' failed' . ($err ? ': ' . $err : '.'), 'manual' => true, 'backup_id' => $bkId];
        }
        $done[] = $k . '=' . $v;
    }
    if (!$done) return ['ok' => false, 'msg' => 'No valid tweak keys to set.'];
    smpro_tun_profile_add([['engine' => 'cpanel', 'id' => $pid, 'change' => 'set_tweaksetting ' . implode(', ', $done), 'from' => 'previous']]);
    return ['ok' => true, 'applied' => $label !== '' ? $label : implode(', ', $done), 'note' => 'Applied via WHM API (set_tweaksetting).' . ($bkId !== '' ? ' Backup: ' . $bkId . '.' : '')];
}

/* --- SA: safe whmapi1 caller (server-side only, never calls browser-supplied function names) --- */
function smpro_tun_sa_call_whm(string $bin, string $fn, array $args, string $pid, string $bkId): array {
    // Strict allow-list format: lowercase letters, digits, underscores, 1-80 chars
    if (!preg_match('/^[a-z][a-z0-9_]{0,79}$/i', $fn)) return ['ok' => false, 'msg' => 'Invalid whmapi1 function name.'];
    // Block explicitly destructive functions regardless of source
    foreach (['kill', 'delete', 'remove', 'terminate', 'reset_root', 'destroy', 'format', 'wipe'] as $bad)
        if (stripos($fn, $bad) !== false) return ['ok' => false, 'msg' => 'Function "' . $fn . '" is blocked for safety.'];

    $cmd = escapeshellarg($bin) . ' --output=json ' . escapeshellarg($fn);
    foreach ($args as $k => $v) {
        // Only alphanumeric+underscore keys, scalar values
        if (!preg_match('/^[a-z0-9_]+$/i', (string)$k) || !is_scalar($v)) continue;
        $cmd .= ' ' . escapeshellarg((string)$k . '=' . (string)$v);
    }
    $out = smpro_tun_sh($cmd, 25);
    $j   = json_decode($out, true);
    if (!is_array($j) || empty($j['metadata']['result'])) {
        $err = mb_substr(strip_tags($out), 0, 140);
        return ['ok' => false, 'msg' => 'whmapi1 ' . $fn . ' failed' . ($err ? ': ' . $err : '.'), 'backup_id' => $bkId];
    }
    smpro_tun_profile_add([['engine' => 'cpanel', 'id' => $pid, 'change' => 'whmapi1 ' . $fn, 'from' => 'see Security Advisor']]);
    return ['ok' => true, 'applied' => 'whmapi1 ' . $fn, 'note' => 'Applied via WHM API. Backup: ' . $bkId . '. Re-scan Security Advisor to confirm.'];
}

/* shared: write one directive to the cPanel-safe Apache include drop-in, validate, reload */
function smpro_tun_sa_apache_dir(string $directive, string $key, string $pid, string $applied, string $note, string $bkId): array {
    foreach (['/etc/apache2/conf.d/includes', '/usr/local/apache/conf/includes'] as $dir) if (is_dir($dir)) break;
    if (!is_dir($dir)) return ['ok' => false, 'msg' => 'Apache include dir not found — apply via WHM › Include Editor.', 'manual' => true, 'backup_id' => $bkId];
    $file = $dir . '/zz-smpro-tuning.conf';
    $bk   = is_file($file) ? (string)@file_get_contents($file) : null;
    $cur  = trim(preg_replace('/^\s*' . preg_quote($key, '/') . '\b.*$/im', '', (string)@file_get_contents($file)));
    $new  = "# Safety Monitor Pro tune-up (managed)\n" . ($cur !== '' ? $cur . "\n" : '') . $directive . "\n";
    if (@file_put_contents($file, $new, LOCK_EX) === false) return ['ok' => false, 'msg' => 'Cannot write Apache include (permission denied).', 'backup_id' => $bkId];
    $t = smpro_tun_sh('apachectl -t 2>&1; httpd -t 2>&1; /usr/local/apache/bin/httpd -t 2>&1', 15);
    if (stripos($t, 'Syntax OK') === false) { if ($bk !== null) @file_put_contents($file, $bk, LOCK_EX); else @unlink($file); return ['ok' => false, 'msg' => 'Apache config test failed — rolled back. ' . trim(mb_substr($t, 0, 140)), 'backup_id' => $bkId]; }
    smpro_tun_sh('/usr/local/cpanel/scripts/restartsrv_httpd --graceful 2>&1; apachectl -k graceful 2>&1', 30);
    smpro_tun_profile_add([['engine' => 'apache', 'id' => $pid, 'change' => $directive, 'from' => 'not set']]);
    return ['ok' => true, 'applied' => $applied, 'note' => $note . ' Backup: ' . $bkId . '.'];
}

/* shared: write one directive to sshd drop-in, validate (sshd -t), reload */
function smpro_tun_sa_sshd(string $key, string $val, string $pid, string $bkId): array {
    $dir = '/etc/ssh/sshd_config.d';
    $useDrop = is_dir($dir) && stripos((string)@file_get_contents('/etc/ssh/sshd_config'), 'Include') !== false;
    if ($useDrop) {
        $tgt = $dir . '/zz-smpro-tuning.conf';
        $cur = trim(preg_replace('/^\s*' . preg_quote($key, '/') . '\b.*$/im', '', (string)@file_get_contents($tgt)));
        $new = "# Safety Monitor Pro tune-up (managed)\n" . ($cur !== '' ? $cur . "\n" : '') . $key . ' ' . $val . "\n";
    } else {
        $tgt = '/etc/ssh/sshd_config';
        $new = rtrim(preg_replace('/^\s*' . preg_quote($key, '/') . '\b.*$/im', '', (string)@file_get_contents($tgt))) . "\n" . $key . ' ' . $val . "\n";
    }
    $bk = (string)@file_get_contents($tgt);
    if (@file_put_contents($tgt, $new, LOCK_EX) === false) return ['ok' => false, 'msg' => 'Cannot write sshd config (permission denied).', 'backup_id' => $bkId];
    $t = smpro_tun_sh('sshd -t 2>&1; /usr/sbin/sshd -t 2>&1', 10);
    if (trim($t) !== '' && stripos($t, 'warning') === false) { @file_put_contents($tgt, $bk, LOCK_EX); return ['ok' => false, 'msg' => 'sshd config test failed — rolled back. ' . trim(mb_substr($t, 0, 120)), 'backup_id' => $bkId]; }
    smpro_tun_sh('systemctl reload sshd 2>&1; systemctl reload ssh 2>&1', 15);
    smpro_tun_profile_add([['engine' => 'ssh', 'id' => $pid, 'change' => $key . ' ' . $val, 'from' => 'previous']]);
    return ['ok' => true, 'applied' => $key . ' ' . $val, 'note' => 'Applied + sshd reloaded. IMPORTANT: keep this session open and verify a new SSH connection works. Backup: ' . $bkId . '.'];
}

function smpro_tun_sa_cphulk(string $bkId): array {
    $bin = smpro_tun_sa_bin(); if ($bin === '') return ['ok'=>false,'msg'=>'whmapi1 not found.','backup_id'=>$bkId];
    // The real function is enable_cphulk (no args). `set_cphulk_config` does NOT exist on cPanel 11.136 —
    // whmapi1 answers "Unknown app", so the old call silently no-op'd and this fix never enabled anything.
    $out = smpro_tun_sh(escapeshellarg($bin) . ' --output=json enable_cphulk 2>&1', 25);
    $j   = json_decode($out, true);
    $ok  = is_array($j) && !empty($j['metadata']['result']);
    if (!$ok) {
        smpro_tun_sh('/usr/local/cpanel/etc/init/startcphulkd 2>&1', 15); // fallback: start the daemon
    }
    // Tighten the threshold through the per-key setter. `max_failures` is a real config key; the old call's
    // `brutes` was not one at all. Best-effort — a failure here does not invalidate the enable above.
    if ($ok) smpro_tun_sh(escapeshellarg($bin) . ' --output=json set_cphulk_config_key key=max_failures value=25 2>&1', 15);
    // VERIFY the outcome instead of assuming success — the old code always returned ok=true and the UI
    // removed the advisory even when nothing was actually applied.
    $sj = json_decode(smpro_tun_sh(escapeshellarg($bin) . ' --output=json cphulk_status 2>&1', 12), true);
    $on = is_array($sj) && ((int)($sj['data']['is_enabled'] ?? 0) === 1 || ($sj['data']['is_enabled'] ?? null) === true);
    if (!$ok && !$on) {
        return ['ok' => false, 'msg' => 'Could not confirm cPHulkD was enabled (whmapi1 did not report success). Enable it manually in WHM › cPHulkD Brute Force Protection.', 'backup_id' => $bkId];
    }
    smpro_tun_profile_add([['engine' => 'cpanel', 'id' => 'CPHULK', 'change' => 'cPHulkD enabled (max_failures=25)', 'from' => 'disabled']]);
    return ['ok' => true, 'applied' => 'cPHulkD brute-force protection enabled', 'note' => 'cPHulkD is active. Accounts blocked after 25 failures/15 min. Fine-tune in WHM › cPHulkD. Backup: ' . $bkId . '.'];
}

function smpro_tun_sa_mysql_remoteroot(string $bkId): array {
    $df  = is_file('/root/.my.cnf') ? '--defaults-extra-file=/root/.my.cnf' : '';
    // Enumerate the remote-root accounts FIRST so this is genuinely reversible — the file backup ($bkId)
    // holds only config files, never these privilege rows (the old note wrongly implied it could restore them).
    $hostsRaw = smpro_tun_sh("mysql $df -N -B -e \"SELECT Host FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1');\" 2>&1", 15);
    if (stripos($hostsRaw, 'ERROR') !== false) return ['ok' => false, 'msg' => 'MySQL error: ' . mb_substr($hostsRaw, 0, 200), 'backup_id' => $bkId];
    $hosts = array_values(array_filter(array_map('trim', explode("\n", $hostsRaw)), fn($h) => $h !== ''));
    if (!$hosts) return ['ok' => true, 'applied' => 'MySQL remote root already restricted', 'note' => 'No remote-root accounts existed — nothing to change.'];
    // Save SHOW GRANTS for each removed account so an admin can recreate them by hand if ever needed.
    $esc = fn($h) => str_replace(['\\', "'"], ['\\\\', "\\'"], $h);
    $dump = "-- MySQL remote-root grants revoked by SM Pro on " . date('c') . "\n";
    foreach ($hosts as $h) {
        $g = smpro_tun_sh("mysql $df -N -B -e " . escapeshellarg("SHOW GRANTS FOR 'root'@'" . $esc($h) . "';") . " 2>&1", 12);
        $dump .= "-- root@" . $h . "\n" . rtrim($g) . "\n\n";
    }
    $bkDir = SMPRO_TUN_BK . '/' . preg_replace('/[^0-9_]/', '', $bkId);
    @is_dir($bkDir) || @mkdir($bkDir, 0700, true);
    $grantsFile = $bkDir . '/mysql_remote_root_grants.sql';
    @file_put_contents($grantsFile, $dump, LOCK_EX); @chmod($grantsFile, 0600);
    // Revoke with DROP USER (removes the account cleanly, incl. privilege-table rows — DELETE left orphans).
    $drops = 'FLUSH PRIVILEGES; ';
    foreach ($hosts as $h) $drops .= "DROP USER IF EXISTS 'root'@'" . $esc($h) . "'; ";
    $drops .= 'FLUSH PRIVILEGES;';
    $out = smpro_tun_sh("mysql $df -e " . escapeshellarg($drops) . " 2>&1", 15);
    if (stripos($out, 'ERROR') !== false) return ['ok' => false, 'msg' => 'MySQL error: ' . mb_substr($out, 0, 200), 'backup_id' => $bkId];
    smpro_tun_profile_add([['engine' => 'mysql', 'id' => 'REMOTEROOT', 'change' => 'MySQL remote root access revoked (' . count($hosts) . ' host(s))', 'from' => 'allowed']]);
    return ['ok' => true, 'applied' => 'MySQL remote root access revoked', 'note' => 'Root MySQL access is now localhost-only (' . count($hosts) . ' remote host(s) removed). The removed grants were saved to ' . $grantsFile . ' — recreate them by hand from that file if ever needed (the config Backup does NOT contain them).'];
}

function smpro_tun_sa_maxemail(string $bkId): array {
    $bin = smpro_tun_sa_bin(); if ($bin === '') return ['ok'=>false,'msg'=>'whmapi1 not found.','backup_id'=>$bkId];
    $r = smpro_tun_set_tweaksetting($bin, ['maxemailsperhour' => '500'], 'MAXEMAIL', $bkId, 'Max emails/hour = 500 per account');
    if (!empty($r['ok'])) $r['note'] = 'Rate-limit active. Adjust threshold in WHM › Tweak Settings. Backup: ' . $bkId . '.';
    return $r;
}

function smpro_tun_sa_compilers(string $bkId): array {
    // Prefer cPanel's own script (there is NO whmapi1 function for compiler access — the old `compilerinstall`
    // call is "Unknown app" and silently no-ops). Fall back to a clear manual instruction if the script isn't present.
    $script = '/usr/local/cpanel/scripts/set_compiler_access';
    if (is_executable($script)) {
        $out = smpro_tun_sh(escapeshellarg($script) . ' 0 2>&1', 30);   // 0 = disable compiler access for unprivileged users
        $off = is_executable('/usr/bin/gcc') ? (strpos((string)@shell_exec('sudo -u nobody gcc --version 2>&1'), 'ermission') !== false) : true;
        if (stripos($out, 'error') === false) {
            smpro_tun_profile_add([['engine' => 'cpanel', 'id' => 'COMPILERS', 'change' => 'Compiler access disabled', 'from' => 'enabled']]);
            return ['ok' => true, 'applied' => 'Compiler access disabled (gcc/cc) for unprivileged users', 'note' => 'Run via ' . $script . ' 0. Re-enable with "' . $script . ' 1".'];
        }
    }
    return ['ok' => false, 'msg' => 'Disable compiler access in WHM › Security Center › Compiler Access ("Disable compilers for unprivileged users").', 'manual' => true, 'backup_id' => $bkId];
}

function smpro_tun_sa_autoupdate(string $bkId): array {
    $bin = smpro_tun_sa_bin(); if ($bin === '') return ['ok'=>false,'msg'=>'whmapi1 not found.','backup_id'=>$bkId];
    // 'automatic' is NOT a valid value (whmapi1 returns result:0) — set_cpanel_updates only accepts daily/manual/never.
    $out = smpro_tun_sh(escapeshellarg($bin) . ' --output=json set_cpanel_updates updates=daily 2>&1', 20);
    $j   = json_decode($out, true);
    if (!is_array($j) || empty($j['metadata']['result'])) return ['ok' => false, 'msg' => 'whmapi1 set_cpanel_updates failed — apply via WHM › Update Preferences.', 'manual' => true, 'backup_id' => $bkId];
    smpro_tun_profile_add([['engine' => 'cpanel', 'id' => 'AUTOUPDATE', 'change' => 'cPanel updates=daily (automatic)', 'from' => 'manual/disabled']]);
    return ['ok' => true, 'applied' => 'cPanel automatic updates enabled', 'note' => 'cPanel will auto-update on new releases. Backup: ' . $bkId . '.'];
}

function smpro_tun_sa_twofactor(string $bkId): array {
    $bin = smpro_tun_sa_bin(); if ($bin === '') return ['ok'=>false,'msg'=>'whmapi1 not found.','backup_id'=>$bkId];
    // The real function is twofactorauth_enable_policy (no args). The old names (twofactorauth_set_policy /
    // enable_twofactorauth) are "Unknown app" and silently no-op.
    foreach (['twofactorauth_enable_policy'] as $apiCall) {
        $out = smpro_tun_sh(escapeshellarg($bin) . ' --output=json ' . $apiCall . ' 2>&1', 20);
        $j   = json_decode($out, true);
        if (is_array($j) && !empty($j['metadata']['result'])) {
            smpro_tun_profile_add([['engine' => 'cpanel', 'id' => 'TWOFACTORAUTH', 'change' => 'WHM 2FA policy enforced', 'from' => 'optional']]);
            return ['ok' => true, 'applied' => 'Two-factor authentication enforced for WHM', 'note' => 'All WHM users must now configure a TOTP app. Backup: ' . $bkId . '.'];
        }
    }
    return ['ok' => false, 'msg' => 'Could not enable 2FA via API — enable in WHM › Security › Two-Factor Authentication.', 'manual' => true, 'backup_id' => $bkId];
}

function smpro_tun_sa_modsecurity(string $bkId): array {
    $bin = smpro_tun_sa_bin(); if ($bin === '') return ['ok'=>false,'msg'=>'whmapi1 not found.','backup_id'=>$bkId];
    // There is no `modsec_enable_disable` (Unknown app). If the ea-apache24-mod_security2 module is installed,
    // turn the engine On via modsec_set_setting + deploy; otherwise it needs the EA4 package first (manual).
    $inst = json_decode(smpro_tun_sh(escapeshellarg($bin) . ' --output=json modsec_is_installed 2>&1', 15), true);
    if (!is_array($inst) || empty($inst['metadata']['result']) || empty($inst['data']['installed'])) {
        return ['ok' => false, 'msg' => 'ModSecurity (ea-apache24-mod_security2) is not installed — install it in WHM › EasyApache 4, then enable the engine in WHM › Security Center › ModSecurity.', 'manual' => true, 'backup_id' => $bkId];
    }
    $out = smpro_tun_sh(escapeshellarg($bin) . ' --output=json modsec_set_setting setting_id=SecRuleEngine state=On 2>&1', 20);
    $j   = json_decode($out, true);
    $ok  = is_array($j) && !empty($j['metadata']['result']);
    if ($ok) smpro_tun_sh(escapeshellarg($bin) . ' --output=json modsec_deploy_settings_changes 2>&1', 30);
    if (!$ok) return ['ok' => false, 'msg' => 'Could not turn on the ModSecurity engine via API — enable it in WHM › Security Center › ModSecurity.', 'manual' => true, 'backup_id' => $bkId];
    smpro_tun_profile_add([['engine' => 'apache', 'id' => 'MODSECURITY', 'change' => 'ModSecurity engine On', 'from' => 'disabled']]);
    return ['ok' => true, 'applied' => 'ModSecurity WAF engine turned On', 'note' => 'Confirm an active rule set (OWASP CRS / Comodo) in WHM › Security Center › ModSecurity Vendors.'];
}

/* ---------------- backups (timestamped, listed) ---------------- */
/** SM Pro-managed drop-in files the tune-up appliers create (Apache Include + per-EA-PHP php.d). Backup/restore
 *  track these so a change written to a NEW drop-in is fully reversible (restore removes it). */
function smpro_tun_managed_dropins(): array {
    $out = [];
    foreach (['/etc/apache2/conf.d/includes', '/usr/local/apache/conf/includes'] as $d) if (is_dir($d)) $out[] = $d . '/zz-smpro-tuning.conf';
    foreach (glob('/opt/cpanel/ea-php*/root/etc/php.d', GLOB_ONLYDIR) ?: [] as $d) $out[] = $d . '/zz-smpro-tuning.ini';
    return array_values(array_unique($out));
}
function smpro_tun_backup_all(): array {
    $det = smpro_tun_detect();
    $id = date('Ymd_His'); $dir = SMPRO_TUN_BK . '/' . $id;
    @mkdir($dir, 0700, true);
    $files = []; $absent = [];
    foreach (['/etc/my.cnf', '/etc/csf/csf.conf'] as $f) if (is_file($f)) { @copy($f, $dir . '/' . str_replace('/', '_', ltrim($f, '/'))); $files[] = $f; }
    foreach ($det as $eng) if (!empty($eng['conf']) && is_file($eng['conf'])) { $dst = $dir . '/' . str_replace('/', '_', ltrim($eng['conf'], '/')); if (!is_file($dst)) { @copy($eng['conf'], $dst); $files[] = $eng['conf']; } }
    // SM Pro-managed drop-ins: back up if present; else record as ABSENT so restore REMOVES one created after this snapshot.
    foreach (smpro_tun_managed_dropins() as $f) {
        if (is_file($f)) { @copy($f, $dir . '/' . str_replace('/', '_', ltrim($f, '/'))); $files[] = $f; }
        else $absent[] = $f;
    }
    @file_put_contents($dir . '/manifest.json', json_encode(['id' => $id, 'ts' => time(), 'files' => array_values(array_unique($files)), 'absent' => array_values(array_unique($absent))], JSON_PRETTY_PRINT));
    return ['id' => $id, 'files' => array_values(array_unique($files))];
}
function smpro_tun_backups(): array {
    $out = [];
    foreach (array_reverse(glob(SMPRO_TUN_BK . '/*', GLOB_ONLYDIR) ?: []) as $d) {
        $m = json_decode((string)@file_get_contents($d . '/manifest.json'), true);
        $out[] = ['id' => basename($d), 'ts' => $m['ts'] ?? @filemtime($d), 'files' => $m['files'] ?? [], 'count' => count(glob($d . '/*') ?: []) - 1];
    }
    return $out;
}

/** Restore a timestamped backup — copies each file back to its original location.
 *  Before overwriting, saves the CURRENT config as a new "pre-restore" safeguard backup.
 *  If CSF was included, reloads it with `csf -r`. Returns ['ok','msg','restored','pre_restore_backup'?]. */
function smpro_tun_restore(string $backupId): array {
    if (!preg_match('/^[0-9]{8}_[0-9]{6}/', $backupId)) return ['ok'=>false,'msg'=>'Invalid backup ID'];
    $dir = SMPRO_TUN_BK . '/' . $backupId;
    if (!is_dir($dir)) return ['ok'=>false,'msg'=>'Backup not found'];
    $m = json_decode((string)@file_get_contents($dir . '/manifest.json'), true);
    if (!is_array($m) || empty($m['files'])) return ['ok'=>false,'msg'=>'Manifest missing or empty'];
    // Save the CURRENT config as a safeguard before overwriting anything.
    $sgId = date('Ymd_His') . '_pre'; $sgDir = SMPRO_TUN_BK . '/' . $sgId; @mkdir($sgDir, 0700, true);
    $restored = []; $failed = []; $removed = []; $csfTouched = false; $apacheTouched = false; $phpTouched = false;
    foreach ((array)$m['files'] as $origPath) {
        $origPath = (string)$origPath;
        if (strpos($origPath, '..') !== false || strpos($origPath, '/') !== 0) { $failed[] = $origPath . ' (unsafe path)'; continue; }
        $bkFile = $dir . '/' . str_replace('/', '_', ltrim($origPath, '/'));
        if (!is_file($bkFile)) { $failed[] = $origPath . ' (backup file missing)'; continue; }
        // Preserve the file's REAL mode — blindly forcing 0640 broke files that must be world-readable
        // (e.g. /etc/my.cnf is 0644; at 0640 root:root the mysql user can't read it → DB starts on defaults).
        $origMode = @is_file($origPath) ? (@fileperms($origPath) & 0777) : null;
        if (is_file($origPath)) @copy($origPath, $sgDir . '/' . str_replace('/', '_', ltrim($origPath, '/')));
        if (@copy($bkFile, $origPath)) {
            @chmod($origPath, $origMode !== null ? $origMode : (strpos($origPath, 'my.cnf') !== false ? 0644 : 0640));
            $restored[] = $origPath;
            if (strpos($origPath, 'csf') !== false) $csfTouched = true;
            elseif (strpos($origPath, 'php.d') !== false || strpos($origPath, 'php.ini') !== false) $phpTouched = true;
            elseif (strpos($origPath, 'apache') !== false || strpos($origPath, 'httpd') !== false || strpos($origPath, 'includes') !== false) $apacheTouched = true;
        } else { $failed[] = $origPath . ' (copy failed — check ownership)'; }
    }
    // REMOVE SM Pro-managed drop-ins that did NOT exist at snapshot time (they were created by an apply afterwards),
    // so "restore" fully undoes the Apache/PHP drop-in changes too. Only ever touches our own zz-smpro-tuning.* files.
    foreach ((array)($m['absent'] ?? []) as $ab) {
        $ab = (string)$ab;
        if (strpos($ab, '..') !== false || strpos($ab, '/') !== 0 || strpos(basename($ab), 'zz-smpro-tuning.') !== 0) continue;
        if (is_file($ab)) { @copy($ab, $sgDir . '/' . str_replace('/', '_', ltrim($ab, '/'))); if (@unlink($ab)) { $removed[] = $ab; if (strpos($ab, 'php.d') !== false) $phpTouched = true; else $apacheTouched = true; } }
    }
    @file_put_contents($sgDir . '/manifest.json', json_encode(['id'=>$sgId,'ts'=>time(),'files'=>$restored,'removed'=>$removed,'type'=>'pre-restore-safeguard','source_backup'=>$backupId], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    if (!$restored && !$removed) return ['ok'=>false,'msg'=>'No files restored.' . ($failed ? ' ' . implode('; ', $failed) : '')];
    if ($csfTouched && smpro_tun_has('csf')) @shell_exec('csf -r >/dev/null 2>&1 &');
    if ($apacheTouched) { $t = smpro_tun_sh('apachectl -t 2>&1; httpd -t 2>&1', 15); if (stripos($t, 'Syntax OK') !== false) smpro_tun_sh('/usr/local/cpanel/scripts/restartsrv_httpd --graceful 2>&1; apachectl -k graceful 2>&1', 30); }
    if ($phpTouched) smpro_tun_sh('/usr/local/cpanel/scripts/restartsrv_apache_php_fpm 2>&1', 60);
    if (function_exists('smpro_audit')) smpro_audit('tuning_restore', ['backup_id'=>$backupId,'restored'=>count($restored),'removed'=>count($removed),'failed'=>count($failed)]);
    $msg = 'Restored ' . count($restored) . ' file(s)' . ($removed ? ' + removed ' . count($removed) . ' SM Pro drop-in(s)' : '') . ' from backup ' . date('Y-m-d H:i', (int)($m['ts'] ?? 0)) . '.' . ($csfTouched ? ' CSF reloaded.' : '') . (($apacheTouched || $phpTouched) ? ' Web/PHP reloaded.' : '') . ($failed ? ' Warnings: ' . implode('; ', $failed) : '');
    return ['ok'=>true,'restored'=>count($restored),'removed'=>count($removed),'msg'=>$msg,'pre_restore_backup'=>$sgId];
}

/* ---------------- applied-change profiles ---------------- */
function smpro_tun_profile_add(array $changes): string {
    @mkdir(SMPRO_TUN_PROF, 0700, true);
    $id = date('Ymd_His');
    @file_put_contents(SMPRO_TUN_PROF . '/' . $id . '.json', json_encode(['id' => $id, 'ts' => time(), 'changes' => $changes], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    @chmod(SMPRO_TUN_PROF . '/' . $id . '.json', 0600);
    if (function_exists('smpro_audit')) smpro_audit('tuning_profile', ['id' => $id, 'n' => count($changes)]);
    return $id;
}
function smpro_tun_profiles(): array {
    $out = [];
    foreach (array_reverse(glob(SMPRO_TUN_PROF . '/*.json') ?: []) as $f) { $j = json_decode((string)@file_get_contents($f), true); if (is_array($j)) $out[] = $j; }
    return $out;
}

/* ---------------- apply (safe subset only) ----------------
 * AUTO-applicable on cPanel = CSF settings (validated by `csf -r`) and my.cnf additions (appended under
 * [mysqld] WITHOUT restarting — takes effect on the next planned restart, so nothing breaks live).
 * Apache/PHP are cPanel-managed (regenerated from templates) → advisory only, never auto-edited here.
 * Every apply: backup → change → (validate) → record profile. */
function smpro_tun_apply_map(): array {
    return [
        'mysql_bufferpool' => ['mycnf', 'innodb_buffer_pool_size'],
        'mysql_skipdns'    => ['mycnf_flag', 'skip-name-resolve'],
        'mysql_slowlog'    => ['mycnf', 'slow_query_log', '1', 'long_query_time', '2'],
        'mysql_localinfile'=> ['mycnf', 'local-infile', '0'],
        'csf_synflood'     => ['csf', 'SYNFLOOD', '1'],
        'csf_ct'           => ['csf', 'CT_LIMIT', '300'],
        'csf_testing'      => ['csf', 'TESTING', '0'],
        // Apache: written to a cPanel-safe Include drop-in (survives template rebuilds) → validate → graceful reload.
        'apache_tokens'    => ['apache_inc', 'ServerTokens Prod'],
        'apache_sig'       => ['apache_inc', 'ServerSignature Off'],
        'apache_keepalive' => ['apache_inc', "KeepAlive On\nKeepAliveTimeout 5"],
        // PHP: written to a php.d drop-in for every EA-PHP version → restart PHP-FPM.
        'php_expose'       => ['php_ini', 'expose_php', 'Off'],
        'php_opcache'      => ['php_ini', 'opcache.enable', '1'],
        // previously advisory-only — now real, validated, reversible appliers:
        'csf_alert'        => ['csf_alert'],                          // LF_ALERT_TO = server contact email
        'imunify_pad'      => ['imunify_pd'],                         // enable Proactive Defense
        'http_h2_apache'   => ['apache_h2'],                         // install mod_http2 + Protocols
        'ssh_root'         => ['sshd', 'PermitRootLogin', 'prohibit-password'],
        'ssh_passauth'     => ['sshd', 'PasswordAuthentication', 'no'],
        'ssh_port'         => ['sshd', 'Port', '2222'],              // opens CSF TCP_IN first to avoid lockout
        'ssh_x11'          => ['sshd', 'X11Forwarding', 'no'],       // safe (no lockout)
        // Access isolation / jailing (WHM-Security-Advisor parity):
        'harden_symlink'   => ['jail_apache'],                         // cPanel fixes symlink races by enabling Jail Apache (mod_ruid2)
        'harden_ruid2'     => ['jail_apache'],                         // install mod_ruid2 (if missing) + enable Jail Apache
        'harden_jailshell' => ['jailshell'],                           // switch full-shell cPanel accounts to jailshell
        'harden_cagefs'    => ['cagefs_enable'],                       // cagefsctl --enable-all (CloudLinux)
    ];
}

/** Optimization score (0-100): start at 100, each open finding subtracts by severity. Rises as items are applied. */
function smpro_tun_score(array $recs): array {
    $w = ['high' => 10, 'medium' => 6, 'low' => 3];
    $pen = 0; $h = 0; $me = 0; $lo = 0;
    foreach ($recs as $r) {
        $sev = $r['sev'] ?? 'low'; $pen += $w[$sev] ?? 4;
        if ($sev === 'high') $h++; elseif ($sev === 'medium') $me++; else $lo++;
    }
    $score = max(0, 100 - $pen);
    $grade = $score >= 85 ? 'A' : ($score >= 70 ? 'B' : ($score >= 50 ? 'C' : 'D'));
    return ['score' => $score, 'grade' => $grade, 'high' => $h, 'medium' => $me, 'low' => $lo, 'open' => count($recs), 'w' => $w];
}
function smpro_tun_apply(string $recId, bool $skipBackup = false): array {
    $scan = smpro_tun_scan();
    $rec = null; foreach ($scan['recs'] as $r) if ($r['id'] === $recId) { $rec = $r; break; }
    if (!$rec) return ['ok' => false, 'msg' => 'Recommendation not found (re-scan).'];
    $map = smpro_tun_apply_map();
    if (!isset($map[$recId])) return ['ok' => false, 'msg' => 'This change is cPanel-managed — apply it via WHM (advisory). Recommended: ' . $rec['recommended'], 'manual' => true];

    $bkId = '';
    if (!$skipBackup) { $bkAll = smpro_tun_backup_all(); $bkId = is_array($bkAll) ? (string)($bkAll['id'] ?? '') : ''; }   // always back up first
    $m = $map[$recId]; $kind = $m[0];

    if ($kind === 'csf') {
        $file = '/etc/csf/csf.conf'; $key = $m[1]; $val = $m[2];
        $c = (string)@file_get_contents($file); if ($c === '') return ['ok' => false, 'msg' => 'csf.conf unreadable'];
        $new = preg_replace('/^\s*' . preg_quote($key, '/') . '\s*=\s*"[^"]*"/im', $key . ' = "' . $val . '"', $c, 1, $cnt);
        if ($cnt === 0) $new = rtrim($c) . "\n" . $key . ' = "' . $val . "\"\n";
        if (@file_put_contents($file, $new, LOCK_EX) === false) return ['ok' => false, 'msg' => 'Could not write ' . $file . ' (permission denied).'];
        $out = smpro_tun_sh('csf -r', 20);                              // csf validates on reload
        smpro_tun_profile_add([['engine' => 'csf', 'id' => $recId, 'change' => $key . '=' . $val, 'from' => $rec['current']]]);
        return ['ok' => true, 'applied' => $key . '=' . $val, 'note' => 'CSF reloaded.'];
    }
    if ($kind === 'mycnf' || $kind === 'mycnf_flag') {
        $file = smpro_tun_mycnf();
        $lines = ['# Safety Monitor Pro tune-up ' . date('Y-m-d') . ' (' . $recId . ')'];
        if ($kind === 'mycnf_flag') { $lines[] = $m[1]; }
        else { for ($i = 1; $i + 1 < count($m); $i += 2) { $val = $m[$i + 1] ?? ''; if ($m[$i] === 'innodb_buffer_pool_size') $val = max(1, (int)round($scan['ram_mb'] * 0.5 / 1024)) . 'G'; $lines[] = $m[$i] . ' = ' . $val; } }
        $c = (string)@file_get_contents($file);
        // ensure it lands under [mysqld]
        if (preg_match('/^\s*\[mysqld\]/im', $c)) $new = preg_replace('/^(\s*\[mysqld\][^\n]*\n)/im', "$1" . implode("\n", $lines) . "\n", $c, 1);
        else $new = "[mysqld]\n" . implode("\n", $lines) . "\n" . $c;
        if (@file_put_contents($file, $new, LOCK_EX) === false) return ['ok' => false, 'msg' => 'Could not write ' . $file . ' (permission denied).'];
        smpro_tun_profile_add([['engine' => 'mysql', 'id' => $recId, 'change' => implode('; ', $lines), 'from' => $rec['current']]]);
        return ['ok' => true, 'applied' => implode('; ', array_slice($lines, 1)), 'note' => 'Added to my.cnf — takes effect on the NEXT MySQL restart (do it at a quiet time). Not restarted now (safe).', 'needs_restart' => 'mysql'];
    }
    // Apache: cPanel-safe Include drop-in (NOT httpd.conf — survives EasyApache rebuilds), validated + graceful reload + auto-rollback.
    if ($kind === 'apache_inc') {
        $dir = '/etc/apache2/conf.d/includes'; if (!is_dir($dir)) $dir = is_dir('/usr/local/apache/conf/includes') ? '/usr/local/apache/conf/includes' : '';
        if ($dir === '') return ['ok' => false, 'msg' => 'Apache cPanel-include dir not found — apply via WHM › Include Editor. Recommended: ' . $rec['recommended'], 'manual' => true];
        $file = $dir . '/zz-smpro-tuning.conf'; $directive = $m[1];
        $dkey = preg_split('/\s+/', trim($directive))[0];
        $cur = (string)@file_get_contents($file);
        $cur = trim(preg_replace('/^\s*' . preg_quote($dkey, '/') . '\b.*$/im', '', $cur));
        $new = "# Safety Monitor Pro tune-up (managed)\n" . ($cur !== '' ? $cur . "\n" : '') . $directive . "\n";
        $bk = is_file($file) ? (string)@file_get_contents($file) : null;
        if (@file_put_contents($file, $new, LOCK_EX) === false) return ['ok' => false, 'msg' => 'Could not write ' . $file . ' (permission denied).'];
        $t = smpro_tun_sh('apachectl -t 2>&1; httpd -t 2>&1; /usr/local/apache/bin/httpd -t 2>&1', 15);
        if (stripos($t, 'Syntax OK') === false) { if ($bk !== null) @file_put_contents($file, $bk, LOCK_EX); else @unlink($file); return ['ok' => false, 'msg' => 'Apache config test failed — change rolled back. ' . trim(mb_substr($t, 0, 180))]; }
        smpro_tun_sh('/usr/local/cpanel/scripts/restartsrv_httpd --graceful 2>&1; apachectl -k graceful 2>&1', 30);
        smpro_tun_profile_add([['engine' => 'apache', 'id' => $recId, 'change' => str_replace("\n", ' / ', $directive), 'from' => $rec['current']]]);
        return ['ok' => true, 'applied' => str_replace("\n", ' / ', $directive), 'note' => 'Written to a cPanel-safe Apache Include + reloaded (graceful, validated).'];
    }
    // PHP: php.d drop-in for every EA-PHP version (survives rebuilds) + PHP-FPM restart.
    if ($kind === 'php_ini') {
        $iniKey = $m[1]; $iniVal = $m[2];
        $vers = [];
        foreach (glob('/opt/cpanel/ea-php*/root/usr/bin/php') ?: [] as $p) if (preg_match('#/(ea-php\d+)/#', $p, $mm)) $vers[$mm[1]] = '/opt/cpanel/' . $mm[1] . '/root/etc/php.d';
        if (!$vers) return ['ok' => false, 'msg' => 'No EA-PHP found — apply via WHM › MultiPHP INI Editor. Recommended: ' . $rec['recommended'], 'manual' => true];
        // OPcache needs the Zend extension package — a php.d "opcache.enable=1" is INERT without it. Install it first.
        $need = [];
        if ($recId === 'php_opcache') {
            foreach ($vers as $v => $d) if (!glob('/opt/cpanel/' . $v . '/root/usr/lib*/php/modules/opcache.so')) $need[] = $v . '-php-opcache';
            if ($need) {
                $pm = smpro_tun_has('dnf') ? 'dnf' : (smpro_tun_has('yum') ? 'yum' : '');
                if ($pm === '') return ['ok' => false, 'msg' => 'OPcache extension not installed and no dnf/yum available — install ' . implode(' ', $need) . ' via WHM › EasyApache 4.', 'manual' => true];
                smpro_tun_sh($pm . ' -y install ' . implode(' ', array_map('escapeshellarg', $need)) . ' 2>&1', 300);
            }
        }
        $wrote = 0; $prev = [];
        $binOf = []; foreach (glob('/opt/cpanel/ea-php*/root/usr/bin/php') ?: [] as $p) if (preg_match('#/(ea-php\d+)/#', $p, $mm)) $binOf[$mm[1]] = $p;
        foreach ($vers as $v => $d) {
            if (!is_dir($d)) continue;
            $file = $d . '/zz-smpro-tuning.ini';
            $prev[$v] = ['file' => $file, 'content' => is_file($file) ? (string)@file_get_contents($file) : null];
            $cur = trim(preg_replace('/^\s*' . preg_quote($iniKey, '/') . '\s*=.*$/im', '', (string)@file_get_contents($file)));
            $new = "; Safety Monitor Pro tune-up (managed)\n" . ($cur !== '' ? $cur . "\n" : '') . $iniKey . ' = ' . $iniVal . "\n";
            if (@file_put_contents($file, $new, LOCK_EX) !== false) $wrote++;
        }
        if (!$wrote) return ['ok' => false, 'msg' => 'Could not write any php.d drop-in (permission denied).'];
        // lint each drop-in with its own PHP binary; roll back any version whose PHP can't start with it (never restart
        // FPM into a broken .ini). Config-test parity with the Apache appliers.
        foreach ($prev as $v => $pv) { $bin = $binOf[$v] ?? '';
            if ($bin === '' || !is_file($pv['file'])) continue;
            $chk = smpro_tun_sh(escapeshellarg($bin) . ' -n -c ' . escapeshellarg($pv['file']) . ' -v 2>&1', 10);
            if (stripos($chk, 'PHP ') === false) {   // PHP failed to even print its version with this .ini → bad drop-in
                if ($pv['content'] === null) @unlink($pv['file']); else @file_put_contents($pv['file'], $pv['content'], LOCK_EX);
                $wrote--;
            }
        }
        if ($wrote < 1) return ['ok' => false, 'msg' => 'PHP config test failed on all versions — the change was rolled back.'];
        smpro_tun_sh('/usr/local/cpanel/scripts/restartsrv_apache_php_fpm 2>&1', 60);
        // HONEST verify for OPcache: confirm the extension is actually present now (no false "applied").
        if ($recId === 'php_opcache') {
            $loaded = false; foreach ($vers as $v => $d) if (glob('/opt/cpanel/' . $v . '/root/usr/lib*/php/modules/opcache.so')) { $loaded = true; break; }
            if (!$loaded) return ['ok' => false, 'msg' => 'Setting written, but the OPcache extension could not be installed (' . implode(' ', $need) . ') — install it via WHM › EasyApache 4, then re-scan.'];
        }
        smpro_tun_profile_add([['engine' => 'php', 'id' => $recId, 'change' => $iniKey . '=' . $iniVal, 'from' => $rec['current']]]);
        return ['ok' => true, 'applied' => $iniKey . ' = ' . $iniVal, 'note' => 'Written to php.d on ' . $wrote . ' EA-PHP version(s)' . ($recId === 'php_opcache' ? ' + OPcache extension installed' : '') . ' + PHP-FPM restarted.'];
    }
    // CSF/LFD alert email → server contact (safe).
    if ($kind === 'csf_alert') {
        $file = '/etc/csf/csf.conf'; $c = (string)@file_get_contents($file); if ($c === '') return ['ok' => false, 'msg' => 'csf.conf unreadable'];
        $email = trim(smpro_tun_sh("awk '/^CONTACTEMAIL/{print \$2}' /etc/wwwacct.conf 2>/dev/null | head -1"));
        if ($email === '' || strpos($email, '@') === false) $email = 'root@' . trim(smpro_tun_sh('hostname -f 2>/dev/null'));
        $new = preg_replace('/^\s*LF_ALERT_TO\s*=\s*"[^"]*"/im', 'LF_ALERT_TO = "' . $email . '"', $c, 1, $cnt);
        if ($cnt === 0) $new = rtrim($c) . "\nLF_ALERT_TO = \"" . $email . "\"\n";
        if (@file_put_contents($file, $new, LOCK_EX) === false) return ['ok' => false, 'msg' => 'Could not write csf.conf (permission denied).'];
        smpro_tun_sh('csf -r', 20);
        smpro_tun_profile_add([['engine' => 'csf', 'id' => $recId, 'change' => 'LF_ALERT_TO=' . $email, 'from' => $rec['current']]]);
        return ['ok' => true, 'applied' => 'LF_ALERT_TO = ' . $email, 'note' => 'CSF/LFD alerts now go to ' . $email . '. Change it in WHM › CSF if needed.'];
    }
    // Imunify Proactive Defense → KILL mode (safe).
    if ($kind === 'imunify_pd') {
        if (!smpro_tun_has('imunify360-agent')) return ['ok' => false, 'msg' => 'imunify360-agent not found — apply via the Imunify UI.', 'manual' => true];
        smpro_tun_sh('imunify360-agent config update \'{"PROACTIVE_DEFENSE": {"mode": "KILL"}}\' 2>&1', 40);
        smpro_tun_profile_add([['engine' => 'imunify', 'id' => $recId, 'change' => 'PROACTIVE_DEFENSE=KILL', 'from' => $rec['current']]]);
        return ['ok' => true, 'applied' => 'Proactive Defense → KILL', 'note' => 'Imunify Proactive Defense enabled.'];
    }
    // Apache HTTP/2 → ensure mod_http2 + Protocols directive in the cPanel-safe include (validated + graceful reload).
    if ($kind === 'apache_h2') {
        $bin = $scan['engines']['apache']['bin'] ?? 'httpd';
        if (!preg_match('/http2_module|mod_http2/i', smpro_tun_sh(escapeshellarg($bin) . ' -M 2>&1', 12))) {
            $pm = smpro_tun_has('dnf') ? 'dnf' : (smpro_tun_has('yum') ? 'yum' : '');
            if ($pm) smpro_tun_sh($pm . ' -y install ea-apache24-mod_http2 2>&1', 300);
        }
        $dir = '/etc/apache2/conf.d/includes'; if (!is_dir($dir)) return ['ok' => false, 'msg' => 'Apache include dir not found — apply via WHM.', 'manual' => true];
        $file = $dir . '/zz-smpro-tuning.conf';
        $cur = trim(preg_replace('/^\s*Protocols\b.*$/im', '', (string)@file_get_contents($file)));
        $new = "# Safety Monitor Pro tune-up (managed)\n" . ($cur !== '' ? $cur . "\n" : '') . "Protocols h2 http/1.1\n";
        $bk = is_file($file) ? (string)@file_get_contents($file) : null;
        if (@file_put_contents($file, $new, LOCK_EX) === false) return ['ok' => false, 'msg' => 'Could not write Apache include (permission denied).'];
        $t = smpro_tun_sh('apachectl -t 2>&1; httpd -t 2>&1; ' . escapeshellarg($bin) . ' -t 2>&1', 15);
        if (stripos($t, 'Syntax OK') === false) { if ($bk !== null) @file_put_contents($file, $bk, LOCK_EX); else @unlink($file); return ['ok' => false, 'msg' => 'Apache config test failed — rolled back. ' . trim(mb_substr($t, 0, 160))]; }
        smpro_tun_sh('/usr/local/cpanel/scripts/restartsrv_httpd --graceful 2>&1; apachectl -k graceful 2>&1', 30);
        smpro_tun_profile_add([['engine' => 'apache', 'id' => $recId, 'change' => 'mod_http2 + Protocols h2 http/1.1', 'from' => $rec['current']]]);
        return ['ok' => true, 'applied' => 'HTTP/2 enabled', 'note' => 'mod_http2 ensured + Protocols set in a cPanel-safe include + Apache reloaded (graceful).'];
    }
    // SSH hardening via sshd_config.d drop-in → validate (sshd -t) → reload. ACCESS-RISK: port change opens CSF first.
    if ($kind === 'sshd') {
        $key = $m[1]; $val = $m[2];
        if ($key === 'Port' && is_file('/etc/csf/csf.conf')) {                    // open the new port in CSF BEFORE changing sshd (anti-lockout)
            $cc = (string)@file_get_contents('/etc/csf/csf.conf');
            if (preg_match('/^\s*TCP_IN\s*=\s*"([^"]*)"/im', $cc, $mm) && strpos(',' . $mm[1] . ',', ',' . $val . ',') === false) {
                $nc = preg_replace('/^(\s*TCP_IN\s*=\s*")([^"]*)(")/im', '${1}${2},' . $val . '${3}', $cc, 1);
                @file_put_contents('/etc/csf/csf.conf', $nc, LOCK_EX); smpro_tun_sh('csf -r', 20);
            }
        }
        $dir = '/etc/ssh/sshd_config.d';
        $useDrop = is_dir($dir) && stripos((string)@file_get_contents('/etc/ssh/sshd_config'), 'Include') !== false;
        if ($useDrop) { $tgt = $dir . '/zz-smpro-tuning.conf'; $cur = trim(preg_replace('/^\s*' . preg_quote($key, '/') . '\b.*$/im', '', (string)@file_get_contents($tgt))); $new = "# Safety Monitor Pro tune-up (managed)\n" . ($cur !== '' ? $cur . "\n" : '') . $key . ' ' . $val . "\n"; }
        else { $tgt = '/etc/ssh/sshd_config'; $new = rtrim(preg_replace('/^\s*' . preg_quote($key, '/') . '\b.*$/im', '', (string)@file_get_contents($tgt))) . "\n" . $key . ' ' . $val . "\n"; }
        $bk = (string)@file_get_contents($tgt);
        if (@file_put_contents($tgt, $new, LOCK_EX) === false) return ['ok' => false, 'msg' => 'Could not write ' . $tgt . ' (permission denied).'];
        $t = smpro_tun_sh('sshd -t 2>&1; /usr/sbin/sshd -t 2>&1', 10);
        if (trim($t) !== '' && stripos($t, 'warning') === false) { @file_put_contents($tgt, $bk, LOCK_EX); return ['ok' => false, 'msg' => 'sshd config test failed — rolled back. ' . trim(mb_substr($t, 0, 160))]; }
        smpro_tun_sh('systemctl reload sshd 2>&1; systemctl reload ssh 2>&1; service sshd reload 2>&1', 15);
        smpro_tun_profile_add([['engine' => 'ssh', 'id' => $recId, 'change' => $key . ' ' . $val, 'from' => $rec['current']]]);
        return ['ok' => true, 'applied' => $key . ' ' . $val, 'note' => 'Applied + sshd reloaded. IMPORTANT: keep this session open and confirm a NEW SSH login works before closing it.' . ($key === 'Port' ? ' New port ' . $val . ' was opened in CSF first.' : '')];
    }
    // Access isolation — install mod_ruid2 (if missing) + enable Jail Apache; rebuild + graceful restart.
    if ($kind === 'jail_apache') {
        $bin = smpro_tun_sa_bin();
        if ($bin === '') return ['ok' => false, 'msg' => 'whmapi1 not available — enable Jail Apache in WHM › Tweak Settings.', 'manual' => true];
        $abin = $scan['engines']['apache']['bin'] ?? 'httpd';
        if (!preg_match('/ruid2/i', smpro_tun_sh(escapeshellarg($abin) . ' -M 2>&1', 12))) {
            $pm = smpro_tun_has('dnf') ? 'dnf' : (smpro_tun_has('yum') ? 'yum' : '');
            if ($pm === '') return ['ok' => false, 'msg' => 'mod_ruid2 not installed and no dnf/yum — install ea-apache24-mod_ruid2 via WHM › EasyApache 4, then enable Jail Apache in Tweak Settings.', 'manual' => true];
            smpro_tun_sh($pm . ' -y install ea-apache24-mod_ruid2 2>&1', 300);
        }
        $r = smpro_tun_set_tweaksetting($bin, ['jailapache' => '1'], $recId, $bkId, 'Jail Apache enabled');
        if (empty($r['ok'])) return $r + ['manual' => true];
        smpro_tun_sh('/usr/local/cpanel/scripts/rebuildhttpdconf 2>&1', 90);
        smpro_tun_sh('/usr/local/cpanel/scripts/restartsrv_httpd --graceful 2>&1; apachectl -k graceful 2>&1', 40);
        $loaded = (bool)preg_match('/ruid2/i', smpro_tun_sh(escapeshellarg($abin) . ' -M 2>&1', 12));
        smpro_tun_profile_add([['engine' => 'access', 'id' => $recId, 'change' => 'mod_ruid2 + jailapache=1', 'from' => 'shared web user']]);
        return ['ok' => true, 'applied' => 'Jail Apache + mod_ruid2 enabled',
            'note' => ($loaded ? 'Apache now runs each vhost as its owner (mod_ruid2). ' : 'Jail Apache tweak set — if mod_ruid2 is not loaded yet, rebuild EasyApache 4. ') . 'Reversible: turn Jail Apache off in WHM › Tweak Settings. Note: this can affect accessing Mailman via Apache. Backup: ' . $bkId . '.'];
    }
    // Access isolation — move full-shell cPanel accounts into jailshell (reversible per-account).
    if ($kind === 'jailshell') {
        $js = '/usr/local/cpanel/bin/jailshell';
        if (!is_executable($js)) return ['ok' => false, 'msg' => 'jailshell not found at ' . $js . ' — set shells in WHM › Manage Shell Access.', 'manual' => true];
        $users = smpro_tun_shell_users();
        if (!$users) return ['ok' => false, 'msg' => 'No accounts on a full shell — nothing to change.'];
        $done = []; $fail = [];
        foreach ($users as $u) {
            smpro_tun_sh('usermod -s ' . escapeshellarg($js) . ' ' . escapeshellarg($u['user']) . ' 2>&1', 15);
            $line = trim(smpro_tun_sh('getent passwd ' . escapeshellarg($u['user']) . ' 2>/dev/null'));
            $now = ''; if ($line !== '') { $pp = explode(':', $line); $now = (string)end($pp); }
            if ($now === $js) $done[] = $u['user']; else $fail[] = $u['user'];
        }
        if (!$done) return ['ok' => false, 'msg' => 'Could not change any shell (permission denied?). Users: ' . implode(', ', array_slice($fail, 0, 6))];
        smpro_tun_profile_add([['engine' => 'access', 'id' => $recId, 'change' => 'jailshell: ' . implode(', ', $done), 'from' => 'full shell']]);
        return ['ok' => true, 'applied' => count($done) . ' account(s) → jailshell',
            'note' => ($fail ? count($fail) . ' could not be changed (' . implode(', ', array_slice($fail, 0, 5)) . '). ' : '') . 'Reversible per-account in WHM › Manage Shell Access. Backup: ' . $bkId . '.'];
    }
    // Access isolation — enable CageFS for all users (CloudLinux). Reversible: cagefsctl --disable-all.
    if ($kind === 'cagefs_enable') {
        $ctl = smpro_tun_cagefsctl();
        if ($ctl === '') return ['ok' => false, 'msg' => 'cagefsctl not found — install CageFS from WHM › CloudLinux™ Manager first.', 'manual' => true];
        smpro_tun_sh(escapeshellarg($ctl) . ' --enable-all 2>&1', 180);
        smpro_tun_sh(escapeshellarg($ctl) . ' --force-update 2>&1', 180);
        $disN = (int)trim(smpro_tun_sh(escapeshellarg($ctl) . ' --list-disabled 2>/dev/null | grep -c .'));
        smpro_tun_profile_add([['engine' => 'access', 'id' => $recId, 'change' => 'cagefsctl --enable-all', 'from' => 'partial/off']]);
        return ['ok' => true, 'applied' => 'CageFS enabled for all users',
            'note' => ($disN > 0 ? $disN . ' user(s) still not enabled — see cagefsctl --list-disabled. ' : 'Every account is now isolated in its own virtual filesystem. ') . 'Reversible: cagefsctl --disable-all.'];
    }
    return ['ok' => false, 'msg' => 'unsupported'];
}
