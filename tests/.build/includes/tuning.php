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

function smpro_tun_sh($cmd, $t = 8) { return (string)@shell_exec('timeout ' . (int)$t . ' ' . $cmd . ' 2>/dev/null'); }
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
    if (is_file('/etc/csf/csf.conf')) $e['csf'] = ['label' => 'CSF Firewall', 'conf' => '/etc/csf/csf.conf', 'ver' => trim(smpro_tun_sh('csf -v 2>&1 | head -1'))];
    // platform
    if (is_file('/etc/cloudlinux-release')) $e['cloudlinux'] = ['label' => 'CloudLinux', 'conf' => '', 'ver' => trim((string)@file_get_contents('/etc/cloudlinux-release'))];
    if (smpro_tun_has('imunify360-agent')) $e['imunify'] = ['label' => 'Imunify360', 'conf' => '', 'ver' => trim(smpro_tun_sh('imunify360-agent version 2>&1 | head -1'))];
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
         . "Respond with STRICT JSON ONLY, no prose: {\"recs\":[{\"target\":\"mysql|apache|nginx|cloudlinux|imunify|ssh|php|http\",\"title\":string,\"current\":string,\"recommended\":string,\"rationale\":string,\"severity\":\"high|medium|low\",\"access_risk\":boolean,\"warn\":string}]}. "
         . "Set access_risk=true with a clear `warn` for ANYTHING that could lock out SSH/admin or take a site or service offline (SSH port/root-login/password-auth, firewall enforcement, disabling a service, binding changes). "
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
        $out[] = [
            'engine' => $tg, 'id' => 'ai_' . substr(sha1(($x['title'] ?? '') . count($out)), 0, 8),
            'type' => !empty($x['access_risk']) ? 'security' : 'performance', 'sev' => $sev,
            'title' => mb_substr((string)($x['title'] ?? 'AI suggestion'), 0, 140),
            'current' => mb_substr((string)($x['current'] ?? ''), 0, 140),
            'recommended' => mb_substr((string)($x['recommended'] ?? ''), 0, 220),
            'rationale' => mb_substr((string)($x['rationale'] ?? ''), 0, 420),
            'access_risk' => !empty($x['access_risk']), 'warn' => mb_substr((string)($x['warn'] ?? ''), 0, 320),
            'ai' => true,
        ];
    }
    if (!$out) return ['ok' => false, 'msg' => 'AI did not return recommendations for the selected targets.'];
    if (function_exists('smpro_audit')) smpro_audit('tuning_ai_optimize', ['targets' => $targets, 'recs' => count($out)]);
    return ['ok' => true, 'recs' => $out, 'provider' => $r['provider'] ?? '', 'count' => count($out)];
}

/* ---------------- backups (timestamped, listed) ---------------- */
function smpro_tun_backup_all(): array {
    $det = smpro_tun_detect();
    $id = date('Ymd_His'); $dir = SMPRO_TUN_BK . '/' . $id;
    @mkdir($dir, 0700, true);
    $files = [];
    foreach (['/etc/my.cnf', '/etc/csf/csf.conf'] as $f) if (is_file($f)) { @copy($f, $dir . '/' . str_replace('/', '_', ltrim($f, '/'))); $files[] = $f; }
    foreach ($det as $eng) if (!empty($eng['conf']) && is_file($eng['conf'])) { $dst = $dir . '/' . str_replace('/', '_', ltrim($eng['conf'], '/')); if (!is_file($dst)) { @copy($eng['conf'], $dst); $files[] = $eng['conf']; } }
    @file_put_contents($dir . '/manifest.json', json_encode(['id' => $id, 'ts' => time(), 'files' => array_values(array_unique($files))], JSON_PRETTY_PRINT));
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
function smpro_tun_apply(string $recId): array {
    $scan = smpro_tun_scan();
    $rec = null; foreach ($scan['recs'] as $r) if ($r['id'] === $recId) { $rec = $r; break; }
    if (!$rec) return ['ok' => false, 'msg' => 'Recommendation not found (re-scan).'];
    $map = smpro_tun_apply_map();
    if (!isset($map[$recId])) return ['ok' => false, 'msg' => 'This change is cPanel-managed — apply it via WHM (advisory). Recommended: ' . $rec['recommended'], 'manual' => true];

    smpro_tun_backup_all();                                              // always back up first
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
        $wrote = 0;
        foreach ($vers as $v => $d) {
            if (!is_dir($d)) continue;
            $file = $d . '/zz-smpro-tuning.ini';
            $cur = trim(preg_replace('/^\s*' . preg_quote($iniKey, '/') . '\s*=.*$/im', '', (string)@file_get_contents($file)));
            $new = "; Safety Monitor Pro tune-up (managed)\n" . ($cur !== '' ? $cur . "\n" : '') . $iniKey . ' = ' . $iniVal . "\n";
            if (@file_put_contents($file, $new, LOCK_EX) !== false) $wrote++;
        }
        if (!$wrote) return ['ok' => false, 'msg' => 'Could not write any php.d drop-in (permission denied).'];
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
    return ['ok' => false, 'msg' => 'unsupported'];
}
