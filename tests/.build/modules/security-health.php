<?php
/**
 * modules/security-health.php — interactive security posture scan + safe apply.
 * Each check shows Risk / Recommended action / Validation / Evidence.
 * Fixable checks expose an "Apply Fix" (POST+CSRF+root): config is backed up,
 * SSH changes are validated with `sshd -t` BEFORE reload (no lock-out) and
 * auto-reverted on failure. Service-restart fixes warn about downtime.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

define('SMPRO_SH_BACKUP', SMPRO_VARLIB . '/backups/security');

function smpro_sh_run($cmd, $t = null) { return (string)@shell_exec('timeout ' . ($t ?: SMPRO_TIMEOUT_QUICK) . ' ' . $cmd . ' 2>&1'); }
function smpro_sh_proc($name) { return trim((string)@shell_exec('pgrep -x ' . escapeshellarg($name) . ' 2>/dev/null | head -1')) !== ''; }
function smpro_sh_pf($pat) { return trim((string)@shell_exec('pgrep -f ' . escapeshellarg($pat) . ' 2>/dev/null | head -1')) !== ''; }
function smpro_sh_listen($port) { return (bool)preg_match('/(\S+):' . $port . '\s/m', (string)@shell_exec('ss -tlnH 2>/dev/null')); }
/** True only if the port listens on a NON-localhost interface (public exposure). */
function smpro_sh_listen_public($port) {
    foreach (explode("\n", (string)@shell_exec('ss -tlnH 2>/dev/null')) as $l) {
        if (preg_match('/(\S+):' . $port . '\s/', $l, $m)) {
            $a = trim($m[1], '[]');
            if ($a === '127.0.0.1' || $a === '::1' || $a === '::ffff:127.0.0.1') continue;
            return true;
        }
    }
    return false;
}
function smpro_sh_cfg($file, $key) {
    if (!is_readable($file)) return null; $v = null;
    foreach (file($file, FILE_IGNORE_NEW_LINES) ?: [] as $l) { $l = trim($l);
        if ($l === '' || $l[0] === '#') continue;
        if (preg_match('/^' . preg_quote($key, '/') . '\s+(.+)$/i', $l, $m)) $v = trim($m[1]); }
    return $v;
}
function smpro_sh_backup($file) {
    @is_dir(SMPRO_SH_BACKUP) || @mkdir(SMPRO_SH_BACKUP, 0700, true);
    $b = SMPRO_SH_BACKUP . '/' . basename($file) . '.' . date('Ymd_His') . '.bak';
    @copy($file, $b); return $b;
}

/* ---- safe apply registry (only safe/known fixes are executable) ---- */
function smpro_sh_fixspec() {
    return [
        'ssh_rootlogin' => ['type'=>'sshd','key'=>'PermitRootLogin','val'=>'prohibit-password','risk'=>'Safe: validated with sshd -t and reloaded (existing sessions stay). Ensure you have a sudo user or SSH key.'],
        'ssh_passauth'  => ['type'=>'sshd','key'=>'PasswordAuthentication','val'=>'no','danger'=>true,'risk'=>'DANGER: only apply AFTER confirming SSH key login works, otherwise you may be locked out. Validated with sshd -t.'],
        'ssh_emptypw'   => ['type'=>'sshd','key'=>'PermitEmptyPasswords','val'=>'no','risk'=>'Safe.'],
        'ssh_maxauth'   => ['type'=>'sshd','key'=>'MaxAuthTries','val'=>'3','risk'=>'Safe.'],
        'mysql_bind'        => ['type'=>'mycnf','key'=>'bind-address','val'=>'127.0.0.1','danger'=>true,'risk'=>'MySQL/MariaDB will RESTART — sites have a brief (seconds) outage. Config is backed up and auto-reverted if the DB fails to start.'],
        'mysql_localinfile' => ['type'=>'mycnf','key'=>'local_infile','val'=>'0','danger'=>true,'risk'=>'MySQL/MariaDB will RESTART (brief outage). Backed up + auto-reverted on failure.'],
        'mysql_securefile'  => ['type'=>'mycnf','key'=>'secure_file_priv','val'=>'/var/lib/mysql-files','danger'=>true,'risk'=>'Creates /var/lib/mysql-files and RESTARTS MySQL/MariaDB (brief outage). Backed up + auto-reverted on failure.'],
    ];
}
/** Edit my.cnf [mysqld] safely + restart; revert if the DB does not come back. */
function smpro_sh_apply_mycnf($key, $val) {
    $f = is_file('/etc/my.cnf') ? '/etc/my.cnf' : (is_file('/etc/mysql/my.cnf') ? '/etc/mysql/my.cnf' : '');
    if ($f === '' || !is_writable($f)) return [false, 'my.cnf not writable'];
    if ($key === 'secure_file_priv') { @mkdir($val, 0750, true); @chown($val, 'mysql'); @chgrp($val, 'mysql'); }
    $bak = smpro_sh_backup($f);
    $lines = file($f, FILE_IGNORE_NEW_LINES) ?: [];
    $clean = [];
    foreach ($lines as $l) { if (preg_match('/^\s*' . preg_quote($key, '/') . '\s*=/i', $l)) continue; $clean[] = $l; }
    $out = []; $ins = false;
    foreach ($clean as $l) { $out[] = $l; if (!$ins && preg_match('/^\s*\[mysqld\]\s*$/i', $l)) { $out[] = "$key=$val"; $ins = true; } }
    if (!$ins) { $out[] = '[mysqld]'; $out[] = "$key=$val"; }
    @file_put_contents($f, implode("\n", $out) . "\n");
    $svc = (is_file('/usr/lib/systemd/system/mariadb.service') || smpro_sh_proc('mariadbd')) ? 'mariadb' : 'mysqld';
    smpro_sh_run('systemctl restart ' . $svc, 60);
    sleep(2);
    $up = trim(smpro_sh_run('systemctl is-active ' . $svc)) === 'active' || smpro_sh_proc('mysqld') || smpro_sh_proc('mariadbd');
    if (!$up) { @copy($bak, $f); smpro_sh_run('systemctl restart ' . $svc, 60); return [false, 'Database did not come up — config REVERTED and DB restarted. Backup: ' . $bak]; }
    return [true, "$key set to $val; $svc restarted and is up. Backup: $bak"];
}
/** Apply an sshd_config directive safely (validate before reload, revert on error). */
function smpro_sh_apply_sshd($key, $val) {
    $f = '/etc/ssh/sshd_config';
    if (!is_writable($f)) return [false, 'sshd_config is not writable'];
    $bak = smpro_sh_backup($f);
    $lines = file($f, FILE_IGNORE_NEW_LINES) ?: [];
    $out = []; $set = false;
    foreach ($lines as $l) {
        if (preg_match('/^\s*' . preg_quote($key, '/') . '\s+/i', $l)) { if (!$set) { $out[] = "$key $val"; $set = true; } }
        else $out[] = $l;
    }
    if (!$set) $out[] = "$key $val";
    @file_put_contents($f, implode("\n", $out) . "\n");
    $test = trim(smpro_sh_run('sshd -t'));
    if ($test !== '') { @copy($bak, $f); return [false, 'Invalid config — reverted. (' . $test . ')']; }
    smpro_sh_run('systemctl reload sshd', 20);
    return [true, "$key set to $val; sshd reloaded. Backup: $bak"];
}

/* ---- POST: apply a fix (CSRF + root) ---- */
$reqMethod = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));
if ($reqMethod === 'POST' && ($_POST['sh_apply'] ?? '') !== '') {
    smpro_require_valid_csrf('sh_apply');
    smpro_require_root();
    $id = preg_replace('/[^a-z_]/', '', (string)$_POST['sh_apply']);
    $spec = smpro_sh_fixspec()[$id] ?? null;
    if (!$spec) { echo json_encode(['ok' => false, 'msg' => 'unknown fix']); exit; }
    if ($spec['type'] === 'sshd') [$ok, $msg] = smpro_sh_apply_sshd($spec['key'], $spec['val']);
    elseif ($spec['type'] === 'mycnf') [$ok, $msg] = smpro_sh_apply_mycnf($spec['key'], $spec['val']);
    else { $ok = false; $msg = 'unsupported'; }
    smpro_audit('security_health_apply', ['fix' => $id, 'ok' => $ok, 'actor' => smpro_current_actor()]);
    echo json_encode(['ok' => $ok, 'msg' => $msg], JSON_UNESCAPED_SLASHES);
    exit;
}

/* check: title,status,finding,risk,rec,evidence,fix(id|''),manual(cmd) */
function smpro_sh_mk($title, $status, $finding, $risk, $rec, $evidence = '', $fix = '', $manual = '') { return ['title' => $title, 'status' => $status, 'finding' => $finding, 'risk' => $risk, 'rec' => $rec, 'evidence' => $evidence, 'fix' => $fix, 'manual' => $manual]; }

function smpro_sh_all() {
    $C = [];
    /* ---- MySQL / MariaDB ---- */
    $db = smpro_sh_proc('mysqld') || smpro_sh_proc('mariadbd');
    $ver = trim(smpro_sh_run('mysql --version'));
    $myconf = is_readable('/etc/my.cnf') ? '/etc/my.cnf' : (is_readable('/etc/mysql/my.cnf') ? '/etc/mysql/my.cnf' : '/etc/my.cnf');
    $conf = is_readable($myconf) ? (string)@file_get_contents($myconf) : '';
    $bind = preg_match('/^\s*bind-address\s*=\s*(\S+)/mi', $conf, $bm) ? $bm[1] : '';
    $port3306 = smpro_sh_listen_public(3306);   // only warns on PUBLIC exposure, not localhost
    $localInfile = preg_match('/^\s*local[_-]infile\s*=\s*(\S+)/mi', $conf, $lm) ? strtolower($lm[1]) : 'not set';
    $secFile = preg_match('/^\s*secure[_-]file[_-]priv\s*=\s*(\S+)/mi', $conf, $sm) ? $sm[1] : 'not set';
    $C['MySQL / MariaDB'] = [
        smpro_sh_mk('Database process', $db ? 'ok' : 'critical', $db ? 'A MySQL/MariaDB process is running.' : 'No database process detected.', 'The database must run for any site that uses MySQL; if down, those sites break.', $db ? 'No action needed.' : 'Start it: systemctl start mariadb — then check /var/log/mariadb/.', $ver),
        smpro_sh_mk('Database version', 'info', $ver !== '' ? $ver : 'Version unavailable.', 'Old database versions can carry unpatched security bugs.', 'Keep MariaDB/MySQL updated via cPanel/EasyApache.', $ver),
        smpro_sh_mk('Database listening port', $port3306 ? 'warning' : 'ok', $port3306 ? 'Port 3306 is listening on a public/non-local interface.' : 'Port 3306 is local-only or not listening (good).', 'If 3306 is internet-reachable, attackers can brute-force DB logins directly.', $port3306 ? 'Bind MySQL to localhost.' : 'No action needed.', smpro_sh_run('ss -tlnH 2>/dev/null | grep ":3306" | head -2'), $port3306 ? 'mysql_bind' : '', 'Add  bind-address=127.0.0.1  under [mysqld] in ' . $myconf . ' , then  systemctl restart mariadb  (brief downtime).'),
        smpro_sh_mk('Bind address', 'info', $bind !== '' ? 'bind-address = ' . $bind : 'No explicit bind-address.', 'bind-address decides which interfaces MySQL listens on; 127.0.0.1 = local-only (safest).', $bind === '127.0.0.1' ? 'Already local-only — good.' : 'Set bind-address=127.0.0.1 unless remote DB access is required.', '', $bind === '127.0.0.1' ? '' : 'mysql_bind', $bind === '127.0.0.1' ? '' : 'bind-address=127.0.0.1 under [mysqld], then systemctl restart mariadb.'),
        smpro_sh_mk('local_infile', ($localInfile === 'on' || $localInfile === '1') ? 'warning' : 'info', 'local_infile = ' . $localInfile, 'LOAD DATA LOCAL INFILE can let a compromised client read server files.', ($localInfile === 'on' || $localInfile === '1') ? 'Disable local_infile.' : 'Default/disabled is fine.', '', ($localInfile === 'on' || $localInfile === '1') ? 'mysql_localinfile' : '', 'local_infile=0 under [mysqld], then systemctl restart mariadb.'),
        smpro_sh_mk('secure_file_priv', $secFile === 'not set' ? 'warning' : 'ok', 'secure_file_priv = ' . $secFile, 'Limits which directory INTO OUTFILE / LOAD_FILE can use; unset = no restriction.', $secFile === 'not set' ? 'Restrict it to a dedicated dir.' : 'Already restricted — good.', '', $secFile === 'not set' ? 'mysql_securefile' : '', $secFile === 'not set' ? 'mkdir /var/lib/mysql-files; chown mysql:mysql /var/lib/mysql-files; add secure_file_priv=/var/lib/mysql-files under [mysqld]; systemctl restart mariadb.' : ''),
    ];
    /* ---- Apache / Nginx ---- */
    $apache = smpro_sh_proc('httpd') || smpro_sh_proc('apache2');
    $nginx = smpro_sh_proc('nginx');
    $httpdVer = trim(smpro_sh_run('httpd -v 2>/dev/null | head -1'));
    $tokens = trim(smpro_sh_run("grep -rhiE '^\\s*ServerTokens' /etc/apache2 /usr/local/apache/conf /etc/httpd 2>/dev/null | tail -1"));
    $sig = trim(smpro_sh_run("grep -rhiE '^\\s*ServerSignature' /etc/apache2 /usr/local/apache/conf /etc/httpd 2>/dev/null | tail -1"));
    $modsec = trim(smpro_sh_run("grep -rliE 'modsec' /etc/apache2 /usr/local/apache/conf /etc/httpd 2>/dev/null | head -1")) !== '';
    $C['Apache / Nginx'] = [
        smpro_sh_mk('Apache process', $apache ? 'ok' : 'info', $apache ? 'Apache/httpd is running.' : 'Apache/httpd not detected.', 'The web server delivers your sites.', $apache ? 'No action needed.' : 'Confirm your intended web server.', $httpdVer),
        smpro_sh_mk('Nginx process', $nginx ? 'ok' : 'info', $nginx ? 'Nginx is running.' : 'Nginx not detected (normal with Apache).', 'Nginx is often a reverse proxy.', 'No action needed.'),
        smpro_sh_mk('Web server version', 'info', $httpdVer !== '' ? $httpdVer : 'Version not returned.', 'Outdated builds may have known exploits.', 'Apply EasyApache/cPanel updates.', $httpdVer),
        smpro_sh_mk('HTTP/HTTPS listeners', (smpro_sh_listen(80) || smpro_sh_listen(443)) ? 'ok' : 'warning', (smpro_sh_listen(80) ? 'HTTP(80) ' : '') . (smpro_sh_listen(443) ? 'HTTPS(443)' : '') . ' listening.', 'Sites are unreachable if not listening on 80/443.', 'No action needed.'),
        smpro_sh_mk('ServerTokens', 'info', $tokens !== '' ? $tokens : 'Not explicitly set.', 'Controls how much version info Apache leaks in HTTP headers (fingerprinting).', 'Prefer ServerTokens Prod.', $tokens, '', 'Set ServerTokens Prod via WHM > Apache Configuration > Include Editor (Pre Main), then rebuild & graceful restart.'),
        smpro_sh_mk('ServerSignature', 'info', $sig !== '' ? $sig : 'Not explicitly set.', 'Adds a version footer on error pages (info leak).', 'Prefer ServerSignature Off.', $sig, '', 'Set ServerSignature Off in the same Include Editor.'),
        smpro_sh_mk('ModSecurity (WAF)', $modsec ? 'ok' : 'info', $modsec ? 'ModSecurity references found.' : 'No ModSecurity references.', 'A Web Application Firewall blocks many common attacks.', $modsec ? 'Confirm an active rule set (OWASP CRS / Comodo).' : 'Enable ModSecurity in WHM and turn on a rule set.'),
    ];
    /* ---- SSH (fixable) ---- */
    $sshd = smpro_sh_proc('sshd');
    $rootLogin = smpro_sh_cfg('/etc/ssh/sshd_config', 'PermitRootLogin') ?? 'not set';
    $passAuth = smpro_sh_cfg('/etc/ssh/sshd_config', 'PasswordAuthentication') ?? 'not set';
    $emptyPw = smpro_sh_cfg('/etc/ssh/sshd_config', 'PermitEmptyPasswords') ?? 'not set';
    $maxAuth = smpro_sh_cfg('/etc/ssh/sshd_config', 'MaxAuthTries') ?? 'not set';
    $sshPort = smpro_sh_cfg('/etc/ssh/sshd_config', 'Port') ?? '22';
    $C['SSH'] = [
        smpro_sh_mk('SSH daemon process', $sshd ? 'ok' : 'critical', $sshd ? 'sshd is running.' : 'sshd not detected.', 'SSH is your remote admin channel; losing it can mean losing access.', $sshd ? 'No action needed.' : 'Check console: systemctl status sshd.'),
        smpro_sh_mk('Root login policy', strtolower($rootLogin) === 'yes' ? 'warning' : 'ok', 'PermitRootLogin = ' . $rootLogin, 'Direct root SSH means attackers only need the root password to own the server.', strtolower($rootLogin) === 'yes' ? 'Set PermitRootLogin to prohibit-password (key-only).' : 'Already restricted — good.', 'grep -i PermitRootLogin /etc/ssh/sshd_config', strtolower($rootLogin) === 'yes' ? 'ssh_rootlogin' : ''),
        smpro_sh_mk('Password authentication', strtolower($passAuth) === 'yes' ? 'warning' : 'info', 'PasswordAuthentication = ' . $passAuth, 'Password auth is brute-forceable; keys are far stronger.', strtolower($passAuth) === 'yes' ? 'Disable password auth AFTER confirming key login works.' : 'Prefer keys + PasswordAuthentication no.', '', strtolower($passAuth) === 'yes' ? 'ssh_passauth' : ''),
        smpro_sh_mk('Empty passwords', strtolower($emptyPw) === 'yes' ? 'critical' : 'ok', 'PermitEmptyPasswords = ' . $emptyPw, 'Permitting empty passwords lets passwordless accounts log in — extremely dangerous.', strtolower($emptyPw) === 'yes' ? 'Disable empty passwords now.' : 'Safe — good.', '', strtolower($emptyPw) === 'yes' ? 'ssh_emptypw' : ''),
        smpro_sh_mk('MaxAuthTries', ($maxAuth === 'not set' || (int)$maxAuth > 4) ? 'info' : 'ok', 'MaxAuthTries = ' . $maxAuth, 'Lower values reduce guesses per connection.', 'Set MaxAuthTries 3.', '', 'ssh_maxauth'),
        smpro_sh_mk('SSH listening port', 'info', 'SSH port: ' . $sshPort . ($sshPort !== '22' ? ' (non-default)' : ' (default)'), 'A non-default port cuts automated scanning noise.', $sshPort === '22' ? 'Optionally move SSH to a high port (open it in CSF first).' : 'Non-default — good.'),
    ];
    /* ---- cPanel / WHM ---- */
    $cpsrvd = smpro_sh_pf('cpsrvd'); $cpVer = trim((string)@file_get_contents('/usr/local/cpanel/version')); $cphulk = smpro_sh_pf('cphulkd');
    $C['cPanel / WHM'] = [
        smpro_sh_mk('cpsrvd process', $cpsrvd ? 'ok' : 'warning', $cpsrvd ? 'cpsrvd is running.' : 'cpsrvd not detected.', 'Serves WHM/cPanel/webmail; if down the panel is unreachable.', $cpsrvd ? 'No action needed.' : 'Run /scripts/restartsrv_cpsrvd manually.'),
        smpro_sh_mk('cPanel version', 'info', $cpVer !== '' ? 'cPanel ' . $cpVer : 'Version not detected.', 'Current builds get security patches.', 'Keep cPanel on a maintained tier.', $cpVer),
        smpro_sh_mk('cPHulk brute-force protection', $cphulk ? 'ok' : 'warning', $cphulk ? 'cPHulk (cphulkd) is running.' : 'cPHulk not detected.', 'cPHulk blocks brute-force against cPanel/WHM/SSH logins.', $cphulk ? 'Confirm it is enabled in WHM.' : 'Enable cPHulk in WHM > cPHulk Brute Force Protection.'),
        smpro_sh_mk('WHM ports exposure', smpro_sh_listen(2087) ? 'info' : 'info', 'WHM(2087)/cPanel(2083) listeners.', 'Panel ports should be firewalled to trusted IPs where feasible.', 'Restrict 2087/2083 in CSF to admin IPs if possible.'),
    ];
    /* ---- Email ---- */
    $exim = smpro_sh_pf('exim'); $dovecot = smpro_sh_proc('dovecot');
    $C['Email Services'] = [
        smpro_sh_mk('Exim process', $exim ? 'ok' : 'info', $exim ? 'Exim is running.' : 'Exim not detected.', 'Exim sends/receives mail.', $exim ? 'No action needed.' : 'Verify Exim if this server handles mail.'),
        smpro_sh_mk('Dovecot process', $dovecot ? 'ok' : 'info', $dovecot ? 'Dovecot is running.' : 'Dovecot not detected.', 'Serves IMAP/POP3 mailboxes.', 'No action needed if mail works.'),
        smpro_sh_mk('Mail TLS ports', 'info', 'Listeners: ' . (smpro_sh_listen(587) ? '587 ' : '') . (smpro_sh_listen(993) ? '993' : ''), 'Submission(587)/IMAPS(993) must use TLS.', 'Ensure TLS enforced on 587/993.'),
        smpro_sh_mk('SPF / DKIM / DMARC', 'info', 'Verify email authentication DNS records.', 'These stop domain spoofing and improve deliverability.', 'Enable DKIM+SPF in WHM > Email Authentication; add a DMARC record.'),
    ];
    /* ---- FTP ---- */
    $ftp = smpro_sh_proc('pure-ftpd') || smpro_sh_proc('proftpd'); $ftp21 = smpro_sh_listen(21);
    $C['FTP'] = [
        smpro_sh_mk('FTP daemon', 'info', $ftp ? 'An FTP daemon is running.' : 'No FTP daemon.', 'Plain FTP sends credentials unencrypted; many servers do not need FTP.', $ftp ? 'Prefer SFTP (over SSH).' : 'Good — no FTP.'),
        smpro_sh_mk('FTP port 21', $ftp21 ? 'warning' : 'ok', $ftp21 ? 'FTP port 21 is listening.' : 'FTP port 21 not listening.', 'Plain FTP exposes passwords and is heavily brute-forced.', $ftp21 ? 'Use SFTP/FTPS; if FTP stays, require TLS.' : 'Good — not exposed.', '', '', $ftp21 ? 'WHM > FTP Server Configuration: set "TLS Encryption Required", disable anonymous FTP.' : ''),
    ];
    /* ---- Firewall / Protection ---- */
    $csf = smpro_csf_bin() !== ''; $lfd = trim(smpro_sh_run('systemctl is-active lfd')) === 'active';
    $C['Firewall / Protection'] = [
        smpro_sh_mk('CSF installed', $csf ? 'ok' : 'critical', $csf ? 'CSF is installed.' : 'CSF not detected.', 'CSF manages the firewall and blocks attackers.', $csf ? 'No action needed.' : 'Install CSF/LFD.'),
        smpro_sh_mk('LFD service', $lfd ? 'ok' : 'warning', $lfd ? 'LFD is active.' : 'LFD not active.', 'LFD auto-blocks brute-force/login failures.', $lfd ? 'No action needed.' : 'systemctl start lfd && systemctl enable lfd.'),
        smpro_sh_mk('CSF TESTING mode', (smpro_sh_cfg('/etc/csf/csf.conf', 'TESTING') === null) ? 'info' : ((trim((string)@shell_exec("grep -E '^TESTING' /etc/csf/csf.conf 2>/dev/null")) === 'TESTING = "1"') ? 'warning' : 'ok'), trim((string)@shell_exec("grep -E '^TESTING' /etc/csf/csf.conf 2>/dev/null")) ?: 'TESTING unknown', 'TESTING=1 means CSF rules are NOT enforced.', 'Set TESTING=0 in /etc/csf/csf.conf and run csf -r once verified.'),
    ];
    /* ---- System / PHP Hardening (added checks) ---- */
    $imun = is_executable('/usr/bin/imunify360-agent'); $imunRun = $imun && smpro_sh_pf('imunify360');
    $tmpNoexec = (bool)preg_match('#\s/tmp\s.*noexec#', (string)@shell_exec('mount 2>/dev/null'));
    $disableFns = trim(smpro_sh_run("php -i 2>/dev/null | grep -iE '^disable_functions' | head -1"));
    $expose = trim(smpro_sh_run("php -i 2>/dev/null | grep -iE '^expose_php' | head -1"));
    $C['System / PHP Hardening'] = [
        smpro_sh_mk('Imunify360 / malware protection', $imun ? ($imunRun ? 'ok' : 'warning') : 'info', $imun ? ($imunRun ? 'Imunify360 agent installed and running.' : 'Imunify360 installed but agent not detected running.') : 'Imunify360 not detected.', 'Imunify360 adds malware scanning, WAF and proactive defense.', $imun ? ($imunRun ? 'Confirm scans are scheduled.' : 'Check imunify360 service status.') : 'Consider Imunify360 / ImunifyAV for malware protection.'),
        smpro_sh_mk('/tmp noexec mount', $tmpNoexec ? 'ok' : 'warning', $tmpNoexec ? '/tmp is mounted noexec.' : '/tmp is NOT noexec.', 'A noexec /tmp stops attackers running uploaded scripts from /tmp.', $tmpNoexec ? 'Good.' : 'Use cPanel’s securetmp (/scripts/securetmp) to mount /tmp noexec.', (string)@shell_exec('mount 2>/dev/null | grep " /tmp "')),
        smpro_sh_mk('PHP disable_functions', ($disableFns === '' || stripos($disableFns, 'exec') === false) ? 'warning' : 'ok', $disableFns !== '' ? $disableFns : 'disable_functions not set.', 'Dangerous PHP functions (exec, system, passthru, shell_exec) enable command execution if a site is compromised.', 'Disable risky functions in WHM > MultiPHP INI Editor (disable_functions).', $disableFns),
        smpro_sh_mk('PHP information exposure', stripos($expose, 'on') !== false ? 'warning' : 'info', $expose !== '' ? $expose : 'expose_php unknown.', 'expose_php=On leaks your PHP version via X-Powered-By.', 'Set expose_php=Off in MultiPHP INI Editor.', $expose),
    ];
    return $C;
}

$cats = smpro_sh_all();
$total = 0; $okN = 0; $infoN = 0; $warnN = 0; $critN = 0;
foreach ($cats as $checks) foreach ($checks as $c) { $total++;
    if ($c['status']==='ok') $okN++; elseif ($c['status']==='info') $infoN++; elseif ($c['status']==='warning') $warnN++; elseif ($c['status']==='critical') $critN++; }
$score = max(0, 100 - $warnN * 3 - $critN * 12);
$risk = $critN > 0 ? ['Critical', 'danger'] : ($warnN >= 5 ? ['Warning', 'warn'] : ($warnN > 0 ? ['Review', 'warn'] : ['Good', 'good']));

smpro_audit('security_health_view', ['score' => $score, 'warnings' => $warnN, 'critical' => $critN]);
smpro_layout_header('Security Health');
$fixspec = smpro_sh_fixspec();
function smpro_sh_badge($s) { $m = ['ok'=>['good','OK'],'info'=>['blue','INFO'],'warning'=>['warn','WARNING'],'critical'=>['danger','CRITICAL']]; [$c,$t]=$m[$s]??['gray',strtoupper($s)]; return '<span class="shb '.$c.'">'.$t.'</span>'; }
?>
<h1 class="h">Security Health</h1>
<p class="sub">Interactive security posture scan. Click any check for the risk, recommended action, validation steps and evidence. Fixable items can be applied safely.</p>

<div class="card sh-note">&#9889; <b>Interactive fixes:</b> applying a fix backs up the config first, and SSH changes are validated with <code>sshd -t</code> before reload (no lock-out, existing sessions kept). Service-restart fixes are shown as manual commands and clearly warn about downtime.</div>

<div class="sh-score">
  <div class="card sh-sc"><div class="lbl">Security Score</div><div class="v" style="color:var(--<?= $score>=80?'good':($score>=60?'warn':'dang') ?>)"><?= (int)$score ?>/100</div></div>
  <div class="card sh-sc"><div class="lbl">Overall Risk</div><div class="v"><span class="pill <?= $risk[1] ?>"><?= $risk[0] ?></span></div></div>
  <div class="card sh-sc"><div class="lbl">Critical</div><div class="v" style="color:<?= $critN?'var(--dang)':'var(--good)' ?>"><?= (int)$critN ?></div></div>
  <div class="card sh-sc"><div class="lbl">Warnings</div><div class="v" style="color:<?= $warnN?'var(--warn)':'var(--good)' ?>"><?= (int)$warnN ?></div></div>
  <div class="card sh-sc"><div class="lbl">OK / Info</div><div class="v"><?= (int)$okN ?> / <?= (int)$infoN ?></div></div>
  <div class="card sh-sc"><div class="lbl">Total Checks</div><div class="v"><?= (int)$total ?></div></div>
</div>
<script>var SH_CSRF=<?= json_encode(smpro_csrf_generate('sh_apply')) ?>;</script>

<div class="sh-cats">
  <?php foreach ($cats as $cat => $checks): ?>
  <div class="card sh-cat">
    <div class="sh-cathead"><?= smpro_h($cat) ?> <span class="meta"><?= count($checks) ?></span></div>
    <?php foreach ($checks as $i => $c): $tid = 'sh-' . md5($cat . $i); $applyable = $c['fix'] !== '' && isset($fixspec[$c['fix']]); ?>
      <div class="sh-check <?= $c['status'] ?>">
        <div class="sh-row" data-t="<?= $tid ?>">
          <?= smpro_sh_badge($c['status']) ?>
          <div class="sh-title"><?= smpro_h($c['title']) ?><div class="sh-finding"><?= smpro_h($c['finding']) ?></div></div>
          <button class="sh-act" type="button" data-t="<?= $tid ?>"><?= $c['status']==='ok'?'Details':($c['status']==='info'?'Review':'Fix') ?></button>
        </div>
        <div class="sh-detail" id="<?= $tid ?>">
          <div class="sh-kv"><span>Risk</span><?= smpro_h($c['risk']) ?></div>
          <div class="sh-rec"><span>Recommended action</span><?= smpro_h($c['rec']) ?></div>
          <div class="sh-kv"><span>Validation</span>Re-run Security Health after any change to confirm the status flips to OK.</div>
          <?php if ($c['manual'] !== ''): ?><div class="sh-cmd"><span>Manual command</span><code><?= smpro_h($c['manual']) ?></code></div><?php endif; ?>
          <?php if ($c['evidence'] !== ''): ?><div class="sh-ev"><button type="button" class="sh-evbtn" data-t="<?= $tid ?>-ev">Evidence</button><pre id="<?= $tid ?>-ev" class="sh-evbox"><?= smpro_h(trim($c['evidence'])) ?></pre></div><?php endif; ?>
          <?php if ($applyable): ?>
            <div class="sh-apply">
              <button class="sh-applybtn<?= !empty($fixspec[$c['fix']]['danger'])?' danger':'' ?>" data-fix="<?= smpro_h($c['fix']) ?>" data-risk="<?= smpro_h($fixspec[$c['fix']]['risk']) ?>" data-desc="<?= smpro_h($fixspec[$c['fix']]['key'].' = '.$fixspec[$c['fix']]['val']) ?>">&#9889; Apply this fix</button>
              <span class="sh-applynote"><?= smpro_h($fixspec[$c['fix']]['risk']) ?></span>
            </div>
          <?php endif; ?>
        </div>
      </div>
    <?php endforeach; ?>
  </div>
  <?php endforeach; ?>
</div>

<style>
.sh-note{background:var(--brand-bg);color:#26408b;font-size:13px;margin-bottom:14px;border-left:4px solid var(--brand);line-height:1.6}
.sh-score{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:14px}
@media(max-width:1100px){.sh-score{grid-template-columns:repeat(3,1fr)}}@media(max-width:600px){.sh-score{grid-template-columns:repeat(2,1fr)}}
.sh-sc{padding:14px 16px}.sh-sc .lbl{font-size:11px;color:var(--muted);text-transform:uppercase;font-weight:700}.sh-sc .v{font-size:24px;font-weight:800;margin-top:6px}
.sh-cats{display:grid;grid-template-columns:1fr 1fr;gap:14px}@media(max-width:900px){.sh-cats{grid-template-columns:1fr}}
.sh-cat{padding:0;overflow:hidden}
.sh-cathead{padding:12px 16px;border-bottom:1px solid var(--line);font-weight:700;font-size:14px}.sh-cathead .meta{color:var(--muted);font-weight:400;font-size:12px}
.sh-check{border-bottom:1px solid var(--line)}.sh-check:last-child{border-bottom:0}
.sh-row{display:flex;align-items:flex-start;gap:10px;padding:11px 16px;cursor:pointer}.sh-row:hover{background:#f9fbff}
.sh-check.warning .sh-row{background:#fffdf7}.sh-check.critical .sh-row{background:#fdf4f4}
.sh-title{flex:1;font-size:13px;font-weight:600}.sh-finding{font-weight:400;color:var(--muted);font-size:12px;margin-top:2px}
.sh-act{font-size:11px;font-weight:600;border:1px solid var(--line);background:#fff;border-radius:7px;padding:4px 12px;cursor:pointer;color:var(--brand);white-space:nowrap}.sh-act:hover{background:var(--brand-bg)}
.sh-detail{display:none;padding:4px 16px 14px}.sh-detail.open{display:block}
.sh-kv,.sh-rec,.sh-cmd{font-size:12px;line-height:1.6;margin-top:9px}
.sh-kv span,.sh-rec span,.sh-cmd span{display:block;font-size:10px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);font-weight:700;margin-bottom:1px}
.sh-rec{background:#f7f9fc;border:1px solid var(--line);border-left:3px solid var(--brand);border-radius:8px;padding:9px 11px}.sh-rec span{color:var(--brand)}
.sh-cmd code{display:block;background:#0f172a;color:#e5e7eb;border-radius:8px;padding:9px 11px;font-size:12px;white-space:pre-wrap;word-break:break-word}
.sh-evbtn{font-size:11px;font-weight:600;border:1px solid var(--line);background:#fff;border-radius:7px;padding:3px 10px;cursor:pointer;color:var(--brand);margin-top:9px}
.sh-evbox{display:none;background:#0f172a;color:#e5e7eb;border-radius:8px;padding:10px;font-size:11px;white-space:pre-wrap;word-break:break-word;margin-top:6px}
.sh-evbox.open{display:block}
.sh-apply{margin-top:10px;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.sh-applybtn{font-size:12px;font-weight:700;border:0;border-radius:8px;padding:8px 14px;cursor:pointer;background:var(--good);color:#fff}.sh-applybtn:hover{filter:brightness(.95)}
.sh-applybtn.danger{background:var(--dang)}
.sh-applynote{font-size:11px;color:var(--muted)}
.shb{display:inline-block;font-size:10px;font-weight:800;padding:2px 8px;border-radius:20px;min-width:64px;text-align:center;margin-top:1px}
.shb.good{background:var(--good-bg);color:var(--good)}.shb.blue{background:var(--brand-bg);color:var(--brand)}.shb.warn{background:var(--warn-bg);color:var(--warn)}.shb.danger{background:var(--dang-bg);color:var(--dang)}
.pill{display:inline-block;font-size:12px;font-weight:700;padding:3px 12px;border-radius:20px}
.pill.good{background:var(--good-bg);color:var(--good)}.pill.warn{background:var(--warn-bg);color:var(--warn)}.pill.danger{background:var(--dang-bg);color:var(--dang)}
.meta{color:var(--muted)}
</style>
<script>
(function(){
  function toggle(tid){var d=document.getElementById(tid);if(!d)return;d.classList.toggle('open');
    var b=document.querySelector('.sh-act[data-t="'+tid+'"]');if(b){if(b.dataset.lbl===undefined)b.dataset.lbl=b.textContent;b.textContent=d.classList.contains('open')?'Hide':b.dataset.lbl;}}
  document.addEventListener('click',function(e){
    var ev=e.target.closest('.sh-evbtn');if(ev){var x=document.getElementById(ev.getAttribute('data-t'));if(x)x.classList.toggle('open');return;}
    var ap=e.target.closest('.sh-applybtn');if(ap){applyFix(ap);return;}
    var row=e.target.closest('[data-t]');if(row&&!e.target.closest('.sh-evbtn')&&!e.target.closest('.sh-applybtn'))toggle(row.getAttribute('data-t'));});
  function applyFix(btn){
    var fix=btn.getAttribute('data-fix'),risk=btn.getAttribute('data-risk'),desc=btn.getAttribute('data-desc');
    if(!confirm('Apply fix: '+desc+'\n\n'+risk+'\n\nA backup is taken first. Continue?'))return;
    btn.disabled=true;btn.textContent='Applying…';
    var fd=new URLSearchParams();fd.set('sh_apply',fix);fd.set('smpro_csrf',SH_CSRF);
    fetch('index.cgi?page=security-health',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'})
      .then(function(r){return r.json();}).then(function(j){
        btn.disabled=false;
        if(j&&j.ok){btn.textContent='✓ Applied';btn.style.background='var(--good)';alert('Applied: '+(j.msg||'')+'\n\nReloading to re-scan…');location.reload();}
        else{btn.textContent='⚠ Failed';btn.classList.add('danger');alert('Not applied: '+((j&&j.msg)||'error'));}
      }).catch(function(){btn.disabled=false;btn.textContent='⚠ Failed';alert('Failed (network/permission).');});
  }
})();
</script>
<?php
smpro_layout_footer();
