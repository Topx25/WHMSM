<?php
/**
 * modules/security-health.php - interactive security posture scan + safe apply.
 * Each check shows Risk / Recommended action / Validation / Evidence.
 * Fixable checks expose an "Apply Fix" (POST+CSRF+root): config is backed up,
 * SSH changes are validated with `sshd -t` BEFORE reload (no lock-out) and
 * auto-reverted on failure. Service-restart fixes warn about downtime.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

define('SMPRO_SH_BACKUP', SMPRO_VARLIB . '/backups/security');
require_once __DIR__ . '/../includes/shharden.php';

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
/** Read a  KEY = "value"  setting from csf.conf CONTENT. Anchored `KEY\s*=` so SYNFLOOD
 *  cannot match SYNFLOOD_RATE and RESTRICT_SYSLOG cannot match RESTRICT_SYSLOG_GROUP
 *  (verified against a real csf.conf where a loose grep matched all of those). */
function smpro_sh_csf_key($conf, $key) {
    return preg_match('/^\s*' . preg_quote($key, '/') . '\s*=\s*"([^"]*)"/m', $conf, $m) ? trim($m[1]) : null;
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
        'ssh_x11'       => ['type'=>'sshd','key'=>'X11Forwarding','val'=>'no','risk'=>'Safe: a server has no display to forward.'],
        'ssh_grace'     => ['type'=>'sshd','key'=>'LoginGraceTime','val'=>'30','risk'=>'Safe: half-open logins are dropped after 30 seconds instead of 2 minutes.'],
        'kernel_harden'  => ['type'=>'shh','key'=>'sysctl','val'=>'hardened (see Evidence)','risk'=>'Safe: takes effect at once, no restart. Undo puts back the previous values.'],
        'shm_noexec'     => ['type'=>'shh','key'=>'/dev/shm','val'=>'noexec,nosuid,nodev','risk'=>'Safe for hosting: nothing legitimate runs programs from shared memory. Undo remounts it as before.'],
        'php_urlinclude' => ['type'=>'shh','key'=>'allow_url_include','val'=>'Off','risk'=>'Safe: no current software needs it. Each php.ini is kept first; running PHP-FPM pools restart (a second).'],
        'csf_harden'     => ['type'=>'shh','key'=>'csf.conf','val'=>'hardened (see Evidence)','risk'=>'The firewall reloads (a few seconds). If LFD does not come back, the old csf.conf is put back automatically.'],
        'mail_caps'      => ['type'=>'shh','key'=>'cPanel mail caps','val'=>'500/hour per domain','risk'=>'A domain sending more than 500 messages an hour has the rest queued until the next hour. Undo removes the cap.'],
        'imunify_harden' => ['type'=>'shh','key'=>'Imunify360','val'=>'hardened (see Evidence)','risk'=>'A daily scan uses some CPU at night. Undo sets the previous values back.'],
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
/** Full path to sshd - the WHM CGI PATH usually lacks /usr/sbin, so a bare `sshd -t`
 *  returns "command not found", which the old code mistook for an invalid config. */
function smpro_sh_sshd_bin() {
    foreach (['/usr/sbin/sshd', '/usr/local/sbin/sshd', '/sbin/sshd'] as $p) if (@is_executable($p)) return $p;
    return 'sshd';
}
/** Effective sshd setting via `sshd -T` - resolves Include drop-ins (first match wins),
 *  which a plain grep of /etc/ssh/sshd_config cannot see. Returns null if unavailable. */
function smpro_sh_sshd_effective($key) {
    static $map = null;
    if ($map === null) {
        $map = [];
        $out = (string)@shell_exec('timeout 10 ' . smpro_sh_sshd_bin() . ' -T 2>/dev/null');
        foreach (explode("\n", $out) as $l) {
            $l = trim($l); if ($l === '') continue;
            $sp = strpos($l, ' '); if ($sp === false) continue;
            $k = strtolower(substr($l, 0, $sp));
            if (!isset($map[$k])) $map[$k] = substr($l, $sp + 1);   // first wins (matches sshd semantics; port lists primary first)
        }
    }
    return $map[strtolower($key)] ?? null;
}
/** Apply an sshd_config directive safely (validate before reload, revert on error).
 *  Modern OSes `Include /etc/ssh/sshd_config.d/*.conf` at the TOP of sshd_config and
 *  sshd uses FIRST-match-wins - a vendor/cloud-init drop-in silently overrides anything
 *  written to the main file. When the Include is active we write our own 00- drop-in
 *  (sorts first -> always wins); otherwise we edit the main file as before. */
function smpro_sh_apply_sshd($key, $val) {
    $main = '/etc/ssh/sshd_config';
    $dropDir = '/etc/ssh/sshd_config.d';
    $useDrop = is_dir($dropDir)
        && preg_match('~^\s*Include\s+/etc/ssh/sshd_config\.d/~mi', (string)@file_get_contents($main));
    if ($useDrop) {
        $f = $dropDir . '/00-smpro.conf';
        $prev = is_file($f) ? (string)@file_get_contents($f) : null;   // null = file did not exist
        $bak = $prev !== null ? smpro_sh_backup($f) : '';
        $lines = $prev !== null ? explode("\n", rtrim($prev, "\n")) : ['# Managed by Safety Monitor Pro — Security Health fixes.'];
        $out = [];
        foreach ($lines as $l) { if (preg_match('/^\s*' . preg_quote($key, '/') . '\s+/i', $l)) continue; $out[] = $l; }
        $out[] = "$key $val";
        if (@file_put_contents($f, implode("\n", $out) . "\n") === false) return [false, 'Could not write ' . $f];
        @chmod($f, 0600);
    } else {
        $f = $main;
        if (!is_writable($f)) return [false, 'sshd_config is not writable'];
        $prev = null; $bak = smpro_sh_backup($f);
        $lines = file($f, FILE_IGNORE_NEW_LINES) ?: [];
        $out = []; $set = false;
        foreach ($lines as $l) {
            if (preg_match('/^\s*' . preg_quote($key, '/') . '\s+/i', $l)) { if (!$set) { $out[] = "$key $val"; $set = true; } }
            else $out[] = $l;
        }
        if (!$set) $out[] = "$key $val";
        @file_put_contents($f, implode("\n", $out) . "\n");
    }
    // Validate with the EXIT CODE - sshd -t prints non-fatal deprecation warnings to
    // stderr, so "any output = invalid" wrongly reverted perfectly valid changes.
    $rc = 1; $msg = [];
    @exec('timeout 10 ' . smpro_sh_sshd_bin() . ' -t 2>&1', $msg, $rc);
    if ($rc !== 0) {
        if ($useDrop) { $prev === null ? @unlink($f) : @file_put_contents($f, $prev); }
        else @copy($bak, $f);
        return [false, 'Invalid config — reverted. (' . trim(implode(' ', $msg)) . ')'];
    }
    smpro_sh_run('systemctl reload sshd', 20);
    return [true, "$key set to $val" . ($useDrop ? " (drop-in $f)" : '') . '; sshd reloaded.' . ($bak !== '' ? " Backup: $bak" : '')];
}

/* ---- POST: apply a fix (CSRF + root) ---- */
$reqMethod = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));
if ($reqMethod === 'POST' && ($_POST['sh_apply'] ?? '') !== '') {
    smpro_require_valid_csrf('sh_apply');
    smpro_require_root();
    $id = preg_replace('/[^a-z_]/', '', (string)$_POST['sh_apply']);
    $spec = smpro_sh_fixspec()[$id] ?? null;
    if (!$spec) { echo json_encode(['ok' => false, 'msg' => 'unknown fix']); exit; }
    @ignore_user_abort(true); @set_time_limit(600);   // a started fix finishes even if the page is closed
    if ($spec['type'] === 'shh') [$ok, $msg] = smpro_shh_apply($id);
    elseif ($spec['type'] === 'sshd') [$ok, $msg] = smpro_sh_apply_sshd($spec['key'], $spec['val']);
    elseif ($spec['type'] === 'mycnf') [$ok, $msg] = smpro_sh_apply_mycnf($spec['key'], $spec['val']);
    else { $ok = false; $msg = 'unsupported'; }
    if ($ok && function_exists('smpro_cache_bust')) smpro_cache_bust('sh_scan');   // reload shows the fix's effect immediately
    smpro_audit('security_health_apply', ['fix' => $id, 'ok' => $ok, 'actor' => smpro_current_actor()]);
    echo json_encode(['ok' => $ok, 'msg' => $msg], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

/* ---- POST: undo one hardening fix (or every one), or apply every safe open fix at once ---- */
if ($reqMethod === 'POST' && (($_POST['sh_undo'] ?? '') !== '' || ($_POST['sh_apply_all'] ?? '') !== '')) {
    smpro_require_valid_csrf('sh_apply');
    smpro_require_root();
    @ignore_user_abort(true); @set_time_limit(900);
    if (($_POST['sh_undo'] ?? '') !== '') {
        $id = preg_replace('/[^a-z_]/', '', (string)$_POST['sh_undo']);
        [$ok, $msg] = smpro_shh_undo($id === 'all' ? '' : $id);
        smpro_audit('security_health_undo', ['fix' => $id, 'ok' => $ok, 'actor' => smpro_current_actor()]);
    } else {
        // only fixes whose check is open right now, and never the ones marked danger (lock-out / DB restart)
        $spec = smpro_sh_fixspec(); $open = [];
        foreach (smpro_sh_all() as $checks) foreach ($checks as $c) if ($c['fix'] !== '' && isset($spec[$c['fix']]) && empty($spec[$c['fix']]['danger']) && $c['fix'] !== 'ssh_rootlogin') $open[$c['fix']] = true;
        $done = []; $bad = [];
        foreach (array_keys($open) as $id) {
            $s = $spec[$id];
            [$ok1, $m1] = $s['type'] === 'shh' ? smpro_shh_apply($id) : ($s['type'] === 'sshd' ? smpro_sh_apply_sshd($s['key'], $s['val']) : [false, 'skipped']);
            if ($ok1) $done[] = $id; else $bad[] = $id . ': ' . $m1;
        }
        $ok = !$bad; $msg = $open ? count($done) . ' fix(es) applied' . ($bad ? '; not applied: ' . implode(' | ', $bad) : '') : 'Nothing to apply — every safe fix is already in place.';
        smpro_audit('security_health_apply_all', ['done' => $done, 'failed' => count($bad), 'actor' => smpro_current_actor()]);
    }
    if (function_exists('smpro_cache_bust')) smpro_cache_bust('sh_scan');
    echo json_encode(['ok' => $ok, 'msg' => $msg], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

/** A PHP ini setting as reported by every interpreter that ACTUALLY serves websites, keyed by version.
 *  A bare `php` resolves to cPanel's own bundled build (/usr/local/bin/php). That interpreter serves no
 *  customer site and is not what MultiPHP INI Editor hardens, so reading it answered the wrong question on
 *  every cPanel server - it could report a hardened box as unhardened, or an unhardened box as fine, purely
 *  by coincidence. Falls back to whatever `php` exists only when no EA-PHP is installed. Empty array = no
 *  interpreter could be read, which the caller must render as "unknown", never as a pass. */
function smpro_sh_php_ini_all(string $key): array {
    static $cache = [];
    if (isset($cache[$key])) return $cache[$key];
    $code = 'echo (string)ini_get(' . var_export($key, true) . ');';
    $out  = [];
    $bins = glob('/opt/cpanel/ea-php*/root/usr/bin/php') ?: [];
    natsort($bins);
    foreach ($bins as $b) {
        if (!@is_executable($b)) continue;
        $v = preg_match('#/(ea-php\d+)/#', $b, $m) ? $m[1] : basename(dirname($b));
        $out[$v] = trim(smpro_sh_run(escapeshellarg($b) . ' -d error_reporting=0 -r ' . escapeshellarg($code), 8));
    }
    if (!$out && trim((string)@shell_exec('command -v php 2>/dev/null')) !== '') {
        $out['php (cli)'] = trim(smpro_sh_run('php -d error_reporting=0 -r ' . escapeshellarg($code), 8));
    }
    return ($cache[$key] = $out);
}

/** Effective MySQL/MariaDB variable, asked of the RUNNING server. Authoritative where a file grep is not:
 *  /etc/my.cnf on a cPanel box is usually just `!includedir /etc/my.cnf.d`, so reading only the top-level file
 *  reports "not set" for settings that ARE set in an included file - exactly the mistake `sshd -T` exists to
 *  avoid above. Returns null when the server cannot be queried, so the caller can say "unknown" rather than
 *  render a false all-clear. */
function smpro_sh_mysql_var(string $name): ?string {
    static $cache = [];
    if (array_key_exists($name, $cache)) return $cache[$name];
    if (!preg_match('/^[a-z0-9_]+$/i', $name)) return ($cache[$name] = null);
    $df  = is_readable('/root/.my.cnf') ? '--defaults-extra-file=/root/.my.cnf ' : '';
    $out = smpro_sh_run('mysql ' . $df . '-N -B -e ' . escapeshellarg("SHOW GLOBAL VARIABLES LIKE '" . $name . "'"), 10);
    if (trim($out) === '' || stripos($out, 'ERROR') !== false) return ($cache[$name] = null);
    $p = explode("\t", trim($out, "\n"));
    return ($cache[$name] = (count($p) >= 2 ? trim($p[1]) : ''));
}

/** my.cnf content INCLUDING every file pulled in by !include / !includedir, concatenated in load order so
 *  "last definition wins" still holds. Used only as the fallback when the server cannot be queried. */
function smpro_sh_mycnf_all(string $main): string {
    $out = ''; $seen = [];
    $read = function ($f) use (&$read, &$out, &$seen) {
        $f = (string)$f;
        if ($f === '' || isset($seen[$f]) || !is_readable($f)) return;
        $seen[$f] = 1;
        foreach (explode("\n", (string)@file_get_contents($f)) as $line) {
            if (preg_match('/^\s*!includedir\s+(\S+)/i', $line, $m)) {
                $g = glob(rtrim($m[1], '/') . '/*.cnf') ?: []; sort($g);   // MySQL reads the directory in name order
                foreach ($g as $inc) $read($inc);
            } elseif (preg_match('/^\s*!include\s+(\S+)/i', $line, $m)) {
                $read($m[1]);
            } else {
                $out .= $line . "\n";
            }
        }
    };
    $read($main);
    return $out;
}

/* check: title,status,finding,risk,rec,evidence,fix(id|''),manual(cmd) */
function smpro_sh_mk($title, $status, $finding, $risk, $rec, $evidence = '', $fix = '', $manual = '') { return ['title' => $title, 'status' => $status, 'finding' => $finding, 'risk' => $risk, 'rec' => $rec, 'evidence' => $evidence, 'fix' => $fix, 'manual' => $manual]; }

function smpro_sh_all() {
    $C = [];
    /* ---- MySQL / MariaDB ---- */
    $db = smpro_sh_proc('mysqld') || smpro_sh_proc('mariadbd');
    $ver = trim(smpro_sh_run('mysql --version'));
    $myconf = is_readable('/etc/my.cnf') ? '/etc/my.cnf' : (is_readable('/etc/mysql/my.cnf') ? '/etc/mysql/my.cnf' : '/etc/my.cnf');
    // Ask the running server first; fall back to the config files (include-aware) only if it cannot be queried.
    // A third state - "could not determine" - is kept distinct from "not set" so an unreadable server can never
    // be rendered as a clean result.
    $conf = is_readable($myconf) ? smpro_sh_mycnf_all($myconf) : '';
    $vBind = smpro_sh_mysql_var('bind_address');
    $vLoc  = smpro_sh_mysql_var('local_infile');
    $vSec  = smpro_sh_mysql_var('secure_file_priv');
    $live  = ($vLoc !== null || $vSec !== null || $vBind !== null);   // did the server answer at all?
    $src   = $live ? 'running server' : ($conf !== '' ? 'config files' : 'unavailable');

    $bind = $vBind !== null ? $vBind : (preg_match('/^\s*bind[_-]address\s*=\s*(\S+)/mi', $conf, $bm) ? $bm[1] : '');
    $port3306 = smpro_sh_listen_public(3306);   // only warns on PUBLIC exposure, not localhost
    if ($vLoc !== null)      $localInfile = strtolower($vLoc) === 'on' ? 'on' : (strtolower($vLoc) === 'off' ? 'off' : strtolower($vLoc));
    elseif ($conf !== '')    $localInfile = preg_match('/^\s*local[_-]infile\s*=\s*(\S+)/mi', $conf, $lm) ? strtolower($lm[1]) : 'not set';
    else                     $localInfile = 'unknown';
    if ($vSec !== null)      $secFile = ($vSec === '' ? 'not set' : $vSec);
    elseif ($conf !== '')    $secFile = preg_match('/^\s*secure[_-]file[_-]priv\s*=\s*(\S+)/mi', $conf, $sm) ? $sm[1] : 'not set';
    else                     $secFile = 'unknown';
    $C['MySQL / MariaDB'] = [
        smpro_sh_mk('Database process', $db ? 'ok' : 'critical', $db ? 'A MySQL/MariaDB process is running.' : 'No database process detected.', 'The database must run for any site that uses MySQL; if down, those sites break.', $db ? 'No action needed.' : 'Start it: systemctl start mariadb — then check /var/log/mariadb/.', $ver),
        smpro_sh_mk('Database version', 'info', $ver !== '' ? $ver : 'Version unavailable.', 'Old database versions can carry unpatched security bugs.', 'Keep MariaDB/MySQL updated via cPanel/EasyApache.', $ver),
        smpro_sh_mk('Database listening port', $port3306 ? 'warning' : 'ok', $port3306 ? 'Port 3306 is listening on a public/non-local interface.' : 'Port 3306 is local-only or not listening (good).', 'If 3306 is internet-reachable, attackers can brute-force DB logins directly.', $port3306 ? 'Bind MySQL to localhost.' : 'No action needed.', smpro_sh_run('ss -tlnH 2>/dev/null | grep ":3306" | head -2'), $port3306 ? 'mysql_bind' : '', 'Add  bind-address=127.0.0.1  under [mysqld] in ' . $myconf . ' , then  systemctl restart mariadb  (brief downtime).'),
        smpro_sh_mk('Bind address', 'info', $bind !== '' ? 'bind-address = ' . $bind : 'No explicit bind-address.', 'bind-address decides which interfaces MySQL listens on; 127.0.0.1 = local-only (safest).', $bind === '127.0.0.1' ? 'Already local-only — good.' : 'Set bind-address=127.0.0.1 unless remote DB access is required.', '', $bind === '127.0.0.1' ? '' : 'mysql_bind', $bind === '127.0.0.1' ? '' : 'bind-address=127.0.0.1 under [mysqld], then systemctl restart mariadb.'),
        smpro_sh_mk('local_infile', ($localInfile === 'on' || $localInfile === '1') ? 'warning' : (($localInfile === 'off' || $localInfile === '0') ? 'ok' : 'info'), 'local_infile = ' . $localInfile . ' (read from the ' . $src . ')', 'LOAD DATA LOCAL INFILE can let a compromised client read server files.', ($localInfile === 'on' || $localInfile === '1') ? 'Disable local_infile.' : 'Default/disabled is fine.', '', ($localInfile === 'on' || $localInfile === '1') ? 'mysql_localinfile' : '', 'local_infile=0 under [mysqld], then systemctl restart mariadb.'),
        smpro_sh_mk('secure_file_priv', $secFile === 'unknown' ? 'info' : ($secFile === 'not set' ? 'warning' : 'ok'), 'secure_file_priv = ' . $secFile . ' (read from the ' . $src . ')', 'Limits which directory INTO OUTFILE / LOAD_FILE can use; unset = no restriction.', $secFile === 'not set' ? 'Restrict it to a dedicated dir.' : 'Already restricted — good.', '', $secFile === 'not set' ? 'mysql_securefile' : '', $secFile === 'not set' ? 'mkdir /var/lib/mysql-files; chown mysql:mysql /var/lib/mysql-files; add secure_file_priv=/var/lib/mysql-files under [mysqld]; systemctl restart mariadb.' : ''),
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
    // Effective values via `sshd -T` (resolves sshd_config.d drop-ins, first match wins);
    // fall back to grepping the main file only if -T is unavailable.
    $rootLogin = smpro_sh_sshd_effective('PermitRootLogin') ?? smpro_sh_cfg('/etc/ssh/sshd_config', 'PermitRootLogin') ?? 'not set';
    $passAuth = smpro_sh_sshd_effective('PasswordAuthentication') ?? smpro_sh_cfg('/etc/ssh/sshd_config', 'PasswordAuthentication') ?? 'not set';
    $emptyPw = smpro_sh_sshd_effective('PermitEmptyPasswords') ?? smpro_sh_cfg('/etc/ssh/sshd_config', 'PermitEmptyPasswords') ?? 'not set';
    $maxAuth = smpro_sh_sshd_effective('MaxAuthTries') ?? smpro_sh_cfg('/etc/ssh/sshd_config', 'MaxAuthTries') ?? 'not set';
    $sshPort = smpro_sh_sshd_effective('Port') ?? smpro_sh_cfg('/etc/ssh/sshd_config', 'Port') ?? '22';
    $C['SSH'] = [
        smpro_sh_mk('SSH daemon process', $sshd ? 'ok' : 'critical', $sshd ? 'sshd is running.' : 'sshd not detected.', 'SSH is your remote admin channel; losing it can mean losing access.', $sshd ? 'No action needed.' : 'Check console: systemctl status sshd.'),
        smpro_sh_mk('Root login policy', strtolower($rootLogin) === 'yes' ? 'warning' : 'ok', 'PermitRootLogin = ' . $rootLogin, 'Direct root SSH means attackers only need the root password to own the server.', strtolower($rootLogin) === 'yes' ? 'Set PermitRootLogin to prohibit-password (key-only).' : 'Already restricted — good.', 'sshd -T | grep -i permitrootlogin', strtolower($rootLogin) === 'yes' ? 'ssh_rootlogin' : ''),
        smpro_sh_mk('Password authentication', strtolower($passAuth) === 'yes' ? 'warning' : 'info', 'PasswordAuthentication = ' . $passAuth, 'Password auth is brute-forceable; keys are far stronger.', strtolower($passAuth) === 'yes' ? 'Disable password auth AFTER confirming key login works.' : 'Prefer keys + PasswordAuthentication no.', '', strtolower($passAuth) === 'yes' ? 'ssh_passauth' : ''),
        smpro_sh_mk('Empty passwords', strtolower($emptyPw) === 'yes' ? 'critical' : 'ok', 'PermitEmptyPasswords = ' . $emptyPw, 'Permitting empty passwords lets passwordless accounts log in — extremely dangerous.', strtolower($emptyPw) === 'yes' ? 'Disable empty passwords now.' : 'Safe — good.', '', strtolower($emptyPw) === 'yes' ? 'ssh_emptypw' : ''),
        smpro_sh_mk('MaxAuthTries', ($maxAuth === 'not set' || (int)$maxAuth > 4) ? 'info' : 'ok', 'MaxAuthTries = ' . $maxAuth, 'Lower values reduce guesses per connection.', 'Set MaxAuthTries 3.', '', ($maxAuth === 'not set' || (int)$maxAuth > 4) ? 'ssh_maxauth' : ''),
        smpro_sh_mk('X11 forwarding', strtolower((string)(smpro_sh_sshd_effective('X11Forwarding') ?? 'no')) === 'yes' ? 'warning' : 'ok', 'X11Forwarding = ' . (smpro_sh_sshd_effective('X11Forwarding') ?? 'not set'), 'A server has no display; X11 forwarding only adds a channel an attacker with a shell can tunnel through.', 'Set X11Forwarding no.', '', strtolower((string)(smpro_sh_sshd_effective('X11Forwarding') ?? 'no')) === 'yes' ? 'ssh_x11' : ''),
        smpro_sh_mk('Login grace time', ((int)(smpro_sh_sshd_effective('LoginGraceTime') ?? 120) === 0 || (int)(smpro_sh_sshd_effective('LoginGraceTime') ?? 120) > 60) ? 'info' : 'ok', 'LoginGraceTime = ' . (smpro_sh_sshd_effective('LoginGraceTime') ?? 'not set'), 'Each half-open login holds a slot for this long; a long grace time lets a slow brute force fill MaxStartups and lock real admins out.', 'Set LoginGraceTime 30.', '', ((int)(smpro_sh_sshd_effective('LoginGraceTime') ?? 120) === 0 || (int)(smpro_sh_sshd_effective('LoginGraceTime') ?? 120) > 60) ? 'ssh_grace' : ''),
        smpro_sh_mk('SSH listening port', 'info', 'SSH port: ' . $sshPort . ($sshPort !== '22' ? ' (non-default)' : ' (default)'), 'A non-default port cuts automated scanning noise.', $sshPort === '22' ? 'Optionally move SSH to a high port (open it in CSF first).' : 'Non-default — good.'),
    ];
    /* ---- cPanel / WHM ---- */
    $cpsrvd = smpro_sh_pf('cpsrvd'); $cpVer = trim((string)@file_get_contents('/usr/local/cpanel/version')); $cphulk = smpro_sh_pf('cphulkd');
    // cPHulk ENABLED flag via the WHM API - authoritative, unlike the process check above:
    // a real production box had is_enabled:0 (protection OFF) despite thousands of failed SSH
    // logins. Fixed-literal command (no dynamic args), bounded with `timeout`; stderr dropped
    // so stdout stays pure JSON. Shape confirmed: {"data":{"is_enabled":1,"service":"cPHulk"}}.
    // Read from cPanel's own switch file (smpro_cphulk_enabled): the API answered in 20 ms from a shell but took
    // 12 s from inside this CGI on a production server - it was most of this page's render time.
    $hulkEnabled = function_exists('smpro_cphulk_enabled') ? smpro_cphulk_enabled() : null;
    $hulkEnabled = $hulkEnabled === null ? null : ($hulkEnabled ? 1 : 0);
    $hulkOff = $hulkEnabled !== null && (int)$hulkEnabled !== 1;
    // DNS cluster peers - only meaningful when clustering is actually configured, so the check reports
    // "not configured" on the majority of servers instead of inventing a finding.
    $dnsC = function_exists('smpro_dns_cluster_health') ? smpro_dns_cluster_health() : ['configured' => false, 'peers' => [], 'worst' => 'none'];
    $dnsLbl = ''; $dnsSev = 'info'; $dnsFind = ''; $dnsRec = ''; $dnsEv = '';
    if (!$dnsC['configured']) {
        $dnsFind = 'No DNS cluster is configured on this server.';
        $dnsRec  = 'Nothing to do — this only applies to servers that sync zones to other nameservers.';
    } else {
        $down = array_values(array_filter($dnsC['peers'], fn($p) => $p['status'] === 'down'));
        $slow = array_values(array_filter($dnsC['peers'], fn($p) => $p['status'] === 'slow'));
        $ev = []; foreach ($dnsC['peers'] as $p) $ev[] = $p['host'] . '  ' . strtoupper($p['status']) . '  ' . $p['ms'] . 'ms' . ($p['why'] !== '' ? '  (' . $p['why'] . ')' : '');
        foreach (smpro_dns_cluster_log_failures() as $ln) $ev[] = 'dnsadmin: ' . $ln;
        $dnsEv = implode("\n", $ev);
        if ($down) {
            $dnsSev  = 'warning';
            $dnsFind = count($down) . ' of ' . count($dnsC['peers']) . ' DNS cluster peer(s) are not answering: ' . implode(', ', array_column($down, 'host')) . '.';
            $dnsRec  = 'cPanel writes every zone change to each peer and waits for it, so an unreachable peer makes account creation, domain adds and zone edits hang — the symptom usually looks like "WHM is slow", not like a DNS problem. Bring the peer back, or remove it in WHM > Clusters > DNS Cluster until it is fixed.';
        } elseif ($slow) {
            $dnsSev  = 'warning';
            $dnsFind = count($slow) . ' DNS cluster peer(s) are answering slowly: ' . implode(', ', array_column($slow, 'host')) . '.';
            $dnsRec  = 'Every zone write waits on the slowest peer. Investigate that server\'s load or network path before it starts timing out.';
        } else {
            $dnsSev  = 'ok';
            $dnsFind = 'All ' . count($dnsC['peers']) . ' DNS cluster peer(s) are reachable.';
            $dnsRec  = 'No action needed.';
        }
    }
    $C['cPanel / WHM'] = [
        smpro_sh_mk('DNS cluster peers', $dnsSev, $dnsFind,
            'In a DNS cluster every zone change is pushed to each peer synchronously. One silent peer does not break DNS — it stalls the operations that write zones (account creation, domain adds), which is easy to misdiagnose as a slow control panel.',
            $dnsRec, $dnsEv),
        smpro_sh_mk('cpsrvd process', $cpsrvd ? 'ok' : 'warning', $cpsrvd ? 'cpsrvd is running.' : 'cpsrvd not detected.', 'Serves WHM/cPanel/webmail; if down the panel is unreachable.', $cpsrvd ? 'No action needed.' : 'Run /scripts/restartsrv_cpsrvd manually.'),
        smpro_sh_mk('cPanel version', 'info', $cpVer !== '' ? 'cPanel ' . $cpVer : 'Version not detected.', 'Current builds get security patches.', 'Keep cPanel on a maintained tier.', $cpVer),
        smpro_sh_mk('cPHulk brute-force protection', $cphulk ? 'ok' : 'warning', $cphulk ? 'cPHulk (cphulkd) is running.' : 'cPHulk not detected.', 'cPHulk blocks brute-force against cPanel/WHM/SSH logins.', $cphulk ? 'Confirm it is enabled in WHM.' : 'Enable cPHulk in WHM > cPHulk Brute Force Protection.'),
        smpro_sh_mk('cPHulk enabled (WHM API)',
            $hulkEnabled === null ? 'info' : ($hulkOff ? 'warning' : 'ok'),
            $hulkEnabled === null ? 'cPHulk status unavailable (neither the switch file nor the API answered).' : ($hulkOff ? 'cPHulk brute-force protection is DISABLED (is_enabled:0).' : 'cPHulk brute-force protection is enabled (is_enabled:1).'),
            'With cPHulk disabled nothing throttles repeated login failures against cPanel/WHM/SSH/mail — real servers have accumulated thousands of failed SSH logins with this switch off while the cphulkd process still looked alive.',
            $hulkOff ? 'Enable it in WHM > Security Center > cPHulk Brute Force Protection (cPHulkD), then review its history to confirm failed logins are being blocked.' : ($hulkEnabled === null ? 'Check cPHulk manually: /usr/local/cpanel/bin/whmapi1 cphulk_status.' : 'No action needed — keep it enabled.'),
            $hulkEnabled === null ? '' : ('/var/cpanel/hulkd/enabled ' . ($hulkEnabled ? 'present' : 'absent') . ' (the switch file cPanel itself keeps)'),
            '',
            $hulkOff ? '/usr/local/cpanel/bin/whmapi1 enable_cphulk' : ''),
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
    // CSF hardening gaps - only emitted when CSF is actually installed (csf.conf present).
    // Seen in the field: SYNFLOOD="0", RESTRICT_SYSLOG="0" and PORTFLOOD="" while every other
    // firewall check looked fine. Read-only: a single file read, parsed with anchored keys.
    if (is_file('/etc/csf/csf.conf')) {
        if (!is_readable('/etc/csf/csf.conf')) {
            $C['Firewall / Protection'][] = smpro_sh_mk('CSF hardening (SYNFLOOD / RESTRICT_SYSLOG / PORTFLOOD)', 'info', '/etc/csf/csf.conf exists but is not readable.', 'Cannot audit SYN-flood, syslog-restriction or port-flood settings without reading csf.conf.', 'Check permissions on /etc/csf/csf.conf and re-run this scan.');
        } else {
            $csfC = (string)@file_get_contents('/etc/csf/csf.conf');
            $synflood  = smpro_sh_csf_key($csfC, 'SYNFLOOD');
            $rsyslog   = smpro_sh_csf_key($csfC, 'RESTRICT_SYSLOG');
            $portflood = smpro_sh_csf_key($csfC, 'PORTFLOOD');
            $csfGaps = [];
            // NB: SYNFLOOD is deliberately NOT flagged as a gap. It ships "0" by default and ConfigServer
            // advises enabling it ONLY while actively under a SYN flood (real per-connection performance cost;
            // can drop legitimate traffic). Flagging SYNFLOOD="0" would fire on nearly every default CSF
            // install and contradict vendor guidance. RESTRICT_SYSLOG / PORTFLOOD below DO follow CSF guidance.
            if ($rsyslog !== '3') $csfGaps[] = 'RESTRICT_SYSLOG = "3" (currently ' . ($rsyslog === null ? 'unset' : '"' . $rsyslog . '"') . ' — unrestricted syslog lets local users spoof log lines and mislead LFD)';
            if ($portflood === null || $portflood === '') $csfGaps[] = 'PORTFLOOD = "22;tcp;5;300" (per-port connection-flood limits are unset)';
            $synNote = ($synflood !== '1') ? ' (SYNFLOOD is off — that is CSF\'s default; enable it only while under an active SYN flood.)' : '';
            preg_match_all('/^\s*(SYNFLOOD|RESTRICT_SYSLOG|PORTFLOOD)\s*=.*$/m', $csfC, $csfEv);
            $C['Firewall / Protection'][] = smpro_sh_mk('CSF hardening (RESTRICT_SYSLOG / PORTFLOOD)',
                $csfGaps ? 'warning' : 'ok',
                ($csfGaps ? 'CSF hardening gaps: ' . count($csfGaps) . ' setting(s) weaken protection.' : 'RESTRICT_SYSLOG and PORTFLOOD are hardened.') . $synNote,
                'RESTRICT_SYSLOG not set to 3 lets any local process write spoofed syslog entries (defeating LFD log-based blocking), and an empty PORTFLOOD means no per-port connection-rate limits.',
                $csfGaps ? 'Set in /etc/csf/csf.conf: ' . implode('; ', $csfGaps) . '. Then apply with csf -r.' : 'No action needed.',
                !empty($csfEv[0]) ? implode("\n", $csfEv[0]) : '',
                $csfGaps ? 'csf_harden' : '',
                $csfGaps ? 'Edit /etc/csf/csf.conf: RESTRICT_SYSLOG = "3", PORTFLOOD = "22;tcp;5;300" — then csf -r' : '');
        }
    }
    /* ---- System / PHP Hardening (added checks) ---- */
    $imun = is_executable('/usr/bin/imunify360-agent'); $imunRun = $imun && smpro_sh_pf('imunify360');
    $tmpNoexec = (bool)preg_match('#\s/tmp\s.*noexec#', (string)@shell_exec('mount 2>/dev/null'));
    // Per-interpreter, because a server runs several EA-PHP versions and hardening is applied to each one
    // separately - a single unhardened version is enough for an attacker, so the worst version sets the verdict.
    $dfAll  = smpro_sh_php_ini_all('disable_functions');
    $expAll = smpro_sh_php_ini_all('expose_php');
    $dfWeak = [];   // versions that do not block command execution
    foreach ($dfAll as $v => $val) if (stripos($val, 'exec') === false) $dfWeak[] = $v;
    $expOn = [];    // versions that leak the PHP version
    foreach ($expAll as $v => $val) { $lv = strtolower(trim($val)); if ($lv === '1' || $lv === 'on') $expOn[] = $v; }
    $dfEvid = ''; foreach ($dfAll as $v => $val) $dfEvid .= $v . ': ' . ($val !== '' ? $val : '(not set)') . "\n";
    $expEvid = ''; foreach ($expAll as $v => $val) $expEvid .= $v . ': ' . ($val !== '' ? $val : '(not set)') . "\n";
    $disableFns = $dfAll ? ($dfWeak ? 'Not blocking command execution in: ' . implode(', ', $dfWeak) : 'Command-execution functions are blocked in all ' . count($dfAll) . ' interpreter(s).')
                         : 'No PHP interpreter could be read.';
    $expose     = $expAll ? ($expOn ? 'expose_php is On in: ' . implode(', ', $expOn) : 'expose_php is Off in all ' . count($expAll) . ' interpreter(s).')
                          : 'No PHP interpreter could be read.';
    // EOL EA-PHP versions - pure directory listing of /opt/cpanel (NO per-version `php -r`
    // render probes). Servers commonly carry a stack of old EA-PHP packages, all end-of-life.
    // Cutoff is DATE-DRIVEN, not a hardcoded version. php.net security-support end per branch; compared against
    // the clock so the line moves on its own. The old fixed "< 81" test kept calling an 8.1-only server green
    // long after 8.1 stopped receiving security patches (31 Dec 2025) - the check aged into a false all-clear.
    $phpEolDates = [
        '54'=>'2015-09-14','55'=>'2016-07-21','56'=>'2018-12-31','70'=>'2019-01-10','71'=>'2019-12-01',
        '72'=>'2020-11-30','73'=>'2021-12-06','74'=>'2022-11-28','80'=>'2023-11-26','81'=>'2025-12-31',
        '82'=>'2026-12-31','83'=>'2027-12-31','84'=>'2028-12-31','85'=>'2029-12-31',
    ];
    $nowT = time();
    $eaPhp = []; $eolPhp = []; $eolSoon = [];
    foreach ((is_dir('/opt/cpanel') ? (glob('/opt/cpanel/ea-php*', GLOB_ONLYDIR) ?: []) : []) as $eaDir) {
        $eaB = basename($eaDir); $eaPhp[] = $eaB;
        if (!preg_match('/^ea-php(\d{2,3})$/', $eaB, $eaM)) continue;
        $eaV = $eaM[1];
        if (!isset($phpEolDates[$eaV])) {
            // Branch newer than this table knows about -> treat as supported. Only flag a genuinely old
            // unknown version, so a future ea-php86 never gets called EOL just because we have no date for it.
            if ((int)$eaV < 81) $eolPhp[] = $eaB;
            continue;
        }
        $eaT = (int)strtotime($phpEolDates[$eaV] . ' 23:59:59');
        if ($eaT <= $nowT)                      $eolPhp[]  = $eaB;
        elseif (($eaT - $nowT) < 150 * 86400)   $eolSoon[] = $eaB;   // ~5 months' warning to plan the migration
    }
    $phpSupported = array_values(array_diff($eaPhp, $eolPhp));
    $eolSoonTxt   = $eolSoon ? ' Losing support within ~5 months: ' . implode(', ', $eolSoon) . '.' : '';
    // Kernel symlink/hardlink protection - with these off, a local user can plant a symlink/hardlink to trick a
    // root process into following it onto a system file (classic local-privesc primitive). Enabled by default on
    // modern kernels; SM Pro's own root file-ops resolve realpaths + gate on owner, but this is defense-in-depth.
    $psym = trim(smpro_sh_run("cat /proc/sys/fs/protected_symlinks 2>/dev/null"));
    $phard = trim(smpro_sh_run("cat /proc/sys/fs/protected_hardlinks 2>/dev/null"));
    $slGaps = [];
    if ($psym !== '1') $slGaps[] = 'fs.protected_symlinks';
    if ($phard !== '1') $slGaps[] = 'fs.protected_hardlinks';
    $C['System / PHP Hardening'] = [
        smpro_sh_mk('Imunify360 / malware protection', $imun ? ($imunRun ? 'ok' : 'warning') : 'info', $imun ? ($imunRun ? 'Imunify360 agent installed and running.' : 'Imunify360 installed but agent not detected running.') : 'Imunify360 not detected.', 'Imunify360 adds malware scanning, WAF and proactive defense.', $imun ? ($imunRun ? 'Confirm scans are scheduled.' : 'Check imunify360 service status.') : 'Consider Imunify360 / ImunifyAV for malware protection.'),
        smpro_sh_mk('/tmp noexec mount', $tmpNoexec ? 'ok' : 'warning', $tmpNoexec ? '/tmp is mounted noexec.' : '/tmp is NOT noexec.', 'A noexec /tmp stops attackers running uploaded scripts from /tmp.', $tmpNoexec ? 'Good.' : 'Use cPanel’s securetmp (/scripts/securetmp) to mount /tmp noexec.', (string)@shell_exec('mount 2>/dev/null | grep " /tmp "')),
        smpro_sh_mk('PHP disable_functions', !$dfAll ? 'info' : ($dfWeak ? 'warning' : 'ok'), $disableFns,
            'Dangerous PHP functions (exec, system, passthru, shell_exec) enable command execution if a site is compromised. Each installed PHP version is hardened separately, so one unhardened version is all an attacker needs — this reads every interpreter that serves sites, not the bundled cPanel PHP, which serves none.',
            $dfWeak ? 'In WHM > MultiPHP INI Editor pick each version listed above and set disable_functions there — the editor applies to one version at a time.' : ($dfAll ? 'No action needed.' : 'No EA-PHP interpreter was found. If sites run PHP here, confirm which interpreter serves them.'),
            $dfEvid),
        smpro_sh_mk('PHP information exposure', !$expAll ? 'info' : ($expOn ? 'warning' : 'ok'), $expose,
            'expose_php=On leaks your PHP version via the X-Powered-By header, which tells an attacker exactly which exploits to try.',
            $expOn ? 'Set expose_php=Off for each version listed above in MultiPHP INI Editor.' : ($expAll ? 'No action needed.' : 'No EA-PHP interpreter was found.'),
            $expEvid),
        smpro_sh_mk('End-of-life PHP versions (EA-PHP)',
            $eolPhp ? 'warning' : ($eolSoon ? 'warning' : ($eaPhp ? 'ok' : 'info')),
            $eolPhp
                ? 'End-of-life PHP installed: ' . implode(', ', $eolPhp) . ' — no security patches for these versions.' . $eolSoonTxt
                : ($eaPhp
                    ? ($eolSoon
                        ? 'All installed EA-PHP versions still receive security fixes, but support is ending soon for: ' . implode(', ', $eolSoon) . '.'
                        : 'All installed EA-PHP versions (' . implode(', ', $eaPhp) . ') still receive upstream security fixes.')
                    : 'No EA-PHP versions detected under /opt/cpanel.'),
            'A PHP branch past its php.net end-of-life date receives no upstream security fixes; one vulnerable site running on an EOL interpreter is enough to compromise the whole server. This check compares each installed branch against its real end-of-life date, so it stays accurate as branches age out (PHP 8.1 ended 31 Dec 2025, 8.2 ends 31 Dec 2026).',
            $eolPhp
                ? 'In WHM > MultiPHP Manager move every domain onto a branch that is still supported' . ($phpSupported ? ' (installed and supported here: ' . implode(', ', $phpSupported) . ')' : ' — install a current EA-PHP package first') . ', then remove the EOL packages so nothing can silently switch back to them.'
                : ($eolSoon
                    ? 'Plan the migration off ' . implode(', ', $eolSoon) . ' before its end-of-life date — moving domains after support ends means running unpatched in the meantime.'
                    : ($eaPhp ? 'No action needed — keep PHP versions current.' : 'If sites run PHP here, confirm which interpreter they use and keep it on a supported version.')),
            $eaPhp ? implode("\n", $eaPhp) : '',
            '',
            $eolPhp ? 'WHM > MultiPHP Manager: switch every domain to ' . ($phpSupported ? implode(' / ', $phpSupported) : 'a currently supported EA-PHP branch') . ', then remove: yum remove ' . implode('* ', $eolPhp) . '*' : ''),
        smpro_sh_mk('Kernel symlink/hardlink protection (fs.protected_*)',
            $slGaps ? 'warning' : 'ok',
            $slGaps ? 'Disabled: ' . implode(', ', $slGaps) . ' (protected_symlinks=' . ($psym === '' ? '?' : $psym) . ', protected_hardlinks=' . ($phard === '' ? '?' : $phard) . ').' : 'protected_symlinks and protected_hardlinks are both enabled.',
            'With these off, a local (e.g. hosting-account) user can plant a symlink or hardlink in an account-owned path to trick a root process into following it onto a system file — a classic local privilege-escalation primitive. They are enabled by default on modern kernels.',
            $slGaps ? 'Enable both: they cost nothing and block a whole class of TOCTOU/symlink attacks.' : 'No action needed — keep these enabled.',
            'protected_symlinks=' . ($psym === '' ? 'n/a' : $psym) . "\nprotected_hardlinks=" . ($phard === '' ? 'n/a' : $phard),
            $slGaps ? 'kernel_harden' : '',
            $slGaps ? 'sysctl -w fs.protected_symlinks=1 ; sysctl -w fs.protected_hardlinks=1 — then persist in /etc/sysctl.d/99-hardening.conf: fs.protected_symlinks=1 and fs.protected_hardlinks=1' : ''),
    ];
    /* ---- Server hardening (fixable, each with Undo) ---- */
    $C['Server Hardening'] = smpro_shh_checks();
    return $C;
}

// smpro_sh_all() runs php -i twice + recursive Apache-config greps + ss/sshd/mysql probes - too heavy for
// every render (incl. the post-Apply reload). Cache it; the apply handler busts the cache so a fix shows
// its effect immediately on reload.
$cats = smpro_cache_through('sh_scan', 120, fn() => smpro_sh_all());
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

<?php
// overview strip + navigator: one chip per category; the Critical / Warnings tiles open the first category holding one
$shCatId = function ($cat) { return 'sh-cat-' . trim(preg_replace('/[^a-z0-9]+/', '-', strtolower($cat)), '-'); };
$shFirst = ['critical' => '', 'warning' => '']; $shCatN = ['critical' => [], 'warning' => []];
foreach ($cats as $shCat => $shChecks) foreach ($shChecks as $shC) {
    if (!isset($shFirst[$shC['status']])) continue;
    if ($shFirst[$shC['status']] === '') $shFirst[$shC['status']] = $shCatId($shCat);
    $shCatN[$shC['status']][$shCat] = ($shCatN[$shC['status']][$shCat] ?? 0) + 1;
}
$shFirstCat = $cats ? $shCatId(array_key_first($cats)) : '';
$shKpis = [
  [$shFirstCat,                            'Security Score', (int)$score . '/100',                 $score >= 80 ? 'good' : ($score >= 60 ? 'warn' : 'dang'), '100 − 3/warning − 12/critical'],
  [$shFirstCat,                            'Overall Risk',   $risk[0],                             $risk[1] === 'danger' ? 'dang' : $risk[1],               $critN ? 'critical findings present' : ($warnN ? 'warnings to review' : 'nothing open')],
  [$shFirst['critical'] ?: $shFirstCat,    'Critical',       (string)(int)$critN,                  $critN ? 'dang' : 'good',                                 $critN ? count($shCatN['critical']) . ' categor' . (count($shCatN['critical']) === 1 ? 'y' : 'ies') : 'none'],
  [$shFirst['warning'] ?: $shFirstCat,     'Warnings',       (string)(int)$warnN,                  $warnN ? 'warn' : 'good',                                 $warnN ? count($shCatN['warning']) . ' categor' . (count($shCatN['warning']) === 1 ? 'y' : 'ies') : 'none'],
  [$shFirstCat,                            'OK / Info',      (int)$okN . ' / ' . (int)$infoN,      'brand',                                                  'passed / informational'],
  [$shFirstCat,                            'Total Checks',   (string)(int)$total,                  'muted',                                                  count($cats) . ' categories · cached 2 min'],
];
?>
<div class="fw-kpis">
  <?php foreach ($shKpis as $k): ?>
  <a class="fw-kpi <?= $k[3] ?>" href="#<?= smpro_h($k[0]) ?>" data-go="<?= smpro_h($k[0]) ?>"><div class="l"><?= smpro_h($k[1]) ?></div><div class="v"><?= smpro_h($k[2]) ?></div><div class="s"><?= smpro_h($k[4]) ?></div></a>
  <?php endforeach; ?>
</div>
<nav class="fw-nav" id="shNav"><?php foreach ($cats as $shCat => $shChecks): ?><a href="#<?= smpro_h($shCatId($shCat)) ?>" data-go="<?= smpro_h($shCatId($shCat)) ?>"><?= smpro_h($shCat) ?><?php if (!empty($shCatN['critical'][$shCat])): ?> <span class="shb danger"><?= (int)$shCatN['critical'][$shCat] ?></span><?php elseif (!empty($shCatN['warning'][$shCat])): ?> <span class="shb warn"><?= (int)$shCatN['warning'][$shCat] ?></span><?php endif; ?></a><?php endforeach; ?><span class="sp"></span><button type="button" class="fw-navx" id="shOpenAll">expand all</button><button type="button" class="fw-navx" id="shCloseAll">collapse all</button></nav>
<?php
$shUndoable = smpro_shh_undoable();
$shUndoMap = ['Kernel network & info-leak settings' => 'kernel_harden', '/dev/shm noexec' => 'shm_noexec', 'PHP allow_url_include' => 'php_urlinclude',
              'CSF/LFD attack detection' => 'csf_harden', 'Outgoing mail caps' => 'mail_caps', 'Imunify360 protection settings' => 'imunify_harden'];
$shSafeOpen = 0; foreach ($cats as $shChecks) foreach ($shChecks as $shC) if ($shC['fix'] !== '' && isset($fixspec[$shC['fix']]) && empty($fixspec[$shC['fix']]['danger']) && $shC['fix'] !== 'ssh_rootlogin') $shSafeOpen++;
?>
<div class="card sh-bulk">
  <div><b>Server hardening</b> &mdash; <?= $shSafeOpen ? (int)$shSafeOpen . ' safe fix(es) open.' : 'every safe fix is in place.' ?> Each change is backed up and can be undone one by one or all together. Root key-only SSH and database restarts are never applied in bulk.</div>
  <div class="sh-bulkbtns">
    <button type="button" class="sh-applybtn" id="shApplyAll"<?= $shSafeOpen ? '' : ' disabled' ?>>&#9889; Apply all safe fixes<?= $shSafeOpen ? ' (' . (int)$shSafeOpen . ')' : '' ?></button>
    <?php if ($shUndoable): ?><button type="button" class="sh-act" id="shUndoAll">&#8630; Roll back all (<?= count($shUndoable) ?>)</button><?php endif; ?>
  </div>
</div>
<script>var SH_CSRF=<?= json_encode(smpro_csrf_generate('sh_apply')) ?>;</script>

<div class="sh-cats">
  <?php foreach ($cats as $cat => $checks): ?>
  <div class="card sh-cat" id="<?= smpro_h($shCatId($cat)) ?>">
    <div class="sh-cathead"><b><?= smpro_h($cat) ?></b><span class="sh-n"><?= count($checks) ?></span><?php if (!empty($shCatN['critical'][$cat])): ?><span class="shb danger"><?= (int)$shCatN['critical'][$cat] ?> critical</span><?php endif; ?><?php if (!empty($shCatN['warning'][$cat])): ?><span class="shb warn"><?= (int)$shCatN['warning'][$cat] ?> warn</span><?php endif; ?></div>
    <?php foreach ($checks as $i => $c): $tid = 'sh-' . md5($cat . $i); $applyable = $c['fix'] !== '' && isset($fixspec[$c['fix']]); ?>
      <div class="sh-check <?= $c['status'] ?>">
        <div class="sh-row" data-t="<?= $tid ?>">
          <?= smpro_sh_badge($c['status']) ?>
          <div class="sh-title"><?= smpro_h($c['title']) ?><div class="sh-finding"><?= smpro_h($c['finding']) ?></div></div>
          <?php /* the row button only OPENS the panel; it says "Fix" only when a one-click fix really sits inside, "How to fix" when the panel holds instructions only */ ?>
          <button class="sh-act" type="button" data-t="<?= $tid ?>"<?= $applyable ? ' data-hasfix="1"' : '' ?>><?= $c['status']==='ok'?'Details':($c['status']==='info'?'Review':($applyable?'&#9889; Fix':'How to fix')) ?></button>
        </div>
        <div class="sh-detail" id="<?= $tid ?>">
          <div class="sh-kv"><span>Risk</span><?= smpro_h($c['risk']) ?></div>
          <div class="sh-rec"><span>Recommended action</span><?= smpro_h($c['rec']) ?></div>
          <div class="sh-kv"><span>Validation</span>Re-run Security Health after any change to confirm the status flips to OK.</div>
          <?php if ($c['manual'] !== ''): ?><div class="sh-cmd"><span>Manual command</span><code><?= smpro_h($c['manual']) ?></code></div><?php endif; ?>
          <?php if ($c['evidence'] !== ''): ?><div class="sh-ev"><button type="button" class="sh-evbtn" data-t="<?= $tid ?>-ev">Evidence</button><pre id="<?= $tid ?>-ev" class="sh-evbox"><?= smpro_h(trim($c['evidence'])) ?></pre></div><?php endif; ?>
          <?php if ($applyable): ?>
            <div class="sh-apply">
              <button type="button" class="sh-applybtn<?= !empty($fixspec[$c['fix']]['danger'])?' danger':'' ?>" data-fix="<?= smpro_h($c['fix']) ?>" data-risk="<?= smpro_h($fixspec[$c['fix']]['risk']) ?>" data-desc="<?= smpro_h($fixspec[$c['fix']]['key'].' = '.$fixspec[$c['fix']]['val']) ?>">&#9889; Apply this fix</button>
              <span class="sh-applynote"><?= smpro_h($fixspec[$c['fix']]['risk']) ?></span>
            </div>
          <?php endif; ?>
          <?php $shUid = $shUndoMap[$c['title']] ?? ''; if ($shUid !== '' && isset($shUndoable[$shUid])): ?>
            <div class="sh-apply"><button type="button" class="sh-act" data-undo="<?= smpro_h($shUid) ?>">&#8630; Undo this change</button><span class="sh-applynote">Puts back the exact previous state saved when the fix was applied.</span></div>
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
.sh-row{display:flex;align-items:flex-start;gap:10px;padding:11px 16px;cursor:pointer}.sh-row:hover{background:var(--card)}
.sh-check.warning .sh-row{background:var(--card)}.sh-check.critical .sh-row{background:var(--dang-bg)}
.sh-title{flex:1;font-size:13px;font-weight:600}.sh-finding{font-weight:400;color:var(--muted);font-size:12px;margin-top:2px}
.sh-act{font-size:11px;font-weight:600;border:1px solid var(--line);background:var(--card);border-radius:7px;padding:4px 12px;cursor:pointer;color:var(--brand);white-space:nowrap}.sh-act:hover{background:var(--brand-bg)}
.sh-detail{display:none;padding:4px 16px 14px}.sh-detail.open{display:block}
.sh-kv,.sh-rec,.sh-cmd{font-size:12px;line-height:1.6;margin-top:9px}
.sh-kv span,.sh-rec span,.sh-cmd span{display:block;font-size:10px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);font-weight:700;margin-bottom:1px}
.sh-rec{background:var(--card);border:1px solid var(--line);border-left:3px solid var(--brand);border-radius:8px;padding:9px 11px}.sh-rec span{color:var(--brand)}
.sh-cmd code{display:block;background:#0f172a;color:#e5e7eb;border-radius:8px;padding:9px 11px;font-size:12px;white-space:pre-wrap;word-break:break-word}
.sh-evbtn{font-size:11px;font-weight:600;border:1px solid var(--line);background:var(--card);border-radius:7px;padding:3px 10px;cursor:pointer;color:var(--brand);margin-top:9px}
.sh-evbox{display:none;background:#0f172a;color:#e5e7eb;border-radius:8px;padding:10px;font-size:11px;white-space:pre-wrap;word-break:break-word;margin-top:6px}
.sh-evbox.open{display:block}
.sh-apply{margin-top:10px;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.sh-applybtn{font-size:12px;font-weight:700;border:0;border-radius:8px;padding:8px 14px;cursor:pointer;background:var(--good);color:#fff}.sh-applybtn:hover{filter:brightness(.95)}
.sh-applybtn.danger{background:var(--dang)}
.sh-applynote{font-size:11px;color:var(--muted)}
.sh-bulk{display:flex;gap:14px;align-items:center;justify-content:space-between;flex-wrap:wrap;font-size:13px;margin-bottom:14px}
.sh-bulkbtns{display:flex;gap:8px;flex-wrap:wrap}.sh-applybtn[disabled]{opacity:.5;cursor:default}
.shb{display:inline-block;font-size:10px;font-weight:800;padding:2px 8px;border-radius:20px;min-width:64px;text-align:center;margin-top:1px}
.shb.good{background:var(--good-bg);color:var(--good)}.shb.blue{background:var(--brand-bg);color:var(--brand)}.shb.warn{background:var(--warn-bg);color:var(--warn)}.shb.danger{background:var(--dang-bg);color:var(--dang)}
.pill{display:inline-block;font-size:12px;font-weight:700;padding:3px 12px;border-radius:20px}
.pill.good{background:var(--good-bg);color:var(--good)}.pill.warn{background:var(--warn-bg);color:var(--warn)}.pill.danger{background:var(--dang-bg);color:var(--dang)}
.meta{color:var(--muted)}
/* ---- overview strip / navigator / collapsible cards (pattern: firewall-status.php) ---- */
/* .fw-kpis / .fw-nav / .fw-collapse / pager styles: shared, in includes/layout.php */
.sh-cathead{cursor:pointer}.sh-cathead .sh-n{font-size:11.5px;font-weight:800;padding:1px 8px;border-radius:999px;background:var(--brand-bg);color:var(--brand);margin-left:4px}
.sh-cathead .shb{margin-left:4px;min-width:0}
@media print{.fw-nav{display:none!important}}
.sh-applybtn.sh-flash{box-shadow:0 0 0 4px var(--brand-bg);outline:2px solid var(--brand)}
</style>
<script>
(function(){
  function toggle(tid){var d=document.getElementById(tid);if(!d)return;d.classList.toggle('open');
    var b=document.querySelector('.sh-act[data-t="'+tid+'"]');if(b){if(b.dataset.lbl===undefined)b.dataset.lbl=b.textContent;b.textContent=d.classList.contains('open')?'Hide':b.dataset.lbl;
      /* a "Fix" row opened: bring the one-click Apply button into view and flash it, so the next click is the fix itself */
      if(b.dataset.hasfix&&d.classList.contains('open')){var ap=d.querySelector('.sh-applybtn');if(ap){ap.scrollIntoView({behavior:'smooth',block:'center'});ap.classList.add('sh-flash');setTimeout(function(){ap.classList.remove('sh-flash');},1800);}}}}
  document.addEventListener('click',function(e){
    var ev=e.target.closest('.sh-evbtn');if(ev){var x=document.getElementById(ev.getAttribute('data-t'));if(x)x.classList.toggle('open');return;}
    var ap=e.target.closest('.sh-applybtn');if(ap){applyFix(ap);return;}
    var row=e.target.closest('[data-t]');if(row&&!e.target.closest('.sh-evbtn')&&!e.target.closest('.sh-applybtn'))toggle(row.getAttribute('data-t'));});
  function shPost(field,val,btn,label,confirmTxt){
    if(!confirm(confirmTxt))return;
    btn.disabled=true;var t0=btn.textContent;btn.textContent=label;
    var fd=new URLSearchParams();fd.set(field,val);fd.set('smpro_csrf',SH_CSRF);
    fetch('index.cgi?page=security-health',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'})
      .then(function(r){return r.json();}).then(function(j){alert(((j&&j.ok)?'Done: ':'Not complete: ')+((j&&j.msg)||'error')+'\n\nReloading to re-scan…');location.reload();})
      .catch(function(){btn.disabled=false;btn.textContent=t0;alert('Failed (network/permission). A started change still finishes on the server; reload in a minute.');});
  }
  document.addEventListener('click',function(e){
    var b=e.target.closest&&e.target.closest('[data-undo],#shApplyAll,#shUndoAll');if(!b)return;
    if(b.id==='shApplyAll')shPost('sh_apply_all','1',b,'Applying…','Apply every safe fix that is open now?\n\nEach change is backed up first and can be undone. Fixes that can lock you out or restart the database are NOT included.');
    else if(b.id==='shUndoAll')shPost('sh_undo','all',b,'Rolling back…','Put back every server-hardening change made from this page, newest first?');
    else shPost('sh_undo',b.getAttribute('data-undo'),b,'Undoing…','Put back the previous state of this setting?');
  });
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
<script>
(function(){
  /* collapsible section cards + sticky navigator (pattern: modules/firewall-status.php). The header of every
     card is a real toggle (role=button, keyboard), the open/closed choice is remembered per section. */
  var KEY='smpro:security-health:open', HSEL='.smpro-main .card > .sh-cathead', PFX='sh', open={};
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

  }
  window[PFX+'OpenCard']=openCard;
  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',init); else init();
})();
</script>
<?php
smpro_layout_footer();
