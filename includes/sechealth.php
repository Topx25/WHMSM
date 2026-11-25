<?php
/**
 * includes/sechealth.php - the Security Health checks and their safe appliers, moved out of the page module so a
 * scheduled worker (bin/sechealth_tick.php) can run the SAME checks and alert on a newly worsened posture. The
 * page (modules/security-health.php) require_once's this and keeps only its POST handling and its render; nothing
 * about a check changed in the move. smpro_sh_all() returns the findings as an array; smpro_sh_badge() stays on the
 * page (render only).
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

defined('SMPRO_SH_BACKUP') || define('SMPRO_SH_BACKUP', SMPRO_VARLIB . '/backups/security');
require_once __DIR__ . '/shharden.php';

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

/**
 * The single security-score formula, shared by the page render and the scheduled scan so the number the page
 * shows and the number the trend is built from can never drift apart. Takes smpro_sh_all()'s category map (or a
 * flat list of checks) and returns ['score'=>0..100, 'critical'=>n, 'warning'=>n]. 100 minus 3 per warning and
 * 12 per critical, floored at 0 - the same weighting the page has always used, now in one place.
 */
function smpro_sh_score(array $cats): array {
    $crit = 0; $warn = 0;
    foreach ($cats as $checks) {
        // accept either [cat => [check,...]] or a flat [check,...]
        $list = (is_array($checks) && isset($checks['status'])) ? [$checks] : (array)$checks;
        foreach ($list as $c) {
            if (!is_array($c)) continue;
            $s = strtolower((string)($c['status'] ?? ''));
            if ($s === 'critical') $crit++; elseif ($s === 'warning') $warn++;
        }
    }
    return ['score' => max(0, 100 - $warn * 3 - $crit * 12), 'critical' => $crit, 'warning' => $warn];
}

/**
 * Parse the text of `dnf/yum updateinfo list --security` into counts + the worst severity. A pure function (no
 * shell), so the severity/CVE/dedup logic can be tested against real vendor output without a package manager.
 * Each row looks like: "ALSA-2026:1234 Important/Sec. openssl-1.1.1k-9.el9.x86_64" (CVE ids appear when the list
 * was produced with --with-cve). Vendors vary the severity wording, so it is matched case-insensitively, and an
 * advisory seen on several package rows is counted once at its highest severity.
 */
function smpro_sh_parse_updateinfo(string $raw): array {
    $sevRank = ['critical' => 4, 'important' => 3, 'moderate' => 2, 'low' => 1, 'none' => 0];
    $advisories = []; $pkgs = []; $cves = []; $worst = 'none'; $kept = [];
    foreach (explode("\n", $raw) as $l) {
        $l = trim($l); if ($l === '') continue;
        if (stripos($l, 'Last metadata') !== false || stripos($l, 'updateinfo') !== false) continue;   // header noise
        if (!preg_match('/^(\S+)\s+(\S+)\s+(\S+)/', $l, $m)) continue;
        $adv = $m[1]; $sevRaw = $m[2]; $pkg = $m[3];
        // the first token must look like an advisory id (LETTERS-YEAR:NUM or a CVE), not a stray word
        if (!preg_match('/^[A-Z]+-\d{4}[:\-]\d+/i', $adv) && !preg_match('/^CVE-\d{4}-\d+/i', $adv)) continue;
        $kept[] = $l;
        $sev = 'none';
        foreach ($sevRank as $s => $_r) if (stripos($sevRaw, $s) !== false) { $sev = $s; break; }
        // keep an advisory at its HIGHEST severity across its package rows
        if (!isset($advisories[$adv]) || $sevRank[$sev] > $sevRank[$advisories[$adv]]) $advisories[$adv] = $sev;
        $pkgs[$pkg] = true;
        if ($sevRank[$sev] > $sevRank[$worst]) $worst = $sev;
        if (preg_match_all('/CVE-\d{4}-\d{4,}/i', $l, $cm)) foreach ($cm[0] as $c) $cves[strtoupper($c)] = true;
    }
    return ['advisories' => count($advisories), 'packages' => count($pkgs), 'cves' => count($cves),
            'worst' => $worst, 'sample' => array_slice(array_keys($advisories), 0, 8),
            'raw' => implode("\n", array_slice($kept, 0, 20))];
}

/**
 * Pending OS security updates, read from the distribution's OWN security advisory data (dnf/yum updateinfo) -
 * no external feed, no CVE database to keep current, no version guessing: the vendor (AlmaLinux / CloudLinux /
 * Rocky / CentOS) ships the advisory metadata in its repos and marks which updates are security fixes and how
 * severe. This turns the section from a hardening checklist into a real "are there known-vulnerable packages
 * installed right now" check. Returns a structured result so both the page check and the auto-scan can use it.
 *
 * Three states are kept DISTINCT so an unreadable or advisory-less box is never shown as clean:
 *   has_updates  - security updates are waiting (severity + counts set)
 *   clean        - no security updates AND the repo carries advisory metadata (a trustworthy all-clear)
 *   no_metadata  - the repos do not publish updateinfo advisories here, so security status cannot be judged
 *   unavailable  - no dnf/yum, or the query failed
 */
function smpro_sh_os_security(): array {
    $mgr = trim(smpro_sh_run('command -v dnf', 5)) !== '' ? 'dnf' : (trim(smpro_sh_run('command -v yum', 5)) !== '' ? 'yum' : '');
    if ($mgr === '') return ['state' => 'unavailable', 'why' => 'Neither dnf nor yum is present (not an RPM-based system).'];

    // The security advisory list: one line per (advisory, package). Severity is a column; CVE ids appear with --with-cve
    // on dnf. Bounded; metadata refresh is capped so a slow mirror cannot hang the page. 2>/dev/null keeps stdout clean.
    $raw = smpro_sh_run(escapeshellarg($mgr) . ' -q --setopt=metadata_expire=3h updateinfo list --security 2>/dev/null', 45);
    $p = smpro_sh_parse_updateinfo($raw);

    if ($p['advisories'] > 0) {
        return ['state' => 'has_updates', 'manager' => $mgr, 'worst' => $p['worst'],
                'advisories' => $p['advisories'], 'packages' => $p['packages'], 'cves' => $p['cves'],
                'sample' => $p['sample'], 'raw' => $p['raw']];
    }

    // No security advisories came back. Decide between a real all-clear and a repo that simply has no advisory data:
    // if there ARE pending updates at all but updateinfo named none, the metadata is the thing missing, not the risk.
    $anyUpd = smpro_sh_run(escapeshellarg($mgr) . ' -q check-update 2>/dev/null | grep -cE ' . escapeshellarg('^[a-zA-Z0-9]'), 45);
    $pending = (int)trim($anyUpd);
    $summary = smpro_sh_run(escapeshellarg($mgr) . ' -q updateinfo summary 2>/dev/null', 30);
    $hasMeta = trim($summary) !== '' || $pending === 0;   // a clean box legitimately prints an empty summary
    if ($pending > 0 && trim($summary) === '')
        return ['state' => 'no_metadata', 'manager' => $mgr, 'pending' => $pending,
                'why' => $pending . ' update(s) are available but the repositories publish no security advisory data, so which of them are security fixes cannot be determined here.'];
    return ['state' => 'clean', 'manager' => $mgr, 'pending' => $pending];
}

/**
 * Is the running kernel exposed to a known, fixed flaw? The single most common real case is NOT an EOL kernel -
 * it is a patched kernel that has been installed but the server is still running the OLD one because it was never
 * rebooted: the fix is on disk, doing nothing, and uname looks "old" while the security update already shipped.
 *
 * The subtlety that makes a naive check wrong: a LIVE-PATCHING kernel (KernelCare/kpatch) rewrites the RUNNING
 * kernel in memory without a reboot, so uname deliberately shows an "old" version that is in fact fully fixed.
 * Comparing uname to the newest installed RPM there would cry "reboot needed" on a server that is already
 * patched - exactly the kind of false alarm that teaches an operator to ignore this page. So:
 *   - KernelCare active + "patch is applied" + no newer patch  -> OK (effective kernel is current, no reboot).
 *   - KernelCare active but a newer patch is available         -> warning (apply it: kcarectl --update).
 *   - no live patching: compare running vs newest-installed; different -> warning (a fix is installed but the
 *     server runs the old kernel; needs-restarting -r, when present, is the authoritative confirmation).
 * Returns a structured result; the page + the scheduled scan both render from it.
 */
function smpro_sh_kernel_exposure(): array {
    $running = trim(smpro_sh_run('uname -r'));
    if ($running === '') return ['state' => 'unknown', 'running' => '', 'why' => 'uname did not answer'];

    // live patching first - it changes the whole meaning of "running vs installed"
    $kc = trim(smpro_sh_run('command -v kcarectl', 5));
    if ($kc !== '') {
        $info = smpro_sh_run('kcarectl --info 2>/dev/null', 15);
        $applied = stripos($info, 'patch is applied') !== false;
        $noNewer = stripos($info, 'No newer patch is available') !== false;
        $effective = preg_match('/5\.\d+\.\d+-\S+|\b\d+\.\d+\.\d+-\S+/', (string)(preg_match('/kpatch-description:[^;]*;(\S+)/', $info, $dm) ? $dm[1] : ''), $em) ? $em[0] : '';
        if ($applied && $noNewer) return ['state' => 'ok', 'running' => $running, 'livepatch' => 'kernelcare', 'effective' => $effective,
            'why' => 'KernelCare live patching is active and up to date; the running kernel is patched in memory without a reboot' . ($effective !== '' ? ' (effective ' . $effective . ')' : '') . '.'];
        if ($applied && !$noNewer) return ['state' => 'warning', 'running' => $running, 'livepatch' => 'kernelcare',
            'why' => 'KernelCare is active but a newer live patch is available for this kernel.',
            'fix' => 'kcarectl --update'];
        // KernelCare present but not confirming an applied patch - treat like no live patch, fall through to the RPM compare
    }

    // no (confirmed) live patch: a newer kernel installed but not booted is the real exposure
    $newest = trim(smpro_sh_run("rpm -q kernel --qf '%{VERSION}-%{RELEASE}.%{ARCH}\\n' 2>/dev/null | sort -V | tail -1"));
    // needs-restarting -r is authoritative when it exists (0 = no reboot needed, 1 = reboot needed)
    $nrBin = trim(smpro_sh_run('command -v needs-restarting', 5));
    $nrReboot = null;
    if ($nrBin !== '') { $out = smpro_sh_run('needs-restarting -r 2>&1; echo "RC=$?"', 20); if (preg_match('/RC=(\d+)/', $out, $rm)) $nrReboot = ((int)$rm[1] === 1); }

    if ($newest !== '' && $newest !== $running) {
        // a different newest-installed kernel: the fix is on disk but the old kernel is still running
        $sev = ($nrReboot === false) ? 'ok' : 'warning';   // needs-restarting can still clear it (e.g. only non-kernel pkgs newer)
        if ($sev === 'ok') return ['state' => 'ok', 'running' => $running, 'newest' => $newest,
            'why' => 'A newer kernel (' . $newest . ') is installed, but the system reports no reboot is required (needs-restarting -r).'];
        return ['state' => 'warning', 'running' => $running, 'newest' => $newest, 'needs_reboot' => $nrReboot,
            'why' => 'A newer kernel is installed (' . $newest . ') but the server is still running ' . $running . '. Any kernel security fix in that newer build is installed but NOT in effect until a reboot.',
            'fix' => 'Reboot into the newer kernel during a maintenance window (SM Pro > Reboot can schedule it).'];
    }

    if ($nrReboot === true) return ['state' => 'warning', 'running' => $running, 'newest' => $newest ?: $running, 'needs_reboot' => true,
        'why' => 'The system reports a reboot is required (needs-restarting -r) for updated core libraries/services to take effect.',
        'fix' => 'Reboot during a maintenance window (SM Pro > Reboot can schedule it).'];

    return ['state' => 'ok', 'running' => $running, 'newest' => $newest ?: $running,
        'why' => 'The running kernel is the newest installed and no reboot is pending.'];
}

/**
 * Three failures that look like nothing at all from the panel. A malware scan that has said "running" for months
 * (nothing is being scanned); one of the operator's own servers sitting in a ban list (its calls fail, and any reply it
 * sends is dropped); and an SSH flood limit low enough that the operator's own tools trip it (a silent drop, no deny line).
 */
function smpro_sh_scan_own_checks() {
    $out = [];
    // a) Imunify on-demand scan stuck
    if (trim(smpro_sh_run('command -v imunify360-agent', 5)) === '') {
        $out[] = smpro_sh_mk('Malware scan progress (Imunify)', 'info', 'Imunify360 is not installed, so there is no on-demand scan to check.', 'n/a', 'No action needed.');
    } else {
        $j = json_decode(smpro_sh_run('imunify360-agent malware on-demand list --limit 5 --json', 40), true);
        if (!is_array($j)) {
            $out[] = smpro_sh_mk('Malware scan progress (Imunify)', 'info', 'Imunify did not answer the scan list, so its progress could not be checked.', 'A scan that never finishes looks exactly like a clean server.', 'Check Imunify360 > Malware Scanner by hand.');
        } else {
            $stuck = [];
            foreach ((array)($j['items'] ?? []) as $it) {
                $started = (int)($it['started'] ?? 0);
                if (in_array((string)($it['scan_status'] ?? ''), ['running', 'queued'], true) && $started > 0 && $started < time() - 172800)
                    $stuck[] = (string)($it['path'] ?? '?') . ' - ' . (string)$it['scan_status'] . ' since ' . date('Y-m-d', $started) . ', ' . (int)($it['total'] ?? 0) . ' file(s) scanned';
            }
            $out[] = smpro_sh_mk('Malware scan progress (Imunify)', $stuck ? 'critical' : 'ok',
                $stuck ? count($stuck) . ' scan(s) have been running or queued for more than 2 days: ' . implode('; ', array_slice($stuck, 0, 3)) : 'No on-demand scan has been stuck for more than 2 days.',
                'While a scan is stuck nothing new is scanned, and the panel still shows Imunify as working: malware arriving now is not found.',
                $stuck ? 'Stop the stuck scan and queue a fresh one (see the command).' : 'No action needed.',
                '', '', $stuck ? 'imunify360-agent malware on-demand stop; systemctl restart imunify360; imunify360-agent malware on-demand queue put /home' : '');
        }
    }
    // b) own servers / never-block addresses inside a ban list
    if (!function_exists('smpro_gh_trusted_ips')) { $gf = dirname(__DIR__) . '/includes/geohulk.php'; if (is_file($gf)) require_once $gf; }
    $trusted = function_exists('smpro_gh_trusted_ips') ? smpro_gh_trusted_ips() : [];
    $nft = smpro_sh_run('nft list set inet filter cphulk-TempBan', 10) . smpro_sh_run('nft list set inet filter cphulk-PermBan', 10);
    $deny = function_exists('smpro_csf_blocked_set') ? smpro_csf_blocked_set() : [];
    $hit = [];
    foreach ($trusted as $t) {
        if (strpos($t, '/') !== false) continue;
        if (preg_match('/(^|[\s,{])' . preg_quote($t, '/') . '([\s,}]|$)/', $nft)) $hit[] = $t . ' (cPHulk ban)';
        elseif (isset($deny[$t])) $hit[] = $t . ' (CSF deny)';
    }
    $out[] = smpro_sh_mk('Own servers not banned', $hit ? 'critical' : 'ok',
        $hit ? 'Addresses this server must trust are banned: ' . implode(', ', array_slice($hit, 0, 6)) : 'None of the ' . count($trusted) . ' trusted address(es) (own, csf.allow, fleet) is in a ban list.',
        'A banned sibling server cannot reach this one, and its replies to this server are dropped too: anything here that calls it (a store admin, an API, a backup) hangs.',
        $hit ? 'Lift the ban and whitelist the address (see the command).' : 'No action needed.',
        '', '', $hit ? 'for ip in ' . implode(' ', array_map(fn($x) => strtok($x, ' '), array_slice($hit, 0, 6))) . '; do whmapi1 create_cphulk_record list_name=white ip=$ip comment=own-server; whmapi1 flush_cphulk_login_history_for_ips ip=$ip; csf -dr $ip; done' : '');
    // c) SSH flood limit
    $pf = ''; foreach (@file('/etc/csf/csf.conf', FILE_IGNORE_NEW_LINES) ?: [] as $ln) if (preg_match('/^PORTFLOOD\s*=\s*"([^"]*)"/', $ln, $m)) { $pf = $m[1]; break; }
    $low = '';
    foreach (array_filter(array_map('trim', explode(',', $pf))) as $e) { $q = explode(';', $e); if (count($q) === 4 && (int)$q[0] === 22 && (int)$q[2] < 40) $low = $e; }
    $out[] = smpro_sh_mk('SSH flood limit (CSF PORTFLOOD)', $pf === '' ? 'info' : ($low !== '' ? 'warning' : 'ok'),
        $pf === '' ? 'No PORTFLOOD rule is set.' : ($low !== '' ? 'PORTFLOOD allows only ' . explode(';', $low)[2] . ' new SSH connection(s) per ' . explode(';', $low)[3] . ' s from one address (' . $low . ').' : 'PORTFLOOD is ' . $pf . '.'),
        'Above the limit, new SSH connections are dropped silently - no csf.deny line, nothing for the home-region shield to lift. Admin tools that open many short connections, and people sharing one office address, trip it.',
        $low !== '' ? 'Raise it to 60 connections per 60 s; SSH is still protected by the country wall and the login guard.' : 'No action needed.',
        '', '', $low !== '' ? "sed -i 's/" . $low . "/22;tcp;60;60/' /etc/csf/csf.conf && csf -r" : '');
    return $out;
}

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
    /* ---- Known-vulnerable packages: pending OS security updates from the vendor's own advisory data ---- */
    $osv = smpro_sh_os_security();
    if ($osv['state'] === 'has_updates') {
        $sevWord = ucfirst($osv['worst']);
        $isCrit  = in_array($osv['worst'], ['critical', 'important'], true);
        $cveTxt  = $osv['cves'] > 0 ? ' (' . $osv['cves'] . ' CVE' . ($osv['cves'] === 1 ? '' : 's') . ')' : '';
        $C['Security updates'] = [
            smpro_sh_mk('Pending OS security updates',
                $isCrit ? 'critical' : 'warning',
                $osv['advisories'] . ' security advisory(ies)' . $cveTxt . ' affecting ' . $osv['packages'] . ' installed package(s) are waiting — highest severity: ' . $sevWord . '.',
                'Each advisory is a vendor-published fix for a KNOWN vulnerability in a package installed on this server. Until it is applied the server is running software with a publicly documented flaw — exactly what mass scanners look for. A Critical/Important advisory for an internet-facing service (OpenSSL, the kernel, Exim, a web server) is the highest-priority item on this whole page.',
                'Apply the security updates: ' . $osv['manager'] . ' -y update --security  (schedule a brief window; a kernel or glibc update needs a reboot to take effect). Review first with: ' . $osv['manager'] . ' updateinfo list --security.',
                'Highest severity: ' . $sevWord . "\nAdvisories: " . implode(', ', $osv['sample']) . (count($osv['sample']) < $osv['advisories'] ? ' …' : '') . "\n\n" . $osv['raw'],
                '',
                $osv['manager'] . ' -y update --security   # then reboot if the kernel or glibc was updated'),
        ];
    } elseif ($osv['state'] === 'no_metadata') {
        $C['Security updates'] = [
            smpro_sh_mk('Pending OS security updates', 'info',
                $osv['why'],
                'Without the vendor\'s security-advisory metadata this server cannot tell which pending updates are security fixes, so a known-vulnerable package could be installed without this check seeing it.',
                'Install the advisory metadata so security updates become visible: ' . $osv['manager'] . ' install -y dnf-plugins-core (and enable the distro\'s updateinfo, e.g. the AlmaLinux/Rocky release repos). Until then, apply all updates regularly: ' . $osv['manager'] . ' -y update.',
                $osv['pending'] . ' update(s) pending; no security advisory data from the repos.'),
        ];
    } elseif ($osv['state'] === 'clean') {
        $C['Security updates'] = [
            smpro_sh_mk('Pending OS security updates', 'ok',
                'No security updates are waiting — every vendor security advisory for the installed packages has been applied.' . ((int)($osv['pending'] ?? 0) > 0 ? ' (' . (int)$osv['pending'] . ' non-security update(s) are available.)' : ''),
                'Known-vulnerable packages are the most commonly exploited way into a server; keeping security advisories applied closes that door.',
                (int)($osv['pending'] ?? 0) > 0 ? 'Up to date on security; apply the remaining non-security updates at your convenience: ' . $osv['manager'] . ' -y update.' : 'No action needed — keep applying security updates as they are published.',
                'Checked via ' . $osv['manager'] . ' updateinfo (vendor advisory data).'),
        ];
    }
    // state 'unavailable' -> not an RPM system; emit nothing rather than a misleading finding.

    /* ---- Kernel exposure: a security-fixed kernel installed but not running (reboot), live-patch aware ---- */
    $kx = smpro_sh_kernel_exposure();
    if (($kx['state'] ?? '') !== 'unknown') {
        $kSev = ($kx['state'] === 'warning') ? 'warning' : 'ok';
        $kEv  = 'running: ' . ($kx['running'] ?? '?')
              . (isset($kx['newest']) ? "\nnewest installed: " . $kx['newest'] : '')
              . (isset($kx['effective']) && $kx['effective'] !== '' ? "\nlive-patch effective: " . $kx['effective'] : '')
              . (isset($kx['livepatch']) ? "\nlive patching: " . $kx['livepatch'] : '');
        $C['Security updates'] = array_merge($C['Security updates'] ?? [], [
            smpro_sh_mk('Running kernel up to date', $kSev,
                (string)($kx['why'] ?? ''),
                'A kernel security fix only protects the server once that kernel is actually running. The common trap is a patched kernel installed by an update but never booted — the fix is on disk, doing nothing, while scanners still reach the running (vulnerable) kernel. Live-patching (KernelCare) is the exception: it fixes the running kernel in memory with no reboot, so an "old" uname can be fully patched.',
                $kSev === 'warning' ? (string)($kx['fix'] ?? 'Reboot into the newest kernel during a maintenance window.') : 'No action needed — the effective kernel is current.',
                $kEv,
                '',
                $kSev === 'warning' ? (string)($kx['fix'] ?? '') : ''),
        ]);
    }

    /* ---- Hosting-stack CVEs: installed cPanel/Imunify/CSF/LiteSpeed vs the signed advisory feed ---- */
    if (!function_exists('smpro_vf_match_product')) { $vf = dirname(__DIR__) . '/includes/vulnfeed.php'; if (is_file($vf)) require_once $vf; }
    if (function_exists('smpro_vf_match_product') && function_exists('smpro_vf_status')) {
        $vfSt = smpro_vf_status();
        $vfChecks = [];
        $anyInstalled = false; $sevRank = ['none' => 0, 'low' => 1, 'moderate' => 2, 'important' => 3, 'critical' => 4];
        foreach (smpro_vf_known_products() as $prod) {
            $m = smpro_vf_match_product($prod);
            if (!$m['installed']) continue;
            $anyInstalled = true;
            $label = ['cpanel' => 'cPanel & WHM', 'imunify360' => 'Imunify360', 'csf' => 'CSF (ConfigServer Firewall)', 'litespeed' => 'LiteSpeed'][$prod] ?? $prod;
            if (!$vfSt['have']) {
                // feed not configured yet: show the version, flag nothing - never a false "vulnerable" or "clean".
                $vfChecks[] = smpro_sh_mk($label . ' version', 'info',
                    $label . ' ' . $m['version'] . ' is installed. The vulnerability advisory feed is not configured, so it was not checked against known CVEs.',
                    'Without the signed advisory feed this server cannot tell whether the installed hosting-stack versions carry a published vulnerability.',
                    'The advisory feed is served by the licence server; once it is published this check lights up automatically. ' . ($vfSt['why'] !== '' ? '(' . $vfSt['why'] . ')' : ''),
                    'Installed: ' . $m['version']);
                continue;
            }
            $hits = $m['hits'];
            if (!$hits) {
                $vfChecks[] = smpro_sh_mk($label . ' known vulnerabilities', 'ok',
                    $label . ' ' . $m['version'] . ' has no known advisory affecting it in the current feed.',
                    'A hosting-stack component with a published CVE is a direct, remotely known way in.',
                    'No action needed — keep it updated.',
                    'Installed: ' . $m['version'] . ' · feed built ' . date('Y-m-d H:i', (int)$vfSt['generated']));
                continue;
            }
            // worst severity + fixed-in across the matching advisories
            $prodWorst = 'low'; $cves = []; $fixedTo = '';
            foreach ($hits as $h) {
                if (($sevRank[$h['severity']] ?? 0) > ($sevRank[$prodWorst] ?? 0)) $prodWorst = $h['severity'];
                foreach ((array)($h['cves'] ?? []) as $c) $cves[strtoupper($c)] = true;
                if ($fixedTo === '' || version_compare((string)$h['fixed'], $fixedTo, '>')) $fixedTo = (string)$h['fixed'];
            }
            $isCrit = in_array($prodWorst, ['critical', 'important'], true);
            $cveList = array_keys($cves);
            $ev = [];
            foreach ($hits as $h) $ev[] = (string)($h['id'] ?? '?') . '  ' . ucfirst((string)$h['severity']) . '  fixed in ' . (string)$h['fixed'] . (($h['cves'] ?? []) ? '  (' . implode(', ', (array)$h['cves']) . ')' : '') . (($h['title'] ?? '') !== '' ? '  — ' . (string)$h['title'] : '');
            $vfChecks[] = smpro_sh_mk($label . ' known vulnerabilities',
                $isCrit ? 'critical' : 'warning',
                $label . ' ' . $m['version'] . ' is affected by ' . count($hits) . ' known advisory(ies)' . ($cveList ? ' (' . implode(', ', array_slice($cveList, 0, 4)) . (count($cveList) > 4 ? ' …' : '') . ')' : '') . ' — highest severity: ' . ucfirst($prodWorst) . '. Fixed in ' . $fixedTo . '.',
                'This is a component of your hosting stack running a version with a PUBLISHED vulnerability and a vendor fix available. A Critical/Important advisory against cPanel, Imunify, CSF or the web server is a direct, documented way into the server.',
                'Update ' . $label . ' to ' . $fixedTo . ' or later. ' . ($prod === 'cpanel' ? 'cPanel updates via /scripts/upcp (or WHM > Upgrade to Latest Version).' : ($prod === 'imunify360' ? 'imunify360-agent update, or yum update imunify360.' : ($prod === 'csf' ? 'csf -u (CSF self-update).' : 'Update LiteSpeed from its control panel / vendor packages.'))),
                implode("\n", $ev));
        }
        if ($vfChecks) {
            // keep the section even when every product is clean; it is the "known-CVE" half of Security updates.
            $C['Security updates'] = array_merge($C['Security updates'] ?? [], $vfChecks);
        } elseif (!$anyInstalled) {
            // none of the four products present (rare on a cPanel box) - say nothing rather than an empty finding.
        }
    }

    /* ---- scanning that silently stopped, own servers in a ban list, SSH flood limit ---- */
    $C['Scanning & own servers'] = smpro_sh_scan_own_checks();
    /* ---- Server hardening (fixable, each with Undo) ---- */
    $C['Server Hardening'] = smpro_shh_checks();
    return $C;
}

/** Schedule the automatic Security Health scan (bin/sechealth_tick.php). Daily by default; the tick itself
 *  decides whether its interval has passed. Mirrors smpro_sr_cron_sync. Off removes the cron file. */
function smpro_sh_cron_sync(): bool {
    if (defined('SMPRO_TEST_SRC')) return true;
    $f = '/etc/cron.d/smpro-sechealth';
    // default ON: the whole point is that the check no longer waits for someone to open the page
    $stateFile = SMPRO_VARLIB . '/sechealth_auto.json';
    $st = @is_file($stateFile) ? (array)json_decode((string)@file_get_contents($stateFile), true) : [];
    if (isset($st['cfg']['enabled']) && empty($st['cfg']['enabled'])) { if (@is_file($f)) @unlink($f); return true; }
    $bin = SMPRO_BASE . '/bin/sechealth_tick.php'; if (!@is_file($bin)) return false;
    $php = function_exists('smpro_php_cli_bin') ? smpro_php_cli_bin() : (is_executable('/usr/local/cpanel/3rdparty/bin/php') ? '/usr/local/cpanel/3rdparty/bin/php' : 'php');
    $lockDir = defined('SMPRO_LOCKS') ? SMPRO_LOCKS : (SMPRO_VARLIB . '/locks'); @is_dir($lockDir) || @mkdir($lockDir, 0700, true);
    $flock = is_executable('/usr/bin/flock') ? '/usr/bin/flock' : 'flock';
    // twice a day; the tick's own interval (default daily) decides if it actually runs, so this only sets an upper bound
    $desired = "# Safety Monitor Pro - automatic Security Health scan: runs the posture checks and alerts on a NEW or worsened critical/warning finding\n"
             . '17 */12 * * * root ' . $flock . ' -n ' . $lockDir . '/sechealth.lock timeout 600 nice -n 10 ' . $php . ' ' . $bin . ' >/dev/null 2>&1' . "\n";
    return function_exists('smpro_cron_install') ? smpro_cron_install($f, $desired) : (@file_put_contents($f, $desired) !== false && @chmod($f, 0644));
}
