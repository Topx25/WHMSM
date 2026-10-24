<?php
/**
 * fileaudit.php - WHO changed a file, through WHICH door, from WHICH address, WHEN.
 *
 * THE QUESTION THIS ANSWERS, AND WHY NOTHING ELSE ON THE SERVER COULD.
 *
 * An operator investigating an account wants to know who deleted or changed its files. The timeline could not
 * say, because the evidence did not exist anywhere on the server:
 *
 *   - File Manager. Deletes and saves go to POST /json-api/cpanel with the function and the file in the request
 *     BODY, which the cPanel access log does not record. 3,953 such calls in four months on one server, every
 *     one of them blind. cPanel's own "API log" tweak records only Module::function - no file, no address.
 *   - FTP. proftpd logs "session opened" with the address but not the user; the transfer log is split and
 *     deleted by cpanellogd within minutes; a DELE command is never written anywhere at all.
 *   - SFTP / SSH. Nothing.
 *
 * So the evidence is made here, by the kernel, through auditd - which is already installed and running on every
 * cPanel server that has Imunify. A syscall rule records every delete and rename under the home partitions, and
 * every write that comes through one of the three doors a person uses (a login session, FTP, the cPanel binary).
 * The record carries the uid, the pid, the login session, the executable and the path. From those, the address
 * is joined at collection time, while the joining logs are still fresh:
 *
 *   ssh / sftp    the audit stream's own USER_LOGIN record for the same session id carries addr=
 *   ftp           /var/log/messages: "proftpd[PID] ... (IP[IP]): FTP session opened" - the SAME pid
 *   file manager  the cPanel access log: the same user's Fileman request in the same second or two
 *   php / cron    no network door of their own; labelled as such, never given a guessed address
 *
 * WHY IT IS COLLECTED EVERY MINUTE INTO OUR OWN STORE. auditd keeps 5 x 8 MB by default. On a server with
 * Imunify's rules that is minutes of history, not days. The raw log is a conveyor belt; this reads it from a
 * checkpoint (inode + offset, so a rotation is followed rather than lost) and writes one JSONL per account per
 * day under SMPRO_VARLIB, kept for SMPRO_FA_KEEP_DAYS.
 *
 * WHY THE LOG IS READ DIRECTLY AND NOT THROUGH ausearch. ausearch walks the whole log for every query; on a lab
 * box it did not return in ninety seconds. Reading forward from a checkpoint is a few kilobytes a minute.
 *
 * "COULD NOT LOOK" IS A RESULT. If auditd is absent, the rules are not loaded, the log is unreadable or the
 * checkpoint is stale, smpro_fa_status() says so and the page shows it - an empty table under a working banner
 * would be this product's own failure class: a check that could not run reading exactly like one that found
 * nothing.
 *
 * Root-only. Nothing here is copied to the account-side plugin.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

if (!defined('SMPRO_FA_DIR'))       define('SMPRO_FA_DIR', SMPRO_VARLIB . '/fileaudit');
if (!defined('SMPRO_FA_KEEP_DAYS')) define('SMPRO_FA_KEEP_DAYS', 90);
if (!defined('SMPRO_FA_RULES'))     define('SMPRO_FA_RULES', '/etc/audit/rules.d/smpro-files.rules');
if (!defined('SMPRO_FA_KEY'))       define('SMPRO_FA_KEY', 'smpro_files');
if (!defined('SMPRO_FA_AUDITLOG'))  define('SMPRO_FA_AUDITLOG', '/var/log/audit/audit.log');

/* ============================================================================================ configuration */

function smpro_fa_dir(): string {
    if (!@is_dir(SMPRO_FA_DIR)) { @mkdir(SMPRO_FA_DIR, 0700, true); @chmod(SMPRO_FA_DIR, 0700); }
    return SMPRO_FA_DIR;
}

function smpro_fa_cfg(): array {
    $f = smpro_fa_dir() . '/config.json';
    $j = @is_file($f) ? json_decode((string)@file_get_contents($f), true) : null;
    $c = is_array($j) ? $j : [];
    // ON by default: the product provisions what it needs, and an operator who opens the investigation page
    // expects the answer to exist for the days before they asked. Switching it off is a decision, not a default.
    $c += ['enabled' => true, 'writes' => true];
    $c['enabled'] = !empty($c['enabled']);
    $c['writes']  = !empty($c['writes']);
    return $c;
}

function smpro_fa_cfg_save(array $c): bool {
    $f = smpro_fa_dir() . '/config.json';
    $keep = ['enabled' => !empty($c['enabled']), 'writes' => !empty($c['writes'])];
    return @file_put_contents($f, json_encode($keep, JSON_PRETTY_PRINT), LOCK_EX) !== false;
}

/**
 * The partitions home directories live on, from the accounts themselves - never a guessed "/home".
 * A server with /home2 or /home3 (a real one has 78 accounts on /home2) would otherwise be watched on the
 * wrong disk and report nothing, which reads exactly like nothing happened.
 */
function smpro_fa_roots(): array {
    $roots = [];
    foreach (glob('/var/cpanel/users/*') ?: [] as $f) {
        $u = basename($f);
        if (!preg_match('/^[a-zA-Z0-9._-]{1,64}$/', $u) || !function_exists('posix_getpwnam')) continue;
        $pw = @posix_getpwnam($u);
        $home = is_array($pw) ? (string)($pw['dir'] ?? '') : '';
        if ($home === '' || $home[0] !== '/') continue;
        $parts = explode('/', trim($home, '/'));
        if (count($parts) < 2) continue;                          // an account whose home is "/" or "/x" is not ours to watch
        $roots['/' . $parts[0]] = true;
    }
    if (!$roots) foreach (glob('/home*', GLOB_ONLYDIR) ?: [] as $d) if (preg_match('#^/home\d*$#', $d)) $roots[$d] = true;
    $out = array_keys($roots);
    sort($out);
    return $out;
}

/**
 * The executables behind the doors a PERSON uses, present on this server. Only what exists is named in a
 * rule: auditctl refuses a rule whose -F exe= path does not exist, and one refused line would fail the whole
 * file - so the list is built from the disk, not from memory.
 */
function smpro_fa_door_exes(): array {
    $cand = [
        'ftp'    => ['/usr/sbin/proftpd', '/usr/sbin/pure-ftpd', '/usr/local/sbin/pure-ftpd'],
        'cpanel' => ['/usr/local/cpanel/cpanel', '/usr/local/cpanel/cpsrvd', '/usr/local/cpanel/cpsrvd.so'],
        'sftp'   => ['/usr/libexec/openssh/sftp-server', '/usr/lib/openssh/sftp-server', '/usr/libexec/openssh/sshd-session', '/usr/sbin/sshd'],
    ];
    $out = [];
    foreach ($cand as $door => $paths) foreach ($paths as $p) if (@is_file($p) && !@is_link($p)) $out[$door][] = $p;
    return $out;
}

/**
 * The rules file, as text. Deterministic, so a re-provision that changes nothing writes nothing.
 *
 *   smpro_files_del   every unlink / rename / rmdir under a home root, by anyone through any door
 *   smpro_files_ses   every write under a home root from a LOGIN session (auid set): ssh, sftp, su, a shell
 *   smpro_files_door  every write by the FTP daemon or the cPanel binary (auid unset, so the rule above misses them)
 *
 * Web requests (php-fpm, lsphp, httpd) and cron are deliberately NOT in the write rules: a busy site writes
 * cache files thousands of times a minute and the log would rotate before it was read. Their deletes are still
 * recorded by the first rule, which is the one that matters for "who removed my files".
 */
function smpro_fa_rules_text(array $roots = [], array $doors = [], bool $writes = true): string {
    $roots = $roots ?: smpro_fa_roots();
    $doors = $doors ?: smpro_fa_door_exes();
    $l = ['## Safety Monitor Pro - file changes with actor, door and address (see includes/fileaudit.php)',
          '## Managed file: rewritten by the plugin. Removing it stops the file-change evidence, nothing else.'];
    foreach ($roots as $r) {
        $l[] = "-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat,renameat2,rmdir -F dir=$r -k " . SMPRO_FA_KEY . '_del';
        if (!$writes) continue;
        $l[] = "-a always,exit -F arch=b64 -S openat,openat2,creat,truncate,ftruncate -F dir=$r -F perm=w -F auid!=unset -k " . SMPRO_FA_KEY . '_ses';
        foreach ($doors as $door => $exes) foreach ($exes as $exe) {
            $l[] = "-a always,exit -F arch=b64 -S openat,openat2,creat,truncate,ftruncate -F dir=$r -F perm=w -F auid=unset -F exe=$exe -k " . SMPRO_FA_KEY . '_door';
        }
    }
    return implode("\n", $l) . "\n";
}

/* ============================================================================================ provisioning */

function smpro_fa_bin(string $name): string {
    foreach (['/usr/sbin/', '/sbin/', '/usr/bin/', '/bin/'] as $d) if (@is_executable($d . $name)) return $d . $name;
    return '';
}

/** Are OUR rules loaded in the kernel right now? Read back from auditctl, never assumed from the file. */
function smpro_fa_rules_live(): array {
    $ac = smpro_fa_bin('auditctl');
    if ($ac === '') return ['ok' => false, 'n' => 0, 'why' => 'auditctl is not installed'];
    $out = function_exists('smpro_run') ? smpro_run($ac . ' -l', 10) : (string)@shell_exec('timeout 10 ' . $ac . ' -l 2>&1');
    if (stripos($out, 'No rules') !== false) return ['ok' => false, 'n' => 0, 'why' => 'no audit rules are loaded'];
    if (preg_match('/Error|cannot|denied/i', $out) && strpos($out, SMPRO_FA_KEY) === false)
        return ['ok' => false, 'n' => 0, 'why' => 'auditctl could not list the rules: ' . trim(substr($out, 0, 120))];
    $n = preg_match_all('/key=' . preg_quote(SMPRO_FA_KEY, '/') . '_/', $out);
    return ['ok' => $n > 0, 'n' => (int)$n, 'why' => $n > 0 ? '' : 'the file-change rules are not loaded'];
}

/**
 * Make the evidence exist: auditd present and running, our rules on disk and in the kernel.
 * Idempotent and cheap when nothing changed. Returns what it did and what it could not do.
 */
function smpro_fa_provision(bool $force = false): array {
    $cfg = smpro_fa_cfg();
    $did = []; $why = '';
    if (!$cfg['enabled']) {
        if (@is_file(SMPRO_FA_RULES)) { @unlink(SMPRO_FA_RULES); smpro_fa_load_rules(); $did[] = 'rules removed (feature off)'; }
        return ['ok' => true, 'did' => $did, 'why' => 'off'];
    }
    // 1. auditd itself - install if the package manager can, enable if present.
    if (smpro_fa_bin('auditctl') === '') {
        // The install is DETACHED (the per-minute tick is killed at 110 s, and a package manager killed mid-transaction
        // leaves a broken rpm/dpkg database), attempted at most once a day, and never behind a busy package manager.
        $flag = SMPRO_VARLIB . '/fileaudit_install_attempt';
        $recent = @is_file($flag) && (time() - (int)@filemtime($flag)) < 86400;
        if (!$recent && function_exists('smpro_pkg_mgr') && smpro_pkg_mgr() !== '' && !(function_exists('smpro_pkg_mgr_busy') && smpro_pkg_mgr_busy())) {
            $pm = smpro_pkg_mgr();
            $cmd = $pm === 'apt' ? 'DEBIAN_FRONTEND=noninteractive apt-get install -y auditd' : ($pm . ' install -y audit');
            @is_dir(SMPRO_VARLIB) || @mkdir(SMPRO_VARLIB, 0700, true); @touch($flag);
            @shell_exec('nohup setsid sh -c ' . escapeshellarg('timeout 900 ' . $cmd) . ' >/dev/null 2>&1 &');
            $did[] = 'auditd install started in the background (checked again next tick)';
        }
        return ['ok' => false, 'did' => $did, 'why' => $recent ? 'auditd is not installed (an install was attempted in the last 24 h - install the "audit" package by hand if it keeps failing)' : 'auditd is not installed - installing'];
    }
    $sc = smpro_fa_bin('systemctl');
    if ($sc !== '') {
        $act = trim((string)@shell_exec('timeout 10 ' . $sc . ' is-active auditd 2>/dev/null'));
        if ($act !== 'active') {
            @shell_exec('timeout 60 ' . $sc . ' enable --now auditd >/dev/null 2>&1');
            $act = trim((string)@shell_exec('timeout 10 ' . $sc . ' is-active auditd 2>/dev/null'));
            $did[] = $act === 'active' ? 'auditd started' : 'auditd could not be started';
            if ($act !== 'active') return ['ok' => false, 'did' => $did, 'why' => 'auditd is installed but not running'];
        }
    }
    // 2. the rules file - only rewritten when its text changes.
    $want = smpro_fa_rules_text([], [], $cfg['writes']);
    $have = @is_file(SMPRO_FA_RULES) ? (string)@file_get_contents(SMPRO_FA_RULES) : '';
    if ($force || $have !== $want) {
        @is_dir(dirname(SMPRO_FA_RULES)) || @mkdir(dirname(SMPRO_FA_RULES), 0750, true);
        if (@file_put_contents(SMPRO_FA_RULES . '.tmp', $want, LOCK_EX) === false || !@rename(SMPRO_FA_RULES . '.tmp', SMPRO_FA_RULES)) {
            return ['ok' => false, 'did' => $did, 'why' => 'could not write ' . SMPRO_FA_RULES];
        }
        @chmod(SMPRO_FA_RULES, 0640);
        $did[] = 'rules written';
        $l = smpro_fa_load_rules();
        $did[] = $l['ok'] ? 'rules loaded' : ('rules NOT loaded: ' . $l['why']);
        if (!$l['ok']) $why = $l['why'];
    } else {
        $live = smpro_fa_rules_live();
        if (!$live['ok']) { $l = smpro_fa_load_rules(); $did[] = $l['ok'] ? 'rules re-loaded' : ('rules NOT loaded: ' . $l['why']); if (!$l['ok']) $why = $l['why']; }
    }
    $live = smpro_fa_rules_live();
    if (function_exists('smpro_audit') && $did) @smpro_audit('fileaudit_provision', ['did' => $did, 'live_rules' => $live['n']]);
    return ['ok' => $live['ok'], 'did' => $did, 'why' => $live['ok'] ? '' : ($why ?: $live['why'])];
}

/** Load /etc/audit/rules.d into the kernel. augenrules when present (the distro way), auditctl -R otherwise. */
function smpro_fa_load_rules(): array {
    $ag = smpro_fa_bin('augenrules'); $ac = smpro_fa_bin('auditctl');
    $out = '';
    if ($ag !== '')      $out = (string)@shell_exec('timeout 60 ' . $ag . ' --load 2>&1');
    elseif ($ac !== '')  $out = (string)@shell_exec('timeout 60 ' . $ac . ' -R ' . escapeshellarg(SMPRO_FA_RULES) . ' 2>&1');
    else return ['ok' => false, 'why' => 'neither augenrules nor auditctl is available'];
    // "-e 2" makes the rule set immutable until reboot: a hardened box. Say so; do not pretend.
    if (stripos($out, 'immutable') !== false || stripos($out, 'Operation not permitted') !== false)
        return ['ok' => false, 'why' => 'the audit rule set is locked (immutable) until the next reboot'];
    $live = smpro_fa_rules_live();
    return ['ok' => $live['ok'], 'why' => $live['ok'] ? '' : ($live['why'] . (trim($out) !== '' ? ' (' . trim(substr($out, 0, 160)) . ')' : ''))];
}

/* ============================================================================================ collection */

function smpro_fa_state_path(): string { return smpro_fa_dir() . '/state.json'; }

function smpro_fa_state(): array {
    $j = @is_file(smpro_fa_state_path()) ? json_decode((string)@file_get_contents(smpro_fa_state_path()), true) : null;
    $s = is_array($j) ? $j : [];
    $s += ['inode' => 0, 'offset' => 0, 'last_run' => 0, 'last_record' => 0, 'records' => 0, 'ses_ip' => [], 'ftp_ip' => [], 'blind' => ''];
    return $s;
}

function smpro_fa_state_save(array $s): void {
    // The session->address maps are bounded, or a year of logins would live in every write of this file.
    foreach (['ses_ip', 'ftp_ip'] as $k) if (count($s[$k]) > 2000) $s[$k] = array_slice($s[$k], -1000, null, true);
    $tmp = smpro_fa_state_path() . '.tmp';
    if (@file_put_contents($tmp, json_encode($s), LOCK_EX) !== false) @rename($tmp, smpro_fa_state_path());
}

/**
 * Parse one audit event (the SYSCALL + CWD + PATH + PROCTITLE lines that share a msg id) into the record we keep.
 * Returns null for events that are not ours or carry nothing usable.
 *
 * Every field comes from the record itself. The account is the owner of the home root in the path, NOT the
 * uid: root deleting a customer's file from a shell is exactly the event the account's owner will ask about.
 */
function smpro_fa_parse_event(array $lines): ?array {
    $sys = null; $paths = []; $cwd = '';
    foreach ($lines as $ln) {
        if (strpos($ln, 'type=SYSCALL ') === 0)      $sys = $ln;
        elseif (strpos($ln, 'type=PATH ') === 0)     $paths[] = $ln;
        elseif (strpos($ln, 'type=CWD ') === 0 && preg_match('/ cwd="([^"]*)"/', $ln, $m)) $cwd = $m[1];
    }
    if ($sys === null || !preg_match('/ key="?(' . preg_quote(SMPRO_FA_KEY, '/') . '_[a-z]+)"?/', $sys, $km)) return null;
    if (!preg_match('/msg=audit\((\d+)\.\d+:(\d+)\)/', $sys, $mm)) return null;
    $f = [];
    foreach (['syscall', 'success', 'pid', 'ppid', 'auid', 'uid', 'ses', 'comm', 'exe', 'SYSCALL', 'UID', 'AUID'] as $k) {
        if (preg_match('/(?:^|\s)' . $k . '=("?)([^"\s]*)\1/', $sys, $m)) $f[$k] = $m[2];
    }
    if (($f['success'] ?? '') !== 'yes') return null;                    // an attempt that failed changed nothing
    $sc = (string)($f['SYSCALL'] ?? '');
    if ($sc === '') $sc = smpro_fa_syscall_name((int)($f['syscall'] ?? -1));

    // Which PATH item is the thing that changed. nametype tells us exactly, when the log is ENRICHED or not.
    $target = ''; $from = ''; $op = '';
    foreach ($paths as $p) {
        if (!preg_match('/ name="?([^"\s]*)"?/', $p, $nm)) continue;
        $name = $nm[1]; $nt = preg_match('/ nametype=(\w+)/', $p, $t) ? $t[1] : '';
        if ($name === '' || $name === '(null)') continue;
        if ($name[0] !== '/') $name = rtrim($cwd, '/') . '/' . $name;
        if ($nt === 'DELETE')      { if ($sc === 'rename' || $sc === 'renameat' || $sc === 'renameat2') { if ($from === '') $from = $name; } else { $target = $name; $op = 'deleted'; } }
        elseif ($nt === 'CREATE')  { $target = $name; $op = ($sc === 'rename' || $sc === 'renameat' || $sc === 'renameat2') ? 'renamed' : 'created'; }
        elseif ($nt === 'NORMAL')  { if ($target === '') { $target = $name; $op = $op ?: 'modified'; } }
    }
    if ($target === '') return null;
    if ($op === 'renamed' && $from === '') $from = '';
    if ($sc === 'rmdir') $op = 'deleted';
    if (in_array($sc, ['truncate', 'ftruncate'], true)) $op = 'modified';

    $account = smpro_fa_account_of($target);
    $exe = (string)($f['exe'] ?? '');
    // A chrooted process (proftpd under DefaultRoot) reports its cwd as "/" and the name relative to the jail, so
    // the path built above is "/fa_up.txt" and belongs to nobody. The uid still says whose process it was: the
    // FTP daemon has already become the account. The path is completed later, from the FTP login's home.
    $chroot = false;
    if ($account === '' && isset($f['uid']) && function_exists('posix_getpwuid')) {
        $pw = @posix_getpwuid((int)$f['uid']);
        $n = is_array($pw) ? (string)$pw['name'] : '';
        if ($n !== '' && @is_file('/var/cpanel/users/' . $n)) { $account = $n; $chroot = true; }
    }
    $door = smpro_fa_door($exe, (string)($f['comm'] ?? ''), (string)($f['auid'] ?? ''), (string)($f['ppid'] ?? ''));
    $actor = (string)($f['UID'] ?? '');
    if ($actor === '' && isset($f['uid']) && function_exists('posix_getpwuid')) { $pw = @posix_getpwuid((int)$f['uid']); $actor = is_array($pw) ? (string)$pw['name'] : (string)$f['uid']; }
    $login = (string)($f['AUID'] ?? '');
    if ($login === 'unset' || $login === '-1' || $login === '4294967295') $login = '';
    if ($login === '' && isset($f['auid']) && $f['auid'] !== 'unset' && (int)$f['auid'] >= 0 && (int)$f['auid'] !== 4294967295 && function_exists('posix_getpwuid')) {
        $pw = @posix_getpwuid((int)$f['auid']); $login = is_array($pw) ? (string)$pw['name'] : '';
    }
    return ['ts' => (int)$mm[1], 'id' => (int)$mm[2], 'key' => $km[1], 'op' => $op, 'path' => $target, 'from' => $from,
            'account' => $account, 'actor' => $actor, 'login' => $login, 'door' => $door, 'exe' => $exe,
            'comm' => (string)($f['comm'] ?? ''), 'pid' => (int)($f['pid'] ?? 0), 'ses' => (string)($f['ses'] ?? ''),
            'ip' => '', 'ip_how' => '', 'chroot' => $chroot];
}

function smpro_fa_syscall_name(int $n): string {
    static $map = [87 => 'unlink', 263 => 'unlinkat', 82 => 'rename', 264 => 'renameat', 316 => 'renameat2', 84 => 'rmdir',
                   257 => 'openat', 437 => 'openat2', 85 => 'creat', 76 => 'truncate', 77 => 'ftruncate', 2 => 'open'];
    return $map[$n] ?? ('syscall' . $n);
}

/** The cPanel account whose home holds this path: /home2/USER/... -> USER. '' when it is nobody's. */
function smpro_fa_account_of(string $path): string {
    if (preg_match('#^/home\d*/([a-zA-Z0-9._-]{1,64})(?:/|$)#', $path, $m)) return $m[1];
    return '';
}

/** Which door a change came through, from the executable and the login state. Named, never guessed. */
function smpro_fa_door(string $exe, string $comm, string $auid, string $ppid): string {
    $b = basename($exe);
    $inSession = ($auid !== '' && $auid !== 'unset' && $auid !== '4294967295' && $auid !== '-1');
    if (preg_match('/^(sftp-server|sshd|sshd-session)$/', $b))                        return 'sftp';
    if (preg_match('/^(proftpd|pure-ftpd|pure-uploadscript)$/', $b))                  return 'ftp';
    // A login session is a shell whatever it ran: `uapi` typed by root over ssh is not the File Manager, and
    // labelling it "cpanel" would send the address join to the wrong log and come back empty.
    if ($inSession)                                                                     return 'shell';
    if (strpos($exe, '/usr/local/cpanel/') === 0)                                      return 'cpanel';
    if (preg_match('/^(php-fpm|lsphp|httpd|php-cgi|nginx|litespeed|lshttpd)/', $b) || strpos($exe, '/opt/cpanel/ea-php') === 0 || strpos($exe, '/usr/local/lsws/') === 0) return 'web';
    if (preg_match('/^(crond|cron|CRON)$/', $b))                                       return 'cron';
    if (preg_match('/^(exim|dovecot|imap|pop3|lmtp|lda|dovecot-lda|cpanellogd|cpbackup|pkgacct|rsync|restic|jetbackup)/', $b)) return 'system';
    return 'other';
}

/**
 * Read the audit log forward from the checkpoint and file every record of ours. Follows a rotation: when the
 * inode under /var/log/audit/audit.log changes, the previous file is finished first (it is audit.log.1 now).
 */
function smpro_fa_collect(int $budgetSec = 40): array {
    $st = smpro_fa_state();
    $st['last_run'] = time();
    $deadline = time() + max(5, $budgetSec);
    $n = 0; $blind = '';

    if (!@is_readable(SMPRO_FA_AUDITLOG)) {
        $st['blind'] = 'the audit log ' . SMPRO_FA_AUDITLOG . ' is not readable';
        smpro_fa_state_save($st);
        return ['ok' => false, 'records' => 0, 'why' => $st['blind']];
    }
    $cur = @stat(SMPRO_FA_AUDITLOG);
    $files = [];
    if ((int)$st['inode'] > 0 && (int)$st['inode'] !== (int)$cur['ino']) {
        // rotated since last time: find the file we were reading and finish it
        foreach (glob(SMPRO_FA_AUDITLOG . '.*') ?: [] as $old) {
            $os = @stat($old);
            if ($os && (int)$os['ino'] === (int)$st['inode']) { $files[] = [$old, (int)$st['offset']]; break; }
        }
        $files[] = [SMPRO_FA_AUDITLOG, 0];
    } else {
        $off = (int)$st['inode'] === (int)$cur['ino'] ? (int)$st['offset'] : 0;
        if ($off > (int)$cur['size']) $off = 0;                        // truncated in place
        $files[] = [SMPRO_FA_AUDITLOG, $off];
    }

    $pending = []; $pendingId = '';
    $flush = function () use (&$pending, &$pendingId, &$st, &$n) {
        if ($pendingId === '') return;
        $rec = smpro_fa_parse_event($pending);
        if ($rec !== null && $rec['account'] !== '' && !smpro_fa_is_noise($rec['path'])) {
            smpro_fa_join_ip($rec, $st);
            if (smpro_fa_store($rec)) { $n++; $st['last_record'] = $rec['ts']; }
        }
        $pending = []; $pendingId = '';
    };

    foreach ($files as [$path, $offset]) {
        $fh = @fopen($path, 'r');
        if (!$fh) continue;
        if ($offset > 0) fseek($fh, $offset);
        while (($ln = fgets($fh)) !== false) {
            if (time() > $deadline) { $blind = 'collection ran out of time; it will continue next minute'; break; }
            // USER_LOGIN carries the address of every ssh session; remembered by session id for the join below.
            if (strpos($ln, 'type=USER_LOGIN ') === 0) {
                if (preg_match('/ ses=(\d+) .*addr=([0-9a-fA-F.:]+) .*res=success/', $ln, $m)) $st['ses_ip'][$m[1]] = $m[2];
                continue;
            }
            if (!preg_match('/^type=(SYSCALL|CWD|PATH|PROCTITLE|EOE) msg=audit\((\d+\.\d+:\d+)\)/', $ln, $m)) continue;
            if ($m[2] !== $pendingId) { $flush(); $pendingId = $m[2]; }
            if ($m[1] === 'SYSCALL' && strpos($ln, SMPRO_FA_KEY . '_') === false) { $pendingId = ''; $pending = []; continue; }   // not ours - skip the whole event
            if ($pendingId !== '') $pending[] = rtrim($ln, "\n");
        }
        $pos = ftell($fh);
        fclose($fh);
        if ($path === SMPRO_FA_AUDITLOG) { $st['inode'] = (int)$cur['ino']; $st['offset'] = (int)$pos; }
        if ($blind !== '') break;
    }
    $flush();
    $st['records'] = (int)$st['records'] + $n;
    $st['blind'] = $blind;
    smpro_fa_state_save($st);
    return ['ok' => true, 'records' => $n, 'why' => $blind];
}

/** Paths whose churn is machinery, not a person: never worth a row, never worth the disk. */
function smpro_fa_is_noise(string $p): bool {
    return (bool)preg_match('#/(\.cagefs|virtfs|\.cpanel/(caches|datastore|nvdata)|\.cphorde|tmp|\.trash|mail|etc|logs|access-logs|\.cache|cache|wp-content/cache|storage/framework|var/cache|sessions?|\.php-sessions)/#', $p . '/')
        || (bool)preg_match('#/(\.bash_history|\.lesshst|\.viminfo|error_log|\.ftpquota|\.htpasswd\.tmp)$#', $p)
        || (bool)preg_match('#\.lock-[0-9a-f-]+$#', $p) || (bool)preg_match('#/\.tmp\.[0-9a-f]+\.#', $p)   // the cPanel editor's lock + temp
        // Measured on the first production day: 512 of 607 records were WordPress probing whether a folder is
        // writable (create + delete a temp-write-test file on every request), cPanel's sub-account sqlite journal
        // and Wordfence's log rotation. Machinery, not a person.
        || (bool)preg_match('#/temp-write-test-[0-9a-f-]+$#', $p) || strpos($p, '/.subaccounts/') !== false
        || strpos($p, '/wp-content/wflogs/') !== false || (bool)preg_match('#/\.lastlogin$#', $p)
        || (bool)preg_match('#\.(log|tmp|swp|swx|lock|pid|sock|part)$#', $p)
        || strpos($p, '/.siteprotection/') !== false;
}

/** Attach the address the change came from, from the log that knows it. Leaves '' when nothing does. */
function smpro_fa_join_ip(array &$rec, array &$st): void {
    if ($rec['door'] === 'shell' || $rec['door'] === 'sftp') {
        if ($rec['ses'] !== '' && isset($st['ses_ip'][$rec['ses']])) { $rec['ip'] = $st['ses_ip'][$rec['ses']]; $rec['ip_how'] = 'ssh session ' . $rec['ses']; return; }
        // a session that began before our checkpoint: look it up once in the log we have
        $ip = smpro_fa_ses_ip_lookup($rec['ses']);
        if ($ip !== '') { $st['ses_ip'][$rec['ses']] = $ip; $rec['ip'] = $ip; $rec['ip_how'] = 'ssh session ' . $rec['ses']; }
        return;
    }
    if ($rec['door'] === 'ftp') {
        $key = (string)$rec['pid'];
        if (!isset($st['ftp_ip'][$key]) || !is_array($st['ftp_ip'][$key])) {
            $s = smpro_fa_ftp_session_lookup($rec['pid']);
            if ($s['ip'] !== '' || $s['login'] !== '') $st['ftp_ip'][$key] = $s;
        }
        $s = (isset($st['ftp_ip'][$key]) && is_array($st['ftp_ip'][$key])) ? $st['ftp_ip'][$key] : ['ip' => '', 'login' => ''];
        if ($s['ip'] !== '')    { $rec['ip'] = $s['ip']; $rec['ip_how'] = 'ftp session pid ' . $rec['pid']; }
        if ($s['login'] !== '') { $rec['actor'] = $s['login']; }
        // proftpd is jailed in the FTP login's home, so the kernel saw "/x.txt". Put the jail back in front.
        if (!empty($rec['chroot'])) {
            $home = smpro_fa_ftp_home($rec['account'], $s['login']);
            if ($home !== '') {
                $rec['path'] = rtrim($home, '/') . $rec['path'];
                if ($rec['from'] !== '') $rec['from'] = rtrim($home, '/') . $rec['from'];
                $rec['chroot'] = false;
            }
        }
        return;
    }
    if ($rec['door'] === 'cpanel') {
        [$ip, $how] = smpro_fa_cpanel_ip_lookup($rec['actor'] !== '' ? $rec['actor'] : $rec['account'], $rec['ts']);
        if ($ip !== '') { $rec['ip'] = $ip; $rec['ip_how'] = $how; }
    }
}

function smpro_fa_ses_ip_lookup(string $ses): string {
    if ($ses === '' || !ctype_digit($ses)) return '';
    $out = (string)@shell_exec('timeout 8 grep -a -m1 -E ' . escapeshellarg('type=USER_LOGIN .* ses=' . $ses . ' .*res=success') . ' ' . escapeshellarg(SMPRO_FA_AUDITLOG) . ' 2>/dev/null');
    return preg_match('/addr=([0-9a-fA-F.:]+)/', $out, $m) ? $m[1] : '';
}

/**
 * proftpd / pure-ftpd write "session opened" and "USER x: Login successful" with the child's pid and the client
 * address to syslog. The same pid is on the audit record, so this is a join, not a guess.
 */
function smpro_fa_ftp_session_lookup(int $pid): array {
    $r = ['ip' => '', 'login' => ''];
    if ($pid <= 0) return $r;
    foreach (['/var/log/messages', '/var/log/syslog'] as $log) {
        if (!@is_readable($log)) continue;
        $out = (string)@shell_exec('timeout 8 grep -a -E ' . escapeshellarg('(proftpd|pure-ftpd)\[' . $pid . '\]') . ' ' . escapeshellarg($log) . ' 2>/dev/null | tail -n 8');
        if ($out === '') continue;
        if (preg_match('/\(([0-9a-fA-F.:]+)\[[0-9a-fA-F.:]+\]\)/', $out, $m)) $r['ip'] = $m[1];          // proftpd: (host[ip])
        elseif (preg_match('/\(\?@([0-9a-fA-F.:]+)\)/', $out, $m)) $r['ip'] = $m[1];                      // pure-ftpd: (?@ip)
        elseif (preg_match('/from ([0-9a-fA-F.:]+)/', $out, $m)) $r['ip'] = $m[1];
        if (preg_match('/USER ([^\s:]+): Login successful/', $out, $m)) $r['login'] = $m[1];             // proftpd
        elseif (preg_match('/\[INFO\] ([^\s]+) is now logged in/', $out, $m)) $r['login'] = $m[1];       // pure-ftpd
        if ($r['ip'] !== '') break;
    }
    return $r;
}

/** The directory an FTP login is jailed in: the account's home for the main login, the sub-login's own dir otherwise. */
function smpro_fa_ftp_home(string $account, string $login): string {
    $pw = function_exists('posix_getpwnam') ? @posix_getpwnam($account) : null;
    $home = is_array($pw) ? (string)($pw['dir'] ?? '') : '';
    if ($login === '' || $login === $account || strpos($login, '@') === false) return $home;
    // cPanel keeps one file per account AND a merged one; a login that has just been removed is in neither, and
    // then the account's home is the honest fallback (the path is still inside that account).
    foreach (['/etc/proftpd/' . $account, '/etc/proftpd/passwd.vhosts', '/etc/pure-ftpd/' . $account] as $f) {
        foreach ((array)@file($f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $ln) {
            $c = explode(':', (string)$ln);
            if (count($c) >= 6 && $c[0] === $login && $c[5] !== '' && $c[5][0] === '/') return $c[5];
        }
    }
    return $home;
}

/**
 * The cPanel access log line for the same user in the same moment. A File Manager change is made while its
 * request is in flight, so the request line lands within a second or two of the syscall. One candidate
 * address in the window is a join; two different ones is "one of these", said as such.
 */
function smpro_fa_cpanel_ip_lookup(string $user, int $ts): array {
    $log = '/usr/local/cpanel/logs/access_log';
    if ($user === '' || !@is_readable($log)) return ['', ''];
    $needle = ' - ' . $user . ' [';
    $out = (string)@shell_exec('timeout 8 grep -a -F ' . escapeshellarg($needle) . ' ' . escapeshellarg($log) . ' 2>/dev/null | tail -n 400');
    $ips = []; $tokens = [];
    foreach (explode("\n", $out) as $ln) {
        if (!preg_match('#^(\S+) - \S+ \[(\d\d)/(\d\d)/(\d{4}):(\d\d):(\d\d):(\d\d) ([+-]\d{4})\] "\w+ (\S+)#', $ln, $m)) continue;
        $t = gmmktime((int)$m[5], (int)$m[6], (int)$m[7], (int)$m[2], (int)$m[3], (int)$m[4]);
        $t -= ((int)substr($m[8], 0, 3)) * 3600 + ((int)substr($m[8], 3, 2)) * 60 * ((int)substr($m[8], 0, 3) < 0 ? -1 : 1);
        if (abs($t - $ts) > 3) continue;
        if (!preg_match('#(Fileman|filemanager|fileop|upload|savefile|editit|/execute/|json-api)#i', $m[9])) continue;
        $ips[$m[1]] = ($ips[$m[1]] ?? 0) + 1;
        if (preg_match('#^/(cpsess\d{6,12})/#', $m[9], $tk)) $tokens[$tk[1]] = 1;
    }
    if (!$ips) return ['', ''];
    // cpsrvd behind the service-subdomain proxy (cpanel.<domain> through nginx or Apache) sees every visitor as
    // 127.0.0.1 and keeps no forwarded address. The session token is in every request line, and the proxy logged
    // the same line with the real address: the token is the join, not the clock.
    $loop = array_filter(array_keys($ips), fn($ip) => in_array($ip, ['127.0.0.1', '::1'], true));
    if ($loop && count($loop) === count($ips) && $tokens) {
        foreach (array_keys($tokens) as $tok) {
            [$rip, $rhow] = smpro_fa_proxy_ip_for_token($tok);
            if ($rip !== '') return [$rip, $rhow];
        }
        return ['127.0.0.1', 'cpanel through a local proxy; the real address was not found in the proxy logs for session ' . implode(', ', array_keys($tokens))];
    }
    if (count($ips) === 1) return [array_key_first($ips), 'cpanel request in the same second'];
    arsort($ips);
    return [array_key_first($ips), 'one of ' . count($ips) . ' cpanel addresses active in the same second: ' . implode(', ', array_keys($ips))];
}

/**
 * The real client address of a cPanel session that reached cpsrvd through the local service-subdomain proxy.
 * Reads the front proxy's own logs (ea-nginx per-vhost logs for cpanel.* / webmail.* / whm.*, the nginx main log,
 * and Apache's proxy-subdomains log) for request lines carrying the session token. A Cloudflare edge address is
 * returned AS a Cloudflare edge and says so: it is not the visitor, and the record must not pretend it is.
 */
function smpro_fa_proxy_ip_for_token(string $token): array {
    if (!preg_match('/^cpsess\d{6,12}$/', $token)) return ['', ''];
    // WebShield (owns cPanel's ports on an Imunify server), the nginx/Apache service-subdomain vhosts and the main
    // proxy log - every one discovered from the running configuration, none named here
    if (!function_exists('smpro_front_logs_all')) { $fl = __DIR__ . '/frontlogs.php'; if (is_file($fl)) require_once $fl; }
    $logs = function_exists('smpro_front_logs_all') ? smpro_front_logs_all() : [];
    if (!$logs) return ['', ''];
    $cmd = 'timeout 10 grep -a -h -F ' . escapeshellarg('/' . $token . '/');
    foreach ($logs as $f) $cmd .= ' ' . escapeshellarg($f);
    $out = (string)@shell_exec($cmd . ' 2>/dev/null | tail -n 200');
    $seen = [];
    foreach (explode("\n", $out) as $ln) {
        // ea-nginx cp_combined starts "server:port addr - user [...]", common/combined starts "addr - user [...]"
        if (!preg_match('/^(?:\S+:\d+\s+)?([0-9a-fA-F.:]+)\s+-\s+/', trim($ln), $m)) continue;
        $ip = $m[1];
        if (!filter_var($ip, FILTER_VALIDATE_IP) || in_array($ip, ['127.0.0.1', '::1'], true)) continue;
        $seen[$ip] = ($seen[$ip] ?? 0) + 1;
    }
    if (!$seen) return ['', ''];
    arsort($seen); $ip = (string)array_key_first($seen);
    if (!function_exists('smpro_ip_is_cloudflare')) { $fi = __DIR__ . '/intrusion.php'; if (is_file($fi)) require_once $fi; }
    if (function_exists('smpro_ip_is_cloudflare') && smpro_ip_is_cloudflare($ip))
        return [$ip, 'Cloudflare edge for cpanel session ' . $token . ' - the visitor is hidden behind it (the proxy is not restoring the real address)'];
    return [$ip, 'proxy log for cpanel session ' . $token . (count($seen) > 1 ? ' (also: ' . implode(', ', array_slice(array_keys($seen), 1, 3)) . ')' : '')];
}

/** Append one record to the account's day file. */
function smpro_fa_store(array $rec): bool {
    $dir = smpro_fa_dir() . '/' . $rec['account'];
    if (!@is_dir($dir)) { @mkdir($dir, 0700, true); }
    $f = $dir . '/' . gmdate('Y-m-d', $rec['ts']) . '.jsonl';
    return @file_put_contents($f, json_encode($rec, JSON_UNESCAPED_SLASHES) . "\n", FILE_APPEND | LOCK_EX) !== false;
}

/* ============================================================================================ reading */

/**
 * The file changes of one account in [from,to], newest first. Bounded by $limit.
 * ['ok'=>bool,'events'=>[...],'why'=>'',...] - ok=false means "could not look", not "nothing happened".
 */
function smpro_fa_events(string $account, int $from, int $to, int $limit = 2000): array {
    $account = preg_replace('/[^a-zA-Z0-9._-]/', '', $account);
    $status = smpro_fa_status();
    $dir = SMPRO_FA_DIR . '/' . $account;
    $out = [];
    if ($account !== '' && @is_dir($dir)) {
        for ($d = $to; $d >= $from - 86400; $d -= 86400) {
            $f = $dir . '/' . gmdate('Y-m-d', $d) . '.jsonl';
            if (!@is_file($f)) continue;
            foreach (array_reverse((array)@file($f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES)) as $ln) {
                $r = json_decode($ln, true);
                if (!is_array($r) || (int)$r['ts'] < $from || (int)$r['ts'] > $to) continue;
                $out[] = $r;
                if (count($out) >= $limit) break 2;
            }
        }
    }
    usort($out, fn($a, $b) => ($b['ts'] <=> $a['ts']) ?: ($b['id'] <=> $a['id']));
    $doors = []; $ips = []; $ops = [];
    foreach ($out as $r) { $doors[$r['door']] = ($doors[$r['door']] ?? 0) + 1; if ($r['ip'] !== '') $ips[$r['ip']] = 1; $ops[$r['op']] = ($ops[$r['op']] ?? 0) + 1; }
    // The window is only covered from the moment the collector first ran. Before that, the evidence does not exist.
    $since = smpro_fa_first_record_ts();
    return ['ok' => $status['ok'], 'why' => $status['why'], 'events' => $out, 'doors' => $doors, 'ips' => count($ips), 'ops' => $ops,
            'covered_from' => $since, 'partial' => ($since > 0 && $since > $from), 'status' => $status];
}

function smpro_fa_first_record_ts(): int {
    $f = SMPRO_FA_DIR . '/first_record';
    if (@is_file($f)) return (int)@file_get_contents($f);
    $st = smpro_fa_state();
    if ((int)$st['last_record'] > 0) { @file_put_contents($f, (string)$st['last_run']); return (int)$st['last_run']; }
    return 0;
}

/** Is the evidence being made and collected right now? Every "no" comes with its reason. */
function smpro_fa_status(): array {
    $cfg = smpro_fa_cfg();
    if (!$cfg['enabled']) return ['ok' => false, 'why' => 'file-change evidence is switched off', 'state' => 'off'];
    if (smpro_fa_bin('auditctl') === '') return ['ok' => false, 'why' => 'auditd is not installed on this server', 'state' => 'missing'];
    $sc = smpro_fa_bin('systemctl');
    if ($sc !== '' && trim((string)@shell_exec('timeout 10 ' . $sc . ' is-active auditd 2>/dev/null')) !== 'active')
        return ['ok' => false, 'why' => 'auditd is installed but not running', 'state' => 'stopped'];
    $live = smpro_fa_rules_live();
    if (!$live['ok']) return ['ok' => false, 'why' => $live['why'], 'state' => 'norules'];
    $st = smpro_fa_state();
    if ((int)$st['last_run'] === 0) return ['ok' => false, 'why' => 'the collector has not run yet', 'state' => 'notrun'];
    if (time() - (int)$st['last_run'] > 600) return ['ok' => false, 'why' => 'the collector last ran ' . intdiv(time() - (int)$st['last_run'], 60) . ' minutes ago - its cron is not running', 'state' => 'stale'];
    if (!@is_file('/etc/cron.d/smpro-fileaudit')) return ['ok' => false, 'why' => 'the collector is not scheduled', 'state' => 'nocron'];
    return ['ok' => true, 'why' => '', 'state' => 'ok', 'rules' => $live['n'], 'records' => (int)$st['records'], 'last_run' => (int)$st['last_run']];
}

/* ============================================================================================ housekeeping */

function smpro_fa_prune(): int {
    $n = 0; $cut = gmdate('Y-m-d', time() - SMPRO_FA_KEEP_DAYS * 86400);
    foreach (glob(SMPRO_FA_DIR . '/*/????-??-??.jsonl') ?: [] as $f) {
        if (basename($f, '.jsonl') < $cut && @unlink($f)) $n++;
    }
    return $n;
}

function smpro_fa_cron_sync() {
    $f = '/etc/cron.d/smpro-fileaudit';
    if (!is_file(SMPRO_BASE . '/bin/fileaudit_tick.php')) { if (is_file($f)) @unlink($f); return; }
    if (defined('SMPRO_TEST_SRC')) return true;                         // a test must never install a live cron
    $php = function_exists('smpro_php_cli_bin') ? smpro_php_cli_bin() : '/usr/local/cpanel/3rdparty/bin/php';
    $ld  = SMPRO_VARLIB . '/locks'; @is_dir($ld) || @mkdir($ld, 0700, true);
    $flock = is_executable('/usr/bin/flock') ? '/usr/bin/flock' : 'flock';
    $want = "# Safety Monitor Pro - file-change evidence: collect who/door/address/when from auditd every minute\n"
          // Every minute because the raw audit log is a conveyor belt: 5 x 8 MB, minutes of history on a busy server.
          . "* * * * * root $flock -n $ld/fileaudit.cron.lock timeout 110 $php " . SMPRO_BASE . "/bin/fileaudit_tick.php >/dev/null 2>&1\n";
    if (is_file($f) && (string)@file_get_contents($f) === $want) return true;
    if (function_exists('smpro_cron_install')) return smpro_cron_install($f, $want);
    return @file_put_contents($f, $want) !== false;
}

/** One tick: make sure the evidence exists, collect it, prune the old. Called by bin/fileaudit_tick.php. */
function smpro_fa_run(): array {
    $cfg = smpro_fa_cfg();
    if (!$cfg['enabled']) return ['ok' => true, 'records' => 0, 'why' => 'off'];
    $p = smpro_fa_provision();
    $c = $p['ok'] ? smpro_fa_collect() : ['ok' => false, 'records' => 0, 'why' => $p['why']];
    if (!$p['ok']) { $st = smpro_fa_state(); $st['last_run'] = time(); $st['blind'] = $p['why']; smpro_fa_state_save($st); }
    static $pruned = false;
    if (!$pruned && (int)date('i') === 7) { smpro_fa_prune(); $pruned = true; }
    return ['ok' => $c['ok'], 'records' => (int)$c['records'], 'why' => (string)$c['why'], 'provision' => $p];
}
