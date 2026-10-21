<?php
/**
 * includes/sysupd.php — System updates: the server's own packages (dnf), cPanel's build, and the kernel.
 *
 * WHY THIS FILE EXISTS. Updates arrive on their own schedule and fail quietly: a mirror that stops answering, a
 * repository whose metadata will not download, a stale package lock, a damaged rpm database - and the nightly job
 * that was supposed to patch a critical PHP release just does nothing, every night, while every page says the
 * server is fine. This section looks every few hours, SHOWS what is pending (and what it is: kernel, PHP, security),
 * tells the operator through their channels when something new appears, applies it by itself or waits for the
 * button - as the operator chose - and when a download breaks it diagnoses the break, repairs the kinds it can
 * (cache, lock, rpm database, one bad repository), and reports the kind it cannot, by name.
 *
 * Three rules it keeps:
 *   - "Could not check" and "nothing to update" are different facts and are never shown the same.
 *   - It never reboots. A new kernel is installed to disk and the page says "reboot pending", with the live-patch
 *     state (KernelCare) beside it, so the operator decides.
 *   - Every apply is logged whole (the tool's own output), audited, and followed by a service check; a service that
 *     stopped is restarted once and said.
 * No server, mirror, package or address is named in this code: the lists come from dnf and cPanel on the server.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit; }

define('SMPRO_SU_DIR',   SMPRO_VARLIB . '/sysupd');
define('SMPRO_SU_CRON',  '/etc/cron.d/smpro-sysupd');
define('SMPRO_SU_LOG',   SMPRO_SU_DIR . '/apply.log');
define('SMPRO_SU_TIERS', 'https://httpupdate.cpanel.net/cpanelsync/TIERS');

function smpro_su_dir(): string { if (!is_dir(SMPRO_SU_DIR)) @mkdir(SMPRO_SU_DIR, 0700, true); return SMPRO_SU_DIR; }
function smpro_su_load(string $n, array $def = []): array { $f = smpro_su_dir() . '/' . $n . '.json'; $d = @is_file($f) ? json_decode((string)@file_get_contents($f), true) : null; return is_array($d) ? array_replace($def, $d) : $def; }
function smpro_su_save(string $n, array $v): void { smpro_json_save(smpro_su_dir() . '/' . $n . '.json', $v); }

/** The operator's choices. mode: 'manual' (show + tell, never apply) | 'auto' (apply at the hour, packages only;
 *  cPanel by its own nightly job unless cpanel_auto). */
function smpro_su_cfg(): array {
    $c = smpro_su_load('cfg', ['mode' => 'manual', 'hour' => 4, 'check_hours' => 6, 'cpanel_auto' => false, 'notify_new' => true, 'notify_result' => true, 'notify_problem' => true]);
    $c['mode'] = in_array((string)$c['mode'], ['manual', 'auto'], true) ? (string)$c['mode'] : 'manual';
    $c['hour'] = max(0, min(23, (int)$c['hour'])); $c['check_hours'] = max(1, min(24, (int)$c['check_hours']));
    foreach (['cpanel_auto', 'notify_new', 'notify_result', 'notify_problem'] as $k) $c[$k] = !empty($c[$k]);
    return $c;
}
function smpro_su_cfg_save(array $patch): array { $c = array_replace(smpro_su_cfg(), $patch); smpro_su_save('cfg', $c); return smpro_su_cfg(); }
function smpro_su_state(): array { return smpro_su_load('state', ['last_check' => 0, 'check_ok' => null, 'check_err' => '', 'pending' => [], 'cpanel' => [], 'kernel' => [], 'last_apply' => [], 'problems' => [], 'seen_sig' => '']); }
function smpro_su_state_save(array $s): void { smpro_su_save('state', $s); }

function smpro_su_run(string $cmd, int $t = 60): array {
    $out = (string)@shell_exec('LC_ALL=C PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin timeout ' . $t . ' ' . $cmd . ' 2>&1; echo "__rc=$?"');
    preg_match('/__rc=(\d+)\s*$/', $out, $m);
    return [(int)($m[1] ?? 1), trim((string)preg_replace('/__rc=\d+\s*$/', '', $out))];
}
function smpro_su_dnf(): string { foreach (['/usr/bin/dnf', '/usr/bin/yum'] as $b) if (is_executable($b)) return $b; return ''; }

/* ------------------------------------------------------------------ what is pending */

/** Classify a package name so the list says what matters: kernel, php, web, mail, db, security tooling, panel. */
function smpro_su_kind(string $name): string {
    $n = strtolower($name);
    if (preg_match('/^kernel(-|$)|^kmod-|^kcare|^kernelcare/', $n)) return 'kernel';
    if (preg_match('/php/', $n)) return 'php';
    if (preg_match('/^ea-apache|^ea-nginx|^nginx|^httpd|^ea-openssl|^openssl|^ea-modsec|^mod_/', $n)) return 'web';
    if (preg_match('/^exim|^dovecot|^spamassassin|^clamav|^mailman/', $n)) return 'mail';
    if (preg_match('/^mariadb|^mysql|^percona|^postgres/', $n)) return 'db';
    if (preg_match('/^imunify|^csf|^lfd|^cagefs|^lve|^alt-|^cloudlinux|^cl-/', $n)) return 'security';
    if (preg_match('/^cpanel|^ea-/', $n)) return 'panel';
    if (preg_match('/^glibc|^systemd|^sudo|^curl|^bash|^zlib|^libxml|^gnutls|^krb5|^bind|^openssh/', $n)) return 'base';
    return 'other';
}
/** `dnf check-update`: 100 = updates listed, 0 = none, anything else = COULD NOT CHECK (said as such). */
function smpro_su_check_packages(): array {
    $dnf = smpro_su_dnf(); if ($dnf === '') return ['ok' => false, 'err' => 'no package manager (dnf/yum) found', 'pending' => []];
    [$rc, $out] = smpro_su_run($dnf . ' -q check-update', 240);
    if ($rc !== 0 && $rc !== 100) return ['ok' => false, 'err' => 'check-update failed (rc ' . $rc . '): ' . substr($out, -400), 'pending' => [], 'raw' => $out];
    $p = [];
    foreach (explode("\n", $out) as $l) {
        if (!preg_match('/^(\S+?)\.(x86_64|noarch|i686|aarch64)\s+(\S+)\s+(\S+)\s*$/', trim($l), $m)) continue;
        $p[] = ['name' => $m[1], 'arch' => $m[2], 'version' => $m[3], 'repo' => $m[4], 'kind' => smpro_su_kind($m[1])];
    }
    return ['ok' => true, 'err' => '', 'pending' => $p];
}
/** cPanel: the installed build against the tier's current build (cPanel's own TIERS file). */
function smpro_su_check_cpanel(): array {
    $cur = trim((string)@file_get_contents('/usr/local/cpanel/version'));
    $tier = 'release';
    if (preg_match('/^CPANEL=(\S+)/m', (string)@file_get_contents('/etc/cpupdate.conf'), $m)) $tier = strtolower(trim($m[1]));
    $r = ['current' => $cur, 'tier' => $tier, 'latest' => '', 'ok' => null, 'behind' => null, 'err' => ''];
    [$rc, $out] = smpro_su_run('curl -sS -m 20 ' . escapeshellarg(SMPRO_SU_TIERS), 30);
    if ($rc !== 0 || $out === '') { $r['err'] = 'could not fetch the TIERS list: ' . substr($out, -200); return $r; }
    // Lines are "tier:version"; a tier pinned to an exact version (a four-part build number) also appears as a key.
    foreach (explode("\n", $out) as $l) { $l = trim($l); if (preg_match('/^' . preg_quote($tier, '/') . ':(\d+\.\d+\.\d+\.\d+)$/', $l, $m)) { $r['latest'] = $m[1]; break; } }
    if ($r['latest'] === '' && preg_match('/^\d+\.\d+\.\d+\.\d+$/', $tier)) $r['latest'] = $tier;   // a pinned version
    if ($r['latest'] === '') { $r['err'] = 'tier "' . $tier . '" is not in the TIERS list'; return $r; }
    $r['ok'] = true; $r['behind'] = version_compare($cur, $r['latest'], '<');
    return $r;
}
/** The kernel: running vs newest installed, and what the live patcher says (never a reason to reboot by itself). */
function smpro_su_check_kernel(): array {
    $running = trim((string)@shell_exec('uname -r 2>/dev/null'));
    [$rc, $out] = smpro_su_run('rpm -q kernel --last', 20);
    $installed = ''; if ($rc === 0 && preg_match('/^kernel-(\S+?)(?:\.x86_64|\.aarch64)?\s/m', $out, $m)) $installed = $m[1];
    $kc = ''; if (is_executable('/usr/bin/kcarectl')) { [$krc, $ko] = smpro_su_run('/usr/bin/kcarectl --uname', 20); if ($krc === 0) $kc = trim($ko); }
    $reboot = $installed !== '' && $running !== '' && strpos($running, $installed) !== 0;
    return ['running' => $running, 'installed' => $installed, 'livepatch' => $kc, 'reboot_pending' => $reboot];
}
/** One full check; stores the state; returns it. Tells the operator when something NEW appeared. */
function smpro_su_check(bool $notify = true): array {
    $s = smpro_su_state(); $cfg = smpro_su_cfg();
    $pk = smpro_su_check_packages();
    $s['last_check'] = time(); $s['check_ok'] = $pk['ok']; $s['check_err'] = $pk['err'];
    if ($pk['ok']) $s['pending'] = $pk['pending'];
    $s['cpanel'] = smpro_su_check_cpanel();
    $s['kernel'] = smpro_su_check_kernel();
    if (!$pk['ok']) {
        // a check that could not run is a problem in its own right: diagnose it like a failed apply
        $d = smpro_su_diagnose((string)($pk['raw'] ?? $pk['err']));
        $s['problems'] = $d ? [$d] : [['kind' => 'unknown', 'what' => $pk['err'], 'repair' => '']];
        if ($notify && $cfg['notify_problem'] && function_exists('smpro_notify')) {
            @smpro_notify('sysupd_problem', 'Updates cannot be checked', 'The package manager could not check for updates on this server: ' . $pk['err'] . ($d ? "\nDiagnosis: " . $d['what'] . ($d['repair'] !== '' ? "\nRepair offered: " . $d['repair'] : '') : '') . "\nOpen System updates and press Repair downloads, then Check now.");
        }
    } else {
        $s['problems'] = [];
        $sig = sha1(implode('|', array_map(fn($x) => $x['name'] . '=' . $x['version'], $s['pending'])) . '|' . (string)($s['cpanel']['latest'] ?? ''));
        if ($s['pending'] && $sig !== (string)($s['seen_sig'] ?? '') && $notify && $cfg['notify_new'] && function_exists('smpro_notify')) {
            $kinds = []; foreach ($s['pending'] as $x) $kinds[$x['kind']] = ($kinds[$x['kind']] ?? 0) + 1; arsort($kinds);
            $hl = array_filter($s['pending'], fn($x) => in_array($x['kind'], ['kernel', 'php', 'web', 'security', 'base'], true));
            @smpro_notify('sysupd_new', count($s['pending']) . ' update(s) available' . (!empty($s['cpanel']['behind']) ? ' + cPanel ' . $s['cpanel']['latest'] : ''),
                'Pending on this server: ' . count($s['pending']) . ' package(s) - ' . implode(', ', array_map(fn($k, $n) => $k . ' ' . $n, array_keys($kinds), $kinds)) . '.'
              . ($hl ? "\nWorth attention: " . implode(', ', array_map(fn($x) => $x['name'] . ' ' . $x['version'], array_slice(array_values($hl), 0, 8))) : '')
              . (!empty($s['cpanel']['behind']) ? "\ncPanel " . $s['cpanel']['current'] . ' -> ' . $s['cpanel']['latest'] . ' (tier ' . $s['cpanel']['tier'] . ')' : '')
              . "\nMode: " . ($cfg['mode'] === 'auto' ? 'automatic - applied at ' . sprintf('%02d:00', $cfg['hour']) . ' server time, no reboot' : 'manual - open System updates and press Update now'));
        }
        $s['seen_sig'] = $sig;
    }
    smpro_su_state_save($s);
    return $s;
}

/* ------------------------------------------------------------------ when a download breaks */

/** Read the tool's output and name the kind of break and the repair this product can do for it. null = no known
 *  pattern (then the raw tail is shown and nothing is attempted). Every pattern is a wording the package manager
 *  itself prints; none names a server or a mirror. */
function smpro_su_diagnose(string $out): ?array {
    $o = $out;
    if (preg_match('/No space left on device|Disk Requirements|At least \d+\s?[MG]B more space needed/i', $o))
        return ['kind' => 'disk', 'what' => 'the disk is full (or too full for the download)', 'repair' => '', 'auto' => false];
    if (preg_match('/Another app is currently holding the (yum|dnf) lock|Waiting for process with pid \d+/i', $o)) {
        $pid = preg_match('/pid:?\s*(\d+)/i', $o, $pm) ? (int)$pm[1] : 0;
        return ['kind' => 'lock', 'what' => 'another package-manager process holds the lock' . ($pid ? ' (pid ' . $pid . ')' : ''), 'repair' => 'wait; if the holder is gone or older than 30 minutes, remove the stale lock', 'auto' => true, 'pid' => $pid];
    }
    if (preg_match('/rpmdb|Berkeley DB|Thread died|DB_RUNRECOVERY|cannot open Packages (index|database)|Failed to open rpmdb/i', $o))
        return ['kind' => 'rpmdb', 'what' => 'the rpm package database is damaged', 'repair' => 'rpm --rebuilddb (the database is backed up first)', 'auto' => true];
    if (preg_match('/GPG check FAILED|Public key for \S+ is not installed|signature.*(BAD|NOKEY)|The GPG keys listed/i', $o))
        return ['kind' => 'gpg', 'what' => 'a package signature could not be verified (missing or wrong repository key)', 'repair' => 'refresh the metadata; the key itself is only taken from the repository\'s own configured gpgkey', 'auto' => true];
    if (preg_match("/Failed to (download|synchronize cache for|synchronize)[^\n]*?repo(?:sitory)?\s+'([A-Za-z0-9._-]+)'/i", $o, $m) || preg_match("/Errors during downloading metadata for repository '([A-Za-z0-9._-]+)'/i", $o, $m2) || preg_match('/Failed to (download|synchronize)[^\n]*(metadata|cache)/i', $o))
        { $repo = $m2[1] ?? ($m[2] ?? ''); return ['kind' => 'repo', 'what' => 'repository ' . ($repo !== '' ? '"' . $repo . '" ' : '') . 'metadata could not be downloaded (mirror down, DNS, firewall or an expired mirror list)', 'repair' => 'clean the cache and rebuild it; if that one repository still fails, update the rest with it skipped for this run and say so', 'auto' => true, 'repo' => $repo]; }
    if (preg_match('/Curl error|Could not resolve host|Connection (timed out|refused)|Network is unreachable|SSL certificate problem|cannot be reached|Cannot download/i', $o))
        return ['kind' => 'network', 'what' => 'the download could not reach the mirror (DNS, firewall, outbound block or a mirror that is down)', 'repair' => 'clean the cache and rebuild it; retry', 'auto' => true];
    if (preg_match('/immutable \(\+i\)|Operation not permitted/i', $o) && preg_match('/\.htaccess|immutable/i', $o))
        return ['kind' => 'immutable', 'what' => 'a file the update must rewrite is immutable (+i). Safety Lock\'s own locks are lifted around every update by this product; a lock set by another product (a WordPress lockdown, a manual chattr) must be lifted where it was set', 'repair' => '', 'auto' => false];
    if (preg_match('/conflicting requests|Problem \d*:|package .* requires|cannot install both|nothing provides/i', $o))
        return ['kind' => 'depsolve', 'what' => 'two packages conflict or a dependency is missing; the manager will not pick', 'repair' => '', 'auto' => false];
    if (preg_match('/Transaction (test|check) error|file .* conflicts between attempted installs|scriptlet failed/i', $o))
        return ['kind' => 'transaction', 'what' => 'a package transaction failed (file conflict or an install script error)', 'repair' => '', 'auto' => false];
    return null;
}
/** Do the repair the diagnosis names, when it is one this product can do safely. Returns [ok, what was done]. */
function smpro_su_repair(?array $d = null): array {
    $dnf = smpro_su_dnf(); $done = [];
    if ($d === null) {   // "Repair downloads" from the page: the generic, always-safe set
        [$rc1, $o1] = smpro_su_run($dnf . ' -q clean all', 120); $done[] = 'cache cleaned' . ($rc1 === 0 ? '' : ' (rc ' . $rc1 . ')');
        [$rc2, $o2] = smpro_su_run($dnf . ' -q makecache', 400); $done[] = 'metadata rebuilt' . ($rc2 === 0 ? '' : ': FAILED - ' . substr($o2, -300));
        if ($rc2 !== 0) { $d2 = smpro_su_diagnose($o2); if ($d2 && $d2['kind'] !== 'repo' && $d2['kind'] !== 'network') { [$ok3, $w3] = smpro_su_repair($d2); $done[] = $w3; return [$ok3, implode('; ', $done)]; } }
        return [$rc2 === 0, implode('; ', $done)];
    }
    switch ($d['kind']) {
        case 'lock':
            $pid = (int)($d['pid'] ?? 0); $age = 0;
            foreach (['/var/run/dnf.pid', '/var/run/yum.pid'] as $lf) if (is_file($lf)) { $age = time() - (int)@filemtime($lf); if ($pid === 0) $pid = (int)trim((string)@file_get_contents($lf)); }
            $alive = $pid > 0 && is_dir('/proc/' . $pid);
            if ($alive && $age < 1800) return [false, 'a package-manager process (pid ' . $pid . ') is really running for ' . intdiv($age, 60) . ' min; nothing removed - try again later'];
            foreach (['/var/run/dnf.pid', '/var/run/yum.pid'] as $lf) if (is_file($lf)) { @rename($lf, $lf . '.stale.' . date('YmdHis')); $done[] = 'stale lock ' . basename($lf) . ' moved aside'; }
            if ($alive) { @posix_kill($pid, 15); $done[] = 'process ' . $pid . ' (older than 30 min) asked to stop'; }
            return [true, implode('; ', $done) ?: 'no lock file found'];
        case 'rpmdb':
            $bk = smpro_su_dir() . '/rpmdb-' . date('YmdHis'); @mkdir($bk, 0700, true);
            smpro_su_run('cp -a /var/lib/rpm ' . escapeshellarg($bk) . '/', 120);
            [$rc, $o] = smpro_su_run('rpm --rebuilddb', 600);
            return [$rc === 0, 'rpm database rebuilt' . ($rc === 0 ? ' (copy kept in ' . $bk . ')' : ': FAILED - ' . substr($o, -300))];
        case 'gpg': case 'network': case 'repo':
            [$rc1] = smpro_su_run($dnf . ' -q clean all', 120); [$rc2, $o2] = smpro_su_run($dnf . ' -q makecache', 400);
            $done[] = 'cache cleaned and metadata rebuilt' . ($rc2 === 0 ? '' : ' - still failing: ' . substr($o2, -200));
            if ($rc2 !== 0 && $d['kind'] === 'repo' && !empty($d['repo']) && preg_match('/^[A-Za-z0-9._-]{1,64}$/', $d['repo'])) {
                [$rc3, $o3] = smpro_su_run($dnf . ' -q --disablerepo=' . escapeshellarg($d['repo']) . ' makecache', 400);
                $done[] = $rc3 === 0 ? 'the other repositories are fine: repository "' . $d['repo'] . '" is the broken one and will be skipped for this run - its packages stay pending until its mirror answers again' : 'other repositories fail too: ' . substr($o3, -200);
                return [$rc3 === 0, implode('; ', $done)];
            }
            return [$rc2 === 0, implode('; ', $done)];
        default:
            return [false, 'no automatic repair for this kind (' . $d['kind'] . '): ' . $d['what']];
    }
}

/* ------------------------------------------------------------------ applying */

/** The services that must still answer after an update; a stopped one is restarted once and reported. */
function smpro_su_service_check(): array {
    $want = ['httpd', 'nginx', 'exim', 'dovecot', 'mariadb', 'mysqld', 'cpanel', 'lfd', 'pure-ftpd', 'proftpd', 'named', 'pdns', 'imunify360'];
    $r = ['ok' => [], 'restarted' => [], 'down' => []];
    foreach ($want as $s) {
        [$rc, $o] = smpro_su_run('systemctl is-enabled ' . $s, 10); if ($rc !== 0) continue;   // not on this server
        [$rc2, $st] = smpro_su_run('systemctl is-active ' . $s, 10);
        if ($rc2 === 0) { $r['ok'][] = $s; continue; }
        smpro_su_run('systemctl restart ' . $s, 120);
        [$rc3] = smpro_su_run('systemctl is-active ' . $s, 10);
        if ($rc3 === 0) $r['restarted'][] = $s; else $r['down'][] = $s;
    }
    return $r;
}
function smpro_su_log(string $line): void { @file_put_contents(SMPRO_SU_LOG, '[' . date('Y-m-d H:i:s') . '] ' . $line . "\n", FILE_APPEND); @chmod(SMPRO_SU_LOG, 0600); if ((int)@filesize(SMPRO_SU_LOG) > 2097152) { $t = (string)@file_get_contents(SMPRO_SU_LOG); @file_put_contents(SMPRO_SU_LOG, substr($t, -1048576)); } }
/** Apply pending package updates (never a reboot). On a failure: diagnose, repair what can be repaired, retry once,
 *  and tell the operator either way. Returns the record that is also stored as last_apply. */
function smpro_su_apply(string $by = 'operator', bool $cpanelToo = false): array {
    $cfg = smpro_su_cfg(); $rec = ['at' => time(), 'by' => $by, 'ok' => false, 'msg' => '', 'updated' => 0, 'services' => [], 'repair' => '', 'cpanel' => ''];
    if (function_exists('smpro_ctl_dry_run') && smpro_ctl_dry_run()) { $rec['msg'] = 'Dry-Run is on: nothing was applied (' . count(smpro_su_state()['pending']) . ' package(s) would have been updated).'; return $rec; }
    $dnf = smpro_su_dnf(); if ($dnf === '') { $rec['msg'] = 'no package manager found'; return $rec; }
    $lock = @fopen(smpro_su_dir() . '/apply.lock', 'c'); if (!$lock || !@flock($lock, LOCK_EX | LOCK_NB)) { $rec['msg'] = 'an update is already running'; return $rec; }
    smpro_su_log('apply started by ' . $by);
    // Safety Lock's immutable bits would stop cPanel's PHP handler hook inside this very transaction: lift them for
    // the run, put them back after (the same pair cPanel's own hooks call).
    if (!function_exists('smpro_slm_release')) { $slf = __DIR__ . '/slmaint.php'; if (is_file($slf)) { foreach (['phlock', 'phstack', 'ph_ignore', 'compcheck', 'spqueue'] as $dep) { $df = __DIR__ . '/' . $dep . '.php'; if (is_file($df)) require_once $df; } require_once $slf; } }
    $rel = function_exists('smpro_slm_release') ? smpro_slm_release('the system update') : null;
    if ($rel) smpro_su_log('safety lock: ' . $rel['msg']);
    [$rc, $out] = smpro_su_run($dnf . ' -y update', 1800);
    smpro_su_log("dnf update rc=$rc\n" . $out);
    if ($rc !== 0) {
        $d = smpro_su_diagnose($out);
        $rec['repair'] = $d ? $d['what'] : 'no known pattern in the output';
        if ($d && !empty($d['auto'])) {
            [$rok, $rwhat] = smpro_su_repair($d); $rec['repair'] .= ' -> ' . $rwhat;
            if ($rok) {
                $extra = ($d['kind'] === 'repo' && !empty($d['repo']) && strpos($rwhat, 'skipped for this run') !== false) ? ' --disablerepo=' . escapeshellarg($d['repo']) : '';
                [$rc, $out] = smpro_su_run($dnf . ' -y' . $extra . ' update', 1800);
                smpro_su_log("retry after repair rc=$rc\n" . $out);
            }
        }
    }
    if ($rel && function_exists('smpro_slm_relock')) { $rl = smpro_slm_relock('the system update'); smpro_su_log('safety lock: ' . $rl['msg']); $rec['safetylock'] = $rl['msg']; }
    $rec['ok'] = $rc === 0;
    if (preg_match_all('/^\s*(Upgraded|Installed|Upgrading|Installing):?\s*$/m', $out)) { preg_match_all('/^\s{2}\S+-\d\S*\s*$/m', $out, $mm); $rec['updated'] = count($mm[0]); }
    if (preg_match('/Nothing to do/i', $out)) $rec['updated'] = 0;
    $rec['services'] = smpro_su_service_check();
    if ($cpanelToo || ($by === 'auto' && $cfg['cpanel_auto'])) {
        [$crc, $cout] = smpro_su_run('/scripts/upcp --cron', 3000);
        smpro_su_log("upcp rc=$crc\n" . substr($cout, -4000));
        $rec['cpanel'] = $crc === 0 ? 'cPanel update ran (' . trim((string)@file_get_contents('/usr/local/cpanel/version')) . ')' : 'cPanel update FAILED (rc ' . $crc . '): ' . substr($cout, -300);
    }
    $rec['msg'] = ($rec['ok'] ? 'Updated: ' . $rec['updated'] . ' package(s).' : 'Update FAILED (rc ' . $rc . '): ' . substr($out, -300))
                . ($rec['repair'] !== '' ? ' Problem: ' . $rec['repair'] . '.' : '')
                . ($rec['services']['restarted'] ? ' Restarted after the update: ' . implode(', ', $rec['services']['restarted']) . '.' : '')
                . ($rec['services']['down'] ? ' STILL DOWN: ' . implode(', ', $rec['services']['down']) . '.' : '')
                . ($rec['cpanel'] !== '' ? ' ' . $rec['cpanel'] : '');
    @flock($lock, LOCK_UN); @fclose($lock);
    $s = smpro_su_state(); $s['last_apply'] = $rec; smpro_su_state_save($s);
    if (function_exists('smpro_audit')) smpro_audit('sysupd_apply', ['by' => $by, 'ok' => $rec['ok'] ? 1 : 0, 'updated' => $rec['updated'], 'repair' => $rec['repair']]);
    if (function_exists('smpro_notify')) {
        if (!$rec['ok'] || $rec['services']['down'] || $rec['services']['restarted']) { if ($cfg['notify_problem']) @smpro_notify('sysupd_problem', $rec['ok'] ? 'Update applied, a service needed attention' : 'System update failed', $rec['msg'] . "\nThe full output is in System updates > Last apply log."); }
        elseif ($cfg['notify_result']) @smpro_notify('sysupd_result', 'System update applied (' . $rec['updated'] . ' package(s))', $rec['msg']);
    }
    smpro_su_check(false);   // refresh what is still pending (a kernel waiting for a reboot, a skipped repository)
    return $rec;
}

/* ------------------------------------------------------------------ schedule */

/** The worker runs every 30 minutes; this decides what, if anything, is due. */
function smpro_su_tick(): array {
    $cfg = smpro_su_cfg(); $s = smpro_su_state(); $did = [];
    if (time() - (int)$s['last_check'] >= $cfg['check_hours'] * 3600) { $s = smpro_su_check(true); $did[] = 'checked'; }
    if ($cfg['mode'] === 'auto' && $s['pending'] && (int)date('G') === $cfg['hour'] && !(function_exists('smpro_ctl_disabled') && smpro_ctl_disabled())) {
        $la = (array)($s['last_apply'] ?? []);
        if (date('Y-m-d', (int)($la['at'] ?? 0)) !== date('Y-m-d')) { smpro_su_apply('auto'); $did[] = 'applied'; }
    }
    return $did;
}
/** Always scheduled: the check must run whatever the mode, so "manual" still means "shown and told". */
function smpro_su_cron_sync(): bool {
    if (defined('SMPRO_TEST_SRC')) return true;
    $php = function_exists('smpro_php_cli_bin') ? smpro_php_cli_bin() : '/usr/local/cpanel/3rdparty/bin/php';
    $lockDir = defined('SMPRO_LOCKS') ? SMPRO_LOCKS : (SMPRO_VARLIB . '/locks'); @is_dir($lockDir) || @mkdir($lockDir, 0700, true);
    $flock = is_executable('/usr/bin/flock') ? '/usr/bin/flock' : 'flock';
    $line = "# Safety Monitor Pro - System updates: look every few hours, apply at the chosen hour when the mode is automatic (never reboots)\n"
          . "*/30 * * * * root " . $flock . " -n " . $lockDir . "/sysupd.lock timeout 3500 " . $php . " " . SMPRO_BASE . "/bin/sysupd_tick.php >/dev/null 2>&1\n";
    return function_exists('smpro_cron_install') ? smpro_cron_install(SMPRO_SU_CRON, $line) : (@file_put_contents(SMPRO_SU_CRON, $line) !== false && @chmod(SMPRO_SU_CRON, 0644));
}
