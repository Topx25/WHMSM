<?php
/**
 * cooler.php — "Cooler mode". Detect what is driving server load (top CPU processes / users)
 * and *throttle* the offender for a chosen duration, fully reversibly:
 *   - renice to +19 (lowest CPU priority) and ionice to idle class,
 *   - if `cpulimit` is installed and a hard cap % is chosen, apply a real CPU ceiling,
 *   - auto-revert after N minutes (a detached timer restores the original priority),
 *   - never kills a process; PID 1/our own CGI are refused; every action is audited.
 * State lives in SMPRO_VARLIB/cooler.json so status/stop work across requests; a cron tick
 * (smpro_cool_tick) is a safety net that reverts if the detached timer ever missed.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

define('SMPRO_COOL_STATE', SMPRO_VARLIB . '/cooler.json');

function smpro_cool_state(): array {
    $d = is_file(SMPRO_COOL_STATE) ? json_decode((string)@file_get_contents(SMPRO_COOL_STATE), true) : null;
    return is_array($d) ? $d : [];
}
function smpro_cool_state_save(array $patch): void {
    $s = array_merge(smpro_cool_state(), $patch);                // MERGE so the guard config survives throttle start/stop
    @is_dir(dirname(SMPRO_COOL_STATE)) || @mkdir(dirname(SMPRO_COOL_STATE), 0700, true);
    @file_put_contents(SMPRO_COOL_STATE . '.tmp', json_encode($s, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT), LOCK_EX);
    @chmod(SMPRO_COOL_STATE . '.tmp', 0600); @rename(SMPRO_COOL_STATE . '.tmp', SMPRO_COOL_STATE);
}
function smpro_cool_has_cpulimit(): string { return trim((string)@shell_exec('command -v cpulimit 2>/dev/null')); }
// How the CPU cap is enforced: native 'cpulimit' if installed, else the shipped built-in throttle, else 'none'.
// The built-in fallback means a hard CPU cap ALWAYS works even when cpulimit can't be installed (no repo/net).
function smpro_cool_cap_method(): string {
    if (smpro_cool_has_cpulimit() !== '') return 'cpulimit';
    if (is_file(SMPRO_BASE . '/bin/cpulimit-lite.sh')) return 'builtin';
    return 'none';
}

/* ---------------- protected (never-throttle) processes ----------------
 * CRITICAL SAFETY RULE: the cooler/guard must NEVER slow down the web server, database, mail,
 * DNS, FTP, SSH, firewall or cPanel services — doing so would degrade or "stop" live customer
 * sites. It also never kills a process and never suspends an account. Only ISOLATED runaway
 * processes (a stray script, a heavy cron/backup, a standalone binary) may be deprioritised. */
// CRITICAL infrastructure — the web server, database, mail, DNS, FTP, SSH, firewall & cPanel
// daemons. Slowing any of these would degrade EVERY hosted site, so they are NEVER throttled,
// not even by a manual selection. (php-fpm master serves all pools, so it stays here too.)
function smpro_cool_critical_exact(): array {
    return [
        'systemd','init','kthreadd','dbus','dbus-daemon','rsyslogd','sshd','agetty','login','auditd',
        'httpd','apache2','nginx','lshttpd','litespeed','lscgid','lswsctrl','php-fpm',
        'mysqld','mariadbd','mysqld_safe','postgres',
        'exim','dovecot','master','pickup','qmgr','smtpd','pop3-login','imap-login','spamd','clamd','freshclam',
        'named','pdns_server','nsd','pure-ftpd','proftpd','pure-authd',
        'cpsrvd','cpaneld','cpdavd','cphulkd','queueprocd','tailwatchd','cpanellogd','dnsadmin','dovecot-auth',
        'lfd','csf','imunify360','defence360agent',
        'redis-server','memcached','mongod','postgres','postmaster','openlitespeed','lsws','litespeed','java','elasticsearch','varnishd','haproxy','passenger','puma','unicorn','gunicorn','uwsgi',
    ];
}
function smpro_cool_critical_prefix(): array {
    return ['systemd-','php-fpm','imunify','cpanel','cpsrvd','cpdavd','cphulk','queueprocd','tailwatchd','mysql','maria','named','exim','clamd','dovecot','sshd','pure-ftpd','proftpd','lfd'];   // 'cpsrvd' covers the renamed session children "cpsrvd (SSL) - serving <user>", which run as the user
}
function smpro_cool_is_critical(string $comm, int $pid = 0): bool {
    if ($pid === 1 || $pid === 2) return true;
    $c = strtolower(trim($comm));
    if ($c === '') return false;
    if (in_array($c, smpro_cool_critical_exact(), true)) return true;
    foreach (smpro_cool_critical_prefix() as $pre) if (strpos($c, $pre) === 0) return true;
    // The name a process shows can be rewritten by the process itself; the executable behind it cannot. A
    // session server (cpsrvd, sshd, an FTP daemon, dovecot) is never throttled whatever it calls itself.
    if ($pid > 0) {
        $exe = strtolower(basename((string)@readlink('/proc/' . $pid . '/exe')));
        if ($exe !== '' && (in_array($exe, smpro_cool_critical_exact(), true) || in_array($exe, ['cpsrvd', 'cpsrvd.so', 'perl', 'cpanel', 'sshd', 'pure-ftpd', 'proftpd', 'dovecot', 'imap-login', 'pop3-login'], true))) return true;
    }
    // Also never throttle a known security/hosting daemon (Imunify rustbolit/aibolit, CloudLinux LVE/CageFS…).
    if (function_exists('smpro_is_trusted_system_proc') && smpro_is_trusted_system_proc($c)) return true;
    return false;
}
// Per-site PHP engines (one request = one customer site). The UNATTENDED guard never touches these
// on its own (so it can't silently slow a customer's site); an admin may still MANUALLY cool a
// confirmed-runaway one. renice only lowers priority — it never stops the request or the site.
function smpro_cool_is_site_engine(string $comm): bool {
    $c = strtolower(trim($comm));
    foreach (['php-cgi', 'lsphp', 'suphp', 'cgiwrap'] as $n) if ($c === $n || strpos($c, $n) === 0) return true;
    return $c === 'php';
}
// Background WordPress cron under a per-site PHP engine (e.g. `php-cgi -q wp-cron.php`). This is NOT a live
// visitor request — it's WP's scheduled-task runner — so throttling it only makes cron run slower, it never
// slows a real page load. The unattended guard MAY cool these; they are the usual cause of wp-cron storms.
function smpro_cool_is_bg_cron(string $args): bool {
    return stripos($args, 'wp-cron.php') !== false;
}
// "protected" (shown locked, refused by start) = the critical infrastructure set.
function smpro_cool_is_protected(string $comm, int $pid = 0): bool {
    return smpro_cool_is_critical($comm, $pid);
}

/* ---------------- detect the load source ---------------- */
// top CPU processes (excluding our own CGI), plus a per-user rollup and current load.
function smpro_cool_sources(int $n = 8): array {
    $self = getmypid();
    // user:32 keeps full cPanel usernames (the bare `user` column truncates >8 chars with a trailing '+',
    // corrupting the per-user rollup key and account matching).
    $raw = (string)@shell_exec('ps -eo pid,ppid,pcpu,pmem,user:32,comm,args --sort=-pcpu 2>/dev/null | head -' . (int)max(5, $n + 10));
    $procs = []; $byUser = [];
    foreach (preg_split('/\R/', trim($raw)) as $i => $line) {
        if ($i === 0) continue;                                  // header
        $p = preg_split('/\s+/', trim($line), 7);
        if (count($p) < 6) continue;
        $pid = (int)$p[0]; if ($pid <= 1 || $pid === $self) continue;
        $args = $p[6] ?? '';
        $isSite = smpro_cool_is_site_engine($p[5]);
        $row = ['pid' => $pid, 'ppid' => (int)$p[1], 'cpu' => (float)$p[2], 'mem' => (float)$p[3], 'user' => $p[4], 'comm' => $p[5],
                'protected' => smpro_cool_is_critical($p[5], $pid), 'site_engine' => $isSite,
                'bg_cron' => $isSite && smpro_cool_is_bg_cron($args)];
        $procs[] = $row;
        $byUser[$p[4]] = ($byUser[$p[4]] ?? 0) + (float)$p[2];
        if (count($procs) >= $n) break;
    }
    arsort($byUser);
    $cores = (int)@shell_exec('nproc 2>/dev/null') ?: 1;
    $la = @sys_getloadavg();
    return [
        'procs'  => $procs,
        'users'  => array_slice($byUser, 0, 6, true),
        'cores'  => $cores,
        'load1'  => $la ? round((float)$la[0], 2) : null,
        'loadpct'=> ($la && $cores) ? (int)round($la[0] / $cores * 100) : null,
        'cpulimit' => smpro_cool_has_cpulimit() !== '',
        'cap'      => smpro_cool_cap_method(),
    ];
}

/* ---------------- start throttling ---------------- */
// $pids: list of PIDs to cool. $percent: hard CPU cap per pid (needs cpulimit; 0 = priority-only). $minutes: auto-revert.
/** The kernel's start time of a PID (jiffies, /proc/<pid>/stat field 22): the PID number is reused, this is not. */
function smpro_cool_starttime(int $pid): string {
    $s = (string)@file_get_contents('/proc/' . $pid . '/stat'); $p = strrpos($s, ')');
    if ($s === '' || $p === false) return '';
    $f = preg_split('/\s+/', trim(substr($s, $p + 1)));
    return (string)($f[19] ?? '');
}
/** Shell guard that runs $cmd only while the PID is still the process it was (start time unchanged). */
function smpro_cool_same($pid, string $start, string $cmd): string {
    return '[ "$(sed \'s/.*) //\' /proc/' . (int)$pid . '/stat 2>/dev/null | awk \'{print $20}\')" = ' . escapeshellarg($start) . ' ] && { ' . $cmd . ' ; }';
}
function smpro_cool_start(array $pids, int $percent, int $minutes): array {
    $minutes = max(1, min(720, $minutes));
    $percent = max(0, min(95, $percent));
    $self = getmypid();
    $pids = array_values(array_unique(array_filter(array_map('intval', $pids), fn($p) => $p > 1 && $p !== $self)));
    if (!$pids) return ['ok' => false, 'msg' => 'No valid target process selected.'];

    $cpulimit = smpro_cool_has_cpulimit();
    $lite = SMPRO_BASE . '/bin/cpulimit-lite.sh';   // built-in cap fallback (no cpulimit binary needed)
    $targets = []; $reverts = []; $skipped = [];
    foreach ($pids as $pid) {
        if (!is_dir('/proc/' . $pid)) continue;                  // gone already
        $comm = trim((string)@file_get_contents('/proc/' . $pid . '/comm'));
        if (smpro_cool_is_protected($comm, $pid)) { $skipped[] = $comm; continue; }   // NEVER throttle a critical service / site engine
        if (@fileowner('/proc/' . $pid) === 0) { $skipped[] = $comm . ' (root)'; continue; }   // parity with the Kill guard: never throttle a root-owned process
        $oldNi = trim((string)@shell_exec('ps -o ni= -p ' . (int)$pid . ' 2>/dev/null'));
        $oldNi = ($oldNi === '' ? '0' : $oldNi);
        $start = smpro_cool_starttime((int)$pid); if ($start === '') continue;   // gone between the listing and now
        @shell_exec('renice 19 -p ' . (int)$pid . ' >/dev/null 2>&1');
        @shell_exec('ionice -c3 -p ' . (int)$pid . ' >/dev/null 2>&1');
        if ($percent > 0) {
            if ($cpulimit !== '') {
                // -z makes cpulimit exit when the target dies; detached so it survives this request
                @shell_exec('nohup ' . escapeshellarg($cpulimit) . ' -p ' . (int)$pid . ' -l ' . (int)$percent . ' -z >/dev/null 2>&1 &');
            } elseif (is_file($lite)) {
                // FALLBACK (no cpulimit binary): built-in SIGSTOP/SIGCONT duty-cycle throttle — the cap still works
                @shell_exec('nohup bash ' . escapeshellarg($lite) . ' ' . (int)$pid . ' ' . (int)$percent . ' ' . ($minutes * 60) . ' ' . escapeshellarg($start) . ' >/dev/null 2>&1 &');
            }
        }
        $reverts[] = smpro_cool_same($pid, $start, 'renice ' . (int)$oldNi . ' -p ' . (int)$pid . ' >/dev/null 2>&1; ionice -c2 -n4 -p ' . (int)$pid . ' >/dev/null 2>&1') . '; pkill -f ' . escapeshellarg('cpulimit -p ' . (int)$pid . ' ') . ' >/dev/null 2>&1; pkill -f ' . escapeshellarg('cpulimit-lite.sh ' . (int)$pid . ' ') . ' >/dev/null 2>&1; kill -CONT ' . (int)$pid . ' >/dev/null 2>&1';
        $targets[] = ['pid' => $pid, 'comm' => $comm, 'old_nice' => (int)$oldNi, 'start' => $start];
    }
    if (!$targets) {
        $msg = $skipped ? ('Protected service(s) — not throttled to keep sites/services running: ' . implode(', ', array_unique($skipped))) : 'Target process(es) no longer running.';
        return ['ok' => false, 'msg' => $msg, 'skipped' => array_values(array_unique($skipped))];
    }

    $expires = time() + $minutes * 60;
    // detached timer that restores everything at expiry (independent of cron)
    $revertCmd = implode('; ', $reverts);
    @shell_exec('nohup sh -c ' . escapeshellarg('sleep ' . ($minutes * 60) . '; ' . $revertCmd) . ' >/dev/null 2>&1 &');

    $st = ['active' => true, 'started' => time(), 'expires' => $expires, 'minutes' => $minutes,
           'percent' => $percent, 'cpulimit' => $cpulimit !== '', 'targets' => $targets, 'revert' => $reverts];
    smpro_cool_state_save($st);
    if (function_exists('smpro_audit')) smpro_audit('cooler_start', ['pids' => array_column($targets, 'pid'), 'percent' => $percent, 'minutes' => $minutes]);
    $capNow = $percent > 0 ? ($cpulimit !== '' ? 'cpulimit' : (is_file($lite) ? 'builtin' : 'none')) : 'none';
    return ['ok' => true, 'targets' => $targets, 'expires' => $expires, 'minutes' => $minutes,
            'percent' => $percent, 'cpulimit' => $cpulimit !== '', 'cap' => $capNow,
            'msg' => 'Cooling ' . count($targets) . ' process(es) for ' . $minutes . ' min' . ($capNow !== 'none' ? ' (cap ' . $percent . '%' . ($capNow === 'builtin' ? ', built-in' : '') . ').' : ' (low-priority).')];
}

/* ---------------- stop / revert now ---------------- */
function smpro_cool_revert(array $st): void {
    foreach (($st['revert'] ?? []) as $cmd) @shell_exec($cmd);
    // belt-and-suspenders: restore nice from targets even if revert list was lost
    foreach (($st['targets'] ?? []) as $t) {
        @shell_exec('pkill -f ' . escapeshellarg('cpulimit -p ' . (int)$t['pid'] . ' ') . ' >/dev/null 2>&1');
        @shell_exec('pkill -f ' . escapeshellarg('cpulimit-lite.sh ' . (int)$t['pid'] . ' ') . ' >/dev/null 2>&1');
        // the PID number may belong to someone else by now (hours later): only the very process that was throttled is touched
        if (isset($t['start']) && (string)$t['start'] !== '' && smpro_cool_starttime((int)$t['pid']) !== (string)$t['start']) continue;
        @shell_exec('renice ' . (int)($t['old_nice'] ?? 0) . ' -p ' . (int)$t['pid'] . ' >/dev/null 2>&1');
        @shell_exec('kill -CONT ' . (int)$t['pid'] . ' >/dev/null 2>&1');   // SAFETY: never leave a throttled process stopped
    }
}
function smpro_cool_stop(): array {
    $st = smpro_cool_state();
    if (empty($st['active'])) { smpro_cool_state_save(['active' => false]); return ['ok' => true, 'msg' => 'Cooler was not active.']; }
    smpro_cool_revert($st);
    smpro_cool_state_save(['active' => false, 'stopped' => time(), 'last_targets' => $st['targets'] ?? [], 'targets' => [], 'revert' => []]);
    if (function_exists('smpro_audit')) smpro_audit('cooler_stop', ['pids' => array_column($st['targets'] ?? [], 'pid')]);
    return ['ok' => true, 'msg' => 'Cooler stopped, original priorities restored.'];
}

/* ---------------- status ---------------- */
function smpro_cool_status(): array {
    $st = smpro_cool_state();
    $active = !empty($st['active']) && time() < (int)($st['expires'] ?? 0);
    if (!empty($st['active']) && !$active) { smpro_cool_revert($st); smpro_cool_state_save(['active' => false]); }  // expired → tidy
    $targets = [];
    foreach (($st['targets'] ?? []) as $t) {
        $alive = is_dir('/proc/' . (int)$t['pid']);
        $cpu = $alive ? (float)trim((string)@shell_exec('ps -o pcpu= -p ' . (int)$t['pid'] . ' 2>/dev/null')) : null;
        $targets[] = $t + ['alive' => $alive, 'cpu' => $cpu];
    }
    $la = @sys_getloadavg();
    return ['active' => $active, 'expires' => (int)($st['expires'] ?? 0),
            'remaining' => $active ? max(0, (int)$st['expires'] - time()) : 0,
            'percent' => (int)($st['percent'] ?? 0), 'minutes' => (int)($st['minutes'] ?? 0),
            'cpulimit' => !empty($st['cpulimit']), 'cap' => smpro_cool_cap_method(), 'targets' => $targets,
            'load1' => $la ? round((float)$la[0], 2) : null, 'guard' => smpro_cool_guard()];
}

/* ---------------- cron safety net ---------------- */
function smpro_cool_tick(): void {
    $st = smpro_cool_state();
    if (!empty($st['active']) && time() >= (int)($st['expires'] ?? 0)) { smpro_cool_revert($st); smpro_cool_state_save(['active' => false]); }
}

/* ---------------- automatic load guard ("keep load under a ceiling") ---------------- */
function smpro_cool_guard(): array {
    $g = (array)(smpro_cool_state()['guard'] ?? []);
    return $g + ['enabled' => false, 'ceiling' => 20, 'percent' => 50, 'minutes' => 15,
                 'topk' => 3, 'min_cpu' => 25, 'cooldown' => 600, 'last_fire' => 0];
}
function smpro_cool_guard_save(array $patch): array {
    $g = array_merge(smpro_cool_guard(), $patch);
    $g['enabled'] = !empty($g['enabled']);
    $g['ceiling'] = max(1, min(2048, (float)$g['ceiling']));
    $g['percent'] = max(0, min(95, (int)$g['percent']));
    $g['minutes'] = max(1, min(720, (int)$g['minutes']));
    $g['topk']    = max(1, min(50, (int)$g['topk']));
    $g['min_cpu'] = max(1, min(100, (int)$g['min_cpu']));
    smpro_cool_state_save(['guard' => $g]);
    smpro_cool_guard_install_cron($g['enabled']);                    // 1-min worker so the cap is actually enforced
    if (function_exists('smpro_audit')) smpro_audit('cooler_guard_cfg', ['enabled' => $g['enabled'], 'ceiling' => $g['ceiling']]);
    return ['ok' => true, 'guard' => $g];
}
// install/remove a per-minute cron that enforces the load guard (independent of the Telegram bot / notify cron).
function smpro_cool_guard_install_cron(bool $on): void {
    $cron = '/etc/cron.d/smpro-cooler';
    if (!$on) { @unlink($cron); return; }
    $php = smpro_php_cli_bin();   // canonical: cron's PATH may not resolve a bare `php`
    $script = realpath(SMPRO_BASE . '/bin/cooler_tick.php') ?: (SMPRO_BASE . '/bin/cooler_tick.php');
    if ($php === '' || !is_file($script)) return;
    $lockDir = defined('SMPRO_LOCKS') ? SMPRO_LOCKS : (SMPRO_VARLIB . '/locks'); @is_dir($lockDir) || @mkdir($lockDir, 0700, true); $flock = is_executable('/usr/bin/flock') ? '/usr/bin/flock' : 'flock';
    smpro_cron_install($cron, "# Safety Monitor Pro — load guard (every minute)\n* * * * * root $flock -n $lockDir/cooler.lock timeout 55 $php $script >/dev/null 2>&1\n");
}
/** cron_sync entry: put the load-guard cron back after an update if the guard is on. */
function smpro_cool_cron_sync(): bool { if (defined('SMPRO_TEST_SRC')) return true; $g = smpro_cool_guard(); smpro_cool_guard_install_cron(!empty($g['enabled'])); return true; }
// Cron tick: if 1-min load is over the ceiling and nothing is being cooled yet, throttle the top hogs.
function smpro_cool_guard_tick(): void {
    if (function_exists('smpro_ctl_dry_run') && smpro_ctl_dry_run()) return;   // global Dry-Run: monitor only, never throttle
    $g = smpro_cool_guard();
    if (empty($g['enabled'])) return;
    $la = @sys_getloadavg(); $load1 = $la ? (float)$la[0] : 0;
    $cores = function_exists('smpro_cpu_cores') ? max(1, (int)smpro_cpu_cores()) : max(1, (int)trim((string)@shell_exec('nproc 2>/dev/null')));
    $ceil  = (float)$g['ceiling'];
    if ($ceil < $cores / 2) {   // below half the cores the box is not overloaded: a 1-min load of 10 on 96 threads is ~10% busy
        static $warned = false;
        if (!$warned && function_exists('smpro_audit')) { smpro_audit('cooler_ceiling_raised', ['configured' => $ceil, 'effective' => $cores / 2, 'cores' => $cores]); $warned = true; }
        $ceil = $cores / 2;
    }
    if ($load1 < $ceil) return;                                       // under the ceiling → nothing to do
    if (function_exists('smpro_load_overload_record_if_high')) smpro_load_overload_record_if_high((float)$g['ceiling']);  // report history (deduped ~5min)
    if (!empty(smpro_cool_status()['active'])) return;               // already cooling → let it work
    if (time() - (int)$g['last_fire'] < (int)$g['cooldown']) return; // anti-spam window

    $src = smpro_cool_sources(12); $pids = [];
    // A process holding a listening socket is a server (redis, memcached, an app server behind Passenger): freezing
    // it with SIGSTOP stalls every site that talks to it. The unattended guard never touches a listener.
    $listening = [];
    foreach (explode("\n", (string)@shell_exec('timeout 5 ss -lnpH 2>/dev/null')) as $l) if (preg_match_all('/pid=(\d+)/', $l, $pm)) foreach ($pm[1] as $pid) $listening[(int)$pid] = 1;
    // unattended: isolated runaways + background wp-cron PHP (php-cgi -q wp-cron.php) — never a live service
    // and never a per-site PHP request serving a visitor; skip exited procs.
    foreach ($src['procs'] as $p) { if (empty($p['protected']) && !isset($listening[(int)$p['pid']]) && (empty($p['site_engine']) || !empty($p['bg_cron'])) && $p['cpu'] >= (float)$g['min_cpu'] && is_dir('/proc/' . $p['pid'])) { $pids[] = $p['pid']; if (count($pids) >= (int)$g['topk']) break; } }
    if (!$pids) {                                                          // load is driven by services or customer-site PHP — do NOT touch them automatically
        if (function_exists('smpro_audit')) smpro_audit('cooler_guard_noop', ['load1' => $load1, 'reason' => 'no safe isolated target (services & site PHP are never auto-throttled)']);
        return;
    }

    $r = smpro_cool_start($pids, (int)$g['percent'], (int)$g['minutes']);
    if (empty($r['ok'])) {                                                  // all targets vanished/protected — retry next minute, don't burn the cooldown
        if (function_exists('smpro_audit')) smpro_audit('cooler_guard_miss', ['load1' => $load1, 'msg' => $r['msg'] ?? '']);
        return;
    }
    smpro_cool_state_save(['guard' => array_merge($g, ['last_fire' => time()])]);
    if (function_exists('smpro_audit')) smpro_audit('cooler_guard_fire', ['load1' => $load1, 'ceiling' => $g['ceiling'], 'pids' => array_column($r['targets'] ?? [], 'pid')]);

    // alert (Telegram if the control bot is configured)
    if (!empty($r['ok']) && function_exists('smpro_tg_cfg') && function_exists('smpro_tg_send')) {
        $cfg = smpro_tg_cfg();
        if (!empty($cfg['enabled']) && $cfg['token'] !== '' && $cfg['admin'] !== '') {
            $names = array_map(fn($t) => ($t['comm'] ?? '?') . '(' . $t['pid'] . ')', $r['targets'] ?? []);
            smpro_tg_send($cfg['token'], $cfg['admin'],
                "🌡 <b>Load guard fired</b> — 1-min load " . round($load1, 2) . " ≥ ceiling " . $g['ceiling'] . "\n"
                . "Throttled: " . htmlspecialchars(implode(', ', $names)) . " for " . (int)$g['minutes'] . " min. Auto-reverts after.");
        }
    }
}

/* ---------------- one-call convenience: cool the top SAFE (non-service) CPU hog ---------------- */
function smpro_cool_auto(int $minutes = 15, int $percent = 50): array {
    $src = smpro_cool_sources(12);
    $top = null;
    foreach ($src['procs'] as $p) { if (empty($p['protected']) && $p['cpu'] >= 1) { $top = $p; break; } }   // skip web/db/mail/cPanel services
    if (!$top) return ['ok' => false, 'msg' => 'No isolated runaway process to cool — the load is from core services, which are never throttled.'];
    $r = smpro_cool_start([$top['pid']], $percent, $minutes);
    $r['source'] = $top;
    return $r;
}
