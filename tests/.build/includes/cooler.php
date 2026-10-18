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
    ];
}
function smpro_cool_critical_prefix(): array {
    return ['systemd-','php-fpm','imunify','cpanel','cphulk','mysql','maria','named','exim','clamd','dovecot'];
}
function smpro_cool_is_critical(string $comm, int $pid = 0): bool {
    if ($pid === 1 || $pid === 2) return true;
    $c = strtolower(trim($comm));
    if ($c === '') return false;
    if (in_array($c, smpro_cool_critical_exact(), true)) return true;
    foreach (smpro_cool_critical_prefix() as $pre) if (strpos($c, $pre) === 0) return true;
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
// "protected" (shown locked, refused by start) = the critical infrastructure set.
function smpro_cool_is_protected(string $comm, int $pid = 0): bool {
    return smpro_cool_is_critical($comm, $pid);
}

/* ---------------- detect the load source ---------------- */
// top CPU processes (excluding our own CGI), plus a per-user rollup and current load.
function smpro_cool_sources(int $n = 8): array {
    $self = getmypid();
    $raw = (string)@shell_exec('ps -eo pid,ppid,pcpu,pmem,user,comm --sort=-pcpu 2>/dev/null | head -' . (int)max(5, $n + 10));
    $procs = []; $byUser = [];
    foreach (preg_split('/\R/', trim($raw)) as $i => $line) {
        if ($i === 0) continue;                                  // header
        $p = preg_split('/\s+/', trim($line), 6);
        if (count($p) < 6) continue;
        $pid = (int)$p[0]; if ($pid <= 1 || $pid === $self) continue;
        $row = ['pid' => $pid, 'ppid' => (int)$p[1], 'cpu' => (float)$p[2], 'mem' => (float)$p[3], 'user' => $p[4], 'comm' => $p[5],
                'protected' => smpro_cool_is_critical($p[5], $pid), 'site_engine' => smpro_cool_is_site_engine($p[5])];
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
    ];
}

/* ---------------- start throttling ---------------- */
// $pids: list of PIDs to cool. $percent: hard CPU cap per pid (needs cpulimit; 0 = priority-only). $minutes: auto-revert.
function smpro_cool_start(array $pids, int $percent, int $minutes): array {
    $minutes = max(1, min(720, $minutes));
    $percent = max(0, min(95, $percent));
    $self = getmypid();
    $pids = array_values(array_unique(array_filter(array_map('intval', $pids), fn($p) => $p > 1 && $p !== $self)));
    if (!$pids) return ['ok' => false, 'msg' => 'No valid target process selected.'];

    $cpulimit = smpro_cool_has_cpulimit();
    $targets = []; $reverts = []; $skipped = [];
    foreach ($pids as $pid) {
        if (!is_dir('/proc/' . $pid)) continue;                  // gone already
        $comm = trim((string)@file_get_contents('/proc/' . $pid . '/comm'));
        if (smpro_cool_is_protected($comm, $pid)) { $skipped[] = $comm; continue; }   // NEVER throttle a critical service / site engine
        $oldNi = trim((string)@shell_exec('ps -o ni= -p ' . (int)$pid . ' 2>/dev/null'));
        $oldNi = ($oldNi === '' ? '0' : $oldNi);
        @shell_exec('renice 19 -p ' . (int)$pid . ' >/dev/null 2>&1');
        @shell_exec('ionice -c3 -p ' . (int)$pid . ' >/dev/null 2>&1');
        if ($percent > 0 && $cpulimit !== '') {
            // -z makes cpulimit exit when the target dies; detached so it survives this request
            @shell_exec('nohup ' . escapeshellarg($cpulimit) . ' -p ' . (int)$pid . ' -l ' . (int)$percent . ' -z >/dev/null 2>&1 &');
        }
        $reverts[] = 'renice ' . (int)$oldNi . ' -p ' . (int)$pid . ' >/dev/null 2>&1; ionice -c2 -n4 -p ' . (int)$pid . ' >/dev/null 2>&1; pkill -f ' . escapeshellarg('cpulimit -p ' . (int)$pid . ' ') . ' >/dev/null 2>&1';
        $targets[] = ['pid' => $pid, 'comm' => $comm, 'old_nice' => (int)$oldNi];
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
    return ['ok' => true, 'targets' => $targets, 'expires' => $expires, 'minutes' => $minutes,
            'percent' => $percent, 'cpulimit' => $cpulimit !== '',
            'msg' => 'Cooling ' . count($targets) . ' process(es) for ' . $minutes . ' min' . ($percent > 0 && $cpulimit !== '' ? ' (cap ' . $percent . '%).' : ' (low-priority).')];
}

/* ---------------- stop / revert now ---------------- */
function smpro_cool_revert(array $st): void {
    foreach (($st['revert'] ?? []) as $cmd) @shell_exec($cmd);
    // belt-and-suspenders: restore nice from targets even if revert list was lost
    foreach (($st['targets'] ?? []) as $t) {
        @shell_exec('renice ' . (int)($t['old_nice'] ?? 0) . ' -p ' . (int)$t['pid'] . ' >/dev/null 2>&1');
        @shell_exec('pkill -f ' . escapeshellarg('cpulimit -p ' . (int)$t['pid'] . ' ') . ' >/dev/null 2>&1');
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
            'cpulimit' => !empty($st['cpulimit']), 'targets' => $targets,
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
    $g['topk']    = max(1, min(10, (int)$g['topk']));
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
    $php = is_executable('/usr/local/cpanel/3rdparty/bin/php') ? '/usr/local/cpanel/3rdparty/bin/php' : trim((string)@shell_exec('command -v php 2>/dev/null'));
    $script = realpath(SMPRO_BASE . '/bin/cooler_tick.php') ?: (SMPRO_BASE . '/bin/cooler_tick.php');
    if ($php === '' || !is_file($script)) return;
    @file_put_contents($cron, "# Safety Monitor Pro — load guard (every minute)\n* * * * * root $php $script >/dev/null 2>&1\n");
    @chmod($cron, 0644);
}
// Cron tick: if 1-min load is over the ceiling and nothing is being cooled yet, throttle the top hogs.
function smpro_cool_guard_tick(): void {
    if (function_exists('smpro_ctl_dry_run') && smpro_ctl_dry_run()) return;   // global Dry-Run: monitor only, never throttle
    $g = smpro_cool_guard();
    if (empty($g['enabled'])) return;
    $la = @sys_getloadavg(); $load1 = $la ? (float)$la[0] : 0;
    if ($load1 < (float)$g['ceiling']) return;                       // under the ceiling → nothing to do
    if (!empty(smpro_cool_status()['active'])) return;               // already cooling → let it work
    if (time() - (int)$g['last_fire'] < (int)$g['cooldown']) return; // anti-spam window

    $src = smpro_cool_sources(12); $pids = [];
    // unattended: only isolated runaways — never a service, and never per-site PHP (php-cgi/lsphp); skip exited procs
    foreach ($src['procs'] as $p) { if (empty($p['protected']) && empty($p['site_engine']) && $p['cpu'] >= (float)$g['min_cpu'] && is_dir('/proc/' . $p['pid'])) { $pids[] = $p['pid']; if (count($pids) >= (int)$g['topk']) break; } }
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
