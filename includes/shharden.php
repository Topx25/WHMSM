<?php
/**
 * includes/shharden.php — server hardening fixes for Security Health, each with a journaled undo.
 *
 * Grew out of hardening a production server by hand: every step that proved safe there is a fix here, so
 * every licensee gets the same result from one page. Rules:
 *  - each step reads the live state first and is offered only when it is actually weaker than the target;
 *  - nothing is assumed about the host: ports, PHP builds, config paths and tools are discovered;
 *  - every change records how to put it back (root-only journal); Undo restores the exact previous state;
 *  - a step whose tool is missing is reported as "not applicable", never as passed.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

if (!defined('SMPRO_SH_BACKUP')) define('SMPRO_SH_BACKUP', SMPRO_VARLIB . '/backups/security');
define('SMPRO_SHH_JOURNAL', SMPRO_SH_BACKUP . '/hardening-journal.json');

function smpro_shh_x(string $cmd, int $t = 30): array {
    $o = []; $rc = 1; @exec('timeout ' . $t . ' ' . $cmd . ' 2>&1', $o, $rc);
    return [$rc, trim(implode("\n", $o))];
}
function smpro_shh_keep(string $f): ?string {
    if (!is_file($f)) return null;
    @is_dir(SMPRO_SH_BACKUP) || @mkdir(SMPRO_SH_BACKUP, 0700, true);
    $b = SMPRO_SH_BACKUP . '/' . trim(str_replace('/', '_', $f), '_') . '.' . date('Ymd_His') . '.' . substr(md5(uniqid('', true)), 0, 6) . '.bak';
    if (!@copy($f, $b)) return null;
    @chmod($b, 0600);
    return $b;
}

/* ---------------- journal ---------------- */
function smpro_shh_journal(): array {
    $j = json_decode((string)@file_get_contents(SMPRO_SHH_JOURNAL), true);
    return is_array($j) ? $j : [];
}
function smpro_shh_journal_save(array $j): void {
    @is_dir(SMPRO_SH_BACKUP) || @mkdir(SMPRO_SH_BACKUP, 0700, true);
    $t = SMPRO_SHH_JOURNAL . '.tmp';
    if (@file_put_contents($t, json_encode($j, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT)) !== false) { @chmod($t, 0600); @rename($t, SMPRO_SHH_JOURNAL); }
}
function smpro_shh_journal_add(string $id, array $undo, string $msg): void {
    $j = smpro_shh_journal();
    $j[] = ['id' => $id, 'at' => time(), 'msg' => $msg, 'undo' => $undo, 'undone' => false];
    smpro_shh_journal_save(array_slice($j, -200));
}

/* ---------------- live state ---------------- */
/** The kernel settings this hardening wants; only keys the running kernel has are considered. */
function smpro_shh_sysctl_want(): array {
    return [
        'net.ipv4.conf.all.accept_redirects' => '0', 'net.ipv4.conf.default.accept_redirects' => '0',
        'net.ipv4.conf.all.secure_redirects' => '0', 'net.ipv4.conf.all.send_redirects' => '0',
        'net.ipv4.conf.default.send_redirects' => '0', 'net.ipv6.conf.all.accept_redirects' => '0',
        'net.ipv4.conf.all.accept_source_route' => '0', 'net.ipv4.conf.all.log_martians' => '1',
        'net.ipv4.tcp_syncookies' => '1', 'kernel.dmesg_restrict' => '1', 'kernel.kptr_restrict' => '2',
        'kernel.yama.ptrace_scope' => '1', 'fs.protected_symlinks' => '1', 'fs.protected_hardlinks' => '1',
        'fs.protected_fifos' => '2', 'fs.protected_regular' => '2', 'fs.suid_dumpable' => '0',
    ];
}
function smpro_shh_sysctl_get(string $k): ?string {
    $p = '/proc/sys/' . str_replace('.', '/', $k);
    return is_readable($p) ? trim((string)@file_get_contents($p)) : null;
}
/** [key => [current, wanted]] for every setting that is weaker than wanted. */
function smpro_shh_sysctl_gaps(): array {
    $g = [];
    foreach (smpro_shh_sysctl_want() as $k => $v) { $c = smpro_shh_sysctl_get($k); if ($c !== null && $c !== $v) $g[$k] = [$c, $v]; }
    return $g;
}
function smpro_shh_shm_opts(): string {
    foreach (@file('/proc/mounts', FILE_IGNORE_NEW_LINES) ?: [] as $l) { $p = preg_split('/\s+/', $l); if (($p[1] ?? '') === '/dev/shm') return (string)($p[3] ?? ''); }
    return '';
}
/** PHP ini files (every EA-PHP / alt-php build) that allow including code from a URL. */
function smpro_shh_php_urlinclude(): array {
    $bad = [];
    foreach (array_merge(glob('/opt/cpanel/ea-php*/root/etc/php.ini') ?: [], glob('/opt/alt/php*/etc/php.ini') ?: []) as $f) {
        if (preg_match('/^\s*allow_url_include\s*=\s*(on|1|true|yes)\s*$/mi', (string)@file_get_contents($f))) $bad[] = $f;
    }
    return $bad;
}
/** CSF settings this hardening wants. The SSH port comes from the running sshd, never a fixed 22. */
function smpro_shh_csf_want(): array {
    $port = '22';
    if (function_exists('smpro_sh_sshd_effective')) { $p = (string)(smpro_sh_sshd_effective('Port') ?? ''); if (preg_match('/^\d+$/', $p)) $port = $p; }
    $w = ['LF_DISTATTACK' => '1', 'LF_SCRIPT_ALERT' => '1', 'RESTRICT_SYSLOG' => '3', 'CONNLIMIT' => $port . ';10', 'PORTFLOOD' => $port . ';tcp;20;60'];
    if (trim((string)@shell_exec('command -v ipset 2>/dev/null')) !== '') $w['LF_IPSET'] = '1';
    return $w;
}
function smpro_shh_csf_gaps(): ?array {
    $f = '/etc/csf/csf.conf'; if (!is_readable($f)) return null;
    $c = (string)@file_get_contents($f); $g = [];
    foreach (smpro_shh_csf_want() as $k => $v) {
        $cur = preg_match('/^\s*' . preg_quote($k, '/') . '\s*=\s*"([^"]*)"/m', $c, $m) ? $m[1] : null;
        if ($cur === null) continue;                       // a key this CSF version does not have
        if ($k === 'CONNLIMIT' || $k === 'PORTFLOOD') { if (trim($cur) !== '') continue; }   // keep an operator's own limits
        if ($cur !== $v) $g[$k] = [$cur, $v];
    }
    return $g;
}
// cookieipvalidation is deliberately NOT here: behind a front proxy (Imunify WebShield, a load balancer) the same visitor
// reaches cPanel sometimes as 127.0.0.1 and sometimes as their own address, and any IP binding then ends every session
// within minutes (seen on a production server the day it was applied).
function smpro_shh_tweak_want(): array { return ['maxemailsperhour' => '500', 'emailsperdaynotify' => '1000']; }
/** CSF's CC_ALLOW is not "let these countries in" - it is "never block these countries": CSF puts it as an ACCEPT
 *  jump BEFORE csf.allow, csf.deny and every rule the plugin writes, so a block on an address from a listed country
 *  is silently void. A production server had 22 countries there, including the ones its attackers came from, and
 *  90 lock blocks that never did anything. "Reach the login ports from these countries" is CC_ALLOW_PORTS, which
 *  stays as it is. Returns the current value when it is non-empty, else ''. */
function smpro_shh_csf_cc_allow(): ?string {
    $f = '/etc/csf/csf.conf'; if (!is_readable($f)) return null;
    return preg_match('/^\s*CC_ALLOW\s*=\s*"([^"]*)"/m', (string)@file_get_contents($f), $m) ? trim($m[1]) : null;
}
function smpro_shh_fix_cc_allow(): array {
    $cur = smpro_shh_csf_cc_allow(); if ($cur === null) return [false, 'CSF is not installed', []];
    if ($cur === '') return [true, 'already empty', []];
    $f = '/etc/csf/csf.conf'; $bak = smpro_shh_keep($f); if ($bak === null) return [false, 'could not back up csf.conf', []];
    $c = preg_replace('/^(\s*CC_ALLOW\s*=\s*)"[^"]*"/m', '${1}""', (string)@file_get_contents($f), 1);
    if (@file_put_contents($f, $c) === false) return [false, 'could not write csf.conf', []];
    smpro_shh_csf_reload();
    [$rc, $st] = smpro_shh_x('systemctl is-active lfd', 5);
    if (trim($st) !== 'active') { @copy($bak, $f); smpro_shh_csf_reload(); return [false, 'LFD did not come back — csf.conf put back', []]; }
    return [true, 'CC_ALLOW emptied (was "' . $cur . '"); every block now applies to those countries too; firewall reloaded', [['file', $f, $bak], ['csf']]];
}
function smpro_shh_tweak_gaps(): ?array {
    $f = '/var/cpanel/cpanel.config'; if (!is_readable($f)) return null;
    $c = (string)@file_get_contents($f); $g = [];
    foreach (smpro_shh_tweak_want() as $k => $v) {
        $cur = preg_match('/^' . preg_quote($k, '/') . '=(.*)$/m', $c, $m) ? trim($m[1]) : '';
        if ($k === 'maxemailsperhour' && $cur !== '' && (int)$cur > 0 && (int)$cur <= (int)$v) continue;   // already stricter
        if ($k === 'emailsperdaynotify' && $cur !== '' && (int)$cur > 0) continue;
        if ($cur !== $v) $g[$k] = [$cur, $v];
    }
    return $g;
}
function smpro_shh_imunify_bin(): string {
    foreach (['/usr/bin/imunify360-agent', '/usr/sbin/imunify360-agent'] as $b) if (@is_executable($b)) return $b;
    return '';
}
function smpro_shh_imunify_want(): array {
    return [['MALWARE_SCAN_SCHEDULE', 'interval', 'day'], ['PAM', 'ftp_protection', true], ['KERNELCARE', 'edf', true],
            ['PROACTIVE_DEFENCE', 'php_immunity', true], ['MALWARE_DATABASE_SCAN', 'enable', true], ['MOD_SEC', 'cms_account_compromise_prevention', true]];
}
/** null = Imunify360 not installed / not readable; else [ "SEC.key" => [current, wanted] ]. */
function smpro_shh_imunify_gaps(): ?array {
    $b = smpro_shh_imunify_bin(); if ($b === '') return null;
    [$rc, $out] = smpro_shh_x(escapeshellarg($b) . ' config show --json', 40);
    $j = json_decode($out, true); $c = $j['items'] ?? null;
    if ($rc !== 0 || !is_array($c)) return null;
    $g = [];
    foreach (smpro_shh_imunify_want() as [$s, $k, $v]) if (isset($c[$s]) && array_key_exists($k, $c[$s]) && $c[$s][$k] !== $v) $g["$s.$k"] = [$c[$s][$k], $v];
    return $g;
}

/* ---------------- fixes: return [ok, message, undo-ops] ---------------- */
function smpro_shh_fix_kernel(): array {
    $gaps = smpro_shh_sysctl_gaps(); if (!$gaps) return [true, 'already hardened', []];
    $f = '/etc/sysctl.d/90-smpro-harden.conf'; $bak = smpro_shh_keep($f);
    $lines = ['# Managed by Safety Monitor Pro — Security Health (server hardening).'];
    foreach (smpro_shh_sysctl_want() as $k => $v) if (smpro_shh_sysctl_get($k) !== null) $lines[] = "$k = $v";
    if (@file_put_contents($f, implode("\n", $lines) . "\n") === false) return [false, 'could not write ' . $f, []];
    $undo = [['file', $f, $bak]]; $done = [];
    foreach ($gaps as $k => [$cur, $v]) {
        [$rc] = smpro_shh_x('sysctl -qw ' . escapeshellarg("$k=$v"), 10);
        if ($rc === 0) { $done[] = $k; $undo[] = ['sysctl', $k, $cur]; }
    }
    return [true, count($done) . ' kernel setting(s) hardened and kept across reboots (' . $f . ')', $undo];
}
function smpro_shh_fix_shm(): array {
    $o = smpro_shh_shm_opts(); if ($o === '') return [false, '/dev/shm is not mounted', []];
    if (strpos(",$o,", ',noexec,') !== false) return [true, 'already noexec', []];
    [$rc, $msg] = smpro_shh_x('mount -o remount,noexec,nosuid,nodev /dev/shm', 15);
    if ($rc !== 0) return [false, 'remount failed: ' . $msg, []];
    $undo = [['remount', '/dev/shm', $o]];
    $fs = '/etc/fstab'; $bak = smpro_shh_keep($fs); $c = (string)@file_get_contents($fs);
    if (preg_match('#^(\S+\s+/dev/shm\s+\S+\s+)(\S+)#m', $c)) $c = preg_replace('#^(\S+\s+/dev/shm\s+\S+\s+)(\S+)#m', '${1}defaults,noexec,nosuid,nodev', $c, 1);
    else $c = rtrim($c, "\n") . "\ntmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0\n";
    if ($bak !== null && @file_put_contents($fs, $c) !== false) $undo[] = ['file', $fs, $bak];
    return [true, '/dev/shm remounted noexec,nosuid,nodev and kept in /etc/fstab — nothing can be run from shared memory', $undo];
}
function smpro_shh_fix_php(): array {
    $bad = smpro_shh_php_urlinclude(); if (!$bad) return [true, 'already off', []];
    $undo = []; $n = 0; $vers = [];
    foreach ($bad as $f) {
        $bak = smpro_shh_keep($f); if ($bak === null) continue;
        $c = preg_replace('/^\s*allow_url_include\s*=.*$/mi', 'allow_url_include = Off', (string)@file_get_contents($f));
        if (@file_put_contents($f, $c) !== false) { $undo[] = ['file', $f, $bak]; $n++; if (preg_match('#/(ea-php\d+)/#', $f, $m)) $vers[] = $m[1]; }
    }
    foreach ($vers as $v) {   // a running FPM pool reads php.ini at start only
        [$rc, $st] = smpro_shh_x('systemctl is-active ' . escapeshellarg($v . '-php-fpm'), 5);
        if (trim($st) === 'active') { smpro_shh_x('systemctl restart ' . escapeshellarg($v . '-php-fpm'), 60); $undo[] = ['fpm', $v]; }
    }
    return [$n > 0, "allow_url_include turned Off in $n php.ini file(s)", $undo];
}
function smpro_shh_csf_reload(): void { smpro_shh_x('csf -r', 120); smpro_shh_x('systemctl restart lfd', 60); }
function smpro_shh_fix_csf(): array {
    $g = smpro_shh_csf_gaps(); if ($g === null) return [false, 'CSF is not installed', []];
    if (!$g) return [true, 'already hardened', []];
    $f = '/etc/csf/csf.conf'; $bak = smpro_shh_keep($f); if ($bak === null) return [false, 'could not back up csf.conf', []];
    $c = (string)@file_get_contents($f);
    foreach ($g as $k => [$cur, $v]) $c = preg_replace('/^(\s*' . preg_quote($k, '/') . '\s*=\s*)"[^"]*"/m', '${1}"' . $v . '"', $c, 1);
    if (@file_put_contents($f, $c) === false) return [false, 'could not write csf.conf', []];
    smpro_shh_csf_reload();
    [$rc, $st] = smpro_shh_x('systemctl is-active lfd', 5);
    if (trim($st) !== 'active') { @copy($bak, $f); smpro_shh_csf_reload(); return [false, 'LFD did not come back — csf.conf put back', []]; }
    $d = []; foreach ($g as $k => [$cur, $v]) $d[] = "$k \"$cur\" → \"$v\"";
    return [true, 'CSF: ' . implode(', ', $d) . '; firewall reloaded', [['file', $f, $bak], ['csf']]];
}
function smpro_shh_whmapi(): string { foreach (['/usr/local/cpanel/bin/whmapi1', '/usr/sbin/whmapi1'] as $b) if (@is_executable($b)) return $b; return ''; }
function smpro_shh_fix_tweaks(): array {
    $g = smpro_shh_tweak_gaps(); $w = smpro_shh_whmapi();
    if ($g === null || $w === '') return [false, 'cPanel tweak settings are not available', []];
    if (!$g) return [true, 'already set', []];
    $undo = []; $d = [];
    foreach ($g as $k => [$cur, $v]) {
        [$rc, $o] = smpro_shh_x(escapeshellarg($w) . ' set_tweaksetting key=' . escapeshellarg($k) . ' value=' . escapeshellarg($v), 60);
        if ($rc === 0 && strpos($o, 'result: 1') !== false) { $undo[] = ['tweak', $k, $cur]; $d[] = "$k → $v"; }
    }
    return [(bool)$d, 'cPanel: ' . ($d ? implode(', ', $d) : 'nothing could be set'), $undo];
}
function smpro_shh_fix_imunify(): array {
    $g = smpro_shh_imunify_gaps(); $b = smpro_shh_imunify_bin();
    if ($g === null) return [false, 'Imunify360 is not installed or did not answer', []];
    if (!$g) return [true, 'already set', []];
    $want = []; $old = [];
    foreach ($g as $sk => [$cur, $v]) { [$s, $k] = explode('.', $sk, 2); $want[$s][$k] = $v; $old[$s][$k] = $cur; }
    [$rc, $o] = smpro_shh_x(escapeshellarg($b) . ' config update ' . escapeshellarg(json_encode($want)), 60);
    if ($rc !== 0) return [false, 'Imunify360 refused the change: ' . substr($o, 0, 200), []];
    return [true, 'Imunify360: ' . implode(', ', array_keys($g)) . ' updated', [['imunify', json_encode($old)]]];
}

/* ---------------- undo ---------------- */
function smpro_shh_undo_ops(array $ops): array {
    $bad = [];
    foreach (array_reverse($ops) as $op) {
        switch ($op[0] ?? '') {
            case 'file':
                [$_, $f, $b] = $op;
                if ($b === null) { if (is_file($f) && !@unlink($f)) $bad[] = "remove $f"; }
                elseif (!is_file($b) || !@copy($b, $f)) $bad[] = "restore $f";
                break;
            case 'sysctl':  [$rc] = smpro_shh_x('sysctl -qw ' . escapeshellarg($op[1] . '=' . $op[2]), 10); if ($rc !== 0) $bad[] = $op[1]; break;
            case 'remount': [$rc] = smpro_shh_x('mount -o ' . escapeshellarg('remount,' . $op[2]) . ' ' . escapeshellarg($op[1]), 15); if ($rc !== 0) $bad[] = 'remount ' . $op[1]; break;
            case 'csf':     smpro_shh_csf_reload(); break;
            case 'fpm':     smpro_shh_x('systemctl restart ' . escapeshellarg($op[1] . '-php-fpm'), 60); break;
            case 'tweak':   $w = smpro_shh_whmapi(); if ($w !== '') smpro_shh_x(escapeshellarg($w) . ' set_tweaksetting key=' . escapeshellarg($op[1]) . ' value=' . escapeshellarg((string)$op[2]), 60); break;
            case 'imunify': $b = smpro_shh_imunify_bin(); if ($b !== '') { [$rc] = smpro_shh_x(escapeshellarg($b) . ' config update ' . escapeshellarg((string)$op[1]), 60); if ($rc !== 0) $bad[] = 'imunify'; } break;
        }
    }
    return $bad;
}
/** Undo the newest not-yet-undone change of $id ('' = every change, newest first). */
function smpro_shh_undo(string $id): array {
    $j = smpro_shh_journal(); $n = 0; $bad = [];
    for ($i = count($j) - 1; $i >= 0; $i--) {
        if ($j[$i]['undone'] || ($id !== '' && $j[$i]['id'] !== $id)) continue;
        $bad = array_merge($bad, smpro_shh_undo_ops((array)$j[$i]['undo']));
        $j[$i]['undone'] = true; $n++;
        if ($id !== '') break;
    }
    smpro_shh_journal_save($j);
    if (!$n) return [false, 'nothing to undo'];
    return [!$bad, $n . ' change(s) put back' . ($bad ? '; could not restore: ' . implode(', ', $bad) : '')];
}
function smpro_shh_undoable(): array {
    $u = []; foreach (smpro_shh_journal() as $e) if (!$e['undone'] && $e['undo']) $u[$e['id']] = true;
    return $u;
}

/** The registry the Security Health page uses: id => [label, apply callable]. */
function smpro_shh_fixes(): array {
    return [
        'kernel_harden'  => ['Kernel network & info-leak settings', 'smpro_shh_fix_kernel'],
        'shm_noexec'     => ['/dev/shm without exec', 'smpro_shh_fix_shm'],
        'php_urlinclude' => ['PHP allow_url_include Off', 'smpro_shh_fix_php'],
        'csf_harden'     => ['CSF/LFD hardening', 'smpro_shh_fix_csf'],
        'mail_caps'      => ['Outgoing mail caps', 'smpro_shh_fix_tweaks'],
        'csf_cc_allow'   => ['Country exemption that voids every block', 'smpro_shh_fix_cc_allow'],
        'imunify_harden' => ['Imunify360 protection settings', 'smpro_shh_fix_imunify'],
    ];
}
function smpro_shh_apply(string $id): array {
    $f = smpro_shh_fixes()[$id] ?? null; if (!$f) return [false, 'unknown fix'];
    [$ok, $msg, $undo] = call_user_func($f[1]);
    if ($ok && $undo) smpro_shh_journal_add($id, $undo, $msg);
    return [$ok, $msg];
}

/** WP Guard WHM status, read from its own database in read-only mode (never written, never locked for long).
 *  null when WP Guard is not installed. */
function smpro_shh_wpguard_status(): ?array {
    if (!function_exists('smpro_wpguard_whm')) return null;
    $w = smpro_wpguard_whm(); if (!$w['installed']) return null;
    $s = ['version' => $w['version'], 'url' => $w['url'], 'sites' => null, 'open' => [], 'read' => false];
    $bin = trim((string)@shell_exec('command -v sqlite3 2>/dev/null'));
    if ($w['db'] === '' || $bin === '') return $s;
    $q = function (string $sql) use ($bin, $w) { return trim((string)@shell_exec('timeout 10 ' . escapeshellarg($bin) . ' -readonly -cmd ' . escapeshellarg('.timeout 3000') . ' ' . escapeshellarg($w['db']) . ' ' . escapeshellarg($sql) . ' 2>/dev/null')); };
    $n = $q("SELECT COUNT(*) FROM wg_sites WHERE platform='wordpress'");
    if ($n !== '' && ctype_digit($n)) { $s['sites'] = (int)$n; $s['read'] = true; }
    foreach (explode("\n", $q("SELECT sev, COUNT(*) FROM wg_cx WHERE status='open' GROUP BY sev")) as $l) { $p = explode('|', $l); if (count($p) === 2 && ctype_digit($p[1])) $s['open'][$p[0]] = (int)$p[1]; }
    return $s;
}

/** Checks for the "Server Hardening" category (same shape as smpro_sh_mk). */
function smpro_shh_checks(): array {
    $C = [];
    $wg = smpro_shh_wpguard_status();
    if ($wg !== null) {
        $serious = (int)($wg['open']['crit'] ?? 0) + (int)($wg['open']['high'] ?? 0);
        $ev = 'WP Guard ' . $wg['version'] . "\nWordPress sites in its inventory: " . ($wg['sites'] ?? 'unreadable') . "\nOpen Compromise-check findings: " . ($wg['open'] ? json_encode($wg['open']) : 'none');
        $C[] = smpro_sh_mk('WP Guard (WHM) — WordPress protection', !$wg['read'] ? 'info' : ($serious ? 'warning' : 'ok'),
            !$wg['read'] ? 'WP Guard ' . $wg['version'] . ' is installed; its database could not be read.' : ('WP Guard ' . $wg['version'] . ' protects ' . (int)$wg['sites'] . ' WordPress site(s); ' . ($serious ? $serious . ' critical/high Compromise-check finding(s) are open.' : 'no critical or high finding is open.')),
            'WP Guard cleans WordPress sites (planted plugins, database malware, hidden admins) and keeps every original in its root-only quarantine. SM Pro reads its status only and never alerts on, cleans or deletes the files in that quarantine, so WP Guard\'s Undo keeps working.',
            $serious ? 'Open WP Guard > Threats > Compromise check and fix the open findings there (each fix has Undo).' : 'No action needed.',
            $ev);
    }
    $sg = smpro_shh_sysctl_gaps(); $ev = ''; foreach ($sg as $k => [$c, $v]) $ev .= "$k = $c (want $v)\n";
    $C[] = smpro_sh_mk('Kernel network & info-leak settings', $sg ? 'warning' : 'ok',
        $sg ? count($sg) . ' kernel setting(s) weaker than recommended.' : 'Redirects, source routing, dmesg/kptr/ptrace and protected files are hardened.',
        'ICMP redirects let a neighbour reroute traffic; readable kernel pointers and dmesg help a local exploit; unrestricted ptrace lets one process of an account read another\'s memory; unprotected FIFOs/regular files in sticky folders allow the same tricks as symlinks.',
        $sg ? 'Apply: every value is set now and kept across reboots in /etc/sysctl.d. Undo puts back the exact previous values.' : 'No action needed.', $ev, $sg ? 'kernel_harden' : '');
    $o = smpro_shh_shm_opts(); $shmBad = $o !== '' && strpos(",$o,", ',noexec,') === false;
    $C[] = smpro_sh_mk('/dev/shm noexec', $o === '' ? 'info' : ($shmBad ? 'warning' : 'ok'),
        $o === '' ? '/dev/shm is not mounted.' : ($shmBad ? '/dev/shm allows running programs (' . $o . ').' : '/dev/shm is mounted noexec.'),
        'Malware that rebuilds itself after every clean-up keeps a copy in shared memory and runs it from /dev/shm. Without exec there nothing planted in it can start.',
        $shmBad ? 'Apply: remount noexec,nosuid,nodev now and keep it in /etc/fstab.' : 'No action needed.', $o, $shmBad ? 'shm_noexec' : '');
    $pb = smpro_shh_php_urlinclude();
    $C[] = smpro_sh_mk('PHP allow_url_include', $pb ? 'critical' : 'ok',
        $pb ? 'allow_url_include is On in ' . count($pb) . ' PHP build(s).' : 'No PHP build allows including code from a URL.',
        'With allow_url_include On, one file-inclusion bug in any site runs code fetched from the attacker\'s server.',
        $pb ? 'Apply: set it Off in each listed php.ini (each one kept first); running PHP-FPM pools are restarted.' : 'No action needed.', implode("\n", $pb), $pb ? 'php_urlinclude' : '');
    $cg = smpro_shh_csf_gaps();
    if ($cg !== null) { $ev = ''; foreach ($cg as $k => [$c, $v]) $ev .= "$k = \"$c\" (want \"$v\")\n";
        $C[] = smpro_sh_mk('CSF/LFD attack detection', $cg ? 'warning' : 'ok',
            $cg ? count($cg) . ' CSF setting(s) weaker than recommended.' : 'Distributed-attack and mail-script detection, syslog restriction and SSH connection limits are on.',
            'Without LF_DISTATTACK a password-spraying botnet that uses one try per address is never blocked; without LF_SCRIPT_ALERT a hacked site that sends spam is never reported; without SSH connection limits brute force runs at line speed.',
            $cg ? 'Apply: csf.conf is kept, the values are changed, and the firewall reloads. If LFD does not come back, the old file is put back automatically.' : 'No action needed.', $ev, $cg ? 'csf_harden' : ''); }
    $cca = smpro_shh_csf_cc_allow();
    if ($cca !== null) {
        $C[] = smpro_sh_mk('Country exemption that voids every block (CSF CC_ALLOW)', $cca !== '' ? 'critical' : 'ok',
            $cca !== '' ? 'CC_ALLOW lists ' . count(array_filter(explode(',', $cca))) . ' countr' . (count(array_filter(explode(',', $cca))) === 1 ? 'y' : 'ies') . ': addresses there can never be blocked.' : 'CC_ALLOW is empty.',
            'CSF places CC_ALLOW as an ACCEPT before csf.allow, csf.deny and every rule this plugin writes. An attacker from a listed country passes every block - the Country Login Lock, Intrusion Monitor, WP Guard and manual denies all become void for that country. Letting countries REACH the login ports is CC_ALLOW_PORTS, a different setting that is left as it is.',
            $cca !== '' ? 'Apply: CC_ALLOW is emptied (csf.conf kept first) and the firewall reloads; if LFD does not come back the old file is put back automatically. Undo restores it.' : 'No action needed.',
            $cca !== '' ? 'CC_ALLOW = "' . $cca . '"' : '', $cca !== '' ? 'csf_cc_allow' : '');
    }
    $tg = smpro_shh_tweak_gaps();
    if ($tg !== null) { $ev = ''; foreach ($tg as $k => [$c, $v]) $ev .= "$k = '" . $c . "' (want '$v')\n";
        $C[] = smpro_sh_mk('Outgoing mail caps', $tg ? 'warning' : 'ok',
            $tg ? 'No per-domain hourly cap on outgoing mail.' : 'Outgoing mail is capped per domain.',
            'A single hacked site can send tens of thousands of messages in an hour and get the server\'s address blacklisted for every customer.',
            $tg ? 'Apply: 500 messages per domain per hour, and a notice at 1000 per day.' : 'No action needed.', $ev, $tg ? 'mail_caps' : ''); }
    $ig = smpro_shh_imunify_gaps();
    if ($ig !== null) { $ev = ''; foreach ($ig as $k => [$c, $v]) $ev .= $k . ' = ' . json_encode($c) . ' (want ' . json_encode($v) . ")\n";
        $C[] = smpro_sh_mk('Imunify360 protection settings', $ig ? 'warning' : 'ok',
            $ig ? count($ig) . ' Imunify360 setting(s) weaker than recommended.' : 'Daily scans, FTP brute-force protection and kernel exploit detection are on.',
            'A weekly scan leaves a planted file working for days; FTP without PAM protection is brute-forced freely; exploit detection catches privilege escalation the scanner cannot see.',
            $ig ? 'Apply: the listed settings are changed through imunify360-agent; Undo sets the previous values back.' : 'No action needed.', $ev, $ig ? 'imunify_harden' : ''); }
    return $C;
}
