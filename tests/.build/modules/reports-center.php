<?php
/**
 * modules/reports-center.php — Reports Center.
 * Two things: (1) a comprehensive per-IP report pulling everything the plugin knows about
 * an address (geo/ASN/reputation, firewall status, 30-day web-attack profile from the index),
 * with Block / Allow / export; and (2) a directory of every saved report across all sections.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

/* Collect saved reports from every section's store into one list. */
function smpro_rc_collect() {
    $out = [];
    foreach ([
        ['sec'=>'Intrusion Monitor','idx'=>SMPRO_VARLIB.'/reports/intrusion/index.json','page'=>'intrusion-monitor&tab=reports'],
        ['sec'=>'Account Audit',    'idx'=>SMPRO_VARLIB.'/reports/index.json',           'page'=>'account-audit'],
        ['sec'=>'Forensics',        'idx'=>SMPRO_VARLIB.'/reports/forensics/index.json',  'page'=>'forensics-audit'],
    ] as $s) {
        $idx = is_file($s['idx']) ? json_decode((string)@file_get_contents($s['idx']), true) : [];
        if (is_array($idx)) foreach ($idx as $r) $out[] = ['sec'=>$s['sec'],'page'=>$s['page'],
            'name'=>(string)($r['name'] ?? $r['created'] ?? $r['id'] ?? 'report'),
            'date'=>(string)($r['at'] ?? $r['created'] ?? ''),'ts'=>(int)($r['ts'] ?? $r['created_ts'] ?? 0),
            'extra'=>isset($r['total']) ? $r['total'].' rows' : (isset($r['domains']) ? $r['domains'].' domains' : '')];
    }
    foreach ([
        ['sec'=>'DB Cleanup','dir'=>SMPRO_VARLIB.'/reports/db_cleanup','page'=>'database-cleanup'],
        ['sec'=>'Imunify Detections','dir'=>SMPRO_VARLIB.'/reports/detections','page'=>'imunify360-reports'],
        ['sec'=>'Disk Deletions','dir'=>SMPRO_VARLIB.'/reports/disk_deletions','page'=>'disk-storage'],
        ['sec'=>'Emergency Actions','dir'=>SMPRO_VARLIB.'/profiles','page'=>'intrusion-monitor&tab=emergency'],
    ] as $d) {
        foreach (glob($d['dir'].'/*.json') ?: [] as $f) { if (basename($f) === 'index.json') continue;
            $out[] = ['sec'=>$d['sec'],'page'=>$d['page'],'name'=>basename($f,'.json'),'date'=>date('Y-m-d H:i',(int)@filemtime($f)),'ts'=>(int)@filemtime($f),'extra'=>smpro_rc_bytes((int)@filesize($f))];
        }
    }
    usort($out, fn($a,$b) => $b['ts'] <=> $a['ts']);
    return $out;
}
function smpro_rc_bytes($b) { $u=['B','KB','MB','GB']; $i=0; while($b>=1024&&$i<3){$b/=1024;$i++;} return round($b,$i?1:0).$u[$i]; }

/* ---- Live IP Watch: every request an IP makes across all domains, from domlogs ---- */
function smpro_rc_domlogs_base() { foreach (['/etc/apache2/logs/domlogs','/usr/local/apache/domlogs','/var/log/apache2/domlogs'] as $p) if (is_dir($p)) return $p; return ''; }
function smpro_rc_alog_ts($t) { if (preg_match('#^(\d{1,2})/(\w{3})/(\d{4}):(\d{2}:\d{2}:\d{2})#', $t, $m)) return strtotime($m[1].' '.$m[2].' '.$m[3].' '.$m[4]) ?: 0; return strtotime($t) ?: 0; }
/** Recent requests from one IP across every hosted domain (bounded, throttled grep of domlogs). */
function smpro_rc_ip_live($ip, $limit = 150) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return [];
    $base = smpro_rc_domlogs_base(); if ($base === '') return [];
    $cmd = 'timeout 25 nice -n 19 ionice -c3 grep -rHF ' . escapeshellarg($ip . ' ') . ' ' . escapeshellarg($base)
         . ' 2>/dev/null | grep -avE "bytes_log:|/ftp" | tail -n 4000';
    $raw = (string)@shell_exec($cmd);
    $rows = [];
    foreach (explode("\n", $raw) as $l) {
        if (!preg_match('#^([^:]+):(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d{3})\s+(\S+)#', $l, $m)) continue;
        if ($m[2] !== $ip) continue;                          // IP must be the request's client (line start), not coincidental
        $dom = basename($m[1]); if (substr($dom, -8) === '-ssl_log') $dom = substr($dom, 0, -8);
        $method = ''; $path = ''; if (preg_match('#^(\S+)\s+(\S+)#', $m[4], $rm)) { $method = $rm[1]; $path = $rm[2]; }
        $ua = preg_match('/"[^"]*"\s+"([^"]*)"\s*$/', $l, $um) ? $um[1] : '';
        $rows[] = ['ts'=>smpro_rc_alog_ts($m[3]),'domain'=>$dom,'method'=>$method,'path'=>$path,'status'=>(int)$m[5],'bytes'=>$m[6],'ua'=>$ua];
        if (count($rows) >= 5000) break;
    }
    usort($rows, fn($a, $b) => $b['ts'] <=> $a['ts']);
    return array_slice($rows, 0, $limit);
}
/** Parse ?from / ?to (YYYY-MM-DD) → [sinceTs, untilTs] (0 = open). */
function smpro_rc_range() {
    $f = isset($_GET['from']) && $_GET['from'] !== '' ? strtotime($_GET['from'] . ' 00:00:00') : 0;
    $t = isset($_GET['to']) && $_GET['to'] !== '' ? strtotime($_GET['to'] . ' 23:59:59') : 0;
    return [$f ?: 0, $t ?: 0];
}
/** Human label for an audited action (prettify + a few known names). */
function smpro_rc_op_label($a) {
    static $map = [
        'intrusion_block'=>'Blocked (CSF/Cloudflare)','intrusion_allow'=>'Allowed (CSF + allowlist)','reports_center_block'=>'Blocked from Reports','reports_center_allow'=>'Allowed from Reports',
        'login_monitor_csf_block'=>'Blocked (Login&Access)','login_monitor_csf_allow'=>'Allowed','login_monitor_csf_unblock'=>'Unblocked','login_access_csf_block'=>'Blocked','login_access_csf_allow'=>'Allowed','login_access_csf_unblock'=>'Unblocked',
        'firewall_unblock'=>'Unblocked (Firewall)','intrusion_emergency'=>'Emergency response','intrusion_emergency_manual'=>'Emergency (manual)','intrusion_block_auto'=>'Auto-blocked',
    ];
    return $map[$a] ?? ucfirst(str_replace('_', ' ', (string)$a));
}
/** Every audited OPERATION performed on/about this IP (block, allow, emergency, …), within the window. */
function smpro_rc_ip_operations($ip, $sinceTs = 0, $untilTs = 0, $limit = 200) {
    if (!defined('SMPRO_AUDIT_LOG') || !is_file(SMPRO_AUDIT_LOG)) return [];
    $since = $sinceTs ?: (time() - 90 * 86400); $until = $untilTs ?: time();
    $raw = (string)@shell_exec('timeout 15 grep -aF ' . escapeshellarg($ip) . ' ' . escapeshellarg(SMPRO_AUDIT_LOG) . ' 2>/dev/null | tail -n 4000');
    $out = [];
    foreach (explode("\n", $raw) as $l) {
        $l = trim($l); if ($l === '') continue;
        $j = json_decode($l, true); if (!is_array($j) || empty($j['action'])) continue;
        $det = $j['details'] ?? []; $detStr = is_array($det) ? json_encode($det, JSON_UNESCAPED_SLASHES) : (string)$det;
        if (strpos($detStr, $ip) === false) continue;                 // target IP must be in the action's details
        $ts = strtotime($j['timestamp'] ?? '') ?: 0;
        if ($ts < $since || $ts > $until) continue;
        $res = '';
        if (is_array($det)) { if (isset($det['ok'])) $res = $det['ok'] ? 'ok' : 'failed'; if (!empty($det['msg'])) $res .= ($res ? ' — ' : '') . $det['msg']; if (!empty($det['action'])) $res = $det['action'] . ($res ? ' · ' . $res : ''); }
        $out[] = ['ts'=>$ts,'action'=>$j['action'],'label'=>smpro_rc_op_label($j['action']),'actor'=>$j['actor'] ?? 'root','admin_ip'=>$j['ip'] ?? '','result'=>$res];
    }
    usort($out, fn($a, $b) => $b['ts'] <=> $a['ts']);
    return array_slice($out, 0, $limit);
}
/** Build the full per-IP report (read-only) within an optional date window. */
function smpro_rc_ip_report($ip, $sinceTs = 0, $untilTs = 0) {
    $intel = function_exists('smpro_ip_intel') ? smpro_ip_intel($ip, false) : [];
    $csf   = function_exists('smpro_im_csf_blocked') ? smpro_im_csf_blocked() : [];
    return [
        'ip'=>$ip,
        'country'=>strtoupper((string)($intel['country'] ?? '')),'provider'=>(string)($intel['provider'] ?? ''),'asn'=>(string)($intel['asn'] ?? ''),
        'datacenter'=>function_exists('smpro_ip_is_datacenter') && smpro_ip_is_datacenter($intel),
        'external'=>!function_exists('smpro_ip_is_external') || smpro_ip_is_external($ip),
        'server_ip'=>function_exists('smpro_is_server_ip') && smpro_is_server_ip($ip),
        'abuse'=>function_exists('smpro_im_abuse_score') ? smpro_im_abuse_score($ip) : '',
        'csf'=>$csf[$ip] ?? '', 'allowlisted'=>function_exists('smpro_im_allowlisted') && smpro_im_allowlisted($ip),
        'attacks'=>function_exists('smpro_in_ip_summary') ? smpro_in_ip_summary($ip, $sinceTs, $untilTs) : ['total'=>0],
        'operations'=>smpro_rc_ip_operations($ip, $sinceTs, $untilTs),
    ];
}

/* ---------------- Incident analysis — read the logs for an outage window and infer the cause ---------------- */
function smpro_rc_logcmd($cmd) { return (string)@shell_exec('timeout 25 ' . $cmd . ' 2>/dev/null'); }
function smpro_rc_has($bin) { return trim(smpro_rc_logcmd('command -v ' . escapeshellarg($bin))) !== ''; }

/**
 * Analyse an outage window [$fromTs,$toTs]: pull system/firewall/kernel logs for that time,
 * decide whether the box rebooted / ran out of memory / was flooded / was up-but-unreachable,
 * and return a structured report with a probable cause + recommendations. Read-only.
 */
/** grep -E alternation of the syslog "Mon  D" date prefix for EVERY day in [from,to] (capped) so a
 *  multi-day window reads all of its days, not just the first. e.g. "Jun [ ]?20|Jun [ ]?21". */
function smpro_rc_day_pats($fromTs, $toTs) {
    $pats = []; $d = strtotime(date('Y-m-d', $fromTs)); $n = 0;
    while ($d <= $toTs && $n++ < 40) { $pats[date('M [ ]?j', $d)] = 1; $d += 86400; }
    return implode('|', array_keys($pats)) ?: date('M [ ]?j', $fromTs);
}
function smpro_rc_outage_analyze($fromTs, $toTs) {
    $rep = ['from'=>$fromTs, 'to'=>$toTs, 'events'=>[], 'reboot'=>null, 'reboot_attr'=>null, 'continuity'=>null, 'sar'=>[], 'cause'=>'', 'confidence'=>'low', 'recommend'=>[], 'fixes'=>[]];
    if (!$fromTs || !$toTs || $toTs <= $fromTs) { $rep['cause'] = 'Invalid time window.'; return $rep; }
    $dayPat = smpro_rc_day_pats($fromTs, $toTs);   // multi-day date pattern for the date-keyed log greps
    $fromStr = date('Y-m-d H:i:s', $fromTs); $toStr = date('Y-m-d H:i:s', $toTs);
    $add = function ($ts, $sev, $src, $txt) use (&$rep) { $t = trim((string)$txt); if ($t === '') return; $rep['events'][] = ['ts'=>(int)$ts, 'sev'=>$sev, 'src'=>$src, 'txt'=>mb_substr($t, 0, 220)]; };
    $hasJournal = smpro_rc_has('journalctl');

    // 1) reboot / boot inside (or right after) the window
    $bootTs = (int)trim(smpro_rc_logcmd('date -d "$(uptime -s 2>/dev/null)" +%s 2>/dev/null'));
    if ($bootTs && $bootTs >= $fromTs - 300 && $bootTs <= $toTs + 900) {
        $rep['reboot'] = $bootTs;
        $rep['reboot_attr'] = smpro_rc_reboot_attribution($bootTs);   // WHO / WHAT caused it
        $add($bootTs, $rep['reboot_attr']['sev'] ?? 'critical', 'system', 'Server BOOTED at ' . date('Y-m-d H:i', $bootTs) . ' — ' . ($rep['reboot_attr']['text'] ?? 'a reboot/crash happened in this window'));
        if (!empty($rep['reboot_attr']['evidence'])) foreach (array_slice(explode("\n", $rep['reboot_attr']['evidence']), 0, 4) as $el) $add($bootTs, 'warn', 'shutdown', $el);
    }

    // 2) kernel / system events in the window
    if ($hasJournal) {
        $jc = smpro_rc_logcmd('journalctl --since ' . escapeshellarg($fromStr) . ' --until ' . escapeshellarg($toStr) . ' --no-pager 2>/dev/null | grep -iE "out of memory|oom-kill|killed process|kernel panic|hung task|watchdog|shutting down|systemd.*Reboot|emergency mode|segfault|link is down|EXT4-fs error" | head -40');
        foreach (array_filter(array_map('trim', explode("\n", $jc))) as $l) $add($fromTs, preg_match('/out of memory|oom|panic|watchdog|ext4-fs error/i', $l) ? 'critical' : 'warn', 'journal', $l);
    } elseif (is_readable('/var/log/messages')) {
        $mg = smpro_rc_logcmd('grep -E ' . escapeshellarg($dayPat) . ' /var/log/messages 2>/dev/null | grep -iE "out of memory|killed process|panic|watchdog|shutting down|reboot|segfault" | head -40');
        foreach (array_filter(array_map('trim', explode("\n", $mg))) as $l) $add($fromTs, 'warn', 'messages', $l);
    }

    // 3) OOM via dmesg (timestamps may be relative — informational)
    $oom = smpro_rc_logcmd('dmesg -T 2>/dev/null | grep -iE "out of memory|killed process|oom-kill" | tail -8');
    foreach (array_filter(array_map('trim', explode("\n", $oom))) as $l) $add($fromTs, 'critical', 'dmesg', $l);

    // 4) CSF / LFD flood or mass-block in the window
    if (is_readable('/var/log/lfd.log')) {
        $lfd = smpro_rc_logcmd('grep -E ' . escapeshellarg($dayPat) . ' /var/log/lfd.log 2>/dev/null | grep -iE "SYNFLOOD|DENY|conntrack|limit|blocked" | head -30');
        $n = 0; foreach (array_filter(array_map('trim', explode("\n", $lfd))) as $l) { if ($n++ >= 8) break; $add($fromTs, stripos($l, 'synflood') !== false ? 'critical' : 'warn', 'lfd', $l); }
    }

    // 5) was the box UP and logging mid-window? (up+logging but unreachable ⇒ network/null-route)
    if ($hasJournal) {
        $mid = (int)(($fromTs + $toTs) / 2);
        $cont = (int)trim(smpro_rc_logcmd('journalctl --since ' . escapeshellarg(date('Y-m-d H:i:s', $mid - 150)) . ' --until ' . escapeshellarg(date('Y-m-d H:i:s', $mid + 150)) . ' --no-pager 2>/dev/null | wc -l'));
        $rep['continuity'] = $cont > 3;
    }

    // 6) sar history (sysstat) — load / memory / network around the window
    if (smpro_rc_has('sar')) {
        $h1 = date('H:i:s', $fromTs); $h2 = date('H:i:s', $toTs);
        $rep['sar']['load'] = trim(smpro_rc_logcmd('sar -q -s ' . $h1 . ' -e ' . $h2 . ' 2>/dev/null | tail -16'));
        $rep['sar']['mem']  = trim(smpro_rc_logcmd('sar -r -s ' . $h1 . ' -e ' . $h2 . ' 2>/dev/null | tail -10'));
        $rep['sar']['net']  = trim(smpro_rc_logcmd('sar -n DEV -s ' . $h1 . ' -e ' . $h2 . ' 2>/dev/null | grep -iE "eth0|ens|enp|bond" | tail -16'));
    }

    // 6b) DEEP read — every relevant log for the window, not just kernel/firewall
    $win = function ($cmd) { return smpro_rc_logcmd($cmd); };
    $grab = function ($lines, $sev, $src, $max = 6) use (&$add, $fromTs) {
        $n = 0; foreach (array_filter(array_map('trim', explode("\n", (string)$lines))) as $l) { if ($n++ >= $max) break; $add($fromTs, $sev, $src, $l); }
    };
    // failed systemd services right now + service crashes in window
    if ($hasJournal) {
        $grab($win('systemctl --failed --no-legend 2>/dev/null | head -8'), 'critical', 'services', 8);
        $grab($win('journalctl --since ' . escapeshellarg($fromStr) . ' --until ' . escapeshellarg($toStr) . ' --no-pager 2>/dev/null | grep -iE "Failed with result|core-dump|segfault|Main process exited|Start request repeated|Stopping|entered failed" | head -20'), 'warn', 'services', 8);
    }
    // MySQL / MariaDB crashes — multi-day date pattern (both ymd + Y-m-d formats, every day in the window)
    $myDays = []; $md = strtotime(date('Y-m-d', $fromTs)); $mn = 0;
    while ($md <= $toTs && $mn++ < 40) { $myDays[date('ymd', $md)] = 1; $myDays[date('Y-m-d', $md)] = 1; $md += 86400; }
    $myPat = implode('|', array_keys($myDays));
    foreach (['/var/lib/mysql/*.err', '/var/log/mysqld.log', '/var/log/mariadb/mariadb.log'] as $mf)
        $grab($win('grep -ihE ' . escapeshellarg($myPat) . ' ' . $mf . ' 2>/dev/null | grep -iE "crash|got signal|InnoDB:.*(corrupt|assertion)|Out of memory|mysqld got|restart" | tail -8'), 'critical', 'mysql', 6);
    // Apache / LiteSpeed / PHP-FPM errors
    foreach (['/etc/apache2/logs/error_log', '/usr/local/apache/logs/error_log', '/var/log/apache2/error_log', '/usr/local/lsws/logs/error.log'] as $af)
        if (is_readable($af)) $grab($win('grep -aE ' . escapeshellarg($dayPat) . ' ' . escapeshellarg($af) . ' 2>/dev/null | grep -iE "segfault|MaxRequestWorkers|MaxClients|out of memory|cannot allocate|child pid .* exit signal|server reached" | tail -8'), 'warn', 'web', 6);
    // Exim panic
    if (is_readable('/var/log/exim_paniclog')) $grab($win('tail -8 /var/log/exim_paniclog 2>/dev/null'), 'warn', 'exim', 6);
    // disk full anywhere in the window
    if ($hasJournal) $grab($win('journalctl --since ' . escapeshellarg($fromStr) . ' --until ' . escapeshellarg($toStr) . ' --no-pager 2>/dev/null | grep -iE "No space left on device|disk full|quota exceeded" | head -8'), 'critical', 'disk', 6);
    $grab($win("df -P 2>/dev/null | awk 'NR>1 && \$5+0>=95 {print \$6\" is \"\$5\" full (\"\$4\" free)\"}'"), 'critical', 'disk', 6);
    // SSH logins / sudo around the window (context for manual actions)
    foreach (['/var/log/secure', '/var/log/auth.log'] as $sf) if (is_readable($sf))
        $grab($win('grep -aE ' . escapeshellarg($dayPat) . ' ' . escapeshellarg($sf) . ' 2>/dev/null | grep -iE "Accepted (password|publickey)|sudo:.*COMMAND|Failed password" | tail -10'), 'info', 'secure', 6);

    // 7) heuristic conclusion
    $txtAll = strtolower(implode(' ', array_map(fn($e) => $e['txt'], $rep['events'])));
    $hasOOM = strpos($txtAll, 'memory') !== false || strpos($txtAll, 'oom') !== false;
    $hasFlood = strpos($txtAll, 'synflood') !== false;
    if ($hasOOM) { $rep['cause'] = 'Out of memory — the kernel killed processes (RAM exhaustion). The box likely became unresponsive until memory freed or it rebooted.'; $rep['confidence'] = 'high'; $rep['recommend'][] = 'Find the memory hog in Top Processes / Load Monitor; add swap or tune limits.'; }
    elseif ($rep['reboot'] !== null) { $rep['cause'] = 'The server REBOOTED at ' . date('H:i', (int)$rep['reboot']) . '. ' . ($rep['reboot_attr']['text'] ?? 'A boot was detected in this window.'); $rep['confidence'] = 'high'; $rep['recommend'][] = ($rep['reboot_attr']['auto'] ?? true) ? 'It was not a person — investigate the crash/power cause above and add monitoring.' : 'It was a manual/clean reboot — confirm who/what scheduled it.'; }
    elseif ($hasFlood) { $rep['cause'] = 'Network flood — CSF/LFD SYNFLOOD/connection-limit mitigation fired, which can make the server unreachable during an attack.'; $rep['confidence'] = 'medium'; $rep['recommend'][] = 'Review the attacking IPs in the Firewall log; consider upstream/Cloudflare DDoS protection.'; }
    elseif ($rep['continuity'] === true) { $rep['cause'] = 'The server was UP and logging throughout the window but was unreachable from outside — most consistent with a provider null-route / upstream DDoS mitigation, or a network/route issue (NOT the server going down).'; $rep['confidence'] = 'medium'; $rep['recommend'][] = 'Check the hosting provider panel (traffic graphs / DDoS / abuse) for this exact window.'; }
    elseif ($rep['continuity'] === false) { $rep['cause'] = 'No system logging during the window — the server was most likely DOWN (crash / hang / power) and recovered afterwards.'; $rep['confidence'] = 'medium'; $rep['recommend'][] = 'Check hardware/IPMI + the provider panel; look for an fsck or long boot afterwards.'; }
    else { $rep['cause'] = 'No strong signal in the available logs — inconclusive. Widen the window, ensure sysstat (sar) is installed, and check the provider panel.'; $rep['confidence'] = 'low'; }
    $rep['recommend'][] = 'Cross-check Forensics / Audit and the Firewall log around this time.';
    usort($rep['events'], fn($a, $b) => $a['ts'] <=> $b['ts']);
    $rep['fixes'] = smpro_rc_build_fixes($rep);
    return $rep;
}

/** Flatten an outage report into a compact evidence block for the AI prompt. */
function smpro_rc_outage_ai_evidence($rep) {
    $L = [];
    $L[] = 'WINDOW: ' . date('Y-m-d H:i', (int)$rep['from']) . ' → ' . date('H:i', (int)$rep['to']);
    $L[] = 'HEURISTIC CAUSE: ' . $rep['cause'] . ' (confidence ' . $rep['confidence'] . ')';
    $L[] = 'REBOOT IN WINDOW: ' . ($rep['reboot'] ? date('Y-m-d H:i', (int)$rep['reboot']) : 'no');
    if (!empty($rep['reboot_attr'])) $L[] = 'REBOOT ATTRIBUTION: ' . $rep['reboot_attr']['text'] . (!empty($rep['reboot_attr']['evidence']) ? "\n  evidence: " . str_replace("\n", ' | ', mb_substr($rep['reboot_attr']['evidence'], 0, 300)) : '');
    $L[] = 'LOGGING CONTINUITY: ' . ($rep['continuity'] === null ? 'unknown' : ($rep['continuity'] ? 'server was UP and logging' : 'NO logs (server likely down)'));
    $L[] = '';
    $L[] = 'LOG EVENTS (' . count($rep['events']) . '):';
    $n = 0; foreach ($rep['events'] as $e) {
        if ($n++ >= 70) { $L[] = '... (' . (count($rep['events']) - 70) . ' more lines omitted)'; break; }
        $L[] = '[' . date('H:i', (int)$e['ts']) . '][' . $e['sev'] . '][' . $e['src'] . '] ' . $e['txt'];
    }
    foreach (['load'=>'SAR LOAD AVERAGE', 'mem'=>'SAR MEMORY', 'net'=>'SAR NETWORK'] as $k=>$lbl)
        if (!empty($rep['sar'][$k])) { $L[] = ''; $L[] = $lbl . ":\n" . $rep['sar'][$k]; }
    return implode("\n", $L);
}

/**
 * WHO/WHAT caused a reboot at $bootTs. Reads the PREVIOUS boot's shutdown phase + the auth log
 * (sudo reboot/shutdown), the kernel crash log, and OS-update logs. Returns a clear attribution.
 */
function smpro_rc_reboot_attribution($bootTs) {
    $ev = [];
    // crash signatures in the previous boot's kernel log (or messages near the boot date)
    $crash = '';
    $crashRe = 'kernel panic|soft lockup|hard lockup|nmi watchdog|watchdog: BUG|hung_task|task .* blocked for more than|general protection fault|kernel oops|Oops: |out of memory|killed process';
    if (smpro_rc_has('journalctl')) $crash = smpro_rc_logcmd('journalctl -b -1 -k -p warning -n 300 --no-pager 2>/dev/null | grep -iE ' . escapeshellarg($crashRe) . ' | tail -12');
    if (trim($crash) === '') $crash = smpro_rc_logcmd('grep -iE ' . escapeshellarg(date('M [ ]?j', $bootTs)) . ' /var/log/messages 2>/dev/null | grep -iE ' . escapeshellarg($crashRe) . ' | tail -12');
    $lc = strtolower($crash);
    if (strpos($lc, 'panic') !== false || strpos($lc, 'lockup') !== false || strpos($lc, 'hung') !== false || strpos($lc, 'general protection') !== false || strpos($lc, 'oops') !== false)
        return ['auto' => true, 'sev' => 'critical', 'how' => 'kernel crash', 'who' => 'the kernel (crash)', 'text' => 'AUTOMATIC — the kernel CRASHED (panic / watchdog / hung-task) and the machine reset itself. Nobody pressed reboot.', 'evidence' => trim($crash)];
    if (strpos($lc, 'out of memory') !== false || strpos($lc, 'killed process') !== false)
        return ['auto' => true, 'sev' => 'critical', 'how' => 'out of memory', 'who' => 'the kernel (OOM)', 'text' => 'AUTOMATIC — the server ran OUT OF MEMORY; the kernel OOM-killer fired and the box hung/rebooted. Nobody pressed reboot.', 'evidence' => trim($crash)];

    // who initiated a CLEAN shutdown/reboot? (sudo command in auth log, or systemd-logind)
    $who = ''; $howClean = ''; $bad = ['reboot','shutdown','poweroff','halt','system','systemctl','init'];
    foreach (['/var/log/secure', '/var/log/auth.log'] as $sf) if (is_readable($sf)) {
        // only REAL sudo reboot/shutdown commands — capture the invoking user (before " : "), not the run-as USER=
        $s = smpro_rc_logcmd('grep -iE "COMMAND=\\S*(reboot|shutdown|poweroff|halt)|systemctl[[:space:]]+(reboot|poweroff|halt)" ' . escapeshellarg($sf) . ' 2>/dev/null | tail -8');
        if (trim($s) !== '') { $ev[] = trim($s);
            if (preg_match('/\bsudo:\s*([a-z_][a-z0-9_\-]*)\s*:.*COMMAND=/i', $s, $m) && !in_array(strtolower($m[1]), $bad, true)) { $who = $m[1]; $howClean = 'sudo reboot/shutdown command'; }
        }
    }
    $jl = '';
    if (smpro_rc_has('journalctl')) {
        $jl = smpro_rc_logcmd('journalctl -b -1 --no-pager 2>/dev/null | grep -iE "System is (rebooting|powering down|halting)|Requested transition to|Shutting down|systemd-logind.*(power|reboot)|Powering off|Rebooting" | tail -12');
        if (trim($jl) !== '') { $ev[] = trim($jl);
            if ($who === '' && preg_match('/by user ([a-z_][a-z0-9_\-]*)/i', $jl, $m) && !in_array(strtolower($m[1]), $bad, true)) { $who = $m[1]; }
        }
    }
    $cleanInitiated = ($who !== '' || trim($jl) !== '' || trim($howClean) !== '');

    // an unattended OS/kernel update reboot?
    $upd = smpro_rc_logcmd('grep -ihE ' . escapeshellarg(date('M [ ]?j', $bootTs)) . ' /var/log/messages /var/log/dnf.rpm.log /var/log/yum.log 2>/dev/null | grep -iE "dnf-automatic|unattended|needs-restarting|needrestart|installed kernel| kernel-core" | tail -5');

    if ($who !== '')
        return ['auto' => false, 'sev' => 'info', 'how' => $howClean ?: 'manual command', 'who' => $who,
            'text' => 'MANUAL — user "' . $who . '" ran a reboot/shutdown command. This was a person, not a crash.', 'evidence' => implode("\n", $ev)];
    if (trim($upd) !== '')
        return ['auto' => true, 'sev' => 'info', 'how' => 'OS/kernel update', 'who' => 'an automatic OS update',
            'text' => 'AUTOMATIC — a clean reboot following an OS / kernel update (package manager). Expected after patching.', 'evidence' => trim($upd)];
    if ($cleanInitiated)
        return ['auto' => false, 'sev' => 'info', 'how' => 'clean shutdown', 'who' => 'someone/something (clean)',
            'text' => 'PLANNED — a clean shutdown/reboot was initiated (a person or a scheduled task) and the kernel logged no crash. Could not pin the exact user from the logs.', 'evidence' => implode("\n", $ev)];
    // nothing logged at all
    return ['auto' => true, 'sev' => 'critical', 'how' => 'power / hypervisor', 'who' => 'no one (lost power)',
        'text' => 'UNEXPECTED — NO clean shutdown was recorded and NO crash was logged. Most likely a power loss, a host/hypervisor reset (common on a VPS), or a hard hang. Nobody typed reboot.', 'evidence' => ''];
}

/** Build deterministic, SAFE remediation suggestions from the analyzed evidence (each with Approve/Cancel). */
function smpro_rc_build_fixes($rep) {
    $fixes = []; $txt = strtolower(implode(' ', array_map(fn($e) => $e['txt'], $rep['events'] ?? [])));
    $has = fn($n) => strpos($txt, $n) !== false;
    // OOM → guided (adding swap/limits is invasive; explain, no auto-button)
    if ($has('out of memory') || $has('oom') || $has('killed process'))
        $fixes[] = ['id' => 'oom', 'sev' => 'critical', 'title' => 'Out of memory', 'action' => '',
            'desc' => 'The kernel killed processes for lack of RAM. Reduce risk: add a swap file, raise/relax LVE or php-fpm memory limits, and find the memory hog in Top Processes.', 'manual' => true];
    // CSF/LFD activity → likely blocking legit EG/SA → one-click add Arab countries to CC_ALLOW
    if ($has('synflood') || $has('lfd') || $has('deny') || $has('blocked') || (($rep['reboot'] ?? null) === null && ($rep['continuity'] ?? null) === true))
        $fixes[] = ['id' => 'cc_allow_arab', 'sev' => 'warn', 'title' => 'Stop blocking legitimate Egypt/Saudi (Arab) IPs', 'action' => 'cc_allow_arab',
            'desc' => 'Add Egypt, Saudi and the Arab region to CSF CC_ALLOW (never-block) so the firewall stops locking out real customers. Reversible from the Firewall page.', 'manual' => false];
    // disk full
    if ($has('no space left') || $has('disk full'))
        $fixes[] = ['id' => 'disk', 'sev' => 'critical', 'title' => 'Disk full', 'action' => '',
            'desc' => 'A filesystem hit 100% — services fail when they cannot write. Clear logs/old backups; check Disk / Storage.', 'manual' => true];
    // a crashed cPanel service → one-click restart
    $svcMap = ['mysql'=>'mysql','mariadb'=>'mysql','httpd'=>'httpd','apache'=>'httpd','exim'=>'exim','dovecot'=>'dovecot','named'=>'named','lsws'=>'lsws','litespeed'=>'lsws','cpsrvd'=>'cpsrvd'];
    foreach ($svcMap as $needle => $svc) if ($has($needle . ' ') && ($has('failed') || $has('crash') || $has('segfault') || $has('killed'))) {
        $fixes['svc_' . $svc] = ['id' => 'svc_' . $svc, 'sev' => 'warn', 'title' => 'Restart ' . $svc, 'action' => 'restart_service', 'svc' => $svc,
            'desc' => ucfirst($svc) . ' looks like it failed/crashed in this window. Restart it via the plugin (safe).', 'manual' => false];
    }
    // sysstat missing → one-click install (better future analysis)
    if (empty($rep['sar']['load']) && empty($rep['sar']['mem']))
        $fixes[] = ['id' => 'sysstat', 'sev' => 'info', 'title' => 'Install sysstat (sar) for deeper history', 'action' => 'install_sysstat',
            'desc' => 'sar/sysstat was not available, so load/memory/network history for the outage is missing. Install it so the next incident has full resource timelines.', 'manual' => false];
    return array_values($fixes);
}

/**
 * Explain WHY a specific IP is (or isn't) firewall-blocked. Reads csf -g (authoritative),
 * csf.deny comment, the LFD trigger history, GeoIP, csf.allow, and CC_ALLOW — then gives a
 * plain verdict + fix. Built for the "Egyptian IP got blocked though it should be allow-listed"
 * case: it tells you the LFD reason AND whether CC_ALLOW covers the IP's country. Read-only.
 */
function smpro_rc_block_reason($ip) {
    $ip = trim($ip);
    $rep = ['ip'=>$ip, 'valid'=>(bool)filter_var($ip, FILTER_VALIDATE_IP), 'blocked'=>false, 'where'=>[],
            'comment'=>'', 'lfd'=>[], 'csf_g'=>'', 'country'=>'', 'provider'=>'', 'datacenter'=>false,
            'in_allow'=>false, 'cc_allow'=>'', 'cc_covers'=>false, 'verdict'=>'', 'fix'=>[]];
    if (!$rep['valid']) { $rep['verdict'] = 'Enter a valid IP address.'; return $rep; }

    // 1) csf -g — authoritative: shows every place the IP is matched (csf.deny / temp ban / iptables / csf.allow)
    $rep['csf_g'] = trim(smpro_rc_logcmd('csf -g ' . escapeshellarg($ip)));
    $g = strtolower($rep['csf_g']);
    if (strpos($g, 'csf.deny') !== false)               { $rep['blocked'] = true; $rep['where'][] = 'csf.deny'; }
    if (strpos($g, 'temporary') !== false && strpos($g, 'deny') !== false) { $rep['blocked'] = true; $rep['where'][] = 'temporary ban'; }
    if (preg_match('/\bDROP\b|\bDENY\b/', $rep['csf_g']) && strpos($g, 'allow') === false) $rep['blocked'] = true;

    // 2) csf.deny line + the comment LFD/admin wrote (the human reason)
    if (is_readable('/etc/csf/csf.deny')) foreach (file('/etc/csf/csf.deny', FILE_IGNORE_NEW_LINES) ?: [] as $l) {
        $l = trim($l); if ($l === '' || $l[0] === '#') continue;
        if (preg_match('/^' . preg_quote($ip, '/') . '(\s|$|\/|#)/', $l)) {
            $rep['blocked'] = true; if (!in_array('csf.deny', $rep['where'], true)) $rep['where'][] = 'csf.deny';
            $h = strpos($l, '#'); $rep['comment'] = $h !== false ? trim(substr($l, $h + 1)) : '';
            break;
        }
    }

    // 3) LFD trigger history for this IP (why it was added)
    $lfd = smpro_rc_logcmd('grep -F ' . escapeshellarg($ip) . ' /var/log/lfd.log 2>/dev/null | tail -8');
    foreach (array_filter(array_map('trim', explode("\n", $lfd))) as $line) $rep['lfd'][] = mb_substr($line, 0, 240);

    // 4) allow status (csf.allow + plugin allowlist)
    $rep['in_allow'] = function_exists('smpro_im_allowlisted') && smpro_im_allowlisted($ip);
    if (is_readable('/etc/csf/csf.allow')) foreach (file('/etc/csf/csf.allow', FILE_IGNORE_NEW_LINES) ?: [] as $l) {
        $l = trim($l); if ($l === '' || $l[0] === '#') continue;
        if (preg_match('/^' . preg_quote($ip, '/') . '(\s|$|\/|#)/', $l)) { $rep['in_allow'] = true; break; }
    }

    // 5) GeoIP + datacenter
    $intel = function_exists('smpro_ip_intel') ? smpro_ip_intel($ip) : [];
    $rep['country']    = strtoupper((string)($intel['country'] ?? ''));
    $rep['provider']   = (string)($intel['provider'] ?? '');
    $rep['datacenter'] = function_exists('smpro_ip_is_datacenter') && smpro_ip_is_datacenter($intel);

    // 6) CC_ALLOW (country never-block) from csf.conf — does it cover this IP's country?
    $cc = trim(smpro_rc_logcmd("grep -E '^CC_ALLOW(_FILTER)? *=' /etc/csf/csf.conf 2>/dev/null"));
    $rep['cc_allow']  = $cc;
    $rep['cc_covers'] = $rep['country'] !== '' && (bool)preg_match('/\b' . preg_quote($rep['country'], '/') . '\b/i', $cc);

    // 7) verdict + fix
    $arab = in_array($rep['country'], ['EG','SA','AE','KW','QA','BH','OM','JO','LB','IQ','SY','PS','YE','SD','LY','TN','DZ','MA','MR','SO','DJ','KM'], true);
    if (!$rep['blocked'] && strpos($g, 'no matches') !== false) {
        $rep['verdict'] = 'This IP is NOT blocked right now — no match in csf.deny, temporary bans, or iptables.';
    } elseif ($rep['in_allow'] && !$rep['blocked']) {
        $rep['verdict'] = 'This IP is allow-listed (csf.allow) and not blocked. If traffic still fails, the block is upstream (Cloudflare / provider), not CSF.';
    } else {
        $reason = $rep['comment'] ?: ($rep['lfd'] ? 'LFD trigger — see history below' : 'manual or temporary block');
        $rep['verdict'] = 'BLOCKED. Reason: ' . $reason . '.';
        if ($arab && !$rep['datacenter']) {
            $rep['verdict'] .= ' This is a RESIDENTIAL ' . ($rep['country'] ?: 'home-region') . ' IP that should normally be allow-listed (your customers are here).';
            if (!$rep['cc_covers']) {
                $rep['verdict'] .= ' CC_ALLOW does NOT include ' . ($rep['country'] ?: 'this country') . ' — that is exactly why a legitimate ' . ($rep['country'] ?: 'local') . ' IP got firewall-blocked.';
                $rep['fix'][] = 'Add ' . ($rep['country'] ?: 'the country') . ' to Firewall → Country Block-Prevention (CC_ALLOW) so it is never blocked again.';
            }
            $rep['fix'][] = 'Unblock now: Firewall → Add IP → Allow, or run on the server:  csf -dr ' . $ip . '  then  csf -a ' . $ip;
        } else {
            if ($rep['in_allow']) $rep['verdict'] .= ' NOTE: the IP is also in csf.allow — a deny entry is overriding it; remove the deny line.';
            $rep['fix'][] = 'If this is a false positive, allow it:  csf -a ' . $ip . '  (Firewall → Add IP → Allow).';
        }
    }
    return $rep;
}

/** Work out WHY a reboot happened at $bts. Returns [severity, plain-cause, short-evidence]. */
function smpro_rc_reboot_cause($bts, array $shutdowns) {
    // A clean shutdown recorded shortly before the boot ⇒ planned/manual reboot, not a crash.
    foreach ($shutdowns as $st) if ($st <= $bts && ($bts - $st) <= 900)
        return ['info', 'Planned reboot — a clean shutdown was recorded just before boot (manual reboot, kernel/OS update, or scheduled maintenance).', 'clean shutdown logged before boot'];
    // Otherwise look for a crash signature in the PREVIOUS boot's kernel log (or /var/log/messages near the boot date).
    $sig = '';
    if (smpro_rc_has('journalctl')) $sig = smpro_rc_logcmd('journalctl -b -1 -k -n 250 --no-pager 2>/dev/null | tail -120');
    if (trim($sig) === '') $sig = smpro_rc_logcmd('grep -iE ' . escapeshellarg(date('M [ ]?j', $bts)) . ' /var/log/messages 2>/dev/null | tail -150');
    $low = strtolower($sig);
    if (strpos($low, 'out of memory') !== false || strpos($low, 'killed process') !== false)
        return ['critical', 'OUT OF MEMORY before the reboot — the kernel exhausted RAM and started killing processes; the server likely hung, then rebooted.', 'OOM killer in kernel log'];
    if (strpos($low, 'kernel panic') !== false || strpos($low, 'watchdog') !== false || strpos($low, 'bug: ') !== false || strpos($low, 'oops') !== false)
        return ['critical', 'KERNEL CRASH (panic / watchdog) before the reboot.', 'panic/watchdog in kernel log'];
    // No clean shutdown AND no crash log ⇒ the power was cut from under it.
    return ['critical', 'UNEXPECTED reboot — no clean shutdown was recorded and no crash was logged. Most likely a power loss, a host/hypervisor reset (common on VPS), or a hard hang.', 'no shutdown record before boot'];
}

/** Reboots in the last $days, each as an incident WITH its inferred cause (from wtmp + kernel logs). */
function smpro_rc_reboot_events($days = 7) {
    $out = []; $since = time() - (int)$days * 86400;
    // clean-shutdown timestamps (to tell a planned reboot from a crash)
    $shutdowns = [];
    foreach (explode("\n", smpro_rc_logcmd('last -x -F shutdown 2>/dev/null | head -25')) as $l)
        if (preg_match('/(\w{3}\s+\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4})/', $l, $m)) { $t = strtotime($m[1]); if ($t) $shutdowns[] = $t; }
    // boot history
    $now = time();
    foreach (explode("\n", smpro_rc_logcmd('last -x -F reboot 2>/dev/null | head -25')) as $l) {
        if (!preg_match('/reboot\s+system boot\s+\S+\s+(\w{3}\s+\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4})/', $l, $m)) continue;
        $bts = strtotime($m[1]); if (!$bts || $bts < $since || $bts > $now + 3600) continue;
        [$sev, $cause, $ev] = smpro_rc_reboot_cause($bts, $shutdowns);
        $ago = $now - $bts; $agoh = $ago < 3600 ? round($ago/60).'m' : round($ago/3600, 1).'h';
        $out[] = ['id' => 'reboot' . $bts, 'ts' => $bts, 'type' => 'system', 'severity' => $sev, 'source' => 'system',
            'title' => $sev === 'info' ? 'Server rebooted (planned)' : 'Server rebooted — UNEXPECTED',
            'detail' => 'Booted ' . date('Y-m-d H:i', $bts) . ' (' . $agoh . ' ago). ' . $cause . ($ev ? ' [' . $ev . ']' : ''),
            'means' => $cause,
            'actor' => ''];
    }
    return $out;
}

/** Auto-detected incidents from the plugin's own data (audit log + local-source attacks + reboots). */
function smpro_rc_incidents_auto($days = 7) {
    $out = []; $since = time() - (int)$days * 86400;
    $sev = [
        'firewall_csf_disable'   => ['critical', 'Firewall (CSF) disabled'],
        'firewall_csf_production' => ['warn', 'CSF switched to production'],
        'firewall_cc_allow'      => ['info', 'Country block-prevention changed'],
        'firewall_service'       => ['warn', 'Firewall service control'],
        'intrusion_autoblock'    => ['warn', 'Auto-blocked an attacking IP'],
        'intrusion_breach'       => ['critical', 'Breach detected'],
        'cooler_start'           => ['warn', 'Load cooler throttled a process'],
    ];
    if (is_readable(SMPRO_AUDIT_LOG)) foreach (explode("\n", (string)@shell_exec('tail -n 4000 ' . escapeshellarg(SMPRO_AUDIT_LOG) . ' 2>/dev/null')) as $l) {
        $j = json_decode(trim($l), true); if (!is_array($j) || empty($j['action']) || !isset($sev[$j['action']])) continue;
        $ts = (int)($j['ts'] ?? 0); if ($ts < $since) continue;
        $out[] = ['id' => 'a' . $ts . $j['action'], 'ts' => $ts, 'type' => 'security', 'severity' => $sev[$j['action']][0], 'source' => 'audit', 'title' => $sev[$j['action']][1], 'detail' => json_encode($j['details'] ?? [], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), 'actor' => (string)($j['actor'] ?? '')];
    }
    if (function_exists('smpro_im_selfattack_recent')) foreach (smpro_im_selfattack_recent(24) as $s) {
        $out[] = ['id' => 'self' . $s['ip'], 'ts' => (int)($s['last'] ?? time()), 'type' => 'self-attack', 'severity' => 'critical', 'source' => 'intrusion', 'title' => 'Web attack from local IP ' . $s['ip'], 'detail' => (int)$s['n'] . ' events on ' . (int)$s['domains'] . ' domain(s) — possible local compromise', 'actor' => ''];
    }
    // Reboots/crashes are real incidents — surface them automatically WITH the inferred cause.
    foreach (smpro_rc_reboot_events($days) as $r) $out[] = $r;
    usort($out, fn($a, $b) => ($b['ts'] ?? 0) <=> ($a['ts'] ?? 0));   // newest first
    return $out;
}

$reqMethod = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));

/* Block / Allow actions (POST + CSRF + root). */
if ($reqMethod === 'POST' && in_array(($_POST['rc_action'] ?? ''), ['block','allow'], true)) {
    smpro_require_valid_csrf('rc_action'); smpro_require_root();
    header('Content-Type: application/json');
    $ip = trim((string)($_POST['ip'] ?? ''));
    $r = $_POST['rc_action'] === 'allow' ? smpro_im_allow_ip($ip) : smpro_im_block_ip($ip, 'reports-center');
    smpro_audit('reports_center_' . $_POST['rc_action'], ['ip'=>$ip,'ok'=>$r['ok']]);
    echo json_encode(['ip'=>$ip] + $r, JSON_UNESCAPED_SLASHES); exit;
}
/* Apply a recommended fix (Approve button). POST + CSRF + root. JSON. SAFE whitelist only. */
if ($reqMethod === 'POST' && ($_POST['rc_action'] ?? '') === 'fix') {
    smpro_require_valid_csrf('rc_action'); smpro_require_root();
    header('Content-Type: application/json');
    $fix = preg_replace('/[^a-z_]/', '', strtolower((string)($_POST['fix'] ?? '')));
    $resp = ['ok' => false, 'msg' => 'Unknown fix'];
    if ($fix === 'cc_allow_arab') {
        $conf = '/etc/csf/csf.conf';
        $arab = 'EG,SA,AE,KW,QA,BH,OM,JO,LB,SY,IQ,YE,PS,DZ,MA,TN,LY,SD,MR,SO,DJ,KM';
        if (!is_file($conf) || !is_writable($conf)) { $resp = ['ok'=>false,'msg'=>'csf.conf not writable (CSF installed?).']; }
        else {
            $c = (string)file_get_contents($conf); @copy($conf, $conf . '.smpro.rcbak');
            // merge with any existing CC_ALLOW
            $cur = preg_match('/^[ \t]*CC_ALLOW[ \t]*=[ \t]*"([^"]*)"/m', $c, $m) ? $m[1] : '';
            $set = array_values(array_unique(array_filter(array_map('trim', array_merge(explode(',', $cur), explode(',', $arab))))));
            sort($set); $val = implode(',', $set);
            $line = 'CC_ALLOW = "' . $val . '"';
            $c = preg_match('/^[ \t]*CC_ALLOW[ \t]*=.*$/m', $c) ? preg_replace('/^[ \t]*CC_ALLOW[ \t]*=.*$/m', $line, $c, 1) : ($c . "\n" . $line . "\n");
            if (file_put_contents($conf, $c) === false) { $resp = ['ok'=>false,'msg'=>'Failed to write csf.conf.']; }
            else { $csf = smpro_csf_bin(); $out = $csf ? (string)@shell_exec('timeout 60 ' . escapeshellarg($csf) . ' -r 2>&1') : 'csf not found'; $resp = ['ok'=>true, 'msg'=>'Added Arab region to CC_ALLOW (' . count($set) . ' countries). Reload: ' . (stripos($out,'error')===false?'ok':'see Firewall page')]; }
        }
    } elseif ($fix === 'restart_service') {
        $svc = preg_replace('/[^a-z0-9_\-]/', '', strtolower((string)($_POST['svc'] ?? '')));
        $ok = in_array($svc, ['mysql','httpd','exim','dovecot','named','lsws','cpsrvd','nginx'], true);
        $script = ''; foreach (['/usr/local/cpanel/scripts/restartsrv_' . $svc, '/scripts/restartsrv_' . $svc] as $s) if ($ok && is_executable($s)) { $script = $s; break; }
        if ($script === '') $resp = ['ok'=>false,'msg'=>'Unknown/unsupported service'];
        else { @shell_exec('timeout 90 ' . escapeshellarg($script) . ' 2>/dev/null'); $resp = ['ok'=>true,'msg'=>ucfirst($svc) . ' restart requested.']; }
    } elseif ($fix === 'install_sysstat') {
        if (function_exists('smpro_env_install')) { [$iok,$d] = smpro_env_install('sysstat'); $resp = ['ok'=>$iok,'msg'=>(string)$d]; }
        else $resp = ['ok'=>false,'msg'=>'installer unavailable'];
    } elseif ($fix === 'unblock_ip') {
        $ip = trim((string)($_POST['ip'] ?? ''));
        if (!filter_var($ip, FILTER_VALIDATE_IP)) $resp = ['ok'=>false,'msg'=>'invalid IP'];
        elseif (function_exists('smpro_im_allow_ip')) { $r = smpro_im_allow_ip($ip); $resp = ['ip'=>$ip] + (array)$r; }
        else $resp = ['ok'=>false,'msg'=>'unsupported'];
    }
    smpro_audit('reports_center_fix', ['fix'=>$fix,'ok'=>!empty($resp['ok'])]);
    echo json_encode($resp, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE); exit;
}

/* CSV export of an IP report. */
if (($_GET['rc_export'] ?? '') === 'csv' && filter_var($_GET['ip'] ?? '', FILTER_VALIDATE_IP)) {
    [$rcxf, $rcxt] = smpro_rc_range();
    $rep = smpro_rc_ip_report($_GET['ip'], $rcxf, $rcxt);
    header('Content-Type: text/csv; charset=utf-8'); header('Content-Disposition: attachment; filename="ip_' . $rep['ip'] . '.csv"');
    $fh = fopen('php://output', 'w');
    fputcsv($fh, ['field','value']);
    fputcsv($fh, ['ip',$rep['ip']]); fputcsv($fh, ['country',$rep['country']]); fputcsv($fh, ['provider',$rep['provider']]); fputcsv($fh, ['asn',$rep['asn']]);
    fputcsv($fh, ['datacenter',$rep['datacenter']?'yes':'no']); fputcsv($fh, ['csf',$rep['csf'] ?: 'not blocked']); fputcsv($fh, ['allowlisted',$rep['allowlisted']?'yes':'no']);
    fputcsv($fh, ['abuse_score',$rep['abuse']]); fputcsv($fh, ['attacks_30d',$rep['attacks']['total']]);
    fputcsv($fh, []); fputcsv($fh, ['attack_time','domain','type','severity','http','uri']);
    foreach (($rep['attacks']['recent'] ?? []) as $e) fputcsv($fh, [date('Y-m-d H:i:s',(int)$e['ts']),$e['domain'],$e['kind'],$e['severity'],$e['code'],$e['uri']]);
    fputcsv($fh, []); fputcsv($fh, ['operation_time','operation','action','by','admin_ip','result']);
    foreach (($rep['operations'] ?? []) as $o) fputcsv($fh, [date('Y-m-d H:i:s',(int)$o['ts']),$o['label'],$o['action'],$o['actor'],$o['admin_ip'],$o['result']]);
    fclose($fh); exit;
}

/* AI cause analysis of an outage window (JSON, polled by the "Analyze with AI" button). */
if (($_GET['rc_ai_outage'] ?? '') === '1'
    && preg_match('/^\d{4}-\d{2}-\d{2}$/', (string)($_GET['o_date'] ?? ''))
    && preg_match('/^\d{2}:\d{2}$/', (string)($_GET['o_from'] ?? ''))
    && preg_match('/^\d{2}:\d{2}$/', (string)($_GET['o_to'] ?? ''))) {
    header('Content-Type: application/json');
    if (!function_exists('smpro_ai_chat') || !function_exists('smpro_ai_available') || !smpro_ai_available()) {
        echo json_encode(['ok'=>false, 'error'=>'AI is not configured. Add a free provider in Settings → AI Providers, then try again.']); exit;
    }
    $o_d2   = preg_match('/^\d{4}-\d{2}-\d{2}$/', (string)($_GET['o_date2'] ?? '')) ? $_GET['o_date2'] : $_GET['o_date'];
    $fromTs = strtotime($_GET['o_date'] . ' ' . $_GET['o_from'] . ':00');
    $toTs   = strtotime($o_d2 . ' ' . $_GET['o_to'] . ':59');
    if (!$fromTs || !$toTs || $toTs <= $fromTs || ($toTs - $fromTs) > 31 * 86400) { echo json_encode(['ok'=>false,'error'=>'Invalid time window.']); exit; }
    $rep = smpro_rc_outage_analyze($fromTs, $toTs);
    $sys = 'You are a senior Linux/cPanel-WHM incident analyst. You are given the ACTUAL evidence collected from THIS server for ONE time window: reboot detection + attribution (who/what caused it), kernel (journald/dmesg), failed systemd services, MySQL/Apache/LiteSpeed/Exim errors, disk-full checks, CSF/LFD firewall activity, SSH/sudo auth lines, and sysstat (sar). Produce an IN-DEPTH incident report, not a generic checklist.\n'
        . 'Structure (use markdown ## headers + bullets):\n'
        . '## What happened — a short factual timeline of the real events from the evidence (quote the key log lines/timestamps you actually see).\n'
        . '## Reboot — IF a reboot is in the evidence, state plainly WHETHER it was a CRASH/automatic (kernel panic, OOM, watchdog, power loss/hypervisor reset) OR a MANUAL reboot, and WHO/what triggered it (name the user if the auth log shows a sudo reboot). Use the REBOOT ATTRIBUTION line as ground truth.\n'
        . '## Root causes (ranked) — every REAL problem you can find in the evidence, most-to-least likely; for each: why, the evidence line, and how to confirm.\n'
        . '## Fixes — concrete steps to fix and prevent each, ordered by impact.\n'
        . 'Rules: be specific to the evidence, quote real lines, do NOT invent logs. If something is missing, say what to collect. Critical local context: this server hosts mostly Egyptian (EG) & Saudi (SA) customers — a very common "customers cannot log in" cause is CSF/LFD blocking residential EG/SA IPs because CC_ALLOW omits those countries; call this out explicitly whenever firewall/LFD activity appears. You may answer in Arabic.';
    $usr = "Write the in-depth incident report from this evidence:\n\n" . smpro_rc_outage_ai_evidence($rep);
    $r = smpro_ai_chat($sys, $usr, ['max_tokens'=>1700, 'temperature'=>0.2, 'context'=>'outage_analysis']);
    smpro_audit('reports_center_ai_outage', ['from'=>$fromTs, 'to'=>$toTs, 'ok'=>!empty($r['ok'])]);
    if (empty($r['ok'])) { echo json_encode(['ok'=>false, 'error'=>(string)($r['error'] ?? 'AI request failed')]); exit; }
    echo json_encode(['ok'=>true, 'text'=>(string)$r['text'], 'provider'=>(string)($r['provider'] ?? ''), 'model'=>(string)($r['model'] ?? '')], JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); exit;
}

/* CSV export of an outage report (analyzer output for a time window). */
if (($_GET['rc_export'] ?? '') === 'outage'
    && preg_match('/^\d{4}-\d{2}-\d{2}$/', (string)($_GET['o_date'] ?? ''))
    && preg_match('/^\d{2}:\d{2}$/', (string)($_GET['o_from'] ?? ''))
    && preg_match('/^\d{2}:\d{2}$/', (string)($_GET['o_to'] ?? ''))) {
    $o_d2   = preg_match('/^\d{4}-\d{2}-\d{2}$/', (string)($_GET['o_date2'] ?? '')) ? $_GET['o_date2'] : $_GET['o_date'];
    $fromTs = strtotime($_GET['o_date'] . ' ' . $_GET['o_from'] . ':00');
    $toTs   = strtotime($o_d2 . ' ' . $_GET['o_to'] . ':59');
    if ($fromTs && $toTs && $toTs > $fromTs && ($toTs - $fromTs) <= 31 * 86400) {
        $rep = smpro_rc_outage_analyze($fromTs, $toTs);
        smpro_audit('reports_center_export_outage', ['from'=>$fromTs,'to'=>$toTs]);
        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename="outage_' . $_GET['o_date'] . '_' . str_replace(':','',$_GET['o_from']) . '-' . str_replace(':','',$_GET['o_to']) . '.csv"');
        $fh = fopen('php://output', 'w');
        fputcsv($fh, ['Outage report']);
        fputcsv($fh, ['window_from', date('Y-m-d H:i:s', (int)$rep['from'])]);
        fputcsv($fh, ['window_to', date('Y-m-d H:i:s', (int)$rep['to'])]);
        fputcsv($fh, ['probable_cause', $rep['cause']]);
        fputcsv($fh, ['confidence', $rep['confidence']]);
        fputcsv($fh, ['reboot_detected', $rep['reboot'] ? date('Y-m-d H:i:s', (int)$rep['reboot']) : 'no']);
        fputcsv($fh, ['logging_continuity', $rep['continuity'] === null ? 'unknown' : ($rep['continuity'] ? 'up+logging' : 'no logs (likely down)')]);
        fputcsv($fh, []);
        fputcsv($fh, ['Recommendations']);
        foreach (($rep['recommend'] ?? []) as $r) fputcsv($fh, [$r]);
        fputcsv($fh, []);
        fputcsv($fh, ['Log events', '', '']);
        fputcsv($fh, ['time','severity','source','log_line']);
        foreach (($rep['events'] ?? []) as $e) fputcsv($fh, [date('Y-m-d H:i:s',(int)$e['ts']), $e['sev'], $e['src'], $e['txt']]);
        foreach (['load'=>'sar load','mem'=>'sar memory','net'=>'sar network'] as $k=>$lbl) {
            if (empty($rep['sar'][$k])) continue;
            fputcsv($fh, []); fputcsv($fh, [$lbl]);
            foreach (explode("\n", (string)$rep['sar'][$k]) as $ln) { $ln = rtrim($ln); if ($ln !== '') fputcsv($fh, [$ln]); }
        }
        fclose($fh); exit;
    }
}

/* Live IP Watch feed (GET JSON, polled every ~10s). */
if (($_GET['rc_live'] ?? '') === '1') {
    header('Content-Type: application/json');
    $ip = (string)($_GET['ip'] ?? '');
    if (!filter_var($ip, FILTER_VALIDATE_IP)) { echo json_encode(['ok'=>false,'msg'=>'invalid IP']); exit; }
    $rows = smpro_rc_ip_live($ip, 150);
    echo json_encode(['ok'=>true,'count'=>count($rows),'now'=>date('H:i:s'),'rows'=>array_map(fn($r)=>['time'=>$r['ts']?date('H:i:s',$r['ts']):'','domain'=>$r['domain'],'method'=>$r['method'],'path'=>mb_substr($r['path'],0,120),'status'=>$r['status'],'bytes'=>$r['bytes'],'ua'=>mb_substr($r['ua'],0,90)], $rows)], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE); exit;
}
$tab = preg_replace('/[^a-z]/','',strtolower((string)($_GET['tab'] ?? 'ip')));
if (!in_array($tab,['ip','live','directory','incidents'],true)) $tab = 'ip';
$csrf = smpro_csrf_generate('rc_action');
$qip = filter_var($_GET['ip'] ?? '', FILTER_VALIDATE_IP) ? $_GET['ip'] : '';
[$rcFrom, $rcTo] = smpro_rc_range();
$gfrom = smpro_h($_GET['from'] ?? ''); $gto = smpro_h($_GET['to'] ?? '');
$rep = $qip ? smpro_rc_ip_report($qip, $rcFrom, $rcTo) : null;
$winLbl = ($rcFrom || $rcTo) ? (($gfrom ?: '…') . ' → ' . ($gto ?: 'now')) : 'last 30 days';
smpro_audit('reports_center_view', ['tab'=>$tab,'ip'=>$qip]);
smpro_layout_header('Reports Center');
?>
<script>var RC_CSRF=<?= json_encode($csrf) ?>;</script>
<div class="svc-kicker">Reports</div>
<h1 class="h" style="margin:2px 0 4px" data-i18n>Reports Center</h1>
<p class="sub" data-i18n>One place for every report across all sections — and a full lookup of everything the plugin knows about any IP address.</p>

<div class="la-tabs">
  <a class="la-tab <?= $tab==='ip'?'active':'' ?>" href="index.cgi?page=reports-center&tab=ip" data-i18n>IP Report</a>
  <a class="la-tab <?= $tab==='live'?'active':'' ?>" href="index.cgi?page=reports-center&tab=live" data-i18n>Live IP Watch</a>
  <a class="la-tab <?= $tab==='directory'?'active':'' ?>" href="index.cgi?page=reports-center&tab=directory" data-i18n>All Reports</a>
  <a class="la-tab <?= $tab==='incidents'?'active':'' ?>" href="index.cgi?page=reports-center&tab=incidents" data-i18n>Incidents</a>
</div>

<?php if ($tab === 'ip'): ?>
  <form method="get" class="rc-search">
    <input type="hidden" name="page" value="reports-center"><input type="hidden" name="tab" value="ip">
    <input type="text" name="ip" class="rc-in" value="<?= smpro_h($qip) ?>" placeholder="Enter an IP address (e.g. 203.0.113.5)…" autofocus>
    <label class="rc-dt"><span data-i18n>From</span> <input type="date" name="from" class="rc-in" value="<?= $gfrom ?>"></label>
    <label class="rc-dt"><span data-i18n>To</span> <input type="date" name="to" class="rc-in" value="<?= $gto ?>"></label>
    <button class="tp-btn primary" type="submit" data-i18n>Build report</button>
  </form>
  <?php if ($qip && $rep): $a = $rep['attacks']; ?>
  <div class="card rc-card" id="rcCard" data-ip="<?= smpro_h($rep['ip']) ?>">
    <div class="rc-head">
      <div><span class="rc-ipv"><?= smpro_h($rep['ip']) ?></span>
        <span class="meta"><?= smpro_h($rep['country']) ?><?= $rep['provider']?' · '.smpro_h($rep['provider']):'' ?><?= $rep['asn']?' · '.smpro_h($rep['asn']):'' ?></span>
        <?php if ($rep['datacenter']): ?> <span class="b crit">&#129302; datacenter/bot</span><?php endif; ?>
        <?php if ($rep['server_ip']): ?> <span class="b">server's own IP</span><?php elseif (!$rep['external']): ?> <span class="b">private/local</span><?php endif; ?>
        <?php if ($rep['abuse']!==''): ?> <span class="b <?= (int)$rep['abuse']>=50?'crit':'' ?>">AbuseIPDB <?= (int)$rep['abuse'] ?></span><?php endif; ?>
      </div>
      <div class="rc-actions">
        <?php if ($rep['csf']): ?><span class="b crit">CSF <?= smpro_h($rep['csf']) ?></span><?php endif; ?>
        <?php if ($rep['allowlisted']): ?><span class="b" style="background:var(--good-bg);color:var(--good)">allowlisted</span><?php endif; ?>
        <button class="rc-act block" data-ip="<?= smpro_h($rep['ip']) ?>" data-i18n>Block</button>
        <button class="rc-act allow" data-ip="<?= smpro_h($rep['ip']) ?>" data-i18n>Allow</button>
        <a class="lnk" href="index.cgi?page=reports-center&tab=live&ip=<?= urlencode($rep['ip']) ?>" data-i18n>Watch live &#8594;</a>
        <a class="lnk" href="index.cgi?page=reports-center&rc_export=csv&ip=<?= urlencode($rep['ip']) ?>&from=<?= urlencode($_GET['from'] ?? '') ?>&to=<?= urlencode($_GET['to'] ?? '') ?>" data-i18n>CSV</a>
        <a class="lnk" href="javascript:window.print()" data-i18n>Print</a>
      </div>
    </div>

    <div class="rc-kpis">
      <div><span class="l">Web attacks (<?= smpro_h($winLbl) ?>)</span><b><?= number_format($a['total']) ?></b></div>
      <div><span class="l" data-i18n>Domains targeted</span><b><?= number_format(count($a['domains'])) ?></b></div>
      <div><span class="l" data-i18n>Max severity</span><b><?= smpro_h($a['sev'] ?: '—') ?></b></div>
      <div><span class="l" data-i18n>First → last seen</span><b style="font-size:13px"><?= $a['first']?smpro_h(date('Y-m-d H:i',$a['first'])):'—' ?><?= $a['last']?' → '.smpro_h(date('m-d H:i',$a['last'])):'' ?></b></div>
    </div>

    <?php if ($a['total'] > 0): ?>
    <div class="rc-two">
      <div><h4 data-i18n>Attack types</h4><?php foreach ($a['cats'] as $c=>$n): ?><div class="rc-li"><span><?= smpro_h($c) ?></span><b><?= (int)$n ?></b></div><?php endforeach; ?></div>
      <div><h4 data-i18n>Domains targeted</h4><?php $i=0; foreach ($a['domains'] as $d=>$n){ if($i++>=12)break; ?><div class="rc-li"><span><?= smpro_h($d) ?></span><b><?= (int)$n ?></b></div><?php } ?></div>
      <div><h4>HTTP codes</h4><?php foreach ($a['codes'] as $c=>$n): ?><div class="rc-li"><span><?= smpro_h($c) ?></span><b><?= (int)$n ?></b></div><?php endforeach; ?></div>
    </div>
    <h4 style="margin:14px 0 6px" data-i18n>Recent events</h4>
    <div class="rc-scroll"><table class="smpro-table"><thead><tr><th data-i18n>Time</th><th data-i18n>Domain</th><th data-i18n>Type</th><th data-i18n>Severity</th><th>HTTP</th><th data-i18n>Request</th></tr></thead><tbody>
      <?php foreach ($a['recent'] as $e): ?><tr><td class="meta"><?= smpro_h(date('Y-m-d H:i:s',(int)$e['ts'])) ?></td><td><b><?= smpro_h($e['domain']) ?></b></td><td><span class="k"><?= smpro_h($e['kind']) ?></span></td><td><?= smpro_h($e['severity']) ?></td><td><?= smpro_h($e['code']) ?></td><td class="meta" title="<?= smpro_h($e['uri']) ?>"><?= smpro_h(mb_substr((string)$e['uri'],0,60)) ?></td></tr><?php endforeach; ?>
    </tbody></table></div>
    <?php else: ?>
    <p class="meta" data-i18n>No web-attack events recorded for this IP in this window (the index fills as attacks happen). Firewall/geo status above still applies.</p>
    <?php endif; ?>

    <h4 style="margin:16px 0 6px" data-i18n>Operations performed on this IP</h4>
    <?php if (!empty($rep['operations'])): ?>
    <div class="rc-scroll" style="max-height:300px"><table class="smpro-table"><thead><tr><th data-i18n>Time</th><th data-i18n>Operation</th><th data-i18n>By</th><th data-i18n>Result</th></tr></thead><tbody>
      <?php foreach ($rep['operations'] as $o): ?><tr><td class="meta"><?= smpro_h(date('Y-m-d H:i:s',(int)$o['ts'])) ?></td><td><b><?= smpro_h($o['label']) ?></b> <span class="meta" style="font-size:11px"><?= smpro_h($o['action']) ?></span></td><td><?= smpro_h($o['actor']) ?><?= $o['admin_ip']?' <span class="meta">from '.smpro_h($o['admin_ip']).'</span>':'' ?></td><td class="meta"><?= smpro_h($o['result']) ?></td></tr><?php endforeach; ?>
    </tbody></table></div>
    <?php else: ?><p class="meta" data-i18n>No operations performed on this IP yet — block / allow / emergency / firewall actions will appear here with time, actor and result.</p><?php endif; ?>
  </div>
  <?php elseif ($qip): ?><div class="card" style="padding:16px"><span class="meta">Invalid IP.</span></div><?php endif; ?>

<?php elseif ($tab === 'live'): $lip = filter_var($_GET['ip'] ?? '', FILTER_VALIDATE_IP) ? $_GET['ip'] : ''; ?>
  <form method="get" class="rc-search">
    <input type="hidden" name="page" value="reports-center"><input type="hidden" name="tab" value="live">
    <input type="text" name="ip" class="rc-in" value="<?= smpro_h($lip) ?>" placeholder="Enter an IP to watch live (every request it makes)…" autofocus>
    <button class="tp-btn primary" type="submit" data-i18n>Watch</button>
  </form>
  <?php if ($lip): ?>
  <div class="tp-th"><b data-i18n>Live activity</b> <span class="ipmono"><?= smpro_h($lip) ?></span>
    <label class="lm-chkl" style="margin-left:14px"><input type="checkbox" id="rcLiveAuto" checked> <span data-i18n>Auto-refresh (10s)</span></label>
    <button class="rc-act block" data-ip="<?= smpro_h($lip) ?>">Block</button>
    <button class="rc-act allow" data-ip="<?= smpro_h($lip) ?>">Allow</button>
    <span class="meta" id="rcLiveMeta" style="margin-left:auto">—</span></div>
  <div class="rc-scroll" style="max-height:560px"><table class="smpro-table nowrap" id="rcLiveTbl">
    <thead><tr><th data-i18n>Time</th><th data-i18n>Domain</th><th data-i18n>Method</th><th data-i18n>Path</th><th>HTTP</th><th data-i18n>Size</th><th data-i18n>User-Agent</th></tr></thead>
    <tbody id="rcLiveBody"><tr><td colspan="7" class="rc-empty" data-i18n>Loading live activity…</td></tr></tbody></table></div>
  <p class="meta" style="font-size:11px;margin-top:8px" data-i18n>Reads every hosted domain's access log for this IP (throttled). Shows ALL requests — not just attacks. Non-2xx and known attack paths are highlighted.</p>
  <?php else: ?>
  <div class="card" style="padding:16px"><span class="meta" data-i18n>Enter an IP above to watch every request it makes across the server in real time (like a filtered tail -f on the access logs).</span></div>
  <?php endif; ?>

<?php elseif ($tab === 'directory'): $all = smpro_rc_collect(); ?>
  <div class="rc-toolbar">
    <b data-i18n>All saved reports</b>
    <input type="text" id="rcFilter" class="rc-in" placeholder="Filter…" style="max-width:190px">
    <label class="rc-dt"><span data-i18n>From</span> <input type="date" id="rcFrom" class="rc-in"></label>
    <label class="rc-dt"><span data-i18n>To</span> <input type="date" id="rcTo" class="rc-in"></label>
    <span class="meta" id="rcCount" style="margin-left:auto"><?= count($all) ?> report(s)</span>
  </div>
  <div class="rc-scroll" style="max-height:560px"><table class="smpro-table" id="rcDir">
    <thead><tr><th data-i18n>Section</th><th data-i18n>Report</th><th data-i18n>Details</th><th data-i18n>Date</th><th></th></tr></thead><tbody>
    <?php if (!$all): ?><tr><td colspan="5" class="rc-empty" data-i18n>No saved reports yet — generate them from each section.</td></tr><?php endif; ?>
    <?php foreach ($all as $r): ?>
      <tr data-search="<?= smpro_h(strtolower($r['sec'].' '.$r['name'])) ?>" data-ts="<?= (int)$r['ts'] ?>">
        <td><span class="b"><?= smpro_h($r['sec']) ?></span></td>
        <td><?= smpro_h($r['name']) ?></td>
        <td class="meta"><?= smpro_h($r['extra']) ?></td>
        <td class="meta"><?= smpro_h($r['date']) ?></td>
        <td><a class="lnk" href="index.cgi?page=<?= smpro_h($r['page']) ?>" data-i18n>Open</a></td>
      </tr>
    <?php endforeach; ?>
    </tbody></table></div>

<?php elseif ($tab === 'incidents'):
  $incidents = smpro_rc_incidents_auto(7);
  // Outage-window inputs (GET): date + from/to time. Build timestamps and run the log analyzer.
  $oDate = preg_match('/^\d{4}-\d{2}-\d{2}$/', (string)($_GET['o_date'] ?? '')) ? $_GET['o_date'] : '';
  $oFrom = preg_match('/^\d{2}:\d{2}$/', (string)($_GET['o_from'] ?? '')) ? $_GET['o_from'] : '';
  $oTo   = preg_match('/^\d{2}:\d{2}$/', (string)($_GET['o_to'] ?? '')) ? $_GET['o_to'] : '';
  $oDate2 = preg_match('/^\d{4}-\d{2}-\d{2}$/', (string)($_GET['o_date2'] ?? '')) ? $_GET['o_date2'] : $oDate;   // optional To-date (defaults to From-date)
  $report = null; $winErr = '';
  if ($oDate && $oFrom && $oTo) {
    $fromTs = strtotime($oDate . ' ' . $oFrom . ':00');
    $toTs   = strtotime($oDate2 . ' ' . $oTo . ':59');
    if ($fromTs && $toTs && $toTs > $fromTs && ($toTs - $fromTs) <= 31 * 86400) {
      $report = smpro_rc_outage_analyze($fromTs, $toTs);
    } else { $winErr = 'Invalid window — the "to" must be after "from", and the window ≤ 31 days.'; }
  }
  $confCls = ['high'=>'crit','medium'=>'high','low'=>''];
  // Block-reason lookup (GET ?bip=IP)
  $bip = trim((string)($_GET['bip'] ?? ''));
  $br  = $bip !== '' ? smpro_rc_block_reason($bip) : null;
  $aiOn = function_exists('smpro_ai_available') && smpro_ai_available();
?>
<div class="card" style="padding:14px;margin-bottom:12px;border-left:4px solid #3b5bdb">
  <b data-i18n>&#128161; What this section is for</b>
  <p class="sub" style="margin:4px 0 0;line-height:1.6" data-i18n>When customers <b>couldn't log in</b> or the <b>server was down/unreachable</b>, you usually have no idea why after it recovers. This section reconstructs what happened <b>from the server's own logs</b> for the exact time window — reboot/crash, out-of-memory, network flood, a <b>firewall block of legitimate (Egyptian/Saudi) IPs</b>, or a provider null-route — so you get a <b>root cause</b>, evidence, and how to prevent it. Use <b>"Why is an IP blocked?"</b> for a specific customer IP, the <b>Outage report</b> for a downtime window, and <b>Analyze with AI</b> for a written explanation of the causes.</p>
</div>
<details class="rc-acc" open style="margin-bottom:12px">
  <summary>
    <span>&#128272; <span data-i18n>Why is an IP blocked?</span></span>
    <span class="rc-count" data-i18n>find the exact firewall block reason</span>
    <span class="rc-arw">&#9656;</span>
  </summary>
  <div class="rc-body">
    <p class="rc-count" style="margin:0 0 8px" data-i18n>Enter an IP (e.g. a customer's Egyptian IP that can't connect). It reads CSF (csf -g), the csf.deny reason, the LFD trigger history, GeoIP and CC_ALLOW — and tells you exactly why it's blocked and how to fix it.</p>
    <form method="get" action="index.cgi" style="display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end">
      <input type="hidden" name="page" value="reports-center"><input type="hidden" name="tab" value="incidents">
      <label style="display:flex;flex-direction:column;gap:3px;font-size:12px;color:var(--muted)">IP address
        <input class="tp-in" name="bip" value="<?= smpro_h($bip) ?>" placeholder="197.x.x.x" style="min-width:200px"></label>
      <button class="fw-act fix" type="submit" data-i18n>Check block reason</button>
    </form>
    <?php if ($br): if (!$br['valid']): ?>
      <p class="meta" style="color:var(--bad,#d93b3b);margin:10px 0 0"><?= smpro_h($br['verdict']) ?></p>
    <?php else:
      $vCls = $br['blocked'] ? 'crit' : (($br['in_allow']) ? '' : 'high');
    ?>
      <div style="margin-top:12px;border:1px solid var(--border,#e3e8f2);border-radius:10px;padding:12px">
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:6px">
          <code style="font-weight:800"><?= smpro_h($br['ip']) ?></code>
          <span class="b <?= $vCls ?>"><?= $br['blocked'] ? 'BLOCKED' : ($br['in_allow'] ? 'ALLOW-LISTED' : 'NOT BLOCKED') ?></span>
          <?php if ($br['country']): ?><span class="rc-count"><?= smpro_h($br['country']) ?><?= $br['datacenter'] ? ' · datacenter' : ' · residential' ?><?= $br['provider'] ? ' · ' . smpro_h($br['provider']) : '' ?></span><?php endif; ?>
          <?php if ($br['where']): ?><span class="rc-count">via <?= smpro_h(implode(', ', $br['where'])) ?></span><?php endif; ?>
        </div>
        <p style="margin:0;font-size:14px;line-height:1.55"><?= smpro_h($br['verdict']) ?></p>
        <?php if (!empty($br['fix'])): ?>
          <div style="margin-top:8px;font-weight:700;font-size:13px" data-i18n>How to fix</div>
          <ul style="margin:5px 0 0;padding-left:18px;color:var(--muted);font-size:13px">
            <?php foreach ($br['fix'] as $f): ?><li><code style="font-size:12px"><?= smpro_h($f) ?></code></li><?php endforeach; ?>
          </ul>
        <?php endif; ?>
        <div style="margin-top:8px;font-size:12px;color:var(--muted)">
          CC_ALLOW: <code><?= smpro_h($br['cc_allow'] ?: '(not set)') ?></code>
          <?= $br['country'] ? ' — covers ' . smpro_h($br['country']) . ': <b>' . ($br['cc_covers'] ? 'yes' : 'NO') . '</b>' : '' ?>
        </div>
        <?php if (!empty($br['lfd'])): ?>
          <details class="rc-grp" style="margin-top:10px"><summary><span>LFD trigger history</span><span class="b high" style="margin-left:4px"><?= count($br['lfd']) ?></span><span class="rc-arw">&#9656;</span></summary>
            <pre class="rc-pre"><?php foreach ($br['lfd'] as $l) echo smpro_h($l) . "\n"; ?></pre>
          </details>
        <?php endif; ?>
        <?php if ($br['csf_g'] !== ''): ?>
          <details class="rc-grp" style="margin-top:8px"><summary><span>csf -g output</span><span class="rc-arw">&#9656;</span></summary>
            <pre class="rc-pre"><?= smpro_h($br['csf_g']) ?></pre>
          </details>
        <?php endif; ?>
      </div>
    <?php endif; endif; ?>
  </div>
</details>
<div class="card" style="padding:14px;margin-bottom:12px">
  <b data-i18n>Outage report — analyze the logs for a time window</b>
  <p class="sub" style="margin:2px 0 10px" data-i18n>Pick the start and end (date + time) of the period the server was down/unreachable — any window up to 31 days, can span multiple days. We read the system, kernel and firewall logs for that window and infer the probable cause.</p>
  <form method="get" action="index.cgi" style="display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end">
    <input type="hidden" name="page" value="reports-center"><input type="hidden" name="tab" value="incidents">
    <label style="display:flex;flex-direction:column;gap:3px;font-size:12px;color:var(--muted)">From day
      <input class="tp-in" type="date" name="o_date" value="<?= smpro_h($oDate ?: date('Y-m-d')) ?>" required></label>
    <label style="display:flex;flex-direction:column;gap:3px;font-size:12px;color:var(--muted)">From time
      <input class="tp-in" type="time" name="o_from" value="<?= smpro_h($oFrom ?: '00:00') ?>" required></label>
    <label style="display:flex;flex-direction:column;gap:3px;font-size:12px;color:var(--muted)">To day
      <input class="tp-in" type="date" name="o_date2" value="<?= smpro_h($oDate2 ?: ($oDate ?: date('Y-m-d'))) ?>" required></label>
    <label style="display:flex;flex-direction:column;gap:3px;font-size:12px;color:var(--muted)">To time
      <input class="tp-in" type="time" name="o_to" value="<?= smpro_h($oTo ?: '23:59') ?>" required></label>
    <button class="fw-act fix" type="submit" data-i18n>Analyze</button>
  </form>
  <?php if ($winErr): ?><p class="meta" style="color:var(--bad,#d93b3b);margin:8px 0 0"><?= smpro_h($winErr) ?></p><?php endif; ?>
</div>
<style>
/* AI report rendered as markdown */
.rc-aimd{line-height:1.65;font-size:13.5px;color:var(--ink)}
.rc-aimd .rc-mdh{margin:14px 0 6px;font-size:14px;font-weight:800;color:var(--ink);border-bottom:1px solid var(--line);padding-bottom:4px}
.rc-aimd ul{margin:4px 0 4px 2px;padding-left:18px}
.rc-aimd li{margin:3px 0}
.rc-aimd code{background:var(--brand-bg);color:var(--brand);padding:1px 5px;border-radius:5px;font-size:12px}
/* reboot attribution banner */
.rc-reboot{display:flex;gap:12px;align-items:flex-start;border:1px solid var(--line);border-left-width:4px;border-radius:11px;padding:13px 15px;margin-bottom:12px;background:var(--card)}
.rc-reboot.rc-rb-crit{border-left-color:var(--dang);background:var(--dang-bg)}
.rc-reboot.rc-rb-warn{border-left-color:var(--warn);background:var(--warn-bg)}
.rc-reboot.rc-rb-ok{border-left-color:var(--good);background:var(--good-bg)}
.rc-rb-ic{font-size:22px;line-height:1}
.rc-rb-h{font-weight:800;font-size:14px;color:var(--ink)}
.rc-rb-t{font-size:13px;color:var(--ink);margin-top:3px;line-height:1.55}
.rc-rb-w{font-size:12.5px;color:var(--muted);margin-top:4px}
/* recommended fixes */
.rc-fixes{border:1px solid var(--line);border-radius:12px;padding:14px 16px;margin-bottom:12px;background:var(--card)}
.rc-fixes-h{font-weight:800;font-size:14px;color:var(--ink);margin-bottom:8px;display:flex;gap:8px;align-items:center}
.rc-fix{display:flex;gap:12px;align-items:flex-start;justify-content:space-between;border-top:1px solid var(--line);padding:11px 0;flex-wrap:wrap}
.rc-fix:first-of-type{border-top:0}
.rc-fix-b{flex:1;min-width:240px;border-left:3px solid var(--line);padding-left:10px}
.rc-fix-crit .rc-fix-b{border-left-color:var(--dang)}.rc-fix-warn .rc-fix-b{border-left-color:var(--warn)}.rc-fix-ok .rc-fix-b{border-left-color:var(--good)}
.rc-fix-t{font-weight:700;font-size:13.5px;color:var(--ink)}
.rc-fix-d{font-size:12.5px;color:var(--muted);margin-top:3px;line-height:1.5}
.rc-fix-msg{font-size:12.5px;margin-top:5px}
.rc-fix-a{display:flex;gap:6px;align-items:center;flex-wrap:wrap}
.rc-fix-manual{font-size:11.5px;color:var(--muted);background:var(--bg);border:1px solid var(--line);padding:3px 10px;border-radius:20px}
.fw-act.fix{background:var(--good);color:#fff;border:1px solid var(--good)}
.rc-acc{border:1px solid var(--border,#e3e8f2);border-radius:12px;margin-bottom:12px;overflow:hidden;background:var(--card,#fff)}
.rc-acc>summary,.rc-grp>summary{list-style:none;cursor:pointer;display:flex;align-items:center;gap:8px;padding:13px 16px;font-weight:700;user-select:none}
.rc-acc>summary::-webkit-details-marker,.rc-grp>summary::-webkit-details-marker{display:none}
.rc-acc>summary:hover,.rc-grp>summary:hover{background:rgba(148,163,184,.07)}
.rc-arw{margin-left:auto;transition:transform .18s;color:var(--muted);font-size:12px}
details[open]>summary .rc-arw{transform:rotate(90deg)}
.rc-body{padding:4px 16px 15px}
.rc-count{font-weight:500;font-size:12px;color:var(--muted)}
.rc-grp{border:1px solid var(--border,#eef1f6);border-radius:9px;margin-top:8px;overflow:hidden}
.rc-grp>summary{padding:9px 12px;font-size:13px;background:rgba(148,163,184,.05)}
.rc-srcname{font-family:monospace;font-weight:700}
.rc-pre{margin:4px 0 0;padding:8px;background:var(--code-bg,#0d1117);color:var(--code-fg,#c9d1d9);border-radius:6px;overflow:auto;font-size:11px;line-height:1.4}
</style>
<?php
  $sevCls = ['critical'=>'crit','warn'=>'high','info'=>''];
  if ($report):
    $cc = $confCls[$report['confidence']] ?? '';
    $expQ = 'index.cgi?page=reports-center&rc_export=outage&o_date=' . urlencode($oDate) . '&o_date2=' . urlencode($oDate2) . '&o_from=' . urlencode($oFrom) . '&o_to=' . urlencode($oTo);
    // group the log events by source so each log stream is its own collapsible group
    $byHostSrc = [];
    foreach ($report['events'] as $e) { $byHostSrc[$e['src'] ?: 'other'][] = $e; }
    $grpSev = function ($rows) { foreach (['critical','warn','info'] as $s) foreach ($rows as $r) if (($r['sev'] ?? '') === $s) return $s; return ''; };
?>
<details class="rc-acc" open>
  <summary>
    <span>&#129513; Probable cause</span>
    <span class="b <?= $cc ?>"><?= smpro_h(strtoupper($report['confidence'])) ?></span>
    <span class="rc-count"><?= smpro_h(date('Y-m-d H:i', (int)$report['from'])) ?> &rarr; <?= smpro_h(date('H:i', (int)$report['to'])) ?></span>
    <span class="rc-arw">&#9656;</span>
  </summary>
  <div class="rc-body">
    <div style="display:flex;gap:6px;margin:0 0 10px">
      <a class="fw-act" href="<?= smpro_h($expQ) ?>" data-i18n>&#11015; Export CSV</a>
      <button class="fw-act" type="button" onclick="window.print()" data-i18n>&#128424; Print</button>
    </div>
    <p style="margin:0;font-size:14px;line-height:1.55"><?= smpro_h($report['cause']) ?></p>
    <p class="rc-count" style="margin:8px 0 0;line-height:1.55" data-i18n>&#128161; In simple terms: this is what your server's own logs say happened during the time it was down or customers couldn't log in. The steps below tell you how to fix it — or press <b>Analyze with AI</b> for a plain-language explanation (Arabic supported).</p>
    <?php if (!empty($report['recommend'])): ?>
      <div style="margin-top:10px;font-weight:700;font-size:13px" data-i18n>Recommended next steps</div>
      <ul style="margin:6px 0 0;padding-left:18px;color:var(--muted);font-size:13px">
        <?php foreach ($report['recommend'] as $r): ?><li><?= smpro_h($r) ?></li><?php endforeach; ?>
      </ul>
    <?php endif; ?>
  </div>
</details>

<?php $aiQ = 'index.cgi?page=reports-center&rc_ai_outage=1&o_date=' . urlencode($oDate) . '&o_date2=' . urlencode($oDate2) . '&o_from=' . urlencode($oFrom) . '&o_to=' . urlencode($oTo); ?>
<details class="rc-acc" open>
  <summary>
    <span>&#129302; <span data-i18n>AI cause analysis</span></span>
    <span class="rc-count"><?= $aiOn ? 'explain the outage causes' : 'AI not configured' ?></span>
    <span class="rc-arw">&#9656;</span>
  </summary>
  <div class="rc-body">
    <?php if (!$aiOn): ?>
      <p class="rc-count" style="margin:0">Enable an AI provider in <a href="index.cgi?page=ai-providers">Settings &rarr; AI Providers</a> (free options available), then come back and the AI will read the evidence and explain the most likely causes of the outage.</p>
    <?php else: ?>
      <p class="rc-count" style="margin:0 0 8px" data-i18n>Let the AI read the log evidence for this window and explain — in plain language — the most likely reasons the server/login went down, ranked, with how to prevent each.</p>
      <button class="fw-act fix" type="button" id="rcAiBtn" data-url="<?= smpro_h($aiQ) ?>" data-i18n>&#129302; Analyze causes with AI</button>
      <div id="rcAiOut" style="margin-top:10px;display:none"></div>
    <?php endif; ?>
  </div>
</details>
<?php if ($aiOn): ?>
<script>
function rcEsc(s){return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function rcMd(t){
  var h=rcEsc(t||'');
  h=h.replace(/^#{1,6}\s*(.*)$/gm,'<h4 class="rc-mdh">$1</h4>');
  h=h.replace(/\*\*([^*]+)\*\*/g,'<b>$1</b>').replace(/`([^`]+)`/g,'<code>$1</code>');
  h=h.replace(/^\s*[-*]\s+(.*)$/gm,'<li>$1</li>').replace(/^\s*\d+\.\s+(.*)$/gm,'<li>$1</li>');
  h=h.replace(/(<li>[\s\S]*?<\/li>)(?=\s*(?:<h4|$))/g,'<ul>$1</ul>');
  return h.replace(/\n{2,}/g,'<br><br>').replace(/\n/g,'<br>');
}
(function(){
  var b=document.getElementById('rcAiBtn'); if(!b) return;
  b.addEventListener('click',function(){
    var out=document.getElementById('rcAiOut');
    b.disabled=true; var t=b.textContent; b.textContent='🤖 Analyzing… (up to ~30s)';
    out.style.display='block'; out.innerHTML='<span class="rc-count">Reading the logs and asking the AI…</span>';
    fetch(b.getAttribute('data-url'),{cache:'no-store'}).then(function(r){return r.json();}).then(function(j){
      b.disabled=false; b.textContent=t;
      if(j&&j.ok){
        out.innerHTML='<div class="rc-aimd">'+rcMd(j.text)+'</div>'+
          '<div class="rc-count" style="margin-top:10px">&#129302; '+rcEsc(j.provider)+' / '+rcEsc(j.model)+'</div>';
      } else { out.innerHTML='<span style="color:var(--dang,#d93b3b)">'+((j&&j.error)||'AI request failed')+'</span>'; }
    }).catch(function(){ b.disabled=false; b.textContent=t; out.innerHTML='<span style="color:var(--bad,#d93b3b)">Request failed.</span>'; });
  });
})();
</script>
<?php endif; ?>

<?php if (!empty($report['reboot_attr'])): $ra = $report['reboot_attr']; $raCls = ($ra['sev'] ?? 'warn') === 'critical' ? 'rc-rb-crit' : (($ra['sev'] ?? '') === 'info' ? 'rc-rb-ok' : 'rc-rb-warn'); ?>
<div class="rc-reboot <?= $raCls ?>">
  <div class="rc-rb-ic"><?= ($ra['auto'] ?? true) ? '&#9888;' : '&#128100;' ?></div>
  <div>
    <div class="rc-rb-h">Server rebooted at <?= smpro_h(date('Y-m-d H:i', (int)$report['reboot'])) ?> — <?= ($ra['auto'] ?? true) ? 'AUTOMATIC' : 'BY A PERSON' ?></div>
    <div class="rc-rb-t"><?= smpro_h($ra['text'] ?? '') ?></div>
    <?php if (!empty($ra['who']) && !($ra['auto'] ?? true)): ?><div class="rc-rb-w">Triggered by: <b><?= smpro_h($ra['who']) ?></b> &middot; method: <?= smpro_h($ra['how'] ?? '') ?></div><?php endif; ?>
    <?php if (!empty($ra['evidence'])): ?><pre class="rc-pre" style="margin-top:6px;max-height:120px;overflow:auto"><?= smpro_h(mb_substr($ra['evidence'],0,500)) ?></pre><?php endif; ?>
  </div>
</div>
<?php endif; ?>

<?php if (!empty($report['fixes'])): $rcFixCsrf = smpro_csrf_generate('rc_action'); ?>
<div class="rc-fixes">
  <div class="rc-fixes-h">&#128295; Recommended fixes <span class="rc-count">review and approve</span></div>
  <?php foreach ($report['fixes'] as $fx): $fc = ($fx['sev'] ?? 'info')==='critical'?'crit':(($fx['sev']??'')==='warn'?'warn':'ok'); ?>
  <div class="rc-fix rc-fix-<?= $fc ?>" data-fix="<?= smpro_h($fx['id']) ?>">
    <div class="rc-fix-b">
      <div class="rc-fix-t"><?= smpro_h($fx['title']) ?></div>
      <div class="rc-fix-d"><?= smpro_h($fx['desc']) ?></div>
      <div class="rc-fix-msg"></div>
    </div>
    <div class="rc-fix-a">
      <?php if (empty($fx['manual']) && !empty($fx['action'])): ?>
        <button class="fw-act fix rc-fix-go" type="button"
          data-action="<?= smpro_h($fx['action']) ?>" data-svc="<?= smpro_h($fx['svc'] ?? '') ?>">&#10003; Approve &amp; apply</button>
        <button class="fw-act rc-fix-no" type="button">Dismiss</button>
      <?php else: ?>
        <span class="rc-fix-manual">Manual step</span>
      <?php endif; ?>
    </div>
  </div>
  <?php endforeach; ?>
</div>
<script>
(function(){
  var CS=<?= json_encode($rcFixCsrf) ?>;
  document.querySelectorAll('.rc-fix-no').forEach(function(b){b.addEventListener('click',function(){var c=b.closest('.rc-fix');c.style.opacity=.45;c.querySelector('.rc-fix-a').innerHTML='<span class="rc-count">dismissed</span>';});});
  document.querySelectorAll('.rc-fix-go').forEach(function(b){b.addEventListener('click',function(){
    var c=b.closest('.rc-fix'),msg=c.querySelector('.rc-fix-msg');
    if(!confirm('Apply this fix now? It is reversible.'))return;
    b.disabled=true;var t=b.innerHTML;b.innerHTML='Applying…';
    var fd=new URLSearchParams();fd.set('rc_action','fix');fd.set('fix',b.getAttribute('data-action'));fd.set('svc',b.getAttribute('data-svc')||'');fd.set('smpro_csrf',CS);
    fetch('index.cgi?page=reports-center',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString()}).then(function(r){return r.json();}).then(function(j){
      b.disabled=false;b.innerHTML=t;
      msg.innerHTML='<span style="color:'+((j&&j.ok)?'var(--good)':'var(--dang)')+';font-weight:600">'+((j&&j.ok)?'✓ ':'✗ ')+rcEsc((j&&(j.msg||j.message))||'done')+'</span>';
      if(j&&j.ok){c.querySelector('.rc-fix-a').innerHTML='<span class="rc-count">applied ✓</span>';}
    }).catch(function(){b.disabled=false;b.innerHTML=t;msg.innerHTML='<span style="color:var(--dang)">request failed</span>';});
  });});
})();
</script>
<?php endif; ?>

<details class="rc-acc">
  <summary>
    <span>&#128220; <span data-i18n>What the logs show</span></span>
    <span class="rc-count"><?= count($report['events']) ?> event(s) &middot; <?= count($byHostSrc) ?> source(s)</span>
    <span class="rc-arw">&#9656;</span>
  </summary>
  <div class="rc-body">
    <?php if (!$report['events']): ?>
      <p class="rc-count" style="padding:4px 0" data-i18n>No matching log lines were found in this window.</p>
    <?php else: foreach ($byHostSrc as $src => $rows): $gs = $grpSev($rows); ?>
      <details class="rc-grp">
        <summary>
          <span class="rc-srcname"><?= smpro_h($src) ?></span>
          <span class="b <?= $sevCls[$gs] ?? '' ?>" style="margin-left:4px"><?= count($rows) ?></span>
          <span class="rc-arw">&#9656;</span>
        </summary>
        <table class="smpro-table" style="margin:0"><tbody>
          <?php foreach ($rows as $e): $cls = $sevCls[$e['sev']] ?? ''; ?>
            <tr>
              <td class="meta" style="white-space:nowrap"><?= smpro_h(date('H:i', (int)$e['ts'])) ?></td>
              <td><span class="b <?= $cls ?>"><?= smpro_h($e['sev']) ?></span></td>
              <td><code style="font-size:12px;word-break:break-word"><?= smpro_h($e['txt']) ?></code></td>
            </tr>
          <?php endforeach; ?>
        </tbody></table>
      </details>
    <?php endforeach; endif; ?>
  </div>
</details>

<?php
  $sarBlocks = ['load'=>'Load average (sar -q)', 'mem'=>'Memory (sar -r)', 'net'=>'Network (sar -n DEV)'];
  $hasSar = false; foreach ($sarBlocks as $k=>$v) if (!empty($report['sar'][$k])) $hasSar = true;
?>
<details class="rc-acc">
  <summary>
    <span>&#128202; <span data-i18n>Resource history (sysstat / sar)</span></span>
    <span class="rc-count"><?= $hasSar ? 'load &middot; memory &middot; network' : 'not available' ?></span>
    <span class="rc-arw">&#9656;</span>
  </summary>
  <div class="rc-body">
    <?php if ($hasSar): foreach ($sarBlocks as $k=>$label): if (empty($report['sar'][$k])) continue; ?>
      <div style="margin-top:8px"><span class="rc-count"><?= smpro_h($label) ?></span>
        <pre class="rc-pre"><?= smpro_h($report['sar'][$k]) ?></pre></div>
    <?php endforeach; else: ?>
      <p class="rc-count" data-i18n>No sar/sysstat history for this window — install the <code>sysstat</code> package to enable load/memory/network timelines.</p>
    <?php endif; ?>
  </div>
</details>
<?php endif; /* $report */ ?>

<details class="rc-acc"<?= $report ? '' : ' open' ?>>
  <summary>
    <span>&#128276; <span data-i18n>Recent auto-detected incidents</span></span>
    <span class="rc-count"><?= count($incidents) ?> in 7d</span>
    <span class="rc-arw">&#9656;</span>
  </summary>
  <div class="rc-body" style="padding-left:0;padding-right:0">
    <table class="smpro-table" style="margin:0"><thead><tr><th data-i18n>Time</th><th data-i18n>Severity</th><th data-i18n>Type</th><th data-i18n>Incident</th><th data-i18n>Source</th></tr></thead><tbody>
    <?php if (!$incidents): ?><tr><td colspan="5" style="padding:16px;color:var(--muted)" data-i18n>No incidents auto-detected in the last 7 days.</td></tr><?php endif; ?>
    <?php usort($incidents, fn($a,$b) => ($b['ts'] ?? 0) <=> ($a['ts'] ?? 0)); foreach ($incidents as $i): $cls = $sevCls[$i['severity'] ?? 'warn'] ?? ''; ?>
      <tr>
        <td class="meta"><?= !empty($i['ts']) ? smpro_h(date('Y-m-d H:i', (int)$i['ts'])) : '&mdash;' ?></td>
        <td><span class="b <?= $cls ?>"><?= smpro_h($i['severity'] ?? '') ?></span></td>
        <td><?= smpro_h($i['type'] ?? '') ?></td>
        <td><b><?= smpro_h($i['title'] ?? '') ?></b><?= !empty($i['detail']) ? '<br><span class="meta">' . smpro_h(mb_substr((string)$i['detail'], 0, 400)) . '</span>' : '' ?></td>
        <td><span class="meta"><?= smpro_h($i['source'] ?? '') ?><?= !empty($i['actor']) ? ' &middot; ' . smpro_h($i['actor']) : '' ?></span></td>
      </tr>
    <?php endforeach; ?>
    </tbody></table>
  </div>
</details>
<?php endif; ?>

<style>
.la-tabs{display:flex;gap:4px;border-bottom:2px solid var(--line);margin:16px 0 14px}
.la-tab{padding:9px 16px;font-size:14px;font-weight:600;color:var(--muted);text-decoration:none;border-bottom:3px solid transparent;margin-bottom:-2px}.la-tab.active{color:var(--brand);border-bottom-color:var(--brand)}
.rc-search{display:flex;gap:8px;margin:6px 0 14px;flex-wrap:wrap;align-items:center}.rc-in{border:1px solid var(--line);border-radius:9px;padding:9px 12px;font-size:14px;flex:1;max-width:420px}
.rc-toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;padding:6px 2px 12px}.rc-toolbar .rc-in{flex:none}
.rc-dt{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--muted);font-weight:600}.rc-dt .rc-in{flex:none;max-width:160px;padding:7px 9px;font-size:13px}
.tp-btn{border:1px solid var(--line);background:#fff;color:var(--ink);border-radius:9px;padding:9px 14px;font-size:13px;cursor:pointer;font-weight:600}.tp-btn.primary{background:var(--brand);color:#fff;border-color:var(--brand)}
.rc-card{padding:18px 20px}.rc-head{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;flex-wrap:wrap;margin-bottom:12px}
.rc-ipv{font-family:ui-monospace,Consolas,monospace;font-size:20px;font-weight:800}
.rc-actions{display:flex;gap:6px;align-items:center;flex-wrap:wrap}
.rc-act{font-size:12px;font-weight:600;border:1px solid var(--line);background:#fff;border-radius:7px;padding:5px 11px;cursor:pointer}
.rc-act.block{color:var(--dang);border-color:#f3c4c4}.rc-act.block:hover{background:var(--dang);color:#fff}
.rc-act.allow{color:var(--good);border-color:#bfe6cd}.rc-act.allow:hover{background:var(--good);color:#fff}
.rc-kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:8px 0 14px}@media(max-width:760px){.rc-kpis{grid-template-columns:repeat(2,1fr)}}
.rc-kpis>div{background:#f7f9fc;border:1px solid var(--line);border-radius:12px;padding:10px 14px;display:flex;flex-direction:column;gap:2px}
.rc-kpis .l{font-size:11px;color:var(--muted);text-transform:uppercase;font-weight:700}.rc-kpis b{font-size:20px}
.rc-two{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}@media(max-width:760px){.rc-two{grid-template-columns:1fr}}
.rc-two h4{margin:0 0 6px;font-size:13px}.rc-li{display:flex;justify-content:space-between;font-size:12.5px;padding:3px 0;border-bottom:1px solid var(--line)}.rc-li b{font-weight:700}
.rc-scroll{max-height:380px;overflow:auto;border:1px solid var(--line);border-radius:10px}
.smpro-table{width:100%;border-collapse:collapse;font-size:12.5px}.smpro-table th,.smpro-table td{padding:7px 11px;text-align:left;border-bottom:1px solid var(--line)}
.smpro-table th{font-size:11px;text-transform:uppercase;color:var(--muted);position:sticky;top:0;background:#fafbfe}
.rc-empty{padding:18px;text-align:center;color:var(--muted)}.svc-kicker{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--brand);font-weight:700}.meta{color:var(--muted)}
.k{display:inline-block;font-size:11px;background:var(--brand-bg);color:var(--brand);border-radius:10px;padding:1px 8px}
.b{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:20px;background:#f1f5f9;color:#475569}.b.crit{background:#fdecec;color:#b91c1c}.b.high{background:#fdeee2;color:#c2410c}.b.med{background:#fdf6e7;color:#a16207}.b.ok{background:var(--good-bg);color:var(--good)}.b.ai{background:var(--brand-bg);color:var(--brand)}.b.arc{background:#fef3c7;color:#92702a}.b.sv{background:var(--good-bg);color:var(--good)}
.lm-chkl{display:inline-flex;align-items:center;gap:6px;font-size:13px}.smpro-table.nowrap th,.smpro-table.nowrap td{white-space:nowrap}
.lnk{color:var(--brand);text-decoration:none;font-size:12px;border:1px solid var(--line);padding:4px 9px;border-radius:7px}.lnk:hover{background:var(--brand-bg)}
</style>
<script>
(function(){
  document.addEventListener('click',function(e){var b=e.target.closest('.rc-act');if(!b)return;
    var ip=b.getAttribute('data-ip'),act=b.classList.contains('allow')?'allow':'block';
    if(!confirm((act==='allow'?'ALLOW (CSF allow + never auto-block) ':'BLOCK (CSF + Cloudflare) ')+ip+'?'))return;
    var fd=new URLSearchParams();fd.set('rc_action',act);fd.set('ip',ip);fd.set('smpro_csrf',RC_CSRF);
    fetch('index.cgi?page=reports-center',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'}).then(function(r){return r.json();}).then(function(j){alert((j&&j.ok)?(act+' ok: '+(j.msg||'')):'Failed: '+((j&&j.msg)||'token/license'));}).catch(function(){alert('Request failed.');});});
  var f=document.getElementById('rcFilter'),fr=document.getElementById('rcFrom'),tg=document.getElementById('rcTo'),tbl=document.getElementById('rcDir'),cnt=document.getElementById('rcCount');
  if(tbl){function rcApply(){var q=(f&&f.value||'').toLowerCase();
    var fs=fr&&fr.value?Math.floor(new Date(fr.value+'T00:00:00').getTime()/1000):0;
    var ts=tg&&tg.value?Math.floor(new Date(tg.value+'T23:59:59').getTime()/1000):Infinity;var n=0;
    tbl.querySelectorAll('tbody tr').forEach(function(tr){var s=tr.getAttribute('data-search')||'';var t=parseInt(tr.getAttribute('data-ts')||'0',10);
      var ok=(!q||s.indexOf(q)>=0)&&t>=fs&&t<=ts;tr.style.display=ok?'':'none';if(ok)n++;});
    if(cnt)cnt.textContent=n+' report(s)';}
    [f,fr,tg].forEach(function(el){if(el)el.addEventListener('input',rcApply);});}
})();
</script>
<script>
/* Live IP Watch — poll the IP's requests across all domains every 10s */
(function(){
  var body=document.getElementById('rcLiveBody');if(!body)return;
  var auto=document.getElementById('rcLiveAuto'),meta=document.getElementById('rcLiveMeta');
  var ip=new URLSearchParams(location.search).get('ip')||'';if(!ip)return;
  function esc(s){return (s==null?'':String(s)).replace(/[&<>"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
  function scls(s){s=+s;return s>=500?'crit':(s>=400?'high':(s>=300?'med':'ok'));}
  function susp(p){return /wp-login|xmlrpc|\.env|\.git|wp-json\/wp\/v2\/users|phpmyadmin|\/\.\.|union\s|eval\(|base64_|\/wp-admin|\.sql/i.test(p||'');}
  function load(){
    fetch('index.cgi?page=reports-center&rc_live=1&ip='+encodeURIComponent(ip),{cache:'no-store'}).then(function(r){return r.json();}).then(function(j){
      if(!j||!j.ok){body.innerHTML='<tr><td colspan="7" class="rc-empty">'+esc((j&&j.msg)||'failed')+'</td></tr>';return;}
      var rows=j.rows||[];
      if(!rows.length)body.innerHTML='<tr><td colspan="7" class="rc-empty">No recent requests from this IP in the access logs.</td></tr>';
      else body.innerHTML=rows.map(function(x){var sp=susp(x.path);
        return '<tr'+(sp?' style="background:rgba(220,38,38,.07)"':'')+'><td class="meta">'+esc(x.time)+'</td><td><b>'+esc(x.domain)+'</b></td><td>'+esc(x.method)+'</td>'+
        '<td class="ipmono" title="'+esc(x.path)+'">'+esc((x.path||'').slice(0,70))+(sp?' <span class="b crit">attack?</span>':'')+'</td>'+
        '<td><span class="b '+scls(x.status)+'">'+esc(x.status)+'</span></td><td class="meta">'+esc(x.bytes)+'</td>'+
        '<td class="meta" title="'+esc(x.ua)+'">'+esc((x.ua||'').slice(0,42))+'</td></tr>';}).join('');
      if(meta)meta.textContent=j.count+' request(s) · updated '+j.now;
    }).catch(function(){});
  }
  load();setInterval(function(){if(!auto||auto.checked)load();},10000);
})();
</script>
<?php
smpro_layout_footer();
