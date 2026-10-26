<?php
/**
 * modules/reports-center.php - Reports Center.
 * Two things: (1) a comprehensive per-IP report pulling everything the plugin knows about
 * an address (geo/ASN/reputation, firewall status, 30-day web-attack profile from the index),
 * with Block / Allow / export; and (2) a directory of every saved report across all sections.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }
/* ---------------- Daily Security Report: endpoints (root + CSRF for writes; downloads need the WHM session only) ---------------- */
if (function_exists('smpro_sr_get') && isset($_GET['sr'])) {
    smpro_require_root();
    $srWhat = (string)$_GET['sr']; $srId = preg_replace('/[^0-9]/', '', (string)($_GET['id'] ?? ''));
    if ($srWhat === 'html' || $srWhat === 'print') {
        $rep = smpro_sr_get($srId); if (!$rep) { http_response_code(404); exit('no such report'); }
        $html = smpro_sr_render_html($rep, true);
        if ($srWhat === 'html') { header('Content-Type: text/html; charset=UTF-8'); header('Content-Disposition: attachment; filename="security-report-' . $rep['day'] . '.html"'); echo $html; exit; }
        header('Content-Type: text/html; charset=UTF-8'); echo str_replace('</body>', '<script>window.addEventListener("load",function(){setTimeout(function(){window.print();},400);});</script></body>', $html); exit;
    }
    if ($srWhat === 'pdf') {
        $rep = smpro_sr_get($srId); if (!$rep) { http_response_code(404); exit('no such report'); }
        $pdf = smpro_sr_dir() . '/' . $rep['id'] . '.pdf';
        if (!is_file($pdf)) smpro_sr_pdf(smpro_sr_render_html($rep, true), $pdf);
        if (is_file($pdf)) { header('Content-Type: application/pdf'); header('Content-Disposition: attachment; filename="security-report-' . $rep['day'] . '.pdf"'); readfile($pdf); exit; }
        header('Location: index.cgi?page=reports-center&sr=print&id=' . $rep['id']); exit;   // no renderer here: the print view saves as PDF from the browser
    }
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        smpro_require_valid_csrf('secreport'); header('Content-Type: application/json'); @ignore_user_abort(true); @set_time_limit(600);
        if ($srWhat === 'generate') { $day = preg_match('/^\d{4}-\d{2}-\d{2}$/', (string)($_POST['day'] ?? '')) ? strtotime($_POST['day'] . ' 00:00:00') : 0; $r = smpro_sr_run(true, $day); echo json_encode(['ok' => !empty($r['ok']), 'id' => (string)($r['id'] ?? ''), 'score' => (int)($r['score'] ?? 0), 'msg' => !empty($r['ok']) ? 'Report built for ' . date('Y-m-d', $day ?: strtotime('yesterday')) . ' (score ' . (int)$r['score'] . ').' : 'Not built.']); exit; }
        if ($srWhat === 'send') { $rep = smpro_sr_get($srId); if (!$rep) { echo json_encode(['ok' => false, 'msg' => 'No such report.']); exit; } $ch = []; foreach (['email', 'telegram', 'whatsapp'] as $c) if (!empty($_POST[$c])) $ch[$c] = true; $d = smpro_sr_deliver($rep, $ch); $okc = array_keys(array_filter($d, fn($x) => !empty($x['ok']))); $bad = []; foreach ($d as $c => $x) if (empty($x['ok'])) $bad[] = $c . ': ' . (string)$x['detail']; echo json_encode(['ok' => (bool)$okc, 'msg' => ($okc ? 'Sent on ' . implode(', ', $okc) : 'Not sent') . ($bad ? ' · ' . implode(' · ', $bad) : '') . '.']); exit; }
        if ($srWhat === 'settings') { $c = smpro_sr_cfg(); $c['enabled'] = !empty($_POST['enabled']); $c['hour'] = max(0, min(23, (int)($_POST['hour'] ?? 6))); foreach (['panel', 'email', 'telegram', 'whatsapp'] as $k) $c['channels'][$k] = $k === 'panel' ? true : !empty($_POST['ch_' . $k]); smpro_sr_cfg_save($c); smpro_sr_cron_sync(); smpro_audit('daily_security_report_settings', $c); echo json_encode(['ok' => true, 'msg' => $c['enabled'] ? 'Scheduled: every day at ' . sprintf('%02d:07', $c['hour']) . ' for the previous day, to ' . implode(', ', array_keys(array_filter($c['channels']))) . '.' : 'Schedule switched off; reports can still be built by hand.']); exit; }
        echo json_encode(['ok' => false, 'msg' => 'Unknown action.']); exit;
    }
}


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
/** Parse ?from / ?to (YYYY-MM-DD) -> [sinceTs, untilTs] (0 = open). */
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
/** Every audited OPERATION performed on/about this IP (block, allow, emergency, ...), within the window. */
function smpro_rc_ip_operations($ip, $sinceTs = 0, $untilTs = 0, $limit = 200) {
    if (!defined('SMPRO_AUDIT_LOG') || !is_file(SMPRO_AUDIT_LOG)) return [];
    $since = $sinceTs ?: (time() - 90 * 86400); $until = $untilTs ?: time();
    $raw = (string)@shell_exec('timeout 15 grep -aF ' . escapeshellarg($ip) . ' ' . escapeshellarg(SMPRO_AUDIT_LOG) . ' 2>/dev/null | tail -n 4000');
    $out = [];
    foreach (explode("\n", $raw) as $l) {
        $l = trim($l); if ($l === '') continue;
        $j = json_decode($l, true); if (!is_array($j) || empty($j['action'])) continue;
        $det = $j['details'] ?? []; $detStr = is_array($det) ? json_encode($det, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE) : (string)$det;
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
/** Login/auth attempts by this IP across ALL services (SSH, mail, FTP, cPanel/WHM/webmail).
 *  Uses the shared, service-complete scanner so a mail/SSH/FTP brute-forcer isn't reported as
 *  "no activity" just because it never hit SSH or cPanel. */
function smpro_rc_ip_logins($ip, $sinceTs = 0, $untilTs = 0) {
    if (function_exists('smpro_ip_auth_attempts')) return smpro_ip_auth_attempts($ip, $sinceTs, $untilTs, 300);
    return [];
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
        'firewall'=>smpro_rc_block_reason($ip),                    // full block + allow status (csf -g, csf.deny reason, LFD, csf.allow, CC_ALLOW)
        'attacks'=>function_exists('smpro_in_ip_summary') ? smpro_in_ip_summary($ip, $sinceTs, $untilTs) : ['total'=>0],
        'operations'=>smpro_rc_ip_operations($ip, $sinceTs, $untilTs),
        'logins'=>smpro_rc_ip_logins($ip, $sinceTs, $untilTs),
        'requests'=>smpro_rc_ip_live($ip, 300),
    ];
}

/* ---------------- Incident analysis - read the logs for an outage window and infer the cause ---------------- */
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

    // 3) OOM via dmesg (timestamps may be relative - informational)
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

    // 6) sar history (sysstat) - load / memory / network around the window
    if (smpro_rc_has('sar')) {
        // Point sar at the DAILY file for the window's date (-f). Without it, sar always reads TODAY's
        // file, so analyzing yesterday's outage showed today's numbers as "evidence" (and fed them to the AI).
        $saFile = '/var/log/sa/sa' . date('d', $fromTs);
        $fArg = is_readable($saFile) ? ('-f ' . escapeshellarg($saFile) . ' ') : '';
        $h1 = date('H:i:s', $fromTs);
        // sar reads one daily file; if the window crosses midnight, clamp the end to that day so it isn't empty.
        $h2 = date('Ymd', $fromTs) === date('Ymd', $toTs) ? date('H:i:s', $toTs) : '23:59:59';
        $rep['sar']['load'] = trim(smpro_rc_logcmd('sar ' . $fArg . '-q -s ' . $h1 . ' -e ' . $h2 . ' 2>/dev/null | tail -16'));
        $rep['sar']['mem']  = trim(smpro_rc_logcmd('sar ' . $fArg . '-r -s ' . $h1 . ' -e ' . $h2 . ' 2>/dev/null | tail -10'));
        $rep['sar']['net']  = trim(smpro_rc_logcmd('sar ' . $fArg . '-n DEV -s ' . $h1 . ' -e ' . $h2 . ' 2>/dev/null | grep -iE "eth0|ens|enp|bond" | tail -16'));
    }

    // 6b) DEEP read - every relevant log for the window, not just kernel/firewall
    $win = function ($cmd) { return smpro_rc_logcmd($cmd); };
    $grab = function ($lines, $sev, $src, $max = 6) use (&$add, $fromTs) {
        $n = 0; foreach (array_filter(array_map('trim', explode("\n", (string)$lines))) as $l) { if ($n++ >= $max) break; $add($fromTs, $sev, $src, $l); }
    };
    // failed systemd services right now + service crashes in window
    if ($hasJournal) {
        $grab($win('systemctl --failed --no-legend 2>/dev/null | head -8'), 'critical', 'services', 8);
        $grab($win('journalctl --since ' . escapeshellarg($fromStr) . ' --until ' . escapeshellarg($toStr) . ' --no-pager 2>/dev/null | grep -iE "Failed with result|core-dump|segfault|Main process exited|Start request repeated|Stopping|entered failed" | head -20'), 'warn', 'services', 8);
    }
    // MySQL / MariaDB crashes - multi-day date pattern (both ymd + Y-m-d formats, every day in the window)
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
    if (smpro_rc_has('journalctl')) {
        // The crash that CAUSED a reboot is in the log of the boot that PRECEDED it. Find the boot index K
        // whose start ≈ $bootTs, then read boot K-1 (one older). A bare `-b -1` is only correct for the most
        // recent reboot; for older reboots in the list it read the wrong boot's kernel log entirely.
        $bsel = '-b -1';
        $lb = smpro_rc_logcmd('journalctl --list-boots -q --no-pager 2>/dev/null');
        foreach (explode("\n", $lb) as $bl) {
            if (preg_match('/^\s*(-?\d+)\b.*?(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})/', $bl, $bm)) {
                $bts2 = strtotime($bm[2]);
                if ($bts2 && abs($bts2 - $bootTs) <= 3600) { $bsel = '-b ' . ((int)$bm[1] - 1); break; }   // preceding boot
            }
        }
        $crash = smpro_rc_logcmd('journalctl ' . $bsel . ' -k -p warning -n 300 --no-pager 2>/dev/null | grep -iE ' . escapeshellarg($crashRe) . ' | tail -12');
    }
    if (trim($crash) === '') $crash = smpro_rc_logcmd('grep -iE ' . escapeshellarg(date('M [ ]?j', $bootTs)) . ' /var/log/messages 2>/dev/null | grep -iE ' . escapeshellarg($crashRe) . ' | tail -12');
    $lc = strtolower($crash);
    if (strpos($lc, 'panic') !== false || strpos($lc, 'lockup') !== false || strpos($lc, 'hung') !== false || strpos($lc, 'general protection') !== false || strpos($lc, 'oops') !== false)
        return ['auto' => true, 'sev' => 'critical', 'how' => 'kernel crash', 'who' => 'the kernel (crash)', 'text' => 'AUTOMATIC — the kernel CRASHED (panic / watchdog / hung-task) and the machine reset itself. Nobody pressed reboot.', 'evidence' => trim($crash)];
    if (strpos($lc, 'out of memory') !== false || strpos($lc, 'killed process') !== false)
        return ['auto' => true, 'sev' => 'critical', 'how' => 'out of memory', 'who' => 'the kernel (OOM)', 'text' => 'AUTOMATIC — the server ran OUT OF MEMORY; the kernel OOM-killer fired and the box hung/rebooted. Nobody pressed reboot.', 'evidence' => trim($crash)];

    // who initiated a CLEAN shutdown/reboot? (sudo command in auth log, or systemd-logind)
    $who = ''; $howClean = ''; $bad = ['reboot','shutdown','poweroff','halt','system','systemctl','init'];
    foreach (['/var/log/secure', '/var/log/auth.log'] as $sf) if (is_readable($sf)) {
        // only REAL sudo reboot/shutdown commands - capture the invoking user (before " : "), not the run-as USER=
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
    // OOM -> guided (adding swap/limits is invasive; explain, no auto-button)
    if ($has('out of memory') || $has('oom') || $has('killed process'))
        $fixes[] = ['id' => 'oom', 'sev' => 'critical', 'title' => 'Out of memory', 'action' => '',
            'desc' => 'The kernel killed processes for lack of RAM. Reduce risk: add a swap file, raise/relax LVE or php-fpm memory limits, and find the memory hog in Top Processes.', 'manual' => true];
    // disk full
    if ($has('no space left') || $has('disk full'))
        $fixes[] = ['id' => 'disk', 'sev' => 'critical', 'title' => 'Disk full', 'action' => '',
            'desc' => 'A filesystem hit 100% — services fail when they cannot write. Clear logs/old backups; check Disk / Storage.', 'manual' => true];
    // a crashed cPanel service -> one-click restart
    $svcMap = ['mysql'=>'mysql','mariadb'=>'mysql','httpd'=>'httpd','apache'=>'httpd','exim'=>'exim','dovecot'=>'dovecot','named'=>'named','lsws'=>'lsws','litespeed'=>'lsws','cpsrvd'=>'cpsrvd'];
    foreach ($svcMap as $needle => $svc) if ($has($needle . ' ') && ($has('failed') || $has('crash') || $has('segfault') || $has('killed'))) {
        $fixes['svc_' . $svc] = ['id' => 'svc_' . $svc, 'sev' => 'warn', 'title' => 'Restart ' . $svc, 'action' => 'restart_service', 'svc' => $svc,
            'desc' => ucfirst($svc) . ' looks like it failed/crashed in this window. Restart it via the plugin (safe).', 'manual' => false];
    }
    // sysstat missing -> one-click install (better future analysis)
    if (empty($rep['sar']['load']) && empty($rep['sar']['mem']))
        $fixes[] = ['id' => 'sysstat', 'sev' => 'info', 'title' => 'Install sysstat (sar) for deeper history', 'action' => 'install_sysstat',
            'desc' => 'sar/sysstat was not available, so load/memory/network history for the outage is missing. Install it so the next incident has full resource timelines.', 'manual' => false];
    return array_values($fixes);
}

/**
 * Explain WHY a specific IP is (or isn't) firewall-blocked. Reads csf -g (authoritative),
 * csf.deny comment, the LFD trigger history, GeoIP, csf.allow, and CC_ALLOW - then gives a
 * plain verdict + fix. Built for the "this IP got blocked though it should be allow-listed"
 * case: it tells you the LFD reason AND whether CC_ALLOW covers the IP's country. Read-only.
 */
function smpro_rc_block_reason($ip) {
    $ip = trim($ip);
    $rep = ['ip'=>$ip, 'valid'=>(bool)filter_var($ip, FILTER_VALIDATE_IP), 'blocked'=>false, 'where'=>[],
            'comment'=>'', 'lfd'=>[], 'csf_g'=>'', 'country'=>'', 'provider'=>'', 'datacenter'=>false,
            'in_allow'=>false, 'cc_allow'=>'', 'cc_covers'=>false, 'verdict'=>'', 'fix'=>[],
            'imunify'=>['present'=>false, 'lists'=>[], 'graylisted'=>false, 'blacklisted'=>false, 'whitelisted'=>false, 'incidents'=>[], 'console'=>[], 'webshield'=>null]];
    if (!$rep['valid']) { $rep['verdict'] = 'Enter a valid IP address.'; return $rep; }

    // 1) csf -g - authoritative: shows every place the IP is matched (csf.deny / temp ban / iptables / csf.allow).
    //    Use the resolved binary path - a bare "csf" isn't on the CGI PATH, so it returned nothing and the
    //    verdict below wrongly fell through to "BLOCKED" for IPs that were not blocked at all.
    $csfBin = function_exists('smpro_csf_bin') ? smpro_csf_bin() : 'csf';
    $rep['csf_g'] = $csfBin ? trim(smpro_rc_logcmd(escapeshellarg($csfBin) . ' -g ' . escapeshellarg($ip))) : '';
    $rep['csf_ok'] = $rep['csf_g'] !== '';                  // did csf -g actually return output?
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

    // 5b) Imunify360 - the layer this report never looked at. A customer "could not open the sites"; this report
    //     said "NOT blocked" because CSF held nothing, and it was right about CSF. Imunify had graylisted the
    //     address (WebShield then serves its challenge / splash page instead of the site), which is a block a
    //     customer feels and CSF cannot see. Read Imunify's lists, its incidents for the address, and its own
    //     console lines that name the decision.
    if (function_exists('smpro_fw_has_imunify') && smpro_fw_has_imunify()) {
        $im = &$rep['imunify']; $im['present'] = true;
        // The agent has no per-address query; each list is read and matched here (exact address, or a CIDR
        // that contains it). A first draft used a per-address query the agent does not have, and printed
        // "on no list" for an address that was on the white list - the verified-on-real-data rule, again.
        foreach (['white', 'black', 'gray'] as $lname) {
            $raw = smpro_rc_logcmd('imunify360-agent ' . $lname . 'list ip list --json --limit 5000 2>/dev/null');
            $j = json_decode($raw, true);
            foreach ((array)($j['items'] ?? []) as $row) {
                if (!is_array($row)) continue;
                $entry = (string)($row['ip'] ?? '');
                $hit = ($entry === $ip) || (strpos($entry, '/') !== false && function_exists('smpro_in_cidr_match') && smpro_in_cidr_match($ip, $entry));
                if (!$hit) continue;
                $ln = strtoupper((string)($row['listname'] ?? $lname));
                $im['lists'][] = ['list' => $ln, 'ip' => $entry, 'comment' => (string)($row['comment'] ?? ''),
                                  'expires' => (int)($row['expiration'] ?? 0), 'manual' => !empty($row['manual'])];
                if ($ln === 'GRAY')  $im['graylisted']  = true;
                if ($ln === 'BLACK') $im['blacklisted'] = true;
                if ($ln === 'WHITE') $im['whitelisted'] = true;
            }
        }
        $raw = smpro_rc_logcmd('imunify360-agent list incidents --by-abuser ' . escapeshellarg($ip) . ' --json --limit 6 2>/dev/null');
        $j = json_decode($raw, true);
        foreach ((array)($j['items'] ?? []) as $row) {
            if (!is_array($row)) continue;
            $im['incidents'][] = ['when' => (int)($row['time'] ?? $row['timestamp'] ?? 0), 'rule' => (string)($row['rule'] ?? ''),
                                  'name' => (string)($row['name'] ?? ''), 'severity' => (string)($row['severity'] ?? ''),
                                  'what' => mb_substr((string)($row['description'] ?? ''), 0, 160)];
        }
        // Imunify's console names its decisions: "IP x is graylisted", "Rejected: IP x is whitelisted" ...
        // today's file is dated on some installs and plain on others; both are read, newest last
        $raw = smpro_rc_logcmd('cat /var/log/imunify360/console.log-' . date('Ymd') . ' /var/log/imunify360/console.log 2>/dev/null | grep -h -F ' . escapeshellarg($ip) . ' | grep -viE ' . escapeshellarg('unified|simple_rpc|GET |POST ') . ' | tail -n 8');
        foreach (array_filter(array_map('trim', explode("\n", $raw))) as $line) $im['console'][] = mb_substr($line, 0, 220);
        $cfg = json_decode(smpro_rc_logcmd('imunify360-agent config show --json 2>/dev/null'), true);
        if (is_array($cfg) && isset($cfg['WEBSHIELD'])) $im['webshield'] = ['enable' => !empty($cfg['WEBSHIELD']['enable']), 'splash' => !empty($cfg['WEBSHIELD']['splash_screen']), 'panel' => !empty($cfg['WEBSHIELD']['panel_protection'])];
        if ($im['graylisted'] || $im['blacklisted']) {
            $rep['blocked'] = true;
            $rep['where'][] = $im['blacklisted'] ? 'Imunify360 black list' : 'Imunify360 gray list (WebShield challenge / splash page)';
        }
        unset($im);
    }

    // 6) CC_ALLOW (country never-block) from csf.conf - does it cover this IP's country?
    $cc = trim(smpro_rc_logcmd("grep -E '^CC_ALLOW(_FILTER)? *=' /etc/csf/csf.conf 2>/dev/null"));
    $rep['cc_allow']  = $cc;
    $rep['cc_covers'] = $rep['country'] !== '' && (bool)preg_match('/\b' . preg_quote($rep['country'], '/') . '\b/i', $cc);

    // 7) verdict + fix
    $arab = function_exists('smpro_cc_is_arab') && smpro_cc_is_arab((string)$rep['country']);   // configured trusted region (home ∪ caution), not a fixed list
    $imx = $rep['imunify'];
    if (!empty($imx['present']) && ($imx['graylisted'] || $imx['blacklisted'])) {
        $why = $imx['incidents'] ? ($imx['incidents'][0]['name'] ?: $imx['incidents'][0]['rule'] ?: 'see incidents below') : 'see Imunify360 for the rule';
        $rep['verdict'] = ($imx['blacklisted'] ? 'BLOCKED by Imunify360 (black list)' : 'CHALLENGED by Imunify360 (gray list): WebShield serves its challenge or splash page instead of the site, which a customer sees as "the site does not open"')
                        . '. CSF holds nothing for this address. Reason: ' . $why . '.';
        $rep['fix'][] = 'Allow it here (the Allow button puts it on Imunify360\'s white list as well as csf.allow), or in Imunify360 › Firewall remove it from the gray list.';
        $rep['fix'][] = 'If this is a customer, that is the fix. If it is an attacker that Imunify challenged correctly, leave it.';
    } elseif (!$rep['blocked'] && (strpos($g, 'no matches') !== false || ($rep['csf_ok'] && strpos($g, 'deny') === false))) {
        $rep['verdict'] = 'This IP is NOT blocked right now — no match in csf.deny, temporary bans, or iptables'
                        . (!empty($imx['present']) ? ($imx['whitelisted'] ? ', and Imunify360 white-lists it.' : ', and Imunify360 has it on no list.') : '.')
                        . (!empty($imx['webshield']['enable']) && empty($imx['whitelisted']) ? ' Imunify360 WebShield is on' . (!empty($imx['webshield']['panel']) ? ' (including panel protection)' : '') . ': an address it decides to challenge gets a splash page even with CSF clear - check the lines below.' : '');
    } elseif ($rep['in_allow'] && !$rep['blocked']) {
        $rep['verdict'] = 'This IP is allow-listed (csf.allow) and not blocked. If traffic still fails, the block is upstream (Cloudflare / provider), not CSF.';
    } elseif (!$rep['blocked'] && !$rep['csf_ok']) {
        // csf -g produced no output (csf unavailable/timed out) AND the IP is not in csf.deny/csf.allow files.
        // Do NOT claim it is blocked - that was the false-positive. Report the inconclusive state honestly.
        $rep['verdict'] = 'Could not confirm firewall status — the IP is not in csf.deny or csf.allow, but the live CSF lookup returned nothing (csf may be unavailable). Check the Firewall page.';
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
    // action => [severity, human title, type]. 'maintenance' actions are routine automation, not security.
    $sev = [
        'firewall_csf_disable'    => ['critical', 'Firewall (CSF) disabled', 'security'],
        'firewall_csf_production' => ['warn', 'CSF switched to production', 'security'],
        'firewall_cc_allow'       => ['info', 'Country block-prevention changed', 'security'],
        'firewall_service'        => ['warn', 'Firewall service control', 'security'],
        'intrusion_autoblock'     => ['warn', 'Auto-blocked an attacking IP', 'security'],
        'intrusion_breach'        => ['critical', 'Breach detected', 'security'],
        'cooler_start'            => ['info', 'Load cooler throttled a runaway process', 'maintenance'],
        'cooler_guard_fire'       => ['info', 'Load guard throttled a runaway process', 'maintenance'],
    ];
    // Turn the raw audit JSON into one plain sentence - never show the raw {"pids":[...]} to the admin.
    $humanize = function ($action, $d) {
        $d = is_array($d) ? $d : [];
        $n = is_array($d['pids'] ?? null) ? count($d['pids']) : null;
        if ($action === 'cooler_start' || $action === 'cooler_guard_fire')
            return 'Throttled ' . ($n ?? 0) . ' process' . (($n ?? 0) === 1 ? '' : 'es') . ' to ' . (int)($d['percent'] ?? $d['ceiling'] ?? 0) . '% CPU for ' . (int)($d['minutes'] ?? 10) . ' min'
                 . (isset($d['load1']) ? ' (load was ' . $d['load1'] . ')' : '');
        if ($action === 'intrusion_autoblock') return 'Blocked ' . ($d['ip'] ?? 'an IP') . (isset($d['reason']) ? ' — ' . $d['reason'] : '');
        if (strpos($action, 'firewall_') === 0)  return trim(($d['msg'] ?? '') . (isset($d['enabled']) ? ' (enabled=' . ($d['enabled'] ? 'yes' : 'no') . ')' : ''));
        // generic fallback: key: value pairs, not JSON braces
        $parts = []; foreach ($d as $kk => $vv) { if (is_array($vv)) $vv = count($vv) . ' item(s)'; $parts[] = $kk . ': ' . $vv; }
        return implode(' · ', array_slice($parts, 0, 4));
    };
    // Collect audit events per action first, so a routine action that fired hundreds of times
    // becomes ONE grouped row instead of flooding the list.
    $byAction = [];
    if (is_readable(SMPRO_AUDIT_LOG)) foreach (explode("\n", (string)@shell_exec('tail -n 8000 ' . escapeshellarg(SMPRO_AUDIT_LOG) . ' 2>/dev/null')) as $l) {
        $j = json_decode(trim($l), true); if (!is_array($j) || empty($j['action']) || !isset($sev[$j['action']])) continue;
        // smpro_audit() writes the time under 'timestamp' (ISO-8601), never 'ts'.
        $ts = strtotime((string)($j['timestamp'] ?? '')) ?: 0; if ($ts < $since) continue;
        $dd = is_array($j['details'] ?? null) ? $j['details'] : [];
        $byAction[$j['action']][] = ['ts' => $ts, 'detail' => $humanize($j['action'], $dd), 'actor' => (string)($j['actor'] ?? ''),
            'pids' => is_array($dd['pids'] ?? null) ? $dd['pids'] : []];
    }
    // RECURRING LOAD PRESSURE: when an auto-throttle keeps firing, the same long-lived processes are usually
    // behind it. Tally which PIDs recur across the events, resolve the ones still alive to process + owning
    // (cPanel) account, and raise ONE actionable finding - so the admin fixes the cause instead of watching the
    // guard fire forever. (Read-only /proc lookups, only the few most-frequent PIDs.)
    foreach (['cooler_start', 'cooler_guard_fire'] as $ca) {
        if (empty($byAction[$ca]) || count($byAction[$ca]) < 12) continue;   // must be persistent to be a pattern
        $freq = [];
        foreach ($byAction[$ca] as $e) foreach (($e['pids'] ?? []) as $p) { $p = (int)$p; if ($p > 0) $freq[$p] = ($freq[$p] ?? 0) + 1; }
        arsort($freq);
        $offenders = []; $ownerCount = []; $n = 0;
        foreach ($freq as $pid => $c) {
            if ($c < 3) break;                                              // appeared in at least 3 separate firings
            $alive = @is_dir('/proc/' . $pid);
            $comm = $alive ? trim((string)@file_get_contents('/proc/' . $pid . '/comm')) : '';
            $owner = '';
            if ($alive) { $stt = @stat('/proc/' . $pid); $uid = (int)($stt['uid'] ?? -1); if ($uid >= 0 && function_exists('posix_getpwuid')) { $pw = @posix_getpwuid($uid); $owner = $pw['name'] ?? (string)$uid; } }
            $isCp = ($owner !== '' && function_exists('smpro_is_cpanel_user') && smpro_is_cpanel_user($owner));
            $offenders[] = ['pid' => $pid, 'count' => $c, 'alive' => $alive, 'process' => $comm !== '' ? $comm : '(ended)', 'owner' => $owner, 'is_cpanel' => $isCp];
            if ($owner !== '') $ownerCount[$owner] = ($ownerCount[$owner] ?? 0) + $c;
            if (++$n >= 8) break;
        }
        if (!$offenders) continue;
        arsort($ownerCount);
        $topOwner = $ownerCount ? array_key_first($ownerCount) : '';
        $fires = count($byAction[$ca]);
        $detail = 'The load guard fired ' . $fires . ' times, and the same processes keep tripping it — that is a root cause to fix, not just repeated throttling. '
            . ($topOwner !== '' ? 'Most of it involves ' . ($offenders[0]['is_cpanel'] ? 'cPanel account' : 'user') . ' "' . $topOwner . '". ' : '')
            . 'Investigate the top process in Top Processes / the Overload Investigator and cap or fix it.';
        $out[] = ['id' => 'recur:' . $ca, 'ts' => time(), 'type' => 'performance', 'severity' => 'warn', 'source' => 'analysis',
            'title' => 'Recurring load pressure — the same processes keep tripping the load guard', 'detail' => $detail, 'actor' => '', 'offenders' => $offenders];
    }
    foreach ($byAction as $action => $evts) {
        $meta = $sev[$action]; $type = $meta[2] ?? 'security';
        if (count($evts) > 3) {                                  // recurring -> collapse into one grouped incident
            usort($evts, fn($a, $b) => ($b['ts'] ?? 0) <=> ($a['ts'] ?? 0));
            $last = (int)$evts[0]['ts']; $first = (int)end($evts)['ts'];
            $span = max(1, $last - $first);
            $out[] = ['id' => 'grp:' . $action, 'ts' => $last, 'type' => $type, 'severity' => $meta[0], 'source' => 'audit',
                'title' => $meta[1], 'count' => count($evts), 'first_ts' => $first, 'last_ts' => $last,
                'detail' => 'Fired ' . count($evts) . ' times over ' . smpro_dur($span) . ' — about once every ' . smpro_dur((int)round($span / max(1, count($evts) - 1))) . '. Latest: ' . ($evts[0]['detail'] ?? ''),
                'children' => array_slice(array_map(fn($e) => ['ts' => $e['ts'], 'detail' => $e['detail']], $evts), 0, 60),
                'actor' => $evts[0]['actor']];
        } else {
            foreach ($evts as $e) $out[] = ['id' => 'a' . $e['ts'] . $action, 'ts' => (int)$e['ts'], 'type' => $type, 'severity' => $meta[0], 'source' => 'audit', 'title' => $meta[1], 'detail' => $e['detail'], 'actor' => $e['actor']];
        }
    }
    if (function_exists('smpro_im_selfattack_recent')) foreach (smpro_im_selfattack_recent(24) as $s) {
        $out[] = ['id' => 'self' . $s['ip'], 'ts' => (int)($s['last'] ?? time()), 'type' => 'self-attack', 'severity' => 'critical', 'source' => 'intrusion', 'title' => 'Web attack from local IP ' . $s['ip'], 'detail' => (int)$s['n'] . ' events on ' . (int)$s['domains'] . ' domain(s) — possible local compromise', 'actor' => ''];
    }
    // Reboots/crashes are real incidents - surface them automatically WITH the inferred cause.
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
    echo json_encode(['ip'=>$ip] + $r, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
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
    echo json_encode($resp, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

/* CSV export of an IP report. */
if (($_GET['rc_export'] ?? '') === 'csv' && filter_var($_GET['ip'] ?? '', FILTER_VALIDATE_IP)) {
    [$rcxf, $rcxt] = smpro_rc_range();
    $rep = smpro_rc_ip_report($_GET['ip'], $rcxf, $rcxt);
    header('Content-Type: text/csv; charset=utf-8'); header('Content-Disposition: attachment; filename="ip_' . $rep['ip'] . '.csv"');
    $fh = fopen('php://output', 'w');
    smpro_fputcsv($fh, ['field','value']);
    smpro_fputcsv($fh, ['ip',$rep['ip']]); smpro_fputcsv($fh, ['country',$rep['country']]); smpro_fputcsv($fh, ['provider',$rep['provider']]); smpro_fputcsv($fh, ['asn',$rep['asn']]);
    smpro_fputcsv($fh, ['datacenter',$rep['datacenter']?'yes':'no']); smpro_fputcsv($fh, ['csf',$rep['csf'] ?: 'not blocked']); smpro_fputcsv($fh, ['allowlisted',$rep['allowlisted']?'yes':'no']);
    smpro_fputcsv($fh, ['abuse_score',$rep['abuse']]); smpro_fputcsv($fh, ['attacks_30d',$rep['attacks']['total']]);
    // firewall block + allow status
    $fw = $rep['firewall'] ?? [];
    smpro_fputcsv($fh, ['blocked',!empty($fw['blocked'])?'yes':'no']); smpro_fputcsv($fh, ['blocked_where',implode(' | ',($fw['where'] ?? []))]);
    smpro_fputcsv($fh, ['block_reason',$fw['comment'] ?? '']); smpro_fputcsv($fh, ['allow_listed',!empty($fw['in_allow'])?'yes':'no']);
    smpro_fputcsv($fh, ['cc_allow_covers_country',!empty($fw['cc_covers'])?'yes':'no']); smpro_fputcsv($fh, ['firewall_verdict',$fw['verdict'] ?? '']);
    foreach (($fw['lfd'] ?? []) as $ll) smpro_fputcsv($fh, ['lfd_history',$ll]);
    smpro_fputcsv($fh, []); smpro_fputcsv($fh, ['attack_time','domain','type','severity','http','uri']);
    foreach (($rep['attacks']['recent'] ?? []) as $e) smpro_fputcsv($fh, [date('Y-m-d H:i:s',(int)$e['ts']),$e['domain'],$e['kind'],$e['severity'],$e['code'],$e['uri']]);
    smpro_fputcsv($fh, []); smpro_fputcsv($fh, ['operation_time','operation','action','by','admin_ip','result']);
    foreach (($rep['operations'] ?? []) as $o) smpro_fputcsv($fh, [date('Y-m-d H:i:s',(int)$o['ts']),$o['label'],$o['action'],$o['actor'],$o['admin_ip'],$o['result']]);
    smpro_fputcsv($fh, []); smpro_fputcsv($fh, ['login_time','source','result','user','detail']);
    foreach (($rep['logins'] ?? []) as $lg) smpro_fputcsv($fh, [$lg['ts']?date('Y-m-d H:i:s',(int)$lg['ts']):'', $lg['source'],$lg['result'],$lg['user'],$lg['detail']]);
    smpro_fputcsv($fh, []); smpro_fputcsv($fh, ['request_time','domain','method','path','http_status','bytes','user_agent']);
    foreach (($rep['requests'] ?? []) as $rq) smpro_fputcsv($fh, [$rq['ts']?date('Y-m-d H:i:s',(int)$rq['ts']):'', $rq['domain'],$rq['method'],$rq['path'],$rq['status'],$rq['bytes'],$rq['ua']]);
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
        . 'Rules: be specific to the evidence, quote real lines, do NOT invent logs. If something is missing, say what to collect. Critical local context: this server hosts mostly customers in ' . smpro_im_home_regions_label() . ' — a very common "customers cannot log in" cause is CSF/LFD blocking residential IPs from those regions because CC_ALLOW omits them; call this out explicitly whenever firewall/LFD activity appears. You may answer in Arabic.';
    $usr = "Write the in-depth incident report from this evidence:\n\n" . smpro_rc_outage_ai_evidence($rep);
    $r = smpro_ai_chat($sys, $usr, ['max_tokens'=>1700, 'temperature'=>0.2, 'context'=>'outage_analysis']);
    smpro_audit('reports_center_ai_outage', ['from'=>$fromTs, 'to'=>$toTs, 'ok'=>!empty($r['ok'])]);
    if (empty($r['ok'])) { echo json_encode(['ok'=>false, 'error'=>(string)($r['error'] ?? 'AI request failed')]); exit; }
    echo json_encode(['ok'=>true, 'text'=>(string)$r['text'], 'provider'=>(string)($r['provider'] ?? ''), 'model'=>(string)($r['model'] ?? '')], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

/** Compact the per-IP report into evidence text for the AI (trims the big request/operation lists to keep tokens sane). */
function smpro_rc_ip_ai_evidence($rep) {
    $c = $rep;
    if (isset($c['requests']) && is_array($c['requests']))   $c['requests']   = array_slice($c['requests'], 0, 25);
    if (isset($c['operations']) && is_array($c['operations'])) $c['operations'] = array_slice($c['operations'], 0, 20);
    if (isset($c['logins']) && is_array($c['logins']))       $c['logins']     = array_slice($c['logins'], 0, 20);
    return json_encode($c, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_INVALID_UTF8_SUBSTITUTE);
}

/* AI plain-language verdict on a single IP (read-only; reads the same evidence the IP report shows). */
if (($_GET['rc_ai_ip'] ?? '') === '1' && filter_var($_GET['ip'] ?? '', FILTER_VALIDATE_IP)) {
    header('Content-Type: application/json');
    if (!function_exists('smpro_ai_chat') || !function_exists('smpro_ai_available') || !smpro_ai_available()) {
        echo json_encode(['ok'=>false, 'error'=>'AI is not configured. Add a free provider in Settings → AI Providers, then try again.']); exit;
    }
    $ip = $_GET['ip'];
    [$aiFrom, $aiTo] = smpro_rc_range();
    $rep = smpro_rc_ip_report($ip, $aiFrom, $aiTo);
    $sys = 'You are a senior cPanel/WHM server-security analyst. You are given the ACTUAL evidence THIS server holds about ONE IP address: geolocation/ASN, AbuseIPDB score, firewall/CSF status, attack events the plugin detected, admin/account operations, login attempts, and a sample of recent HTTP requests. Give the admin a clear, decisive verdict — not a generic lecture.\n'
        . 'Structure (markdown ## headers + short bullets, keep it tight):\n'
        . '## Verdict — one line: is this IP HOSTILE, SUSPICIOUS, or BENIGN, with your confidence.\n'
        . '## Why — the specific evidence behind the verdict (quote the real numbers/paths/lines you actually see).\n'
        . '## Recommended action — exactly what to do: block (and for how long), allow-list, or leave it. If it is ALREADY blocked (see the firewall/CSF fields), say whether that block is justified or a likely false-positive to clear.\n'
        . 'Critical local context: this server hosts mostly customers in ' . smpro_im_home_regions_label() . ' — a residential IP from those regions hitting webmail/login a handful of times is almost always a REAL customer, not an attacker; never recommend blocking those. A datacenter/hosting IP scanning many distinct paths, probing wp-login/xmlrpc, or touching many accounts IS suspicious. Be specific to the evidence, do not invent logs. You may answer in Arabic.';
    $usr = "Assess this IP from the evidence:\n\n" . smpro_rc_ip_ai_evidence($rep);
    $r = smpro_ai_chat($sys, $usr, ['max_tokens'=>1100, 'temperature'=>0.2, 'context'=>'ip_assessment']);
    smpro_audit('reports_center_ai_ip', ['ip'=>$ip, 'ok'=>!empty($r['ok'])]);
    if (empty($r['ok'])) { echo json_encode(['ok'=>false, 'error'=>(string)($r['error'] ?? 'AI request failed')]); exit; }
    echo json_encode(['ok'=>true, 'text'=>(string)$r['text'], 'provider'=>(string)($r['provider'] ?? ''), 'model'=>(string)($r['model'] ?? '')], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
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
        smpro_fputcsv($fh, ['Outage report']);
        smpro_fputcsv($fh, ['window_from', date('Y-m-d H:i:s', (int)$rep['from'])]);
        smpro_fputcsv($fh, ['window_to', date('Y-m-d H:i:s', (int)$rep['to'])]);
        smpro_fputcsv($fh, ['probable_cause', $rep['cause']]);
        smpro_fputcsv($fh, ['confidence', $rep['confidence']]);
        smpro_fputcsv($fh, ['reboot_detected', $rep['reboot'] ? date('Y-m-d H:i:s', (int)$rep['reboot']) : 'no']);
        smpro_fputcsv($fh, ['logging_continuity', $rep['continuity'] === null ? 'unknown' : ($rep['continuity'] ? 'up+logging' : 'no logs (likely down)')]);
        smpro_fputcsv($fh, []);
        smpro_fputcsv($fh, ['Recommendations']);
        foreach (($rep['recommend'] ?? []) as $r) smpro_fputcsv($fh, [$r]);
        smpro_fputcsv($fh, []);
        smpro_fputcsv($fh, ['Log events', '', '']);
        smpro_fputcsv($fh, ['time','severity','source','log_line']);
        foreach (($rep['events'] ?? []) as $e) smpro_fputcsv($fh, [date('Y-m-d H:i:s',(int)$e['ts']), $e['sev'], $e['src'], $e['txt']]);
        foreach (['load'=>'sar load','mem'=>'sar memory','net'=>'sar network'] as $k=>$lbl) {
            if (empty($rep['sar'][$k])) continue;
            smpro_fputcsv($fh, []); smpro_fputcsv($fh, [$lbl]);
            foreach (explode("\n", (string)$rep['sar'][$k]) as $ln) { $ln = rtrim($ln); if ($ln !== '') smpro_fputcsv($fh, [$ln]); }
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
    echo json_encode(['ok'=>true,'count'=>count($rows),'now'=>date('H:i:s'),'rows'=>array_map(fn($r)=>['time'=>$r['ts']?date('H:i:s',$r['ts']):'','domain'=>$r['domain'],'method'=>$r['method'],'path'=>mb_substr($r['path'],0,120),'status'=>$r['status'],'bytes'=>$r['bytes'],'ua'=>mb_substr($r['ua'],0,90)], $rows)], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}
$tab = preg_replace('/[^a-z]/','',strtolower((string)($_GET['tab'] ?? 'ip')));
if (!in_array($tab,['ip','live','directory','incidents','moves'],true)) $tab = 'ip';
$csrf = smpro_csrf_generate('rc_action');
$qip = filter_var($_GET['ip'] ?? '', FILTER_VALIDATE_IP) ? $_GET['ip'] : '';
[$rcFrom, $rcTo] = smpro_rc_range();
$gfrom = smpro_h($_GET['from'] ?? ''); $gto = smpro_h($_GET['to'] ?? '');
$rep = $qip ? smpro_rc_ip_report($qip, $rcFrom, $rcTo) : null;
$winLbl = ($rcFrom || $rcTo) ? (($gfrom ?: '…') . ' → ' . ($gto ?: 'now')) : 'last 30 days';
smpro_audit('reports_center_view', ['tab'=>$tab,'ip'=>$qip]);
smpro_layout_header('Reports Center');
?>
<?php if (function_exists('smpro_sr_list')): $srCfg = smpro_sr_cfg(); $srList = smpro_sr_list(30); $srCsrf = smpro_csrf_generate('secreport'); $srLatest = $srList[0] ?? null; $srHasPdf = trim((string)@shell_exec('command -v wkhtmltopdf chromium chromium-browser google-chrome 2>/dev/null')) !== ''; ?>
<style>
.sr-card{background:var(--card);border:1px solid var(--line);border-radius:14px;margin:0 0 16px;overflow:hidden}.sr-hd{padding:12px 16px;border-bottom:1px solid var(--line);display:flex;gap:10px;align-items:center;flex-wrap:wrap}.sr-hd b{font-size:14px}.sr-hd .meta{margin-left:auto}
.sr-body{padding:12px 16px}.sr-row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:0 0 10px}.sr-score{font-size:30px;font-weight:800;color:var(--brand);line-height:1}
.sr-tbl{width:100%;border-collapse:collapse;font-size:12.5px}.sr-tbl th{text-align:left;font-size:10.5px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);padding:6px 8px;border-bottom:1px solid var(--line)}.sr-tbl td{padding:6px 8px;border-bottom:1px solid var(--line)}.sr-tbl .num{text-align:right;font-variant-numeric:tabular-nums}
.sr-set{display:flex;gap:10px;flex-wrap:wrap;align-items:center;font-size:12.5px;padding:10px 12px;border:1px dashed var(--line);border-radius:10px;margin-top:10px}.sr-msg{font-size:12.5px;margin-top:6px;min-height:16px}
</style>
<div class="sr-card" id="sr">
  <div class="sr-hd"><b>&#128203; Daily Security Report</b><span class="meta"><?= $srLatest ? 'latest: ' . smpro_h($srLatest['day']) . ' · score ' . (int)$srLatest['score'] : 'no report built yet' ?> · <?= $srCfg['enabled'] ? 'scheduled every day at ' . sprintf('%02d:07', (int)$srCfg['hour']) : 'not scheduled' ?></span></div>
  <div class="sr-body">
    <div class="sr-row">
      <?php if ($srLatest): ?><span class="sr-score"><?= (int)$srLatest['score'] ?></span><span class="meta" style="max-width:260px">security score for <?= smpro_h($srLatest['day']) ?> · <?= (int)$srLatest['served'] ?> served exploit(s) · <?= (int)$srLatest['foreign'] ?> foreign sign-in(s) · <?= (int)$srLatest['sent'] ?> alert(s) sent, <?= (int)$srLatest['held'] ?> held</span>
      <a class="btn btn-xs btn-secondary" href="index.cgi?page=reports-center&amp;sr=print&amp;id=<?= smpro_h($srLatest['id']) ?>" target="_blank">Open</a>
      <a class="btn btn-xs btn-ghost" href="index.cgi?page=reports-center&amp;sr=html&amp;id=<?= smpro_h($srLatest['id']) ?>">Download HTML</a>
      <a class="btn btn-xs btn-ghost" href="index.cgi?page=reports-center&amp;sr=pdf&amp;id=<?= smpro_h($srLatest['id']) ?>" title="<?= $srHasPdf ? 'rendered on the server' : 'no PDF renderer on this server: the print view opens, save it as PDF from the browser' ?>">Download PDF</a>
      <button type="button" class="btn btn-xs btn-ghost" data-srsend="<?= smpro_h($srLatest['id']) ?>">Send now</button>
      <?php endif; ?>
      <span style="flex:1"></span>
      <input type="date" id="srDay" class="tp-in" value="<?= smpro_h(date('Y-m-d', strtotime('yesterday'))) ?>" max="<?= smpro_h(date('Y-m-d')) ?>" style="font-size:12px"><button type="button" class="btn btn-xs btn-danger" id="srGen">Build report for that day</button>
    </div>
    <div class="sr-msg" id="srMsg"></div>
    <?php if (count($srList) > 1): ?><details style="margin-top:6px"><summary class="meta" style="cursor:pointer">Earlier reports (<?= count($srList) ?>)</summary><table class="sr-tbl" data-nopage="1"><thead><tr><th>Day</th><th class="num">Score</th><th class="num">Served</th><th class="num">Foreign</th><th class="num">Sent / held</th><th></th></tr></thead><tbody>
      <?php foreach ($srList as $x): ?><tr><td><?= smpro_h($x['day']) ?></td><td class="num"><?= (int)$x['score'] ?></td><td class="num"><?= (int)$x['served'] ?></td><td class="num"><?= (int)$x['foreign'] ?></td><td class="num"><?= (int)$x['sent'] ?> / <?= (int)$x['held'] ?></td><td><a class="fa-lnk" href="index.cgi?page=reports-center&amp;sr=print&amp;id=<?= smpro_h($x['id']) ?>" target="_blank">open</a> · <a class="fa-lnk" href="index.cgi?page=reports-center&amp;sr=html&amp;id=<?= smpro_h($x['id']) ?>">html</a> · <a class="fa-lnk" href="index.cgi?page=reports-center&amp;sr=pdf&amp;id=<?= smpro_h($x['id']) ?>">pdf</a></td></tr><?php endforeach; ?>
    </tbody></table></details><?php endif; ?>
    <div class="sr-set">
      <label style="font-weight:700"><input type="checkbox" id="srEn"<?= $srCfg['enabled'] ? ' checked' : '' ?>> Build and send every day</label>
      <label>at <select id="srHour" class="tp-sel"><?php for ($hh = 0; $hh < 24; $hh++) echo '<option value="' . $hh . '"' . ((int)$srCfg['hour'] === $hh ? ' selected' : '') . '>' . sprintf('%02d:07', $hh) . '</option>'; ?></select></label>
      <span class="meta">to:</span>
      <label><input type="checkbox" checked disabled> Panel (always kept, 90 days)</label>
      <label><input type="checkbox" id="srEmail"<?= !empty($srCfg['channels']['email']) ? ' checked' : '' ?>> Email (<?= $srHasPdf ? 'PDF' : 'HTML' ?> attached)</label>
      <label><input type="checkbox" id="srTg"<?= !empty($srCfg['channels']['telegram']) ? ' checked' : '' ?>> Telegram (summary)</label>
      <label><input type="checkbox" id="srWa"<?= !empty($srCfg['channels']['whatsapp']) ? ' checked' : '' ?>> WhatsApp (summary + where to open)</label>
      <button type="button" class="btn btn-xs btn-ghost" id="srSave">Save schedule</button>
      <span class="meta">Channels and recipients are the ones set in Notifications.</span>
    </div>
  </div>
</div>
<script>
(function(){
  var m=document.getElementById('srMsg'); if(!m) return; var CS=<?= json_encode($srCsrf) ?>;
  function say(ok,t){m.style.color=ok?'var(--good)':'var(--dang)';m.textContent=(ok?'\u2705 ':'\u26a0 ')+t;}
  function post(what,fd,cb){fd.set('smpro_csrf',CS);fetch('index.cgi?page=reports-center&sr='+what,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'}).then(function(r){return r.json();}).then(cb).catch(function(){say(false,'the request did not complete');});}
  var g=document.getElementById('srGen'); g.addEventListener('click',function(){g.disabled=true;say(true,'building\u2026 (reads the whole day; up to two minutes)');var fd=new URLSearchParams();fd.set('day',document.getElementById('srDay').value);post('generate',fd,function(j){g.disabled=false;say(!!(j&&j.ok),(j&&j.msg)||'failed');if(j&&j.ok)setTimeout(function(){location.href='index.cgi?page=reports-center#sr';location.reload();},900);});});
  document.querySelectorAll('[data-srsend]').forEach(function(b){b.addEventListener('click',function(){var ch=prompt('Send on which channels? (email, telegram, whatsapp - comma separated)','email');if(!ch)return;b.disabled=true;var fd=new URLSearchParams();fd.set('id',b.dataset.srsend);ch.split(',').forEach(function(c){fd.set(c.trim().toLowerCase(),'1');});post('send&id='+encodeURIComponent(b.dataset.srsend),fd,function(j){b.disabled=false;say(!!(j&&j.ok),(j&&j.msg)||'failed');});});});
  document.getElementById('srSave').addEventListener('click',function(){var fd=new URLSearchParams();fd.set('enabled',document.getElementById('srEn').checked?'1':'0');fd.set('hour',document.getElementById('srHour').value);fd.set('ch_email',document.getElementById('srEmail').checked?'1':'0');fd.set('ch_telegram',document.getElementById('srTg').checked?'1':'0');fd.set('ch_whatsapp',document.getElementById('srWa').checked?'1':'0');post('settings',fd,function(j){say(!!(j&&j.ok),(j&&j.msg)||'failed');});});
})();
</script>
<?php endif; ?>

<script>var RC_CSRF=<?= json_encode($csrf) ?>;</script>
<div class="svc-kicker">Reports</div>
<h1 class="h" style="margin:2px 0 4px" data-i18n>Reports Center</h1>
<p class="sub" data-i18n>One place for every report across all sections — and a full lookup of everything the plugin knows about any IP address.</p>

<div class="la-tabs">
  <a class="la-tab <?= $tab==='ip'?'active':'' ?>" href="index.cgi?page=reports-center&tab=ip" data-i18n>IP Report</a>
  <a class="la-tab <?= $tab==='live'?'active':'' ?>" href="index.cgi?page=reports-center&tab=live" data-i18n>Live IP Watch</a>
  <a class="la-tab <?= $tab==='directory'?'active':'' ?>" href="index.cgi?page=reports-center&tab=directory" data-i18n>All Reports</a>
  <a class="la-tab <?= $tab==='incidents'?'active':'' ?>" href="index.cgi?page=reports-center&tab=incidents" data-i18n>Incidents</a>
  <a class="la-tab <?= $tab==='moves'?'active':'' ?>" href="index.cgi?page=reports-center&tab=moves" data-i18n>Account moves</a>
</div>
<?php
// ---- per-tab overview strip + sticky navigator (each tab fills it from the variables it already has)
$rcStrip = function (array $cards, array $nav): void {
  echo '<div class="fw-kpis">';
  foreach ($cards as $k) echo '<a class="fw-kpi ' . smpro_h($k['cls']) . '" href="#' . smpro_h($k['id']) . '" data-go="' . smpro_h($k['id']) . '"><div class="l">' . smpro_h($k['l']) . '</div><div class="v">' . smpro_h($k['v']) . '</div><div class="s">' . smpro_h($k['s']) . '</div></a>';
  echo '</div><nav class="fw-nav" id="rcNav">';
  foreach ($nav as $n) echo '<a href="#' . smpro_h($n[0]) . '" data-go="' . smpro_h($n[0]) . '">' . $n[1] . '</a>';
  echo '<span class="sp"></span><button type="button" class="fw-navx" id="rcOpenAll">expand all</button><button type="button" class="fw-navx" id="rcCloseAll">collapse all</button></nav>';
};
?>

<?php if ($tab === 'ip'): ?>
  <form method="get" class="rc-search">
    <input type="hidden" name="page" value="reports-center"><input type="hidden" name="tab" value="ip">
    <input type="text" name="ip" class="rc-in" value="<?= smpro_h($qip) ?>" placeholder="Enter an IP address (e.g. 203.0.113.5)…" autofocus>
    <label class="rc-dt"><span data-i18n>From</span> <input type="date" name="from" class="rc-in" value="<?= $gfrom ?>"></label>
    <label class="rc-dt"><span data-i18n>To</span> <input type="date" name="to" class="rc-in" value="<?= $gto ?>"></label>
    <button class="tp-btn primary" type="submit" data-i18n>Build report</button>
  </form>
  <?php if ($qip && $rep): $a = $rep['attacks']; ?>
  <?php
  $rcFwOv = $rep['firewall'] ?? null;
  $rcStrip([
    ['id' => 'rc-ip-events', 'l' => 'Web attacks', 'v' => number_format($a['total']), 'cls' => $a['total'] > 0 ? 'dang' : 'good', 's' => $winLbl],
    ['id' => 'rc-ip-events', 'l' => 'Domains targeted', 'v' => number_format(count($a['domains'])), 'cls' => count($a['domains']) ? 'warn' : 'muted', 's' => $a['domains'] ? ('most hit: ' . (string)array_key_first($a['domains'])) : 'none'],
    ['id' => 'rc-ip-events', 'l' => 'Max severity', 'v' => $a['sev'] ?: '—', 'cls' => $a['sev'] ? (in_array(strtolower((string)$a['sev']), ['critical', 'high'], true) ? 'dang' : 'warn') : 'muted', 's' => $a['last'] ? ('last seen ' . date('Y-m-d H:i', $a['last'])) : 'no events'],
    ['id' => 'rc-ip-fw', 'l' => 'Firewall', 'v' => $rcFwOv ? (!empty($rcFwOv['blocked']) ? 'BLOCKED' : (!empty($rcFwOv['in_allow']) ? 'allow-listed' : 'not blocked')) : '—', 'cls' => $rcFwOv ? (!empty($rcFwOv['blocked']) ? 'dang' : 'good') : 'muted', 's' => $rep['csf'] ? ('CSF ' . $rep['csf']) : ($rep['allowlisted'] ? 'allowlisted' : 'csf.deny / csf.allow')],
    ['id' => 'rc-ip-ops', 'l' => 'Operations', 'v' => (string)count($rep['operations'] ?? []), 'cls' => 'brand', 's' => 'block / allow / emergency actions'],
    ['id' => 'rc-ip-logins', 'l' => 'Login attempts', 'v' => (string)count($rep['logins'] ?? []), 'cls' => count($rep['logins'] ?? []) ? 'warn' : 'muted', 's' => 'SSH · mail · FTP · cPanel'],
  ], [['rcCard', '&#128270; IP report'], ['rc-ip-fw', '&#128737; Firewall'], ['rc-ip-events', '&#9889; Attacks'], ['rc-ip-ops', '&#9881; Operations'], ['rc-ip-logins', '&#128273; Logins'], ['rc-ip-web', '&#127760; Access log']]);
  ?>
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
        <?php if (function_exists('smpro_ai_available') && smpro_ai_available()): ?>
        <button class="rc-act" id="rcAiIpBtn" data-url="index.cgi?page=reports-center&rc_ai_ip=1&ip=<?= urlencode($rep['ip']) ?>&from=<?= urlencode($_GET['from'] ?? '') ?>&to=<?= urlencode($_GET['to'] ?? '') ?>" title="Ask AI for a plain-language verdict on this IP" style="background:var(--brand-bg);color:var(--brand)">&#129302; AI verdict</button>
        <?php endif; ?>
      </div>
    </div>
    <div id="rcAiIpOut" style="display:none;margin:0 0 4px"></div>
    <?php if (function_exists('smpro_ai_available') && smpro_ai_available()): ?>
    <script>
    (function(){
      var b=document.getElementById('rcAiIpBtn'); if(!b||b.dataset.wired) return; b.dataset.wired='1';
      function esc(s){return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
      function md(t){var h=esc(t||'');h=h.replace(/^#{1,6}\s*(.*)$/gm,'<h4 class="rc-mdh">$1</h4>');h=h.replace(/\*\*([^*]+)\*\*/g,'<b>$1</b>').replace(/`([^`]+)`/g,'<code>$1</code>');h=h.replace(/^\s*[-*]\s+(.*)$/gm,'<li>$1</li>').replace(/^\s*\d+\.\s+(.*)$/gm,'<li>$1</li>');h=h.replace(/(<li>[\s\S]*?<\/li>)(?=\s*(?:<h4|$))/g,'<ul>$1</ul>');return h.replace(/\n{2,}/g,'<br><br>').replace(/\n/g,'<br>');}
      b.addEventListener('click',function(){
        var out=document.getElementById('rcAiIpOut'); var t=b.innerHTML; b.disabled=true; b.innerHTML='&#129302; Assessing…';
        out.style.display='block'; out.innerHTML='<span class="rc-count">Reading this IP’s evidence and asking the AI…</span>';
        fetch(b.getAttribute('data-url'),{cache:'no-store'}).then(function(r){return r.json();}).then(function(j){
          b.disabled=false; b.innerHTML=t;
          if(j&&j.ok){ out.innerHTML='<div class="rc-aimd" style="border:1px solid var(--line);border-radius:8px;padding:12px 14px;background:var(--card)">'+md(j.text)+'<div class="rc-count" style="margin-top:10px">&#129302; '+esc(j.provider)+' / '+esc(j.model)+'</div></div>'; }
          else { out.innerHTML='<span style="color:var(--dang,#d93b3b)">'+esc((j&&j.error)||'AI request failed')+'</span>'; }
        }).catch(function(){ b.disabled=false; b.innerHTML=t; out.innerHTML='<span style="color:var(--dang,#d93b3b)">Request failed.</span>'; });
      });
    })();
    </script>
    <?php endif; ?>

    <?php $fw = $rep['firewall'] ?? null; if ($fw): $fwState = $fw['blocked'] ? 'dang' : ($fw['in_allow'] ? 'good' : ''); ?>
    <div class="rc-fw" id="rc-ip-fw" style="margin:14px 0 4px;padding:12px 14px;border:1px solid var(--line);border-left:4px solid var(--<?= $fwState ?: 'line' ?>);border-radius:8px;background:var(--<?= $fwState?$fwState.'-bg':'card' ?>)">
      <div style="display:flex;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:6px">
        <h4 style="margin:0;font-size:14px">Firewall — Block &amp; Allow status</h4>
        <?php if ($fw['blocked']): ?><span class="b crit">&#9940; BLOCKED</span>
        <?php elseif ($fw['in_allow']): ?><span class="b" style="background:var(--good-bg);color:var(--good)">&#10003; Allow-listed</span>
        <?php else: ?><span class="b" style="background:var(--good-bg);color:var(--good)">&#9711; Not blocked</span><?php endif; ?>
        <?php foreach ($fw['where'] as $w): ?><span class="k"><?= smpro_h($w) ?></span><?php endforeach; ?>
        <?php if ($fw['in_allow']): ?><span class="k">csf.allow / allowlist</span><?php endif; ?>
        <?php if ($fw['cc_covers'] && $fw['country']): ?><span class="k" title="CC_ALLOW never-block covers this country"><?= smpro_h($fw['country']) ?> never-block</span><?php endif; ?>
      </div>
      <?php if (!empty($fw['verdict'])): ?><p class="meta" style="margin:0 0 6px;line-height:1.5"><?= smpro_h($fw['verdict']) ?></p><?php endif; ?>
      <?php if (!empty($fw['comment'])): ?><p class="meta" style="margin:0 0 4px"><b>csf.deny reason:</b> <?= smpro_h($fw['comment']) ?></p><?php endif; ?>
      <?php if (!empty($fw['fix'])): ?><ul style="margin:6px 0 0;padding-left:18px"><?php foreach ($fw['fix'] as $fx): ?><li class="meta" style="margin:2px 0"><?= smpro_h($fx) ?></li><?php endforeach; ?></ul><?php endif; ?>
      <?php if (!empty($fw['lfd'])): ?><details style="margin-top:8px"><summary class="meta" style="cursor:pointer">LFD trigger history (<?= count($fw['lfd']) ?>)</summary><pre style="white-space:pre-wrap;word-break:break-all;font-size:11px;margin:6px 0 0;max-height:200px;overflow:auto"><?php foreach ($fw['lfd'] as $ll) echo smpro_h($ll)."\n"; ?></pre></details><?php endif; ?>
      <?php if (!empty($fw['csf_g'])): ?><details style="margin-top:6px"><summary class="meta" style="cursor:pointer">Raw firewall lookup (csf -g)</summary><pre style="white-space:pre-wrap;word-break:break-all;font-size:11px;margin:6px 0 0;max-height:240px;overflow:auto"><?= smpro_h($fw['csf_g']) ?></pre></details><?php endif; ?>
    </div>
    <?php endif; ?>

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
    <h4 id="rc-ip-events" style="margin:14px 0 6px" data-i18n>Recent events</h4>
    <div class="rc-scroll"><table class="smpro-table"><thead><tr><th data-i18n>Time</th><th data-i18n>Domain</th><th data-i18n>Type</th><th data-i18n>Severity</th><th>HTTP</th><th data-i18n>Request</th></tr></thead><tbody>
      <?php foreach ($a['recent'] as $e): ?><tr><td class="meta"><?= smpro_h(date('Y-m-d H:i:s',(int)$e['ts'])) ?></td><td><b><?= smpro_h($e['domain']) ?></b></td><td><span class="k"><?= smpro_h($e['kind']) ?></span></td><td><?= smpro_h($e['severity']) ?></td><td><?= smpro_h($e['code']) ?></td><td class="meta" title="<?= smpro_h($e['uri']) ?>"><?= smpro_h(mb_substr((string)$e['uri'],0,60)) ?></td></tr><?php endforeach; ?>
    </tbody></table></div>
    <?php else: ?>
    <p class="meta" data-i18n>No web-attack events recorded for this IP in this window (the index fills as attacks happen). Firewall/geo status above still applies.</p>
    <?php endif; ?>

    <h4 id="rc-ip-ops" style="margin:16px 0 6px" data-i18n>Operations performed on this IP</h4>
    <?php if (!empty($rep['operations'])): ?>
    <div class="rc-scroll" style="max-height:300px"><table class="smpro-table"><thead><tr><th data-i18n>Time</th><th data-i18n>Operation</th><th data-i18n>By</th><th data-i18n>Result</th></tr></thead><tbody>
      <?php foreach ($rep['operations'] as $o): ?><tr><td class="meta"><?= smpro_h(date('Y-m-d H:i:s',(int)$o['ts'])) ?></td><td><b><?= smpro_h($o['label']) ?></b> <span class="meta" style="font-size:11px"><?= smpro_h($o['action']) ?></span></td><td><?= smpro_h($o['actor']) ?><?= $o['admin_ip']?' <span class="meta">from '.smpro_h($o['admin_ip']).'</span>':'' ?></td><td class="meta"><?= smpro_h($o['result']) ?></td></tr><?php endforeach; ?>
    </tbody></table></div>
    <?php else: ?><p class="meta" data-i18n>No operations performed on this IP yet — block / allow / emergency / firewall actions will appear here with time, actor and result.</p><?php endif; ?>

    <h4 id="rc-ip-logins" style="margin:16px 0 6px">Login Attempts <span class="meta" style="font-weight:normal;font-size:12px">(SSH · mail · FTP · cPanel/WHM/webmail auth logs)</span></h4>
    <?php if (!empty($rep['logins'])): $failCnt=0; $okCnt=0; $bySvc=[]; foreach($rep['logins'] as $lg){if($lg['result']==='failed')$failCnt++;else $okCnt++;$bySvc[$lg['source']]=($bySvc[$lg['source']]??0)+1;} arsort($bySvc); ?>
    <p class="meta" style="margin:0 0 6px"><b style="color:var(--warn)"><?= $failCnt ?> failed</b> &nbsp;·&nbsp; <?= $okCnt ?> successful &nbsp;·&nbsp; <?php $sp=[]; foreach($bySvc as $sv=>$c)$sp[]=smpro_h($sv).' '.$c; echo implode(' · ', $sp); ?></p>
    <div class="rc-scroll" style="max-height:320px"><table class="smpro-table"><thead><tr><th>Time</th><th>Source</th><th>Result</th><th>User</th><th>Detail</th></tr></thead><tbody>
      <?php foreach ($rep['logins'] as $lg): $isFail = $lg['result']==='failed'; ?><tr data-row<?= $isFail?' class="warn"':'' ?>><td class="meta" style="white-space:nowrap"><?= $lg['ts']?smpro_h(date('Y-m-d H:i:s',(int)$lg['ts'])):'—' ?></td><td><span class="k"><?= smpro_h($lg['source']) ?></span></td><td><b style="color:var(--<?= $isFail?'warn':'good' ?>)"><?= smpro_h($lg['result']) ?></b></td><td><?= smpro_h($lg['user']) ?></td><td class="meta"><?= smpro_h($lg['detail']) ?></td></tr><?php endforeach; ?>
    </tbody></table></div>
    <?php else: ?><p class="meta">No login attempts from this IP in the SSH, mail, FTP or cPanel auth logs (within the retained log window).</p><?php endif; ?>

    <h4 id="rc-ip-web" style="margin:16px 0 6px">Web Access Log <span class="meta" style="font-weight:normal;font-size:12px">(all requests — latest 300 across all domains)</span></h4>
    <?php if (!empty($rep['requests'])): ?>
    <div class="rc-scroll" style="max-height:420px"><table class="smpro-table nowrap" style="font-size:12px"><thead><tr><th>Time</th><th>Domain</th><th>Method</th><th>Path</th><th>HTTP</th><th>Size</th><th>User-Agent</th></tr></thead><tbody>
      <?php foreach ($rep['requests'] as $rq): $sc=(int)$rq['status']; $cls=$sc>=500?'crit':($sc>=400?'warn':''); ?><tr data-row<?= $cls?' class="'.$cls.'"':'' ?>><td class="meta" style="white-space:nowrap"><?= $rq['ts']?smpro_h(date('Y-m-d H:i:s',(int)$rq['ts'])):'—' ?></td><td><?= smpro_h($rq['domain']) ?></td><td><b><?= smpro_h($rq['method']) ?></b></td><td class="meta" title="<?= smpro_h($rq['path']) ?>"><?= smpro_h(mb_substr((string)$rq['path'],0,90)) ?></td><td><?= smpro_h((string)$rq['status']) ?></td><td class="meta"><?= smpro_h($rq['bytes']) ?></td><td class="meta" title="<?= smpro_h($rq['ua']) ?>"><?= smpro_h(mb_substr((string)$rq['ua'],0,70)) ?></td></tr><?php endforeach; ?>
    </tbody></table></div>
    <?php else: ?><p class="meta">No access log entries found for this IP — domlogs may not exist yet, or the IP has not accessed any hosted domain.</p><?php endif; ?>
  </div>
  <?php elseif ($qip): ?><div class="card" style="padding:16px"><span class="meta">Invalid IP.</span></div><?php endif; ?>

<?php elseif ($tab === 'live'): $lip = filter_var($_GET['ip'] ?? '', FILTER_VALIDATE_IP) ? $_GET['ip'] : ''; ?>
  <form method="get" class="rc-search">
    <input type="hidden" name="page" value="reports-center"><input type="hidden" name="tab" value="live">
    <input type="text" name="ip" class="rc-in" value="<?= smpro_h($lip) ?>" placeholder="Enter an IP to watch live (every request it makes)…" autofocus>
    <button class="tp-btn primary" type="submit" data-i18n>Watch</button>
  </form>
  <?php if ($lip): ?>
  <?php $rcStrip([
    ['id' => 'rc-live', 'l' => 'Watching', 'v' => $lip, 'cls' => 'brand', 's' => 'every request across all hosted domains'],
    ['id' => 'rc-live', 'l' => 'Refresh', 'v' => '10s', 'cls' => 'muted', 's' => 'auto-refresh (toggle below)'],
  ], [['rc-live', '&#128065;&#65039; Live activity']]); ?>
  <div class="card" id="rc-live" style="padding:12px 16px">
  <div class="tp-th"><b data-i18n>Live activity</b> <span class="ipmono"><?= smpro_h($lip) ?></span>
    <label class="lm-chkl" style="margin-left:14px"><input type="checkbox" id="rcLiveAuto" checked> <span data-i18n>Auto-refresh (10s)</span></label>
    <button class="rc-act block" data-ip="<?= smpro_h($lip) ?>">Block</button>
    <button class="rc-act allow" data-ip="<?= smpro_h($lip) ?>">Allow</button>
    <span class="meta" id="rcLiveMeta" style="margin-left:auto">—</span></div>
  <div class="rc-scroll" style="max-height:560px"><table class="smpro-table nowrap" id="rcLiveTbl">
    <thead><tr><th data-i18n>Time</th><th data-i18n>Domain</th><th data-i18n>Method</th><th data-i18n>Path</th><th>HTTP</th><th data-i18n>Size</th><th data-i18n>User-Agent</th></tr></thead>
    <tbody id="rcLiveBody"><tr><td colspan="7" class="rc-empty" data-i18n>Loading live activity…</td></tr></tbody></table></div>
  <p class="meta" style="font-size:11px;margin-top:8px" data-i18n>Reads every hosted domain's access log for this IP (throttled). Shows ALL requests — not just attacks. Non-2xx and known attack paths are highlighted.</p>
  </div>
  <?php else: ?>
  <div class="card" style="padding:16px"><span class="meta" data-i18n>Enter an IP above to watch every request it makes across the server in real time (like a filtered tail -f on the access logs).</span></div>
  <?php endif; ?>

<?php elseif ($tab === 'directory'): $all = smpro_rc_collect(); ?>
  <?php
  $rcSecN = []; foreach ($all as $r) { $rcSecN[(string)$r['sec']] = ($rcSecN[(string)$r['sec']] ?? 0) + 1; } arsort($rcSecN);
  $rcDirOv = [['id' => 'rc-dir', 'l' => 'Saved reports', 'v' => (string)count($all), 'cls' => count($all) ? 'brand' : 'muted', 's' => count($rcSecN) . ' section(s)']];
  $rcI = 0; foreach ($rcSecN as $sec => $n) { if ($rcI++ >= 5) break; $rcDirOv[] = ['id' => 'rc-dir', 'l' => $sec, 'v' => (string)$n, 'cls' => 'muted', 's' => 'report(s) from this section']; }
  $rcStrip($rcDirOv, [['rc-dir', '&#128194; All reports']]);
  ?>
  <div class="card" id="rc-dir" style="padding:0 14px 12px">
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
      <tr data-row data-search="<?= smpro_h(strtolower($r['sec'].' '.$r['name'])) ?>" data-ts="<?= (int)$r['ts'] ?>">
        <td><span class="b"><?= smpro_h($r['sec']) ?></span></td>
        <td><?= smpro_h($r['name']) ?></td>
        <td class="meta"><?= smpro_h($r['extra']) ?></td>
        <td class="meta"><?= smpro_h($r['date']) ?></td>
        <td><a class="lnk" href="index.cgi?page=<?= smpro_h($r['page']) ?>" data-i18n>Open</a></td>
      </tr>
    <?php endforeach; ?>
    </tbody></table></div>
  </div>

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
  $rcSevN = ['critical' => 0, 'warn' => 0, 'info' => 0];
  foreach ($incidents as $rcInc) { $rcS = (string)($rcInc['severity'] ?? 'warn'); $rcSevN[$rcS] = ($rcSevN[$rcS] ?? 0) + 1; }
  $rcStrip([
    ['id' => 'rc-incidents', 'l' => 'Incidents (7d)', 'v' => (string)count($incidents), 'cls' => count($incidents) ? 'warn' : 'good', 's' => 'auto-detected from the logs'],
    ['id' => 'rc-incidents', 'l' => 'Critical', 'v' => (string)$rcSevN['critical'], 'cls' => $rcSevN['critical'] ? 'dang' : 'muted', 's' => 'severity: critical'],
    ['id' => 'rc-incidents', 'l' => 'Warnings', 'v' => (string)$rcSevN['warn'], 'cls' => $rcSevN['warn'] ? 'warn' : 'muted', 's' => 'severity: warn'],
    ['id' => 'rc-incidents', 'l' => 'Info', 'v' => (string)$rcSevN['info'], 'cls' => 'muted', 's' => 'severity: info'],
    ['id' => 'rc-outage', 'l' => 'Outage report', 'v' => $report ? strtoupper((string)$report['confidence']) : 'not run', 'cls' => $report ? 'brand' : 'muted', 's' => $report ? (date('Y-m-d H:i', (int)$report['from']) . ' → ' . date('H:i', (int)$report['to'])) : 'pick a window below'],
    ['id' => 'rc-blocked', 'l' => 'Block reason', 'v' => $br ? ($br['valid'] ? ($br['blocked'] ? 'BLOCKED' : ($br['in_allow'] ? 'allow-listed' : 'not blocked')) : 'invalid IP') : '—', 'cls' => $br ? ($br['valid'] ? ($br['blocked'] ? 'dang' : 'good') : 'warn') : 'muted', 's' => $bip !== '' ? $bip : 'enter an IP below'],
  ], [['rc-about', '&#128161; About'], ['rc-blocked', '&#128272; Why blocked?'], ['rc-outage', '&#128340; Outage report'], ['rc-cause', '&#129513; Probable cause'], ['rc-ai', '&#129302; AI analysis'], ['rc-incidents', '&#128276; Incidents']]);
?>
<div class="card" id="rc-about" style="padding:14px;margin-bottom:12px;border-left:4px solid #3b5bdb">
  <b data-i18n>&#128161; What this section is for</b>
  <details class="gl-fold" style="margin:4px 0 0"><summary><span class="gl-chev">&#9656;</span>How this works</summary>
  <p class="sub" style="margin:4px 0 0;line-height:1.6" data-i18n>When customers <b>couldn't log in</b> or the <b>server was down/unreachable</b>, you usually have no idea why after it recovers. This section reconstructs what happened <b>from the server's own logs</b> for the exact time window — reboot/crash, out-of-memory, network flood, a <b>firewall block of legitimate home-region IPs</b>, or a provider null-route — so you get a <b>root cause</b>, evidence, and how to prevent it. Use <b>"Why is an IP blocked?"</b> for a specific customer IP, the <b>Outage report</b> for a downtime window, and <b>Analyze with AI</b> for a written explanation of the causes.</p>
  </details>
</div>
<details class="rc-acc" id="rc-blocked" open style="margin-bottom:12px">
  <summary>
    <span>&#128272; <span data-i18n>Why is an IP blocked?</span></span>
    <span class="rc-count" data-i18n>find the exact firewall block reason</span>
    <span class="rc-arw">&#9656;</span>
  </summary>
  <div class="rc-body">
    <p class="rc-count" style="margin:0 0 8px" data-i18n>Enter an IP (e.g. a customer's IP that can't connect). It reads CSF (csf -g), the csf.deny reason, the LFD trigger history, GeoIP and CC_ALLOW — and tells you exactly why it's blocked and how to fix it.</p>
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
        <?php if (!empty($br['imunify']['present'])): $im = $br['imunify']; ?>
          <div style="margin-top:10px;padding:10px 12px;border-radius:9px;border:1px solid var(--line)">
            <b>Imunify360</b>
            <span class="meta" style="margin-left:6px"><?= $im['graylisted'] ? '<span class="b orange">gray list &mdash; challenged</span>' : ($im['blacklisted'] ? '<span class="b red">black list</span>' : ($im['whitelisted'] ? '<span class="b green">white list</span>' : '<span class="b gray">on no list</span>')) ?>
              <?php if (is_array($im['webshield'])): ?> &middot; WebShield <?= $im['webshield']['enable'] ? 'on' : 'off' ?><?= !empty($im['webshield']['panel']) ? ', panel protection on' : '' ?><?= !empty($im['webshield']['splash']) ? ', splash screen on' : '' ?><?php endif; ?></span>
            <?php foreach ($im['lists'] as $l): ?><div class="mono" style="font-size:11.5px;margin-top:4px"><?= smpro_h($l['list']) ?> <?= smpro_h($l['ip']) ?><?= $l['expires'] ? ' until ' . date('Y-m-d H:i', $l['expires']) : '' ?><?= $l['comment'] !== '' ? ' &mdash; ' . smpro_h($l['comment']) : '' ?></div><?php endforeach; ?>
            <?php if ($im['incidents']): ?><div style="margin-top:6px"><b style="font-size:12px">Incidents Imunify recorded for this address</b>
              <?php foreach ($im['incidents'] as $i): ?><div class="mono" style="font-size:11.5px"><?= $i['when'] ? date('Y-m-d H:i', $i['when']) : '' ?> <?= smpro_h($i['severity']) ?> <?= smpro_h($i['name'] ?: $i['rule']) ?> <span class="meta"><?= smpro_h($i['what']) ?></span></div><?php endforeach; ?></div><?php endif; ?>
            <?php if ($im['console']): ?><div style="margin-top:6px"><b style="font-size:12px">Imunify's own decisions about it (console log)</b>
              <?php foreach ($im['console'] as $ln): ?><div class="mono" style="font-size:11px"><?= smpro_h($ln) ?></div><?php endforeach; ?></div><?php endif; ?>
          </div>
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
<div class="card" id="rc-outage" style="padding:14px;margin-bottom:12px">
  <b data-i18n>Outage report — analyze the logs for a time window</b>
  <details class="gl-fold" style="margin:2px 0 10px"><summary><span class="gl-chev">&#9656;</span>How this works</summary>
  <p class="sub" style="margin:2px 0 0" data-i18n>Pick the start and end (date + time) of the period the server was down/unreachable — any window up to 31 days, can span multiple days. We read the system, kernel and firewall logs for that window and infer the probable cause.</p>
  </details>
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
<details class="rc-acc" id="rc-cause" open>
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
<details class="rc-acc" id="rc-ai" open>
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
      } else { out.innerHTML='<span style="color:var(--dang,#d93b3b)">'+rcEsc((j&&j.error)||'AI request failed')+'</span>'; }
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

<?php endif; /* $report */ ?>

<details class="rc-acc" id="rc-incidents"<?= $report ? '' : ' open' ?>>
  <summary>
    <span>&#128276; <span data-i18n>Recent auto-detected incidents</span></span>
    <span class="rc-count"><?= count($incidents) ?> in 7d</span>
    <span class="rc-arw">&#9656;</span>
  </summary>
  <div class="rc-body" style="padding:10px 14px 14px">
    <?php if (!$incidents): ?>
      <div style="padding:16px;color:var(--muted)" data-i18n>No incidents auto-detected in the last 7 days.</div>
    <?php else: ?>
      <div class="rc-inctools">
        <button type="button" class="rc-incall" data-open="1">&#9662; Expand all</button>
        <button type="button" class="rc-incall" data-open="0">&#9656; Collapse all</button>
        <span class="rc-count" style="margin-left:auto"><?= count($incidents) ?> in 7d</span>
      </div>
      <div id="rcIncList">
      <?php
        usort($incidents, fn($a, $b) => ($b['ts'] ?? 0) <=> ($a['ts'] ?? 0));
        $sevBorder = ['critical' => 'var(--dang)', 'warn' => 'var(--warn)', 'info' => 'var(--brand)'];
        foreach ($incidents as $i):
          $sev = $i['severity'] ?? 'warn'; $cls = $sevCls[$sev] ?? ''; $grp = !empty($i['count']);
          $bcol = $sevBorder[$sev] ?? 'var(--line)';
          $timeTxt = $grp
            ? date('m-d H:i', (int)($i['first_ts'] ?? $i['ts'])) . ' → ' . date('m-d H:i', (int)($i['last_ts'] ?? $i['ts']))
            : (!empty($i['ts']) ? date('Y-m-d H:i', (int)$i['ts']) : '—');
      ?>
        <details class="rc-inc" style="border-left-color:<?= $bcol ?>">
          <summary class="rc-incsum">
            <span class="rc-chev">&#9656;</span>
            <span class="b <?= $cls ?>"><?= smpro_h($sev) ?></span>
            <span class="rc-inctitle"><?= smpro_h($i['title'] ?? '') ?><?php if ($grp): ?> <span class="rc-xn">&times;<?= (int)$i['count'] ?></span><?php endif; ?></span>
            <span class="rc-inctype"><?= smpro_h($i['type'] ?? '') ?></span>
            <span class="rc-inctime"><?= smpro_h($timeTxt) ?></span>
          </summary>
          <div class="rc-incbody">
            <?php if (!empty($i['detail'])): ?><div class="rc-incdetail"><?= smpro_h(mb_substr((string)$i['detail'], 0, 600)) ?></div><?php endif; ?>
            <?php if (!empty($i['offenders'])): ?>
              <div class="rc-offwrap"><table class="rc-grptbl"><thead><tr><th>Process</th><th>Owner</th><th class="num">Throttled</th><th>PID</th></tr></thead><tbody>
                <?php foreach ($i['offenders'] as $o): ?>
                  <tr data-row><td><b><?= smpro_h($o['process']) ?></b><?= $o['alive'] ? '' : ' <span class="meta">(ended)</span>' ?></td>
                    <td><?= $o['owner'] !== '' ? smpro_h($o['owner']) : '<span class="meta">—</span>' ?><?= !empty($o['is_cpanel']) ? ' <span class="b">cPanel</span>' : '' ?></td>
                    <td class="num">&times;<?= (int)$o['count'] ?></td>
                    <td class="mono meta"><?= (int)$o['pid'] ?></td></tr>
                <?php endforeach; ?>
              </tbody></table></div>
            <?php endif; ?>
            <?php if ($grp && !empty($i['children'])): ?>
              <div class="rc-incsub">Individual events</div>
              <div class="rc-grpwrap"><table class="rc-grptbl"><tbody>
                <?php foreach ($i['children'] as $c): ?>
                  <tr><td class="meta" style="white-space:nowrap"><?= smpro_h(date('Y-m-d H:i', (int)$c['ts'])) ?></td><td><?= smpro_h($c['detail']) ?></td></tr>
                <?php endforeach; ?>
                <?php if ((int)$i['count'] > count($i['children'])): ?><tr><td></td><td class="meta">…and <?= (int)$i['count'] - count($i['children']) ?> more (older ones trimmed)</td></tr><?php endif; ?>
              </tbody></table></div>
            <?php endif; ?>
            <div class="rc-incmeta">Source: <?= smpro_h($i['source'] ?? '') ?><?= !empty($i['actor']) ? ' &middot; ' . smpro_h($i['actor']) : '' ?></div>
          </div>
        </details>
      <?php endforeach; ?>
      </div>
      <script>(function(){var l=document.getElementById('rcIncList');if(!l)return;
        document.querySelectorAll('.rc-incall').forEach(function(b){b.addEventListener('click',function(){
          var o=b.getAttribute('data-open')==='1';l.querySelectorAll('details.rc-inc').forEach(function(d){d.open=o;});});});})();</script>
    <?php endif; ?>
  </div>
</details>

<?php elseif ($tab === 'moves'):
  /* Account moves - history of home-directory relocations between partitions (written by bin/home_move.php). */
  $mvRows = function_exists('smpro_ds_home_history') ? smpro_ds_home_history(100) : [];
  $mvH = function ($b) { $b = (float)$b; $u = ['B','KB','MB','GB','TB']; $i = 0; while ($b >= 1024 && $i < 4) { $b /= 1024; $i++; } return round($b, $i > 1 ? 1 : 0) . ' ' . $u[$i]; };
  $mvDur = function ($s) { $s = (int)$s; if ($s <= 0) return '—'; if ($s < 60) return $s . 's'; if ($s < 3600) return floor($s/60) . 'm ' . ($s%60) . 's'; return floor($s/3600) . 'h ' . floor(($s%3600)/60) . 'm'; };
  $mvN = ['move' => 0, 'finalize' => 0, 'rollback' => 0, 'problem' => 0];
  foreach ($mvRows as $m) { $mvE = (string)($m['event'] ?? ''); if (isset($mvN[$mvE])) $mvN[$mvE]++; if (empty($m['ok'])) $mvN['problem']++; }
  $rcStrip([
    ['id' => 'rc-moves', 'l' => 'Move records', 'v' => (string)count($mvRows), 'cls' => count($mvRows) ? 'brand' : 'muted', 's' => 'home directories relocated between partitions'],
    ['id' => 'rc-moves', 'l' => 'Moved', 'v' => (string)$mvN['move'], 'cls' => $mvN['move'] ? 'brand' : 'muted', 's' => 'switched to a new partition'],
    ['id' => 'rc-moves', 'l' => 'Old copy deleted', 'v' => (string)$mvN['finalize'], 'cls' => $mvN['finalize'] ? 'good' : 'muted', 's' => 'finalized moves'],
    ['id' => 'rc-moves', 'l' => 'Rolled back', 'v' => (string)$mvN['rollback'], 'cls' => $mvN['rollback'] ? 'warn' : 'muted', 's' => 'returned to where they came from'],
    ['id' => 'rc-moves', 'l' => 'Problems', 'v' => (string)$mvN['problem'], 'cls' => $mvN['problem'] ? 'dang' : 'good', 's' => 'records that did not end ok'],
  ], [['rc-moves', '&#128230; Account moves']]);
?>
<div class="card" id="rc-moves" style="padding:0;overflow:hidden">
  <div class="rc-head"><b>&#128230; Account moves</b>
    <span class="rc-count"><?= count($mvRows) ?> record(s) &middot; home directories relocated between partitions</span></div>
  <?php if (!$mvRows): ?>
    <div style="padding:16px;color:var(--muted);font-size:13px">No account has been moved between partitions yet. You can move one from <a class="lnk" href="index.cgi?page=disk-storage">Disk / Storage</a> when a partition fills up.</div>
  <?php else: ?>
  <div class="rc-scroll" style="max-height:600px"><table class="smpro-table nowrap">
    <thead><tr><th>When</th><th>Event</th><th>Account</th><th>From</th><th>To</th><th class="num">Size</th><th class="num">Took</th><th>Result</th></tr></thead>
    <tbody>
    <?php foreach ($mvRows as $m):
        $ev = (string)($m['event'] ?? ''); $ok = !empty($m['ok']);
        $lbl = ['move' => 'Moved', 'finalize' => 'Old copy deleted', 'rollback' => 'Rolled back'][$ev] ?? $ev;
        $cls = $ev === 'move' ? 'blue' : ($ev === 'finalize' ? 'green' : 'orange'); ?>
      <tr data-row>
        <td class="mono"><?= smpro_h(date('Y-m-d H:i', (int)($m['ts'] ?? 0))) ?></td>
        <td><span class="b <?= $cls ?>"><?= smpro_h($lbl) ?></span></td>
        <td class="mono"><b><?= smpro_h((string)($m['user'] ?? '')) ?></b></td>
        <td class="mono meta"><?= smpro_h((string)($m['src'] ?? '')) ?></td>
        <td class="mono meta"><?= smpro_h((string)($m['dst'] ?? '')) ?></td>
        <td class="num mono"><?= !empty($m['bytes']) ? smpro_h($mvH((int)$m['bytes'])) : '—' ?></td>
        <td class="num mono"><?= $ev === 'move' ? smpro_h($mvDur((int)($m['duration'] ?? 0))) : '—' ?></td>
        <td>
          <?php if ($ok): ?><span class="b green">ok</span><?php else: ?><span class="b red">problem</span><?php endif; ?>
          <?php if ($ev === 'move' && !empty($m['http_after'])): ?><span class="meta" style="margin-left:6px">site HTTP <?= smpro_h((string)$m['http_after']) ?></span><?php endif; ?>
          <?php if (!empty($m['resumed'])): ?><span class="b orange" style="margin-left:6px">resumed &times;<?= (int)$m['resumed'] ?></span><?php endif; ?>
        </td>
      </tr>
    <?php endforeach; ?>
    </tbody></table></div>
  <div style="padding:9px 16px;border-top:1px solid var(--line);color:var(--muted);font-size:11.5px">A <b>Moved</b> entry means the account was switched to the new partition while its site stayed up; the old copy is kept until <b>Old copy deleted</b>. <b>Rolled back</b> means it was returned to where it came from.</div>
  <?php endif; ?>
</div>
<?php endif; ?>

<style>
.rc-xn{display:inline-block;font-size:11px;font-weight:700;color:var(--muted);background:var(--bg);border:1px solid var(--line);border-radius:20px;padding:1px 8px;vertical-align:middle}
.rc-inctools{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:0 0 10px}
.rc-incall{font-size:12px;font-weight:600;color:var(--brand);background:var(--card);border:1px solid var(--line);border-radius:8px;padding:5px 11px;cursor:pointer}
.rc-incall:hover{background:var(--brand-bg)}
.rc-inc{border:1px solid var(--line);border-left-width:3px;border-radius:10px;margin:8px 0;background:var(--card);overflow:hidden}
.rc-incsum{list-style:none;cursor:pointer;display:flex;align-items:center;gap:10px;padding:10px 14px;flex-wrap:wrap}
.rc-incsum::-webkit-details-marker{display:none}
.rc-incsum:hover{background:var(--bg)}
.rc-chev{color:var(--muted);font-size:11px;transition:transform .15s ease;flex:none}
.rc-inc[open] .rc-chev{transform:rotate(90deg)}
.rc-inctitle{font-weight:700;font-size:13px;min-width:0}
.rc-inctype{font-size:11px;color:var(--muted);text-transform:capitalize}
.rc-inctime{margin-left:auto;font-size:11.5px;color:var(--muted);white-space:nowrap;font-variant-numeric:tabular-nums}
.rc-incbody{padding:2px 14px 12px 34px;border-top:1px solid var(--line)}
.rc-incdetail{font-size:12.5px;line-height:1.6;margin:10px 0}
.rc-incsub{font-size:10.5px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);font-weight:800;margin:10px 0 4px}
.rc-incmeta{font-size:11.5px;color:var(--muted);margin-top:8px}
@media (prefers-reduced-motion:reduce){.rc-chev{transition:none}}
.rc-grpwrap{max-height:280px;overflow:auto;margin-top:7px;border:1px solid var(--line);border-radius:9px}
.rc-grptbl{width:100%;border-collapse:collapse;font-size:12px}
.rc-grptbl td{padding:5px 10px;border-bottom:1px solid var(--line)}
.rc-grptbl tr:last-child td{border-bottom:none}
.rc-offwrap{margin-top:8px;border:1px solid var(--line);border-radius:9px;overflow:hidden}
.rc-offwrap .rc-grptbl th{background:var(--bg);font-size:10.5px;text-transform:uppercase;letter-spacing:.03em;color:var(--muted);font-weight:800;padding:6px 10px;text-align:left}
.rc-offwrap .rc-grptbl th.num,.rc-offwrap .rc-grptbl td.num{text-align:right}
.la-tabs{display:flex;gap:4px;border-bottom:2px solid var(--line);margin:16px 0 14px}
.la-tab{padding:9px 16px;font-size:14px;font-weight:600;color:var(--muted);text-decoration:none;border-bottom:3px solid transparent;margin-bottom:-2px}.la-tab.active{color:var(--brand);border-bottom-color:var(--brand)}
.rc-search{display:flex;gap:8px;margin:6px 0 14px;flex-wrap:wrap;align-items:center}.rc-in{border:1px solid var(--line);border-radius:9px;padding:9px 12px;font-size:14px;flex:1;max-width:420px}
.rc-toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;padding:6px 2px 12px}.rc-toolbar .rc-in{flex:none}
.rc-dt{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--muted);font-weight:600}.rc-dt .rc-in{flex:none;max-width:160px;padding:7px 9px;font-size:13px}
.tp-btn{border:1px solid var(--line);background:var(--card);color:var(--ink);border-radius:9px;padding:9px 14px;font-size:13px;cursor:pointer;font-weight:600}
.rc-card{padding:18px 20px}.rc-head{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;flex-wrap:wrap;margin-bottom:12px}
.rc-ipv{font-family:ui-monospace,Consolas,monospace;font-size:20px;font-weight:800}
.rc-actions{display:flex;gap:6px;align-items:center;flex-wrap:wrap}
.rc-act{font-size:12px;font-weight:600;border:1px solid var(--line);background:var(--card);border-radius:7px;padding:5px 11px;cursor:pointer}
.rc-act.block{color:var(--dang);border-color:#f3c4c4}.rc-act.block:hover{background:var(--dang);color:#fff}
.rc-act.allow{color:var(--good);border-color:#bfe6cd}.rc-act.allow:hover{background:var(--good);color:#fff}
.rc-kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:8px 0 14px}@media(max-width:760px){.rc-kpis{grid-template-columns:repeat(2,1fr)}}
.rc-kpis>div{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:10px 14px;display:flex;flex-direction:column;gap:2px}
.rc-kpis .l{font-size:11px;color:var(--muted);text-transform:uppercase;font-weight:700}.rc-kpis b{font-size:20px}
.rc-two{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}@media(max-width:760px){.rc-two{grid-template-columns:1fr}}
.rc-two h4{margin:0 0 6px;font-size:13px}.rc-li{display:flex;justify-content:space-between;font-size:12.5px;padding:3px 0;border-bottom:1px solid var(--line)}.rc-li b{font-weight:700}
.rc-scroll{max-height:380px;overflow:auto;border:1px solid var(--line);border-radius:10px}
.smpro-table{width:100%;border-collapse:collapse;font-size:12.5px}.smpro-table th,.smpro-table td{padding:7px 11px;text-align:left;border-bottom:1px solid var(--line)}
.smpro-table th{font-size:11px;text-transform:uppercase;color:var(--muted);position:sticky;top:0;background:var(--card)}
.rc-empty{padding:18px;text-align:center;color:var(--muted)}.svc-kicker{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--brand);font-weight:700}.meta{color:var(--muted)}
.k{display:inline-block;font-size:11px;background:var(--brand-bg);color:var(--brand);border-radius:10px;padding:1px 8px}
.b{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:20px;background:var(--card);color:#475569}.b.crit{background:var(--dang-bg);color:#b91c1c}.b.high{background:var(--warn-bg);color:#c2410c}.b.med{background:var(--warn-bg);color:#a16207}.b.ok{background:var(--good-bg);color:var(--good)}.b.ai{background:var(--brand-bg);color:var(--brand)}.b.arc{background:var(--warn-bg);color:#92702a}.b.sv{background:var(--good-bg);color:var(--good)}
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
/* Live IP Watch - poll the IP's requests across all domains every 10s */
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
<style>
/* ---- overview strip + sticky navigator + collapsible cards + folds + pager (pattern: firewall-status.php) ---- */
.fw-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:12px 0}
@media(max-width:640px){.fw-kpis{grid-template-columns:repeat(2,1fr)}}
.fw-nav{position:sticky;top:calc(var(--toph,52px) + 6px);z-index:5;display:flex;gap:6px;flex-wrap:wrap;align-items:center;padding:8px 10px;margin:0 0 14px;background:var(--card);border:1px solid var(--line);border-radius:12px;box-shadow:0 2px 10px rgba(0,0,0,.05)}
.fw-nav a{font-size:12px;font-weight:700;text-decoration:none;color:var(--ink);padding:4px 10px;border-radius:20px;border:1px solid var(--line);white-space:nowrap}
.fw-toggle{cursor:pointer;user-select:none}.fw-toggle:hover{background:var(--bg)}
.gl-fold{margin:6px 0}.gl-fold>summary{cursor:pointer;list-style:none;font-size:12.5px;font-weight:700;color:var(--brand);display:flex;align-items:center;gap:6px}
.gl-fold>summary::-webkit-details-marker{display:none}
.gl-fold>summary .gl-chev{display:inline-block;transition:transform .15s;font-weight:800}.gl-fold[open]>summary .gl-chev{transform:rotate(90deg)}
.fw-pg{display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:8px 16px;border-bottom:1px solid var(--line);font-size:12px;color:var(--muted)}
.fw-pg input{border:1px solid var(--line);border-radius:8px;padding:5px 9px;font-size:12.5px;min-width:180px;background:var(--card);color:inherit}
.fw-pg .sp{flex:1}.fw-pg button{font-size:11.5px;font-weight:700;border:1px solid var(--line);border-radius:7px;padding:3px 9px;cursor:pointer;background:var(--card);color:var(--ink)}
.fw-pg button:disabled{opacity:.45;cursor:default}.fw-pg .n{font-variant-numeric:tabular-nums}
tr.fw-pghide{display:none !important}
</style>
<script>
(function(){
  // make every section card collapsible - click its header to open/close; the choice is remembered per section
  var KEY='smpro:reports-center:open', SEL='.card > .rc-head, .card > .tp-th', EXTRA='details.rc-acc';
  var open={};
  try{ open=JSON.parse(localStorage.getItem(KEY)||'{}')||{}; }catch(err){ open={}; }
  function remember(){ try{ localStorage.setItem(KEY, JSON.stringify(open)); }catch(err){} }
  function toggleOf(card){ for(var i=0;i<card.children.length;i++){ var c=card.children[i]; if(c.classList&&c.classList.contains('fw-toggle')) return c; } return null; }
  function openCard(id, scroll){
    var el=document.getElementById(id); if(!el) return;
    var node=el;
    while(node && node!==document.body){
      if(node.classList && node.classList.contains('card')){ var th=toggleOf(node); if(th && !node.classList.contains('fw-open')){ node.classList.add('fw-open'); th.setAttribute('aria-expanded','true'); open[th.getAttribute('data-fold')]=true; remember(); } }
      if(node.tagName==='DETAILS' && !node.open) node.open=true;
      node=node.parentElement;
    }
    if(el.tagName!=='DETAILS' && el.classList.contains('card') && !toggleOf(el)){ var d=el.querySelector('details'); if(d && !d.open) d.open=true; }
    if(scroll){ el.style.scrollMarginTop='120px'; try{ el.scrollIntoView({behavior:'smooth',block:'start'}); }catch(e2){ el.scrollIntoView(); } }   // the page scrolls inside .smpro-main
  }
  var gos=document.querySelectorAll('[data-go]');
  for(var g=0;g<gos.length;g++){ (function(a){
    var tid=a.getAttribute('data-go');
    if(!document.getElementById(tid)){ if(a.parentElement && a.parentElement.classList.contains('fw-nav')) a.style.display='none'; return; }   // chip for a section this page does not have
    a.addEventListener('click',function(e){ e.preventDefault(); openCard(tid,true); var xs=document.querySelectorAll('.fw-nav a'); for(var i=0;i<xs.length;i++){ xs[i].classList.toggle('on', xs[i].getAttribute('data-go')===tid); } try{ history.replaceState(null,'','#'+tid); }catch(err){} });
  })(gos[g]); }
  function setAll(on){
    var cards=document.querySelectorAll('.smpro-main .card');
    for(var i=0;i<cards.length;i++){ var th=toggleOf(cards[i]); if(!th) continue; cards[i].classList.toggle('fw-open',on); th.setAttribute('aria-expanded',on?'true':'false'); open[th.getAttribute('data-fold')]=on; }
    if(EXTRA){ var ds=document.querySelectorAll(EXTRA); for(var k=0;k<ds.length;k++){ ds[k].open=on; } }
    remember();
  }
  var oa=document.getElementById('rcOpenAll'), ca=document.getElementById('rcCloseAll');
  if(oa) oa.addEventListener('click',function(){ setAll(true); });
  if(ca) ca.addEventListener('click',function(){ setAll(false); });
  var ths=document.querySelectorAll(SEL);
  for(var t=0;t<ths.length;t++){ (function(th, n){
    var card=th.parentElement; if(!card||!card.classList.contains('card')) return;
    var body=document.createElement('div'); body.className='fw-collapse';
    while(th.nextSibling){ body.appendChild(th.nextSibling); }
    card.appendChild(body);
    th.classList.add('fw-toggle');
    if(!th.querySelector('.fw-chev')) th.insertAdjacentHTML('afterbegin','<span class="fw-chev">&#9656;</span> ');
    // A stable name for this section: its own heading text (position would move every remembered state when a section is added above it).
    var id=(th.textContent||'').replace(/\s+/g,' ').trim().slice(0,60) || ('card'+n);
    th.setAttribute('data-fold', id);
    var closedByDefault=card.hasAttribute('data-fold-closed');
    var isOpen=Object.prototype.hasOwnProperty.call(open,id) ? !!open[id] : !closedByDefault;
    card.classList.toggle('fw-open', isOpen);
    th.setAttribute('role','button'); th.setAttribute('tabindex','0'); th.style.cursor='pointer'; th.setAttribute('aria-expanded', isOpen?'true':'false');
    function toggle(){ var now=card.classList.toggle('fw-open'); th.setAttribute('aria-expanded', now?'true':'false'); open[id]=now; remember(); }
    th.addEventListener('click',function(e){ if(e.target.closest('a,button,input,select,label,textarea,summary')) return; toggle(); });   // header controls keep working
    th.addEventListener('keydown',function(e){ if(e.key===' '||e.key==='Enter'||e.key==='Spacebar'){ e.preventDefault(); toggle(); } });
  })(ths[t], t); }
  if(location.hash && document.getElementById(location.hash.slice(1))) setTimeout(function(){ openCard(location.hash.slice(1), true); }, 150);
  window.smproOpenCard=openCard;

  // client-side filter + paging (50/page) for a PHP-rendered table: rows carry data-row, hidden rows get .fw-pghide
  function smproPager(tbl, opt){
    opt=opt||{}; var per=opt.per||50; if(!tbl||!tbl.tBodies||!tbl.tBodies[0]) return null;
    var tb=tbl.tBodies[0], rows=[], i;
    for(i=0;i<tb.rows.length;i++){ if(tb.rows[i].hasAttribute('data-row')) rows.push(tb.rows[i]); }
    if(rows.length<(opt.min||12)) return null;
    var wrap=tbl.parentElement, bar=document.createElement('div'); bar.className='fw-pg';
    bar.innerHTML=(opt.nofilter?'':'<input type="search" placeholder="'+(opt.ph||'Filter rows\u2026')+'">')+'<span class="sp"></span><span class="n fw-pginfo"></span><button type="button" class="fw-pgprev">&#8249; prev</button><span class="n fw-pgpos"></span><button type="button" class="fw-pgnext">next &#8250;</button>';
    wrap.parentElement.insertBefore(bar, wrap);
    var inp=bar.querySelector('input'), info=bar.querySelector('.fw-pginfo'), pos=bar.querySelector('.fw-pgpos'), prev=bar.querySelector('.fw-pgprev'), next=bar.querySelector('.fw-pgnext');
    var q='', page=0;
    function textOf(tr){ return (tr.getAttribute('data-search')||tr.textContent||'').replace(/\s+/g,' ').toLowerCase(); }
    function hide(tr,h){ tr.classList.toggle('fw-pghide',h); if(opt.follow){ var nx=tr.nextElementSibling; if(nx&&nx.classList.contains(opt.follow)) nx.classList.toggle('fw-pghide',h); } }
    function draw(){
      var view=[]; for(var k=0;k<rows.length;k++){ var tr=rows[k]; var ok=(!q||textOf(tr).indexOf(q)!==-1) && !(opt.skip&&opt.skip(tr)); if(ok) view.push(tr); else hide(tr,true); }
      var pages=Math.max(1,Math.ceil(view.length/per)); if(page>=pages) page=pages-1; if(page<0) page=0;
      for(var j=0;j<view.length;j++){ hide(view[j], j<page*per || j>=(page+1)*per); }
      var a=view.length?page*per+1:0, b=Math.min((page+1)*per,view.length);
      info.textContent=(view.length>per?('showing '+a+'\u2013'+b+' of '):'')+view.length+' of '+rows.length+' rows';
      pos.textContent=(page+1)+' / '+pages; prev.disabled=page<=0; next.disabled=page>=pages-1;
      var ctrl=rows.length>per?'':'none'; prev.style.display=ctrl; next.style.display=ctrl; pos.style.display=ctrl;
    }
    if(inp) inp.addEventListener('input',function(){ q=inp.value.trim().toLowerCase(); page=0; draw(); });
    prev.addEventListener('click',function(){ if(page>0){ page--; draw(); } });
    next.addEventListener('click',function(){ page++; draw(); });
    draw(); return {draw:draw};
  }
  window.smproPager=smproPager;

  // All Reports: the page's own filter/date-range JS (rcApply) hides non-matching rows with style.display; the pager
  // layers 50/page on top of whatever rcApply left visible and re-draws after it runs (its listeners were added first).
  var dir=document.getElementById('rcDir');
  if(dir){ var dp=smproPager(dir, {nofilter:true, skip:function(tr){ return tr.style.display==='none'; }});
    if(dp){ var ins=['rcFilter','rcFrom','rcTo']; for(var i=0;i<ins.length;i++){ var el=document.getElementById(ins[i]); if(el) el.addEventListener('input',function(){ dp.draw(); }); } } }
  var offs=document.querySelectorAll('.rc-offwrap table'); for(var o=0;o<offs.length;o++){ smproPager(offs[o], {ph:'Filter processes\u2026'}); }
  var mv=document.getElementById('rc-moves'); if(mv) smproPager(mv.querySelector('table.smpro-table'), {ph:'Filter by account, partition, event\u2026'});
  // IP report: the login-attempts and access-log tables sit right after their <h4>; find each without crossing the next heading
  function tableAfter(h){ var n=h?h.nextElementSibling:null; while(n && n.tagName!=='H4'){ if(n.classList.contains('rc-scroll')) return n.querySelector('table'); n=n.nextElementSibling; } return null; }
  var lt=tableAfter(document.getElementById('rc-ip-logins')); if(lt) smproPager(lt, {ph:'Filter logins (service, user, result)\u2026'});
  var wt=tableAfter(document.getElementById('rc-ip-web')); if(wt) smproPager(wt, {ph:'Filter requests (domain, path, agent)\u2026'});
})();
</script>

<?php
smpro_layout_footer();
