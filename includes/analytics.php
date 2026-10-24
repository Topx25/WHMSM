<?php
/**
 * includes/analytics.php - the Analytics page's log counts, as pure functions so bin/notify_check.php can keep them
 * warm: every count is a memoised shell command keyed by its text, which carries the day pattern, so the first open
 * after midnight used to pay 4 s. The worker now pays it every 15 minutes instead.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

function smpro_ar_du($path) {   // 0.4 s per render for the plugin's own data dir: remembered ten minutes
    $f = function () use ($path) { $o = (string)@shell_exec('timeout 10 du -sb ' . escapeshellarg($path) . ' 2>/dev/null'); return (int)trim(explode("\t", $o)[0] ?? 0); };
    return function_exists('smpro_memo') ? (int)smpro_memo('ar_du_' . sha1($path), 600, $f) : $f();
}
function smpro_ar_sh($cmd) { return (string)@shell_exec('timeout 14 sh -c ' . escapeshellarg($cmd) . ' 2>/dev/null'); }
/**
 * Self-contained counts from the server's own logs, FILTERED to the selected date window
 * [$fromTs,$toTs]. exim uses ISO-date column matching; lfd/secure use a syslog "Mon D" day
 * pattern; modsec uses "[D/Mon/YYYY". Imunify/backup are current-state (labelled as such).
 * Degrades to 0 / 'n/a' when a source isn't present.
 */
function smpro_ar_reports($fromTs, $toTs) {
    // Cache the heavy log scans (exim/modsec/secure greps) - recompute at most every 5 min per window,
    // so repeat opens are instant instead of re-grepping multi-GB logs on every page load.
    $ck = (defined('SMPRO_CACHE') ? SMPRO_CACHE : sys_get_temp_dir()) . '/ar_reports_' . (int)$fromTs . '_' . (int)$toTs . '.json';
    if (is_readable($ck) && (time() - (int)@filemtime($ck)) < 300) { $c = json_decode((string)@file_get_contents($ck), true); if (is_array($c) && $c) return $c; }
    // build date filters for the window
    $dayList = [];
    for ($t = strtotime(date('Y-m-d', $fromTs)); $t <= $toTs && count($dayList) < 95; $t += 86400) $dayList[] = $t;
    if (!$dayList) $dayList = [$fromTs];
    $fromD = date('Y-m-d', $fromTs); $toD = date('Y-m-d', $toTs);
    $sysPat = implode('|', array_map(fn($t) => '^' . date('M', $t) . ' +' . (int)date('j', $t) . ' ', $dayList)); // "^Jun +19 "
    $msPat  = implode('|', array_map(fn($t) => '\\[' . (int)date('j', $t) . '/' . date('M', $t) . '/' . date('Y', $t), $dayList)); // "[19/Jun/2026"
    $win = ' · in range';   // literal middot - this string is later run through smpro_h(), which would double-escape an HTML entity

    $R = [];
    // Window span in days (+1 day margin for rotation timing). The report window goes up to 90 days, but a
    // weekly-rotating box keeps only ~5 days in the LIVE log - so reading the live file alone UNDER-counts every
    // security metric on the 14/30/90-day views, i.e. the dashboard reads safer than the server actually is.
    $winDays = max(1, (int)ceil(($toTs - $fromTs) / 86400) + 1);
    // Read INCLUDING rotated generations (budgeted via smpro_syslog_read_cmd: a busy server with huge rotated
    // logs falls back to the live file, so this never turns a count into a timeout). Falls back to a plain tail
    // if the shared helper is unavailable. `tail -n 800000` still bounds the work - 800k lines covers any window.
    $rd = function ($file, $days) {
        $cat = function_exists('smpro_syslog_read_cmd') ? smpro_syslog_read_cmd($file, (int)$days) : '';
        return $cat !== '' ? $cat . ' | tail -n 800000' : 'tail -n 800000 ' . escapeshellarg($file);
    };
    // Each count below decompresses rotated archives (three modsec .gz alone cost 3 s per render on a production
    // server). The command text carries the window, so memoising on it is exact: ten minutes per window.
    $cnt = function (string $cmd) { return function_exists('smpro_memo_cmd') ? smpro_memo_cmd('ar_' . sha1($cmd), 600, $cmd, 14) : (string)smpro_ar_sh($cmd); };   // stale-while-refresh: the 4 s cold render became a background job
    // BRUTE-FORCE - failed SSH/FTP/mail logins (lfd + secure), within the window
    $bf = 0;
    if (is_readable('/var/log/lfd.log'))  $bf += (int)trim($cnt($rd('/var/log/lfd.log', $winDays) . " | grep -aE " . escapeshellarg($sysPat) . " | grep -aciE 'failed|login failures|\\bLF_'"));
    $secf = is_readable('/var/log/secure') ? '/var/log/secure' : (is_readable('/var/log/auth.log') ? '/var/log/auth.log' : '');
    if ($secf) $bf += (int)trim($cnt($rd($secf, $winDays) . " | grep -aE " . escapeshellarg($sysPat) . " | grep -ac 'Failed password'"));
    $R['brute'] = ['icon'=>'&#128272;','title'=>'Brute-force','n'=>$bf,'note'=>'failed SSH / FTP / mail logins' . $win,'sev'=>$bf>200?'crit':($bf>20?'warn':'ok'),'page'=>'account-audit'];
    // WEB ATTACKS - ModSecurity / WAF, within the window
    $atk = 0; $ms = '';
    foreach (['/var/log/modsec_audit.log','/usr/local/apache/logs/modsec_audit.log','/etc/apache2/logs/modsec_audit.log'] as $p) if (is_readable($p)) { $ms = $p; break; }
    if ($ms) $atk = (int)trim($cnt($rd($ms, $winDays) . " | grep -aE " . escapeshellarg($msPat) . " | grep -aic 'ModSecurity'"));
    $R['attack'] = ['icon'=>'&#128680;','title'=>'Web attacks','n'=>$atk,'note'=>'requests blocked by ModSecurity / WAF' . $win,'sev'=>$atk>500?'crit':($atk>50?'warn':'ok'),'page'=>'intrusion-monitor'];
    // SPAM - exim rejections / spam-scored, within the window (ISO date column $1)
    $spam = 0;
    if (is_readable('/var/log/exim_mainlog')) $spam = (int)trim($cnt($rd('/var/log/exim_mainlog', $winDays) . " | grep -aiE 'rejected|spam' | awk -v a=" . escapeshellarg($fromD) . " -v b=" . escapeshellarg($toD) . " '$1>=a && $1<=b' | wc -l"));
    $R['spam'] = ['icon'=>'&#128231;','title'=>'Spam','n'=>$spam,'note'=>'rejected / spam-scored mail (exim)' . $win,'sev'=>$spam>1000?'crit':($spam>100?'warn':'ok'),'page'=>'spam-phishing'];
    // IMUNIFY - malware / quarantine (CURRENT state, not window-filtered)
    $imu = 0; $note = 'Imunify not installed';
    if (trim(smpro_ar_sh('command -v imunify360-agent')) !== '') {
        // Use the JSON count, not a line count of the table: the plain output includes a HEADER row and keeps
        // listing files Imunify already cleaned in place (status "cleanup_done"), so `grep -c` reported ~1992
        // "issues" on a server whose real malicious count was 765.
        $imuJ = json_decode($cnt("imunify360-agent malware malicious list --limit 2000 --json 2>/dev/null"), true);
        if (is_array($imuJ) && isset($imuJ['malicious_count']))      $imu = (int)$imuJ['malicious_count'];
        elseif (is_array($imuJ) && is_array($imuJ['items'] ?? null)) $imu = count(array_filter($imuJ['items'], fn($r) => (string)($r['status'] ?? '') !== 'cleanup_done'));
        else                                                         $imu = 0;
        $note = 'malware / quarantined items now — check for false positives that broke a site';
    } elseif (is_readable('/var/log/imunify360/console.log')) {
        $imu = (int)trim($cnt($rd('/var/log/imunify360/console.log', $winDays) . " | grep -aE " . escapeshellarg($sysPat) . " | grep -aciE 'malware|quarantin|blocked'"));
        $note = 'Imunify events (malware / quarantine / blocks)' . $win;
    }
    $R['imunify'] = ['icon'=>'&#9888;','title'=>'Imunify issues','n'=>$imu,'note'=>$note,'sev'=>$imu>0?'warn':'ok','page'=>'imunify360-reports'];
    // BACKUP - last backup result (CURRENT state)
    $bk = 0; $bn = 'no backup logs found'; $bs = 'warn';
    $cpb = '/usr/local/cpanel/logs/cpbackup';
    if (is_dir($cpb)) {
        $last = trim(smpro_ar_sh('ls -1t ' . escapeshellarg($cpb) . '/*.log 2>/dev/null | head -1'));
        if ($last !== '') { $bk = (int)trim(smpro_ar_sh("grep -aciE 'fail|error|cannot' " . escapeshellarg($last))); $bn = $bk > 0 ? ('errors in last backup (' . basename($last) . ')') : 'last backup completed OK'; $bs = $bk > 0 ? 'crit' : 'ok'; }
    } elseif (trim(smpro_ar_sh('command -v jetbackup5')) !== '' || is_dir('/usr/local/jetapps')) { $bn = 'JetBackup detected — open Backup Monitor for status'; $bs = 'ok'; }
    $R['backup'] = ['icon'=>'&#128190;','title'=>'Backups','n'=>$bk,'note'=>$bn,'sev'=>$bs,'page'=>'backup-monitor'];
    if (is_dir(dirname($ck)) || @mkdir(dirname($ck), 0700, true)) @file_put_contents($ck, json_encode($R), LOCK_EX);
    return $R;
}

/** Keep the default 7-day window warm (called by the notify worker). Cheap while fresh; does the work when a key is new. */
function smpro_ar_prewarm(): void {
    if (!function_exists('smpro_memo_cmd')) return;
    $to = time(); smpro_ar_reports($to - 7 * 86400, $to);
}
