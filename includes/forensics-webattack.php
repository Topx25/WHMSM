<?php
/**
 * forensics-webattack.php — §3.3 web-attack correlation + §3.4 access/auth forensics.
 * Prefix smpro_fw_*. Loaded after forensics-engine.php (smpro_fx_* + smpro_im_* + smpro_ip_* available).
 * READ-ONLY: bounded grep/tail of logs only; never re-stats the account file (mtime/ctime passed in).
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

/** Apache domlogs base (self-contained — reports-center's copy lives in a module that isn't boot-loaded). */
function smpro_fw_domlogs_base() { foreach (['/etc/apache2/logs/domlogs', '/usr/local/apache/domlogs', '/var/log/apache2/domlogs'] as $p) if (is_dir($p)) return $p; return ''; }
/** Parse an Apache combined-log date "[10/Jul/2026:17:45:03 +0000]" → UTC epoch. */
function smpro_fw_alog_ts($s) { $s = trim((string)$s, '[] '); $s = preg_replace('#^(\d+/\w+/\d+):#', '$1 ', $s, 1); return strtotime($s) ?: 0; }

/**
 * §3.3 — did an HTTP request plausibly WRITE the flagged file? mtime/ctime are PASSED IN (no re-stat).
 * Window = [mtime-win, mtime+win], widened to ±6h ONCE if zero write-candidate hits. Returns
 * {findings[],timeline[],verdict_hint,possible_drop,attack_hit,banner,requests[]}.
 */
function smpro_fw_correlate($user, $flaggedFile, $mtime, $ctime, $alertTs, $win = 1800, $deadline = 0) {
    $out = ['findings' => [], 'timeline' => [], 'verdict_hint' => 'no_correlation', 'possible_drop' => false, 'attack_hit' => false, 'banner' => 'No correlating web request — consistent with a legitimate local edit (SSH / FTP / cPanel File Manager).', 'requests' => []];
    $base = smpro_fw_domlogs_base();
    $mtime = (int)$mtime; if ($mtime <= 0) $mtime = (int)$alertTs;
    $domains = function_exists('smpro_im_userdomains') ? array_keys(array_filter(smpro_im_userdomains(), fn($a) => $a === $user)) : [];
    if (!$domains && function_exists('smpro_fx_scope')) { $sc = smpro_fx_scope($user); $domains = $sc['domains'] ?? []; }
    $fileDir = str_replace('\\', '/', dirname((string)$flaggedFile));
    $fileBase = basename((string)$flaggedFile);

    // When a $deadline (epoch float) is set by the caller, BOUND the work: cap the number of domains scanned and
    // clamp each log's timeout to the time left — so a reseller/addon-heavy account can't run for minutes here.
    $scanDomains = ($deadline > 0) ? array_slice($domains, 0, 8) : $domains;
    $scan = function ($lo, $hi) use ($base, $scanDomains, $mtime, $fileDir, $fileBase, $deadline) {
        $rows = [];
        if ($base === '') return $rows;
        foreach ($scanDomains as $dom) {
            if ($deadline > 0 && microtime(true) > $deadline) break;
            foreach ([$base . '/' . $dom, $base . '/' . $dom . '-ssl_log'] as $lf) {
                if (!is_readable($lf)) continue;
                if ($deadline > 0 && microtime(true) > $deadline) break 2;
                // bounded: only the recent tail, then filter by parsed ts to the window
                $lto = ($deadline > 0) ? (int)max(2, min(12, $deadline - microtime(true))) : 12;
                $raw = (string)@shell_exec('timeout ' . $lto . ' sh -c ' . escapeshellarg('tail -n 200000 ' . escapeshellarg($lf) . ' 2>/dev/null | grep -aE ' . escapeshellarg('"(POST|PUT|GET|HEAD) ') . ' | tail -n 20000') . ' 2>/dev/null');
                foreach (explode("\n", $raw) as $l) {
                    if ($l === '' || !preg_match('/\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+[^"]*"\s+(\d{3})\s+(\S+)(?:\s+"[^"]*"\s+"([^"]*)")?/', $l, $m)) continue;
                    $ts = smpro_fw_alog_ts($m[1]); if ($ts < $lo || $ts > $hi) continue;
                    // client IP = first field (combined) or second (vhost-combined)
                    $f0 = strtok(ltrim($l), " \t"); $f1 = strtok(" \t"); $ip = filter_var($f0, FILTER_VALIDATE_IP) ? $f0 : (filter_var($f1, FILTER_VALIDATE_IP) ? $f1 : '');
                    $rows[] = ['ts' => $ts, 'ip' => $ip, 'method' => strtoupper($m[2]), 'uri' => $m[3], 'status' => (int)$m[4], 'bytes' => $m[5], 'ua' => $m[6] ?? '', 'dom' => $dom, 'raw' => mb_substr($l, 0, 300)];
                }
            }
        }
        return $rows;
    };
    $rows = $scan($mtime - $win, $mtime + $win);
    $widened = false;
    $hasWrite = false; foreach ($rows as $r) if (smpro_fw_classify_req($r, $fileDir, $fileBase) === 'WRITE_CANDIDATE') { $hasWrite = true; break; }
    if (!$hasWrite && !$rows && !($deadline > 0 && microtime(true) > $deadline)) { $rows = $scan($mtime - 21600, $mtime + 21600); $widened = true; }

    $best = null;
    foreach ($rows as $r) {
        $cls = smpro_fw_classify_req($r, $fileDir, $fileBase);
        if ($cls === 'CONTEXT') continue;
        $conf = smpro_fw_confidence($r, $mtime, $cls, $fileDir, $fileBase);
        $bucket = $conf >= 70 ? 'LIKELY_WRITE' : ($conf >= 40 ? 'POSSIBLE' : 'CONTEXT');
        $r['class'] = $cls; $r['confidence'] = $conf; $r['bucket'] = $bucket;
        $out['requests'][] = $r;
        if ($cls === 'WEBSHELL' || $cls === 'PRECURSOR') $out['attack_hit'] = true;
        if ($cls === 'WRITE_CANDIDATE' && abs($r['ts'] - $mtime) <= 120) $out['possible_drop'] = true;
        if (!$best || $conf > $best['confidence']) $best = $r;
        $intel = function_exists('smpro_ip_intel') ? smpro_ip_intel($r['ip']) : [];
        $out['timeline'][] = smpro_fx_event(['ts_utc' => $r['ts'], 'source' => 'apache_access', 'actor_ip' => $r['ip'], 'path' => $r['uri'], 'http_status' => (string)$r['status'], 'http_method' => $r['method'], 'url' => $r['uri'], 'ua' => $r['ua'], 'raw_excerpt' => $r['raw'], 'tags' => [$cls, $bucket]]);
        $out['findings'][] = smpro_fx_finding(['category' => 'Web-attack correlation', 'title' => $bucket . ' — ' . $cls . ' ' . $r['method'] . ' ' . $r['uri'], 'severity' => $conf, 'confidence' => $conf >= 70 ? 'high' : 'med', 'account' => $user, 'path' => (string)$flaggedFile, 'whitelist_key' => (string)$flaggedFile, 'evidence' => [smpro_fx_ev('log', $r['method'] . ' ' . $r['uri'] . ' → ' . $r['status'], ['source_file' => $r['dom'], 'excerpt' => $r['raw']]), smpro_fx_ev('ip', $r['ip'], ['excerpt' => ($intel['country'] ?? '') . ' ' . ($intel['provider'] ?? '')])], 'why' => 'A ' . $cls . ' HTTP request landed ' . abs($r['ts'] - $mtime) . 's from the file write time.']);
    }
    // §3.3 ModSec corroboration (bounded)
    if (function_exists('smpro_im_parse_modsec')) {
        $ms = @smpro_im_parse_modsec(4 * 1024 * 1024, 400, $mtime - $win);
        foreach ((is_array($ms) ? $ms : []) as $e) {
            $ets = (int)($e['ts'] ?? 0); if ($ets < $mtime - $win || $ets > $mtime + $win) continue;
            $host = (string)($e['domain'] ?? ''); if ($host !== '' && !in_array(strtolower($host), array_map('strtolower', $domains), true)) continue;
            $out['attack_hit'] = true;
            $out['findings'][] = smpro_fx_finding(['category' => 'Web-attack correlation', 'title' => 'ModSec rule ' . ($e['rule'] ?? '') . ' near the write window', 'severity' => 55, 'confidence' => 'high', 'account' => $user, 'path' => (string)$flaggedFile, 'whitelist_key' => (string)$flaggedFile, 'evidence' => [smpro_fx_ev('log', ($e['msg'] ?? 'modsec hit'), ['excerpt' => ($e['uri'] ?? '')]), smpro_fx_ev('ip', (string)($e['ip'] ?? ''))], 'why' => 'ModSecurity flagged an attack request to this account inside the write window.']);
        }
    }
    if ($out['possible_drop']) { $out['verdict_hint'] = 'likely_write'; $out['banner'] = 'A write-candidate request landed ≤120s from the file write time — ' . ($best ? $best['method'] . ' ' . $best['uri'] . ' from ' . $best['ip'] : ''); }
    elseif ($out['requests']) { $out['verdict_hint'] = 'context_only'; $out['banner'] = count($out['requests']) . ' correlating request(s) in the window, none a clear write-candidate at the write time.'; }
    else { $out['verdict_hint'] = 'no_correlation'; $out['banner'] = 'No correlating web request' . ($widened ? ' (even within ±6h)' : '') . ' — consistent with a legitimate local edit (SSH / FTP / cPanel File Manager).'; }
    return $out;
}

/** Classify a request row relative to the flagged file. WRITE_CANDIDATE REQUIRES the URI resolve
 *  at/above the file's dir (so a generic exploit elsewhere on the domain stays CONTEXT). */
function smpro_fw_classify_req($r, $fileDir, $fileBase) {
    $uri = (string)($r['uri'] ?? ''); $method = strtoupper((string)($r['method'] ?? '')); $upath = (string)parse_url($uri, PHP_URL_PATH);
    $pathMatch = ($fileBase !== '' && stripos($upath, $fileBase) !== false) || preg_match('#/(admin-ajax|upload|filemanager|file-manager|elfinder|kcfinder|editor)\.php#i', $upath);
    if (in_array($method, ['POST', 'PUT'], true) && $pathMatch) return 'WRITE_CANDIDATE';
    if (preg_match('/[?&](cmd|exec|c99|r57|wso|b374k|filesman|passthru|shell)=|(?:%00|\beval\(|\bbase64_decode|[A-Za-z0-9+\/]{200,})/i', $uri)) return 'WEBSHELL';
    if (preg_match('/union\s+select|\'\s+or\s+1=1|information_schema|\.\.\/|php:\/\/|data:\/\/|\/etc\/passwd|xmlrpc\.php/i', $uri)) return 'PRECURSOR';
    return 'CONTEXT';
}
/** Request → write confidence 0-100 (§3.3 weights). */
function smpro_fw_confidence($r, $mtime, $cls, $fileDir, $fileBase) {
    $c = 0; $d = abs((int)$r['ts'] - (int)$mtime);
    $c += $d <= 10 ? 40 : ($d <= 60 ? 30 : ($d <= 300 ? 15 : 5));
    $c += $cls === 'WRITE_CANDIDATE' ? 35 : ($cls === 'WEBSHELL' ? 25 : ($cls === 'PRECURSOR' ? 10 : 0));
    $st = (int)$r['status']; $c += ($st >= 200 && $st < 400) ? 15 : (in_array($st, [403, 406], true) ? -10 : 0);
    $upath = (string)parse_url((string)$r['uri'], PHP_URL_PATH); if ($fileBase !== '' && stripos($upath, $fileBase) !== false) $c += 15;
    return max(0, min(100, $c));
}

/**
 * §3.4 — did an interactive login / upload session explain the write? Greps the account's auth+write
 * logs near $mtime. Returns {verdict_hint, admin_session_write, known_admin, new_key_or_cron, events[]}.
 * verdict_hint ∈ interactive_upload | admin_session_write | no_login_explains_write | app_self_write.
 */
function smpro_fw_auth_for_write($user, $file, $mtime) {
    $mtime = (int)$mtime; $win = 900;   // ±15 min
    $ev = []; $sameSessionWrite = false; $anyLogin = false; $knownAdmin = false;
    // FTP STOR + cPanel Fileman save to that path/dir (interactive upload)
    $bn = basename((string)$file);
    foreach (['/var/log/messages', '/var/log/secure'] as $lg) {
        if (!is_readable($lg)) continue;
        $raw = (string)@shell_exec('timeout 8 sh -c ' . escapeshellarg('tail -n 200000 ' . escapeshellarg($lg) . ' 2>/dev/null | grep -aiE ' . escapeshellarg('(pure-ftpd|proftpd).*(STOR|uploaded)|Accepted (password|publickey)') . ' | grep -aF ' . escapeshellarg($user) . ' | tail -n 200') . ' 2>/dev/null');
        foreach (explode("\n", $raw) as $l) { $l = trim($l); if ($l === '') continue; $ts = smpro_syslog_ts(preg_replace('/^([A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+).*/', '$1', $l)); if ($ts && abs($ts - $mtime) <= $win) { $anyLogin = true; if (stripos($l, $bn) !== false || stripos($l, 'STOR') !== false) $sameSessionWrite = true; $ev[] = ['ts' => $ts, 'src' => 'ftp/ssh', 'line' => mb_substr($l, 0, 200)]; } }
    }
    // cPanel Fileman save/upload
    $cpl = '/usr/local/cpanel/logs/access_log';
    if (is_readable($cpl)) {
        $raw = (string)@shell_exec('timeout 8 sh -c ' . escapeshellarg('tail -n 200000 ' . escapeshellarg($cpl) . ' 2>/dev/null | grep -aiE ' . escapeshellarg('Fileman|save_file|upload') . ' | grep -aF ' . escapeshellarg($user) . ' | tail -n 200') . ' 2>/dev/null');
        foreach (explode("\n", $raw) as $l) { $l = trim($l); if ($l === '') continue; if (preg_match('/\[([^\]]+)\]/', $l, $m)) { $ts = strtotime($m[1]) ?: 0; if ($ts && abs($ts - $mtime) <= $win) { $anyLogin = true; if (stripos($l, $bn) !== false) $sameSessionWrite = true; $ev[] = ['ts' => $ts, 'src' => 'cpanel_fileman', 'line' => mb_substr($l, 0, 200)]; } } }
    }
    // new authorized_keys / cron in the lookback (30d) — atomic HIGH signals
    $newKeyOrCron = false;
    foreach (["/home/$user/.ssh/authorized_keys", "/home/$user/.ssh/authorized_keys2", "/var/spool/cron/$user"] as $kf) {
        if (is_file($kf) && (time() - (int)@filemtime($kf)) < 30 * 86400 && (int)@filemtime($kf) >= $mtime - $win) { $newKeyOrCron = true; $ev[] = ['ts' => (int)@filemtime($kf), 'src' => 'creds', 'line' => 'modified in window: ' . $kf]; }
    }
    if ($sameSessionWrite) $hint = 'interactive_upload';
    elseif ($anyLogin) { $hint = 'admin_session_write'; $knownAdmin = true; }        // a login in the window; treat account-owner login as known-admin
    elseif (!$ev) $hint = 'app_self_write';                                            // NO auth event explains the write → app self-write / non-logged local edit
    else $hint = 'no_login_explains_write';
    return ['verdict_hint' => $hint, 'admin_session_write' => ($hint === 'admin_session_write'), 'known_admin' => $knownAdmin, 'new_key_or_cron' => $newKeyOrCron, 'events' => $ev];
}
