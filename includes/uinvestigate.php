<?php
/**
 * includes/uinvestigate.php — User Investigation engine (BETA, 1.1.x).
 *
 * Builds a per-cPanel-ACCOUNT incident TIMELINE, assembled READ-ONLY from what the server actually
 * logs, with every event carrying a SOURCE and an honest CONFIDENCE label (confirmed | likely | possible).
 * v1 sources (all include-safe, per-account): web attacks (intrusion index), cPanel panel/API actions
 * (access_log), and logins (login_log). Forensic findings / mail / file-change are added in later phases.
 *
 * NO mutation, no restart — pure collectors. See SM-Pro-User-Investigation-Roadmap.md.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

/** cPanel accounts, for the picker. */
function smpro_ui_accounts() {
    $u = [];
    foreach (glob('/var/cpanel/users/*') ?: [] as $f) { $b = basename($f); if (preg_match('/^[a-z0-9][a-z0-9._-]*$/i', $b)) $u[] = $b; }
    sort($u); return $u;
}

/** Parse a cPanel access_log timestamp "MM/DD/YYYY:HH:MM:SS +0000" (US-ordered) → unix ts (0 on failure). */
function smpro_ui_parse_apachetime($t) {
    if (preg_match('#^(\d{2})/(\d{2})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+\-]\d{4})?#', (string)$t, $m))
        return strtotime($m[3] . '-' . $m[1] . '-' . $m[2] . ' ' . $m[4] . ':' . $m[5] . ':' . $m[6] . ' ' . ($m[7] ?: '+0000')) ?: 0;
    return @strtotime((string)$t) ?: 0;
}

/** Parse a login_log bracket timestamp → unix ts. Handles ISO "YYYY-MM-DD HH:MM:SS +0000" (whostmgrd/cpaneld)
 *  AND Apache-style "DD/Mon/YYYY:HH:MM:SS +0000" / "MM/DD/YYYY:HH:MM:SS +0000" (webmail) where a COLON — not a
 *  space — separates date from time (strtotime can't parse that until the first colon becomes a space).
 *  Mirrors the shipped login-monitor parser so all sources agree. */
function smpro_ui_login_ts($t) {
    $t = trim((string)$t);
    if ($t === '') return 0;
    // Apache-style "DD/Mon/YYYY:HH:MM:SS +zzzz" (webmail) — rebuild with SPACES; strtotime can't read slash+month-name.
    if (preg_match('#^(\d{1,2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?\s*([+\-]\d{4})?#', $t, $m))
        return strtotime($m[1] . ' ' . $m[2] . ' ' . $m[3] . ' ' . $m[4] . ':' . $m[5] . ':' . $m[6] . ' ' . ($m[7] ?? '')) ?: 0;
    // Numeric "MM/DD/YYYY:HH:MM:SS +zzzz" — swap the first colon (date/time separator) to a space.
    if (preg_match('#^\d{1,2}/\d{1,2}/\d{4}:#', $t)) $t = preg_replace('/:/', ' ', $t, 1);
    // ISO "YYYY-MM-DD HH:MM:SS +zzzz" parses directly.
    return @strtotime($t) ?: 0;
}

/** cPanel panel / API actions performed BY $account (from access_log), within [from,to]. Confirmed.
 *  Keeps only real API calls (/execute/Module/func) + login endpoints; skips UI/static asset GETs;
 *  dedupes identical op+ip within the same minute so the timeline isn't flooded with clicks. */
function smpro_ui_panel_actions($account, $fromTs, $toTs, $maxLines = 8000) {
    $log = '/usr/local/cpanel/logs/access_log';
    $account = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)$account);
    if ($account === '' || !is_readable($log)) return [];
    $needle = ' - ' . $account . ' [';   // matches "IP - account [ts]" exactly (space+bracket boundary)
    $raw = (string)@shell_exec('timeout 25 grep -F ' . escapeshellarg($needle) . ' ' . escapeshellarg($log) . ' 2>/dev/null | tail -n ' . (int)$maxLines);
    if ($raw === '') return [];
    $seen = []; $out = [];
    foreach (explode("\n", $raw) as $ln) {
        if (!preg_match('#^(\S+)\s+-\s+' . preg_quote($account, '#') . '\s+\[([^\]]+)\]\s+"([A-Z]+)\s+(\S+)\s+HTTP/[\d.]+"\s+(\d{3})#', $ln, $m)) continue;
        $ip = $m[1]; $method = $m[3]; $path = $m[4]; $code = $m[5];
        if (strpos($path, '/execute/') === false && strpos($path, '/login') === false) continue;   // real actions only
        $ts = smpro_ui_parse_apachetime($m[2]);
        if (!$ts || $ts < $fromTs || $ts > $toTs) continue;   // drop undated/out-of-window (keeps the [from,to] contract)
        $op = preg_match('#/execute/([A-Za-z0-9_]+)/([A-Za-z0-9_]+)#', $path, $pm) ? ($pm[1] . '::' . $pm[2]) : (strpos($path, '/login') !== false ? 'login' : $path);
        $key = $op . '|' . $ip . '|' . intdiv((int)$ts, 60);
        if (isset($seen[$key])) continue;
        $seen[$key] = 1;
        $sev = preg_match('#Fileman|Mysql|Ftp|SSH|Cron|passwd|resetpass|Backup|SubDomain|Addon|Api(Token|Shell)#i', $op) ? 'low' : 'info';
        $out[] = ['ts'=>(int)$ts,'source'=>'cpanel_panel','actor_ip'=>$ip,'domain'=>'','action'=>$method . ' ' . $op,'target'=>$path,'severity'=>$sev,'confidence'=>'confirmed'];
        if (count($out) >= 400) break;
    }
    return $out;
}

/** cPanel/WHM logins for $account (from login_log), within [from,to]. Confirmed. */
function smpro_ui_logins($account, $fromTs, $toTs, $maxLines = 0) {
    $log = '/usr/local/cpanel/logs/login_log';
    // The tail must cover the window, not a fixed 6,000 lines: on a busy server 6,000 lines of session_log is a
    // day, and a 7-day investigation then showed no sign-ins at all - which reads as "nobody signed in".
    if ($maxLines <= 0) $maxLines = min(400000, max(20000, (int)ceil(($toTs - $fromTs) / 86400) * 30000));
    $account = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)$account);
    if ($account === '' || !is_readable($log)) return [];
    $raw = (string)@shell_exec('timeout 20 tail -n ' . (int)$maxLines . ' ' . escapeshellarg($log) . ' 2>/dev/null');
    // Empty tail of a non-empty log is a FAILED read (timeout/permission), not "no activity" — surface it rather
    // than let the timeline quietly show a blank where the evidence should be.
    if ($raw === '') {
        if ((int)@filesize($log) > 0 && function_exists('smpro_audit')) smpro_audit('uinv_read_failed', ['log' => basename($log), 'account' => $account]);
        return [];
    }
    $out = [];
    // Successful sign-ins are in session_log on current cPanel, so an account timeline built on login_log alone
    // showed the failed attempts against an account and none of the logins that actually got in.
    if (!function_exists('smpro_lf_success')) { $lf = __DIR__ . '/loginfeed.php'; if (@is_file($lf)) require_once $lf; }
    if (function_exists('smpro_lf_success')) {
        foreach ((array)smpro_lf_success($fromTs, $maxLines, ['password', 'operator', 'api'])['events'] as $e) {
            if (strtolower((string)$e['user']) !== strtolower($account) || $e['ip'] === '') continue;
            $ts = (int)$e['ts']; if (!$ts || $ts < $fromTs || $ts > $toTs) continue;
            $op = ($e['kind'] === 'operator' || $e['kind'] === 'api');
            $out[] = ['ts' => $ts, 'source' => 'login', 'actor_ip' => (string)$e['ip'], 'domain' => '',
                      'action' => $op ? 'Operator opened this account' : 'Successful login',
                      'target' => (string)$e['service'] . ($op ? ' (no account password used)' : ''),
                      'severity' => 'info', 'confidence' => 'confirmed'];
        }
    }
    foreach (explode("\n", $raw) as $ln) {
        $ln = trim($ln); if ($ln === '') continue;
        // Two coexisting cPanel login_log shapes (mirror account-audit / login-monitor, the shipped+tested parsers):
        //   A (cpaneld/whostmgrd): [ts] level [service] IP - user <rest>   (rest = "- RESULT" or "\"req\" RESULT")
        //   B (webmail/cpdavd):    IP - user [date] "req" RESULT
        if (preg_match('/^\[([^\]]+)\]\s+\S+\s+\[[^\]]+\]\s+(\S+)\s+-\s+(\S+)\s+(.+)$/', $ln, $m))      { $traw = $m[1]; $ip = $m[2]; $user = rawurldecode($m[3]); $rest = $m[4]; }
        elseif (preg_match('/^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"[^"]*"\s+(.+)$/', $ln, $m))        { $ip = $m[1]; $user = rawurldecode($m[2]); $traw = $m[3]; $rest = $m[4]; }
        else continue;
        if (strtolower($user) !== strtolower($account) || !filter_var($ip, FILTER_VALIDATE_IP)) continue;
        $ts = smpro_ui_login_ts($traw);
        if (!$ts || $ts < $fromTs || $ts > $toTs) continue;
        if (preg_match('/SUCCEEDED\s+LOGIN/i', $rest))                                    { continue; }   // already carried by the feed
        elseif (preg_match('/FAILED\s+LOGIN|AUTHENTICATION\s+FAILED|INVALID/i', $rest))   { $res = 'Failed login';     $sev = 'medium'; }
        elseif (preg_match('/DEFERRED\s+LOGIN/i', $rest))                                 { $res = 'Deferred login';   $sev = 'low'; }
        else continue;
        $out[] = ['ts'=>(int)$ts,'source'=>'login','actor_ip'=>$ip,'domain'=>'','action'=>$res,'target'=>trim(preg_replace('/\s+/', ' ', mb_substr($rest, 0, 120))),'severity'=>$sev,'confidence'=>'confirmed'];
    }
    return $out;
}

/** Outbound mail attributed to $account via Exim (cwd=/home/<acct>/ script sends), within [from,to]. READ-ONLY.
 *  Surfaces the compromise VECTOR from Exim's P= field: P=local/pipe = a script on the account sent the mail
 *  (compromised web app is the likely cause); P=esmtpa = authenticated SMTP (a mailbox password is in use). An
 *  outbound burst is one of the strongest early compromise signals on shared hosting (research: Exim cwd/P). */
function smpro_ui_mail_events($account, $fromTs, $toTs, $maxLines = 15000) {
    $log = '/var/log/exim_mainlog';
    $account = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)$account);
    if ($account === '' || !is_readable($log)) return [];
    // Exim writes the REAL working directory, so the needle must be the account's real home. Built as
    // "cwd=/home/<acct>/" it matched nothing for any account on /home2 — and an empty grep result is
    // indistinguishable from an account that simply sent no mail, so a compromised account reported clean.
    $home = smpro_user_home($account);
    if ($home === '') return [];                                                  // cannot look != nothing found
    $needle = 'cwd=' . $home . '/';
    // Read rotated generations across the investigation window: exim rotates weekly, so an account's outbound-mail
    // timeline (the strongest compromised-account-sending signal) would otherwise stop ~5 days back on a 14/30-day
    // investigation and the burst would be invisible. Budgeted reader → busy servers fall back to the live file.
    $winDays = max(1, (int)ceil(($toTs - $fromTs) / 86400) + 1);
    $cat = function_exists('smpro_syslog_read_cmd') ? smpro_syslog_read_cmd($log, $winDays) : '';
    $inner = ($cat !== '' ? $cat : 'cat ' . escapeshellarg($log)) . ' 2>/dev/null | grep -F ' . escapeshellarg($needle) . ' | tail -n ' . (int)$maxLines;
    $raw = (string)@shell_exec('timeout 25 sh -c ' . escapeshellarg($inner) . ' 2>/dev/null');
    if ($raw === '') return [];
    $out = []; $byScript = []; $n = 0;
    foreach (explode("\n", $raw) as $ln) {
        if (strpos($ln, ' <= ') === false) continue;                                  // message-received (sending) line
        if (!preg_match('/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/', $ln, $tm)) continue;
        $ts = @strtotime($tm[1]) ?: 0;                                                // exim mainlog = server local time
        if (!$ts || $ts < $fromTs || $ts > $toTs) continue;
        $proto  = preg_match('/\bP=(\S+)/', $ln, $pm) ? $pm[1] : '';
        $cwd    = preg_match('#cwd=(' . preg_quote($home, '#') . '/\S*)#', $ln, $cm) ? $cm[1] : $home;
        $sender = preg_match('/<=\s+(\S+)/', $ln, $sm) ? $sm[1] : '';
        $vector = in_array($proto, ['local', 'pipe', 'spool'], true) ? 'a script on the account (compromised app likely)'
                : (stripos($proto, 'esmtpa') !== false ? 'authenticated SMTP (mailbox password in use)' : ($proto !== '' ? ('P=' . $proto) : 'local'));
        $byScript[$cwd] = ($byScript[$cwd] ?? 0) + 1; $n++;
        if (count($out) < 300)
            $out[] = ['ts'=>(int)$ts,'source'=>'outbound_mail','actor_ip'=>'','domain'=>'','action'=>'Outbound mail sent — ' . $vector,
                'target'=>$cwd . ($sender !== '' ? ('  from ' . $sender) : ''),'severity'=>'medium','confidence'=>'confirmed'];
    }
    if ($n >= 100 && $out) {                                                          // burst → single high-severity marker
        arsort($byScript); $top = (string)array_key_first($byScript);
        $out[] = ['ts'=>(int)$out[0]['ts'],'source'=>'outbound_mail','actor_ip'=>'','domain'=>'',
            'action'=>'Outbound mail BURST — ' . $n . ' script sends in window (possible compromise)',
            'target'=>'top script: ' . $top . ' (' . (int)$byScript[$top] . ' sends)','severity'=>'high','confidence'=>'confirmed'];
    }
    return $out;
}

/** Suspected web shells from the account's Apache domlogs: a .php URL that was SERVED (2xx), hit by only 1–2
 *  client IPs, and POST-heavy and/or referer-less — the classic web-shell access fingerprint (NSA/CISA "Detect
 *  and Prevent Web Shell Malware"). Catches shells the WAF never saw. READ-ONLY, bounded (domains, lines, time). */
function smpro_ui_webshell_suspects($account, $fromTs, $toTs, $maxDomains = 30, $maxLines = 20000) {
    $account = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)$account);
    if ($account === '') return [];
    $domains = [];
    foreach (@file('/etc/userdomains', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
        $p = strrpos($line, ':'); if ($p === false) continue;
        $dom = strtolower(trim(substr($line, 0, $p))); $usr = trim(substr($line, $p + 1));
        if ($usr === $account && $dom !== '' && $dom !== '*') $domains[$dom] = 1;
    }
    $domains = array_slice(array_keys($domains), 0, $maxDomains);
    if (!$domains) return [];
    $dirs = ['/var/log/apache2/domlogs', '/usr/local/apache/domlogs', '/etc/apache2/logs/domlogs'];
    $agg = []; $deadline = time() + 20;
    foreach ($domains as $dom) {
        if (time() > $deadline) break;
        $logf = ''; foreach ($dirs as $d) { if (@is_readable($d . '/' . $dom)) { $logf = $d . '/' . $dom; break; } }
        if ($logf === '') continue;
        $raw = (string)@shell_exec('timeout 15 tail -n ' . (int)$maxLines . ' ' . escapeshellarg($logf) . ' 2>/dev/null');
        if ($raw === '') continue;
        foreach (explode("\n", $raw) as $ln) {
            if (!preg_match('#^(\S+) \S+ \S+ \[([^\]]+)\] "([A-Z]+) (\S+) HTTP/[\d.]+" (\d{3}) \S+ "([^"]*)" "([^"]*)"#', $ln, $m)) continue;
            $ip = $m[1]; $ts = smpro_ui_login_ts($m[2]); $method = $m[3]; $uri = $m[4]; $code = (int)$m[5]; $ref = $m[6];
            if ($ts && ($ts < $fromTs || $ts > $toTs)) continue;
            $path = (string)parse_url($uri, PHP_URL_PATH);
            if ($path === '' || !preg_match('/\.php$/i', $path)) continue;
            if (preg_match('#/wp-(login|cron)\.php$#i', $path)) continue;              // noisy legit endpoints
            if (!isset($agg[$path])) $agg[$path] = ['hits'=>0,'post'=>0,'noref'=>0,'ips'=>[],'c2'=>0,'last'=>0];
            $a =& $agg[$path]; $a['hits']++; if ($method === 'POST') $a['post']++; if ($ref === '' || $ref === '-') $a['noref']++;
            $a['ips'][$ip] = 1; if ($code >= 200 && $code < 300) $a['c2']++; if ($ts > $a['last']) $a['last'] = $ts; unset($a);
        }
    }
    $out = [];
    foreach ($agg as $uri => $a) {
        $nip = count($a['ips']);
        $postHeavy = $a['post'] >= max(3, (int)($a['hits'] * 0.5));
        $noRef     = $a['noref'] >= max(3, (int)($a['hits'] * 0.6));
        if ($a['c2'] >= 3 && $nip <= 2 && ($postHeavy || $noRef)) {                    // served + few clients + shell-like
            $why = [];
            if ($postHeavy) $why[] = 'POST-heavy (' . $a['post'] . '/' . $a['hits'] . ')';
            if ($noRef)     $why[] = 'no Referer';
            $why[] = $nip . ' client IP' . ($nip === 1 ? '' : 's');
            $out[] = ['ts'=>(int)($a['last'] ?: $toTs),'source'=>'webshell_suspect','actor_ip'=>(string)array_key_first($a['ips']),'domain'=>'',
                'action'=>'Suspected web shell — ' . implode(', ', $why),'target'=>$uri,'severity'=>'high','confidence'=>'suspected'];
            if (count($out) >= 40) break;
        }
    }
    return $out;
}

/**
 * Orchestrate the per-account timeline (READ-ONLY).
 * Returns ['account','from','to','events'=>[newest-first],'stats','sources'].
 */
function smpro_ui_collect($account, $fromTs, $toTs) {
    $account = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)$account);
    $events = []; $sources = ['web_attack' => 0, 'cpanel_panel' => 0, 'login' => 0, 'outbound_mail' => 0, 'webshell_suspect' => 0];
    if ($account !== '') {
        if (function_exists('smpro_in_by_account')) {
            foreach (smpro_in_by_account($account, $fromTs, $toTs, 2000) as $a) {
                $events[] = [
                    'ts'=>(int)($a['ts'] ?? 0), 'source'=>'web_attack', 'actor_ip'=>(string)($a['ip'] ?? ''), 'domain'=>(string)($a['domain'] ?? ''),
                    'action'=>((string)($a['kind'] ?: 'WAF event')) . (($a['code'] ?? '') !== '' ? ' (' . $a['code'] . ')' : ''),
                    'target'=>(string)($a['uri'] ?? ''), 'severity'=>strtolower((string)($a['severity'] ?: 'warning')), 'confidence'=>'confirmed',
                    '_kind'=>(string)($a['kind'] ?? ''), '_code'=>(string)($a['code'] ?? ''),   // raw fields for the forensic pass; stripped before the client payload
                ];
                $sources['web_attack']++;
            }
        }
        foreach (smpro_ui_panel_actions($account, $fromTs, $toTs) as $e) { $events[] = $e; $sources['cpanel_panel']++; }
        foreach (smpro_ui_logins($account, $fromTs, $toTs) as $e)        { $events[] = $e; $sources['login']++; }
        // NEW timeline sources (research-driven): Exim outbound-mail attribution + access-log web-shell hunt.
        // Appended AFTER the above so the web_attack event indices the forensic pass decorates stay stable.
        foreach (smpro_ui_mail_events($account, $fromTs, $toTs) as $e)       { $events[] = $e; $sources['outbound_mail']++; }
        foreach (smpro_ui_webshell_suspects($account, $fromTs, $toTs) as $e) { $events[] = $e; $sources['webshell_suspect']++; }
    }
    // Forensic enrichment (READ-ONLY, bounded, cached): outcome-classify web attacks + correlate reached-app
    // exploit requests with real webroot file changes. Merged by BUILD-ORDER index (before usort). If the
    // forensic engine is unavailable it returns ['ok'=>false] and the timeline renders exactly as before.
    $forensic = ($account !== '' && function_exists('smpro_ui_forensics')) ? smpro_ui_forensics($account, $events, $fromTs, $toTs) : ['ok'=>false];
    if (!empty($forensic['ok'])) {
        foreach ((array)($forensic['decorations'] ?? []) as $i => $d) {
            if (!isset($events[$i])) continue;
            if (isset($d['confidence'])) $events[$i]['confidence'] = $d['confidence'];
            if (isset($d['fx']))         $events[$i]['fx']         = $d['fx'];
        }
    }
    foreach ($events as &$ev) { unset($ev['_kind'], $ev['_code']); } unset($ev);   // never leak raw fields to the client JSON
    usort($events, fn($a, $b) => $b['ts'] <=> $a['ts']);
    $ips = []; $failed = 0;
    foreach ($events as $e) { if ($e['actor_ip'] !== '') $ips[$e['actor_ip']] = 1; if ($e['action'] === 'Failed login') $failed++; }
    $stats = ['total'=>count($events), 'attacks'=>$sources['web_attack'], 'panel'=>$sources['cpanel_panel'], 'logins'=>$sources['login'],
        'mail'=>$sources['outbound_mail'], 'webshell'=>$sources['webshell_suspect'], 'ips'=>count($ips), 'failed_logins'=>$failed];
    return ['account'=>$account, 'from'=>$fromTs, 'to'=>$toTs, 'events'=>$events, 'stats'=>$stats, 'sources'=>$sources, 'forensic'=>$forensic];
}

/* =========================================================================================
 *  Forensic enrichment (READ-ONLY). Outcome-classify web attacks from their HTTP status, and — ONLY when
 *  an exploit-class request actually reached the app (2xx/3xx) — run a bounded webroot change-scan
 *  (mirroring smpro_im_breaches) + deep verdict (smpro_fx_deepfile) + whitelist (smpro_fe_wl_match) to
 *  decide whether a malicious file was actually written. Every heavy step is gated, capped, deadline-
 *  bounded and disk-cached. The ONLY write is a cache JSON under SMPRO_CACHE — never an account file.
 * ======================================================================================= */

/** OUTCOME of a web-attack event from its HTTP status (zero I/O). blocked = WAF/client refusal;
 *  reached = 2xx/3xx (request reached the application, boundary mirrors smpro_im_breaches exactly);
 *  other = 404/5xx/empty/non-numeric. */
function smpro_ui_outcome($code) {
    $c = (int)$code;
    if (in_array($c, [400, 401, 403, 406, 429], true)) return 'blocked';
    if ($c >= 200 && $c < 400)                          return 'reached';
    return 'other';
}

/** Is $uri a legitimate authenticated WP-admin endpoint (owner installing a plugin/theme/media), NOT a
 *  drive-by upload? A 200 on wp-admin/update.php?action=upload-plugin is the site owner, not an exploit —
 *  it must not read as "Malicious Upload / confirmed" nor arm the file scan. Display-time reclassification
 *  only (no disk whitelist). */
function smpro_ui_is_wpadmin_legit($uri) {
    $p = (string)parse_url((string)$uri, PHP_URL_PATH); if ($p === '') $p = (string)$uri;
    // ONLY endpoints WordPress core gates behind a logged-in admin session + nonce. admin-ajax.php and
    // async-upload.php are deliberately EXCLUDED — both are reachable by unauthenticated (nopriv) handlers
    // and are primary drive-by upload/RCE vectors, so they must NOT be auto-cleared or excused from the scan.
    return (bool)preg_match('#/wp-admin/(?:update|update-core|plugin-install|theme-install|plugin-editor|theme-editor|media-new|import|press-this)\.php$#i', $p);
}

/** Banner headline + color class for an account verdict. Copy is truthful — green states say "no evidence",
 *  never "safe". $nBlocked used only for the blocked-count phrasing. */
function smpro_ui_verdict_copy($verdict, $nBlocked = 0, $scanned = true) {
    switch ($verdict) {
        case 'compromise_confirmed': return ['Confirmed file impact — a malicious file was written during an exploit-class request that reached the application. Treat this account as compromised until reviewed.', 'red'];
        case 'compromise_suspected': return ['Attacks reached the application and a recently-changed webroot file looks suspicious around the same time — the link is proximity only, not confirmed. Review the flagged file in Forensics.', 'amber'];
        case 'suspicious_file':      return ['A recently-changed webroot file looks suspicious, but no exploit request correlates to it in time — it may be unrelated (a legitimate edit or an older change). Review it in Forensics.', 'amber'];
        case 'attacks_reached':      return [$scanned
            ? 'Exploit-class requests reached the application, but a bounded scan found no malicious file change near them. Verify in Forensics / Audit.'
            : 'Exploit-class requests reached the application; file inspection was unavailable for this account. Verify in Forensics / Audit.', 'amber'];
        case 'attacks_blocked':      return [($nBlocked > 0 ? 'All ' . (int)$nBlocked . ' attack attempt(s) were handled at the WAF' : 'Attack attempts were handled at the WAF') . ' — no exploit-class request reached the application.', 'green'];
        case 'reconnaissance':       return ['Only reconnaissance activity (scanners and probes) was seen — no attempted exploitation reached the application.', 'neutral'];
        default:                     return ['No web attacks of consequence in this window. Note: log retention is limited, so absence of evidence is not proof of safety.', 'green'];
    }
}

/** Prune stale enrichment cache + lock files so the dir can't grow without bound (bounded work per call). */
function smpro_ui_fx_gc($cacheDir) {
    $now = time();
    foreach (array_slice((array)@glob($cacheDir . '/*') ?: [], 0, 500) as $f) {
        if (($now - (int)@filemtime($f)) > 900) @unlink($f);   // > 15 min old → gone (TTL is 5 min)
    }
}

/** Atomic cache write to SMPRO_CACHE (never an account path). */
function smpro_ui_fx_write_cache($cf, $cacheDir, array $out) {
    if (!(@is_dir($cacheDir) || @mkdir($cacheDir, 0700, true))) return;
    $tmp = @tempnam($cacheDir, 'ui'); if (!$tmp) return;
    if (@file_put_contents($tmp, json_encode($out)) === false) { @unlink($tmp); return; }
    @chmod($tmp, 0600); if (!@rename($tmp, $cf)) @unlink($tmp);
}

/** See section header. Returns ['ok'=>false] when the forensic engine is unavailable (caller renders as today). */
function smpro_ui_forensics($account, array $events, $fromTs, $toTs) {
    $t0 = microtime(true);
    $account = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)$account);
    // STEP 0 — degrade guard
    if ($account === '' || !function_exists('smpro_in_by_account') || !function_exists('smpro_im_exploit_kind') || !function_exists('smpro_fx_scope'))
        return ['ok' => false];

    // freshness tokens for the cache key (a new/edited attack row busts the cache)
    $maxAttackTs = 0; $attackCount = 0;
    foreach ($events as $e) if (($e['source'] ?? '') === 'web_attack') { $attackCount++; if ((int)$e['ts'] > $maxAttackTs) $maxAttackTs = (int)$e['ts']; }

    $cacheDir = SMPRO_CACHE . '/uinvest';
    // Bucket the window bounds to 5-min granularity in the KEY so a per-second $toTs (=time()) does not mint a
    // brand-new key every second — that made the cache never hit and grow unbounded. Freshness is still exact:
    // $maxAttackTs + $attackCount change the key the instant a new attack is indexed.
    $bucket = 300; $kFrom = intdiv((int)$fromTs, $bucket) * $bucket; $kTo = intdiv((int)$toTs, $bucket) * $bucket;
    $key = sha1($account . '|' . $kFrom . '|' . $kTo . '|' . SMPRO_VERSION . '|' . $maxAttackTs . '|' . $attackCount);
    $cf  = $cacheDir . '/' . $key . '.json';
    $dbm = defined('SMPRO_IN_DB') ? (int)@filemtime(SMPRO_IN_DB) : 0;   // stat the ACTUAL attacks DB (not smpro.db)
    // STEP 2 — cache read (fresh TTL, and no older than the attacks DB when we can stat it)
    if (is_file($cf) && (time() - (int)@filemtime($cf) < $bucket) && (int)@filemtime($cf) >= $dbm) {
        $cached = json_decode((string)@file_get_contents($cf), true);
        if (is_array($cached) && !empty($cached['ok'])) return $cached;
    }
    // concurrent-render lock — never launch a parallel find storm for the same key
    @is_dir($cacheDir) || @mkdir($cacheDir, 0700, true);
    smpro_ui_fx_gc($cacheDir);   // prune stale cache/lock files so the dir cannot grow without bound
    $lockFp = @fopen($cf . '.lock', 'c');
    $locked = $lockFp ? @flock($lockFp, LOCK_EX | LOCK_NB) : false;
    if ($lockFp && !$locked) {
        // a concurrent render is already computing this key — block briefly for it, then serve its cache
        // rather than launching a parallel find/deepfile storm (the anti-stampede guarantee).
        if (@flock($lockFp, LOCK_EX)) { @flock($lockFp, LOCK_UN); }
        if (is_file($cf)) { $c2 = json_decode((string)@file_get_contents($cf), true); if (is_array($c2) && !empty($c2['ok'])) { @fclose($lockFp); return $c2; } }
        @fclose($lockFp); $lockFp = false;   // still nothing cached → compute inline (unlocked) as a last resort
    }

    $DEADLINE = $t0 + 20.0;
    $modsec = function_exists('smpro_im_modsec_engine_state') ? (string)(smpro_im_modsec_engine_state()['summary'] ?? 'unknown') : 'unknown';
    $decor = []; $blockedN = 0; $reachedN = 0; $reconN = 0;
    $reachedExploit = [];   // build-order index => [domain,ts,kind,ip,uri]

    // STEP 3/4/5 — cheap outcome pass (zero I/O)
    foreach ($events as $i => $e) {
        if (($e['source'] ?? '') !== 'web_attack') continue;
        $kind = (string)($e['_kind'] ?? ''); $code = (string)($e['_code'] ?? ''); $uri = (string)($e['target'] ?? '');
        $outcome = smpro_ui_outcome($code);
        $fx = ['outcome' => $outcome, 'label' => '', 'file' => '', 'band' => '', 'note' => '', 'ts' => 0];
        $conf = $e['confidence'] ?? 'confirmed';
        if ($outcome === 'blocked') {
            $blockedN++; $fx['label'] = 'Blocked by WAF'; $conf = 'confirmed · blocked';
        } elseif ($outcome === 'reached') {
            $reachedN++;
            $isExploit = smpro_im_exploit_kind($kind); $legit = smpro_ui_is_wpadmin_legit($uri);
            if ($isExploit && $legit)       { $fx['label'] = 'Admin action (authenticated WP-admin)'; $conf = 'possible'; }
            elseif ($isExploit)             { $fx['label'] = 'Reached app — exploit-class request, no impact evidence'; $conf = 'reached — no file impact';
                                              // arm the file scan for EVERY reached exploit-class request — the scan is account-scoped
                                              // (docroots), so a missing Host header must not silently skip it.
                                              $reachedExploit[$i] = ['domain'=>(string)($e['domain'] ?? ''),'ts'=>(int)$e['ts'],'kind'=>$kind,'ip'=>(string)($e['actor_ip'] ?? ''),'uri'=>$uri]; }
            else                            { $fx['label'] = 'Reached app (2xx)'; $conf = 'reached'; }
        } else {
            $fx['label'] = 'No impact' . ($code !== '' ? ' (' . preg_replace('/[^0-9]/', '', $code) . ')' : '');
            if ((int)$code === 404 || preg_match('/scanner|recon|sensitive/i', $kind)) $reconN++;
        }
        $decor[$i] = ['confidence' => $conf, 'fx' => $fx];
    }

    // single-return builder (captures the stable context; varying data passed as args)
    $done = function($verdict, $scanned, $impacts, $kpi, $truncated, $degraded, $scannedFiles) use (&$decor, $modsec, $t0, $cf, $cacheDir, $lockFp, $locked) {
        $vc  = smpro_ui_verdict_copy($verdict, $kpi['blocked'], $scanned);
        $out = ['ok'=>true, 'verdict'=>$verdict, 'headline'=>$vc[0], 'color'=>$vc[1], 'modsec'=>$modsec,
                'decorations'=>$decor, 'kpi'=>$kpi, 'impacts'=>$impacts, 'scanned'=>$scanned, 'degraded'=>$degraded,
                'scanned_files'=>(int)$scannedFiles, 'truncated'=>$truncated, 'elapsed_ms'=>(int)round((microtime(true)-$t0)*1000)];
        smpro_ui_fx_write_cache($cf, $cacheDir, $out);
        if ($lockFp) { if ($locked) @flock($lockFp, LOCK_UN); @fclose($lockFp); }
        return $out;
    };
    $kpi0 = ['blocked'=>$blockedN, 'reached'=>$reachedN, 'confirmed_impact'=>0, 'suspicious_files'=>0];

    // STEP 6 — performance gate: no reached-app exploit ⇒ ZERO filesystem I/O
    if (!$reachedExploit) {
        $verdict = $blockedN > 0 ? 'attacks_blocked' : ($reconN > 0 ? 'reconnaissance' : 'clean');
        return $done($verdict, false, [], $kpi0, false, false, 0);
    }

    // STEP 7 — scope + null guard (never pass null to the array-typed $scope)
    $scope = smpro_fx_scope($account);
    if (!is_array($scope) || !function_exists('smpro_fx_deepfile')) return $done('attacks_reached', false, [], $kpi0, false, true, 0);
    $home  = rtrim((string)($scope['home'] ?? (smpro_user_home($account))), '/');
    $roots = (array)($scope['docroots'] ?? []);
    if (!$roots && function_exists('smpro_im_docroots')) $roots = smpro_im_docroots($account);
    if (!$roots && is_dir($home . '/public_html'))       $roots = [$home . '/public_html'];

    // STEP 8/9 — bounded webroot find (mirror smpro_im_breaches) + reuse the FP filter chain verbatim.
    // Every expensive step is deadline-bounded: each find's own timeout is clamped to the time left, and the
    // inner per-file filter chain (sha256 + per-file grep) checks the deadline AND a cumulative-file cap so a
    // docroot with dozens of recently-changed .php files can never push the render past the 20s budget.
    $winMin = max(1, (int)ceil(($toTs - $fromTs) / 60));   // full selected window (cost bounded by find timeout + caps)
    $candidates = []; $seen = []; $rootsSeen = []; $examined = 0; $truncated = false;
    foreach (array_slice($roots, 0, 6) as $root) {
        if (count($candidates) >= 8 || $examined >= 50) break;
        $left = (int)($DEADLINE - microtime(true)); if ($left < 3) { $truncated = true; break; }   // out of budget
        // Resolve symlinked docroots (public_html is frequently a symlink) and scan the REAL target — find
        // won't descend an un-resolved symlink. The realpath-must-stay-under-home check IS the blast-radius
        // guard: a symlink escaping the account's home tree resolves outside $home and is skipped.
        $rp = @realpath((string)$root);
        if (!$rp || strpos($rp . '/', $home . '/') !== 0 || isset($rootsSeen[$rp])) continue;
        $rootsSeen[$rp] = 1;
        $cmd = 'timeout ' . (int)min(14, $left) . ' nice -n ' . SMPRO_SCAN_NICE . ' ionice -c3 find ' . escapeshellarg($rp)
             . ' -maxdepth 6 -type f \\( -name "*.php" -o -name "*.phtml" \\) -mmin -' . (int)$winMin . ' 2>/dev/null | head -n 60';
        foreach (array_filter(explode("\n", (string)@shell_exec($cmd))) as $f) {
            if ($examined >= 50 || microtime(true) > $DEADLINE) { $truncated = true; break 2; }   // honor the budget PER FILE
            if (isset($seen[$f])) continue; $seen[$f] = 1; $examined++;
            if (function_exists('smpro_im_breach_excluded') && smpro_im_breach_excluded($f)) continue;   // Imunify/Wordfence/caches/mu-plugins/WP Guard
            if (function_exists('smpro_im_is_wp_plugin')   && smpro_im_is_wp_plugin($f))   continue;     // admin-installed plugin (Plugin Name header)
            if (function_exists('smpro_im_wl_suppress')    && smpro_im_wl_suppress($account, $f)) continue; // operator-whitelisted, not re-armed
            if (function_exists('smpro_im_looks_malicious')&& !smpro_im_looks_malicious($f)) continue;   // only web-shell-looking files survive
            $candidates[] = $f;
            if (count($candidates) >= 8) break;
        }
    }

    // STEP 10 — deep verdict (≤5 executed, deadline-guarded). Only medium+ non-trusted files become impacts.
    $impacts = []; $deepRun = 0; $selfCache = [];
    foreach ($candidates as $path) {
        if ($deepRun >= 5 || microtime(true) > $DEADLINE) { if (count($candidates) > $deepRun) $truncated = true; break; }
        $st = @lstat($path); $ck = $path . '|' . (int)($st['mtime'] ?? 0) . '|' . (int)($st['size'] ?? 0);
        $deep = $selfCache[$ck] ?? ($selfCache[$ck] = smpro_fx_deepfile($path, $scope));
        $deepRun++;
        if (empty($deep['exists']) || !empty($deep['wp_guard_trusted'])) continue;   // trusted files are capped at info — not an impact
        $band = (string)($deep['band'] ?? 'clean');
        if (!in_array($band, ['medium', 'high', 'critical'], true)) continue;
        $note = '';
        if (function_exists('smpro_fe_wl_match')) { $m = smpro_fe_wl_match($account, $path, $deep['sha256'] ?? null, $deep['size'] ?? null); if (is_array($m)) $note = ($m['mode'] === 'rearm' ? 'Whitelisted but re-armed — ' : '') . (string)($m['note'] ?? ''); }
        $impacts[] = ['path'=>$path, 'band'=>$band, 'mtime'=>(int)($deep['mtime'] ?? 0), 'ctime'=>(int)($deep['ctime'] ?? 0),
                      'families'=>array_values((array)($deep['families_seen'] ?? [])), 'nested'=>!empty($deep['nested_chain']),
                      'note'=>$note, 'proof'=>'mtime_only', 'corr_i'=>null];
    }

    // STEP 11 — Tier-1 correlation (free): nearest reached-exploit event within ±30 min
    foreach ($impacts as &$imp) {
        $best = null; $bestD = PHP_INT_MAX;
        if ($imp['mtime'] > 0) foreach ($reachedExploit as $i => $re) { $d = abs($imp['mtime'] - $re['ts']); if ($d <= 1800 && $d < $bestD) { $bestD = $d; $best = $i; } }
        $imp['corr_i'] = $best;
    } unset($imp);

    // STEP 12 — Tier-2 correlation (bounded, ≤3 calls, each deadline-capped): only for high/critical + Tier-1 hit.
    // proof precedence: only 'write_at_request' (a dir-scoped WRITE_CANDIDATE at the file's write time) PROVES a
    // write. 'attack_in_window' is domain-wide traffic near the time — corroborating, NOT proof of THIS file.
    $corrRun = 0;
    foreach ($impacts as &$imp) {
        if ($imp['corr_i'] === null || !in_array($imp['band'], ['high', 'critical'], true)) continue;
        if ($corrRun >= 3 || !function_exists('smpro_fw_correlate')) break;
        $left = $DEADLINE - microtime(true); if ($left < 3) { $truncated = true; break; }
        $corrRun++;
        $c = @smpro_fw_correlate($account, $imp['path'], $imp['mtime'], $imp['ctime'], $reachedExploit[$imp['corr_i']]['ts'], 1800, microtime(true) + min(6.0, $left));
        if (!empty($c['possible_drop']))   $imp['proof'] = 'write_at_request';
        elseif (!empty($c['attack_hit']))  $imp['proof'] = 'attack_in_window';
    } unset($imp);

    // STEP 13/14 — classify impacts, decorate correlated events, account verdict.
    //   confirmed  = write PROVEN at the request time (possible_drop) on a high/critical file
    //   correlated = a medium+ file whose mtime is within ±30min of a reached exploit (proximity, not proof)
    //   loose      = a medium+ suspicious file with NO time correlation (may be an unrelated/legit edit)
    $confirmed = 0; $correlated = 0; $loose = 0;
    foreach ($impacts as $imp) {
        $isConfirmed = $imp['proof'] === 'write_at_request' && in_array($imp['band'], ['high', 'critical'], true);
        $i = $imp['corr_i'];
        if     ($isConfirmed) $confirmed++;
        elseif ($i !== null)  $correlated++;
        else                  $loose++;
        if ($i === null || !isset($decor[$i])) continue;
        $decor[$i]['fx']['outcome'] = 'impact';
        $decor[$i]['fx']['file']    = $imp['path'];
        $decor[$i]['fx']['band']    = $imp['band'];
        $decor[$i]['fx']['ts']      = $imp['mtime'];
        $decor[$i]['fx']['note']    = $imp['note'];
        if ($isConfirmed) { $decor[$i]['confidence'] = 'compromise'; $decor[$i]['fx']['label'] = 'Confirmed impact — malicious file written at the request time'; }
        else              { $decor[$i]['confidence'] = 'possible';   $decor[$i]['fx']['label'] = 'Possible impact — suspicious file changed near this request'; }
    }
    if     ($confirmed > 0)  $verdict = 'compromise_confirmed';
    elseif ($correlated > 0) $verdict = 'compromise_suspected';   // a real proximity link exists
    elseif ($loose > 0)      $verdict = 'suspicious_file';        // suspicious file, but no correlated request
    else                     $verdict = 'attacks_reached';        // exploit reached, nothing suspicious found nearby
    $kpi = ['blocked'=>$blockedN, 'reached'=>$reachedN, 'confirmed_impact'=>$confirmed, 'suspicious_files'=>count($impacts)];
    return $done($verdict, !empty($rootsSeen), array_slice($impacts, 0, 8), $kpi, $truncated, false, $deepRun);
}
