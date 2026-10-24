<?php
/* The event filters (is_local_ip / filter_local / count_local / filter_country) live in includes/breakin.php,
   beside the collector whose output they narrow: they decide what the page COUNTS, and a number nobody can
   reproduce outside the page is a number nobody can check. */
/**
 * modules/account-audit.php - Account activity audit (read-only).
 * Reads cPanel login_log + access_log, filtered by user/type/date range/log-lines.
 * Adds IP intelligence (country/provider/ASN via Team Cymru whois + cache),
 * CSV export, and 90-day saved reports. Target of the "Audit" relation from
 * Top Processes (?page=account-audit&audit_user=<user>).
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

define('SMPRO_AA_IPCACHE',   SMPRO_VARLIB . '/cache/ipintel.json');
define('SMPRO_AA_IPTTL',     30 * 86400);
define('SMPRO_AA_IPMAXNEW',  40);
define('SMPRO_AA_REPORTS',   SMPRO_VARLIB . '/reports');
define('SMPRO_AA_REPIDX',    SMPRO_VARLIB . '/reports/index.json');
define('SMPRO_AA_RETENTION', 90 * 86400);

// Login & Access engine (merged in as tabs). Library: defines functions only.
require_once __DIR__ . '/login-monitor.php';

/* ===================================================================
 * WEB ACTIVITY tab - per-account analysis of Apache domlogs
 * (uploads / downloads / file access / errors / visitors).
 * =================================================================== */
function smpro_aa_domlogs_base() {
    foreach (['/usr/local/apache/domlogs', '/etc/apache2/logs/domlogs', '/var/log/apache2/domlogs'] as $p) if (is_dir($p)) return $p;
    return '';
}
function smpro_aa_web_logfiles($user) {
    $base = smpro_aa_domlogs_base(); if ($base === '' || !smpro_is_cpanel_user($user)) return [];
    $files = [];
    foreach (smpro_aa_user_domains($user) as $d) foreach ([$d, $d . '-ssl_log'] as $f) {
        $p = $base . '/' . $f; if (is_file($p) && is_readable($p)) $files[] = $p;
    }
    return array_values(array_unique($files));
}
function smpro_aa_web_filetype($path) {
    if (!preg_match('/\.([a-z0-9]{1,6})(?:$|\?)/i', $path, $m)) return 'page';
    $e = strtolower($m[1]);
    if (in_array($e, ['zip','rar','tar','gz','tgz','7z','bz2','xz'], true)) return 'archive';
    if (in_array($e, ['mp4','mkv','avi','mov','webm','mp3','wav','flv','m3u8','ts','m4a'], true)) return 'media';
    if (in_array($e, ['jpg','jpeg','png','gif','webp','svg','ico','bmp'], true)) return 'image';
    if (in_array($e, ['pdf','doc','docx','xls','xlsx','ppt','pptx','csv','txt'], true)) return 'document';
    if (in_array($e, ['js','css','map','woff','woff2','ttf','eot'], true)) return 'asset';
    if (in_array($e, ['php','asp','aspx','cgi','pl','py','jsp'], true)) return 'script';
    return 'other';
}
function smpro_aa_web_collect($user, $tail) {
    $files = smpro_aa_web_logfiles($user);
    $o = ['ok' => (bool)$files, 'files' => count($files), 'total' => 0, 'bytes' => 0,
          'methods' => [], 'status' => ['2xx'=>0,'3xx'=>0,'4xx'=>0,'5xx'=>0], 'paths' => [], 'dl' => [], 'types' => [],
          'ips' => [], 'uas' => [], 'uploads' => [], 'errors' => [], 'recent' => []];
    if (!$files) return $o;
    $perFile = max(3000, (int)($tail / max(1, count($files))));
    foreach ($files as $f) {
        // domain that owns this log (for the full URL = host + path)
        $dom = preg_replace('/-(ssl_log|bytes_log)$/', '', basename($f));
        $scheme = (substr(basename($f), -8) === '-ssl_log') ? 'https://' : 'http://';
        $raw = (string)@shell_exec('timeout 30 nice -n ' . SMPRO_SCAN_NICE . ' tail -n ' . $perFile . ' ' . escapeshellarg($f) . ' 2>/dev/null');
        foreach (explode("\n", $raw) as $l) {
            if (!preg_match('/^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+[^"]*"\s+(\d{3})\s+(\S+)\s+"([^"]*)"\s+"([^"]*)"/', $l, $m)) continue;
            $ip = $m[1]; $method = strtoupper($m[4]); $path = $m[5]; $status = (int)$m[6]; $bytes = $m[7] === '-' ? 0 : (int)$m[7]; $ua = $m[9];
            $url = $scheme . $dom . $path;   // full URL (no truncation)
            $o['total']++; $o['bytes'] += $bytes;
            $o['methods'][$method] = ($o['methods'][$method] ?? 0) + 1;
            $cls = intdiv($status, 100); if ($cls >= 2 && $cls <= 5) $o['status'][$cls . 'xx']++;
            if (!isset($o['paths'][$url])) $o['paths'][$url] = ['hits'=>0,'bytes'=>0]; $o['paths'][$url]['hits']++; $o['paths'][$url]['bytes'] += $bytes;
            $type = smpro_aa_web_filetype($path); $o['types'][$type] = ($o['types'][$type] ?? 0) + $bytes;
            if ($bytes > 0 && in_array($type, ['archive','media','document','image'], true)) { if (!isset($o['dl'][$url])) $o['dl'][$url] = ['hits'=>0,'bytes'=>0,'type'=>$type]; $o['dl'][$url]['hits']++; $o['dl'][$url]['bytes'] += $bytes; }
            $o['ips'][$ip] = ($o['ips'][$ip] ?? 0) + 1;
            $o['uas'][$ua] = ($o['uas'][$ua] ?? 0) + 1;
            if ($method === 'POST' || $method === 'PUT') { $o['uploads'][$url] = ($o['uploads'][$url] ?? 0) + 1; }
            if ($status >= 400) { if (!isset($o['errors'][$url])) $o['errors'][$url] = ['hits'=>0,'status'=>$status]; $o['errors'][$url]['hits']++; }
            $o['recent'][] = ['ip'=>$ip,'method'=>$method,'path'=>$url,'status'=>$status,'bytes'=>$bytes,'date'=>$m[3]];
        }
    }
    arsort($o['methods']); arsort($o['ips']); arsort($o['uas']); arsort($o['uploads']); arsort($o['types']);
    uasort($o['paths'], fn($a,$b) => $b['hits'] <=> $a['hits']);
    uasort($o['dl'], fn($a,$b) => $b['bytes'] <=> $a['bytes']);
    uasort($o['errors'], fn($a,$b) => $b['hits'] <=> $a['hits']);
    $o['recent'] = array_slice(array_reverse($o['recent']), 0, 200);
    return $o;
}
/** Everything one IP did across ALL web logs (domlogs, server-wide, bounded). */
function smpro_aa_ip_web($ip) {
    $base = smpro_aa_domlogs_base();
    if ($base === '' || !filter_var($ip, FILTER_VALIDATE_IP)) return null;
    static $own = null;
    if ($own === null) { $own = []; if (is_readable('/etc/userdomains')) foreach (file('/etc/userdomains', FILE_IGNORE_NEW_LINES) ?: [] as $l) if (preg_match('/^([^:]+):\s*(\S+)/', $l, $m)) $own[strtolower(trim($m[1]))] = trim($m[2]); }
    // -F IP (no trailing space - matches the client field regardless of the exact separator); exclude the
    // big *-bytes_log files at grep level for speed on busy boxes; generous but bounded timeout.
    $cmd = 'timeout 60 nice -n ' . SMPRO_SCAN_NICE . ' ionice -c3 grep -rHaF --exclude=' . escapeshellarg('*-bytes_log') . ' ' . escapeshellarg($ip) . ' ' . escapeshellarg($base) . ' 2>/dev/null | grep -vE "bytes_log:|ftpxferlog|/ftp" | head -n 8000';
    $raw = (string)@shell_exec($cmd);
    $o = ['ip' => $ip, 'total' => 0, 'bytes' => 0, 'accounts' => [], 'domains' => [], 'urls' => [], 'methods' => [], 'status' => ['2xx'=>0,'3xx'=>0,'4xx'=>0,'5xx'=>0], 'recent' => []];
    foreach (explode("\n", $raw) as $line) {
        $c = strpos($line, ':'); if ($c === false) continue;
        $file = substr($line, 0, $c); $log = substr($line, $c + 1);
        if (strpos($file, $base) !== 0) continue;
        $dom = preg_replace('/-(ssl_log|bytes_log)$/', '', basename($file));
        $scheme = (substr(basename($file), -8) === '-ssl_log') ? 'https://' : 'http://';
        // Parse the request/status/bytes from the "..." quote - position-independent, so a leading
        // %v vhost field (some cPanel LogFormats) no longer makes the whole line unparse.
        if (!preg_match('/\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+[^"]*"\s+(\d{3})\s+(\S+)/', $log, $m)) continue;
        // require the request to come FROM this IP: it must be the 1st field (combined) or 2nd (vhost-combined),
        // NOT merely appear in a URL/referer/UA.
        $f0 = strtok(ltrim($log), " \t"); $f1 = strtok(" \t");
        if ($f0 !== $ip && $f1 !== $ip) continue;
        $m = [0, $f0, $m[1], $m[2], $m[3], $m[4], $m[5]];   // realign to the old capture indices used below
        $method = strtoupper($m[3]); $url = $scheme . $dom . $m[4]; $status = (int)$m[5]; $bytes = $m[6] === '-' ? 0 : (int)$m[6];
        $o['total']++; $o['bytes'] += $bytes;
        $o['domains'][$dom] = ($o['domains'][$dom] ?? 0) + 1;
        $acct = $own[strtolower($dom)] ?? '?'; $o['accounts'][$acct] = ($o['accounts'][$acct] ?? 0) + 1;
        $o['methods'][$method] = ($o['methods'][$method] ?? 0) + 1;
        $cls = intdiv($status, 100); if ($cls >= 2 && $cls <= 5) $o['status'][$cls . 'xx']++;
        if (!isset($o['urls'][$url])) $o['urls'][$url] = ['hits'=>0,'bytes'=>0]; $o['urls'][$url]['hits']++; $o['urls'][$url]['bytes'] += $bytes;
        $o['recent'][] = ['url'=>$url, 'method'=>$method, 'status'=>$status, 'bytes'=>$bytes, 'date'=>$m[2], 'dom'=>$dom];
    }
    arsort($o['accounts']); arsort($o['domains']); arsort($o['methods']);
    uasort($o['urls'], fn($a,$b) => $b['hits'] <=> $a['hits']);
    $o['recent'] = array_slice($o['recent'], -150);
    $o['recent'] = array_reverse($o['recent']);
    return $o;
}
/** Every LOGIN / AUTH attempt one IP made across ALL services (SSH, mail, FTP, cPanel/WHM/webmail) -
 *  not just the cPanel access logs. This is what makes a "login-problem" IP (mail/SSH/FTP brute-force)
 *  actually show up in the report instead of appearing as "no activity". Bounded + recent-focused. */
function smpro_aa_ip_auth($ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return null;
    $ipq = escapeshellarg($ip);
    $o = ['ip' => $ip, 'total' => 0, 'failed' => 0, 'success' => 0, 'services' => [], 'users' => [], 'first_ts' => 0, 'last_ts' => 0, 'recent' => []];
    // (log => default service hint). Content-based classification below wins; the hint is a fallback.
    $sources = [
        ['/var/log/secure', 'ssh'], ['/var/log/auth.log', 'ssh'],
        ['/var/log/exim_mainlog', 'mail'], ['/var/log/maillog', 'mail'], ['/var/log/mail.log', 'mail'],
        ['/var/log/messages', 'ftp'], ['/usr/local/cpanel/logs/login_log', 'cpanel'],
        ['/usr/local/cpanel/logs/access_log', 'cpanel'],
    ];
    $curYear = (int)date('Y');
    $budgetStart = microtime(true); $truncated = false;
    foreach ($sources as $src) {
        [$file, $hint] = $src;
        if (!is_readable($file)) continue;
        if (microtime(true) - $budgetStart > 32) { $truncated = true; break; }   // hard wall-clock budget for a busy shared box
        // read only the recent tail (fast on huge busy-box logs - seeks near EOF), grep the IP, keep the last matches
        $raw = (string)@shell_exec('timeout 12 sh -c ' . escapeshellarg('tail -n 250000 ' . escapeshellarg($file) . ' 2>/dev/null | grep -aF ' . $ipq . ' | tail -n 500') . ' 2>/dev/null');
        foreach (explode("\n", $raw) as $l) {
            $l = trim($l); if ($l === '' || strpos($l, $ip) === false) continue;
            // service classification (content beats the file hint)
            $svc = $hint;
            if (stripos($l, 'sshd') !== false || stripos($l, 'ssh2') !== false) $svc = 'ssh';
            elseif (preg_match('/pure-?ftpd|proftpd|ftpd|pure-authd/i', $l)) $svc = 'ftp';
            elseif (preg_match('/dovecot|imap-login|pop3-login|authenticator failed|_login authenticator|exim|set_id=|A=(dovecot|courier)/i', $l)) $svc = 'mail';
            elseif (preg_match('/whostmgrd|cpaneld|webmaild|cpsrvd|LOGIN\b/i', $l)) $svc = (stripos($l, 'webmaild') !== false || stripos($l, 'webmail') !== false) ? 'webmail' : 'cpanel';
            // result
            $failed = (bool)preg_match('/Failed|Invalid|failure|Incorrect|authentication (failed|error)|rejected|denied|not allowed|refused|FAILED LOGIN|DEFERRED|access denied|negativ/i', $l);
            $success = !$failed && (bool)preg_match('/Accepted|SUCCEEDED LOGIN|SUCCESS|authentication succeeded|logged in|session opened/i', $l);
            if (!$failed && !$success) {
                // only keep auth-relevant lines (skip generic noise that merely mentions the IP)
                if (!preg_match('/login|auth|password|sshd|ftpd|dovecot|LOGIN/i', $l)) continue;
                $failed = true; // an auth-context line we can't classify -> treat as an attempt
            }
            // targeted username
            $user = '';
            if ($svc === 'ssh') { if (preg_match('/for (?:invalid user )?([^\s]+) from/i', $l, $um)) $user = $um[1]; elseif (preg_match('/invalid user ([^\s]+)/i', $l, $um)) $user = $um[1]; }
            elseif ($svc === 'mail') { if (preg_match('/set_id=([^\s)]+)/i', $l, $um)) $user = $um[1]; elseif (preg_match('/U=([^\s]+)/', $l, $um)) $user = $um[1]; elseif (preg_match('/for user \[?([^\]\s]+)/i', $l, $um)) $user = $um[1]; }
            elseif ($svc === 'ftp') { if (preg_match('/user \[([^\]]+)\]/i', $l, $um)) $user = $um[1]; elseif (preg_match('/Authentication failed for user \[?([^\]\s]+)/i', $l, $um)) $user = $um[1]; }
            else { if (preg_match('/\]\s+' . preg_quote($ip, '/') . '\s+-\s+([^\s"]+)/', $l, $um)) $user = rawurldecode($um[1]); }
            $user = trim($user, "[]\"' "); if ($user === '-' ) $user = '';
            // timestamp (several formats)
            $ts = 0;
            if (preg_match('/^\[([^\]]+)\]/', $l, $tm)) $ts = smpro_aa_ts($tm[1]);                                       // cpanel [2026-.. ]
            elseif (preg_match('/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/', $l, $tm)) $ts = strtotime($tm[1]);            // exim
            elseif (preg_match('/^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/', $l, $tm)) $ts = strtotime($tm[1] . ' ' . $curYear); // syslog
            $o['total']++; if ($failed) $o['failed']++; if ($success) $o['success']++;
            $o['services'][$svc] = ($o['services'][$svc] ?? 0) + 1;
            if ($user !== '') $o['users'][$user] = ($o['users'][$user] ?? 0) + 1;
            if ($ts) { $o['first_ts'] = $o['first_ts'] ? min($o['first_ts'], $ts) : $ts; $o['last_ts'] = max($o['last_ts'], $ts); }
            if (count($o['recent']) < 400) $o['recent'][] = ['ts' => $ts, 'svc' => $svc, 'result' => $failed ? 'failed' : ($success ? 'success' : 'attempt'), 'user' => $user, 'line' => function_exists('smpro_redact_sensitive') ? smpro_redact_sensitive(mb_substr($l, 0, 300)) : mb_substr($l, 0, 300)];
        }
    }
    arsort($o['services']); arsort($o['users']);
    usort($o['recent'], fn($a, $b) => ($b['ts'] ?? 0) <=> ($a['ts'] ?? 0));
    $o['recent'] = array_slice($o['recent'], 0, 200);
    $o['truncated'] = $truncated;
    return $o;
}

/** IP investigation header + web-activity-by-IP, shown when the audit search is an IP. */
function smpro_aa_ip_investigation_render($ip) {
    $in = function_exists('smpro_ip_intel') ? smpro_ip_intel($ip) : [];
    $cc = strtoupper((string)($in['country'] ?? '')); $bot = function_exists('smpro_ip_is_datacenter') && smpro_ip_is_datacenter($in);
    $bytes = fn($b) => function_exists('smpro_bytes') ? smpro_bytes((int)$b) : number_format($b);
    ?>
    <div class="card aa-ipban">
      <div class="aa-ipl"><span class="aa-ipip"><?= smpro_h($ip) ?></span>
        <?php if ($cc!==''&&$cc!=='N/A'): ?><span class="b blue"><?= smpro_h($cc) ?></span><?php endif; ?>
        <?php if (!empty($in['provider'])&&$in['provider']!=='n/a'): ?><span class="meta"><?= smpro_h($in['provider']) ?></span><?php endif; ?>
        <?php if (!empty($in['asn'])): ?><span class="meta">(<?= smpro_h($in['asn']) ?>)</span><?php endif; ?>
        <?php if ($bot): ?><span class="b red">&#129302; datacenter / bot</span><?php endif; ?>
        <?php if (($in['scope']??'')==='local'): ?><span class="b gray">local / server IP</span><?php endif; ?>
      </div>
      <div class="meta" style="font-size:12px">Full IP investigation — login &amp; access attempts across ALL services (SSH · mail · FTP · cPanel/WHM/webmail) plus every web request this IP made across all accounts.</div>
    </div>
    <?php
    // ---- LOGIN / AUTH attempts across ALL services (the part that shows a brute-forcer's real activity) ----
    $au = function_exists('smpro_aa_ip_auth') ? smpro_aa_ip_auth($ip) : null;
    if ($au && $au['total'] > 0):
        $svcLabel = ['ssh'=>'SSH','mail'=>'Mail (IMAP/POP/SMTP)','ftp'=>'FTP','cpanel'=>'cPanel / WHM','webmail'=>'Webmail'];
        $span = ($au['first_ts'] && $au['last_ts']) ? (date('Y-m-d H:i', $au['first_ts']) . ' → ' . date('Y-m-d H:i', $au['last_ts'])) : '';
    ?>
    <div class="card" id="aa-ip-login" style="padding:0;overflow:hidden;margin-bottom:14px;border-top:3px solid var(--dang)">
      <div class="tp-th"><b>&#128272; Login &amp; access attempts by <?= smpro_h($ip) ?></b><span class="meta"><?= number_format($au['total']) ?> attempts · <span style="color:var(--dang);font-weight:700"><?= number_format($au['failed']) ?> failed</span> · <?= number_format($au['success']) ?> succeeded<?= $span ? ' · ' . smpro_h($span) : '' ?><?= !empty($au['truncated']) ? ' · <span style="color:#c47f17">partial (time-limited scan)</span>' : '' ?></span></div>
      <div class="wa-row" style="margin:0;border-bottom:1px solid var(--line);grid-template-columns:repeat(3,1fr)">
        <div class="wa-mini"><div class="wa-h">Services hit</div><?php foreach ($au['services'] as $sv=>$n): ?><div class="wa-line"><span><?= smpro_h($svcLabel[$sv] ?? $sv) ?></span><b><?= number_format($n) ?></b></div><?php endforeach; ?></div>
        <div class="wa-mini"><div class="wa-h">Targeted usernames (top)</div><?php $ui=0; foreach ($au['users'] as $un=>$n){ if($ui++>=10)break; ?><div class="wa-line"><span class="mono" style="font-size:11.5px;word-break:break-all"><?= smpro_h($un) ?></span><b><?= number_format($n) ?></b></div><?php } if(!$au['users']){ ?><div class="wa-line meta">—</div><?php } ?></div>
        <div class="wa-mini"><div class="wa-h">Outcome</div><div class="wa-line"><span class="b red">Failed</span><b><?= number_format($au['failed']) ?></b></div><div class="wa-line"><span class="b green">Succeeded</span><b><?= number_format($au['success']) ?></b></div><div class="wa-line"><span class="b gray">Attempts</span><b><?= number_format($au['total']) ?></b></div></div>
      </div>
      <div class="tp-th" style="border-top:0"><b>Recent login attempts</b><span class="meta">newest first · redacted</span></div>
      <div class="wa-tw" style="max-height:360px"><table class="smpro-table"><thead><tr><th>Time</th><th>Service</th><th>Result</th><th>User</th><th>Evidence</th></tr></thead><tbody>
        <?php foreach ($au['recent'] as $r): ?><tr>
          <td class="mono" style="font-size:11px"><?= $r['ts'] ? smpro_h(date('Y-m-d H:i:s', $r['ts'])) : '—' ?></td>
          <td><?= smpro_h($svcLabel[$r['svc']] ?? $r['svc']) ?></td>
          <td><span class="b <?= $r['result']==='failed'?'red':($r['result']==='success'?'green':'gray') ?>"><?= smpro_h($r['result']) ?></span></td>
          <td class="mono" style="font-size:11px"><?= smpro_h($r['user']) ?: '—' ?></td>
          <td class="ev" style="font-family:ui-monospace,Consolas,monospace;font-size:11px;color:var(--muted);word-break:break-all"><?= smpro_h($r['line']) ?></td>
        </tr><?php endforeach; ?>
      </tbody></table></div>
    </div>
    <?php endif; ?>
    <?php
    $w = smpro_aa_ip_web($ip);
    if (($w === null || !$w['total'])) {
        if (!$au || !$au['total']) echo '<div class="card" style="color:var(--muted)">No login attempts or web requests from this IP were found in the retained logs. It may be older than the current logs (they rotate), or the activity is on a service this host does not log here. Try again, or widen the window.</div>';
        else echo '<div class="card" style="color:var(--muted)">No Apache web requests from this IP — its activity is login/mail/SSH/FTP (shown above), not web browsing.</div>';
        return;
    }
    ?>
    <div class="card" id="aa-ip-web" style="padding:0;overflow:hidden;margin-bottom:14px;border-top:3px solid var(--brand)">
      <div class="tp-th"><b>&#127760; Web requests by <?= smpro_h($ip) ?></b><span class="meta"><?= number_format($w['total']) ?> requests · <?= $bytes($w['bytes']) ?> served · <?= count($w['accounts']) ?> account(s)</span></div>
      <div class="wa-row" style="margin:0;border-bottom:1px solid var(--line);grid-template-columns:repeat(4,1fr)">
        <div class="wa-mini"><div class="wa-h">Accounts hit</div><?php foreach (array_slice($w['accounts'],0,8,true) as $a=>$n): ?><div class="wa-line"><a class="fa-lnk" href="index.cgi?page=account-audit&tab=webact&audit_user=<?= urlencode($a) ?>"><?= smpro_h($a) ?></a><b><?= number_format($n) ?></b></div><?php endforeach; ?></div>
        <div class="wa-mini"><div class="wa-h">Domains hit</div><?php foreach (array_slice($w['domains'],0,8,true) as $dm=>$n): ?><div class="wa-line"><span class="mono" style="font-size:11.5px;word-break:break-all"><?= smpro_h($dm) ?></span><b><?= number_format($n) ?></b></div><?php endforeach; ?></div>
        <div class="wa-mini"><div class="wa-h">Methods</div><?php foreach ($w['methods'] as $mt=>$n): ?><div class="wa-line"><span class="b <?= $mt==='GET'?'gray':($mt==='POST'?'blue':'orange') ?>"><?= smpro_h($mt) ?></span><b><?= number_format($n) ?></b></div><?php endforeach; ?></div>
        <div class="wa-mini"><div class="wa-h">Status</div><?php foreach (['2xx'=>'green','3xx'=>'gray','4xx'=>'orange','5xx'=>'red'] as $sc=>$cl): ?><div class="wa-line"><span class="b <?= $cl ?>"><?= $sc ?></span><b><?= number_format($w['status'][$sc]) ?></b></div><?php endforeach; ?></div>
      </div>
      <div class="tp-th" style="border-top:0"><b>Top URLs by this IP</b><span class="meta">aggregated · most-hit first</span></div>
      <div class="wa-tw" style="max-height:300px"><table class="smpro-table"><thead><tr><th class="num">Hits</th><th class="num">Bytes</th><th>URL</th></tr></thead><tbody>
        <?php $i=0; foreach ($w['urls'] as $u=>$r){ if($i++>=40)break; ?><tr><td class="num"><b><?= number_format($r['hits']) ?></b></td><td class="num meta"><?= $r['bytes']?$bytes($r['bytes']):'—' ?></td><td class="mono wa-file"><?= smpro_h($u) ?></td></tr><?php } ?>
      </tbody></table></div>
      <div class="tp-th" style="border-top:0"><b>Recent requests</b><span class="meta">full URL · newest first</span></div>
      <div class="wa-tw" style="max-height:420px"><table class="smpro-table"><thead><tr><th>Time</th><th>Method</th><th class="num">Status</th><th class="num">Bytes</th><th>URL</th></tr></thead><tbody>
        <?php foreach ($w['recent'] as $r): ?><tr><td class="mono" style="font-size:11px"><?= smpro_h(preg_replace('#^(\d+/\w+/\d+):#','$1 ',$r['date'])) ?></td><td><span class="b <?= $r['method']==='GET'?'gray':($r['method']==='POST'?'blue':'orange') ?>"><?= smpro_h($r['method']) ?></span></td><td class="num"><span class="b <?= $r['status']>=500?'red':($r['status']>=400?'orange':($r['status']>=300?'gray':'green')) ?>"><?= (int)$r['status'] ?></span></td><td class="num meta"><?= $r['bytes']?$bytes($r['bytes']):'—' ?></td><td class="mono wa-file"><?= smpro_h($r['url']) ?></td></tr><?php endforeach; ?>
      </tbody></table></div>
    </div>
    <style>.aa-ipban{margin-bottom:14px}.aa-ipl{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:4px}.aa-ipip{font-family:ui-monospace,Consolas,monospace;font-weight:800;font-size:18px}
    .wa-row{display:grid;grid-template-columns:1fr 1fr 1fr;gap:1px;background:var(--line)}.wa-mini{background:var(--card);padding:12px 14px}.wa-h{font-size:11px;font-weight:700;color:var(--muted);text-transform:uppercase;margin-bottom:6px}.wa-line{display:flex;justify-content:space-between;align-items:center;padding:3px 0;font-size:12.5px}
    .wa-tw{overflow:auto}.wa-tw thead th{position:sticky;top:0;background:var(--card);z-index:1;box-shadow:inset 0 -1px 0 var(--line)}.wa-file{white-space:normal;word-break:break-all;max-width:640px;font-size:11.5px}
    .b.blue{background:var(--brand-bg);color:var(--brand)}.fa-lnk{color:var(--brand);text-decoration:none;font-size:11px;border:1px solid var(--line);padding:1px 7px;border-radius:6px}</style>
    <?php
}
/** Render the Web Activity tab for $user (Apache domlogs analysis). */
function smpro_aa_web_render($user) {
    $base = smpro_aa_domlogs_base();
    $lines = (int)($_GET['weblines'] ?? 60000); if (!in_array($lines, [20000,60000,150000,400000], true)) $lines = 60000;
    $bytes = fn($b) => function_exists('smpro_bytes') ? smpro_bytes((int)$b) : number_format($b);
    ?>
    <p class="sub" style="margin:0 0 12px">Every web request for this account from its Apache logs — uploads, downloads, file access, errors and visitors. Outgoing bytes are the response size served (downloads); uploads are detected by POST/PUT.</p>
    <form method="get" action="index.cgi" class="card wa-bar">
      <input type="hidden" name="page" value="account-audit"><input type="hidden" name="tab" value="webact">
      <label class="wa-fld">cPanel account<input class="tp-in" name="audit_user" value="<?= smpro_h($user) ?>" placeholder="start typing…" data-ac="accounts" autocomplete="off"></label>
      <label class="wa-fld">Log lines<select class="tp-sel" name="weblines"><?php foreach ([20000=>'20k',60000=>'60k',150000=>'150k',400000=>'400k'] as $k=>$v): ?><option value="<?= $k ?>"<?= $lines===$k?' selected':'' ?>><?= $v ?></option><?php endforeach; ?></select></label>
      <button class="tp-btn primary" type="submit" data-scan="Reading the account’s web logs…">&#127760; Analyze web activity</button>
    </form>
    <?php
    if ($base === '') { echo '<div class="card" style="color:var(--muted)">No Apache domlogs directory found on this host (looked in /usr/local/apache/domlogs).</div>'; return; }
    if ($user === '' || !smpro_is_cpanel_user($user)) { echo '<div class="card" style="color:var(--muted)">Pick a cPanel account above to analyse its web traffic.</div>'; return; }
    $d = smpro_aa_web_collect($user, $lines);
    if (!$d['ok']) { echo '<div class="card" style="color:var(--muted)">No readable web logs found for <b>' . smpro_h($user) . '</b> (no domains or empty logs).</div>'; return; }
    $errRate = $d['total'] ? round(($d['status']['4xx'] + $d['status']['5xx']) / $d['total'] * 100, 1) : 0;
    if ($d['ips']) smpro_ip_intel_bulk(array_keys(array_slice($d['ips'], 0, 30, true)), true);
    ?>
    <div class="wa-kpis">
      <div class="wa-kpi"><div class="kn"><?= number_format($d['total']) ?></div><div class="kl">Requests</div><div class="km"><?= (int)$d['files'] ?> log file(s)</div></div>
      <div class="wa-kpi dn"><div class="kn"><?= $bytes($d['bytes']) ?></div><div class="kl">Served (downloads ↓)</div></div>
      <div class="wa-kpi up"><div class="kn"><?= number_format(($d['methods']['POST'] ?? 0) + ($d['methods']['PUT'] ?? 0)) ?></div><div class="kl">Upload requests ↑</div><div class="km">POST / PUT</div></div>
      <div class="wa-kpi"><div class="kn"><?= number_format(count($d['ips'])) ?></div><div class="kl">Unique visitors</div></div>
      <div class="wa-kpi <?= $errRate>=10?'crit':'' ?>"><div class="kn"><?= $errRate ?>%</div><div class="kl">Error rate</div><div class="km"><?= number_format($d['status']['4xx']) ?>×4xx · <?= number_format($d['status']['5xx']) ?>×5xx</div></div>
    </div>

    <div class="wa-row">
      <div class="card wa-mini"><div class="wa-h">Methods</div><?php foreach (array_slice($d['methods'],0,6,true) as $mth=>$n): ?><div class="wa-line"><span class="b <?= $mth==='GET'?'gray':($mth==='POST'?'blue':'orange') ?>"><?= smpro_h($mth) ?></span><b><?= number_format($n) ?></b></div><?php endforeach; ?></div>
      <div class="card wa-mini"><div class="wa-h">Status</div>
        <?php foreach (['2xx'=>'green','3xx'=>'gray','4xx'=>'orange','5xx'=>'red'] as $sc=>$cl): ?><div class="wa-line"><span class="b <?= $cl ?>"><?= $sc ?></span><b><?= number_format($d['status'][$sc]) ?></b></div><?php endforeach; ?>
      </div>
      <div class="card wa-mini"><div class="wa-h">Bytes by type (served)</div><?php foreach (array_slice($d['types'],0,6,true) as $tp=>$bt): if(!$bt)continue; ?><div class="wa-line"><span class="meta"><?= smpro_h($tp) ?></span><b><?= $bytes($bt) ?></b></div><?php endforeach; ?></div>
    </div>

    <div class="ar-two">
      <div class="card" style="padding:0;overflow:hidden">
        <div class="tp-th"><b>&#128229; Uploads (POST / PUT endpoints)</b><span class="meta">incoming — where data is posted</span></div>
        <div class="wa-tw"><table class="smpro-table"><thead><tr><th>Endpoint</th><th class="num">Requests</th></tr></thead><tbody>
          <?php if(!$d['uploads']): ?><tr><td colspan="2" class="wa-empty">No uploads in this window.</td></tr><?php else: $i=0; foreach($d['uploads'] as $p=>$n){ if($i++>=20)break; ?><tr><td class="mono wa-file"><?= smpro_h($p) ?></td><td class="num"><?= number_format($n) ?></td></tr><?php } endif; ?>
        </tbody></table></div>
      </div>
      <div class="card" style="padding:0;overflow:hidden">
        <div class="tp-th"><b>&#128230; Top downloads (largest served)</b><span class="meta">outgoing files by bytes</span></div>
        <div class="wa-tw"><table class="smpro-table"><thead><tr><th>File</th><th>Type</th><th class="num">Hits</th><th class="num">Bytes</th></tr></thead><tbody>
          <?php if(!$d['dl']): ?><tr><td colspan="4" class="wa-empty">No file downloads in this window.</td></tr><?php else: $i=0; foreach($d['dl'] as $p=>$r){ if($i++>=20)break; ?><tr><td class="mono wa-file"><?= smpro_h($p) ?></td><td><span class="b gray"><?= smpro_h($r['type']) ?></span></td><td class="num"><?= number_format($r['hits']) ?></td><td class="num"><b><?= $bytes($r['bytes']) ?></b></td></tr><?php } endif; ?>
        </tbody></table></div>
      </div>
    </div>

    <div class="ar-two">
      <div class="card" style="padding:0;overflow:hidden">
        <div class="tp-th"><b>Top requested files / paths</b></div>
        <div class="wa-tw"><table class="smpro-table"><thead><tr><th>Path</th><th class="num">Hits</th><th class="num">Bytes</th></tr></thead><tbody>
          <?php $i=0; foreach($d['paths'] as $p=>$r){ if($i++>=25)break; ?><tr><td class="mono wa-file"><?= smpro_h($p) ?></td><td class="num"><?= number_format($r['hits']) ?></td><td class="num meta"><?= $bytes($r['bytes']) ?></td></tr><?php } ?>
        </tbody></table></div>
      </div>
      <div class="card" style="padding:0;overflow:hidden">
        <div class="tp-th"><b>Top visitors (IPs)</b></div>
        <div class="wa-tw"><table class="smpro-table"><thead><tr><th>IP</th><th>Country / Bot</th><th class="num">Hits</th><th>Audit</th></tr></thead><tbody>
          <?php $i=0; foreach($d['ips'] as $ip=>$n){ if($i++>=25)break; $in=smpro_ip_intel($ip,false); $cc=strtoupper((string)($in['country']??'')); $bot=smpro_ip_is_datacenter($in); ?>
            <tr><td class="ipmono"><?= smpro_h($ip) ?></td><td class="meta"><?= $cc&&$cc!=='N/A'?'<b>'.smpro_h($cc).'</b> ':'' ?><?= smpro_h($in['provider']??'') ?><?= $bot?' <span class="b red">&#129302; bot</span>':'' ?></td><td class="num"><?= number_format($n) ?></td><td><a class="fa-lnk" href="index.cgi?page=account-audit&do=search&q=<?= urlencode($ip) ?>&loglines=200000">Audit</a></td></tr>
          <?php } ?>
        </tbody></table></div>
      </div>
    </div>

    <div class="ar-two">
      <div class="card" style="padding:0;overflow:hidden">
        <div class="tp-th"><b>&#9888; Errors (4xx / 5xx)</b><span class="meta">broken links · forbidden · probes</span></div>
        <div class="wa-tw" style="max-height:300px"><table class="smpro-table"><thead><tr><th>Path</th><th class="num">Status</th><th class="num">Hits</th></tr></thead><tbody>
          <?php if(!$d['errors']): ?><tr><td colspan="3" class="wa-empty" style="color:var(--good)">&#10003; No errors in this window.</td></tr><?php else: $i=0; foreach($d['errors'] as $p=>$r){ if($i++>=25)break; ?><tr><td class="mono wa-file"><?= smpro_h($p) ?></td><td class="num"><span class="b <?= $r['status']>=500?'red':'orange' ?>"><?= (int)$r['status'] ?></span></td><td class="num"><?= number_format($r['hits']) ?></td></tr><?php } endif; ?>
        </tbody></table></div>
      </div>
      <div class="card" style="padding:0;overflow:hidden">
        <div class="tp-th"><b>Top user-agents</b></div>
        <div class="wa-tw" style="max-height:300px"><table class="smpro-table"><tbody>
          <?php $i=0; foreach($d['uas'] as $ua=>$n){ if($i++>=20)break; ?><tr><td class="mono wa-file" style="font-size:11px"><?= smpro_h($ua?:'—') ?></td><td class="num"><?= number_format($n) ?></td></tr><?php } ?>
        </tbody></table></div>
      </div>
    </div>

    <div class="card" style="padding:0;overflow:hidden">
      <div class="tp-th"><b>Recent requests</b><span class="meta">newest first · last <?= count($d['recent']) ?></span></div>
      <div class="wa-tw" style="max-height:420px"><table class="smpro-table"><thead><tr><th>Time</th><th>Method</th><th class="num">Status</th><th class="num">Bytes</th><th>Path</th><th>IP</th></tr></thead><tbody>
        <?php foreach($d['recent'] as $r): ?><tr><td class="mono" style="font-size:11px"><?= smpro_h(preg_replace('#^(\d+/\w+/\d+):#','$1 ',$r['date'])) ?></td><td><span class="b <?= $r['method']==='GET'?'gray':($r['method']==='POST'?'blue':'orange') ?>"><?= smpro_h($r['method']) ?></span></td><td class="num"><span class="b <?= $r['status']>=500?'red':($r['status']>=400?'orange':($r['status']>=300?'gray':'green')) ?>"><?= (int)$r['status'] ?></span></td><td class="num meta"><?= $r['bytes']?$bytes($r['bytes']):'—' ?></td><td class="mono wa-file"><?= smpro_h($r['path']) ?></td><td class="ipmono" style="font-size:11px"><?= smpro_h($r['ip']) ?></td></tr><?php endforeach; ?>
      </tbody></table></div>
    </div>

    <style>
    .wa-bar{display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap;margin:0 0 14px;padding:14px 16px}
    .wa-fld{display:flex;flex-direction:column;gap:5px;font-size:11px;text-transform:uppercase;color:var(--muted);font-weight:700}
    .wa-kpis{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:0 0 14px}@media(max-width:900px){.wa-kpis{grid-template-columns:repeat(2,1fr)}}
    .wa-kpi{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px;text-align:center}
    .wa-kpi.dn{border-top:3px solid var(--good)}.wa-kpi.up{border-top:3px solid var(--brand)}.wa-kpi.crit{border-top:3px solid var(--dang)}
    .wa-kpi .kn{font-size:22px;font-weight:800;line-height:1}.wa-kpi .kl{font-size:11px;text-transform:uppercase;color:var(--muted);margin-top:6px;font-weight:700}.wa-kpi .km{font-size:11px;color:var(--muted);margin-top:2px}
    .wa-kpi.crit .kn{color:var(--dang)}.wa-kpi.dn .kn{color:var(--good)}.wa-kpi.up .kn{color:var(--brand)}
    .wa-row{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px;margin:0 0 14px}@media(max-width:760px){.wa-row{grid-template-columns:1fr}}
    .wa-mini{padding:14px 16px}.wa-h{font-size:12px;font-weight:700;color:var(--muted);text-transform:uppercase;margin-bottom:8px}
    .wa-line{display:flex;justify-content:space-between;align-items:center;padding:4px 0;font-size:13px}
    .ar-two{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin:0 0 14px}@media(max-width:900px){.ar-two{grid-template-columns:1fr}}
    .wa-tw{overflow:auto;max-height:360px}.wa-tw thead th{position:sticky;top:0;background:var(--card);z-index:1;box-shadow:inset 0 -1px 0 var(--line)}
    .wa-file{white-space:normal;word-break:break-all;max-width:640px;font-size:11.5px}.wa-empty{padding:16px;text-align:center;color:var(--muted)}
    .tp-th{display:flex;align-items:center;gap:10px;padding:12px 16px;border-bottom:1px solid var(--line);font-weight:700;font-size:14px}.tp-th .meta{margin-left:auto;color:var(--muted);font-size:12px}
    .ipmono{font-family:ui-monospace,Consolas,monospace;font-weight:700}.b.blue{background:var(--brand-bg);color:var(--brand)}
    </style>
    <?php
}


/* ---------- log reading ---------- */









/* ---------- IP intelligence (cached, capped) ---------- */










/* ---------- saved reports + retention ---------- */
function smpro_aa_purge_old() {
    $idx = smpro_aa_json_load(SMPRO_AA_REPIDX); $now = time(); $changed = false;
    foreach ($idx as $id => $meta) {
        if (($now - (int)($meta['created_ts'] ?? 0)) > SMPRO_AA_RETENTION) {
            if (!empty($meta['path']) && is_file($meta['path'])) @unlink($meta['path']);
            unset($idx[$id]); $changed = true;
        }
    }
    if ($changed) smpro_aa_json_save(SMPRO_AA_REPIDX, $idx);
}
function smpro_aa_save_report($user, $params, $events, $summary) {
    smpro_aa_purge_old();
    $id = date('Ymd_His') . '_' . substr(hash('sha256', $user . json_encode($params) . uniqid('', true)), 0, 10);
    $path = SMPRO_AA_REPORTS . '/' . date('Ym') . '/' . $id . '.json';
    smpro_aa_json_save($path, ['id' => $id, 'created_at' => date('c'), 'audit_user' => $user, 'params' => $params, 'summary' => $summary, 'events' => $events]);
    $idx = smpro_aa_json_load(SMPRO_AA_REPIDX);
    $idx[$id] = ['id' => $id, 'created_at' => date('c'), 'created_ts' => time(), 'audit_user' => $user,
                 'from_date' => $params['from'], 'to_date' => $params['to'], 'event_type' => $params['type'], 'total' => $summary['total'], 'path' => $path];
    smpro_aa_json_save(SMPRO_AA_REPIDX, $idx);
    return $id;
}
function smpro_aa_delete_report($id) {
    $id = preg_replace('/[^a-zA-Z0-9_-]/', '', (string)$id);
    if ($id === '') return false;
    $idx = smpro_aa_json_load(SMPRO_AA_REPIDX);
    if (!isset($idx[$id])) return false;
    $p = (string)($idx[$id]['path'] ?? '');
    if ($p !== '' && strpos($p, SMPRO_AA_REPORTS) === 0 && is_file($p)) @unlink($p);
    unset($idx[$id]);
    smpro_aa_json_save(SMPRO_AA_REPIDX, $idx);
    return true;
}
function smpro_aa_saved_for($user) {
    $idx = smpro_aa_json_load(SMPRO_AA_REPIDX); $rows = [];
    foreach ($idx as $m) { if (!is_array($m)) continue; if ($user !== '' && ($m['audit_user'] ?? '') !== $user) continue; $rows[] = $m; }
    usort($rows, fn($a, $b) => ($b['created_ts'] ?? 0) <=> ($a['created_ts'] ?? 0));
    return array_slice($rows, 0, 12);
}

/** Standalone HTML/PDF report (self-contained, no app chrome). */
function smpro_aa_render_report($events, $meta, $print = false) {
    $sum = ['total' => count($events), 'success' => 0, 'failed' => 0, 'ips' => []];
    foreach ($events as $e) {
        if (($e['kind'] ?? '') === 'success_login') $sum['success']++;
        if (($e['kind'] ?? '') === 'failed_login') $sum['failed']++;
        if (!empty($e['ip'])) $sum['ips'][$e['ip']] = true;
    }
    $h = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $title = 'Account Audit Report' . ($meta['user'] ? ' — ' . $meta['user'] : ' — all users');
    echo "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>" . $h($title) . "</title>\n";
    echo "<style>
*{box-sizing:border-box}body{font:13px/1.5 -apple-system,Segoe UI,Arial,sans-serif;color:#1f2733;margin:0;padding:28px;background:var(--card)}
h1{font-size:20px;margin:0 0 4px}.muted{color:#6b7686;font-size:12px;margin:0 0 16px}
.cards{display:flex;gap:10px;flex-wrap:wrap;margin:0 0 18px}
.c{border:1px solid #e6eaf1;border-radius:10px;padding:10px 14px;min-width:120px}
.c .l{font-size:10px;text-transform:uppercase;color:#6b7686;letter-spacing:.04em}.c .v{font-size:20px;font-weight:700}
table{width:100%;border-collapse:collapse;font-size:12px}
th,td{border:1px solid #e6eaf1;padding:6px 8px;text-align:left;vertical-align:top}
th{background:var(--bg);font-size:10px;text-transform:uppercase;color:#475569}
.b{display:inline-block;font-size:10px;font-weight:700;padding:1px 7px;border-radius:20px}
.green{background:var(--good-bg);color:#1f9d55}.red{background:var(--dang-bg);color:#d93b3b}.gray{background:var(--card);color:#475569}.orange{background:var(--warn-bg);color:#c47f17}
.ev{font-family:ui-monospace,Consolas,monospace;font-size:11px;color:#475569;word-break:break-all}
.head{display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:10px}
.brand{font-weight:700;color:#3b5bdb}
@media print{body{padding:0}.noprint{display:none}}
</style></head><body>";
    // Period: when a bound was left open, show the actual oldest->newest detected in the events.
    if (($meta['from'] ?? '') === '' || ($meta['to'] ?? '') === '') {
        $mn = 0; $mx = 0; foreach ($events as $e) { $t = (int)($e['ts'] ?? 0); if ($t) { $mn = $mn ? min($mn, $t) : $t; $mx = max($mx, $t); } }
        $periodStr = ($mn && $mx) ? (date('Y-m-d H:i', $mn) . ' → ' . date('Y-m-d H:i', $mx) . ' (full available range)') : 'full available range';
    } else { $periodStr = $h($meta['from']) . ' → ' . $h($meta['to']); }
    echo "<div class=\"head\"><div><h1>" . $h($title) . "</h1>"
       . "<p class=\"muted\">Period " . $periodStr . " · event type: " . $h($meta['type'])
       . " · generated " . $h(date('Y-m-d H:i:s')) . (isset($meta['saved_id']) ? ' · saved ' . $h($meta['saved_id']) : '') . "</p></div>"
       . "<div class=\"brand\">&#128737; Safety Monitor Pro</div></div>";
    echo "<div class=\"cards\">"
       . "<div class=\"c\"><div class=\"l\">Total</div><div class=\"v\">" . (int)$sum['total'] . "</div></div>"
       . "<div class=\"c\"><div class=\"l\">Successful</div><div class=\"v\">" . (int)$sum['success'] . "</div></div>"
       . "<div class=\"c\"><div class=\"l\">Failed</div><div class=\"v\">" . (int)$sum['failed'] . "</div></div>"
       . "<div class=\"c\"><div class=\"l\">Unique IPs</div><div class=\"v\">" . count($sum['ips']) . "</div></div></div>";
    echo "<table><thead><tr><th>Time</th><th>Type</th><th>Service</th><th>IP / Country / Provider</th><th>Login User</th><th>Account</th><th>Action</th><th>Evidence</th></tr></thead><tbody>";
    if (!$events) {
        echo "<tr><td colspan=\"8\" style=\"text-align:center;color:#6b7686;padding:18px\">No events.</td></tr>";
    } else foreach ($events as $e) {
        $i = smpro_aa_ip_intel($e['ip'] ?? '');
        $cls = ($e['kind'] ?? '') === 'success_login' ? 'green' : (($e['kind'] ?? '') === 'failed_login' ? 'red' : 'gray');
        $ipline = $h($e['ip'] ?? '');
        if (!empty($i['country']) && $i['country'] !== 'n/a') $ipline .= '<br>' . $h($i['country']);
        if (!empty($i['provider']) && $i['provider'] !== 'n/a') $ipline .= ' · ' . $h($i['provider']);
        if (!empty($i['asn'])) $ipline .= ' (' . $h($i['asn']) . ')';
        echo "<tr><td>" . $h($e['time'] ?? '') . "</td><td><span class=\"b $cls\">" . $h($e['type'] ?? '') . "</span></td>"
           . "<td>" . $h($e['service'] ?? '') . "</td><td>" . $ipline . "</td>"
           . "<td>" . $h($e['login_user'] ?? '') . "</td><td>" . $h($e['account'] ?? '') . "</td>"
           . "<td>" . $h($e['action'] ?? '') . "</td><td class=\"ev\">" . $h($e['evidence'] ?? '') . "</td></tr>";
    }
    echo "</tbody></table>";
    if ($print) echo "<script>window.onload=function(){setTimeout(function(){window.print();},300);};</script>";
    echo "</body></html>";
}

/* ---------- break-in report: ignored networks (ASN or country key) ---------- */
// SMPRO_AA_BFIGN now lives in includes/breakin.php, beside the functions that read it, and index.php loads
// that before any module. Defining it here as well produced a duplicate the moment both files were loaded
// together - and a guarded define does not survive the test extractor, which keeps the define() and drops
// the if() around it. One definition, in the file that uses it.






function smpro_aa_bf_rank($v) { return ['block' => 0, 'watch' => 1, 'normal' => 2][$v] ?? 1; }

/**
 * The facts about one network that may leave this server for a third-party AI endpoint.
 *
 * NUMBERS AND NAMES ONLY: how many addresses, how many attempts, how many accounts, which doors, over how long,
 * cloud or not, provider and country. No IP address, no account name, no log line ever goes out. The AI is asked
 * to judge a shape, and a shape is all it needs - which also means there is nothing here worth redacting.
 */
function smpro_aa_bf_facts(array $nv): array {
    $as = smpro_aa_bf_assess($nv);
    return [
        'key'      => smpro_aa_bf_key($nv),
        'provider' => substr((string)($nv['provider'] ?? ''), 0, 80),
        'country'  => (string)($nv['cc'] ?? ''),
        'cloud'    => !empty($nv['bot']),
        'addresses'=> count((array)($nv['ips'] ?? [])),
        'attempts' => (int)($nv['fails'] ?? 0),
        'accounts' => count((array)($nv['users'] ?? [])),
        'services' => array_values(array_map('strval', array_keys((array)($nv['services'] ?? [])))),
        'span_min' => (int)round(max(0, (int)($nv['last'] ?? 0) - (int)($nv['first'] ?? 0)) / 60),
        'rules_say'=> $as['verdict'],
    ];
}

/** Normalise one network's facts as they come back from the page, so a tampered field cannot reach the prompt. */
function smpro_aa_bf_facts_clean($n): ?array {
    if (!is_array($n)) return null;
    $key = preg_replace('/[^A-Za-z0-9:_.-]/', '', (string)($n['key'] ?? ''));
    if ($key === '') return null;
    $svc = [];
    foreach (array_slice((array)($n['services'] ?? []), 0, 6) as $x) { $x = preg_replace('/[^a-zA-Z0-9_.-]/', '', (string)$x); if ($x !== '') $svc[] = $x; }
    return [
        'key'      => $key,
        'provider' => preg_replace('/[^\x20-\x7E]/', '', substr((string)($n['provider'] ?? ''), 0, 80)),
        'country'  => strtoupper(preg_replace('/[^A-Za-z]/', '', (string)($n['country'] ?? ''))),
        'cloud'    => !empty($n['cloud']),
        'addresses'=> max(0, min(100000, (int)($n['addresses'] ?? 0))),
        'attempts' => max(0, min(10000000, (int)($n['attempts'] ?? 0))),
        'accounts' => max(0, min(100000, (int)($n['accounts'] ?? 0))),
        'services' => $svc,
        'span_min' => max(0, min(525600, (int)($n['span_min'] ?? 0))),
        'rules_say'=> in_array((string)($n['rules_say'] ?? ''), ['block','watch','normal'], true) ? (string)$n['rules_say'] : 'watch',
    ];
}

/**
 * Ask the AI to judge each network. It RECOMMENDS; it never blocks, allow-lists or ignores anything - the buttons
 * stay where they were and the operator presses them. A network the AI does not mention keeps the rules' verdict,
 * so a short or malformed answer degrades to what the page already said rather than to silence.
 */
function smpro_aa_bf_ai_review(array $nets): array {
    if (!function_exists('smpro_ai_available') || !smpro_ai_available())
        return ['ok' => false, 'error' => 'No AI provider is configured. Set one up in AI Providers, then run this again.', 'rows' => []];
    if (!$nets) return ['ok' => true, 'rows' => [], 'provider' => ''];

    $sys = 'You are a hosting security analyst reviewing FAILED LOGIN attempts against a cPanel/WHM server, grouped '
         . 'by the network each address belongs to. For every network decide: "block" (an attack — blocking is right), '
         . '"watch" (could be a person or an attack — the operator should look before acting), or "keep" (not an attack '
         . '— blocking would cost more than it saves). Judge the shape of the traffic: many accounts tried = password '
         . 'spraying; many addresses from one provider = one actor renting addresses; a high per-address rate = a script; '
         . 'one address, one account, a few attempts = a wrong saved password. A cloud/hosting network is never a real '
         . 'customer signing in. Search and archive crawlers never attempt a login, so none of these is a crawler. '
         . 'Say plainly what blocking would cost if you are wrong. '
         . 'Answer ONLY with JSON: {"rows":[{"key":"...","decision":"block|watch|keep","reason":"one or two sentences"}]}';
    $r = smpro_ai_chat_json($sys, json_encode(['networks' => array_slice($nets, 0, 60)], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
        ['max_tokens' => 1800, 'temperature' => 0, 'context' => 'breakin_review']);
    if (empty($r['ok']) || !is_array($r['data'] ?? null))
        return ['ok' => false, 'error' => (string)($r['error'] ?? 'The AI did not return a usable answer.'), 'rows' => [], 'provider' => (string)($r['provider'] ?? '')];

    $byKey = []; foreach ($nets as $n) $byKey[$n['key']] = $n;
    $rows = [];
    foreach ((array)($r['data']['rows'] ?? []) as $x) {
        $k = preg_replace('/[^A-Za-z0-9:_.-]/', '', (string)($x['key'] ?? ''));
        if ($k === '' || !isset($byKey[$k]) || isset($rows[$k])) continue;          // only networks we actually asked about
        $d = (string)($x['decision'] ?? '');
        if (!in_array($d, ['block', 'watch', 'keep'], true)) $d = 'watch';
        $rows[$k] = ['key' => $k, 'decision' => $d,
                     'reason' => substr(trim(preg_replace('/\s+/', ' ', (string)($x['reason'] ?? ''))), 0, 400),
                     'agrees' => ($d === 'block') === ($byKey[$k]['rules_say'] === 'block')];
    }
    return ['ok' => true, 'rows' => array_values($rows), 'provider' => (string)($r['provider'] ?? ''), 'model' => (string)($r['model'] ?? '')];
}

/** The Break-in Report page: every network that tried to break in, with a decision per network. */
function smpro_aa_bf_render(array $human, array $bots, array $ignored, array $trusted, string $back, $totalIps, $totalFails, $homeLabel) {
    $row = function (array $nv, $mode) {
        $cnt = count($nv['ips']); $key = smpro_aa_bf_key($nv); $ips = implode(',', array_map(fn($x) => $x['ip'], $nv['ips']));
        $ccName = $nv['cc'] !== '' ? (function_exists('smpro_cc_name') ? smpro_cc_name($nv['cc']) : $nv['cc']) : 'several countries';
        $as = smpro_aa_bf_assess($nv); ?>
        <div class="aa-net aa-v-<?= smpro_h($as['verdict']) ?>" data-key="<?= smpro_h($key) ?>" data-facts="<?= smpro_h(json_encode(smpro_aa_bf_facts($nv), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)) ?>">
          <div class="aa-net-head">
            <div class="aa-net-id"><b><?= smpro_h($nv['provider']) ?></b>
              <span class="aa-net-meta"><?= $nv['asn'] !== '' ? smpro_h($nv['asn']) . ' &middot; ' : '' ?><?= smpro_h($ccName) ?><?= !empty($nv['bot']) ? ' &middot; cloud/hosting (automated scanner)' : ' &middot; residential / business network' ?></span>
              <?php if ($mode === 'ignored'): ?><span class="aa-net-meta">ignored by <?= smpro_h($nv['ign']['by'] ?? '') ?> on <?= smpro_h(date('Y-m-d', (int)($nv['ign']['at'] ?? 0))) ?></span><?php endif; ?>
            </div>
            <div class="aa-net-num"><span class="aa-vpill <?= smpro_h($as['verdict']) ?>"><?= smpro_h($as['label']) ?></span> <b><?= $cnt ?></b> address<?= $cnt === 1 ? '' : 'es' ?> &middot; <b><?= number_format($nv['fails']) ?></b> attempts</div>
            <div class="aa-bf-acts">
              <?php if ($mode !== 'ignored'): ?>
              <button class="tp-btn danger aaBlockNet" type="button" data-ips="<?= smpro_h($ips) ?>" data-label="<?= smpro_h($nv['provider']) ?>">Block all <?= $cnt ?></button>
              <button class="tp-btn aaBfAllow" type="button" data-ips="<?= smpro_h($ips) ?>" data-label="<?= smpro_h($nv['provider']) ?>" title="Add these addresses to the firewall allow-list (never blocked)">Allow-list</button>
              <button class="tp-btn aaBfIgnore" type="button" data-key="<?= smpro_h($key) ?>" data-label="<?= smpro_h($nv['provider']) ?>" title="Stop showing this network in the report and the banner">Ignore</button>
              <?php else: ?>
              <button class="tp-btn aaBfUnignore" type="button" data-key="<?= smpro_h($key) ?>">Show again</button>
              <?php endif; ?>
            </div>
          </div>
          <div class="aa-why"><b><?= smpro_h($as['what']) ?>.</b> <?= smpro_h(implode(' · ', $as['why'])) ?></div>
          <details class="aa-net-det"><summary>show the addresses</summary>
            <div class="aa-geobar-list">
              <?php foreach ($nv['ips'] as $bx): ?>
              <span class="aa-geochip"><?= smpro_h($bx['ip']) ?> &middot; <b><?= (int)$bx['n'] ?></b><?= ($bx['user'] ?? '') !== '' ? ' &middot; ' . smpro_h($bx['user']) : '' ?>
                <?php if ($mode !== 'ignored'): ?><button class="tp-btn danger aaBlock" type="button" data-ip="<?= smpro_h($bx['ip']) ?>">Block</button><?php endif; ?></span>
              <?php endforeach; ?>
            </div>
          </details>
        </div>
    <?php }; ?>
<style>
.aa-bf-acts{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
.aa-bf-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:12px 0 16px}
.aa-bf-kpi{background:var(--card,#fff);border:1px solid var(--line,#e5e7eb);border-radius:10px;padding:10px 12px}.aa-bf-kpi .n{font-size:24px;font-weight:800}.aa-bf-kpi .l{font-size:12px;opacity:.75}
.aa-bf-sec{margin:20px 0 8px;display:flex;align-items:baseline;gap:10px}.aa-bf-sec h2{margin:0;font-size:16px}.aa-bf-sec .meta{font-size:12.5px;opacity:.75}
.aa-bf-empty{opacity:.7;padding:10px 4px;font-size:13px}
.aa-vpill{display:inline-block;font-size:10.5px;font-weight:800;letter-spacing:.03em;text-transform:uppercase;padding:2px 8px;border-radius:999px;margin-right:6px}
.aa-vpill.block{background:rgba(220,38,38,.12);color:#dc2626}.aa-vpill.watch{background:rgba(180,83,9,.14);color:#b45309}.aa-vpill.normal{background:rgba(107,114,128,.14);color:#4b5563}
.aa-net.aa-v-block{border-left:4px solid #dc2626}.aa-net.aa-v-watch{border-left:4px solid #b45309}.aa-net.aa-v-normal{border-left:4px solid #9ca3af}
.aa-why{font-size:12.5px;line-height:1.6;opacity:.9;margin:4px 0 6px}
.aa-ai{font-size:12.5px;line-height:1.6;margin:2px 0 8px;padding:7px 10px;border-radius:8px;background:rgba(99,102,241,.08);border:1px solid rgba(99,102,241,.22)}
.aa-ai b{font-weight:800}
.aa-ai .d{display:inline-block;font-size:10.5px;font-weight:800;letter-spacing:.03em;text-transform:uppercase;padding:2px 8px;border-radius:999px;margin-right:6px}
.aa-ai .d.block{background:rgba(220,38,38,.12);color:#dc2626}.aa-ai .d.watch{background:rgba(180,83,9,.14);color:#b45309}.aa-ai .d.keep{background:rgba(5,150,105,.14);color:#059669}
.aa-ai .dis{color:#b45309;font-weight:700}
.tp-btn.aa-rec{outline:2px solid rgba(99,102,241,.65);outline-offset:1px}
</style>
<?php
$aaBfOv = [
  ['id' => 'aa-bf-human', 'l' => 'Addresses', 'v' => number_format((int)$totalIps), 'cls' => $totalIps ? 'warn' : 'good', 's' => 'tried to break in'],
  ['id' => 'bfr', 'l' => 'Failed attempts', 'v' => number_format((int)$totalFails), 'cls' => $totalFails ? 'dang' : 'good', 's' => 'in the scanned log window'],
  ['id' => 'aa-bf-human', 'l' => 'Residential / business', 'v' => (string)count($human), 'cls' => $human ? 'warn' : 'good', 's' => 'networks worth a look'],
  ['id' => 'aa-bf-cloud', 'l' => 'Cloud / hosting', 'v' => (string)count($bots), 'cls' => $bots ? 'brand' : 'good', 's' => 'automated scanner networks'],
  ['id' => 'aa-bf-ignored', 'l' => 'Ignored', 'v' => (string)count($ignored), 'cls' => 'muted', 's' => 'networks hidden until shown again'],
];
$aaBfNav = array_values(array_filter([
  (function_exists('smpro_bfr_cfg') || @is_file(SMPRO_BASE . '/includes/bfrules.php')) ? ['bfr', '&#9889; Auto-block rules'] : null,
  ['aa-bf-human', '&#127968; Residential / business'], ['aa-bf-cloud', '&#9729; Cloud / hosting'], $trusted ? ['aa-bf-allow', '&#10003; Allow-listed'] : null, ['aa-bf-ignored', '&#128065; Ignored'],
]));
?>
<div class="fw-kpis">
  <?php foreach ($aaBfOv as $k): ?>
  <a class="fw-kpi <?= $k['cls'] ?>" href="<?= isset($k['href']) ? smpro_h($k['href']) : '#' . $k['id'] ?>"<?= isset($k['href']) ? '' : ' data-go="' . $k['id'] . '"' ?>><div class="l"><?= smpro_h($k['l']) ?></div><div class="v"><?= smpro_h($k['v']) ?></div><div class="s"><?= smpro_h($k['s']) ?></div></a>
  <?php endforeach; ?>
</div>
<nav class="fw-nav" id="fwNav"><?php foreach ($aaBfNav as [$id, $lbl]): ?><a href="#<?= $id ?>" data-go="<?= $id ?>"><?= $lbl ?></a><?php endforeach; ?><span class="sp"></span><button type="button" class="fw-navx" id="fwOpenAll">expand all</button><button type="button" class="fw-navx" id="fwCloseAll">collapse all</button></nav>
<div class="card" style="padding:16px 18px">
  <div style="display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:baseline">
    <div><b style="font-size:16px">&#9888;&#65039; Break-in report</b><details class="gl-fold"><summary><span class="fw-chev gl-chev">&#9656;</span>How this works</summary><div class="meta">Failed logins grouped by the network each address belongs to: a run from one provider is one attacker renting many addresses, so the decision is made per network. Home region: <?= smpro_h($homeLabel) ?>. Addresses inside it, and private/local ones, are never blocked here — that check runs again on the server for every address. Each network carries a verdict: <span class="aa-vpill block">Attack — block</span> <span class="aa-vpill watch">Look first</span> <span class="aa-vpill normal">Probably not an attack</span> — with the numbers behind it. Search and archive crawlers never attempt a login, so none of these is a crawler.</div></details></div>
    <div style="display:flex;gap:8px;align-items:center">
      <?php if (function_exists('smpro_ai_available') && smpro_ai_available()): ?>
      <button class="tp-btn" id="aaBfAi" type="button" title="Ask the configured AI to judge every network below. It recommends only — nothing is blocked, allow-listed or ignored by this button.">&#129302; AI review</button>
      <?php else: ?>
      <span class="meta" title="Configure a provider in AI Providers to enable the AI second opinion">&#129302; AI review — no provider configured</span>
      <?php endif; ?>
      <a class="tp-btn" href="<?= smpro_h($back) ?>">&larr; Back to Account Audit</a>
    </div>
  </div>
  <div id="aaBfAiPanel" hidden style="margin:10px 0 4px;padding:10px 12px;border:1px solid var(--line,#e5e7eb);border-radius:10px;font-size:13px"></div>
  <?php
  /* Rules that act on the verdicts below, without a person present.
     Every decision comes from smpro_aa_bf_assess() -- the same function that writes the sentence on each card --
     so what gets blocked is exactly what this page already called an attack, and the recorded reason is that
     same sentence. The rules add no detection of their own. */
  if (!function_exists('smpro_bfr_cfg')) { $bfrF = SMPRO_BASE . '/includes/bfrules.php'; if (@is_file($bfrF)) require_once $bfrF; }
  if (function_exists('smpro_bfr_cfg')):
    $bfrCfg = smpro_bfr_cfg(); $bfrPats = smpro_bfr_patterns();
    $bfrState = empty($bfrCfg['enabled']) ? 'off' : (!empty($bfrCfg['dryrun']) ? 'dry run' : 'ARMED');
  ?>
  <div class="card" id="bfr" style="padding:0;overflow:hidden;margin:10px 0 12px">
    <div class="tp-th"><b>&#9889; Block these automatically</b>
      <span class="meta">An attack that starts at 3am runs until somebody opens this page. These rules act on the verdicts below without waiting for that.</span>
      <span style="flex:1"></span>
      <span class="ph-badge" style="background:<?= $bfrState === 'ARMED' ? 'rgba(220,38,38,.12)' : ($bfrState === 'dry run' ? 'rgba(180,83,9,.14)' : 'rgba(107,114,128,.16)') ?>"><?= smpro_h($bfrState) ?></span>
    </div>
    <div style="padding:12px 14px">
      <details class="gl-fold"><summary><span class="fw-chev gl-chev">&#9656;</span>How this works</summary>
      <p class="meta" style="margin:0 0 10px;line-height:1.7">
        A rule can ask for <b>more</b> evidence than this page needs, never less &mdash; below the threshold the page
        does not call it an attack at all, so a lower rule would be blocking on its own "not sure".
        Only <b>Attack &mdash; block</b> is ever actioned: <b>Look first</b> exists because the evidence was not conclusive.
        Allow-listed addresses, your own address, Cloudflare edges and forward-confirmed crawlers are refused at the
        firewall itself, so no rule here can take a search engine off this server.
      </p>
      </details>
      <div style="overflow-x:auto"><table class="smpro-table"><thead><tr>
        <th style="width:30px"></th><th>Pattern</th><th>What it means</th><th style="width:150px">Block when at least</th></tr></thead><tbody>
      <?php foreach ($bfrPats as $bk => $bp): $br = $bfrCfg['rules'][$bk] ?? ['enabled' => false, 'min' => $bp['default_min']]; ?>
        <tr>
          <td><input type="checkbox" class="bfrOn" data-k="<?= smpro_h($bk) ?>"<?= !empty($br['enabled']) ? ' checked' : '' ?>></td>
          <td><b><?= smpro_h($bp['title']) ?></b></td>
          <td class="meta"><?= smpro_h($bp['means']) ?></td>
          <td><input type="number" class="tp-in bfrMin" data-k="<?= smpro_h($bk) ?>" style="width:74px"
                     min="<?= (int)$bp['floor'] ?>" value="<?= (int)$br['min'] ?>">
              <span class="meta"><?= smpro_h($bp['unit']) ?></span>
              <div class="meta" style="font-size:11px">never below <?= (int)$bp['floor'] ?></div></td>
        </tr>
      <?php endforeach; ?>
      </tbody></table></div>
      <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:12px">
        <label style="font-size:13px"><input type="checkbox" id="bfrEnabled"<?= !empty($bfrCfg['enabled']) ? ' checked' : '' ?>> Turn the rules on</label>
        <label style="font-size:13px"><input type="checkbox" id="bfrDry"<?= !empty($bfrCfg['dryrun']) ? ' checked' : '' ?>> Dry run &mdash; report only, change nothing</label>
        <label class="ui-fld" style="margin:0">Ceiling per run <input type="number" id="bfrMax" class="tp-in" style="width:80px" min="1" max="2000" value="<?= (int)$bfrCfg['max_per_run'] ?>"></label>
        <span style="flex:1"></span>
        <button class="tp-btn" id="bfrPreview" type="button">&#128269; Show me what this would block</button>
        <button class="tp-btn primary" id="bfrSave" type="button">Save</button><span id="bfrSaved" class="meta" style="font-size:12px;font-weight:700;margin-left:6px"></span>
        <button class="tp-btn danger" id="bfrRun" type="button">&#9889; Run now</button>
      </div>
      <div class="meta" style="margin-top:6px">Leave <b>dry run</b> on until you have looked at what it would block. Arming is refused if your own address is in a network these rules would catch.</div>
      <div id="bfrOut" hidden style="margin-top:10px"></div>
<script>
  /* This block used to sit at the end of the module, after a `smpro_layout_footer(); return;` that the Break-in tab takes -
     so it was NEVER sent to the browser and Save/Preview/Run did nothing. It lives with the card now, with its own token. */
  var AA_CSRF = <?= json_encode(smpro_csrf_generate('aa_delete')) ?>;
/* Break-in rules. Every confirm()/alert() string is ONE line: a raw newline inside a single-quoted JS string is
   a SyntaxError, and a SyntaxError discards the whole <script> block -- the button then does nothing at all,
   with no error anywhere. That exact failure shipped twice before. */
(function(){
  var out=document.getElementById('bfrOut'); if(!out) return;
  function esc(x){return String(x==null?'':x).replace(/[<>&"]/g,function(c){return {'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;'}[c];});}
  function cfg(){
    var rules={};
    Array.prototype.forEach.call(document.querySelectorAll('.bfrOn'),function(c){
      var k=c.getAttribute('data-k');
      var m=document.querySelector('.bfrMin[data-k="'+k+'"]');
      rules[k]={enabled:c.checked,min:parseInt(m&&m.value||'0',10)||0};
    });
    return {enabled:document.getElementById('bfrEnabled').checked,
            dryrun:document.getElementById('bfrDry').checked,
            max_per_run:parseInt(document.getElementById('bfrMax').value||'200',10)||200,
            rules:rules};
  }
  function post(fd,cb){
    fd.set('smpro_csrf',AA_CSRF);
    fetch('index.cgi?page=account-audit&tab=bruteforce',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString()})
      .then(function(r){ return r.text().then(function(tx){ try { return JSON.parse(tx); } catch(e) { throw new Error('the server answered HTTP '+r.status+' without a result'+(r.status===400?' - the page\'s security token may have expired; reload and try again':'')); } }); })
      .then(cb).catch(function(e){show('<b style="color:var(--dang)">'+esc(e&&e.message?e.message:e)+'</b>'); var sv=document.getElementById('bfrSaved'); if(sv){sv.style.color='var(--dang)';sv.textContent='not saved';}});
  }
  function show(h){out.hidden=false;out.innerHTML=h;}
  function rows(list,title,cls){
    if(!list||!list.length) return '';
    var h='<div style="margin-top:8px"><b class="'+cls+'">'+esc(title)+' ('+list.length+')</b>'
         +'<div style="max-height:260px;overflow:auto;margin-top:4px">';
    list.slice(0,400).forEach(function(r){
      h+='<div class="meta" style="padding:2px 0"><code>'+esc(r.ip||r.network||'')+'</code> &middot; '+esc(r.why||'')+'</div>';
    });
    if(list.length>400) h+='<div class="meta">… and '+(list.length-400)+' more</div>';
    return h+'</div></div>';
  }
  function render(j){
    if(!j){show('<b style="color:var(--dang)">No answer from the server.</b>');return;}
    var h='<b>'+esc(j.msg||'')+'</b>';
    if(j.dryrun) h+=' <span class="meta">(dry run — nothing was changed)</span>';
    h+=rows(j.would,'Would be blocked','')+rows(j.blocked,'Blocked','')+rows(j.refused,'Refused','');
    /* The near-misses matter as much as the hits: a rule that quietly does nothing looks exactly like a rule
       that is working, which is the confusion this panel exists to remove. */
    if(j.skipped&&j.skipped.length){
      h+='<details style="margin-top:8px"><summary class="meta">'+j.skipped.length+' network(s) were not actioned — why</summary>';
      j.skipped.slice(0,200).forEach(function(r){h+='<div class="meta" style="padding:2px 0">'+esc(r.network||'')+' — '+esc(r.why||'')+'</div>';});
      h+='</details>';
    }
    show(h);
  }
  document.getElementById('bfrSave').addEventListener('click',function(){
    var c=cfg(), b=this, o=b.textContent;
    if(c.enabled&&!c.dryrun&&!confirm('Arm these rules? Matching addresses will be blocked without anyone present. Your own address is checked first and arming is refused if a rule would catch it.')) return;
    b.disabled=true;b.textContent='Saving…';
    var fd=new URLSearchParams();fd.set('aa_action','bfr_save');fd.set('cfg',JSON.stringify(c));
    post(fd,function(j){b.disabled=false;b.textContent=o;
      var ok=!!(j&&j.ok), sv=document.getElementById('bfrSaved');
      var st=!c.enabled?'off':(c.dryrun?'dry run':'ARMED');
      if(sv){sv.style.color=ok?'var(--good)':'var(--dang)';sv.textContent=ok?('\u2713 Saved '+new Date().toLocaleTimeString()+' \u00b7 rules '+st):'not saved';}
      var bd=document.querySelector('#bfr .ph-badge'); if(bd&&ok){bd.textContent=st;bd.style.background=st==='ARMED'?'rgba(220,38,38,.12)':(st==='dry run'?'rgba(180,83,9,.14)':'rgba(107,114,128,.16)');}
      show('<b'+(ok?'':' style="color:var(--dang)"')+'>'+esc((j&&j.msg)||(ok?'Saved.':'Not saved.'))+'</b>'+(ok&&!c.enabled?' <span class="meta">The rules are saved but OFF - tick "Turn the rules on" and save again to arm them (leave dry run on first).</span>':''));});
  });
  document.getElementById('bfrPreview').addEventListener('click',function(){
    var b=this,o=b.textContent;b.disabled=true;b.textContent='Checking…';
    var fd=new URLSearchParams();fd.set('aa_action','bfr_preview');
    post(fd,function(j){b.disabled=false;b.textContent=o;render(j);});
  });
  document.getElementById('bfrRun').addEventListener('click',function(){
    if(!confirm('Run the rules now against the networks on this page? Addresses that match an enabled rule will be blocked immediately unless dry run is on.')) return;
    var b=this,o=b.textContent;b.disabled=true;b.textContent='Running…';
    var fd=new URLSearchParams();fd.set('aa_action','bfr_run');
    post(fd,function(j){b.disabled=false;b.textContent=o;render(j);});
  });
})();
</script>
    </div>
  </div>
  <?php endif; ?>
  <div class="aa-bf-sec" id="aa-bf-human"><h2>Residential / business networks</h2><span class="meta">somewhere a person is — the ones worth a look</span></div>
  <?php $byV = function (array $l) { uasort($l, function ($a, $b) { $r = smpro_aa_bf_rank(smpro_aa_bf_assess($a)['verdict']) <=> smpro_aa_bf_rank(smpro_aa_bf_assess($b)['verdict']); return $r !== 0 ? $r : ($b['fails'] <=> $a['fails']); }); return $l; };
        $human = $byV($human); $bots = $byV($bots); ?>
  <?php if ($human) { foreach ($human as $nv) $row($nv, 'human'); } else echo '<div class="aa-bf-empty">Nothing came from a residential or business network.</div>'; ?>
  <div class="aa-bf-sec" id="aa-bf-cloud"><h2>Cloud / hosting networks</h2><span class="meta">automated scanners every server receives — still blockable</span></div>
  <?php if ($bots) { foreach ($bots as $nv) $row($nv, 'bot'); } else echo '<div class="aa-bf-empty">None.</div>'; ?>
  <?php if ($trusted): ?>
  <div class="aa-bf-sec" id="aa-bf-allow"><h2>Left out: on your allow-list</h2><span class="meta">a crawler or monitor failing to sign in is not an intrusion; these are never blocked</span></div>
  <div class="aa-geobar-list"><?php foreach ($trusted as $tx): ?><span class="aa-geochip"><?= smpro_h($tx['ip']) ?> &middot; <b><?= (int)$tx['n'] ?></b> &middot; <?= smpro_h($tx['who']) ?></span><?php endforeach; ?></div>
  <?php endif; ?>
  <div class="aa-bf-sec" id="aa-bf-ignored"><h2>Ignored networks</h2><span class="meta">hidden from the banner and the lists above until shown again</span></div>
  <?php if ($ignored) { foreach ($ignored as $nv) $row($nv, 'ignored'); } else echo '<div class="aa-bf-empty">None.</div>'; ?>
</div>
<script>
document.addEventListener('click',function(e){
  function post(fd,cb){fd.set('smpro_csrf',AA_CSRF);fetch('index.cgi?page=account-audit',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString()}).then(function(r){return r.json();}).then(cb).catch(function(){cb({ok:false,msg:'Request failed.'});});}
  var a=e.target.closest&&e.target.closest('.aaBfAllow');
  if(a){var ips=(a.getAttribute('data-ips')||'').split(',').filter(Boolean);if(!ips.length)return;
    if(!confirm('Add '+ips.length+' address(es) from '+(a.getAttribute('data-label')||'this network')+' to the firewall allow-list?\n\nThey will never be blocked by the firewall or by the plugin.'))return;
    var o=a.textContent;a.disabled=true;a.textContent='Allowing…';var fd=new URLSearchParams();fd.set('aa_action','bf_allow');fd.set('ips',ips.join(','));
    post(fd,function(j){if(j&&j.ok){a.textContent='✓ allow-listed';}else{a.disabled=false;a.textContent=o;}if(j&&j.msg)alert(j.msg);});return;}
  var g=e.target.closest&&e.target.closest('.aaBfIgnore');
  if(g){var k=g.getAttribute('data-key');var fd=new URLSearchParams();fd.set('aa_action','bf_ignore');fd.set('key',k);fd.set('label',g.getAttribute('data-label')||'');
    g.disabled=true;post(fd,function(j){if(j&&j.ok){var row=g.closest('.aa-net');if(row)row.style.opacity='.4';setTimeout(function(){location.reload();},600);}else{g.disabled=false;alert((j&&j.msg)||'Failed');}});return;}
  var ai=e.target.closest&&e.target.closest('#aaBfAi');
  if(ai){
    // Everything asked about is already on this page; the answer is pinned back onto the card it belongs to, and a
    // network the AI skips simply keeps the verdict the rules gave it.
    var cards=Array.prototype.slice.call(document.querySelectorAll('.aa-net[data-facts]'));
    var nets=[];cards.forEach(function(c){try{nets.push(JSON.parse(c.getAttribute('data-facts')));}catch(err){}});
    var panel=document.getElementById('aaBfAiPanel');
    if(!nets.length){panel.hidden=false;panel.innerHTML='<b>Nothing to review.</b>';return;}
    var ot=ai.innerHTML;ai.disabled=true;ai.innerHTML='&#129302; Reviewing '+nets.length+' network(s)… (up to ~30s)';
    panel.hidden=false;panel.innerHTML='<span class="meta">Sending the numbers only — no address, account name or log line leaves the server.</span>';
    var fd=new URLSearchParams();fd.set('aa_action','bf_ai');fd.set('nets',JSON.stringify(nets));
    post(fd,function(j){
      ai.disabled=false;ai.innerHTML=ot;
      if(!j||!j.ok){panel.innerHTML='<b style="color:var(--dang,#dc2626)">AI review unavailable.</b> <span class="meta">'+String((j&&(j.error||j.msg))||'Request failed.').replace(/[<>&]/g,'')+'</span>';return;}
      var rows=j.rows||[],dis=0;
      var lbl={block:'Block it',watch:'Look first',keep:'Leave it'};
      rows.forEach(function(r){
        var card=document.querySelector('.aa-net[data-key="'+String(r.key).replace(/"/g,'')+'"]');if(!card)return;
        if(!r.agrees)dis++;
        var old=card.querySelector('.aa-ai');if(old)old.parentNode.removeChild(old);
        var d=document.createElement('div');d.className='aa-ai';
        d.innerHTML='<span class="d '+r.decision+'">'+lbl[r.decision]+'</span><b>&#129302; AI:</b> '
          +String(r.reason||'').replace(/[<>]/g,'')
          +(r.agrees?'':' <span class="dis">&#9888; disagrees with the rules on this network — your call.</span>');
        var why=card.querySelector('.aa-why');why.parentNode.insertBefore(d,why.nextSibling);
        var b=card.querySelector('.aaBlockNet');if(b){b.classList.toggle('aa-rec',r.decision==='block');if(r.decision==='block')b.title='The AI recommends blocking this network';}
        var g=card.querySelector('.aaBfIgnore');if(g)g.classList.toggle('aa-rec',r.decision==='keep');
      });
      panel.innerHTML='<b>&#129302; AI review'+(j.provider?' ('+String(j.provider).replace(/[<>&]/g,'')+')':'')+'</b> &middot; '
        +rows.length+' of '+nets.length+' network(s) judged &middot; '
        +(dis?('<span class="dis" style="color:#b45309;font-weight:700">'+dis+' disagree with the rules</span>'):'agrees with the rules everywhere')
        +'<div class="meta" style="margin-top:4px">A recommendation only — nothing was blocked, allow-listed or ignored. The outlined buttons are what the AI suggests.</div>';
    });
    return;
  }
  var u=e.target.closest&&e.target.closest('.aaBfUnignore');
  if(u){var fd=new URLSearchParams();fd.set('aa_action','bf_unignore');fd.set('key',u.getAttribute('data-key'));u.disabled=true;post(fd,function(j){if(j&&j.ok)location.reload();else{u.disabled=false;alert((j&&j.msg)||'Failed');}});return;}
});
</script>
<?php }

/* ---------- request params ---------- */
$user = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)($_GET['audit_user'] ?? $_GET['user'] ?? ''));
$type = preg_replace('/[^a-z_]/', '', strtolower((string)($_GET['event_type'] ?? 'all')));
if (!in_array($type, ['all','success_login','failed_login','login_request','password_change','technical','panel_action'], true)) $type = 'all';
$search = trim((string)($_GET['q'] ?? ''));
$country = (string)($_GET['country'] ?? 'all');
$country = ($country === 'foreign' || $country === 'all') ? $country : strtoupper(preg_replace('/[^a-zA-Z]/', '', $country));
if ($country === '') $country = 'all';
$showlocal = (string)($_GET['showlocal'] ?? '') === '1';   // localhost (127.0.0.1/::1) hidden unless requested
$aaT = ['start' => microtime(true)];   // where the time goes, printed as an HTML comment at the end of the page
$dlog   = (int)($_GET['loglines'] ?? 50000);
if (!in_array($dlog, [20000,50000,100000,200000,500000], true)) $dlog = 50000;

$today  = date('Y-m-d');
// A BLANK date field = OPEN bound -> cover the full available range (oldest...newest present in the
// scanned log window), instead of forcing the old last-7-days default. Only a valid date narrows it.
$from   = preg_match('/^\d{4}-\d{2}-\d{2}$/', (string)($_GET['from'] ?? '')) ? $_GET['from'] : '';
$to     = preg_match('/^\d{4}-\d{2}-\d{2}$/', (string)($_GET['to'] ?? '')) ? $_GET['to'] : '';
$fromTs = $from !== '' ? strtotime($from . ' 00:00:00') : 0;                 // 0 = no lower bound (oldest available)
$toTs   = $to   !== '' ? strtotime($to . ' 23:59:59')   : (time() + 86400); // no upper bound (latest available)
$openRange = ($from === '' || $to === '');

$fmt    = (string)($_GET['format'] ?? '');
$page   = max(1, (int)($_GET['p'] ?? 1));

/*
 * SORTING IS DONE HERE, ON THE WHOLE RESULT, NOT IN THE BROWSER ON ONE PAGE.
 *
 * The shared table script reorders the rows it can see. On a result of 15,000 events across 305 pages that
 * sorts fifty of them, while the column arrow says the table is sorted - so "sort by Type to see the successful
 * logins together" returns the two or three that were already on the page, under a counter reading 533.
 *
 * These keys are whitelisted rather than taken from the URL, because they name a field that is read out of every
 * event and a URL is not a place to accept arbitrary field names.
 */
$aaSortable = smpro_aa_sort_keys();
$aaSort = (string)($_GET['sort'] ?? 'time');
if (!isset($aaSortable[$aaSort])) $aaSort = 'time';
$aaDir  = (($_GET['dir'] ?? '') === 'asc') ? 'asc' : 'desc';
$perPage = 50;

/* ---------- tabs: Account Audit (default) + merged Login & Access tabs ---------- */
$aaTab = (string)($_GET['tab'] ?? 'audit');
if (!in_array($aaTab, ['audit', 'bruteforce', 'overview', 'correlation', 'resets', 'webact'], true)) $aaTab = 'audit';
$laDays = (int)($_GET['days'] ?? 7); if (!in_array($laDays, [1, 7, 30], true)) $laDays = 7;
$laFromTs = time() - $laDays * 86400; $laToTs = time();
$laFrom = date('Y-m-d', $laFromTs); $laTo = date('Y-m-d', $laToTs);

/* ---------- POST: Login&Access actions (CSF block/allow/unblock, hide) - exits if matched ---------- */
smpro_la_handle_post();

/* ---------- delete saved report(s) - AJAX, POST + CSRF, returns JSON ---------- */
$reqMethod = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));
if ($reqMethod === 'POST' && ($_POST['aa_action'] ?? '') === 'delete_report') {
    smpro_require_valid_csrf('aa_delete');
    smpro_require_root();
    $ids = array_filter(array_map(
        fn($s) => preg_replace('/[^a-zA-Z0-9_-]/', '', $s),
        explode(',', (string)($_POST['report_ids'] ?? $_POST['report_id'] ?? ''))
    ));
    $deleted = [];
    foreach ($ids as $rid) if (smpro_aa_delete_report($rid)) $deleted[] = $rid;
    smpro_audit('account_audit_report_delete', ['ids' => $ids, 'deleted' => $deleted]);
    echo json_encode(['ok' => true, 'deleted' => $deleted], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

/* ---------- break-in report decisions: allow-list a network, ignore / un-ignore a network ---------- */
if ($reqMethod === 'POST' && ($_POST['aa_action'] ?? '') === 'bf_ai') {
    smpro_require_valid_csrf('aa_delete'); smpro_require_root();
    header('Content-Type: application/json');
    // The page sends back the same numbers it is displaying, so the review costs no second parse of a 200k-line log.
    // Those numbers are only ever used to ASK a question and to key the answer to a card already on screen - nothing
    // is blocked, allow-listed or stored from them - so a tampered field can mislead nobody but its own sender.
    $in = json_decode((string)($_POST['nets'] ?? '[]'), true);
    $nets = [];
    foreach ((array)(is_array($in) ? $in : []) as $n) { $c = smpro_aa_bf_facts_clean($n); if ($c) $nets[] = $c; }
    try {
        $r = smpro_aa_bf_ai_review($nets);
    } catch (\Throwable $e) {
        if (function_exists('smpro_soft_fail')) smpro_soft_fail('breakin_ai_review', $e);
        $r = ['ok' => false, 'error' => 'The AI review hit an error: ' . $e->getMessage(), 'rows' => []];
    }
    smpro_audit('account_audit_breakin_ai', ['nets' => count($nets), 'ok' => !empty($r['ok']), 'rows' => count($r['rows'] ?? [])]);
    echo json_encode($r, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

if ($reqMethod === 'POST' && in_array((string)($_POST['aa_action'] ?? ''), ['bf_allow', 'bf_ignore', 'bf_unignore'], true)) {
    smpro_require_valid_csrf('aa_delete'); smpro_require_root();
    header('Content-Type: application/json');
    $act = (string)$_POST['aa_action']; $by = function_exists('smpro_current_actor') ? smpro_current_actor() : 'root';
    if ($act === 'bf_allow') {
        $list = array_values(array_unique(array_filter(array_map('trim', explode(',', (string)($_POST['ips'] ?? ''))))));
        if (!$list || count($list) > 500) { echo json_encode(['ok'=>false,'msg'=>'Nothing to allow, or too many addresses in one request.']); exit; }
        if (!function_exists('smpro_csf_allow_add')) { echo json_encode(['ok'=>false,'msg'=>'Allow-list helper unavailable.']); exit; }
        $done = 0; $failed = [];
        foreach ($list as $one) { if (!filter_var($one, FILTER_VALIDATE_IP)) continue; $r = smpro_csf_allow_add($one, 'Account Audit allow-list by ' . $by); if (!empty($r['ok'])) $done++; else $failed[] = $one; }
        smpro_audit('account_audit_allowlist_network', ['requested'=>count($list),'allowed'=>$done,'failed'=>count($failed),'by'=>$by]);
        echo json_encode(['ok'=>$done > 0, 'msg'=>'Allow-listed ' . $done . ' of ' . count($list) . ' address(es) in csf.allow.' . ($failed ? ' Failed: ' . implode(', ', array_slice($failed, 0, 5)) : '')]); exit;
    }
    $key = (string)($_POST['key'] ?? '');
    if ($act === 'bf_ignore') { $ok = smpro_aa_bf_ign_add($key, (string)($_POST['label'] ?? ''), $by); smpro_audit('account_audit_bf_ignore', ['key'=>$key,'by'=>$by]); echo json_encode(['ok'=>$ok, 'msg'=>$ok ? 'Network ignored.' : 'Invalid network key.']); exit; }
    smpro_aa_bf_ign_remove($key); smpro_audit('account_audit_bf_unignore', ['key'=>$key,'by'=>$by]); echo json_encode(['ok'=>true, 'msg'=>'Network shown again.']); exit;
}

/* ---------- block a foreign attacker IP (POST + CSRF) - home-region/local IPs are refused ---------- */
if ($reqMethod === 'POST' && ($_POST['aa_action'] ?? '') === 'block_ip') {
    smpro_require_valid_csrf('aa_delete');
    smpro_require_root();
    header('Content-Type: application/json');
    // A whole network can be blocked in one request, but every address in it is still checked on its own here:
    // the list arrives from the page and the page is not trusted to have filtered it. An Arab or local address
    // smuggled into the list is refused exactly as it would be on its own, and the reply names what it skipped.
    if (($_POST['ips'] ?? '') !== '') {
        $list = array_values(array_unique(array_filter(array_map('trim', explode(',', (string)$_POST['ips'])))));
        if (count($list) > 500) { echo json_encode(['ok'=>false,'msg'=>'Too many addresses in one request.']); exit; }
        $done = 0; $skipped = []; $failed = [];
        foreach ($list as $one) {
            if (!filter_var($one, FILTER_VALIDATE_IP)) { $skipped[] = $one . ' (not an address)'; continue; }
            $i2 = smpro_aa_ip_intel($one);
            $c2 = strtoupper((string)($i2['country'] ?? ''));
            $ok2 = (($i2['scope'] ?? '') === 'external' && $c2 !== '' && $c2 !== 'N/A' && $c2 !== 'NA' && !smpro_cc_is_arab($c2));
            if (!$ok2) { $skipped[] = $one . ' (' . ($c2 ?: 'unplaced') . ')'; continue; }
            if (!function_exists('smpro_im_block_ip')) { echo json_encode(['ok'=>false,'msg'=>'Block engine unavailable.']); exit; }
            $r2 = smpro_im_block_ip($one, 'Account Audit: foreign brute-force from ' . $c2);
            if (!empty($r2['ok'])) $done++; else $failed[] = $one;
        }
        smpro_audit('account_audit_block_network', ['requested'=>count($list),'blocked'=>$done,'skipped'=>count($skipped),'failed'=>count($failed)]);
        $msg = 'Blocked ' . $done . ' of ' . count($list) . ' address(es).';
        if ($skipped) $msg .= ' Skipped ' . count($skipped) . ' that are not blockable here: ' . implode(', ', array_slice($skipped, 0, 6)) . (count($skipped) > 6 ? ' …' : '') . '.';
        if ($failed)  $msg .= ' ' . count($failed) . ' could not be written to the firewall.';
        echo json_encode(['ok'=>$done > 0, 'msg'=>$msg]); exit;
    }
    $ip = trim((string)($_POST['ip'] ?? ''));
    if (!filter_var($ip, FILTER_VALIDATE_IP)) { echo json_encode(['ok'=>false,'msg'=>'Invalid IP.']); exit; }
    $in = smpro_aa_ip_intel($ip);
    $cc = strtoupper((string)($in['country'] ?? ''));
    $isLocal = ($in['scope'] ?? '') === 'local';
    $isHome = smpro_cc_is_arab($cc);
    $foreign = (($in['scope'] ?? '') === 'external' && $cc !== '' && $cc !== 'N/A' && $cc !== 'NA' && !$isHome);
    if (!$foreign) {
        $why = $isLocal ? 'local/private' : ($isHome ? ('home-region country ' . $cc . ' — protected') : ('country ' . ($cc ?: 'unknown') . ' is not flagged foreign'));
        echo json_encode(['ok'=>false,'msg'=>'Refused: only addresses outside the home region are blockable here (' . $why . ').']); exit;
    }
    if (!function_exists('smpro_im_block_ip')) { echo json_encode(['ok'=>false,'msg'=>'Block engine unavailable.']); exit; }
    $r = smpro_im_block_ip($ip, 'Account Audit: foreign brute-force from ' . $cc);
    smpro_audit('account_audit_block_ip', ['ip'=>$ip,'cc'=>$cc,'ok'=>!empty($r['ok'])]);
    echo json_encode(['ok'=>!empty($r['ok']), 'msg'=>!empty($r['ok']) ? ('Blocked ' . $ip . ' (' . $cc . ').') : ('Block failed: ' . ($r['msg'] ?? 'unknown'))]); exit;
}

/* ---------- exports for the merged Login&Access tabs ---------- */
if ($aaTab !== 'audit' && in_array($fmt, ['csv', 'html', 'pdf'], true)) {
    smpro_la_export($aaTab, $fmt, $laDays, $laFrom, $laTo, $laFromTs, $laToTs);
    exit; // (la_export exits on a match; guard against falling through to the audit export)
}

/* ---------- exports (CSV / HTML / PDF) served by index.cgi ---------- */
if ($aaTab === 'audit' && in_array($fmt, ['csv', 'html', 'pdf'], true)) {
    $savedReq = preg_replace('/[^a-zA-Z0-9_-]/', '', (string)($_GET['saved'] ?? ''));
    $metaInfo = ['user' => $user, 'from' => $from, 'to' => $to, 'type' => $type];
    if ($savedReq !== '') {
        $idx = smpro_aa_json_load(SMPRO_AA_REPIDX);
        $path = (string)($idx[$savedReq]['path'] ?? '');
        $rep = ($path && strpos($path, SMPRO_AA_REPORTS) === 0 && is_file($path)) ? smpro_aa_json_load($path) : [];
        $events = $rep['events'] ?? [];
        $metaInfo = ['user' => $rep['audit_user'] ?? $user, 'from' => $rep['params']['from'] ?? $from, 'to' => $rep['params']['to'] ?? $to, 'type' => $rep['params']['type'] ?? $type, 'saved_id' => $savedReq];
    } else {
        [$events, $h, $aaScanMeta] = smpro_aa_cached(['u'=>$user,'t'=>$type,'n'=>$dlog,'f'=>$from,'to'=>$to,'q'=>''], fn() => smpro_aa_collect($user, $type, $dlog, $fromTs, $toTs), !empty($_GET['fresh']));
        if ($search !== '') { $n = strtolower($search); $events = array_values(array_filter($events, fn($e) => strpos(strtolower($e['ip'].' '.$e['login_user'].' '.$e['type'].' '.$e['evidence']), $n) !== false)); }
        $events = smpro_aa_filter_country($events, $country);
        $events = smpro_aa_filter_local($events, $showlocal);
    }

    if ($fmt === 'csv') {
        $fh = fopen('php://output', 'w');
        fputcsv($fh, ['time','type','result','service','ip','country','provider','asn','scope','login_user','account','action','source','evidence']);
        foreach ($events as $e) {
            $i = smpro_aa_ip_intel($e['ip']);
            smpro_fputcsv($fh, [$e['time'],$e['type'],$e['result'],$e['service'],$e['ip'],$i['country'],$i['provider'],$i['asn'],$i['scope'],$e['login_user'],$e['account'],$e['action'],$e['source'],$e['evidence']]);
        }
        fclose($fh);
    } else {
        smpro_aa_render_report($events, $metaInfo, $fmt === 'pdf');
    }
    exit;
}

/* ---------- collect for display (Account Audit tab only) ---------- */
$slice = []; $saved = []; $savedId = ''; $localCount = 0; $total = 0; $pages = 1;
$sum = ['total' => 0, 'success' => 0, 'failed' => 0, 'ips' => []]; $uniqueIps = 0; $hiddenTech = 0;
if ($aaTab === 'audit' || $aaTab === 'bruteforce') {
    $aaT['collect'] = microtime(true);
    [$events, $hiddenTech, $aaScanMeta] = smpro_aa_cached(['u'=>$user,'t'=>$type,'n'=>$dlog,'f'=>$from,'to'=>$to,'q'=>$search], fn() => smpro_aa_collect($user, $type, $dlog, $fromTs, $toTs, $search), !empty($_GET['fresh']));
    $aaT['collected'] = microtime(true);
    if ($search !== '') { $n = strtolower($search); $events = array_values(array_filter($events, fn($e) => strpos(strtolower($e['ip'].' '.$e['login_user'].' '.$e['type'].' '.$e['evidence']), $n) !== false)); }
    $events = smpro_aa_filter_country($events, $country);
    $localCount = smpro_aa_count_local($events);             // localhost events present before hiding
    $events = smpro_aa_filter_local($events, $showlocal);

    $sum = ['total' => count($events), 'success' => 0, 'failed' => 0, 'ips' => []];
    $spanMin = 0; $spanMax = 0;
    foreach ($events as $e) {
        if ($e['kind'] === 'success_login') $sum['success']++;
        if ($e['kind'] === 'failed_login') $sum['failed']++;
        if ($e['ip'] !== '') $sum['ips'][$e['ip']] = true;
        $ts = (int)($e['ts'] ?? 0); if ($ts) { $spanMin = $spanMin ? min($spanMin, $ts) : $ts; $spanMax = max($spanMax, $ts); }
    }
    $uniqueIps = count($sum['ips']);

    // Save a report when the user explicitly searches (the break-in report view never saves one).
    if (($_GET['do'] ?? '') === 'search' && $aaTab === 'audit') {
        $savedId = smpro_aa_save_report($user, ['from' => $from, 'to' => $to, 'type' => $type, 'loglines' => $dlog],
            $events, ['total' => $sum['total'], 'unique_ips' => $uniqueIps, 'success' => $sum['success'], 'failed' => $sum['failed'], 'hidden_tech' => $hiddenTech]);
    }
    $saved = smpro_aa_saved_for($user);

    // Sorted before it is counted and cut, so page 1 really is the top of the order the header claims.
    $events = smpro_aa_sort_events($events, $aaSort, $aaDir);

    $total = count($events);
    $pages = max(1, (int)ceil($total / $perPage));
    $page  = min($page, $pages);
    $slice = array_slice($events, ($page - 1) * $perPage, $perPage);
    // Attach IP intel only to the visible slice (bounded lookups).
    foreach ($slice as &$e) $e['intel'] = smpro_aa_ip_intel($e['ip']);
    unset($e);

    // Foreign-country (non-Arab) alerts - uses cached geo only (cheap). Red = a successful
    // foreign login; Orange = an IP with >3 failed foreign attempts (brute-force -> blockable).
    $aaForeignSucc = []; $aaFFail = [];
    foreach ($events as $e) {
        $k = $e['kind'] ?? '';
        if ($k !== 'success_login' && $k !== 'failed_login') continue;
        $in = smpro_aa_ip_intel($e['ip'] ?? '');
        $cc = strtoupper((string)($in['country'] ?? ''));
        // foreign = external + resolved + NON-Arab
        if (($in['scope'] ?? '') !== 'external' || $cc === '' || $cc === 'N/A' || $cc === 'NA' || smpro_cc_is_arab($cc)) continue;
        if ($k === 'success_login') {
            $aaForeignSucc[] = ['ip'=>$e['ip'],'cc'=>$cc,'user'=>$e['account'] ?: $e['login_user'],'time'=>$e['time']];
        } else {
            $ipk = $e['ip'];
            if (!isset($aaFFail[$ipk])) $aaFFail[$ipk] = ['ip'=>$e['ip'],'cc'=>$cc,'n'=>0,'user'=>$e['account'] ?: $e['login_user'],'users'=>[],'first'=>0,'last'=>0,'services'=>[]];
            $aaFFail[$ipk]['n']++;
            $u0 = (string)($e['account'] ?: $e['login_user']); if ($u0 !== '') $aaFFail[$ipk]['users'][$u0] = ($aaFFail[$ipk]['users'][$u0] ?? 0) + 1;
            $t0 = (int)($e['ts'] ?? 0); if ($t0) { $aaFFail[$ipk]['first'] = $aaFFail[$ipk]['first'] ? min($aaFFail[$ipk]['first'], $t0) : $t0; $aaFFail[$ipk]['last'] = max($aaFFail[$ipk]['last'], $t0); }
            $sv = (string)($e['service'] ?? ''); if ($sv !== '') $aaFFail[$ipk]['services'][$sv] = 1;
        }
    }
    $aaBrute = array_values(array_filter($aaFFail, fn($x) => $x['n'] > 3));   // >3 failed = brute-force
    usort($aaBrute, fn($a,$b) => $b['n'] <=> $a['n']);

    // Addresses belonging to a provider on the allow-list are taken out of the attacker list. They are in
    // csf.allow precisely because they must never be blocked - a search crawler, an uptime monitor, the CDN in
    // front of every site here - so listing them as attackers, next to a Block button that the server would
    // refuse anyway, states the opposite of the decision already made about them. They are counted and named
    // rather than dropped without trace: a crawler failing to log in over and over is worth knowing about, it
    // is just not an intrusion.
    $aaTrusted = [];
    if (function_exists('smpro_fw_allow_covers_name')) {
        $keep = [];
        foreach ($aaBrute as $bx) {
            $who = smpro_fw_allow_covers_name($bx['ip']);
            if ($who !== '') { $bx['who'] = $who; $aaTrusted[] = $bx; } else { $keep[] = $bx; }
        }
        $aaBrute = $keep;
    }

    // Group the offenders by the NETWORK they came from. A list of 289 addresses reads as 289 problems needing
    // 289 decisions, but a scan run from one cloud provider is ONE actor renting many addresses - blocking them
    // one at a time is both unreadable and endless, and the pattern that identifies the campaign is invisible.
    // Now that the ASN comes from the local database (no network call, no per-page budget) every offender can be
    // placed, so the page can group by network and offer the decision at the size it is actually made.
    // One bulk lookup for every offender not yet in the cache (single round-trip, hard 14 s cap), so the loop
    // below reads the cache and the local databases only. Without it each new address cost a whois call.
    $aaT['intel'] = microtime(true);
    if (function_exists('smpro_ip_intel_bulk') && $aaBrute) smpro_ip_intel_bulk(array_column($aaBrute, 'ip'), true);
    $aaNets = [];
    foreach ($aaBrute as $bx) {
        $in  = smpro_aa_ip_intel($bx['ip']);
        $asn = (string)($in['asn'] ?? '');
        $key = $asn !== '' ? $asn : ('cc:' . $bx['cc']);
        if (!isset($aaNets[$key])) {
            $aaNets[$key] = ['asn' => $asn, 'provider' => (string)($in['provider'] ?? ''),
                             'cc' => $bx['cc'], 'ips' => [], 'fails' => 0, 'users' => [], 'first' => 0, 'last' => 0, 'services' => [],
                             // A cloud or hosting network is an automated scanner sweeping the whole internet.
                             // It is still an attack and still blockable - but it is not a lead about THIS
                             // server, so it is separated from traffic that came from somewhere a person is.
                             'bot' => function_exists('smpro_ip_is_datacenter') ? smpro_ip_is_datacenter($in) : false];
        }
        $aaNets[$key]['ips'][] = $bx;
        $aaNets[$key]['fails'] += (int)$bx['n'];
        foreach ((array)($bx['users'] ?? []) as $uu => $un) $aaNets[$key]['users'][$uu] = ($aaNets[$key]['users'][$uu] ?? 0) + (int)$un;
        foreach ((array)($bx['services'] ?? []) as $ss => $_1) $aaNets[$key]['services'][$ss] = 1;
        if (!empty($bx['first'])) $aaNets[$key]['first'] = $aaNets[$key]['first'] ? min($aaNets[$key]['first'], (int)$bx['first']) : (int)$bx['first'];
        if (!empty($bx['last']))  $aaNets[$key]['last']  = max($aaNets[$key]['last'], (int)$bx['last']);
        if ($aaNets[$key]['cc'] !== $bx['cc']) $aaNets[$key]['cc'] = '';   // a network spanning countries shows none
    }
    $aaT['nets'] = microtime(true);
    foreach ($aaNets as &$_n) {
        $p = trim($_n['provider']);
        if ($p === '' || strtolower($p) === 'n/a') $_n['provider'] = $_n['asn'] !== '' ? $_n['asn'] : 'unidentified network';
    }
    unset($_n);
    // Worst network first - by how many addresses it fielded, then by total attempts.
    uasort($aaNets, function ($a, $b) {
        $c = count($b['ips']) <=> count($a['ips']);
        return $c !== 0 ? $c : ($b['fails'] <=> $a['fails']);
    });
    // Split, do not drop. Automated cloud scanners are folded away because they are the same background noise
    // every server on the internet receives, and burying the one attack that came from somewhere real underneath
    // two hundred of them is how the real one gets missed. They are still counted, still shown on request, and
    // still blockable - the page says how many it folded, so "quiet" can never mean "not looked at".
    // Networks the operator chose to ignore in the Break-in Report are kept aside: not in the banner, not in
    // the lists, but on the report page under "Ignored" so the decision is visible and reversible.
    $aaNetsIgnored = []; $aaIgn = smpro_aa_bf_ign_all();
    foreach ($aaNets as $k => $nv) if (isset($aaIgn[$k])) { $nv['ign'] = $aaIgn[$k]; $aaNetsIgnored[$k] = $nv; unset($aaNets[$k]); }
    $aaNetsHuman = array_filter($aaNets, fn($n) => empty($n['bot']));
    $aaNetsBots  = array_filter($aaNets, fn($n) => !empty($n['bot']));
    $aaBotIps    = array_sum(array_map(fn($n) => count($n['ips']), $aaNetsBots));
    $aaBotFails  = array_sum(array_map(fn($n) => $n['fails'], $aaNetsBots));
}

/* ---------------------------------------------------------------------------------------------------------
 * Break-in rules: save, preview, run.
 *
 * Deliberately placed here, after the networks have been rebuilt from this server's own logs. The other
 * aa_action endpoints sit near the top of this file, before that data exists, and the AI one takes its numbers
 * from the browser -- which is safe for asking a question and would NOT be safe for issuing a block. Every
 * decision below is made from what this server just read, never from what the page sent back.
 * ------------------------------------------------------------------------------------------------------- */
if ($reqMethod === 'POST' && in_array((string)($_POST['aa_action'] ?? ''), ['bfr_save', 'bfr_preview', 'bfr_run'], true)) {
    smpro_require_valid_csrf('aa_delete'); smpro_require_root();
    header('Content-Type: application/json');
    if (!function_exists('smpro_bfr_cfg')) { $f = SMPRO_BASE . '/includes/bfrules.php'; if (@is_file($f)) require_once $f; }
    $act  = (string)$_POST['aa_action'];
    $nets = array_values(array_merge((array)($aaNetsHuman ?? []), (array)($aaNetsBots ?? [])));
    $out  = ['ok' => false, 'msg' => 'Unknown action.'];
    try {
        if (!function_exists('smpro_bfr_cfg')) {
            $out = ['ok' => false, 'msg' => 'The rules engine is not installed on this server.'];
        } elseif ($act === 'bfr_save') {
            $in = json_decode((string)($_POST['cfg'] ?? '{}'), true);
            $cfg = is_array($in) ? $in : [];
            // Arming is checked BEFORE it is saved. Being locked out of the page that holds the unblock button is
            // the one failure with no way back from inside this server.
            if (!empty($cfg['enabled']) && empty($cfg['dryrun'])) {
                $myIp = '';
                $myIp = function_exists('smpro_admin_ip') ? smpro_admin_ip() : '';   // REMOTE_ADDR first: cpsrvd is the direct peer, the forwarded headers are what the browser sent
                $chk = smpro_bfr_arm_check(array_replace(smpro_bfr_cfg(), $cfg), $myIp, $nets);
                if (empty($chk['ok'])) { echo json_encode(['ok' => false, 'msg' => $chk['msg']]); exit; }
            }
            $ok = smpro_bfr_save($cfg);
            $out = ['ok' => $ok, 'msg' => $ok ? 'Saved.' : 'Could not write the rules.', 'cfg' => smpro_bfr_cfg()];
        } else {
            $dry = ($act === 'bfr_preview') ? true : null;
            $out = smpro_bfr_run($nets, null, $dry, smpro_current_actor());
            $out['history'] = smpro_bfr_history(50);
        }
    } catch (\Throwable $e) {
        if (function_exists('smpro_soft_fail')) smpro_soft_fail('bfrules_endpoint', $e);
        $out = ['ok' => false, 'msg' => 'The rules hit an error: ' . $e->getMessage()];
    }
    smpro_audit('account_audit_bfrules', ['action' => $act, 'ok' => !empty($out['ok'])]);
    echo json_encode($out, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

smpro_audit('account_audit_view', ['tab' => $aaTab, 'user' => $user, 'type' => $type, 'total' => $total]);

/* ---------- render ---------- */
smpro_layout_header('Account Audit');
$self = 'index.cgi';
function smpro_aa_badge($kind) {
    $map = ['success_login'=>['green','Successful Login'],'failed_login'=>['red','Failed Login'],'password_change'=>['orange','Password Change'],'login_request'=>['blue','Login Request'],'technical'=>['gray','Technical'],'panel_action'=>['blue','Panel Action']];
    [$c,$t] = $map[$kind] ?? ['gray', ucfirst($kind)]; return '<span class="b '.$c.'">'.smpro_h($t).'</span>';
}
function smpro_aa_qs($o) { $q = []; foreach ($o as $k=>$v) $q[] = $k.'='.urlencode((string)$v); return 'index.cgi?'.implode('&',$q); }
$aaTabUrl = fn($t) => 'index.cgi?page=account-audit&tab=' . $t . ($t!=='audit' ? '&days='.$laDays : '');
?>
<div style="display:flex;justify-content:space-between;align-items:flex-start;gap:14px;flex-wrap:wrap;margin-bottom:4px">
  <div><h1 class="h" style="margin:0">Account Audit</h1>
    <p class="sub" style="margin:2px 0 0">Unified account &amp; login security — activity audit, login monitoring, source-IP correlation and password-reset auditing.</p></div>
  <?php if ($aaTab !== 'audit' && $aaTab !== 'bruteforce'): ?>
  <form method="get" action="index.cgi" class="la-toolbar" style="display:flex;gap:8px;align-items:center">
    <input type="hidden" name="page" value="account-audit"><input type="hidden" name="tab" value="<?= smpro_h($aaTab) ?>">
    <select class="tp-sel" name="days" onchange="this.form.submit()">
      <?php foreach ([1=>'Last 24h',7=>'Last 7 days',30=>'Last 30 days'] as $k=>$v): ?><option value="<?= $k ?>"<?= $laDays===$k?' selected':'' ?>><?= $v ?></option><?php endforeach; ?>
    </select>
    <div class="aa-export"><button class="tp-btn green" type="button" id="laExportBtn">Export &#9662;</button>
      <div class="aa-menu" id="laExportMenu"><a href="<?= smpro_h($aaTabUrl($aaTab)) ?>&format=csv">CSV</a>
        <?php if ($aaTab==='overview'): ?><a href="<?= smpro_h($aaTabUrl($aaTab)) ?>&format=html">HTML</a><a target="_blank" href="<?= smpro_h($aaTabUrl($aaTab)) ?>&format=pdf">PDF (print)</a><?php endif; ?></div>
    </div>
  </form>
  <?php endif; ?>
</div>
<?php if (!empty($aaForeignSucc) || !empty($aaBrute)): ?>
<style>
.aa-geo-alerts{margin:10px 0 6px;display:flex;flex-direction:column;gap:10px}
.aa-geobar{display:flex;gap:12px;align-items:flex-start;padding:12px 14px;border-radius:12px;border:1px solid}
.aa-geobar.red{background:var(--dang-bg);border-color:#f3c9c9}
.aa-geobar.orange{background:var(--warn-bg);border-color:#f0d8b8}
.aa-geobar-ic{font-size:20px;line-height:1.2}
.aa-geobar-body{flex:1;min-width:0}
.aa-geobar-body>b{font-size:13.5px}
.aa-geobar-list{display:flex;flex-wrap:wrap;gap:6px;margin-top:7px}
.aa-geochip{display:inline-flex;align-items:center;gap:7px;background:var(--card);border:1px solid var(--line);border-radius:20px;padding:3px 10px;font-size:12px;font-family:ui-monospace,Consolas,monospace}
.aa-geochip .tp-btn{font-size:11px;padding:2px 9px}
.aa-geobar-note{font-size:11.5px;color:var(--muted);margin-top:8px}
.aa-nets{display:flex;flex-direction:column;gap:7px;margin-top:10px}
.aa-net{background:var(--card);border:1px solid var(--line);border-radius:9px;padding:9px 11px}
.aa-net-head{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.aa-net-id{flex:1;min-width:190px}
.aa-net-id>b{font-size:13px}
.aa-net-meta{display:block;font-size:11.5px;color:var(--muted);font-family:ui-monospace,Consolas,monospace;margin-top:1px}
.aa-net-num{font-size:12px;color:var(--muted);white-space:nowrap}
.aa-net-num b{color:var(--fg)}
.aa-net-det{margin-top:8px}
.aa-net-det>summary{cursor:pointer;font-size:11.5px;color:var(--muted);user-select:none}
.aa-net-det[open]>summary{margin-bottom:6px}
.aa-net-det .aa-geobar-list{max-height:210px;overflow:auto}
.aa-net-none{font-size:12px;color:var(--muted);margin-top:10px}
.aa-bots{margin-top:9px;border-top:1px dashed var(--line);padding-top:9px}
.aa-bots>summary{cursor:pointer;font-size:12px;color:var(--muted);user-select:none}
.aa-bots>summary b{color:var(--fg)}
.aa-bots>summary span{display:block;font-size:11px;margin-top:1px}
.aa-bots[open]>summary{margin-bottom:8px}
</style>
<div class="aa-geo-alerts">
  <?php if (!empty($aaForeignSucc)): ?>
  <div class="aa-geobar red">
    <div class="aa-geobar-ic">&#128681;</div>
    <div class="aa-geobar-body">
      <b><?= count($aaForeignSucc) ?> successful login(s) from outside the home region</b>
      <div class="aa-geobar-list">
        <?php foreach (array_slice($aaForeignSucc, 0, 8) as $s): ?>
        <span class="aa-geochip"><?= smpro_h($s['cc']) ?> &middot; <?= smpro_h($s['ip']) ?> &middot; <?= smpro_h($s['user']) ?> &middot; <?= smpro_h($s['time']) ?></span>
        <?php endforeach; ?>
      </div>
      <?php /* Blocking the address stops that address. What the person has is the PASSWORD, and a password that is
           known stays known - so the only action that ends this is changing it. The reset lives in one place and is
           linked to from here rather than built a second time: two bulk-reset buttons would be two implementations
           to keep honest, and the one that drifted would be the one someone used during an incident. */ ?>
      <div style="margin-top:9px">
        <a class="tp-btn danger" href="index.cgi?page=firewall-status#gr">&#128273; Reset these passwords in bulk &rarr;</a>
        <span class="aa-geobar-note" style="display:inline-block;margin:0 0 0 8px">Blocking the address does not help &mdash; they have the password.</span>
      </div>
    </div>
  </div>
  <?php endif; ?>
  <?php /* The break-in statement lives on its own tab, which already carries the network count in its label.
     It used to be rendered here, above the tab bar, so it appeared on EVERY tab - a standing wall of text on
     five screens that are not about it, pushing the thing each screen IS about below the fold. Shown only on
     the Account Audit tab, as a pointer. */ ?>
  <?php if (!empty($aaBrute) && $aaTab === 'audit'): ?>
  <?php $aaTotFails = array_sum(array_map(fn($n) => $n['fails'], $aaNets)) + array_sum(array_map(fn($n) => $n['fails'], $aaNetsIgnored));
        $aaBfUrl = 'index.cgi?' . http_build_query(['page'=>'account-audit','tab'=>'bruteforce','audit_user'=>$user,'event_type'=>$type,'country'=>$country,'showlocal'=>($showlocal?'1':'0'),'from'=>$from,'to'=>$to,'loglines'=>$dlog,'q'=>$search]); ?>
  <div class="aa-geobar orange">
    <div class="aa-geobar-ic">&#9888;&#65039;</div>
    <div class="aa-geobar-body" style="display:flex;justify-content:space-between;gap:12px;align-items:center;flex-wrap:wrap">
      <div><b><?= count($aaBrute) ?> addresses tried to break in, from <?= count($aaNets) ?> network<?= count($aaNets) === 1 ? '' : 's' ?></b>
        <div class="aa-geobar-note" style="margin-top:3px"><?= number_format($aaTotFails) ?> failed attempts &middot; <?= count($aaNetsHuman) ?> residential/business, <?= count($aaNetsBots) ?> cloud/hosting<?= $aaNetsIgnored ? ', ' . count($aaNetsIgnored) . ' ignored' : '' ?><?= $aaTrusted ? ', ' . count($aaTrusted) . ' allow-listed address(es) left out' : '' ?>. Decide per network on the report: block, allow-list, or ignore.</div></div>
      <a class="tp-btn danger" href="<?= smpro_h($aaBfUrl) ?>">Open the break-in report &rarr;</a>
    </div>
  </div>
  <?php endif; ?>
</div>
<script>
document.addEventListener('click',function(e){
  var n=e.target.closest&&e.target.closest('.aaBlockNet');
  if(n){
    var ips=(n.getAttribute('data-ips')||'').split(',').filter(Boolean);
    var label=n.getAttribute('data-label')||'this network';
    if(!ips.length)return;
    if(!confirm('Block '+ips.length+' address'+(ips.length===1?'':'es')+' from '+label+'?\n\nEach one is checked again on the server; home-region and local addresses are refused.'))return;
    var on=n.textContent;n.disabled=true;n.textContent='Blocking '+ips.length+'…';
    var fn=new URLSearchParams();fn.set('aa_action','block_ip');fn.set('ips',ips.join(','));fn.set('smpro_csrf',AA_CSRF);
    fetch('index.cgi?page=account-audit',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fn.toString()})
      .then(function(r){return r.json();}).then(function(j){
        if(j&&j.ok){n.textContent='✓ done';n.style.background='var(--good)';n.style.borderColor='var(--good)';n.style.color='#fff';}
        else{n.disabled=false;n.textContent=on;}
        if(j&&j.msg)alert(j.msg);
      }).catch(function(){n.disabled=false;n.textContent=on;alert('Request failed.');});
    return;
  }
  var b=e.target.closest&&e.target.closest('.aaBlock'); if(!b)return;
  var ip=b.getAttribute('data-ip');
  if(!confirm('Block foreign IP '+ip+' in the firewall?'))return;
  var o=b.textContent;b.disabled=true;b.textContent='Blocking…';
  var fd=new URLSearchParams();fd.set('aa_action','block_ip');fd.set('ip',ip);fd.set('smpro_csrf',AA_CSRF);
  fetch('index.cgi?page=account-audit',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString()})
    .then(function(r){return r.json();}).then(function(j){
      if(j&&j.ok){b.textContent='✓ blocked';b.style.background='var(--good)';b.style.borderColor='var(--good)';b.style.color='#fff';}
      else{b.disabled=false;b.textContent=o;alert((j&&j.msg)||'Block failed.');}
    }).catch(function(){b.disabled=false;b.textContent=o;alert('Request failed.');});
});
</script>
<?php endif; ?>
<div class="la-tabs">
  <a class="la-tab<?= $aaTab==='audit'?' active':'' ?>"       href="<?= smpro_h($aaTabUrl('audit')) ?>">&#9679; Account Audit</a>
  <a class="la-tab<?= $aaTab==='bruteforce'?' active':'' ?>"  href="index.cgi?page=account-audit&amp;tab=bruteforce&amp;loglines=<?= (int)$dlog ?>">&#9888;&#65039; Break-in Report<?= !empty($aaBrute) ? ' <b>' . count($aaNets) . '</b>' : '' ?></a>
  <a class="la-tab<?= $aaTab==='overview'?' active':'' ?>"    href="<?= smpro_h($aaTabUrl('overview')) ?>">&#128274; Login Monitor</a>
  <a class="la-tab<?= $aaTab==='correlation'?' active':'' ?>" href="<?= smpro_h($aaTabUrl('correlation')) ?>">&#8644; IP Correlation</a>
  <a class="la-tab<?= $aaTab==='resets'?' active':'' ?>"      href="<?= smpro_h($aaTabUrl('resets')) ?>">&#8635; Password Resets</a>
  <a class="la-tab<?= $aaTab==='webact'?' active':'' ?>"      href="<?= smpro_h($aaTabUrl('webact')) ?>">&#127760; Web Activity</a>
</div>
<?php smpro_la_assets(); ?>
<style>
/* ===== overview strip / navigator / collapsible cards (same rules as firewall-status.php) ===== */
/* page additions: header-level open state (works for cards AND for header+siblings sections), prose folds, table pager */
.fw-toggle.fw-open .fw-chev{transform:rotate(90deg)}
.fw-collapse.fw-show{display:block}
.gl-fold{margin:6px 0}.gl-fold>summary{cursor:pointer;font-size:13px;font-weight:700;list-style:none;display:flex;align-items:center;gap:8px;color:var(--brand)}
.fw-pager{display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:8px 16px;border-bottom:1px solid var(--line);font-size:12px;color:var(--muted)}
.fw-pager .fw-pgq{border:1px solid var(--line);border-radius:9px;padding:5px 10px;font-size:12.5px;background:var(--card);color:var(--ink);min-width:180px}
.fw-pager .sp{flex:1}.fw-pgctl{display:inline-flex;align-items:center;gap:6px}
.fw-pgbtn{border:1px solid var(--line);background:var(--card);color:var(--ink);border-radius:7px;padding:2px 9px;font-size:13px;cursor:pointer;line-height:1.4}.fw-pgbtn[disabled]{opacity:.4;cursor:not-allowed}
.aa-bf-sec.fw-toggle{cursor:pointer}
</style>
<script>
(function(){
  // make every section card collapsible - click its title (or chevron) to open/close; remembered per section
  var KEY='smpro:account-audit:open', HDR='.smpro-main .card > .tp-th, .smpro-main .aa-bf-sec';
  var open={};
  try{ open=JSON.parse(localStorage.getItem(KEY)||'{}')||{}; }catch(err){ open={}; }
  function remember(){ try{ localStorage.setItem(KEY, JSON.stringify(open)); }catch(err){} }
  function matches(el,sel){ if(!el||el.nodeType!==1) return false; var m=el.matches||el.msMatchesSelector||el.webkitMatchesSelector; return m?m.call(el,sel):false; }
  var folds={};
  function setOpen(f,on){ f.th.classList.toggle('fw-open',on); f.body.classList.toggle('fw-show',on); if(f.card) f.card.classList.toggle('fw-open',on); f.th.setAttribute('aria-expanded',on?'true':'false'); open[f.id]=on; }
  function fold(th){
    if(th.getAttribute('data-fold')) return;
    var host=th.parentElement; if(!host||host.classList.contains('fw-collapse')) return;   // a sub-header inside an already folded section
    var isCard=host.classList.contains('card') && (th.classList.contains('tp-th') || th.classList.contains('fa-head'));   // card header -> fold the whole card; anything else folds its following siblings
    var nodes=[], n=th.nextSibling;
    while(n){
      var nx=n.nextSibling;
      if(n.nodeType===1){
        var tg=n.tagName;
        if(!isCard && (matches(n,HDR) || n.classList.contains('foot'))) break;       // next section / page footer
        if(tg==='SCRIPT'||tg==='STYLE'||tg==='LINK'||tg==='DATALIST'||tg==='TEMPLATE'){ n=nx; continue; }
      }
      nodes.push(n); n=nx;
    }
    var body=document.createElement('div'); body.className='fw-collapse';
    host.insertBefore(body, th.nextSibling);
    for(var i=0;i<nodes.length;i++) body.appendChild(nodes[i]);
    // a stable name for this section: its element id when it has one, else its own heading text (read before the chevron is added)
    var id=(isCard?host.id:'')||th.id||(th.textContent||'').replace(/\s+/g,' ').trim().slice(0,60)||('card'+Math.random());
    th.classList.add('fw-toggle');
    if(!th.querySelector('.fw-chev')) th.insertAdjacentHTML('afterbegin','<span class="fw-chev">&#9656;</span> ');
    th.setAttribute('data-fold', id);
    var f={id:id, th:th, body:body, card:isCard?host:null}; folds[id]=f;
    var isOpen = Object.prototype.hasOwnProperty.call(open,id) ? !!open[id] : !th.hasAttribute('data-closed');
    setOpen(f,isOpen);
    th.setAttribute('role','button'); th.setAttribute('tabindex','0'); th.style.cursor='pointer';
    th.addEventListener('click',function(e){
      if(e.target.closest('a,button,input,select,label,textarea,summary,details,.fw-chk')) return;   // header controls keep working
      setOpen(f,!body.classList.contains('fw-show')); remember();
    });
    th.addEventListener('keydown',function(e){
      if(e.target!==th) return;
      if(e.key===' '||e.key==='Enter'||e.key==='Spacebar'){ e.preventDefault(); setOpen(f,!body.classList.contains('fw-show')); remember(); }
    });
  }
  function foldAll(root){ Array.prototype.forEach.call((root||document).querySelectorAll(HDR), fold); }
  function openCard(id, scroll){
    var el=document.getElementById(id); if(!el) return;
    var f=folds[id]; if(f && !f.body.classList.contains('fw-show')){ setOpen(f,true); remember(); }
    if(scroll){ el.style.scrollMarginTop='120px'; el.scrollIntoView({behavior:'smooth',block:'start'}); }
  }
  function all(on){ for(var k in folds){ if(Object.prototype.hasOwnProperty.call(folds,k)) setOpen(folds[k],on); } remember(); }
  function init(){
    foldAll(document);
    Array.prototype.forEach.call(document.querySelectorAll('[data-go]'),function(a){ a.addEventListener('click',function(e){ e.preventDefault(); var id=a.getAttribute('data-go'); openCard(id,true); Array.prototype.forEach.call(document.querySelectorAll('.fw-nav a'),function(x){ x.classList.toggle('on', x.getAttribute('data-go')===id); }); try{ history.replaceState(null,'','#'+id); }catch(err){} }); });
    var oa=document.getElementById('fwOpenAll'), ca=document.getElementById('fwCloseAll');
    if(oa) oa.addEventListener('click',function(){ all(true); });
    if(ca) ca.addEventListener('click',function(){ all(false); });
    if(location.hash && document.getElementById(location.hash.slice(1))) setTimeout(function(){ openCard(location.hash.slice(1), true); }, 150);
  }
  window.smproFold=foldAll;        // re-fold a container whose HTML was replaced by AJAX
  window.smproOpenCard=openCard;
  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',init); else init();
})();
(function(){
  // table pager: a <div class="fw-pager"> placed right before a table (or its wrapper) filters + pages the <tr data-row> rows of that table.
  // data-per = rows per page (0 = filter only); data-input = id of an existing filter input to read instead of its own box.
  function setup(bar){
    if(bar.getAttribute('data-init')) return; bar.setAttribute('data-init','1');
    var nx=bar.nextElementSibling; while(nx && nx.tagName!=='TABLE' && !nx.querySelector('table')) nx=nx.nextElementSibling;
    var tbl=nx ? (nx.tagName==='TABLE'?nx:nx.querySelector('table')) : null; if(!tbl) return;
    var per=parseInt(bar.getAttribute('data-per')||'50',10); if(isNaN(per)||per<0) per=50;
    var ext=bar.getAttribute('data-input'), inp=ext?document.getElementById(ext):bar.querySelector('.fw-pgq');
    if(ext){ var own=bar.querySelector('.fw-pgq'); if(own) own.style.display='none'; }
    var info=bar.querySelector('.fw-pginfo'), ctl=bar.querySelector('.fw-pgctl'), num=bar.querySelector('.fw-pgnum'), prev=bar.querySelector('.fw-pgprev'), next=bar.querySelector('.fw-pgnext');
    var page=0, q='';
    function show(r,on){ r.style.display=on?'':'none'; var d=r.nextElementSibling; if(!on && d && d.tagName==='TR' && !d.hasAttribute('data-row')) d.style.display='none'; }
    function draw(){
      var tb=tbl.tBodies[0]; if(!tb) return;
      var rows=Array.prototype.slice.call(tb.querySelectorAll('tr[data-row]')), vis=[], i;
      for(i=0;i<rows.length;i++){ var r=rows[i]; var s=((r.getAttribute('data-search')||'')+' '+(r.textContent||'')).toLowerCase(); if(!q || s.indexOf(q)>=0) vis.push(r); else show(r,false); }
      var pages=per>0?Math.max(1,Math.ceil(vis.length/per)):1; if(page>pages-1) page=pages-1; if(page<0) page=0;
      for(i=0;i<vis.length;i++) show(vis[i], per<=0 || (i>=page*per && i<(page+1)*per));
      if(info) info.textContent = q ? (vis.length+' of '+rows.length+' match') : (rows.length+' row'+(rows.length===1?'':'s'));
      if(ctl) ctl.style.display = pages>1 ? '' : 'none';
      if(num) num.textContent=(page+1)+' / '+pages;
      if(prev) prev.disabled=page<=0; if(next) next.disabled=page>=pages-1;
    }
    if(inp) inp.addEventListener('input',function(){ q=(inp.value||'').trim().toLowerCase(); page=0; draw(); });
    if(prev) prev.addEventListener('click',function(){ if(page>0){ page--; draw(); } });
    if(next) next.addEventListener('click',function(){ page++; draw(); });
    tbl.addEventListener('click',function(e){ if(e.target.closest('thead th')) setTimeout(draw,0); });   // re-page after the global column sort reorders rows
    draw();
  }
  function all(root){ Array.prototype.forEach.call((root||document).querySelectorAll('.fw-pager'), setup); }
  window.smproPagers=all;
  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',function(){ all(document); }); else all(document);
})();
</script>

<?php if ($aaTab === 'bruteforce'): smpro_aa_bf_render($aaNetsHuman ?? [], $aaNetsBots ?? [], $aaNetsIgnored ?? [], $aaTrusted ?? [], 'index.cgi?' . http_build_query(['page'=>'account-audit','do'=>'search','audit_user'=>$user,'event_type'=>$type,'country'=>$country,'showlocal'=>($showlocal?'1':'0'),'from'=>$from,'to'=>$to,'loglines'=>$dlog,'q'=>$search]), array_sum(array_map(fn($n) => count($n['ips']), ($aaNets ?? []) + ($aaNetsIgnored ?? []))), array_sum(array_map(fn($n) => $n['fails'], ($aaNets ?? []) + ($aaNetsIgnored ?? []))), function_exists('smpro_im_home_regions_label') ? smpro_im_home_regions_label() : 'not set'); if (!empty($aaT)) { $aaT['end'] = microtime(true); $aaTs = []; $aaPrev = $aaT['start']; foreach ($aaT as $k => $v) { if ($k === 'start') continue; $aaTs[] = $k . '=' . round($v - $aaPrev, 2) . 's'; $aaPrev = $v; } echo "\n<!-- smpro-timing account-audit: total=" . round($aaT['end'] - $aaT['start'], 2) . "s " . implode(' ', $aaTs) . " -->\n"; }
smpro_layout_footer(); return; endif; ?>
<?php if ($aaTab === 'webact'): smpro_aa_web_render($user); if (!empty($aaT)) { $aaT['end'] = microtime(true); $aaTs = []; $aaPrev = $aaT['start']; foreach ($aaT as $k => $v) { if ($k === 'start') continue; $aaTs[] = $k . '=' . round($v - $aaPrev, 2) . 's'; $aaPrev = $v; } echo "\n<!-- smpro-timing account-audit: total=" . round($aaT['end'] - $aaT['start'], 2) . "s " . implode(' ', $aaTs) . " -->\n"; }
smpro_layout_footer(); return; ?>
<?php elseif ($aaTab !== 'audit'): smpro_la_render_tab($aaTab, $laDays, $laFrom, $laTo, $laFromTs, $laToTs); if (!empty($aaT)) { $aaT['end'] = microtime(true); $aaTs = []; $aaPrev = $aaT['start']; foreach ($aaT as $k => $v) { if ($k === 'start') continue; $aaTs[] = $k . '=' . round($v - $aaPrev, 2) . 's'; $aaPrev = $v; } echo "\n<!-- smpro-timing account-audit: total=" . round($aaT['end'] - $aaT['start'], 2) . "s " . implode(' ', $aaTs) . " -->\n"; }
smpro_layout_footer(); return; ?>
<?php endif; ?>
<p class="sub" style="margin:0 0 12px">Read-only login &amp; activity audit from cPanel logs, with IP intelligence. Evidence redacted (no tokens/cpsess).</p>
<?php
// ---- the overview for this tab, read from the same values the cards below use
$aaFS = $aaForeignSucc ?? []; $aaBF = $aaBrute ?? [];
$aaOv = [
  ['id' => 'aa-events', 'l' => 'Events', 'v' => number_format((int)$total), 'cls' => 'brand', 's' => 'matched in the scanned log window'],
  ['id' => 'aa-events', 'l' => 'Local', 'v' => number_format((int)$localCount), 'cls' => 'muted', 's' => 'localhost (127.0.0.1) events' . ($showlocal ? ' · shown' : ' · hidden')],
  ['id' => 'aa-events', 'l' => 'Foreign successes', 'v' => (string)count($aaFS), 'cls' => $aaFS ? 'dang' : 'good', 's' => $aaFS ? 'successful sign-ins from outside the region' : 'no foreign successful sign-in'],
  ['id' => 'aa-events', 'href' => 'index.cgi?page=account-audit&tab=bruteforce&loglines=' . (int)$dlog, 'l' => 'Brute-force sources', 'v' => (string)count($aaBF), 'cls' => $aaBF ? 'warn' : 'good', 's' => $aaBF ? 'addresses with >3 failed foreign attempts · open the report' : 'no brute-force source'],
];
$aaNav = [['aa-events', '&#128203; Events'], ['aaSavedCard', '&#128190; Saved reports']];
?>
<div class="fw-kpis">
  <?php foreach ($aaOv as $k): ?>
  <a class="fw-kpi <?= $k['cls'] ?>" href="<?= isset($k['href']) ? smpro_h($k['href']) : '#' . $k['id'] ?>"<?= isset($k['href']) ? '' : ' data-go="' . $k['id'] . '"' ?>><div class="l"><?= smpro_h($k['l']) ?></div><div class="v"><?= smpro_h($k['v']) ?></div><div class="s"><?= smpro_h($k['s']) ?></div></a>
  <?php endforeach; ?>
</div>
<nav class="fw-nav" id="fwNav"><?php foreach ($aaNav as [$id, $lbl]): ?><a href="#<?= $id ?>" data-go="<?= $id ?>"><?= $lbl ?></a><?php endforeach; ?><span class="sp"></span><button type="button" class="fw-navx" id="fwOpenAll">expand all</button><button type="button" class="fw-navx" id="fwCloseAll">collapse all</button></nav>

<form method="get" action="<?= $self ?>" class="card" style="margin-bottom:14px">
  <input type="hidden" name="tab" value="audit">
  <input type="hidden" name="page" value="account-audit">
  <input type="hidden" name="do" value="search">
  <div class="aa-grid">
    <label>cPanel account<input class="tp-in" name="audit_user" value="<?= smpro_h($user) ?>" placeholder="start typing… (blank = all)" data-ac="accounts" autocomplete="off"></label>
    <label>Event type
      <select class="tp-sel" name="event_type">
        <?php foreach (['all'=>'All Events','success_login'=>'Successful logins','failed_login'=>'Failed logins','login_request'=>'Login requests','password_change'=>'Password changes','technical'=>'Technical','panel_action'=>'Panel actions (API / File Manager)'] as $k=>$v): ?>
          <option value="<?= $k ?>"<?= $type===$k?' selected':'' ?>><?= $v ?></option>
        <?php endforeach; ?>
      </select>
    </label>
    <label>Country
      <select class="tp-sel" name="country">
        <?php $cOpts = ['all'=>'All countries','foreign'=>'Foreign (outside the home regions)'];
        foreach (smpro_im_home_regions() as $hrCc) $cOpts[$hrCc] = $hrCc . ' only'; ?>
        <?php foreach ($cOpts as $k=>$v): ?>
          <option value="<?= $k ?>"<?= $country===$k?' selected':'' ?>><?= $v ?></option>
        <?php endforeach; ?>
        <?php if (!isset($cOpts[$country]) && $country!=='all'): ?><option value="<?= smpro_h($country) ?>" selected><?= smpro_h($country) ?> only</option><?php endif; ?>
      </select>
    </label>
    <label>Localhost (127.0.0.1)
      <select class="tp-sel" name="showlocal">
        <option value="0"<?= $showlocal?'':' selected' ?>>Hidden (default)</option>
        <option value="1"<?= $showlocal?' selected':'' ?>>Show 127.0.0.1 events</option>
      </select>
    </label>
    <label>From date <span class="meta" style="font-weight:400">(blank = oldest)</span><input class="tp-in" type="date" name="from" value="<?= smpro_h($from) ?>" title="Leave blank to scan from the oldest available log entry"></label>
    <label>To date <span class="meta" style="font-weight:400">(blank = latest)</span><input class="tp-in" type="date" name="to" value="<?= smpro_h($to) ?>" title="Leave blank to scan up to the newest available log entry"></label>
    <label>Log lines
      <select class="tp-sel" name="loglines">
        <?php foreach ([20000,50000,100000,200000,500000] as $n): ?>
          <option value="<?= $n ?>"<?= $dlog===$n?' selected':'' ?>><?= number_format($n) ?></option>
        <?php endforeach; ?>
      </select>
    </label>
    <input type="hidden" name="q" value="<?= smpro_h($search) ?>">
    <div class="aa-actions">
      <button class="tp-btn primary" type="submit">Search</button>
      <?php $exp = ['page'=>'account-audit','audit_user'=>$user,'event_type'=>$type,'country'=>$country,'showlocal'=>($showlocal?'1':'0'),'from'=>$from,'to'=>$to,'loglines'=>$dlog,'q'=>$search]; ?>
      <div class="aa-export">
        <button class="tp-btn green" type="button" id="aaExportBtn">Export ▾</button>
        <div class="aa-menu" id="aaExportMenu">
          <a href="<?= smpro_h(smpro_aa_qs($exp + ['format'=>'csv'])) ?>">CSV</a>
          <a href="<?= smpro_h(smpro_aa_qs($exp + ['format'=>'html'])) ?>">HTML</a>
          <a href="<?= smpro_h(smpro_aa_qs($exp + ['format'=>'pdf'])) ?>" target="_blank">PDF (print)</a>
        </div>
      </div>
    </div>
  </div>
  <div style="margin-top:10px"><a class="tp-btn" href="<?= $self ?>?page=account-audit&tab=resets">Password Reset Audit</a>
    <?php if ($user): ?><a class="tp-btn" href="<?= $self ?>?page=top-processes">← Top Processes</a><?php endif; ?></div>
</form>

<?php if ($search !== '' && filter_var($search, FILTER_VALIDATE_IP)) smpro_aa_ip_investigation_render($search); ?>

<?php if ($savedId): ?>
<div class="card" style="margin-bottom:14px;border-left:3px solid var(--good);background:var(--good-bg);color:var(--good)">
  <b>Report saved for 90 days: <?= smpro_h($savedId) ?></b>
</div>
<?php endif; ?>

<div class="aa-sum">
  <div class="card"><div class="lbl">User</div><div class="val" style="font-size:18px"><?= $user!==''?smpro_h($user):'all' ?></div></div>
  <div class="card"><div class="lbl">Total events</div><div class="val"><?= (int)$sum['total'] ?></div></div>
  <div class="card"><div class="lbl">Unique addresses</div><div class="val"><?= (int)$uniqueIps ?></div></div>
  <div class="card"><div class="lbl">Successful logins</div><div class="val" style="color:var(--good)"><?= (int)$sum['success'] ?></div></div>
  <div class="card"><div class="lbl">Failed attempts</div><div class="val" style="color:var(--dang)"><?= (int)$sum['failed'] ?></div></div>
  <div class="card"><div class="lbl">Hidden technical</div><div class="val"><?= (int)$hiddenTech ?></div></div>
</div>
<?php
  // Period line - when a date box is left blank we scan the FULL available window; show the ACTUAL
  // oldest->newest timestamps detected (bounded by the log-lines setting), not an artificial 7-day span.
  $periodTxt = ($from !== '' || $to !== '')
      ? (($from !== '' ? smpro_h($from) : 'oldest') . ' → ' . ($to !== '' ? smpro_h($to) : 'latest'))
      : (($spanMin && $spanMax) ? (date('Y-m-d H:i', $spanMin) . ' → ' . date('Y-m-d H:i', $spanMax) . ' (full available range)') : 'full available range');
?>
<div class="card" style="margin-bottom:12px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;font-size:13px">
  <span class="b <?= $openRange ? 'blue' : 'gray' ?>">&#128197; Period</span>
  <b><?= $periodTxt ?></b>
  <?php if ($openRange): ?><span class="meta">— both date boxes blank means the widest range in the last <?= number_format($dlog) ?> log lines. Set a date to narrow it.</span><?php endif; ?>
  <?php if (!empty($aaScanMeta)): ?><span class="meta" style="margin-left:8px"><?= !empty($aaScanMeta['cached']) ? 'from the scan of ' . smpro_h(date('H:i:s', (int)$aaScanMeta['at'])) . ' (paging and sorting do not re-read the log)' : 'scan took ' . smpro_h((string)$aaScanMeta['took']) . ' s' ?> &middot; <a href="<?= smpro_h(smpro_aa_qs(['page'=>'account-audit','audit_user'=>$user,'event_type'=>$type,'country'=>$country,'showlocal'=>($showlocal?'1':'0'),'from'=>$from,'to'=>$to,'loglines'=>$dlog,'q'=>$search,'do'=>'search','fresh'=>1])) ?>">re-scan now</a></span><?php endif; ?>
</div>

<div class="card" id="aa-events" style="padding:0;overflow:hidden">
  <div class="tp-th"><b>Events</b><span class="meta"><?= (int)$total ?> matched · page <?= (int)$page ?>/<?= (int)$pages ?><?php if (!$showlocal && $localCount > 0): ?> · <a href="<?= smpro_h(smpro_aa_qs($exp + ['showlocal'=>'1','do'=>'search'])) ?>"><?= (int)$localCount ?> localhost (127.0.0.1) hidden — show</a><?php elseif ($showlocal): ?> · <a href="<?= smpro_h(smpro_aa_qs($exp + ['showlocal'=>'0','do'=>'search'])) ?>">hide 127.0.0.1</a><?php endif; ?></span></div>
  <div class="fw-pager" data-per="0"><input type="text" class="fw-pgq" placeholder="Filter this page&hellip;"><span class="fw-pginfo"></span><span class="sp"></span><span class="fw-pgctl"><button type="button" class="fw-pgbtn fw-pgprev">&#8249;</button> <span class="mono fw-pgnum"></span> <button type="button" class="fw-pgbtn fw-pgnext">&#8250;</button></span></div>
  <div class="smpro-tablewrap">
    <table class="smpro-table aa-events" data-serversort="1">
      <?php
        // Each header is a real link: it re-runs the search with a new order and returns to page 1, so the sort
        // applies to the whole result and survives paging. Clicking the active column flips its direction.
        $aaSortBase = ['page'=>'account-audit','audit_user'=>$user,'event_type'=>$type,'country'=>$country,
                       'showlocal'=>($showlocal?'1':'0'),'from'=>$from,'to'=>$to,'loglines'=>$dlog,'q'=>$search,'do'=>'search'];
        $aaTh = function (string $key, string $label) use ($aaSortBase, $aaSort, $aaDir) {
            $active = ($aaSort === $key);
            $next   = ($active && $aaDir === 'desc') ? 'asc' : 'desc';
            $arrow  = $active ? ($aaDir === 'asc' ? ' \u{25B2}' : ' \u{25BC}') : '';
            $url    = smpro_aa_qs($aaSortBase + ['sort'=>$key,'dir'=>$next]);
            printf('<th%s><a href="%s" style="color:inherit;text-decoration:none" title="Sort the whole result by %s">%s%s</a></th>',
                $active ? ' class="sorted"' : '', smpro_h($url), smpro_h($label), smpro_h($label), $arrow);
        };
      ?>
      <thead><tr><?php
        $aaTh('time','Time'); $aaTh('type','Type'); $aaTh('result','Result'); $aaTh('service','Service');
        $aaTh('ip','IP / Country / Provider'); $aaTh('user','Login User'); $aaTh('account','Account');
        $aaTh('action','Action');
      ?><th>Details</th></tr></thead>
      <tbody id="aaBody">
      <?php if (!$slice): ?>
        <tr><td colspan="9" style="padding:24px;text-align:center;color:var(--muted)">No matching events were found for the selected period and log range.</td></tr>
      <?php else: $i=0; foreach ($slice as $e): $i++; $in=$e['intel']; ?>
        <tr data-row>
          <td><?= smpro_h($e['time']) ?></td>
          <td><?= smpro_aa_badge($e['kind']) ?></td>
          <td><?= smpro_h($e['result'] ?? '') ?></td>
          <td><?= smpro_h($e['service']) ?></td>
          <td>
            <div class="ipmono"><?= smpro_h($e['ip']) ?></div>
            <?php if (($in['scope'] ?? '')==='external'): ?><span class="b orange">External</span><?php elseif (($in['scope'] ?? '')==='local'): ?><span class="b gray">Local</span><?php endif; ?>
            <?php if (!empty($in['country']) && $in['country']!=='n/a'): ?><div class="ipmeta"><b>Country:</b> <?= smpro_h($in['country']) ?></div><?php endif; ?>
            <?php if (!empty($in['provider']) && $in['provider']!=='n/a'): ?><div class="ipmeta"><b>Provider:</b> <?= smpro_h($in['provider']) ?></div><?php endif; ?>
            <?php if (!empty($in['asn'])): ?><div class="ipmeta"><b>ASN:</b> <?= smpro_h($in['asn']) ?></div><?php endif; ?>
            <?php if (!empty($in['source']) && $in['source']!=='unavailable'): ?><div class="ipmeta"><b>Lookup:</b> <?= smpro_h($in['source']) ?></div><?php endif; ?>
          </td>
          <td class="uname"><?= smpro_h($e['login_user']) ?: '—' ?></td>
          <td class="uname"><?= smpro_h($e['account']) ?: '—' ?></td>
          <td class="meta"><?= smpro_h($e['action']) ?></td>
          <td><button class="tp-btn" type="button" data-det="<?= $i ?>">Details</button></td>
        </tr>
        <tr class="aa-det"><td colspan="9">
          <div class="tp-details"><?php
            echo '<span class="dl">SOURCE</span>' . smpro_h($e['source'])
               . '<span class="dl">EVIDENCE</span>' . smpro_h($e['evidence']);
          ?></div>
        </td></tr>
      <?php endforeach; endif; ?>
      </tbody>
    </table>
  </div>
  <?php if ($pages > 1): $base = ['page'=>'account-audit','audit_user'=>$user,'event_type'=>$type,'country'=>$country,'showlocal'=>($showlocal?'1':'0'),'from'=>$from,'to'=>$to,'loglines'=>$dlog,'q'=>$search,'sort'=>$aaSort,'dir'=>$aaDir,'do'=>'search']; ?>
  <div style="display:flex;gap:8px;align-items:center;justify-content:center;padding:14px;flex-wrap:wrap">
    <?php if ($page>1): ?><a class="tp-btn" href="<?= smpro_h(smpro_aa_qs($base + ['p'=>$page-1])) ?>">‹ Prev</a><?php endif; ?>
    <span class="meta">Page <?= (int)$page ?> of <?= (int)$pages ?></span>
    <?php if ($page<$pages): ?><a class="tp-btn" href="<?= smpro_h(smpro_aa_qs($base + ['p'=>$page+1])) ?>">Next ›</a><?php endif; ?>
  </div>
  <?php endif; ?>
</div>

<div class="card" id="aaSavedCard" style="padding:0;overflow:hidden;margin-top:14px<?= $saved ? '' : ';display:none' ?>">
  <div class="tp-th"><b>Saved Reports</b><span class="meta">kept 90 days</span>
    <span style="flex:1"></span>
    <button class="tp-btn danger" id="aaDelSel" type="button" disabled>Delete selected (<span id="aaSelN">0</span>)</button>
  </div>
  <div class="smpro-tablewrap"><table class="smpro-table">
    <thead><tr>
      <th style="width:34px"><input type="checkbox" id="aaChkAll" title="Select all"></th>
      <th>Created</th><th>Period</th><th>Event type</th><th class="num">Events</th><th>Download</th><th>Manage</th>
    </tr></thead>
    <tbody id="aaSavedBody">
    <?php foreach ($saved as $r): ?>
      <tr data-rid="<?= smpro_h($r['id']) ?>">
        <td><input type="checkbox" class="aa-chk" value="<?= smpro_h($r['id']) ?>"></td>
        <td><?= smpro_h($r['created_at']) ?></td><td><?= ($r['from_date']==='' && $r['to_date']==='') ? '<span class="meta">full range</span>' : smpro_h(($r['from_date']?:'oldest').' / '.($r['to_date']?:'latest')) ?></td>
        <td><?= smpro_h($r['event_type']) ?></td><td class="num"><?= (int)$r['total'] ?></td>
        <td class="aa-dl">
          <a class="tp-btn" href="<?= smpro_h(smpro_aa_qs(['page'=>'account-audit','format'=>'csv','saved'=>$r['id']])) ?>">CSV</a>
          <a class="tp-btn" href="<?= smpro_h(smpro_aa_qs(['page'=>'account-audit','format'=>'html','saved'=>$r['id']])) ?>">HTML</a>
          <a class="tp-btn" target="_blank" href="<?= smpro_h(smpro_aa_qs(['page'=>'account-audit','format'=>'pdf','saved'=>$r['id']])) ?>">PDF</a>
        </td>
        <td><button class="tp-btn danger aa-del1" type="button" data-rid="<?= smpro_h($r['id']) ?>">Delete</button></td>
      </tr>
    <?php endforeach; ?>
    </tbody>
  </table></div>
  <div class="meta" id="aaSavedEmpty" style="padding:14px 16px;<?= $saved ? 'display:none' : '' ?>">No saved reports.</div>
  <div class="meta" style="padding:10px 16px;border-top:1px solid var(--line)">Reports auto-expire after 90 days. Select rows to delete several at once.</div>
</div>
<script>var AA_CSRF=<?= json_encode(smpro_csrf_generate('aa_delete')) ?>;</script>

<style>
.aa-sum{display:grid;grid-template-columns:repeat(6,1fr);gap:14px;margin-bottom:14px}
@media(max-width:1200px){.aa-sum{grid-template-columns:repeat(3,1fr)}}
@media(max-width:680px){.aa-sum{grid-template-columns:repeat(2,1fr)}}
.aa-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(165px,1fr));gap:12px;align-items:end}
.aa-grid label{display:flex;flex-direction:column;gap:5px;font-size:11px;text-transform:uppercase;letter-spacing:.03em;color:var(--muted);font-weight:700}
.aa-grid .tp-in,.aa-grid .tp-sel{width:100%}
.aa-actions{grid-column:1/-1;display:flex;gap:8px;align-items:center;justify-content:flex-end;margin-top:6px;padding-top:12px;border-top:1px solid var(--line)}
.aa-export{position:relative}
.aa-menu{display:none;position:absolute;right:0;top:calc(100% + 4px);background:var(--card);border:1px solid var(--line);border-radius:10px;box-shadow:0 12px 28px rgba(15,23,42,.12);z-index:5;min-width:140px;overflow:hidden}
.aa-export.open .aa-menu{display:block}
.aa-menu a{display:block;padding:9px 14px;font-size:13px;color:var(--ink);text-decoration:none;border:0}
.aa-menu a:hover{background:var(--brand-bg);color:var(--brand)}
.aa-dl{display:flex;gap:6px;flex-wrap:wrap}.aa-dl .tp-btn{padding:5px 10px;font-size:12px}
.tp-btn,.tp-sel,.tp-in{border:1px solid var(--line);background:var(--card);color:var(--ink);border-radius:9px;padding:8px 12px;font-size:13px;text-decoration:none}.tp-btn:hover{background:var(--brand-bg)}
.tp-btn.green{background:var(--good);color:#fff;border-color:var(--good)}
.tp-th{display:flex;align-items:center;gap:10px;padding:12px 16px;border-bottom:1px solid var(--line);flex-wrap:wrap}
.tp-th .meta{color:var(--muted);font-size:12px}
.smpro-tablewrap{overflow-x:auto}
.smpro-table{width:100%;border-collapse:collapse;font-size:13px}
.smpro-table th,.smpro-table td{padding:10px 12px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}
.smpro-table.aa-events th,.smpro-table.aa-events td{white-space:normal}
.smpro-table th{font-size:11px;text-transform:uppercase;letter-spacing:.03em;color:var(--muted);white-space:nowrap}
.smpro-table th.num,.smpro-table td.num{text-align:right}
.uname{font-family:ui-monospace,Consolas,monospace;font-weight:600}
.ipmono{font-family:ui-monospace,Consolas,monospace;font-weight:700}
.ipmeta{font-size:12px;color:var(--muted);margin-top:2px}.ipmeta b{color:var(--ink)}
.b{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:20px}
.b.red{background:var(--dang-bg);color:var(--dang)}.b.orange{background:var(--warn-bg);color:var(--warn)}.b.green{background:var(--good-bg);color:var(--good)}
.b.blue{background:var(--brand-bg);color:var(--brand)}.b.gray{background:var(--card);color:#475569}
.tp-details{display:none;background:#0f172a;color:#e5e7eb;border-radius:10px;padding:12px 14px;white-space:pre-wrap;word-break:break-word;font-family:ui-monospace,Consolas,monospace;font-size:12px;margin:4px 0;line-height:1.5}
.tp-details .dl{display:block;color:#7f93b8;font-weight:700;font-size:10px;letter-spacing:.08em;margin:8px 0 2px}
.tp-details .dl:first-child{margin-top:0}
tr.open + tr .tp-details{display:block}
</style>
<script>
document.getElementById('aaBody').addEventListener('click',function(ev){
  var b=ev.target.closest('button[data-det]');if(!b)return;
  b.closest('tr').classList.toggle('open');
});
(function(){
  var btn=document.getElementById('aaExportBtn');
  if(!btn)return;
  var box=btn.closest('.aa-export');
  btn.addEventListener('click',function(e){e.stopPropagation();box.classList.toggle('open');});
  document.addEventListener('click',function(){box.classList.remove('open');});
})();
// Saved Reports: AJAX delete (single + multi-select), no page reload.
(function(){
  var body=document.getElementById('aaSavedBody');
  if(!body)return;
  var chkAll=document.getElementById('aaChkAll'), delSel=document.getElementById('aaDelSel'), selN=document.getElementById('aaSelN');
  function checked(){return Array.prototype.slice.call(body.querySelectorAll('.aa-chk:checked'));}
  function refresh(){
    var n=checked().length;
    selN.textContent=n; delSel.disabled=n===0;
    var all=body.querySelectorAll('.aa-chk').length;
    chkAll.checked=all>0&&n===all; chkAll.indeterminate=n>0&&n<all;
  }
  function afterDelete(ids){
    ids.forEach(function(id){var tr=body.querySelector('tr[data-rid="'+CSS.escape(id)+'"]');if(tr)tr.remove();});
    if(!body.querySelector('tr')){
      var card=document.getElementById('aaSavedCard');
      document.getElementById('aaSavedEmpty').style.display='';
    }
    refresh();
  }
  function del(ids){
    if(!ids.length)return;
    if(!confirm('Delete '+ids.length+' saved report'+(ids.length>1?'s':'')+' permanently?'))return;
    var fd=new URLSearchParams();
    fd.set('aa_action','delete_report'); fd.set('report_ids',ids.join(',')); fd.set('smpro_csrf',AA_CSRF);
    fetch('index.cgi?page=account-audit',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'})
      .then(function(r){return r.json();})
      .then(function(j){if(j&&j.ok)afterDelete(j.deleted||ids);else alert('Delete failed.');})
      .catch(function(){alert('Delete failed (security token may have expired — reload the page).');});
  }
  body.addEventListener('change',function(e){if(e.target.classList.contains('aa-chk'))refresh();});
  body.addEventListener('click',function(e){var b=e.target.closest('.aa-del1');if(b)del([b.getAttribute('data-rid')]);});
  chkAll.addEventListener('change',function(){body.querySelectorAll('.aa-chk').forEach(function(c){c.checked=chkAll.checked;});refresh();});
  delSel.addEventListener('click',function(){del(checked().map(function(c){return c.value;}));});
  refresh();
})();
</script>
?>
<?php
if (!empty($aaT)) { $aaT['end'] = microtime(true); $aaTs = []; $aaPrev = $aaT['start']; foreach ($aaT as $k => $v) { if ($k === 'start') continue; $aaTs[] = $k . '=' . round($v - $aaPrev, 2) . 's'; $aaPrev = $v; } echo "\n<!-- smpro-timing account-audit: total=" . round($aaT['end'] - $aaT['start'], 2) . "s " . implode(' ', $aaTs) . " -->\n"; }
smpro_layout_footer();
