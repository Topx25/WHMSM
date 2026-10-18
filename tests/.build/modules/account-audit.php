<?php
/**
 * modules/account-audit.php — Account activity audit (read-only).
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
 * WEB ACTIVITY tab — per-account analysis of Apache domlogs
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
    $cmd = 'timeout 60 nice -n ' . SMPRO_SCAN_NICE . ' ionice -c3 grep -rHF ' . escapeshellarg($ip . ' ') . ' ' . escapeshellarg($base) . ' 2>/dev/null | grep -vE "bytes_log:|/ftp" | head -n 6000';
    $raw = (string)@shell_exec($cmd);
    $o = ['ip' => $ip, 'total' => 0, 'bytes' => 0, 'accounts' => [], 'domains' => [], 'urls' => [], 'methods' => [], 'status' => ['2xx'=>0,'3xx'=>0,'4xx'=>0,'5xx'=>0], 'recent' => []];
    foreach (explode("\n", $raw) as $line) {
        $c = strpos($line, ':'); if ($c === false) continue;
        $file = substr($line, 0, $c); $log = substr($line, $c + 1);
        if (strpos($file, $base) !== 0) continue;
        $dom = preg_replace('/-(ssl_log|bytes_log)$/', '', basename($file));
        $scheme = (substr(basename($file), -8) === '-ssl_log') ? 'https://' : 'http://';
        if (!preg_match('/^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+[^"]*"\s+(\d{3})\s+(\S+)/', $log, $m)) continue;
        if ($m[1] !== $ip) continue;
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
      <div class="meta" style="font-size:12px">Full IP investigation — login events below, plus every web request this IP made across all accounts.</div>
    </div>
    <?php
    $w = smpro_aa_ip_web($ip);
    if ($w === null) return;
    if (!$w['total']) { echo '<div class="card" style="color:var(--muted)">No web requests from this IP in the current domlogs.</div>'; return; }
    ?>
    <div class="card" style="padding:0;overflow:hidden;margin-bottom:14px;border-top:3px solid var(--brand)">
      <div class="tp-th"><b>&#127760; Web requests by <?= smpro_h($ip) ?></b><span class="meta"><?= number_format($w['total']) ?> requests · <?= $bytes($w['bytes']) ?> served · <?= count($w['accounts']) ?> account(s)</span></div>
      <div class="wa-row" style="margin:0;border-bottom:1px solid var(--line)">
        <div class="wa-mini"><div class="wa-h">Accounts hit</div><?php foreach (array_slice($w['accounts'],0,8,true) as $a=>$n): ?><div class="wa-line"><a class="fa-lnk" href="index.cgi?page=account-audit&tab=webact&audit_user=<?= urlencode($a) ?>"><?= smpro_h($a) ?></a><b><?= number_format($n) ?></b></div><?php endforeach; ?></div>
        <div class="wa-mini"><div class="wa-h">Methods</div><?php foreach ($w['methods'] as $mt=>$n): ?><div class="wa-line"><span class="b <?= $mt==='GET'?'gray':($mt==='POST'?'blue':'orange') ?>"><?= smpro_h($mt) ?></span><b><?= number_format($n) ?></b></div><?php endforeach; ?></div>
        <div class="wa-mini"><div class="wa-h">Status</div><?php foreach (['2xx'=>'green','3xx'=>'gray','4xx'=>'orange','5xx'=>'red'] as $sc=>$cl): ?><div class="wa-line"><span class="b <?= $cl ?>"><?= $sc ?></span><b><?= number_format($w['status'][$sc]) ?></b></div><?php endforeach; ?></div>
      </div>
      <div class="tp-th" style="border-top:0"><b>Recent requests</b><span class="meta">full URL · newest first</span></div>
      <div class="wa-tw" style="max-height:420px"><table class="smpro-table"><thead><tr><th>Time</th><th>Method</th><th class="num">Status</th><th class="num">Bytes</th><th>URL</th></tr></thead><tbody>
        <?php foreach ($w['recent'] as $r): ?><tr><td class="mono" style="font-size:11px"><?= smpro_h(preg_replace('#^(\d+/\w+/\d+):#','$1 ',$r['date'])) ?></td><td><span class="b <?= $r['method']==='GET'?'gray':($r['method']==='POST'?'blue':'orange') ?>"><?= smpro_h($r['method']) ?></span></td><td class="num"><span class="b <?= $r['status']>=500?'red':($r['status']>=400?'orange':($r['status']>=300?'gray':'green')) ?>"><?= (int)$r['status'] ?></span></td><td class="num meta"><?= $r['bytes']?$bytes($r['bytes']):'—' ?></td><td class="mono wa-file"><?= smpro_h($r['url']) ?></td></tr><?php endforeach; ?>
      </tbody></table></div>
    </div>
    <style>.aa-ipban{margin-bottom:14px}.aa-ipl{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:4px}.aa-ipip{font-family:ui-monospace,Consolas,monospace;font-weight:800;font-size:18px}
    .wa-row{display:grid;grid-template-columns:1fr 1fr 1fr;gap:1px;background:var(--line)}.wa-mini{background:#fff;padding:12px 14px}.wa-h{font-size:11px;font-weight:700;color:var(--muted);text-transform:uppercase;margin-bottom:6px}.wa-line{display:flex;justify-content:space-between;align-items:center;padding:3px 0;font-size:12.5px}
    .wa-tw{overflow:auto}.wa-tw thead th{position:sticky;top:0;background:#fafbfe;z-index:1;box-shadow:inset 0 -1px 0 var(--line)}.wa-file{white-space:normal;word-break:break-all;max-width:640px;font-size:11.5px}
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
    if ($d['ips']) smpro_ip_intel_bulk(array_keys(array_slice($d['ips'], 0, 30, true)));
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
    .wa-kpi{background:#fff;border:1px solid var(--line);border-radius:12px;padding:14px;text-align:center}
    .wa-kpi.dn{border-top:3px solid var(--good)}.wa-kpi.up{border-top:3px solid var(--brand)}.wa-kpi.crit{border-top:3px solid var(--dang)}
    .wa-kpi .kn{font-size:22px;font-weight:800;line-height:1}.wa-kpi .kl{font-size:11px;text-transform:uppercase;color:var(--muted);margin-top:6px;font-weight:700}.wa-kpi .km{font-size:11px;color:var(--muted);margin-top:2px}
    .wa-kpi.crit .kn{color:var(--dang)}.wa-kpi.dn .kn{color:var(--good)}.wa-kpi.up .kn{color:var(--brand)}
    .wa-row{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px;margin:0 0 14px}@media(max-width:760px){.wa-row{grid-template-columns:1fr}}
    .wa-mini{padding:14px 16px}.wa-h{font-size:12px;font-weight:700;color:var(--muted);text-transform:uppercase;margin-bottom:8px}
    .wa-line{display:flex;justify-content:space-between;align-items:center;padding:4px 0;font-size:13px}
    .ar-two{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin:0 0 14px}@media(max-width:900px){.ar-two{grid-template-columns:1fr}}
    .wa-tw{overflow:auto;max-height:360px}.wa-tw thead th{position:sticky;top:0;background:#fafbfe;z-index:1;box-shadow:inset 0 -1px 0 var(--line)}
    .wa-file{white-space:normal;word-break:break-all;max-width:640px;font-size:11.5px}.wa-empty{padding:16px;text-align:center;color:var(--muted)}
    .tp-th{display:flex;align-items:center;gap:10px;padding:12px 16px;border-bottom:1px solid var(--line);font-weight:700;font-size:14px}.tp-th .meta{margin-left:auto;color:var(--muted);font-size:12px}
    .ipmono{font-family:ui-monospace,Consolas,monospace;font-weight:700}.b.blue{background:var(--brand-bg);color:var(--brand)}
    </style>
    <?php
}

/* ---------- small json helpers ---------- */
function smpro_aa_json_load($p) { $d = is_file($p) ? json_decode((string)@file_get_contents($p), true) : null; return is_array($d) ? $d : []; }
function smpro_aa_json_save($p, $d) { @is_dir(dirname($p)) || @mkdir(dirname($p), 0700, true); $t = $p . '.tmp'; @file_put_contents($t, json_encode($d, JSON_UNESCAPED_SLASHES), LOCK_EX); @rename($t, $p); @chmod($p, 0600); }

/* ---------- log reading ---------- */
function smpro_aa_tail($file, $lines) {
    if (!is_readable($file)) return [];
    $n = max(1000, min(500000, (int)$lines));
    $raw = @shell_exec('timeout ' . SMPRO_TIMEOUT_NORMAL . ' tail -n ' . $n . ' ' . escapeshellarg($file) . ' 2>/dev/null');
    if ($raw === null || $raw === '') return [];
    return explode("\n", rtrim($raw, "\n"));
}

/* ---------- cPanel mapping ---------- */
function smpro_aa_user_domains($user) {
    static $c = [];
    if ($user === '' || !smpro_is_cpanel_user($user)) return [];
    if (isset($c[$user])) return $c[$user];
    $d = [];
    $f = '/var/cpanel/users/' . $user;
    if (is_readable($f)) foreach (file($f, FILE_IGNORE_NEW_LINES) ?: [] as $ln)
        if (preg_match('/^(?:DNS\d*|DOMAIN)\s*=\s*(\S+)/i', $ln, $m)) $d[strtolower($m[1])] = true;
    return $c[$user] = array_keys($d);
}
function smpro_aa_needles($wanted) {
    if ($wanted === '') return [];
    $n = [strtolower($wanted)];
    foreach (smpro_aa_user_domains($wanted) as $d) $n[] = $d;
    return $n;
}
function smpro_aa_match($needles, $actor, $evidence) {
    if (!$needles) return true;
    $a = strtolower($actor);
    foreach ($needles as $n) {
        if ($n === '') continue;
        if ($a === $n) return true;
        if (preg_match('/\b' . preg_quote($n, '/') . '\b/i', $evidence)) return true;
    }
    return false;
}
/** Resolve the cPanel account owning an actor (email user@domain → owner). */
function smpro_aa_resolve_account($actor) {
    static $map = null;
    if ($map === null) {
        $map = [];
        if (is_readable('/etc/userdomains')) foreach (file('/etc/userdomains', FILE_IGNORE_NEW_LINES) ?: [] as $ln)
            if (preg_match('/^([^:]+):\s*(\S+)/', $ln, $m)) $map[strtolower(trim($m[1]))] = trim($m[2]);
    }
    if (strpos($actor, '@') !== false) {
        $dom = strtolower(substr(strrchr($actor, '@'), 1));
        if (isset($map[$dom])) return $map[$dom];
    }
    if (smpro_is_cpanel_user($actor)) return $actor;
    return '';
}

/* ---------- time ---------- */
function smpro_aa_ts($raw) {
    $raw = trim($raw);
    if (preg_match('#^\d{1,2}/\w{1,3}/\d{4}:#', $raw) || preg_match('#^\d{1,2}/\d{1,2}/\d{4}:#', $raw))
        $raw = preg_replace('/:/', ' ', $raw, 1);
    return strtotime($raw) ?: 0;
}

/* ---------- IP intelligence (cached, capped) ---------- */
function &smpro_aa_ipcache() { static $c = null; if ($c === null) $c = smpro_aa_json_load(SMPRO_AA_IPCACHE); return $c; }
function smpro_aa_is_external($ip) { return (bool)filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE); }
function smpro_aa_parse_cymru($lines) {
    foreach ($lines as $l) {
        $l = trim($l);
        if ($l === '' || stripos($l, 'AS Name') !== false || stripos($l, 'Bulk mode') !== false || strpos($l, '|') === false) continue;
        $p = array_map('trim', explode('|', $l));
        if (count($p) >= 7) return ['asn' => 'AS' . $p[0], 'country' => $p[3], 'provider' => $p[6], 'source' => 'Team Cymru whois'];
    }
    return [];
}
function smpro_aa_ip_intel($ip) {
    static $new = 0;
    $ip = trim($ip);
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return ['ip' => $ip, 'country' => '', 'provider' => '', 'asn' => '', 'scope' => 'invalid', 'source' => 'invalid'];
    if (!smpro_aa_is_external($ip)) return ['ip' => $ip, 'country' => 'LOCAL', 'provider' => 'Private/Reserved', 'asn' => '', 'scope' => 'local', 'source' => 'local'];

    $cache = &smpro_aa_ipcache();
    $now = time();
    if (isset($cache[$ip]) && ($now - (int)($cache[$ip]['cached_at'] ?? 0)) < SMPRO_AA_IPTTL) {
        $r = $cache[$ip]; $r['scope'] = 'external'; return $r;
    }
    if ($new >= SMPRO_AA_IPMAXNEW) {
        $r = $cache[$ip] ?? ['ip' => $ip, 'country' => 'n/a', 'provider' => 'lookup limit reached', 'asn' => ''];
        $r['scope'] = 'external'; $r['source'] = 'lookup-limit'; return $r;
    }
    $new++;
    $intel = ['ip' => $ip, 'country' => 'n/a', 'provider' => 'n/a', 'asn' => '', 'source' => 'unavailable', 'cached_at' => $now];
    if (is_executable('/usr/bin/whois') || trim((string)@shell_exec('command -v whois')) !== '') {
        $raw = @shell_exec('timeout 4 whois -h whois.cymru.com ' . escapeshellarg(' -v ' . $ip) . ' 2>/dev/null');
        if ($raw) { $p = smpro_aa_parse_cymru(explode("\n", $raw)); if ($p) { $intel = array_merge($intel, $p); } }
    }
    $intel['scope'] = 'external';
    $cache[$ip] = $intel;
    smpro_aa_json_save(SMPRO_AA_IPCACHE, $cache);
    return $intel;
}

/* ---------- event collection ---------- */
function smpro_aa_collect($user, $type, $tail, $fromTs, $toTs) {
    $events = []; $hiddenTech = 0;
    $needles = smpro_aa_needles($user);
    $loginLog = '/usr/local/cpanel/logs/login_log';
    $accessLog = '/usr/local/cpanel/logs/access_log';
    $wantSuccess = in_array($type, ['all', 'success_login'], true);
    $wantFailed = in_array($type, ['all', 'failed_login'], true);

    if ($wantSuccess || $wantFailed) {
        foreach (smpro_aa_tail($loginLog, $tail) as $raw) {
            $raw = trim($raw); if ($raw === '') continue;
            // Two formats coexist in login_log:
            //  A) [TIME] level [service] IP - user - RESULT LOGIN service   (cpaneld/WHM account logins)
            //  B) IP - user [date] "METHOD" RESULT LOGIN service            (cpdavd/webmail)
            if (preg_match('/^\[([^\]]+)\]\s+\S+\s+\[([^\]]+)\]\s+(\S+)\s+-\s+(\S+)\s+-\s+(.+)$/', $raw, $m)) {
                $timeRaw = $m[1]; $svcA = $m[2]; $ip = $m[3]; $actor = rawurldecode($m[4]); $rest = $m[5];
            } elseif (preg_match('/^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*)"\s+(.+)$/', $raw, $m)) {
                $ip = $m[1]; $actor = rawurldecode($m[2]); $timeRaw = $m[3]; $svcA = ''; $rest = $m[5];
            } else {
                continue;
            }
            $isSuccess = (bool)preg_match('/SUCCEEDED\s+LOGIN|SUCCESS\s+LOGIN/i', $rest);
            $isFailed = !$isSuccess && (bool)preg_match('/FAILED\s+LOGIN|DEFERRED\s+LOGIN|AUTHENTICATION\s+FAILED|INVALID|FAILURE/i', $rest);
            if (!$isSuccess && !$isFailed) continue;
            if ($isSuccess && !$wantSuccess) continue;
            if ($isFailed && !$wantFailed) continue;
            if (!smpro_aa_match($needles, $actor, $raw)) continue;
            $ts = smpro_aa_ts($timeRaw); if ($ts < $fromTs || $ts > $toTs) continue;
            $service = $svcA !== '' ? $svcA
                     : (preg_match('/\b([a-z0-9_]+):/i', $rest, $sm) ? $sm[1] : (preg_match('/LOGIN\s+(\S+)/i', $rest, $s2) ? $s2[1] : 'cpanel'));
            $events[] = [
                'ts' => $ts, 'time' => date('Y-m-d H:i:s O', $ts),
                'type' => $isSuccess ? 'Successful Login' : 'Failed Login',
                'kind' => $isSuccess ? 'success_login' : 'failed_login',
                'result' => $isSuccess ? 'Successful Login' : 'Failed Login Attempt',
                'service' => $service, 'ip' => $ip,
                'login_user' => $actor, 'account' => smpro_aa_resolve_account($actor) ?: $actor,
                'action' => $isSuccess ? 'cPanel or WHM login event' : 'Rejected cPanel/WHM login attempt',
                'status' => '', 'source' => $loginLog, 'evidence' => smpro_redact_sensitive($raw),
            ];
        }
    }
    if (in_array($type, ['all', 'login_request', 'password_change', 'failed_login', 'technical'], true)) {
        foreach (smpro_aa_tail($accessLog, $tail) as $raw) {
            $raw = trim($raw); if ($raw === '') continue;
            if (!preg_match('/^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d{3})/', $raw, $m)) continue;
            $ip = $m[1]; $actor = rawurldecode($m[2]); if ($actor === '-') $actor = ''; $timeRaw = $m[3]; $request = $m[4]; $status = $m[5];
            $method = ''; $path = ''; $query = '';
            if (preg_match('/^(\S+)\s+(\S+)/', $request, $rm)) { $method = strtoupper($rm[1]); $path = parse_url($rm[2], PHP_URL_PATH) ?? $rm[2]; $query = parse_url($rm[2], PHP_URL_QUERY) ?? ''; }
            $isLogin = strpos($path, '/login') !== false || strpos($query, 'login_only=') !== false || strpos($query, 'user=') !== false;
            // Real password change = an actual change endpoint. Exclude bot file-probes
            // like GET /.htpasswd (404 scans) which merely contain the substring "passwd".
            $isPass = strpos($path, '.htpasswd') === false && (
                strpos($path, 'changepass') !== false ||
                strpos($path, 'change_password') !== false ||
                strpos($path, 'password/change') !== false ||
                strpos($path, 'passwd_pop') !== false ||
                (bool)preg_match('#/passwd(?:/|$)#', $path) ||
                strpos($query, 'emailpass') !== false
            );
            // A genuine password change is a POST that did not error out.
            if ($isPass && ($method !== 'POST' || in_array($status, ['400','401','403','404','429'], true))) {
                $isPass = false;
            }
            if (!$isLogin && !$isPass) continue;
            if (!smpro_aa_match($needles, $actor, $raw)) continue;
            $ts = smpro_aa_ts($timeRaw); if ($ts < $fromTs || $ts > $toTs) continue;
            $isFailedHttp = in_array($status, ['400','401','403','429'], true);
            $isTech = in_array($status, ['200','301','302','303','307','308'], true);
            if ($isTech && $type !== 'technical') { $hiddenTech++; continue; }
            if ($type === 'technical' && !$isTech) continue;
            if ($type === 'failed_login' && !$isFailedHttp) continue;
            if ($type === 'login_request' && (!$isLogin || $isFailedHttp || $isTech)) continue;
            if ($type === 'password_change' && (!$isPass || $isFailedHttp || $isTech)) continue;
            if ($isTech) { $kind='technical'; $t='Technical HTTP Event'; $res='HTTP '.$status; $act='Technical web login flow'; }
            elseif ($isFailedHttp) { $kind='failed_login'; $t='Failed Login'; $res='Failed Login Attempt'; $act='Rejected web login attempt'; }
            elseif ($isPass) { $kind='password_change'; $t='Password Change'; $res='HTTP '.$status; $act='Password related action'; }
            else { $kind='login_request'; $t='Login Request'; $res='HTTP '.$status; $act='Web login request'; }
            $events[] = [
                'ts' => $ts, 'time' => date('Y-m-d H:i:s O', $ts), 'type' => $t, 'kind' => $kind, 'result' => $res,
                'service' => 'cpanel access_log', 'ip' => $ip,
                'login_user' => $actor, 'account' => smpro_aa_resolve_account($actor) ?: $actor,
                'action' => $act, 'status' => $status, 'source' => $accessLog, 'evidence' => smpro_redact_sensitive($raw),
            ];
        }
    }
    usort($events, fn($a, $b) => $b['ts'] <=> $a['ts']);
    return [$events, $hiddenTech];
}

/**
 * Filter events by country using IP intelligence.
 *  'all'     → no filter
 *  'foreign' → external IPs whose country is NOT EG/SA (unknown externals kept,
 *              so suspicious un-resolved foreign IPs are never hidden)
 *  '<CC>'    → only that 2-letter country
 * Attaches ['intel'] to each surviving event so the view reuses it.
 */
/** Localhost (127.0.0.1 / ::1) events are internal cPanel noise — hidden unless requested. */
function smpro_aa_is_local_ip($ip) { return $ip === '127.0.0.1' || $ip === '::1' || strpos((string)$ip, '127.') === 0; }
function smpro_aa_filter_local($events, $show) {
    if ($show) return $events;
    return array_values(array_filter($events, fn($e) => !smpro_aa_is_local_ip($e['ip'] ?? '')));
}
function smpro_aa_count_local($events) { $n = 0; foreach ($events as $e) if (smpro_aa_is_local_ip($e['ip'] ?? '')) $n++; return $n; }

function smpro_aa_filter_country($events, $country) {
    if ($country === 'all' || $country === '') return $events;
    $out = [];
    foreach ($events as $e) {
        $in = smpro_aa_ip_intel($e['ip'] ?? '');
        $cc = strtoupper((string)($in['country'] ?? ''));
        $e['intel'] = $in;
        if ($country === 'foreign') {
            // foreign = external + NON-Arab (EG/SA/all Arab countries are trusted, never "foreign")
            if (($in['scope'] ?? '') === 'external' && $cc !== '' && !smpro_cc_is_arab($cc)) $out[] = $e;
        } elseif ($cc === $country) {
            $out[] = $e;
        }
    }
    return $out;
}

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
*{box-sizing:border-box}body{font:13px/1.5 -apple-system,Segoe UI,Arial,sans-serif;color:#1f2733;margin:0;padding:28px;background:#fff}
h1{font-size:20px;margin:0 0 4px}.muted{color:#6b7686;font-size:12px;margin:0 0 16px}
.cards{display:flex;gap:10px;flex-wrap:wrap;margin:0 0 18px}
.c{border:1px solid #e6eaf1;border-radius:10px;padding:10px 14px;min-width:120px}
.c .l{font-size:10px;text-transform:uppercase;color:#6b7686;letter-spacing:.04em}.c .v{font-size:20px;font-weight:700}
table{width:100%;border-collapse:collapse;font-size:12px}
th,td{border:1px solid #e6eaf1;padding:6px 8px;text-align:left;vertical-align:top}
th{background:#f4f6fb;font-size:10px;text-transform:uppercase;color:#475569}
.b{display:inline-block;font-size:10px;font-weight:700;padding:1px 7px;border-radius:20px}
.green{background:#e9f8ef;color:#1f9d55}.red{background:#fdecec;color:#d93b3b}.gray{background:#f1f5f9;color:#475569}.orange{background:#fdf6e7;color:#c47f17}
.ev{font-family:ui-monospace,Consolas,monospace;font-size:11px;color:#475569;word-break:break-all}
.head{display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:10px}
.brand{font-weight:700;color:#3b5bdb}
@media print{body{padding:0}.noprint{display:none}}
</style></head><body>";
    echo "<div class=\"head\"><div><h1>" . $h($title) . "</h1>"
       . "<p class=\"muted\">Period " . $h($meta['from']) . " → " . $h($meta['to']) . " · event type: " . $h($meta['type'])
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

/* ---------- request params ---------- */
$user = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)($_GET['audit_user'] ?? $_GET['user'] ?? ''));
$type = preg_replace('/[^a-z_]/', '', strtolower((string)($_GET['event_type'] ?? 'all')));
if (!in_array($type, ['all','success_login','failed_login','login_request','password_change','technical'], true)) $type = 'all';
$search = trim((string)($_GET['q'] ?? ''));
$country = (string)($_GET['country'] ?? 'all');
$country = ($country === 'foreign' || $country === 'all') ? $country : strtoupper(preg_replace('/[^a-zA-Z]/', '', $country));
if ($country === '') $country = 'all';
$showlocal = (string)($_GET['showlocal'] ?? '') === '1';   // localhost (127.0.0.1/::1) hidden unless requested
$dlog   = (int)($_GET['loglines'] ?? 50000);
if (!in_array($dlog, [20000,50000,100000,200000,500000], true)) $dlog = 50000;

$today  = date('Y-m-d');
$from   = preg_match('/^\d{4}-\d{2}-\d{2}$/', (string)($_GET['from'] ?? '')) ? $_GET['from'] : date('Y-m-d', time() - 7*86400);
$to     = preg_match('/^\d{4}-\d{2}-\d{2}$/', (string)($_GET['to'] ?? '')) ? $_GET['to'] : $today;
$fromTs = strtotime($from . ' 00:00:00');
$toTs   = strtotime($to . ' 23:59:59');

$fmt    = (string)($_GET['format'] ?? '');
$page   = max(1, (int)($_GET['p'] ?? 1));
$perPage = 50;

/* ---------- tabs: Account Audit (default) + merged Login & Access tabs ---------- */
$aaTab = (string)($_GET['tab'] ?? 'audit');
if (!in_array($aaTab, ['audit', 'overview', 'correlation', 'resets', 'webact'], true)) $aaTab = 'audit';
$laDays = (int)($_GET['days'] ?? 7); if (!in_array($laDays, [1, 7, 30], true)) $laDays = 7;
$laFromTs = time() - $laDays * 86400; $laToTs = time();
$laFrom = date('Y-m-d', $laFromTs); $laTo = date('Y-m-d', $laToTs);

/* ---------- POST: Login&Access actions (CSF block/allow/unblock, hide) — exits if matched ---------- */
smpro_la_handle_post();

/* ---------- delete saved report(s) — AJAX, POST + CSRF, returns JSON ---------- */
$reqMethod = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));
if ($reqMethod === 'POST' && ($_POST['aa_action'] ?? '') === 'delete_report') {
    smpro_require_valid_csrf('aa_delete');
    $ids = array_filter(array_map(
        fn($s) => preg_replace('/[^a-zA-Z0-9_-]/', '', $s),
        explode(',', (string)($_POST['report_ids'] ?? $_POST['report_id'] ?? ''))
    ));
    $deleted = [];
    foreach ($ids as $rid) if (smpro_aa_delete_report($rid)) $deleted[] = $rid;
    smpro_audit('account_audit_report_delete', ['ids' => $ids, 'deleted' => $deleted]);
    echo json_encode(['ok' => true, 'deleted' => $deleted], JSON_UNESCAPED_SLASHES);
    exit;
}

/* ---------- block a foreign attacker IP (POST + CSRF) — Arab/local IPs are refused ---------- */
if ($reqMethod === 'POST' && ($_POST['aa_action'] ?? '') === 'block_ip') {
    smpro_require_valid_csrf('aa_delete');
    smpro_require_root();
    header('Content-Type: application/json');
    $ip = trim((string)($_POST['ip'] ?? ''));
    if (!filter_var($ip, FILTER_VALIDATE_IP)) { echo json_encode(['ok'=>false,'msg'=>'Invalid IP.']); exit; }
    $in = smpro_aa_ip_intel($ip);
    $cc = strtoupper((string)($in['country'] ?? ''));
    $isLocal = ($in['scope'] ?? '') === 'local';
    $isArab = smpro_cc_is_arab($cc);
    $foreign = (($in['scope'] ?? '') === 'external' && $cc !== '' && $cc !== 'N/A' && $cc !== 'NA' && !$isArab);
    if (!$foreign) {
        $why = $isLocal ? 'local/private' : ($isArab ? ('Arab country ' . $cc . ' — protected') : ('country ' . ($cc ?: 'unknown') . ' is not flagged foreign'));
        echo json_encode(['ok'=>false,'msg'=>'Refused: only NON-Arab foreign IPs are blockable here (' . $why . ').']); exit;
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
        [$events, $h] = smpro_aa_collect($user, $type, $dlog, $fromTs, $toTs);
        if ($search !== '') { $n = strtolower($search); $events = array_values(array_filter($events, fn($e) => strpos(strtolower($e['ip'].' '.$e['login_user'].' '.$e['type'].' '.$e['evidence']), $n) !== false)); }
        $events = smpro_aa_filter_country($events, $country);
        $events = smpro_aa_filter_local($events, $showlocal);
    }

    if ($fmt === 'csv') {
        $fh = fopen('php://output', 'w');
        fputcsv($fh, ['time','type','result','service','ip','country','provider','asn','scope','login_user','account','action','source','evidence']);
        foreach ($events as $e) {
            $i = smpro_aa_ip_intel($e['ip']);
            fputcsv($fh, [$e['time'],$e['type'],$e['result'],$e['service'],$e['ip'],$i['country'],$i['provider'],$i['asn'],$i['scope'],$e['login_user'],$e['account'],$e['action'],$e['source'],$e['evidence']]);
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
if ($aaTab === 'audit') {
    [$events, $hiddenTech] = smpro_aa_collect($user, $type, $dlog, $fromTs, $toTs);
    if ($search !== '') { $n = strtolower($search); $events = array_values(array_filter($events, fn($e) => strpos(strtolower($e['ip'].' '.$e['login_user'].' '.$e['type'].' '.$e['evidence']), $n) !== false)); }
    $events = smpro_aa_filter_country($events, $country);
    $localCount = smpro_aa_count_local($events);             // localhost events present before hiding
    $events = smpro_aa_filter_local($events, $showlocal);

    $sum = ['total' => count($events), 'success' => 0, 'failed' => 0, 'ips' => []];
    foreach ($events as $e) {
        if ($e['kind'] === 'success_login') $sum['success']++;
        if ($e['kind'] === 'failed_login') $sum['failed']++;
        if ($e['ip'] !== '') $sum['ips'][$e['ip']] = true;
    }
    $uniqueIps = count($sum['ips']);

    // Save a report when the user explicitly searches.
    if (($_GET['do'] ?? '') === 'search') {
        $savedId = smpro_aa_save_report($user, ['from' => $from, 'to' => $to, 'type' => $type, 'loglines' => $dlog],
            $events, ['total' => $sum['total'], 'unique_ips' => $uniqueIps, 'success' => $sum['success'], 'failed' => $sum['failed'], 'hidden_tech' => $hiddenTech]);
    }
    $saved = smpro_aa_saved_for($user);

    $total = count($events);
    $pages = max(1, (int)ceil($total / $perPage));
    $page  = min($page, $pages);
    $slice = array_slice($events, ($page - 1) * $perPage, $perPage);
    // Attach IP intel only to the visible slice (bounded lookups).
    foreach ($slice as &$e) $e['intel'] = smpro_aa_ip_intel($e['ip']);
    unset($e);

    // Foreign-country (non-Arab) alerts — uses cached geo only (cheap). Red = a successful
    // foreign login; Orange = an IP with >3 failed foreign attempts (brute-force → blockable).
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
            if (!isset($aaFFail[$ipk])) $aaFFail[$ipk] = ['ip'=>$e['ip'],'cc'=>$cc,'n'=>0,'user'=>$e['account'] ?: $e['login_user']];
            $aaFFail[$ipk]['n']++;
        }
    }
    $aaBrute = array_values(array_filter($aaFFail, fn($x) => $x['n'] > 3));   // >3 failed = brute-force
    usort($aaBrute, fn($a,$b) => $b['n'] <=> $a['n']);
}

smpro_audit('account_audit_view', ['tab' => $aaTab, 'user' => $user, 'type' => $type, 'total' => $total]);

/* ---------- render ---------- */
smpro_layout_header('Account Audit');
$self = 'index.cgi';
function smpro_aa_badge($kind) {
    $map = ['success_login'=>['green','Successful Login'],'failed_login'=>['red','Failed Login'],'password_change'=>['orange','Password Change'],'login_request'=>['blue','Login Request'],'technical'=>['gray','Technical']];
    [$c,$t] = $map[$kind] ?? ['gray', ucfirst($kind)]; return '<span class="b '.$c.'">'.smpro_h($t).'</span>';
}
function smpro_aa_qs($o) { $q = []; foreach ($o as $k=>$v) $q[] = $k.'='.urlencode((string)$v); return 'index.cgi?'.implode('&',$q); }
$aaTabUrl = fn($t) => 'index.cgi?page=account-audit&tab=' . $t . ($t!=='audit' ? '&days='.$laDays : '');
?>
<div style="display:flex;justify-content:space-between;align-items:flex-start;gap:14px;flex-wrap:wrap;margin-bottom:4px">
  <div><h1 class="h" style="margin:0">Account Audit</h1>
    <p class="sub" style="margin:2px 0 0">Unified account &amp; login security — activity audit, login monitoring, source-IP correlation and password-reset auditing.</p></div>
  <?php if ($aaTab !== 'audit'): ?>
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
.aa-geobar.red{background:#fff5f5;border-color:#f3c9c9}
.aa-geobar.orange{background:#fffaf3;border-color:#f0d8b8}
.aa-geobar-ic{font-size:20px;line-height:1.2}
.aa-geobar-body{flex:1;min-width:0}
.aa-geobar-body>b{font-size:13.5px}
.aa-geobar-list{display:flex;flex-wrap:wrap;gap:6px;margin-top:7px}
.aa-geochip{display:inline-flex;align-items:center;gap:7px;background:#fff;border:1px solid var(--line);border-radius:20px;padding:3px 10px;font-size:12px;font-family:ui-monospace,Consolas,monospace}
.aa-geochip .tp-btn{font-size:11px;padding:2px 9px}
.aa-geobar-note{font-size:11.5px;color:var(--muted);margin-top:8px}
</style>
<div class="aa-geo-alerts">
  <?php if (!empty($aaForeignSucc)): ?>
  <div class="aa-geobar red">
    <div class="aa-geobar-ic">&#128681;</div>
    <div class="aa-geobar-body">
      <b><?= count($aaForeignSucc) ?> successful login(s) from a FOREIGN (non-Arab) country</b>
      <div class="aa-geobar-list">
        <?php foreach (array_slice($aaForeignSucc, 0, 8) as $s): ?>
        <span class="aa-geochip"><?= smpro_h($s['cc']) ?> &middot; <?= smpro_h($s['ip']) ?> &middot; <?= smpro_h($s['user']) ?> &middot; <?= smpro_h($s['time']) ?></span>
        <?php endforeach; ?>
      </div>
    </div>
  </div>
  <?php endif; ?>
  <?php if (!empty($aaBrute)): ?>
  <div class="aa-geobar orange">
    <div class="aa-geobar-ic">&#9888;&#65039;</div>
    <div class="aa-geobar-body">
      <b><?= count($aaBrute) ?> foreign IP(s) with brute-force (&gt;3 failed logins)</b>
      <div class="aa-geobar-list">
        <?php foreach ($aaBrute as $bx): ?>
        <span class="aa-geochip"><?= smpro_h($bx['cc']) ?> &middot; <?= smpro_h($bx['ip']) ?> &middot; <b><?= (int)$bx['n'] ?></b> fails
          <button class="tp-btn danger aaBlock" type="button" data-ip="<?= smpro_h($bx['ip']) ?>">Block</button></span>
        <?php endforeach; ?>
      </div>
      <div class="aa-geobar-note">Foreign IPs only — Arab &amp; local IPs are never blocked here. (24/7 auto-block runs in the firewall cron — next step.)</div>
    </div>
  </div>
  <?php endif; ?>
</div>
<script>
document.addEventListener('click',function(e){
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
  <a class="la-tab<?= $aaTab==='overview'?' active':'' ?>"    href="<?= smpro_h($aaTabUrl('overview')) ?>">&#128274; Login Monitor</a>
  <a class="la-tab<?= $aaTab==='correlation'?' active':'' ?>" href="<?= smpro_h($aaTabUrl('correlation')) ?>">&#8644; IP Correlation</a>
  <a class="la-tab<?= $aaTab==='resets'?' active':'' ?>"      href="<?= smpro_h($aaTabUrl('resets')) ?>">&#8635; Password Resets</a>
  <a class="la-tab<?= $aaTab==='webact'?' active':'' ?>"      href="<?= smpro_h($aaTabUrl('webact')) ?>">&#127760; Web Activity</a>
</div>
<?php smpro_la_assets(); ?>
<?php if ($aaTab === 'webact'): smpro_aa_web_render($user); smpro_layout_footer(); return; ?>
<?php elseif ($aaTab !== 'audit'): smpro_la_render_tab($aaTab, $laDays, $laFrom, $laTo, $laFromTs, $laToTs); smpro_layout_footer(); return; ?>
<?php endif; ?>
<p class="sub" style="margin:0 0 12px">Read-only login &amp; activity audit from cPanel logs, with IP intelligence. Evidence redacted (no tokens/cpsess).</p>

<form method="get" action="<?= $self ?>" class="card" style="margin-bottom:14px">
  <input type="hidden" name="tab" value="audit">
  <input type="hidden" name="page" value="account-audit">
  <input type="hidden" name="do" value="search">
  <div class="aa-grid">
    <label>cPanel account<input class="tp-in" name="audit_user" value="<?= smpro_h($user) ?>" placeholder="start typing… (blank = all)" data-ac="accounts" autocomplete="off"></label>
    <label>Event type
      <select class="tp-sel" name="event_type">
        <?php foreach (['all'=>'All Events','success_login'=>'Successful logins','failed_login'=>'Failed logins','login_request'=>'Login requests','password_change'=>'Password changes','technical'=>'Technical'] as $k=>$v): ?>
          <option value="<?= $k ?>"<?= $type===$k?' selected':'' ?>><?= $v ?></option>
        <?php endforeach; ?>
      </select>
    </label>
    <label>Country
      <select class="tp-sel" name="country">
        <?php $cOpts = ['all'=>'All countries','foreign'=>'Foreign (exclude EG, SA)','EG'=>'Egypt only','SA'=>'Saudi only']; ?>
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
    <label>From date<input class="tp-in" type="date" name="from" value="<?= smpro_h($from) ?>"></label>
    <label>To date<input class="tp-in" type="date" name="to" value="<?= smpro_h($to) ?>"></label>
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

<div class="card" style="padding:0;overflow:hidden">
  <div class="tp-th"><b>Events</b><span class="meta"><?= (int)$total ?> matched · page <?= (int)$page ?>/<?= (int)$pages ?><?php if (!$showlocal && $localCount > 0): ?> · <a href="<?= smpro_h(smpro_aa_qs($exp + ['showlocal'=>'1','do'=>'search'])) ?>"><?= (int)$localCount ?> localhost (127.0.0.1) hidden — show</a><?php elseif ($showlocal): ?> · <a href="<?= smpro_h(smpro_aa_qs($exp + ['showlocal'=>'0','do'=>'search'])) ?>">hide 127.0.0.1</a><?php endif; ?></span></div>
  <div class="smpro-tablewrap">
    <table class="smpro-table aa-events">
      <thead><tr><th>Time</th><th>Type</th><th>Result</th><th>Service</th><th>IP / Country / Provider</th><th>Login User</th><th>Account</th><th>Action</th><th>Details</th></tr></thead>
      <tbody id="aaBody">
      <?php if (!$slice): ?>
        <tr><td colspan="9" style="padding:24px;text-align:center;color:var(--muted)">No matching events were found for the selected period and log range.</td></tr>
      <?php else: $i=0; foreach ($slice as $e): $i++; $in=$e['intel']; ?>
        <tr>
          <td><?= smpro_h($e['time']) ?></td>
          <td><?= smpro_aa_badge($e['kind']) ?></td>
          <td><?= smpro_aa_badge($e['kind']) ?></td>
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
  <?php if ($pages > 1): $base = ['page'=>'account-audit','audit_user'=>$user,'event_type'=>$type,'country'=>$country,'from'=>$from,'to'=>$to,'loglines'=>$dlog,'q'=>$search]; ?>
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
        <td><?= smpro_h($r['created_at']) ?></td><td><?= smpro_h($r['from_date'].' / '.$r['to_date']) ?></td>
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
.aa-menu{display:none;position:absolute;right:0;top:calc(100% + 4px);background:#fff;border:1px solid var(--line);border-radius:10px;box-shadow:0 12px 28px rgba(15,23,42,.12);z-index:5;min-width:140px;overflow:hidden}
.aa-export.open .aa-menu{display:block}
.aa-menu a{display:block;padding:9px 14px;font-size:13px;color:var(--ink);text-decoration:none;border:0}
.aa-menu a:hover{background:var(--brand-bg);color:var(--brand)}
.aa-dl{display:flex;gap:6px;flex-wrap:wrap}.aa-dl .tp-btn{padding:5px 10px;font-size:12px}
.tp-btn,.tp-sel,.tp-in{border:1px solid var(--line);background:#fff;color:var(--ink);border-radius:9px;padding:8px 12px;font-size:13px;text-decoration:none}
.tp-btn{cursor:pointer;font-weight:600;display:inline-block}.tp-btn:hover{background:#f3f6ff}
.tp-btn.primary{background:var(--brand);color:#fff;border-color:var(--brand)}
.tp-btn.green{background:var(--good);color:#fff;border-color:var(--good)}
.tp-btn.danger{background:var(--dang-bg);color:var(--dang);border-color:#f3c4c4}.tp-btn.danger:hover{background:var(--dang);color:#fff}
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
.b.blue{background:var(--brand-bg);color:var(--brand)}.b.gray{background:#f1f5f9;color:#475569}
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
<?php
smpro_layout_footer();
