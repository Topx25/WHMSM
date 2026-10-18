<?php
/**
 * modules/intrusion-monitor.php — Intrusion Monitor (UI).
 *
 * Detects, tracks and reports web-attack attempts AS THEY HAPPEN, attributed to the
 * exact DOMAIN each attempt targeted. The detection ENGINE lives in includes/intrusion.php
 * (shared with the notify cron, so alerts fire even with no page open).
 *
 * Tabs:  live      → auto-refreshing feed of the most recent attacks (poll, no reload)
 *        domains   → attempts aggregated BY DOMAIN (counts, attack types, top attackers)
 *        breaches  → likely successful compromises (attack 200 + recent docroot change)
 *        campaigns → coordinated attacks (one IP → many domains, many IPs → one domain)
 *        reports   → generate / view / export (CSV) / delete full saved reports
 *        settings  → Cloudflare/CSF blocking, auto-response, allowlist, alert thresholds
 *
 * Read on GET; all state-changing actions are POST + CSRF + root + audit. IP blocking
 * (CSF + Cloudflare edge) never touches the admin's own IP, the server, or allowlisted IPs.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

define('SMPRO_IM_REPORTS', SMPRO_VARLIB . '/reports/intrusion');
define('SMPRO_IM_REPIDX',  SMPRO_IM_REPORTS . '/index.json');

/* ============================ saved reports ============================ */
function smpro_im_json_load($p) { $d = is_file($p) ? json_decode((string)@file_get_contents($p), true) : null; return is_array($d) ? $d : []; }
function smpro_im_json_save($p, $d) { @is_dir(dirname($p)) || @mkdir(dirname($p), 0700, true); $t = $p . '.tmp'; @file_put_contents($t, json_encode($d, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), LOCK_EX); @rename($t, $p); @chmod($p, 0600); }
function smpro_im_reports_index() { $i = smpro_im_json_load(SMPRO_IM_REPIDX); return is_array($i) ? $i : []; }
function smpro_im_save_report($mins, $events, $byDomain) {
    $id = date('Ymd_His') . '_' . substr(hash('sha256', uniqid('', true)), 0, 8);
    $path = SMPRO_IM_REPORTS . '/' . $id . '.json';
    $rec = ['id'=>$id,'created_ts'=>time(),'created'=>date('Y-m-d H:i:s'),'window_mins'=>(int)$mins,'total'=>count($events),'domains'=>count($byDomain),
        'uniq_ips'=>count(array_unique(array_filter(array_map(fn($e)=>$e['ip'],$events)))),
        'by_domain'=>array_map(fn($g)=>['domain'=>$g['domain'],'account'=>$g['account'],'total'=>$g['total'],'uniq_ips'=>$g['uniq_ips'],'top_cat'=>$g['top_cat'],'cats'=>$g['cats'],'sev'=>$g['sevlabel'],'top_ips'=>array_slice($g['ips'],0,10,true),'first'=>$g['first'],'last'=>$g['last']], $byDomain)];
    smpro_im_json_save($path, $rec);
    $idx = smpro_im_reports_index();
    array_unshift($idx, ['id'=>$id,'created'=>$rec['created'],'created_ts'=>$rec['created_ts'],'total'=>$rec['total'],'domains'=>$rec['domains'],'window_mins'=>$rec['window_mins'],'path'=>$path]);
    smpro_im_json_save(SMPRO_IM_REPIDX, array_slice($idx, 0, 200));
    return $id;
}
function smpro_im_delete_report($id) {
    $id = preg_replace('/[^0-9A-Za-z_]/', '', (string)$id); if ($id === '') return false;
    $idx = smpro_im_reports_index(); $keep = []; $ok = false;
    foreach ($idx as $r) { if (($r['id'] ?? '') === $id) { $p = $r['path'] ?? ''; if ($p && strpos($p, SMPRO_IM_REPORTS) === 0 && is_file($p)) @unlink($p); $ok = true; } else $keep[] = $r; }
    smpro_im_json_save(SMPRO_IM_REPIDX, $keep);
    return $ok;
}
function smpro_im_report_path($id) { $id = preg_replace('/[^0-9A-Za-z_]/', '', (string)$id); foreach (smpro_im_reports_index() as $r) if (($r['id'] ?? '') === $id) return $r['path'] ?? ''; return ''; }
function smpro_im_render_report_html($rep, $print) {
    $h = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    echo "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Intrusion Report " . $h($rep['id'] ?? '') . "</title><style>
*{box-sizing:border-box}body{font:13px/1.5 -apple-system,Segoe UI,Arial,sans-serif;color:#1f2733;margin:0;padding:28px}
h1{font-size:20px;margin:0 0 4px}.muted{color:#6b7686;font-size:12px;margin:0 0 16px}
table{width:100%;border-collapse:collapse;font-size:12px;margin-top:10px}th,td{border:1px solid #e6eaf1;padding:6px 9px;text-align:left;vertical-align:top}
th{background:#f4f6fb;text-transform:uppercase;font-size:10px;color:#475569}
.b{display:inline-block;font-size:10px;font-weight:700;padding:1px 7px;border-radius:20px;background:#fdecec;color:#b91c1c}
.k{display:inline-block;font-size:10px;background:#eef2ff;color:#3b5bdb;border-radius:10px;padding:1px 7px;margin:1px}
.brand{color:#3b5bdb;font-weight:700;float:right}.sum{display:flex;gap:18px;margin:8px 0 4px;flex-wrap:wrap}
.sum div{background:#f7f9fc;border:1px solid #e6eaf1;border-radius:10px;padding:8px 14px}.sum b{font-size:18px;display:block}</style></head><body>";
    echo "<div class=\"brand\">&#128737; Safety Monitor Pro</div><h1>Intrusion Report — attacks by domain</h1>";
    echo "<p class=\"muted\">Window: last " . (int)($rep['window_mins'] ?? 0) . " min · generated " . $h($rep['created'] ?? '') . "</p>";
    echo "<div class=\"sum\"><div>Total attempts<b>" . (int)($rep['total'] ?? 0) . "</b></div><div>Domains targeted<b>" . (int)($rep['domains'] ?? 0) . "</b></div><div>Unique attacker IPs<b>" . (int)($rep['uniq_ips'] ?? 0) . "</b></div></div>";
    echo "<table><thead><tr><th>Domain</th><th>Account</th><th>Attempts</th><th>Uniq IPs</th><th>Top attack</th><th>Severity</th><th>Attack types</th><th>Top attacker IPs</th><th>Last seen</th></tr></thead><tbody>";
    if (empty($rep['by_domain'])) echo "<tr><td colspan=\"9\" style=\"text-align:center;color:#6b7686;padding:18px\">No attacks recorded in this window.</td></tr>";
    foreach (($rep['by_domain'] ?? []) as $g) {
        $cats = ''; foreach ((array)($g['cats'] ?? []) as $c => $n) $cats .= '<span class="k">' . $h($c) . ' ' . (int)$n . '</span>';
        $ips = ''; foreach ((array)($g['top_ips'] ?? []) as $ip => $c) $ips .= $h($ip) . ' (' . (int)$c . ')<br>';
        echo "<tr><td><b>" . $h($g['domain']) . "</b></td><td>" . $h($g['account'] ?? '') . "</td><td>" . (int)$g['total'] . "</td><td>" . (int)($g['uniq_ips'] ?? 0) . "</td><td>" . $h($g['top_cat'] ?? '') . "</td><td><span class=\"b\">" . $h($g['sev'] ?? '') . "</span></td><td>$cats</td><td>$ips</td><td>" . (!empty($g['last']) ? $h(date('Y-m-d H:i', $g['last'])) : '') . "</td></tr>";
    }
    echo "</tbody></table>";
    if ($print) echo "<script>window.onload=function(){setTimeout(function(){window.print();},300);};</script>";
    echo "</body></html>";
}

/* ============================ POST + AJAX dispatch (before output) ============================ */
$reqMethod = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));

if ($reqMethod === 'POST' && ($_POST['im_action'] ?? '') === 'block') {
    smpro_require_valid_csrf('im_action'); smpro_require_root();
    header('Content-Type: application/json');
    $ips = array_unique(array_filter(array_map('trim', explode(',', (string)($_POST['ips'] ?? '')))));
    $res = [];
    foreach ($ips as $ip) { $r = smpro_im_block_ip($ip, 'manual block'); smpro_audit('intrusion_block', ['ip'=>$ip,'ok'=>$r['ok']]); $res[] = ['ip'=>$ip] + $r; }
    $allOk = $res ? array_reduce($res, fn($a,$r)=>$a && !empty($r['ok']), true) : false;   // honest: true only if EVERY block really enforced
    echo json_encode(['ok'=>$allOk,'results'=>$res], JSON_UNESCAPED_SLASHES); exit;
}
if ($reqMethod === 'POST' && ($_POST['im_action'] ?? '') === 'allow') {
    smpro_require_valid_csrf('im_action'); smpro_require_root();
    header('Content-Type: application/json');
    $ips = array_unique(array_filter(array_map('trim', explode(',', (string)($_POST['ips'] ?? '')))));
    $res = [];
    foreach ($ips as $ip) { $r = smpro_im_allow_ip($ip); smpro_audit('intrusion_allow', ['ip'=>$ip,'ok'=>$r['ok']]); $res[] = ['ip'=>$ip] + $r; }
    $allOk = $res ? array_reduce($res, fn($a,$r)=>$a && !empty($r['ok']), true) : false;
    echo json_encode(['ok'=>$allOk,'results'=>$res], JSON_UNESCAPED_SLASHES); exit;
}
if ($reqMethod === 'POST' && ($_POST['im_action'] ?? '') === 'gen_report') {
    smpro_require_valid_csrf('im_action'); smpro_require_root();
    header('Content-Type: application/json');
    $mins = max(5, min(43200, (int)($_POST['mins'] ?? 1440)));
    $events = smpro_im_parse_modsec(SMPRO_IM_REPORT_BYTES, SMPRO_IM_CAP, time() - $mins * 60);
    $byDom = smpro_im_by_domain($events);
    $id = smpro_im_save_report($mins, $events, $byDom);
    smpro_audit('intrusion_report', ['id'=>$id,'mins'=>$mins,'total'=>count($events)]);
    echo json_encode(['ok'=>true,'id'=>$id,'total'=>count($events),'domains'=>count($byDom)], JSON_UNESCAPED_SLASHES); exit;
}
if ($reqMethod === 'POST' && ($_POST['im_action'] ?? '') === 'delete_report') {
    smpro_require_valid_csrf('im_action'); smpro_require_root();
    header('Content-Type: application/json');
    $ids = array_unique(array_filter(array_map('trim', explode(',', (string)($_POST['report_ids'] ?? '')))));
    $del = []; foreach ($ids as $rid) if (smpro_im_delete_report($rid)) $del[] = $rid;
    smpro_audit('intrusion_report_delete', ['deleted'=>$del]);
    echo json_encode(['ok'=>true,'deleted'=>$del], JSON_UNESCAPED_SLASHES); exit;
}
if ($reqMethod === 'POST' && ($_POST['im_action'] ?? '') === 'save_settings') {
    smpro_require_valid_csrf('im_action'); smpro_require_root();
    header('Content-Type: application/json');
    $cur = smpro_in_cfg();
    $patch = [
        'cf_account'        => trim((string)($_POST['cf_account'] ?? $cur['cf_account'])),
        'use_csf'           => !empty($_POST['use_csf']),
        'use_cloudflare'    => !empty($_POST['use_cloudflare']),
        'auto_block'        => !empty($_POST['auto_block']),
        'auto_block_dryrun' => !empty($_POST['auto_block_dryrun']),
        'auto_block_threshold' => max(5, min(100000, (int)($_POST['auto_block_threshold'] ?? ($cur['auto_block_threshold'] ?? 30)))),
        'protect_arab'      => !empty($_POST['protect_arab']),
        'ai_block'          => !empty($_POST['ai_block']),
        'thr_domain_attacks'=> max(5, min(100000, (int)($_POST['thr_domain_attacks'] ?? $cur['thr_domain_attacks']))),
        'thr_ip_domains'    => max(2, min(10000, (int)($_POST['thr_ip_domains'] ?? $cur['thr_ip_domains']))),
        'alert_window_min'  => max(2, min(180, (int)($_POST['alert_window_min'] ?? $cur['alert_window_min']))),
        'allowlist'         => array_values(array_filter(array_map('trim', preg_split('/[\s,]+/', (string)($_POST['allowlist'] ?? ''))))),
        'breach_exclude'    => array_values(array_filter(array_map('trim', preg_split('/[\r\n,]+/', (string)($_POST['breach_exclude'] ?? ''))))),
    ];
    // secrets: only overwrite when a new value is submitted (blank = keep existing)
    if (trim((string)($_POST['cf_token'] ?? '')) !== '')      $patch['cf_token'] = trim((string)$_POST['cf_token']);
    if (trim((string)($_POST['abuseipdb_key'] ?? '')) !== '') $patch['abuseipdb_key'] = trim((string)$_POST['abuseipdb_key']);
    smpro_in_cfg_save($patch);
    if (function_exists('smpro_ntf_cron_sync')) smpro_ntf_cron_sync();   // auto-block needs the scanner cron running
    smpro_audit('intrusion_settings', ['cf'=>$patch['cf_account']!=='','auto_block'=>$patch['auto_block'],'dryrun'=>$patch['auto_block_dryrun']]);
    echo json_encode(['ok'=>true], JSON_UNESCAPED_SLASHES); exit;
}
if ($reqMethod === 'POST' && ($_POST['im_action'] ?? '') === 'update_geoip') {
    smpro_require_valid_csrf('im_action'); smpro_require_root();
    header('Content-Type: application/json');
    if (function_exists('smpro_deps_ensure')) { try { smpro_deps_ensure(true); } catch (\Throwable $e) {} }   // also (re)install mmdblookup
    $rc = function_exists('smpro_geoip_update') ? smpro_geoip_update('Country') : ['ok'=>false,'msg'=>'unavailable'];
    $ra = function_exists('smpro_geoip_update') ? smpro_geoip_update('ASN') : ['ok'=>false,'msg'=>'unavailable'];
    smpro_audit('intrusion_geoip_update', ['country'=>!empty($rc['ok']),'asn'=>!empty($ra['ok'])]);
    echo json_encode(['ok'=>(!empty($rc['ok'])||!empty($ra['ok'])),'country'=>$rc,'asn'=>$ra], JSON_UNESCAPED_SLASHES); exit;
}

/* AI review: ask the AI which current attacker IPs to block (returns recommendation, no action). */
if ($reqMethod === 'POST' && ($_POST['im_action'] ?? '') === 'ai_review') {
    smpro_require_valid_csrf('im_action'); smpro_require_root();
    header('Content-Type: application/json');
    $mins = max(15, min(1440, (int)($_POST['mins'] ?? 240)));
    $ev = smpro_im_parse_modsec(SMPRO_IM_PAGE_BYTES, SMPRO_IM_CAP, time() - $mins * 60);
    $off = smpro_im_offenders($ev, 30);
    $ai = smpro_im_ai_block_decide($off);
    smpro_audit('intrusion_ai_review', ['ok'=>$ai['ok'],'n'=>count($ai['block'] ?? [])]);
    // Build ONE enriched per-IP row list (intel + region policy + decision + plain reason) so the UI
    // can show each IP with its own Block/Allow buttons and an explanation of WHY.
    $intel = []; foreach ($off as $o) $intel[$o['ip']] = $o;
    $mkRow = function($ip, $decision) use ($intel) {
        $o = $intel[$ip] ?? [];
        $region = function_exists('smpro_im_region_status') ? smpro_im_region_status($ip) : 'normal';
        $bot = !empty($o['bot']);
        if ($decision === 'block') {
            $reason = $bot ? 'Datacenter/hosting network attacking — safe to block.'
                : 'Clear, repeated web attack — recommended to block.';
        } elseif ($region === 'core_protected') {
            $reason = 'Home region (Egypt/Saudi) residential IP — NOT auto-blocked (likely a real customer whose device is compromised). Block only if you confirm it is an attacker.';
        } elseif ($region === 'arab_caution') {
            $reason = 'Arab-region residential IP, not yet a clear/repeated attack — review before blocking.';
        } else {
            $reason = 'Likely legitimate (crawler / low-volume / possible false positive) — kept.';
        }
        return ['ip'=>$ip,'country'=>(string)($o['country'] ?? ''),'provider'=>(string)($o['provider'] ?? ''),
                'bot'=>$bot,'hits'=>(int)($o['hits'] ?? 0),'region'=>$region,'decision'=>$decision,'reason'=>$reason];
    };
    $rows = [];
    foreach (($ai['block'] ?? []) as $ip)  $rows[] = $mkRow($ip, 'block');
    foreach (($ai['review'] ?? []) as $ip) $rows[] = $mkRow($ip, 'review');
    foreach (($ai['keep'] ?? []) as $ip)   { if (filter_var($ip, FILTER_VALIDATE_IP)) $rows[] = $mkRow($ip, 'keep'); }
    echo json_encode(['ok'=>!empty($ai['ok']),'rows'=>$rows,'block'=>$ai['block'] ?? [],'keep'=>$ai['keep'] ?? [],'review'=>$ai['review'] ?? [],'reason'=>$ai['reason'] ?? '','provider'=>$ai['provider'] ?? '','offenders'=>$off], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE); exit;
}

/* EMERGENCY: save just the emergency toggles (independent of the Settings tab). */
if ($reqMethod === 'POST' && ($_POST['im_action'] ?? '') === 'emergency_save') {
    smpro_require_valid_csrf('im_action'); smpro_require_root();
    header('Content-Type: application/json');
    smpro_in_cfg_save([
        'emergency'        => !empty($_POST['emergency']),
        'emergency_harden' => !empty($_POST['emergency_harden']),
        'emergency_clean'  => !empty($_POST['emergency_clean']),
        'emergency_block_scanners' => !empty($_POST['emergency_block_scanners']),
        'emergency_batch'  => max(1, min(50, (int)($_POST['emergency_batch'] ?? 3))),
        'emergency_block_digest_hours' => max(1, min(168, (int)($_POST['emergency_block_digest_hours'] ?? 12))),
        'emergency_dryrun' => !empty($_POST['emergency_dryrun']),
    ]);
    if (function_exists('smpro_ntf_cron_sync')) smpro_ntf_cron_sync();   // emergency auto-response needs the scanner cron running
    smpro_audit('intrusion_emergency_cfg', ['on'=>!empty($_POST['emergency'])]);
    echo json_encode(['ok'=>true,'scanner'=>is_file('/etc/cron.d/smpro-notify')], JSON_UNESCAPED_SLASHES); exit;
}

/* EMERGENCY: run the harden(+clean) sweep now over currently-attacked sites. */
if ($reqMethod === 'POST' && ($_POST['im_action'] ?? '') === 'emergency_run') {
    smpro_require_valid_csrf('im_action'); smpro_require_root();
    header('Content-Type: application/json');
    $dry = !empty($_POST['dryrun']);
    $ev = smpro_im_parse_modsec(SMPRO_IM_PAGE_BYTES, SMPRO_IM_CAP, time() - max(60, (int)($_POST['mins'] ?? 360)) * 60);
    $r = smpro_im_emergency_run($ev, $dry);
    $cf = 0; foreach ($r['cleaned'] as $x) $cf += count($x['files']);
    $blk = $r['blocked'] ?? [];
    smpro_audit('intrusion_emergency_manual', ['dryrun'=>$dry,'hardened'=>count($r['hardened']),'cleaned'=>$cf,'blocked'=>count($blk)]);
    echo json_encode(['ok'=>true,'dryrun'=>$r['dryrun'],'hardened'=>$r['hardened'],'cleaned'=>$r['cleaned'],'cleaned_count'=>$cf,'blocked'=>$blk,'blocked_count'=>count($blk)], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE); exit;
}
/* EMERGENCY: undo (restore) a recorded emergency action. */
if ($reqMethod === 'POST' && ($_POST['im_action'] ?? '') === 'emergency_undo') {
    smpro_require_valid_csrf('im_action'); smpro_require_root();
    header('Content-Type: application/json');
    $ok = smpro_im_emergency_undo((string)($_POST['eid'] ?? ''));
    smpro_audit('intrusion_emergency_undo', ['eid'=>(string)($_POST['eid'] ?? ''),'ok'=>$ok]);
    echo json_encode(['ok'=>$ok], JSON_UNESCAPED_SLASHES); exit;
}

/* LIVE feed (GET, JSON) — polled by the page; also indexes into SQLite history. */
if (($_GET['im_live'] ?? '') === '1') {
    smpro_require_root();                                // these GET feeds return attacker IPs/domains — root-only
    header('Content-Type: application/json');
    $mins = max(1, min(1440, (int)($_GET['mins'] ?? 120)));
    $events = smpro_im_ingest_recent(SMPRO_IM_LIVE_BYTES, $mins);
    $events = array_filter($events, fn($e) => ($e['ts'] ?? 0) >= time() - $mins * 60);
    $rows = [];
    if ($events) smpro_ip_intel_bulk(array_slice(array_values(array_unique(array_filter(array_map(fn($e)=>$e['ip'],$events)))), 0, 120));
    foreach (array_slice($events, 0, 250) as $e) {
        $in = $e['ip'] !== '' ? smpro_ip_intel($e['ip'], false) : [];
        $rows[] = ['time'=>$e['ts']?date('H:i:s',$e['ts']):'','ip'=>$e['ip'],'cc'=>strtoupper((string)($in['country']??'')),
                   'provider'=>(string)($in['provider']??''),'asn'=>(string)($in['asn']??''),'bot'=>(smpro_ip_is_datacenter($in)?1:0),
                   'domain'=>$e['domain'],'account'=>smpro_im_account_for($e['domain']),'kind'=>$e['kind'],'severity'=>$e['severity'],'code'=>$e['code'],'method'=>$e['method'],'uri'=>mb_substr((string)$e['uri'],0,120)];
    }
    echo json_encode(['ok'=>true,'count'=>count($events),'rows'=>$rows,'now'=>date('H:i:s')], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE); exit;
}
if (($_GET['im_export'] ?? '') !== '') {
    smpro_require_root();                                // report exports contain attacker IPs/accounts — root-only
    $id = preg_replace('/[^0-9A-Za-z_]/', '', (string)($_GET['report'] ?? ''));
    $rep = smpro_im_json_load(smpro_im_report_path($id));
    if (!$rep) { http_response_code(404); echo 'report not found'; exit; }
    if ($_GET['im_export'] === 'csv') {
        header('Content-Type: text/csv; charset=utf-8'); header('Content-Disposition: attachment; filename="intrusion_' . $id . '.csv"');
        $fh = fopen('php://output', 'w');
        fputcsv($fh, ['domain','account','attempts','unique_ips','top_attack','max_severity','top_attacker_ips','first_seen','last_seen']);
        foreach ($rep['by_domain'] as $g) { $ips = []; foreach ((array)($g['top_ips'] ?? []) as $ip => $c) $ips[] = $ip . '(' . $c . ')';
            fputcsv($fh, [$g['domain'],$g['account'] ?? '',$g['total'],$g['uniq_ips'] ?? '',$g['top_cat'] ?? '',$g['sev'] ?? '',implode(' ', $ips),!empty($g['first'])?date('Y-m-d H:i',$g['first']):'',!empty($g['last'])?date('Y-m-d H:i',$g['last']):'']); }
        fclose($fh); exit;
    }
    smpro_im_render_report_html($rep, ($_GET['im_export'] === 'pdf')); exit;
}
/* Full attack-analysis CSV. */
if (($_GET['im_attack'] ?? '') === 'csv') {
    smpro_require_root();
    $mins = max(5, min(43200, (int)($_GET['mins'] ?? 1440)));
    $aa = smpro_im_attack_analysis(smpro_im_parse_modsec(SMPRO_IM_PAGE_BYTES, SMPRO_IM_CAP, time() - $mins * 60));
    header('Content-Type: text/csv; charset=utf-8'); header('Content-Disposition: attachment; filename="attack_report.csv"');
    $fh = fopen('php://output', 'w');
    fputcsv($fh, ['== ATTACK PHASES ==']); fputcsv($fh, ['phase','events']); foreach ($aa['phases'] as $p => $n) fputcsv($fh, [$p, $n]);
    fputcsv($fh, []); fputcsv($fh, ['== TARGETED PATHS ==']); fputcsv($fh, ['path','requests','uniq_ips']); foreach ($aa['paths'] as $p) fputcsv($fh, [$p['path'], $p['n'], $p['uniq_ips']]);
    fputcsv($fh, []); fputcsv($fh, ['== COORDINATED CAMPAIGNS (/24) ==']); fputcsv($fh, ['subnet','attacker_ips','requests']); foreach ($aa['campaigns'] as $s) fputcsv($fh, [$s['subnet'], $s['uniq_ips'], $s['n']]);
    fputcsv($fh, []); fputcsv($fh, ['== TOP SOURCE IPs ==']); fputcsv($fh, ['rank','ip','country','provider','requests','main_target','user_agents']);
    $r = 0; foreach ($aa['attackers'] as $x) { $r++; $in = smpro_ip_intel($x['ip'], false); fputcsv($fh, [$r, $x['ip'], strtoupper((string)($in['country'] ?? '')), (string)($in['provider'] ?? ''), $x['n'], $x['top_path'], $x['ua_count']]); }
    fclose($fh); exit;
}

/* ============================ PAGE RENDER ============================ */
$tab  = preg_replace('/[^a-z]/', '', strtolower((string)($_GET['tab'] ?? 'live')));
if (!in_array($tab, ['live','domains','attack','breaches','campaigns','reports','settings','emergency'], true)) $tab = 'live';
$mins = max(5, min(43200, (int)($_GET['mins'] ?? 1440)));
$modsec = smpro_im_modsec_log();
$csrf = smpro_csrf_generate('im_action');

$events = ($tab !== 'reports' && $tab !== 'settings' && $modsec !== '') ? smpro_im_parse_modsec(SMPRO_IM_PAGE_BYTES, SMPRO_IM_CAP, time() - $mins * 60) : [];
if ($events) { smpro_in_ingest($events); smpro_ip_intel_bulk(array_slice(array_keys(array_count_values(array_filter(array_map(fn($e)=>$e['ip'],$events)))), 0, 80)); }
$byDom  = $events ? smpro_im_by_domain($events) : [];
$totalAttacks = count($events);
$uniqIps = count(array_unique(array_filter(array_map(fn($e) => $e['ip'], $events))));
$crit = count(array_filter($events, fn($e) => smpro_im_sev_rank($e['severity']) >= 5));
$hist = smpro_in_stats(time() - 30 * 86400);

smpro_audit('intrusion_view', ['tab' => $tab]);
smpro_layout_header('Intrusion Monitor');
?>
<script>var IM_CSRF=<?= json_encode($csrf) ?>;</script>
<div class="svc-kicker">Security &amp; Access</div>
<h1 class="h" style="margin:2px 0 4px" data-i18n>Intrusion Monitor</h1>
<p class="sub" data-i18n>Live web-attack detection per domain (ModSecurity WAF) with breach correlation, campaign tracking, CSF + Cloudflare blocking, and push alerts.</p>

<?php if ($modsec === ''): ?>
<div class="card" style="border-left:4px solid var(--warn);padding:14px 16px;margin:12px 0">
  <b data-i18n>ModSecurity audit log not found.</b>
  <p class="meta" style="margin:6px 0 0">Enable ModSecurity (WHM → Security Center → ModSecurity Vendors) to populate per-domain attack detection.</p>
</div>
<?php endif; ?>

<?php
// Blocking-effectiveness banner: the #1 reason "Block" appears to do nothing is CSF in TESTING mode (rules
// written to csf.deny but never loaded into iptables) or CSF not installed. Tell the admin plainly + how to fix.
$imCfg2 = function_exists('smpro_in_cfg') ? smpro_in_cfg() : [];
$csfTesting = function_exists('smpro_csf_testing') && smpro_csf_testing();
$csfMissing = function_exists('smpro_csf_bin') && smpro_csf_bin() === '';
if (!empty($imCfg2['use_csf']) && $csfTesting): ?>
<div class="card" style="border-left:4px solid var(--dang);background:var(--dang-bg);padding:14px 16px;margin:12px 0">
  <b>&#9888; CSF is in TESTING mode — blocks are NOT enforced.</b>
  <p class="meta" style="margin:6px 0 0">When you block an IP (manually or automatically) the rule is written to <code>csf.deny</code>, but CSF does not load it into the firewall while <code>TESTING=1</code>, so attackers are <b>not actually blocked</b>. Set <code>TESTING=0</code> in <code>/etc/csf/csf.conf</code> (or via <a href="index.cgi?page=server-tuning">Server Tune-up</a>) and restart CSF — then both manual and automatic blocking take effect.</p>
</div>
<?php elseif (!empty($imCfg2['use_csf']) && $csfMissing): ?>
<div class="card" style="border-left:4px solid var(--warn);background:var(--warn-bg);padding:14px 16px;margin:12px 0">
  <b>&#9888; CSF firewall not installed — blocks can't be enforced.</b>
  <p class="meta" style="margin:6px 0 0">"Block" needs an active firewall. Install CSF, or enable Cloudflare blocking in <a href="index.cgi?page=intrusion-monitor&tab=settings">Settings</a>, so blocks take effect.</p>
</div>
<?php endif; ?>

<div class="im-hero">
  <div class="im-c"><span class="lbl" data-i18n>Attack attempts</span><span class="v"><?= number_format($totalAttacks) ?></span><span class="meta">last <?= (int)($mins/60) ?>h · 30d indexed: <?= number_format($hist['total']) ?></span></div>
  <div class="im-c"><span class="lbl" data-i18n>Domains targeted</span><span class="v"><?= number_format(count($byDom)) ?></span></div>
  <div class="im-c"><span class="lbl" data-i18n>Unique attacker IPs</span><span class="v"><?= number_format($uniqIps) ?></span></div>
  <div class="im-c"><span class="lbl" data-i18n>Critical</span><span class="v" style="color:var(--dang)"><?= number_format($crit) ?></span></div>
</div>

<div class="la-tabs">
  <?php foreach (['live'=>'Live attacks','domains'=>'By domain','attack'=>'Attack Report','breaches'=>'Breaches','campaigns'=>'Campaigns','reports'=>'Reports','settings'=>'Settings'] as $tk=>$tl): ?>
    <a class="la-tab <?= $tab===$tk?'active':'' ?>" href="index.cgi?page=intrusion-monitor&tab=<?= $tk ?>" data-i18n><?= $tl ?></a>
  <?php endforeach; ?>
  <a class="la-tab im-emtab <?= $tab==='emergency'?'active':'' ?><?= !empty(smpro_in_cfg()['emergency'])?' on':'' ?>" href="index.cgi?page=intrusion-monitor&tab=emergency">&#128680; <span data-i18n>Emergency</span><?= !empty(smpro_in_cfg()['emergency'])?' <span class="b crit" style="margin-left:4px">ON</span>':'' ?></a>
</div>

<div class="im-bulk" id="imBulk"><span><b id="imBulkN">0</b> <span data-i18n>selected</span></span>
  <button class="im-bbtn block" id="imBulkBlock" type="button">&#128683; <span data-i18n>Block selected</span></button>
  <button class="im-bbtn allow" id="imBulkAllow" type="button">&#10003; <span data-i18n>Allow selected</span></button>
  <button class="im-bbtn ghost" id="imBulkClear" type="button" data-i18n>Clear</button></div>

<?php if ($tab === 'live'): ?>
  <div class="tp-th"><b data-i18n>Live attack feed</b>
    <label class="lm-chkl"><input type="checkbox" id="imAuto" checked> <span data-i18n>Auto-refresh</span></label>
    <input type="text" id="imLiveFilter" class="tp-in" placeholder="Filter IP / domain / type…" style="max-width:220px">
    <button class="tp-btn" id="imAiBtn" type="button">&#129302; <span data-i18n>AI: review &amp; recommend blocks</span></button>
    <span class="meta" id="imLiveMeta" style="margin-left:auto">—</span></div>
  <div id="imAiPanel" class="card" hidden style="padding:14px 16px;margin:0 0 12px;border-left:4px solid var(--brand)"></div>
  <div class="la-scroll"><table class="smpro-table nowrap sortable" id="imLiveTbl">
    <thead><tr><th style="width:26px"><input type="checkbox" id="imSelAll" title="Select all"></th><th data-sort="str" data-i18n>Time</th><th data-sort="str" data-i18n>Attacker IP</th><th data-sort="str" data-i18n>Country / Provider</th><th data-sort="str" data-i18n>Domain targeted</th><th data-sort="str" data-i18n>Account</th><th data-sort="str" data-i18n>Attack type</th><th data-sort="num" data-i18n>Severity</th><th data-sort="num">HTTP</th><th data-sort="str" data-i18n>Request</th><th data-i18n>Action</th></tr></thead>
    <tbody id="imLiveBody"><tr><td colspan="11" class="lm-empty" data-i18n>Loading live feed…</td></tr></tbody></table></div>

<?php elseif ($tab === 'domains'): ?>
  <div class="tp-th"><b data-i18n>Attacks by domain</b><input type="text" id="imDomFilter" class="tp-in" placeholder="Filter domain / account…" style="margin-left:auto"></div>
  <div class="la-scroll"><table class="smpro-table nowrap sortable" id="imDomTbl">
    <thead><tr><th style="width:26px"><input type="checkbox" id="imSelAllDom" title="Select all"></th><th data-sort="str" data-i18n>Domain</th><th data-sort="str" data-i18n>Account</th><th class="num" data-sort="num" data-i18n>Attempts</th><th class="num" data-sort="num" data-i18n>Uniq IPs</th><th data-i18n>Top attack</th><th data-sort="num" data-i18n>Severity</th><th data-i18n>Top attacker (geo)</th><th data-sort="num" data-i18n>Last seen</th><th></th></tr></thead><tbody>
    <?php if (!$byDom): ?><tr><td colspan="10" class="lm-empty" data-i18n>No attacks detected in this window.</td></tr><?php endif; ?>
    <?php foreach ($byDom as $g): $topip = $g['ips'] ? array_key_first($g['ips']) : ''; $sevc = smpro_im_sev_rank($g['sevlabel'])>=5?'crit':(smpro_im_sev_rank($g['sevlabel'])>=4?'high':'med'); $tin = $topip ? smpro_ip_intel($topip, false) : []; ?>
      <tr data-search="<?= smpro_h(strtolower($g['domain'].' '.$g['account'])) ?>">
        <td><?php if ($topip): ?><input type="checkbox" class="im-chk" value="<?= smpro_h($topip) ?>"><?php endif; ?></td>
        <td><b><?= smpro_h($g['domain']) ?></b></td><td class="uname"><?= smpro_h($g['account']) ?: '<span class="meta">—</span>' ?></td>
        <td class="num"><b><?= number_format($g['total']) ?></b></td><td class="num"><?= number_format($g['uniq_ips']) ?></td>
        <td><span class="k"><?= smpro_h($g['top_cat']) ?></span></td><td data-val="<?= smpro_im_sev_rank($g['sevlabel']) ?>"><span class="b <?= $sevc ?>"><?= smpro_h($g['sevlabel'] ?: '—') ?></span></td>
        <td class="ipmono"><?= smpro_h($topip) ?><?php if ($topip): ?><span class="meta"> <?= smpro_h(strtoupper((string)($tin['country']??''))) ?><?= !empty($tin['provider'])?' · '.smpro_h(mb_substr($tin['provider'],0,18)):'' ?><?= smpro_ip_is_datacenter($tin)?' &#129302;':'' ?></span> <button class="la-act block" data-ip="<?= smpro_h($topip) ?>">Block</button> <button class="la-act allow" data-ip="<?= smpro_h($topip) ?>">Allow</button><?php endif; ?></td>
        <td class="meta" data-val="<?= (int)$g['last'] ?>"><?= $g['last'] ? smpro_h(date('Y-m-d H:i', $g['last'])) : '' ?></td>
        <td><a class="lnk" href="index.cgi?page=intrusion-monitor&tab=live&dom=<?= urlencode($g['domain']) ?>" data-i18n>View</a></td>
      </tr>
    <?php endforeach; ?>
    </tbody></table></div>

<?php elseif ($tab === 'attack'): $aa = smpro_im_attack_analysis($events);
  if ($aa['attackers']) smpro_ip_intel_bulk(array_slice(array_map(fn($x)=>$x['ip'],$aa['attackers']),0,80)); $topIp = $aa['attackers'][0]['ip'] ?? ''; ?>
  <div class="tp-th"><b data-i18n>Full attack analysis</b><span class="meta"><?= number_format($aa['total']) ?> events · last <?= (int)($mins/60) ?>h</span>
    <a class="lnk" href="index.cgi?page=intrusion-monitor&im_attack=csv&mins=<?= (int)$mins ?>" style="margin-left:auto" data-i18n>CSV</a>
    <a class="lnk" href="javascript:window.print()" data-i18n>Print</a></div>
  <div class="card" style="padding:14px 16px;margin-bottom:12px"><b data-i18n>Attack phases</b>
    <div class="im-phases"><?php $pmax=max(1,$aa['phases']?max($aa['phases']):1); foreach ($aa['phases'] as $ph=>$n): ?>
      <div class="im-ph"><span class="im-phl"><?= smpro_h($ph) ?></span><div class="im-phb"><i style="width:<?= round($n/$pmax*100) ?>%"></i></div><b><?= number_format($n) ?></b></div>
    <?php endforeach; ?></div>
  </div>
  <div class="la-tabs2">
    <div class="card" style="padding:0;overflow:hidden">
      <div class="tp-th"><b data-i18n>Most-targeted paths</b></div>
      <div class="la-scroll" style="max-height:300px"><table class="smpro-table sortable">
        <thead><tr><th data-sort="str" data-i18n>Path</th><th class="num" data-sort="num" data-i18n>Requests</th><th class="num" data-sort="num" data-i18n>Uniq IPs</th></tr></thead><tbody>
        <?php if(!$aa['paths']):?><tr><td colspan="3" class="lm-empty">—</td></tr><?php endif;?>
        <?php foreach ($aa['paths'] as $p): ?><tr><td class="ipmono" title="<?= smpro_h($p['path']) ?>"><?= smpro_h(mb_substr($p['path'],0,52)) ?></td><td class="num"><b><?= number_format($p['n']) ?></b></td><td class="num"><?= number_format($p['uniq_ips']) ?></td></tr><?php endforeach; ?>
      </tbody></table></div>
    </div>
    <div class="card" style="padding:0;overflow:hidden">
      <div class="tp-th"><b data-i18n>Coordinated campaigns</b><span class="meta">/24 subnet = likely botnet</span></div>
      <div class="la-scroll" style="max-height:300px"><table class="smpro-table sortable">
        <thead><tr><th data-i18n>Subnet</th><th class="num" data-sort="num" data-i18n>Attacker IPs</th><th class="num" data-sort="num" data-i18n>Requests</th></tr></thead><tbody>
        <?php if(!$aa['campaigns']):?><tr><td colspan="3" class="lm-empty" data-i18n>No coordinated subnet campaigns detected.</td></tr><?php endif;?>
        <?php foreach ($aa['campaigns'] as $s): ?><tr><td class="ipmono"><?= smpro_h($s['subnet']) ?> <span class="b crit">&#129302; botnet</span></td><td class="num"><b><?= (int)$s['uniq_ips'] ?></b></td><td class="num"><?= number_format($s['n']) ?></td></tr><?php endforeach; ?>
      </tbody></table></div>
    </div>
  </div>
  <div class="tp-th" style="margin-top:12px"><b data-i18n>Top source IPs</b><input type="text" id="imAtkFilter" class="tp-in" placeholder="Filter…" style="margin-left:auto;max-width:200px"></div>
  <div class="la-scroll" style="max-height:440px"><table class="smpro-table sortable" id="imAtkTbl">
    <thead><tr><th style="width:26px"><input type="checkbox" id="imSelAllAtk" title="Select all"></th><th>#</th><th data-sort="str" data-i18n>Attacker IP</th><th data-sort="str" data-i18n>Country / Provider</th><th class="num" data-sort="num" data-i18n>Requests</th><th data-i18n>Main target</th><th class="num" data-sort="num" data-i18n>User-Agents</th><th data-i18n>Action</th></tr></thead><tbody>
    <?php $rank=0; foreach ($aa['attackers'] as $x): $rank++; $in=smpro_ip_intel($x['ip'],false); ?>
      <tr data-search="<?= smpro_h(strtolower($x['ip'].' '.($in['country']??'').' '.($in['provider']??'').' '.$x['top_path'])) ?>">
        <td><input type="checkbox" class="im-chk" value="<?= smpro_h($x['ip']) ?>"></td><td><?= $rank ?></td>
        <td class="ipmono"><?= smpro_h($x['ip']) ?><?php if($x['ip']===$topIp):?> <span class="b crit">top</span><?php endif;?></td>
        <td class="meta"><?= smpro_h(strtoupper((string)($in['country']??''))) ?><?= !empty($in['provider'])?' · '.smpro_h(mb_substr($in['provider'],0,18)):'' ?><?= smpro_ip_is_datacenter($in)?' &#129302;':'' ?></td>
        <td class="num"><b><?= number_format($x['n']) ?></b></td>
        <td class="ipmono meta" title="<?= smpro_h($x['top_path']) ?>"><?= smpro_h(mb_substr($x['top_path'],0,36)) ?></td>
        <td class="num" data-val="<?= (int)$x['ua_count'] ?>"><?= (int)$x['ua_count'] ?><?php if($x['ua_count']>=4):?> <span class="b crit" title="rotating User-Agents to evade blocks">&#9851; rotating</span><?php endif;?></td>
        <td class="nowrap"><button class="la-act block" data-ip="<?= smpro_h($x['ip']) ?>">Block</button> <button class="la-act allow" data-ip="<?= smpro_h($x['ip']) ?>">Allow</button></td>
      </tr>
    <?php endforeach; ?>
  </tbody></table></div>

<?php elseif ($tab === 'breaches'): $breaches = $events ? smpro_im_breaches($events, 1440, 40) : []; ?>
  <div class="tp-th"><b data-i18n>Likely compromises</b><span class="meta" style="margin-left:auto">attack served 2xx/3xx + recently-changed PHP in the domain's docroot</span></div>
  <?php if (!$breaches): ?>
    <div class="card" style="padding:16px;border-left:4px solid var(--good)"><b data-i18n>No likely compromises detected.</b><p class="meta" style="margin:6px 0 0">No domain shows an exploit-class attack with a successful response AND recently modified PHP files. (Heuristic — absence is not proof.)</p></div>
  <?php else: ?>
    <div class="card" style="padding:0">
    <?php foreach ($breaches as $b): ?>
      <div style="padding:14px 16px;border-bottom:1px solid var(--line)">
        <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
          <span class="b crit">POSSIBLE COMPROMISE</span>
          <b><?= smpro_h($b['domain']) ?></b> <span class="meta">account <span class="uname"><?= smpro_h($b['account']) ?></span></span>
          <span style="margin-left:auto"><a class="lnk" href="index.cgi?page=forensics-audit&user=<?= urlencode($b['account']) ?>" data-i18n>Open Forensics</a>
          <?php if (!empty($b['ips'][0])): ?><button class="la-act block" data-ip="<?= smpro_h($b['ips'][0]) ?>">Block IP</button><?php endif; ?></span>
        </div>
        <div class="meta" style="margin-top:6px">Attack types: <?= smpro_h(implode(', ', $b['kinds'])) ?> · last <?= $b['last']?smpro_h(date('Y-m-d H:i',$b['last'])):'' ?></div>
        <div style="margin-top:6px;font-size:12px">Recently changed files:<br><span class="mono" style="color:var(--dang)"><?= smpro_h(implode("\n", $b['changed'])) ?></span></div>
      </div>
    <?php endforeach; ?>
    </div>
  <?php endif; ?>

<?php elseif ($tab === 'campaigns'): $camp = $events ? smpro_im_campaigns($events) : ['distributed'=>[],'targeted'=>[]];
  if ($camp['distributed']) smpro_ip_intel_bulk(array_column(array_slice($camp['distributed'],0,100), 'ip')); ?>
  <div class="tp-th"><b data-i18n>Distributed scanners</b><input type="text" id="imCampFilter" class="tp-in" placeholder="Filter IP / provider…" style="margin-left:auto;max-width:240px"></div>
  <div class="la-scroll" style="max-height:320px"><table class="smpro-table sortable" id="imCampTbl">
    <thead><tr><th style="width:26px"><input type="checkbox" id="imSelAllCamp" title="Select all"></th><th data-sort="str" data-i18n>Attacker IP</th><th data-sort="str" data-i18n>Country / Provider</th><th class="num" data-sort="num" data-i18n>Domains hit</th><th class="num" data-sort="num" data-i18n>Total hits</th><th data-i18n>Action</th></tr></thead><tbody>
    <?php if (!$camp['distributed']): ?><tr><td colspan="6" class="lm-empty" data-i18n>No distributed scanning detected.</td></tr><?php endif; ?>
    <?php foreach (array_slice($camp['distributed'],0,100) as $d): $cin = smpro_ip_intel($d['ip'], false); ?>
      <tr data-search="<?= smpro_h(strtolower($d['ip'].' '.($cin['country']??'').' '.($cin['provider']??''))) ?>"><td><input type="checkbox" class="im-chk" value="<?= smpro_h($d['ip']) ?>"></td>
      <td class="ipmono"><?= smpro_h($d['ip']) ?></td>
      <td class="meta"><?= smpro_h(strtoupper((string)($cin['country']??''))) ?><?= !empty($cin['provider'])?' · '.smpro_h(mb_substr($cin['provider'],0,22)):'' ?><?= smpro_ip_is_datacenter($cin)?' <span class="b crit">&#129302; bot</span>':'' ?></td>
      <td class="num"><b><?= (int)$d['domains'] ?></b></td><td class="num"><?= (int)$d['hits'] ?></td>
      <td><button class="la-act block" data-ip="<?= smpro_h($d['ip']) ?>">Block</button> <button class="la-act allow" data-ip="<?= smpro_h($d['ip']) ?>">Allow</button></td></tr>
    <?php endforeach; ?>
    </tbody></table></div>
  <div class="tp-th" style="margin-top:14px"><b data-i18n>Most-targeted domains</b><span class="meta" style="margin-left:auto">many distinct IPs attacking one domain</span></div>
  <div class="la-scroll" style="max-height:260px"><table class="smpro-table">
    <thead><tr><th data-i18n>Domain</th><th class="num" data-i18n>Distinct attacker IPs</th></tr></thead><tbody>
    <?php if (!$camp['targeted']): ?><tr><td colspan="2" class="lm-empty" data-i18n>No coordinated targeting detected.</td></tr><?php endif; ?>
    <?php foreach (array_slice($camp['targeted'],0,100) as $t): ?><tr><td><b><?= smpro_h($t['domain']) ?></b></td><td class="num"><?= (int)$t['ips'] ?></td></tr><?php endforeach; ?>
    </tbody></table></div>

<?php elseif ($tab === 'reports'): $idx = smpro_im_reports_index(); ?>
  <div class="tp-th"><b data-i18n>Saved reports</b>
    <span style="margin-left:auto;display:flex;gap:8px;align-items:center">
      <select id="imRepWin" class="tp-sel"><option value="360">last 6h</option><option value="1440" selected>last 24h</option><option value="4320">last 3d</option><option value="10080">last 7d</option></select>
      <button class="tp-btn primary" id="imGenBtn" data-i18n>Generate report</button></span></div>
  <div class="la-scroll"><table class="smpro-table" id="imRepTbl">
    <thead><tr><th data-i18n>Created</th><th data-i18n>Window</th><th class="num" data-i18n>Attempts</th><th class="num" data-i18n>Domains</th><th data-i18n>Actions</th></tr></thead><tbody>
    <?php if (!$idx): ?><tr id="imRepEmpty"><td colspan="5" class="lm-empty" data-i18n>No saved reports yet — generate one above.</td></tr><?php endif; ?>
    <?php foreach ($idx as $r): ?>
      <tr data-rid="<?= smpro_h($r['id']) ?>"><td><?= smpro_h($r['created'] ?? '') ?></td><td><?= (int)(($r['window_mins'] ?? 0)/60) ?>h</td>
        <td class="num"><?= number_format($r['total'] ?? 0) ?></td><td class="num"><?= number_format($r['domains'] ?? 0) ?></td>
        <td class="nowrap"><a class="lnk" href="index.cgi?page=intrusion-monitor&im_export=html&report=<?= smpro_h($r['id']) ?>" target="_blank" data-i18n>View</a>
          <a class="lnk" href="index.cgi?page=intrusion-monitor&im_export=csv&report=<?= smpro_h($r['id']) ?>" data-i18n>CSV</a>
          <button class="la-act block imDel" data-rid="<?= smpro_h($r['id']) ?>" data-i18n>Delete</button></td></tr>
    <?php endforeach; ?>
    </tbody></table></div>

<?php elseif ($tab === 'emergency'): $c = smpro_in_cfg(); $emlog = function_exists('smpro_im_em_manifest_load') ? array_reverse(smpro_im_em_manifest_load()) : []; ?>
  <div class="card" style="padding:18px 20px;max-width:840px;border-left:4px solid var(--dang)">
    <h3 style="margin:0 0 6px;color:var(--dang)">&#128680; <span data-i18n>Emergency auto-response</span> <?= !empty($c['emergency'])?'<span class="b crit">ACTIVE</span>':'<span class="b" style="background:#f1f5f9;color:#475569">off</span>' ?></h3>
    <p class="meta" data-i18n>When ON: the moment a site is hit by an exploit-class attack AND its files have just changed, the plugin automatically (1) quarantines any uploaded web-shells, (2) hardens the site — disables PHP execution in upload/cache folders and locks core files (wp-config, .htaccess, index…), and (3) alerts the admin. Every action is backed up and reversible from the log below.</p>
    <div class="im-frm">
      <label class="lm-chkl"><input type="checkbox" id="emOn" <?= !empty($c['emergency'])?'checked':'' ?>> <b data-i18n>Activate Emergency mode</b></label>
      <label class="lm-chkl"><input type="checkbox" id="emHarden" <?= !empty($c['emergency_harden'])?'checked':'' ?>> <span data-i18n>Harden (block PHP in upload/cache dirs + lock core files)</span></label>
      <label class="lm-chkl"><input type="checkbox" id="emClean" <?= !empty($c['emergency_clean'])?'checked':'' ?>> <span data-i18n>Clean (quarantine recently-changed files that look like web-shells)</span></label>
      <label class="lm-chkl"><input type="checkbox" id="emBlock" <?= (!isset($c['emergency_block_scanners'])||!empty($c['emergency_block_scanners']))?'checked':'' ?>> <span data-i18n>Auto-block malicious scanners (credential-file probes &amp; bare server-IP scans, e.g. cloud bots — blocks the specific IP only, never search engines)</span></label>
      <label class="sw"><input type="checkbox" id="emDry" <?= !empty($c['emergency_dryrun'])?'checked':'' ?>><span class="track"></span><span class="lbl" data-i18n>Dry-run mode (preview only — do not touch files)</span><span class="st"></span></label>
      <label class="lm-chkl" style="gap:8px"><span data-i18n>Group site-protection notifications: one message every</span> <input type="number" id="emBatch" min="1" max="50" value="<?= (int)($c['emergency_batch'] ?? 3) ?>" style="width:70px"> <span data-i18n>action(s)</span></label>
      <label class="lm-chkl" style="gap:8px"><span data-i18n>Scanner auto-blocks: one grouped digest every</span> <input type="number" id="emDigestH" min="1" max="168" value="<?= (int)($c['emergency_block_digest_hours'] ?? 12) ?>" style="width:70px"> <span data-i18n>hour(s) — keeps routine GCP/.env scanner blocks from spamming alerts</span></label>
      <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap;align-items:center">
        <button class="tp-btn primary" id="emSave" type="button" data-i18n>Save</button>
        <button class="tp-btn" id="emRunDry" type="button">&#128065; <span data-i18n>Preview sweep now</span></button>
        <button class="tp-btn" id="emRun" type="button" style="background:var(--dang);color:#fff;border-color:var(--dang)">&#128680; <span data-i18n>Run emergency sweep now</span></button>
        <span id="emMsg" class="meta"></span>
      </div>
      <div id="emOut" class="card" hidden style="margin:12px 0 0;padding:12px 14px;border-left:4px solid var(--brand)"></div>
    </div>
  </div>
  <div class="tp-th" style="margin-top:16px"><b data-i18n>Emergency action log</b><span class="meta" style="margin-left:auto" data-i18n>Restore = un-lock files + put quarantined files back</span></div>
  <div class="la-scroll" style="max-height:360px"><table class="smpro-table">
    <thead><tr><th data-i18n>When</th><th data-i18n>Domain</th><th data-i18n>Account</th><th data-i18n>Actions</th><th></th></tr></thead><tbody>
    <?php if (!$emlog): ?><tr><td colspan="5" class="lm-empty" data-i18n>No emergency actions taken yet.</td></tr><?php endif; ?>
    <?php foreach (array_slice($emlog,0,200) as $e): $acts=$e['actions']??[]; $nq=0;$nh=0; foreach($acts as $a){ (($a['type']??'')==='quarantine')?$nq++:$nh++; } ?>
      <tr data-eid="<?= smpro_h($e['id']??'') ?>">
        <td class="meta"><?= smpro_h(date('Y-m-d H:i', (int)($e['ts']??0))) ?></td>
        <td><b><?= smpro_h($e['domain']??'') ?></b></td><td class="uname"><?= smpro_h($e['account']??'') ?></td>
        <td><?php if($nq):?><span class="b crit">&#129529; <?= $nq ?> quarantined</span> <?php endif;?><?php if($nh):?><span class="b" style="background:var(--good-bg);color:var(--good)">&#128737; <?= $nh ?> hardened</span><?php endif;?>
          <?php $qf=[]; foreach($acts as $a){ if(($a['type']??'')==='quarantine' && !empty($a['path'])) $qf[]=basename((string)$a['path']); }
                if($qf): ?><div class="meta" style="margin-top:4px;font-size:11px;word-break:break-all" title="<?= smpro_h(implode(', ', array_map(fn($a)=>($a['path']??''), array_filter($acts,fn($a)=>($a['type']??'')==='quarantine')))) ?>">&#129529; <?= smpro_h(implode(', ', array_slice($qf,0,6))) ?><?= count($qf)>6?' +'.(count($qf)-6):'' ?></div><?php endif; ?>
        </td>
        <td><button class="la-act emUndo" data-eid="<?= smpro_h($e['id']??'') ?>" data-i18n>Restore</button></td>
      </tr>
    <?php endforeach; ?>
    </tbody></table></div>

<?php else: /* settings */ $c = smpro_in_cfg(); ?>
  <div class="card" style="padding:18px 20px;max-width:760px">
    <h3 style="margin:0 0 12px" data-i18n>Blocking &amp; response</h3>
    <div class="im-frm">
      <label class="lm-chkl"><input type="checkbox" id="cfgUseCsf" <?= !empty($c['use_csf'])?'checked':'' ?>> <span data-i18n>Block via CSF (local firewall)</span></label>
      <label class="lm-chkl"><input type="checkbox" id="cfgUseCf" <?= !empty($c['use_cloudflare'])?'checked':'' ?>> <span data-i18n>Block via Cloudflare edge</span></label>
      <div class="im-row"><label data-i18n>Cloudflare Account ID</label><input type="text" id="cfgCfAcct" class="tp-in" value="<?= smpro_h($c['cf_account']) ?>" placeholder="32-char account id"></div>
      <div class="im-row"><label data-i18n>Cloudflare API Token</label><input type="password" id="cfgCfTok" class="tp-in" placeholder="<?= $c['cf_token']!==''?'•••••• (saved — leave blank to keep)':'token with Account Firewall Access Rules: Edit' ?>"></div>
      <div class="im-row"><label data-i18n>AbuseIPDB Key (optional)</label><input type="password" id="cfgAbuse" class="tp-in" placeholder="<?= $c['abuseipdb_key']!==''?'•••••• (saved)':'optional reputation enrichment' ?>"></div>
      <div class="im-row"><label data-i18n>Offline GeoIP database (country + datacenter detection)</label>
        <div><button class="tp-btn" id="imGeoBtn" type="button" data-i18n>Update GeoIP database now</button>
        <span id="imGeoMsg" class="meta"><?php $glu=(int)(smpro_in_cfg()['geoip_last_update']??0); $haveDb=function_exists('smpro_geoip_db')&&smpro_geoip_db('Country')!==''; echo $glu?('updated '.date('Y-m-d',$glu)):($haveDb?'system DB in use':'no DB yet — click to download'); ?></span></div>
        <span class="meta" data-i18n>Downloads a fresh Country + ASN database (auto-refreshes weekly). Required for the Arab-exclusion and the geo auto-block rule.</span></div>
      <hr style="border:0;border-top:1px solid var(--line);margin:14px 0">
      <h3 style="margin:0 0 12px" data-i18n>Auto-response</h3>
      <label class="lm-chkl"><input type="checkbox" id="cfgAuto" <?= !empty($c['auto_block'])?'checked':'' ?>> <span data-i18n>Auto-block the worst attacker IPs (from the alert cron)</span></label>
      <label class="lm-chkl"><input type="checkbox" id="cfgAi" <?= !empty($c['ai_block'])?'checked':'' ?>> <span data-i18n>Use AI to decide which IPs to block (analyses attacks + applies SOC conditions; needs an AI provider)</span> <?= (function_exists('smpro_ai_available') && smpro_ai_available()) ? '<span class="b" style="background:var(--good-bg);color:var(--good)">AI ready</span>' : '<span class="b crit">no AI provider</span>' ?></label>
      <label class="sw"><input type="checkbox" id="cfgDry" <?= !empty($c['auto_block_dryrun'])?'checked':'' ?>><span class="track"></span><span class="lbl" data-i18n>Dry-run mode (log/alert only, do not actually block)</span><span class="st"></span></label>
      <div class="im-row"><label data-i18n>Auto-block any non-Arab IP after this many attacks</label><input type="number" id="cfgAutoMin" class="tp-in" value="<?= (int)($c['auto_block_threshold'] ?? 30) ?>" min="5"></div>
      <label class="lm-chkl"><input type="checkbox" id="cfgProtArab" <?= !empty($c['protect_arab'] ?? true)?'checked':'' ?>> <span data-i18n>Protect Arab residential IPs (EG/SA never auto-blocked; other Arab countries need 3× the threshold; datacenter &amp; non-Arab blocked at the threshold)</span></label>
      <div class="im-row"><label data-i18n>Allowlist (never block — IPs/CIDRs, one per line)</label><textarea id="cfgAllow" class="tp-in" rows="3"><?= smpro_h(implode("\n", (array)$c['allowlist'])) ?></textarea></div>
      <div class="im-row"><label data-i18n>Breach scan — ignore paths (legit auto-updating files, one per line/substring match)</label><textarea id="cfgBreach" class="tp-in" rows="3" placeholder="imunify-security&#10;/wp-content/cache/"><?= smpro_h(implode("\n", (array)($c['breach_exclude'] ?? []))) ?></textarea><span class="meta" data-i18n>e.g. imunify-security (Imunify's own WordPress plugin) — excluded so it is not mistaken for a web-shell.</span></div>
      <hr style="border:0;border-top:1px solid var(--line);margin:14px 0">
      <h3 style="margin:0 0 12px" data-i18n>Alert thresholds (push notifications)</h3>
      <div class="im-row"><label data-i18n>Alert window (minutes)</label><input type="number" id="cfgWin" class="tp-in" value="<?= (int)$c['alert_window_min'] ?>" min="2" max="180"></div>
      <div class="im-row"><label data-i18n>Domain attack spike (attempts/window)</label><input type="number" id="cfgThrDom" class="tp-in" value="<?= (int)$c['thr_domain_attacks'] ?>" min="5"></div>
      <div class="im-row"><label data-i18n>Distributed scan (IP → distinct domains)</label><input type="number" id="cfgThrIp" class="tp-in" value="<?= (int)$c['thr_ip_domains'] ?>" min="2"></div>
      <p class="meta" data-i18n>Alerts use the channels configured in Settings → Notifications (Telegram / WhatsApp / Email). The notify cron runs the alert scan.</p>
      <div style="margin-top:14px"><button class="tp-btn primary" id="imSaveBtn" data-i18n>Save settings</button> <span id="imSaveMsg" class="meta"></span></div>
    </div>
  </div>
<?php endif; ?>

<style>
.im-hero{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:14px 0 6px}@media(max-width:760px){.im-hero{grid-template-columns:repeat(2,1fr)}}
.im-c{background:#f7f9fc;border:1px solid var(--line);border-radius:14px;padding:14px 16px;display:flex;flex-direction:column;gap:2px}
.im-c .lbl{font-size:11px;color:var(--muted);text-transform:uppercase;font-weight:700}.im-c .v{font-size:24px;font-weight:800;line-height:1.1}
.la-tabs{display:flex;gap:4px;border-bottom:2px solid var(--line);margin:16px 0 14px;flex-wrap:wrap}
.la-tab{padding:9px 15px;font-size:14px;font-weight:600;color:var(--muted);text-decoration:none;border-bottom:3px solid transparent;margin-bottom:-2px;border-radius:8px 8px 0 0}
.la-tab:hover{color:var(--ink);background:var(--brand-bg)}.la-tab.active{color:var(--brand);border-bottom-color:var(--brand)}
/* vertical column dividers (grid) for the attack tables */
#imLiveTbl th,#imLiveTbl td,#imDomTbl th,#imDomTbl td,#imAtkTbl th,#imAtkTbl td,#imCampTbl th,#imCampTbl td{border-right:1px solid #e2e8f0}
#imLiveTbl th:last-child,#imLiveTbl td:last-child,#imDomTbl th:last-child,#imDomTbl td:last-child,#imAtkTbl th:last-child,#imAtkTbl td:last-child,#imCampTbl th:last-child,#imCampTbl td:last-child{border-right:0}
.la-scroll{max-height:560px;overflow:auto}.la-scroll table{margin:0}.la-scroll thead th{position:sticky;top:0;background:#fafbfe;z-index:1;box-shadow:inset 0 -1px 0 var(--line)}
.smpro-table{width:100%;border-collapse:collapse;font-size:13px}.smpro-table th,.smpro-table td{padding:8px 12px;text-align:left;border-bottom:1px solid var(--line)}
.smpro-table.nowrap th,.smpro-table.nowrap td{white-space:nowrap}.smpro-table th{font-size:11px;text-transform:uppercase;color:var(--muted)}.smpro-table th.num,.smpro-table td.num{text-align:right}
.tp-th{display:flex;align-items:center;gap:10px;padding:10px 2px;flex-wrap:wrap}.tp-in,.tp-sel{border:1px solid var(--line);border-radius:9px;padding:7px 11px;font-size:13px;background:#fff}
.tp-btn{border:1px solid var(--line);background:#fff;color:var(--ink);border-radius:9px;padding:8px 12px;font-size:13px;cursor:pointer;font-weight:600}.tp-btn.primary{background:var(--brand);color:#fff;border-color:var(--brand)}
.la-act{font-size:11px;font-weight:600;border:1px solid var(--line);background:#fff;border-radius:7px;padding:3px 9px;cursor:pointer}.la-act.block{color:var(--dang);border-color:#f3c4c4}.la-act.block:hover{background:var(--dang);color:#fff}
.la-act.allow{color:var(--good);border-color:#bfe6cd}.la-act.allow:hover{background:var(--good);color:#fff}
table.sortable th[data-sort]{cursor:pointer;user-select:none}table.sortable th[data-sort]:hover{color:var(--brand)}table.sortable th.sorted-asc::after{content:" \25B2";font-size:8px}table.sortable th.sorted-desc::after{content:" \25BC";font-size:8px}
.lnk{color:var(--brand);text-decoration:none;font-size:12px;border:1px solid var(--line);padding:3px 9px;border-radius:7px}.lnk:hover{background:var(--brand-bg)}
.ipmono,.uname{font-family:ui-monospace,Consolas,monospace}.mono{font-family:ui-monospace,Consolas,monospace;white-space:pre-wrap;word-break:break-all}
.lm-chkl{display:flex;align-items:center;gap:6px;font-size:13px;margin:6px 0}.lm-empty{padding:18px;color:var(--muted);text-align:center}
.k{display:inline-block;font-size:11px;background:var(--brand-bg);color:var(--brand);border-radius:10px;padding:1px 8px}
.b{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:20px}.b.crit{background:#fdecec;color:#b91c1c}.b.high{background:#fdeee2;color:#c2410c}.b.med{background:#fdf6e7;color:#a16207}
.meta{color:var(--muted)}.svc-kicker{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--brand);font-weight:700}
.la-tabs2{display:grid;grid-template-columns:1fr 1fr;gap:12px}@media(max-width:820px){.la-tabs2{grid-template-columns:1fr}}
.im-phases{display:flex;flex-direction:column;gap:8px;margin-top:10px}
.im-ph{display:flex;align-items:center;gap:10px;font-size:12.5px}.im-phl{width:210px;flex:none;color:var(--muted)}.im-phb{flex:1;height:9px;background:#eef1f6;border-radius:8px;overflow:hidden}.im-phb>i{display:block;height:100%;background:var(--dang);border-radius:8px}.im-ph b{width:64px;text-align:right}
.im-frm .im-row{display:flex;flex-direction:column;gap:4px;margin:10px 0}.im-frm label{font-size:13px;font-weight:600}.im-frm .tp-in{max-width:480px}
.sw{display:flex;align-items:center;gap:10px;cursor:pointer;margin:8px 0;font-size:13px;font-weight:600}
.sw input{display:none}
.sw .track{flex:none;width:44px;height:24px;border-radius:20px;background:#cbd5e1;position:relative;transition:background .15s}
.sw .track::after{content:"";position:absolute;top:2px;left:2px;width:20px;height:20px;border-radius:50%;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.25);transition:transform .15s}
.sw input:checked+.track{background:var(--brand)}
.sw input:checked+.track::after{transform:translateX(20px)}
.sw .lbl{flex:1}
.sw .st{flex:none;font-weight:800;font-size:11px;letter-spacing:.04em;padding:2px 9px;border-radius:20px;background:#f1f5f9;color:#64748b}
.sw .st::after{content:"OFF"}
.sw input:checked~.st{background:var(--brand-bg);color:var(--brand)}
.sw input:checked~.st::after{content:"ON"}
</style>

<script>
// Hide the just-used action button(s) for these IPs across ALL tables and replace with a "done" chip.
function imHideActBtns(ips,action){var e=(window.CSS&&CSS.escape)?CSS.escape:function(s){return s.replace(/"/g,'\\"');};
  ips.forEach(function(ip){document.querySelectorAll('.la-act.'+action+'[data-ip="'+e(ip)+'"]').forEach(function(btn){
    var chip=document.createElement('span');chip.className='la-done'+(action==='allow'?' allow':'');chip.textContent=action==='block'?'✓ Blocked':'✓ Allowed';
    btn.parentNode.replaceChild(chip,btn);
  });});}
function imClearSel(){document.querySelectorAll('.im-chk:checked').forEach(function(c){c.checked=false;});
  ['imSelAll','imSelAllDom','imSelAllCamp','imSelAllAtk'].forEach(function(id){var x=document.getElementById(id);if(x)x.checked=false;});
  if(window.imSyncBulk)window.imSyncBulk();}
function imAct(action,ips,btn){
  if(!ips.length)return; var verb=action==='block'?'Block':'Allow';
  smConfirm({icon:'ask',danger:action==='block',title:verb+' '+ips.length+' IP'+(ips.length>1?'s':'')+'?',
    confirmText:verb,
    message:(action==='block'?'They will be blocked in CSF (+ Cloudflare if enabled).':'They will be allowed in CSF and never auto-blocked.')+'\n\n'+ips.join('\n'),
    onConfirm:function(){
      if(btn)btn.disabled=true;
      var fd=new URLSearchParams();fd.set('im_action',action);fd.set('ips',ips.join(','));fd.set('smpro_csrf',IM_CSRF);
      fetch('index.cgi?page=intrusion-monitor',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'})
        .then(function(r){return r.json();}).then(function(j){
          if(!j||(!j.ok&&!(j.results&&j.results.length))){if(btn)btn.disabled=false;smDone({icon:'err',title:verb+' failed',message:(j&&j.error)||'Token/license error.'});return;}
          var okIps=(j.results||[]).filter(function(r){return r.ok;}).map(function(r){return r.ip;});
          var failed=(j.results||[]).filter(function(r){return !r.ok;});
          imHideActBtns(okIps,action);            // hide the used button(s)
          imClearSel();                           // clear the selection / bulk bar
          var msg=(action==='block'?'Blocked ':'Allowed ')+okIps.length+' IP'+(okIps.length===1?'':'s')+'.';
          if(failed.length)msg+='\nFailed: '+failed.map(function(r){return r.ip+' ('+(r.msg||'error')+')';}).join(', ');
          smDone({icon:failed.length?'warn':'ok',title:failed.length?'Done with warnings':(action==='block'?'Blocked':'Allowed'),message:msg});
        }).catch(function(){if(btn)btn.disabled=false;smDone({icon:'err',title:'Action failed',message:'Network error — try again.'});});
    }});
}
// thin wrappers so existing bulk / AI-apply callers keep working (and get the new modal + hide behaviour)
function imBlock(ips,btn){imAct('block',ips,btn);} function imAllow(ips,btn){imAct('allow',ips,btn);}
window.imBlock=imBlock; window.imAllow=imAllow;
document.addEventListener('click',function(e){var b=e.target.closest('.la-act.block');if(!b||b.classList.contains('imDel'))return;var ip=b.getAttribute('data-ip');if(ip)imAct('block',[ip],b);});
document.addEventListener('click',function(e){var b=e.target.closest('.la-act.allow');if(!b)return;var ip=b.getAttribute('data-ip');if(ip)imAct('allow',[ip],b);});
/* live/campaign filters (sorting + column resize/hide are handled by the GLOBAL table engine in layout.php;
   window.imReapplySort is provided globally and used after the live feed re-renders its rows) */
(function(){
  var lf=document.getElementById('imLiveFilter'),lb=document.getElementById('imLiveBody');
  window.imLiveApplyFilter=function(){if(!lf||!lb)return;var q=lf.value.toLowerCase();lb.querySelectorAll('tr').forEach(function(tr){var s=tr.getAttribute('data-search')||'';tr.style.display=(!q||s.indexOf(q)>=0)?'':'none';});};
  if(lf)lf.addEventListener('input',window.imLiveApplyFilter);
  [['imCampFilter','imCampTbl'],['imAtkFilter','imAtkTbl']].forEach(function(p){var ff=document.getElementById(p[0]),tt=document.getElementById(p[1]);
    if(ff&&tt)ff.addEventListener('input',function(){var q=ff.value.toLowerCase();tt.querySelectorAll('tbody tr').forEach(function(tr){var s=tr.getAttribute('data-search')||'';tr.style.display=(!q||s.indexOf(q)>=0)?'':'none';});});});
})();

(function(){var body=document.getElementById('imLiveBody');if(!body)return;var auto=document.getElementById('imAuto'),meta=document.getElementById('imLiveMeta');
  var domFilter=new URLSearchParams(location.search).get('dom')||'';
  function esc(s){return (s==null?'':String(s)).replace(/[&<>"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
  function sev(s){s=(s||'').toLowerCase();return s.indexOf('crit')>=0?'crit':(s.indexOf('err')>=0?'high':'med');}
  function load(){fetch('index.cgi?page=intrusion-monitor&im_live=1&mins=120',{cache:'no-store'}).then(function(r){return r.json();}).then(function(j){
    if(!j||!j.ok)return;var rows=j.rows||[];if(domFilter)rows=rows.filter(function(x){return (x.domain||'').indexOf(domFilter)>=0;});
    if(!rows.length)body.innerHTML='<tr><td colspan="11" class="lm-empty">No attacks in the last 2 hours'+(domFilter?' for '+esc(domFilter):'')+'.</td></tr>';
    else body.innerHTML=rows.map(function(x){return '<tr data-search="'+esc(((x.ip||'')+' '+(x.domain||'')+' '+(x.account||'')+' '+(x.kind||'')).toLowerCase())+'">'+
      '<td>'+(x.ip?'<input type="checkbox" class="im-chk" value="'+esc(x.ip)+'">':'')+'</td>'+
      '<td class="meta">'+esc(x.time)+'</td>'+
      '<td class="ipmono">'+esc(x.ip)+'</td>'+
      '<td class="meta">'+esc(x.cc||'')+(x.provider?' · '+esc((x.provider||'').slice(0,18)):'')+(x.bot?' <span class="b crit" title="datacenter / bot network">&#129302;</span>':'')+'</td>'+
      '<td><b>'+esc(x.domain)+'</b></td><td class="uname">'+esc(x.account||'')+'</td>'+
      '<td><span class="k">'+esc(x.kind)+'</span></td>'+
      '<td data-val="'+({crit:3,high:2,med:1}[sev(x.severity)]||0)+'"><span class="b '+sev(x.severity)+'">'+esc(x.severity||'—')+'</span></td>'+
      '<td>'+esc(x.code||'')+'</td>'+
      '<td class="meta" title="'+esc(x.uri)+'">'+esc((x.method||'')+' '+(x.uri||'')).slice(0,60)+'</td>'+
      '<td class="nowrap">'+(x.ip?'<button class="la-act block" data-ip="'+esc(x.ip)+'">Block</button> <button class="la-act allow" data-ip="'+esc(x.ip)+'">Allow</button>':'')+'</td></tr>';}).join('');
    if(window.imSyncBulk)window.imSyncBulk(); if(window.imLiveApplyFilter)window.imLiveApplyFilter();
    if(window.imReapplySort)window.imReapplySort(document.getElementById('imLiveTbl'));   // keep the user's sort after refresh
    if(meta)meta.textContent=j.count+' attack(s) · updated '+j.now+(domFilter?' · '+domFilter:'');}).catch(function(){});}
  load();setInterval(function(){if(!auto||auto.checked)load();},8000);})();

(function(){var f=document.getElementById('imDomFilter'),tbl=document.getElementById('imDomTbl');if(!f||!tbl)return;
  f.addEventListener('input',function(){var q=f.value.toLowerCase();tbl.querySelectorAll('tbody tr').forEach(function(tr){var s=tr.getAttribute('data-search')||'';tr.style.display=(!q||s.indexOf(q)>=0)?'':'none';});});})();

(function(){var gen=document.getElementById('imGenBtn');if(gen)gen.addEventListener('click',function(){var win=document.getElementById('imRepWin').value;gen.disabled=true;gen.textContent='Generating…';
  var fd=new URLSearchParams();fd.set('im_action','gen_report');fd.set('mins',win);fd.set('smpro_csrf',IM_CSRF);
  fetch('index.cgi?page=intrusion-monitor',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'}).then(function(r){return r.json();}).then(function(j){
    if(!j||!j.ok){alert('Report failed (token/license).');gen.disabled=false;gen.textContent='Generate report';return;}location.reload();}).catch(function(){alert('Report failed.');gen.disabled=false;gen.textContent='Generate report';});});
  document.addEventListener('click',function(e){var b=e.target.closest('.imDel');if(!b)return;var rid=b.getAttribute('data-rid');if(!confirm('Delete this report permanently?'))return;
    var fd=new URLSearchParams();fd.set('im_action','delete_report');fd.set('report_ids',rid);fd.set('smpro_csrf',IM_CSRF);
    fetch('index.cgi?page=intrusion-monitor',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'}).then(function(r){return r.json();}).then(function(j){if(j&&j.ok){var tr=b.closest('tr');if(tr)tr.remove();}else alert('Delete failed.');}).catch(function(){alert('Delete failed.');});});})();

(function(){var s=document.getElementById('imSaveBtn');if(!s)return;s.addEventListener('click',function(){
  var fd=new URLSearchParams();fd.set('im_action','save_settings');fd.set('smpro_csrf',IM_CSRF);
  fd.set('cf_account',document.getElementById('cfgCfAcct').value);fd.set('cf_token',document.getElementById('cfgCfTok').value);
  fd.set('abuseipdb_key',document.getElementById('cfgAbuse').value);
  if(document.getElementById('cfgUseCsf').checked)fd.set('use_csf','1');if(document.getElementById('cfgUseCf').checked)fd.set('use_cloudflare','1');
  if(document.getElementById('cfgAuto').checked)fd.set('auto_block','1');if(document.getElementById('cfgDry').checked)fd.set('auto_block_dryrun','1');
  if(document.getElementById('cfgAi')&&document.getElementById('cfgAi').checked)fd.set('ai_block','1');
  if(document.getElementById('cfgAutoMin'))fd.set('auto_block_threshold',document.getElementById('cfgAutoMin').value);
  if(document.getElementById('cfgProtArab')&&document.getElementById('cfgProtArab').checked)fd.set('protect_arab','1');
  fd.set('allowlist',document.getElementById('cfgAllow').value);fd.set('alert_window_min',document.getElementById('cfgWin').value);
  if(document.getElementById('cfgBreach'))fd.set('breach_exclude',document.getElementById('cfgBreach').value);
  fd.set('thr_domain_attacks',document.getElementById('cfgThrDom').value);fd.set('thr_ip_domains',document.getElementById('cfgThrIp').value);
  var m=document.getElementById('imSaveMsg');m.textContent='Saving…';
  fetch('index.cgi?page=intrusion-monitor',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'}).then(function(r){return r.json();}).then(function(j){m.textContent=(j&&j.ok)?'Saved ✓':'Save failed';if(j&&j.ok){document.getElementById('cfgCfTok').value='';document.getElementById('cfgAbuse').value='';}}).catch(function(){m.textContent='Save failed';});});})();

(function(){var b=document.getElementById('imGeoBtn');if(!b)return;b.addEventListener('click',function(){
  var m=document.getElementById('imGeoMsg');b.disabled=true;if(m)m.textContent='Downloading… (may take ~30s)';
  var fd=new URLSearchParams();fd.set('im_action','update_geoip');fd.set('smpro_csrf',IM_CSRF);
  fetch('index.cgi?page=intrusion-monitor',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'})
   .then(function(r){return r.json();}).then(function(j){b.disabled=false;if(m)m.textContent=(j&&j.ok)?('Updated ✓ — Country '+((j.country&&j.country.ok)?'ok':'fail')+', ASN '+((j.asn&&j.asn.ok)?'ok':'fail')):'Update failed (check outbound HTTPS)';})
   .catch(function(){b.disabled=false;if(m)m.textContent='Update failed';});});})();
</script>
<style>
.im-bulk{display:none;position:fixed;left:50%;transform:translateX(-50%);bottom:18px;z-index:50;background:#10182b;color:#fff;border-radius:14px;padding:10px 16px;align-items:center;gap:12px;box-shadow:0 18px 40px rgba(0,0,0,.35)}
.im-bulk.show{display:flex}.im-bulk b{color:#fff}.im-bbtn{font-size:13px;font-weight:600;border:0;border-radius:9px;padding:8px 14px;cursor:pointer}
.im-bbtn.block{background:var(--dang);color:#fff}.im-bbtn.allow{background:var(--good);color:#fff}.im-bbtn.ghost{background:#23304d;color:#cfd8ef}
/* AI recommendation decision badges */
.im-rb{display:inline-block;font-size:10px;font-weight:800;letter-spacing:.02em;padding:2px 7px;border-radius:20px;white-space:nowrap}
.im-rb.dang{background:var(--dang-bg);color:var(--dang)}
.im-rb.warn{background:var(--warn-bg);color:var(--warn)}
.im-rb.ok{background:var(--good-bg);color:var(--good)}
.im-rb.prot{background:#fef3c7;color:#b45309}
/* AI "recommended action" mark on the row's action button */
.la-act.im-rec{box-shadow:0 0 0 2px var(--brand);font-weight:800;position:relative}
.im-recstar{color:#f5b301;font-size:11px;vertical-align:middle}
.im-rec-hint{font-size:10.5px;font-weight:700;color:#b45309;background:#fef3c7;padding:2px 7px;border-radius:20px;white-space:nowrap}
</style>
<script>
/* multi-select bulk block (works across live / domains / campaigns tables) */
(function(){
  var n=document.getElementById('imBulkN'),bar=document.getElementById('imBulk');
  function selected(){return Array.prototype.slice.call(document.querySelectorAll('.im-chk:checked')).map(function(c){return c.value;}).filter(function(v,i,a){return v&&a.indexOf(v)===i;});}
  window.imSyncBulk=function(){var s=selected();if(n)n.textContent=s.length;if(bar)bar.classList.toggle('show',s.length>0);};
  document.addEventListener('change',function(e){
    var t=e.target;
    if(t.id==='imSelAll'||t.id==='imSelAllDom'||t.id==='imSelAllCamp'||t.id==='imSelAllAtk'){var tbl=t.closest('table');if(tbl)tbl.querySelectorAll('.im-chk').forEach(function(c){c.checked=t.checked;});}
    if((t.classList&&t.classList.contains('im-chk'))||(t.id&&t.id.indexOf('imSelAll')===0))window.imSyncBulk();
  });
  var bb=document.getElementById('imBulkBlock');if(bb)bb.addEventListener('click',function(){var s=selected();if(s.length&&window.imBlock)imBlock(s);});
  var ba=document.getElementById('imBulkAllow');if(ba)ba.addEventListener('click',function(){var s=selected();if(s.length&&window.imAllow)imAllow(s);});
  var bc=document.getElementById('imBulkClear');if(bc)bc.addEventListener('click',function(){document.querySelectorAll('.im-chk').forEach(function(c){c.checked=false;});['imSelAll','imSelAllDom','imSelAllCamp','imSelAllAtk'].forEach(function(id){var x=document.getElementById(id);if(x)x.checked=false;});window.imSyncBulk();});
})();
/* AI: review current attackers and recommend blocks */
(function(){var b=document.getElementById('imAiBtn'),p=document.getElementById('imAiPanel');if(!b||!p)return;
  function esc(s){return (s==null?'':String(s)).replace(/[&<>"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
  b.addEventListener('click',function(){var ot=b.innerHTML;b.disabled=true;b.innerHTML='&#129302; Analysing…';p.hidden=false;p.innerHTML='<div class="meta">&#129302; The AI is reviewing current attackers…</div>';
    var fd=new URLSearchParams();fd.set('im_action','ai_review');fd.set('mins','240');fd.set('smpro_csrf',IM_CSRF);
    fetch('index.cgi?page=intrusion-monitor',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'}).then(function(r){return r.json();}).then(function(j){
      b.disabled=false;b.innerHTML=ot;
      if(!j||!j.ok){p.innerHTML='<b style="color:var(--dang)">AI review unavailable.</b> <span class="meta">'+esc((j&&j.reason)||'Configure an AI provider in Settings → AI Providers.')+'</span>';return;}
      var rows=j.rows||[],blk=j.block||[];
      // group meta per decision
      var DEC={block:{t:'Block — recommended',c:'var(--dang)',ic:'&#128683;'},
               review:{t:'Manual review — your call',c:'#d97706',ic:'&#128737;'},
               keep:{t:'Keep — likely legitimate',c:'var(--muted)',ic:'&#9989;'}};
      function regBadge(r){if(r.decision==='block')return '<span class="im-rb dang">BLOCK</span>';
        if(r.region==='core_protected')return '<span class="im-rb prot">&#128737; PROTECTED '+esc(r.country||'')+'</span>';
        if(r.region==='arab_caution')return '<span class="im-rb warn">&#9888; REVIEW '+esc(r.country||'')+'</span>';
        if(r.decision==='keep')return '<span class="im-rb ok">KEEP</span>';
        return '<span class="im-rb warn">REVIEW</span>';}
      var html='<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap"><b>&#129302; AI recommendation'+(j.provider?' ('+esc(j.provider)+')':'')+'</b>';
      if(blk.length)html+='<button class="im-bbtn block" id="imAiApply" style="margin-left:auto">Block all '+blk.length+' recommended</button>';
      html+='</div>';
      if(j.reason)html+='<p class="meta" style="margin:8px 0">'+esc(j.reason)+'</p>';
      if(!rows.length){html+='<div class="meta" style="margin-top:6px">No attacker IPs to evaluate in this window.</div>';p.innerHTML=html;return;}
      // ONE table: each IP on its own row with its own Block / Allow buttons + a per-IP reason.
      html+='<div class="la-scroll" style="margin-top:8px"><table class="smpro-table nowrap" style="font-size:12px">'
        +'<thead><tr><th>Attacker IP</th><th>Country / Provider</th><th>Type</th><th>Decision &amp; why</th><th>Action</th></tr></thead><tbody>';
      ['block','review','keep'].forEach(function(dec){
        rows.filter(function(r){return r.decision===dec;}).forEach(function(r){
          var ipe=esc(r.ip);
          html+='<tr data-ip="'+ipe+'">'
            +'<td class="ipmono"><b>'+ipe+'</b><div class="meta" style="font-size:10px">'+r.hits+' attacks</div></td>'
            +'<td>'+esc(r.country||'?')+' <span class="meta">'+esc(r.provider||'')+'</span></td>'
            +'<td>'+(r.bot?'<span class="im-rb dang">datacenter</span>':'<span class="im-rb ok">residential</span>')+'</td>'
            +'<td>'+regBadge(r)+'<div class="meta" style="font-size:11px;margin-top:2px;white-space:normal;max-width:340px">'+esc(r.reason||'')+'</div></td>'
            +'<td style="white-space:nowrap">'
              +'<button class="la-act block'+(r.decision==='block'?' im-rec':'')+'" data-ip="'+ipe+'" title="'+(r.decision==='block'?'AI recommends blocking this IP':'Block this IP in the firewall')+'">&#128683; Block'+(r.decision==='block'?' <span class="im-recstar">&#9733;</span>':'')+'</button> '
              +'<button class="la-act allow'+(r.decision==='keep'?' im-rec':'')+'" data-ip="'+ipe+'" title="'+(r.decision==='keep'?'AI recommends keeping/allowing this IP':'Whitelist this IP')+'">&#9989; Allow'+(r.decision==='keep'?' <span class="im-recstar">&#9733;</span>':'')+'</button>'
              +(r.decision==='review'?' <span class="im-rec-hint" title="The AI leaves this to your judgement">&#128737; your call</span>':'')
            +'</td></tr>';
        });
      });
      html+='</tbody></table></div>';
      p.innerHTML=html;
      var ap=document.getElementById('imAiApply');if(ap&&blk.length)ap.addEventListener('click',function(){if(window.imBlock)imBlock(blk);});
      // per-row .la-act Block/Allow buttons are handled by the existing global delegate (confirm modal +
      // hide-on-success ✓ chip). Region protection only gates AUTO blocks — explicit clicks always act.
    }).catch(function(){b.disabled=false;b.innerHTML=ot;p.innerHTML='<b style="color:var(--dang)">AI request failed.</b>';});
  });
})();
</script>
<style>.la-tab.im-emtab{color:var(--dang);font-weight:700}.la-tab.im-emtab.on{background:rgba(220,38,38,.1);border-bottom-color:var(--dang)}</style>
<script>
/* Emergency tab: save toggles, run/preview sweep, restore actions */
(function(){
  function P(id){return document.getElementById(id);}
  function esc(s){return (s==null?'':String(s)).replace(/[&<>"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
  var save=P('emSave');
  if(save)save.addEventListener('click',function(){var m=P('emMsg');m.textContent='Saving…';
    var fd=new URLSearchParams();fd.set('im_action','emergency_save');fd.set('smpro_csrf',IM_CSRF);
    if(P('emOn').checked)fd.set('emergency','1');if(P('emHarden').checked)fd.set('emergency_harden','1');if(P('emClean').checked)fd.set('emergency_clean','1');if(P('emBlock').checked)fd.set('emergency_block_scanners','1');if(P('emBatch'))fd.set('emergency_batch',P('emBatch').value);if(P('emDigestH'))fd.set('emergency_block_digest_hours',P('emDigestH').value);if(P('emDry').checked)fd.set('emergency_dryrun','1');
    fetch('index.cgi?page=intrusion-monitor',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'}).then(function(r){return r.json();}).then(function(j){m.textContent=(j&&j.ok)?'Saved ✓':'Save failed';}).catch(function(){m.textContent='Save failed';});});
  function run(dry){var out=P('emOut'),btn=dry?P('emRunDry'):P('emRun');
    if(!dry&&!confirm('Run the EMERGENCY sweep now?\n\nQuarantines web-shells + hardens (locks core files + blocks PHP in upload dirs) on every site currently under exploit attack with recently-changed files. All actions are backed up and reversible.'))return;
    var ot=btn.innerHTML;btn.disabled=true;btn.innerHTML='Running…';out.hidden=false;out.innerHTML='<div class="meta">Sweeping attacked sites…</div>';
    var fd=new URLSearchParams();fd.set('im_action','emergency_run');fd.set('smpro_csrf',IM_CSRF);if(dry)fd.set('dryrun','1');
    fetch('index.cgi?page=intrusion-monitor',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'}).then(function(r){return r.json();}).then(function(j){
      btn.disabled=false;btn.innerHTML=ot;
      if(!j||!j.ok){out.innerHTML='<b style="color:var(--dang)">Sweep failed (token/license).</b>';return;}
      var h=(j.hardened||[]),c=(j.cleaned||[]),bk=(j.blocked||[]);
      var html='<b>'+(j.dryrun?'DRY-RUN — would act on ':'Done — ')+(bk.length?bk.length+' scanner IP(s) blocked, ':'')+h.length+' site(s) hardened, '+(j.cleaned_count||0)+' web-shell(s) quarantined.</b>';
      if(!h.length&&!c.length&&!bk.length)html+='<div class="meta" style="margin-top:6px">No malicious scanners and no attacked site with changed files — nothing to do.</div>';
      bk.forEach(function(x){html+='<div style="margin-top:6px">&#128683; <b>'+esc(x.ip)+'</b> — '+esc(x.reason)+'</div>';});
      c.forEach(function(x){html+='<div style="margin-top:6px">&#129529; <b>'+esc(x.domain)+'</b>: '+(x.files||[]).map(function(f){return esc((f.path||'').split('/').pop());}).join(', ')+'</div>';});
      h.forEach(function(x){html+='<div class="meta" style="margin-top:4px">&#128737; '+esc(x.domain)+' — '+x.n+' hardening action(s)</div>';});
      if(!j.dryrun)html+='<div class="meta" style="margin-top:8px">Reload to see the action log + restore.</div>';
      out.innerHTML=html;
    }).catch(function(){btn.disabled=false;btn.innerHTML=ot;out.innerHTML='<b style="color:var(--dang)">Request failed.</b>';});}
  if(P('emRun'))P('emRun').addEventListener('click',function(){run(false);});
  if(P('emRunDry'))P('emRunDry').addEventListener('click',function(){run(true);});
  document.addEventListener('click',function(e){var b=e.target.closest('.emUndo');if(!b)return;var eid=b.getAttribute('data-eid');
    if(!confirm('Restore this emergency action? (un-lock files + put quarantined files back)'))return;
    var fd=new URLSearchParams();fd.set('im_action','emergency_undo');fd.set('eid',eid);fd.set('smpro_csrf',IM_CSRF);
    fetch('index.cgi?page=intrusion-monitor',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'}).then(function(r){return r.json();}).then(function(j){if(j&&j.ok){var tr=b.closest('tr');if(tr)tr.remove();}else alert('Restore failed.');}).catch(function(){alert('Restore failed.');});});
})();
</script>
<?php
smpro_layout_footer();
