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
th{background:var(--bg);text-transform:uppercase;font-size:10px;color:#475569}
.b{display:inline-block;font-size:10px;font-weight:700;padding:1px 7px;border-radius:20px;background:var(--dang-bg);color:#b91c1c}
.k{display:inline-block;font-size:10px;background:var(--brand-bg);color:#3b5bdb;border-radius:10px;padding:1px 7px;margin:1px}
.brand{color:#3b5bdb;font-weight:700;float:right}.sum{display:flex;gap:18px;margin:8px 0 4px;flex-wrap:wrap}
.sum div{background:var(--card);border:1px solid #e6eaf1;border-radius:10px;padding:8px 14px}.sum b{font-size:18px;display:block}</style></head><body>";
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

/* ============================ subnet (/24) block + reputation cache ============================ */
define('SMPRO_IM_ABUSE_CACHE', SMPRO_VARLIB . '/im_abuse_cache.json');

/**
 * Block a whole /24 subnet in CSF. The single-IP deny path (smpro_im_block_ip → smpro_csf_deny_add) validates
 * with FILTER_VALIDATE_IP and REFUSES a CIDR, so a subnet block goes straight to the csf binary (CSF accepts a
 * CIDR in csf.deny). Strict /24 only, and it reuses the SAME refusal guards the single-IP block applies —
 * server IP / private-local / allowlisted / Cloudflare edge — evaluated over the whole range (a /24 deny hits
 * all 256 addresses), PLUS the home-region guard (never black-hole a home-region residential /24). Never weakens a gate.
 */
function smpro_im_block_subnet24($cidr) {
    $cidr = trim((string)$cidr);
    if (!preg_match('#^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.0/24$#', $cidr, $m))       return ['ok'=>false,'msg'=>'not a /24 CIDR'];
    $net = $m[1] . '.' . $m[2] . '.' . $m[3] . '.0';
    if (!filter_var($net, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4))                     return ['ok'=>false,'msg'=>'invalid /24 network'];   // rejects octets > 255
    if (function_exists('smpro_ip_is_external') && !smpro_ip_is_external($net))      return ['ok'=>false,'msg'=>'refused: private/local range'];
    if (function_exists('smpro_ip_is_cloudflare') && smpro_ip_is_cloudflare($net))   return ['ok'=>false,'msg'=>'refused: Cloudflare edge range — a deny would cut inbound traffic to every site'];
    if (function_exists('smpro_im_allowlisted') && smpro_im_allowlisted($net))       return ['ok'=>false,'msg'=>'refused: allowlisted'];
    // The server's own IP anywhere inside this /24 → denying the range would black-hole the box.
    if (function_exists('smpro_server_ips') && function_exists('smpro_in_cidr_match')) {
        foreach (array_keys(smpro_server_ips()) as $sip) if (smpro_in_cidr_match($sip, $cidr)) return ['ok'=>false,'msg'=>'refused: this server\'s IP is inside the /24'];
    } elseif (function_exists('smpro_is_server_ip') && smpro_is_server_ip($net))     return ['ok'=>false,'msg'=>'refused: server IP'];
    // Home-region protection (same policy as smpro_im_region_status): never deny an entire home-region residential
    // /24 — that is 256 likely-real customers. Block the individual attacker IPs instead.
    if (function_exists('smpro_im_region_status') && smpro_im_region_status($net) === 'core_protected')
                                                                                    return ['ok'=>false,'msg'=>'refused: home-region (' . smpro_im_home_regions_short() . ') residential /24 — block the individual attacker IPs instead'];
    $c = function_exists('smpro_in_cfg') ? smpro_in_cfg() : [];
    if (empty($c['use_csf']))                                                       return ['ok'=>false,'msg'=>'enable CSF blocking in Settings to block a subnet'];
    $csf = function_exists('smpro_csf_bin') ? smpro_csf_bin() : '';
    if ($csf === '')                                                                return ['ok'=>false,'msg'=>'CSF firewall not installed — cannot block a subnet'];
    $testing = function_exists('smpro_csf_testing') && smpro_csf_testing();
    // Route through the firewall that is ACTUALLY enforcing (CSF may be installed but disabled while something
    // else owns the rules — writing to csf.deny then blocks nothing while reporting success).
    // ONE block path (helpers.php, boot-loaded): engine detection + Cloudflare refusal. The raw `csf -d` fallback that
    // used to follow was dead code (the helper is always present) and skipped those guards when it did run.
    $r = smpro_fw_block_ip($cidr, 'smpro Intrusion Monitor subnet');
    return ['ok'=>!empty($r['ok']), 'testing'=>!empty($r['testing']) || $testing, 'engine'=>(string)($r['engine'] ?? ''), 'msg'=>(string)($r['msg'] ?? '')];
}

/**
 * AbuseIPDB reputation for an already-capped set of offender IPs, resolved at render time. smpro_im_abuse_score()
 * makes a LIVE call per IP with no cache, so this is bounded three ways: a small local file cache (12h TTL, negative
 * results cached too), a hard per-render live-lookup count budget, and a wall-clock deadline. Fresh cache hits cost
 * no network; uncached IPs beyond the budget/deadline are simply left blank and fill in on later loads. Returns
 * [ip => int score]. Empty when no AbuseIPDB key is configured (caller then omits the column).
 */
function smpro_im_abuse_scores(array $ips, $liveBudget = 12, $ttl = 43200) {
    $c = function_exists('smpro_in_cfg') ? smpro_in_cfg() : [];
    if (($c['abuseipdb_key'] ?? '') === '' || !function_exists('smpro_im_abuse_score')) return [];
    $cache = smpro_im_json_load(SMPRO_IM_ABUSE_CACHE);
    $now = time(); $out = []; $fetched = 0; $dirty = false; $deadline = microtime(true) + 5.0;
    foreach ($ips as $ip) {
        $ip = (string)$ip;
        if (!filter_var($ip, FILTER_VALIDATE_IP) || array_key_exists($ip, $out)) continue;
        $ent = $cache[$ip] ?? null;
        if (is_array($ent) && ($now - (int)($ent['ts'] ?? 0)) < $ttl) {                 // fresh cache hit → no network
            if (($ent['score'] ?? '') !== '') $out[$ip] = (int)$ent['score'];
            continue;
        }
        if ($fetched >= $liveBudget || microtime(true) >= $deadline) continue;          // bounded: cached-only past the budget/deadline
        $fetched++;
        $s = smpro_im_abuse_score($ip);                                                 // one live AbuseIPDB lookup (hard-capped count + time)
        $cache[$ip] = ['score' => ($s === '' ? '' : (int)$s), 'ts' => $now]; $dirty = true;   // negative-cache misses too
        if ($s !== '') $out[$ip] = (int)$s;
    }
    if ($dirty) { if (count($cache) > 5000) $cache = array_slice($cache, -4000, 4000, true); smpro_im_json_save(SMPRO_IM_ABUSE_CACHE, $cache); }
    return $out;
}

/* ============================ POST + AJAX dispatch (before output) ============================ */
$reqMethod = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));

/* Every im_action is an AJAX/JSON endpoint. Send the JSON content-type UP FRONT (before the
 * CSRF/root gates run) so any early smpro_fail() — expired token, license hiccup, non-root —
 * is returned as parseable JSON, not an HTML page (which made the UI show the misleading
 * "Request failed — check you are on the Security Monitor page"). Scoped to known actions so an
 * unknown value still falls through to the normal HTML page render. */
$__im_ajax_actions = ['block','allow','unblock','gen_report','delete_report','save_settings','update_geoip','ip_lookup','ai_review','emergency_save','emergency_run','emergency_undo','token'];
if ($reqMethod === 'POST' && in_array($_POST['im_action'] ?? '', $__im_ajax_actions, true)) {
    $GLOBALS['SMPRO_FORCE_JSON'] = true;   // make smpro_fail() return JSON even under the CLI SAPI (header() is a no-op there)
    header('Content-Type: application/json');
}

/* Fresh CSRF token for THIS page's im_action fetches — lets a long-open Live-attacks / AI-review page
 * recover from an EXPIRED token (1h TTL) without a full reload. Root-gated (authenticated WHM session);
 * no CSRF required (it mints one) and no state change. The token is actor-bound and only readable
 * same-origin, so it can't be exfiltrated cross-site. */
if ($reqMethod === 'POST' && ($_POST['im_action'] ?? '') === 'token') {
    smpro_require_root();
    echo json_encode(['ok'=>true,'token'=>smpro_csrf_generate('im_action')], JSON_UNESCAPED_SLASHES|JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

if ($reqMethod === 'POST' && ($_POST['im_action'] ?? '') === 'block') {
    smpro_require_valid_csrf('im_action'); smpro_require_root();
    header('Content-Type: application/json');
    $ips = array_unique(array_filter(array_map('trim', explode(',', (string)($_POST['ips'] ?? '')))));
    $res = [];
    foreach ($ips as $ip) {
        // a strict /24 CIDR blocks the whole subnet (guards inside); anything else is a single IP as before
        $r = preg_match('#^(\d{1,3}\.){3}0/24$#', $ip) ? smpro_im_block_subnet24($ip) : smpro_im_block_ip($ip, 'manual block');
        smpro_audit('intrusion_block', ['ip'=>$ip,'ok'=>$r['ok']]); $res[] = ['ip'=>$ip] + $r;
    }
    $allOk = $res ? array_reduce($res, fn($a,$r)=>$a && !empty($r['ok']), true) : false;   // honest: true only if EVERY block really enforced
    echo json_encode(['ok'=>$allOk,'results'=>$res], JSON_UNESCAPED_SLASHES|JSON_INVALID_UTF8_SUBSTITUTE); exit;
}
if ($reqMethod === 'POST' && ($_POST['im_action'] ?? '') === 'allow') {
    smpro_require_valid_csrf('im_action'); smpro_require_root();
    header('Content-Type: application/json');
    $ips = array_unique(array_filter(array_map('trim', explode(',', (string)($_POST['ips'] ?? '')))));
    $res = [];
    foreach ($ips as $ip) { $r = smpro_im_allow_ip($ip); smpro_audit('intrusion_allow', ['ip'=>$ip,'ok'=>$r['ok']]); $res[] = ['ip'=>$ip] + $r; }
    $allOk = $res ? array_reduce($res, fn($a,$r)=>$a && !empty($r['ok']), true) : false;
    echo json_encode(['ok'=>$allOk,'results'=>$res], JSON_UNESCAPED_SLASHES|JSON_INVALID_UTF8_SUBSTITUTE); exit;
}
/* Unblock, from the IP modal. It existed nowhere on that dialog: once an address was blocked the only button
 * left was Add to Allowlist — a permanent exemption — so "I blocked the wrong one" had no cheap way back and the
 * expensive one was the tempting one. Removing a block is the reversible correction; allow-listing is not. */
if ($reqMethod === 'POST' && ($_POST['im_action'] ?? '') === 'unblock') {
    smpro_require_valid_csrf('im_action'); smpro_require_root();
    header('Content-Type: application/json');
    $ips = array_unique(array_filter(array_map('trim', explode(',', (string)($_POST['ips'] ?? '')))));
    $res = [];
    foreach ($ips as $ip) {
        $r = smpro_csf_do('unblock', $ip);                      // verified: reports ok only when it really left csf.deny
        if (!empty($r['ok']) && function_exists('smpro_im_blocked_forget')) @smpro_im_blocked_forget($ip);
        smpro_audit('intrusion_unblock', ['ip' => $ip, 'ok' => !empty($r['ok']), 'actor' => function_exists('smpro_current_actor') ? smpro_current_actor() : 'root']);
        $res[] = ['ip' => $ip] + $r;
    }
    $allOk = $res ? array_reduce($res, fn($a, $r) => $a && !empty($r['ok']), true) : false;
    echo json_encode(['ok' => $allOk, 'results' => $res], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}
if ($reqMethod === 'POST' && ($_POST['im_action'] ?? '') === 'gen_report') {
    smpro_require_valid_csrf('im_action'); smpro_require_root();
    header('Content-Type: application/json');
    $mins = max(5, min(43200, (int)($_POST['mins'] ?? 1440)));
    $events = smpro_im_parse_modsec(SMPRO_IM_REPORT_BYTES, SMPRO_IM_CAP, time() - $mins * 60);
    $byDom = smpro_im_by_domain($events);
    $id = smpro_im_save_report($mins, $events, $byDom);
    smpro_audit('intrusion_report', ['id'=>$id,'mins'=>$mins,'total'=>count($events)]);
    echo json_encode(['ok'=>true,'id'=>$id,'total'=>count($events),'domains'=>count($byDom)], JSON_UNESCAPED_SLASHES|JSON_INVALID_UTF8_SUBSTITUTE); exit;
}
if ($reqMethod === 'POST' && ($_POST['im_action'] ?? '') === 'delete_report') {
    smpro_require_valid_csrf('im_action'); smpro_require_root();
    header('Content-Type: application/json');
    $ids = array_unique(array_filter(array_map('trim', explode(',', (string)($_POST['report_ids'] ?? '')))));
    $del = []; foreach ($ids as $rid) if (smpro_im_delete_report($rid)) $del[] = $rid;
    smpro_audit('intrusion_report_delete', ['deleted'=>$del]);
    echo json_encode(['ok'=>true,'deleted'=>$del], JSON_UNESCAPED_SLASHES|JSON_INVALID_UTF8_SUBSTITUTE); exit;
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
        // The login guard's second rule: a scan spread thinly across many addresses of one network, where no
        // single address ever reaches the per-address threshold. Both numbers must be met before it acts.
        'login_guard_net'       => !empty($_POST['login_guard_net']),
        'login_guard_net_ips'   => max(2, min(500,   (int)($_POST['login_guard_net_ips']   ?? ($cur['login_guard_net_ips']   ?? 2)))),
        'login_guard_net_fails' => max(2, min(100000,(int)($_POST['login_guard_net_fails'] ?? ($cur['login_guard_net_fails'] ?? 10)))),
        'protect_arab'      => !empty($_POST['protect_arab']),
        // Only overwrite when actually submitted (a stale cached page without these fields must not wipe them).
        'protect_regions'   => array_key_exists('protect_regions', $_POST) ? smpro_im_parse_ccs((string)$_POST['protect_regions']) : (array)($cur['protect_regions'] ?? ['EG','SA']),
        'caution_regions'   => array_key_exists('caution_regions', $_POST) ? smpro_im_parse_ccs((string)$_POST['caution_regions']) : (array)($cur['caution_regions'] ?? []),
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
    echo json_encode(['ok'=>true], JSON_UNESCAPED_SLASHES|JSON_INVALID_UTF8_SUBSTITUTE); exit;
}
if ($reqMethod === 'POST' && ($_POST['im_action'] ?? '') === 'update_geoip') {
    smpro_require_valid_csrf('im_action'); smpro_require_root();
    header('Content-Type: application/json');
    if (function_exists('smpro_deps_ensure')) { try { smpro_deps_ensure(true); } catch (\Throwable $e) { if (function_exists('smpro_soft_fail')) smpro_soft_fail(basename(__FILE__) . ':' . __LINE__, $e); } }   // also (re)install mmdblookup
    $rc = function_exists('smpro_geoip_update') ? smpro_geoip_update('Country') : ['ok'=>false,'msg'=>'unavailable'];
    $ra = function_exists('smpro_geoip_update') ? smpro_geoip_update('ASN') : ['ok'=>false,'msg'=>'unavailable'];
    smpro_audit('intrusion_geoip_update', ['country'=>!empty($rc['ok']),'asn'=>!empty($ra['ok'])]);
    echo json_encode(['ok'=>(!empty($rc['ok'])||!empty($ra['ok'])),'country'=>$rc,'asn'=>$ra], JSON_UNESCAPED_SLASHES|JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

/* Global IP profile — aggregates GeoIP + CSF block status + allowlist + attack DB + saved reports. */
if ($reqMethod === 'POST' && ($_POST['im_action'] ?? '') === 'ip_lookup') {
    // Must be set BEFORE the guards below. Without it a REFUSED request answers in HTML — header() is a no-op
    // under this SAPI — so the dialog's r.json() rejects and it falls back to the generic "could not load"
    // message. The renderer already knows how to say "reload the page to refresh your session" for an expired
    // token, but only if the refusal reaches it as JSON. That is why a page left open past its token looked
    // broken rather than stale, and why carefully guarding the body below was not enough on its own.
    $GLOBALS['SMPRO_FORCE_JSON'] = true;
    smpro_require_valid_csrf('im_action', false); smpro_require_root();   // read-only: no live license round-trip (robust to license-server hiccups)
    header('Content-Type: application/json');
    $ip = trim((string)($_POST['ip'] ?? ''));
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        echo json_encode(['ok'=>false,'error'=>'Invalid IP address'], JSON_UNESCAPED_SLASHES|JSON_INVALID_UTF8_SUBSTITUTE); exit;
    }
    // Whole body guarded: any single data source that throws MUST still return parseable JSON, or the
    // modal's r.json() rejects and shows "Could not load IP details". Each optional source degrades to a default.
    try {
        $intel   = function_exists('smpro_ip_intel') ? smpro_ip_intel($ip, false) : [];
        $isBot   = function_exists('smpro_ip_is_datacenter') ? smpro_ip_is_datacenter($intel) : false;
        $blocked = function_exists('smpro_im_csf_blocked') ? isset(smpro_im_blocked_set()[$ip]) : false;
        $allowl  = function_exists('smpro_im_allowlisted') ? smpro_im_allowlisted($ip) : false;
        $sum     = function_exists('smpro_in_ip_summary') ? smpro_in_ip_summary($ip) : ['total'=>0,'recent'=>[]];
        $recent  = array_map(fn($e) => [
            'ts'       => (int)($e['ts'] ?? 0),
            'domain'   => (string)($e['domain'] ?? ''),
            'kind'     => (string)($e['kind'] ?? ''),
            'severity' => (string)($e['severity'] ?? ''),
            'uri'      => mb_substr((string)($e['uri'] ?? ''), 0, 60),
            'code'     => (string)($e['code'] ?? ''),
        ], array_slice($sum['recent'] ?? [], 0, 25));
        unset($sum['recent']);
        // login/auth attempts across ALL services (SSH/mail/FTP/cPanel) — so a brute-forcer isn't blank
        $logins = function_exists('smpro_ip_auth_attempts') ? array_slice(smpro_ip_auth_attempts($ip, 0, 0, 60), 0, 40) : [];
        $lsum = ['failed'=>0,'success'=>0,'services'=>[]];
        foreach ($logins as $lg) { if (($lg['result']??'')==='failed') $lsum['failed']++; elseif (($lg['result']??'')==='success') $lsum['success']++; $s=$lg['source']??'?'; $lsum['services'][$s]=($lsum['services'][$s]??0)+1; }
        $inRep = [];
        if (function_exists('smpro_im_reports_index')) foreach (array_slice(smpro_im_reports_index(), 0, 60) as $r) {
            if (count($inRep) >= 10) break;
            $p = $r['path'] ?? ''; if (!$p || !is_file($p)) continue;
            $rep = smpro_im_json_load($p);
            foreach (($rep['by_domain'] ?? []) as $g) {
                if (isset($g['top_ips'][$ip])) $inRep[] = ['id'=>$r['id'],'created'=>$r['created'],'domain'=>$g['domain'],'count'=>(int)$g['top_ips'][$ip]];
            }
        }
        smpro_audit('intrusion_ip_lookup', ['ip'=>$ip]);
        echo json_encode([
            'ok'=>true,'ip'=>$ip,
            'geo'=>['country'=>(string)($intel['country']??''),'provider'=>(string)($intel['provider']??''),'datacenter'=>$isBot],
            'blocked'=>$blocked,'allowlisted'=>$allowl,
            'summary'=>$sum,'recent'=>$recent,'logins'=>$logins,'login_summary'=>$lsum,'in_reports'=>$inRep,
        ], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_INVALID_UTF8_SUBSTITUTE);
    } catch (\Throwable $e) {
        smpro_audit('intrusion_ip_lookup_error', ['ip'=>$ip,'err'=>$e->getMessage()]);
        echo json_encode(['ok'=>false,'error'=>'IP lookup hit an error: ' . $e->getMessage()], JSON_UNESCAPED_SLASHES|JSON_INVALID_UTF8_SUBSTITUTE);
    }
    exit;
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
    $csfBlk = function_exists('smpro_im_csf_blocked') ? smpro_im_blocked_set() : [];   // mark IPs already in csf.deny
    $mkRow = function($ip, $decision) use ($intel, $csfBlk) {
        $o = $intel[$ip] ?? [];
        $region = function_exists('smpro_im_region_status') ? smpro_im_region_status($ip) : 'normal';
        $bot = !empty($o['bot']);
        if ($decision === 'block') {
            $reason = $bot ? 'Datacenter/hosting network attacking — safe to block.'
                : 'Clear, repeated web attack — recommended to block.';
        } elseif ($region === 'core_protected') {
            $reason = 'Home region (' . smpro_im_home_regions_short() . ') residential IP — NOT auto-blocked (likely a real customer whose device is compromised). Block only if you confirm it is an attacker.';
        } elseif ($region === 'arab_caution') {
            $reason = 'Arab-region residential IP, not yet a clear/repeated attack — review before blocking.';
        } else {
            $reason = 'Likely legitimate (crawler / low-volume / possible false positive) — kept.';
        }
        return ['ip'=>$ip,'country'=>(string)($o['country'] ?? ''),'provider'=>(string)($o['provider'] ?? ''),
                'bot'=>$bot,'hits'=>(int)($o['hits'] ?? 0),'region'=>$region,'decision'=>$decision,'reason'=>$reason,'blocked'=>isset($csfBlk[$ip])];
    };
    $rows = [];
    foreach (($ai['block'] ?? []) as $ip)  $rows[] = $mkRow($ip, 'block');
    foreach (($ai['review'] ?? []) as $ip) $rows[] = $mkRow($ip, 'review');
    foreach (($ai['keep'] ?? []) as $ip)   { if (filter_var($ip, FILTER_VALIDATE_IP)) $rows[] = $mkRow($ip, 'keep'); }
    echo json_encode(['ok'=>!empty($ai['ok']),'rows'=>$rows,'block'=>$ai['block'] ?? [],'keep'=>$ai['keep'] ?? [],'review'=>$ai['review'] ?? [],'reason'=>$ai['reason'] ?? '','provider'=>$ai['provider'] ?? '','offenders'=>$off], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_INVALID_UTF8_SUBSTITUTE); exit;
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
    echo json_encode(['ok'=>true,'scanner'=>is_file('/etc/cron.d/smpro-notify')], JSON_UNESCAPED_SLASHES|JSON_INVALID_UTF8_SUBSTITUTE); exit;
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
    echo json_encode(['ok'=>true,'dryrun'=>$r['dryrun'],'hardened'=>$r['hardened'],'cleaned'=>$r['cleaned'],'cleaned_count'=>$cf,'blocked'=>$blk,'blocked_count'=>count($blk)], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_INVALID_UTF8_SUBSTITUTE); exit;
}
/* EMERGENCY: undo (restore) a recorded emergency action. */
if ($reqMethod === 'POST' && ($_POST['im_action'] ?? '') === 'emergency_undo') {
    smpro_require_valid_csrf('im_action'); smpro_require_root();
    header('Content-Type: application/json');
    $ok = smpro_im_emergency_undo((string)($_POST['eid'] ?? ''));
    smpro_audit('intrusion_emergency_undo', ['eid'=>(string)($_POST['eid'] ?? ''),'ok'=>$ok]);
    echo json_encode(['ok'=>$ok], JSON_UNESCAPED_SLASHES|JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

/* LIVE feed (GET, JSON) — polled by the page; also indexes into SQLite history. */
if (($_GET['im_live'] ?? '') === '1') {
    smpro_require_root();                                // these GET feeds return attacker IPs/domains — root-only
    header('Content-Type: application/json');
    $mins = max(1, min(1440, (int)($_GET['mins'] ?? 120)));
    $events = smpro_im_ingest_recent(SMPRO_IM_LIVE_BYTES, $mins);
    $events = array_filter($events, fn($e) => ($e['ts'] ?? 0) >= time() - $mins * 60);
    $rows = [];
    if ($events) smpro_ip_intel_bulk(array_slice(array_values(array_unique(array_filter(array_map(fn($e)=>$e['ip'],$events)))), 0, 120), true);
    foreach (array_slice($events, 0, 250) as $e) {
        $in = $e['ip'] !== '' ? smpro_ip_intel($e['ip'], false) : [];
        $rows[] = ['time'=>$e['ts']?date('H:i:s',$e['ts']):'','ip'=>$e['ip'],'cc'=>strtoupper((string)($in['country']??'')),
                   'provider'=>(string)($in['provider']??''),'asn'=>(string)($in['asn']??''),'bot'=>(smpro_ip_is_datacenter($in)?1:0),
                   'domain'=>$e['domain'],'account'=>smpro_im_account_for($e['domain']),'kind'=>$e['kind'],'severity'=>$e['severity'],'code'=>$e['code'],'method'=>$e['method'],'uri'=>mb_substr((string)$e['uri'],0,120)];
    }
    echo json_encode(['ok'=>true,'count'=>count($events),'rows'=>$rows,'now'=>date('H:i:s')], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_INVALID_UTF8_SUBSTITUTE); exit;
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
            smpro_fputcsv($fh, [$g['domain'],$g['account'] ?? '',$g['total'],$g['uniq_ips'] ?? '',$g['top_cat'] ?? '',$g['sev'] ?? '',implode(' ', $ips),!empty($g['first'])?date('Y-m-d H:i',$g['first']):'',!empty($g['last'])?date('Y-m-d H:i',$g['last']):'']); }
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
    fputcsv($fh, []); fputcsv($fh, ['== TARGETED PATHS ==']); fputcsv($fh, ['path','requests','uniq_ips']); foreach ($aa['paths'] as $p) smpro_fputcsv($fh, [$p['path'], $p['n'], $p['uniq_ips']]);
    fputcsv($fh, []); fputcsv($fh, ['== COORDINATED CAMPAIGNS (/24) ==']); fputcsv($fh, ['subnet','attacker_ips','requests']); foreach ($aa['campaigns'] as $s) fputcsv($fh, [$s['subnet'], $s['uniq_ips'], $s['n']]);
    fputcsv($fh, []); fputcsv($fh, ['== TOP SOURCE IPs ==']); fputcsv($fh, ['rank','ip','country','provider','requests','main_target','user_agents']);
    $r = 0; foreach ($aa['attackers'] as $x) { $r++; $in = smpro_ip_intel($x['ip'], false); smpro_fputcsv($fh, [$r, $x['ip'], strtoupper((string)($in['country'] ?? '')), (string)($in['provider'] ?? ''), $x['n'], $x['top_path'], $x['ua_count']]); }
    fclose($fh); exit;
}

/* ============================ PAGE RENDER ============================ */
$tab  = preg_replace('/[^a-z]/', '', strtolower((string)($_GET['tab'] ?? 'live')));
if (!in_array($tab, ['live','domains','attack','breaches','campaigns','reports','settings','emergency'], true)) $tab = 'live';
$mins = max(5, min(43200, (int)($_GET['mins'] ?? 1440)));
$modsec = smpro_im_modsec_log();
$csrf = smpro_csrf_generate('im_action');

// The 9 MB audit-log parse ran on EVERY render (0.7 s warm on a busy server). It is memoised for a minute per
// window; the index ingest and the intel warm-up run only when the parse really ran.
$imFresh = false;
$events = ($tab !== 'reports' && $tab !== 'settings' && $modsec !== '')
    ? (array)smpro_memo('im_page_' . $mins, 60, function () use ($mins, &$imFresh) { $imFresh = true; return smpro_im_parse_modsec(SMPRO_IM_PAGE_BYTES, SMPRO_IM_CAP, time() - $mins * 60); })
    : [];
if ($events && $imFresh) { smpro_in_ingest($events); smpro_ip_intel_bulk(array_slice(array_keys(array_count_values(array_filter(array_map(fn($e)=>$e['ip'],$events)))), 0, 80), true); }
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
// Honesty banner: ModSecurity present but its rule engine is Off / DetectionOnly on some/all vhosts → it LOGS
// attacks but does NOT block them. cPanel sets SecRuleEngine per-vhost, so we report how many contexts are off.
$mse = function_exists('smpro_im_modsec_engine_state') ? smpro_im_modsec_engine_state() : ['off'=>0,'detection'=>0,'on'=>0];
$mseNoBlock = (int)($mse['off'] ?? 0) + (int)($mse['detection'] ?? 0);
if ($modsec !== '' && $mseNoBlock > 0): ?>
<div class="card" style="border-left:4px solid var(--warn);background:var(--warn-bg);padding:14px 16px;margin:12px 0">
  <b>&#9888; ModSecurity is logging attacks but NOT blocking them on <?= $mseNoBlock ?> site context(s).<?= smpro_beta_badge() ?></b>
  <p class="meta" style="margin:6px 0 0"><code>SecRuleEngine</code> is Off/DetectionOnly for <?= $mseNoBlock ?> context(s)<?= (int)($mse['on'] ?? 0) > 0 ? (' (and On for ' . (int)$mse['on'] . ')') : '' ?>. The detections below are read from the audit log, but the WAF is not stopping those requests. To actually block, set <code>SecRuleEngine On</code> in WHM → Security Center → ModSecurity — or use the CSF / Cloudflare IP blocking on this page.</p>
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

<?php
// ---- the overview: one tile per fact, read from the values already computed above. Each tile opens its section when that
// section is on the current tab, and switches to the right tab otherwise. The navigator lists the sections of THIS tab.
$imTabOf = ['im-feed' => 'live', 'im-bydom' => 'domains', 'im-analysis' => 'attack', 'im-attackers' => 'attack', 'im-compromise' => 'breaches',
            'im-scanners' => 'campaigns', 'im-domains' => 'campaigns', 'im-saved' => 'reports', 'im-emergency' => 'emergency', 'im-emlog' => 'emergency',
            'im-blocking' => 'settings', 'im-auto' => 'settings', 'im-breach' => 'settings', 'im-alerts' => 'settings'];
$imLbl = ['im-feed' => '&#9889; Live feed', 'im-bydom' => '&#127760; By domain', 'im-analysis' => '&#128202; Analysis', 'im-attackers' => '&#128123; Source IPs', 'im-compromise' => '&#9888; Compromises',
          'im-scanners' => '&#128269; Scanners', 'im-domains' => '&#127919; Targeted domains', 'im-saved' => '&#128190; Saved reports', 'im-emergency' => '&#128680; Emergency', 'im-emlog' => '&#128203; Action log',
          'im-blocking' => '&#128683; Blocking', 'im-auto' => '&#9881; Auto-response', 'im-breach' => '&#128737; Breach exceptions', 'im-alerts' => '&#128276; Alerts'];
$imCsfOn = !$csfTesting && !$csfMissing;
$imOv = [
  ['id' => 'im-feed', 'l' => 'Attacks', 'v' => number_format($totalAttacks), 'cls' => $totalAttacks ? 'warn' : 'good', 's' => 'last ' . (int)($mins/60) . 'h · 30d indexed: ' . number_format($hist['total'])],
  ['id' => 'im-bydom', 'l' => 'Domains hit', 'v' => number_format(count($byDom)), 'cls' => $byDom ? 'warn' : 'good', 's' => 'domains with at least one detection'],
  ['id' => 'im-attackers', 'l' => 'Attacker IPs', 'v' => number_format($uniqIps), 'cls' => $uniqIps ? 'brand' : 'good', 's' => 'unique source addresses'],
  ['id' => 'im-feed', 'l' => 'Critical', 'v' => number_format($crit), 'cls' => $crit ? 'dang' : 'good', 's' => 'critical-severity events'],
  ['id' => '', 'l' => 'WAF not blocking', 'v' => $modsec === '' ? 'no log' : ($mseNoBlock > 0 ? number_format($mseNoBlock) . ' contexts' : 'blocking'), 'cls' => $modsec === '' ? 'muted' : ($mseNoBlock > 0 ? 'dang' : 'good'), 's' => $mseNoBlock > 0 ? 'SecRuleEngine Off / DetectionOnly' : 'ModSecurity SecRuleEngine On'],
  ['id' => 'im-blocking', 'l' => 'CSF enforcing', 'v' => $imCsfOn ? 'YES' : 'NO', 'cls' => $imCsfOn ? 'good' : 'dang', 's' => $csfMissing ? 'CSF not installed' : ($csfTesting ? 'TESTING mode - blocks not loaded' : 'blocks are loaded into the firewall')],
];
$imNav = [];
foreach ($imTabOf as $imId => $imT) if ($imT === $tab) $imNav[] = [$imId, $imLbl[$imId]];
?>
<div class="fw-kpis">
  <?php foreach ($imOv as $k): $kOn = $k['id'] !== '' && ($imTabOf[$k['id']] ?? '') === $tab; ?>
  <?php if ($k['id'] === ''): ?><div class="fw-kpi <?= $k['cls'] ?>"><div class="l"><?= smpro_h($k['l']) ?></div><div class="v"><?= smpro_h($k['v']) ?></div><div class="s"><?= smpro_h($k['s']) ?></div></div>
  <?php else: ?><a class="fw-kpi <?= $k['cls'] ?>" href="<?= $kOn ? '#' . $k['id'] : 'index.cgi?page=intrusion-monitor&amp;tab=' . $imTabOf[$k['id']] . '#' . $k['id'] ?>"<?= $kOn ? ' data-go="' . $k['id'] . '"' : '' ?>><div class="l"><?= smpro_h($k['l']) ?></div><div class="v"><?= smpro_h($k['v']) ?></div><div class="s"><?= smpro_h($k['s']) ?></div></a><?php endif; ?>
  <?php endforeach; ?>
</div>
<nav class="fw-nav" id="fwNav"><?php foreach ($imNav as [$id, $lbl]): ?><a href="#<?= $id ?>" data-go="<?= $id ?>"><?= $lbl ?></a><?php endforeach; ?><span class="sp"></span><button type="button" class="fw-navx" id="fwOpenAll">expand all</button><button type="button" class="fw-navx" id="fwCloseAll">collapse all</button></nav>

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
  <div class="tp-th" id="im-feed"><b data-i18n>Live attack feed</b>
    <label class="lm-chkl"><input type="checkbox" id="imAuto" checked> <span data-i18n>Auto-refresh</span></label>
    <input type="text" id="imLiveFilter" class="tp-in" placeholder="Filter IP / domain / type…" style="max-width:220px">
    <label class="lm-chkl" style="gap:5px"><span data-i18n>Group by</span>
      <select id="imGroupBy" class="tp-sel" style="max-width:150px"><option value="" data-i18n>None (each hit)</option><option value="ip" data-i18n>Attacker IP</option><option value="host" data-i18n>Host / domain</option></select></label>
    <button class="tp-btn" id="imAiBtn" type="button">&#129302; <span data-i18n>AI: review &amp; recommend blocks</span></button>
    <span class="meta" id="imLiveMeta" style="margin-left:auto">—</span></div>
  <div id="imAiPanel" class="card" hidden style="padding:14px 16px;margin:0 0 12px;border-left:4px solid var(--brand)"></div>
  <div class="la-scroll"><table class="smpro-table nowrap sortable" id="imLiveTbl">
    <thead><tr><th style="width:26px"><input type="checkbox" id="imSelAll" title="Select all"></th><th data-sort="str" data-i18n>Time</th><th data-sort="str" data-i18n>Attacker IP</th><th data-sort="str" data-i18n>Country / Provider</th><th data-sort="str" data-i18n>Domain targeted</th><th data-sort="str" data-i18n>Account</th><th data-sort="str" data-i18n>Attack type</th><th data-sort="num" data-i18n>Severity</th><th data-sort="num">HTTP</th><th data-sort="str" data-i18n>Request</th><th data-i18n>Action</th></tr></thead>
    <tbody id="imLiveBody"><tr><td colspan="11" class="lm-empty" data-i18n>Loading live feed…</td></tr></tbody></table></div>

<?php elseif ($tab === 'domains'): ?>
  <div class="tp-th" id="im-bydom"><b data-i18n>Attacks by domain</b><input type="text" id="imDomFilter" class="tp-in" placeholder="Filter domain / account…" style="margin-left:auto"></div>
  <div class="fw-pager" data-per="50" data-input="imDomFilter"><span class="fw-pginfo"></span><span class="sp"></span><span class="fw-pgctl"><button type="button" class="fw-pgbtn fw-pgprev">&#8249;</button> <span class="mono fw-pgnum"></span> <button type="button" class="fw-pgbtn fw-pgnext">&#8250;</button></span></div>
  <div class="la-scroll"><table class="smpro-table nowrap sortable" id="imDomTbl">
    <thead><tr><th style="width:26px"><input type="checkbox" id="imSelAllDom" title="Select all"></th><th data-sort="str" data-i18n>Domain</th><th data-sort="str" data-i18n>Account</th><th class="num" data-sort="num" data-i18n>Attempts</th><th class="num" data-sort="num" data-i18n>Uniq IPs</th><th data-i18n>Top attack</th><th data-sort="num" data-i18n>Severity</th><th data-i18n>Top attacker (geo)</th><th data-sort="num" data-i18n>Last seen</th><th></th></tr></thead><tbody>
    <?php if (!$byDom): ?><tr><td colspan="10" class="lm-empty" data-i18n>No attacks detected in this window.</td></tr><?php endif; ?>
    <?php foreach ($byDom as $g): $topip = $g['ips'] ? array_key_first($g['ips']) : ''; $sevc = smpro_im_sev_rank($g['sevlabel'])>=5?'crit':(smpro_im_sev_rank($g['sevlabel'])>=4?'high':'med'); $tin = $topip ? smpro_ip_intel($topip, false) : []; ?>
      <tr data-row data-search="<?= smpro_h(strtolower($g['domain'].' '.$g['account'])) ?>">
        <td><?php if ($topip): ?><input type="checkbox" class="im-chk" value="<?= smpro_h($topip) ?>"><?php endif; ?></td>
        <td><b><?= smpro_h($g['domain']) ?></b></td><td class="uname"><?= smpro_h($g['account']) ?: '<span class="meta">—</span>' ?></td>
        <td class="num"><b><?= number_format($g['total']) ?></b></td><td class="num"><?= number_format($g['uniq_ips']) ?></td>
        <td><span class="k"><?= smpro_h($g['top_cat']) ?></span></td><td data-val="<?= smpro_im_sev_rank($g['sevlabel']) ?>"><span class="b <?= $sevc ?>"><?= smpro_h($g['sevlabel'] ?: '—') ?></span></td>
        <td class="ipmono"><?= smpro_h($topip) ?><?php if ($topip): ?><span class="meta"> <?= smpro_h(strtoupper((string)($tin['country']??''))) ?><?= !empty($tin['provider'])?' · '.smpro_h(mb_substr($tin['provider'],0,18)):'' ?><?= smpro_ip_is_datacenter($tin)?' &#129302;':'' ?></span> <button type="button" class="la-act block" data-ip="<?= smpro_h($topip) ?>">Block</button> <button type="button" class="la-act allow" data-ip="<?= smpro_h($topip) ?>">Allow</button><?php endif; ?></td>
        <td class="meta" data-val="<?= (int)$g['last'] ?>"><?= $g['last'] ? smpro_h(date('Y-m-d H:i', $g['last'])) : '' ?></td>
        <td><a class="lnk" href="index.cgi?page=intrusion-monitor&tab=live&dom=<?= urlencode($g['domain']) ?>" data-i18n>View</a></td>
      </tr>
    <?php endforeach; ?>
    </tbody></table></div>

<?php elseif ($tab === 'attack'): $aa = smpro_im_attack_analysis($events);
  if ($aa['attackers']) smpro_ip_intel_bulk(array_slice(array_map(fn($x)=>$x['ip'],$aa['attackers']),0,80), true); $topIp = $aa['attackers'][0]['ip'] ?? '';
  $csfBlk = function_exists('smpro_im_csf_blocked') ? smpro_im_blocked_set() : [];
  $abuseOn = (($imCfg2['abuseipdb_key'] ?? '') !== '');                                  // only show the Abuse column when a key is configured
  $abuseScores = $abuseOn ? smpro_im_abuse_scores(array_map(fn($x)=>$x['ip'],$aa['attackers'])) : [];
  $abusePill = function($v){ if ($v === null) return '<span class="meta">—</span>'; $v=(int)$v;
    if ($v>=75) return '<span class="b crit" title="AbuseIPDB confidence of abuse">'.$v.'</span>';
    if ($v>=25) return '<span class="b high" title="AbuseIPDB confidence of abuse">'.$v.'</span>';
    return '<span class="b" style="background:var(--good-bg);color:var(--good)" title="AbuseIPDB confidence of abuse">'.$v.'</span>'; }; ?>
  <div class="fw-kpis" style="grid-template-columns:repeat(2,minmax(0,1fr));max-width:480px">
    <a class="fw-kpi <?= $aa['attackers'] ? 'warn' : 'good' ?>" href="#im-attackers" data-go="im-attackers"><div class="l">Attackers</div><div class="v"><?= number_format(count($aa['attackers'])) ?></div><div class="s">top source IPs in this window</div></a>
    <a class="fw-kpi <?= $aa['campaigns'] ? 'dang' : 'good' ?>" href="#im-analysis" data-go="im-analysis"><div class="l">Campaigns</div><div class="v"><?= number_format(count($aa['campaigns'])) ?></div><div class="s">coordinated /24 subnets</div></a>
  </div>
  <div class="tp-th" id="im-analysis"><b data-i18n>Full attack analysis</b><span class="meta"><?= number_format($aa['total']) ?> events · last <?= (int)($mins/60) ?>h</span>
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
        <thead><tr><th data-i18n>Subnet</th><th class="num" data-sort="num" data-i18n>Attacker IPs</th><th class="num" data-sort="num" data-i18n>Requests</th><th data-i18n>Action</th></tr></thead><tbody>
        <?php if(!$aa['campaigns']):?><tr><td colspan="4" class="lm-empty" data-i18n>No coordinated subnet campaigns detected.</td></tr><?php endif;?>
        <?php foreach ($aa['campaigns'] as $s): $snet = preg_replace('#/24$#', '', (string)$s['subnet']); $snBlk = isset($csfBlk[$snet]); ?><tr><td class="ipmono"><?= smpro_h($s['subnet']) ?> <span class="b crit">&#129302; botnet</span></td><td class="num"><b><?= (int)$s['uniq_ips'] ?></b></td><td class="num"><?= number_format($s['n']) ?></td><td class="nowrap"><?php if ($snBlk): ?><span class="la-done">&#10003; Blocked</span><?php else: ?><button type="button" class="la-act block" data-ip="<?= smpro_h($s['subnet']) ?>" title="Block this whole /24 subnet in CSF">Block /24</button><?php endif; ?></td></tr><?php endforeach; ?>
      </tbody></table></div>
    </div>
  </div>
  <div class="tp-th" id="im-attackers" style="margin-top:12px"><b data-i18n>Top source IPs</b><input type="text" id="imAtkFilter" class="tp-in" placeholder="Filter…" style="margin-left:auto;max-width:200px"></div>
  <div class="fw-pager" data-per="50" data-input="imAtkFilter"><span class="fw-pginfo"></span><span class="sp"></span><span class="fw-pgctl"><button type="button" class="fw-pgbtn fw-pgprev">&#8249;</button> <span class="mono fw-pgnum"></span> <button type="button" class="fw-pgbtn fw-pgnext">&#8250;</button></span></div>
  <div class="la-scroll" style="max-height:440px"><table class="smpro-table sortable" id="imAtkTbl">
    <thead><tr><th style="width:26px"><input type="checkbox" id="imSelAllAtk" title="Select all"></th><th>#</th><th data-sort="str" data-i18n>Attacker IP</th><th data-sort="str" data-i18n>Country / Provider</th><?php if($abuseOn): ?><th class="num" data-sort="num" data-i18n>Abuse</th><?php endif; ?><th class="num" data-sort="num" data-i18n>Requests</th><th data-i18n>Main target</th><th class="num" data-sort="num" data-i18n>User-Agents</th><th data-i18n>Action</th></tr></thead><tbody>
    <?php $csfBlk = $csfBlk ?? (function_exists('smpro_im_csf_blocked') ? smpro_im_blocked_set() : []);
      $rank=0; foreach ($aa['attackers'] as $x): $rank++; $in=smpro_ip_intel($x['ip'],false); $isBlk = isset($csfBlk[$x['ip']]); ?>
      <tr data-row data-search="<?= smpro_h(strtolower($x['ip'].' '.($in['country']??'').' '.($in['provider']??'').' '.$x['top_path'])) ?>">
        <td><input type="checkbox" class="im-chk" value="<?= smpro_h($x['ip']) ?>"></td><td><?= $rank ?></td>
        <td class="ipmono"><?= smpro_h($x['ip']) ?><?php if($x['ip']===$topIp):?> <span class="b crit">top</span><?php endif;?></td>
        <td class="meta"><?= smpro_h(strtoupper((string)($in['country']??''))) ?><?= !empty($in['provider'])?' · '.smpro_h(mb_substr($in['provider'],0,18)):'' ?><?= smpro_ip_is_datacenter($in)?' &#129302;':'' ?></td>
        <?php if($abuseOn): $ab = $abuseScores[$x['ip']] ?? null; ?><td class="num" data-val="<?= $ab===null?-1:(int)$ab ?>"><?= $abusePill($ab) ?></td><?php endif; ?>
        <td class="num"><b><?= number_format($x['n']) ?></b></td>
        <td class="ipmono meta" title="<?= smpro_h($x['top_path']) ?>"><?= smpro_h(mb_substr($x['top_path'],0,36)) ?></td>
        <td class="num" data-val="<?= (int)$x['ua_count'] ?>"><?= (int)$x['ua_count'] ?><?php if($x['ua_count']>=4):?> <span class="b crit" title="rotating User-Agents to evade blocks">&#9851; rotating</span><?php endif;?></td>
        <td class="nowrap"><?php if ($isBlk): ?><span class="la-done">&#10003; Blocked</span> <button type="button" class="la-act allow" data-ip="<?= smpro_h($x['ip']) ?>" title="Lift the CSF block + allowlist">Unblock</button><?php else: ?><button type="button" class="la-act block" data-ip="<?= smpro_h($x['ip']) ?>">Block</button> <button type="button" class="la-act allow" data-ip="<?= smpro_h($x['ip']) ?>">Allow</button><?php endif; ?></td>
      </tr>
    <?php endforeach; ?>
  </tbody></table></div>

<?php elseif ($tab === 'breaches'): $breaches = $events ? smpro_im_breaches($events, 1440, 40) : []; ?>
  <div class="tp-th" id="im-compromise"><b data-i18n>Likely compromises</b><span class="meta" style="margin-left:auto">attack served 2xx/3xx + recently-changed PHP in the domain's docroot</span></div>
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
          <?php if (!empty($b['ips'][0])): $csfBlk = $csfBlk ?? (function_exists('smpro_im_csf_blocked') ? smpro_im_blocked_set() : []); if (isset($csfBlk[$b['ips'][0]])): ?><span class="la-done">&#10003; Blocked</span><?php else: ?><button type="button" class="la-act block" data-ip="<?= smpro_h($b['ips'][0]) ?>">Block IP</button><?php endif; endif; ?></span>
        </div>
        <div class="meta" style="margin-top:6px">Attack types: <?= smpro_h(implode(', ', $b['kinds'])) ?> · last <?= $b['last']?smpro_h(date('Y-m-d H:i',$b['last'])):'' ?></div>
        <div style="margin-top:6px;font-size:12px">Recently changed files:<br><span class="mono" style="color:var(--dang)"><?= smpro_h(implode("\n", $b['changed'])) ?></span></div>
      </div>
    <?php endforeach; ?>
    </div>
  <?php endif; ?>

<?php elseif ($tab === 'campaigns'): $camp = $events ? smpro_im_campaigns($events) : ['distributed'=>[],'targeted'=>[]];
  if ($camp['distributed']) smpro_ip_intel_bulk(array_column(array_slice($camp['distributed'],0,100), 'ip'), true); ?>
  <div class="tp-th" id="im-scanners"><b data-i18n>Distributed scanners</b><input type="text" id="imCampFilter" class="tp-in" placeholder="Filter IP / provider…" style="margin-left:auto;max-width:240px"></div>
  <div class="fw-pager" data-per="50" data-input="imCampFilter"><span class="fw-pginfo"></span><span class="sp"></span><span class="fw-pgctl"><button type="button" class="fw-pgbtn fw-pgprev">&#8249;</button> <span class="mono fw-pgnum"></span> <button type="button" class="fw-pgbtn fw-pgnext">&#8250;</button></span></div>
  <div class="la-scroll" style="max-height:320px"><table class="smpro-table sortable" id="imCampTbl">
    <thead><tr><th style="width:26px"><input type="checkbox" id="imSelAllCamp" title="Select all"></th><th data-sort="str" data-i18n>Attacker IP</th><th data-sort="str" data-i18n>Country / Provider</th><th class="num" data-sort="num" data-i18n>Domains hit</th><th class="num" data-sort="num" data-i18n>Total hits</th><th data-i18n>Action</th></tr></thead><tbody>
    <?php if (!$camp['distributed']): ?><tr><td colspan="6" class="lm-empty" data-i18n>No distributed scanning detected.</td></tr><?php endif; ?>
    <?php foreach (array_slice($camp['distributed'],0,100) as $d): $cin = smpro_ip_intel($d['ip'], false); ?>
      <tr data-row data-search="<?= smpro_h(strtolower($d['ip'].' '.($cin['country']??'').' '.($cin['provider']??''))) ?>"><td><input type="checkbox" class="im-chk" value="<?= smpro_h($d['ip']) ?>"></td>
      <td class="ipmono"><?= smpro_h($d['ip']) ?></td>
      <td class="meta"><?= smpro_h(strtoupper((string)($cin['country']??''))) ?><?= !empty($cin['provider'])?' · '.smpro_h(mb_substr($cin['provider'],0,22)):'' ?><?= smpro_ip_is_datacenter($cin)?' <span class="b crit">&#129302; bot</span>':'' ?></td>
      <td class="num"><b><?= (int)$d['domains'] ?></b></td><td class="num"><?= (int)$d['hits'] ?></td>
      <td><button type="button" class="la-act block" data-ip="<?= smpro_h($d['ip']) ?>">Block</button> <button type="button" class="la-act allow" data-ip="<?= smpro_h($d['ip']) ?>">Allow</button></td></tr>
    <?php endforeach; ?>
    </tbody></table></div>
  <div class="tp-th" id="im-domains" style="margin-top:14px"><b data-i18n>Most-targeted domains</b><span class="meta" style="margin-left:auto">many distinct IPs attacking one domain</span></div>
  <div class="la-scroll" style="max-height:260px"><table class="smpro-table">
    <thead><tr><th data-i18n>Domain</th><th class="num" data-i18n>Distinct attacker IPs</th></tr></thead><tbody>
    <?php if (!$camp['targeted']): ?><tr><td colspan="2" class="lm-empty" data-i18n>No coordinated targeting detected.</td></tr><?php endif; ?>
    <?php foreach (array_slice($camp['targeted'],0,100) as $t): ?><tr><td><b><?= smpro_h($t['domain']) ?></b></td><td class="num"><?= (int)$t['ips'] ?></td></tr><?php endforeach; ?>
    </tbody></table></div>

<?php elseif ($tab === 'reports'): $idx = smpro_im_reports_index(); ?>
  <div class="tp-th" id="im-saved"><b data-i18n>Saved reports</b>
    <span style="margin-left:auto;display:flex;gap:8px;align-items:center">
      <select id="imRepWin" class="tp-sel"><option value="360">last 6h</option><option value="1440" selected>last 24h</option><option value="4320">last 3d</option><option value="10080">last 7d</option></select>
      <button type="button" class="tp-btn primary" id="imGenBtn" data-i18n>Generate report</button></span></div>
  <div class="la-scroll"><table class="smpro-table" id="imRepTbl">
    <thead><tr><th data-i18n>Created</th><th data-i18n>Window</th><th class="num" data-i18n>Attempts</th><th class="num" data-i18n>Domains</th><th data-i18n>Actions</th></tr></thead><tbody>
    <?php if (!$idx): ?><tr id="imRepEmpty"><td colspan="5" class="lm-empty" data-i18n>No saved reports yet — generate one above.</td></tr><?php endif; ?>
    <?php foreach ($idx as $r): ?>
      <tr data-rid="<?= smpro_h($r['id']) ?>"><td><?= smpro_h($r['created'] ?? '') ?></td><td><?= (int)(($r['window_mins'] ?? 0)/60) ?>h</td>
        <td class="num"><?= number_format($r['total'] ?? 0) ?></td><td class="num"><?= number_format($r['domains'] ?? 0) ?></td>
        <td class="nowrap"><a class="lnk" href="index.cgi?page=intrusion-monitor&im_export=html&report=<?= smpro_h($r['id']) ?>" target="_blank" data-i18n>View</a>
          <a class="lnk" href="index.cgi?page=intrusion-monitor&im_export=csv&report=<?= smpro_h($r['id']) ?>" data-i18n>CSV</a>
          <button type="button" class="la-act block imDel" data-rid="<?= smpro_h($r['id']) ?>" data-i18n>Delete</button></td></tr>
    <?php endforeach; ?>
    </tbody></table></div>

<?php elseif ($tab === 'emergency'): $c = smpro_in_cfg(); $emlog = function_exists('smpro_im_em_manifest_load') ? array_reverse(smpro_im_em_manifest_load()) : []; ?>
  <div class="card" style="padding:18px 20px;max-width:840px;border-left:4px solid var(--dang)">
    <h3 id="im-emergency" style="margin:0 0 6px;color:var(--dang)">&#128680; <span data-i18n>Emergency auto-response</span> <?= !empty($c['emergency'])?'<span class="b crit">ACTIVE</span>':'<span class="b" style="background:var(--card);color:#475569">off</span>' ?></h3>
    <details class="gl-fold"><summary><span class="fw-chev gl-chev">&#9656;</span>How this works</summary>
    <p class="meta" data-i18n>When ON: the moment a site is hit by an exploit-class attack AND its files have just changed, the plugin automatically (1) quarantines any uploaded web-shells, (2) hardens the site — disables PHP execution in upload/cache folders and locks core files (wp-config, .htaccess, index…), and (3) alerts the admin. Every action is backed up and reversible from the log below.</p>
    </details>
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
  <div class="tp-th" id="im-emlog" style="margin-top:16px"><b data-i18n>Emergency action log</b><span class="meta" style="margin-left:auto" data-i18n>Restore = un-lock files + put quarantined files back</span></div>
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
        <td><button type="button" class="la-act emUndo" data-eid="<?= smpro_h($e['id']??'') ?>" data-i18n>Restore</button></td>
      </tr>
    <?php endforeach; ?>
    </tbody></table></div>

<?php else: /* settings */ $c = smpro_in_cfg(); ?>
  <div class="card" style="padding:18px 20px;max-width:760px">
    <div class="im-frm">
    <h3 id="im-blocking" style="margin:0 0 12px" data-i18n>Blocking &amp; response</h3>
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
      <h3 id="im-auto" style="margin:0 0 12px" data-i18n>Auto-response</h3>
      <label class="lm-chkl"><input type="checkbox" id="cfgAuto" <?= !empty($c['auto_block'])?'checked':'' ?>> <span data-i18n>Auto-block the worst attacker IPs (from the alert cron)</span></label>
      <label class="lm-chkl"><input type="checkbox" id="cfgAi" <?= !empty($c['ai_block'])?'checked':'' ?>> <span data-i18n>Use AI to decide which IPs to block (analyses attacks + applies SOC conditions; needs an AI provider)</span> <?= (function_exists('smpro_ai_available') && smpro_ai_available()) ? '<span class="b" style="background:var(--good-bg);color:var(--good)">AI ready</span>' : '<span class="b crit">no AI provider</span>' ?></label>
      <label class="sw"><input type="checkbox" id="cfgDry" <?= !empty($c['auto_block_dryrun'])?'checked':'' ?>><span class="track"></span><span class="lbl" data-i18n>Dry-run mode (log/alert only, do not actually block)</span><span class="st"></span></label>
      <div class="im-row"><label data-i18n>Auto-block an attacking IP after this many attacks</label><input type="number" id="cfgAutoMin" class="tp-in" value="<?= (int)($c['auto_block_threshold'] ?? 30) ?>" min="5"></div>
      <div class="im-row"><label data-i18n>Also block a whole network that is scanning from several addresses at once</label>
        <input type="checkbox" id="cfgLgNet" <?= !empty($c['login_guard_net']) ? 'checked' : '' ?>></div>
      <div class="im-row"><label data-i18n>&nbsp;&nbsp;&#8627; when it uses at least this many addresses</label>
        <input type="number" id="cfgLgNetIps" class="tp-in" value="<?= (int)($c['login_guard_net_ips'] ?? 2) ?>" min="2"></div>
      <div class="im-row"><label data-i18n>&nbsp;&nbsp;&#8627; AND they total at least this many failed logins</label>
        <input type="number" id="cfgLgNetFails" class="tp-in" value="<?= (int)($c['login_guard_net_fails'] ?? 10) ?>" min="2"></div>
      <label class="lm-chkl"><input type="checkbox" id="cfgProtArab" <?= !empty($c['protect_arab'] ?? true)?'checked':'' ?>> <span data-i18n>Region-aware auto-blocking — treat residential IPs from the regions you set below more carefully. Datacenter/hosting IPs are always blocked at the threshold regardless of country.</span></label>
      <div class="im-row" style="align-items:flex-start"><label data-i18n>Home regions — residential IPs here are <b>never</b> auto-blocked (routed to manual review). ISO 3166-1 alpha-2 codes, comma-separated.</label>
        <input type="text" id="cfgHomeRegions" class="tp-in" placeholder="e.g. EG, SA" value="<?= smpro_h(implode(', ', array_map('strtoupper', array_filter((array)($c['protect_regions'] ?? []))))) ?>" style="max-width:360px" autocomplete="off" spellcheck="false">
        <span class="meta" data-i18n>Set these to your own customers' country/countries. Empty = no country is auto-protected.</span></div>
      <div class="im-row" style="align-items:flex-start"><label>Caution regions — residential IPs here need 3× the attack count before auto-block. Empty disables this tier. <a href="#" id="cautionArabPreset" style="white-space:nowrap">Use Arab countries</a></label>
        <input type="text" id="cfgCaution" class="tp-in" placeholder="e.g. AE, KW, QA" value="<?= smpro_h(implode(', ', array_map('strtoupper', array_filter((array)($c['caution_regions'] ?? []))))) ?>" style="max-width:360px" autocomplete="off" spellcheck="false"></div>
      <div class="im-row"><label data-i18n>Allowlist (never block — IPs/CIDRs, one per line)</label><textarea id="cfgAllow" class="tp-in" rows="3"><?= smpro_h(implode("\n", (array)$c['allowlist'])) ?></textarea></div>
      <hr style="border:0;border-top:1px solid var(--line);margin:14px 0">
      <h3 id="im-breach" style="margin:0 0 4px" data-i18n>Breach scan — exceptions</h3>
      <p class="meta" style="margin:0 0 10px" data-i18n>Security plugins keep the same dangerous function names (eval, shell_exec, base64_decode) inside their own scanners, so a plain pattern match reads them as web-shells. Anything matched here is skipped by the breach scan.</p>

      <div class="im-row" style="align-items:flex-start">
        <label data-i18n>Built in (always on)</label>
        <div>
          <div class="im-exwrap"><?php foreach (smpro_im_breach_exclude_seed() as $sEx): ?><span class="im-ex"><?= smpro_h($sEx) ?></span><?php endforeach; ?></div>
          <span class="meta" data-i18n>Widely distributed security plugins and cache directories only. Shown here so nothing is excluded invisibly. Our own WP Guard is deliberately not on this list — it is trusted by verified file header instead, which a folder name cannot fake.</span>
        </div>
      </div>

      <div class="im-row" style="align-items:flex-start">
        <label data-i18n>Your exceptions (this server only)</label>
        <div>
          <textarea id="cfgBreach" class="tp-in" rows="4" placeholder="/wp-content/plugins/my-security-plugin/&#10;/wp-content/mu-plugins/site-guard.php&#10;/wp-content/plugins/in-house-scanner/"><?= smpro_h(implode("\n", (array)($c['breach_exclude'] ?? []))) ?></textarea>
          <span class="meta" data-i18n>One plugin path or name per line — matched as a substring of the full file path. Put site-specific plugins here (a custom mu-plugin, an in-house security plugin) rather than anywhere else: entries added here apply to THIS server only. Keep them as specific as you can — a bare short word excludes every path that happens to contain it.</span>
        </div>
      </div>
      <hr style="border:0;border-top:1px solid var(--line);margin:14px 0">
      <h3 id="im-alerts" style="margin:0 0 12px" data-i18n>Alert thresholds (push notifications)</h3>
      <div class="im-row"><label data-i18n>Alert window (minutes)</label><input type="number" id="cfgWin" class="tp-in" value="<?= (int)$c['alert_window_min'] ?>" min="2" max="180"></div>
      <div class="im-row"><label data-i18n>Domain attack spike (attempts/window)</label><input type="number" id="cfgThrDom" class="tp-in" value="<?= (int)$c['thr_domain_attacks'] ?>" min="5"></div>
      <div class="im-row"><label data-i18n>Distributed scan (IP → distinct domains)</label><input type="number" id="cfgThrIp" class="tp-in" value="<?= (int)$c['thr_ip_domains'] ?>" min="2"></div>
      <p class="meta" data-i18n>Alerts use the channels configured in Settings → Notifications (Telegram / WhatsApp / Email). The notify cron runs the alert scan.</p>
      <div style="margin-top:14px"><button type="button" class="tp-btn primary" id="imSaveBtn" data-i18n>Save settings</button> <span id="imSaveMsg" class="meta"></span></div>
    </div>
  </div>
<?php endif; ?>

<style>
.im-hero{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:14px 0 6px}@media(max-width:760px){.im-hero{grid-template-columns:repeat(2,1fr)}}
.im-c{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px 16px;display:flex;flex-direction:column;gap:2px}
.im-c .lbl{font-size:11px;color:var(--muted);text-transform:uppercase;font-weight:700}.im-c .v{font-size:24px;font-weight:800;line-height:1.1}
.la-tabs{display:flex;gap:4px;border-bottom:2px solid var(--line);margin:16px 0 14px;flex-wrap:wrap}
.la-tab{padding:9px 15px;font-size:14px;font-weight:600;color:var(--muted);text-decoration:none;border-bottom:3px solid transparent;margin-bottom:-2px;border-radius:8px 8px 0 0}
.la-tab:hover{color:var(--ink);background:var(--brand-bg)}.la-tab.active{color:var(--brand);border-bottom-color:var(--brand)}
/* vertical column dividers (grid) for the attack tables */
#imLiveTbl th,#imLiveTbl td,#imDomTbl th,#imDomTbl td,#imAtkTbl th,#imAtkTbl td,#imCampTbl th,#imCampTbl td{border-right:1px solid #e2e8f0}
#imLiveTbl th:last-child,#imLiveTbl td:last-child,#imDomTbl th:last-child,#imDomTbl td:last-child,#imAtkTbl th:last-child,#imAtkTbl td:last-child,#imCampTbl th:last-child,#imCampTbl td:last-child{border-right:0}
.la-scroll{max-height:560px;overflow:auto}.la-scroll table{margin:0}.la-scroll thead th{position:sticky;top:0;background:var(--card);z-index:1;box-shadow:inset 0 -1px 0 var(--line)}
.smpro-table{width:100%;border-collapse:collapse;font-size:13px}.smpro-table th,.smpro-table td{padding:8px 12px;text-align:left;border-bottom:1px solid var(--line)}
.smpro-table.nowrap th,.smpro-table.nowrap td{white-space:nowrap}.smpro-table th{font-size:11px;text-transform:uppercase;color:var(--muted)}.smpro-table th.num,.smpro-table td.num{text-align:right}
.tp-th{display:flex;align-items:center;gap:10px;padding:10px 2px;flex-wrap:wrap}.tp-in,.tp-sel{border:1px solid var(--line);border-radius:9px;padding:7px 11px;font-size:13px;background:var(--card)}
.tp-btn{border:1px solid var(--line);background:var(--card);color:var(--ink);border-radius:9px;padding:8px 12px;font-size:13px;cursor:pointer;font-weight:600}.tp-btn.primary{background:var(--brand);color:#fff;border-color:var(--brand)}
.la-act{font-size:11px;font-weight:600;border:1px solid var(--line);background:var(--card);border-radius:7px;padding:3px 9px;cursor:pointer}.la-act.block{color:var(--dang);border-color:#f3c4c4}.la-act.block:hover{background:var(--dang);color:#fff}
.la-act.allow{color:var(--good);border-color:#bfe6cd}.la-act.allow:hover{background:var(--good);color:#fff}
table.sortable th[data-sort]{cursor:pointer;user-select:none}table.sortable th[data-sort]:hover{color:var(--brand)}table.sortable th.sorted-asc::after{content:" \25B2";font-size:8px}table.sortable th.sorted-desc::after{content:" \25BC";font-size:8px}
.lnk{color:var(--brand);text-decoration:none;font-size:12px;border:1px solid var(--line);padding:3px 9px;border-radius:7px}.lnk:hover{background:var(--brand-bg)}
.ipmono,.uname{font-family:ui-monospace,Consolas,monospace}.mono{font-family:ui-monospace,Consolas,monospace;white-space:pre-wrap;word-break:break-all}
.lm-chkl{display:flex;align-items:center;gap:6px;font-size:13px;margin:6px 0}.lm-empty{padding:18px;color:var(--muted);text-align:center}
.k{display:inline-block;font-size:11px;background:var(--brand-bg);color:var(--brand);border-radius:10px;padding:1px 8px}
.b{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:20px}.b.crit{background:var(--dang-bg);color:#b91c1c}.b.high{background:var(--warn-bg);color:#c2410c}.b.med{background:var(--warn-bg);color:#a16207}
.meta{color:var(--muted)}.svc-kicker{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--brand);font-weight:700}
.la-tabs2{display:grid;grid-template-columns:1fr 1fr;gap:12px}@media(max-width:820px){.la-tabs2{grid-template-columns:1fr}}
.im-phases{display:flex;flex-direction:column;gap:8px;margin-top:10px}
.im-ph{display:flex;align-items:center;gap:10px;font-size:12.5px}.im-phl{width:210px;flex:none;color:var(--muted)}.im-phb{flex:1;height:9px;background:var(--card);border-radius:8px;overflow:hidden}.im-phb>i{display:block;height:100%;background:var(--dang);border-radius:8px}.im-ph b{width:64px;text-align:right}
.im-frm .im-row{display:flex;flex-direction:column;gap:4px;margin:10px 0}.im-frm label{font-size:13px;font-weight:600}.im-frm .tp-in{max-width:480px}
.im-exwrap{display:flex;flex-wrap:wrap;gap:5px;max-width:480px;margin:2px 0 5px}
.im-ex{display:inline-block;padding:2px 8px;border:1px solid var(--line);border-radius:11px;background:var(--card2,transparent);color:var(--muted);font:600 11px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace;white-space:nowrap}
.sw{display:flex;align-items:center;gap:10px;cursor:pointer;margin:8px 0;font-size:13px;font-weight:600}
.sw input{display:none}
.sw .track{flex:none;width:44px;height:24px;border-radius:20px;background:#cbd5e1;position:relative;transition:background .15s}
.sw .track::after{content:"";position:absolute;top:2px;left:2px;width:20px;height:20px;border-radius:50%;background:var(--card);box-shadow:0 1px 3px rgba(0,0,0,.25);transition:transform .15s}
.sw input:checked+.track{background:var(--brand)}
.sw input:checked+.track::after{transform:translateX(20px)}
.sw .lbl{flex:1}
.sw .st{flex:none;font-weight:800;font-size:11px;letter-spacing:.04em;padding:2px 9px;border-radius:20px;background:var(--card);color:#64748b}
.sw .st::after{content:"OFF"}
.sw input:checked~.st{background:var(--brand-bg);color:var(--brand)}
.sw input:checked~.st::after{content:"ON"}

/* ===== overview strip / navigator / collapsible sections (same rules as firewall-status.php) ===== */
/* page additions: header-level open state (works for cards AND for header+siblings sections), prose folds, table pager */
.fw-toggle.fw-open .fw-chev{transform:rotate(90deg)}
.fw-collapse.fw-show{display:block}
.gl-fold{margin:6px 0}.gl-fold>summary{cursor:pointer;font-size:13px;font-weight:700;list-style:none;display:flex;align-items:center;gap:8px;color:var(--brand)}
.fw-pager{display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:6px 2px 8px;font-size:12px;color:var(--muted)}
.fw-pager .fw-pgq{border:1px solid var(--line);border-radius:9px;padding:5px 10px;font-size:12.5px;background:var(--card);color:var(--ink);min-width:180px}
.fw-pager .sp{flex:1}.fw-pgctl{display:inline-flex;align-items:center;gap:6px}
.fw-pgbtn{border:1px solid var(--line);background:var(--card);color:var(--ink);border-radius:7px;padding:2px 9px;font-size:13px;cursor:pointer;line-height:1.4}.fw-pgbtn[disabled]{opacity:.4;cursor:not-allowed}
.im-frm>h3.fw-toggle,.card>h3.fw-toggle{margin-top:0}
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
// Pull a fresh im_action CSRF token (root session) and update IM_CSRF — used to auto-recover an expired token.
function imRefreshToken(){var fd=new URLSearchParams();fd.set('im_action','token');
  return fetch('index.cgi?page=intrusion-monitor',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'})
    .then(function(r){return r.json();}).then(function(j){if(j&&j.ok&&j.token){IM_CSRF=j.token;return true;}return false;}).catch(function(){return false;});}
function imAct(action,ips,btn){
  if(!ips.length)return; var verb=action==='block'?'Block':'Allow';
  smConfirm({icon:'ask',danger:action==='block',title:verb+' '+ips.length+' IP'+(ips.length>1?'s':'')+'?',
    confirmText:verb,
    message:(action==='block'?'They will be blocked in CSF (+ Cloudflare if enabled).':'They will be allowed in CSF and never auto-blocked.')+'\n\n'+ips.join('\n'),
    onConfirm:function(){
      if(btn)btn.disabled=true;
      // send once; if the page's session token expired, silently refresh it and retry once
      function send(isRetry){
        var fd=new URLSearchParams();fd.set('im_action',action);fd.set('ips',ips.join(','));fd.set('smpro_csrf',IM_CSRF);
        return fetch('index.cgi?page=intrusion-monitor',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'})
          .then(function(r){return r.json();}).then(function(j){
            if(j&&j.csrf&&!isRetry){ return imRefreshToken().then(function(ok){ return ok?send(true):j; }); }
            return j;
          });
      }
      send(false).then(function(j){
          if(!j||(!j.ok&&!(j.results&&j.results.length))){if(btn)btn.disabled=false;smDone({icon:'err',title:verb+' failed',message:(j&&(j.error||j.message||j.msg))||'Token/license error.'});return;}
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

(function(){var body=document.getElementById('imLiveBody');if(!body)return;
  var auto=document.getElementById('imAuto'),meta=document.getElementById('imLiveMeta'),grp=document.getElementById('imGroupBy');
  var domFilter=new URLSearchParams(location.search).get('dom')||'';
  window.imSel=window.imSel||{};   // persistent selection set (IP => 1) — survives auto-refresh + group switches
  var lastRows=[];
  function esc(s){return (s==null?'':String(s)).replace(/[&<>"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
  function sev(s){s=(s||'').toLowerCase();return s.indexOf('crit')>=0?'crit':(s.indexOf('err')>=0?'high':'med');}
  function sevVal(s){return {crit:3,high:2,med:1}[sev(s)]||0;}
  function flat(x){return '<tr data-search="'+esc(((x.ip||'')+' '+(x.domain||'')+' '+(x.account||'')+' '+(x.kind||'')).toLowerCase())+'">'+
    '<td>'+(x.ip?'<input type="checkbox" class="im-chk" value="'+esc(x.ip)+'">':'')+'</td>'+
    '<td class="meta">'+esc(x.time)+'</td><td class="ipmono">'+esc(x.ip)+'</td>'+
    '<td class="meta">'+esc(x.cc||'')+(x.provider?' · '+esc((x.provider||'').slice(0,18)):'')+(x.bot?' <span class="b crit" title="datacenter / bot network">&#129302;</span>':'')+'</td>'+
    '<td><b>'+esc(x.domain)+'</b></td><td class="uname">'+esc(x.account||'')+'</td>'+
    '<td><span class="k">'+esc(x.kind)+'</span></td>'+
    '<td data-val="'+sevVal(x.severity)+'"><span class="b '+sev(x.severity)+'">'+esc(x.severity||'—')+'</span></td>'+
    '<td>'+esc(x.code||'')+'</td>'+
    '<td class="meta" title="'+esc(x.uri)+'">'+esc((x.method||'')+' '+(x.uri||'')).slice(0,60)+'</td>'+
    '<td class="nowrap">'+(x.ip?'<button type="button" class="la-act block" data-ip="'+esc(x.ip)+'">Block</button> <button type="button" class="la-act allow" data-ip="'+esc(x.ip)+'">Allow</button>':'')+'</td></tr>';}
  function grouped(rows,by){
    var g={};rows.forEach(function(x){var k=(by==='host'?(x.domain||'(none)'):(x.ip||'(none)'));if(!g[k])g[k]={key:k,n:0,ips:{},doms:{},accts:{},last:'',cc:'',prov:'',bot:false,kind:{},sev:0};
      var G=g[k];G.n++;if(x.ip)G.ips[x.ip]=1;if(x.domain)G.doms[x.domain]=1;if(x.account)G.accts[x.account]=1;if((x.time||'')>G.last)G.last=x.time;if(!G.cc&&x.cc)G.cc=x.cc;if(!G.prov&&x.provider)G.prov=x.provider;if(x.bot)G.bot=true;G.kind[x.kind]=(G.kind[x.kind]||0)+1;var v=sevVal(x.severity);if(v>G.sev)G.sev=v;});
    var arr=Object.keys(g).map(function(k){return g[k];});arr.sort(function(a,b){return b.n-a.n;});var lbl=['—','med','high','crit'];
    return arr.map(function(G){var tk=Object.keys(G.kind).sort(function(a,b){return G.kind[b]-G.kind[a];})[0]||'';var svl=lbl[G.sev];var blk=(by==='ip'&&G.key&&G.key!=='(none)');
      var ipCell=(by==='ip')?('<td class="ipmono">'+esc(G.key)+'</td>'):('<td class="meta">'+Object.keys(G.ips).length+' IP(s)</td>');
      var domCell=(by==='host')?('<td><b>'+esc(G.key)+'</b></td>'):('<td class="meta">'+Object.keys(G.doms).length+' domain(s)</td>');
      return '<tr data-search="'+esc(G.key.toLowerCase())+'">'+
        '<td>'+(blk?'<input type="checkbox" class="im-chk" value="'+esc(G.key)+'">':'')+'</td>'+
        '<td class="meta">'+esc(G.last)+'</td>'+ipCell+
        '<td class="meta">'+esc(G.cc||'')+(G.prov?' · '+esc(G.prov.slice(0,18)):'')+(G.bot?' <span class="b crit">&#129302;</span>':'')+'</td>'+
        domCell+'<td class="uname">'+esc(Object.keys(G.accts)[0]||'')+'</td>'+
        '<td><span class="k">'+esc(tk)+'</span></td>'+
        '<td data-val="'+G.sev+'"><span class="b '+svl+'">'+esc(svl)+'</span></td>'+
        '<td></td><td class="meta"><b>'+G.n+'</b> hit(s)</td>'+
        '<td class="nowrap">'+(blk?'<button type="button" class="la-act block" data-ip="'+esc(G.key)+'">Block</button> <button type="button" class="la-act allow" data-ip="'+esc(G.key)+'">Allow</button>':'')+'</td></tr>';});
  }
  function render(){
    if(!lastRows.length){body.innerHTML='<tr><td colspan="11" class="lm-empty">No attacks in the last 2 hours'+(domFilter?' for '+esc(domFilter):'')+'.</td></tr>';if(window.imSyncBulk)window.imSyncBulk();return;}
    var by=grp?grp.value:'';
    body.innerHTML=(by?grouped(lastRows,by):lastRows.map(flat)).join('');
    body.querySelectorAll('.im-chk').forEach(function(c){if(window.imSel[c.value])c.checked=true;});   // restore selections after re-render
    if(window.imSyncBulk)window.imSyncBulk();if(window.imLiveApplyFilter)window.imLiveApplyFilter();
    if(window.imReapplySort)window.imReapplySort(document.getElementById('imLiveTbl'));
  }
  function load(){fetch('index.cgi?page=intrusion-monitor&im_live=1&mins=120',{cache:'no-store'}).then(function(r){return r.json();}).then(function(j){
    if(!j||!j.ok)return;var rows=j.rows||[];if(domFilter)rows=rows.filter(function(x){return (x.domain||'').indexOf(domFilter)>=0;});
    lastRows=rows;render();
    if(meta)meta.textContent=j.count+' attack(s) · updated '+j.now+(domFilter?' · '+domFilter:'');}).catch(function(){});}
  if(grp)grp.addEventListener('change',render);
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

(function(){var a=document.getElementById('cautionArabPreset');if(a)a.addEventListener('click',function(e){e.preventDefault();
  var f=document.getElementById('cfgCaution');if(f)f.value='AE, KW, QA, BH, OM, JO, LB, SY, IQ, YE, PS, DZ, MA, TN, LY, SD, MR, SO, DJ, KM';});})();
(function(){var s=document.getElementById('imSaveBtn');if(!s)return;s.addEventListener('click',function(){
  var fd=new URLSearchParams();fd.set('im_action','save_settings');fd.set('smpro_csrf',IM_CSRF);
  fd.set('cf_account',document.getElementById('cfgCfAcct').value);fd.set('cf_token',document.getElementById('cfgCfTok').value);
  fd.set('abuseipdb_key',document.getElementById('cfgAbuse').value);
  if(document.getElementById('cfgUseCsf').checked)fd.set('use_csf','1');if(document.getElementById('cfgUseCf').checked)fd.set('use_cloudflare','1');
  if(document.getElementById('cfgAuto').checked)fd.set('auto_block','1');if(document.getElementById('cfgDry').checked)fd.set('auto_block_dryrun','1');
  if(document.getElementById('cfgAi')&&document.getElementById('cfgAi').checked)fd.set('ai_block','1');
  if(document.getElementById('cfgAutoMin'))fd.set('auto_block_threshold',document.getElementById('cfgAutoMin').value);
  if(document.getElementById('cfgLgNet')&&document.getElementById('cfgLgNet').checked)fd.set('login_guard_net','1');
  if(document.getElementById('cfgLgNetIps'))fd.set('login_guard_net_ips',document.getElementById('cfgLgNetIps').value);
  if(document.getElementById('cfgLgNetFails'))fd.set('login_guard_net_fails',document.getElementById('cfgLgNetFails').value);
  if(document.getElementById('cfgProtArab')&&document.getElementById('cfgProtArab').checked)fd.set('protect_arab','1');
  if(document.getElementById('cfgHomeRegions'))fd.set('protect_regions',document.getElementById('cfgHomeRegions').value);
  if(document.getElementById('cfgCaution'))fd.set('caution_regions',document.getElementById('cfgCaution').value);
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
.im-rb.prot{background:var(--warn-bg);color:#b45309}
/* AI "recommended action" mark on the row's action button */
.la-act.im-rec{box-shadow:0 0 0 2px var(--brand);font-weight:800;position:relative}
.im-recstar{color:#f5b301;font-size:11px;vertical-align:middle}
.im-rec-hint{font-size:10.5px;font-weight:700;color:#b45309;background:var(--warn-bg);padding:2px 7px;border-radius:20px;white-space:nowrap}
</style>
<script>
/* multi-select bulk block (works across live / domains / campaigns tables) */
(function(){
  var n=document.getElementById('imBulkN'),bar=document.getElementById('imBulk');
  window.imSel=window.imSel||{};
  function vis(c){var tr=c.closest('tr');return tr&&tr.offsetParent!==null;}   // visible = passes the filter (not display:none)
  // selection + bulk action target ONLY the visible (filtered) rows, never hidden ones
  function selected(){return Array.prototype.slice.call(document.querySelectorAll('.im-chk:checked')).filter(vis).map(function(c){return c.value;}).filter(function(v,i,a){return v&&a.indexOf(v)===i;});}
  window.imSyncBulk=function(){var s=selected();if(n)n.textContent=s.length;if(bar)bar.classList.toggle('show',s.length>0);};
  document.addEventListener('change',function(e){
    var t=e.target;
    if(t.id&&t.id.indexOf('imSelAll')===0){var tbl=t.closest('table');if(tbl)tbl.querySelectorAll('.im-chk').forEach(function(c){if(!vis(c))return;c.checked=t.checked;if(c.checked)window.imSel[c.value]=1;else delete window.imSel[c.value];});}
    else if(t.classList&&t.classList.contains('im-chk')){if(t.checked)window.imSel[t.value]=1;else delete window.imSel[t.value];}
    if((t.classList&&t.classList.contains('im-chk'))||(t.id&&t.id.indexOf('imSelAll')===0))window.imSyncBulk();
  });
  var bb=document.getElementById('imBulkBlock');if(bb)bb.addEventListener('click',function(){var s=selected();if(s.length&&window.imBlock)imBlock(s);});
  var ba=document.getElementById('imBulkAllow');if(ba)ba.addEventListener('click',function(){var s=selected();if(s.length&&window.imAllow)imAllow(s);});
  var bc=document.getElementById('imBulkClear');if(bc)bc.addEventListener('click',function(){window.imSel={};document.querySelectorAll('.im-chk').forEach(function(c){c.checked=false;});['imSelAll','imSelAllDom','imSelAllCamp','imSelAllAtk'].forEach(function(id){var x=document.getElementById(id);if(x)x.checked=false;});window.imSyncBulk();});
})();
/* AI: review current attackers and recommend blocks */
(function(){var b=document.getElementById('imAiBtn'),p=document.getElementById('imAiPanel');if(!b||!p)return;
  function esc(s){return (s==null?'':String(s)).replace(/[&<>"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
  b.addEventListener('click',function(){var ot=b.innerHTML;b.disabled=true;b.innerHTML='&#129302; Analysing…';p.hidden=false;p.innerHTML='<div class="meta">&#129302; The AI is reviewing current attackers…</div>';
    var fd=new URLSearchParams();fd.set('im_action','ai_review');fd.set('mins','240');fd.set('smpro_csrf',IM_CSRF);
    fetch('index.cgi?page=intrusion-monitor',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'}).then(function(r){return r.json();}).then(function(j){
      b.disabled=false;b.innerHTML=ot;
      if(!j||!j.ok){p.innerHTML='<b style="color:var(--dang)">AI review unavailable.</b> <span class="meta">'+esc((j&&j.reason)||'Configure an AI provider in Settings → AI Providers.')+'</span>';return;}
      var rows=j.rows||[];
      var _blkSet={};rows.forEach(function(r){if(r.blocked)_blkSet[r.ip]=1;});
      var blk=(j.block||[]).filter(function(ip){return !_blkSet[ip];});   // don't re-offer to block IPs already in csf.deny
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
      if(blk.length)html+='<button type="button" class="im-bbtn block" id="imAiApply" style="margin-left:auto">Block all '+blk.length+' recommended</button>';
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
              +(r.blocked
                 ? '<span class="la-done">&#10003; Blocked</span> <button type="button" class="la-act allow" data-ip="'+ipe+'" title="Lift the CSF block + allowlist">Unblock</button>'
                 : '<button type="button" class="la-act block'+(r.decision==='block'?' im-rec':'')+'" data-ip="'+ipe+'" title="'+(r.decision==='block'?'AI recommends blocking this IP':'Block this IP in the firewall')+'">&#128683; Block'+(r.decision==='block'?' <span class="im-recstar">&#9733;</span>':'')+'</button> '
                   +'<button type="button" class="la-act allow'+(r.decision==='keep'?' im-rec':'')+'" data-ip="'+ipe+'" title="'+(r.decision==='keep'?'AI recommends keeping/allowing this IP':'Whitelist this IP')+'">&#9989; Allow'+(r.decision==='keep'?' <span class="im-recstar">&#9733;</span>':'')+'</button>'
                   +(r.decision==='review'?' <span class="im-rec-hint" title="The AI leaves this to your judgement">&#128737; your call</span>':''))
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
<script>
(function(){
  // make every section collapsible - click its title (or chevron) to open/close; remembered per section
  var KEY='smpro:intrusion-monitor:open', HDR='.smpro-main .tp-th, .smpro-main .card > h3, .smpro-main .im-frm > h3';
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

<?php
smpro_layout_footer();
