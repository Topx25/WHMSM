<?php
/**
 * includes/fwallow.php — Recommended firewall allow-lists (trusted provider IP ranges → csf.allow).
 * Optional + reversible + tagged. Supports a LIVE fetch of the current ranges (Cloudflare / UptimeRobot / Google /
 * Bing) and an opt-in BACKGROUND auto-update (cron) that keeps csf.allow in sync with the provider feed — so the
 * admin enables it once and never has to come back. Shared by modules/firewall-status.php + bin/fw_allow_sync.php.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

if (!defined('SMPRO_FWA_CFG'))   define('SMPRO_FWA_CFG',   SMPRO_VARLIB . '/fw_recs.json');    // {ignored:[], autoupdate:[]}
if (!defined('SMPRO_FWA_CACHE')) define('SMPRO_FWA_CACHE', SMPRO_VARLIB . '/fw_ranges');       // per-provider fetched-range cache
if (!defined('SMPRO_FWA_ALLOW')) define('SMPRO_FWA_ALLOW', '/etc/csf/csf.allow');
if (!defined('SMPRO_FW_LIVE'))   define('SMPRO_FW_LIVE',   SMPRO_VARLIB . '/fw_live_allow.json');   // IPs SM Pro allowed directly in live iptables

/* ============================ LIVE firewall allow (works WITH or WITHOUT CSF) ============================
 * Historically every "allow an IP" path went only through `csf -a` / csf.allow, so on a box where CSF is NOT
 * installed/active (e.g. Imunify360 is the firewall) an allow did NOTHING to the live rules. This engine fixes
 * that: it routes an allow to whatever firewall is actually running — CSF allow-list and/or Imunify's own
 * whitelist — AND always inserts a top-of-INPUT ACCEPT into live iptables/ip6tables so the allow takes effect
 * IMMEDIATELY (a rule at INPUT position 1 short-circuits the imunify360/LOCALINPUT drop chains, since those are
 * jumped from INPUT after it). It also records the IP so a reboot/firewall-reload can re-apply it. */
function smpro_fw_has_imunify() { return trim((string)@shell_exec('command -v imunify360-agent 2>/dev/null')) !== ''; }
/** Every DISTINCT iptables backend binary present for v4/v6 — covers both the nft default AND iptables-legacy,
 *  because some boxes (this one) keep rules in the legacy tables. Deduped when `iptables` symlinks to iptables-nft. */
function smpro_fw_ipt_bins($v6 = false) {
    $names = $v6 ? ['ip6tables', 'ip6tables-legacy', 'ip6tables-nft'] : ['iptables', 'iptables-legacy', 'iptables-nft'];
    $seen = []; $out = [];
    foreach ($names as $n) {
        $p = '';
        foreach (["/usr/sbin/$n", "/sbin/$n", "/usr/bin/$n"] as $cand) if (@is_executable($cand)) { $p = $cand; break; }
        if ($p === '') { $c = trim((string)@shell_exec('command -v ' . escapeshellarg($n) . ' 2>/dev/null')); if ($c !== '') $p = $c; }
        if ($p === '') continue;
        $real = @realpath($p) ?: $p; if (isset($seen[$real])) continue; $seen[$real] = 1; $out[] = $p;
    }
    return $out;
}
/** Insert (default) or delete a top-of-INPUT rule for $ip on EVERY backend present. $target = 'ACCEPT' | 'DROP'.
 *  Idempotent (checks -C before inserting). Returns the backend basenames touched. */
function smpro_fw_ipt_all($ip, $target = 'ACCEPT', $del = false) {
    $ip = trim((string)$ip); $v6 = strpos($ip, ':') !== false; $a = escapeshellarg($ip); $done = [];
    $target = ($target === 'DROP') ? 'DROP' : 'ACCEPT';
    foreach (smpro_fw_ipt_bins($v6) as $b) {
        if ($del) @shell_exec('timeout 10 sh -c ' . escapeshellarg('for i in 1 2 3 4 5; do ' . $b . ' -D INPUT -s ' . $a . ' -j ' . $target . ' 2>/dev/null || break; done') . ' 2>&1');
        else      @shell_exec('timeout 10 sh -c ' . escapeshellarg($b . ' -C INPUT -s ' . $a . ' -j ' . $target . ' 2>/dev/null || ' . $b . ' -I INPUT 1 -s ' . $a . ' -j ' . $target) . ' 2>&1');
        $done[] = basename($b);
    }
    return $done;
}
function smpro_fw_live_list() { $d = @is_file(SMPRO_FW_LIVE) ? json_decode((string)@file_get_contents(SMPRO_FW_LIVE), true) : null; return is_array($d) ? array_values($d) : []; }
function smpro_fw_live_save($list) {
    $f = SMPRO_FW_LIVE; @is_dir(dirname($f)) || @mkdir(dirname($f), 0700, true);
    $t = $f . '.tmp'; if (@file_put_contents($t, json_encode(array_values(array_unique($list)), JSON_PRETTY_PRINT), LOCK_EX) !== false) { @chmod($t, 0600); @rename($t, $f); }
}
/** Allow an IP/CIDR in the LIVE firewall right now, whatever firewall is running (CSF, Imunify, or neither).
 *  Idempotent + persistent. This is what the "Add IP → Allow" card calls so it works even with NO CSF installed. */
function smpro_fw_live_allow($ip, $comment = 'SM Pro admin allow') {
    $ip = trim((string)$ip);
    if (!smpro_fw_cidr_valid($ip)) return ['ok' => false, 'msg' => 'Enter a valid IP or CIDR.'];
    $did = []; $live = '';
    // 1) csf.allow persistence + live iptables insert — smpro_csf_allow_add already does BOTH (and its live insert
    //    works even when CSF is absent, via smpro_fw_iptables_allow), so it covers the CSF and the no-CSF cases.
    if (function_exists('smpro_csf_allow_add')) { $r = @smpro_csf_allow_add($ip, $comment); if (!empty($r['ok'])) $did[] = 'CSF/csf.allow'; }
    $be = smpro_fw_ipt_all($ip, 'ACCEPT');                 // live ACCEPT at top of INPUT on EVERY backend (nft + legacy)
    if ($be) { $live = implode('/', array_unique($be)); $did[] = 'live iptables (' . $live . ')'; }
    // 2) Imunify present → add to ITS whitelist so Imunify keeps it (and won't drop it on its next reload)
    if (smpro_fw_has_imunify()) {
        $out = (string)@shell_exec('timeout 30 imunify360-agent whitelist ip add ' . escapeshellarg($ip) . ' --comment ' . escapeshellarg($comment) . ' 2>&1');
        if (stripos($out, 'usage:') !== false || stripos($out, 'invalid choice') !== false)   // CLI variant fallback
            @shell_exec('timeout 30 imunify360-agent ip-list local add --purpose white --ip ' . escapeshellarg($ip) . ' 2>&1');
        $did[] = 'Imunify allow-list';
    }
    // 3) record it so a reboot / firewall flush re-applies the live rule (safety net for a no-CSF, no-Imunify box)
    $list = smpro_fw_live_list(); if (!in_array($ip, $list, true)) { $list[] = $ip; smpro_fw_live_save($list); }
    if (function_exists('smpro_audit')) @smpro_audit('fw_live_allow', ['ip' => $ip, 'live' => $live !== '' ? 1 : 0, 'via' => implode('+', $did)]);
    return ['ok' => !empty($did),
            'msg' => empty($did) ? ('Could not allow ' . $ip . ' — no firewall control available.')
                                 : ($ip . ' allowed via ' . implode(' + ', array_unique($did)) . ($live !== '' ? ' — inserted into live iptables, so it takes effect immediately (even with no CSF).' : '.'))];
}
/** Remove a live-allow IP (live rule + our store). Does not touch CSF/Imunify lists — remove those in their own UI. */
function smpro_fw_live_remove($ip) {
    $ip = trim((string)$ip); if (!smpro_fw_cidr_valid($ip)) return ['ok' => false, 'msg' => 'Invalid IP.'];
    smpro_fw_ipt_all($ip, 'ACCEPT', true);                // delete the live ACCEPT on every backend
    smpro_fw_live_save(array_values(array_filter(smpro_fw_live_list(), fn($x) => $x !== $ip)));
    if (function_exists('smpro_audit')) @smpro_audit('fw_live_allow_remove', ['ip' => $ip]);
    return ['ok' => true, 'msg' => 'Removed ' . $ip . ' from the live allow-list (iptables rule deleted).'];
}
/** Block an IP in the LIVE firewall when CSF isn't the manager (Imunify block-list + a live iptables DROP).
 *  Refuses the admin's own IP and Cloudflare edge IPs (blocking those would cut access / whole sites). */
function smpro_fw_live_block($ip, $comment = 'SM Pro block') {
    $ip = trim((string)$ip);
    if (!smpro_fw_cidr_valid($ip)) return ['ok' => false, 'msg' => 'Enter a valid IP or CIDR.'];
    if (function_exists('smpro_admin_ip') && $ip === smpro_admin_ip()) return ['ok' => false, 'msg' => 'Refused — that is YOUR current IP; blocking it would lock you out.'];
    if (function_exists('smpro_csf_is_cloudflare_ip') && smpro_csf_is_cloudflare_ip($ip)) return ['ok' => false, 'msg' => 'Refused — that is a Cloudflare edge IP; blocking it would cut every proxied site. Block the visitor at Cloudflare instead.'];
    $did = [];
    if (smpro_fw_has_imunify()) { @shell_exec('timeout 30 imunify360-agent blacklist ip add ' . escapeshellarg($ip) . ' --comment ' . escapeshellarg($comment) . ' 2>&1'); $did[] = 'Imunify block-list'; }
    $be = smpro_fw_ipt_all($ip, 'DROP');                  // live DROP at top of INPUT on every backend
    if ($be) $did[] = 'live iptables (' . implode('/', array_unique($be)) . ')';
    if (function_exists('smpro_audit')) @smpro_audit('fw_live_block', ['ip' => $ip, 'via' => implode('+', $did)]);
    return ['ok' => !empty($did), 'msg' => empty($did) ? ('No firewall control available to block ' . $ip . '.') : ($ip . ' blocked via ' . implode(' + ', $did) . '.')];
}
/** Boot self-heal: re-insert every stored live-allow IP (idempotent) so admin allows survive a reboot / firewall flush. */
function smpro_fw_live_apply_all() {
    foreach (smpro_fw_live_list() as $ip) if (smpro_fw_cidr_valid($ip)) smpro_fw_ipt_all($ip, 'ACCEPT');
}

/* ----------------------------- provider catalog ----------------------------- */
function smpro_fw_allow_providers() {
    return [
        'cloudflare' => [
            'name'   => 'Cloudflare',
            'desc'   => 'Cloudflare edge IP ranges (IPv4 + IPv6). If any site is behind Cloudflare, allow-listing these stops LFD/CSF from blocking the proxy — which would otherwise take the site down.',
            'note'   => 'While traffic is proxied through Cloudflare it all arrives FROM these IPs, so LFD can no longer block a visitor by IP. Block abusive clients at Cloudflare instead, and restore real IPs (CF-Connecting-IP).',
            'fetch'  => ['https://www.cloudflare.com/ips-v4', 'https://www.cloudflare.com/ips-v6'],
            'ranges' => ['173.245.48.0/20','103.21.244.0/22','103.22.200.0/22','103.31.4.0/22','141.101.64.0/18',
                         '108.162.192.0/18','190.93.240.0/20','188.114.96.0/20','197.234.240.0/22','198.41.128.0/17',
                         '162.158.0.0/15','104.16.0.0/13','104.24.0.0/14','172.64.0.0/13','131.0.72.0/22',
                         '2400:cb00::/32','2606:4700::/32','2803:f800::/32','2405:b500::/32','2405:8100::/32','2a06:98c0::/29','2c0f:f248::/32'],
        ],
        'uptimerobot' => [
            'name'   => 'UptimeRobot (monitoring)',
            'desc'   => 'UptimeRobot monitoring-probe IPs — allow-list so your uptime checks are never blocked as "excessive requests" and false-alert you.',
            'note'   => '',
            'fetch'  => ['https://uptimerobot.com/inc/files/ips/IPv4.txt', 'https://uptimerobot.com/inc/files/ips/IPv6.txt'],
            'ranges' => [],
        ],
        'googlebot' => [
            'name'      => 'Googlebot (crawler)',
            'desc'      => 'Google\'s official crawler IP ranges — allow-list so Googlebot is never blocked (protects your SEO crawl).',
            'note'      => 'Google recommends verifying Googlebot by reverse DNS; IP allow-listing is a convenience, not a guarantee.',
            'fetch'     => ['https://developers.google.com/static/search/apis/ipranges/googlebot.json'],
            'fetch_json'=> 'prefixes',
            'ranges'    => [],
        ],
        'meta' => [
            'name'      => 'Meta / Facebook (crawler, link previews, WhatsApp, Instagram, Graph API)',
            'desc'      => 'Every address Meta announces (AS32934): the Facebook / Instagram / WhatsApp link-preview fetchers, the Meta crawler, and the Graph API callbacks. Blocking any of them breaks link previews and app integrations for every site here.',
            'note'      => 'Meta publishes no fixed list; the ranges come from what AS32934 announces (RIPEstat), refreshed with the other providers. Also used by Bot Guard to verify a Facebook claimant when it has no reverse DNS.',
            'fetch'     => ['https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS32934'],
            'fetch_json'=> 'data.prefixes',
            'ranges'    => [],
        ],
        'openai' => [
            'name'      => 'OpenAI crawlers (GPTBot, OAI-SearchBot, ChatGPT-User)',
            'desc'      => 'OpenAI\'s published crawler IP ranges. Used by Bot Guard to tell a real GPTBot from a fake one (the real ones have no reverse DNS, so the ranges are the only proof). Allow-listing is optional.',
            'note'      => 'Three feeds: GPTBot (training), OAI-SearchBot (ChatGPT search) and ChatGPT-User (fetches on a user\'s behalf).',
            'fetch'     => ['https://openai.com/gptbot.json', 'https://openai.com/searchbot.json', 'https://openai.com/chatgpt-user.json'],
            'fetch_json'=> 'prefixes',
            'ranges'    => [],
        ],
        'bingbot' => [
            'name'      => 'Bingbot (crawler)',
            'desc'      => 'Microsoft Bing\'s official crawler IP ranges — allow-list so Bingbot is never blocked.',
            'note'      => '',
            'fetch'     => ['https://www.bing.com/toolbox/bingbot.json'],
            'fetch_json'=> 'prefixes',
            'ranges'    => [],
        ],
        'cpanel' => [
            'name'   => 'cPanel license servers',
            'desc'   => 'cPanel license-verification servers — allow-list so LFD never blocks license checks (a blocked check can suspend cPanel/WHM).',
            'note'   => '',
            'ranges' => ['208.74.121.65','208.74.123.100'],
        ],
    ];
}

/* ----------------------------- helpers ----------------------------- */
function smpro_fw_allow_marker($key) { return 'smpro-allow:' . preg_replace('/[^a-z0-9]/', '', (string)$key); }
function smpro_fw_allow_csf_bin() { foreach (['/usr/sbin/csf', '/usr/local/csf/bin/csf'] as $b) if (is_executable($b)) return $b; return ''; }
function smpro_fw_cidr_valid($c) {
    $c = trim((string)$c); if ($c === '') return false;
    if (strpos($c, '/') === false) return filter_var($c, FILTER_VALIDATE_IP) !== false;
    $p = explode('/', $c, 2); if (!ctype_digit($p[1])) return false; $pfx = (int)$p[1];
    if (filter_var($p[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return $pfx >= 0 && $pfx <= 32;
    if (filter_var($p[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) return $pfx >= 0 && $pfx <= 128;
    return false;
}

/* ----------------------------- live fetch + cache ----------------------------- */
function smpro_fw_allow_cache_file($key) { return SMPRO_FWA_CACHE . '/' . preg_replace('/[^a-z0-9]/', '', (string)$key) . '.json'; }
/** Fetch the CURRENT ranges live from the provider feed(s). URLs are fixed constants (no SSRF). Returns [] on failure. */
function smpro_fw_allow_fetch_raw($pv) {
    $out = [];
    foreach ((array)($pv['fetch'] ?? []) as $url) {
        if (!preg_match('#^https://[A-Za-z0-9._~:/?\#\[\]@!$&\'()*+,;=%-]+$#', (string)$url)) continue;   // https only
        // -L is REQUIRED: Google now 302s googlebot.json to /static/crawling/ipranges/common-crawlers.json,
        // so without it curl returns a 279-byte HTML redirect page, json_decode fails, and the provider
        // silently yields ZERO ranges — the list renders empty and Sync looks like it did nothing. Measured:
        // without -L 0 prefixes, with -L 315 (Google) and 28 (Bing). Capped at 5 hops so a loop can't hang.
        $body = (string)@shell_exec('timeout 15 curl -fsSL --max-redirs 5 --max-time 12 -A ' . escapeshellarg('SMPro-fw/1.0') . ' ' . escapeshellarg($url) . ' 2>/dev/null');
        if ($body === '') continue;
        if (!empty($pv['fetch_json'])) {
            $j = json_decode($body, true); $arr = $j;
            foreach (explode('.', (string)$pv['fetch_json']) as $seg) { $arr = is_array($arr) ? ($arr[$seg] ?? []) : []; }   // a dotted path reaches a nested list (RIPEstat: data.prefixes)
            foreach ((array)$arr as $e) foreach (['ipv4Prefix','ipv6Prefix','prefix','cidr'] as $k) { if (!empty($e[$k]) && smpro_fw_cidr_valid($e[$k])) $out[$e[$k]] = 1; }
        } else {
            foreach (preg_split('/[\s,]+/', $body) as $line) { $line = trim($line); if ($line !== '' && smpro_fw_cidr_valid($line)) $out[$line] = 1; }
        }
    }
    return array_keys($out);
}
/** Fetch + write the per-provider cache; returns the fetched ranges (or [] if the feed was unreachable). */
function smpro_fw_allow_fetch($key) {
    $pv = smpro_fw_allow_providers()[$key] ?? null; if (!$pv || empty($pv['fetch'])) return [];
    $r = smpro_fw_allow_fetch_raw($pv);
    if ($r) {
        @is_dir(SMPRO_FWA_CACHE) || @mkdir(SMPRO_FWA_CACHE, 0700, true);
        $f = smpro_fw_allow_cache_file($key); $t = $f . '.tmp';
        if (@file_put_contents($t, json_encode(['ranges' => $r, 'fetched_at' => time()]), LOCK_EX) !== false) { @chmod($t, 0600); @rename($t, $f); }
    }
    return $r;
}
/** Current ranges for display/apply: cached fetch if present, else the static seed. Does NOT hit the network. */
function smpro_fw_allow_ranges($key) {
    $f = smpro_fw_allow_cache_file($key);
    if (@is_file($f)) { $d = json_decode((string)@file_get_contents($f), true); if (is_array($d) && !empty($d['ranges'])) return $d['ranges']; }
    $pv = smpro_fw_allow_providers()[$key] ?? null; return $pv['ranges'] ?? [];
}
/** Deployment-provider ranges (classification only, never allow-listed) ride along with the allow-list refresh. */
function smpro_fw_deploy_refresh_hook(): void {
    if (!function_exists('smpro_deploy_refresh')) { $f = __DIR__ . '/deployer.php'; if (@is_file($f)) require_once $f; }
    if (function_exists('smpro_deploy_refresh')) { try { smpro_deploy_refresh(); } catch (\Throwable $e) { if (function_exists('smpro_soft_fail')) smpro_soft_fail('deploy_refresh', $e); } }
}
function smpro_fw_allow_synced_at($key) { $f = smpro_fw_allow_cache_file($key); if (!@is_file($f)) return 0; $d = json_decode((string)@file_get_contents($f), true); return (int)($d['fetched_at'] ?? @filemtime($f)); }

/** How many of a provider's ranges are in csf.allow, and how many carry OUR marker. */
function smpro_fw_allow_status($ranges, $key) {
    $marker = smpro_fw_allow_marker($key);
    // one pass over csf.allow: which leading tokens exist, and which of them carry our marker
    $have = []; $mine = [];
    if (is_readable(SMPRO_FWA_ALLOW)) foreach (file(SMPRO_FWA_ALLOW, FILE_IGNORE_NEW_LINES) ?: [] as $l) {
        $l = trim($l); if ($l === '' || $l[0] === '#') continue;
        $tok = preg_split('/[\s#]/', $l, 2)[0]; if ($tok === '') continue;
        $have[$tok] = 1; $slash = strpos($tok, '/'); if ($slash !== false) $have[substr($tok, 0, $slash)] = 1;
        if (strpos($l, $marker) !== false) $mine[$tok] = 1;
    }
    $present = 0; $marked = 0;
    foreach ($ranges as $r) { $r = (string)$r; if (isset($have[$r])) { $present++; if (isset($mine[$r])) $marked++; } }
    return ['total' => count($ranges), 'present' => $present, 'marked' => $marked];
}

/* ----------------------------- apply / undo / reconcile ----------------------------- */
/** Add a provider's CURRENT ranges (fetches the live feed first) to csf.allow, tagged. */
function smpro_fw_allow_apply($key) {
    $pv = smpro_fw_allow_providers()[$key] ?? null; if (!$pv) return ['ok'=>false,'msg'=>'Unknown provider.'];
    $csf = smpro_fw_allow_csf_bin(); if ($csf === '') return ['ok'=>false,'msg'=>'CSF not installed.'];
    if (!empty($pv['fetch'])) smpro_fw_allow_fetch($key);                 // refresh from the live feed first
    $ranges = smpro_fw_allow_ranges($key);
    if (!$ranges) return ['ok'=>false,'msg'=>$pv['name'] . ': could not obtain current IP ranges (the feed was unreachable). Try again.'];
    $marker = smpro_fw_allow_marker($key); $added = 0; $skipped = 0;
    foreach ($ranges as $r) {
        if (!smpro_fw_cidr_valid($r)) continue;
        if (smpro_csf_allowlisted($r)) { $skipped++; continue; }
        @shell_exec('timeout 20 ' . escapeshellarg($csf) . ' -a ' . escapeshellarg($r) . ' ' . escapeshellarg($marker) . ' 2>&1');
        clearstatcache();
        if (!smpro_csf_allowlisted($r) && is_file(SMPRO_FWA_ALLOW) && is_writable(SMPRO_FWA_ALLOW)) { @file_put_contents(SMPRO_FWA_ALLOW, $r . ' # ' . $marker . ' - ' . date('D M j H:i:s Y') . "\n", FILE_APPEND | LOCK_EX); clearstatcache(); }
        if (smpro_csf_allowlisted($r)) $added++;
    }
    @shell_exec('timeout 60 ' . escapeshellarg($csf) . ' -r >/dev/null 2>&1');
    $st = smpro_fw_allow_status($ranges, $key);
    if (function_exists('smpro_audit')) smpro_audit('firewall_allow_provider', ['provider'=>$key, 'op'=>'add', 'added'=>$added, 'actor'=>function_exists('smpro_current_actor')?smpro_current_actor():'root']);
    return ['ok'=>true, 'msg'=>$pv['name'] . ': ' . $added . ' range(s) added' . ($skipped ? ', ' . $skipped . ' already present' : '') . ' — ' . $st['present'] . '/' . $st['total'] . ' now allow-listed. CSF reloaded.'];
}
/** Remove ONLY our marked lines for a provider. */
function smpro_fw_allow_undo($key) {
    $pv = smpro_fw_allow_providers()[$key] ?? null; if (!$pv) return ['ok'=>false,'msg'=>'Unknown provider.'];
    $csf = smpro_fw_allow_csf_bin(); $marker = smpro_fw_allow_marker($key);
    if (!is_file(SMPRO_FWA_ALLOW) || !is_writable(SMPRO_FWA_ALLOW)) return ['ok'=>false,'msg'=>'csf.allow is not writable.'];
    $lines = file(SMPRO_FWA_ALLOW, FILE_IGNORE_NEW_LINES) ?: []; $keep = []; $removed = 0;
    foreach ($lines as $l) { $t = trim($l); if ($t !== '' && $t[0] !== '#' && strpos($t, $marker) !== false) { $removed++; continue; } $keep[] = $l; }
    if ($removed > 0) { @copy(SMPRO_FWA_ALLOW, SMPRO_FWA_ALLOW . '.smpro.bak'); @file_put_contents(SMPRO_FWA_ALLOW, implode("\n", $keep) . "\n", LOCK_EX); if ($csf !== '') @shell_exec('timeout 60 ' . escapeshellarg($csf) . ' -r >/dev/null 2>&1'); }
    if (function_exists('smpro_audit')) smpro_audit('firewall_allow_provider', ['provider'=>$key, 'op'=>'remove', 'removed'=>$removed, 'actor'=>function_exists('smpro_current_actor')?smpro_current_actor():'root']);
    return ['ok'=>true, 'msg'=>$pv['name'] . ': removed ' . $removed . ' allow-list range(s). CSF reloaded.'];
}
/** Auto-update reconcile: fetch latest → add new tagged → drop OUR tagged entries no longer in the feed. */
function smpro_fw_allow_reconcile($key) {
    $pv = smpro_fw_allow_providers()[$key] ?? null; if (!$pv) return ['added'=>0,'removed'=>0,'err'=>'unknown provider'];
    // Say WHY nothing happened. Returning a bare added=0 made the UI report "Synced — added 0, removed 0",
    // which reads as success on a server where CSF simply is not the firewall (or is not installed at all).
    $csf = smpro_fw_allow_csf_bin();
    if ($csf === '') return ['added'=>0,'removed'=>0,'err'=>'CSF is not installed on this server, so allow-list entries cannot be written. Ranges were still fetched and are listed above.'];
    $live = !empty($pv['fetch']) ? smpro_fw_allow_fetch($key) : ($pv['ranges'] ?? []);
    if (!$live) return ['added'=>0,'removed'=>0,'err'=>'the provider feed returned no usable ranges (unreachable, or it moved) — existing entries kept'];   // never prune on a failed fetch
    $marker = smpro_fw_allow_marker($key); $added = 0; $removed = 0;
    foreach ($live as $r) { if (smpro_fw_cidr_valid($r) && !smpro_csf_allowlisted($r)) { @shell_exec('timeout 20 ' . escapeshellarg($csf) . ' -a ' . escapeshellarg($r) . ' ' . escapeshellarg($marker) . ' 2>&1'); clearstatcache(); if (smpro_csf_allowlisted($r)) $added++; } }
    $liveSet = array_flip($live);
    // a feed that came back much smaller than the last good one is a truncated download, not a provider that
    // halved its network: nothing is removed on its evidence
    $prevN = count(smpro_fw_allow_ranges($key)); $partial = $prevN >= 10 && count($live) < (int)($prevN * 0.5);
    if (!$partial && is_file(SMPRO_FWA_ALLOW) && is_writable(SMPRO_FWA_ALLOW)) {
        $lines = file(SMPRO_FWA_ALLOW, FILE_IGNORE_NEW_LINES) ?: []; $keep = [];
        foreach ($lines as $l) { $t = trim($l);
            if ($t !== '' && $t[0] !== '#' && strpos($t, $marker) !== false) { $ip = preg_split('/\s+/', $t)[0]; if (!isset($liveSet[$ip])) { $removed++; continue; } }
            $keep[] = $l;
        }
        if ($removed > 0) { @copy(SMPRO_FWA_ALLOW, SMPRO_FWA_ALLOW . '.smpro.bak'); @file_put_contents(SMPRO_FWA_ALLOW, implode("\n", $keep) . "\n", LOCK_EX); }
    }
    if ($added || $removed) @shell_exec('timeout 60 ' . escapeshellarg($csf) . ' -r >/dev/null 2>&1');
    return ['added'=>$added, 'removed'=>$removed] + ($partial ? ['err' => 'the feed returned ' . count($live) . ' ranges against ' . $prevN . ' last time - treated as a partial download, nothing removed'] : []);
}

/* ----------------------------- config: ignored + auto-update ----------------------------- */
function smpro_fw_allow_cfg() {
    $d = @is_file(SMPRO_FWA_CFG) ? json_decode((string)@file_get_contents(SMPRO_FWA_CFG), true) : null;
    if (!is_array($d)) $d = [];
    return ['ignored' => (isset($d['ignored']) && is_array($d['ignored'])) ? array_values(array_map('strval', $d['ignored'])) : [],
            'autoupdate' => (isset($d['autoupdate']) && is_array($d['autoupdate'])) ? array_values(array_map('strval', $d['autoupdate'])) : []];
}
function smpro_fw_allow_cfg_save($c) {
    $f = SMPRO_FWA_CFG; $dir = dirname($f); if (!is_dir($dir)) @mkdir($dir, 0700, true);
    $t = $f . '.tmp'; if (@file_put_contents($t, json_encode(['ignored'=>array_values($c['ignored']), 'autoupdate'=>array_values($c['autoupdate'])], JSON_PRETTY_PRINT), LOCK_EX) === false) return false;
    @chmod($t, 0600); $ok = @rename($t, $f);
    // Keep the cron in step, but do NOT fold its result into this return value. This function is also the
    // write path for unrelated preferences (hiding a recommendation), and coupling them meant a preference
    // that saved perfectly reported "Could not update" whenever /etc/cron.d happened to be unwritable.
    // The auto-update toggle checks the cron separately, where the failure actually matters.
    if (function_exists('smpro_fw_allow_cron_sync')) smpro_fw_allow_cron_sync();
    return $ok;
}
function smpro_fw_rec_ignored() { return smpro_fw_allow_cfg()['ignored']; }
function smpro_fw_rec_set_ignore($key, $ignore) {
    $key = preg_replace('/[^a-z0-9_]/', '', strtolower((string)$key)); if ($key === '') return false;
    $c = smpro_fw_allow_cfg(); if ($ignore) { if (!in_array($key, $c['ignored'], true)) $c['ignored'][] = $key; } else $c['ignored'] = array_values(array_diff($c['ignored'], [$key]));
    return smpro_fw_allow_cfg_save($c);
}
function smpro_fw_allow_autoupdate() { return smpro_fw_allow_cfg()['autoupdate']; }
function smpro_fw_allow_set_autoupdate($key, $on) {
    $key = preg_replace('/[^a-z0-9_]/', '', strtolower((string)$key)); if ($key === '') return false;
    // Turning auto-update ON is the one case where the cron IS the feature: without it nothing ever runs, so
    // report failure rather than a preference saved into a vacuum. (cfg_save keeps the cron in step but no
    // longer fails unrelated preference writes over it.)
    $c = smpro_fw_allow_cfg(); if ($on) { if (!in_array($key, $c['autoupdate'], true)) $c['autoupdate'][] = $key; } else $c['autoupdate'] = array_values(array_diff($c['autoupdate'], [$key]));
    $saved = smpro_fw_allow_cfg_save($c);
    if (!$saved) return false;
    // Only when switching ON does a failed cron install make a "saved" result a lie.
    return $on && function_exists('smpro_fw_allow_cron_sync') ? smpro_fw_allow_cron_sync() : true;
}

/* ----------------------------- cron + worker entrypoint ----------------------------- */
/** Returns true when the cron is in the intended state (installed and verified, or correctly absent). */
function smpro_fw_allow_cron_sync() {
    // A test must never install a live cron. The shared writer refuses too, but a test that loads only
    // this file has no shared writer to refuse - function_exists() is false and the fallback writes
    // /etc/cron.d directly. The lab caught exactly that, restored the file, and went red at random.
    if (defined('SMPRO_TEST_SRC')) return true;
    $f = '/etc/cron.d/smpro-fwallow';
    if (!count(smpro_fw_allow_autoupdate())) { if (@is_file($f)) @unlink($f); return true; }   // nothing auto -> no cron
    $bin = SMPRO_BASE . '/bin/fw_allow_sync.php'; if (!@is_file($bin)) return false;
    // Canonical interpreter: cPanel's bundled PHP, else the newest installed EA-PHP. `command -v php` can be
    // empty under cron's minimal PATH, which would bake a bare "php" into the cron line and never run.
    $php = function_exists('smpro_php_cli_bin') ? smpro_php_cli_bin()
         : (is_executable('/usr/local/cpanel/3rdparty/bin/php') ? '/usr/local/cpanel/3rdparty/bin/php' : (trim((string)@shell_exec('command -v php 2>/dev/null')) ?: 'php'));
    $lockDir = defined('SMPRO_LOCKS') ? SMPRO_LOCKS : (SMPRO_VARLIB . '/locks'); @is_dir($lockDir) || @mkdir($lockDir, 0700, true);
    $flock = is_executable('/usr/bin/flock') ? '/usr/bin/flock' : 'flock';
    $desired = "# Safety Monitor Pro — firewall allow-list auto-update (fetch provider IP ranges + reconcile csf.allow every 6h)\n"
             . "9 */6 * * * root $flock -n " . $lockDir . "/fwallow.lock timeout 300 $php $bin >/dev/null 2>&1\n";
    // Verify the write instead of assuming it: a read-only /etc or a full disk would otherwise leave the
    // provider showing "auto-update on" while nothing is ever scheduled.
    return function_exists('smpro_cron_install')
        ? smpro_cron_install($f, $desired)
        : (@file_put_contents($f, $desired) !== false && @chmod($f, 0644));
}
function smpro_fw_allow_autoupdate_run() {
    foreach (smpro_fw_allow_autoupdate() as $key) {
        $r = smpro_fw_allow_reconcile($key);
        if (function_exists('smpro_audit')) @smpro_audit('firewall_allow_autoupdate', ['provider'=>$key, 'added'=>$r['added'] ?? 0, 'removed'=>$r['removed'] ?? 0]);
    }
}

/**
 * Which managed provider — if any — publishes this address.
 *
 * The allow-list feature puts these ranges in csf.allow so CSF never blocks them, but until this existed nothing
 * ELSE in the plugin knew about them: the reports still listed Googlebot and UptimeRobot among the attackers, and
 * the block path's own guard only consulted the plugin's small manual allowlist. So a crawler could be presented
 * as a threat, and an automatic response could be aimed at it — CSF would have refused the deny because the range
 * is allowed there, but the plugin would have recorded a block that never happened and shown it as done.
 *
 * Returns the provider key ('googlebot', 'cloudflare', …) or '' when the address is not one of theirs.
 * The range set is loaded once per request; matching is CIDR, because a crawler address is almost never listed
 * on its own — it lives inside a published prefix.
 */
function smpro_fw_allow_covers($ip) {
    static $ranges = null;
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return '';
    if ($ranges === null) {
        $ranges = [];
        foreach (array_keys(smpro_fw_allow_providers()) as $k) {
            foreach (smpro_fw_allow_ranges($k) as $r) if (smpro_fw_cidr_valid($r)) $ranges[] = [$r, $k];
        }
    }
    if (!function_exists('smpro_in_cidr_match')) { $fi = __DIR__ . '/intrusion.php'; if (is_file($fi)) require_once $fi; }   // the matcher lives there; a caller that did not load it must still get a real answer, not 'no match'
    if (!$ranges || !function_exists('smpro_in_cidr_match')) return '';
    foreach ($ranges as $pair) {
        if (strpos($pair[0], '/') === false) { if ($pair[0] === $ip) return $pair[1]; continue; }
        if (smpro_in_cidr_match($ip, $pair[0])) return $pair[1];
    }
    return '';
}

/** Display name for whoever publishes this address, or '' — for labelling a row rather than calling it an attack. */
function smpro_fw_allow_covers_name($ip) {
    $k = smpro_fw_allow_covers($ip);
    if ($k === '') return '';
    $pv = smpro_fw_allow_providers()[$k] ?? null;
    return $pv['name'] ?? $k;
}
