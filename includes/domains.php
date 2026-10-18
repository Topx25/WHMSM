<?php
/**
 * domains.php — Domain Checker engine.
 *
 * Enumerates every domain hosted on the server (cPanel get_domain_info → /etc/userdomains
 * fallback), and for each one resolves:
 *   - owning cPanel user + account status (active / suspended)
 *   - the LIVE public A record(s) the domain points to (via an external resolver)
 *   - whether that IP matches one of THIS server's IPs (mismatch = points elsewhere)
 *   - the registrar expiry date (WHOIS) → expired / expiring-soon flag
 *
 * Read = safe (scan). Actions (suspend / terminate an account) are root-gated, CSRF-gated,
 * POST-only, never touch system/root accounts, and are explicit per request.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

define('SMPRO_DOM_CACHE', SMPRO_CACHE . '/domains');
define('SMPRO_DOM_WHOIS_TTL', 12 * 3600);   // registrar expiry changes rarely
define('SMPRO_DOM_DNS_TTL',   30 * 60);      // A records can change; re-check every 30 min

// Force a full PATH — the WHM CGI runs with a minimal PATH where dig/host/whois/curl may be unfound,
// which silently broke NS/WHOIS lookups (they fell back to PHP DNS funcs that some hosts disable).
function smpro_dom_sh($cmd, $t = 8) { return smpro_run((string)$cmd, (int)$t, ['path' => true, 'stderr' => 'discard']); }
function smpro_dom_has($bin) { return trim(smpro_dom_sh('command -v ' . escapeshellarg($bin))) !== ''; }
function smpro_dom_whmapi() { foreach (['/usr/local/cpanel/bin/whmapi1', '/usr/bin/whmapi1'] as $b) if (is_executable($b)) return $b; return smpro_dom_has('whmapi1') ? 'whmapi1' : ''; }

/* ---------------- DNS cluster: peer reachability ----------------
 * A cPanel DNS cluster writes every zone change to each peer SYNCHRONOUSLY. When one peer stops
 * answering, cPanel keeps waiting on it, so the visible symptom is not "DNS is broken" — it is account
 * creation, domain adds and zone edits hanging or timing out, with nothing obviously wrong locally.
 * That link between "one silent peer" and "the panel feels stuck" is what this surfaces.
 *
 * Read-only, and inert on the majority of servers: no cluster configured means no peers, and the whole
 * check reports "not configured" rather than inventing a problem. Peers come from cPanel's own
 * list_configclusterservers API, never from a hand-maintained list. */

/** Configured DNS-cluster peers. [] when DNS clustering is not in use.
 *
 *  Source of truth is cPanel's own DNS-cluster store, mirroring Cpanel::DNSLib::PeerConfig:
 *    /var/cpanel/useclusteringdns        — the master switch; absent means no DNS cluster at all
 *    /var/cpanel/cluster/<user>/config/  — one file per peer, named by host, holding its dnsrole
 *  Each reseller with the cluster privilege can have their own peer set, so every user directory is read.
 *
 *  NOT `list_configclusterservers`: that API is the CONFIGURATION cluster (WHM › Configuration Cluster,
 *  which copies WHM settings between servers, stored in /var/cpanel/clusterserver). It is a different
 *  feature with a different store — reading it meant a server with a real DNS cluster reported "no cluster
 *  configured" while a hung DNS peer was actively stalling zone writes, and a config-cluster-only server had
 *  its settings peers mislabelled as DNS peers. */
function smpro_dns_cluster_peers(string $confGlob = '/var/cpanel/cluster/*/config/*', string $switch = '/var/cpanel/useclusteringdns'): array {
    if (!@is_file($switch)) return [];      // DNS clustering switched off entirely
    $out = [];
    foreach (glob($confGlob) ?: [] as $f) {
        if (!@is_file($f)) continue;
        $host = trim(basename($f));
        // The peer file is named exactly by hostname/IP. cPanel keeps THREE siblings beside it - <host>.cache,
        // <host>-dnsrole, <host>-state.json - and treating those as peers meant probing "1.2.3.4-dnsrole" as a
        // hostname: 5 s of DNS failure each, until the 12 s budget was gone. That was 12 of Security Health's
        // 13 seconds on a production server whose two real peers answer in under 10 ms.
        if ($host === '' || !preg_match('/^[A-Za-z0-9._:-]+$/', $host)) continue;
        if ($host[0] === '.' || preg_match('/(\.cache|-dnsrole|-state\.json|\.json|\.tmp|\.bak|\.lock)$/i', $host)) continue;
        $role = '';
        foreach (@file($f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $ln) {
            if (preg_match('/^\s*dnsrole\s*[:=]\s*(\S+)/i', $ln, $m)) { $role = strtolower($m[1]); break; }
        }
        $out[$host] = ['host' => $host, 'role' => $role];          // keyed: the same peer may serve several users
    }
    return array_values($out);
}

/** Probe one peer's WHM API port. Returns [reachable(bool), ms(int), why(string)]. */
function smpro_dns_peer_probe(string $host, int $port = 2087, int $timeout = 5): array {
    if (!preg_match('/^[A-Za-z0-9._:-]+$/', $host)) return [false, 0, 'invalid host'];
    $t0 = microtime(true);
    // TLS handshake is not attempted — a TCP connect is enough to tell "answering" from "hanging", and it
    // cannot be tripped up by a self-signed cert, which cPanel peers commonly use.
    $errno = 0; $err = '';
    // smpro_host_port() brackets an IPv6 literal; without it the port is read as part of the address and
    // every v6 peer silently reports "down". Hostnames and IPv4 pass through unchanged.
    $target = function_exists('smpro_host_port') ? smpro_host_port($host, $port) : $host . ':' . $port;
    $fp = @stream_socket_client('tcp://' . $target, $errno, $err, max(1, $timeout));
    $ms = (int)round((microtime(true) - $t0) * 1000);
    if ($fp === false) return [false, $ms, $err !== '' ? $err : ('connect failed (' . $errno . ')')];
    @fclose($fp);
    return [true, $ms, ''];
}

/**
 * Health of every configured peer.
 * status: 'ok' | 'slow' | 'down'   ($slowMs+ still answers but is dragging every zone write)
 * Returns ['configured'=>bool, 'peers'=>[...], 'worst'=>'ok|slow|down|none'].
 */
function smpro_dns_cluster_health(int $slowMs = 1500): array {
    if (function_exists('smpro_memo')) { $m = smpro_memo('dns_cluster_health_' . $slowMs, 300, fn() => smpro_dns_cluster_health_live($slowMs)); if (is_array($m)) return $m; }
    return smpro_dns_cluster_health_live($slowMs);
}
/** The probe itself; smpro_dns_cluster_health() serves it from a five-minute memo on the render path. */
function smpro_dns_cluster_health_live(int $slowMs = 1500): array {
    $peers = smpro_dns_cluster_peers();
    if (!$peers) return ['configured' => false, 'peers' => [], 'worst' => 'none'];
    $rows = []; $worst = 'ok';
    // TOTAL time budget: this runs on the Security Health render path, and probing N unreachable peers at
    // 5s each would stall the page itself. Once the budget is spent the remaining peers are reported as
    // "not checked" rather than silently omitted — the page must never hang to produce a health card.
    $budget = 12.0; $spent = 0.0;
    foreach ($peers as $p) {
        if ($spent >= $budget) {
            $rows[] = ['host' => $p['host'], 'role' => $p['role'], 'status' => 'skipped', 'ms' => 0,
                       'why' => 'not checked — probe time budget reached'];
            continue;
        }
        $t0 = microtime(true);
        // Shrink the per-peer timeout so the last peers still get a real chance inside the budget.
        [$up, $ms, $why] = smpro_dns_peer_probe($p['host'], 2087, (int)max(2, min(5, ceil($budget - $spent))));
        $spent += microtime(true) - $t0;
        $st = !$up ? 'down' : ($ms >= $slowMs ? 'slow' : 'ok');
        if ($st === 'down') $worst = 'down';
        elseif ($st === 'slow' && $worst !== 'down') $worst = 'slow';
        $rows[] = ['host' => $p['host'], 'role' => $p['role'], 'status' => $st, 'ms' => $ms, 'why' => $why];
    }
    return ['configured' => true, 'peers' => $rows, 'worst' => $worst];
}

/** Recent peer failures from cPanel's dnsadmin log — corroborates a probe, and catches a peer that is
 *  reachable now but has been timing out. Log line shape: "[ISO ts] level [dnsadmin] message". */
function smpro_dns_cluster_log_failures(int $max = 5): array {
    $log = '/usr/local/cpanel/logs/dnsadmin_log';
    if (!@is_readable($log)) return [];
    $cat = function_exists('smpro_log_read_cmd') ? smpro_log_read_cmd($log, 3) : '';
    $inner = ($cat !== '' ? $cat : 'cat ' . escapeshellarg($log))
           . ' 2>/dev/null | grep -aiE "timed out|timeout|connection refused|unreachable|failed to connect" | tail -n ' . (int)$max;
    $raw = (string)@shell_exec('timeout 12 sh -c ' . escapeshellarg($inner) . ' 2>/dev/null');
    $out = [];
    foreach (array_filter(explode("\n", trim($raw))) as $ln) $out[] = trim(mb_substr($ln, 0, 200));
    return $out;
}

/* ---------------- this server's IPs (the "match" set) ---------------- */
function smpro_dom_server_ips(): array {
    static $ips = null;
    if ($ips !== null) return $ips;
    $set = [];
    foreach (['/var/cpanel/mainip', '/var/cpanel/mainserverip'] as $f)
        if (is_readable($f)) { $v = trim((string)@file_get_contents($f)); if (filter_var($v, FILTER_VALIDATE_IP)) $set[$v] = 1; }
    // all bound IPs (cPanel listips → addresses on the box)
    $bin = smpro_dom_whmapi();
    if ($bin !== '') {
        $j = json_decode(smpro_dom_sh(escapeshellarg($bin) . ' --output=json listips', 12), true);
        foreach ((array)($j['data']['ip'] ?? []) as $row) { $v = trim((string)($row['ip'] ?? '')); if (filter_var($v, FILTER_VALIDATE_IP)) $set[$v] = 1; }
    }
    // kernel-bound IPv4/IPv6 (covers IPs not in cPanel's list)
    foreach (preg_split('/\s+/', smpro_dom_sh("ip -o addr show scope global 2>/dev/null | awk '{print \$4}' | cut -d/ -f1")) as $v)
        if (filter_var(trim($v), FILTER_VALIDATE_IP)) $set[trim($v)] = 1;
    $ips = array_keys($set);
    return $ips;
}

/* ---------------- enumerate every hosted domain (fast, no DNS/WHOIS) ---------------- */
function smpro_dom_list(): array {
    $out = [];
    $bin = smpro_dom_whmapi();
    if ($bin !== '') {
        $j = json_decode(smpro_dom_sh(escapeshellarg($bin) . ' --output=json get_domain_info', 25), true);
        foreach ((array)($j['data']['domains'] ?? []) as $d) {
            $domain = strtolower(trim((string)($d['domain'] ?? '')));
            if ($domain === '') continue;
            $out[$domain] = [
                'domain'  => $domain,
                'user'    => trim((string)($d['user'] ?? '')),
                'type'    => trim((string)($d['domain_type'] ?? 'main')),   // main|addon|parked|sub
                'conf_ip' => trim((string)($d['ipv4'] ?? ($d['ipv4_dedicated'] ?? ''))),
                'docroot' => trim((string)($d['docroot'] ?? '')),
            ];
        }
    }
    // Fallback / supplement: /etc/userdomains (authoritative domain→user map)
    if (!$out && is_readable('/etc/userdomains')) {
        foreach (file('/etc/userdomains', FILE_IGNORE_NEW_LINES) ?: [] as $l) {
            if (!preg_match('/^([^:]+):\s*(\S+)/', $l, $m)) continue;
            $domain = strtolower(trim($m[1])); $user = trim($m[2]);
            if ($domain === '' || $user === '*' || $user === 'nobody') continue;
            $out[$domain] = ['domain' => $domain, 'user' => $user, 'type' => 'main', 'conf_ip' => '', 'docroot' => ''];
        }
    }
    // account status: a suspended account has /var/cpanel/suspended/<user>
    foreach ($out as $k => &$row) {
        $u = $row['user'];
        $row['suspended'] = ($u !== '' && is_file('/var/cpanel/suspended/' . $u));
    }
    unset($row);
    ksort($out);
    return array_values($out);
}

/* ---------------- parking nameservers — a domain on these is parked/inactive (treat as expired) ----------------
 * dns-parking.com = the registrar/Namecheap "parked" NS; the rest are common domain-parking monetizers. */
function smpro_dom_parking_ns(array $ns): string {
    $providers = [
        'dns-parking.com'  => 'dns-parking',
        'sedoparking.com'  => 'Sedo',
        'parkingcrew.net'  => 'ParkingCrew',
        'bodis.com'        => 'Bodis',
        'above.com'        => 'Above.com',
        'parklogic.com'    => 'ParkLogic',
        'fabulous.com'     => 'Fabulous',
        'cashparking.com'  => 'GoDaddy Parking',
        'voodoo.com'       => 'Voodoo',
        'parkingpage'      => 'Parking',
        'domainparking'    => 'Parking',
        'park-domains'     => 'Parking',
        'sedo.com'         => 'Sedo',
        'hastydns.com'     => 'Parking',
    ];
    foreach ($ns as $host) {
        $h = strtolower((string)$host);
        foreach ($providers as $needle => $label) if (strpos($h, $needle) !== false) return $label;
    }
    return '';
}

/* ---------------- known CDN ranges (so a proxied site is not mistaken for a hijack) ---------------- */
function smpro_dom_cdn_label(string $ip): string {
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return '';
    // Cloudflare IPv4 (subset of published ranges — enough to label the common cases)
    $cf = ['173.245.48.0/20','103.21.244.0/22','103.22.200.0/22','103.31.4.0/22','141.101.64.0/18',
           '108.162.192.0/18','190.93.240.0/20','188.114.96.0/20','197.234.240.0/22','198.41.128.0/17',
           '162.158.0.0/15','104.16.0.0/13','104.24.0.0/14','172.64.0.0/13','131.0.72.0/22'];
    foreach ($cf as $cidr) if (smpro_dom_ip_in_cidr($ip, $cidr)) return 'Cloudflare';
    return '';
}
function smpro_dom_ip_in_cidr(string $ip, string $cidr): bool {
    [$net, $bits] = array_pad(explode('/', $cidr), 2, '32');
    $ipL = ip2long($ip); $netL = ip2long($net); if ($ipL === false || $netL === false) return false;
    $mask = $bits == 0 ? 0 : (~0 << (32 - (int)$bits)) & 0xFFFFFFFF;
    return ($ipL & $mask) === ($netL & $mask);
}

/* ---------------- DNS-over-HTTPS resolver (works where the local `dig` fails, e.g. .sa TLDs) ----------------
 * Returns ['status'=>int (0=ok,3=NXDOMAIN), 'data'=>[answers...]] via Google then Cloudflare DoH JSON. */
function smpro_dom_doh(string $name, string $type): array {
    $eps = [
        ['https://dns.google/resolve?name=' . urlencode($name) . '&type=' . $type, ''],
        ['https://cloudflare-dns.com/dns-query?name=' . urlencode($name) . '&type=' . $type, '-H ' . escapeshellarg('accept: application/dns-json') . ' '],
    ];
    foreach ($eps as $ep) {
        // -L: this response is PARSED as JSON, so a provider that starts redirecting (as Google did with its
        // bot-ranges feed) would hand us an HTML page, json_decode would fail, and DNS checks would go quiet
        // with no error at all. Both endpoints answer 200 directly today, so following costs nothing — it
        // just removes a silent outage the day either provider moves a path.
        $raw = smpro_dom_sh('curl -s -L --max-redirs 3 --max-time 8 ' . $ep[1] . escapeshellarg($ep[0]), 10);
        $j = json_decode($raw, true);
        if (is_array($j) && isset($j['Status'])) {
            $data = [];
            foreach ((array)($j['Answer'] ?? []) as $a) { $v = rtrim(strtolower((string)($a['data'] ?? '')), '.'); if ($v !== '') $data[] = $v; }
            return ['status' => (int)$j['Status'], 'data' => $data];
        }
    }
    return ['status' => -1, 'data' => []];
}

/* ---------------- live DNS A record(s) (what the public actually resolves) ---------------- */
function smpro_dom_resolve(string $domain): array {
    // Use an external resolver so we see the PUBLIC answer, not a local /etc/hosts or split-horizon view.
    $ips = [];
    if (smpro_dom_has('dig')) {
        foreach (['1.1.1.1', '8.8.8.8'] as $rs) {
            $raw = smpro_dom_sh('dig +short +time=3 +tries=1 A ' . escapeshellarg($domain) . ' @' . $rs, 8);
            foreach (preg_split('/\s+/', trim($raw)) as $line) if (filter_var($line, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) $ips[$line] = 1;
            if ($ips) break;
        }
    }
    // system resolver fallbacks (dig with no @server, then host, then PHP) — for boxes that firewall public DNS
    if (!$ips && smpro_dom_has('dig')) { $raw = smpro_dom_sh('dig +short +time=3 +tries=1 A ' . escapeshellarg($domain), 6); foreach (preg_split('/\s+/', trim($raw)) as $l) if (filter_var($l, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) $ips[$l] = 1; }
    if (!$ips && smpro_dom_has('host')) { $raw = smpro_dom_sh('host -t A ' . escapeshellarg($domain), 6); if (preg_match_all('/has address (\d+\.\d+\.\d+\.\d+)/', $raw, $mm)) foreach ($mm[1] as $v) $ips[$v] = 1; }
    if (!$ips) { $r = @gethostbynamel($domain); if (is_array($r)) foreach ($r as $v) if (filter_var($v, FILTER_VALIDATE_IP)) $ips[$v] = 1; }
    // DNS-over-HTTPS — last resort for TLDs the local resolver can't reach (e.g. .sa)
    if (!$ips) { $d = smpro_dom_doh($domain, 'A'); foreach ($d['data'] as $v) if (filter_var($v, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) $ips[$v] = 1; }
    return array_keys($ips);
}

/* ---------------- authoritative nameservers (NS records) — shows where DNS is managed ----------------
 * NS lives at the registered zone, so for a subdomain/addon we walk UP to the parent zone. */
function smpro_dom_ns(string $domain): array {
    $domain = strtolower(trim($domain, " \t."));
    $labels = explode('.', $domain);
    // try the domain, then progressively strip the leftmost label, down to 2 labels (3 for 2-part TLDs like co.uk/com.sa)
    $twoPart = ['co','com','net','org','gov','edu','ac','nic'];
    $minLabels = (count($labels) >= 2 && in_array($labels[count($labels) - 2], $twoPart, true)) ? 3 : 2;
    for ($i = 0; $i <= count($labels) - $minLabels; $i++) {
        $cand = implode('.', array_slice($labels, $i));
        $ns = [];
        if (smpro_dom_has('dig')) {
            // system resolver first (works even when public DNS is firewalled), then public as a fallback
            $raw = smpro_dom_sh('dig +short +time=3 +tries=1 NS ' . escapeshellarg($cand), 8);
            if (trim($raw) === '') $raw = smpro_dom_sh('dig +short +time=3 +tries=1 NS ' . escapeshellarg($cand) . ' @1.1.1.1', 8);
            foreach (preg_split('/\s+/', trim($raw)) as $line) { $line = rtrim(strtolower(trim($line)), '.'); if ($line !== '' && strpos($line, '.') !== false) $ns[$line] = 1; }
        }
        if (!$ns && smpro_dom_has('host')) { $raw = smpro_dom_sh('host -t NS ' . escapeshellarg($cand), 8); if (preg_match_all('/name server (\S+)/i', $raw, $mm)) foreach ($mm[1] as $v) $ns[rtrim(strtolower($v), '.')] = 1; }
        if (!$ns) { $r = @dns_get_record($cand, DNS_NS); if (is_array($r)) foreach ($r as $rec) if (!empty($rec['target'])) $ns[rtrim(strtolower($rec['target']), '.')] = 1; }
        if (!$ns) { $d = smpro_dom_doh($cand, 'NS'); foreach ($d['data'] as $v) if (strpos($v, '.') !== false) $ns[$v] = 1; }   // DoH (fixes .sa & co)
        if ($ns) return array_keys($ns);
    }
    return [];
}

/* ---------------- WHOIS over a raw socket (port 43), no `whois` binary needed ----------------
 * Routes to the right registry by TLD, follows ONE registrar referral, falls back to the IANA
 * root (which returns the authoritative whois server for any TLD) and finally to the CLI. */
function smpro_dom_whois_server(string $tld): string {
    $map = [
        'com' => 'whois.verisign-grs.com', 'net' => 'whois.verisign-grs.com',
        'org' => 'whois.pir.org', 'info' => 'whois.afilias.net', 'biz' => 'whois.nic.biz',
        'sa' => 'whois.nic.net.sa', 'com.sa' => 'whois.nic.net.sa',
        'io' => 'whois.nic.io', 'co' => 'whois.nic.co', 'me' => 'whois.nic.me', 'tv' => 'whois.nic.tv',
        'xyz' => 'whois.nic.xyz', 'online' => 'whois.nic.online', 'site' => 'whois.nic.site',
        'store' => 'whois.nic.store', 'shop' => 'whois.nic.shop', 'ltd' => 'whois.nic.ltd',
        'cc' => 'whois.nic.cc', 'app' => 'whois.nic.google', 'dev' => 'whois.nic.google',
        'uk' => 'whois.nic.uk', 'de' => 'whois.denic.de', 'fr' => 'whois.nic.fr', 'eu' => 'whois.eu',
        'ae' => 'whois.aeda.net.ae', 'eg' => 'whois.ripe.net',
    ];
    return $map[$tld] ?? '';
}
function smpro_dom_whois_socket(string $server, string $query, int $t = 4): string {
    if ($server === '' || !function_exists('fsockopen')) return '';
    $fp = @fsockopen($server, 43, $errno, $errstr, $t);
    if (!$fp) return '';
    @stream_set_timeout($fp, $t);
    // verisign needs the "domain " keyword to return the full thick record on some queries
    @fputs($fp, $query . "\r\n");
    $out = ''; $start = time();
    while (!feof($fp)) { $out .= @fgets($fp, 256); if (strlen($out) > 60000 || (time() - $start) > ($t + 1)) break; }
    @fclose($fp);
    return $out;
}
function smpro_dom_whois_raw(string $domain): string {
    $domain = strtolower(trim($domain));
    $parts = explode('.', $domain);
    $tld  = end($parts);
    $tld2 = count($parts) >= 2 ? $parts[count($parts) - 2] . '.' . $tld : $tld;   // e.g. com.sa
    $server = smpro_dom_whois_server($tld2) ?: smpro_dom_whois_server($tld);

    // No known server → ask the IANA root which whois server is authoritative for this TLD.
    if ($server === '') {
        $iana = smpro_dom_whois_socket('whois.iana.org', $domain);
        if (preg_match('/whois:\s*(\S+)/i', $iana, $m)) $server = trim($m[1]);
    }
    $raw = $server !== '' ? smpro_dom_whois_socket($server, $domain) : '';

    // Thin registry (.com/.net) → follow the registrar's whois server ONCE for the expiry/registrar detail.
    if ($raw !== '' && preg_match('/Registrar WHOIS Server:\s*(\S+)/i', $raw, $m)) {
        $ref = trim($m[1]);
        if ($ref !== '' && stripos($ref, $server) === false) { $more = smpro_dom_whois_socket($ref, $domain); if ($more !== '') $raw .= "\n" . $more; }
    }
    // Last resort: the system `whois` binary (richer parsing for odd TLDs), if present.
    if (trim($raw) === '' && smpro_dom_has('whois')) $raw = smpro_dom_sh('whois ' . escapeshellarg($domain), 12);
    return $raw;
}

/* ---------------- registrar expiry, parsed from the raw WHOIS (many TLD formats) ---------------- */
function smpro_dom_whois_expiry(string $domain): array {
    $raw = smpro_dom_whois_raw($domain);
    if (trim($raw) === '') return ['ts' => 0, 'registrar' => '', 'unreg' => false, 'err' => 'no whois response'];
    // not registered / dropped / available → strong "expired" signal for a domain still hosted here
    if (preg_match('/(domain not found|no match for|not found:|no entries found|no data found|no object found|status:\s*free|status:\s*available|is available for registration|not been registered)/i', $raw))
        return ['ts' => 0, 'registrar' => '', 'unreg' => true, 'err' => 'not registered'];
    $exp = ''; $reg = '';
    // expiry — Latin + Arabic labels, ISO/various date forms
    if (preg_match('/(?:Registry Expiry Date|Registrar Registration Expiration Date|Expiry Date|Expiration Date|Expiration Time|expires(?: on)?|paid-till|renewal date|valid until)\s*:?\s*([0-9A-Za-z TZ:\-\.\/]+)/i', $raw, $m)
        || preg_match('/(?:تاريخ الانتهاء|الانتهاء|تاريخ انتهاء)\s*:?\s*([0-9TZ:\-\.\/ ]+)/u', $raw, $m))
        $exp = trim($m[1]);
    if (preg_match('/Registrar\s*:\s*(.+)/i', $raw, $m)) $reg = trim($m[1]);
    $ts = $exp !== '' ? strtotime($exp) : 0;
    return ['ts' => ($ts ?: 0), 'registrar' => mb_substr($reg, 0, 80), 'unreg' => false, 'err' => $ts ? '' : 'expiry not found'];
}

/* ---------------- HTTP liveness + page title (does the domain actually serve?) ----------------
 * matched-IP + non-200 = points here but the site is down; mismatched-IP + 200 = moved & live. */
function smpro_dom_http(string $domain): array {
    $code = 0; $title = '';
    if (smpro_dom_has('curl')) {
        $out = smpro_dom_sh('curl -sS -m 6 -L --max-redirs 3 -A ' . escapeshellarg('Mozilla/5.0 SafetyMonitorPro/DomainChecker')
             . ' -w ' . escapeshellarg('\n__SMHTTP__%{http_code}') . ' ' . escapeshellarg('http://' . $domain), 9);
        if (preg_match('/__SMHTTP__(\d{3})\s*$/', $out, $m)) $code = (int)$m[1];
        if (preg_match('/<title[^>]*>(.*?)<\/title>/is', $out, $m)) $title = mb_substr(trim(html_entity_decode(strip_tags($m[1]), ENT_QUOTES, 'UTF-8')), 0, 60);
    }
    return ['code' => $code, 'title' => $title];
}

/* ---------------- deep check ONE domain (DNS + WHOIS), file-cached ---------------- */
function smpro_dom_check(string $domain, bool $fresh = false): array {
    $domain = strtolower(trim($domain));
    if ($domain === '' || !preg_match('/^[a-z0-9.\-]+\.[a-z]{2,}$/i', $domain)) return ['ok' => false, 'msg' => 'Invalid domain'];
    @is_dir(SMPRO_DOM_CACHE) || @mkdir(SMPRO_DOM_CACHE, 0700, true);
    $cf = SMPRO_DOM_CACHE . '/' . sha1($domain) . '.json';

    $cached = is_file($cf) ? json_decode((string)@file_get_contents($cf), true) : null;
    $now = time();
    if (!$fresh && is_array($cached)) {
        $dnsFresh   = ($now - (int)($cached['dns_at'] ?? 0))   < SMPRO_DOM_DNS_TTL;
        $whoisFresh = ($now - (int)($cached['whois_at'] ?? 0)) < SMPRO_DOM_WHOIS_TTL;
        if ($dnsFresh && $whoisFresh) { $cached['ok'] = true; $cached['cached'] = true; return $cached; }
    }

    // DNS
    $ips = smpro_dom_resolve($domain);
    $ns  = smpro_dom_ns($domain);
    $server = smpro_dom_server_ips();
    $match = false; $cdn = '';
    foreach ($ips as $ip) { if (in_array($ip, $server, true)) { $match = true; } if ($cdn === '') $cdn = smpro_dom_cdn_label($ip); }

    // WHOIS (reuse cached expiry if still fresh, to avoid hammering registrars)
    if (!$fresh && is_array($cached) && ($now - (int)($cached['whois_at'] ?? 0)) < SMPRO_DOM_WHOIS_TTL && isset($cached['expiry_ts'])) {
        $expTs = (int)$cached['expiry_ts']; $registrar = (string)($cached['registrar'] ?? ''); $whoisAt = (int)$cached['whois_at']; $whoisErr = (string)($cached['whois_err'] ?? ''); $unreg = !empty($cached['unregistered']);
    } else {
        $w = smpro_dom_whois_expiry($domain); $expTs = (int)$w['ts']; $registrar = (string)$w['registrar']; $whoisAt = $now; $whoisErr = (string)$w['err']; $unreg = !empty($w['unreg']);
    }
    // parking nameservers → domain is parked/inactive, treat as expired
    $parkProvider = smpro_dom_parking_ns($ns);
    $parked    = ($parkProvider !== '');
    // WHOIS "not registered" is only real when the domain ALSO does not resolve. If it resolves to
    // anything (server IP, elsewhere, or a CDN) the whois answer is a false positive (rate-limit /
    // unparsed TLD / subdomain) → NOT expired.
    $unregReal = $unreg && empty($ips);
    $expired   = $unregReal || $parked || ($expTs > 0 && $expTs < $now);
    $expSoon   = ($expTs > 0 && !$expired && ($expTs - $now) < 30 * 86400);

    // HTTP liveness (reuse cached for the short DNS TTL window)
    if (!$fresh && is_array($cached) && ($now - (int)($cached['dns_at'] ?? 0)) < SMPRO_DOM_DNS_TTL && isset($cached['http_code'])) {
        $httpCode = (int)$cached['http_code']; $httpTitle = (string)($cached['http_title'] ?? '');
    } else {
        $h = smpro_dom_http($domain); $httpCode = (int)$h['code']; $httpTitle = (string)$h['title'];
    }

    $res = [
        'ok'         => true,
        'domain'     => $domain,
        'ips'        => $ips,
        'ns'         => $ns,
        'match'      => $match,
        'cdn'        => $cdn,
        'expiry_ts'  => $expTs,
        'expired'    => $expired,
        'expiring'   => $expSoon,
        'parked'     => $parked,
        'park_provider' => $parkProvider,
        'unregistered' => $unregReal,
        'registrar'  => $registrar,
        'whois_err'  => $whoisErr,
        'http_code'  => $httpCode,
        'http_title' => $httpTitle,
        'dns_at'     => $now,
        'whois_at'   => $whoisAt,
        'checked_at' => $now,
    ];
    @file_put_contents($cf, json_encode($res, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE)); @chmod($cf, 0600);
    $res['cached'] = false;
    return $res;
}

/* ---------------- guard: which accounts may NEVER be suspended/terminated ---------------- */
function smpro_dom_user_protected(string $user): bool {
    $u = strtolower(trim($user));
    if ($u === '' || $u === 'root' || $u === 'nobody' || $u === 'system' || $u === 'cpanel') return true;
    // must be a real cPanel account (exists in /var/cpanel/users) and not a system uid
    if (!is_file('/var/cpanel/users/' . $user)) return true;
    $uid = (int)smpro_dom_sh('id -u ' . escapeshellarg($user) . " 2>/dev/null | tr -d '\\n'");
    if ($uid > 0 && $uid < 1000) return true;
    return false;
}

/* ---------------- ACTION: suspend an account (root + reason) ---------------- */
function smpro_dom_suspend(string $user, string $reason): array {
    $user = trim($user);
    if (smpro_dom_user_protected($user)) return ['ok' => false, 'msg' => 'Refused: "' . $user . '" is a protected/system account.'];
    $bin = smpro_dom_whmapi(); if ($bin === '') return ['ok' => false, 'msg' => 'whmapi1 not available.'];
    if (is_file('/var/cpanel/suspended/' . $user)) return ['ok' => true, 'already' => true, 'msg' => 'Account "' . $user . '" is already suspended.'];
    $reason = mb_substr(preg_replace('/[^\P{C}]+/u', ' ', $reason ?: 'Suspended via Safety Monitor Pro Domain Checker'), 0, 200);
    $out = smpro_dom_sh(escapeshellarg($bin) . ' --output=json suspendacct user=' . escapeshellarg($user) . ' reason=' . escapeshellarg($reason), 40);
    $j = json_decode($out, true);
    $ok = is_array($j) && !empty($j['metadata']['result']);
    if (function_exists('smpro_audit')) smpro_audit('domain_suspend', ['user' => $user, 'ok' => $ok, 'reason' => $reason]);
    return $ok ? ['ok' => true, 'msg' => 'Account "' . $user . '" suspended.']
               : ['ok' => false, 'msg' => 'Suspend failed: ' . mb_substr(strip_tags((string)($j['metadata']['reason'] ?? $out)), 0, 160)];
}

/* ---------------- ACTION: full account backup to /backup/ (pkgacct) ----------------
 * Produces a complete, restorable cpmove archive (files + email + DBs + DNS + settings). */
function smpro_dom_backup(string $user): array {
    $user = trim($user);
    if (smpro_dom_user_protected($user)) return ['ok' => false, 'msg' => 'Refused: "' . $user . '" is a protected/system account.'];
    if (!is_file('/var/cpanel/users/' . $user)) return ['ok' => false, 'msg' => 'No such cPanel account: ' . $user];
    $script = '';
    foreach (['/usr/local/cpanel/scripts/pkgacct', '/scripts/pkgacct'] as $s) if (is_executable($s)) { $script = $s; break; }
    if ($script === '') return ['ok' => false, 'msg' => 'pkgacct not found — cannot create a backup.'];
    @is_dir('/backup') || @mkdir('/backup', 0700, true);
    @unlink('/backup/cpmove-' . $user . '.tar.gz');   // drop any STALE archive so "created" can't be a false positive off an old run
    // pkgacct <user> <dir> → /backup/cpmove-<user>.tar.gz   (long-running; allow up to 15 min)
    $out  = smpro_dom_sh(escapeshellarg($script) . ' ' . escapeshellarg($user) . ' /backup 2>&1', 900);
    $file = '';
    foreach (glob('/backup/cpmove-' . $user . '.tar.gz') ?: [] as $g) { $file = $g; break; }
    // NOTE the dot: 'cpmove-<user>.*' — prevents user "bob" from matching another account's "cpmove-bobby.tar.gz".
    if ($file === '') foreach (glob('/backup/cpmove-' . $user . '.*') ?: [] as $g) { if (is_file($g)) { $file = $g; break; } }
    $ok = ($file !== '' && is_file($file) && filesize($file) > 1024);
    if (function_exists('smpro_audit')) smpro_audit('domain_backup', ['user' => $user, 'ok' => $ok, 'file' => $file]);
    return $ok ? ['ok' => true, 'file' => $file, 'size' => filesize($file), 'msg' => 'Full backup created: ' . $file]
               : ['ok' => false, 'msg' => 'Backup failed (pkgacct did not produce an archive). ' . mb_substr(strip_tags($out), -160)];
}

/* ---------------- ACTION: terminate an account (root + DESTRUCTIVE) ----------------
 * If $backup, a full /backup/ archive is created FIRST; if that fails the account is NOT deleted. */
function smpro_dom_terminate(string $user, bool $backup = false): array {
    $user = trim($user);
    if (smpro_dom_user_protected($user)) return ['ok' => false, 'msg' => 'Refused: "' . $user . '" is a protected/system account.'];
    $bin = smpro_dom_whmapi(); if ($bin === '') return ['ok' => false, 'msg' => 'whmapi1 not available.'];
    if (!is_file('/var/cpanel/users/' . $user)) return ['ok' => false, 'msg' => 'No such cPanel account: ' . $user];
    $backupNote = '';
    if ($backup) {
        $b = smpro_dom_backup($user);
        if (empty($b['ok'])) return ['ok' => false, 'msg' => 'Aborted — backup failed, account NOT deleted: ' . ($b['msg'] ?? '')];
        $backupNote = ' Backup saved: ' . ($b['file'] ?? '/backup/');
    }
    $out = smpro_dom_sh(escapeshellarg($bin) . ' --output=json removeacct user=' . escapeshellarg($user) . ' keepdns=0', 120);
    $j = json_decode($out, true);
    $ok = is_array($j) && !empty($j['metadata']['result']);
    if (function_exists('smpro_audit')) smpro_audit('domain_terminate', ['user' => $user, 'ok' => $ok, 'backup' => $backup]);
    return $ok ? ['ok' => true, 'msg' => 'Account "' . $user . '" terminated (removed).' . $backupNote]
               : ['ok' => false, 'msg' => 'Terminate failed: ' . mb_substr(strip_tags((string)($j['metadata']['reason'] ?? $out)), 0, 160)];
}

/* ---------------- ACTION: terminate in the BACKGROUND (detached job) ----------------
 * pkgacct + removeacct can take minutes; run them detached so the plugin/UI never blocks.
 * Returns instantly with a job id the UI polls via smpro_dom_job(). */
function smpro_dom_terminate_bg(string $user, bool $backup): array {
    $user = trim($user);
    if (smpro_dom_user_protected($user)) return ['ok' => false, 'msg' => 'Refused: "' . $user . '" is a protected/system account.'];
    if (!is_file('/var/cpanel/users/' . $user)) return ['ok' => false, 'msg' => 'No such cPanel account: ' . $user];
    $dir = SMPRO_VARLIB . '/domjobs'; @is_dir($dir) || @mkdir($dir, 0700, true);
    $id  = date('Ymd_His') . '_' . substr(sha1($user . mt_rand() . uniqid('', true)), 0, 6);
    $jf  = $dir . '/' . $id . '.json';
    $sf  = $dir . '/' . $id . '.sh';
    @file_put_contents($jf, json_encode(['id' => $id, 'user' => $user, 'backup' => $backup, 'status' => 'queued', 'phase' => 'starting', 'msg' => 'Queued', 'ts' => time()]));
    @chmod($jf, 0600);
    $bk = $backup ? '1' : '0';
    // self-contained worker (independent of the obfuscated plugin code); writes JSON status into $jf as it progresses.
    $sh = "#!/bin/bash\n"
        . 'JF=' . escapeshellarg($jf) . "\n"
        . 'U=' . escapeshellarg($user) . "\n"
        . "BK=$bk\n"
        . 'w(){ printf "{\"id\":\"' . $id . '\",\"user\":\"%s\",\"status\":\"%s\",\"phase\":\"%s\",\"msg\":\"%s\",\"ts\":%s}" "$U" "$1" "$2" "$3" "$(date +%s)" > "$JF"; }' . "\n"
        . 'if [ "$BK" = "1" ]; then w running backup "Creating full backup in /backup ..."; '
        .   'rm -f /backup/cpmove-"$U".tar.gz >/dev/null 2>&1; '   // drop any STALE archive so the gate below can only pass on a freshly-created one
        .   'B=""; for s in /usr/local/cpanel/scripts/pkgacct /scripts/pkgacct; do [ -x "$s" ] && B="$s" && break; done; '
        .   '[ -n "$B" ] && "$B" "$U" /backup >"$JF.log" 2>&1; '
        .   'if ! ls /backup/cpmove-"$U".tar.gz >/dev/null 2>&1; then w failed backup "Backup failed - account NOT deleted"; exit 1; fi; fi' . "\n"
        . 'w running terminate "Removing account ..."' . "\n"
        . 'A=""; for a in /usr/local/cpanel/bin/whmapi1 /usr/bin/whmapi1; do [ -x "$a" ] && A="$a" && break; done' . "\n"
        . '"$A" --output=json removeacct user="$U" keepdns=0 >"$JF.log2" 2>&1' . "\n"
        . 'if grep -qE "\"result\" *: *1" "$JF.log2"; then w done done "Account $U terminated' . ($backup ? ' (backup in /backup)' : '') . '"; else w failed terminate "Terminate failed - see WHM"; fi' . "\n";
    @file_put_contents($sf, $sh); @chmod($sf, 0700);
    $launch = (smpro_dom_has('setsid') ? 'setsid ' : 'nohup ') . 'bash ' . escapeshellarg($sf) . ' >/dev/null 2>&1 </dev/null &';
    @shell_exec('PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin ' . $launch);
    if (function_exists('smpro_audit')) smpro_audit('domain_terminate_bg', ['user' => $user, 'backup' => $backup, 'job' => $id]);
    return ['ok' => true, 'job' => $id, 'msg' => 'Termination started in the background for "' . $user . '"' . ($backup ? ' (full backup first)' : '') . '.'];
}

/** Read a background job's status file (for UI polling). */
function smpro_dom_job(string $id): array {
    $id = preg_replace('/[^0-9A-Za-z_]/', '', $id);
    if ($id === '') return ['ok' => false, 'msg' => 'Bad job id'];
    $jf = SMPRO_VARLIB . '/domjobs/' . $id . '.json';
    if (!is_file($jf)) return ['ok' => false, 'msg' => 'Job not found'];
    $j = json_decode((string)@file_get_contents($jf), true);
    if (!is_array($j)) return ['ok' => false, 'msg' => 'Job unreadable'];
    $j['ok'] = true;
    return $j;
}

/** Resolve a domain → its owning cPanel user (for an action triggered on a domain row). */
function smpro_dom_user_of(string $domain): string {
    $domain = strtolower(trim($domain));
    foreach (smpro_dom_list() as $d) if ($d['domain'] === $domain) return $d['user'];
    return '';
}

/* ===========================================================================
 * BACKGROUND SCAN — check every hosted domain as a non-blocking server job.
 * The PHP CLI worker runs detached, writes progress to a job file, and stores
 * each domain's result in the standard per-domain cache.  The UI polls
 * smpro_dom_scan_status() incrementally and survives page navigation.
 * =========================================================================== */

/** Start a background scan of all hosted domains.  Returns quickly with the job id. */
function smpro_dom_bgscan_start(array $domainList): array {
    $domains = array_values(array_filter(array_column($domainList, 'domain')));
    if (!$domains) return ['ok' => false, 'msg' => 'No domains found.'];

    $dir = SMPRO_VARLIB . '/domjobs';
    @is_dir($dir) || @mkdir($dir, 0700, true);

    $id = 'scan_' . date('Ymd_His') . '_' . substr(sha1(uniqid('', true)), 0, 6);
    $jf = $dir . '/' . $id . '.json';
    $wf = $dir . '/' . $id . '_worker.php';

    // Lightweight job file: status + domain list (no results — those live in per-domain cache files).
    @file_put_contents($jf, json_encode([
        'id'      => $id,
        'status'  => 'queued',
        'total'   => count($domains),
        'done'    => 0,
        'domains' => $domains,
        'ts'      => time(),
    ], JSON_UNESCAPED_SLASHES));
    @chmod($jf, 0600);

    // Self-contained PHP worker — only needs defines + domains includes.
    $defPath = SMPRO_INCLUDES . '/defines.php';
    $domPath = SMPRO_INCLUDES . '/domains.php';
    $worker  = "<?php\n"
        . "define('SMPRO_BOOT', true);\n"
        . "require " . var_export($defPath, true) . ";\n"
        . "require SMPRO_INCLUDES . '/domains.php';\n"
        . '$jf=' . var_export($jf, true) . ";\n"
        . '$st=json_decode(file_get_contents($jf),true);' . "\n"
        . '$doms=$st[\'domains\'];$tot=count($doms);$done=0;' . "\n"
        . '$st[\'status\']=\'running\';file_put_contents($jf,json_encode($st,320));' . "\n"
        . 'foreach($doms as $dom){' . "\n"
        . '  smpro_dom_check($dom);' . "\n"  // writes to per-domain cache file automatically
        . '  $done++;$st[\'done\']=$done;$st[\'ts\']=time();' . "\n"
        . '  $st[\'status\']=($done>=$tot)?\'done\':\'running\';' . "\n"
        . '  file_put_contents($jf,json_encode($st,320));' . "\n"
        . "}\n";
    @file_put_contents($wf, $worker);
    @chmod($wf, 0700);

    // Find PHP CLI (cPanel standard path first, then ea-php, then which).
    $phpBin = '';
    foreach (['/usr/local/bin/php'] as $p) if (is_executable($p)) { $phpBin = $p; break; }
    if ($phpBin === '') {
        $globs = glob('/opt/cpanel/ea-php*/root/usr/bin/php') ?: [];
        rsort($globs);
        foreach ($globs as $p) if (is_executable($p)) { $phpBin = $p; break; }
    }
    if ($phpBin === '') $phpBin = trim((string)@shell_exec('PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin which php 2>/dev/null'));
    if ($phpBin === '' || !is_executable($phpBin)) {
        @unlink($jf); @unlink($wf);
        return ['ok' => false, 'msg' => 'PHP CLI not found — cannot run background scan.'];
    }

    $launch = 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin '
            . (smpro_dom_has('setsid') ? 'setsid ' : 'nohup ')
            . escapeshellarg($phpBin) . ' ' . escapeshellarg($wf)
            . ' >/dev/null 2>&1 </dev/null &';
    @shell_exec($launch);

    if (function_exists('smpro_audit')) smpro_audit('domain_bgscan_start', ['id' => $id, 'total' => count($domains)]);
    return ['ok' => true, 'scan_id' => $id, 'total' => count($domains)];
}

/** Poll a background scan — returns progress + results for domains[since..done) from the cache. */
function smpro_dom_scan_status(string $id, int $since): array {
    $id = preg_replace('/[^0-9A-Za-z_]/', '', $id);
    if ($id === '' || strpos($id, 'scan_') !== 0)
        return ['ok' => false, 'msg' => 'Invalid scan id'];
    $jf = SMPRO_VARLIB . '/domjobs/' . $id . '.json';
    if (!is_file($jf)) return ['ok' => false, 'msg' => 'Scan not found'];
    $st = json_decode((string)@file_get_contents($jf), true);
    if (!is_array($st)) return ['ok' => false, 'msg' => 'Scan state unreadable'];

    $status  = (string)($st['status'] ?? 'running');
    $total   = (int)($st['total'] ?? 0);
    $done    = (int)($st['done'] ?? 0);
    $domains = (array)($st['domains'] ?? []);
    $ts      = (int)($st['ts'] ?? 0);

    // Detect stalled worker (no update for >15 min while still "running").
    if ($status === 'running' && $ts > 0 && (time() - $ts) > 900) $status = 'stalled';

    // Return cached results for domains[$since .. $done-1] — incremental, avoids re-sending everything.
    $newResults = [];
    $upto = min($done, count($domains));
    for ($i = max(0, $since); $i < $upto; $i++) {
        $dom = $domains[$i] ?? '';
        if ($dom === '') continue;
        $cf = SMPRO_DOM_CACHE . '/' . sha1($dom) . '.json';
        if (is_file($cf)) {
            $r = json_decode((string)@file_get_contents($cf), true);
            if (is_array($r) && !empty($r['ok'])) $newResults[$dom] = $r;
        }
    }

    return [
        'ok'          => true,
        'status'      => $status,
        'total'       => $total,
        'done'        => $done,
        'new_results' => $newResults,
        'since'       => $since,
        'ts'          => $ts,
    ];
}
