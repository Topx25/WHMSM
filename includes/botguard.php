<?php
/**
 * includes/botguard.php — Bot Guard core. Shared by modules/bot-guard.php (the page) and bin/botguard_tick.php
 * (the worker), so it lives in includes/ and is loaded lazily (require_once) by both — not at boot.
 *
 * What it does, in one pass over the Apache domlogs (streamed, never held in memory) plus the WAF index:
 *   • recognises crawlers by User-Agent and VERIFIES the well-known ones the way their publishers say to
 *     (forward-confirmed reverse DNS: ip → host must end in the publisher's domain → host must resolve back to
 *     the same ip; or the publisher's published IP ranges when the Firewall allow-list feature has them);
 *   • a VERIFIED crawler → allowed automatically (protected from every automatic block in the plugin);
 *   • an UNVERIFIED bot with no bad requests → pending: the admin decides allow / block / ignore;
 *   • any bot that sent attack-signature requests (secret-file probes, injection, web-shell parameters, login
 *     brute force, or a known scanner tool as its User-Agent) → GRAY list with a per-window counter;
 *   • a gray-list address past the threshold → blocked automatically through smpro_im_block_ip(), which already
 *     refuses the server's own IP, Cloudflare edges, private ranges and anything allow-listed, and which the
 *     master Dry-Run switch turns into a "would block" record.
 *
 * Nothing here names a customer, a server, or a market. The publisher domains below are the crawler vendors'
 * own verification domains, published by them; they are in build/hardcode-allow.txt as vendors.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

if (!defined('SMPRO_BG_DIR'))   define('SMPRO_BG_DIR',   SMPRO_VARLIB . '/botguard');
if (!defined('SMPRO_BG_CFG'))   define('SMPRO_BG_CFG',   SMPRO_BG_DIR . '/config.json');
if (!defined('SMPRO_BG_STATE')) define('SMPRO_BG_STATE', SMPRO_BG_DIR . '/state.json');
if (!defined('SMPRO_BG_LOG'))   define('SMPRO_BG_LOG',   SMPRO_BG_DIR . '/events.log');
if (!defined('SMPRO_BG_RDNS'))  define('SMPRO_BG_RDNS',  SMPRO_BG_DIR . '/rdns.json');

/* ---------------- config + state (atomic 0600 json) ---------------- */
function smpro_bg_defaults(): array {
    return [
        // Reverse-DNS sweeps. Every one of these is a setting rather than a literal because the right value
        // depends on the server's resolver, which differs on every box we ship to: a fast local caching resolver
        // wants a short wait and a wide flight, a slow forwarder wants the opposite. The sweep's overall budget
        // is DERIVED from these and from how many addresses are actually left after the cache, never fixed.
        'rdns_concurrency' => 16,      // lookups in flight
        'rdns_timeout'     => 2,       // seconds allowed per lookup, one try
        'rdns_cache_days'  => 7,       // a reverse name rarely changes; empty answers are cached too
        'rdns_max_seconds' => 120,     // ceiling on any single sweep, however long the list
        'enabled'                 => false,   // the worker runs only when on; "Scan now" works regardless
        'auto_block'              => true,    // gray list past the threshold → block (Dry-Run turns this into a record)
        'gray_threshold'          => 25,      // attack-signature requests inside the window
        'window_hours'            => 24,      // how far back a scan looks (domlog mtime + line timestamps)
        'tail_lines'              => 20000,   // per domlog, newest lines
        'max_logs'                => 150,     // newest-modified domlogs per scan
        'allow_verified'          => true,    // verified official crawlers are allowed automatically
        'firewall_allow_verified' => false,   // ALSO write verified crawler IPs to csf.allow (off: allowed = exempt from Bot Guard/auto-blocks only)
        'scan_minutes'            => 5,       // worker cadence: an attacker past the threshold is blocked within 5 min, not 15 (one scan is ~2 s)
        'ignore_ips'              => [],      // never tracked (admin-entered)
        'custom_bots'             => [],      // operator-defined crawlers: [{key,name,kind,ua,rdns:[suffix,…]}]
    ];
}
function smpro_bg_json_load(string $f): array { $d = @is_file($f) ? json_decode((string)@file_get_contents($f), true) : null; return is_array($d) ? $d : []; }
function smpro_bg_json_save(string $f, array $d): bool {
    @is_dir(dirname($f)) || @mkdir(dirname($f), 0700, true);
    $t = $f . '.tmp';
    if (@file_put_contents($t, json_encode($d, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE), LOCK_EX) === false) return false;
    @chmod($t, 0600);
    return @rename($t, $f);
}
function smpro_bg_cfg(): array {
    $c = array_replace(smpro_bg_defaults(), smpro_bg_json_load(SMPRO_BG_CFG));
    $c['gray_threshold'] = max(3, min(5000, (int)$c['gray_threshold']));
    $c['window_hours']   = max(1, min(168, (int)$c['window_hours']));
    $c['tail_lines']     = max(1000, min(200000, (int)$c['tail_lines']));
    $c['max_logs']       = max(5, min(2000, (int)$c['max_logs']));
    $c['scan_minutes']   = max(5, min(240, (int)$c['scan_minutes']));
    $c['ignore_ips']     = array_values(array_filter(array_map('trim', (array)$c['ignore_ips']), fn($x) => $x !== ''));
    return $c;
}
function smpro_bg_cfg_save(array $patch): array { $c = array_replace(smpro_bg_cfg(), $patch); smpro_bg_json_save(SMPRO_BG_CFG, $c); return smpro_bg_cfg(); }
function smpro_bg_state(): array { $s = smpro_bg_json_load(SMPRO_BG_STATE); $s['bots'] = is_array($s['bots'] ?? null) ? $s['bots'] : []; return $s; }
function smpro_bg_state_save(array $s): bool { return smpro_bg_json_save(SMPRO_BG_STATE, $s); }
function smpro_bg_log(string $line): void {
    @is_dir(SMPRO_BG_DIR) || @mkdir(SMPRO_BG_DIR, 0700, true);
    @file_put_contents(SMPRO_BG_LOG, date('c') . ' ' . $line . "\n", FILE_APPEND | LOCK_EX);
    if (@filesize(SMPRO_BG_LOG) > 2 * 1048576) { $t = (string)@file_get_contents(SMPRO_BG_LOG); @file_put_contents(SMPRO_BG_LOG, substr($t, -1048576), LOCK_EX); }
}

/* ---------------- crawler catalogue (publisher verification, as each publisher documents it) ---------------- */
/**
 * family => name, kind, ua (regex), rdns (host suffixes the publisher uses; [] = the publisher offers no rDNS
 * verification, so the bot can only be PENDING), ranges (Firewall allow-list provider key whose published IP
 * ranges also verify it). Suffix match is on a dot boundary: "googlebot.com" matches "crawl-1.googlebot.com",
 * never "fakegooglebot.com".
 */
function smpro_bg_catalog(): array {
    static $memo = null;
    if ($memo !== null) return $memo;
    return $memo = array_replace(smpro_bg_catalog_builtin(), smpro_bg_catalog_custom());
}
/** The list we ship. Kept separate so a custom entry can be seen to be an addition, never a silent replacement. */
function smpro_bg_catalog_builtin(): array {
    return [
        'googlebot'  => ['name' => 'Googlebot',        'kind' => 'search',  'ua' => '/Googlebot|Google-InspectionTool|AdsBot-Google|APIs-Google|Mediapartners-Google|GoogleOther|Storebot-Google|Google-Read-Aloud/i', 'rdns' => ['googlebot.com', 'google.com'], 'ranges' => 'googlebot'],
        'bingbot'    => ['name' => 'Bingbot',          'kind' => 'search',  'ua' => '/bingbot|BingPreview|adidxbot|MicrosoftPreview/i', 'rdns' => ['search.msn.com'], 'ranges' => 'bingbot'],
        'duckduckgo' => ['name' => 'DuckDuckBot',      'kind' => 'search',  'ua' => '/DuckDuckBot|DuckDuckGo-Favicons-Bot/i', 'rdns' => ['duckduckgo.com'], 'ranges' => ''],
        'applebot'   => ['name' => 'Applebot',         'kind' => 'search',  'ua' => '/Applebot/i', 'rdns' => ['applebot.apple.com'], 'ranges' => ''],
        'yandex'     => ['name' => 'YandexBot',        'kind' => 'search',  'ua' => '/Yandex(?:Bot|Images|MobileBot|Accessibility|Metrika|Video|Media|Webmaster)/i', 'rdns' => ['yandex.ru', 'yandex.net', 'yandex.com'], 'ranges' => ''],
        'baidu'      => ['name' => 'Baiduspider',      'kind' => 'search',  'ua' => '/Baiduspider/i', 'rdns' => ['crawl.baidu.com', 'crawl.baidu.jp'], 'ranges' => ''],
        'yahoo'      => ['name' => 'Yahoo Slurp',      'kind' => 'search',  'ua' => '/Yahoo! Slurp|Slurp/i', 'rdns' => ['crawl.yahoo.net'], 'ranges' => ''],
        'petalbot'   => ['name' => 'PetalBot (Huawei)','kind' => 'search',  'ua' => '/PetalBot/i', 'rdns' => ['petalsearch.com', 'aspiegel.com'], 'ranges' => ''],
        'seznam'     => ['name' => 'SeznamBot',        'kind' => 'search',  'ua' => '/SeznamBot/i', 'rdns' => ['seznam.cz'], 'ranges' => ''],
        'facebook'   => ['name' => 'Facebook / Meta',  'kind' => 'social',  'ua' => '/facebookexternalhit|facebookcatalog|meta-externalagent|meta-externalfetcher/i', 'rdns' => ['facebook.com', 'fbsv.net', 'tfbnw.net'], 'ranges' => 'meta'],   // many Meta fetcher addresses carry no PTR: the announced ranges verify them
        'twitter'    => ['name' => 'Twitterbot / X',   'kind' => 'social',  'ua' => '/Twitterbot/i', 'rdns' => [], 'ranges' => ''],
        'linkedin'   => ['name' => 'LinkedInBot',      'kind' => 'social',  'ua' => '/LinkedInBot/i', 'rdns' => [], 'ranges' => ''],
        'pinterest'  => ['name' => 'Pinterestbot',     'kind' => 'social',  'ua' => '/Pinterestbot/i', 'rdns' => ['pinterest.com'], 'ranges' => ''],
        'ahrefs'     => ['name' => 'AhrefsBot',        'kind' => 'seo',     'ua' => '/AhrefsBot|AhrefsSiteAudit/i', 'rdns' => ['ahrefs.com', 'ahrefs.net'], 'ranges' => ''],
        'semrush'    => ['name' => 'SemrushBot',       'kind' => 'seo',     'ua' => '/SemrushBot/i', 'rdns' => ['semrush.com'], 'ranges' => ''],
        'mj12'       => ['name' => 'MJ12bot (Majestic)','kind' => 'seo',    'ua' => '/MJ12bot/i', 'rdns' => [], 'ranges' => ''],
        'dotbot'     => ['name' => 'DotBot (Moz)',     'kind' => 'seo',     'ua' => '/DotBot/i', 'rdns' => [], 'ranges' => ''],
        'uptimerobot'=> ['name' => 'UptimeRobot',      'kind' => 'monitor', 'ua' => '/UptimeRobot/i', 'rdns' => [], 'ranges' => 'uptimerobot'],
        'pingdom'    => ['name' => 'Pingdom',          'kind' => 'monitor', 'ua' => '/Pingdom/i', 'rdns' => ['pingdom.com'], 'ranges' => ''],
        // Chrome fetches a page ahead of the click through Google's own proxy; the address is Google's and says so in rDNS
        'google_prefetch' => ['name' => 'Google prefetch proxy (Chrome)', 'kind' => 'social', 'ua' => '/Chrome Privacy Preserving Prefetch Proxy/i', 'rdns' => ['google.com', '1e100.net'], 'ranges' => 'googlebot'],   // never googleusercontent.com: that is rented Google Cloud, not Google
        'openai'     => ['name' => 'OpenAI (GPTBot)',  'kind' => 'ai',      'ua' => '/GPTBot|ChatGPT-User|OAI-SearchBot/i', 'rdns' => [], 'ranges' => 'openai'],   // no rDNS on the real ones: ranges are the proof
        'anthropic'  => ['name' => 'ClaudeBot',        'kind' => 'ai',      'ua' => '/ClaudeBot|anthropic-ai|Claude-Web/i', 'rdns' => [], 'ranges' => ''],
        'perplexity' => ['name' => 'PerplexityBot',    'kind' => 'ai',      'ua' => '/PerplexityBot/i', 'rdns' => ['perplexity.ai'], 'ranges' => ''],
        'bytedance'  => ['name' => 'Bytespider (ByteDance)', 'kind' => 'ai', 'ua' => '/Bytespider/i', 'rdns' => [], 'ranges' => ''],
        'commoncrawl'=> ['name' => 'Common Crawl',     'kind' => 'ai',      'ua' => '/CCBot/i', 'rdns' => [], 'ranges' => ''],
        'archive'    => ['name' => 'Internet Archive', 'kind' => 'archive', 'ua' => '/archive\.org_bot|ia_archiver/i', 'rdns' => ['archive.org'], 'ranges' => ''],
        /* A publisher only gets an 'rdns' suffix here when that suffix is the one it documents for verification.
         * Where a publisher documents no reverse-DNS method, the entry carries an empty list on purpose: it is
         * still recognised and reported, but it is NOT shielded, because a guessed suffix is worse than none —
         * too narrow and the shield never fires, too broad and it shields whoever registers a matching name. */
        'amazonbot'  => ['name' => 'Amazonbot',        'kind' => 'search',  'ua' => '/Amazonbot/i', 'rdns' => ['crawl.amazonbot.amazon'], 'ranges' => ''],
        'naver'      => ['name' => 'Naver Yeti',       'kind' => 'search',  'ua' => '/Yeti\//i', 'rdns' => ['naver.com'], 'ranges' => ''],
        'sogou'      => ['name' => 'Sogou Spider',     'kind' => 'search',  'ua' => '/Sogou (?:web|inst|pic|news|video) spider/i', 'rdns' => ['crawl.sogou.com'], 'ranges' => ''],
        'coccoc'     => ['name' => 'Coc Coc',          'kind' => 'search',  'ua' => '/coccocbot/i', 'rdns' => ['coccoc.com'], 'ranges' => ''],
        'mojeek'     => ['name' => 'MojeekBot',        'kind' => 'search',  'ua' => '/MojeekBot/i', 'rdns' => ['mojeek.com'], 'ranges' => ''],
        'qwant'      => ['name' => 'Qwant',            'kind' => 'search',  'ua' => '/Qwantbot|Qwantify/i', 'rdns' => ['qwant.com'], 'ranges' => ''],
        'diffbot'    => ['name' => 'Diffbot',          'kind' => 'ai',      'ua' => '/Diffbot/i', 'rdns' => ['diffbot.com'], 'ranges' => ''],
        'amazon_ads' => ['name' => 'Amazon Ads',       'kind' => 'seo',     'ua' => '/Amazon-Advertising|amazon-kendra/i', 'rdns' => [], 'ranges' => ''],
        'google_ext' => ['name' => 'Google-Extended',  'kind' => 'ai',      'ua' => '/Google-Extended|Google-CloudVertexBot/i', 'rdns' => ['googlebot.com', 'google.com'], 'ranges' => 'googlebot'],
        'apple_ext'  => ['name' => 'Applebot-Extended','kind' => 'ai',      'ua' => '/Applebot-Extended/i', 'rdns' => ['applebot.apple.com'], 'ranges' => ''],
        'statuscake' => ['name' => 'StatusCake',       'kind' => 'monitor', 'ua' => '/StatusCake/i', 'rdns' => ['statuscake.com'], 'ranges' => ''],
        'site24x7'   => ['name' => 'Site24x7',         'kind' => 'monitor', 'ua' => '/Site24x7/i', 'rdns' => ['site24x7.com'], 'ranges' => ''],
        'betteruptime'=>['name' => 'Better Stack',     'kind' => 'monitor', 'ua' => '/Better Uptime|BetterStack/i', 'rdns' => [], 'ranges' => ''],
        'telegram'   => ['name' => 'TelegramBot',      'kind' => 'social',  'ua' => '/TelegramBot/i', 'rdns' => [], 'ranges' => ''],
        'whatsapp'   => ['name' => 'WhatsApp preview', 'kind' => 'social',  'ua' => '/WhatsApp/i', 'rdns' => ['facebook.com', 'fbsv.net'], 'ranges' => ''],
        'slack'      => ['name' => 'Slackbot',         'kind' => 'social',  'ua' => '/Slackbot|Slack-ImgProxy/i', 'rdns' => [], 'ranges' => ''],
        'discord'    => ['name' => 'Discordbot',       'kind' => 'social',  'ua' => '/Discordbot/i', 'rdns' => [], 'ranges' => ''],
    ];
}

/**
 * A reverse-DNS suffix an operator may add. Refused unless it is a domain with at least one label of its own
 * ABOVE a public suffix — "com", "co.uk" or "amazon" alone would shield every host on earth that ends that way,
 * which is the one mistake in this feature that cannot be undone by noticing it later.
 */
function smpro_bg_suffix_ok(string $sfx): bool {
    $sfx = strtolower(trim(trim($sfx), '.'));
    if ($sfx === '' || strlen($sfx) > 190) return false;
    if (!preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/', $sfx)) return false;
    $parts = explode('.', $sfx);
    // Two labels is the minimum, and three when the last two are a country-code second level (co.uk, com.br…).
    $need = (count($parts) >= 2 && strlen($parts[count($parts) - 1]) === 2 && in_array($parts[count($parts) - 2], ['co', 'com', 'net', 'org', 'gov', 'ac', 'edu'], true)) ? 3 : 2;
    return count($parts) >= $need;
}

/**
 * Operator-defined crawler entries, merged OVER the built-in catalogue.
 *
 * The built-in list is deliberately static product data — a publisher's verification domain effectively never
 * changes, and inventing one would be worse than omitting it. But a crawler that appears next month should not
 * need a release to be protected, and an operator who knows their own traffic should not have to wait for us.
 * So the catalogue is the built-in list plus whatever this server has been told, with the same verification
 * applied to both: a custom entry buys a name and a suffix, never an exemption from forward confirmation.
 */
function smpro_bg_catalog_custom(array $cfg = []): array {
    $cfg = $cfg ?: smpro_bg_cfg();
    $out = [];
    foreach ((array)($cfg['custom_bots'] ?? []) as $row) {
        if (!is_array($row)) continue;
        $key = preg_replace('/[^a-z0-9_]/', '', strtolower((string)($row['key'] ?? '')));
        $name = trim(preg_replace('/[^\x20-\x7E]/', '', substr((string)($row['name'] ?? ''), 0, 60)));
        if ($key === '' || $name === '') continue;
        $rdns = [];
        foreach ((array)($row['rdns'] ?? []) as $sfx) { $sfx = strtolower(trim(trim((string)$sfx), '.')); if (smpro_bg_suffix_ok($sfx)) $rdns[] = $sfx; }
        if (!$rdns) continue;                                   // no verifiable suffix = nothing to shield with
        $kind = in_array((string)($row['kind'] ?? ''), ['search', 'social', 'seo', 'monitor', 'ai', 'archive'], true) ? (string)$row['kind'] : 'search';
        $ua = trim((string)($row['ua'] ?? ''));
        // The UA pattern is matched as a literal fragment, never as an operator-supplied regex: a bad pattern
        // there would take the scan down, and a clever one would match everything.
        $uaRe = $ua !== '' ? '/' . preg_quote(substr($ua, 0, 60), '/') . '/i' : '/(?!)/';
        $out[$key] = ['name' => $name, 'kind' => $kind, 'ua' => $uaRe, 'rdns' => array_values(array_unique($rdns)), 'ranges' => '', 'custom' => true];
    }
    return $out;
}
function smpro_bg_kind_label(string $k): string { return ['search' => 'Search engine', 'social' => 'Social preview', 'seo' => 'SEO tool', 'monitor' => 'Uptime monitor', 'ai' => 'AI crawler', 'archive' => 'Archive'][$k] ?? 'Bot'; }
/** Catalogue family for a User-Agent, or ''. */
function smpro_bg_family(string $ua): string {
    if ($ua === '' || $ua === '-') return '';
    foreach (smpro_bg_catalog() as $k => $f) if (preg_match($f['ua'], $ua)) return $k;
    return '';
}
/** Does the UA look automated at all (any bot, tool or library)? Browsers say no. */
/** Who a pending row is, for grouping: the catalog name, else the name the client gives itself in its User-Agent
 *  (ExaSearchBot, SomeCrawler/1.0 ...), else its network. Pure; a notice of 4,184 addresses was 1 crawler x 8 IPs
 *  repeated, and nobody can decide anything from a list of addresses. */
function smpro_bg_identity(array $b): string {
    if ((string)($b['name'] ?? '') !== '') return (string)$b['name'];
    $ua = (string)($b['ua'] ?? '');
    if (preg_match('/\b([A-Za-z][A-Za-z0-9._-]{1,40}(?:bot|Bot|BOT|spider|Spider|crawler|Crawler|Fetcher|fetcher))\b/', $ua, $m)) return $m[1] . ' (declared, not verified)';
    $prov = trim((string)($b['provider'] ?? ''));
    $prov = preg_replace('/\s*(as\d+|inc\.?|ltd\.?|llc|gmbh|s\.a\.|co\.|corp\.?|,.*)$/i', '', $prov);
    if ($prov !== '') return 'unnamed clients on ' . $prov;
    return 'unnamed clients, unknown network';
}
function smpro_bg_is_botlike(string $ua): bool {
    if ($ua === '' || $ua === '-') return true;   // an empty User-Agent is a script, not a person
    return (bool)preg_match('/bot\b|bot\/|crawl|spider|slurp|scan|fetch|scrap|python|curl\/|wget|go-http|java\/|libwww|httpclient|okhttp|headless|phantom|puppeteer|selenium|axios|node-fetch|http_request|winhttp|perl|ruby|php\/|monitor|checker|validator|archive|preview|feed|rss/i', $ua);
}
/** Known attack / scanner tools announcing themselves in the UA. Their presence is itself an attack signal. */
function smpro_bg_scanner_ua(string $ua): bool {
    return (bool)preg_match('/nikto|sqlmap|masscan|zgrab|nmap|nuclei|wpscan|dirbuster|dirb\b|gobuster|ffuf|acunetix|nessus|openvas|w3af|havij|hydra|medusa|joomscan|droopescan|xsser|commix|arachni|netsparker|burp|python-requests\/[\d.]+$|Go-http-client\/1\.1$/i', $ua);
}
/**
 * Attack signature of ONE request (method, uri, ua). Returns '' or a category:
 *   exploit    — injection / traversal / web-shell parameters / remote-include
 *   probe      — secret files and admin panels that a legitimate crawler has no business fetching
 *   bruteforce — POSTs to login endpoints (each one is a credential guess)
 *   scanner    — a known attack tool in the User-Agent
 * Deliberately conservative: a normal page, image, or feed fetch never matches.
 */
function smpro_bg_classify_req(string $method, string $uri, string $ua): string {
    if (smpro_bg_scanner_ua($ua)) return 'scanner';
    $m = strtoupper($method); $path = (string)parse_url($uri, PHP_URL_PATH); if ($path === '') $path = $uri;
    $dec = rawurldecode($uri);
    if (preg_match('/[?&](cmd|exec|c99|r57|wso|b374k|filesman|passthru|shell|eval|system)=|%00|\beval\(|base64_decode|union[\s+]+select|\'\s*or\s*1\s*=\s*1|information_schema|\.\.\/|\.\.\\\\|php:\/\/|data:\/\/|expect:\/\/|\/etc\/passwd|\/proc\/self|<script|javascript:|\$\{jndi:|\{\{.*\}\}|sleep\(\d+\)|benchmark\(/i', $dec)) return 'exploit';
    if (preg_match('#/(?:\.env|\.git/|\.svn/|\.htpasswd|\.aws/|\.ssh/|\.DS_Store|wp-config\.php(?:\.bak|~|\.old|\.save)?|config\.php\.bak|backup\.(?:zip|sql|tar|gz)|db\.sql|dump\.sql|phpinfo\.php|phpmyadmin|pma/|adminer\.php|xmlrpc\.php|vendor/phpunit|eval-stdin\.php|cgi-bin/(?:php|luci|test-cgi)|wp-content/uploads/.*\.php|\.well-known/.*\.php|shell\.php|wso\.php|c99\.php|alfa\.php|filemanager\.php|owa/|autodiscover/|boaform/|HNAP1|actuator/|\.php7|\.phtml)#i', $path)) return 'probe';
    if ($m === 'POST' && preg_match('#/(?:wp-login\.php|xmlrpc\.php|administrator/index\.php|admin/login|user/login|login\.php|signin|wp-admin/admin-ajax\.php\?action=(?:login|auth))#i', $uri)) return 'bruteforce';
    return '';
}

/* ---------------- domlog parsing ---------------- */
/** Parse one Apache "combined" line → [ip, ts, method, uri, status, ua] or null. cPanel domlogs are this format. */
function smpro_bg_parse_line(string $l): ?array {
    if (!preg_match('/^(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d{3}) \S+ "[^"]*" "([^"]*)"/', $l, $m)) return null;
    $req = $m[3]; $method = ''; $uri = '';
    if (preg_match('/^(\S+)\s+(\S+)/', $req, $r)) { $method = $r[1]; $uri = $r[2]; } elseif ($req !== '') { $uri = $req; }
    // "06/Sep/2026:14:05:07 +0000" — strtotime cannot read slash + month-name, so rebuild it with spaces.
    $t = $m[2]; $ts = 0;
    if (preg_match('#^(\d{1,2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+\-]\d{4})?#', $t, $d)) $ts = (int)(@strtotime($d[1] . ' ' . $d[2] . ' ' . $d[3] . ' ' . $d[4] . ':' . $d[5] . ':' . $d[6] . ' ' . ($d[7] ?? '')) ?: 0);
    else $ts = (int)(@strtotime($t) ?: 0);
    return ['ip' => $m[1], 'ts' => $ts, 'method' => $method, 'uri' => $uri, 'status' => (int)$m[4], 'ua' => $m[5]];
}
function smpro_bg_domlogs_base(): string {
    if (function_exists('smpro_fw_domlogs_base')) return (string)smpro_fw_domlogs_base();
    foreach (['/etc/apache2/logs/domlogs', '/usr/local/apache/domlogs', '/var/log/apache2/domlogs'] as $p) if (is_dir($p)) return $p;
    return '';
}
/** Newest-modified domlogs inside the window (both http and ssl logs; never the bytes/ftp logs). */
function smpro_bg_domlogs(int $windowHours, int $max): array {
    $base = smpro_bg_domlogs_base(); if ($base === '') return [];
    $cmd = 'find ' . escapeshellarg($base) . ' -maxdepth 2 -type f -mmin -' . (int)($windowHours * 60)
         . " ! -name '*bytes_log' ! -name 'ftp*' ! -name '*.gz' ! -name '*.offset' -size +0 -printf '%T@ %p\\n' 2>/dev/null | sort -rn | head -n " . (int)$max;
    $out = function_exists('smpro_run') ? smpro_run('sh -c ' . escapeshellarg($cmd), 30, ['stderr' => 'discard']) : (string)@shell_exec('timeout 30 sh -c ' . escapeshellarg($cmd) . ' 2>/dev/null');
    $files = [];
    foreach (explode("\n", trim($out)) as $ln) { $p = strstr(trim($ln), ' '); if ($p !== false && is_file(trim($p))) $files[] = trim($p); }
    return $files;
}
/** Aggregate one parsed request into the per-IP map. Pure; also used by the tests with synthetic lines. */
function smpro_bg_aggregate(array &$ips, array $r, string $domain, int $cutoff): void {
    if ($r['ts'] > 0 && $r['ts'] < $cutoff) return;
    if (!filter_var($r['ip'], FILTER_VALIDATE_IP)) return;
    $cat = smpro_bg_classify_req($r['method'], $r['uri'], $r['ua']);
    $bot = smpro_bg_is_botlike($r['ua']);
    if ($cat === '' && !$bot) return;                      // an ordinary visitor: not tracked at all
    $ip = $r['ip'];
    if (!isset($ips[$ip])) $ips[$ip] = ['ip' => $ip, 'hits' => 0, 'attacks' => 0, 'cats' => [], 'uas' => [], 'domains' => [], 'first' => 0, 'last' => 0, 'sample' => '', 'botlike' => false, 'urls' => [], 'statuses' => []];
    $a =& $ips[$ip];
    $a['hits']++;
    if ($bot) $a['botlike'] = true;
    if ($cat !== '') { $a['attacks']++; $a['cats'][$cat] = ($a['cats'][$cat] ?? 0) + 1; if ($a['sample'] === '' || $cat === 'exploit') $a['sample'] = substr($r['method'] . ' ' . $r['uri'], 0, 160); }
    $ua = substr((string)$r['ua'], 0, 160); if (count($a['uas']) < 6 || isset($a['uas'][$ua])) $a['uas'][$ua] = ($a['uas'][$ua] ?? 0) + 1;
    if ($domain !== '' && (isset($a['domains'][$domain]) || count($a['domains']) < 40)) $a['domains'][$domain] = ($a['domains'][$domain] ?? 0) + 1;
    $st = (int)($r['status'] ?? 0); if ($st) $a['statuses'][$st] = ($a['statuses'][$st] ?? 0) + 1;
    // last five requests, bad ones preferred: what the visitor was actually doing
    $u = substr($r['method'] . ' ' . $r['uri'], 0, 140) . ($cat !== '' ? '  [' . $cat . ']' : '');
    if ($cat !== '' || count($a['urls']) < 5) { $a['urls'][] = $u; if (count($a['urls']) > 5) array_shift($a['urls']); }
    if ($r['ts'] > 0) { $a['first'] = $a['first'] ? min($a['first'], $r['ts']) : $r['ts']; $a['last'] = max($a['last'], $r['ts']); }
    unset($a);
}
/** The scan: stream the newest domlogs + merge the WAF index. Returns ['ips'=>map, 'files'=>n, 'lines'=>n, 'waf'=>n]. */
function smpro_bg_scan(array $cfg): array {
    $cutoff = time() - $cfg['window_hours'] * 3600;
    $ips = []; $files = smpro_bg_domlogs($cfg['window_hours'], $cfg['max_logs']); $lines = 0; $deadline = microtime(true) + 240;
    // One tail for every 100 files (it prints "==> path <==" before each file's lines): a scan of 1,350 domlogs used to
    // fork 1,350 times every 15 minutes.
    foreach (array_chunk($files, 100) as $chunk) {
        if (microtime(true) > $deadline) break;
        $domain = preg_replace('/-ssl_log$/', '', basename($chunk[0]));   // a chunk of one file prints no header
        $it = function_exists('smpro_run_lines') ? smpro_run_lines('tail -n ' . (int)$cfg['tail_lines'] . ' -- ' . implode(' ', array_map('escapeshellarg', $chunk)), 120) : [];
        foreach ($it as $l) {
            if ($l === '') continue;
            if (strpos($l, '==> ') === 0 && substr($l, -4) === ' <==') { $domain = preg_replace('/-ssl_log$/', '', basename(substr($l, 4, -4))); continue; }
            $lines++; $r = smpro_bg_parse_line($l); if ($r) smpro_bg_aggregate($ips, $r, $domain, $cutoff);
        }
    }
    // WAF index (ModSecurity events already parsed by the intrusion engine): every row is an attack by definition.
    $waf = 0;
    if (function_exists('smpro_in_history')) {
        foreach (smpro_in_history($cutoff, 20000) as $row) {
            $ip = (string)($row['ip'] ?? ''); if (!filter_var($ip, FILTER_VALIDATE_IP)) continue;
            if (!isset($ips[$ip])) $ips[$ip] = ['ip' => $ip, 'hits' => 0, 'attacks' => 0, 'cats' => [], 'uas' => [], 'domains' => [], 'first' => 0, 'last' => 0, 'sample' => '', 'botlike' => false, 'urls' => [], 'statuses' => []];
            $ips[$ip]['attacks']++; $ips[$ip]['hits']++; $ips[$ip]['cats']['waf'] = ($ips[$ip]['cats']['waf'] ?? 0) + 1; $waf++;
            if (($row['domain'] ?? '') !== '' && count($ips[$ip]['domains']) < 40) $ips[$ip]['domains'][(string)$row['domain']] = 1;
            $ts = (int)($row['ts'] ?? 0); if ($ts) { $ips[$ip]['first'] = $ips[$ip]['first'] ? min($ips[$ip]['first'], $ts) : $ts; $ips[$ip]['last'] = max($ips[$ip]['last'], $ts); }
            if ($ips[$ip]['sample'] === '' && ($row['uri'] ?? '') !== '') $ips[$ip]['sample'] = substr('WAF ' . (string)$row['uri'], 0, 160);
        }
    }
    return ['ips' => $ips, 'files' => count($files), 'lines' => $lines, 'waf' => $waf];
}

/* ---------------- verification ---------------- */
/** Default resolvers; a test injects its own. rev: ip → hostname|''. fwd: host → [ips]. */
function smpro_bg_resolvers(): array {
    return [
        'rev' => function (string $ip): string { $h = @gethostbyaddr($ip); return ($h === false || $h === $ip) ? '' : strtolower(rtrim($h, '.')); },
        'fwd' => function (string $host): array { $a = @gethostbynamel($host); if (!is_array($a)) $a = []; foreach ((array)@dns_get_record($host, DNS_AAAA) as $r) if (!empty($r['ipv6'])) $a[] = strtolower($r['ipv6']); return $a; },
    ];
}
function smpro_bg_host_under(string $host, array $suffixes): bool {
    $host = strtolower(rtrim($host, '.'));
    foreach ($suffixes as $s) { $s = strtolower($s); if ($host === $s || (strlen($host) > strlen($s) && substr($host, -strlen($s) - 1) === '.' . $s)) return true; }
    return false;
}
/**
 * Verify that $ip really belongs to $family. Returns ['verified'=>bool, 'how'=>'range'|'rdns'|'', 'host'=>rdns, 'why'=>text].
 * Forward-confirmed reverse DNS is what Google, Bing, Apple, Yandex and the others document; a UA string alone
 * proves nothing (anyone can send "Googlebot").
 */
function smpro_bg_verify(string $ip, string $family, ?array $res = null): array {
    $cat = smpro_bg_catalog()[$family] ?? null;
    if (!$cat) return ['verified' => false, 'how' => '', 'host' => '', 'why' => 'not in the catalogue'];
    if ($cat['ranges'] !== '' && function_exists('smpro_fw_allow_covers') && smpro_fw_allow_covers($ip) === $cat['ranges'])
        return ['verified' => true, 'how' => 'range', 'host' => '', 'why' => 'inside the publisher\'s published IP ranges'];
    if (!$cat['rdns']) return ['verified' => false, 'how' => '', 'host' => '', 'why' => 'this publisher offers no reverse-DNS verification'];
    $res = $res ?: smpro_bg_resolvers();
    $host = (string)$res['rev']($ip);
    if ($host === '') return ['verified' => false, 'how' => '', 'host' => '', 'why' => 'no reverse DNS'];
    if (!smpro_bg_host_under($host, $cat['rdns'])) return ['verified' => false, 'how' => '', 'host' => $host, 'why' => 'reverse DNS is not under ' . implode(' / ', $cat['rdns'])];
    $fwd = array_map('strtolower', (array)$res['fwd']($host));
    if (!in_array(strtolower($ip), $fwd, true)) return ['verified' => false, 'how' => '', 'host' => $host, 'why' => 'host does not resolve back to this IP (spoofed reverse DNS)'];
    return ['verified' => true, 'how' => 'rdns', 'host' => $host, 'why' => 'forward-confirmed reverse DNS: ' . $host];
}

/**
 * Reverse-resolve MANY addresses, in parallel, and remember the answers.
 *
 * gethostbyaddr() is sequential and waits out the resolver's own timeout on every miss. On a box whose resolver is
 * slow that is most of a second each: a sweep of 199 blocked addresses got through 30 before its budget ran out,
 * which is a check nobody will run seven times. `dig` asks for all of them at once instead — 16 in flight, each
 * given two seconds and a single try — so the same 199 finish in the time two sequential lookups used to take.
 *
 * A reverse name changes rarely, so answers are cached for a week, including the ones that came back empty; a
 * re-run then costs nothing at all. Without `dig` this falls back to gethostbyaddr and stays honest about the
 * budget rather than pretending to have checked.
 *
 * Returns [ip => host] with '' for "no reverse DNS", and only for the addresses it actually got to.
 */
/** How long a reverse sweep of $n unresolved addresses actually needs, from the numbers that decide it.
 *  Each flight costs at most one lookup timeout, and there are ceil(n / concurrency) flights. Deriving it means
 *  a longer list gets longer, a mostly-cached list finishes at once, and nobody has to guess a wall that fits. */
function smpro_bg_rdns_budget(int $n, int $conc = 0, int $perFlight = 0, int $ceiling = 0): int {
    $conc      = $conc      > 0 ? $conc      : (int)smpro_bg_cfg()['rdns_concurrency'];
    $perFlight = $perFlight > 0 ? $perFlight : (int)smpro_bg_cfg()['rdns_timeout'];
    $ceiling   = $ceiling   > 0 ? $ceiling   : (int)smpro_bg_cfg()['rdns_max_seconds'];
    if ($n <= 0) return 0;
    return max(5, min($ceiling, (int)ceil($n / max(1, $conc)) * max(1, $perFlight) + 3));   // +3: process spawn and parse
}

function smpro_bg_rdns_bulk(array $ips, int $budget = 0, int $conc = 0): array {
    $ips = array_values(array_unique(array_filter(array_map('trim', $ips), fn($x) => (bool)filter_var($x, FILTER_VALIDATE_IP))));
    if (!$ips) return [];
    $cfg = smpro_bg_cfg();
    $conc = $conc > 0 ? $conc : max(1, (int)$cfg['rdns_concurrency']);
    $wait = max(1, (int)$cfg['rdns_timeout']);
    $now = time(); $ttl = max(3600, (int)$cfg['rdns_cache_days'] * 86400);
    $cache = smpro_bg_json_load(SMPRO_BG_RDNS);
    $out = []; $todo = [];
    foreach ($ips as $ip) {
        $e = $cache[$ip] ?? null;
        if (is_array($e) && ($now - (int)($e['at'] ?? 0)) < $ttl) $out[$ip] = (string)($e['host'] ?? '');
        else $todo[] = $ip;
    }
    if (!$todo) return $out;

    // Sized from what is actually left to do, after the cache has taken its share. A caller may still impose its
    // own ceiling, but nothing here assumes a list length.
    $budget = $budget > 0 ? $budget : smpro_bg_rdns_budget(count($todo), $conc, $wait);
    $started = time(); $dirty = false;
    $dig = trim((string)@shell_exec('command -v dig 2>/dev/null')) !== '';

    if ($dig && function_exists('proc_open') && DIRECTORY_SEPARATOR === '/') {
        foreach (array_chunk($todo, $conc) as $chunk) {
            if (time() - $started >= $budget) break;
            $procs = [];
            foreach ($chunk as $ip) {
                $cmd = 'dig +short +time=' . $wait . ' +tries=1 -x ' . escapeshellarg($ip) . ' 2>/dev/null';
                $ph = @proc_open($cmd, [1 => ['pipe', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
                if (!is_resource($ph)) { $out[$ip] = ''; continue; }
                $procs[$ip] = [$ph, $pipes[1]];
            }
            foreach ($procs as $ip => [$ph, $pipe]) {
                $txt = (string)@stream_get_contents($pipe); @fclose($pipe); @proc_close($ph);
                $host = '';
                foreach (explode("\n", $txt) as $line) {
                    $line = strtolower(trim(rtrim(trim($line), '.')));
                    if ($line !== '' && strpos($line, ' ') === false) { $host = $line; break; }
                }
                $out[$ip] = $host;
                $cache[$ip] = ['host' => $host, 'at' => $now]; $dirty = true;
            }
        }
    } else {
        foreach ($todo as $ip) {
            if (time() - $started >= $budget) break;
            $h = @gethostbyaddr($ip);
            $host = ($h === false || $h === $ip) ? '' : strtolower(rtrim($h, '.'));
            $out[$ip] = $host;
            $cache[$ip] = ['host' => $host, 'at' => $now]; $dirty = true;
        }
    }

    if ($dirty) {
        // Keep the file from growing without bound on a busy box: drop anything older than the TTL before saving.
        foreach ($cache as $k => $v) if (!is_array($v) || ($now - (int)($v['at'] ?? 0)) >= $ttl) unset($cache[$k]);
        smpro_bg_json_save(SMPRO_BG_RDNS, $cache);
    }
    return $out;
}

/**
 * Is this address a REAL search / archive / monitoring crawler? Answered by forward-confirmed reverse DNS against
 * the catalogue above — the method Google, Bing, Apple and Yandex each document — not by a User-Agent string,
 * which anyone can send, and not by the owner of the network, which proves nothing either way.
 *
 * This exists because of a genuine confusion the firewall page makes easy: a rented virtual machine inside Google
 * Cloud reverse-resolves to *.bc.googleusercontent.com and is labelled a "bot" by the network classifier, while
 * Googlebot itself resolves to *.googlebot.com. They are different services on different address ranges, and only
 * the second one indexes anything. Blocking the first cannot cost a single position in search; blocking the
 * second silently removes the site from the index days later, with no error anywhere to explain why.
 *
 * Cost: ONE reverse lookup. The forward confirmation only runs when the reverse name already sits under a
 * publisher's domain, which is almost never true for an attacker. Answers are cached for the request, and a DNS
 * failure returns "not a crawler" so a resolver outage can never stop an operator blocking an attacker.
 *
 * Returns ['crawler'=>bool, 'family'=>key, 'name'=>label, 'kind'=>kind, 'host'=>rdns, 'why'=>text].
 */
function smpro_bg_crawler_shield(string $ip, ?array $res = null, ?string $knownHost = null): array {
    static $memo = [];
    $no = ['crawler' => false, 'family' => '', 'name' => '', 'kind' => '', 'host' => '', 'why' => ''];
    $ip = trim($ip);
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return $no;
    if (isset($memo[$ip])) return $memo[$ip];

    $res = $res ?: smpro_bg_resolvers();
    // A bulk sweep has already resolved this one; asking the resolver again would be the whole cost of the sweep
    // paid twice. An empty string is a real answer ("no reverse DNS"), which is why null means "not known yet".
    $host = $knownHost !== null ? strtolower(rtrim(trim($knownHost), '.')) : (string)$res['rev']($ip);
    if ($host === '') return $memo[$ip] = $no;                      // no reverse DNS at all — no publisher claims it

    foreach (smpro_bg_catalog() as $fam => $cat) {
        if (!$cat['rdns'] || !smpro_bg_host_under($host, $cat['rdns'])) continue;
        $v = smpro_bg_verify($ip, $fam, $res);                      // this re-resolves forward and confirms
        if (empty($v['verified'])) {
            // The reverse name claims a publisher but does not resolve back: that is a SPOOF, and blocking it is
            // exactly right. Say so rather than staying silent, so the log explains the decision.
            return $memo[$ip] = ['crawler' => false, 'family' => $fam, 'name' => (string)$cat['name'], 'kind' => (string)$cat['kind'],
                                 'host' => $host, 'why' => 'claims ' . $cat['name'] . ' but ' . (string)($v['why'] ?? 'did not verify')];
        }
        return $memo[$ip] = ['crawler' => true, 'family' => $fam, 'name' => (string)$cat['name'], 'kind' => (string)$cat['kind'],
                             'host' => $host, 'why' => 'forward-confirmed ' . $cat['name'] . ' (' . $host . ')'];
    }
    return $memo[$ip] = $no;
}

/* ---------------- ignore list: an entry may be a single address OR a range ---------------- */
/**
 * Does $ip fall inside $cidr (an exact address counts as itself)? Self-contained on purpose: smpro_bg_decide is
 * pure and is exercised without the intrusion engine loaded, so it cannot depend on smpro_in_cidr_match(). v4
 * and v6, compared as packed bytes; a v4 entry never matches a v6 address.
 *
 * The settings field is labelled "IPs/CIDRs" and its validator accepts a range, but the scan matched the list
 * with a plain string comparison — so a range was accepted, shown as saved, and silently did nothing while
 * every address inside it stayed trackable and auto-blockable. An ignore rule that reads as applied and is not
 * is worse than one that is refused.
 */
function smpro_bg_cidr_has(string $cidr, string $ip): bool {
    $cidr = trim($cidr); $ip = trim($ip);
    if ($cidr === '' || $ip === '') return false;
    if (strpos($cidr, '/') === false) return $cidr === $ip;
    [$net, $bits] = explode('/', $cidr, 2);
    if ($bits === '' || !ctype_digit($bits)) return false;
    $a = @inet_pton(trim($net)); $b = @inet_pton($ip);
    if ($a === false || $b === false || strlen($a) !== strlen($b)) return false;   // unparsable, or different families
    $bits = (int)$bits; $max = strlen($a) * 8;
    if ($bits < 0 || $bits > $max) return false;
    $whole = intdiv($bits, 8); $rest = $bits % 8;
    if ($whole > 0 && strncmp($a, $b, $whole) !== 0) return false;
    if ($rest === 0) return true;
    $mask = chr((0xFF << (8 - $rest)) & 0xFF);
    return ($a[$whole] & $mask) === ($b[$whole] & $mask);
}
/** Is this address covered by any entry of the operator's ignore list (address or range)? */
function smpro_bg_ip_ignored(string $ip, array $list): bool {
    foreach ($list as $e) if (smpro_bg_cidr_has((string)$e, $ip)) return true;
    return false;
}

/* ---------------- the decision (pure) ---------------- */
/**
 * Merge a scan into the state and decide each address. $verify(ip, family) → smpro_bg_verify shape.
 * Statuses: allowed (verified, or admin) · pending (unverified bot, no attacks) · gray (attacked, under threshold)
 *           · block (gray past threshold, to be blocked now) · blocked · ignored · denied (admin refused to allow)
 * Admin decisions (decided_by !== 'auto') are never overturned by a scan; counters still refresh.
 * Returns ['state'=>..., 'to_block'=>[ip=>reason], 'new_pending'=>[ip], 'new_gray'=>[ip], 'warn_allowed'=>[ip]].
 */
/** Never auto-blocked by Bot Guard: a residential address in a configured home region, or an allow-listed one. */
function smpro_bg_never_autoblock(string $ip): bool {
    if (function_exists('smpro_im_allowlisted') && smpro_im_allowlisted($ip)) return true;
    if (function_exists('smpro_im_region_status') && smpro_im_region_status($ip) === 'core_protected') return true;
    return false;
}
function smpro_bg_decide(array $scan, array $cfg, array $state, callable $verify, int $now = 0): array {
    $now = $now ?: time(); $bots = $state['bots']; $cat = smpro_bg_catalog();
    $toBlock = []; $newPending = []; $newGray = []; $warnAllowed = []; $review = [];
    $ignore = array_values(array_filter((array)($cfg['ignore_ips'] ?? [])));
    foreach ($scan['ips'] as $ip => $a) {
        if ($ignore && smpro_bg_ip_ignored((string)$ip, $ignore)) continue;
        $prev = $bots[$ip] ?? null;
        $topUa = ''; if ($a['uas']) { arsort($a['uas']); $topUa = (string)array_key_first($a['uas']); }
        $family = '';
        foreach ($a['uas'] as $ua => $n) { $f = smpro_bg_family((string)$ua); if ($f !== '') { $family = $f; break; } }
        $b = [
            'ip' => $ip, 'ua' => $topUa, 'family' => $family, 'name' => $family !== '' ? $cat[$family]['name'] : '', 'kind' => $family !== '' ? $cat[$family]['kind'] : '',
            'hits' => (int)$a['hits'], 'attacks' => (int)$a['attacks'], 'cats' => $a['cats'], 'domains' => count($a['domains']), 'sample' => (string)$a['sample'],
            'domains_top' => (function ($d) { arsort($d); return array_slice($d, 0, 5, true); })((array)$a['domains']), 'urls' => array_values((array)($a['urls'] ?? [])), 'statuses' => (array)($a['statuses'] ?? []),
            'hits_per_hour' => round((int)$a['hits'] / max(1, (int)$cfg['window_hours']), 1), 'bad_ratio' => (int)$a['hits'] > 0 ? (int)round(100 * (int)$a['attacks'] / (int)$a['hits']) : 0,
            'country' => (string)($prev['country'] ?? ''), 'provider' => (string)($prev['provider'] ?? ''),
            'first' => $prev['first'] ?? ($a['first'] ?: $now), 'last' => max((int)($a['last'] ?: $now), (int)($prev['last'] ?? 0)), 'seen' => $now,
            'status' => $prev['status'] ?? '', 'decided_by' => $prev['decided_by'] ?? '', 'decided_at' => $prev['decided_at'] ?? 0,
            'verified' => $prev['verified'] ?? false, 'how' => $prev['how'] ?? '', 'host' => $prev['host'] ?? '', 'why' => $prev['why'] ?? '', 'note' => $prev['note'] ?? '',
            'attacks_total' => (int)($prev['attacks_total'] ?? 0) + (int)$a['attacks'],
        ];
        // verification is cached per ip+family for 7 days (DNS is slow and does not change by the minute)
        if ($family !== '' && (empty($prev['verified_at']) || ($prev['family'] ?? '') !== $family || $now - (int)$prev['verified_at'] > 7 * 86400)) {
            $v = $verify($ip, $family);
            $b['verified'] = (bool)$v['verified']; $b['how'] = (string)$v['how']; $b['host'] = (string)$v['host']; $b['why'] = (string)$v['why']; $b['verified_at'] = $now;
        } else { $b['verified_at'] = (int)($prev['verified_at'] ?? 0); }
        $manual = $b['decided_by'] !== '' && $b['decided_by'] !== 'auto';
        if ($manual) {
            if ($b['status'] === 'allowed' && $b['attacks'] > 0) $warnAllowed[] = $ip;   // admin-allowed but now attacking: tell, don't override
            $bots[$ip] = $b; continue;
        }
        if ($b['status'] === 'blocked') { $bots[$ip] = $b; continue; }   // already blocked by us; keep counting only
        if ($b['attacks'] > 0) {
            if ($b['verified'] && $family !== '') {            // a real Googlebot fetching a hacked link is not an attacker; never auto-block a verified crawler
                $b['status'] = 'allowed'; $b['decided_by'] = 'auto'; $warnAllowed[] = $ip;
            } elseif ($b['attacks'] >= $cfg['gray_threshold'] && smpro_bg_never_autoblock($ip)) {
                // A RESIDENTIAL address in the operator's home region, or one on the Intrusion Monitor allow-list:
                // the Intrusion Monitor has never auto-blocked these (an editor at work, a customer on a phone);
                // Bot Guard did, and locked a home-region editor out of the sites. Over the line it goes to the
                // gray list with the reason, and the operator decides.
                if (($prev['status'] ?? '') !== 'gray' || strpos((string)($prev['note'] ?? ''), 'never auto-blocked') === false) $review[] = $ip;
                $b['status'] = 'gray'; $b['decided_by'] = 'auto';
                $b['note'] = 'over the threshold (' . $b['attacks'] . ' in ' . $cfg['window_hours'] . 'h) but a home-region residential / allow-listed address is never auto-blocked — your decision';
            } elseif ($b['attacks'] >= $cfg['gray_threshold']) {
                $b['status'] = 'block'; $b['decided_by'] = 'auto'; $b['decided_at'] = $now;
                $toBlock[$ip] = $b['attacks'] . ' attack-signature requests in ' . $cfg['window_hours'] . 'h (' . implode(', ', array_keys($b['cats'])) . ')';
            } else {
                if (($prev['status'] ?? '') !== 'gray') $newGray[] = $ip;
                $b['status'] = 'gray'; $b['decided_by'] = 'auto';
            }
        } elseif ($family !== '' && $b['verified'] && $cfg['allow_verified']) {
            $b['status'] = 'allowed'; $b['decided_by'] = 'auto'; if (!$b['decided_at']) $b['decided_at'] = $now;
        } elseif ($b['status'] === 'gray' && $b['attacks'] === 0) {
            $b['status'] = 'pending';                           // the window rolled past its last bad request
        } else {
            if (($prev['status'] ?? '') === '') $newPending[] = $ip;
            $b['status'] = $b['status'] ?: 'pending';
        }
        $bots[$ip] = $b;
    }
    // forget untouched entries older than 30 days that carry no admin decision
    foreach ($bots as $ip => $b) if (($b['decided_by'] ?? '') === 'auto' || ($b['decided_by'] ?? '') === '') { $age = $now - (int)($b['seen'] ?? 0); if (($b['status'] ?? '') !== 'blocked' ? $age > 30 * 86400 : $age > 14 * 86400) unset($bots[$ip]); }   // blocked rows age out too: csf.deny / im_blocked.json are the authority, the state file is not a second firewall
    $state['bots'] = $bots; $state['last_scan'] = $now; $state['last_files'] = (int)($scan['files'] ?? 0); $state['last_lines'] = (int)($scan['lines'] ?? 0); $state['last_waf'] = (int)($scan['waf'] ?? 0);
    return ['state' => $state, 'to_block' => $toBlock, 'new_pending' => $newPending, 'new_gray' => $newGray, 'warn_allowed' => $warnAllowed, 'review' => $review];
}

/* ---------------- the verdict: what this bot is, why, and what blocking it would cost ---------------- */
/**
 * Pure. Turns one state row into a verdict an operator can act on without decoding it.
 *   verdict: trusted | impersonator | attacker | suspicious | scraper | harmless | unknown
 */
function smpro_bg_assess(array $b, array $cfg = []): array {
    $cat = smpro_bg_catalog(); $fam = (string)($b['family'] ?? ''); $f = $cat[$fam] ?? null; $kind = $f['kind'] ?? '';
    $ver = !empty($b['verified']); $att = (int)($b['attacks'] ?? 0); $hits = (int)($b['hits'] ?? 0); $hph = (float)($b['hits_per_hour'] ?? 0);
    $thr = (int)($cfg['gray_threshold'] ?? 25); $why = []; $cost = ''; $status = (string)($b['status'] ?? '');
    $costByKind = ['search' => 'blocking it removes your customers\' sites from that search engine over time',
                   'social' => 'blocking it breaks link previews when the sites are shared there',
                   'monitor' => 'blocking it makes the customer\'s uptime checks report the site as down',
                   'seo' => 'blocking it only stops a third-party SEO tool from indexing the sites; no visitor is lost',
                   'ai' => 'blocking it stops the sites\' content being read for AI answers; it sends no visitors, so nothing is lost but a possible mention',
                   'archive' => 'blocking it stops the sites being archived; no visitors are involed'];
    if ($fam !== '' && $ver) {
        $verdict = 'trusted'; $what = ($f['name'] ?? $fam) . ' (' . smpro_bg_kind_label($kind) . ')';
        $why[] = 'identity verified by ' . (($b['how'] ?? '') === 'range' ? 'the publisher\'s IP ranges' : 'forward-confirmed reverse DNS (' . ($b['host'] ?? '') . ')') . ' — this really is ' . ($f['name'] ?? $fam);
        if ($att > 0) $why[] = $att . ' of its requests looked bad: a real crawler follows links it finds, including links a hacked page planted — it is not the attacker';
        $cost = $costByKind[$kind] ?? '';
    } elseif ($fam !== '' && !$ver && !$f['rdns'] && $f['ranges'] !== '' && (!function_exists('smpro_fw_allow_ranges') || !smpro_fw_allow_ranges($f['ranges']))) {
        $verdict = 'unknown'; $what = 'Says ' . ($f['name'] ?? $fam) . ' - not checked yet';
        $why[] = 'this publisher is verified by its published IP ranges, and the range list has not been fetched on this server yet (it is fetched by the next scan)';
        $cost = $costByKind[$kind] ?? 'unknown';
    } elseif ($fam !== '' && !$ver && ($f['rdns'] || $f['ranges'] !== '')) {
        $verdict = 'impersonator'; $what = 'Claims to be ' . ($f['name'] ?? $fam) . ' but is not';
        $why[] = 'the User-Agent says ' . ($f['name'] ?? $fam) . ', but ' . (($b['why'] ?? '') !== '' ? $b['why'] : 'the address does not verify');
        $why[] = 'a fake crawler identity is used to slip past robots.txt and rate limits — treat as hostile';
        $cost = 'none: the real ' . ($f['name'] ?? $fam) . ' comes from verified addresses and is unaffected';
    } elseif ($att >= $thr || $status === 'blocked' || $status === 'block') {
        $verdict = 'attacker'; $what = 'Attack traffic';
        $why[] = $att . ' attack-signature requests (' . implode(', ', array_keys((array)($b['cats'] ?? []))) . ')' . ($att >= $thr ? ' — past the threshold of ' . $thr : '');
        $cost = 'none';
    } elseif ($att > 0) {
        $verdict = 'suspicious'; $what = 'Probing';
        $why[] = $att . ' bad request' . ($att === 1 ? '' : 's') . ' out of ' . $hits . ' (' . (int)($b['bad_ratio'] ?? 0) . '%): ' . implode(', ', array_keys((array)($b['cats'] ?? []))) . '; auto-block at ' . $thr;
        $cost = 'none';
    } elseif ($fam !== '') {
        $verdict = $kind === 'ai' || $kind === 'seo' ? 'scraper' : 'unknown'; $what = ($f['name'] ?? $fam) . ' (' . smpro_bg_kind_label($kind) . ', unverifiable)';
        $why[] = 'this publisher offers no reverse-DNS or IP-range verification, so the identity cannot be confirmed; it has sent no bad request';
        $cost = $costByKind[$kind] ?? 'unknown';
    } elseif ($hph >= 200) {
        $verdict = 'scraper'; $what = 'Heavy automated client';
        $why[] = 'about ' . (int)$hph . ' requests per hour across ' . (int)($b['domains'] ?? 0) . ' domain(s) with a tool/script User-Agent — bulk scraping, not a visitor';
        $cost = 'none for visitors; it may be a customer\'s own script — the domains it hits tell you';
    } elseif ($hits <= 20) {
        $verdict = 'harmless'; $what = 'Light automated client';
        $why[] = 'a script or tool User-Agent with ' . $hits . ' request(s) and nothing bad — a checker, a feed reader, or a one-off fetch';
        $cost = 'none';
    } else {
        $verdict = 'unknown'; $what = 'Unidentified automated client';
        $why[] = $hits . ' requests, no bad ones, no known identity — decide from the domains and URLs it touches';
        $cost = 'unknown';
    }
    $labels = ['trusted' => 'Verified crawler', 'impersonator' => 'Impersonating a crawler', 'attacker' => 'Attacker', 'suspicious' => 'Suspicious', 'scraper' => 'Scraper', 'harmless' => 'Harmless', 'unknown' => 'Unknown'];
    $advice = ['trusted' => 'keep allowed', 'impersonator' => 'block', 'attacker' => 'block', 'suspicious' => 'watch; block if it continues', 'scraper' => 'allow or block by policy', 'harmless' => 'ignore', 'unknown' => 'look at its URLs, then decide'];
    return ['verdict' => $verdict, 'label' => $labels[$verdict], 'what' => $what, 'why' => $why, 'cost' => $cost, 'advice' => $advice[$verdict]];
}
function smpro_bg_rank(string $v): int { return ['impersonator' => 0, 'attacker' => 1, 'suspicious' => 2, 'scraper' => 3, 'unknown' => 4, 'harmless' => 5, 'trusted' => 6][$v] ?? 4; }

/** Daily history buckets (last 14 days) for the 7-day summary. */
function smpro_bg_history_note(array &$state, array $patch): void {
    $d = date('Y-m-d'); $h = is_array($state['history'] ?? null) ? $state['history'] : [];
    $row = $h[$d] ?? ['tracked' => 0, 'new_pending' => 0, 'autoblocked' => 0, 'manual_blocked' => 0, 'allowed' => 0, 'top' => []];
    foreach (['tracked', 'new_pending', 'autoblocked', 'manual_blocked', 'allowed'] as $k) if (isset($patch[$k])) $row[$k] = $k === 'tracked' ? (int)$patch[$k] : (int)$row[$k] + (int)$patch[$k];
    if (!empty($patch['top'])) { foreach ((array)$patch['top'] as $ip => $n) $row['top'][$ip] = max((int)($row['top'][$ip] ?? 0), (int)$n); arsort($row['top']); $row['top'] = array_slice($row['top'], 0, 5, true); }
    $h[$d] = $row; krsort($h); $state['history'] = array_slice($h, 0, 14, true);
}

/* ---------------- the run (worker + "Scan now") ---------------- */
/** Make sure every range feed the catalogue verifies by is on disk (fetched at most once a day). */
function smpro_bg_ranges_warm(): void {
    if (!function_exists('smpro_fw_allow_fetch') || !function_exists('smpro_fw_allow_synced_at')) return;
    $need = [];
    foreach (smpro_bg_catalog() as $f) if (($f['ranges'] ?? '') !== '') $need[$f['ranges']] = 1;
    foreach (array_keys($need) as $k) { if (time() - (int)smpro_fw_allow_synced_at($k) > 86400) { try { smpro_fw_allow_fetch($k); } catch (\Throwable $e) { if (function_exists('smpro_soft_fail')) smpro_soft_fail('bg_ranges_' . $k, $e); } } }
}
function smpro_bg_run(bool $manual = false): array {
    smpro_bg_ranges_warm();
    $cfg = smpro_bg_cfg();
    if (!$manual && empty($cfg['enabled'])) return ['ok' => false, 'msg' => 'Bot Guard is off.'];
    if (!function_exists('smpro_fw_allow_covers')) { $fw = __DIR__ . '/fwallow.php'; if (@is_file($fw)) require_once $fw; }   // range verification + allow-list awareness
    $t0 = microtime(true);
    $scan = smpro_bg_scan($cfg);
    $d = smpro_bg_decide($scan, $cfg, smpro_bg_state(), fn($ip, $fam) => smpro_bg_verify($ip, $fam));
    $state = $d['state']; $blocked = []; $would = []; $refused = [];
    $dry = function_exists('smpro_ctl_dry_run') && smpro_ctl_dry_run();
    foreach ($d['to_block'] as $ip => $why) {
        if (!$cfg['auto_block'] || $dry) { $state['bots'][$ip]['status'] = 'gray'; $state['bots'][$ip]['note'] = ($dry ? 'Dry-Run: would block — ' : 'auto-block off — over threshold: ') . $why; $would[] = $ip; continue; }
        $r = function_exists('smpro_im_block_ip') ? smpro_im_block_ip($ip, 'Bot Guard: ' . $why) : ['ok' => false, 'msg' => 'block function unavailable'];
        if (!empty($r['ok'])) { $state['bots'][$ip]['status'] = 'blocked'; $state['bots'][$ip]['decided_at'] = time(); $state['bots'][$ip]['note'] = $why . ' → ' . (string)($r['msg'] ?? 'blocked'); $blocked[] = $ip; smpro_bg_log("autoblock $ip: $why → " . (string)($r['msg'] ?? '')); }
        else { $state['bots'][$ip]['status'] = 'gray'; $state['bots'][$ip]['note'] = 'block refused: ' . (string)($r['msg'] ?? '?'); $refused[] = $ip . ' (' . (string)($r['msg'] ?? '?') . ')'; smpro_bg_log("autoblock refused $ip: " . (string)($r['msg'] ?? '')); }
    }
    if ($cfg['firewall_allow_verified'] && function_exists('smpro_csf_allow_add')) {
        foreach ($state['bots'] as $ip => $b) if ($b['status'] === 'allowed' && !empty($b['verified']) && empty($b['fw_allowed'])) { $r = @smpro_csf_allow_add($ip, 'SM Pro Bot Guard: verified ' . $b['name']); if (!empty($r['ok'])) $state['bots'][$ip]['fw_allowed'] = time(); }
    }
    // country / network once per address (offline database; cached in the row)
    foreach ($state['bots'] as $ip => $b) if (($b['country'] ?? '') === '' && function_exists('smpro_ip_intel')) { $i = smpro_ip_intel($ip, false); $state['bots'][$ip]['country'] = strtoupper((string)($i['country'] ?? '')); $state['bots'][$ip]['provider'] = (string)($i['provider'] ?? ''); }
    $topAtt = []; foreach ($scan['ips'] as $ip => $a) if ($a['attacks'] > 0) $topAtt[$ip] = (int)$a['attacks']; arsort($topAtt);
    smpro_bg_history_note($state, ['tracked' => count($scan['ips']), 'new_pending' => count($d['new_pending']), 'autoblocked' => count($blocked), 'top' => array_slice($topAtt, 0, 5, true)]);
    // The scan took up to two minutes; an operator who pressed Allow / Ignore / Reset meanwhile must not be overwritten
    // by this pass's stale copy. Their rows win.
    $fresh = smpro_bg_state();
    foreach ((array)($fresh['bots'] ?? []) as $ip => $b) if (!in_array((string)($b['decided_by'] ?? ''), ['auto', ''], true)) $state['bots'][$ip] = $b;
    smpro_bg_state_save($state);
    $pending = count(array_filter($state['bots'], fn($b) => $b['status'] === 'pending'));
    if (function_exists('smpro_notify')) {
        if (!empty($d['review'])) smpro_notify('bot_autoblock', count($d['review']) . ' home-region address(es) over the Bot Guard threshold — NOT blocked, your decision',
            "These addresses crossed the attack-signature threshold but are residential addresses in your home region (or on the allow-list), which Bot Guard never blocks on its own — an editor at work looks like this when the WAF logs their admin requests.\n"
            . implode("\n", array_map(fn($ip) => "  $ip — " . (string)($state['bots'][$ip]['country'] ?? '') . ' · ' . (int)($state['bots'][$ip]['attacks'] ?? 0) . ' flagged request(s) · ' . substr((string)($state['bots'][$ip]['ua'] ?? ''), 0, 60), $d['review']))
            . "\n\nOpen Bot Guard › Gray list: Block if it really is an attacker, Allow or Ignore if it is a person.", ['severity' => 'medium']);
        if ($blocked) smpro_notify('bot_autoblock', 'Bot Guard auto-blocked ' . count($blocked) . ' address(es)', "Gray-listed addresses crossed the threshold of {$cfg['gray_threshold']} attack-signature requests in {$cfg['window_hours']}h and were blocked:\n" . implode("\n", array_map(fn($ip) => "  $ip — " . ($state['bots'][$ip]['note'] ?? ''), $blocked)) . ($refused ? "\nRefused (safety guard): " . implode('; ', $refused) : '') . "\nReview: WHM → SM Pro → Bot Guard.", ['severity' => 'high']);
        // GROUPED: one line per identity with its address count. Sent only when an identity appears that was not in the
        // last notice - a known crawler gaining addresses is not news - and never more than once in six hours.
        $groups = [];
        foreach ($state['bots'] as $gip => $gb) if (($gb['status'] ?? '') === 'pending') { $gk = smpro_bg_identity($gb); $groups[$gk] = ($groups[$gk] ?? 0) + 1; }
        arsort($groups);
        $known = array_flip((array)($state['pending_groups_notified'] ?? []));
        $newGroups = array_values(array_filter(array_keys($groups), fn($g) => !isset($known[$g])));
        if ($newGroups && (time() - (int)($state['last_pending_notice'] ?? 0)) > 6 * 3600) {
            $state['last_pending_notice'] = time(); $state['pending_groups_notified'] = array_slice(array_keys($groups), 0, 2000); smpro_bg_state_save($state);
            $lines = [];
            foreach (array_slice($newGroups, 0, 10) as $g) $lines[] = '  NEW  ' . $g . ' — ' . $groups[$g] . ' address' . ($groups[$g] === 1 ? '' : 'es');
            if (count($newGroups) > 10) $lines[] = '  … and ' . (count($newGroups) - 10) . ' more new identities';
            smpro_notify('bot_pending', count($newGroups) . ' new crawler identit' . (count($newGroups) === 1 ? 'y' : 'ies') . ' awaiting your decision (' . count($groups) . ' identities, ' . $pending . ' addresses in all)',
                "Automated clients that could not be verified as official crawlers, grouped by who they are:\n" . implode("\n", $lines)
                . "\nDecide per group (Allow / Block / Ignore the whole group) in WHM → SM Pro → Bot Guard - grouping is on by default.", ['severity' => 'medium']);
        } elseif (!$groups) $state['pending_groups_notified'] = [];
    }
    if (function_exists('smpro_audit')) @smpro_audit('botguard_scan', ['manual' => $manual ? 1 : 0, 'files' => $scan['files'], 'lines' => $scan['lines'], 'tracked' => count($scan['ips']), 'blocked' => count($blocked), 'would' => count($would), 'pending' => $pending, 'secs' => round(microtime(true) - $t0, 1)]);
    return ['ok' => true, 'files' => $scan['files'], 'lines' => $scan['lines'], 'waf' => $scan['waf'], 'tracked' => count($scan['ips']), 'blocked' => $blocked, 'would_block' => $would, 'refused' => $refused,
            'new_pending' => count($d['new_pending']), 'new_gray' => count($d['new_gray']), 'warn_allowed' => $d['warn_allowed'], 'pending' => $pending, 'secs' => round(microtime(true) - $t0, 1),
            'msg' => 'Scanned ' . $scan['files'] . ' log(s), ' . number_format($scan['lines']) . ' lines' . ($scan['waf'] ? ' + ' . $scan['waf'] . ' WAF events' : '') . ' → ' . count($scan['ips']) . ' automated client(s); blocked ' . count($blocked) . ($would ? ', would block ' . count($would) : '') . ', ' . $pending . ' awaiting decision.'];
}

/* ---------------- admin actions ---------------- */
function smpro_bg_action(string $act, string $ip, string $by, array $opt = []): array {
    $ip = trim($ip); if (!filter_var($ip, FILTER_VALIDATE_IP)) return ['ok' => false, 'msg' => 'Invalid IP.'];
    $st = smpro_bg_state(); $b = $st['bots'][$ip] ?? ['ip' => $ip, 'ua' => '', 'family' => '', 'name' => '', 'kind' => '', 'hits' => 0, 'attacks' => 0, 'cats' => [], 'domains' => 0, 'sample' => '', 'first' => time(), 'last' => time(), 'seen' => time(), 'status' => '', 'verified' => false, 'how' => '', 'host' => '', 'why' => '', 'note' => '', 'attacks_total' => 0];
    $msg = ''; $ok = true;
    switch ($act) {
        case 'allow':
            $b['status'] = 'allowed'; $b['decided_by'] = $by; $b['decided_at'] = time(); $b['note'] = 'allowed by ' . $by;
            $msg = $ip . ' allowed — exempt from Bot Guard actions.';
            if (!empty($opt['firewall']) && function_exists('smpro_csf_allow_add')) { $r = smpro_csf_allow_add($ip, 'SM Pro Bot Guard: allowed by ' . $by); if (!empty($r['ok'])) { $b['fw_allowed'] = time(); $msg .= ' Added to csf.allow.'; } else $msg .= ' (csf.allow: ' . (string)($r['msg'] ?? 'failed') . ')'; }
            if (function_exists('smpro_csf_denied') && smpro_csf_denied($ip) && function_exists('smpro_csf_do')) { $u = smpro_csf_do('unblock', $ip); if (!empty($u['ok'])) { $msg .= ' Removed from csf.deny.'; if (function_exists('smpro_im_blocked_forget')) @smpro_im_blocked_forget($ip); } }
            break;
        case 'block':
            // The one deliberate path: the operator is looking at this bot, at its verification status and at what
            // blocking it would cost, and pressed Block anyway. So it goes past the crawler shield — but only from
            // here, and only when the page has already said what it is.
            $r = function_exists('smpro_fw_block_ip') ? smpro_fw_block_ip($ip, 'Bot Guard: blocked by ' . $by, true)
               : (function_exists('smpro_im_block_ip') ? smpro_im_block_ip($ip, 'Bot Guard: blocked by ' . $by) : ['ok' => false, 'msg' => 'block function unavailable']);
            if (!empty($r['ok'])) { $b['status'] = 'blocked'; $b['decided_by'] = $by; $b['decided_at'] = time(); $b['note'] = 'blocked by ' . $by . ' → ' . (string)($r['msg'] ?? ''); $msg = (string)($r['msg'] ?? ($ip . ' blocked.')); smpro_bg_history_note($st, ['manual_blocked' => 1]); }
            else { $ok = false; $msg = 'Block refused: ' . (string)($r['msg'] ?? '?'); }
            break;
        case 'ignore':
            $b['status'] = 'ignored'; $b['decided_by'] = $by; $b['decided_at'] = time(); $b['note'] = 'ignored by ' . $by; $msg = $ip . ' ignored — it will not be raised again (still counted).';
            break;
        case 'deny':   // "not a legitimate bot" without blocking: keeps it out of pending, no firewall change
            $b['status'] = 'denied'; $b['decided_by'] = $by; $b['decided_at'] = time(); $b['note'] = 'marked not legitimate by ' . $by; $msg = $ip . ' marked as not legitimate — it will be gray-listed on its first bad request and blocked at the threshold.';
            $b['decided_by'] = 'auto';   // hand it back to the automatic rules from here on
            break;
        case 'unblock':
            $u = function_exists('smpro_csf_do') ? smpro_csf_do('unblock', $ip) : ['ok' => false, 'msg' => 'csf unavailable'];
            if (function_exists('smpro_im_blocked_forget')) @smpro_im_blocked_forget($ip);
            $b['status'] = 'ignored'; $b['decided_by'] = $by; $b['decided_at'] = time(); $b['note'] = 'unblocked by ' . $by . ' → ' . (string)($u['msg'] ?? '');
            $ok = !empty($u['ok']); $msg = (string)($u['msg'] ?? ($ip . ' unblocked.')) . ' It is now ignored; use Reset to let the rules judge it again.';
            break;
        case 'verify':
            if (!function_exists('smpro_fw_allow_covers')) { $fw = __DIR__ . '/fwallow.php'; if (@is_file($fw)) require_once $fw; }
            $fam = (string)($b['family'] ?? ''); if ($fam === '' && $b['ua'] !== '') $fam = smpro_bg_family((string)$b['ua']);
            if ($fam === '') { $st['bots'][$ip] = $b; smpro_bg_state_save($st); return ['ok' => true, 'msg' => $ip . ': no crawler family claimed in its User-Agent, so there is nothing to verify against.', 'verified' => false]; }
            $v = smpro_bg_verify($ip, $fam);
            $b['family'] = $fam; $b['verified'] = (bool)$v['verified']; $b['how'] = (string)$v['how']; $b['host'] = (string)$v['host']; $b['why'] = (string)$v['why']; $b['verified_at'] = time();
            $st['bots'][$ip] = $b; smpro_bg_state_save($st); smpro_bg_log("verify $ip ($fam) by $by: " . ($v['verified'] ? 'verified via ' . $v['how'] : 'NOT verified: ' . $v['why']));
            return ['ok' => true, 'verified' => (bool)$v['verified'], 'msg' => $ip . ' → ' . ($v['verified'] ? 'VERIFIED ' . (smpro_bg_catalog()[$fam]['name'] ?? $fam) . ' (' . $v['why'] . ')' : 'NOT verified as ' . (smpro_bg_catalog()[$fam]['name'] ?? $fam) . ': ' . $v['why'])];
        case 'reset':
            unset($st['bots'][$ip]); smpro_bg_state_save($st); smpro_bg_log("reset $ip by $by");
            if (function_exists('smpro_audit')) @smpro_audit('botguard_action', ['act' => 'reset', 'ip' => $ip, 'by' => $by]);
            return ['ok' => true, 'msg' => $ip . ' forgotten — the next scan judges it afresh.'];
        default: return ['ok' => false, 'msg' => 'Unknown action.'];
    }
    $st['bots'][$ip] = $b; smpro_bg_state_save($st);
    smpro_bg_log("$act $ip by $by: $msg");
    if (function_exists('smpro_audit')) @smpro_audit('botguard_action', ['act' => $act, 'ip' => $ip, 'by' => $by, 'ok' => $ok ? 1 : 0]);
    return ['ok' => $ok, 'msg' => $msg, 'status' => $b['status']];
}

/** Apply one action to many addresses (bulk bar). Capped; each address goes through the single-address path. */
function smpro_bg_bulk(string $act, array $ips, string $by, array $opt = []): array {
    $ips = array_values(array_unique(array_filter(array_map('trim', $ips), fn($x) => filter_var($x, FILTER_VALIDATE_IP))));
    if (!$ips) return ['ok' => false, 'msg' => 'No valid addresses.'];
    if (count($ips) > 200) return ['ok' => false, 'msg' => 'At most 200 addresses per bulk action.'];
    $ok = 0; $fail = [];
    foreach ($ips as $ip) { $r = smpro_bg_action($act, $ip, $by, $opt); if (!empty($r['ok'])) $ok++; else $fail[] = $ip . ' (' . (string)($r['msg'] ?? '?') . ')'; }
    return ['ok' => $ok > 0, 'done' => $ok, 'msg' => ucfirst($act) . ': ' . $ok . ' of ' . count($ips) . ' done.' . ($fail ? ' Failed: ' . implode('; ', array_slice($fail, 0, 5)) . (count($fail) > 5 ? ' …' : '') : '')];
}

/** CSV rows for export (header + one row per bot, verdict included). */
function smpro_bg_export_rows(array $state, array $cfg): array {
    $rows = [['ip', 'status', 'verdict', 'what', 'family', 'kind', 'verified', 'how', 'rdns', 'country', 'provider', 'user_agent', 'hits', 'attacks', 'bad_ratio_pct', 'hits_per_hour', 'domains', 'top_domains', 'categories', 'last_urls', 'first_seen', 'last_seen', 'decided_by', 'note']];
    foreach ($state['bots'] as $ip => $b) {
        $as = smpro_bg_assess($b, $cfg); $cats = (array)($b['cats'] ?? []); arsort($cats);
        $rows[] = [$ip, (string)($b['status'] ?? ''), $as['verdict'], $as['what'], (string)($b['name'] ?? ''), (string)($b['kind'] ?? ''), !empty($b['verified']) ? 'yes' : 'no', (string)($b['how'] ?? ''), (string)($b['host'] ?? ''),
                   (string)($b['country'] ?? ''), (string)($b['provider'] ?? ''), (string)($b['ua'] ?? ''), (int)($b['hits'] ?? 0), (int)($b['attacks'] ?? 0), (int)($b['bad_ratio'] ?? 0), (float)($b['hits_per_hour'] ?? 0), (int)($b['domains'] ?? 0),
                   implode(' ', array_map(fn($d, $n) => "$d($n)", array_keys((array)($b['domains_top'] ?? [])), (array)($b['domains_top'] ?? []))), implode(' ', array_map(fn($c, $n) => "$c($n)", array_keys($cats), $cats)), implode(' | ', (array)($b['urls'] ?? [])),
                   !empty($b['first']) ? date('Y-m-d H:i', (int)$b['first']) : '', !empty($b['last']) ? date('Y-m-d H:i', (int)$b['last']) : '', (string)($b['decided_by'] ?? ''), (string)($b['note'] ?? '')];
    }
    return $rows;
}

/* ---------------- cron ---------------- */
function smpro_bg_cron_sync(): bool {
    // A test must never install a live cron. The shared writer refuses too, but a test that loads only
    // this file has no shared writer to refuse - function_exists() is false and the fallback writes
    // /etc/cron.d directly. The lab caught exactly that, restored the file, and went red at random.
    if (defined('SMPRO_TEST_SRC')) return true;
    $f = '/etc/cron.d/smpro-botguard'; $cfg = smpro_bg_cfg();
    if (empty($cfg['enabled'])) { if (@is_file($f)) @unlink($f); return true; }
    $bin = SMPRO_BASE . '/bin/botguard_tick.php'; if (!@is_file($bin)) return false;
    $php = function_exists('smpro_php_cli_bin') ? smpro_php_cli_bin() : (is_executable('/usr/local/cpanel/3rdparty/bin/php') ? '/usr/local/cpanel/3rdparty/bin/php' : 'php');
    $lockDir = defined('SMPRO_LOCKS') ? SMPRO_LOCKS : (SMPRO_VARLIB . '/locks'); @is_dir($lockDir) || @mkdir($lockDir, 0700, true);
    $flock = is_executable('/usr/bin/flock') ? '/usr/bin/flock' : 'flock';
    $every = (int)$cfg['scan_minutes']; $expr = $every < 60 ? ('*/' . $every . ' * * * *') : ('7 */' . max(1, intdiv($every, 60)) . ' * * *');
    $desired = "# Safety Monitor Pro — Bot Guard scan (verify crawlers, gray-list attackers, auto-block past threshold) every {$every} min\n"
             . "$expr root $flock -n " . $lockDir . "/botguard.lock timeout 600 nice -n 10 $php $bin >/dev/null 2>&1\n";
    return function_exists('smpro_cron_install') ? smpro_cron_install($f, $desired) : (@file_put_contents($f, $desired) !== false && @chmod($f, 0644));
}
