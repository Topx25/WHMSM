<?php
/**
 * t53_botguard.php — Bot Guard core (includes/botguard.php), pure parts with injected DNS.
 *   U90 parse_line     — cPanel combined-log line → fields; garbage → null
 *   U91 family / botlike / scanner UA — recognition without trusting the string
 *   U92 classify_req   — exploit / probe / bruteforce / scanner; ordinary fetches never match
 *   U93 verify         — forward-confirmed rDNS: spoofed PTR fails, sibling-domain trick fails, real one passes;
 *                        publishers without rDNS are never "verified"
 *   U94 decide         — verified→allowed, unverified→pending, attacks→gray, threshold→block, admin decisions
 *                        survive, a verified crawler with bad URLs is warned about but never auto-blocked,
 *                        ignore list respected, window roll-off gray→pending
 *   U95 aggregate/scan shape — ordinary visitors are not tracked at all
 *   U96 cron expression + config clamps
 */
require __DIR__ . '/../support/bootstrap.php';
require SMPRO_BASE . '/tests/support/plugin_funcs.php';
smpro_plugin_funcs('includes/helpers.php');
smpro_plugin_funcs('includes/botguard.php');

ok(function_exists('smpro_bg_decide') && function_exists('smpro_bg_verify') && function_exists('smpro_bg_classify_req'), 'U90: botguard core loaded router-free');

/* ---------- U90 parse ---------- */
$L = '203.0.113.7 - - [06/Sep/2026:14:05:07 +0000] "GET /wp-login.php HTTP/1.1" 200 1234 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"';
$r = smpro_bg_parse_line($L);
ok(is_array($r), 'U90: combined line parses');
is_eq($r['ip'], '203.0.113.7', 'U90: ip'); is_eq($r['method'], 'GET', 'U90: method'); is_eq($r['uri'], '/wp-login.php', 'U90: uri'); is_eq($r['status'], 200, 'U90: status');
is_eq($r['ts'], gmmktime(14, 5, 7, 9, 6, 2026), 'U90: Apache DD/Mon/YYYY:HH:MM:SS timestamp');
has($r['ua'], 'Googlebot', 'U90: user-agent captured');
is_eq(smpro_bg_parse_line('garbage line'), null, 'U90: garbage → null');
$r2 = smpro_bg_parse_line('203.0.113.8 - - [06/Sep/2026:14:05:07 +0000] "-" 408 0 "-" "-"');
ok(is_array($r2) && $r2['uri'] === '-' && $r2['ua'] === '-', 'U90: empty request/UA line still parses');

/* ---------- U91 recognition ---------- */
is_eq(smpro_bg_family('Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'), 'googlebot', 'U91: Googlebot family');
is_eq(smpro_bg_family('Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)'), 'bingbot', 'U91: bingbot family');
is_eq(smpro_bg_family('GPTBot/1.0'), 'openai', 'U91: GPTBot family');
is_eq(smpro_bg_family('Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0'), '', 'U91: a browser has no family');
ok(smpro_bg_is_botlike('python-requests/2.31'), 'U91: python-requests is bot-like');
ok(smpro_bg_is_botlike('-'), 'U91: empty UA is bot-like (a script)');
ok(smpro_bg_is_botlike('Mozilla/5.0 (compatible; SomethingBot/1.0)'), 'U91: unknown *Bot is bot-like');
ok(!smpro_bg_is_botlike('Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Safari/604.1'), 'U91: Safari is not bot-like');
ok(smpro_bg_scanner_ua('sqlmap/1.7#stable'), 'U91: sqlmap is a scanner UA');
ok(smpro_bg_scanner_ua('Mozilla/5.0 (Nikto/2.1.6)'), 'U91: nikto is a scanner UA');
ok(!smpro_bg_scanner_ua('Mozilla/5.0 (compatible; Googlebot/2.1)'), 'U91: Googlebot is not a scanner UA');

/* ---------- U92 classify ---------- */
is_eq(smpro_bg_classify_req('GET', '/index.php?id=1%20union%20select%201,2,3', 'x'), 'exploit', 'U92: SQL injection → exploit');
is_eq(smpro_bg_classify_req('GET', '/shell.php?cmd=id', 'x'), 'exploit', 'U92: cmd= param → exploit (checked before the path probe)');
is_eq(smpro_bg_classify_req('GET', '/../../etc/passwd', 'x'), 'exploit', 'U92: traversal → exploit');
is_eq(smpro_bg_classify_req('GET', '/.env', 'x'), 'probe', 'U92: .env → probe');
is_eq(smpro_bg_classify_req('GET', '/wp-config.php.bak', 'x'), 'probe', 'U92: wp-config backup → probe');
is_eq(smpro_bg_classify_req('GET', '/phpmyadmin/index.php', 'x'), 'probe', 'U92: phpmyadmin → probe');
is_eq(smpro_bg_classify_req('GET', '/wp-content/uploads/2026/x.php', 'x'), 'probe', 'U92: php under uploads → probe');
is_eq(smpro_bg_classify_req('POST', '/wp-login.php', 'x'), 'bruteforce', 'U92: POST wp-login → bruteforce');
is_eq(smpro_bg_classify_req('POST', '/xmlrpc.php', 'x'), 'probe', 'U92: xmlrpc is a probe path (matched before the login rule)');
is_eq(smpro_bg_classify_req('GET', '/wp-login.php', 'x'), '', 'U92: GET wp-login (the form) is not an attack');
is_eq(smpro_bg_classify_req('GET', '/', 'sqlmap/1.7'), 'scanner', 'U92: scanner UA wins even on /');
is_eq(smpro_bg_classify_req('GET', '/blog/hello-world/', 'Mozilla/5.0'), '', 'U92: ordinary page fetch');
is_eq(smpro_bg_classify_req('GET', '/images/logo.png', 'Googlebot-Image/1.0'), '', 'U92: image fetch');
is_eq(smpro_bg_classify_req('GET', '/feed/', 'Feedly/1.0'), '', 'U92: feed fetch');
is_eq(smpro_bg_classify_req('GET', '/products/select-your-union-jack-flag', 'x'), '', 'U92: "union" and "select" as words in a slug do not match (needs the SQL shape)');

/* ---------- U93 verify with injected DNS ---------- */
$dns = function (array $ptr, array $fwd) { return ['rev' => fn($ip) => $ptr[$ip] ?? '', 'fwd' => fn($h) => $fwd[$h] ?? []]; };
$v = smpro_bg_verify('203.0.113.10', 'googlebot', $dns(['203.0.113.10' => 'crawl-203-0-113-10.googlebot.com'], ['crawl-203-0-113-10.googlebot.com' => ['203.0.113.10']]));
ok($v['verified'] && $v['how'] === 'rdns', 'U93: forward-confirmed rDNS verifies Googlebot');
$v = smpro_bg_verify('203.0.113.11', 'googlebot', $dns(['203.0.113.11' => 'crawl-1.googlebot.com'], ['crawl-1.googlebot.com' => ['203.0.113.99']]));
ok(!$v['verified'], 'U93: PTR that does not resolve back is a spoof → not verified'); has($v['why'], 'does not resolve back', 'U93: reason names the spoof');
$v = smpro_bg_verify('203.0.113.12', 'googlebot', $dns(['203.0.113.12' => 'fakegooglebot.com'], ['fakegooglebot.com' => ['203.0.113.12']]));
ok(!$v['verified'], 'U93: "fakegooglebot.com" is NOT under googlebot.com (dot-boundary match)');
$v = smpro_bg_verify('203.0.113.13', 'googlebot', $dns(['203.0.113.13' => 'googlebot.com.evil.example'], ['googlebot.com.evil.example' => ['203.0.113.13']]));
ok(!$v['verified'], 'U93: suffix trick "googlebot.com.evil" is not under googlebot.com');
$v = smpro_bg_verify('203.0.113.14', 'googlebot', $dns([], []));
ok(!$v['verified'] && $v['why'] === 'no reverse DNS', 'U93: no PTR → not verified, honest reason');
$v = smpro_bg_verify('203.0.113.15', 'twitter', $dns(['203.0.113.15' => 'anything.example'], []));
ok(!$v['verified'], 'U93: a publisher without rDNS verification can never be verified'); has($v['why'], 'no reverse-DNS verification', 'U93: says so');
$v = smpro_bg_verify('203.0.113.16', 'nonsense', $dns([], []));
ok(!$v['verified'], 'U93: unknown family → not verified');
ok(smpro_bg_host_under('a.b.search.msn.com', ['search.msn.com']), 'U93: deep subdomain is under');
ok(!smpro_bg_host_under('search.msn.com.example', ['search.msn.com']), 'U93: appended label is not under');

/* ---------- U94 decide ---------- */
$cfg = array_replace(smpro_bg_defaults(), ['gray_threshold' => 5, 'window_hours' => 24, 'ignore_ips' => ['203.0.113.250']]);
$mk = function (string $ip, string $ua, int $hits, int $attacks, array $cats = []) { return ['ip' => $ip, 'hits' => $hits, 'attacks' => $attacks, 'cats' => $cats, 'uas' => [$ua => $hits], 'domains' => ['a.example' => 1], 'first' => 1000, 'last' => 2000, 'sample' => $attacks ? 'GET /.env' : '', 'botlike' => true]; };
$scan = ['ips' => [
    '203.0.113.20' => $mk('203.0.113.20', 'Mozilla/5.0 (compatible; Googlebot/2.1)', 50, 0),          // verified → allowed
    '203.0.113.21' => $mk('203.0.113.21', 'Mozilla/5.0 (compatible; Googlebot/2.1)', 50, 0),          // spoofed → pending
    '203.0.113.22' => $mk('203.0.113.22', 'python-requests/2.31', 30, 0),                             // unknown bot → pending
    '203.0.113.23' => $mk('203.0.113.23', 'python-requests/2.31', 30, 3, ['probe' => 3]),             // attacks under threshold → gray
    '203.0.113.24' => $mk('203.0.113.24', 'sqlmap/1.7', 40, 40, ['scanner' => 40]),                   // over threshold → block
    '203.0.113.25' => $mk('203.0.113.25', 'Mozilla/5.0 (compatible; Googlebot/2.1)', 50, 9, ['probe' => 9]),  // verified but bad URLs → allowed + warned, never blocked
    '203.0.113.250' => $mk('203.0.113.250', 'sqlmap/1.7', 99, 99, ['scanner' => 99]),                 // ignore list
], 'files' => 3, 'lines' => 100, 'waf' => 0];
$verify = function ($ip, $fam) { return in_array($ip, ['203.0.113.20', '203.0.113.25'], true) ? ['verified' => true, 'how' => 'rdns', 'host' => 'crawl.googlebot.com', 'why' => 'ok'] : ['verified' => false, 'how' => '', 'host' => '', 'why' => 'spoof']; };
$d = smpro_bg_decide($scan, $cfg, ['bots' => []], $verify, 5000);
$B = $d['state']['bots'];
is_eq($B['203.0.113.20']['status'], 'allowed', 'U94: verified Googlebot → allowed'); is_eq($B['203.0.113.20']['decided_by'], 'auto', 'U94: allowed by auto');
is_eq($B['203.0.113.21']['status'], 'pending', 'U94: spoofed Googlebot → pending (never trusted on the UA)');
is_eq($B['203.0.113.22']['status'], 'pending', 'U94: unknown bot with no bad request → pending');
is_eq($B['203.0.113.23']['status'], 'gray', 'U94: 3 attacks under threshold 5 → gray');
is_eq($B['203.0.113.24']['status'], 'block', 'U94: 40 attacks ≥ 5 → block');
has($d['to_block']['203.0.113.24'] ?? '', '40 attack-signature', 'U94: block reason carries the count');
is_eq($B['203.0.113.25']['status'], 'allowed', 'U94: verified crawler with bad URLs is allowed, not blocked');
ok(in_array('203.0.113.25', $d['warn_allowed'], true), 'U94: …but the admin is warned about it');
ok(!isset($B['203.0.113.250']), 'U94: ignore-listed address is not tracked');
is_eq(array_keys($d['to_block']), ['203.0.113.24'], 'U94: exactly one address to block');
sort($d['new_pending']); is_eq($d['new_pending'], ['203.0.113.21', '203.0.113.22'], 'U94: new pending list');
is_eq($d['new_gray'], ['203.0.113.23'], 'U94: new gray list');
// second scan: admin decisions survive, gray rolls off, blocked stays blocked
$st = $d['state']; $st['bots']['203.0.113.24']['status'] = 'blocked';
$st['bots']['203.0.113.22']['status'] = 'allowed'; $st['bots']['203.0.113.22']['decided_by'] = 'root';
$scan2 = ['ips' => [
    '203.0.113.22' => $mk('203.0.113.22', 'python-requests/2.31', 30, 8, ['probe' => 8]),     // admin-allowed, now attacking
    '203.0.113.23' => $mk('203.0.113.23', 'python-requests/2.31', 10, 0),                     // window rolled off
    '203.0.113.24' => $mk('203.0.113.24', 'sqlmap/1.7', 5, 5, ['scanner' => 5]),               // still blocked
], 'files' => 1, 'lines' => 10, 'waf' => 0];
$d2 = smpro_bg_decide($scan2, $cfg, $st, $verify, 6000);
$B2 = $d2['state']['bots'];
is_eq($B2['203.0.113.22']['status'], 'allowed', 'U94: an admin allow is never overturned by a scan');
ok(in_array('203.0.113.22', $d2['warn_allowed'], true), 'U94: …but the admin is told it is now attacking');
is_eq($B2['203.0.113.23']['status'], 'pending', 'U94: gray with no attacks in the new window → back to pending');
is_eq($B2['203.0.113.24']['status'], 'blocked', 'U94: blocked stays blocked; not re-queued for blocking');
is_eq($d2['to_block'], [], 'U94: nothing new to block');
is_eq($B2['203.0.113.24']['attacks_total'], 45, 'U94: lifetime attack counter accumulates (40+5)');
is_eq($B2['203.0.113.20']['status'], 'allowed', 'U94: an address absent from this scan keeps its state');
ok($B2['203.0.113.20']['verified_at'] === 5000, 'U94: verification result is cached, not re-resolved every scan');
// verification cache expiry: 8 days later it re-verifies
$calls = 0; $vCount = function ($ip, $fam) use (&$calls) { $calls++; return ['verified' => true, 'how' => 'rdns', 'host' => 'h', 'why' => 'ok']; };
smpro_bg_decide(['ips' => ['203.0.113.20' => $mk('203.0.113.20', 'Mozilla/5.0 (compatible; Googlebot/2.1)', 1, 0)], 'files' => 0, 'lines' => 0, 'waf' => 0], $cfg, $d2['state'], $vCount, 5000 + 8 * 86400 + 1);
is_eq($calls, 1, 'U94: cached verification expires after 7 days');
// auto-block disabled is a config concern of smpro_bg_run, but decide still reports what crossed the threshold
$d3 = smpro_bg_decide(['ips' => ['203.0.113.30' => $mk('203.0.113.30', '-', 6, 6, ['bruteforce' => 6])], 'files' => 0, 'lines' => 0, 'waf' => 0], $cfg, ['bots' => []], $verify, 7000);
is_eq($d3['state']['bots']['203.0.113.30']['status'], 'block', 'U94: an empty-UA brute-forcer at threshold → block');
// stale entries are forgotten after 30 days, blocked ones kept
$old = ['bots' => ['203.0.113.40' => ['status' => 'pending', 'decided_by' => 'auto', 'seen' => 100], '203.0.113.41' => ['status' => 'blocked', 'decided_by' => 'auto', 'seen' => 100], '203.0.113.42' => ['status' => 'allowed', 'decided_by' => 'root', 'seen' => 100]]];
$d4 = smpro_bg_decide(['ips' => [], 'files' => 0, 'lines' => 0, 'waf' => 0], $cfg, $old, $verify, 100 + 31 * 86400);
ok(!isset($d4['state']['bots']['203.0.113.40']), 'U94: stale auto pending is forgotten after 30 days');
ok(!isset($d4['state']['bots']['203.0.113.41']), 'U94: a blocked row ages out after 14 days (csf.deny is the authority, the state file is not a second firewall)');
$d4b = smpro_bg_decide(['ips' => [], 'files' => 0, 'lines' => 0, 'waf' => 0], $cfg, ['bots' => ['203.0.113.41' => ['status' => 'blocked', 'decided_by' => 'auto', 'seen' => 100]]], $verify, 100 + 10 * 86400);
ok(isset($d4b['state']['bots']['203.0.113.41']), 'U94: ...and is kept inside those 14 days');
ok(isset($d4['state']['bots']['203.0.113.42']), 'U94: admin decisions are kept');

/* ---------- U95 aggregate ---------- */
$ips = [];
smpro_bg_aggregate($ips, smpro_bg_parse_line('203.0.113.50 - - [06/Sep/2026:14:05:07 +0000] "GET /about/ HTTP/1.1" 200 10 "-" "Mozilla/5.0 (Windows NT 10.0) Chrome/120"'), 'a.example', 0);
is_eq($ips, [], 'U95: an ordinary visitor is not tracked');
smpro_bg_aggregate($ips, smpro_bg_parse_line('203.0.113.51 - - [06/Sep/2026:14:05:07 +0000] "GET /.git/config HTTP/1.1" 404 10 "-" "Mozilla/5.0 (Windows NT 10.0) Chrome/120"'), 'a.example', 0);
ok(isset($ips['203.0.113.51']) && $ips['203.0.113.51']['attacks'] === 1 && ($ips['203.0.113.51']['cats']['probe'] ?? 0) === 1, 'U95: a browser-UA probe IS tracked (attack by request, not by UA)');
ok($ips['203.0.113.51']['botlike'] === false, 'U95: …and marked not bot-like');
smpro_bg_aggregate($ips, smpro_bg_parse_line('203.0.113.52 - - [06/Sep/2026:14:05:07 +0000] "GET / HTTP/1.1" 200 10 "-" "curl/8.0"'), 'b.example', 0);
ok(isset($ips['203.0.113.52']) && $ips['203.0.113.52']['attacks'] === 0 && $ips['203.0.113.52']['botlike'], 'U95: a tool UA with a clean request is tracked as a bot');
smpro_bg_aggregate($ips, smpro_bg_parse_line('203.0.113.52 - - [01/Jan/2020:00:00:00 +0000] "GET /.env HTTP/1.1" 404 10 "-" "curl/8.0"'), 'b.example', gmmktime(0, 0, 0, 1, 1, 2026));
is_eq($ips['203.0.113.52']['attacks'], 0, 'U95: a line older than the window cutoff is ignored');
smpro_bg_aggregate($ips, smpro_bg_parse_line('not-an-ip - - [06/Sep/2026:14:05:07 +0000] "GET /.env HTTP/1.1" 404 10 "-" "curl/8.0"'), 'b.example', 0);
ok(!isset($ips['not-an-ip']), 'U95: an invalid address is dropped');

/* ---------- U96 config clamps + cron ---------- */
$c = smpro_bg_cfg_save(['gray_threshold' => 1, 'window_hours' => 999, 'tail_lines' => 5, 'scan_minutes' => 1, 'ignore_ips' => [' 203.0.113.1 ', '']]);
is_eq($c['gray_threshold'], 3, 'U96: threshold floor 3'); is_eq($c['window_hours'], 168, 'U96: window ceiling 168h'); is_eq($c['tail_lines'], 1000, 'U96: tail floor'); is_eq($c['scan_minutes'], 5, 'U96: cadence floor 5 min');
is_eq($c['ignore_ips'], ['203.0.113.1'], 'U96: ignore list trimmed and blanks dropped');
ok(!$c['enabled'], 'U96: ships OFF');
smpro_bg_cfg_save(smpro_bg_defaults());
$src = (string)file_get_contents(SMPRO_BASE . '/includes/botguard.php');
has($src, "'*/' . \$every . ' * * * *'", 'U96: cron expression for sub-hour cadence');
has($src, 'smpro_im_block_ip($ip, \'Bot Guard: \' . $why)', 'U96: auto-block goes through the guarded block path (server IP / Cloudflare / allow-list refusals)');
has($src, 'smpro_ctl_dry_run()', 'U96: Dry-Run is honoured');
$mod = (string)file_get_contents(SMPRO_BASE . '/modules/bot-guard.php');
has($mod, "smpro_require_valid_csrf('bg_action'); smpro_require_root();", 'U96: every POST is CSRF + root gated');
$menu = (string)file_get_contents(SMPRO_BASE . '/includes/menu.php');
has($menu, "'id' => 'bot-guard'", 'U96: registered in the menu'); ok((bool)preg_match("/'bot-guard'\s+=> '1\.\d+\.\d+'/", $menu), 'U96: NEW badge registered (any shipping tag)');
$ntf = (string)file_get_contents(SMPRO_BASE . '/includes/notify.php');
has($ntf, "'bot_autoblock'", 'U96: bot_autoblock notification type'); has($ntf, "'bot_pending'", 'U96: bot_pending notification type');

/* ---------- U97: verdicts, history, bulk, export (2026-09-08: "Bot Guard must be more professional") ---------- */
ok(function_exists('smpro_bg_assess') && function_exists('smpro_bg_bulk') && function_exists('smpro_bg_export_rows') && function_exists('smpro_bg_history_note'), 'U97: new core functions loaded');
$cfgA = smpro_bg_defaults();
$row = fn(array $o) => array_replace(['ip' => '203.0.113.1', 'ua' => 'x', 'family' => '', 'name' => '', 'kind' => '', 'hits' => 10, 'attacks' => 0, 'cats' => [], 'domains' => 1, 'sample' => '', 'first' => 1, 'last' => 2, 'status' => 'pending', 'decided_by' => '', 'verified' => false, 'how' => '', 'host' => '', 'why' => '', 'hits_per_hour' => 0.4, 'bad_ratio' => 0], $o);
$a = smpro_bg_assess($row(['family' => 'googlebot', 'name' => 'Googlebot', 'kind' => 'search', 'verified' => true, 'how' => 'rdns', 'host' => 'crawl.googlebot.com', 'status' => 'allowed']), $cfgA);
is_eq($a['verdict'], 'trusted', 'U97: verified Googlebot → trusted'); has($a['cost'], 'removes your customers', 'U97: cost of blocking a search crawler is stated'); has(implode(' ', $a['why']), 'forward-confirmed reverse DNS (crawl.googlebot.com)', 'U97: names the proof');
$a = smpro_bg_assess($row(['family' => 'googlebot', 'name' => 'Googlebot', 'kind' => 'search', 'verified' => false, 'why' => 'reverse DNS is not under googlebot.com / google.com']), $cfgA);
is_eq($a['verdict'], 'impersonator', 'U97: unverified Googlebot claim → impersonator'); is_eq($a['advice'], 'block', 'U97: advice block'); has($a['cost'], 'unaffected', 'U97: the real crawler is unaffected');
$a = smpro_bg_assess($row(['attacks' => 30, 'cats' => ['probe' => 30], 'hits' => 40, 'bad_ratio' => 75]), $cfgA);
is_eq($a['verdict'], 'attacker', 'U97: past threshold → attacker'); has(implode(' ', $a['why']), 'past the threshold of 25', 'U97: threshold named');
$a = smpro_bg_assess($row(['attacks' => 3, 'cats' => ['exploit' => 3], 'hits' => 50, 'bad_ratio' => 6]), $cfgA);
is_eq($a['verdict'], 'suspicious', 'U97: a few bad requests → suspicious'); has(implode(' ', $a['why']), 'auto-block at 25', 'U97: says when it will be blocked');
$a = smpro_bg_assess($row(['family' => 'bytedance', 'name' => 'Bytespider (ByteDance)', 'kind' => 'ai']), $cfgA);
is_eq($a['verdict'], 'scraper', 'U97: unverifiable AI crawler → scraper'); has($a['cost'], 'sends no visitors', 'U97: AI cost stated');
$a = smpro_bg_assess($row(['hits' => 6000, 'hits_per_hour' => 250, 'domains' => 40]), $cfgA);
is_eq($a['verdict'], 'scraper', 'U97: 250 req/h unknown tool → scraper'); has(implode(' ', $a['why']), 'bulk scraping', 'U97: reason');
$a = smpro_bg_assess($row(['hits' => 3]), $cfgA);
is_eq($a['verdict'], 'harmless', 'U97: 3 clean requests → harmless'); is_eq($a['advice'], 'ignore', 'U97: advice ignore');
$a = smpro_bg_assess($row(['hits' => 80]), $cfgA);
is_eq($a['verdict'], 'unknown', 'U97: 80 clean requests, no identity → unknown');
ok(smpro_bg_rank('impersonator') < smpro_bg_rank('attacker') && smpro_bg_rank('attacker') < smpro_bg_rank('suspicious') && smpro_bg_rank('harmless') < smpro_bg_rank('trusted'), 'U97: rank order for sorting');
$stH = ['bots' => []]; smpro_bg_history_note($stH, ['tracked' => 12, 'new_pending' => 2, 'autoblocked' => 1, 'top' => ['203.0.113.9' => 7]]);
smpro_bg_history_note($stH, ['tracked' => 15, 'new_pending' => 1, 'manual_blocked' => 1, 'top' => ['203.0.113.9' => 9, '203.0.113.8' => 3]]);
$today = $stH['history'][date('Y-m-d')];
is_eq([$today['tracked'], $today['new_pending'], $today['autoblocked'], $today['manual_blocked']], [15, 3, 1, 1], 'U97: history bucket: tracked replaced, counters added');
is_eq($today['top'], ['203.0.113.9' => 9, '203.0.113.8' => 3], 'U97: top attackers keep the max and sort');
$r = smpro_bg_bulk('ignore', ['203.0.113.21', 'not-an-ip', '203.0.113.21'], 'root');
is_eq($r['done'], 1, 'U97: bulk dedupes and drops invalid addresses'); is_eq(smpro_bg_state()['bots']['203.0.113.21']['status'], 'ignored', 'U97: bulk applied the single-address path');
$r = smpro_bg_bulk('ignore', array_map(fn($i) => '203.0.113.' . $i, range(1, 201)), 'root'); ok(!$r['ok'] && strpos($r['msg'], 'At most 200') !== false, 'U97: bulk capped at 200');
$r = smpro_bg_action('verify', '203.0.113.21', 'root'); ok($r['ok'] && $r['verified'] === false && strpos($r['msg'], 'nothing to verify') !== false, 'U97: verify on a bot with no claimed family says so');
$rows = smpro_bg_export_rows(smpro_bg_state(), $cfgA);
is_eq($rows[0][0], 'ip', 'U97: export header'); is_eq(count($rows[0]), 24, 'U97: export columns'); ok(count($rows) >= 2 && in_array('203.0.113.21', array_column($rows, 0), true), 'U97: export carries the rows');
smpro_bg_action('reset', '203.0.113.21', 'root');
$modSrc = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/bot-guard.php'));
foreach (['data-bulk="block"', 'id="bgQ"', 'data-act="verify"', 'export=csv', 'export=html', 'Last 7 days', 'If blocked:', 'last requests'] as $needle) has($modSrc, $needle, "U97: page has $needle");
has($modSrc, "if (\$export === 'csv') {\n    smpro_audit('botguard_export'", 'U97: CSV export is audited');

/* ---------- U98: the ignore list accepts a RANGE, so it must match one (independent review, 2026-09-09) ---------- */
// The settings field is labelled "IPs/CIDRs" and its validator accepts a range, but the scan compared the list
// with a plain string equality — so a range was accepted, displayed as saved, and silently did nothing while
// every address inside it stayed trackable and auto-blockable.
ok(function_exists('smpro_bg_cidr_has') && function_exists('smpro_bg_ip_ignored'), 'U98: range matching exists');
ok(smpro_bg_cidr_has('203.0.113.0/24', '203.0.113.7'), 'U98: v4 address inside the range');
ok(!smpro_bg_cidr_has('203.0.113.0/24', '203.0.114.7'), 'U98: v4 address outside it');
ok(smpro_bg_cidr_has('203.0.113.0/32', '203.0.113.0'), 'U98: /32 is the address itself');
ok(!smpro_bg_cidr_has('203.0.113.0/32', '203.0.113.1'), 'U98: /32 matches nothing else');
ok(smpro_bg_cidr_has('203.0.113.7', '203.0.113.7'), 'U98: a bare address still matches exactly');
ok(!smpro_bg_cidr_has('203.0.113.7', '203.0.113.8'), 'U98: ...and only itself');
ok(smpro_bg_cidr_has('0.0.0.0/0', '198.51.100.1'), 'U98: /0 covers everything');
ok(smpro_bg_cidr_has('2001:db8::/32', '2001:db8::1'), 'U98: v6 range');
ok(!smpro_bg_cidr_has('2001:db8::/32', '2001:db9::1'), 'U98: v6 outside');
ok(!smpro_bg_cidr_has('203.0.113.0/24', '2001:db8::1'), 'U98: a v4 range never matches a v6 address');
ok(!smpro_bg_cidr_has('203.0.113.0/33', '203.0.113.7'), 'U98: an impossible prefix matches nothing');
ok(!smpro_bg_cidr_has('not-a-range', '203.0.113.7'), 'U98: garbage matches nothing');
ok(!smpro_bg_cidr_has('', '203.0.113.7'), 'U98: an empty entry matches nothing');
ok(smpro_bg_ip_ignored('203.0.113.7', ['198.51.100.0/24', '203.0.113.0/24']), 'U98: ip_ignored scans the whole list');
ok(!smpro_bg_ip_ignored('203.0.113.7', ['198.51.100.0/24']), 'U98: ...and says no when nothing covers it');
$cfgR = array_replace(smpro_bg_defaults(), ['gray_threshold' => 5, 'ignore_ips' => ['203.0.113.0/24']]);
$scanR = ['ips' => [
    '203.0.113.30' => $mk('203.0.113.30', 'sqlmap/1.7', 99, 99, ['scanner' => 99]),   // inside the ignored range
    '198.51.100.30' => $mk('198.51.100.30', 'sqlmap/1.7', 99, 99, ['scanner' => 99]), // outside it
], 'files' => 0, 'lines' => 0, 'waf' => 0];
$dR = smpro_bg_decide($scanR, $cfgR, ['bots' => []], $verify, 9000);
ok(!isset($dR['state']['bots']['203.0.113.30']), 'U98: an address inside an ignored RANGE is not tracked at all');
ok(isset($dR['state']['bots']['198.51.100.30']), 'U98: an address outside it still is');
is_eq(array_keys($dR['to_block']), ['198.51.100.30'], 'U98: and only the one outside the range is blocked');

/* ---------- beta300: OpenAI verified by its published ranges; unfetched range feeds never read as impersonation ---------- */
$cat = smpro_bg_catalog();
is_eq($cat['openai']['ranges'], 'openai', 'U97: OpenAI verifies by its published ranges');
is_eq($cat['openai']['rdns'], [], 'U97: ...and not by reverse DNS (the real GPTBot has none)');
require_once SMPRO_BASE . '/includes/fwallow.php';
ok(isset(smpro_fw_allow_providers()['openai']) && count(smpro_fw_allow_providers()['openai']['fetch']) === 3, 'U97: the three OpenAI feeds are a range provider');
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/botguard.php'));
has($src, "'unknown'; \$what = 'Says ' . (\$f['name'] ?? \$fam) . ' - not checked yet';", 'U98: a claimant whose range feed is not on disk is "not checked yet", not an impersonator');
has($src, "function smpro_bg_ranges_warm(): void {", 'U98: the scan fetches the feeds the catalogue relies on');
has($src, "    smpro_bg_ranges_warm();", 'U98: ...at the start of every run');
$mod = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/bot-guard.php'));
has($mod, 'What the verdicts mean, and what to do', 'U99: the page explains every verdict');

/* ---------- beta310: Meta verified by its announced ranges as well as rDNS ---------- */
is_eq($cat['facebook']['ranges'], 'meta', 'U100: Facebook claimants can verify by the Meta ranges');
ok(isset(smpro_fw_allow_providers()['meta']) && smpro_fw_allow_providers()['meta']['fetch_json'] === 'data.prefixes', 'U100: the Meta provider reads the nested RIPEstat list');
$fw = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/fwallow.php'));
has($fw, "foreach (explode('.', (string)\$pv['fetch_json']) as \$seg)", 'U100: the feed parser walks a dotted path');
