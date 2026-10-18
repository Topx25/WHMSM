<?php
/**
 * t57_crawler_shield.php — a block aimed at a real search crawler must be refused.
 *
 * This is the one mistake in the whole firewall that produces NO error and NO symptom: block Googlebot and
 * everything looks fine, the site simply falls out of the index over the following days and nothing on the server
 * ever connects the two events. The confusion that makes it easy is on the firewall page itself — a rented VM in
 * Google Cloud reverse-resolves to *.bc.googleusercontent.com and was labelled "🤖 bot", while Googlebot resolves
 * to *.googlebot.com. One indexes the site; the other was failing cPanel logins.
 *
 * Verification is forward-confirmed reverse DNS, the method the publishers document. The resolvers are injected,
 * so these assertions never touch the network.
 */
require __DIR__ . '/../support/bootstrap.php';
require SMPRO_BASE . '/tests/support/plugin_funcs.php';
smpro_plugin_funcs('includes/botguard.php');

ok(function_exists('smpro_bg_crawler_shield'), 'C0: the shield exists');

/** A fake DNS world: rdns[ip] => host, fwd[host] => [ips]. */
$mk = function (array $rdns, array $fwd) {
    return ['rev' => fn(string $ip) => strtolower((string)($rdns[$ip] ?? '')),
            'fwd' => fn(string $h) => array_map('strtolower', (array)($fwd[strtolower($h)] ?? []))];
};

/* ---------- C1: the real Googlebot is recognised ---------- */
// The verification is on the NAME, never on the address, so the address here is a documentation one: hardcoding
// a crawler's current IP would be a fact that rots, and is exactly what forward-confirmed DNS exists to avoid.
$G = '203.0.113.1';
$res = $mk([$G => 'crawl-203-0-113-1.googlebot.com'], ['crawl-203-0-113-1.googlebot.com' => [$G]]);
$r = smpro_bg_crawler_shield($G, $res);
ok($r['crawler'] === true, 'C1: forward-confirmed googlebot.com -> a real crawler');
is_eq($r['name'], 'Googlebot', 'C1: named, so the refusal can say what it is');
is_eq($r['kind'], 'search', 'C1: and what blocking it would cost');
has($r['why'], 'forward-confirmed', 'C1: with the reason');

/* ---------- C2: a rented machine inside the same company is NOT a crawler ---------- */
// The shape seen on real servers: an address whose reverse name is *.bc.googleusercontent.com, failing cPanel
// logins. Same company as Googlebot, different service — a customer's virtual machine. googleusercontent.com is
// not under googlebot.com or google.com, so no amount of "it says Google" makes this one protected.
// (Documentation-range address: this tree ships to every licensee and carries nobody's real traffic.)
$V = '198.51.100.9';
$r2 = smpro_bg_crawler_shield($V, $mk([$V => 'vm-a1b2c3.bc.googleusercontent.com'], []));
ok($r2['crawler'] === false, 'C2: a rented Google Cloud VM is NOT a crawler — blocking it costs nothing in search');
is_eq($r2['name'], '', 'C2: ...and it is not even claiming to be one');

/* ---------- C3: a spoofed reverse name is a block, not a pass ---------- */
$S = '203.0.113.7';
$r3 = smpro_bg_crawler_shield($S, $mk([$S => 'crawl-evil.googlebot.com'], ['crawl-evil.googlebot.com' => ['203.0.113.1']]));
ok($r3['crawler'] === false, 'C3: reverse DNS claiming Googlebot that does not resolve back is NOT protected');
has($r3['why'], 'claims Googlebot', 'C3: ...and the reason names the spoof, so the log explains the decision');

/* ---------- C4: the ordinary attacker path costs one lookup and protects nobody ---------- */
$A = '198.51.100.23';
$r4 = smpro_bg_crawler_shield($A, $mk([$A => 'vps-1234.example-hosting.net'], []));
ok($r4['crawler'] === false, 'C4: an ordinary host is not a crawler');
$r5 = smpro_bg_crawler_shield('198.51.100.24', $mk([], []));
ok($r5['crawler'] === false, 'C4: no reverse DNS at all -> not a crawler, so a resolver outage never blocks a block');
ok(smpro_bg_crawler_shield('not-an-ip', $mk([], []))['crawler'] === false, 'C4: junk input is not a crawler');

/* ---------- C5: every block on this server passes the shield ---------- */
$fw = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/helpers.php'));
has($fw, "function smpro_fw_block_ip(\$ip, \$reason = '', \$force = false) {", 'C5: the chokepoint takes a deliberate override');
has($fw, "if (!\$isCidr && !\$force) {", 'C5: ...and applies the shield unless it is given');
has($fw, "smpro_audit('firewall_block_refused_crawler'", 'C5: a refusal is recorded, so it is never silent');
has($fw, "'refused: this is really ' . \$cs['name']", 'C5: the message says what the address really is');
has($fw, 'Blocking it removes the site from ', 'C5: ...and what blocking it would have cost');
has($fw, "\$bg = __DIR__ . '/botguard.php'; if (@is_file(\$bg)) require_once \$bg;",
    'C5: the shield is pulled in here — every bin/ worker that blocks loads helpers.php and none loads botguard.php, so a function_exists check alone would have held in the panel and done nothing in the automatic response');

/* ---------- C6: Bot Guard stays the one deliberate way to block a crawler ---------- */
$bg = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/botguard.php'));
has($bg, "smpro_fw_block_ip(\$ip, 'Bot Guard: blocked by ' . \$by, true)",
    'C6: Bot Guard passes the override — the operator is looking at the verification and the cost when they press it');
is_eq(substr_count($fw, '$force'), 3, 'C6: the override exists in exactly one place and is not spread around');

/* ---------- C7: the firewall page no longer calls a rented server a bot ---------- */
$fs = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/firewall-status.php'));
hasnt($fs, '&#129302; bot</span>', 'C7: the misleading "bot" badge is gone');
has($fs, '&#9729;&#65039; cloud/hosting', 'C7: it says what it actually means');
has($fs, 'not that it is a search engine', 'C7: ...and spells out the difference on hover');
has($fs, "=== 'crawler_audit'", 'C7: and the already-blocked list can be swept for real crawlers');
has($fs, 'smpro_bg_rdns_bulk($ips)', 'C7: the sweep is bounded — by a budget it derives, see C9');
has($fs, "'complete'=>\$complete", 'C7: ...and says how far it got, instead of reading as "all clean"');

/* ---------- C8: the sweep resolves in parallel, or it is not a sweep anybody finishes ---------- */
// Measured on dc1 (2026-09-12): one address at a time got through 30 of 199 blocked addresses inside the 25s
// budget — about 830ms each, spent waiting out the resolver's timeout on every miss. A check that needs seven
// runs to finish is a check nobody runs.
ok(function_exists('smpro_bg_rdns_bulk'), 'C8: the bulk resolver exists');
has($bg, "'dig +short +time=' . \$wait . ' +tries=1 -x '", 'C8: the per-lookup wait comes from settings, not from a literal in the command');
has($bg, 'foreach (array_chunk($todo, $conc) as $chunk) {', 'C8: ...and they are asked in flights, not one after another');
has($bg, "\$ttl = max(3600, (int)\$cfg['rdns_cache_days'] * 86400);", 'C8: the cache lifetime is a setting too');
has($bg, "\$cache[\$ip] = ['host' => \$host, 'at' => \$now]; \$dirty = true;", 'C8: including the empty ones, so a re-run does not re-wait for the same misses');
has($bg, "foreach (\$cache as \$k => \$v) if (!is_array(\$v) || (\$now - (int)(\$v['at'] ?? 0)) >= \$ttl) unset(\$cache[\$k]);",
    'C8: and the cache is pruned as it is written, so it cannot grow without bound');
has($bg, "} else {\n        foreach (\$todo as \$ip) {\n            if (time() - \$started >= \$budget) break;\n            \$h = @gethostbyaddr(\$ip);",
    'C8: a server without dig still works, sequentially, inside the same budget');
has($bg, 'function smpro_bg_crawler_shield(string $ip, ?array $res = null, ?string $knownHost = null): array {',
    'C8: the shield takes an already-resolved name, so a sweep never resolves the same address twice');
has($bg, "\$host = \$knownHost !== null ? strtolower(rtrim(trim(\$knownHost), '.')) : (string)\$res['rev'](\$ip);",
    'C8: ...and an empty known name means "no reverse DNS", not "unknown"');

$fs2 = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/firewall-status.php'));
has($fs2, '$rdns = smpro_bg_rdns_bulk($ips);', 'C8: the firewall sweep uses it');
has($fs2, "if (!array_key_exists(\$ip, \$rdns)) { \$complete = false; continue; }",
    'C8: an address the sweep did not reach is reported as not reached, never counted as clean');
has($fs2, 'the next run picks up where this one stopped', 'C8: and the operator is told the second run is cheap');

/* ---------- C9: nothing about the sweep is a number picked in advance ---------- */
// A fixed budget is a guess about somebody else's resolver and somebody else's block list. On a fast box it wastes
// the operator's time; on a slow one it truncates and reports a partial answer — which is how a sweep of 199
// addresses came back having checked 30 and still read as reassuring.
ok(function_exists('smpro_bg_rdns_budget'), 'C9: the budget is computed');
$d = smpro_bg_defaults();
foreach (['rdns_concurrency', 'rdns_timeout', 'rdns_cache_days', 'rdns_max_seconds'] as $k)
    ok(isset($d[$k]), 'C9: ' . $k . ' is a setting on this server, not a constant in the code');

$small = smpro_bg_rdns_budget(10, 16, 2);
$big   = smpro_bg_rdns_budget(2000, 16, 2);
ok($big > $small, 'C9: a longer list gets a longer budget (' . $small . 's for 10, ' . $big . 's for 2000)');
is_eq(smpro_bg_rdns_budget(0), 0, 'C9: nothing to resolve needs no time at all');
ok(smpro_bg_rdns_budget(1, 16, 2) >= 5, 'C9: ...but a single lookup still gets a workable floor');
is_eq(smpro_bg_rdns_budget(100000, 16, 2, 120), 120, 'C9: and an absurd list is capped by the ceiling setting, not by luck');
$slow = smpro_bg_rdns_budget(100, 16, 5, 999); $fast = smpro_bg_rdns_budget(100, 16, 1, 999);
ok($slow > $fast, 'C9: a server whose resolver is slower is given more time for the same list');
$wide = smpro_bg_rdns_budget(100, 64, 2, 999); $narrow = smpro_bg_rdns_budget(100, 4, 2, 999);
ok($wide < $narrow, 'C9: ...and a wider flight needs less of it');

$fs3 = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/firewall-status.php'));
hasnt($fs3, '$budget = 25;', 'C9: the firewall sweep no longer carries a fixed wall');
hasnt($fs3, "array_slice(array_keys(\$ips), 0, 500)", 'C9: ...nor a fixed cap on how much of the server it will look at');
has($fs3, '$rdns = smpro_bg_rdns_bulk($ips);', 'C9: it asks for the whole list and lets the sweep size itself');

/* ---------- C10: the tree carries no real address from anybody's server ---------- */
// Standing rule for this product: it ships to every licensee, so a real IP, host or account name from a live box
// has no place in it — not in shipped code and not in a test either.
foreach ([SMPRO_BASE . '/includes/botguard.php', SMPRO_BASE . '/modules/firewall-status.php', __FILE__] as $f) {
    $txt = (string)file_get_contents($f);
    preg_match_all('/\b(?:\d{1,3}\.){3}\d{1,3}\b/', $txt, $m);
    $bad = [];
    foreach (array_unique($m[0]) as $ip) {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) continue;  // private/reserved are fine
        // RFC 5737 documentation ranges are the only public-looking addresses allowed to appear.
        if (strpos($ip, '192.0.2.') === 0 || strpos($ip, '198.51.100.') === 0 || strpos($ip, '203.0.113.') === 0) continue;
        $bad[] = $ip;
    }
    ok($bad === [], 'C10: ' . basename($f) . ' carries no real public address' . ($bad ? ' — found ' . implode(', ', $bad) : ''));
}
