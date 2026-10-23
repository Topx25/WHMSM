<?php
/**
 * t58_catalog_extend.php — the crawler catalogue stops being the one thing only a release can change.
 *
 * The built-in list is deliberately static: a publisher's verification domain effectively never changes, and
 * inventing one would be worse than omitting it. But a crawler that appears next month should not need a release
 * to be protected. So an operator can add entries — under exactly the same verification, never as an exemption.
 *
 * The failure this file is really about: a suffix like "com" would forward-confirm nothing and shield everything.
 */
require __DIR__ . '/../support/bootstrap.php';
require SMPRO_BASE . '/tests/support/plugin_funcs.php';
smpro_plugin_funcs('includes/botguard.php');

/* ---------- E1: a suffix has to be specific enough to mean something ---------- */
foreach (['crawl.example.com', 'example.com', 'googlebot.com', 'a.b.example.co.uk', 'crawl.amazonbot.amazon'] as $good)
    ok(smpro_bg_suffix_ok($good), 'E1: "' . $good . '" is a usable suffix');
foreach (['com', 'co.uk', 'amazon', '', '.', 'a', '*.example.com', 'exam ple.com', 'example.com/evil', '-bad.com'] as $bad)
    ok(!smpro_bg_suffix_ok($bad), 'E1: "' . substr($bad, 0, 20) . '" is refused — it would shield far more than one publisher');
ok(!smpro_bg_suffix_ok(str_repeat('x', 200) . '.com'), 'E1: an absurdly long suffix is refused too');

/* ---------- E2: a custom entry is added, and is verified like every other ---------- */
$cfg = ['custom_bots' => [['key' => 'ExampleBot!', 'name' => 'ExampleBot', 'kind' => 'search', 'ua' => 'ExampleBot', 'rdns' => ['crawl.example.com']]]];
$cus = smpro_bg_catalog_custom($cfg);
ok(isset($cus['examplebot']), 'E2: the key is normalised, not rejected');
is_eq($cus['examplebot']['name'], 'ExampleBot', 'E2: named');
is_eq($cus['examplebot']['kind'], 'search', 'E2: with its kind');
is_eq($cus['examplebot']['rdns'], ['crawl.example.com'], 'E2: and its suffix');
ok(!empty($cus['examplebot']['custom']), 'E2: marked as an addition, so it can never be mistaken for something we shipped');

$mk = fn(array $rdns, array $fwd) => ['rev' => fn(string $ip) => strtolower((string)($rdns[$ip] ?? '')),
                                      'fwd' => fn(string $h) => array_map('strtolower', (array)($fwd[strtolower($h)] ?? []))];
$ip = '203.0.113.5';
// smpro_bg_verify reads the live catalogue, which merges whatever this server has saved. With nothing saved the
// entry is absent — and "absent" must read as NOT verified rather than as verified, which is the safe direction.
$v = smpro_bg_verify($ip, 'examplebot', $mk([$ip => 'a.crawl.example.com'], ['a.crawl.example.com' => [$ip]]));
ok(is_array($v) && array_key_exists('verified', $v), 'E2: an unknown family answers, it does not throw');
ok($v['verified'] === false, 'E2: ...and an entry this server has not been told about is NOT verified');

/* ---------- E3: nothing an operator types can widen the shield beyond one publisher ---------- */
$bad = smpro_bg_catalog_custom(['custom_bots' => [
    ['key' => 'everything', 'name' => 'Everything', 'kind' => 'search', 'ua' => 'x', 'rdns' => ['com']],
    ['key' => 'nosuffix',   'name' => 'No Suffix',  'kind' => 'search', 'ua' => 'x', 'rdns' => []],
    ['key' => '',           'name' => 'No Key',     'kind' => 'search', 'ua' => 'x', 'rdns' => ['crawl.example.com']],
    ['key' => 'noname',     'name' => '',           'kind' => 'search', 'ua' => 'x', 'rdns' => ['crawl.example.com']],
    'not an array',
]]);
is_eq($bad, [], 'E3: every unusable line is dropped — none of them becomes a rule that looks applied and is not');

$weird = smpro_bg_catalog_custom(['custom_bots' => [['key' => 'k', 'name' => 'K', 'kind' => 'invented', 'ua' => '.*', 'rdns' => ['crawl.example.com']]]]);
is_eq($weird['k']['kind'], 'search', 'E3: an invented kind falls back, it does not pass through');
ok(@preg_match($weird['k']['ua'], 'x') !== false, 'E3: what comes out is always a valid pattern');
is_eq(@preg_match($weird['k']['ua'], 'anything'), 0, 'E3: ...and ".*" is quoted as a literal, so an operator cannot write a pattern that matches every visitor');
is_eq(@preg_match($weird['k']['ua'], 'a .* b'), 1, 'E3: it still matches the literal text that was typed');
$noua = smpro_bg_catalog_custom(['custom_bots' => [['key' => 'k', 'name' => 'K', 'kind' => 'seo', 'ua' => '', 'rdns' => ['crawl.example.com']]]]);
is_eq(@preg_match($noua['k']['ua'], 'anything at all'), 0, 'E3: no UA given means it matches nothing, never everything');

/* ---------- E4: the built-in list is still the built-in list ---------- */
$built = smpro_bg_catalog_builtin();
ok(count($built) >= 40, 'E4: the shipped catalogue covers ' . count($built) . ' publishers');
foreach (['googlebot', 'bingbot', 'archive', 'amazonbot', 'naver', 'sogou', 'mojeek', 'statuscake'] as $k)
    ok(isset($built[$k]), 'E4: ' . $k . ' is shipped');
$badSfx = []; $badUa = [];
foreach ($built as $k => $e) {
    foreach ((array)$e['rdns'] as $sfx) if (!smpro_bg_suffix_ok($sfx)) $badSfx[] = $k . ':' . $sfx;
    if (@preg_match($e['ua'], '') === false) $badUa[] = $k;
}
is_eq($badSfx, [], 'E4: every shipped suffix is specific enough to be safe — a loose one here would shield strangers');
is_eq($badUa, [], 'E4: every shipped UA pattern compiles');

$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/botguard.php'));
has($src, "return \$memo = array_replace(smpro_bg_catalog_builtin(), function_exists('smpro_tf_families') ? smpro_tf_families() : [], smpro_bg_catalog_custom());",
    'E4: custom entries are layered OVER the shipped list, so an upgrade cannot silently drop them and they cannot silently drop ours');
has($src, 'a guessed suffix is worse than none', 'E4: and the rule for adding one is written down where the list is');

/* ---------- E5: the page tells the truth about what it accepted ---------- */
$pg = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/bot-guard.php'));
has($pg, "\$patch['custom_bots'] = \$custom;", 'E5: the field is saved');
has($pg, "'custom_bots' => count(\$accepted)", 'E5: and how many survived validation is reported back, not just "Saved"');
has($pg, 'line(s) in force', 'E5: the settings box shows accepted-vs-typed, so a dropped line cannot pass for an applied one');
has($pg, 'never replacing it', 'E5: and says these are additions');
has($pg, "'custom_bots'].forEach(function(n){fd.set(n,f.elements[n].value);});", 'E5: the form actually sends it');
