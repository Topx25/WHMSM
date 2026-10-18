<?php
require __DIR__ . '/../support/bootstrap.php';
/**
 * t17_modules_dbspam.php — pure scanners from
 *   modules/database-cleanup.php  (smpro_db_* : U65–U68)
 *   modules/spam-phishing.php     (smpro_sp_* : U85–U88)
 *
 * Both modules are loaded via smpro_plugin_funcs (router stripped). The two modules
 * share NO function names, so loading both is safe.
 * Every expected value below is derived by READING the actual source.
 */
require __DIR__ . '/../support/plugin_funcs.php';
smpro_plugin_funcs('modules/database-cleanup.php');
smpro_plugin_funcs('modules/spam-phishing.php');

/* =====================================================================
 * U65 — smpro_db_analyze (malicious-snippet analyzer)
 * ===================================================================== */

// --- script backdoor: 'A<script>x</script>B' -> one snippet 'AB' on strip
$a = smpro_db_analyze('A<script>x</script>B');
ok($a['changed'], 'U65 analyze: <script> block flags changed=true');
is_eq(count($a['snippets']), 1, 'U65 analyze: <script> de-overlaps to exactly 1 snippet');
is_eq($a['snippets'][0]['type'], 'script', 'U65 analyze: snippet type = script');
is_eq($a['snippets'][0]['off'], 1, 'U65 analyze: snippet offset is 1 (after the leading A)');
is_eq($a['snippets'][0]['len'], strlen('<script>x</script>'), 'U65 analyze: snippet len covers whole script tag');
is_eq($a['snippets'][0]['text'], '<script>x</script>', 'U65 analyze: snippet text is the exact substring');
is_eq($a['snippets'][0]['i'], 0, 'U65 analyze: first snippet index is 0');

// --- hash is md5 of the ORIGINAL value
$src = 'A<script>x</script>B';
is_eq($a['hash'], md5($src), 'U65 analyze: hash === md5(original value)');

// --- clean / benign input: no snippets, changed=false, but hash still set
$clean = smpro_db_analyze('just some harmless text');
is_eq($clean['changed'], false, 'U65 analyze: benign text -> changed=false');
is_eq($clean['snippets'], [], 'U65 analyze: benign text -> empty snippets array');
is_eq($clean['hash'], md5('just some harmless text'), 'U65 analyze: benign hash still md5');

// --- empty input
$empty = smpro_db_analyze('');
is_eq($empty['changed'], false, 'U65 analyze: empty string -> changed=false');
is_eq($empty['hash'], md5(''), 'U65 analyze: empty string hash = md5("")');

// --- iframe + php detection
$if = smpro_db_analyze('<iframe src="//evil.test"></iframe>');
ok($if['changed'], 'U65 analyze: <iframe> flagged');
is_eq($if['snippets'][0]['type'], 'iframe', 'U65 analyze: iframe snippet type');
$php = smpro_db_analyze('x<?php echo 1; ?>y');
ok($php['changed'], 'U65 analyze: <?php block flagged');
is_eq($php['snippets'][0]['type'], 'php', 'U65 analyze: php snippet type');

// --- eval(base64_decode(...)) detection
$ev = smpro_db_analyze('var z=eval(base64_decode("AAAA"));');
ok($ev['changed'], 'U65 analyze: eval(base64_decode()) flagged');
is_eq($ev['snippets'][0]['type'], 'eval', 'U65 analyze: eval snippet type');

// --- external SEO-spam anchor: host not owned, not safe-listed -> extlink
$ext = smpro_db_analyze('<a href="http://spammy.example">cheap</a>', ['mysite.com']);
ok($ext['changed'], 'U65 analyze: external anchor (foreign host) flagged');
is_eq($ext['snippets'][0]['type'], 'extlink', 'U65 analyze: foreign anchor -> extlink type');
is_eq($ext['snippets'][0]['host'], 'spammy.example', 'U65 analyze: extlink records the host');

// --- own-domain anchor is NOT flagged (skips own domains)
$own = smpro_db_analyze('<a href="http://mysite.com/page">home</a>', ['mysite.com']);
is_eq($own['changed'], false, 'U65 analyze: own-domain anchor is skipped');
$sub = smpro_db_analyze('<a href="https://blog.mysite.com/x">sub</a>', ['mysite.com']);
is_eq($sub['changed'], false, 'U65 analyze: subdomain of own domain is skipped');

// --- safe-listed host (youtube.com) is NOT flagged
$safe = smpro_db_analyze('<a href="https://www.youtube.com/watch">vid</a>', ['mysite.com']);
is_eq($safe['changed'], false, 'U65 analyze: safe-listed host (youtube) is skipped');

// --- relative anchor (no scheme/host) is NOT flagged (only absolute external URLs)
$rel = smpro_db_analyze('<a href="/local/page">link</a>', ['mysite.com']);
is_eq($rel['changed'], false, 'U65 analyze: relative href is not an external link');

// --- de-overlap: nested anchor inside a script is dropped (one outer snippet)
$nest = smpro_db_analyze('<script><a href="http://evil.test">x</a></script>', ['mysite.com']);
is_eq(count($nest['snippets']), 1, 'U65 analyze: nested hit inside <script> de-overlaps to 1');
is_eq($nest['snippets'][0]['type'], 'script', 'U65 analyze: outer (script) snippet kept, inner dropped');

/* =====================================================================
 * U66 — smpro_db_strip (precise, offset-based removal; round-trips analyze)
 * ===================================================================== */

$v1 = 'A<script>x</script>B';
$a1 = smpro_db_analyze($v1);
$sel1 = array_map(fn($s) => $s['i'], $a1['snippets']);
is_eq(smpro_db_strip($v1, $a1['snippets'], $sel1), 'AB', 'U66 strip: round-trip removes script -> "AB"');

// --- selecting nothing leaves the value untouched
is_eq(smpro_db_strip($v1, $a1['snippets'], []), $v1, 'U66 strip: empty selection is a no-op');

// --- two snippets removed back-to-front keeps offsets valid
$v2 = 'X<script>a</script>Y<script>b</script>Z';
$a2 = smpro_db_analyze($v2);
is_eq(count($a2['snippets']), 2, 'U66 strip: two script blocks analyzed');
$sel2 = array_map(fn($s) => $s['i'], $a2['snippets']);
is_eq(smpro_db_strip($v2, $a2['snippets'], $sel2), 'XYZ', 'U66 strip: both blocks removed back-to-front -> "XYZ"');

// --- removing only the SECOND snippet (back-to-front integrity for a single later hit)
is_eq(smpro_db_strip($v2, $a2['snippets'], [1]), 'X<script>a</script>YZ', 'U66 strip: remove only snippet index 1');
// --- removing only the FIRST snippet
is_eq(smpro_db_strip($v2, $a2['snippets'], [0]), 'XY<script>b</script>Z', 'U66 strip: remove only snippet index 0');

// --- text-mismatch guard: a snippet whose text no longer matches is NOT removed
$bad = [['i' => 0, 'type' => 'script', 'host' => '', 'off' => 1, 'len' => 18, 'text' => 'DOES-NOT-MATCH-XX']];
is_eq(smpro_db_strip($v1, $bad, [0]), $v1, 'U66 strip: snippet whose text mismatches is skipped (safety)');

// --- out-of-range offset guard
$oor = [['i' => 0, 'type' => 'script', 'host' => '', 'off' => 9999, 'len' => 5, 'text' => 'xxxxx']];
is_eq(smpro_db_strip('short', $oor, [0]), 'short', 'U66 strip: out-of-range snippet is skipped');

/* =====================================================================
 * U67 — smpro_db_spam_score + smpro_db_is_spam_content
 * ===================================================================== */

// 'viagra'x2 + 'cialis'x1 -> distinct=2, hits=3
$sc = smpro_db_spam_score('buy viagra cialis viagra');
is_eq($sc['distinct'], 2, 'U67 score: "buy viagra cialis viagra" -> 2 distinct terms');
is_eq($sc['hits'], 3, 'U67 score: "buy viagra cialis viagra" -> 3 total hits');
is_eq($sc['terms'], ['viagra', 'cialis'], 'U67 score: terms reported in source-list order, capped list');
ok(smpro_db_is_spam_content('buy viagra cialis viagra'), 'U67 is_spam: viagra/cialis content -> true');
// overlap fix: "casinos" (contains "casino") counts as ONE distinct term, not two (no double-count)
$cz = smpro_db_spam_score('casinos casinos casinos');
is_eq($cz['distinct'], 1, 'U67 score: 3x "casinos" -> 1 distinct term (casino) — overlap no longer double-counts');
is_eq($cz['hits'], 3, 'U67 score: 3x "casinos" -> 3 hits (not 6 from casino+casinos)');

// benign text -> not spam
$hw = smpro_db_spam_score('hello world');
is_eq($hw['distinct'], 0, 'U67 score: "hello world" -> 0 distinct');
is_eq($hw['hits'], 0, 'U67 score: "hello world" -> 0 hits');
is_eq($hw['terms'], [], 'U67 score: "hello world" -> empty terms');
nok(smpro_db_is_spam_content('hello world'), 'U67 is_spam: "hello world" -> false');

// boundary: distinct>=2 AND hits>=3 both required.
// one distinct term repeated 3x => distinct=1 -> NOT spam
nok(smpro_db_is_spam_content('viagra viagra viagra'), 'U67 is_spam: single term x3 (distinct=1) -> false');
// two distinct terms but only 2 hits => hits<3 -> NOT spam
nok(smpro_db_is_spam_content('viagra cialis'), 'U67 is_spam: 2 distinct but only 2 hits -> false');

// case-insensitive (mb_strtolower) detection
ok(smpro_db_is_spam_content('VIAGRA Cialis VIAGRA'), 'U67 is_spam: uppercase still detected (mb_strtolower)');

/* =====================================================================
 * U68 — smpro_db_host_is_own / smpro_db_host_is_safe / smpro_db_family
 * ===================================================================== */

// host_is_own
ok(smpro_db_host_is_own('mysite.com', ['mysite.com']), 'U68 own: exact own domain -> true');
ok(smpro_db_host_is_own('www.mysite.com', ['mysite.com']), 'U68 own: www. prefix stripped -> true');
ok(smpro_db_host_is_own('blog.mysite.com', ['mysite.com']), 'U68 own: subdomain of own -> true');
ok(smpro_db_host_is_own('', ['mysite.com']), 'U68 own: empty host (relative/anchor) -> true');
nok(smpro_db_host_is_own('evil.test', ['mysite.com']), 'U68 own: foreign host -> false');
nok(smpro_db_host_is_own('notmysite.com', ['mysite.com']), 'U68 own: suffix-but-not-subdomain -> false');

// host_is_safe (static allow-list)
ok(smpro_db_host_is_safe('youtube.com'), 'U68 safe: youtube.com -> true');
ok(smpro_db_host_is_safe('ajax.googleapis.com'), 'U68 safe: subdomain of googleapis.com -> true');
ok(smpro_db_host_is_safe('YouTu.be'), 'U68 safe: case-insensitive (youtu.be) -> true');
nok(smpro_db_host_is_safe('spammy.example'), 'U68 safe: unknown host -> false');
nok(smpro_db_host_is_safe(''), 'U68 safe: empty host -> false');

// db_family: parse the family out of an SMW signature, else passthrough
is_eq(smpro_db_family('SMW-INJ-12345-spamlink-9'), 'spamlink', 'U68 family: extracts family token from SMW signature');
is_eq(smpro_db_family('plain-string'), 'plain-string', 'U68 family: non-matching signature passes through');
is_eq(smpro_db_family(''), '', 'U68 family: empty input -> empty string');

/* =====================================================================
 * U85 — smpro_sp_decode_subject
 * ===================================================================== */

// ASCII passthrough (no =?, valid UTF-8)
is_eq(smpro_sp_decode_subject('Hello World'), 'Hello World', 'U85 decode: plain ASCII passes through unchanged');

// stripcslashes on octal escape + quote
is_eq(smpro_sp_decode_subject('a\\"b'), 'a"b', 'U85 decode: escaped quote unescaped via stripcslashes');

// MIME =?UTF-8?B?...?= base64
is_eq(smpro_sp_decode_subject('=?UTF-8?B?SGVsbG8=?='), 'Hello', 'U85 decode: MIME =?UTF-8?B? base64 decoded');
// MIME =?UTF-8?Q?...?= quoted-printable
is_eq(smpro_sp_decode_subject('=?UTF-8?Q?Hi=5FThere?='), 'Hi_There', 'U85 decode: MIME =?UTF-8?Q? decoded');

// Windows-1256 Arabic raw bytes -> valid UTF-8
$win1256 = "\xE3\xD1\xCD\xC8\xC7";   // مرحبا in Windows-1256
$decoded = smpro_sp_decode_subject($win1256);
ok(mb_check_encoding($decoded, 'UTF-8'), 'U85 decode: Windows-1256 Arabic -> valid UTF-8');
isnt_eq($decoded, $win1256, 'U85 decode: raw 8-bit Arabic was actually transcoded');

// empty input is safe and stays valid UTF-8
is_eq(smpro_sp_decode_subject(''), '', 'U85 decode: empty subject -> empty string');

/* =====================================================================
 * U86 — smpro_sp_mail_scan (scoring over parsed exim_mainlog lines)
 * NOTE: smpro_sp_server_domains() reads /etc/userdomains (absent in sandbox) ->
 *       returns []; account matching therefore relies on the cwd=/home/<acct> path.
 * ===================================================================== */

// empty log -> zeroed aggregates, low verdict
$mEmpty = smpro_sp_mail_scan('acct1', []);
is_eq($mEmpty['account'], 'acct1', 'U86 scan: account echoed back');
is_eq($mEmpty['total_msgs'], 0, 'U86 scan: empty log -> 0 messages');
is_eq($mEmpty['total_rcpts'], 0, 'U86 scan: empty log -> 0 recipients');
is_eq($mEmpty['score'], 0, 'U86 scan: empty log -> score 0');
is_eq($mEmpty['verdict'], 'low', 'U86 scan: empty log -> verdict low');
is_eq($mEmpty['signals'], [], 'U86 scan: empty log -> no signals');

// a single arrival owned by the account (matched via inline cwd=/home/acct1),
// then one external delivery -> 1 msg, 1 external recipient, but below all thresholds.
$lines = [
    '2026-06-25 10:00:00 1aAaAa-000001-AA <= sender@x.com H=mail (m) [1.2.3.4] cwd=/home/acct1 S=1000 T="Hello there"',
    '2026-06-25 10:00:01 1aAaAa-000001-AA => victim@far.example R=dnslookup T=remote_smtp',
];
$m1 = smpro_sp_mail_scan('acct1', $lines);
is_eq($m1['total_msgs'], 1, 'U86 scan: one matched arrival -> 1 message');
is_eq($m1['total_rcpts'], 1, 'U86 scan: one => delivery -> 1 recipient');
is_eq($m1['external'], 1, 'U86 scan: far.example recipient is external (no userdomains) -> 1');
is_eq($m1['internal'], 0, 'U86 scan: no internal recipients');
is_eq($m1['distinct_rcpts'], 1, 'U86 scan: 1 distinct recipient address');
is_eq($m1['score'], 0, 'U86 scan: tiny volume -> no signals fire -> score 0');
is_eq($m1['verdict'], 'low', 'U86 scan: tiny volume -> verdict low');
is_eq($m1['messages'][0]['subj'], 'Hello there', 'U86 scan: subject decoded onto the message');

// arrival NOT owned by the account (different cwd, no matching auth domain) is ignored
$foreign = [
    '2026-06-25 10:00:00 1bBbBb-000002-BB <= a@b.com cwd=/home/someoneelse S=10 T="x"',
];
$mF = smpro_sp_mail_scan('acct1', $foreign);
is_eq($mF['total_msgs'], 0, 'U86 scan: arrival for a different account is ignored');

// spam keyword in subject contributes a +2 signal (single message, kw signal only -> score 2)
$kwLines = [
    '2026-06-25 10:00:00 1cCcCc-000003-CC <= s@x.com cwd=/home/acct1 S=10 T="cheap viagra now"',
];
$mKw = smpro_sp_mail_scan('acct1', $kwLines);
is_eq($mKw['score'], 2, 'U86 scan: one spam-keyword subject -> score 2 (kw signal w=2)');
is_eq($mKw['verdict'], 'low', 'U86 scan: score 2 is still "low" (< 3)');
is_eq(count($mKw['signals']), 1, 'U86 scan: exactly the keyword signal fires');
is_eq($mKw['signals'][0]['w'], 2, 'U86 scan: keyword signal weight is 2');

/* =====================================================================
 * U87 — smpro_sp_outgoing (group by authenticated mailbox)
 * NOTE: h1/h24 depend on time(); we use a fixed-but-recent timestamp and assert
 *       structure + the time-independent fields. spam flag depends on thresholds.
 * ===================================================================== */

// no authenticated arrivals -> empty result
is_eq(smpro_sp_outgoing([]), [], 'U87 outgoing: empty log -> empty array');

// a line WITHOUT an authenticated mailbox (no A=user:mail) is ignored
$noauth = ['2026-06-25 10:00:00 1dDdDd-000004-DD <= s@x.com S=10'];
is_eq(smpro_sp_outgoing($noauth), [], 'U87 outgoing: arrival without A= auth mailbox is ignored');

// one authenticated arrival grouped by the mailbox
$ts = date('Y-m-d H:i:s', time() - 60);   // 1 minute ago -> counts in h1 and h24
$og = [
    $ts . ' 1eEeEe-000005-EE <= bob@dom.com A=dovecot_login:bob@dom.com S=2048 T="Newsletter"',
    $ts . ' 1eEeEe-000005-EE => reader@far.example R=dnslookup',
];
$rows = smpro_sp_outgoing($og);
is_eq(count($rows), 1, 'U87 outgoing: one authenticated mailbox -> 1 row');
is_eq($rows[0]['email'], 'bob@dom.com', 'U87 outgoing: row keyed by authenticated mailbox (lowercased)');
is_eq($rows[0]['total'], 1, 'U87 outgoing: total messages = 1');
is_eq($rows[0]['h1'], 1, 'U87 outgoing: message ~1min ago counts in last-hour');
is_eq($rows[0]['h24'], 1, 'U87 outgoing: message counts in last-24h');
is_eq($rows[0]['spam'], false, 'U87 outgoing: single message below threshold -> spam=false');
is_eq($rows[0]['owner'], '', 'U87 outgoing: owner empty (no /etc/userdomains in sandbox)');
is_eq(count($rows[0]['msgs']), 1, 'U87 outgoing: one sampled message');
is_eq($rows[0]['msgs'][0]['subj'], 'Newsletter', 'U87 outgoing: decoded subject on sampled message');
is_eq($rows[0]['msgs'][0]['to'], 'reader@far.example', 'U87 outgoing: recipient linked from the => line');

// spam threshold: thrHour low so h1 >= thrHour flips spam=true (deterministic via $thrHour=1)
$ogSpam = [
    $ts . ' 1fFfFf-000006-FF <= eve@dom.com A=dovecot_login:eve@dom.com S=1 T="x"',
];
$rowsSpam = smpro_sp_outgoing($ogSpam, 1);
is_eq($rowsSpam[0]['spam'], true, 'U87 outgoing: h1(1) >= thrHour(1) -> spam=true');

/* =====================================================================
 * U88 — smpro_sp_spam_keywords (static keyword list)
 * ===================================================================== */
$kw = smpro_sp_spam_keywords();
ok(is_array($kw) && $kw !== [], 'U88 keywords: returns a non-empty array');
ok(in_array('viagra', $kw, true), 'U88 keywords: includes "viagra"');
ok(in_array('bitcoin', $kw, true), 'U88 keywords: includes "bitcoin"');
ok(in_array('reset your password', $kw, true), 'U88 keywords: includes phishing phrase');
ok(in_array('كازينو', $kw, true), 'U88 keywords: includes an Arabic keyword');
is_eq($kw, smpro_sp_spam_keywords(), 'U88 keywords: deterministic (same list each call)');

/* =====================================================================
 * SKIPPED — impure / need stubs or fixtures beyond Phase 1
 * ===================================================================== */
tap_skip('smpro_db_q / smpro_db_read / smpro_db_pk — needs stub (Phase 3)', 'shells out to mysql client');
tap_skip('smpro_db_injections — needs stub (Phase 3)', 'shells out to imunify360-agent + caches to temp');
tap_skip('smpro_db_clean_apply / smpro_db_fix_database — needs stub (Phase 3)', 'mutates DB via shell_exec + writes reports/audit');
tap_skip('smpro_sp_auth_ips — needs stub (Phase 3)', 'depends on smpro_is_server_ip (server fingerprint)');
tap_skip('smpro_sp_queue — needs stub (Phase 3)', 'shells out to exim -bp/-bpc');
