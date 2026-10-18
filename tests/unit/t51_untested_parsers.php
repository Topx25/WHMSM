<?php
/**
 * t51_untested_parsers.php — the pure logic in seven includes that had NO test references at all
 * (audit 2026-09-06). Each of these decides something an operator acts on: which query shape to show, whether a
 * range is a valid CIDR, whether a sender pattern would block ALL mail, what grade a disk gets, what the load
 * diagnosis says. A wrong answer here reads exactly like a right one on the page. Fixtures are literal inputs;
 * nothing shells out.
 *
 *   U70 dbhealth        — redact_sql / round_mb / active / bytes_h / dur_h
 *   U71 fwallow         — cidr_valid / marker
 *   U72 mailblock       — norm_entry refusals + normalisation, splice/unsplice idempotence
 *   U73 benchdiag       — rate / grade_iops / grade_seq / grade_cls / ruler_pos / disk_expect
 *   U74 load_investigate— diagnose: healthy, swarm, io-bound, memory, broad
 *   U75 upload-breach   — band rank round-trip, under_home containment, token regex
 *   U76 spincheck       — describe never throws on a full finding
 */
require __DIR__ . '/../support/bootstrap.php';
require SMPRO_BASE . '/tests/support/plugin_funcs.php';
smpro_plugin_funcs('includes/helpers.php');
smpro_plugin_funcs('includes/dbhealth.php');
smpro_plugin_funcs('includes/fwallow.php');
smpro_plugin_funcs('includes/mailblock.php');
smpro_plugin_funcs('includes/benchdiag.php');
smpro_plugin_funcs('includes/load_investigate.php');
smpro_plugin_funcs('includes/forensics-upload-breach.php');
smpro_plugin_funcs('includes/spincheck.php');

/* ---------- U70 dbhealth ---------- */
ok(function_exists('smpro_dbh_redact_sql'), 'U70: dbhealth functions loaded router-free');
is_eq(smpro_dbh_redact_sql("SELECT * FROM users WHERE email='a@b.c' AND id=1234567"), "SELECT * FROM users WHERE email='?' AND id=?", 'U70: redact collapses string + long-int literals');
is_eq(smpro_dbh_redact_sql("UPDATE t SET n=\"it's\" WHERE id=42"), 'UPDATE t SET n="?" WHERE id=42', 'U70: redact handles double quotes with an embedded apostrophe; short ints stay');
is_eq(smpro_dbh_redact_sql("SELECT\n  1\t  FROM   x"), 'SELECT 1 FROM x', 'U70: redact folds whitespace');
is_eq(smpro_dbh_redact_sql('NULL'), '', 'U70: redact turns NULL into empty (idle thread)');
is_eq(strlen(smpro_dbh_redact_sql(str_repeat('SELECT 1 ', 100))), 240, 'U70: redact caps at 240 chars');
is_eq(smpro_dbh_round_mb(100 * 1048576), 128 * 1048576, 'U70: round_mb rounds to the 64MB step');
is_eq(smpro_dbh_round_mb(1), 64 * 1048576, 'U70: round_mb never goes below one step');
$pl = [
    ['id'=>1,'command'=>'Sleep','info'=>'','user'=>'a'],
    ['id'=>2,'command'=>'Query','info'=>'SELECT 1','user'=>'b'],
    ['id'=>3,'command'=>'Daemon','info'=>'','user'=>'event_scheduler'],
    ['id'=>4,'command'=>'Query','info'=>'SELECT * FROM information_schema.PROCESSLIST','user'=>'root'],
    ['id'=>5,'command'=>'Query','info'=>'','user'=>'c'],
];
$act = smpro_dbh_active($pl);
is_eq(array_column($act, 'id'), [2, 5], 'U70: active keeps real queries only — drops Sleep, Daemon and our own probe');
is_eq(smpro_dbh_bytes_h(0), '0 B', 'U70: bytes_h zero');
is_eq(smpro_dbh_bytes_h(1536), '1.5 KB', 'U70: bytes_h one decimal under 10');
is_eq(smpro_dbh_bytes_h(3 * 1073741824), '3 GB', 'U70: bytes_h GB');
is_eq(smpro_dbh_dur_h(59), '59s', 'U70: dur_h seconds');
is_eq(smpro_dbh_dur_h(3661), '1h 1m', 'U70: dur_h hours');
is_eq(smpro_dbh_dur_h(90000), '1d 1h', 'U70: dur_h days');

/* ---------- U71 fwallow ---------- */
ok(function_exists('smpro_fw_cidr_valid'), 'U71: fwallow functions loaded router-free');
ok(smpro_fw_cidr_valid('203.0.113.0/24'), 'U71: v4 CIDR valid');
ok(smpro_fw_cidr_valid('203.0.113.7'), 'U71: bare v4 valid');
ok(smpro_fw_cidr_valid('2001:db8::/32'), 'U71: v6 CIDR valid');
ok(!smpro_fw_cidr_valid('203.0.113.0/33'), 'U71: v4 prefix > 32 refused');
ok(!smpro_fw_cidr_valid('2001:db8::/129'), 'U71: v6 prefix > 128 refused');
ok(!smpro_fw_cidr_valid('203.0.113.0/ab'), 'U71: non-numeric prefix refused');
ok(!smpro_fw_cidr_valid('example.com'), 'U71: hostname refused');
ok(!smpro_fw_cidr_valid(''), 'U71: empty refused');
ok(!smpro_fw_cidr_valid('1.2.3.4/24; rm -rf /'), 'U71: shell-ish junk refused (this string reaches csf)');
is_eq(smpro_fw_allow_marker('Cloud-Flare!'), 'smpro-allow:loudlare', 'U71: marker strips everything but [a-z0-9] (no case-fold — uppercase is dropped)');

/* ---------- U72 mailblock ---------- */
ok(function_exists('smpro_mb_norm_entry'), 'U72: mailblock functions loaded router-free');
is_eq(smpro_mb_norm_entry('  Spam@Example.COM ')[1], 'spam@example.com', 'U72: address is trimmed + case-folded');
is_eq(smpro_mb_norm_entry('example.com')[1], '*@example.com', 'U72: bare domain becomes *@domain');
is_eq(smpro_mb_norm_entry('*@example.com')[1], '*@example.com', 'U72: wildcard kept as-is');
foreach (['*', '@', '*@', '*@*', '@*'] as $bad) ok(!smpro_mb_norm_entry($bad)[0], "U72: catastrophic pattern '$bad' refused");
ok(!smpro_mb_norm_entry('a b@example.com')[0], 'U72: whitespace inside is refused, not silently altered');
ok(!smpro_mb_norm_entry('a@example')[0], 'U72: TLD-less address refused');
ok(!smpro_mb_norm_entry("x@example.com\n")[1] === false, 'U72: trailing newline is trimmed');
ok(!smpro_mb_norm_entry('user@localhost')[0] || smpro_mb_norm_entry('localhost')[0] === false, 'U72: *@localhost refused');
ok(!smpro_mb_norm_entry(str_repeat('a', 250) . '@example.com')[0], 'U72: over-long entry refused');
ok(!smpro_mb_norm_entry('a;b@example.com')[0], 'U72: characters exim would misparse are refused');
$block = SMPRO_MB_BEGIN . "\nline1\n" . SMPRO_MB_END;
$once  = smpro_mb_splice("custom top\n", $block);
$twice = smpro_mb_splice($once, $block);
is_eq($twice, $once, 'U72: splice is idempotent (re-splicing replaces, never duplicates)');
has($once, 'custom top', 'U72: splice keeps existing custom content');
is_eq(substr_count($twice, SMPRO_MB_BEGIN), 1, 'U72: exactly one block after two splices');
is_eq(trim(smpro_mb_unsplice($twice)), 'custom top', 'U72: unsplice leaves only the custom content');
is_eq(smpro_mb_unsplice("plain\n"), "plain\n", 'U72: unsplice on content without our block is a no-op');

/* ---------- U73 benchdiag ---------- */
ok(function_exists('smpro_bd_rate'), 'U73: benchdiag functions loaded router-free');
is_eq(smpro_bd_rate(null, [100, 50])[0], 'unknown', 'U73: rate null → unknown (a missing result is not "poor")');
is_eq(smpro_bd_rate('', [100, 50])[0], 'unknown', 'U73: rate empty string → unknown');
is_eq(smpro_bd_rate(150, [100, 50])[0], 'excellent', 'U73: rate at/over good');
is_eq(smpro_bd_rate(60, [100, 50])[0], 'good', 'U73: rate in acceptable band');
is_eq(smpro_bd_rate(30, [100, 50])[0], 'below', 'U73: rate above half of acceptable');
is_eq(smpro_bd_rate(10, [100, 50])[0], 'poor', 'U73: rate under half of acceptable');
is_eq(smpro_bd_grade_iops(null)[0], 'unknown', 'U73: iops null → unknown');
is_eq(smpro_bd_grade_iops(80000)[0], 'excellent', 'U73: iops boundary 80k');
is_eq(smpro_bd_grade_iops(79999)[0], 'verygood', 'U73: iops just under 80k');
is_eq(smpro_bd_grade_iops(99)[0], 'failing', 'U73: iops under 100 is failing');
is_eq(smpro_bd_grade_seq(1500)[0], 'excellent', 'U73: seq 1500 MB/s');
is_eq(smpro_bd_grade_seq(79)[0], 'failing', 'U73: seq under 80 MB/s failing');
foreach (['excellent','verygood','good','poor','failing','unknown','bogus'] as $g) ok(in_array(smpro_bd_grade_cls($g), ['green','blue','orange','red','gray'], true), "U73: grade_cls('$g') maps to a known colour");
is_eq(smpro_bd_ruler_pos(10), 0.0, 'U73: ruler floor at 10 IOPS = 0%');
is_eq(smpro_bd_ruler_pos(500000), 100.0, 'U73: ruler ceiling at 500k = 100%');
is_eq(smpro_bd_ruler_pos(5000000), 100.0, 'U73: ruler clamps above ceiling');
$mid = smpro_bd_ruler_pos(2236);   // ~ geometric mean of 10 and 500k
ok($mid > 45 && $mid < 55, 'U73: ruler is log-scale (geometric midpoint lands near 50%)');
foreach (['nvme','ssd','hdd','unknown'] as $c) { $e = smpro_bd_disk_expect($c); ok($e['w'][0] > $e['w'][1] && $e['r'][0] > $e['r'][1] && $e['i'][0] > $e['i'][1], "U73: disk_expect('$c') bands are ordered good > acceptable"); }
is_eq(smpro_bd_disk_expect('floppy'), smpro_bd_disk_expect('unknown'), 'U73: unknown class falls back');
ok(smpro_bd_disk_expect('hdd')['i'][0] < smpro_bd_disk_expect('ssd')['i'][1], 'U73: an HDD "good" IOPS is below an SSD "acceptable" — the classes do not overlap');

/* ---------- U74 load_investigate ---------- */
ok(function_exists('smpro_load_diagnose'), 'U74: load_investigate functions loaded router-free');
$ev = function (array $o = []) {
    return array_replace_recursive([
        'load' => ['1m' => 2.0], 'cores' => 8, 'load_per_core' => 0.25,
        'cpu' => ['wa' => 1.0], 'mem' => ['used_pct' => 40, 'swap_used_pct' => 0],
        'top_users' => [], 'swarms' => [], 'top_procs' => [],
    ], $o);
};
$d = smpro_load_diagnose($ev());
is_eq($d['status'], 'healthy', 'U74: 25% of capacity, no io/mem pressure → healthy');
is_eq($d['bound'], 'ok', 'U74: healthy bound is ok');
is_eq(count($d['causes']), 1, 'U74: healthy has exactly one (non-)cause line');
$d = smpro_load_diagnose($ev(['load' => ['1m' => 16.0], 'load_per_core' => 2.0,
    'swarms' => [['user' => 'acctone', 'count' => 40, 'comm' => 'php-cgi', 'cpu' => 380, 'wp_cron' => true]]]));
is_eq($d['status'], 'overloaded', 'U74: swarm → overloaded');
has($d['primary'], 'acctone', 'U74: swarm primary names the account');
has($d['primary'], 'background wp-cron', 'U74: swarm primary labels wp-cron');
$acts = array_column(array_filter($d['suggestions'], fn($s) => is_array($s['action'] ?? null)), 'action');
ok(in_array('cool_user', array_column($acts, 'type'), true), 'U74: swarm offers a cool_user action');
ok((bool)array_filter($d['suggestions'], fn($s) => stripos($s['title'], 'pseudo-cron') !== false), 'U74: wp-cron swarm suggests disabling pseudo-cron');
$d = smpro_load_diagnose($ev(['load' => ['1m' => 10.0], 'load_per_core' => 1.25, 'cpu' => ['wa' => 40.0]]));
is_eq($d['bound'], 'io', 'U74: high iowait → io-bound');
has($d['primary'], 'I/O-wait', 'U74: io primary says so');
$d = smpro_load_diagnose($ev(['load' => ['1m' => 10.0], 'load_per_core' => 1.25, 'mem' => ['used_pct' => 97, 'swap_used_pct' => 60]]));
is_eq($d['bound'], 'memory', 'U74: swap + RAM pressure → memory-bound');
$d = smpro_load_diagnose($ev(['load' => ['1m' => 3.0], 'load_per_core' => 0.375, 'mem' => ['used_pct' => 30, 'swap_used_pct' => 50]]));
is_eq($d['status'], 'overloaded', 'U74: heavy swap alone is NOT healthy even at low CPU ratio');
$d = smpro_load_diagnose($ev(['load' => ['1m' => 12.0], 'load_per_core' => 1.5,
    'top_procs' => [['pid' => 4242, 'comm' => 'python3', 'user' => 'accttwo', 'cpu' => 95.0]]]));
has($d['primary'], 'PID 4242', 'U74: single non-system runaway becomes primary');
$d = smpro_load_diagnose($ev(['load' => ['1m' => 12.0], 'load_per_core' => 1.5,
    'top_procs' => [['pid' => 1, 'comm' => 'mysqld', 'user' => 'mysql', 'cpu' => 95.0]]]));
has($d['primary'], 'no single dominant account', 'U74: a busy system service is not called a runaway → broad');
is_eq($d['bound'], 'cpu', 'U74: broad overload is cpu-bound');

/* ---------- U75 upload-breach ---------- */
ok(function_exists('smpro_ub_band_rank'), 'U75: upload-breach functions loaded router-free');
foreach (['clean','info','low','medium','high','critical'] as $b) is_eq(smpro_ub_band_name(smpro_ub_band_rank($b)), $b, "U75: band '$b' round-trips");
is_eq(smpro_ub_band_rank('CRITICAL'), 5, 'U75: band rank is case-insensitive');
is_eq(smpro_ub_band_rank('nonsense'), 0, 'U75: unknown band ranks as clean (never inflated)');
$T = sys_get_temp_dir() . '/smpro_t51_' . getmypid(); @mkdir("$T/home/acct/public_html", 0700, true); @mkdir("$T/other", 0700, true);
file_put_contents("$T/home/acct/public_html/x.php", '1'); file_put_contents("$T/other/y.php", '1');
$homeR = realpath("$T/home/acct");
if (DIRECTORY_SEPARATOR === '/') ok(smpro_ub_under_home("$T/home/acct/public_html/x.php", $homeR) !== '', 'U75: file inside home is under_home');   // realpath() separators differ on Windows; the gate runs on Linux
is_eq(smpro_ub_under_home("$T/other/y.php", $homeR), '', 'U75: file outside home is not');
is_eq(smpro_ub_under_home("$T/home/acct/public_html/../../../other/y.php", $homeR), '', 'U75: dot-dot escape resolved before the prefix test');
is_eq(smpro_ub_under_home("$T/home/acct/nope.php", $homeR), '', 'U75: missing file is not under_home (realpath fails)');
@mkdir("$T/home/acct2", 0700, true); file_put_contents("$T/home/acct2/z.php", '1');
is_eq(smpro_ub_under_home("$T/home/acct2/z.php", $homeR), '', 'U75: sibling account with the same prefix is NOT under home (string-prefix trap)');
$re = '~' . str_replace('[[:space:]]', '\s', smpro_ub_token_re()) . '~';   // the ERE carries a literal "/e"; the delimiter must not be /
foreach (['eval (', 'gzinflate', 'shell_exec(', 'system (', '$_GET["c"](', 'base64_decode($x', '<?php', 'move_uploaded_file'] as $tok) ok((bool)@preg_match($re, "x $tok y"), "U75: token regex matches '$tok'");
ok(!@preg_match($re, "echo 'hello'; \$total = count(\$rows);"), 'U75: token regex does not fire on plain code');
foreach (glob("$T/*/*/*/*") ?: [] as $f) @unlink($f);

/* ---------- U76 spincheck ---------- */
ok(function_exists('smpro_spin_describe'), 'U76: spincheck functions loaded router-free');
$line = smpro_spin_describe(['comm' => 'php-cgi', 'pid' => 777, 'user' => 'acctone', 'pct' => 99, 'days' => 11.8, 'samples' => [99, 99, 99]]);
has($line, 'php-cgi (pid 777, acctone)', 'U76: describe names process, pid, user');
has($line, '11.8 day', 'U76: describe carries the duration');
has($line, '99%, 99%, 99%', 'U76: describe lists the flat samples');
