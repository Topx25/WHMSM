<?php
/**
 * r13_page_memory.php — pages that died silently on a large log window (2026-09-07).
 *
 * Account Audit with loglines=200000 rendered a BLANK page. Measured on the lab: cPanel's CLI php.ini caps
 * memory_limit at 128M; the page read the window with shell_exec + explode, holding ~60MB of text twice, and peaked
 * at 310MB — PHP bailed out with display_errors=0 and stderr discarded, so nothing was shown and nothing was logged.
 * Even 100k lines died. Login Monitor (300k window) and Spam & Phishing (up to 800k exim lines) had the same shape.
 *
 * Three fixes, each locked here:
 *   R1  smpro_run_lines() streams a command's output line by line — 200k lines under a 96M limit, peak stays small.
 *   R2  smpro_page_fatal_guard() turns a fatal into a visible box + page_fatal.log line (HTML and JSON modes).
 *   R3  the wiring: index.cgi raises the cap, index.php arms the guard, the three pages iterate generators.
 */
require __DIR__ . '/../support/bootstrap.php';
require SMPRO_BASE . '/tests/support/plugin_funcs.php';
$helpersDefs = smpro_plugin_funcs('includes/helpers.php');

/* ---------- R1: streaming reader ---------- */
ok(function_exists('smpro_run_lines'), 'R1: smpro_run_lines exists');
$T = sys_get_temp_dir() . '/smpro_r13_' . getmypid(); @mkdir($T, 0700, true);
$big = "$T/big.log";
$fh = fopen($big, 'w');
$pad = str_repeat('a', 180);
for ($i = 0; $i < 200000; $i++) fwrite($fh, "[09/06/2026:14:00:00 -0000] info [cpaneld] 203.0.113." . ($i % 250) . " - user" . ($i % 40) . " \"GET /login/?x=$i HTTP/1.1\" SUCCESS LOGIN cpaneld $pad\n");
fclose($fh);
ok(filesize($big) > 50 * 1048576, 'R1: fixture is a realistic ~60MB, 200k-line window');

$isWin = DIRECTORY_SEPARATOR !== '/';
$catCmd = 'cat ' . escapeshellarg($big);   // `cat`, not `tail`: the lab stubs tail on PATH (tests/support/stub_path) and the stub prints nothing
if (!$isWin) {
    $prev = ini_get('memory_limit'); ini_set('memory_limit', '96M');
    $base = memory_get_usage(true);
    $n = 0; $last = '';
    foreach (smpro_run_lines($catCmd, 60) as $l) { $n++; $last = $l; }
    $peak = memory_get_peak_usage(true) - $base;
    ini_set('memory_limit', $prev);
    is_eq($n, 200000, 'R1: every line of the 200k window was delivered');
    has($last, 'x=199999', 'R1: last line is the newest (tail order preserved)');
    ok($peak < 32 * 1048576, 'R1: peak growth under 32MB for a 60MB window (was ~300MB) — measured ' . round($peak / 1048576) . 'MB');
    ok(substr($last, -1) !== "\n", 'R1: lines come back without their newline');
    $z = 0; foreach (smpro_run_lines('true', 5) as $l) $z++;
    is_eq($z, 0, 'R1: a command with no output yields nothing');
    $z = 0; foreach (smpro_run_lines('sh -c "exit 3"', 5) as $l) $z++;
    is_eq($z, 0, 'R1: a failing command yields nothing and raises no warning');
} else {
    ok(true, 'R1: (streaming measured on the gate host — no coreutils timeout on Windows)');
}

/* ---------- R2: fatal guard ---------- */
ok(function_exists('smpro_page_fatal_guard'), 'R2: smpro_page_fatal_guard exists');
$php = PHP_BINARY;
$script = "$T/fatal.php";
$vlog = str_replace('\\', '/', "$T/varlog");
$boot = SMPRO_BASE . '/tests/support/bootstrap.php';   // defines every SMPRO_* constant the helpers reference at load
file_put_contents($script, "<?php\n"
  . "define('SMPRO_VARLOG', " . var_export($vlog, true) . ");\n"
  . "require " . var_export($boot, true) . ";\n"
  . "if (in_array('json', \$argv, true)) \$_GET['format'] = 'json';\n"
  . "\$_GET['page'] = 'account-audit';\n"
  . "require " . var_export($helpersDefs, true) . ";\n"
  . "smpro_page_fatal_guard();\n"
  . "echo 'BEFORE|';\n"
  . "\$a = []; while (true) \$a[] = str_repeat('x', 65536);\n");
$out = (string)shell_exec(escapeshellarg($php) . ' -d memory_limit=24M -d display_errors=0 ' . escapeshellarg($script) . ' 2>&1');
has($out, 'BEFORE|', 'R2: the page output that came before the fatal is kept');
has($out, 'Page stopped', 'R2: an out-of-memory fatal renders a visible box instead of a blank page');
has($out, 'ran out of memory', 'R2: the box says it was memory and suggests a smaller window');
has($out, 'limit 24M', 'R2: the box states the limit in force');
has($out, 'fatal.php:', 'R2: the box names where it stopped');
$log = (string)@file_get_contents("$vlog/page_fatal.log");
has($log, 'page=account-audit', 'R2: page_fatal.log records the page');
has($log, 'Allowed memory size', 'R2: page_fatal.log carries the engine message');
$outJ = (string)shell_exec(escapeshellarg($php) . ' -d memory_limit=24M -d display_errors=0 ' . escapeshellarg($script) . ' json 2>&1');
$j = json_decode(substr($outJ, strpos($outJ, '{')), true);
ok(is_array($j) && $j['ok'] === false && $j['error'] === 'page_fatal' && $j['oom'] === true, 'R2: format=json gets a JSON error object, not a broken body');
$clean = "$T/clean.php";
file_put_contents($clean, "<?php\ndefine('SMPRO_VARLOG', " . var_export($vlog, true) . ");\nrequire " . var_export($boot, true) . ";\nrequire " . var_export($helpersDefs, true) . ";\nsmpro_page_fatal_guard();\necho 'FINE';\n");
$outC = (string)shell_exec(escapeshellarg($php) . ' -d display_errors=0 ' . escapeshellarg($clean) . ' 2>&1');
has($outC, 'FINE', 'R2: a page that finishes normally still renders');
hasnt($outC, 'Page stopped', 'R2: a page that finishes normally gets no box appended');

/* ---------- R3: wiring ---------- */
$cgi = (string)file_get_contents(SMPRO_BASE . '/index.cgi');
has($cgi, '-d memory_limit=768M', 'R3: index.cgi raises the cap above the 128M cPanel default');
$idx = (string)file_get_contents(SMPRO_BASE . '/index.php');
has($idx, "smpro_page_fatal_guard();", 'R3: index.php arms the guard');
ok(strpos($idx, 'smpro_page_fatal_guard();') > strpos($idx, "includes/helpers.php'"), 'R3: guard is armed right after helpers load (before any module)');
// smpro_aa_tail moved to includes/breakin.php so the break-in judgement could run outside a browser.
// The guarantee it carries is unchanged and still has to hold: a generator over smpro_run_lines, never
// file() pulling a 200k-line log into memory under a 128M cap.
$aa = (string)file_get_contents(SMPRO_BASE . '/includes/breakin.php')
    . (string)file_get_contents(SMPRO_BASE . '/modules/account-audit.php');
ok((bool)preg_match('/function smpro_aa_tail\([^)]*\)\s*\{[^}]*yield from smpro_run_lines/s', $aa), 'R3: account-audit tail is a generator over smpro_run_lines');
hasnt($aa, 'return explode("\n", rtrim($raw, "\n"));', 'R3: account-audit no longer explodes the whole window');
has($aa, "smpro_aa_collect(\$user, \$type, \$dlog, \$fromTs, \$toTs, \$search)", 'R3: the search text is pushed down into collection (pre-filter on the raw line)');
$lm = (string)file_get_contents(SMPRO_BASE . '/modules/login-monitor.php');
ok((bool)preg_match('/function smpro_lm_tail\([^)]*\)\s*\{.*?yield from smpro_run_lines/s', $lm), 'R3: login-monitor tail is a generator');
$sp = (string)file_get_contents(SMPRO_BASE . '/modules/spam-phishing.php');
has($sp, 'function smpro_sp_lines(int $lines, int $days = 7): \Generator', 'R3: spam-phishing has a streaming reader');
hasnt($sp, 'explode("\n", smpro_sp_tail(', 'R3: no caller explodes the exim window any more');
hasnt($sp, '$raw = smpro_sp_tail(', 'R3: no caller holds the exim window as one string');
is_eq(substr_count($sp, 'smpro_sp_lines('), 6, 'R3: five call sites + the definition use the streaming reader');

foreach (glob("$T/varlog/*") ?: [] as $f) @unlink($f);
foreach (glob("$T/*") ?: [] as $f) if (is_file($f)) @unlink($f);
