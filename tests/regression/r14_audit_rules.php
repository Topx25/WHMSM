<?php
/**
 * r14_audit_rules.php — the repository-wide rules from the project rules file, checked as tests so they cannot drift back.
 * Written after the 2026-09-07 full audit found: 25 `catch {}` sites that discarded errors, three dead `csf -d`
 * fallbacks in modules that bypassed the Cloudflare/engine guards, two 60k–80k-line windows held twice in memory
 * inside the notify worker (128M cap), and one file with mixed line endings.
 *
 *   A1 no empty catch outside the two guard-internal ones (helpers.php)
 *   A2 no raw `csf -d` in modules/ or bin/ — every block goes through smpro_fw_block_ip / smpro_im_block_ip / smpro_csf_deny_add
 *   A3 smpro_soft_fail exists, logs, never throws
 *   A4 smpro_worker_fatal_guard exists and is auto-armed for CLI workers; an OOM in a worker leaves a worker_fatal line
 *   A5 no compact()/extract()/$$ in shipped code
 *   A6 no module reads $_POST without smpro_require_valid_csrf — or (AI engine) its own token + smpro_require_root
 *   A7 no bin/ file loads a modules/ file
 *   A8 no mixed line endings in shipped PHP
 *   A9 the notify worker's exim window is streamed
 */
require __DIR__ . '/../support/bootstrap.php';
require SMPRO_BASE . '/tests/support/plugin_funcs.php';
$helpersDefs = smpro_plugin_funcs('includes/helpers.php');

$shipped = [];
foreach (['includes', 'modules', 'bin'] as $d) foreach (glob(SMPRO_BASE . "/$d/*.php") ?: [] as $f) $shipped["$d/" . basename($f)] = (string)file_get_contents($f);
$shipped['index.php'] = (string)file_get_contents(SMPRO_BASE . '/index.php');
ok(count($shipped) > 100, 'audit: shipped tree loaded (' . count($shipped) . ' files)');

/* A1 */
$empty = [];
foreach ($shipped as $f => $s) if (preg_match_all('/catch\s*\(\s*\\\\?(?:Throwable|Exception|Error)\s+\$\w+\s*\)\s*\{\s*\}/', $s, $m)) $empty[$f] = count($m[0]);
is_eq($empty, ['includes/helpers.php' => 4], 'A1: the only empty catches are the four guard-internal ones in helpers.php (audit/soft_fail must not recurse)');

/* A2 */
$raw = [];
foreach ($shipped as $f => $s) {
    if (strpos($f, 'includes/helpers.php') === 0 || strpos($f, 'includes/intrusion.php') === 0) continue;
    foreach (explode("\n", $s) as $n => $l) { $c = explode('//', $l)[0]; if (preg_match("/\\\$csf\\w*\\)\\s*\\.\\s*' -d '|' -d ' \\. escapeshellarg/", $c)) $raw[] = "$f:" . ($n + 1); }
}
is_eq($raw, [], 'A2: no raw `csf -d` outside the shared block helpers');
foreach (['modules/intrusion-monitor.php', 'modules/spam-phishing.php', 'modules/user-investigation.php'] as $f) has($shipped[$f], 'smpro_fw_block_ip(', "A2: $f blocks through smpro_fw_block_ip");

/* A3 */
ok(function_exists('smpro_soft_fail'), 'A3: smpro_soft_fail exists');
$vlog = SMPRO_VARLOG; @mkdir($vlog, 0700, true); @unlink("$vlog/soft_fail.log");
smpro_soft_fail('t:ctx', new \RuntimeException('boom'));
$sf = (string)@file_get_contents("$vlog/soft_fail.log");
has($sf, 't:ctx RuntimeException: boom @ ', 'A3: soft_fail writes context, class, message and location');
$n = 0; foreach ($shipped as $f => $s) $n += substr_count($s, 'smpro_soft_fail(');
ok($n >= 25, "A3: the former empty catches now call smpro_soft_fail ($n sites)");

/* A4 */
ok(function_exists('smpro_worker_fatal_guard'), 'A4: smpro_worker_fatal_guard exists');
has($shipped['includes/helpers.php'], "if (PHP_SAPI === 'cli' && getenv('REQUEST_METHOD') === false && !isset(\$_SERVER['REQUEST_METHOD']) && !defined('SMPRO_TEST_SRC')) smpro_worker_fatal_guard();", 'A4: auto-armed for CLI workers, never for web requests or the lab');
$T = sys_get_temp_dir() . '/smpro_r14_' . getmypid(); @mkdir($T, 0700, true); $wl = str_replace('\\', '/', "$T/varlog");
$script = "$T/worker.php";
file_put_contents($script, "<?php\ndefine('SMPRO_VARLOG', " . var_export($wl, true) . ");\nrequire " . var_export(SMPRO_BASE . '/tests/support/bootstrap.php', true) . ";\nrequire " . var_export($helpersDefs, true) . ";\nsmpro_worker_fatal_guard();\n\$a = []; while (true) \$a[] = str_repeat('x', 65536);\n");
$out = (string)shell_exec(escapeshellarg(PHP_BINARY) . ' -d memory_limit=24M -d display_errors=0 ' . escapeshellarg($script) . ' 2>&1');
$wf = (string)@file_get_contents("$wl/worker_fatal.log");
has($wf, '"worker":"worker.php"', 'A4: an out-of-memory worker leaves a worker_fatal.log line naming the script');
has($wf, '"oom":true', 'A4: …flagged as OOM with the limit');
hasnt($out, 'Page stopped', 'A4: the worker guard prints no HTML');

/* A5 */
$bad = [];
foreach ($shipped as $f => $s) foreach (explode("\n", $s) as $n => $l) { $c = explode('//', $l)[0]; if (preg_match('/\b(compact|extract)\s*\(|\$\$\w/', $c)) $bad[] = "$f:" . ($n + 1); }
is_eq($bad, [], 'A5: no compact()/extract()/$$ in shipped code (the obfuscator renames variables)');

/* A6 */
$ungated = [];
foreach ($shipped as $f => $s) {
    if (strpos($f, 'modules/') !== 0 || strpos($s, '$_POST[') === false) continue;
    $gated = strpos($s, 'smpro_require_valid_csrf(') !== false || (strpos($s, 'mspro_ai304_valid_token(') !== false && strpos($s, 'smpro_require_root()') !== false);
    if (!$gated) $ungated[] = $f;
}
is_eq($ungated, [], 'A6: every module that reads $_POST is CSRF-gated (the AI engine with its own token + root gate)');

/* A7 */
$cross = []; foreach ($shipped as $f => $s) if (strpos($f, 'bin/') === 0 && preg_match('#[\'"/]modules/#', $s)) $cross[] = $f;
is_eq($cross, [], 'A7: no worker loads a page module');

/* A8 */
$mixed = [];
foreach (['includes', 'modules', 'bin'] as $d) foreach (glob(SMPRO_BASE . "/$d/*.php") ?: [] as $f) { $b = (string)file_get_contents($f); $crlf = substr_count($b, "\r\n"); $lf = substr_count($b, "\n") - $crlf; if ($crlf && $lf) $mixed[] = "$d/" . basename($f); }
is_eq($mixed, [], 'A8: no shipped PHP file mixes CRLF and LF');

/* A9 */
has($shipped['includes/notify.php'], "smpro_run_lines(\"sh -c \" . escapeshellarg(\"tail -n 300000 \"", 'A9: the notify worker streams the exim window');
hasnt($shipped['includes/notify.php'], "| tail -n 80000\");\n        foreach (explode(", 'A9: …and no longer explodes it');
has($shipped['includes/ai.php'], "smpro_run_lines('tail -n 60000 '", 'A9: the AI login-evidence reader streams too');

foreach (glob("$wl/*") ?: [] as $f) @unlink($f); @unlink($script);
