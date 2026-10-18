<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/intrusion.php';
/**
 * r28_alert_clears_after_reset.php — an alert must stop when the thing it reports has been fixed.
 *
 * "16 account(s) signed in from several countries" reads a 7-day window of successful logins. The operator does
 * exactly what it asks — resets the password — and receives the same alert, naming the same accounts, every day
 * for the rest of the week, because the logins that triggered it are still inside the window.
 *
 * That is worse than noise. An alert that does not clear when the problem is fixed teaches people to ignore it,
 * and the next one it sends is ignored too. The record needed to tell "before the reset" from "after" already
 * existed — password_resets.log, written by the bulk reset — and the detector was not reading it.
 */

ok(function_exists('smpro_pw_reset_at'), 'R1: the detectors can find out when an account\'s password was changed');

/* ---------- R2: it reads the real record ---------- */
$log = defined('SMPRO_GR_LOG') ? SMPRO_GR_LOG : (SMPRO_VARLOG . '/password_resets.log');
@is_dir(dirname($log)) || @mkdir(dirname($log), 0700, true);
$keep = @is_file($log) ? (string)@file_get_contents($log) : null;

$when = time() - 3600;
$rows = [
    ['at' => date('c', $when),        'user' => 'acct_reset',  'reason' => 'r28', 'by' => 'test', 'result' => 'changed'],
    ['at' => date('c', time() - 60),  'user' => 'acct_failed', 'reason' => 'r28', 'by' => 'test', 'result' => 'failed'],
];
file_put_contents($log, implode("\n", array_map(fn($r) => json_encode($r), $rows)) . "\n");

// The helper memoises in a static, so it is exercised in a CHILD process where the fixture above is what it
// reads. Written to a file rather than passed with -r: quoting inside -r does not survive every shell.
$boot = sys_get_temp_dir() . '/smpro_r28_' . getmypid() . '.php';
// The child bootstrap is assembled with implode rather than escaped string literals: this file has already
// been mangled twice by quoting, and a test that is hard to read is a test nobody trusts when it fails.
$childLines = [
    '<?php',
    "define('SMPRO_BOOT', 1);",
    // The child resolves SMPRO_VARLOG for a real server while the parent runs in the sandbox, so the record
    // path is handed over explicitly and both are certainly talking about the same file.
    "define('SMPRO_GR_LOG', " . var_export($log, true) . ');',
    'require ' . var_export(SMPRO_BASE . '/includes/defines.php', true) . ';',
    'require ' . var_export(SMPRO_BASE . '/includes/helpers.php', true) . ';',
    'require ' . var_export(SMPRO_BASE . '/includes/intrusion.php', true) . ';',
    "echo json_encode([smpro_pw_reset_at('acct_reset'), smpro_pw_reset_at('acct_failed'), smpro_pw_reset_at('acct_none')]);",
];
file_put_contents($boot, implode(PHP_EOL, $childLines) . PHP_EOL);
$out = (string)@shell_exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($boot) . ' 2>&1');
@unlink($boot);
$got = json_decode(trim($out), true);

ok(is_array($got) && count($got) === 3, 'R2: the helper answers for three accounts' . (is_array($got) ? '' : ' — got: ' . substr($out, 0, 200)));
if (is_array($got) && count($got) === 3) {
    ok(abs((int)$got[0] - $when) <= 2, 'R2: a CHANGED reset gives the time it happened');
    is_eq((int)$got[1], 0, 'R2: a FAILED reset gives 0 — it changed nothing, so it suppresses nothing');
    is_eq((int)$got[2], 0, 'R2: an account with no record gives 0');
}

if ($keep === null) @unlink($log); else @file_put_contents($log, $keep);

/* ---------- R3: the detector actually uses it, before counting ---------- */
$in = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/intrusion.php'));
has($in, 'if ($ts && (smpro_pw_reset_at($account) > $ts || smpro_pw_reset_sys((string)$account, (string)$user) > $ts)) continue;',
    'R3: a login from before the password was changed is not counted');
$i = strpos($in, 'smpro_pw_reset_at($account) > $ts');
$j = strpos($in, "\$seen[\$account]['cc'][\$g['cc']] = true;");
ok($i !== false && $j !== false && $i < $j,
   'R3: and it is dropped BEFORE it reaches the country set — otherwise it still counts toward the anomaly');

/* ---------- R4: it fails OPEN ---------- */
// The cost of not suppressing a stale alert is noise. The cost of wrongly suppressing one is a real compromise
// going unreported. So an unreadable record must leave every event counted.
has($in, 'A missing or unreadable record answers 0', 'R4: the reason for failing open is written down');
has($in, "(\$j['result'] ?? '') !== 'changed'", 'R4: only a reset that actually changed the password suppresses anything');

/* ---------- R5: the report starts again after ANY reset ---------- */
// The per-account cutoff stops a login being counted against an account whose password changed. It does not
// stop the report REPEATING: the window is seven days, so each run re-reads the same week and sends the same
// names again. An operator who acted yesterday got the identical alert today, which is how an alert that HAS
// been acted on becomes indistinguishable from one that has not.
ok(function_exists('smpro_pw_any_reset_at'), 'R5: there is a server-wide reset watermark');
$in2 = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/intrusion.php'));
has($in2, 'if ($ts && $ts < smpro_pw_any_reset_at()) continue;',
    'R5: events from before the last reset are not reported again');
$a = strpos($in2, 'if ($ts && $ts < $cutoff) continue;');
$b = strpos($in2, 'if ($ts && $ts < smpro_pw_any_reset_at()) continue;');
ok($a !== false && $b !== false && $a < $b, 'R5: applied inside the same event loop, after the window check');
has($in2, "(\$j['result'] ?? '') !== 'changed'", 'R5: a FAILED reset moves no watermark');
has($in2, 'tail -n 400', 'R5: only the tail is read — these files grow');

/* ---------- R6: an account's MAILBOXES can be reset with it - but only when the operator explicitly asks (beta322) ---------- */
// This is why the alert kept coming. A cPanel password and a mailbox password are separate credentials and
// webmail accepts the mailbox one, so resetting the account left the attacker signing in exactly as before.
// The operator reset the same accounts twice and saw no change, correctly.
$gr2 = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/georeport.php'));
has($gr2, 'function smpro_gr_mailboxes', 'R6: the mailboxes of an account can be listed');
has($gr2, 'function smpro_gr_set_mail_password', 'R6: and each one can be reset');
has($gr2, "foreach (smpro_gr_mailboxes(\$p['id']) as \$box)", 'R6: the bulk reset can walk them');
has($gr2, 'bool $allMailboxes = false', 'R6: but never by default - ticking four identities changed far more than four passwords');
// The password must not travel on the command line: ps is readable by every account on a shared server.
has($gr2, "/usr/bin/uapi --input=json", 'R6: the mailbox password goes through stdin, not the command line');
hasnt($gr2, "passwd_pop'\n         . ' email='", 'R6: and not as an argument');
$i2 = strpos($gr2, 'function smpro_gr_set_mail_password');
$seg = substr($gr2, $i2, 1600);
ok(strpos($seg, 'proc_open') !== false && strpos($seg, 'escapeshellarg($pass)') === false,
   'R6: nothing in that call puts the password where ps can read it');
