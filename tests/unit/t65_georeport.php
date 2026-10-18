<?php
/**
 * t65_georeport.php — the foreign sign-in report, and the bulk password reset it exists to drive.
 *
 * Blocking an address stops that address. It does not stop the person, because what they have is the password.
 * So the report is only useful if it leads to a reset — and a reset is only safe if the new passwords are handled
 * as the dangerous material they are.
 *
 * The decision this file defends: there is NO file of working passwords on the server. A single object whose theft
 * hands over every account is worse than the incident it was made to fix. The passwords are returned once; the
 * record kept on disk carries the account, the reason, the date and the actor, and never the password.
 */
require __DIR__ . '/../support/bootstrap.php';
require SMPRO_BASE . '/tests/support/plugin_funcs.php';
smpro_plugin_funcs('includes/georeport.php');

$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/georeport.php'));
$pg  = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/firewall-status.php'));

/* ---------- P1: the password is never written down ---------- */
has($src, "'note'   => 'password not stored by design',", 'P1: the record says, in itself, that it holds no password');
$rec = [];
if (preg_match('/function smpro_gr_record\(.*?\n\}/s', $src, $m)) $rec = [$m[0]];
ok($rec !== [], 'P1: the record writer was found');
hasnt($rec[0], '$pass', 'P1: ...and no password variable is anywhere in it');
hasnt($rec[0], 'password\'] =', 'P1: nor a password field');
has($src, 'the new passwords exist in ONE response', 'P1: the rule is stated at the top of the file');
has($src, 'a leaked password file costs every account on the server', 'P1: ...with what it is trading against');
// The export is built in memory and handed back; nothing writes it to this server.
has($src, 'Built in memory; never written to this server', 'P1: the export is not a file on the server either');
$exp = smpro_gr_export([['user' => 'demo', 'password' => 'a,b"c']], 'why', 'root');
has($exp, 'THIS IS THE ONLY COPY', 'P1: and it says so to whoever opens it');
has($exp, '"a,b""c"', 'P1: a password containing a comma or a quote survives the CSV intact');

/* ---------- P2: the password never reaches the process table ---------- */
// `ps` is readable by every account on a shared box. A password on the command line is a password published to
// every customer on the server for the life of the call.
has($src, "' --input=json --output=json passwd'", 'P2: the call is made with whmapi1 reading the request from stdin');
hasnt($src, 'password=' . "'" . ' . escapeshellarg($pass)', 'P2: the password is never an argument');
has($src, "@fwrite(\$pipes[0], json_encode(['user' => \$user, 'password' => \$pass]", 'P2: it goes down the pipe');
has($src, 'readable by every account on a shared box', 'P2: with the reason recorded');
// The wrong guess that was caught before it shipped, kept as a warning to the next person.
has($src, 'which whmapi1 does not support', 'P3: the earlier wrong call shape is documented so nobody re-invents it');
has($src, 'password to the literal string', 'P3: ...along with what it would have done');

/* ---------- P4: success is what the API said, not what we hoped ---------- */
has($src, "\$ok = is_array(\$j) && (int)(\$j['metadata']['result'] ?? 0) === 1;", 'P4: only WHM\'s own result counts as changed');
has($src, "'result' => \$ok ? 'changed' : 'failed',", 'P4: and the record carries which it was');
has($src, "\$res['failed'][] = ['user' => \$p['id'], 'msg' => (string)\$r['msg']];", 'P4: a failure is named per identity, not swallowed');
has($src, "smpro_gr_record(\$p['id'], \$note, \$by, false,", 'P4: a failed reset is recorded too — the attempt is part of the history');

/* ---------- P5: a reason is required, because the password is not kept ---------- */
$noReason = smpro_gr_reset_bulk(['someuser'], '   ', 'root');
ok($noReason['ok'] === false, 'P5: no reason, no reset');
has($noReason['msg'], 'reason is required', 'P5: ...and it says why');
is_eq($noReason['secrets'], [], 'P5: and nothing was generated');
$noUser = smpro_gr_reset_bulk([], 'because', 'root');
ok($noUser['ok'] === false, 'P5: no account, no reset');
has($pg, 'It is what the record is for', 'P5: the page explains the requirement rather than just refusing');

/* ---------- P6: the generated password is usable and strong ---------- */
$pw = smpro_gr_password();
is_eq(strlen($pw), 20, 'P6: 20 characters');
ok(preg_match('/[A-Z]/', $pw) && preg_match('/[a-z]/', $pw) && preg_match('/[0-9]/', $pw) && preg_match('/[^A-Za-z0-9]/', $pw),
   'P6: upper, lower, digit and symbol are all guaranteed, not left to the draw');
ok(!preg_match('/[O0lI1]/', $pw), 'P6: no look-alike characters — a password mistyped twice gets replaced by a weak one');
$seen = [];
for ($i = 0; $i < 200; $i++) $seen[smpro_gr_password()] = 1;
is_eq(count($seen), 200, 'P6: 200 draws, 200 distinct passwords');
has($src, 'random_int(', 'P6: drawn from the cryptographic source, not rand()');
hasnt($src, 'mt_rand(', 'P6: ...and never from a predictable one');

/* ---------- P7: the report agrees with the lock about what "allowed" means ---------- */
has($src, "\$allowed = function_exists('smpro_gl_allowed_for') ? smpro_gl_allowed_for(\$u, \$cfg) : \$cfg['countries'];",
    'P7: it uses the Country Login Lock\'s own per-account list');
has($src, 'so the report and the lock can never disagree', 'P7: which is the point, and is stated');
has($src, "if (\$cc === '') { \$out['unknown_cc']++; continue; }", 'P7: an address that cannot be placed is never counted as foreign');
has($src, "\$a['severity'] = \$a['ok'] > 0 ? 'compromised' : 'attempted';",
    'P7: an ACCEPTED password is the finding; failures alone are somebody knocking');
has($pg, 'somebody knocking is not somebody inside', 'P7: ...said plainly, on the page');

/* ---------- P8: it will not report "all clear" when it could not look ---------- */
$blind = smpro_gr_scan(7);
if (!@is_readable('/usr/local/cpanel/logs/login_log')) {
    ok($blind['ok'] === false, 'P8: with no login log, the report refuses rather than returning an empty list');
    has($blind['msg'], 'not seen', 'P8: ...and says "not seen", not "nothing happened"');
} else {
    ok(true, 'P8: (skipped — this box has a readable login_log)');
}
has($src, 'No country list is set yet', 'P8: with no allow-list it refuses instead of flagging the whole server');
has($src, 'every country is "not allowed" and the report would flag the whole server', 'P8: ...and explains why that would be useless');

/* ---------- P9: gated, capped, recorded ---------- */
has($pg, "smpro_require_valid_csrf('fw_csf'); smpro_require_root();", 'P9: root-only and CSRF-checked');
has($src, "smpro_audit('password_reset'", 'P9: every reset reaches the audit log');
has($src, 'At most 200 identities in one reset - nothing was changed.', 'P9: a bulk reset is capped (refused whole, never trimmed silently)');
has($src, '@chmod(SMPRO_GR_LOG, 0600);', 'P9: the record is root-only on disk');
has($pg, 'Reset one account first', 'P9: and the page tells the operator to prove it on one account before the rest');
