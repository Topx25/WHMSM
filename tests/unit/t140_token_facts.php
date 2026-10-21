<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
if (!defined('SMPRO_VARLIB')) define('SMPRO_VARLIB', sys_get_temp_dir() . '/t140_varlib_' . getmypid());
require_once SMPRO_BASE . '/includes/compcheck.php';
require_once SMPRO_BASE . '/includes/ccfix.php';
/** t140 - an API token is only actionable when the operator can see what it can do, who made it, whether it expires
 *  and when it was last used; a token can be closed without being erased; an FTP login can go without its files;
 *  and every kind of door says in one sentence what it is. */
$cc = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/compcheck.php'));
$fx = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/ccfix.php'));
$pg = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/compromise-check.php'));

// the five facts
$line = smpro_cc_token_line('t140_demo', ['create_time' => 1700000000, 'expires_at' => null, 'acls' => ['all' => 1]], true);
has($line, 'can do: EVERYTHING root can do in WHM', 'F1: a WHM token holding "all" says so in words');
has($line, 'expires: NEVER', 'F2: a token with no expiry says NEVER, not an empty field');
has($line, 'made: 2023-11-14', 'F3: the creation time is shown');
has($line, 'by: not in the log kept on this server', 'F4: an unknown creator is said to be unknown, never left out');
has($line, 'last used: never seen in the token log', 'F5: never used is a fact, not a blank');
$line2 = smpro_cc_token_line('t140_demo2', ['create_time' => 1700000000, 'expires_at' => 1700000600, 'acls' => ['list-accts' => 1, 'create-acct' => 1]], true);
has($line2, '2 permission(s): list-accts, create-acct', 'F6: a limited token lists what it may do');
has($line2, '(already expired - it no longer opens anything)', 'F7: an expiry in the past is called out');
$line3 = smpro_cc_token_line('t140_acct', ['create_time' => 0, 'has_full_access' => 1, 'whitelist_ips' => ['203.0.113.4']], false);
has($line3, 'can do: everything the account can do', 'F8: an account token says the account scope, not root');
has($line3, 'only from: 203.0.113.4', 'F9: an address restriction is shown when the token has one');
has($line3, 'made: unknown', 'F10: a missing creation time is unknown');

// the readers are read-only and bounded
has($cc, "'tail -n 20000 ' . escapeshellarg(\$f)", 'R1: the token log is read from its tail, never held whole');
hasnt($cc, 'file_put_contents', 'R2: nothing in the reader writes');
has($cc, "\$m[rawurldecode(\$n[1])] = [\$d ? (int)\$d->getTimestamp() : 0, \$a[1], \$a[2]];", 'R3: the creator address and user come from cPanel own access log');

// closing a token without erasing it
has($fx, "'roottok_disable'=> ['label' => 'Disable (expire now)'", 'D1: a WHM token can be disabled, not only revoked');
has($fx, "whmapi1 api_token_update token_name=' . escapeshellarg(\$a['name']) . ' expires_at=' . (time() - 60)", 'D2: disable = an expiry in the past, through cPanel own API');
has($fx, "if (strpos(\$a['name'], 'reverse_trust_') === 0) { \$r = ['ok' => false, 'msg' => 'refused: that is a cPanel transfer token']; break; }\n                // An expiry in the past", 'D3: a cPanel transfer token is refused by disable too');
ok(isset(smpro_cx_ops()['roottok_disable']) && isset(smpro_cx_ops()['roottok_revoke']), 'D4: both operations are offered');
is_eq(smpro_cx_apply('roottok_disable', ['name' => 'reverse_trust_x'])['ok'], false, 'D5: and the refusal really happens');
has($fx, "'token_disable'=> ['label' => 'Disable (expire now)'", 'D6: an account token can be disabled too');
has($fx, "Cpanel::Security::Authn::APITokens::Write::cpanel->new({ user => \$ARGV[0] }); \$w->update_token({ name => \$ARGV[1], expires_at => ", 'D7: through the store class cPanel itself writes, with the expiry in the past');
has($fx, "\$r = (\$exp > 0 && \$exp < time())", 'D8: and it counts as done only when the public API reads the expiry back');
has($cc, "'alt' => \$dead ? null : ['op' => 'token_disable', 'user' => \$u, 'name' => \$name]", 'D9: every live account token carries both buttons');
has($pg, "if ((\$f['flag'] || \$f['kind'] === 'token') && \$op !== ''", 'D10: a token shows its buttons whatever its age');
has($cc, 'grep -aE "api_token_create|Tokens/create"', 'D11: who made an account token is read from the UAPI creation path too');

// the FTP login goes, the files stay
has($fx, "'ftp_delete'   => ['label' => 'Delete the login, keep the files'", 'P1: the button says what it does');
has($fx, 'destroy=0', 'P2: cPanel is told to keep the files');
has($fx, "Its folder and files were NOT touched (destroy=0) - only the way in is gone.", 'P3: and the result says so afterwards');

// every door kind explains itself
has($pg, '$KIND_WHAT = [', 'E1: each kind of door carries a sentence saying what it is');
foreach (['ftp', 'forwarder', 'cron', 'sshkey', 'contact', 'mailbox', 'token', 'shellrc'] as $k)
    has($pg, "'" . $k . "'", 'E2: ' . $k . ' is explained');
has($pg, 'run on EVERY shell the account opens', 'E3: shell start-up says why it keeps coming back');
has($pg, '"forgot password" links above all', 'E4: the contact address says what is actually at stake');
@exec('rm -rf ' . escapeshellarg(SMPRO_VARLIB));

// the token list is keyed by the NAME, whichever source it came from
has($cc, "foreach (\$toks as \$k => \$x) { \$n = (string)(\$x['name'] ?? ''); if (\$n === '') \$n = (string)\$k; \$byName[\$n] = (array)\$x; }", 'K1: cPanel file (keyed by hash) and API (keyed by name) are both keyed by name');
has($cc, 'Keyed by hash, every "is this one cPanel\'s own?" test below failed', 'K2: the reason is written where the next reader will need it');
$file = ['tokens' => ['a1b2c3hash' => ['name' => 'reverse_trust_1', 'create_time' => 1], 'd4e5f6hash' => ['name' => 'deploy-bot', 'create_time' => 2]]];
$byName = []; foreach ((array)$file['tokens'] as $k => $x) { $n = (string)($x['name'] ?? ''); if ($n === '') $n = (string)$k; $byName[$n] = (array)$x; }
$mine = array_filter($byName, fn($x, $n) => strpos((string)$n, 'reverse_trust_') !== 0, ARRAY_FILTER_USE_BOTH);
is_eq(array_keys($mine), ['deploy-bot'], 'K3: with names as keys, a transfer token is no longer reported as one the operator made');
is_eq(count($byName) - count($mine), 1, 'K4: and the transfer tokens are counted separately');
