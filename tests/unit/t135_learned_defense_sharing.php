<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
if (!defined('SMPRO_VARLIB')) define('SMPRO_VARLIB', sys_get_temp_dir() . '/t135_varlib_' . getmypid());
require_once SMPRO_BASE . '/includes/learn.php';
/** t135 - lessons are shared between servers as PATTERNS only: nothing that identifies a site, an account, a file's
 *  contents or an address leaves; a shared lesson is reported here and never acts by itself; a "wrong" vote goes back. */
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/learn.php'));
has($src, "function smpro_lr_share_types(): array { return ['hash', 'dotdir', 'behaviour', 'docblock']; }", 'S1: only hash, hidden-folder, behaviour and header lessons are shared - never a place inside a site');
has($src, "unset(\$p['telemetry']);", 'S2: the license payload goes without the telemetry block');
has($src, "&& (\$L[\$lid]['source'] ?? '') !== 'shared' && !empty(\$L[\$lid]['incidents'])", 'S3: automatic quarantine needs a lesson confirmed HERE, never a shared one');
has($src, "if (time() - (int)(smpro_lr_load('share')['last'] ?? 0) > 6 * 3600) smpro_lr_share();", 'S4: the worker exchanges every six hours');

// what goes out
$L = [
    'a' => ['id' => 'a', 'type' => 'hash',      'key' => str_repeat('a', 64) . ':639', 'label' => 'The exact file found at /home/acct/public_html/x.php', 'state' => 'on', 'incidents' => [['path' => '/home/acct/public_html/x.php', 'user' => 'acct', 'sha' => 'x']], 'hits' => 3, 'fp' => 0],
    'b' => ['id' => 'b', 'type' => 'relpath',   'key' => 'wp-content/x.php', 'label' => 'A file at wp-content/x.php', 'state' => 'on', 'incidents' => [['path' => '/home/acct/public_html/wp-content/x.php']], 'hits' => 1, 'fp' => 0],
    'c' => ['id' => 'c', 'type' => 'dotdir',    'key' => '.well-known:php', 'label' => '.php script inside .well-known/', 'state' => 'off', 'incidents' => [['path' => '/home/acct/public_html/.well-known/y.php']], 'hits' => 0, 'fp' => 0],
    'd' => ['id' => 'd', 'type' => 'behaviour', 'key' => 'dyn_exec+net_fetch', 'label' => 'Code that downloads code from the internet and runs it', 'state' => 'on', 'incidents' => [], 'hits' => 0, 'fp' => 0],
    'e' => ['id' => 'e', 'type' => 'behaviour', 'key' => 'cmd_exec+req_input', 'label' => 'Code that runs system commands taken from the web request', 'state' => 'off', 'incidents' => [], 'hits' => 2, 'fp' => 1, 'source' => 'shared'],
    'f' => ['id' => 'f', 'type' => 'dotdir',    'key' => '.tmb:php', 'label' => '.php script inside .tmb/', 'state' => 'on', 'incidents' => [], 'hits' => 0, 'fp' => 0, 'source' => 'shared'],
];
$byId = []; foreach ($L as $l) { $l['id'] = substr(sha1($l['type'] . '|' . $l['key']), 0, 12); $byId[$l['id']] = $l; } $L = $byId;
$ID = fn($t, $k) => substr(sha1($t . '|' . $k), 0, 12);
$out = smpro_lr_share_payload($L);
$keys = array_map(fn($x) => $x['type'] . '|' . $x['key'], $out);
is_eq($keys, ['hash|' . str_repeat('a', 64) . ':639', 'behaviour|cmd_exec+req_input'], 'O1: sent = the hash confirmed here + the wrong-vote on a shared lesson; not the place, not the switched-off one, not the unconfirmed behaviour, not an untouched shared one');
$json = json_encode($out);
ok(strpos($json, '/home/') === false && strpos($json, 'acct') === false && strpos($json, 'incidents') === false && strpos($json, 'path') === false, 'O2: no path, no account, no incident goes out');
is_eq($out[1]['fp'], 1, 'O3: the wrong-vote carries its count');
is_eq($out[0]['label'], 'An exact file confirmed as malware (639 bytes)', 'O4: a hash lesson goes out with a label built from its key, not the local one that names the path');

// what comes in
$pool = [
    ['type' => 'hash', 'key' => str_repeat('b', 64) . ':1200', 'label' => 'The exact file found at /home/other/site/z.php', 'servers' => 3],
    ['type' => 'dotdir', 'key' => '.tmb:php', 'label' => '.php script inside .tmb/', 'servers' => 4],
    ['type' => 'relpath', 'key' => 'wp-content/evil.php', 'label' => 'should never arrive', 'servers' => 9],
    ['type' => 'hash', 'key' => str_repeat('a', 64) . ':639', 'label' => 'mine too', 'servers' => 2],
];
[$M, $new] = smpro_lr_share_merge($L, $pool);
is_eq($new, 1, 'I1: one lesson is new here (the hash); the .tmb one was already known as shared, mine stays mine');
$nb = $M[substr(sha1('hash|' . str_repeat('b', 64) . ':1200'), 0, 12)];
is_eq([$nb['source'], $nb['state'], $nb['incidents'], $nb['shared']['servers']], ['shared', 'on', [], 3], 'I1: it arrives as shared, on, with no incidents, and says how many servers vouch for it');
ok(!isset($M[substr(sha1('relpath|wp-content/evil.php'), 0, 12)]), 'I2: a place lesson in the pool is refused on arrival');
is_eq($M[$ID('hash', str_repeat('a', 64) . ':639')]['incidents'][0]['user'], 'acct', 'I3: a local lesson that is also in the pool keeps its own incidents and standing');
is_eq($M[$ID('dotdir', '.tmb:php')]['shared']['servers'], 4, 'I4: a shared lesson still in the pool is refreshed');
ok(isset($M[$ID('behaviour', 'cmd_exec+req_input')]), 'I5: a shared lesson marked wrong here is kept (off) as the record, even when withdrawn upstream');
[$M2] = smpro_lr_share_merge($M, [['type' => 'hash', 'key' => str_repeat('b', 64) . ':1200', 'label' => 'x', 'servers' => 3]]);
ok(!isset($M2[$ID('dotdir', '.tmb:php')]), 'I6: a shared lesson that left the pool (withdrawn) is removed here');
@exec('rm -rf ' . escapeshellarg(SMPRO_VARLIB));
