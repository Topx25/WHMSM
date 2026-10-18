<?php
/**
 * r11_ph_ignore.php — locks the force-unprotect ignore list.
 *
 * The list only earns its place if the UNATTENDED passes obey it. An exclusion that holds in the interface and is
 * ignored by the intrusion tick is worse than none: the operator sees the account listed as excluded and the cron
 * re-locks it anyway, a few hours later, with no visible connection between the two. So what is checked here is
 * the reading side as much as the writing side, and specifically that the reader reachable from a cron worker
 * gives the same answer as the page.
 */
require __DIR__ . '/../support/bootstrap.php';
require SMPRO_BASE . '/tests/support/plugin_funcs.php';
smpro_plugin_funcs('includes/ph_ignore.php');

ok(function_exists('smpro_ph_ign_add') && function_exists('smpro_ph_ign_has'), 'ignore list: functions loaded');

@unlink(smpro_ph_ign_path());
is_eq(count(smpro_ph_ign_all()), 0, 'ignore list: starts empty');
ok(!smpro_ph_ign_has('anyone'), 'ignore list: an account that was never added is NOT excluded');

ok(smpro_ph_ign_add('demoacct', 'self-updating installer rewrites wp-config', 'root'), 'ignore list: an account can be added');
ok(smpro_ph_ign_has('demoacct', 'auto'), 'ignore list: automatic passes skip it');
ok(smpro_ph_ign_has('demoacct', 'manual'), 'ignore list: the default scope also refuses hand-applied protection');

$row = smpro_ph_ign_get('demoacct');
is_eq($row['reason'], 'self-updating installer rewrites wp-config', 'ignore list: the reason is kept, not just the name');
is_eq($row['by'], 'root', 'ignore list: who added it is kept');
ok(($row['at'] ?? '') !== '', 'ignore list: when it was added is kept');

// The narrower scope is the one that is easy to get backwards: it must stop the cron and still allow an admin.
ok(smpro_ph_ign_add('partial', 'deploy pipeline owns the files', 'root', 'auto'), 'ignore list: scope "auto" accepted');
ok(smpro_ph_ign_has('partial', 'auto'), 'ignore list: scope "auto" — automatic passes skip it');
ok(!smpro_ph_ign_has('partial', 'manual'), 'ignore list: scope "auto" — an admin on the page is NOT blocked');

// Persistence across processes is the whole point: the cron worker is a different process from the page.
$reread = json_decode((string)file_get_contents(smpro_ph_ign_path()), true);
ok(is_array($reread) && isset($reread['demoacct']), 'ignore list: written to disk, so another process sees it');
is_eq((int)@fileperms(smpro_ph_ign_path()) & 0777, 0600, 'ignore list: not world-readable');

// A username that could escape the state directory must never become a filename or a key.
ok(!smpro_ph_ign_add('../../etc/passwd', 'x', 'root'), 'ignore list: a path-traversing name is refused');
ok(!smpro_ph_ign_has('../../etc/passwd'), 'ignore list: and is not present afterwards');

ok(smpro_ph_ign_remove('demoacct'), 'ignore list: an entry can be removed');
ok(!smpro_ph_ign_has('demoacct'), 'ignore list: removal takes effect immediately');
ok(!smpro_ph_ign_remove('demoacct'), 'ignore list: removing what is not there reports false, not success');
ok(smpro_ph_ign_has('partial', 'auto'), 'ignore list: removing one entry left the others alone');

@unlink(smpro_ph_ign_path());
