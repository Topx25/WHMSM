<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
/** t104 - smpro_memo_cmd: inline on a miss, cached while fresh, STALE value served (not recomputed) once expired. */
$k = 'test_memo_cmd_' . getmypid();
$f = SMPRO_CACHE . '/memo_' . $k . '.json';
@unlink($f);
$v1 = smpro_memo_cmd($k, 60, 'echo one', 5);
is_eq(trim($v1), 'one', 'U1: a miss runs the command inline');
ok(is_file($f), 'U1: ...and stores it');
$v2 = smpro_memo_cmd($k, 60, 'echo two', 5);
is_eq(trim($v2), 'one', 'U2: while fresh the cache answers, the new command is not run');
@touch($f, time() - 120);
$v3 = smpro_memo_cmd($k, 60, 'echo three', 5);
is_eq(trim($v3), 'one', 'U3: once expired the STALE value is served (refresh goes to the background, which the lab skips)');
hasnt((string)@file_get_contents(SMPRO_CACHE . '/memo_' . $k . '.cmd'), 'three', 'U3: no refresher hand-off inside the lab');
@touch($f, time() - 10 * 86400);
$v4 = smpro_memo_cmd($k, 60, 'echo four', 5);
is_eq(trim($v4), 'four', 'U4: past the stale limit the command runs inline again');
@unlink($f);
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/bin/memo_refresh.php'));
has($src, "SMPRO_CACHE . '/memo_' . \$key . '.cmd'", 'U5: the refresher takes the command from the root-only cache dir, never from argv');
$ar = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/analytics.php'));   // beta297: the counts moved to an include
has($ar, "smpro_memo_cmd('ar_' . sha1(\$cmd), 600, \$cmd, 14)", 'U6: analytics counts use the stale-while-refresh memo');
$db = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/dbhealth.php'));
has($db, "smpro_memo_cmd('dbh_datasize'", 'U6: database size scan too'); has($db, "smpro_memo_cmd('dbh_myisam'", 'U6: MyISAM table scan too');
