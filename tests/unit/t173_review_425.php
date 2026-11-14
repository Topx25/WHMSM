<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
require_once SMPRO_BASE . '/includes/learn.php';
/**
 * t173 - the test copy of the source, the quarantine journal, the scheduled check that never reported, the old
 * home that was deleted with files still being written to it, and two more things an uninstall left behind.
 */
$src = fn($p) => str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $p));

// the copy some tests load instead of the source must be THIS source
if (SMPRO_TEST_BUILD === SMPRO_TEST_SRC) tap_skip('B1-B2: the harness copy is current', 'no harness copy in this run (the tests read the source itself)');
else {
    $v = fn($f) => preg_match("/define\('SMPRO_VERSION',\s*'([^']+)'/", (string)@file_get_contents($f), $m) ? $m[1] : '';
    is_eq($v(SMPRO_TEST_BUILD . '/includes/defines.php'), $v(SMPRO_TEST_SRC . '/includes/defines.php'), 'B1: the harness copy is the version being tested');
    is_eq(count(glob(SMPRO_TEST_BUILD . '/includes/*.php')), count(glob(SMPRO_TEST_SRC . '/includes/*.php')), 'B2: ...with every include of it');
}
$st = is_file(SMPRO_BASE . '/tests/smpro_test.php') ? $src('tests/smpro_test.php') : '';
if ($st === '') tap_skip('B3: a copy that could not be regenerated stops the suite', 'the suite runner is not part of this tree');
else has($st, "if (is_file(\$mkb) && (!isset(\$brc) || (int)\$brc !== 0)) die_unsafe(", 'B3: a copy that could not be regenerated stops the suite');

// the quarantine journal: one writer at a time, replaced in one step
$dir = smpro_lr_dir(); @unlink($dir . '/quarantine.jsonl');
$h = smpro_lr_qlock(); ok($h !== null, 'Q1: the journal lock is taken');
ok(smpro_lr_qwrite([json_encode(['kept' => '/store/a', 'orig' => '/home/u/a.php']), json_encode(['kept' => '/store/b', 'orig' => '/home/u/b.php'])]), 'Q2: the journal is written');
smpro_lr_qunlock($h);
smpro_lr_verdict_save('/store/b', ['verdict' => 'clean', 'sha' => 'x']);
$rows = array_map(fn($l) => json_decode($l, true), file($dir . '/quarantine.jsonl', FILE_IGNORE_NEW_LINES));
ok(count($rows) === 2 && ($rows[1]['verdict']['verdict'] ?? '') === 'clean' && !isset($rows[0]['verdict']), 'Q3: a verdict is written into its own row and no row is lost');
ok(!glob($dir . '/quarantine.jsonl.*.tmp'), 'Q4: no temporary file is left');
$lr = $src('includes/learn.php');
ok(substr_count($lr, 'smpro_lr_qlock();') >= 3 && substr_count($lr, 'smpro_lr_qunlock($qlk);') >= 3, 'Q5: the append, the verdict and the restore all hold the lock');
has($lr, "\$all = @file(smpro_lr_dir() . '/quarantine.jsonl', FILE_IGNORE_NEW_LINES) ?: \$all;   // as it is NOW", 'Q6: the restore re-reads the journal under the lock before it rewrites it');
@unlink($dir . '/quarantine.jsonl');

$cc = $src('includes/ccfix.php');
has($cc, "if (!\$force && !empty(\$c['run_started']) && function_exists('smpro_notify')) {", 'S1: a scheduled check that never finished is reported at the next run');
has($cc, "\$cNow = smpro_cx_sched_cfg(); \$cNow['last_run'] = \$rep['at'];", 'S2: the plan is read again before it is saved');
has($cc, "unset(\$cNow['run_started']);", 'S3: a finished run clears its marker');

$hm = $src('bin/home_move.php');
has($hm, "rsync -aHAXS --numeric-ids --update ' . escapeshellarg(\$src . '/') . ' ' . escapeshellarg((string)\$st['dst'] . '/')", 'H1: reclaim copies what was still written to the old home first');
has($hm, "The old copy at ' . \$src . ' was NOT deleted", 'H2: ...and deletes nothing when that copy failed');

$up = $src('includes/update.php');
has($up, "\$done[] = 'Site Shield removed from the web server (' . \$n . ' file(s))'", 'U1: an uninstall removes the per-site shield files');
has($up, "' -D -k ' . escapeshellarg(defined('SMPRO_FA_KEY') ? SMPRO_FA_KEY : 'smpro_files')", 'U2: ...and the file-audit rules, from the kernel too');
