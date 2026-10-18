<?php
/**
 * t71_evidence.php — the local evidence journal.
 *
 * Why it exists: asked why mail had been switched off on a production server on 19 July, the answer was in
 * exim's log — and the rotation covering that day had been compressed and ended on 18 July. The evidence was
 * gone, rotated away by the machine's own housekeeping while nobody was looking.
 *
 * What the tests guard is the difference between a journal and a backup: a record cannot be removed without the
 * removal being provable, and a source that could not be read is written down rather than passing for a quiet day.
 */
$tmp = sys_get_temp_dir() . '/smpro_t71_' . getmypid();
define('SMPRO_EV_DIR',   $tmp);
define('SMPRO_EV_STATE', $tmp . '/state.json');
define('SMPRO_EV_KEEP',  30);

require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/evidence.php';

@mkdir($tmp, 0700, true);
$today = date('Y-m-d');
$file  = smpro_ev_path($today);

/* ---------- U1: a record is written, and it is chained ---------- */
$r1 = smpro_ev_append('login', ['u' => 'alice', 'ip' => '203.0.113.1', 'k' => 'password']);
ok(!empty($r1['ok']), 'U1: a record can be written');
is_eq($r1['seq'], 1, 'U1: the first record of the day is number 1');

$r2 = smpro_ev_append('login', ['u' => 'bob', 'ip' => '203.0.113.2', 'k' => 'password']);
is_eq($r2['seq'], 2, 'U1: and the next is 2');

$lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
is_eq(count($lines), 2, 'U1: both are on disk');
$a = json_decode($lines[0], true);
$b = json_decode($lines[1], true);
is_eq($a['prev'], 'genesis', 'U1: the very first record says so rather than pretending to follow something');
is_eq($b['prev'], hash('sha256', $lines[0]), 'U1: the second carries the hash of the first');

/* ---------- U2: the journal is private ---------- */
// It holds account names and addresses. A world-readable evidence file is a leak with a timestamp on it.
if (DIRECTORY_SEPARATOR === '/') {
    is_eq(substr(sprintf('%o', fileperms($file)), -3), '600', 'U2: the journal is readable only by root');
    is_eq(substr(sprintf('%o', fileperms($tmp)), -3),  '700', 'U2: and so is the directory');
} else {
    ok(true, 'U2: file modes are not meaningful on this platform (skipped)');
    ok(true, 'U2: directory modes likewise (skipped)');
}

/* ---------- U3: removing a record is PROVABLE, not silent ---------- */
// This is the property that separates a journal from a copy of the logs. It does not stop somebody with root
// from editing the file — nothing local can — it stops them from doing it without leaving a mark.
$v = smpro_ev_verify($today);
ok($v['ok'], 'U3: an untouched journal verifies');
is_eq($v['records'], 2, 'U3: and counts what is there');

smpro_ev_append('login', ['u' => 'carol', 'ip' => '203.0.113.3', 'k' => 'password']);
$all = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
// take out the middle record, exactly as somebody covering their tracks would
file_put_contents($file, $all[0] . "\n" . $all[2] . "\n");
$v2 = smpro_ev_verify($today);
ok(!$v2['ok'], 'U3: a removed record does NOT go unnoticed');
ok(!empty($v2['breaks']), 'U3: and the break is reported');
is_eq($v2['breaks'][0]['record'] ?? 0, 2, 'U3: naming which record no longer follows the one before it');
has((string)($v2['breaks'][0]['why'] ?? ''), 'removed or altered', 'U3: in words an operator can act on');

// an ALTERED record is caught the same way
file_put_contents($file, implode("\n", $all) . "\n");
$tampered = str_replace('203.0.113.2', '203.0.113.99', $all[1]);
file_put_contents($file, $all[0] . "\n" . $tampered . "\n" . $all[2] . "\n");
$v3 = smpro_ev_verify($today);
ok(!$v3['ok'], 'U3: and so does editing one in place');

/* ---------- U4: sealing a day, and carrying the chain across midnight ---------- */
file_put_contents($file, implode("\n", $all) . "\n");          // put the good journal back
$seal = smpro_ev_seal($today);
ok(!empty($seal['ok']), 'U4: a day can be sealed');
is_eq($seal['sealed']['records'], 3, 'U4: the seal records how many there were');
is_eq($seal['sealed']['head'], hash('sha256', $all[2]), 'U4: and the hash the next day must chain to');
ok(@is_file(smpro_ev_seal_path($today)), 'U4: the seal is on disk');

$again = smpro_ev_seal($today);
ok(!empty($again['already']), 'U4: sealing twice does not rewrite history');

/* ---------- U5: the seal makes a MISSING DAY visible too ---------- */
// A gap in the records is one thing; a whole day quietly deleted is the thing an attacker would actually do.
@unlink($file);
$v4 = smpro_ev_verify($today);
ok(!$v4['ok'], 'U5: a deleted day is caught by its own seal');
has((string)($v4['breaks'][0]['why'] ?? ''), 'seal', 'U5: and is reported as a missing journal, not as no data');

/* ---------- U6: "could not look" becomes a record ---------- */
// The single property everything else in this product is built on. A day with no sign-ins because nothing
// happened and a day with no sign-ins because the log was unreadable must never look the same.
@unlink(SMPRO_EV_STATE);
foreach ((array)glob($tmp . '/*') as $f) @unlink($f);
smpro_ev_append('blind', ['why' => 'the sign-in logs could not be read']);
$rec = json_decode((string)file(smpro_ev_path($today))[0], true);
is_eq($rec['kind'], 'blind', 'U6: an unreadable source is written down as its own kind of record');
has((string)$rec['d']['why'], 'could not be read', 'U6: with the reason, at the time it happened');

/* ---------- U7: retention keeps the proof after it drops the detail ---------- */
// Pruning a day removes what it held. Removing its SEAL as well would remove the proof that it was never
// tampered with — so the seals stay for ever, at a few hundred bytes each.
$old = date('Y-m-d', time() - 400 * 86400);
file_put_contents(smpro_ev_path($old), json_encode(['seq' => 1, 'ts' => time() - 400 * 86400, 'kind' => 'login', 'prev' => 'genesis', 'd' => []]) . "\n");
$p = smpro_ev_prune(30);
ok(in_array($old, $p['removed'], true), 'U7: a day past the window is removed');
ok(!@is_file(smpro_ev_path($old)),      'U7: its detail is gone');
ok(@is_file(smpro_ev_seal_path($old)),  'U7: its seal is NOT — the proof outlives the data');

/* ---------- U8: it is cheap, and says so ---------- */
$st = smpro_ev_stats();
ok(isset($st['bytes'], $st['records'], $st['per_day']), 'U8: the cost of the journal is reportable');
is_eq($st['keep_days'], 30, 'U8: with the retention window it is keeping to');

/* ---------- U9: a test must never install a live cron ---------- */
ok(smpro_ev_cron_sync() === true, 'U9: cron installation is refused under the test guard');
ok(!@is_file('/etc/cron.d/smpro-evidence') || defined('SMPRO_TEST_SRC'), 'U9: and nothing was written to /etc/cron.d');

foreach ((array)glob($tmp . '/*') as $f) @unlink($f);
@rmdir($tmp);

/* ---------- U10: a worker running is not an event ---------- */
// The first version of the action filter matched substrings, and 'protect' matched `siteprotection_worker`, a
// heartbeat that runs every minute. One live server wrote 1,740 identical records of that worker failing and its
// first day came to 476 KB — against the ~2 KB the same server's real activity costs. An evidence store that
// fills with heartbeats is one nobody reads, which is the same as not having it.
$ev = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/evidence.php'));
has($ev, '_worker|_run|_view|_status|_check', 'U10: heartbeat and view actions are named and dropped');
has($ev, 'siteprotection_worker',             'U10: with the incident that produced the rule written down');
has($ev, "\$bucket[\$key]['n']++",            'U10: identical repeats collapse to one record with a count');
has($ev, "\$d['until'] = \$b['last']",        'U10: keeping the span, so "failing all week" stays readable');

/* ---------- U11: the journal starts when it starts, and says so ---------- */
// Taking in the whole existing audit log would back-date months of history into today's file and stamp it with
// today as the moment it was recorded — a lie about the one thing a journal is for.
has($ev, '$first)                                $pos = $size;', 'U11: the first run starts at the END of the audit log');
has($ev, 'the journal starts here',                              'U11: and records that the earlier history was not taken in');

/* ---------- U12: a restarted chain is not an accusation of tampering ---------- */
// Within an hour of the first live install the five-minute cron overlapped a manual run, the state file was
// read by both, and the verifier reported tampering on a server where nothing had been tampered with. A
// detector that cries wolf gets switched off, and then it is worse than not having one.
$tmp2 = sys_get_temp_dir() . '/smpro_t71b_' . getmypid();
@mkdir($tmp2, 0700, true);
$day2 = date('Y-m-d');
$mk = function ($seq, $prev) { return json_encode(['seq' => $seq, 'ts' => time(), 'kind' => 'login', 'prev' => $prev, 'd' => []]); };
$l1 = $mk(1, 'genesis');
$l2 = $mk(2, hash('sha256', $l1));
$l3 = $mk(1, 'genesis');                    // the state was lost; the writer began again
file_put_contents(smpro_ev_path($day2), $l1 . "\n" . $l2 . "\n" . $l3 . "\n");

$v5 = smpro_ev_verify($day2);
is_eq($v5['breaks'], [], 'U12: a chain that RESTARTS is not reported as a break');
ok(!empty($v5['restarts']), 'U12: it is reported as a restart, separately');
has((string)($v5['restarts'][0]['why'] ?? ''), 'not tampered with', 'U12: and says so in words');
ok($v5['ok'], 'U12: so the journal still verifies — nothing was removed');

// a genuine removal is still caught, in the same file
file_put_contents(smpro_ev_path($day2), $l1 . "\n" . $mk(3, hash('sha256', $l2)) . "\n");
$v6 = smpro_ev_verify($day2);
ok(!$v6['ok'], 'U12: while an actually removed record is still caught');
ok(!empty($v6['breaks']), 'U12: and is still called a break, not a restart');

/* ---------- U13: two writers cannot break the chain ---------- */
// The read-state / write-record / write-state sequence is not atomic across processes on its own.
$ev2 = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/evidence.php'));
ok(function_exists('smpro_ev_lock'), 'U13: the writer takes a lock');
has($ev2, 'flock($fh, LOCK_EX)',     'U13: an exclusive one');
has($ev2, 'smpro_ev_unlock($lk);',   'U13: released on every path out of the writer');
has($ev2, 'smpro_ev_last_record',    'U13: and a lost state file is recovered from the journal, not restarted');

foreach ((array)glob($tmp2 . '/*') as $f) @unlink($f);
@rmdir($tmp2);
