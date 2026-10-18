<?php
/**
 * t55_lock_batching.php — locking many files must cost a few processes, not four per file.
 *
 * MEASURED on a cPanel box (2026-09-09), locking 200 files:
 *   command -v chattr, before every single file ....  564 ms   (2.82 ms each) — pure waste
 *   chattr +i, one process per file ................  968 ms   (4.84 ms each)
 *   lsattr -d read-back, one per file ..............  877 ms   (4.39 ms each)
 *   the same work in batched calls ..................  29 ms   → 83x faster
 * That arithmetic is why force-unprotect was quietly INCOMPLETE: its 45-second sweep budget was spent forking,
 * so it stopped after a few thousand files and said so, while the customer had been told they were released.
 *
 * These assertions use the lab's recording shims (tests/support/stub_path/{chattr,lsattr}), which write every
 * invocation to a file and change nothing. So they can prove two things a timing test could not prove reliably:
 * how many processes were spawned, and that a tool which accepts the command WITHOUT changing the attribute is
 * reported as a failure rather than a success.
 */
require __DIR__ . '/../support/bootstrap.php';
require SMPRO_BASE . '/tests/support/plugin_funcs.php';
smpro_plugin_funcs('includes/helpers.php');
smpro_plugin_funcs('includes/phlock.php');
smpro_plugin_funcs('modules/php-harden.php');

ok(function_exists('smpro_ph_chattr_many'), 'L0: the batched primitive exists');

/* ---------- these hold everywhere, including a box that has no chattr at all ---------- */
// The batched lock primitive and its helpers moved to includes/phlock.php so the cron worker can reach them;
// the callers that use them are still in the page module, so both files are read as one body of source.
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/phlock.php'))
      . str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/php-harden.php'));
has($src, "function smpro_ph_has(\$cmd) {
    static \$seen = [];", 'L6: smpro_ph_has caches its answer instead of probing before every file');
hasnt($src, "smpro_ph_chattr('-i', \$file); if (\$rc === 0) \$done++;", 'L6: the per-file unlock loop is gone');
$batched = substr_count($src, 'smpro_ph_chattr_many(');
ok($batched >= 6, 'L6: every bulk path goes through the batched call (' . $batched . ' uses) — a count, not a fixed number, so adding one does not fail this');
ok(!preg_match('/foreach[^
]*
\s*(?:\[\$rc\] = )?smpro_ph_chattr\(/', $src), 'L6: no loop calls the single-path version once per file');

/* ---------- L7: locking the site FOLDER — the option that stops a new file appearing at all ---------- */
// A file lock stops an existing file being overwritten; a folder lock stops a new one being created. The dc1
// takeover (2026-09-08) began with a file ADDED at the top of the site by someone holding the account password,
// which no file lock could have prevented. It is off unless ticked, and it is undone by Unlock and by Force
// Unprotect — a folder still locked while the page says "released" would be the same lie those exist to prevent.
has($src, 'function smpro_ph_apply($u, $mode, array $postFiles, array $postDirs, array $exts, array $postLockRoots = [])', 'L7: apply accepts the folders to lock, and defaults to none');
has($src, "if (in_array(\$d, \$accountRoots, true) && is_dir(\$d) && !is_link(\$d)) \$lockRoots[] = \$d;", 'L7: only THIS account\'s document roots qualify — never an arbitrary directory');
ok(strpos($src, "if (\$accountRoots) smpro_ph_chattr_many('-i', \$accountRoots);") < strpos($src, "\$lr = smpro_ph_chattr_many('+i', \$lockRoots);"),
   'L7: every root is opened BEFORE the work and closed after — otherwise a second run cannot write into a folder the first one locked');
has($src, "\$m['locked_roots'] = \$rootRows;", 'L7: what was locked is recorded, so it can be undone deliberately');
has($src, "if (\$rootDirs) { \$done += (int)smpro_ph_chattr_many('-i', \$rootDirs)['done']; }", 'L7: Unlock clears the folders too');
has($src, "foreach ((array)(\$m['locked_roots'] ?? []) as \$d) { \$p = is_array(\$d) ? (string)(\$d['dir'] ?? '') : (string)\$d; if (\$p !== '') \$files[] = \$p; }", 'L7: Force Unprotect clears them too');
has($src, 'Also lock the site folder itself', 'L7: the page offers it');
has($src, 'It also stops the site itself creating files there', 'L7: ...and states the consequence, not just the benefit');
has($src, "function lockRoots(){return Array.prototype.slice.call(document.querySelectorAll('.ph-lockroot:checked'))", 'L7: the choice is sent with the apply');
is_eq(substr_count($src, "lockRoots().forEach(function(r){fd.append('lock_roots[]',r);});"), 2, 'L7: both Fast and Custom send it');

if (DIRECTORY_SEPARATOR !== '/' || !smpro_ph_has('chattr')) {
    ok(true, 'L1-L5: (skipped — this box has no chattr/lsattr; the gate host runs them against the recording shims)');
    return;
}

$T = sys_get_temp_dir() . '/smpro_t55_' . getmypid();
@mkdir($T, 0700, true);
$paths = [];
for ($i = 0; $i < 50; $i++) { $p = "$T/f$i.php"; file_put_contents($p, "<?php // $i\n"); $paths[] = $p; }

$rec = fn($bin) => count(smpro_test_rec_lines($bin));
$calls0 = $rec('chattr');

/* ---------- L1: one process for the whole set, not one per file ---------- */
$r = smpro_ph_chattr_many('+i', $paths);
$spawned = $rec('chattr') - $calls0;
is_eq($spawned, 1, 'L1: 50 files → ' . $spawned . ' chattr process(es) (one per file would be 50)');

/* ---------- L2: a tool that accepts the command and changes nothing is a FAILURE, not a success ---------- */
// The shim exits 0 and sets no attribute — exactly like a filesystem that does not support attributes, or one
// mounted read-only. Trusting the exit code would report all 50 locked.
ok($r['ok'] === false, 'L2: reported as failed, because reading the attribute back showed it did not take');
is_eq(count($r['failed']), 50, 'L2: every file is named, not just a count');
has((string)reset($r['failed']), 'the lock did not take', 'L2: with a reason a person can act on');
is_eq($r['done'], 0, 'L2: nothing is claimed as done');

/* ---------- L3: work that is already done spawns nothing ---------- */
$calls1 = $rec('chattr');
$r2 = smpro_ph_chattr_many('-i', $paths);            // the shim reports nothing locked, so they are already clear
is_eq($rec('chattr') - $calls1, 0, 'L3: clearing files that are already clear spawns no process at all');
is_eq($r2['done'], 50, 'L3: ...and still reports them done');
is_eq(count($r2['already']), 50, 'L3: ...as already in the wanted state');
ok($r2['ok'], 'L3: ok');

/* ---------- L4: large sets are chunked, not one giant command line ---------- */
$many = [];
for ($i = 0; $i < 450; $i++) { $p = "$T/g$i.php"; file_put_contents($p, '<?php'); $many[] = $p; }
$calls2 = $rec('chattr');
smpro_ph_chattr_many('+i', $many);
$n = $rec('chattr') - $calls2;
is_eq($n, 3, 'L4: 450 files → ' . $n . ' chunked calls (200 per call), never one command line of 450 paths');

/* ---------- L5: nothing that cannot be locked reaches a process ---------- */
$calls3 = $rec('chattr');
$r3 = smpro_ph_chattr_many('+i', ["$T/does-not-exist.php", "$T/also-missing.php"]);
is_eq($rec('chattr') - $calls3, 0, 'L5: missing paths are dropped by a stat, not by a process');
is_eq(count($r3['skipped']), 2, 'L5: ...and are reported as skipped');
$r4 = smpro_ph_chattr_many('sudo rm -rf /', $paths);
ok(!$r4['ok'] && $rec('chattr') - $calls3 === 0, 'L5: an invalid flag runs nothing (only +i and -i exist)');
$r5 = smpro_ph_chattr_many('+i', []);
ok($r5['ok'] && $r5['done'] === 0, 'L5: an empty list is a no-op, not an error');

/* ---------- L8: a directory is a path like any other to the batched primitive ---------- */
$dirT = "$T/lockme";
@mkdir($dirT, 0755, true);
$calls4 = $rec('chattr');
$rd = smpro_ph_chattr_many('+i', [$dirT]);
is_eq($rec('chattr') - $calls4, 1, 'L8: locking a folder is one process');
$recLines = smpro_test_rec_lines('chattr'); $last = $recLines ? end($recLines) : '';   // end() takes a variable, not a call
has((string)$last, $dirT, 'L8: ...and the folder is what was passed to chattr');
@rmdir($dirT);

foreach (array_merge($paths, $many) as $p) @unlink($p);
@rmdir($T);
