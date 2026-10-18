<?php
require __DIR__ . '/../support/bootstrap.php';
/**
 * r33_workers_can_load.php — every cron worker must be able to load what it guards on.
 *
 * THE INCIDENT. bin/sp_queue.php performs the file-lock requests accounts make from cPanel. It refuses to run
 * unless smpro_ph_chattr() and smpro_ph_roots() are present, and its own comment said "everything this worker
 * needs now lives in includes/, so nothing is extracted out of a page module at runtime".
 *
 * That was not true. Both functions were still in modules/php-harden.php — and a page module can never be
 * required from cron, because it runs its router at include time. So the guard fired on every single run, the
 * worker exited, and Site Protection performed NOTHING on a live server for 29 hours: 1,768 consecutive refusals,
 * while the panel went on offering the feature to accounts.
 *
 * The guard was right. Refusing is much better than reporting requests as handled without handling them. What
 * was wrong is that a claim about where code lives was written in a comment and then trusted, and nothing
 * checked it — so the only thing that could notice was a production server, and the only way anyone noticed at
 * all was that the new evidence journal wrote the refusal down 1,740 times.
 *
 * So: each worker is booted with exactly the includes IT names, and every function it guards on must resolve.
 * A worker that cannot satisfy its own guard now fails here instead of in somebody's cron.
 */
$root = dirname(__DIR__, 2);
$php  = PHP_BINARY;

$workers = array_values(array_filter((array)glob($root . '/bin/*.php'), function ($f) {
    $b = basename($f);
    return $b !== 'cron_sync.php' && strpos($b, 'gen-') !== 0;
}));
ok(count($workers) > 0, 'R1: there are workers to check (' . count($workers) . ')');

foreach ($workers as $w) {
    $name = basename($w);
    $src  = str_replace(chr(13), '', (string)file_get_contents($w));

    // The include list the worker itself names: foreach (['a','b',...] as $m) { .../includes/$m.php }
    if (!preg_match('/foreach\s*\(\s*\[([^\]]*)\]\s*as\s*\$m\s*\)/', $src, $m)) continue;
    preg_match_all("/'([a-z0-9_\-]+)'/i", $m[1], $mm);
    $mods = $mm[1];
    if (!$mods) continue;

    // Every function the worker checks for before deciding it can run.
    preg_match_all("/function_exists\(\s*'(smpro_[a-z0-9_]+)'\s*\)/i", $src, $fm);
    $needs = array_values(array_unique($fm[1]));
    if (!$needs) continue;

    // Boot a real PHP with exactly those includes and ask which names resolved. A subprocess because the test
    // runner has half the plugin loaded already, and that would hide the very gap being looked for.
    $code = '$base=' . var_export($root, true) . ';'
          . 'define("SMPRO_BOOT",1); define("SMPRO_TEST_SRC",1);'
          . 'foreach (' . var_export($mods, true) . ' as $m) { $f=$base."/includes/$m.php"; if (is_file($f)) @require_once $f; }'
          . '$out=[]; foreach (' . var_export($needs, true) . ' as $fn) if (!function_exists($fn)) $out[]=$fn;'
          . 'echo implode(",", $out);';

    $desc = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $p = @proc_open([$php, '-d', 'error_reporting=0', '-r', $code], $desc, $pipes);
    if (!is_resource($p)) { ok(false, 'R2: ' . $name . ' could not be booted'); continue; }
    $missing = trim((string)stream_get_contents($pipes[1]));
    fclose($pipes[1]); fclose($pipes[2]); proc_close($p);

    ok($missing === '', 'R2: ' . $name . ' can load everything it guards on'
        . ($missing === '' ? ' (' . count($needs) . ' checked)' : ' — MISSING: ' . $missing));
}

/* ---------- R3: and the specific one that was broken ---------- */
// Named on its own so a future move cannot quietly reintroduce it.
$phlock = $root . '/includes/phlock.php';
ok(@is_file($phlock), 'R3: the root-only file-lock helpers have an include of their own');
$pl = str_replace(chr(13), '', (string)@file_get_contents($phlock));
foreach (['smpro_ph_chattr', 'smpro_ph_roots', 'smpro_ph_chattr_many', 'smpro_ph_locked_map'] as $fn)
    has($pl, 'function ' . $fn, 'R3: ' . $fn . ' is in includes/, where cron can reach it');

// And NOT in the page module any more — two copies would drift and the cron one would be the stale one.
$mod = str_replace(chr(13), '', (string)@file_get_contents($root . '/modules/php-harden.php'));
foreach (['smpro_ph_chattr', 'smpro_ph_roots'] as $fn)
    hasnt($mod, 'function ' . $fn . '(', 'R3: and no longer defined in the page module as well');

/* ---------- R4: the account-side plugin must not inherit root-only work ---------- */
// includes/phstack.php is copied wholesale into cpuser/stack.php by the build. Detection belongs there;
// chattr does not — an account cannot set an immutable bit, so it would be surface that can never be used.
// Checked as CODE, not as a word: phstack.php's own header says root-only work "deliberately stayed behind",
// and a test that cannot tell a comment from a call would fail on the sentence explaining why it passes.
$stack = str_replace(chr(13), '', (string)@file_get_contents($root . '/includes/phstack.php'));
$stackCode = preg_replace(['#/\*.*?\*/#s', '#//[^
]*#'], '', $stack);
hasnt($stackCode, 'chattr', 'R4: no chattr CODE in the file that is copied to the account-side plugin');
has($stack, 'deliberately stayed behind', 'R4: with the split written down where the next person will look');
