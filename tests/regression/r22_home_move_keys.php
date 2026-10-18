<?php
/**
 * r22_home_move_keys.php — a supervisor must not warn on a file another process is still writing.
 *
 * Seen on a live server (2026-09-14): the cPanel error log on dc1 was taking two PHP warnings every five seconds,
 * for as long as any home move was running:
 *
 *   PHP Warning: Undefined array key "phase" in .../smpro/bin/home_move_batch.php
 *   PHP Warning: Undefined array key "pct"   in .../smpro/bin/home_move_batch.php
 *
 * The batch supervisor polls each single-account worker's progress file. The worker creates that file the moment
 * it starts and fills in the progress keys a tick later, so between those two moments the keys are simply absent.
 * Reading them blind warned on every pass. Nothing was broken by it — but a plugin that fills a customer's server
 * log with its own noise is telling that customer it is not finished, and it buries the lines that do matter.
 */
require __DIR__ . '/../support/bootstrap.php';

$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/bin/home_move_batch.php'));

/* ---------- H1: nothing is read from another process's file without a guard ---------- */
$blind = [];
foreach (explode("\n", $src) as $n => $line) {
    if (strpos($line, "\$d['") === false) continue;
    if (strpos($line, '??') !== false || strpos($line, 'isset(') !== false || strpos($line, 'empty(') !== false) continue;
    $blind[] = ($n + 1) . ': ' . trim($line);
}
is_eq($blind, [], 'H1: every read of the worker\'s progress file is guarded' . ($blind ? ' — unguarded: ' . implode(' | ', $blind) : ''));

/* ---------- H2: the two keys that actually warned ---------- */
has($src, "if (isset(\$d['pct']))   \$b['accounts'][\$i]['pct']   = \$d['pct'];", 'H2: pct is only copied when the worker has written it');
has($src, "if (isset(\$d['phase'])) \$b['accounts'][\$i]['phase'] = \$d['phase'];", 'H2: and so is phase');

/* ---------- H3: an early poll must not wipe progress that was already known ---------- */
// Overwriting with null every time the poll landed early would make a progress bar drop to zero and climb again.
has($src, "\$b['accounts'][\$i]['pct']   = \$b['accounts'][\$i]['pct']   ?? 0;", 'H3: a missing value falls back, it does not overwrite');
has($src, "\$b['accounts'][\$i]['phase'] = \$b['accounts'][\$i]['phase'] ?? 'starting';", 'H3: ...and reads as "starting" rather than blank');
has($src, 'is a worse lie', 'H3: with the reasoning recorded where the code is');

/* ---------- H4: an absent "done" means NOT done ---------- */
// This is the one where the safe direction matters: reading a missing key as true would finalise an account
// whose files are still being copied.
has($src, "if (!empty(\$d['done'])) {", 'H4: an absent completion flag means not finished');
has($src, "\$b['accounts'][\$i]['status'] = !empty(\$d['ok']) ? 'moved' : 'failed';", 'H4: ...and an absent success flag means failed, not moved');
has($src, 'the opposite would finalise an account that is still being copied', 'H4: the direction is deliberate and says why');
