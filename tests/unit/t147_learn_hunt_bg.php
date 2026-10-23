<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
if (!defined('SMPRO_VARLIB')) define('SMPRO_VARLIB', sys_get_temp_dir() . '/t147_varlib_' . getmypid());
require_once SMPRO_BASE . '/includes/learn.php';
/** t147 - beta356: the Learned Defense hunt runs detached; the page asks for it, shows "hunting now", refreshes
 *  itself, and never waits for a server-wide walk inside its own request. */
$ln = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/learn.php'));
$pg = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/learned-defense.php'));
has($ln, 'function smpro_lr_hunt_running(): bool {', 'A1: running = the tick lock is held');
has($ln, "'/learn.cron.lock'", 'A2: the SAME lock the cron tick uses, so one answer');
has($ln, 'function smpro_lr_hunt_bg(): array {', 'A3: the detached starter');
has($ln, "@touch(smpro_lr_dir() . '/hunt_wanted');\n    if (smpro_lr_hunt_running()) return ['ok' => true, 'started' => false,", 'A4: the flag is set first, so a running hunt picks it up and nothing is doubled');
has($ln, "if (defined('SMPRO_TEST_SRC')) return ['ok' => true, 'started' => true, 'msg' => 'test: no worker started'];", 'A5: a test never spawns a worker');
has($ln, "\$cmd = 'nohup ' . \$flock . ' -n ' . escapeshellarg(\$ld . '/learn.cron.lock') . ' timeout 590 nice -n 15 ' . escapeshellarg(\$php) . ' ' . escapeshellarg(\$bin) . ' >/dev/null 2>&1 </dev/null &';", 'A6: detached, locked, time-bounded, niced');
hasnt($pg, 'smpro_lr_hunt(500)', 'B1: the page never runs the hunt inline');
hasnt($pg, 'smpro_lr_hunt(400)', 'B2: ...not after Teach either');
has($pg, "case 'hunt':      \$r = smpro_lr_hunt_bg();", 'B3: Hunt now asks for a background hunt');
has($pg, "if (\$ok) { \$h = smpro_lr_hunt_bg(); \$msg .= ' ' . \$h['msg']; }", 'B4: Teach asks for one and says so');
has($pg, "\$hunting = smpro_lr_hunt_running();", 'B5: the page knows when a hunt runs');
has($pg, 'hunting now…', 'B6: the tile says so');
has($pg, "<?= \$hunting ? ' disabled title=\"a hunt is running\"' : '' ?>", 'B7: the button is disabled meanwhile');
has($pg, "setTimeout(function(){ if (!document.hidden) location.reload();", 'B8: the page refreshes itself until the findings land');

// C. quarantine through a locked folder (Safety Lock / WP Guard chattr +i on the directory)
has($ln, 'function smpro_lr_unlink_locked(string $file): array {', 'C1: helper');
has($ln, "@exec('chattr -i -a ' . escapeshellarg(\$file) . ' 2>/dev/null');\n    if (@unlink(\$file)) return ['ok' => true, 'why' => '', 'relocked' => false];", 'C2: the plain way first');
has($ln, "\$dir = dirname(\$file); \$flags = smpro_lr_attrs(\$dir);", 'C3: then the PARENT folder\'s flags');
has($ln, "@exec('chattr +' . \$flags . ' ' . escapeshellarg(\$dir) . ' 2>/dev/null');   // put the lock back exactly as it was", 'C4: the other product\'s lock is put back as it was');
has($ln, "\$rm = smpro_lr_unlink_locked(\$safe);\n    if (!\$rm['ok']) { @unlink(\$q); return ['ok' => false, 'msg' => 'The file could not be removed: ' . \$rm['why'] . '.']; }", 'C5: the reason is in the answer, the kept copy is dropped');
hasnt($ln, "'The file could not be removed (immutable or permissions).'", 'C6: the old blind message is gone');
is_eq(smpro_lr_attrs('/definitely/not/here'), '', 'C7: no attrs for a path that is not there');

// D. restore through a locked folder, the same way
has($ln, "\$dir = dirname(\$hit['orig']); \$flags = smpro_lr_attrs(\$dir);\n    if (\$flags !== '') @exec('chattr -i -a ' . escapeshellarg(\$dir) . ' 2>/dev/null');\n    \$wrote = @copy(\$kept, \$hit['orig']);\n    if (\$flags !== '') @exec('chattr +' . \$flags . ' ' . escapeshellarg(\$dir) . ' 2>/dev/null');", 'D1: restore lifts the parent lock for the write and puts it back');
has($ln, "is locked (chattr +' . \$flags . ') and could not be unlocked", 'D2: a failed write names the folder and the flag');
hasnt($ln, "return ['ok' => false, 'msg' => 'Could not write the file back.'];", 'D3: the old blind message is gone');

// E. a quarantined row leaves the list at once (the owner pressed Quarantine, the file moved, the row stayed: "does nothing")
has($ln, 'function smpro_lr_drop_finding(string $path): void {', 'E1: helper');
has($ln, "    smpro_lr_drop_finding(\$safe);   // the row leaves the list now, not at the next hunt", 'E2: quarantine drops the row');
has($pg, "if ((\$f['path'] ?? '') !== '' && !@file_exists(\$f['path'])) \$gone[] = \$i;", 'E3: the page hides findings whose file is already gone');
has($pg, "smpro_lr_save('findings', \$F); }", 'E4: ...and writes the cache back so the counters agree');
