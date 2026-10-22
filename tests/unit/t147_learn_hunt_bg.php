<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
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
