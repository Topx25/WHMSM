<?php
require __DIR__ . '/../support/bootstrap.php';
/**
 * t86_home_move_zombie.php — a batch supervisor cannot outlive the build it started as, or its deadlines.
 *
 * THE INCIDENT. A supervisor started on 27 July with a build that had no stall guard. The plugin was updated
 * eleven times underneath it; the process kept the old code, looped for 58 days over two slots whose workers had
 * finished, and wrote a warning into cPanel's error log on every pass - 1.27 million lines, 207 MB.
 */
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/bin/home_move_batch.php'));
has($src, 'function hb_disk_version(', 'U1: the supervisor can read the build on disk');
has($src, "if (\$bootVersion !== '' && \$dv !== '' && \$dv !== \$bootVersion) {", 'U1: and stops when it differs from the build it started as');
has($src, "'why' => 'plugin updated'", 'U1: audited as such');
has($src, "const HB_SLOT_MAX_SEC  = 48 * 3600;", 'U2: a slot has an absolute deadline');
has($src, "const HB_BATCH_MAX_SEC = 7 * 86400;", 'U2: and so does the batch');
has($src, "\$startedAgo > HB_SLOT_MAX_SEC", 'U2: a slot past its deadline is failed whatever its heartbeat says');
has($src, "time() - (int)\$b['started_at'] > HB_BATCH_MAX_SEC", 'U2: a batch past its deadline is stopped');
// the reads that produced the warnings are guarded
has($src, "if (isset(\$d['pct']))   \$b['accounts'][\$i]['pct']   = \$d['pct'];", 'U3: progress fields are read only when present');
$blind = "['pct']   = (int)" . '$d' . "['pct'];";
hasnt($src, $blind, 'U3: never blind');
$s = "define('SMPRO_VERSION',     '1.2.3-test');";
ok(preg_match("/define\\('SMPRO_VERSION',\\s*'([^']+)'\\)/", $s, $m) === 1 && $m[1] === '1.2.3-test', 'U4: the version pattern matches defines.php as written');
