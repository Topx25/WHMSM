<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
require_once SMPRO_BASE . '/includes/loadhist.php';
/** t94_loadhist.php - the 24 h load ring is bounded by time, fed by cron, and the page only tops it up. */
$now = time();
@is_dir(dirname(SMPRO_LO_HIST)) || @mkdir(dirname(SMPRO_LO_HIST), 0700, true);
file_put_contents(SMPRO_LO_HIST, json_encode([[$now - 40 * 86400, 9.9], [$now - 90000, 8.8], [$now - 3600, 1.1], [$now - 120, 1.2]]));
$h = smpro_lo_hist_tick(2.5);
is_eq(count($h), 3, 'U1: samples older than 24 h are dropped when a new one lands (40-day-old and 25-hour-old gone)');
is_eq($h[count($h) - 1][1], 2.5, 'U1: the new sample is last');
$h2 = smpro_lo_hist_tick(3.0); is_eq(count($h2), 3, 'U1: a second call inside a minute adds nothing');
ok(smpro_lo_load1() >= 0, 'U2: the load reader answers a number');
ok(is_file(SMPRO_BASE . '/bin/loadsample.php'), 'U2: the minute sampler ships');
$cs = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/bin/cron_sync.php'));
has($cs, "'load history'       => 'smpro_lo_cron_sync'", 'U2: cron_sync installs it after every update');
$lm = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/load-monitor.php'));
hasnt($lm, 'function smpro_lo_hist_tick', 'U3: the module no longer carries its own copy of the ring');
has($lm, "require_once SMPRO_INCLUDES . '/loadhist.php'", 'U3: it uses the shared one');
has($lm, "fr.textContent='-'+(hrs>0?hrs+'h'", 'U3: the axis says the real span, not a fixed -24h');
