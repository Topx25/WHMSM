<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
/** t120 - rotating log appender used by every product log, ipintel eviction, fixed purge gated on pressure, weekly index vacuum, partial feeds never prune, loadsample cron locked. */
$r = fn($f) => str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $f));
$f = SMPRO_VARLIB . '/t120.log'; foreach ([$f, "$f.1", "$f.2", "$f.3", "$f.lock"] as $x) @unlink($x);
ok(smpro_log_append($f, "one\n", 8, 3), 'U1: append works');
ok(smpro_log_append($f, "two-two\n", 8, 3), 'U1: ...again');
smpro_log_append($f, "three\n", 8, 3);
ok(is_file("$f.1"), 'U1: the log rotated at the size line');
is_eq(trim((string)file_get_contents($f)), 'three', 'U1: the fresh log holds the last line');
smpro_log_append($f, "four-four-four\n", 8, 3); smpro_log_append($f, "five\n", 8, 3); smpro_log_append($f, "six-six-six-six\n", 8, 3); smpro_log_append($f, "seven\n", 8, 3);
ok(is_file("$f.3") && !is_file("$f.4"), 'U1: three generations, no more');
$h = $r('includes/helpers.php');
has($h, "smpro_log_append(SMPRO_AUDIT_LOG, \$line . \"\\n\", 20971520, 3);", 'U2: the audit log uses it');
has($h, "smpro_log_append(SMPRO_VARLOG . '/worker_fatal.log'", 'U2: so does worker_fatal');
has($h, "smpro_log_append(SMPRO_VARLOG . '/page_fatal.log'", 'U2: and page_fatal');
foreach (['includes/bfrules.php' => 'SMPRO_BFR_LOG', 'includes/georeport.php' => 'SMPRO_GR_LOG', 'includes/geowall.php' => 'SMPRO_GW_LOG', 'bin/hub_worker.php' => "'/hub_worker.log'"] as $file => $k) has($r($file), "smpro_log_append(", 'U2: ' . $file . ' rotates');
has($h, "foreach (\$cache as \$k => \$v) if ((int)(\$v['cached_at'] ?? 0) < \$cut) unset(\$cache[\$k]);", 'U3: ipintel evicts expired entries on save');
$m = $r('includes/maintenance.php');
has($m, "if (!empty(\$cfg['fixed_always']) || \$pct >= 40) { \$run = true;", 'U4: a fixed purge needs a filesystem at 40%+');
$i = $r('includes/intrusion.php');
has($i, "function smpro_in_maintain(): void {\n    if (PHP_SAPI !== 'cli') return;", 'U5: the vacuum runs only from a worker');
has($i, "< 7 * 86400) return;", 'U5: ...once a week');
has($r('bin/notify_check.php'), "smpro_in_maintain();", 'U5: ...from the notify worker');
has($i, "json_encode(array_slice(\$m, -5000)", 'L2: the emergency undo book keeps 5,000 entries');
has($r('includes/fwallow.php'), "\$partial = \$prevN >= 10 && count(\$live) < (int)(\$prevN * 0.5);", 'L6: a half-size feed is a partial download');
has($r('includes/loadhist.php'), "' -n ' . \$lockDir . '/loadsample.lock timeout 50 '", 'L7: the load sampler cron is locked and bounded');
