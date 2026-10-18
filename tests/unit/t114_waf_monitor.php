<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
require_once SMPRO_BASE . '/includes/intrusion.php';
/** t114 - a WAF record from a pass-only monitoring rule (served, NOTICE/DEBUG) is not an attack: excluded from counts, index and alerts; kept for the upload-cluster check. */
ok(smpro_im_is_monitor(['code' => '200', 'severity' => 'NOTICE']), 'U1: served + NOTICE = monitoring');
ok(smpro_im_is_monitor(['code' => '304', 'severity' => 'DEBUG']), 'U1: 304 + DEBUG = monitoring');
ok(!smpro_im_is_monitor(['code' => '403', 'severity' => 'NOTICE']), 'U2: a 403 is a block, never monitoring');
ok(!smpro_im_is_monitor(['code' => '200', 'severity' => 'CRITICAL']), 'U2: a CRITICAL rule that was served is a served exploit attempt, not monitoring');
ok(!smpro_im_is_monitor(['code' => '200', 'severity' => 'NOTICE', 'blocked' => 1]), 'U2: an intercepted transaction is never monitoring');
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/intrusion.php'));
has($src, "if (!\$withMonitor) \$events = array_values(array_filter(\$events, fn(\$e) => empty(\$e['monitor'])));", 'U3: the parser drops monitoring records unless asked');
has($src, "if (stripos(\$ln, 'Action: Intercepted') === 0 || stripos(\$ln, 'Message: Access denied') === 0) \$cur['blocked'] = 1;", 'U3: interception is read from section H');
has($src, "\$eventsAll = smpro_im_ingest_recent(SMPRO_IM_LIVE_BYTES, max(\$win, 60), true);", 'U4: the worker asks for everything...');
has($src, "if (\$u = smpro_im_upload_cluster_alert(\$recentAll))", 'U4: ...and feeds only the upload-cluster check with the monitoring records');
has($src, "function smpro_in_sweep_monitor_rows(): void {", 'U5: the index is swept once of the rows the old parser stored');
$ub = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/forensics-upload-breach.php'));
has($ub, "smpro_im_parse_modsec(4 * 1024 * 1024, 800, (int)\$sinceTs, true)", 'U6: the upload-breach forensics keep the accepted-upload records');
