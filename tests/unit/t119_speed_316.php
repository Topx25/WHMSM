<?php
require __DIR__ . '/../support/bootstrap.php';
/** t119 - speed pass + the last audit mediums: csf.deny paged on the server, the intrusion parse memoised, one tail per 100 domlogs, 5-minute decisions, merged state books, update smoke test + rollback, digest flush atomic, tamper-kill removes every cron. */
$r = fn($f) => str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $f));
$fw = $r('modules/firewall-status.php');
has($fw, "if (\$reqMethod === 'POST' && (\$_POST['fw_action'] ?? '') === 'deny_rows') {", 'S1: csf.deny rows come by request');
has($fw, "smpro_require_valid_csrf('fw_csf'); smpro_require_root();\n    header('Content-Type: application/json", 'S1: ...behind CSRF + root');
has($fw, "<?= \$fwDenyHtml(array_slice(\$denyRows, 0, 50)) ?>", 'S1: the page renders 50 rows');
has($fw, "fd.set('fw_action','deny_rows')", 'S1: the filter box asks the server');
hasnt($fw, "body.querySelectorAll('tr').forEach(function(tr){var cc=tr.getAttribute('data-cc')", 'S1: no client-side filter over thousands of rows');
has($fw, 'id="fwDenyTable" data-nopage="1"', 'S1: the auto-pager leaves it alone');
$im = $r('modules/intrusion-monitor.php');
has($im, "smpro_memo('im_page_' . \$mins, 60, function () use (\$mins, &\$imFresh)", 'S2: the live parse is memoised for a minute');
has($im, "if (\$events && \$imFresh) { smpro_in_ingest(\$events);", 'S2: the index ingest runs only on a real parse');
has($r('includes/intrusion.php'), "if (PHP_SAPI === 'cli') \$db->exec('CREATE INDEX IF NOT EXISTS ix_ts_ip ON attacks(ts, ip)');", 'S2: the covering index is built by a worker, never a page');
$bg = $r('includes/botguard.php');
has($bg, "foreach (array_chunk(\$files, 100) as \$chunk) {", 'S3: one tail per 100 domlogs');
has($bg, "if (strpos(\$l, '==> ') === 0 && substr(\$l, -4) === ' <==') { \$domain = ", 'S3: the file header sets the domain');
has($bg, "'scan_minutes'            => 5,", 'S4: Bot Guard decides every 5 minutes');
$nt = $r('includes/notify.php');
is_eq(substr_count($nt, '*/5 * * * * root $flock -n $lock timeout 600 $php $bin'), 2, 'S4: alerts + intrusion auto-response every 5 minutes (install and heal)');
has($nt, "if (function_exists('smpro_cron_install')) smpro_cron_install(\$f, \$want);", 'L4: the heal goes through the verified installer');
has($r('includes/intrusion.php'), "if (is_array(\$disk) && is_array(\$s)) \$s = array_merge(\$disk, \$s);", 'M1: the intrusion state book is merged under a lock');
has($nt, "\$disk = is_file(SMPRO_NTF_STATE) ? json_decode", 'M1: so is the notifications state book');
$up = $r('includes/update.php');
has($up, "if (\$bad !== '') {\n        @shell_exec('cp -a ' . escapeshellarg(\$bk) . '/. ' . escapeshellarg(\$dest)", 'M3: a build that does not parse is rolled back to the backup');
has($up, "if (is_array(\$ij) && is_array(\$ij['files'] ?? null)) {", 'M3: files the new build no longer ships are removed');
has($r('bin/bfrules_tick.php'), "@ini_set('memory_limit', '512M');", 'M7: the log-heavy worker has the memory it needs');
$dg = $r('includes/digest.php');
has($dg, "if (!is_file(SMPRO_DG_QUEUE) || !@rename(SMPRO_DG_QUEUE, \$taken))", 'M14: the queue is taken aside atomically');
hasnt($dg, "@unlink(SMPRO_DG_QUEUE);", 'M14: ...never deleted under a concurrent append');
hasnt($r('includes/hub.php'), "@fclose(\$fh); @unlink(\$lock);", 'M14: the hub lock file is not unlinked');
has($r('includes/license.php'), "foreach (glob('/etc/cron.d/' . SMPRO_SLUG . '-*') ?: [] as \$cf) @unlink(\$cf);", 'M15: a tamper-kill removes every cron');

/* ---- beta317: the firewall page never waits for its slow readers ---- */
has($fw, "smpro_memo_cmd('fw_nft_n', 300, 'nft list ruleset | wc -l', 30, 86400, true)", 'S5: the nft rule count is five minutes old at most and computed behind the page');
has($fw, "smpro_memo_cmd('fw_csf_t', 60, escapeshellarg(\$csfBin) . ' -t', 20, 3600, true)", 'S5: so is the temporary-ban list');
has($fw, "smpro_memo('fw_ss', 20, fn() => smpro_fw_run('ss -tulnHp', SMPRO_TIMEOUT_NORMAL))", 'S5: listening sockets are memoised');
has($nt, "strpos((string)@file_get_contents('/etc/cron.d/smpro-notify'), '*/5 * * * *') === false || strpos((string)@file_get_contents('/etc/cron.d/smpro-notify'), 'timeout 280') !== false))) smpro_ntf_cron_install();", 'S4: an upgraded server moves to the 5-minute cadence (and the full time limit) by itself');

/* ---- beta318: a page never waits for whois, the 30-day totals and the service states are memoised ---- */
$h = $r('includes/helpers.php');
has($h, "function smpro_ip_intel_bulk(\$ips, bool \$async = false) {", 'S6: bulk intel has an async mode');
has($h, "'source'=>'GeoIP (whois pending)'", 'S6: ...the page gets the country at once');
has($h, "\$bin = SMPRO_BASE . '/bin/ipintel_warm.php';", 'S6: ...and a worker fetches the rest');
ok(is_file(SMPRO_BASE . '/bin/ipintel_warm.php'), 'S6: the worker ships');
has($r('modules/intrusion-monitor.php'), "smpro_ip_intel_bulk(array_slice(array_keys(array_count_values(array_filter(array_map(fn(\$e)=>\$e['ip'],\$events)))), 0, 80), true)", 'S6: the Intrusion Monitor asks asynchronously');
has($r('modules/firewall-status.php'), "array_slice(\$deny, 0, 120)), true);", 'S6: so does Firewall Status');
has($r('includes/intrusion.php'), "smpro_memo('in_stats_' . intdiv((int)\$sinceTs, 60), 60, fn() => smpro_in_stats_live(\$sinceTs))", 'S7: the 30-day totals are kept for a minute');
has($r('includes/intrusion.php'), "smpro_memo('im_engine_state', 300, fn() => smpro_im_modsec_engine_state_live())", 'S7: the WAF engine state is kept for five minutes');
has($fw = $r('modules/firewall-status.php'), "smpro_memo('fw_act_' . \$svc, 15,", 'S8: service states are memoised for the page');
has($fw, "\$now = trim(smpro_fw_run('systemctl is-active ' . escapeshellarg(\$svc))) ?: 'unknown';", 'S8: ...but a button reads the real state');
has($fw, "smpro_memo('fw_gw_live', 15, fn() => smpro_gw_live() ? 1 : 0)", 'S8: the wall probe is memoised for the page only');
has($r('includes/geohulk.php'), "smpro_memo('gh_ranges_n', 120,", 'S8: the cPHulk range count is memoised');

/* ---- beta319: csf.allow indexed once; the login readers memoised ---- */
require_once SMPRO_BASE . '/includes/helpers.php';
has($r('includes/helpers.php'), "function smpro_csf_allow_index(): array {", 'S9: csf.allow is indexed once per process');
has($r('includes/fwallow.php'), "foreach (\$ranges as \$r) { \$r = (string)\$r; if (isset(\$have[\$r])) { \$present++; if (isset(\$mine[\$r])) \$marked++; } }", 'S9: the allow-list status is one pass');
$lm = $r('modules/login-monitor.php');
has($lm, "smpro_memo('lm_ssh_' . (int)\$tail . '_' . intdiv((int)\$fromTs, 60), 20, fn() => smpro_lm_ssh_events_live(\$tail, \$fromTs))", 'S10: SSH events memoised for 20 s');
has($lm, "smpro_memo('lm_cpf_' . (int)\$tail . '_' . intdiv((int)\$fromTs, 60), 20, fn() => smpro_lm_cpanel_failed_live(\$tail, \$fromTs))", 'S10: cPanel failures memoised for 20 s');
has($lm, "fn() => smpro_lm_csf_blocked_live()", 'S10: the csf.deny set memoised (keyed by the file mtime)');
