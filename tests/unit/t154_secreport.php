<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
if (!defined('SMPRO_VARLIB')) define('SMPRO_VARLIB', sys_get_temp_dir() . '/t154_varlib_' . getmypid());
require_once SMPRO_BASE . '/includes/notify.php';
require_once SMPRO_BASE . '/includes/secreport.php';
/** t154 - beta382: the Daily Security Report - held alerts are recorded with reasons, the page renders from the
 *  record, a source that could not be read says so, the score and recommendations follow the data. */
$nt = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/notify.php'));
$sr = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/secreport.php'));
$rc = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/reports-center.php'));
$ix = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/index.php'));
$cs = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/bin/cron_sync.php'));

// A. the notifier records what it did NOT send
has($nt, "define('SMPRO_NTF_HELD',  SMPRO_VARLIB . '/notifications/held.jsonl');", 'A1: a record of its own');
has($nt, "smpro_ntf_held(\$type, \$subject, 'this alert type is switched off in Notifications', \$sig); return; }", 'A2: switched-off types are recorded');
has($nt, "smpro_ntf_held(\$type, \$subject, 'no channel is enabled for this alert type', \$sig); return; }", 'A3: no channel is recorded');
has($nt, "'unchanged since it was last sent (\"only when it changes\" is on)'", 'A4: a silenced repeat is recorded with the rule that silenced it');
smpro_ntf_held('intrusion_attack', 'Web-attack activity detected', 'unchanged since it was last sent ("only when it changes" is on)', 'atk:1');
smpro_ntf_held('intrusion_attack', 'Web-attack activity detected', 'unchanged since it was last sent ("only when it changes" is on)', 'atk:1');
smpro_ntf_held('disk_high', 'Disk usage high', 'no channel is enabled for this alert type', 'disk:1');
smpro_ntf_log('foreign_login', 'Foreign sign-in', ['whatsapp'], ['whatsapp' => ['ok' => true, 'detail' => 'sent']]);
$al = smpro_sr_collect_alerts(time() - 60, time() + 60);
is_eq(count($al['held']['rows']), 2, 'A5: the same held alert, same reason, is one row');
is_eq($al['held']['rows'][0]['times'] + $al['held']['rows'][1]['times'], 3, 'A6: ...with how many times it was held');
is_eq(count($al['sent']['rows']), 1, 'A7: sent alerts are read from the delivery log');
is_eq($al['sent']['by_channel'], ['whatsapp' => 1], 'A8: ...per channel');

// B. the page from a synthetic record
$rep = ['id' => '20260101', 'day' => '2026-01-01', 'from' => strtotime('2026-01-01'), 'to' => strtotime('2026-01-01') + 86399, 'generated' => time(), 'host' => 'host.example', 'version' => 'x', 'allowed_cc' => ['EG'],
    'alerts' => $al,
    'access' => ['checked' => true, 'ok' => 12, 'foreign' => [['ts' => time(), 'user' => 'acct', 'ip' => '203.0.113.7', 'cc' => 'US', 'service' => 'cpaneld']], 'failed' => 40, 'bruteforce' => ['addresses' => 3, 'top' => []], 'users' => 4, 'geo_blocked' => 10, 'wall' => ['enabled' => true, 'live' => true, 'countries' => ['EG'], 'set' => 100, 'built' => 100, 'hook' => true], 'cphulk_lock' => null],
    'attacks' => ['checked' => true, 'total' => 500, 'served' => 1, 'served_domains' => ['shop.example'], 'domains' => 2, 'by_domain' => ['shop.example' => ['total' => 400, 'served' => 1, 'served_rows' => [['ts' => time(), 'ip' => '198.51.100.9', 'uri' => '/x.php', 'rule' => '']], 'kinds' => ['exploit' => 400], 'uniq_ips' => 5]], 'kinds' => ['exploit' => 500], 'hours' => array_fill(0, 24, 20), 'top_nets' => ['AS1 (US)' => 300], 'autoblocked' => 2],
    'malware' => ['checked' => true, 'imunify' => ['checked' => false, 'why' => 'Imunify360 is not installed'], 'learn' => ['checked' => true, 'findings' => 2, 'findings_by_user' => [], 'quarantined_today' => 0, 'store_held' => 5, 'store_malicious' => 5, 'hidden_procs' => 0, 'rows' => []], 'integrity' => ['checked' => true, 'ok' => true]],
    'resources' => ['checked' => true, 'lve' => ['checked' => false, 'why' => 'CloudLinux LVE is not on this server'], 'disk' => ['checked' => true, 'mounts' => ['/' => 61], 'worst' => 61], 'load' => ['now' => 1.2, 'cores' => 8], 'mail_queue' => 3],
    'updates' => ['checked' => true, 'packages_pending' => 0, 'security_pending' => 0, 'kernel' => ['running' => 'a', 'installed' => 'b', 'reboot' => true], 'php' => ['checked' => true, 'eol_domains' => 1, 'per_domain' => [], 'eol_list' => []]],
    'crawlers' => ['checked' => true, 'total' => 1000, 'ai' => 600, 'top' => [], 'refused' => []],
    'domains' => ['shop.example' => ['domain' => 'shop.example', 'account' => 'acct', 'attacks' => 400, 'served' => 1, 'served_rows' => [['ts' => time(), 'ip' => '198.51.100.9', 'uri' => '/x.php', 'rule' => '']], 'kinds' => ['exploit' => 400], 'uniq_ips' => 5, 'malware' => [], 'resources' => [], 'vulns' => [['sev' => 'high', 'what' => 'PHP 74 (end of life)']], 'foreign' => [], 'risk' => 70, 'level' => 'critical']],
];
$rep['score'] = smpro_sr_score($rep); $rep['score']['prev'] = null; $rep['recommendations'] = smpro_sr_recommend($rep); $rep['summary'] = smpro_sr_summary($rep);
ok($rep['score']['score'] < 100 && $rep['score']['score'] > 0, 'B1: a day with a served exploit, a foreign sign-in and a pending reboot scores below 100 (' . $rep['score']['score'] . ')');
ok(in_array('1 exploit request(s) served 2xx', $rep['score']['why'], true), 'B2: ...and says why');
is_eq($rep['recommendations'][0]['p'], 'high', 'B3: the first recommendation is the highest risk');
has($rep['recommendations'][0]['title'], 'served 2xx on shop.example', 'B4: ...the served exploit');
$html = smpro_sr_render_html($rep, true);
has($html, '3 · Alerts NOT sent - and why', 'B5: the held section exists');
has($html, 'no channel is enabled for this alert type', 'B6: ...with the reason');
has($html, '<span class="pill warn">check</span>', 'B7: ...and a flag on the ones worth checking');
has($html, '<span class="nc">Imunify360 is not installed</span>', 'B8: a source that could not be read says so - never zero');
has($html, 'CloudLinux LVE is not on this server', 'B9: ...for every source');
has($html, 'shop.example', 'B10: the per-domain section lists the domain');
has($html, 'PHP 74 (end of life)', 'B11: ...with its vulnerability signs');
has($html, 'kernel reboot pending', 'B12: the KPI strip reflects the updates');
has(smpro_sr_render_text($rep), 'score ' . $rep['score']['score'], 'B13: the channel summary carries the score');

// C. wiring
has($ix, "require __DIR__ . '/includes/secreport.php';", 'C1: loaded by the plugin');
has($cs, "'daily security report' => 'smpro_sr_cron_sync',", 'C2: cron sync keeps the tick');
has($sr, "'*/10 * * * * root ' . \$flock", 'C3: the tick runs every ten minutes and decides by the chosen clock');
has($sr, "if (!\$force && (!\$cfg['enabled'] || \$mins < \$cfg['hour'] * 60 + \$cfg['minute'] || \$cfg['last_day'] === \$today)) return ['ok' => false, 'skipped' => 'not due'];", 'C3b: due = past HH:MM in the chosen zone and not yet built for that day in that zone');
has($sr, "if (smpro_sr_cfg()['tz'] !== '') @date_default_timezone_set(smpro_sr_tz());", 'C3c: the day edges and printed times follow the chosen zone');
has($rc, "\$c['tz'] = in_array((string)(\$_POST['tz'] ?? ''), DateTimeZone::listIdentifiers(), true) ? (string)\$_POST['tz'] : '';", 'C3d: only a real zone name is accepted');
has($rc, "if (\$srWhat === 'html' || \$srWhat === 'print') {", 'C4: download and print endpoints');
has($rc, "header('Location: index.cgi?page=reports-center&sr=print&id=' . \$rep['id']); exit;   // no renderer here: the print view saves as PDF from the browser", 'C5: PDF without a renderer falls back honestly to the print view');
has($rc, "smpro_require_valid_csrf('secreport');", 'C6: writes need CSRF');
has($sr, 'Content-Type: multipart/mixed; boundary=', 'C7: email carries the report as an attachment');

// D. beta385: a busy day's attacks are read row by row, never as one array (a hundred thousand rows broke a 128M CGI)
has($sr, "\$st = \$db->prepare('SELECT ts, ip, domain, kind, code, rule, uri FROM attacks WHERE ts >= ? AND ts <= ? ORDER BY ts'); \$st->execute([\$from, \$to]);", 'D1: one query for the day window');
has($sr, "while ((\$r = \$st->fetch(PDO::FETCH_ASSOC)) !== false) {", 'D2: ...fetched one row at a time');
hasnt($sr, "smpro_in_history(\$from, 100000)", 'D3: the whole-day array is gone');
has($sr, "@ini_set('memory_limit', '512M')", 'D4: headroom for the rest of the build');

// E. beta386: "served" is the same rule for the alert and the report, service hosts are not sites, secret-file hits are re-asked
$in = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/intrusion.php'));
has($in, "function smpro_im_service_host(\$domain) {", 'E1: the panel service hosts are known');
has($in, "    \$served = array_filter(\$recent, fn(\$e) => smpro_im_served(\$e));", 'E2: the critical alert uses the shared rule');
has($in, "if (\$cur['kind'] === 'WAF Block (other)' && smpro_im_recon_path(\$cur['uri'])) \$cur['kind'] = 'Scanner / Recon';", 'E3: a public CMS file is recon, not an exploit');
has($sr, "if (\$answered && function_exists('smpro_im_service_host') && smpro_im_service_host(\$dom)) { \$svcHits++; continue; }", 'E4: the report skips the fixed proxy replies');
has($sr, "\$v = smpro_sr_verify_exposure(\$x['domain'], \$x['path']);", 'E5: ...and asks the site itself about a secret file that got a 200');
require_once SMPRO_BASE . '/includes/intrusion.php';
ok(smpro_im_service_host('autodiscover.example.com') && smpro_im_service_host('cpanel.example.com') && !smpro_im_service_host('shop.example.com') && !smpro_im_service_host('autodiscoverx.example.com'), 'E6: service host detection');
ok(smpro_im_recon_path('/plusmedia/wp-includes/wlwmanifest.xml') && smpro_im_recon_path('/readme.html?x=1') && !smpro_im_recon_path('/wp-admin/admin-ajax.php'), 'E7: recon paths');
ok(smpro_im_served(['code' => 200, 'kind' => 'SQL Injection', 'domain' => 'shop.example.com']) && !smpro_im_served(['code' => 200, 'kind' => 'SQL Injection', 'domain' => 'autoconfig.example.com']) && !smpro_im_served(['code' => 403, 'kind' => 'SQL Injection', 'domain' => 'shop.example.com']) && !smpro_im_served(['code' => 200, 'kind' => 'Scanner / Recon', 'domain' => 'shop.example.com']) && !smpro_im_served(['code' => 301, 'kind' => 'SQL Injection', 'domain' => 'shop.example.com']), 'E8: served = exploit kind + a 2xx answer + real site; a redirect is not an answer');
is_eq(smpro_sr_verify_exposure('bad host!', '/.env')['exposed'], false, 'E9: a malformed domain is never fetched');
is_eq(smpro_sr_verify_exposure('example.com', '/../x')['exposed'], false, 'E10: nor a traversal path');

// F. beta388: a Host header that is not a site on this server is labelled so (wildcard DNS), in the alert and the report
has($in, "function smpro_im_host_known(\$domain) {", 'F1: known-host check');
has($in, "    foreach (\$by as \$g) if (\$g['total'] >= \$thr) \$spiked[] = smpro_im_host_label(\$g['domain']) . ' (' . \$g['total'] . ')';", 'F2: the spike alert labels unknown hosts');
has($sr, "if (function_exists('smpro_im_host_known') && !smpro_im_host_known(\$dom)) \$d[\$k]['note'] =", 'F3: the per-domain row carries the note');
has($sr, "if (!empty(\$d[\$dom]['note'])) continue; \$root = smpro_sr_docroot_of(\$dom);", 'F4: ...and is not scanned for vulnerabilities (no docroot of its own)');
