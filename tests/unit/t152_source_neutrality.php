<?php
require __DIR__ . '/../support/bootstrap.php';
/** t152 - beta373: the shipped source names no market, no server and no incident; the account-side plugin scan is
 *  loaded; comments carry no typographic dashes. Guards the review of 2026-10-24 so it cannot drift back. */
$shipped = [];
foreach (['index.php', 'includes/*.php', 'modules/*.php', 'bin/*.php'] as $g) foreach (glob(SMPRO_BASE . '/' . $g) as $f) $shipped[$f] = str_replace(chr(13), '', (string)file_get_contents($f));

// A. no market default
$im = $shipped[SMPRO_BASE . '/modules/intrusion-monitor.php']; $in = $shipped[SMPRO_BASE . '/includes/intrusion.php']; $fw = $shipped[SMPRO_BASE . '/modules/firewall-status.php'];
has($im, "(array)(\$cur['protect_regions'] ?? [])", 'A1: protect regions default to none');
hasnt($im, "?? ['EG','SA']", 'A2: ...no pre-filled countries');
hasnt($in, "\$d['caution_regions'] = ['AE'", 'A3: no fixed caution tier in the source');
has($fw, "Every ISO 3166-1 code is offered, in code order", 'A4: the country picker is the whole ISO list');
hasnt($fw, "['EG','SA','AE','KW','QA'", 'A5: ...not a region-first hand list');
$bad = [];
foreach ($shipped as $f => $s) if (preg_match("/'(EG|SA|AE|KW|QA|BH|OM)',\s*'(EG|SA|AE|KW|QA|BH|OM)',\s*'(EG|SA|AE|KW|QA|BH|OM)'/", $s)) $bad[] = basename($f);
is_eq($bad, [], 'A6: no file lists one region\'s codes together');

// B. no server, no incident date in code comments
$bad = [];
foreach ($shipped as $f => $s) {
    foreach (explode("\n", $s) as $i => $l) {
        $st = ltrim($l);
        if (!(strpos($st, '//') === 0 || strpos($st, '*') === 0 || strpos($st, '/*') === 0)) continue;
        if (basename($f) === 'evidence.php') continue;   // its header shows day-file names with example dates, not incidents
        if (preg_match('/\b2026-(0[1-9])-\d\d\b/', $l) || preg_match('/\bdc[12]\b/', $l)) $bad[] = basename($f) . ':' . ($i + 1);
    }
}
is_eq($bad, [], 'B1: no incident date or server name in a comment (PHP release dates in October are vendor facts and allowed)');
$bad = [];
foreach ($shipped as $f => $s) {
    foreach (explode("\n", $s) as $i => $l) {
        $st = ltrim($l);
        if (!(strpos($st, '//') === 0 || strpos($st, '*') === 0 || strpos($st, '/*') === 0)) continue;
        if (preg_match('/[\x{2014}\x{2013}\x{2192}\x{2026}]/u', $l)) $bad[] = basename($f) . ':' . ($i + 1);
    }
}
is_eq(count($bad), 0, 'B2: no typographic dash, arrow or ellipsis in a comment line' . ($bad ? ' (' . implode(', ', array_slice($bad, 0, 5)) . ')' : ''));

// C. the account-side scan is loaded where it is shown
$pc = $shipped[SMPRO_BASE . '/modules/plugin-control.php'];
has($pc, "if (!function_exists('smpro_cps_scan') && is_file(SMPRO_INCLUDES . '/cpsidescan.php')) require_once SMPRO_INCLUDES . '/cpsidescan.php';", 'C1: Plugin Control loads the scan before asking for it');

// D. beta375: a web-attack alert's signature is how wide the attack is (a band), not counts and not names
$in = $shipped[SMPRO_BASE . '/includes/intrusion.php']; $nt = $shipped[SMPRO_BASE . '/includes/notify.php'];
has($in, "\$band = fn(int \$n): int => \$n <= 1 ? 1 : (\$n <= 2 ? 2 : (\$n <= 5 ? 5 : (\$n <= 10 ? 10 : 99)));", 'D1: the band');
has($in, "['sig'=>'spike:' . \$band(count(\$spiked)),", 'D2: the spike signature is the band of the domain count');
hasnt($in, "md5(implode(',', \$spiked))", 'D3: not the "domain (count)" lines');
has($in, "['sig'=>'served:' . (count(\$sd) <= 1 ? 1 : (count(\$sd) <= 5 ? 5 : 99)),", 'D4: the served-exploit signature is a band too');
has($nt, "elseif ((int)((\$st['intrusion_attack#atk']['ts'] ?? 0)) < \$now - 1800) \$maybe('intrusion_attack', 'clear', '', '');", 'D5: a dip under the line clears the slot only after thirty quiet minutes');

// E. beta376: an audit scan that could not read a log says so and is never cached as "0 logins"
$bk = $shipped[SMPRO_BASE . '/includes/breakin.php']; $aa = $shipped[SMPRO_BASE . '/modules/account-audit.php'];
has($bk, "\$GLOBALS['smpro_aa_unread'] = [];", 'E1: the collector starts with nothing unread');
has($bk, "if ((\$sv['state'] ?? '') === 'unreadable') \$GLOBALS['smpro_aa_unread'][] = basename((string)(\$sv['path'] ?? \$sk)) . ' (successful sign-ins)';", 'E2: an unreadable sign-in feed is named');
has($bk, "if (\$readN === 0 && (int)@filesize(\$loginLog) > 0) \$GLOBALS['smpro_aa_unread'][] = basename(\$loginLog) . ' (failed sign-ins)';", 'E3: zero lines from a non-empty login_log = not read');
has($bk, "if (isset(\$readA) && \$readA === 0 && (int)@filesize(\$accessLog) > 0) \$GLOBALS['smpro_aa_unread'][] = basename(\$accessLog) . ' (panel requests)';", 'E4: ...and from access_log');
has($bk, "if (!\$unread) smpro_aa_cache_put(\$key,", 'E5: an unread collection is never cached');
has($bk, "'unread' => \$unread]];", 'E6: ...and the page is told');
has($aa, "This scan could not read: <?= smpro_h(implode(', ', (array)\$aaScanMeta['unread'])) ?>.", 'E7: the page says what was not seen');



// F. beta377: the wall covers the panel's proxy subdomains (cpanel./whm./webmail. over 80/443) through Apache
$gw = $shipped[SMPRO_BASE . '/includes/geowall.php']; $fw = $shipped[SMPRO_BASE . '/modules/firewall-status.php'];
has($gw, "define('SMPRO_GW_HTTPD_FILE', '/etc/apache2/conf.d/smpro-geowall-panel.conf');", 'F1: a file of its own under conf.d');
has($gw, "'<If \"%{HTTP_HOST} =~ m#^(' . implode('|', \$r['prefixes']) . ')\\.#i\">'", 'F2: only when the Host is a panel subdomain');
has($gw, "foreach (array_chunk(\$ips, 200) as \$chunk) \$lines[] = '    Require ip ' . implode(' ', \$chunk);", 'F3: the same address set as the kernel rule');
has($gw, "if (\$prev === null) @unlink(SMPRO_GW_HTTPD_FILE); else @file_put_contents(SMPRO_GW_HTTPD_FILE, \$prev, LOCK_EX);", 'F4: a refused configtest leaves Apache as it was');
has($gw, "\$panel = \$live ? smpro_gw_panel_apply(\$cfg, \$ranges, \$always) : ['ok' => false, 'msg' => 'not attempted'];", 'F5: applied with the kernel rule, from the same ranges');
has($gw, "function smpro_gw_remove(bool \$quiet = false): array {\n    smpro_gw_panel_remove(\$quiet);", 'F6: removed with it');
has($gw, "if (in_array('cpanel', \$doors, true))  \$p = array_merge(\$p, ['cpanel', 'webdisk', 'cpcalendars', 'cpcontacts']);", 'F7: prefixes follow the doors');
has($fw, "panel subdomains covered", 'F8: the card says whether the second door is covered');

// G. beta378: the wall's country list survives a save from any page (the cleaner is always there)
$gw = $shipped[SMPRO_BASE . '/includes/geowall.php'];
has($gw, "if (!function_exists('smpro_gl_clean_cc')) { \$glf = __DIR__ . '/geologin.php'; if (is_file(\$glf)) require_once \$glf; }", 'G1: geowall loads the cleaner itself');
has($gw, "function smpro_gw_clean_cc(array \$in): array {", 'G2: ...and has one of its own');
hasnt($gw, "function_exists('smpro_gl_clean_cc') ? smpro_gl_clean_cc((array)(\$j['countries'] ?? [])) : []", 'G3: the read never degrades to an empty list');
hasnt($gw, "function_exists('smpro_gl_clean_cc') ? smpro_gl_clean_cc((array)(\$c['countries'] ?? [])) : []", 'G4: nor the write');

// H. beta381: the wall heals itself - an emptied set lifts the rules, a CSF restart re-asserts, refused allowed-country
//    users take it down, and arming checks recent sign-ins against the list
$gw = $shipped[SMPRO_BASE . '/includes/geowall.php'];
has($gw, "'set_size'   => 0,", 'H1: the built size is remembered');
has($gw, "if (\$size === 0 || (\$built > 0 && \$size < (int)(\$built * 0.9))) {", 'H2: the watcher compares the live set with it');
has($gw, "smpro_gw_remove(true);\n            smpro_gw_record('set_lost',", 'H3: ...and lifts the rules BEFORE rebuilding');
has($gw, "-j LOG --log-prefix \"SMPRO_GEOWALL_DROP: \"", 'H4: a LOG rule above the drop');
has($gw, "if (count(\$d['allowed']) >= 3) {", 'H5: three refused allowed-country addresses in ten minutes take the wall down');
has($gw, "function smpro_gw_hook_install(): bool {", 'H6: the CSF post-start hook');
has($gw, "if (!\$inAllow) \$p[] = 'Your address (' . \$myIp . ') is not in csf.allow.", 'H7: arming needs the operator in csf.allow');
has($gw, "\$unc = smpro_gw_uncovered_logins(\$ccs, \$ranges, \$always);", 'H8: arming checks recent allowed-country sign-ins against the list');
if (!function_exists('smpro_gw_dropped')) { require_once SMPRO_BASE . '/includes/geowall.php'; }
$raw = "Oct 26 01:02:03 host kernel: SMPRO_GEOWALL_DROP: IN=eth0 SRC=203.0.113.5 DST=10.0.0.1 PROTO=TCP DPT=2083\nOct 26 01:02:04 host kernel: SMPRO_GEOWALL_DROP: IN=eth0 SRC=203.0.113.5 DST=10.0.0.1 PROTO=TCP DPT=22\nOct 26 01:02:05 host kernel: SMPRO_GEOWALL_DROP: IN=eth0 SRC=198.51.100.9 DST=10.0.0.1 PROTO=TCP DPT=993\n";
$d = smpro_gw_dropped(10, ['EG'], $raw);
is_eq($d['total'], 2, 'H9: refused addresses are counted once each');

