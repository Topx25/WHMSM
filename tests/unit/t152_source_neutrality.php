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
