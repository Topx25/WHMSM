<?php
/**
 * logtest.php — check the decoder and rule patterns WITHOUT a Wazuh manager.
 *
 * THIS IS NOT wazuh-logtest. It reads the same XML files, applies the same PCRE2 patterns in the same order, and
 * reports what each line would decode to and which rule would match it. What it does NOT model: rule ordering
 * across the whole ruleset, if_matched_sid / frequency / same_user correlation, or Wazuh's own regex quirks.
 *
 * Its job is to catch the cheap mistakes — a pattern that matches nothing, a field that comes out empty, a line
 * shape that falls through — before anything is copied onto a manager. `wazuh-logtest` on a real manager is
 * still the acceptance test, and the README says so.
 *
 *   php logtest.php                          # the shipped sample
 *   php logtest.php /path/to/session_log     # a real log (read only; prints identities, so do it locally)
 */
$base = dirname(__DIR__);
$decFile  = $base . '/decoders/cpanel_session.xml';
$ruleFile = $base . '/rules/cpanel_session_rules.xml';
$logFile  = $argv[1] ?? __DIR__ . '/sample_session_log.txt';

foreach ([$decFile, $ruleFile, $logFile] as $f) {
    if (!is_readable($f)) { fwrite(STDERR, "cannot read $f\n"); exit(2); }
}

/* ---------------------------------------------------------------- load the patterns out of the XML */
libxml_use_internal_errors(true);
// Wazuh ruleset files are XML FRAGMENTS: a decoder file has several <decoder> elements at the top level and no
// single root. That is valid for Wazuh and invalid for every general-purpose XML parser, so wrap before parsing.
$wrap = function (string $file) { return simplexml_load_string('<ossec>' . (string)file_get_contents($file) . '</ossec>'); };
$dec = $wrap($decFile);
$rul = $wrap($ruleFile);
if ($dec === false || $rul === false) {
    fwrite(STDERR, "XML did not parse:\n");
    foreach (libxml_get_errors() as $e) fwrite(STDERR, '  ' . trim($e->message) . "\n");
    exit(2);
}

$prematch = null; $decoders = [];
foreach ($dec->decoder as $d) {
    if (isset($d->prematch)) { $prematch = (string)$d->prematch; continue; }
    if (!isset($d->regex)) continue;
    $decoders[] = [
        'name'  => (string)$d['name'],
        'regex' => (string)$d->regex,
        'order' => array_map('trim', explode(',', (string)$d->order)),
    ];
}

$rules = [];
foreach ($rul->group->rule as $r) {
    $rules[] = [
        'id'    => (string)$r['id'],
        'level' => (int)$r['level'],
        'match' => isset($r->match) ? (string)$r->match : '',
        'field' => isset($r->field) ? ['name' => (string)$r->field['name'], 're' => (string)$r->field] : null,
        'desc'  => trim((string)$r->description),
        'freq'  => isset($r['frequency']) ? (int)$r['frequency'] : 0,
        // A rule with <decoded_as> is the PARENT of the group. It matches, but what an operator is shown is the
        // child that chains off it with if_sid, so it is never the reported hit.
        'parent' => isset($r->decoded_as),
    ];
}
printf("loaded %d decoder pattern(s), %d rule(s)\n\n", count($decoders), count($rules));

/* ---------------------------------------------------------------- run */
$delim = function (string $re): string { return '/' . str_replace('/', '\\/', $re) . '/'; };
$lines = file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
$undecoded = 0; $unmatched = 0; $byRule = [];

foreach ($lines as $line) {
    if ($prematch !== null && !preg_match($delim($prematch), $line)) continue;   // not ours at all

    $fields = []; $used = '';
    foreach ($decoders as $d) {
        if (preg_match($delim($d['regex']), $line, $m)) {
            foreach ($d['order'] as $i => $name) if (isset($m[$i + 1])) $fields[$name] = $m[$i + 1];
            $used = $d['name'];
            break;                                                              // first match wins, as in Wazuh
        }
    }
    if ($used === '') {
        $undecoded++;
        printf("NO DECODER  %s\n", substr($line, 0, 150));
        continue;
    }

    // Highest-level matching rule, which is the one an operator would see.
    $hit = null;
    foreach ($rules as $r) {
        if ($r['freq'] > 0) continue;                                           // correlation rules need a manager
        if ($r['parent']) continue;                                             // the parent is not the answer
        $ok = false;
        if ($r['match'] !== '')        $ok = (bool)preg_match($delim($r['match']), $line);
        elseif ($r['field'] !== null)  $ok = isset($fields[$r['field']['name']])
                                          && (bool)preg_match($delim($r['field']['re']), $fields[$r['field']['name']]);
        // A rule with neither a match nor a field is a catch-all: once the line is decoded, it applies. Skipping
        // those made this tester report "nothing matched" for lines the manager would in fact classify — a
        // checker that under-reports its own coverage is worse than no checker.
        elseif ($r['level'] === 0)     $ok = true;
        // Among siblings at the same level the FIRST match wins, in file order — which is why the catch-all
        // has to be the last rule in the file, and why it only ever collects what nothing else claimed.
        if ($ok && ($hit === null || $r['level'] > $hit['level'])) $hit = $r;
    }

    $id = $hit['id'] ?? '-';
    $byRule[$id] = ($byRule[$id] ?? 0) + 1;
    if ($hit === null) $unmatched++;

    printf("%-5s L%-2s %-22s %-16s %s\n",
        $id, $hit['level'] ?? '-',
        substr((string)($fields['dstuser'] ?? '?'), 0, 22),
        substr((string)($fields['srcip'] ?? ($fields['status'] ?? '-')), 0, 16),
        $hit ? $hit['desc'] : '*** no rule matched this line ***');
}

/* ---------------------------------------------------------------- verdict */
echo "\n--- per rule ---\n";
ksort($byRule);
foreach ($byRule as $id => $n) {
    $d = '';
    foreach ($rules as $r) if ($r['id'] === $id) $d = $r['desc'];
    printf("  %-5s %4d  %s\n", $id, $n, $id === '-' ? 'NOTHING MATCHED' : $d);
}
printf("\n%d line(s) read, %d undecoded, %d decoded but matched no rule\n", count($lines), $undecoded, $unmatched);
echo "Correlation rules (frequency/same_user/different_srcip) are NOT evaluated here — run wazuh-logtest for those.\n";
exit(($undecoded > 0 || $unmatched > 0) ? 1 : 0);
