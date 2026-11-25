<?php
/**
 * vuln_advisories_fetch.php  —  licence-server helper that PROPOSES service-vulnerability advisories into a
 * REVIEW QUEUE from the NVD CVE API (NIST). It never touches the signed feed and never touches the curated
 * source file: it only appends candidates to vuln-advisories.review.json for a human to approve. Approval
 * (moving an entry into vuln-advisories.source.json) stays a manual, reviewed step — a signed security feed
 * must never carry a CVE a scraper invented or mis-parsed.
 *
 * Belongs on the licence server at /opt/aitech-license-server/bin/vuln_advisories_fetch.php (this copy under
 * _srv/ is the reviewed source; it is NOT shipped in the plugin package).
 *
 * Source: https://services.nvd.nist.gov/rest/json/cves/2.0 — official, structured JSON (CVE id, CVSS severity,
 * affected version ranges via CPE). Chosen over scraping vendor HTML because it is stable and machine-readable.
 *
 * Filtering (keeps the queue reviewable, not 478 rows of ancient noise): only CVEs that (a) name a concrete
 * fixed version (versionEndExcluding/Including) so "introduced<=v<fixed" is meaningful, and (b) were published
 * within the recency window. A CVE already present in the source feed or already in the queue is skipped.
 *
 *   php vuln_advisories_fetch.php            # fetch all known products, append new candidates to the queue
 *   php vuln_advisories_fetch.php --product cpanel   # one product only
 */

const VF_SOURCE = '/opt/aitech-license-server/storage/vuln-advisories.source.json';
const VF_QUEUE  = '/opt/aitech-license-server/storage/vuln-advisories.review.json';
const VF_LOG    = '/var/log/smpro-vuln-advisories.log';
const VF_RECENT_DAYS = 1095;                 // ~3 years; older CVEs with a fix are almost always long since patched
// product => the NVD keyword(s) to search. Kept deliberately specific so unrelated products don't flood the queue.
const VF_PRODUCTS = [
    'cpanel'     => 'cpanel',
    'imunify360' => 'imunify360',
    'csf'        => 'configserver security firewall',
    'litespeed'  => 'litespeed web server',
];
const VF_SEV_MAP = ['LOW' => 'low', 'MEDIUM' => 'moderate', 'HIGH' => 'important', 'CRITICAL' => 'critical'];

function vf_log(string $m): void { @file_put_contents(VF_LOG, '[' . date('Y-m-d H:i:s') . '] fetch: ' . $m . "\n", FILE_APPEND | LOCK_EX); }

function vf_load_json(string $path): array { $d = @is_file($path) ? json_decode((string)@file_get_contents($path), true) : []; return is_array($d) ? $d : []; }

/** Pull up to a page of CVEs for one keyword from NVD. Returns the decoded 'vulnerabilities' array (or []). */
function vf_nvd_query(string $keyword): array {
    $url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=100&keywordSearch=' . rawurlencode($keyword);
    $body = (string)@shell_exec('timeout 40 curl -fsSL --max-time 35 -A ' . escapeshellarg('SMPro-vulnfetch/1.0') . ' ' . escapeshellarg($url) . ' 2>/dev/null');
    if ($body === '') return [];
    $d = json_decode($body, true);
    return is_array($d) && isset($d['vulnerabilities']) ? (array)$d['vulnerabilities'] : [];
}

/** From one NVD CVE object + the product key, derive a candidate advisory, or null if it is not usable. */
function vf_candidate(array $v, string $product): ?array {
    $c = $v['cve'] ?? null; if (!is_array($c) || empty($c['id'])) return null;
    $id = (string)$c['id'];
    // recency
    $pub = strtotime((string)($c['published'] ?? '')) ?: 0;
    if ($pub > 0 && (time() - $pub) > VF_RECENT_DAYS * 86400) return null;
    // severity (prefer CVSS v3.1 > v3.0 > v2)
    $sevRaw = '';
    $m = $c['metrics'] ?? [];
    foreach (['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'] as $k) {
        if (!empty($m[$k][0])) { $sevRaw = strtoupper((string)($m[$k][0]['baseSeverity'] ?? ($m[$k][0]['cvssData']['baseSeverity'] ?? ''))); if ($sevRaw !== '') break; }
    }
    $severity = VF_SEV_MAP[$sevRaw] ?? '';
    if ($severity === '') return null;                    // no rated severity -> not actionable, skip
    // affected version range from the CPE match that names this product
    $intro = ''; $fixed = ''; $fixedNote = '';
    foreach ((array)($c['configurations'] ?? []) as $cfg) {
        foreach ((array)($cfg['nodes'] ?? []) as $n) {
            foreach ((array)($n['cpeMatch'] ?? []) as $cm) {
                $crit = strtolower((string)($cm['criteria'] ?? ''));
                if (strpos($crit, $product) === false && strpos($crit, str_replace(' ', '', $product)) === false) continue;
                $end = (string)($cm['versionEndExcluding'] ?? '');
                $endIncl = (string)($cm['versionEndIncluding'] ?? '');
                if ($end === '' && $endIncl === '') continue;         // no concrete fixed version -> not matchable
                $intro = (string)($cm['versionStartIncluding'] ?? '0') ?: '0';
                // we only sign introduced<=v<fixed; for an "including" upper bound, bump is left to the reviewer
                $fixed = $end !== '' ? $end : $endIncl;
                $fixedNote = $end !== '' ? '' : ' (NVD gave versionEndIncluding ' . $endIncl . '; confirm the real fixed version)';
                break 3;
            }
        }
    }
    if ($fixed === '' || !preg_match('/^\d+(\.\d+){0,3}$/', $fixed) || !preg_match('/^\d+(\.\d+){0,3}$/', $intro)) return null;
    $desc = '';
    foreach ((array)($c['descriptions'] ?? []) as $d) if (($d['lang'] ?? '') === 'en') { $desc = (string)$d['value']; break; }
    return [
        'id' => $id, 'product' => $product, 'introduced' => $intro, 'fixed' => $fixed,
        'severity' => $severity, 'cves' => [$id],
        'title' => mb_substr(trim($desc), 0, 180),
        'url' => 'https://nvd.nist.gov/vuln/detail/' . $id,
        '_source' => 'nvd', '_published' => date('Y-m-d', $pub ?: time()),
        '_note' => $fixedNote,
    ];
}

$only = '';
$argv2 = $argv ?? [];
$pi = array_search('--product', $argv2, true);
if ($pi !== false && isset($argv2[$pi + 1])) $only = strtolower((string)$argv2[$pi + 1]);

// IDs already known (in the signed source or already queued) — never propose a duplicate
$src = vf_load_json(VF_SOURCE);
$queue = vf_load_json(VF_QUEUE);
$known = [];
foreach ((array)($src['advisories'] ?? []) as $a) if (!empty($a['id'])) $known[strtoupper($a['id'])] = true;
$queueItems = is_array($queue['candidates'] ?? null) ? $queue['candidates'] : [];
foreach ($queueItems as $a) if (!empty($a['id'])) $known[strtoupper($a['id'])] = true;

$added = 0; $perProduct = [];
foreach (VF_PRODUCTS as $product => $keyword) {
    if ($only !== '' && $only !== $product) continue;
    $rows = vf_nvd_query($keyword);
    $n = 0;
    foreach ($rows as $v) {
        $cand = vf_candidate($v, $product);
        if ($cand === null) continue;
        if (isset($known[strtoupper($cand['id'])])) continue;
        $queueItems[] = $cand; $known[strtoupper($cand['id'])] = true; $added++; $n++;
    }
    $perProduct[$product] = $n;
    usleep(800000);   // be polite to NVD between keywords (no API key: 5 req / 30s)
}

$queue['candidates'] = $queueItems;
$queue['updated'] = time();
$queue['_README'] = 'REVIEW QUEUE — proposed advisories from NVD, NOT yet signed. Check each (especially "fixed"'
    . ' and the version range), then move the good ones into vuln-advisories.source.json and run'
    . ' vuln_advisories_build.php. Delete the rest. Nothing here is served to any client.';
@is_dir(dirname(VF_QUEUE)) || @mkdir(dirname(VF_QUEUE), 0750, true);
$tmp = VF_QUEUE . '.tmp';
@file_put_contents($tmp, json_encode($queue, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), LOCK_EX);
@rename($tmp, VF_QUEUE);

vf_log('queued ' . $added . ' new candidate(s): ' . json_encode($perProduct));
fwrite(STDOUT, 'queued ' . $added . " new candidate(s) for review: " . json_encode($perProduct) . "\n");
fwrite(STDOUT, 'review ' . VF_QUEUE . ", then move approved entries into " . VF_SOURCE . " and run vuln_advisories_build.php\n");
exit(0);
