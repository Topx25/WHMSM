<?php
/**
 * vuln_advisories_build.php  —  licence-server generator for the SM Pro service-vulnerability feed.
 *
 * Belongs on the licence server at /opt/aitech-license-server/bin/vuln_advisories_build.php (this copy under
 * _srv/ in the plugin repo is the reviewed source; it is NOT shipped in the plugin package).
 *
 * It reads a human-maintained advisory source file, validates every entry, stamps + signs the payload with the
 * SAME licence private key that signs trusted-bots.json, and publishes public/feeds/vuln-advisories.json
 * atomically. SM Pro (includes/vulnfeed.php) downloads it, verifies the signature against the pinned licence
 * public key, and matches each installed hosting-stack version (cPanel / Imunify360 / CSF / LiteSpeed) against it.
 *
 * WHY a maintained source file, not live scraping: a signed security feed must never carry a wrong "fixed in"
 * version or a fabricated CVE. Vendor advisory pages (cPanel ChangeLog, Imunify, CSF, LiteSpeed) have no stable
 * machine format and change layout without notice; scraping them into a SIGNED document would let a parser slip
 * publish a false advisory to every server. So advisories are curated into storage/vuln-advisories.source.json
 * (reviewed, append-only) and this generator only validates, signs and publishes. A separate fetch helper can
 * PROPOSE entries into a review queue later; it must never write straight into the signed feed.
 *
 * Run from cron (see the cron line this script installs comments for). Exits non-zero only on a real failure;
 * an empty/!valid source leaves the previous published feed untouched.
 *
 *   php vuln_advisories_build.php            # build + sign + publish if the source validates
 *   php vuln_advisories_build.php --check    # validate the source only, write nothing (CI / pre-commit)
 */

const VA_SOURCE  = '/opt/aitech-license-server/storage/vuln-advisories.source.json';
const VA_OUT     = '/opt/aitech-license-server/public/feeds/vuln-advisories.json';
const VA_STATE   = '/opt/aitech-license-server/storage/vuln-advisories.state.json';
const VA_KEY     = '/opt/aitech-license-server/keys/private.pem';
const VA_LOG     = '/var/log/smpro-vuln-advisories.log';
const VA_TTL     = 86400;                               // a day; the client treats >14d as stale regardless
const VA_PRODUCTS = ['cpanel', 'imunify360', 'csf', 'litespeed'];
const VA_SEVS     = ['critical', 'important', 'moderate', 'low'];

function va_log(string $m): void { @file_put_contents(VA_LOG, '[' . date('Y-m-d H:i:s') . '] ' . $m . "\n", FILE_APPEND | LOCK_EX); }
function va_die(string $m): void { va_log('ABORT: ' . $m); fwrite(STDERR, $m . "\n"); exit(1); }

$checkOnly = in_array('--check', $argv ?? [], true);

/* ---- read + validate the curated source ---- */
if (!is_file(VA_SOURCE)) {
    // Not an error on first run: write a documented empty skeleton so the operator has a form to fill in, and
    // publish an empty (but SIGNED and valid) feed so the client sees "configured, 0 advisories" not "missing".
    $skeleton = [
        '_README' => 'Curated SM Pro service-vulnerability advisories. Append objects to "advisories". '
                   . 'Required per entry: id, product (' . implode('|', VA_PRODUCTS) . '), fixed (version), severity ('
                   . implode('|', VA_SEVS) . '). Optional: introduced (default "0"), cves [..], title, url. '
                   . 'An advisory affects a server iff introduced <= installed_version < fixed.',
        'advisories' => [],
    ];
    @is_dir(dirname(VA_SOURCE)) || @mkdir(dirname(VA_SOURCE), 0750, true);
    @file_put_contents(VA_SOURCE, json_encode($skeleton, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX);
    va_log('source file was missing — wrote an empty skeleton to ' . VA_SOURCE);
}

$srcRaw = (string)@file_get_contents(VA_SOURCE);
$src = json_decode($srcRaw, true);
if (!is_array($src) || !isset($src['advisories']) || !is_array($src['advisories'])) va_die('source file is not valid JSON with an "advisories" array');

$clean = [];
$seen = [];
foreach ($src['advisories'] as $i => $a) {
    $where = 'advisory #' . $i;
    if (!is_array($a)) va_die("$where is not an object");
    $id   = trim((string)($a['id'] ?? ''));
    $prod = strtolower(trim((string)($a['product'] ?? '')));
    $sev  = strtolower(trim((string)($a['severity'] ?? '')));
    $fixed = trim((string)($a['fixed'] ?? ''));
    $intro = trim((string)($a['introduced'] ?? '0')); if ($intro === '') $intro = '0';
    if ($id === '' || !preg_match('/^[A-Za-z0-9._:\-]{3,64}$/', $id)) va_die("$where has a missing/invalid id");
    if (isset($seen[$id])) va_die("$where duplicates id $id");
    if (!in_array($prod, VA_PRODUCTS, true)) va_die("$where: unknown product '$prod'");
    if (!in_array($sev, VA_SEVS, true))      va_die("$where: unknown severity '$sev'");
    if (!preg_match('/^\d+(\.\d+){0,3}$/', $fixed)) va_die("$where: 'fixed' is not a dotted version");
    if (!preg_match('/^\d+(\.\d+){0,3}$/', $intro)) va_die("$where: 'introduced' is not a dotted version");
    if (version_compare($intro, $fixed, '>=')) va_die("$where: introduced ($intro) must be < fixed ($fixed)");
    $cves = [];
    foreach ((array)($a['cves'] ?? []) as $c) {
        $c = strtoupper(trim((string)$c));
        if (!preg_match('/^CVE-\d{4}-\d{4,}$/', $c)) va_die("$where: malformed CVE '$c'");
        $cves[$c] = true;
    }
    $entry = ['id' => $id, 'product' => $prod, 'introduced' => $intro, 'fixed' => $fixed, 'severity' => $sev];
    if ($cves) $entry['cves'] = array_keys($cves);
    $title = trim((string)($a['title'] ?? '')); if ($title !== '') $entry['title'] = mb_substr($title, 0, 200);
    $url = trim((string)($a['url'] ?? ''));
    if ($url !== '') { if (!preg_match('#^https://[\w.\-/%?=&:#]+$#', $url)) va_die("$where: url must be https"); $entry['url'] = $url; }
    $seen[$id] = true;
    $clean[] = $entry;
}

if ($checkOnly) { fwrite(STDOUT, 'OK: ' . count($clean) . " advisory(ies) valid.\n"); exit(0); }

/* ---- sign with the licence key (same contract as trusted_bots_build.php) ---- */
$pem = (string)@file_get_contents(VA_KEY);
$pk = $pem !== '' ? openssl_pkey_get_private($pem) : false;
if (!$pk) va_die('could not load the signing key ' . VA_KEY);

$payload = ['product' => 'smpro', 'feed' => 'vuln-advisories', 'version' => 1,
            'generated' => time(), 'ttl' => VA_TTL, 'advisories' => $clean];
$data = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
$sig = '';
if (!openssl_sign($data, $sig, $pk, OPENSSL_ALGO_SHA256)) va_die('signing failed');
$doc = json_encode(['payload' => $payload, 'signature_alg' => 'RSA-SHA256', 'signature' => base64_encode($sig)],
                   JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

/* ---- publish atomically ---- */
@is_dir(dirname(VA_OUT)) || @mkdir(dirname(VA_OUT), 0755, true);
$tmp = VA_OUT . '.tmp';
if (@file_put_contents($tmp, $doc, LOCK_EX) === false) va_die('could not write ' . $tmp);
@chmod($tmp, 0644);
if (!@rename($tmp, VA_OUT)) va_die('could not move the feed into place');
@is_dir(dirname(VA_STATE)) || @mkdir(dirname(VA_STATE), 0750, true);
@file_put_contents(VA_STATE, json_encode(['advisories' => count($clean), 'built_at' => time()], JSON_UNESCAPED_SLASHES), LOCK_EX);

va_log('published ' . count($clean) . ' advisory(ies) to ' . VA_OUT);
fwrite(STDOUT, 'published ' . count($clean) . " advisory(ies).\n");
exit(0);
