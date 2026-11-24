<?php
/**
 * includes/vulnfeed.php - the client half of the service-version vulnerability check (Security Health plan step 2).
 *
 * Step 1 (OS security updates) covers everything the OS package manager knows about. It does NOT know about the
 * hosting stack that is not an OS package: cPanel/WHM, Imunify360, CSF, LiteSpeed. This feed fills that gap: the
 * licence server publishes a SIGNED advisory list (feeds/vuln-advisories.json) built from the vendors' own
 * security announcements, SM Pro downloads it, verifies it against the SAME pinned licence key trustfeed uses,
 * keeps it, and matches each installed service version against it. Exactly the trusted-bots pattern, for CVEs.
 *
 * This file is SAFE before the licence-server generator exists: with no feed (or an unverifiable/stale one) the
 * check simply reports "vulnerability feed not configured" and flags nothing. It never invents a finding.
 *
 * Advisory document shape (what the generator must sign):
 *   { "payload": {
 *       "feed": "vuln-advisories", "product": "smpro", "generated": <unix>,
 *       "advisories": [
 *         { "id": "CPANEL-SEC-2026-0007", "product": "cpanel",
 *           "introduced": "<from-ver>", "fixed": "<fixed-ver>",   // affected iff introduced <= installed < fixed
 *           "severity": "important", "cves": ["CVE-2026-1234"],
 *           "title": "Privilege escalation in ...", "url": "https://..." }, ...
 *       ] },
 *     "signature": "<base64 RSA signature over json_encode(payload, UNESCAPED_UNICODE|UNESCAPED_SLASHES)>" }
 * Only "product", "fixed" and "severity" are required per advisory; "introduced" defaults to "0" (all versions
 * up to the fix). The client treats the feed as DATA, validating every field before use.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

if (!defined('SMPRO_VF_FILE'))   define('SMPRO_VF_FILE', SMPRO_VARLIB . '/vuln/advisories.json');
if (!defined('SMPRO_VF_PATH'))   define('SMPRO_VF_PATH', '/feeds/vuln-advisories.json');
if (!defined('SMPRO_VF_MAXAGE')) define('SMPRO_VF_MAXAGE', 14 * 86400);   // older than two weeks = history, not truth
if (!defined('SMPRO_VF_SEVS'))   define('SMPRO_VF_SEVS', 'critical,important,moderate,low');

/** The products this check knows how to read a local version for. Keep names lowercase + stable (feed keys match). */
function smpro_vf_known_products(): array { return ['cpanel', 'imunify360', 'csf', 'litespeed']; }

/** Read the installed version of one product, or '' when it is not present / unreadable. Pure reads, bounded. */
function smpro_vf_local_version(string $product): string {
    switch ($product) {
        case 'cpanel':
            // /usr/local/cpanel/version holds a dotted cPanel version string
            return trim((string)@file_get_contents('/usr/local/cpanel/version'));
        case 'imunify360':
            if (trim((string)@shell_exec('command -v imunify360-agent 2>/dev/null')) === '') return '';
            // "imunify360-agent version" -> a line containing e.g. "7.12.3"
            $o = (string)@shell_exec('timeout 15 imunify360-agent version 2>/dev/null');
            return preg_match('/\b(\d+\.\d+\.\d+(?:\.\d+)?)\b/', $o, $m) ? $m[1] : '';
        case 'csf':
            if (!is_readable('/usr/sbin/csf') && trim((string)@shell_exec('command -v csf 2>/dev/null')) === '') return '';
            $o = (string)@shell_exec('timeout 10 csf -v 2>/dev/null');   // "csf: v14.21 (generic)"
            return preg_match('/v?(\d+\.\d+(?:\.\d+)?)/', $o, $m) ? $m[1] : '';
        case 'litespeed':
            foreach (['/usr/local/lsws/bin/lshttpd', '/usr/local/lsws/bin/litespeed'] as $bin) {
                if (!is_executable($bin)) continue;
                $o = (string)@shell_exec('timeout 10 ' . escapeshellarg($bin) . ' -v 2>/dev/null');   // "LiteSpeed/6.1.1 ..."
                if (preg_match('#LiteSpeed/(\d+\.\d+(?:\.\d+)?)#i', $o, $m)) return $m[1];
            }
            return '';
    }
    return '';
}

/** Validate a decoded feed document: signed by the pinned key, well-formed, every advisory sane. ['ok'=>,'why'=>] */
function smpro_vf_validate($doc, int $now = 0): array {
    $now = $now ?: time();
    if (!is_array($doc) || !is_array($doc['payload'] ?? null)) return ['ok' => false, 'why' => 'not a feed document'];
    if (!function_exists('smpro_lic_verify_signature') || !smpro_lic_verify_signature($doc)) return ['ok' => false, 'why' => 'signature does not verify against the pinned licence key'];
    $p = $doc['payload'];
    if (($p['feed'] ?? '') !== 'vuln-advisories' || ($p['product'] ?? '') !== 'smpro') return ['ok' => false, 'why' => 'not the vuln-advisories feed'];
    $gen = (int)($p['generated'] ?? 0);
    if ($gen <= 0 || $gen > $now + 3600) return ['ok' => false, 'why' => 'generated time is missing or in the future'];
    if ($now - $gen > SMPRO_VF_MAXAGE) return ['ok' => false, 'why' => 'older than ' . intdiv(SMPRO_VF_MAXAGE, 86400) . ' days'];
    if (!is_array($p['advisories'] ?? null)) return ['ok' => false, 'why' => 'no advisories array'];
    $sevs = explode(',', SMPRO_VF_SEVS);
    $known = smpro_vf_known_products();
    foreach ($p['advisories'] as $a) {
        if (!is_array($a)) return ['ok' => false, 'why' => 'an advisory is not an object'];
        if (!in_array((string)($a['product'] ?? ''), $known, true)) return ['ok' => false, 'why' => 'advisory names an unknown product'];
        if (!in_array((string)($a['severity'] ?? ''), $sevs, true)) return ['ok' => false, 'why' => 'advisory has an unknown severity'];
        if (!preg_match('/^\d+(\.\d+){0,3}$/', (string)($a['fixed'] ?? ''))) return ['ok' => false, 'why' => 'advisory has no valid "fixed" version'];
        if (isset($a['introduced']) && $a['introduced'] !== '' && !preg_match('/^\d+(\.\d+){0,3}$/', (string)$a['introduced'])) return ['ok' => false, 'why' => 'advisory has a malformed "introduced" version'];
        foreach ((array)($a['cves'] ?? []) as $c) if (!preg_match('/^CVE-\d{4}-\d{4,}$/i', (string)$c)) return ['ok' => false, 'why' => 'advisory carries a malformed CVE id'];
    }
    return ['ok' => true, 'why' => ''];
}

/** Pull the feed from the licence server, verify, keep it. ['ok'=>bool,'msg'=>string,'advisories'=>n] */
function smpro_vf_fetch(): array {
    if (defined('SMPRO_TEST_SRC')) return ['ok' => false, 'msg' => 'test: no network', 'advisories' => 0];
    $bases = function_exists('smpro_tf_bases') ? smpro_tf_bases() : [];
    $last = '';
    foreach ($bases as $base) {
        $url = rtrim($base, '/') . SMPRO_VF_PATH;
        if (!preg_match('#^https://[A-Za-z0-9.-]+(:\d+)?/feeds/vuln-advisories\.json$#', $url)) continue;
        $body = (string)@shell_exec('timeout 25 curl -fsSL --max-redirs 3 --max-time 20 -A ' . escapeshellarg('SMPro-vulnfeed/' . (defined('SMPRO_VERSION') ? SMPRO_VERSION : '1')) . ' ' . escapeshellarg($url) . ' 2>/dev/null');
        if ($body === '') { $last = 'no answer from ' . $base; continue; }
        $doc = json_decode($body, true); $v = smpro_vf_validate($doc);
        if (!$v['ok']) { $last = $base . ': ' . $v['why']; continue; }
        @is_dir(dirname(SMPRO_VF_FILE)) || @mkdir(dirname(SMPRO_VF_FILE), 0700, true);
        $t = SMPRO_VF_FILE . '.tmp';
        if (@file_put_contents($t, $body, LOCK_EX) === false) return ['ok' => false, 'msg' => 'could not write ' . SMPRO_VF_FILE, 'advisories' => 0];
        @chmod($t, 0600); @rename($t, SMPRO_VF_FILE);
        $GLOBALS['smpro_vf_memo'] = null;
        $n = count($doc['payload']['advisories']);
        if (function_exists('smpro_audit')) @smpro_audit('vulnfeed_fetch', ['from' => $base, 'generated' => (int)$doc['payload']['generated'], 'advisories' => $n]);
        return ['ok' => true, 'msg' => 'verified advisory list from ' . $base . ': ' . $n . ' advisory(ies), built ' . date('Y-m-d H:i', (int)$doc['payload']['generated']), 'advisories' => $n];
    }
    return ['ok' => false, 'msg' => 'the licence server did not give a usable advisory list (' . $last . ')', 'advisories' => 0];
}

/** The kept payload, or null when none / stale / no longer verifying. */
function smpro_vf_data(): ?array {
    if (array_key_exists('smpro_vf_memo', $GLOBALS) && $GLOBALS['smpro_vf_memo'] !== null) return $GLOBALS['smpro_vf_memo'] ?: null;
    $doc = @is_file(SMPRO_VF_FILE) ? json_decode((string)@file_get_contents(SMPRO_VF_FILE), true) : null;
    $ok = $doc !== null && smpro_vf_validate($doc)['ok'];
    $GLOBALS['smpro_vf_memo'] = $ok ? $doc['payload'] : false;
    return $ok ? $doc['payload'] : null;
}

/**
 * Advisories that affect one installed version: introduced <= version < fixed. Pure, so it is unit-testable
 * without a feed on disk - pass the advisory list in. version_compare handles the dotted hosting-stack versions.
 */
function smpro_vf_match_version(string $version, array $advisories): array {
    $version = trim($version);
    if ($version === '' || !preg_match('/^\d+(\.\d+){0,3}$/', $version)) return [];
    $hits = [];
    foreach ($advisories as $a) {
        $fixed = (string)($a['fixed'] ?? ''); if ($fixed === '') continue;
        $intro = (string)($a['introduced'] ?? '0'); if ($intro === '') $intro = '0';
        if (version_compare($version, $intro, '>=') && version_compare($version, $fixed, '<')) $hits[] = $a;
    }
    return $hits;
}

/** For one product: its installed version + the advisories that hit it. ['installed'=>, 'version'=>, 'hits'=>[]]. */
function smpro_vf_match_product(string $product): array {
    $p = smpro_vf_data();
    $version = smpro_vf_local_version($product);
    if ($version === '') return ['installed' => false, 'version' => '', 'hits' => []];
    $adv = $p ? array_values(array_filter((array)($p['advisories'] ?? []), fn($a) => (string)($a['product'] ?? '') === $product)) : [];
    return ['installed' => true, 'version' => $version, 'hits' => smpro_vf_match_version($version, $adv)];
}

/** Where the feed stands, for the page + the fetch worker. */
function smpro_vf_status(): array {
    $p = smpro_vf_data(); $mt = @is_file(SMPRO_VF_FILE) ? (int)@filemtime(SMPRO_VF_FILE) : 0;
    if (!$p) return ['have' => false, 'generated' => 0, 'fetched' => $mt, 'advisories' => 0,
                     'why' => $mt ? 'the kept list no longer verifies or is older than ' . intdiv(SMPRO_VF_MAXAGE, 86400) . ' days' : 'not fetched yet'];
    return ['have' => true, 'generated' => (int)$p['generated'], 'fetched' => $mt, 'advisories' => count((array)($p['advisories'] ?? [])), 'why' => ''];
}

/** Schedule the advisory-feed refresh (bin/vulnfeed_tick.php). Mirrors smpro_tf_cron_sync; off removes the file. */
function smpro_vf_cron_sync(): bool {
    if (defined('SMPRO_TEST_SRC')) return true;
    $f = '/etc/cron.d/smpro-vulnfeed';
    $bin = SMPRO_BASE . '/bin/vulnfeed_tick.php'; if (!@is_file($bin)) { if (@is_file($f)) @unlink($f); return false; }
    $php = function_exists('smpro_php_cli_bin') ? smpro_php_cli_bin() : (is_executable('/usr/local/cpanel/3rdparty/bin/php') ? '/usr/local/cpanel/3rdparty/bin/php' : 'php');
    $min = abs(crc32((string)@gethostname())) % 60;
    $h1  = abs(crc32((string)@gethostname() . 'vf')) % 6;            // twice a day, offset per host
    $line = $min . ' ' . $h1 . ',' . ($h1 + 12) . ' * * * root ' . escapeshellarg($php) . ' ' . escapeshellarg($bin) . " >/dev/null 2>&1\n";
    $cur = @is_file($f) ? (string)@file_get_contents($f) : '';
    if ($cur === $line) return true;
    return @file_put_contents($f, $line, LOCK_EX) !== false;
}
