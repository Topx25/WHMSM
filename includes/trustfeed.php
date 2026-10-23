<?php
/**
 * includes/trustfeed.php — the trusted-bots list, pulled from the licence server.
 *
 * The licence server fetches the official range files (Google, Bing, DuckDuckGo, OpenAI, Perplexity, Meta,
 * Cloudflare, UptimeRobot, the Gmail and Microsoft 365 SPF blocks), checks each against its last good copy, signs
 * the result with the licence key this plugin already pins, and publishes it. Here the plugin pulls that one
 * file, verifies the signature, keeps it, and from then on the allow-list providers and Bot Guard read their
 * ranges from it. The vendor feeds remain the fallback for a server that cannot reach the licence host.
 *
 * Nothing here blocks or allows anything by itself: it only answers "which ranges does this provider have" and
 * "which crawler families exist". Every decision stays where it was.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

if (!defined('SMPRO_TF_FILE'))  define('SMPRO_TF_FILE', SMPRO_VARLIB . '/fw_ranges/trusted-bots.json');
if (!defined('SMPRO_TF_PATH'))  define('SMPRO_TF_PATH', '/feeds/trusted-bots.json');
if (!defined('SMPRO_TF_MAXAGE')) define('SMPRO_TF_MAXAGE', 14 * 86400);   // older than this the list is history, not truth

/** The hosts to try, primary first. */
function smpro_tf_bases(): array {
    $b = [];
    if (defined('SMPRO_LIC_BASE')) $b[] = SMPRO_LIC_BASE;
    if (defined('SMPRO_LIC_BASE_FALLBACKS')) foreach (preg_split('/[\s,]+/', (string)SMPRO_LIC_BASE_FALLBACKS) as $x) if ($x !== '') $b[] = $x;
    return array_values(array_unique($b));
}
/** Pure check of a decoded document: signed by the pinned key, well-formed, every range a CIDR. ['ok'=>bool,'why'=>''] */
function smpro_tf_validate($doc, int $now = 0): array {
    $now = $now ?: time();
    if (!is_array($doc) || !is_array($doc['payload'] ?? null)) return ['ok' => false, 'why' => 'not a feed document'];
    if (!function_exists('smpro_lic_verify_signature') || !smpro_lic_verify_signature($doc)) return ['ok' => false, 'why' => 'signature does not verify against the pinned licence key'];
    $p = $doc['payload'];
    if (($p['feed'] ?? '') !== 'trusted-bots' || ($p['product'] ?? '') !== 'smpro') return ['ok' => false, 'why' => 'not the trusted-bots feed'];
    $gen = (int)($p['generated'] ?? 0);
    if ($gen <= 0 || $gen > $now + 3600) return ['ok' => false, 'why' => 'generated time is missing or in the future'];
    if ($now - $gen > SMPRO_TF_MAXAGE) return ['ok' => false, 'why' => 'older than ' . intdiv(SMPRO_TF_MAXAGE, 86400) . ' days'];
    if (!is_array($p['sources'] ?? null) || count($p['sources']) < 5) return ['ok' => false, 'why' => 'fewer than five sources'];
    $n = 0;
    foreach ($p['sources'] as $k => $s) {
        if (!preg_match('/^[a-z0-9_]{1,32}$/', (string)$k) || !is_array($s) || !is_array($s['ranges'] ?? null)) return ['ok' => false, 'why' => 'source ' . $k . ' is malformed'];
        foreach ($s['ranges'] as $c) { if (!is_string($c) || !preg_match('#^([0-9a-f.:]+)/(\d{1,3})$#i', $c, $m) || !filter_var($m[1], FILTER_VALIDATE_IP)) return ['ok' => false, 'why' => 'source ' . $k . ' carries something that is not a range']; $n++; }
    }
    if ($n < 50) return ['ok' => false, 'why' => 'only ' . $n . ' ranges in total'];
    return ['ok' => true, 'why' => ''];
}
/** Pull the feed from the licence server, verify, keep. ['ok'=>bool,'msg'=>'','sources'=>n,'ranges'=>n] */
function smpro_tf_fetch(): array {
    if (defined('SMPRO_TEST_SRC')) return ['ok' => false, 'msg' => 'test: no network', 'sources' => 0, 'ranges' => 0];
    $last = '';
    foreach (smpro_tf_bases() as $base) {
        $url = rtrim($base, '/') . SMPRO_TF_PATH;
        if (!preg_match('#^https://[A-Za-z0-9.-]+(:\d+)?/feeds/trusted-bots\.json$#', $url)) continue;
        $body = (string)@shell_exec('timeout 25 curl -fsSL --max-redirs 3 --max-time 20 -A ' . escapeshellarg('SMPro-trustfeed/' . (defined('SMPRO_VERSION') ? SMPRO_VERSION : '1')) . ' ' . escapeshellarg($url) . ' 2>/dev/null');
        if ($body === '') { $last = 'no answer from ' . $base; continue; }
        $doc = json_decode($body, true); $v = smpro_tf_validate($doc);
        if (!$v['ok']) { $last = $base . ': ' . $v['why']; continue; }
        @is_dir(dirname(SMPRO_TF_FILE)) || @mkdir(dirname(SMPRO_TF_FILE), 0700, true);
        $t = SMPRO_TF_FILE . '.tmp';
        if (@file_put_contents($t, $body, LOCK_EX) === false) return ['ok' => false, 'msg' => 'could not write ' . SMPRO_TF_FILE, 'sources' => 0, 'ranges' => 0];
        @chmod($t, 0600); @rename($t, SMPRO_TF_FILE);
        $GLOBALS['smpro_tf_memo'] = null;
        $n = 0; foreach ($doc['payload']['sources'] as $s) $n += count($s['ranges']);
        if (function_exists('smpro_audit')) @smpro_audit('trustfeed_fetch', ['from' => $base, 'generated' => (int)$doc['payload']['generated'], 'sources' => count($doc['payload']['sources']), 'ranges' => $n]);
        return ['ok' => true, 'msg' => 'verified list from ' . $base . ': ' . count($doc['payload']['sources']) . ' sources, ' . $n . ' ranges, built ' . date('Y-m-d H:i', (int)$doc['payload']['generated']), 'sources' => count($doc['payload']['sources']), 'ranges' => $n];
    }
    return ['ok' => false, 'msg' => 'the licence server did not give a usable list (' . $last . ') - the vendor feeds and the shipped seeds stay in use', 'sources' => 0, 'ranges' => 0];
}
/** The kept payload, or null when none / stale / no longer verifying. */
function smpro_tf_data(): ?array {
    if (array_key_exists('smpro_tf_memo', $GLOBALS) && $GLOBALS['smpro_tf_memo'] !== null) return $GLOBALS['smpro_tf_memo'] ?: null;
    $doc = @is_file(SMPRO_TF_FILE) ? json_decode((string)@file_get_contents(SMPRO_TF_FILE), true) : null;
    $ok = $doc !== null && smpro_tf_validate($doc)['ok'];
    $GLOBALS['smpro_tf_memo'] = $ok ? $doc['payload'] : false;
    return $ok ? $doc['payload'] : null;
}
/** Ranges of one provider from the verified list, or null when the list does not carry it. */
function smpro_tf_ranges(string $key): ?array {
    $p = smpro_tf_data(); if (!$p) return null;
    $s = $p['sources'][$key] ?? null;
    return is_array($s) && !empty($s['ranges']) ? array_values($s['ranges']) : null;
}
/** Crawler families the list adds (same shape as the built-in catalogue). */
function smpro_tf_families(): array {
    $p = smpro_tf_data(); if (!$p || !is_array($p['families'] ?? null)) return [];
    $out = [];
    foreach ($p['families'] as $k => $f) {
        if (!preg_match('/^[a-z0-9_]{1,32}$/', (string)$k) || !is_array($f) || ($f['name'] ?? '') === '' || ($f['ua'] ?? '') === '') continue;
        if (@preg_match((string)$f['ua'], '') === false) continue;   // a pattern that does not compile is not a family
        $out[$k] = ['name' => (string)$f['name'], 'kind' => preg_replace('/[^a-z]/', '', (string)($f['kind'] ?? 'unknown')) ?: 'unknown', 'ua' => (string)$f['ua'],
                    'rdns' => array_values(array_filter(array_map('strval', (array)($f['rdns'] ?? [])))), 'ranges' => preg_replace('/[^a-z0-9_]/', '', (string)($f['ranges'] ?? ''))];
    }
    return $out;
}
/** For the page: where the list stands. */
function smpro_tf_status(): array {
    $p = smpro_tf_data(); $mt = @is_file(SMPRO_TF_FILE) ? (int)@filemtime(SMPRO_TF_FILE) : 0;
    if (!$p) return ['have' => false, 'generated' => 0, 'fetched' => $mt, 'sources' => [], 'ranges' => 0, 'families' => 0, 'why' => $mt ? 'the kept list no longer verifies or is older than ' . intdiv(SMPRO_TF_MAXAGE, 86400) . ' days' : 'not fetched yet'];
    $n = 0; $src = [];
    foreach ($p['sources'] as $k => $s) { $c = count($s['ranges']); $n += $c; $src[$k] = ['name' => (string)($s['name'] ?? $k), 'kind' => (string)($s['kind'] ?? ''), 'count' => $c, 'fetched_at' => (int)($s['fetched_at'] ?? 0), 'stale' => (string)($s['stale_reason'] ?? ''), 'never_block' => !empty($s['never_block'])]; }
    return ['have' => true, 'generated' => (int)$p['generated'], 'fetched' => $mt, 'sources' => $src, 'ranges' => $n, 'families' => count(smpro_tf_families()), 'why' => ''];
}
/** Every six hours, at a minute of this server's own (so hundreds of servers do not call the same second). */
function smpro_tf_cron_sync(): bool {
    if (defined('SMPRO_TEST_SRC')) return true;
    $f = '/etc/cron.d/smpro-trustfeed';
    $bin = SMPRO_BASE . '/bin/trustfeed_tick.php'; if (!@is_file($bin)) { if (@is_file($f)) @unlink($f); return false; }
    $php = function_exists('smpro_php_cli_bin') ? smpro_php_cli_bin() : (is_executable('/usr/local/cpanel/3rdparty/bin/php') ? '/usr/local/cpanel/3rdparty/bin/php' : 'php');
    $min = abs(crc32((string)@gethostname())) % 60;
    $desired = "# Safety Monitor Pro - trusted-bots list from the licence server (verified official crawler / mail ranges), every 6 h\n$min */6 * * * root timeout 120 $php $bin >/dev/null 2>&1\n";
    return function_exists('smpro_cron_install') ? smpro_cron_install($f, $desired) : (@file_put_contents($f, $desired) !== false && @chmod($f, 0644));
}
