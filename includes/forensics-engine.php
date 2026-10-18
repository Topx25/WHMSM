<?php
/**
 * forensics-engine.php — SM Pro "Comprehensive Account Forensics Report" engine.
 *
 * READ-ONLY, per-account deep forensics. Prefixes:
 *   smpro_fx_*  — §3.0 normalized contract, scope, §3.1 flagged-file deep analysis,
 *                 §3.2 file-integrity sweep, per-file baselines.
 *   smpro_fe_*  — the UNIFIED whitelist store (shared with the Malicious-Upload detector),
 *                 §3.5 persistence hunt, §3.6 synthesis, §6 run governor.
 *
 * INVARIANTS (see the build spec):
 *  - Strictly read-only on ACCOUNT files: only lstat/stat/hash_file/bounded-read/find/grep/tail/
 *    lsattr -d/ssh-keygen -lf. The ONLY writes are to SM-owned state under SMPRO_VARLIB.
 *  - Every finding carries ≥1 concrete evidence ref (smpro_fx_finding drops evidence-less findings).
 *  - Bounded + streaming: fixed buffers, per-step timeouts, an overall wall-clock budget, load-gated.
 *  - English-only output.
 *  - State dir is SMPRO_VARLIB (/var/lib/smpro) — the plugin's real convention; the spec's
 *    /var/cpanel/sm_pro/ is aspirational and intentionally NOT used.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

define('SMPRO_FX_ROOT', SMPRO_VARLIB . '/forensics');          // reports + baselines + manifests, per user
define('SMPRO_FE_WL',   SMPRO_VARLIB . '/whitelist.json');     // THE single whitelist both detector + UI use

/* =========================================================================================
 *  §3.0 — normalized data contract (Finding + timeline event) + shared helpers
 * ======================================================================================= */

/** timeout+nice+ionice wrapper (mirrors smpro_fa_wrap; self-contained so the engine never needs a module). */
function smpro_fx_wrap($inner, $t = 30) { return 'timeout ' . (int)$t . ' nice -n ' . SMPRO_SCAN_NICE . ' ionice -c' . SMPRO_SCAN_IONICE_CLASS . ' ' . $inner; }

/** Mask long base64 / hex blobs in an excerpt so evidence never carries a runnable payload. */
function smpro_fx_redact($s, $keep = 120) {
    $s = (string)$s;
    $s = preg_replace_callback('#[A-Za-z0-9+/]{60,}={0,2}#', fn($m) => substr($m[0], 0, 16) . '…[' . strlen($m[0]) . 'B base64]…' . substr($m[0], -8), $s);
    $s = preg_replace_callback('#(?:\\\\x[0-9A-Fa-f]{2}){20,}#', fn($m) => '…[' . (int)(strlen($m[0]) / 4) . ' hex-escapes]…', $s);
    $s = preg_replace('/[^\x09\x20-\x7e]/', '.', $s);          // strip control/non-ascii for safe rendering
    if (strlen($s) > $keep + 40) $s = substr($s, 0, $keep) . '…(' . strlen($s) . 'B)';
    return $s;
}

/** Evidence row — {type,value,sha256?,mtime?,ctime?,source_file?,line_no?,excerpt}. */
function smpro_fx_ev($type, $value, array $extra = []) {
    $e = ['type' => $type, 'value' => (string)$value];
    foreach (['sha256', 'mtime', 'ctime', 'source_file', 'line_no', 'col'] as $k) if (isset($extra[$k])) $e[$k] = $extra[$k];
    if (isset($extra['excerpt'])) $e['excerpt'] = smpro_fx_redact($extra['excerpt']);
    return $e;
}

/** Normalized Finding factory. DROPS (returns null) a finding with no evidence — §2.6. */
function smpro_fx_finding(array $o) {
    $acct = (string)($o['account'] ?? '');
    $ev = $o['evidence'] ?? [];
    if (!is_array($ev) || !$ev) { if (function_exists('smpro_audit')) smpro_audit('forensics_finding_dropped', ['title' => $o['title'] ?? '', 'reason' => 'no evidence']); return null; }
    $wlk = (string)($o['whitelist_key'] ?? ($o['path'] ?? ''));
    return [
        'id'                  => substr(sha1(($o['category'] ?? '') . '|' . $wlk . '|' . $acct), 0, 16),
        'category'            => (string)($o['category'] ?? 'misc'),
        'title'               => (string)($o['title'] ?? ''),
        'severity'            => max(0, min(100, (int)($o['severity'] ?? 0))),
        'confidence'          => in_array($o['confidence'] ?? '', ['low', 'med', 'high'], true) ? $o['confidence'] : 'med',
        'evidence'            => array_values($ev),
        'account'             => $acct,
        'collected_at'        => time(),
        'whitelist_key'       => $wlk,
        'suggested_action'    => (string)($o['suggested_action'] ?? ''),
        'skipped'             => (bool)($o['skipped'] ?? false),
        'skip_reason'         => (string)($o['skip_reason'] ?? ''),
        'contributing_signals'=> array_values((array)($o['contributing_signals'] ?? [])),
        'band'                => (string)($o['band'] ?? ''),
        'why'                 => (string)($o['why'] ?? ''),
        'path'                => (string)($o['path'] ?? ''),
    ];
}

/** Normalized timeline event (consumed only by §3.6). */
function smpro_fx_event(array $o) {
    return [
        'ts_utc'      => (int)($o['ts_utc'] ?? 0),
        'source'      => (string)($o['source'] ?? ''),   // file_write|apache_access|modsec_audit|cpanel_login|ssh_auth|exim|cron|lastlog|ftp
        'actor_ip'    => (string)($o['actor_ip'] ?? ''),
        'actor_type'  => (string)($o['actor_type'] ?? ''),
        'path'        => (string)($o['path'] ?? ''),
        'sha256'      => (string)($o['sha256'] ?? ''),
        'bytes'       => (int)($o['bytes'] ?? 0),
        'http_status' => (string)($o['http_status'] ?? ''),
        'http_method' => (string)($o['http_method'] ?? ''),
        'url'         => (string)($o['url'] ?? ''),
        'ua'          => (string)($o['ua'] ?? ''),
        'log_line_ref'=> (string)($o['log_line_ref'] ?? ''),
        'raw_excerpt' => smpro_fx_redact($o['raw_excerpt'] ?? '', 200),
        'tags'        => array_values((array)($o['tags'] ?? [])),
    ];
}

/** band → 0-100 severity midpoint. */
function smpro_fx_band_to_sev($band) {
    return ['clean' => 0, 'info' => 15, 'low' => 15, 'medium' => 45, 'high' => 75, 'critical' => 92][strtolower((string)$band)] ?? 0;
}
/** 0-100 severity → the existing forensics-audit fa[] severity word. */
function smpro_fx_sev_word($sev) { $sev = (int)$sev; return $sev >= 85 ? 'critical' : ($sev >= 60 ? 'high' : ($sev >= 30 ? 'medium' : 'info')); }

/** ADAPTER: normalized §3.0 Finding → the existing modules/forensics-audit.php fa[] shape so
 *  smpro_fa_render_report / summary / iocs render it unchanged. LOAD-BEARING (unit-tested). */
function smpro_fx_to_fa(array $f) {
    $ev = '';
    foreach (($f['evidence'] ?? []) as $e) {
        $ev .= ($ev === '' ? '' : "\n") . strtoupper((string)($e['type'] ?? '')) . ': ' . (string)($e['value'] ?? '');
        if (!empty($e['sha256'])) $ev .= '  · SHA-256 ' . substr($e['sha256'], 0, 16) . '…';
        if (!empty($e['excerpt'])) $ev .= '  · ' . $e['excerpt'];
        if (!empty($e['source_file'])) $ev .= '  · ' . $e['source_file'] . (!empty($e['line_no']) ? ':' . $e['line_no'] : '');
    }
    $ref = '';
    foreach (($f['evidence'] ?? []) as $e) if (in_array($e['type'] ?? '', ['path', 'hash'], true)) { $ref = (string)$e['value']; break; }
    return [
        'sev'     => smpro_fx_sev_word($f['severity'] ?? 0),
        'conf'    => (string)($f['confidence'] ?? 'med'),
        'cat'     => (string)($f['category'] ?? 'misc'),
        'account' => (string)($f['account'] ?? ''),
        'title'   => (string)($f['title'] ?? ''),
        'evidence'=> $ev,
        'ref'     => $ref !== '' ? $ref : (string)($f['path'] ?? ''),
        'means'   => (string)($f['why'] ?? ''),
        'action'  => (string)($f['suggested_action'] ?? ''),
        'ts'      => (int)($f['collected_at'] ?? 0),
        'fx'      => true,                                        // marks a next-gen finding for the enhanced renderer
        'band'    => (string)($f['band'] ?? ''),
        'signals' => $f['contributing_signals'] ?? [],
        'wl_key'  => (string)($f['whitelist_key'] ?? ''),
        'skipped' => (bool)($f['skipped'] ?? false),
        'skip_reason' => (string)($f['skip_reason'] ?? ''),
    ];
}

/* =========================================================================================
 *  Scope resolution (§3.0) — cheap, shared by all collectors, static-cached per user
 * ======================================================================================= */
function smpro_fx_scope($user) {
    static $cache = [];
    $user = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)$user);
    if ($user === '' || !is_dir(smpro_user_home($user))) return null;
    if (isset($cache[$user])) return $cache[$user];
    $home = smpro_user_home($user);
    // owner uid/gid — NEVER assume; posix guarded, stat fallback, 'unknown' if unresolved
    $uid = null; $gid = null; $owner_verified = false;
    if (function_exists('posix_getpwnam')) { $pw = @posix_getpwnam($user); if (is_array($pw)) { $uid = (int)$pw['uid']; $gid = (int)$pw['gid']; $owner_verified = true; } }
    if ($uid === null) { $st = @stat($home); if ($st) { $uid = (int)$st['uid']; $gid = (int)$st['gid']; $owner_verified = true; } }
    // domains + docroots (reuse the proven intrusion helpers)
    $docroots = function_exists('smpro_im_docroots') ? smpro_im_docroots($user) : [];
    if (!$docroots && is_dir($home . '/public_html')) $docroots = [$home . '/public_html'];
    $domains = [];
    if (function_exists('smpro_im_userdomains')) { foreach (smpro_im_userdomains() as $dom => $acct) if ($acct === $user) $domains[] = $dom; }
    $primary = '';
    if (is_readable('/var/cpanel/users/' . $user)) { $raw = (string)@shell_exec('grep -E ' . escapeshellarg('^DNS=') . ' /var/cpanel/users/' . escapeshellarg($user) . ' 2>/dev/null | head -1'); if (preg_match('/^DNS=(\S+)/', trim($raw), $m)) $primary = strtolower($m[1]); }
    if ($primary === '' && $domains) $primary = $domains[0];
    $email = '';
    if (is_readable('/var/cpanel/users/' . $user)) { $raw = (string)@shell_exec('grep -E ' . escapeshellarg('^CONTACTEMAIL=') . ' /var/cpanel/users/' . escapeshellarg($user) . ' 2>/dev/null | head -1'); if (preg_match('/=(\S+)/', trim($raw), $m)) $email = $m[1]; }
    return $cache[$user] = [
        'user' => $user, 'uid' => $uid, 'gid' => $gid, 'owner_verified' => $owner_verified,
        'home' => $home, 'primary_domain' => $primary, 'domains' => array_values(array_unique($domains)),
        'docroots' => array_values(array_unique($docroots)), 'contact_email' => $email,
        'cagefs' => is_dir('/usr/share/cagefs'),
    ];
}

/** Is $path inside any of the account's docroots (webroot)? */
function smpro_fx_in_webroot($path, array $scope) {
    $rp = str_replace('\\', '/', (string)$path);
    foreach (($scope['docroots'] ?? []) as $d) { $d = rtrim($d, '/'); if ($rp === $d || strpos($rp, $d . '/') === 0) return true; }
    return false;
}

/* =========================================================================================
 *  §3.1 — flagged-file deep analysis: entropy, weighted token scan, verdict, flag-explain
 * ======================================================================================= */

/** Shannon entropy over sampled windows (first 256KB + N seeded blocks). O(1) memory. */
function smpro_fx_entropy($path, $head = 262144, $blocks = 4, $blockLen = 65536) {
    $sz = @filesize($path); if ($sz === false || $sz === 0) return 0.0;
    $fh = @fopen($path, 'rb'); if (!$fh) return 0.0;
    $hist = array_fill(0, 256, 0); $total = 0;
    $chunk = @fread($fh, min($head, $sz)); if ($chunk !== false) { $len = strlen($chunk); for ($i = 0; $i < $len; $i++) { $hist[ord($chunk[$i])]++; } $total += $len; }
    if ($sz > $head + $blockLen) {
        mt_srand(crc32($path));
        for ($b = 0; $b < $blocks; $b++) {
            $off = $head + (int)(mt_rand() / mt_getrandmax() * max(1, $sz - $head - $blockLen));
            if (@fseek($fh, $off) !== 0) break;
            $chunk = @fread($fh, $blockLen); if ($chunk === false || $chunk === '') break;
            $len = strlen($chunk); for ($i = 0; $i < $len; $i++) { $hist[ord($chunk[$i])]++; } $total += $len;
        }
    }
    @fclose($fh);
    if ($total === 0) return 0.0;
    $H = 0.0; foreach ($hist as $c) { if ($c > 0) { $p = $c / $total; $H -= $p * log($p, 2); } }
    return round($H, 2);
}

/** Weighted token table for the deep scan. Each: [regex, weight, family]. families are a SUPERSET
 *  of smpro_im_looks_malicious families so smpro_fx_flag_explain can intersect them. Anchored/
 *  possessive to avoid catastrophic backtracking on a packed single line. */
function smpro_fx_token_table() {
    return [
        ['/\bpreg_replace\s*+\([^)]*+[\'"][^\'"]*+e[\'"]/i', 10, 'exec'],
        ['/\beval\s*+\(/i',                                  9,  'exec'],
        ['/\bassert\s*+\(/i',                                8,  'exec'],
        ['/\bcreate_function\s*+\(/i',                       7,  'exec'],
        ['/\b(?:shell_exec|system|passthru|exec|proc_open|popen)\s*+\(/i', 6, 'exec'],
        ['/\$(?:_(?:GET|POST|REQUEST|COOKIE|SERVER))\b[^;\n]{0,40}?[\)\(]/i', 6, 'input'],
        ['/\$\{\s*+[\'"][A-Za-z0-9_]++[\'"]\s*+\}|\$[A-Za-z0-9_]++\s*+\(\s*+\$[A-Za-z0-9_]/', 5, 'dynamic'],
        ['/\b(?:gzinflate|gzuncompress|str_rot13)\s*+\(/i',  5,  'obfusc'],
        ['/\bbase64_decode\s*+\(/i',                         5,  'obfusc'],
        ['/[A-Za-z0-9+\/]{200,}={0,2}/',                     4,  'obfusc'],
        ['/(?:\\\\x[0-9A-Fa-f]{2}){40,}/',                   4,  'obfusc'],
        ['/\bmove_uploaded_file\s*+\(/i',                    3,  'upload'],
    ];
}

/** Streaming weighted token scan — bounded 64KB fread windows (packed single-line defense),
 *  small overlap for boundary tokens, hard 8MB/60s caps. Returns tokens[], score, nested_chain,
 *  families_seen[], truncated. */
function smpro_fx_tokenscan($path, $capBytes = 8388608, $capSec = 60) {
    $out = ['tokens' => [], 'token_score' => 0, 'nested_chain' => false, 'families_seen' => [], 'truncated' => false];
    @ini_set('pcre.backtrack_limit', '200000'); @ini_set('pcre.jit', '1');
    $fh = @fopen($path, 'rb'); if (!$fh) return $out;
    $table = smpro_fx_token_table();
    $win = 65536; $overlap = 512; $carry = ''; $consumed = 0; $lineBase = 1; $t0 = microtime(true);
    $fams = []; $score = 0; $seen = [];
    while (!feof($fh)) {
        if ($consumed >= $capBytes || (microtime(true) - $t0) > $capSec) { $out['truncated'] = true; break; }
        $data = @fread($fh, $win); if ($data === false || $data === '') break;
        $buf = $carry . $data; $carryLines = substr_count($carry, "\n");
        foreach ($table as [$re, $w, $fam]) {
            if (preg_match_all($re, $buf, $mm, PREG_OFFSET_CAPTURE) && !empty($mm[0])) {
                foreach ($mm[0] as $hit) {
                    [$tok, $off] = $hit;
                    // skip matches wholly inside the carry region (already counted from the previous window)
                    if ($off < strlen($carry) - $overlap && $consumed > 0) continue;
                    $prefixLines = substr_count(substr($buf, 0, $off), "\n");
                    $line = $lineBase - $carryLines + $prefixLines;
                    $lastNl = strrpos(substr($buf, 0, $off), "\n"); $col = $lastNl === false ? $off + 1 : $off - $lastNl;
                    $k = $fam . ':' . $line . ':' . $off;
                    if (isset($seen[$k])) continue; $seen[$k] = 1;
                    $fams[$fam] = ($fams[$fam] ?? 0) + 1; $score += $w;
                    if (count($out['tokens']) < 60) $out['tokens'][] = ['token' => substr($tok, 0, 24), 'weight' => $w, 'family' => $fam, 'line' => max(1, $line), 'col' => $col, 'snippet' => smpro_fx_redact(substr($buf, max(0, $off - 12), 120))];
                }
            }
        }
        // nested decode→eval chain (obfusc inside an exec call) — the strong web-shell signal
        if (!$out['nested_chain'] && preg_match('/\b(?:eval|assert|preg_replace|create_function|system|exec|shell_exec|passthru)\s*+\([^;]{0,80}?\b(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*+\(/i', $buf)) $out['nested_chain'] = true;
        $consumed += strlen($data);
        $lineBase += substr_count($data, "\n") + ($consumed === strlen($data) ? $carryLines : 0);
        $carry = substr($buf, -$overlap);
    }
    @fclose($fh);
    if ($out['nested_chain']) $score += 10;   // ×2-equivalent boost for the chain
    $out['token_score'] = $score;
    $out['families_seen'] = array_keys($fams);
    return $out;
}

/** Full read-only per-file deep analysis. mtime/ctime come from lstat here and are passed onward
 *  (§3.3/§3.4 never re-stat). Symlinks are recorded and NOT dereferenced. */
function smpro_fx_deepfile($path, array $scope, $baseline = null) {
    $r = ['path' => $path, 'exists' => false, 'is_link' => false, 'link_target' => '', 'size' => 0,
          'uid' => null, 'gid' => null, 'owner_ok' => 'unknown', 'mode' => '', 'world_writable' => false,
          'suid_sgid' => false, 'mtime' => 0, 'ctime' => 0, 'atime' => 0, 'timestomp' => 'none',
          'sha256' => '', 'entropy' => 0.0, 'tokens' => [], 'token_score' => 0, 'nested_chain' => false,
          'families_seen' => [], 'in_webroot' => false, 'wp_guard_trusted' => false,
          'baseline_delta' => null, 'band' => 'clean', 'score' => 0, 'contributing_signals' => [], 'truncated' => false];
    $ls = @lstat($path); if (!$ls) return $r;
    $r['exists'] = true;
    $r['in_webroot'] = smpro_fx_in_webroot($path, $scope);
    if (is_link($path)) { $r['is_link'] = true; $r['link_target'] = (string)@readlink($path); $r['contributing_signals'][] = 'symlink_not_followed'; $r['band'] = 'medium'; $r['score'] = 45; return $r; }
    $r['size'] = (int)$ls['size']; $r['mtime'] = (int)$ls['mtime']; $r['ctime'] = (int)$ls['ctime']; $r['atime'] = (int)$ls['atime'];
    $r['uid'] = (int)$ls['uid']; $r['gid'] = (int)$ls['gid']; $r['mode'] = substr(sprintf('%o', $ls['mode']), -4);
    $r['world_writable'] = (bool)($ls['mode'] & 0002); $r['suid_sgid'] = (bool)($ls['mode'] & 06000);
    if (($scope['uid'] ?? null) !== null) $r['owner_ok'] = ((int)$ls['uid'] === (int)$scope['uid']) ? 'yes' : 'no';
    if ($r['ctime'] > 0 && $r['mtime'] > 0 && $r['ctime'] < $r['mtime']) { $r['timestomp'] = 'high'; $r['contributing_signals'][] = 'timestomp_ctime_lt_mtime'; }
    // WP Guard trust short-circuit — never re-flag our own security plugin's files (caps at INFO)
    if (function_exists('smpro_wpguard_trusted') && smpro_wpguard_trusted($path)) { $r['wp_guard_trusted'] = true; $r['contributing_signals'][] = 'wp_guard_trusted'; }
    if ($r['size'] <= 5 * 1024 * 1024) $r['sha256'] = (string)@hash_file('sha256', $path);
    else { $r['sha256'] = 'SKIPPED_LARGE'; $r['contributing_signals'][] = 'hash_skipped_large'; }
    $r['entropy'] = smpro_fx_entropy($path);
    $ts = smpro_fx_tokenscan($path);
    $r['tokens'] = $ts['tokens']; $r['token_score'] = $ts['token_score']; $r['nested_chain'] = $ts['nested_chain'];
    $r['families_seen'] = $ts['families_seen']; $r['truncated'] = $ts['truncated'];
    // baseline diff — "content changed but token fingerprint identical" is the strong FP signal
    if (is_array($baseline)) {
        $prevFams = (array)($baseline['families'] ?? []); sort($prevFams);
        $nowFams = $r['families_seen']; sort($nowFams);
        $added = array_values(array_diff($nowFams, $prevFams));
        $r['baseline_delta'] = ['sha_changed' => ($baseline['sha256'] ?? '') !== $r['sha256'], 'size_delta' => $r['size'] - (int)($baseline['size'] ?? 0), 'added_families' => $added, 'fingerprint_identical' => ($added === [] && array_values($nowFams) === array_values($prevFams))];
        if ($r['baseline_delta']['fingerprint_identical'] && $r['baseline_delta']['sha_changed']) $r['contributing_signals'][] = 'content_only_edit';
    }
    $v = smpro_fx_verdict($r);
    $r['band'] = $v['band']; $r['score'] = $v['score'];
    $r['contributing_signals'] = array_values(array_unique(array_merge($r['contributing_signals'], $v['contributing_signals'])));
    return $r;
}

/** Verdict band from the deep-file signals (§3.1). */
function smpro_fx_verdict(array $d) {
    $sig = []; $band = 'clean';
    $exec = in_array('exec', $d['families_seen'] ?? [], true);
    $obf  = in_array('obfusc', $d['families_seen'] ?? [], true);
    $inp  = in_array('input', $d['families_seen'] ?? [], true);
    $ent  = (float)($d['entropy'] ?? 0);
    $high = false; $crit = false; $med = false; $low = false;
    if (!empty($d['nested_chain'])) { $high = true; $sig[] = 'nested_decode_eval_chain'; }
    if (($d['owner_ok'] ?? '') === 'no' && !empty($d['in_webroot'])) { $high = true; $sig[] = 'owner_mismatch_in_webroot'; }
    if (!empty($d['world_writable']) && $exec && $ent >= 7.2) { $high = true; $sig[] = 'world_writable_exec_entropy'; }
    if ($ent >= 7.2) { $med = true; $sig[] = 'high_entropy_' . $ent; }
    if ($obf) { $med = true; $sig[] = 'obfuscation_token'; }
    if (($d['timestomp'] ?? 'none') === 'high') { $med = true; }
    if ($exec && !$obf && !$inp) { $low = true; $sig[] = 'exec_tokens_framework_like'; }
    // baseline overrides toward FALSE POSITIVE
    $bd = $d['baseline_delta'] ?? null;
    if (is_array($bd) && !empty($bd['fingerprint_identical']) && !empty($bd['sha_changed'])) { $sig[] = 'content_only_edit_fingerprint_identical'; $band = 'low'; }
    elseif ($crit) $band = 'critical';
    elseif ($high) $band = 'high';
    elseif ($med) $band = 'medium';
    elseif ($low) $band = 'low';
    // CRITICAL only when HIGH + baseline shows ADDED obfuscation
    if (($high) && is_array($bd) && !empty($bd['added_families']) && in_array('obfusc', $bd['added_families'], true)) { $band = 'critical'; $sig[] = 'new_obfuscation_vs_baseline'; }
    // WP Guard trust caps at INFO
    if (!empty($d['wp_guard_trusted'])) { $band = smpro_fx_band_to_sev($band) > 15 ? 'info' : $band; }
    return ['band' => $band, 'score' => smpro_fx_band_to_sev($band), 'contributing_signals' => $sig];
}

/** §3.1 Flag Explanation — reproduce the REAL heuristic that fired (NOT the spec's phantom 256KB).
 *  The alert is smpro_im_breaches: an exploit-class ModSec 2xx/3xx AND a webroot .php changed within
 *  ~60 min that trips smpro_im_looks_malicious. We name exactly which token families fired. */
function smpro_fx_flag_explain($path, array $scope, array $deep) {
    // the family set the real detector greps for (mirror of smpro_im_looks_malicious / malice_count)
    $detFams = ['exec', 'obfusc', 'input', 'upload'];
    $matched = array_values(array_intersect($deep['families_seen'] ?? [], $detFams));
    $snips = [];
    foreach (($deep['tokens'] ?? []) as $t) { if (in_array($t['family'], $matched, true) && count($snips) < 6) $snips[] = ['line' => $t['line'], 'token' => $t['token'], 'snippet' => $t['snippet']]; }
    $inWr = !empty($deep['in_webroot']);
    $mins = $deep['mtime'] ? max(0, (int)round((time() - $deep['mtime']) / 60)) : null;
    $contrast = 'The [Malicious Upload] flag fired because this webroot PHP file was recently modified AND its content contains dangerous-function names (' . (implode(', ', $matched) ?: 'exec/obfuscation') . ') that SM Pro\'s breach heuristic greps for. That heuristic does NOT read intent — a legitimate large single-file application legitimately contains these same function names. Deep scan below decides real-vs-false-positive from entropy, obfuscation chains, ownership and the baseline diff.';
    return [
        'matched_families' => $matched,
        'matched_snippets' => $snips,
        'changed_within_min' => $mins,
        'in_webroot' => $inWr,
        'entropy' => $deep['entropy'] ?? 0,
        'nested_chain' => !empty($deep['nested_chain']),
        'verdict_contrast_text' => $contrast,
    ];
}

/* =========================================================================================
 *  §3.1 — per-file baseline (token-fingerprint) store. NEVER writes an account file.
 * ======================================================================================= */
function smpro_fx_baseline_path($user, $path) {
    $user = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)$user);
    return SMPRO_FX_ROOT . '/' . $user . '/baselines/' . substr(sha1((string)$path), 0, 32) . '.json';
}
/** Return the most-recent baseline entry for a path, or null. */
function smpro_fx_baseline_load($user, $path) {
    $bp = smpro_fx_baseline_path($user, $path);
    $all = is_file($bp) ? (json_decode((string)@file_get_contents($bp), true) ?: []) : [];
    return $all ? end($all) : null;
}
/** Append the current deep-scan result as a new baseline entry (ONLY on explicit admin action). Keeps last 5. */
function smpro_fx_baseline_accept($user, array $deep) {
    $bp = smpro_fx_baseline_path($user, $deep['path']);
    @is_dir(dirname($bp)) || @mkdir(dirname($bp), 0700, true);
    $all = is_file($bp) ? (json_decode((string)@file_get_contents($bp), true) ?: []) : [];
    $all[] = ['path' => $deep['path'], 'sha256' => $deep['sha256'], 'size' => $deep['size'], 'mtime' => $deep['mtime'],
              'entropy' => $deep['entropy'], 'families' => $deep['families_seen'], 'accepted_at' => date('c'), 'accepted_ts' => time()];
    $all = array_slice($all, -5);
    $tmp = $bp . '.tmp'; @file_put_contents($tmp, json_encode($all, JSON_UNESCAPED_SLASHES), LOCK_EX); @rename($tmp, $bp); @chmod($bp, 0600);
    if (function_exists('smpro_audit')) smpro_audit('forensics_baseline_accept', ['user' => $user, 'file' => basename($deep['path'])]);
    return true;
}

/* =========================================================================================
 *  §5 — UNIFIED WHITELIST STORE (the single file the Malicious-Upload detector AND the
 *  forensics UI share). Precedence: file_hash(silent) > path_size > path > glob(downgrade).
 *  Only file_hash SILENCES; everything else DOWNGRADES (finding still rendered, greyed).
 * ======================================================================================= */
function smpro_fe_wl_load() {
    static $loaded = false;
    $wl = is_file(SMPRO_FE_WL) ? (json_decode((string)@file_get_contents(SMPRO_FE_WL), true) ?: []) : [];
    if (!$loaded) { $loaded = true; $wl = smpro_fe_wl_migrate($wl); }
    // prune expired (in-memory; persisted lazily on next write)
    $now = time();
    foreach ($wl as $id => $e) if (!empty($e['expires']) && (int)$e['expires'] < $now) unset($wl[$id]);
    return $wl;
}
function smpro_fe_wl_save($wl) {
    @is_dir(dirname(SMPRO_FE_WL)) || @mkdir(dirname(SMPRO_FE_WL), 0700, true);
    $tmp = SMPRO_FE_WL . '.tmp'; @file_put_contents($tmp, json_encode($wl, JSON_UNESCAPED_SLASHES), LOCK_EX); @rename($tmp, SMPRO_FE_WL); @chmod(SMPRO_FE_WL, 0600);
}
/** One-time idempotent seed from the legacy breach_exclude substrings → glob entries (detector-suppression only). */
function smpro_fe_wl_migrate($wl) {
    $changed = false;
    if (function_exists('smpro_in_cfg')) {
        foreach ((array)(smpro_in_cfg()['breach_exclude'] ?? []) as $sub) {
            $sub = trim((string)$sub); if ($sub === '') continue;
            $val = (strpos($sub, '/') !== false || strpos($sub, '*') !== false) ? ('*' . trim($sub, '*') . '*') : ('*' . $sub . '*');
            $id = substr(hash('sha256', '|glob|' . $val), 0, 20);
            if (!isset($wl[$id])) { $wl[$id] = ['id' => $id, 'account' => '', 'scope' => 'glob', 'value' => $val, 'reason' => 'migrated from breach_exclude', 'created_by' => 'system', 'created_at' => date('c'), 'created_ts' => time(), 'expires' => 0, 'migrated' => true]; $changed = true; }
        }
    }
    if ($changed) smpro_fe_wl_save($wl);
    return $wl;
}

/** Add a whitelist entry. scope ∈ file_hash|path_size|path|glob. reason REQUIRED. Returns id. */
function smpro_fe_wl_add($account, $scope, $value, array $opts = []) {
    $account = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)$account);
    $scope = in_array($scope, ['file_hash', 'path_size', 'path', 'glob'], true) ? $scope : 'path';
    $value = (string)$value;
    $reason = trim((string)($opts['reason'] ?? '')); if ($reason === '') $reason = 'no reason given';
    $wl = smpro_fe_wl_load();
    $id = substr(hash('sha256', $account . '|' . $scope . '|' . $value), 0, 20);
    $entry = ['id' => $id, 'account' => $account, 'scope' => $scope, 'value' => $value, 'reason' => $reason,
              'created_by' => function_exists('smpro_current_actor') ? smpro_current_actor() : 'root', 'created_at' => date('c'), 'created_ts' => time(),
              'expires' => (int)($opts['expires'] ?? 0), 'source_run_id' => (string)($opts['source_run_id'] ?? '')];
    if ($scope === 'file_hash') $entry['sha256'] = (string)($opts['sha256'] ?? (is_file($value) ? @hash_file('sha256', $value) : ''));
    if ($scope === 'path_size') { $cur = is_file($value) ? (int)@filesize($value) : 0; $entry['size_ceiling'] = (int)($opts['size_ceiling'] ?? max(65536, $cur * 10)); }
    // Rich fingerprint so tamper is caught even when NO new family name appears (a nested decode→eval
    // chain injected into a file that already has exec+obfusc families = same families, but new chain).
    if (in_array($scope, ['path', 'path_size'], true) && is_file($value)) { $d = smpro_fx_tokenscan($value); $entry['token_fingerprint'] = ['families' => $d['families_seen'], 'nested' => $d['nested_chain'], 'score' => $d['token_score']]; }
    $wl[$id] = $entry; smpro_fe_wl_save($wl);
    if (function_exists('smpro_audit')) smpro_audit('forensics_whitelist_add', ['account' => $account, 'scope' => $scope, 'value' => $value]);
    return $id;
}
function smpro_fe_wl_remove($id) {
    $id = preg_replace('/[^a-f0-9]/', '', (string)$id); if ($id === '') return false;
    $wl = smpro_fe_wl_load(); if (!isset($wl[$id])) return false;
    unset($wl[$id]); smpro_fe_wl_save($wl);
    if (function_exists('smpro_audit')) smpro_audit('forensics_whitelist_remove', ['id' => $id]);
    return true;
}
/** Match a path against the whitelist. Returns null or {mode:silent|downgrade|rearm, note, entry}. */
function smpro_fe_wl_match($account, $path, $sha256 = null, $size = null) {
    $path = (string)$path; if ($path === '') return null;
    $wl = smpro_fe_wl_load();
    $cands = [];
    foreach ($wl as $e) {
        if (($e['account'] ?? '') !== '' && ($e['account'] ?? '') !== $account) continue;
        if (!empty($e['expires']) && (int)$e['expires'] < time()) continue;
        $cands[] = $e;
    }
    // precedence order
    $order = ['file_hash' => 0, 'path_size' => 1, 'path' => 2, 'glob' => 3];
    usort($cands, fn($a, $b) => ($order[$a['scope']] ?? 9) <=> ($order[$b['scope']] ?? 9));
    foreach ($cands as $e) {
        $sc = $e['scope'];
        if ($sc === 'file_hash') { if ($e['value'] === $path && $sha256 !== null && ($e['sha256'] ?? '') === $sha256) return ['mode' => 'silent', 'note' => 'exact hash match', 'entry' => $e]; continue; }
        if ($sc === 'path_size') {
            if ($e['value'] !== $path) continue;
            if ($size !== null && (int)$size > (int)($e['size_ceiling'] ?? PHP_INT_MAX) * 10) return ['mode' => 'rearm', 'note' => 'size jumped >10× the whitelisted ceiling', 'entry' => $e];
            return ['mode' => 'downgrade', 'note' => 'path+size-ceiling whitelist', 'entry' => $e];
        }
        if ($sc === 'path') { if ($e['value'] === $path) return ['mode' => 'downgrade', 'note' => 'path whitelist (any content)', 'entry' => $e]; continue; }
        if ($sc === 'glob') { if (fnmatch($e['value'], $path)) return ['mode' => 'downgrade', 'note' => 'glob whitelist' . (!empty($e['migrated']) ? ' (migrated)' : ''), 'entry' => $e]; continue; }
    }
    return null;
}
/* =========================================================================================
 *  §3.6 (subset) — verdict for the FLAGGED-FILE report + the run orchestrator.
 *  (Account-wide sweep §3.2, persistence §3.5, and the full merged timeline/IOC synthesis are
 *   layered in later stages; the flagged-file verdict below already triages the incident.)
 * ======================================================================================= */

/** Risk verdict for a flagged-file report. Implements the §3.6 weighted model + the explicit
 *  Likely-False-Positive OVERRIDE. $ctx carries deep, flag_explain, web (§3.3) + auth (§3.4) hints
 *  when available (null until those stages run). Returns {verdict,score,reasoning[]}. */
function smpro_fe_verdict_flagged(array $ctx) {
    $deep = $ctx['deep'] ?? [];
    $web  = $ctx['web'] ?? null;      // {verdict_hint, possible_drop(bool), attack_hit(bool)} or null (not collected)
    $auth = $ctx['auth'] ?? null;     // {verdict_hint, admin_session_write(bool), known_admin(bool), new_key_or_cron(bool)} or null
    $score = 0; $why = [];
    // positive (toward compromise)
    if (!empty($deep['nested_chain'])) { $score += 40; $why[] = 'positive: nested decode→eval chain in the file (+40)'; }
    if ($web && !empty($web['possible_drop'])) { $score += 25; $why[] = 'positive: a write landed right after a web request to that path (possible_drop, +25)'; }
    if ($web && !empty($web['attack_hit'])) { $score += 15; $why[] = 'positive: a ModSec/web-attack hit correlates to the path (+15)'; }
    if ($auth && !empty($auth['new_key_or_cron'])) { $score += 30; $why[] = 'positive: a new authorized_key or cron entry appeared in the window (+30)'; }
    if (($deep['owner_ok'] ?? '') === 'no') { $score += 20; $why[] = 'positive: file owner does not match the account (+20)'; }
    if ((float)($deep['entropy'] ?? 0) >= 7.2) { $score += 15; $why[] = 'positive: high entropy suggests packed/encoded payload (+15)'; }
    // mitigating (toward false positive)
    $bd = $deep['baseline_delta'] ?? null;
    if (is_array($bd) && !empty($bd['fingerprint_identical']) && !empty($bd['sha_changed'])) { $score -= 10; $why[] = 'mitigating: content changed but the token fingerprint is identical to the accepted baseline — a content-only edit (−10)'; }
    if ($auth && ($auth['verdict_hint'] ?? '') === 'admin_session_write' && !empty($auth['known_admin'])) { $score -= 30; $why[] = 'mitigating: the write correlates to an admin login from a known-admin IP (−30)'; }
    if ($web && ($web['verdict_hint'] ?? '') === 'no_correlation') { $score -= 15; $why[] = 'mitigating: no web-attack request correlates to the write window (−15)'; }
    if ($auth && ($auth['verdict_hint'] ?? '') === 'app_self_write') { $score -= 15; $why[] = 'mitigating: no interactive login explains the write — consistent with a legitimate app self-write / local edit (−15)'; }
    // active whitelist entry for this exact path
    $wlHit = smpro_fe_wl_match($ctx['account'] ?? '', $deep['path'] ?? '', $deep['sha256'] ?? null, $deep['size'] ?? null);
    if ($wlHit) { $score -= 100; $why[] = 'mitigating: an active whitelist entry covers this file (' . $wlHit['note'] . ', −100)'; }
    $score = max(0, min(100, $score));

    // §3.6 Likely-False-Positive OVERRIDE (MUST fire for the incident)
    $existing = !empty($deep['mtime']);                                            // an existing path (we scanned it; not a fresh drop we detected)
    $onlyLargePhp = empty($deep['nested_chain']) && (float)($deep['entropy'] ?? 0) < 7.2 && ($deep['owner_ok'] ?? '') !== 'no';
    $noAttack = !$web || (($web['verdict_hint'] ?? '') === 'no_correlation' && empty($web['possible_drop']) && empty($web['attack_hit']));
    $adminOrSelf = (!$auth) || ($auth && (($auth['verdict_hint'] ?? '') === 'admin_session_write' && !empty($auth['known_admin'])) || ($auth && ($auth['verdict_hint'] ?? '') === 'app_self_write'));
    $noNewCreds = !$auth || empty($auth['new_key_or_cron']);
    $fpFire = $existing && $onlyLargePhp && $noAttack && $adminOrSelf && $noNewCreds;
    if ($fpFire) {
        $score = min($score, 15);
        $why[] = 'OVERRIDE: Likely-False-Positive rule fired — an existing large webroot PHP flagged only by the large-PHP heuristic, with no attack correlation, no new credentials, and the write consistent with a legitimate admin edit / app self-write.';
        return ['verdict' => 'false_positive_likely', 'score' => $score, 'reasoning' => $why];
    }
    $verdict = $score >= 70 ? 'likely_compromised' : ($score >= 35 ? 'suspicious' : ($score <= 15 ? 'false_positive_likely' : 'suspicious'));
    return ['verdict' => $verdict, 'score' => $score, 'reasoning' => $why];
}

/** Orchestrate a FLAGGED-FILE forensics report (the "Open Forensics" path). READ-ONLY.
 *  Runs scope + deep analysis + flag-explain + baseline; folds in §3.3 web + §3.4 auth correlation
 *  when those collectors are present (function_exists), else marks them partial. Returns the report. */
function smpro_fx_run_flagged($user, $flaggedFiles, array $opts = []) {
    $scope = smpro_fx_scope($user);
    if (!$scope) return ['ok' => false, 'msg' => 'Could not resolve that cPanel account.'];
    $alertTs = (int)($opts['alert_ts'] ?? time());
    $files = array_values(array_filter((array)$flaggedFiles, fn($p) => $p !== '' && strpos($p, smpro_user_home($user) . '/') === 0));
    $partial = []; $findings = []; $sections = [];
    foreach (array_slice($files, 0, 8) as $fp) {
        if (!is_file($fp) && !is_link($fp)) { $partial[] = 'flagged file not found on disk: ' . basename($fp); continue; }
        $base = smpro_fx_baseline_load($user, $fp);
        $deep = smpro_fx_deepfile($fp, $scope, $base);
        $fe = smpro_fx_flag_explain($fp, $scope, $deep);
        // §3.3 web-attack correlation (Stage 3) — optional until built
        $web = null;
        if (function_exists('smpro_fw_correlate')) { $wc = smpro_fw_correlate($user, $fp, $deep['mtime'], $deep['ctime'], $alertTs, (int)($opts['win'] ?? 1800)); $web = ['verdict_hint' => $wc['verdict_hint'] ?? '', 'possible_drop' => !empty($wc['possible_drop']), 'attack_hit' => !empty($wc['attack_hit']), 'result' => $wc]; }
        else $partial[] = 'web-attack correlation not yet available';
        // §3.4 auth correlation (Stage 3) — optional until built
        $auth = null;
        if (function_exists('smpro_fw_auth_for_write')) { $auth = smpro_fw_auth_for_write($user, $fp, $deep['mtime']); }
        else $partial[] = 'auth correlation not yet available';
        $v = smpro_fe_verdict_flagged(['account' => $user, 'deep' => $deep, 'web' => $web, 'auth' => $auth]);
        // build a Finding
        $ev = [smpro_fx_ev('path', $fp, ['sha256' => $deep['sha256'], 'mtime' => $deep['mtime'], 'ctime' => $deep['ctime']])];
        foreach (array_slice($deep['tokens'], 0, 4) as $tk) $ev[] = smpro_fx_ev('log', $tk['token'] . ' (family ' . $tk['family'] . ')', ['source_file' => $fp, 'line_no' => $tk['line'], 'excerpt' => $tk['snippet']]);
        $f = smpro_fx_finding(['category' => 'Flagged file', 'title' => 'Deep analysis of ' . basename($fp) . ' — ' . strtoupper(str_replace('_', ' ', $v['verdict'])), 'severity' => $v['score'], 'confidence' => 'high', 'evidence' => $ev, 'account' => $user, 'path' => $fp, 'whitelist_key' => $fp, 'band' => $deep['band'], 'contributing_signals' => $deep['contributing_signals'], 'why' => $fe['verdict_contrast_text'], 'suggested_action' => $v['verdict'] === 'false_positive_likely' ? 'No action needed. Whitelist this path to stop future re-alerts (genuine tamper still fires).' : 'Review the cited evidence before acting.']);
        if ($f) $findings[] = $f;
        $sections[] = ['file' => $fp, 'deep' => $deep, 'flag_explain' => $fe, 'web' => $web, 'auth' => $auth, 'verdict' => $v];
    }
    // overall verdict = worst of the per-file verdicts
    $rank = ['clean' => 0, 'false_positive_likely' => 1, 'suspicious' => 2, 'likely_compromised' => 3];
    $overall = 'clean'; $oscore = 0;
    foreach ($sections as $s) { if (($rank[$s['verdict']['verdict']] ?? 0) > ($rank[$overall] ?? 0)) $overall = $s['verdict']['verdict']; $oscore = max($oscore, $s['verdict']['score']); }
    smpro_audit('forensics_flagged_run', ['user' => $user, 'files' => count($files), 'verdict' => $overall]);
    return ['ok' => true, 'user' => $user, 'scope' => $scope, 'verdict' => $overall, 'score' => $oscore,
            'sections' => $sections, 'findings' => $findings, 'partial' => array_values(array_unique($partial)),
            'read_only' => true, 'ran_at' => time()];
}

/** Cheap TAMPER signal vs the whitelist entry's cached fingerprint. true ⇒ re-arm (do NOT suppress).
 *  Catches: a NEW token family, a newly-appeared nested decode→eval CHAIN (same families but new
 *  threat — the injected-backdoor case), or a large token-score jump. In-PHP set-compare, at most one
 *  bounded tokenscan per file per run. A glob (pattern/dir) trust is never re-armed (no per-file fp). */
function smpro_fe_wl_added_obfuscation($path, $account) {
    $m = smpro_fe_wl_match($account, $path, null, is_file($path) ? (int)@filesize($path) : null);
    if (!$m || $m['mode'] !== 'downgrade') return false;
    $e = $m['entry'];
    if (($e['scope'] ?? '') === 'glob') return false;         // pattern/dir trust, not a file fingerprint
    $fp = $e['token_fingerprint'] ?? null;
    static $cache = [];
    $ck = $path . '|' . (@filemtime($path) ?: 0) . '|' . (@filesize($path) ?: 0);   // bust cache when the file changes
    if (!isset($cache[$ck])) { $d = smpro_fx_tokenscan($path); $cache[$ck] = ['families' => $d['families_seen'], 'nested' => $d['nested_chain'], 'score' => $d['token_score']]; }
    $cur = $cache[$ck];
    // legacy flat-array fingerprint (families only) or missing → can't fully verify: re-arm on nested chain, else be safe
    if (!is_array($fp) || !isset($fp['families'])) { $prev = is_array($fp) ? $fp : []; return !empty($cur['nested']) || (bool)array_diff($cur['families'], $prev); }
    if (!empty($cur['nested']) && empty($fp['nested'])) return true;                    // a decode→eval chain appeared
    if (array_diff($cur['families'], (array)$fp['families'])) return true;              // a new token family appeared
    if ((int)($cur['score'] ?? 0) > (int)($fp['score'] ?? 0) + 20) return true;         // token score jumped a lot
    return false;
}
