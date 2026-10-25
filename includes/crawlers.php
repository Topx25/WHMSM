<?php
/**
 * includes/crawlers.php - Crawler Control: every known crawler family, what it took from this server (requests,
 * bytes, served vs refused, domains, last seen) over 24 h / 7 d / 30 d, and one switch per family that refuses it
 * on every site of the server.
 *
 * WHY. Bot Guard tells a real Googlebot from a fake one and gray-lists attackers; what it could not do was carry
 * the operator's own decision about a REAL crawler - "I do not want Bytespider or GPTBot reading my customers'
 * shops at all". A CDN does that per site; a server does it once for every site it hosts.
 *
 * HOW.
 *   Counting  - a worker (every 10 minutes) reads each domlog from the byte offset it stopped at last time (inode
 *               and size kept per file, so a rotated or truncated log starts over and nothing is counted twice),
 *               maps the User-Agent to a catalogue family, and adds to an hourly bucket: hits, bytes, served
 *               (2xx/3xx), refused (403/429), the domains touched (capped), last seen. Buckets older than 31 days
 *               are dropped. The page sums buckets; it never reads a log itself.
 *   Refusing  - one Apache file under conf.d (read by every EasyApache build, never rewritten by it): when the
 *               User-Agent matches a blocked family's pattern, 403, on every vhost. It is a server-level <If>
 *               section, which Apache merges after a vhost's own <Location>, so a site with its own access rules
 *               (Site Shield, .htaccess) is still covered. Proven by configtest before a graceful reload; a refused
 *               file is put back as it was. Search engines are never blocked without a second, explicit confirmation
 *               on the page: a lost ranking is the operator's loss, not the crawler's.
 *   Honesty   - a family that matches no request is still listed (so the operator sees it can be refused), with
 *               zeros; a worker that could not read a log says so in its state, and the page shows it.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }
if (!function_exists('smpro_bg_catalog')) { $bgf = __DIR__ . '/botguard.php'; if (is_file($bgf)) require_once $bgf; }

define('SMPRO_CR_DIR',   SMPRO_VARLIB . '/crawlers');
define('SMPRO_CR_CFG',   SMPRO_CR_DIR . '/policy.json');
define('SMPRO_CR_CUR',   SMPRO_CR_DIR . '/cursors.json');
define('SMPRO_CR_STATE', SMPRO_CR_DIR . '/state.json');
define('SMPRO_CR_HTTPD', '/etc/apache2/conf.d/smpro-crawlers.conf');
define('SMPRO_CR_KEEP_DAYS', 31);

function smpro_cr_dir(): string { @is_dir(SMPRO_CR_DIR) || @mkdir(SMPRO_CR_DIR, 0700, true); return SMPRO_CR_DIR; }
function smpro_cr_load(string $f): array { $d = @is_file($f) ? json_decode((string)@file_get_contents($f), true) : null; return is_array($d) ? $d : []; }
function smpro_cr_save(string $f, array $d): bool {
    smpro_cr_dir(); $t = $f . '.tmp';
    if (@file_put_contents($t, json_encode($d, JSON_UNESCAPED_SLASHES), LOCK_EX) === false) return false;
    @chmod($t, 0600); return @rename($t, $f);
}

/* ---------------- the catalogue, as the page shows it ---------------- */
/** Cloudflare-style category of a family: the Bot Guard kind, with the AI kind split by what the agent does. */
function smpro_cr_category(string $key, array $f): string {
    $k = (string)($f['kind'] ?? '');
    if ($k === 'ai') {
        // A family's pattern lists the agents it covers (GPTBot|ChatGPT-User|OAI-SearchBot). It is an "assistant"
        // or "search" family only when EVERY agent in it is one; a mixed family is a crawler, which is what its
        // bulk traffic is. Decided from the alternatives of the pattern, not from one token found anywhere in it.
        $re = (string)($f['ua'] ?? ''); if (preg_match('#^/(.*)/[a-z]*$#s', $re, $m)) $re = $m[1];
        $alts = array_values(array_filter(array_map(fn($a) => strtolower(trim($a, '() ')), preg_split('/\|/', preg_replace('/\(\?:|[()]/', '', $re)))));
        if (!$alts) return 'ai_crawler';
        $isAsst = fn($a) => (bool)preg_match('/-user$|^user-|externalfetcher|duckassist/', $a);
        $isSrch = fn($a) => (bool)preg_match('/searchbot$/', $a);
        if (count(array_filter($alts, $isAsst)) === count($alts)) return 'ai_assistant';
        if (count(array_filter($alts, $isSrch)) === count($alts)) return 'ai_search';
        return 'ai_crawler';
    }
    return ['search' => 'search', 'social' => 'social', 'seo' => 'seo', 'monitor' => 'monitor', 'archive' => 'archive'][$k] ?? 'other';
}
function smpro_cr_category_label(string $c): string {
    return ['ai_crawler' => 'AI Crawler', 'ai_assistant' => 'AI Assistant', 'ai_search' => 'AI Search', 'search' => 'Search Engine Crawler',
            'social' => 'Social Preview', 'seo' => 'SEO Tool', 'monitor' => 'Uptime Monitor', 'archive' => 'Archiver', 'other' => 'Other'][$c] ?? $c;
}
/** Who publishes it, from the name when it says so. */
function smpro_cr_vendor(string $key, array $f): string {
    $n = (string)($f['name'] ?? $key);
    if (preg_match('/\(([^)]+)\)/', $n, $m)) return $m[1];
    $map = ['googlebot' => 'Google', 'google_ext' => 'Google', 'google_prefetch' => 'Google', 'bingbot' => 'Microsoft', 'duckduckgo' => 'DuckDuckGo', 'applebot' => 'Apple', 'apple_ext' => 'Apple',
            'yandex' => 'Yandex', 'baidu' => 'Baidu', 'yahoo' => 'Yahoo', 'seznam' => 'Seznam', 'facebook' => 'Meta', 'whatsapp' => 'Meta', 'twitter' => 'X', 'linkedin' => 'LinkedIn',
            'pinterest' => 'Pinterest', 'ahrefs' => 'Ahrefs', 'semrush' => 'Semrush', 'uptimerobot' => 'UptimeRobot', 'pingdom' => 'Pingdom', 'openai' => 'OpenAI', 'anthropic' => 'Anthropic',
            'perplexity' => 'Perplexity', 'bytedance' => 'ByteDance', 'commoncrawl' => 'Common Crawl', 'archive' => 'Internet Archive', 'amazonbot' => 'Amazon', 'amazon_ads' => 'Amazon',
            'naver' => 'Naver', 'sogou' => 'Sogou', 'coccoc' => 'Coc Coc', 'mojeek' => 'Mojeek', 'qwant' => 'Qwant', 'diffbot' => 'Diffbot', 'statuscake' => 'StatusCake', 'site24x7' => 'Site24x7',
            'betteruptime' => 'Better Stack', 'telegram' => 'Telegram', 'slack' => 'Slack', 'discord' => 'Discord'];
    return $map[$key] ?? '';
}
/** Every family the page lists: catalogue entries with their category and vendor. */
function smpro_cr_families(): array {
    $out = [];
    foreach (smpro_bg_catalog() as $k => $f) {
        if (!is_array($f) || empty($f['ua'])) continue;
        $out[$k] = ['key' => $k, 'name' => (string)($f['name'] ?? $k), 'kind' => (string)($f['kind'] ?? ''), 'category' => smpro_cr_category($k, $f),
                    'vendor' => smpro_cr_vendor($k, $f), 'ua' => (string)$f['ua'], 'custom' => !empty($f['custom'])];
    }
    return $out;
}

/* ---------------- policy ---------------- */
function smpro_cr_policy(): array { $p = smpro_cr_load(SMPRO_CR_CFG); $p['blocked'] = is_array($p['blocked'] ?? null) ? $p['blocked'] : []; return $p; }
function smpro_cr_blocked(): array { return array_keys(smpro_cr_policy()['blocked']); }
/** A search engine is only refused with the second confirmation; the page sends confirm=search for that. */
function smpro_cr_protected(string $key): bool { $f = smpro_cr_families()[$key] ?? null; return $f && $f['category'] === 'search'; }
function smpro_cr_set(string $key, bool $block, string $by, bool $confirmed = false): array {
    $fams = smpro_cr_families();
    if (!isset($fams[$key])) return ['ok' => false, 'msg' => 'Unknown crawler family.'];
    if ($block && smpro_cr_protected($key) && !$confirmed) return ['ok' => false, 'msg' => 'This is a search engine: blocking it removes your customers\' sites from its results. Confirm a second time to do it.', 'needs_confirm' => true];
    if (function_exists('smpro_ctl_dry_run') && smpro_ctl_dry_run()) return ['ok' => false, 'msg' => 'Dry-Run is on: the rule was not written.'];
    $p = smpro_cr_policy();
    if ($block) $p['blocked'][$key] = ['since' => time(), 'by' => $by]; else unset($p['blocked'][$key]);
    smpro_cr_save(SMPRO_CR_CFG, $p);
    $a = smpro_cr_apply();
    if ($a['ok']) smpro_cr_robots_apply();   // a refused family is also asked politely, in every robots.txt
    if (!$a['ok']) {
        // the rule did not go live: the policy must not claim it did
        $p = smpro_cr_policy(); if ($block) unset($p['blocked'][$key]); else $p['blocked'][$key] = ['since' => time(), 'by' => $by]; smpro_cr_save(SMPRO_CR_CFG, $p);
        return ['ok' => false, 'msg' => 'Not changed - ' . $a['msg']];
    }
    if (function_exists('smpro_audit')) smpro_audit('crawler_' . ($block ? 'block' : 'allow'), ['family' => $key, 'by' => $by]);
    return ['ok' => true, 'msg' => ($block ? 'Refused on every site: ' : 'Allowed again: ') . $fams[$key]['name'] . '. ' . $a['msg']];
}
/** Block or allow every family of one category (the "all AI crawlers" switch). Search engines are never bulk-blocked. */
function smpro_cr_set_category(string $cat, bool $block, string $by): array {
    $n = 0; $skipped = 0;
    foreach (smpro_cr_families() as $k => $f) {
        if ($f['category'] !== $cat) continue;
        if ($block && $f['category'] === 'search') { $skipped++; continue; }
        $p = smpro_cr_policy();
        if ($block) $p['blocked'][$k] = ['since' => time(), 'by' => $by]; else unset($p['blocked'][$k]);
        smpro_cr_save(SMPRO_CR_CFG, $p); $n++;
    }
    $a = smpro_cr_apply();
    if ($a['ok']) smpro_cr_robots_apply();
    if (function_exists('smpro_audit')) smpro_audit('crawler_category_' . ($block ? 'block' : 'allow'), ['category' => $cat, 'families' => $n, 'by' => $by]);
    return ['ok' => $a['ok'], 'msg' => $n . ' famil' . ($n === 1 ? 'y' : 'ies') . ($block ? ' refused' : ' allowed') . ($skipped ? ', ' . $skipped . ' search engine(s) left alone' : '') . '. ' . $a['msg']];
}

/* ---------------- enforcement: one Apache file ---------------- */
function smpro_cr_render(array $blocked, array $fams): string {
    $o = "# Safety Monitor Pro - Crawler Control: crawler families the operator refused on every site of this server.\n"
       . "# Generated; do not edit. Change it on the Bot Guard page (Crawlers). Removed when nothing is refused.\n";
    if (!$blocked) return $o . "# (nothing refused)\n";
    $parts = [];
    foreach ($blocked as $k) { if (!isset($fams[$k])) continue; $re = (string)$fams[$k]['ua']; if (preg_match('#^/(.*)/([a-z]*)$#s', $re, $m)) $re = $m[1]; $parts[] = '(?:' . $re . ')'; }
    if (!$parts) return $o . "# (nothing refused)\n";
    $re = implode('|', $parts);
    $o .= "# Families: " . implode(', ', $blocked) . "\n";
    $o .= '<If "%{HTTP_USER_AGENT} =~ m#' . str_replace('#', '\\#', $re) . '#i">' . "\n    Require all denied\n</If>\n";
    return $o;
}
function smpro_cr_httpd_run(string $cmd, int $t = 90): array { $o = (string)@shell_exec('timeout ' . $t . ' ' . $cmd . ' 2>&1; echo "__rc=$?"'); preg_match('/__rc=(\d+)\s*$/', $o, $m); return [(int)($m[1] ?? 1), trim(preg_replace('/__rc=\d+\s*$/', '', $o))]; }
function smpro_cr_live(): array {
    if (!@is_file(SMPRO_CR_HTTPD)) return [];
    if (!preg_match('/^# Families: (.+)$/m', (string)@file_get_contents(SMPRO_CR_HTTPD), $m)) return [];
    return array_values(array_filter(array_map('trim', explode(',', $m[1]))));
}
/** Write the file for the current policy; configtest; graceful. Returns ['ok','msg']. Never leaves a refused file in place. */
function smpro_cr_apply(): array {
    if (defined('SMPRO_TEST_SRC')) return ['ok' => true, 'msg' => 'test: Apache not touched'];
    if (!is_dir('/etc/apache2/conf.d') || !is_executable('/usr/sbin/apachectl')) return ['ok' => false, 'msg' => 'no Apache on this server'];
    $blocked = smpro_cr_blocked(); $fams = smpro_cr_families();
    $prev = @is_file(SMPRO_CR_HTTPD) ? (string)@file_get_contents(SMPRO_CR_HTTPD) : null;
    if (!$blocked) {
        if ($prev === null) return ['ok' => true, 'msg' => 'nothing refused'];
        @unlink(SMPRO_CR_HTTPD);
        [$rc, $o] = smpro_cr_httpd_run('/usr/sbin/apachectl configtest', 60);
        if ($rc === 0) smpro_cr_httpd_run('/usr/sbin/apachectl graceful', 60);
        return ['ok' => true, 'msg' => 'the Apache rule was removed'];
    }
    $body = smpro_cr_render($blocked, $fams);
    if ($prev === $body) return ['ok' => true, 'msg' => 'Apache rule unchanged'];
    if (@file_put_contents(SMPRO_CR_HTTPD . '.tmp', $body, LOCK_EX) === false) return ['ok' => false, 'msg' => 'could not write ' . SMPRO_CR_HTTPD];
    @chmod(SMPRO_CR_HTTPD . '.tmp', 0644); @rename(SMPRO_CR_HTTPD . '.tmp', SMPRO_CR_HTTPD);
    [$rc, $o] = smpro_cr_httpd_run('/usr/sbin/apachectl configtest', 60);
    if ($rc !== 0 || stripos($o, 'Syntax OK') === false) {
        if ($prev === null) @unlink(SMPRO_CR_HTTPD); else @file_put_contents(SMPRO_CR_HTTPD, $prev, LOCK_EX);
        return ['ok' => false, 'msg' => 'Apache configtest refused the rule, nothing changed: ' . substr($o, -200)];
    }
    [$rc, $o] = smpro_cr_httpd_run('/usr/sbin/apachectl graceful', 60);
    return ['ok' => $rc === 0, 'msg' => $rc === 0 ? ('Apache reloaded; ' . count($blocked) . ' famil' . (count($blocked) === 1 ? 'y' : 'ies') . ' refused on every site') : ('Apache graceful reload failed: ' . substr($o, -200))];
}

/* ---------------- counting ---------------- */
/** One combined-log line -> [ts, status, bytes, ua] or null. */
function smpro_cr_parse(string $l): ?array {
    if (!preg_match('/^\S+ \S+ \S+ \[([^\]]+)\] "[^"]*" (\d{3}) (\S+) "[^"]*" "([^"]*)"/', $l, $m)) return null;
    $ts = 0;
    if (preg_match('#^(\d{1,2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+\-]\d{4})?#', $m[1], $d)) $ts = (int)(@strtotime($d[1] . ' ' . $d[2] . ' ' . $d[3] . ' ' . $d[4] . ':' . $d[5] . ':' . $d[6] . ' ' . ($d[7] ?? '')) ?: 0);
    return ['ts' => $ts, 'status' => (int)$m[2], 'bytes' => ctype_digit($m[3]) ? (int)$m[3] : 0, 'ua' => $m[4]];
}
/** Family of a User-Agent through the catalogue, memoised per distinct UA within a run. */
function smpro_cr_family_of(string $ua, array &$memo): string {
    if ($ua === '' || $ua === '-') return '';
    if (isset($memo[$ua])) return $memo[$ua];
    if (count($memo) > 5000) $memo = [];
    return $memo[$ua] = smpro_bg_family($ua);
}
/** Add one request to the hourly buckets. Pure; the tests feed it synthetic lines. */
function smpro_cr_bucket(array &$buckets, string $fam, string $domain, array $r): void {
    $h = gmdate('YmdH', $r['ts'] > 0 ? $r['ts'] : time());
    if (!isset($buckets[$h][$fam])) $buckets[$h][$fam] = ['hits' => 0, 'bytes' => 0, 'served' => 0, 'refused' => 0, 'domains' => [], 'last' => 0];
    $b =& $buckets[$h][$fam];
    $b['hits']++; $b['bytes'] += (int)$r['bytes'];
    $st = (int)$r['status'];
    if ($st >= 200 && $st < 400) $b['served']++; elseif ($st === 403 || $st === 429 || $st === 444) $b['refused']++;
    if ($domain !== '' && (isset($b['domains'][$domain]) || count($b['domains']) < 60)) $b['domains'][$domain] = ($b['domains'][$domain] ?? 0) + 1;
    if ($r['ts'] > $b['last']) $b['last'] = $r['ts'];
    unset($b);
}
function smpro_cr_bucket_file(string $hour): string { return smpro_cr_dir() . '/h-' . substr($hour, 0, 8) . '.json'; }
/** Merge a run's buckets into the day files. */
function smpro_cr_bucket_merge(array $buckets): void {
    $byDay = [];
    foreach ($buckets as $h => $fams) $byDay[substr($h, 0, 8)][$h] = $fams;
    foreach ($byDay as $day => $hours) {
        $f = smpro_cr_dir() . '/h-' . $day . '.json'; $d = smpro_cr_load($f);
        foreach ($hours as $h => $fams) foreach ($fams as $fam => $b) {
            if (!isset($d[$h][$fam])) { $d[$h][$fam] = $b; continue; }
            $x =& $d[$h][$fam];
            $x['hits'] += $b['hits']; $x['bytes'] += $b['bytes']; $x['served'] += $b['served']; $x['refused'] += $b['refused']; $x['last'] = max((int)$x['last'], (int)$b['last']);
            foreach ($b['domains'] as $dom => $n) if (isset($x['domains'][$dom]) || count($x['domains']) < 60) $x['domains'][$dom] = ($x['domains'][$dom] ?? 0) + $n;
            unset($x);
        }
        smpro_cr_save($f, $d);
    }
    // keep a month
    foreach (glob(smpro_cr_dir() . '/h-*.json') ?: [] as $f) { $day = substr(basename($f), 2, 8); if ($day < gmdate('Ymd', time() - SMPRO_CR_KEEP_DAYS * 86400)) @unlink($f); }
}
/**
 * The worker's pass: every domlog from where it stopped last time. Cursors are per path: [inode, offset]; a changed
 * inode or a smaller file means rotation/truncation and the file is read from the start. Bounded by bytes and time;
 * a pass that stops early says so (partial) and the cursors it did not reach are left where they were.
 */
function smpro_cr_collect(int $maxBytes = 200 * 1024 * 1024, int $maxSeconds = 150): array {
    $base = function_exists('smpro_bg_domlogs_base') ? smpro_bg_domlogs_base() : '';
    $res = ['ok' => false, 'files' => 0, 'lines' => 0, 'bytes' => 0, 'partial' => false, 'unreadable' => 0, 'why' => ''];
    if ($base === '' || !is_dir($base)) { $res['why'] = 'no domlogs directory on this server'; return $res; }
    $cur = smpro_cr_load(SMPRO_CR_CUR); $buckets = []; $memo = []; $t0 = microtime(true); $budget = $maxBytes;
    // newest-modified first, so a pass that runs out of budget covers what is moving
    $cmd = 'find ' . escapeshellarg($base) . " -maxdepth 2 -type f ! -name '*bytes_log' ! -name 'ftp*' ! -name '*.gz' ! -name '*.offset' -mmin -1500 -size +0 -printf '%T@ %s %i %p\\n' 2>/dev/null | sort -rn";
    $out = function_exists('smpro_run') ? smpro_run('sh -c ' . escapeshellarg($cmd), 60, ['stderr' => 'discard']) : (string)@shell_exec('timeout 60 sh -c ' . escapeshellarg($cmd) . ' 2>/dev/null');
    foreach (explode("\n", trim((string)$out)) as $ln) {
        if ($ln === '') continue;
        [$mt, $size, $ino, $path] = array_pad(explode(' ', $ln, 4), 4, '');
        $path = trim($path); if ($path === '' || !is_file($path)) continue;
        if (microtime(true) - $t0 > $maxSeconds || $budget <= 0) { $res['partial'] = true; break; }
        $size = (int)$size; $ino = (int)$ino; $c = $cur[$path] ?? null;
        $off = ($c && (int)$c[0] === $ino && (int)$c[1] <= $size) ? (int)$c[1] : 0;
        if ($c === null) $off = max(0, $size - 2 * 1024 * 1024);   // a file never seen: the last 2 MB, not its whole history
        if ($off >= $size) { $cur[$path] = [$ino, $size]; continue; }
        $fh = @fopen($path, 'rb'); if (!$fh) { $res['unreadable']++; continue; }
        if ($off > 0) { @fseek($fh, $off); if ($off > 0) fgets($fh); }   // drop the partial line a previous cut may have left
        $domain = preg_replace('/-ssl_log$/', '', basename($path)); $read = 0;
        while (($l = fgets($fh)) !== false) {
            $read += strlen($l); $res['lines']++;
            $r = smpro_cr_parse($l); if (!$r) continue;
            $fam = smpro_cr_family_of($r['ua'], $memo); if ($fam === '') continue;
            smpro_cr_bucket($buckets, $fam, $domain, $r);
            if ($read > $budget) break;
        }
        $pos = (int)@ftell($fh); @fclose($fh);
        $cur[$path] = [$ino, $pos]; $budget -= $read; $res['bytes'] += $read; $res['files']++;
        if ($read >= $budget && $pos < $size) $res['partial'] = true;
    }
    if ($buckets) smpro_cr_bucket_merge($buckets);
    // cursors of files that disappeared are forgotten
    foreach (array_keys($cur) as $p) if (!is_file($p)) unset($cur[$p]);
    smpro_cr_save(SMPRO_CR_CUR, $cur);
    $res['ok'] = true;
    $st = smpro_cr_load(SMPRO_CR_STATE); $st['last_run'] = time(); $st['last'] = $res; smpro_cr_save(SMPRO_CR_STATE, $st);
    return $res;
}
/** Sums over a window ('24h' | '7d' | '30d') per family. */
function smpro_cr_stats(string $win = '7d'): array {
    $hours = ['24h' => 24, '7d' => 24 * 7, '30d' => 24 * 30][$win] ?? 24 * 7;
    $since = gmdate('YmdH', time() - $hours * 3600); $out = [];
    $days = []; for ($d = time() - $hours * 3600; $d <= time() + 3600; $d += 86400) $days[gmdate('Ymd', $d)] = 1; $days[gmdate('Ymd')] = 1;
    foreach (array_keys($days) as $day) {
        $f = smpro_cr_dir() . '/h-' . $day . '.json'; if (!is_file($f)) continue;
        foreach (smpro_cr_load($f) as $h => $fams) {
            if ($h < $since) continue;
            foreach ($fams as $fam => $b) {
                if (!isset($out[$fam])) $out[$fam] = ['hits' => 0, 'bytes' => 0, 'served' => 0, 'refused' => 0, 'domains' => [], 'last' => 0];
                $x =& $out[$fam];
                $x['hits'] += (int)$b['hits']; $x['bytes'] += (int)$b['bytes']; $x['served'] += (int)$b['served']; $x['refused'] += (int)$b['refused']; $x['last'] = max($x['last'], (int)$b['last']);
                foreach ((array)$b['domains'] as $dom => $n) $x['domains'][$dom] = ($x['domains'][$dom] ?? 0) + (int)$n;
                unset($x);
            }
        }
    }
    foreach ($out as &$x) { $x['domain_count'] = count($x['domains']); arsort($x['domains']); $x['top_domains'] = array_slice(array_keys($x['domains']), 0, 5); unset($x['domains']); }
    unset($x);
    return $out;
}
/** The rows the page draws: every family, with its window numbers (zeros when unseen), policy and live state. */
function smpro_cr_rows(string $win = '7d'): array {
    $stats = smpro_cr_stats($win); $blocked = array_flip(smpro_cr_blocked()); $live = array_flip(smpro_cr_live()); $robots = array_flip(array_keys((array)(smpro_cr_policy()['robots'] ?? []))); $rows = [];
    foreach (smpro_cr_families() as $k => $f) {
        $s = $stats[$k] ?? ['hits' => 0, 'bytes' => 0, 'served' => 0, 'refused' => 0, 'domain_count' => 0, 'top_domains' => [], 'last' => 0];
        $rows[$k] = $f + $s + ['blocked' => isset($blocked[$k]), 'live' => isset($live[$k]), 'protected' => $f['category'] === 'search', 'robots' => isset($robots[$k]) || isset($blocked[$k]), 'robots_own' => isset($robots[$k])];
    }
    uasort($rows, fn($a, $b) => ($b['hits'] <=> $a['hits']) ?: strcmp($a['name'], $b['name']));
    return $rows;
}
function smpro_cr_state(): array { return smpro_cr_load(SMPRO_CR_STATE); }

/* ---------------- the polite layer: robots.txt ----------------
 * A refused crawler gets 403 whatever it asks for; robots.txt is the other half - the published request not to crawl,
 * which the well-behaved ones (and only those) obey, and the one thing a site owner can point to. It is written into
 * each site's robots.txt as ONE marked block, never anywhere else:
 *   - only into a robots.txt that already exists as a real file. A site without one (WordPress serves a virtual
 *     robots.txt with its sitemap line) is LEFT ALONE and counted, because creating a file there would silently
 *     replace what the application serves;
 *   - the original is copied once beside it before the first write (robots.txt.smpro-orig), and removing the block
 *     gives the file back byte for byte;
 *   - an immutable file (Safety Lock, WP Guard) is skipped and counted, never unlocked for this;
 *   - the User-agent tokens come from the catalogue's own patterns (their literal alternatives), nothing invented.
 */
define('SMPRO_CR_RB_BEGIN', '# BEGIN Safety Monitor Pro - Crawler Control (managed block; edits inside it are overwritten)');
define('SMPRO_CR_RB_END',   '# END Safety Monitor Pro - Crawler Control');
/** The robots User-agent tokens of one family: the literal alternatives of its pattern. */
function smpro_cr_robots_tokens(array $f): array {
    $re = (string)($f['ua'] ?? ''); if (preg_match('#^/(.*)/[a-z]*$#s', $re, $m)) $re = $m[1];
    $out = [];
    foreach (preg_split('/\|/', preg_replace('/\(\?:|[()]/', '', $re)) as $a) {
        $a = trim($a); if ($a === '') continue;
        $a = str_replace(['\\-', '\\.', '\\/', '\\ '], ['-', '.', '/', ' '], $a);
        if (preg_match('/[\\\\^$*+?\[\]{}]/', $a)) continue;          // not a literal name: skip rather than guess
        $a = rtrim($a, '/');
        if ($a !== '' && !in_array($a, $out, true)) $out[] = $a;
    }
    return $out;
}
/** Families that carry the robots request: those switched on for it plus every refused one. */
function smpro_cr_robots_families(): array {
    $p = smpro_cr_policy(); $set = [];
    foreach (array_keys((array)($p['robots'] ?? [])) as $k) $set[$k] = 1;
    foreach (array_keys((array)($p['blocked'] ?? [])) as $k) $set[$k] = 1;
    return array_keys($set);
}
/** The managed block for the current policy ('' when nothing is asked). */
function smpro_cr_robots_block(?array $families = null): string {
    $families = $families ?? smpro_cr_robots_families(); $fams = smpro_cr_families(); $lines = [];
    foreach ($families as $k) { if (!isset($fams[$k])) continue; foreach (smpro_cr_robots_tokens($fams[$k]) as $t) $lines[] = 'User-agent: ' . $t; }
    if (!$lines) return '';
    return SMPRO_CR_RB_BEGIN . "\n" . implode("\n", array_unique($lines)) . "\nDisallow: /\n" . SMPRO_CR_RB_END . "\n";
}
/** One file: put the block in (replacing an older one) or take it out. Pure on strings. */
function smpro_cr_robots_splice(string $content, string $block): string {
    $re = '/\n?' . preg_quote(SMPRO_CR_RB_BEGIN, '/') . '.*?' . preg_quote(SMPRO_CR_RB_END, '/') . '\n?/s';
    $base = preg_replace($re, "\n", $content);
    $base = rtrim((string)$base, "\n");
    if ($block === '') return $base === '' ? '' : $base . "\n";
    return ($base === '' ? '' : $base . "\n\n") . $block;
}
/** Every document root with a REAL robots.txt, and those without. */
function smpro_cr_robots_targets(): array {
    if (!function_exists('smpro_lr_docroots')) { $lf = __DIR__ . '/learn.php'; if (is_file($lf)) require_once $lf; }
    $roots = function_exists('smpro_lr_docroots') ? smpro_lr_docroots() : [];
    $have = []; $none = [];
    foreach ($roots as $r => $u) { $f = $r . '/robots.txt'; if (is_file($f) && !is_link($f)) $have[$f] = $u; else $none[$r] = $u; }
    return ['have' => $have, 'none' => $none];
}
/** Write the block into every real robots.txt (or remove it when nothing is asked). Returns counts; never creates a file. */
function smpro_cr_robots_apply(): array {
    $r = ['ok' => true, 'written' => 0, 'unchanged' => 0, 'left_alone' => 0, 'locked' => 0, 'failed' => 0, 'block' => false];
    if (function_exists('smpro_ctl_dry_run') && smpro_ctl_dry_run()) { $r['ok'] = false; $r['why'] = 'dry-run'; return $r; }
    $block = smpro_cr_robots_block(); $r['block'] = $block !== '';
    $t = smpro_cr_robots_targets(); $r['left_alone'] = count($t['none']);
    foreach ($t['have'] as $f => $user) {
        $cur = (string)@file_get_contents($f);
        $orig = $f . '.smpro-orig';
        // Nothing asked and the original is beside the file: the original comes back byte for byte (the splice
        // normalises the trailing newline, which "byte for byte" must not). The copy is then removed.
        if ($block === '' && is_file($orig)) {
            $ob = (string)@file_get_contents($orig);
            if ($ob === $cur) { @unlink($orig); $r['unchanged']++; continue; }
            $attrs = (string)@shell_exec('lsattr -d ' . escapeshellarg($f) . ' 2>/dev/null');
            if (preg_match('/^\S*[ia]\S*\s/', $attrs)) { $r['locked']++; continue; }
            $st = @stat($f);
            if (@file_put_contents($f . '.smpro-tmp', $ob, LOCK_EX) === false) { $r['failed']++; continue; }
            @chown($f . '.smpro-tmp', (int)($st['uid'] ?? 0)); @chgrp($f . '.smpro-tmp', (int)($st['gid'] ?? 0)); @chmod($f . '.smpro-tmp', ($st['mode'] ?? 0644) & 07777);
            if (!@rename($f . '.smpro-tmp', $f)) { @unlink($f . '.smpro-tmp'); $r['failed']++; continue; }
            @unlink($orig); $r['written']++; continue;
        }
        $new = smpro_cr_robots_splice($cur, $block);
        if ($new === $cur) { $r['unchanged']++; continue; }
        $attrs = (string)@shell_exec('lsattr -d ' . escapeshellarg($f) . ' 2>/dev/null');
        if (preg_match('/^\S*[ia]\S*\s/', $attrs)) { $r['locked']++; continue; }
        if (!is_file($orig) && strpos($cur, SMPRO_CR_RB_BEGIN) === false) { @copy($f, $orig); @chown($orig, fileowner($f)); @chgrp($orig, filegroup($f)); @chmod($orig, 0644); }
        $st = @stat($f);
        if (@file_put_contents($f . '.smpro-tmp', $new, LOCK_EX) === false) { $r['failed']++; continue; }
        @chown($f . '.smpro-tmp', (int)($st['uid'] ?? 0)); @chgrp($f . '.smpro-tmp', (int)($st['gid'] ?? 0)); @chmod($f . '.smpro-tmp', ($st['mode'] ?? 0644) & 07777);
        if (!@rename($f . '.smpro-tmp', $f)) { @unlink($f . '.smpro-tmp'); $r['failed']++; continue; }
        $r['written']++;
    }
    $st = smpro_cr_load(SMPRO_CR_STATE); $st['robots'] = $r + ['at' => time()]; smpro_cr_save(SMPRO_CR_STATE, $st);
    if (function_exists('smpro_audit')) smpro_audit('crawler_robots_apply', ['written' => $r['written'], 'left_alone' => $r['left_alone'], 'locked' => $r['locked'], 'block' => $r['block'] ? 1 : 0]);
    return $r;
}
/** Switch the robots request for one family (independent of refusing it). */
function smpro_cr_robots_set(string $key, bool $on, string $by): array {
    $fams = smpro_cr_families(); if (!isset($fams[$key])) return ['ok' => false, 'msg' => 'Unknown crawler family.'];
    $p = smpro_cr_policy(); $p['robots'] = (array)($p['robots'] ?? []);
    if ($on) $p['robots'][$key] = ['since' => time(), 'by' => $by]; else unset($p['robots'][$key]);
    smpro_cr_save(SMPRO_CR_CFG, $p);
    $a = smpro_cr_robots_apply();
    if (!$a['ok']) return ['ok' => false, 'msg' => 'Not changed - ' . (string)($a['why'] ?? 'robots.txt could not be written')];
    if (function_exists('smpro_audit')) smpro_audit('crawler_robots_' . ($on ? 'on' : 'off'), ['family' => $key, 'by' => $by]);
    return ['ok' => true, 'msg' => ($on ? 'Disallow written for ' : 'Disallow removed for ') . $fams[$key]['name'] . ': ' . $a['written'] . ' robots.txt file(s) changed, ' . $a['unchanged'] . ' already right, ' . $a['left_alone'] . ' site(s) without a real robots.txt left alone' . ($a['locked'] ? ', ' . $a['locked'] . ' locked file(s) skipped' : '') . '.'];
}
function smpro_cr_robots_set_category(string $cat, bool $on, string $by): array {
    $n = 0; $p = smpro_cr_policy(); $p['robots'] = (array)($p['robots'] ?? []);
    foreach (smpro_cr_families() as $k => $f) { if ($f['category'] !== $cat) continue; if ($on) $p['robots'][$k] = ['since' => time(), 'by' => $by]; else unset($p['robots'][$k]); $n++; }
    smpro_cr_save(SMPRO_CR_CFG, $p);
    $a = smpro_cr_robots_apply();
    if (function_exists('smpro_audit')) smpro_audit('crawler_robots_category_' . ($on ? 'on' : 'off'), ['category' => $cat, 'families' => $n, 'by' => $by]);
    return ['ok' => $a['ok'], 'msg' => $n . ' famil' . ($n === 1 ? 'y' : 'ies') . ($on ? ' added to' : ' removed from') . ' robots.txt: ' . $a['written'] . ' file(s) changed, ' . $a['left_alone'] . ' site(s) without a real robots.txt left alone' . ($a['locked'] ? ', ' . $a['locked'] . ' locked skipped' : '') . '.'];
}

/* ---------------- cron ---------------- */
function smpro_cr_cron_sync(): bool {
    if (defined('SMPRO_TEST_SRC')) return true;
    $f = '/etc/cron.d/smpro-crawlers'; $bin = SMPRO_BASE . '/bin/crawlers_tick.php';
    if (!@is_file($bin)) return false;
    $php = function_exists('smpro_php_cli_bin') ? smpro_php_cli_bin() : (is_executable('/usr/local/cpanel/3rdparty/bin/php') ? '/usr/local/cpanel/3rdparty/bin/php' : 'php');
    $lockDir = defined('SMPRO_LOCKS') ? SMPRO_LOCKS : (SMPRO_VARLIB . '/locks'); @is_dir($lockDir) || @mkdir($lockDir, 0700, true);
    $flock = is_executable('/usr/bin/flock') ? '/usr/bin/flock' : 'flock';
    $desired = "# Safety Monitor Pro - Crawler Control: count crawler traffic from where the last pass stopped, every 10 min\n"
             . '*/10 * * * * root ' . $flock . ' -n ' . $lockDir . '/crawlers.lock timeout 170 nice -n 10 ' . $php . ' ' . $bin . ' >/dev/null 2>&1' . "\n";
    return function_exists('smpro_cron_install') ? smpro_cron_install($f, $desired) : (@file_put_contents($f, $desired) !== false && @chmod($f, 0644));
}
