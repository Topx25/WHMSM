<?php
/**
 * includes/swdeep.php - Site Watch deep checks: what a file fingerprint cannot see.
 *
 * Born from a real case: a WordPress core file (wp-includes/load.php) carried a few lines on top that served a
 * gambling page to search engines only, on the home page only; a second backdoor sat in the web root and in
 * wp-includes under a cache-tool name; the account's ~/.bashrc was replaced by a password lock; a page cache in
 * front of the site then stored the search-engine answer (a redirect with no target) and every visitor got a white
 * page. Every file was written by the account itself, so nothing looked foreign. These checks look at content:
 *   - core:    WordPress core verified against the official checksums (wp-cli, run AS THE ACCOUNT) -> changed core
 *              files and files that must not exist inside wp-admin / wp-includes;
 *   - cloak:   the home page fetched twice on this server, as a browser and as a search-engine crawler -> a redirect
 *              to another host, a redirect with no target, gambling spam, or a canonical/amphtml link to another host;
 *   - shell:   the account's shell start files (.bashrc, .bash_profile, .profile) -> a password lock;
 *   - fileman: file-manager plugins that give anyone with a WordPress login full file access.
 * A check that could not run says so ('ok' => false + 'why') and never reads as "nothing found".
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

/** wp-cli on this server, or ''. */
function smpro_swd_wpcli(): string {
    foreach (['/usr/local/bin/wp', '/usr/bin/wp', '/usr/local/cpanel/3rdparty/bin/wp'] as $c) if (@is_executable($c)) return $c;
    return '';
}

/** Parse `wp core verify-checksums` output. */
function smpro_swd_parse_verify(string $out): array {
    $mod = []; $extra = [];
    foreach (preg_split('/\r?\n/', $out) as $l) {
        if (preg_match("/File doesn't verify against checksum:\s*(\S+)/", $l, $m)) $mod[] = $m[1];
        elseif (preg_match('/File should not exist:\s*(\S+)/', $l, $m)) $extra[] = $m[1];
    }
    $ok = (bool)preg_match('/Success: WordPress installation verifies against checksums/', $out);
    $err = '';
    if (!$ok && !$mod && !$extra) $err = preg_match('/Error:\s*(.+)/', $out, $m) ? trim($m[1]) : 'wp-cli gave no answer';
    return ['clean' => $ok, 'modified' => array_values(array_unique($mod)), 'extra' => array_values(array_unique($extra)), 'error' => $err];
}

/** WordPress core against the official checksums. ['ok'=>bool, 'why'?, 'modified'=>[], 'extra'=>[]] */
function smpro_swd_core(string $doc, string $user): array {
    if (!@is_file($doc . '/wp-includes/version.php')) return ['ok' => true, 'skip' => 'not WordPress', 'modified' => [], 'extra' => []];
    $wp = smpro_swd_wpcli();
    if ($wp === '') return ['ok' => false, 'why' => 'wp-cli is not installed - core files were not verified', 'modified' => [], 'extra' => []];
    if (!preg_match('/^[a-z0-9_-]+$/i', $user)) return ['ok' => false, 'why' => 'unknown account', 'modified' => [], 'extra' => []];
    // a before_wp_load command (it hashes files, it does not boot the site) - but wp-cli also reads the account's own
    // wp-cli.yml / ~/.wp-cli (require:), so it starts from / with those switched off, and what it prints is still the
    // account's word: every path it names is checked below before anything is done with it
    $cmd = 'cd / && WP_CLI_CONFIG_PATH=/dev/null WP_CLI_PACKAGES_DIR=/nonexistent ' . escapeshellarg($wp) . ' core verify-checksums --include-root --skip-plugins --skip-themes --path=' . escapeshellarg($doc) . ' 2>&1';
    $out = (string)@shell_exec('timeout 120 su -s /bin/bash ' . escapeshellarg($user) . ' -c ' . escapeshellarg($cmd) . ' 2>&1');
    if (stripos($out, 'include-root') !== false && stripos($out, 'unknown') !== false)   // older wp-cli: no root-file check
        $out = (string)@shell_exec('timeout 120 su -s /bin/bash ' . escapeshellarg($user) . ' -c ' . escapeshellarg(str_replace(' --include-root', '', $cmd)) . ' 2>&1');
    $p = smpro_swd_parse_verify($out);
    if ($p['error'] !== '') return ['ok' => false, 'why' => 'core not verified: ' . substr($p['error'], 0, 160), 'modified' => [], 'extra' => []];
    // a path that is not a plain relative one resolving to a regular file inside the site is dropped
    $rdoc = rtrim((string)@realpath($doc), '/');
    $inside = function (string $f) use ($doc, $rdoc): bool {
        if ($f === '' || $f[0] === '/' || strpos($f, '..') !== false) return false;
        $p = $doc . '/' . $f; if (@is_link($p)) return false;
        $rp = @realpath($p); return $rp !== false && $rdoc !== '' && strpos($rp, $rdoc . '/') === 0 && @is_file($rp);
    };
    // a core file REPLACED BY A LINK is a changed core file (never read through - only reported)
    $linked = fn(string $f): bool => $f !== '' && $f[0] !== '/' && strpos($f, '..') === false && @is_link($doc . '/' . $f);
    $p['modified'] = array_values(array_filter($p['modified'], fn($f) => $inside($f) || $linked($f))); $p['extra'] = array_values(array_filter($p['extra'], $inside));
    // only code counts: a translated readme or a dropped .txt is not an attack
    $code = fn($f) => (bool)preg_match('/\.(php\d?|phtml|phar|js|htaccess)$/i', $f) || basename($f) === '.htaccess';
    $mod = array_values(array_filter($p['modified'], fn($f) => $code($f) && $f !== 'wp-config-sample.php' && $f !== 'wp-includes/version.php'));
    // .htaccess inside wp-includes / wp-admin is what hardening tools write there - only foreign CODE counts
    $extra = array_values(array_filter($p['extra'], fn($f) => preg_match('/\.(php\d?|phtml|phar|js)$/i', $f) && preg_match('#^(wp-admin|wp-includes)/#', $f)));
    return ['ok' => true, 'modified' => array_slice($mod, 0, 200), 'extra' => array_slice($extra, 0, 200)];
}

/** What a changed core file starts with, in one line (for the alert), when it looks like an injection. */
function smpro_swd_head_hint(string $abs): string {
    $h = (string)@file_get_contents($abs, false, null, 0, 6000);
    $hits = [];
    foreach (['HTTP_USER_AGENT' => 'reads the visitor type', 'googlebot' => 'targets search engines', 'file_get_contents(' => 'fetches a remote page',
              'base64_decode' => 'decodes hidden code', 'eval(' => 'runs hidden code', 'gzinflate' => 'unpacks hidden code', 'header(' => 'sends a redirect'] as $k => $v)
        if (stripos($h, $k) !== false) $hits[] = $v;
    return $hits ? implode(', ', array_slice($hits, 0, 4)) : '';
}

/* ============================ cloaking + spam ============================ */
function smpro_swd_spam_words(): string {
    return '/\b(togel|slot\s?gacor|situs\s?toto|bandar\s?(togel|toto|slot)|judi\s?online|maxwin|slot\s?online|slot88|link\s?alternatif|dolantogel|pragmatic\s?play|scatter\s?hitam)\b/i';
}
/** The registrable part of a host, good enough to tell "same site" from "another site". */
function smpro_swd_base_host(string $h): string {
    $h = strtolower(trim($h, '. ')); $p = explode('.', $h); $n = count($p);
    if ($n >= 3 && strlen($p[$n - 1]) === 2 && in_array($p[$n - 2], ['com', 'net', 'org', 'co', 'gov', 'edu', 'ac', 'or', 'ne'], true)) return implode('.', array_slice($p, -3));
    return implode('.', array_slice($p, -2));
}
/** Fetch the home page on THIS server (as visitors get it, page cache included). */
function smpro_swd_fetch(string $dom, string $ua): array {
    if (!function_exists('curl_init')) return ['code' => 0, 'err' => 'curl extension missing'];
    foreach (['https' => 443, 'http' => 80] as $sch => $port) {
        $ch = curl_init($sch . '://' . $dom . '/'); $hdr = '';
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 12, CURLOPT_CONNECTTIMEOUT => 4, CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_RESOLVE => [$dom . ':' . $port . ':127.0.0.1'], CURLOPT_SSL_VERIFYPEER => false, CURLOPT_SSL_VERIFYHOST => 0, CURLOPT_USERAGENT => $ua,
            CURLOPT_ENCODING => '', CURLOPT_MAXFILESIZE => 3000000,
            CURLOPT_HEADERFUNCTION => function ($c, $l) use (&$hdr) { $hdr .= $l; return strlen($l); }]);
        $body = curl_exec($ch); $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE); $err = (string)curl_error($ch); curl_close($ch);
        if ($code > 0) {
            $loc = preg_match('/^Location:[ \t]*(\S+)/mi', $hdr, $m) ? $m[1] : '';
            return ['code' => $code, 'loc' => $loc, 'hdr' => $hdr, 'body' => is_string($body) ? substr($body, 0, 400000) : '', 'scheme' => $sch];
        }
    }
    return ['code' => 0, 'err' => $err !== '' ? $err : 'no answer'];
}
/** Pure verdict from the two answers. [[sev, why], ...] */
function smpro_swd_cloak_verdict(string $dom, array $browser, array $bot): array {
    $out = []; $own = smpro_swd_base_host($dom);
    $foreign = function (string $url) use ($own) { $h = (string)parse_url($url, PHP_URL_HOST); return $h !== '' && smpro_swd_base_host($h) !== $own; };
    foreach (['visitors' => $browser, 'search engines' => $bot] as $who => $r) {
        $c = (int)($r['code'] ?? 0); if ($c === 0) continue;
        if ($c >= 300 && $c < 400 && trim((string)($r['loc'] ?? '')) === '') {
            $odd = preg_match('/^(https?)\s*:\s*\/\/(\S+)/mi', (string)($r['hdr'] ?? ''), $m) ? ' (a broken header points to ' . $m[1] . '://' . $m[2] . ')' : '';
            $out[] = ['critical', 'The home page answers ' . $who . ' with a redirect that has no target - a blank page' . $odd];
        } elseif ($c >= 300 && $c < 400 && $foreign((string)$r['loc'])) {
            // everyone sent to the same other site is usually a redirect the owner set (cPanel Redirects) - say it, do
            // not call it an attack; only the crawler being sent elsewhere is cloaking (the rule below)
            $same = $who === 'search engines' && (string)($browser['loc'] ?? '') === (string)$r['loc'];
            if (!$same) $out[] = [$who === 'visitors' ? 'warning' : 'critical', 'The home page sends ' . ($who === 'visitors' ? 'every visitor' : 'search engines') . ' to another site: ' . substr((string)$r['loc'], 0, 120) . ($who === 'visitors' ? ' (a redirect set in cPanel, or a hijack - check it is wanted)' : '')];
        }
        $body = (string)($r['body'] ?? '');
        if ($body !== '' && preg_match_all(smpro_swd_spam_words(), $body, $mm) && count(array_unique(array_map('strtolower', $mm[0]))) >= 2)
            $out[] = ['critical', 'Gambling spam in the home page shown to ' . $who . ' (' . implode(', ', array_slice(array_unique(array_map('strtolower', $mm[0])), 0, 4)) . ')'];
        if ($body !== '' && preg_match_all('#<link[^>]+rel=["\']?(canonical|amphtml)["\']?[^>]*href=["\']([^"\']+)#i', $body, $lm, PREG_SET_ORDER))
            foreach ($lm as $x) if ($foreign($x[2])) { $out[] = ['warning', 'The home page shown to ' . $who . ' names another site as its ' . strtolower($x[1]) . ': ' . substr($x[2], 0, 100)]; break; }
    }
    $bc = (int)($browser['code'] ?? 0); $gc = (int)($bot['code'] ?? 0);
    if ($bc === 200 && $gc >= 300 && $gc < 400) $out[] = ['critical', 'Search engines get a redirect while visitors get the page - cloaking'];
    // the same verdict twice (visitors + search engines) reads as one line
    $seen = []; return array_values(array_filter($out, function ($v) use (&$seen) { $k = preg_replace('/ (visitors|search engines)/', '', $v[1]); if (isset($seen[$k])) return false; $seen[$k] = 1; return true; }));
}
function smpro_swd_cloak(string $dom): array {
    $b = smpro_swd_fetch($dom, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36');
    $g = smpro_swd_fetch($dom, 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)');
    // both fetches must answer: one side missing is "could not compare", never "the same for both"
    if ((int)($b['code'] ?? 0) === 0 || (int)($g['code'] ?? 0) === 0) return ['ok' => false, 'why' => ((int)($b['code'] ?? 0) === 0 && (int)($g['code'] ?? 0) === 0 ? 'the home page did not answer on this server' : 'the home page answered only one of the two requests (' . ((int)($b['code'] ?? 0) === 0 ? 'visitor' : 'search engine') . ' request failed)') . ' (' . ($b['err'] ?? ($g['err'] ?? '')) . ')', 'found' => []];
    return ['ok' => true, 'found' => smpro_swd_cloak_verdict($dom, $b, $g), 'codes' => [(int)($b['code'] ?? 0), (int)($g['code'] ?? 0)]];
}

/* ============================ shell start files ============================ */
/** A shell start file that asks for a password before it lets the account in. Pure. */
function smpro_swd_is_shell_lock(string $s): bool {
    $readSecret = (bool)preg_match('/\bread\s+(-[a-z]*s[a-z]*\b)/', $s);
    $hash = (bool)preg_match('/(sha256sum|sha1sum|md5sum|expected_hash|input_hash)/', $s);
    $loop = (bool)preg_match('/while\s+\[\[?.*!=/', $s) || (bool)preg_match('/trap\s+[\'"].*[\'"]\s+INT/', $s);
    return $readSecret && ($hash || $loop);
}
function smpro_swd_shell(string $user): array {
    $pw = function_exists('posix_getpwnam') ? @posix_getpwnam($user) : null; if (!$pw) return ['ok' => false, 'why' => 'unknown account', 'found' => []];
    $home = rtrim((string)$pw['dir'], '/'); $found = [];
    foreach (['.bashrc', '.bash_profile', '.profile', '.bash_login'] as $f) {
        $p = $home . '/' . $f; if (!@is_file($p) || @is_link($p) || @filesize($p) > 200000) continue;
        if (smpro_swd_is_shell_lock((string)@file_get_contents($p))) $found[] = $f;
    }
    return ['ok' => true, 'found' => $found, 'home' => $home];
}

/* ============================ file-manager plugins ============================ */
function smpro_swd_fileman_slugs(): array { return ['wp-file-manager', 'file-manager-advanced', 'filester', 'file-manager', 'wp-filemanager']; }
function smpro_swd_fileman(string $doc): array {
    $o = []; foreach (smpro_swd_fileman_slugs() as $s) if (@is_dir($doc . '/wp-content/plugins/' . $s) && !@is_link($doc . '/wp-content/plugins/' . $s)) $o[] = $s;
    return $o;
}

/* ============================ run inside a Site Watch check ============================ */
/**
 * Adds events to $batch and returns check rows for the site card. $coreDue: verify core now (daily database cycle,
 * first look, or a core file changed since the last look). The cloak, shell and plugin checks are cheap and run
 * every time. Events of these kinds whose cause is gone are marked resolved - but only when the check really ran.
 */
function smpro_swd_run(string $dom, string $doc, string $user, bool $coreDue, array &$batch, array $prevChecks): array {
    $rows = []; $ran = [];
    // one verification can take a minute (checksums fetched from wordpress.org); a round with hundreds of sites keeps
    // a time budget and leaves the rest for the next round - said on the card, never shown as clean
    static $spent = 0.0;
    $keepCore = function () use (&$rows, $prevChecks) { foreach ($prevChecks as $pc) if (($pc[2] ?? '') === 'core' && ($pc[0] ?? '') !== 'info') $rows[] = $pc; };   // the last real verdict stays on the card
    if ($coreDue && $spent > 1800) { $coreDue = false; $keepCore(); $rows[] = ['info', 'WordPress core not verified in this round (time budget used) - next round', 'core', []]; $budgetNote = true; }
    if ($coreDue) {
        $t0 = microtime(true);
        $c = smpro_swd_core($doc, $user);
        $spent += microtime(true) - $t0;
        if (!empty($c['skip'])) { /* not WordPress */ }
        elseif (empty($c['ok'])) { $keepCore(); $rows[] = ['info', (string)$c['why'], 'core', []]; }   // honest "not verified", not a site problem
        else {
            $ran['core'] = 1;
            foreach ($c['modified'] as $rel) {
                $hint = @is_link($doc . '/' . $rel) ? 'replaced by a link' : smpro_swd_head_hint($doc . '/' . $rel);
                smpro_sw_event_add($dom, $batch, 'critical', 'core_mod', 'WordPress core file changed' . ($hint !== '' ? ' (' . $hint . ')' : '') . ': ' . $rel, ['path' => $rel, 'mtime' => (int)@filemtime($doc . '/' . $rel)]);
            }
            foreach ($c['extra'] as $rel) smpro_sw_event_add($dom, $batch, 'critical', 'core_extra', 'File that is not part of WordPress inside its core folders: ' . $rel, ['path' => $rel, 'mtime' => (int)@filemtime($doc . '/' . $rel)]);
            $n = count($c['modified']) + count($c['extra']);
            $rows[] = $n ? ['fail', 'WordPress core: ' . count($c['modified']) . ' changed, ' . count($c['extra']) . ' foreign file(s)', 'core', array_merge($c['modified'], $c['extra'])] : ['ok', 'WordPress core matches the official checksums', 'core', []];
        }
    } elseif (empty($budgetNote)) {
        foreach ($prevChecks as $pc) if (($pc[2] ?? '') === 'core') $rows[] = $pc;   // keep the last core verdict on the card
    }
    $cl = smpro_swd_cloak($dom);
    if (empty($cl['ok'])) $rows[] = ['info', 'Home page not fetched: ' . $cl['why'], 'cloak', []];
    else {
        $ran['cloak'] = 1;
        foreach ($cl['found'] as [$sev, $why]) smpro_sw_event_add($dom, $batch, $sev, 'cloak', $why, ['path' => 'cloak', 'files' => $why]);
        $rows[] = $cl['found'] ? [array_filter($cl['found'], fn($x) => $x[0] === 'critical') ? 'fail' : 'warn', $cl['found'][0][1], 'cloak', array_column($cl['found'], 1)] : ['ok', 'Home page is the same for visitors and search engines', 'cloak', []];
    }
    $sh = smpro_swd_shell($user);
    if (!empty($sh['ok'])) {
        $ran['shell_lock'] = 1;
        foreach ($sh['found'] as $f) smpro_sw_event_add($dom, $batch, 'critical', 'shell_lock', 'The account\'s ' . $f . ' was replaced by a password lock (an attacker had a shell as this account)', ['path' => '~/' . $f, 'files' => $f]);
        if ($sh['found']) $rows[] = ['fail', 'Shell start file locked by an attacker: ' . implode(', ', $sh['found']), 'shell', $sh['found']];
    }
    $fm = smpro_swd_fileman($doc); $ran['fileman'] = 1;
    foreach ($fm as $s) smpro_sw_event_add($dom, $batch, 'warning', 'fileman', 'File-manager plugin installed (full file access for any WordPress login): ' . $s, ['path' => 'wp-content/plugins/' . $s, 'files' => $s]);
    if ($fm) $rows[] = ['warn', 'File-manager plugin installed: ' . implode(', ', $fm), 'fileman', $fm];
    smpro_swd_autoresolve($dom, $batch, $ran);
    return $rows;
}
/** Events of a deep kind whose check ran and did not find them again are resolved. */
function smpro_swd_autoresolve(string $dom, array $batch, array $ran): void {
    if (!$ran) return;
    $now = array_flip(array_column($batch, 'id'));
    $lk = smpro_sw_evlock($dom);
    $f = smpro_sw_path('sites/' . smpro_sw_key($dom) . '/events.jsonl'); $ls = @file($f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: []; $ch = false;
    foreach ($ls as &$l) {
        $e = json_decode($l, true); if (!is_array($e) || !empty($e['resolved'])) continue;
        $k = (string)($e['kind'] ?? ''); $grp = in_array($k, ['core_mod', 'core_extra'], true) ? 'core' : $k;
        if (!isset($ran[$grp]) || isset($now[$e['id'] ?? ''])) continue;
        $e['resolved'] = time(); $e['resolved_by'] = 'no longer found'; $l = json_encode($e, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); $ch = true;
    }
    unset($l);
    if ($ch) @file_put_contents($f, implode("\n", $ls) . "\n", LOCK_EX);
    smpro_sw_evunlock($lk);
}

/* ============================ cleaning steps ============================ */
/** Steps for the deep events (merged into smpro_sw_plan). */
function smpro_swd_plan(string $dom, array $events, string $doc, string $user): array {
    $steps = []; $seen = [];
    foreach ($events as $e) {
        if (!empty($e['resolved'])) continue; $d = $e['data'] ?? []; $k = (string)($e['kind'] ?? '');
        if ($k === 'core_mod' && !isset($seen['core'])) { $seen['core'] = 1; $steps[] = ['action' => 'core_restore', 'arg' => '', 'label' => 'Replace the WordPress core files with the official copy of the same version (wp-content and wp-config.php untouched; current core backed up)', 'safe' => true, 'event' => $e['id']]; }
        if ($k === 'core_extra' && !empty($d['path']) && !isset($seen['q' . $d['path']]) && @is_file($doc . '/' . $d['path'])) { $seen['q' . $d['path']] = 1; $steps[] = ['action' => 'quarantine', 'arg' => (string)$d['path'], 'label' => 'Move ' . $d['path'] . ' to quarantine (not part of WordPress; original kept)', 'safe' => true, 'event' => $e['id']]; }
        if ($k === 'shell_lock' && !empty($d['files']) && !isset($seen['s' . $d['files']])) { $seen['s' . $d['files']] = 1; $steps[] = ['action' => 'shell_restore', 'arg' => (string)$d['files'], 'label' => 'Replace ~/' . $d['files'] . ' with the system default (the locked one is kept)', 'safe' => true, 'event' => $e['id']]; }
        if ($k === 'fileman' && !empty($d['files']) && !isset($seen['f' . $d['files']]) && @is_dir($doc . '/wp-content/plugins/' . $d['files'])) { $seen['f' . $d['files']] = 1; $steps[] = ['action' => 'plugin_off', 'arg' => (string)$d['files'], 'label' => 'Switch off the file-manager plugin ' . $d['files'] . ' (folder renamed, can be undone)', 'safe' => false, 'event' => $e['id']]; }
        if ($k === 'cloak' && !isset($seen['cache'])) { $seen['cache'] = 1; $steps[] = ['action' => 'purge_cache', 'arg' => '', 'label' => 'Empty the server page cache of this account (after the code is cleaned, so visitors stop getting the stored bad answer)', 'safe' => true, 'event' => $e['id']]; }
    }
    if (isset($seen['cache']) && !isset($seen['core'])) $steps[] = ['action' => 'advice', 'arg' => '', 'label' => 'By hand: the home page is cloaked but WordPress core verified clean - look in the theme (functions.php, header.php), mu-plugins and .htaccess', 'safe' => false, 'event' => ''];
    return $steps;
}
/** Run a deep cleaning step. Returns null when the action is not a deep one. */
function smpro_swd_fix(string $dom, string $doc, string $user, string $action, string $arg): ?array {
    if ($action === 'core_restore') {
        if (!function_exists('smpro_sdb_fix_wp_core')) return ['ok' => false, 'msg' => 'core restore is not available'];
        $r = smpro_sdb_fix_wp_core($dom);
        if (!empty($r['ok'])) smpro_swd_resolve_kind($dom, ['core_mod']);
        return $r;
    }
    if ($action === 'shell_restore') {
        if (!in_array($arg, ['.bashrc', '.bash_profile', '.profile', '.bash_login'], true)) return ['ok' => false, 'msg' => 'refused: not a shell start file'];
        $sh = smpro_swd_shell($user); if (empty($sh['ok'])) return ['ok' => false, 'msg' => $sh['why'] ?? 'unknown account'];
        $home = $sh['home']; $p = $home . '/' . $arg;
        if (@is_link($p) || !@is_file($p)) return ['ok' => false, 'msg' => 'refused: not a regular file'];
        $old = (string)@file_get_contents($p);
        $qd = SMPRO_VARLIB . '/quarantine/sitewatch/' . date('Ymd_His') . '_' . substr(sha1($p), 0, 8); @mkdir($qd, 0700, true);
        $bak = $qd . '/' . ltrim($arg, '.') . '.locked';
        if (@file_put_contents($bak, $old) === false) return ['ok' => false, 'msg' => 'could not keep the locked file - nothing changed'];
        @chmod($bak, 0600);
        $skel = @is_file('/etc/skel/' . $arg) ? (string)@file_get_contents('/etc/skel/' . $arg) : "# .bashrc\n[ -f /etc/bashrc ] && . /etc/bashrc\n";
        if (!function_exists('smpro_sdb_safe_write') || !smpro_sdb_safe_write($home, $arg, $skel)) return ['ok' => false, 'msg' => 'could not write ~/' . $arg . ' (the locked copy is kept at ' . $bak . ')'];
        $id = smpro_inv_manifest_add(['user' => $user, 'domain' => $dom, 'action' => 'sw_shell_restore', 'kind' => 'file', 'from' => $p, 'backup' => $bak]);
        smpro_swd_resolve_kind($dom, ['shell_lock'], $arg);
        return ['ok' => true, 'msg' => '~/' . $arg . ' is the system default again; the locked one is kept at ' . $bak . '. Change the account password: someone had a shell as this account.', 'undo_id' => $id];
    }
    if ($action === 'plugin_off') {
        if (!in_array($arg, smpro_swd_fileman_slugs(), true)) return ['ok' => false, 'msg' => 'refused: not a file-manager plugin'];
        $dir = $doc . '/wp-content/plugins/' . $arg; $real = @realpath($dir);
        if ($real === false || @is_link($dir) || strpos($real, rtrim((string)@realpath($doc), '/') . '/') !== 0) return ['ok' => false, 'msg' => 'refused: not a plugin folder inside the site'];
        // stays on the same disk (a rename, not a copy); a dot-folder is not loaded by WordPress
        $to = dirname($real) . '/.smpro-off-' . $arg . '-' . date('Ymd_His');
        if (!@rename($real, $to)) return ['ok' => false, 'msg' => 'could not rename the plugin folder'];
        $id = smpro_inv_manifest_add(['user' => $user, 'domain' => $dom, 'action' => 'sw_plugin_off', 'from' => $real, 'to' => $to]);
        smpro_swd_resolve_kind($dom, ['fileman'], $arg);
        return ['ok' => true, 'msg' => 'Plugin ' . $arg . ' switched off (folder renamed to ' . basename($to) . ').', 'undo_id' => $id];
    }
    if ($action === 'purge_cache') {
        if (!preg_match('/^[a-z0-9_-]+$/i', $user)) return ['ok' => false, 'msg' => 'unknown account'];
        $done = [];
        foreach (['/var/cache/ea-nginx/proxy/', '/var/cache/nginx/proxy/'] as $base) {
            $d = $base . $user; $r = @realpath($d);
            if ($r === false || strpos($r . '/', $base) !== 0 || $r === rtrim($base, '/')) continue;
            @shell_exec('timeout 60 find ' . escapeshellarg($r) . ' -mindepth 1 -delete 2>/dev/null'); $done[] = $r;
        }
        return $done ? ['ok' => true, 'msg' => 'Page cache emptied: ' . implode(', ', $done)] : ['ok' => true, 'msg' => 'This account has no server page cache - nothing to empty.'];
    }
    return null;
}
function smpro_swd_resolve_kind(string $dom, array $kinds, string $files = ''): void {
    $lk = smpro_sw_evlock($dom);
    $f = smpro_sw_path('sites/' . smpro_sw_key($dom) . '/events.jsonl'); $ls = @file($f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: []; $ch = false;
    foreach ($ls as &$l) { $e = json_decode($l, true); if (!is_array($e) || !empty($e['resolved']) || !in_array($e['kind'] ?? '', $kinds, true)) continue;
        if ($files !== '' && ($e['data']['files'] ?? '') !== $files) continue;
        $e['resolved'] = time(); $l = json_encode($e, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); $ch = true; }
    unset($l); if ($ch) @file_put_contents($f, implode("\n", $ls) . "\n", LOCK_EX);
    smpro_sw_evunlock($lk);
}
