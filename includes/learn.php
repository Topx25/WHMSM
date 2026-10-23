<?php
/**
 * includes/learn.php — Learned Defense: the server learns from incidents the operator confirms, then hunts for the
 * same thing everywhere and reports it. Nothing here names a file, a domain, an address or a customer: every rule is
 * DATA taken from a real incident (a file the operator quarantined, deleted or taught), stored with where it came
 * from, and can be switched off or marked wrong.
 *
 * What one confirmed file teaches (each is a separate lesson, so one can be wrong without the others):
 *   hash      - this exact file. Found anywhere again it is the same malware.
 *   relpath   - this place inside a site (path relative to the document root). Only learned when the place is rare
 *               on this server at learn time, so an infected core file (wp-load.php …) never becomes "every site".
 *   dotdir    - a script inside a hidden folder of a site (.well-known/, .tmb/ …): learned from the folder it was in.
 *   behaviour - what the code does, read after undoing string escapes: fetches code from the network and runs it,
 *               runs commands from request input, writes request data into files while walking folders, heavy
 *               escaping around a dynamic run. Learned as the set of behaviours the confirmed file had.
 *   docblock  - the comment header the file opens with. A planted family keeps its invented header ("Advanced
 *               Application Engine", a fake plugin author) across variants whose hash and code shape differ, and the
 *               header is what a scanner reading behaviour alone misses when the command and its input sit far apart.
 *
 * Separately, and without any lesson, a process check finds what a file scan cannot: an account process whose
 * program runs from memory or was deleted after start, a process whose name disagrees with its program, and a
 * shell or interpreter a web request started that has been running for hours (a remote terminal looks like this).
 *
 * Safety: hunting only reports. "Quarantine" moves a file into a root-only store with a manifest and puts it back on
 * Restore; only an exact-file (hash) match may be quarantined automatically, only when the operator turns that on,
 * and Dry-Run / Disabled only report.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

if (!function_exists('smpro_mg_present')) { $mgf = __DIR__ . '/mailguard.php'; if (is_file($mgf)) require_once $mgf; }   // the worker does not boot index.php
function smpro_lr_dir(string $sub = ''): string {
    $d = SMPRO_VARLIB . '/learn' . ($sub !== '' ? '/' . $sub : '');
    if (!is_dir($d)) @mkdir($d, 0700, true);
    @chmod(SMPRO_VARLIB . '/learn', 0700);
    return $d;
}
function smpro_lr_load(string $name, array $def = []): array {
    $j = json_decode((string)@file_get_contents(smpro_lr_dir() . '/' . $name . '.json'), true);
    return is_array($j) ? $j : $def;
}
function smpro_lr_save(string $name, array $v): void {
    $f = smpro_lr_dir() . '/' . $name . '.json'; $t = $f . '.' . getmypid() . '.tmp';
    if (@file_put_contents($t, json_encode($v, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE)) !== false) { @chmod($t, 0600); @rename($t, $f); }
}
function smpro_lr_cfg(): array {
    $c = smpro_lr_load('config') + ['auto' => 'report', 'recent_days' => 30, 'share' => 'on'];
    if (!in_array($c['auto'], ['report', 'quarantine_exact'], true)) $c['auto'] = 'report';
    if (!in_array($c['share'], ['on', 'off'], true)) $c['share'] = 'on';
    return $c;
}

/* ---------------- sharing lessons between servers (patterns only) ----------------
 * What leaves this server: for each lesson this operator confirmed - its kind, its key and its label - and how
 * often it matched here. A hash key is a sha256 and a size; a hidden-folder key is a folder name and an extension;
 * a behaviour key is a set of tags. A PLACE lesson is never sent (a site's own folder names are its business), and
 * neither are incidents: no path, no account, no file content, no address ever goes out. What comes back is the
 * pool: lessons other operators confirmed, which this server then reports on but never acts on by itself. "Not
 * malicious" here is reported back, so a mistaken lesson is withdrawn for everyone. */
function smpro_lr_share_types(): array { return ['hash', 'dotdir', 'behaviour', 'docblock', 'name']; }
/** The outgoing list: patterns of lessons confirmed HERE, plus "wrong" votes on shared ones. */
function smpro_lr_share_payload(array $L): array {
    $out = [];
    foreach ($L as $l) {
        if (!in_array($l['type'] ?? '', smpro_lr_share_types(), true)) continue;
        $shared = ($l['source'] ?? '') === 'shared';
        if (!$shared && ($l['state'] ?? 'on') !== 'on') continue;                  // a lesson this operator switched off is not vouched for
        if (!$shared && empty($l['incidents'])) continue;                            // only what was confirmed here
        if ($shared && empty($l['fp'])) continue;                                    // a shared lesson is only reported back when it was wrong here
        // A hash lesson's local label names the file's path on THIS server: it never leaves. The outgoing label is
        // built from the key alone; any other label that carries a home or document-root path is dropped too.
        $label = (string)$l['label'];
        if ($l['type'] === 'hash') $label = 'An exact file confirmed as malware (' . (int)(explode(':', (string)$l['key'])[1] ?? 0) . ' bytes)';
        elseif (preg_match('#/home[0-9]*/|public_html|/var/www#', $label)) $label = '';
        $out[] = ['type' => (string)$l['type'], 'key' => substr((string)$l['key'], 0, 190), 'label' => substr($label, 0, 200), 'hits' => (int)($l['hits'] ?? 0), 'fp' => (int)($l['fp'] ?? 0)];
        if (count($out) >= 500) break;
    }
    return $out;
}
/** Merge the pool the server returned: new shared lessons come in (report-only), withdrawn ones go. */
function smpro_lr_share_merge(array $L, array $pool): array {
    $seen = []; $new = 0;
    foreach ($pool as $p) {
        $type = (string)($p['type'] ?? ''); $key = (string)($p['key'] ?? '');
        if (!in_array($type, smpro_lr_share_types(), true) || $key === '' || strlen($key) > 190) continue;
        $id = substr(sha1($type . '|' . $key), 0, 12); $seen[$id] = true;
        if (isset($L[$id])) { if (($L[$id]['source'] ?? '') === 'shared') $L[$id]['shared'] = ['servers' => (int)($p['servers'] ?? 0), 'seen' => time()]; continue; }   // a local lesson keeps its own standing
        $L[$id] = ['id' => $id, 'type' => $type, 'key' => $key, 'label' => substr((string)($p['label'] ?? ''), 0, 200), 'state' => 'on', 'created' => time(), 'incidents' => [], 'hits' => 0, 'fp' => 0,
                   'source' => 'shared', 'shared' => ['servers' => (int)($p['servers'] ?? 0), 'seen' => time()]];
        $new++;
    }
    foreach ($L as $id => $l) if (($l['source'] ?? '') === 'shared' && !isset($seen[$id]) && empty($l['fp'])) unset($L[$id]);   // withdrawn upstream (a lesson marked wrong here stays, off, as the record of that)
    return [$L, $new];
}
/** One exchange with the license server. Returns what happened; never throws. */
function smpro_lr_share(): array {
    $cfg = smpro_lr_cfg();
    if ($cfg['share'] !== 'on') return ['ok' => false, 'why' => 'sharing is off'];
    if (!function_exists('smpro_lic_api') || !function_exists('smpro_lic_key') || !function_exists('smpro_lic_payload')) return ['ok' => false, 'why' => 'no license client'];
    $key = smpro_lic_key(); if (trim($key) === '') return ['ok' => false, 'why' => 'no license key'];
    if (function_exists('smpro_ctl_disabled') && smpro_ctl_disabled()) return ['ok' => false, 'why' => 'plugin disabled'];
    $L = smpro_lr_lessons();
    $p = smpro_lic_payload($key); unset($p['telemetry']);
    $p['lessons'] = smpro_lr_share_payload($L);
    [$code, $j] = smpro_lic_api('/api/lessons', $p, 25, (string)(smpro_lic_state()['srv_ip'] ?? ''));
    $st = smpro_lr_load('share'); $st['last'] = time(); $st['sent'] = count($p['lessons']); $st['code'] = (int)$code;
    if (!is_array($j) || empty($j['ok'])) { $st['err'] = is_array($j) ? (string)($j['error'] ?? 'refused') : 'no answer'; smpro_lr_save('share', $st); return ['ok' => false, 'why' => $st['err']]; }
    [$L, $new] = smpro_lr_share_merge($L, (array)($j['pool'] ?? []));
    smpro_lr_save('lessons', $L);
    $st['err'] = ''; $st['pool'] = count((array)($j['pool'] ?? [])); $st['servers'] = (int)($j['servers'] ?? 0); $st['new'] = $new; smpro_lr_save('share', $st);
    if ($new > 0) @touch(smpro_lr_dir() . '/hunt_wanted');
    if (function_exists('smpro_audit')) @smpro_audit('learn_share', ['sent' => $st['sent'], 'pool' => $st['pool'], 'new' => $new]);
    return ['ok' => true, 'sent' => $st['sent'], 'pool' => $st['pool'], 'new' => $new, 'servers' => $st['servers']];
}

/* ---------------- where sites live ---------------- */
/** [docroot => user] from cPanel's own data; every addon, sub-domain and parked root, once. */
function smpro_lr_docroots(): array {
    static $m = null; if ($m !== null) return $m;
    $m = [];
    foreach (glob('/var/cpanel/userdata/*', GLOB_ONLYDIR) ?: [] as $ud) {
        $u = basename($ud); if ($u === 'nobody' || !preg_match('/^[a-zA-Z0-9._-]{1,64}$/', $u)) continue;
        foreach (scandir($ud) ?: [] as $f) {
            if ($f[0] === '.' || $f === 'main' || strpos($f, '_SSL') !== false || preg_match('/\.(cache|json|yaml|db)$/', $f)) continue;
            if (preg_match('/^[ \t]*documentroot:[ \t]*(\S+)/m', (string)@file_get_contents("$ud/$f", false, null, 0, 16384), $x)) {
                $r = rtrim((string)@realpath($x[1]), '/'); if ($r !== '' && is_dir($r)) $m[$r] = $u;
            }
        }
    }
    return $m;
}
/** The document root a path lives in (longest match) and the account. */
function smpro_lr_owner_root(string $path): array {
    $best = ''; $user = '';
    foreach (smpro_lr_docroots() as $r => $u) if (strpos($path, $r . '/') === 0 && strlen($r) > strlen($best)) { $best = $r; $user = $u; }
    if ($user === '' && preg_match('#^/home[0-9]*/([^/]+)/#', $path, $m)) $user = $m[1];
    return [$best, $user];
}

/* ---------------- reading code ---------------- */
/** Undo the escaping attackers use to hide strings: \xNN and \NNN, and "a"."b" joins. */
function smpro_lr_decode(string $code): string {
    $d = preg_replace_callback('/\\\\x([0-9a-fA-F]{2})/', fn($m) => chr(hexdec($m[1])), $code);
    $d = preg_replace_callback('/\\\\([0-7]{2,3})/', fn($m) => chr(octdec($m[1]) & 255), (string)$d);
    $d = preg_replace('/["\']\s*\.\s*["\']/', '', (string)$d);
    return (string)$d;
}
/** The header comment a file opens with, normalised: lower case, one space, no punctuation noise. '' when there is
 *  none or it is too short to be a signature (a bare "<?php" or a one-word comment is not one). */
function smpro_lr_docblock(string $code): string {
    if (!preg_match('#^\s*<\?php\s*(?:/\*\*?(.*?)\*/|//(.*?)\n)#s', substr($code, 0, 4096), $m)) return '';
    $t = strtolower(preg_replace('/[^a-z0-9 ]+/i', ' ', (string)($m[1] !== '' ? $m[1] : ($m[2] ?? ''))));
    $t = trim(preg_replace('/\s+/', ' ', $t));
    return strlen($t) >= 40 ? $t : '';
}
function smpro_lr_docblock_key(string $code): string { $t = smpro_lr_docblock($code); return $t === '' ? '' : sha1($t); }
/** Behaviour tags of a piece of code. Classes of action, never names. */
function smpro_lr_tags(string $code): array {
    $raw = $code; $d = strtolower(smpro_lr_decode($code)); $t = [];
    $netFetch = (bool)preg_match('/curl_exec\s*\(|curl_init\s*\(|fsockopen\s*\(|stream_socket_client\s*\(/', $d)
             || (bool)preg_match('/(file_get_contents|fopen|readfile|copy)\s*\(\s*["\']https?:\/\//', $d);
    if ($netFetch && preg_match('/["\']https?:\/\/[^"\']+["\']/', $d)) $t['net_fetch'] = true;
    if (preg_match('/\beval\s*\(|\bassert\s*\(\s*\$|create_function\s*\(|["\']\?>["\']\s*\./', $d)) $t['dyn_exec'] = true;
    if (preg_match('/\b(system|shell_exec|passthru|proc_open|popen|pcntl_exec)\s*\(|(?<![a-z_>:])exec\s*\(/', $d)) $t['cmd_exec'] = true;
    if (preg_match('/\$_(get|post|request|cookie|files)\b|php:\/\/input/', $d)) $t['req_input'] = true;
    if (preg_match('/move_uploaded_file\s*\(|file_put_contents\s*\(|fwrite\s*\(/', $d)) $t['file_write'] = true;
    if (preg_match('/\b(scandir|opendir|readdir)\s*\(/', $d)) $t['fs_walk'] = true;
    $esc = preg_match_all('/\\\\x[0-9a-fA-F]{2}|\\\\[0-7]{3}/', $raw);
    if ($esc >= 20 || preg_match('/(gzinflate|gzuncompress|str_rot13)\s*\(\s*(base64_decode|str_rot13|gzinflate)/', $d)) $t['obfuscated'] = true;
    $tags = array_keys($t); sort($tags);
    return $tags;
}
/** Does the dangerous call take the other thing as its own argument (same statement), not just somewhere in the file?
 *  Libraries (a feed parser, a backup plugin) contain a network call and an eval, or exec and $_POST, far apart;
 *  a loader or a shell joins them in one expression. */
function smpro_lr_joined(string $decoded, string $call, string $what, int $win = 400): bool {
    if (!preg_match_all('/' . $call . '/i', $decoded, $m, PREG_OFFSET_CAPTURE)) return false;
    foreach ($m[0] as [$s, $pos]) if (preg_match('/' . $what . '/i', substr($decoded, $pos, $win))) return true;
    return false;
}
/** A behaviour set strong enough to call a file malicious on its own (combinations, not single functions). $code,
 *  when given, must also show the two parts joined in one expression. */
function smpro_lr_tags_strong(array $tags, string $code = ''): string {
    $h = array_flip($tags); $d = $code !== '' ? smpro_lr_decode($code) : '';
    if (isset($h['net_fetch'], $h['dyn_exec']) && ($d === '' || smpro_lr_joined($d, '\beval\s*\(|\bassert\s*\(|create_function\s*\(', 'curl_exec|file_get_contents\s*\(\s*["\']https?:|stream_get_contents|fread\s*\(')))
        return 'downloads code from the internet and runs it';
    if (isset($h['cmd_exec'], $h['req_input']) && ($d === '' || smpro_lr_joined($d, '\b(system|shell_exec|passthru|proc_open|popen|exec)\s*\(', '\$_(get|post|request|cookie)\b|php:\/\/input', 200)))
        return 'runs system commands taken from the web request';
    if (isset($h['obfuscated'], $h['dyn_exec'])) return 'hides its code and runs it dynamically';
    if (isset($h['file_write'], $h['req_input'], $h['fs_walk'], $h['cmd_exec'])) return 'a web file manager that also runs commands';
    return '';
}

/* ---------------- lessons ---------------- */
function smpro_lr_lessons(): array { return smpro_lr_load('lessons'); }
function smpro_lr_lesson_add(array &$L, string $type, string $key, string $label, array $inc): string {
    $id = substr(sha1($type . '|' . $key), 0, 12);
    if (!isset($L[$id])) $L[$id] = ['id' => $id, 'type' => $type, 'key' => $key, 'label' => $label, 'state' => 'on', 'created' => time(), 'incidents' => [], 'hits' => 0, 'fp' => 0];
    foreach ($L[$id]['incidents'] as $i) if (($i['path'] ?? '') === $inc['path'] && ($i['sha'] ?? '') === $inc['sha']) return $id;
    $L[$id]['incidents'][] = $inc; $L[$id]['incidents'] = array_slice($L[$id]['incidents'], -20);
    return $id;
}
/** Learn from one confirmed-bad file. $read is the copy to read (it may already be in quarantine), $where the path it
 *  was found at. Returns the lesson ids it produced or touched. */
function smpro_lr_learn_file(string $read, string $where, string $source): array {
    if (!is_file($read) || is_link($read)) return [];
    $size = (int)@filesize($read); if ($size <= 0 || $size > 8388608) return [];
    $sha = (string)@hash_file('sha256', $read); if ($sha === '') return [];
    if (in_array($sha, smpro_lr_load('allow'), true)) return [];
    [$root, $user] = smpro_lr_owner_root($where);
    $inc = ['at' => time(), 'path' => $where, 'user' => $user, 'sha' => $sha, 'size' => $size, 'source' => $source];
    $L = smpro_lr_lessons(); $ids = [];
    $ids[] = smpro_lr_lesson_add($L, 'hash', $sha . ':' . $size, 'The exact file found at ' . $where, $inc);
    $rel = $root !== '' ? substr($where, strlen($root) + 1) : '';
    $ext = strtolower((string)pathinfo($where, PATHINFO_EXTENSION));
    if ($rel !== '') {
        $first = explode('/', $rel)[0];
        if ($first !== '' && $first[0] === '.' && strpos($rel, '/') !== false && $ext !== '')
            $ids[] = smpro_lr_lesson_add($L, 'dotdir', $first . ':' . $ext, ".$ext script inside the hidden folder $first/ of a site", $inc);
        // a place is a lesson only if it is rare here: an infected core file must not turn every site into a finding
        $roots = smpro_lr_docroots(); $have = 0;
        foreach (array_keys($roots) as $r) if ($r !== $root && @is_file($r . '/' . $rel)) { $have++; if ($have >= 3 && $have > count($roots) * 0.05) break; }
        if (!($have >= 3 && $have > count($roots) * 0.05)) $ids[] = smpro_lr_lesson_add($L, 'relpath', $rel, "A file at $rel inside a site", $inc);
    }
    // The name alone, when it is not one every site has: a planted tool keeps its name from one site to the next while
    // the folders above it change (a sub-site, a theme, a plugin), so the place lesson never met the next copy.
    $name = strtolower(basename($where));
    if (smpro_lr_name_rare($name)) $ids[] = smpro_lr_lesson_add($L, 'name', $name, "A file named $name anywhere in a site", $inc);
    $head = smpro_lr_docblock((string)@file_get_contents($read, false, null, 0, 4096));
    if ($head !== '') $ids[] = smpro_lr_lesson_add($L, 'docblock', sha1($head), 'A file opening with the header "' . substr($head, 0, 70) . (strlen($head) > 70 ? '…' : '') . '"', $inc);
    $tags = smpro_lr_tags((string)@file_get_contents($read, false, null, 0, 1048576));
    $code0 = (string)@file_get_contents($read, false, null, 0, 1048576);
    if (smpro_lr_tags_strong($tags, $code0) !== '') $ids[] = smpro_lr_lesson_add($L, 'behaviour', implode('+', $tags), 'Code that ' . smpro_lr_tags_strong($tags, $code0) . ' (' . implode(', ', $tags) . ')', $inc);
    smpro_lr_save('lessons', $L);
    @touch(smpro_lr_dir() . '/hunt_wanted');
    if (function_exists('smpro_audit')) smpro_audit('learn_file', ['path' => $where, 'sha256' => $sha, 'lessons' => count($ids), 'source' => $source]);
    return array_values(array_unique($ids));
}
/** A file name is a lesson only when it is rare: index.php, wp-load.php or functions.php live in every site and would
 *  turn every site into a finding. Rare = seen in at most two other document roots, top eight levels. */
function smpro_lr_name_rare(string $name): bool {
    if ($name === '' || strlen($name) < 6 || strpos($name, '.') === false) return false;
    if (in_array($name, ['index.php', 'index.html', '.htaccess', 'wp-load.php', 'wp-config.php', 'functions.php', 'config.php', 'readme.html', 'license.txt', 'error_log'], true)) return false;
    $n = 0;
    foreach (array_keys(smpro_lr_docroots()) as $r) {
        $c = (int)trim((string)@shell_exec('timeout 20 find ' . escapeshellarg($r) . ' -xdev -maxdepth 8 -iname ' . escapeshellarg($name) . ' -print 2>/dev/null | head -1 | wc -l'));
        if ($c > 0 && ++$n >= 3) return false;
    }
    return true;
}
/** Structural signs that need no lesson: an .htaccess that turns an odd extension into a CGI program, and a native
 *  (ELF) executable inside a document root. Both were how a planted "cgi-bin" ran compiled kernel exploits and a
 *  Perl shell under a store's folder; no PHP reader would ever have opened them. Returns [[path, why], …]. */
function smpro_lr_structural(string $root): array {
    $out = [];
    $ht = (string)@shell_exec('timeout 30 find ' . escapeshellarg($root) . ' -xdev -maxdepth 8 -type f -name .htaccess -size -64k -print 2>/dev/null | head -2000');
    foreach (explode("\n", $ht) as $p) {
        if ($p === '' || is_link($p)) continue;
        $c = (string)@file_get_contents($p, false, null, 0, 65536);
        if (!preg_match('/^\s*(AddHandler|SetHandler|AddType)\s+(cgi-script|application\/x-httpd-cgi)\b(.*)$/mi', $c, $m)) continue;
        // .cgi and .pl are what a cgi-bin is for; any other extension (.ss, .txt, .jpg, .alfa) is a program in disguise
        $exts = preg_split('/\s+/', trim((string)($m[3] ?? '')), -1, PREG_SPLIT_NO_EMPTY);
        $odd = array_values(array_filter($exts, fn($e) => !in_array(strtolower($e), ['.cgi', '.pl'], true)));
        if ($m[1] === 'SetHandler' || $odd) $out[] = [$p, 'an .htaccess that makes ' . ($odd ? implode(' ', array_slice($odd, 0, 4)) : 'every file') . ' run as a CGI program'];
    }
    // every file over 4k that is not a library's, a shared object or an obvious asset: its first four bytes say whether it is a program
    $bins = (string)@shell_exec('timeout 60 find ' . escapeshellarg($root) . ' -xdev -maxdepth 8 -type f -size +4k -size -20M ! -path "*/vendor/*" ! -path "*/node_modules/*" ! -name "*.so" ! -name "*.so.*" ! -name "*.php" ! -name "*.js" ! -name "*.css" ! -name "*.htm*" ! -name "*.jp*g" ! -name "*.png" ! -name "*.gif" ! -name "*.svg" ! -name "*.woff*" ! -name "*.ttf" ! -name "*.mp4" ! -name "*.pdf" ! -name "*.zip" ! -name "*.gz" -print 2>/dev/null | head -5000');
    foreach (explode("\n", $bins) as $p) {
        if ($p === '' || is_link($p)) continue;
        $h = @fopen($p, 'rb'); if (!$h) continue; $sig = (string)fread($h, 4); fclose($h);
        if ($sig === "\x7fELF") $out[] = [$p, 'a native (ELF) executable inside a web folder'];
        if (count($out) >= 400) break;
    }
    return $out;
}
/** Teach from a folder of kept files whose layout mirrors where they were found (…/home/<acct>/…). */
function smpro_lr_teach_folder(string $dir): array {
    $dir = rtrim((string)realpath($dir), '/');
    if ($dir === '' || !is_dir($dir) || strpos($dir, '/home') === 0) return ['ok' => false, 'msg' => 'Give a folder outside the account homes (a quarantine / evidence folder).'];
    $n = 0; $l = [];
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS));
    foreach ($it as $f) {
        if ($n >= 2000) break;
        $p = $f->getPathname(); if (!$f->isFile() || $f->isLink()) continue;
        $pos = strpos($p, '/home'); if ($pos === false) continue;
        $where = preg_replace('/\.\d{6}$/', '', substr($p, $pos));   // "<file>.HHMMSS" copies keep their original name
        if (!preg_match('#^/home[0-9]*/[^/]+/#', $where)) continue;
        foreach (smpro_lr_learn_file($p, $where, 'taught:' . basename($dir)) as $id) $l[$id] = true;
        $n++;
    }
    return ['ok' => true, 'msg' => "Learned from $n file(s): " . count($l) . ' lesson(s) created or confirmed. A hunt runs next.'];
}

/* ---------------- hunting ---------------- */
/** Files worth reading in one site: anything in a hidden folder, the top level, and what changed in the last N days. */
function smpro_lr_candidates(string $root, int $sinceDays): array {
    $out = [];
    // "top level" is ! -path root/*/* — never -maxdepth inside the tests: find treats -maxdepth as a global option
    // wherever it is written, and a late -maxdepth 1 silently overrode the 8 above (the first hunt took 1 s).
    $cmd = 'timeout 60 find ' . escapeshellarg($root) . ' -xdev -maxdepth 8 -type f \( -name "*.php" -o -name "*.php[0-9]" -o -name "*.phtml" -o -name "*.pht" \) -size -2048k'
         . ' \( -path ' . escapeshellarg($root . '/.*') . ' -o -path ' . escapeshellarg($root . '/*/.*') . ' -o -mtime -' . max(1, $sinceDays) . ' -o ! -path ' . escapeshellarg($root . '/*/*') . ' \) -print 2>/dev/null | head -20000';   // one large docroot had 10,534 candidates; 5,000 cut half of them silently
    foreach (explode("\n", (string)@shell_exec($cmd)) as $p) if ($p !== '') $out[] = $p;
    return $out;
}
/** One full hunt. Writes learn/findings.json; returns it. */
function smpro_lr_hunt(int $budget = 500): array {
    $t0 = time(); $L = smpro_lr_lessons(); $cfg = smpro_lr_cfg(); $GLOBALS['smpro_lr_L'] = $L;
    $allow = array_flip(smpro_lr_load('allow'));
    $on = array_filter($L, fn($l) => ($l['state'] ?? 'on') === 'on');
    $hashes = []; $sizes = []; $rels = []; $dots = []; $behav = []; $docs = []; $names = [];
    foreach ($on as $id => $l) {
        if ($l['type'] === 'hash') { [$h, $s] = explode(':', $l['key']) + ['', '0']; $hashes[$h] = $id; $sizes[(int)$s] = true; }
        elseif ($l['type'] === 'name') $names[strtolower($l['key'])] = $id;
        elseif ($l['type'] === 'relpath') $rels[$l['key']] = $id;
        elseif ($l['type'] === 'dotdir') { [$dd, $ext] = explode(':', $l['key']) + ['', '']; $dots[$dd . ':' . $ext] = $id; }
        elseif ($l['type'] === 'behaviour') $behav[$l['key']] = $id;
        elseif ($l['type'] === 'docblock') $docs[$l['key']] = $id;
    }
    $found = []; $done = 0; $partial = false;
    $add = function (string $p, string $user, string $lid, string $why) use (&$found, $allow) {
        if (function_exists('smpro_wpguard_trusted') && smpro_wpguard_trusted($p)) return;
        if (function_exists('smpro_mg_trusted') && smpro_mg_trusted($p)) return;
        $sha = (string)@hash_file('sha256', $p); if ($sha !== '' && isset($allow[$sha])) return;
        if (!isset($found[$p])) $found[$p] = ['path' => $p, 'user' => $user, 'sha' => $sha, 'size' => (int)@filesize($p), 'mtime' => (int)@filemtime($p), 'lessons' => [], 'why' => []];
        if (!in_array($lid, $found[$p]['lessons'], true)) { $found[$p]['lessons'][] = $lid; $found[$p]['why'][] = $why . (((($GLOBALS['smpro_lr_L'][$lid]['source'] ?? '') === 'shared')) ? ' (a lesson shared by another server)' : ''); }
    };
    $roots = smpro_lr_docroots(); $homes = [];
    // A hunt that hit its budget left a cursor: this round carries on after the sites already covered, keeping their
    // findings, instead of starting over at the first site every ten minutes and never reaching the last ones.
    $cur = smpro_lr_load('cursor'); $skip = [];
    if ($cur && time() - (int)($cur['at'] ?? 0) < 86400 && (int)($cur['lessons'] ?? -1) === count($on)) { $skip = array_flip((array)($cur['done'] ?? [])); foreach ((array)($cur['found'] ?? []) as $f) $found[$f['path']] = $f; }
    $doneRoots = array_keys($skip);
    foreach ($roots as $root => $user) {
        if (isset($skip[$root])) { $done++; $homes[$user] = true; continue; }
        if (time() - $t0 > $budget) { $partial = true; break; }
        $done++; $doneRoots[] = $root;
        foreach ($rels as $rel => $lid) { $p = $root . '/' . $rel; if (is_file($p) && !is_link($p)) $add($p, $user, $lid, 'same place as a confirmed incident'); }
        if ($names) {   // one walk of the site for every name lesson at once, not one walk per name
            $or = implode(' -o ', array_map(fn($nm) => '-iname ' . escapeshellarg($nm), array_keys($names)));
            $hits = (string)@shell_exec('timeout 60 find ' . escapeshellarg($root) . ' -xdev -maxdepth 8 -type f \\( ' . $or . ' \\) -print 2>/dev/null | head -200');
            foreach (explode("\n", $hits) as $p) { $nm = strtolower(basename($p)); if ($p !== '' && !is_link($p) && isset($names[$nm])) $add($p, $user, $names[$nm], 'the same file name as a confirmed incident'); }
        }
        foreach (smpro_lr_structural($root) as [$p, $why]) $add($p, $user, 'structural', $why);
        foreach (smpro_lr_candidates($root, (int)$cfg['recent_days']) as $p) {
            if (is_link($p)) continue;
            $sz = (int)@filesize($p);
            if (isset($sizes[$sz])) { $h = (string)@hash_file('sha256', $p); if (isset($hashes[$h])) $add($p, $user, $hashes[$h], 'the exact file of a confirmed incident'); }
            $rel = substr($p, strlen($root) + 1); $first = explode('/', $rel)[0]; $ext = strtolower((string)pathinfo($p, PATHINFO_EXTENSION));
            if ($first !== '' && $first[0] === '.' && strpos($rel, '/') !== false && isset($dots[$first . ':' . $ext])) $add($p, $user, $dots[$first . ':' . $ext], "a .$ext script inside $first/");
            if ($docs && $sz < 1048576) { $dk = smpro_lr_docblock_key((string)@file_get_contents($p, false, null, 0, 4096)); if ($dk !== '' && isset($docs[$dk])) $add($p, $user, $docs[$dk], 'opens with the same header as a confirmed incident'); }
            if ($behav && $sz < 1048576) {
                $code1 = (string)@file_get_contents($p, false, null, 0, 1048576); $tags = smpro_lr_tags($code1);
                $s = smpro_lr_tags_strong($tags, $code1);
                if ($s !== '') foreach ($behav as $key => $lid) { if (!array_diff(explode('+', $key), $tags)) { $add($p, $user, $lid, 'code that ' . $s); break; } }
            }
        }
        $homes[$user] = true;
    }
    // what MailGuard attributed outgoing mail to: a script that sends in bulk is planted or hijacked, and MailGuard saw
    // the mail this hunt cannot. Reported from its record (read-only); a folder is shown as a folder, never quarantined.
    if (function_exists('smpro_mg_script_origins')) {
        try {
            foreach (smpro_mg_script_origins(60) as $o) {
                [, $ou] = smpro_lr_owner_root($o['path']);
                $add($o['path'], $ou, 'mailguard', 'MailGuard attributed outgoing mail to ' . (is_dir($o['path']) ? 'scripts in this folder' : 'this script') . ' (' . (int)$o['messages'] . ' messages, ' . (int)$o['actions'] . ' action(s) in 60 days)');
            }
        } catch (\Throwable $e) { if (function_exists('smpro_soft_fail')) smpro_soft_fail('learn_mailguard', $e); }
    }
    // scripts left in an account's temporary folders (an upload that was never cleaned up runs from there too)
    foreach (array_keys($homes) as $u) {
        $h = function_exists('smpro_user_home') ? (string)smpro_user_home($u) : ''; if ($h === '') continue;
        foreach ([$h . '/tmp', $h . '/.cagefs/tmp'] as $td) foreach (glob($td . '/*.php') ?: [] as $p) {
            if (is_link($p) || !is_file($p)) continue;
            $code2 = (string)@file_get_contents($p, false, null, 0, 1048576); $tags = smpro_lr_tags($code2); $s = smpro_lr_tags_strong($tags, $code2);
            $dk = smpro_lr_docblock_key($code2); if ($dk !== '' && isset($docs[$dk])) { $add($p, $u, $docs[$dk], 'opens with the same header as a confirmed incident'); continue; }
            $sz = (int)@filesize($p); $h2 = isset($sizes[$sz]) ? (string)@hash_file('sha256', $p) : '';
            if ($h2 !== '' && isset($hashes[$h2])) $add($p, $u, $hashes[$h2], 'the exact file of a confirmed incident');
            elseif ($s !== '') $add($p, $u, 'tmp', 'a script in the account\'s temporary folder that ' . $s);
        }
    }
    foreach ($found as $f) foreach ($f['lessons'] as $lid) if (isset($L[$lid])) $L[$lid]['hits']++;
    smpro_lr_save('lessons', $L);
    $res = ['at' => time(), 'took' => time() - $t0, 'sites' => $done, 'of' => count($roots), 'partial' => $partial, 'lessons' => count($on), 'findings' => array_values($found)];
    smpro_lr_save('findings', $res);
    @unlink(smpro_lr_dir() . '/hunt_wanted');
    if ($partial) { smpro_lr_save('cursor', ['at' => time(), 'lessons' => count($on), 'done' => $doneRoots, 'found' => array_values($found)]); @touch(smpro_lr_dir() . '/hunt_wanted'); }
    else @unlink(smpro_lr_dir() . '/cursor.json');
    if ($cfg['auto'] === 'quarantine_exact' && !(function_exists('smpro_ctl_dry_run') && smpro_ctl_dry_run()) && !(function_exists('smpro_ctl_disabled') && smpro_ctl_disabled())) {
        foreach ($res['findings'] as $f) foreach ($f['lessons'] as $lid) if (($L[$lid]['type'] ?? '') === 'hash' && ($L[$lid]['source'] ?? '') !== 'shared' && !empty($L[$lid]['incidents'])) { smpro_lr_quarantine($f['path'], 'auto: exact file of a confirmed incident'); break; }
    }
    return $res;
}

/* ---------------- quarantine ---------------- */
/** The immutable / append-only flags of one path as lsattr prints them ('' when none or unreadable). */
function smpro_lr_attrs(string $path): string {
    $o = (string)@shell_exec('lsattr -d ' . escapeshellarg($path) . ' 2>/dev/null'); $f = trim((string)strtok($o, ' '));
    return preg_replace('/[^ia]/', '', $f);
}
/**
 * Remove one file even when the account's folders are locked. Safety Lock (this product) and WP Guard lock
 * wp-includes / wp-admin / the docroot itself with chattr +i on the DIRECTORY; unlink needs the parent writable, so
 * the file's own flag being cleared was not enough and the quarantine failed with "immutable or permissions". The
 * parent's flag is lifted for the one unlink and put back EXACTLY as it was, so the other product's lock survives.
 * @return array{ok:bool,why:string,relocked:bool}
 */
function smpro_lr_unlink_locked(string $file): array {
    @exec('chattr -i -a ' . escapeshellarg($file) . ' 2>/dev/null');
    if (@unlink($file)) return ['ok' => true, 'why' => '', 'relocked' => false];
    $dir = dirname($file); $flags = smpro_lr_attrs($dir);
    if ($flags === '') return ['ok' => false, 'why' => 'the folder ' . $dir . ' is not writable by root (' . (is_writable($dir) ? 'unlink refused' : 'permissions') . ')', 'relocked' => false];
    @exec('chattr -i -a ' . escapeshellarg($dir) . ' 2>/dev/null');
    $ok = @unlink($file);
    @exec('chattr +' . $flags . ' ' . escapeshellarg($dir) . ' 2>/dev/null');   // put the lock back exactly as it was
    return ['ok' => $ok, 'why' => $ok ? '' : 'the folder ' . $dir . ' is locked (chattr +' . $flags . ') and could not be unlocked - lift the lock in Safety Lock / WP Guard, then quarantine again', 'relocked' => true];
}
function smpro_lr_quarantine(string $path, string $source): array {
    if (!preg_match('#^/home[0-9]*/([^/]+)/#', $path, $m)) return ['ok' => false, 'msg' => 'Only files inside an account home.'];
    $user = $m[1];
    if (function_exists('smpro_wpguard_trusted') && smpro_wpguard_trusted($path)) return ['ok' => false, 'msg' => 'Refused: this is WP Guard\'s own file.'];
    if (function_exists('smpro_mg_trusted') && smpro_mg_trusted($path)) return ['ok' => false, 'msg' => 'Refused: this is MailGuard\'s own file.'];
    if (is_dir($path)) return ['ok' => false, 'msg' => 'Refused: a folder is reported, not quarantined - open it and quarantine the file that sends.'];
    $safe = function_exists('smpro_path_safe') ? (string)smpro_path_safe($path, [(string)smpro_user_home($user)]) : '';
    if ($safe === '' || !is_file($safe) || is_link($path)) return ['ok' => false, 'msg' => 'Refused: not a regular file inside that account home.'];
    $st = @stat($safe); $sha = (string)@hash_file('sha256', $safe);
    $qd = smpro_lr_dir('quarantine/' . $user); $q = $qd . '/' . date('Ymd-His') . '-' . substr($sha, 0, 12) . '-' . preg_replace('/[^A-Za-z0-9._-]/', '_', basename($safe));
    if (!@copy($safe, $q)) return ['ok' => false, 'msg' => 'Could not keep a copy — nothing was moved.'];
    @chmod($q, 0600);
    $rm = smpro_lr_unlink_locked($safe);
    if (!$rm['ok']) { @unlink($q); return ['ok' => false, 'msg' => 'The file could not be removed: ' . $rm['why'] . '.']; }
    $rec = ['at' => time(), 'orig' => $safe, 'kept' => $q, 'sha' => $sha, 'size' => (int)($st['size'] ?? 0), 'mode' => (int)($st['mode'] ?? 0) & 07777, 'uid' => (int)($st['uid'] ?? 0), 'gid' => (int)($st['gid'] ?? 0), 'mtime' => (int)($st['mtime'] ?? 0), 'source' => $source, 'restored' => 0];
    @file_put_contents(smpro_lr_dir() . '/quarantine.jsonl', json_encode($rec, JSON_UNESCAPED_SLASHES) . "\n", FILE_APPEND | LOCK_EX);
    smpro_lr_drop_finding($safe);   // the row leaves the list now, not at the next hunt
    smpro_lr_learn_file($q, $safe, 'quarantine');
    if (function_exists('smpro_audit')) smpro_audit('learn_quarantine', ['path' => $safe, 'sha256' => $sha, 'kept' => $q, 'source' => $source]);
    return ['ok' => true, 'msg' => 'Moved to the root-only store (Restore puts it back).' . ($rm['relocked'] ? ' The folder was locked; it was unlocked for the move and locked again.' : ''), 'kept' => $q];
}
/** Take one path out of the findings cache (after a quarantine, or when the file is found gone). */
function smpro_lr_drop_finding(string $path): void {
    $F = smpro_lr_load('findings'); if (empty($F['findings'])) return;
    $n = count($F['findings']);
    $F['findings'] = array_values(array_filter((array)$F['findings'], fn($f) => (string)($f['path'] ?? '') !== $path));
    if (count($F['findings']) !== $n) smpro_lr_save('findings', $F);
}
function smpro_lr_quarantined(int $limit = 200): array {
    $rows = []; foreach (array_reverse(@file(smpro_lr_dir() . '/quarantine.jsonl', FILE_IGNORE_NEW_LINES) ?: []) as $l) { $r = json_decode($l, true); if (is_array($r)) $rows[] = $r; if (count($rows) >= $limit) break; }
    return $rows;
}
/** Put a quarantined file back and record it as a false positive (its exact file is never reported again). */
function smpro_lr_restore(string $kept): array {
    $all = @file(smpro_lr_dir() . '/quarantine.jsonl', FILE_IGNORE_NEW_LINES) ?: []; $hit = null; $out = [];
    foreach ($all as $l) { $r = json_decode($l, true); if (is_array($r) && $r['kept'] === $kept && empty($r['restored']) && $hit === null) { $hit = $r; $r['restored'] = time(); } $out[] = json_encode($r, JSON_UNESCAPED_SLASHES); }
    if ($hit === null || !is_file($kept)) return ['ok' => false, 'msg' => 'Nothing to restore.'];
    if (file_exists($hit['orig'])) return ['ok' => false, 'msg' => 'A file already exists at the original place; nothing was overwritten.'];
    if (!preg_match('#^/home[0-9]*/([^/]+)/#', $hit['orig'], $m) || !is_dir(dirname($hit['orig'])) || is_link(dirname($hit['orig']))) return ['ok' => false, 'msg' => 'The original folder is gone.'];
    // the folder may be locked (chattr +i by Safety Lock / WP Guard) exactly like it was when the file was taken out:
    // lift the flag for the one write and put it back as it was, the same way the quarantine did
    $dir = dirname($hit['orig']); $flags = smpro_lr_attrs($dir);
    if ($flags !== '') @exec('chattr -i -a ' . escapeshellarg($dir) . ' 2>/dev/null');
    $wrote = @copy($kept, $hit['orig']);
    if ($flags !== '') @exec('chattr +' . $flags . ' ' . escapeshellarg($dir) . ' 2>/dev/null');
    if (!$wrote) return ['ok' => false, 'msg' => 'Could not write the file back' . ($flags !== '' ? ' - the folder ' . $dir . ' is locked (chattr +' . $flags . ') and could not be unlocked' : ' - the folder ' . $dir . ' is not writable by root') . '.'];
    @chown($hit['orig'], $hit['uid']); @chgrp($hit['orig'], $hit['gid']); @chmod($hit['orig'], $hit['mode'] ?: 0644); @touch($hit['orig'], $hit['mtime'] ?: time());
    @file_put_contents(smpro_lr_dir() . '/quarantine.jsonl', implode("\n", $out) . "\n", LOCK_EX);
    smpro_lr_mark_fp($hit['sha']);
    return ['ok' => true, 'msg' => 'Put back, and remembered as not malicious.' . ($flags !== '' ? ' The folder was locked; it was unlocked for the write and locked again.' : '')];
}
/** "Not malicious": this exact file is never reported again; every lesson it fed loses trust and switches off at 2. */
function smpro_lr_mark_fp(string $sha): void {
    if ($sha === '') return;
    $a = smpro_lr_load('allow'); if (!in_array($sha, $a, true)) { $a[] = $sha; smpro_lr_save('allow', array_slice($a, -5000)); }
    $L = smpro_lr_lessons();
    foreach ($L as $id => $l) {
        $fed = false; foreach ($l['incidents'] as $i) if (($i['sha'] ?? '') === $sha) $fed = true;
        if ($l['type'] === 'hash' && strpos($l['key'], $sha . ':') === 0) { $L[$id]['state'] = 'off'; $L[$id]['fp']++; continue; }
        if ($fed || $l['type'] !== 'hash') {
            // a lesson that matched this file in the last hunt also loses trust
            foreach ((smpro_lr_load('findings')['findings'] ?? []) as $f) if (($f['sha'] ?? '') === $sha && in_array($id, $f['lessons'], true)) $fed = true;
            if ($fed) { $L[$id]['fp']++; if ($L[$id]['fp'] >= 2) $L[$id]['state'] = 'off'; }
        }
    }
    smpro_lr_save('lessons', $L);
}

/* ---------------- processes a file scan cannot see ---------------- */
function smpro_lr_procs(): array {
    $out = [];
    $ps = (string)@shell_exec('ps -eo pid=,ppid=,uid=,etimes=,comm=,args= 2>/dev/null');
    $rows = [];
    foreach (explode("\n", $ps) as $l) if (preg_match('/^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(.*)$/', $l, $m)) $rows[(int)$m[1]] = ['pid' => (int)$m[1], 'ppid' => (int)$m[2], 'uid' => (int)$m[3], 'age' => (int)$m[4], 'comm' => $m[5], 'args' => $m[6]];
    $webParent = function (int $pid) use ($rows): bool { for ($i = 0, $p = $rows[$pid]['ppid'] ?? 0; $i < 6 && $p > 1 && isset($rows[$p]); $i++, $p = $rows[$p]['ppid']) if (preg_match('/^(php-cgi|php-fpm|lsphp|httpd|apache2|litespeed|php)/', $rows[$p]['comm'])) return true; return false; };
    foreach ($rows as $pid => $r) {
        if ($r['uid'] < 1000 || preg_match('/^(php-cgi|php-fpm|lsphp|php|httpd|dovecot|imap|pop3|exim|crond?)/', $r['comm'])) continue;
        $exe = (string)@readlink("/proc/$pid/exe"); $why = [];
        if ($exe !== '' && stripos($exe, 'memfd:') !== false) $why[] = 'its program runs from memory - there is no file on disk';
        elseif ($exe !== '' && substr($exe, -10) === ' (deleted)') $why[] = 'its program file was deleted after it started';
        $a0 = (string)strtok($r['args'], ' ');
        if ($exe !== '' && $a0 !== '' && $a0[0] === '/' && stripos($exe, 'memfd:') === false && basename($a0) !== basename(preg_replace('/ \(deleted\)$/', '', $exe)) && @realpath($a0) !== preg_replace('/ \(deleted\)$/', '', $exe)) $why[] = 'it calls itself ' . basename($a0) . ' but its program is ' . basename($exe);
        if ($r['age'] > 3600 && $webParent($pid) && preg_match('/^(sh|bash|dash|perl|python[0-9.]*|nc|ncat|socat|ruby|node)$/', $r['comm'])) $why[] = 'a web request started it ' . floor($r['age'] / 3600) . ' h ago and it is still running';
        if (!$why) continue;
        $u = function_exists('posix_getpwuid') ? (string)(posix_getpwuid($r['uid'])['name'] ?? $r['uid']) : (string)$r['uid'];
        $out[] = ['pid' => $pid, 'ppid' => $r['ppid'], 'user' => $u, 'age' => $r['age'], 'exe' => $exe, 'cmd' => substr($r['args'], 0, 400), 'why' => $why];
    }
    return $out;
}
function smpro_lr_kill(int $pid): array {
    $p = null; foreach (smpro_lr_procs() as $r) if ($r['pid'] === $pid) $p = $r;
    if (!$p) return ['ok' => false, 'msg' => 'That process is no longer flagged (it ended, or it no longer looks hidden).'];
    $ev = smpro_lr_dir('evidence') . '/proc-' . $pid . '-' . date('Ymd-His') . '.json';
    @file_put_contents($ev, json_encode($p + ['environ_keys' => array_slice(array_map(fn($s) => strtok($s, '='), explode("\0", (string)@file_get_contents("/proc/$pid/environ"))), 0, 60), 'cwd' => (string)@readlink("/proc/$pid/cwd")], JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT)); @chmod($ev, 0600);
    $ok = function_exists('posix_kill') ? @posix_kill($pid, 9) : false;
    if (function_exists('smpro_audit')) smpro_audit('learn_kill', ['pid' => $pid, 'user' => $p['user'], 'cmd' => $p['cmd'], 'ok' => $ok]);
    return ['ok' => (bool)$ok, 'msg' => $ok ? 'Stopped. What it was is kept in ' . $ev : 'Could not stop it.'];
}

/** A new lesson kind only helps if the files already in the store teach it too: relearn them once per schema version. */
function smpro_lr_relearn_store(): int {
    $want = '3'; $f = smpro_lr_dir() . '/schema.ver';
    if (trim((string)@file_get_contents($f)) === $want) return 0;
    $n = 0;
    foreach (smpro_lr_quarantined(2000) as $q) { if (!empty($q['restored']) || !is_file((string)$q['kept'])) continue; smpro_lr_learn_file((string)$q['kept'], (string)$q['orig'], 'relearn'); $n++; }
    @file_put_contents($f, $want);
    return $n;
}
/* ---------------- schedule ---------------- */
/** One tick (every ten minutes): note hidden processes, and hunt when a lesson is new or the last hunt is a day old. */
function smpro_lr_tick(): void {
    smpro_lr_save('procs', ['at' => time(), 'rows' => smpro_lr_procs()]);
    smpro_lr_relearn_store();
    $last = (int)(smpro_lr_load('findings')['at'] ?? 0);
    if (time() - (int)(smpro_lr_load('share')['last'] ?? 0) > 6 * 3600) smpro_lr_share();
    $L = smpro_lr_lessons();
    if ($L && (is_file(smpro_lr_dir() . '/hunt_wanted') || time() - $last > 86400)) smpro_lr_hunt(500);
}
/** Is a hunt running right now? True while the tick's lock is held (the same lock cron uses), so there is one answer. */
function smpro_lr_hunt_running(): bool {
    $l = (defined('SMPRO_LOCKS') ? SMPRO_LOCKS : SMPRO_VARLIB . '/locks') . '/learn.cron.lock';
    if (!@is_file($l)) return false;
    $fh = @fopen($l, 'r'); if (!$fh) return false;
    $free = @flock($fh, LOCK_EX | LOCK_NB); if ($free) @flock($fh, LOCK_UN); @fclose($fh);
    return !$free;
}
/**
 * Ask for a hunt and start it DETACHED. A hunt walks every site (minutes on a big server); run inside the page's
 * own request it kept the browser "loading" for the whole walk. Now the request returns at once, the worker runs
 * under the same lock as the cron tick (so a cron hunt already running is never doubled - it picks the flag up),
 * and the page shows "hunting now" and refreshes itself until the findings land.
 */
function smpro_lr_hunt_bg(): array {
    @touch(smpro_lr_dir() . '/hunt_wanted');
    if (smpro_lr_hunt_running()) return ['ok' => true, 'started' => false, 'msg' => 'A hunt is already running; it covers the new lesson too. The findings appear here when it finishes - this page refreshes itself.'];
    if (defined('SMPRO_TEST_SRC')) return ['ok' => true, 'started' => true, 'msg' => 'test: no worker started'];
    $bin = SMPRO_BASE . '/bin/learn_tick.php'; if (!is_file($bin)) return ['ok' => false, 'started' => false, 'msg' => 'the hunt worker is missing from this build'];
    $php = function_exists('smpro_php_cli_bin') ? smpro_php_cli_bin() : '/usr/local/cpanel/3rdparty/bin/php';
    $ld  = defined('SMPRO_LOCKS') ? SMPRO_LOCKS : SMPRO_VARLIB . '/locks'; @is_dir($ld) || @mkdir($ld, 0700, true);
    $flock = is_executable('/usr/bin/flock') ? '/usr/bin/flock' : 'flock';
    $cmd = 'nohup ' . $flock . ' -n ' . escapeshellarg($ld . '/learn.cron.lock') . ' timeout 590 nice -n 15 ' . escapeshellarg($php) . ' ' . escapeshellarg($bin) . ' >/dev/null 2>&1 </dev/null &';
    @shell_exec($cmd);
    usleep(500000);   // let the worker take the lock before the page asks whether a hunt runs, so the tile is right on this very response
    return ['ok' => true, 'started' => true, 'msg' => 'Hunt started in the background over every site; the findings appear here when it finishes (a few minutes on a big server) - this page refreshes itself, and you can leave it.'];
}
function smpro_lr_cron_sync() {
    $f = '/etc/cron.d/smpro-learn';
    if (!is_file(SMPRO_BASE . '/bin/learn_tick.php')) { if (is_file($f)) @unlink($f); return; }
    if (defined('SMPRO_TEST_SRC')) return true;
    $php = function_exists('smpro_php_cli_bin') ? smpro_php_cli_bin() : '/usr/local/cpanel/3rdparty/bin/php';
    $ld  = SMPRO_VARLIB . '/locks'; @is_dir($ld) || @mkdir($ld, 0700, true);
    $flock = is_executable('/usr/bin/flock') ? '/usr/bin/flock' : 'flock';
    $want = "# Safety Monitor Pro - Learned Defense: hidden-process check, and a hunt after every new lesson or once a day\n"
          . "*/10 * * * * root $flock -n $ld/learn.cron.lock timeout 590 nice -n 15 $php " . SMPRO_BASE . "/bin/learn_tick.php >/dev/null 2>&1\n";
    if (is_file($f) && (string)@file_get_contents($f) === $want) return true;
    if (function_exists('smpro_cron_install')) return smpro_cron_install($f, $want);
    return @file_put_contents($f, $want) !== false;
}
