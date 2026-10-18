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
    $c = smpro_lr_load('config') + ['auto' => 'report', 'recent_days' => 30];
    if (!in_array($c['auto'], ['report', 'quarantine_exact'], true)) $c['auto'] = 'report';
    return $c;
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
    $tags = smpro_lr_tags((string)@file_get_contents($read, false, null, 0, 1048576));
    $code0 = (string)@file_get_contents($read, false, null, 0, 1048576);
    if (smpro_lr_tags_strong($tags, $code0) !== '') $ids[] = smpro_lr_lesson_add($L, 'behaviour', implode('+', $tags), 'Code that ' . smpro_lr_tags_strong($tags, $code0) . ' (' . implode(', ', $tags) . ')', $inc);
    smpro_lr_save('lessons', $L);
    @touch(smpro_lr_dir() . '/hunt_wanted');
    if (function_exists('smpro_audit')) smpro_audit('learn_file', ['path' => $where, 'sha256' => $sha, 'lessons' => count($ids), 'source' => $source]);
    return array_values(array_unique($ids));
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
    $t0 = time(); $L = smpro_lr_lessons(); $cfg = smpro_lr_cfg();
    $allow = array_flip(smpro_lr_load('allow'));
    $on = array_filter($L, fn($l) => ($l['state'] ?? 'on') === 'on');
    $hashes = []; $sizes = []; $rels = []; $dots = []; $behav = [];
    foreach ($on as $id => $l) {
        if ($l['type'] === 'hash') { [$h, $s] = explode(':', $l['key']) + ['', '0']; $hashes[$h] = $id; $sizes[(int)$s] = true; }
        elseif ($l['type'] === 'relpath') $rels[$l['key']] = $id;
        elseif ($l['type'] === 'dotdir') { [$dd, $ext] = explode(':', $l['key']) + ['', '']; $dots[$dd . ':' . $ext] = $id; }
        elseif ($l['type'] === 'behaviour') $behav[$l['key']] = $id;
    }
    $found = []; $done = 0; $partial = false;
    $add = function (string $p, string $user, string $lid, string $why) use (&$found, $allow) {
        if (function_exists('smpro_wpguard_trusted') && smpro_wpguard_trusted($p)) return;
        $sha = (string)@hash_file('sha256', $p); if ($sha !== '' && isset($allow[$sha])) return;
        if (!isset($found[$p])) $found[$p] = ['path' => $p, 'user' => $user, 'sha' => $sha, 'size' => (int)@filesize($p), 'mtime' => (int)@filemtime($p), 'lessons' => [], 'why' => []];
        if (!in_array($lid, $found[$p]['lessons'], true)) { $found[$p]['lessons'][] = $lid; $found[$p]['why'][] = $why; }
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
        foreach (smpro_lr_candidates($root, (int)$cfg['recent_days']) as $p) {
            if (is_link($p)) continue;
            $sz = (int)@filesize($p);
            if (isset($sizes[$sz])) { $h = (string)@hash_file('sha256', $p); if (isset($hashes[$h])) $add($p, $user, $hashes[$h], 'the exact file of a confirmed incident'); }
            $rel = substr($p, strlen($root) + 1); $first = explode('/', $rel)[0]; $ext = strtolower((string)pathinfo($p, PATHINFO_EXTENSION));
            if ($first !== '' && $first[0] === '.' && strpos($rel, '/') !== false && isset($dots[$first . ':' . $ext])) $add($p, $user, $dots[$first . ':' . $ext], "a .$ext script inside $first/");
            if ($behav && $sz < 1048576) {
                $code1 = (string)@file_get_contents($p, false, null, 0, 1048576); $tags = smpro_lr_tags($code1);
                $s = smpro_lr_tags_strong($tags, $code1);
                if ($s !== '') foreach ($behav as $key => $lid) { if (!array_diff(explode('+', $key), $tags)) { $add($p, $user, $lid, 'code that ' . $s); break; } }
            }
        }
        $homes[$user] = true;
    }
    // scripts left in an account's temporary folders (an upload that was never cleaned up runs from there too)
    foreach (array_keys($homes) as $u) {
        $h = function_exists('smpro_user_home') ? (string)smpro_user_home($u) : ''; if ($h === '') continue;
        foreach ([$h . '/tmp', $h . '/.cagefs/tmp'] as $td) foreach (glob($td . '/*.php') ?: [] as $p) {
            if (is_link($p) || !is_file($p)) continue;
            $code2 = (string)@file_get_contents($p, false, null, 0, 1048576); $tags = smpro_lr_tags($code2); $s = smpro_lr_tags_strong($tags, $code2);
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
        foreach ($res['findings'] as $f) foreach ($f['lessons'] as $lid) if (($L[$lid]['type'] ?? '') === 'hash') { smpro_lr_quarantine($f['path'], 'auto: exact file of a confirmed incident'); break; }
    }
    return $res;
}

/* ---------------- quarantine ---------------- */
function smpro_lr_quarantine(string $path, string $source): array {
    if (!preg_match('#^/home[0-9]*/([^/]+)/#', $path, $m)) return ['ok' => false, 'msg' => 'Only files inside an account home.'];
    $user = $m[1];
    if (function_exists('smpro_wpguard_trusted') && smpro_wpguard_trusted($path)) return ['ok' => false, 'msg' => 'Refused: this is WP Guard\'s own file.'];
    $safe = function_exists('smpro_path_safe') ? (string)smpro_path_safe($path, [(string)smpro_user_home($user)]) : '';
    if ($safe === '' || !is_file($safe) || is_link($path)) return ['ok' => false, 'msg' => 'Refused: not a regular file inside that account home.'];
    $st = @stat($safe); $sha = (string)@hash_file('sha256', $safe);
    $qd = smpro_lr_dir('quarantine/' . $user); $q = $qd . '/' . date('Ymd-His') . '-' . substr($sha, 0, 12) . '-' . preg_replace('/[^A-Za-z0-9._-]/', '_', basename($safe));
    if (!@copy($safe, $q)) return ['ok' => false, 'msg' => 'Could not keep a copy — nothing was moved.'];
    @chmod($q, 0600);
    @exec('chattr -i ' . escapeshellarg($safe) . ' 2>/dev/null');
    if (!@unlink($safe)) { @unlink($q); return ['ok' => false, 'msg' => 'The file could not be removed (immutable or permissions).']; }
    $rec = ['at' => time(), 'orig' => $safe, 'kept' => $q, 'sha' => $sha, 'size' => (int)($st['size'] ?? 0), 'mode' => (int)($st['mode'] ?? 0) & 07777, 'uid' => (int)($st['uid'] ?? 0), 'gid' => (int)($st['gid'] ?? 0), 'mtime' => (int)($st['mtime'] ?? 0), 'source' => $source, 'restored' => 0];
    @file_put_contents(smpro_lr_dir() . '/quarantine.jsonl', json_encode($rec, JSON_UNESCAPED_SLASHES) . "\n", FILE_APPEND | LOCK_EX);
    smpro_lr_learn_file($q, $safe, 'quarantine');
    if (function_exists('smpro_audit')) smpro_audit('learn_quarantine', ['path' => $safe, 'sha256' => $sha, 'kept' => $q, 'source' => $source]);
    return ['ok' => true, 'msg' => 'Moved to the root-only store (Restore puts it back).', 'kept' => $q];
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
    if (!@copy($kept, $hit['orig'])) return ['ok' => false, 'msg' => 'Could not write the file back.'];
    @chown($hit['orig'], $hit['uid']); @chgrp($hit['orig'], $hit['gid']); @chmod($hit['orig'], $hit['mode'] ?: 0644); @touch($hit['orig'], $hit['mtime'] ?: time());
    @file_put_contents(smpro_lr_dir() . '/quarantine.jsonl', implode("\n", $out) . "\n", LOCK_EX);
    smpro_lr_mark_fp($hit['sha']);
    return ['ok' => true, 'msg' => 'Put back, and remembered as not malicious.'];
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

/* ---------------- schedule ---------------- */
/** One tick (every ten minutes): note hidden processes, and hunt when a lesson is new or the last hunt is a day old. */
function smpro_lr_tick(): void {
    smpro_lr_save('procs', ['at' => time(), 'rows' => smpro_lr_procs()]);
    $last = (int)(smpro_lr_load('findings')['at'] ?? 0);
    $L = smpro_lr_lessons();
    if ($L && (is_file(smpro_lr_dir() . '/hunt_wanted') || time() - $last > 86400)) smpro_lr_hunt(500);
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
