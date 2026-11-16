<?php
/**
 * phlock.php - the privileged half of file protection: reading and setting the immutable attribute.
 *
 * These lived in modules/php-harden.php, and a page module cannot be required from cron: it runs its router at
 * include time. bin/sp_queue.php is the worker that actually carries out the protect and release requests
 * accounts make from cPanel, it needs exactly these functions, and its own comment claimed they had already been
 * moved here. They had not. The worker's guard refused to run rather than reporting requests as handled without
 * handling them - which is the right refusal, and it meant Site Protection performed nothing at all on a live
 * server for 29 hours while the page went on offering the feature.
 *
 * WHY NOT includes/phstack.php. That file is copied wholesale into the ACCOUNT-side plugin by
 * build/gen-cpuser-stack.php. Detection - which application is in this web root, which of its files matter - is
 * the same question for both sides and belongs there. chattr is not: an account cannot set an immutable bit, so
 * shipping these to the account side would add surface that can never be used. Root-only work lives here.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

function smpro_ph_home($u) { return smpro_user_home($u); }

function smpro_ph_run($cmd) { $out = []; $rc = 0; @exec($cmd . ' 2>&1', $out, $rc); return [$rc, trim(implode("\n", $out))]; }

/** Is a tool present? Probed ONCE per process. It used to be probed before EVERY file, which cost 2.8ms of
 *  process spawning per file for an answer that cannot change while the request is running. */
function smpro_ph_has($cmd) {
    static $seen = [];
    if (isset($seen[$cmd])) return $seen[$cmd];
    $o = []; $rc = 1; @exec('command -v ' . escapeshellarg($cmd) . ' 2>/dev/null', $o, $rc);
    return $seen[$cmd] = ($rc === 0 && !empty($o));
}

function smpro_ph_chattr($flag, $path) {
    if ($flag !== '+i' && $flag !== '-i') return [1, 'invalid flag'];
    if (!smpro_ph_has('chattr')) return [1, 'chattr not available'];
    if (!file_exists($path) || is_link($path)) return [1, 'missing/symlink skipped'];
    return smpro_ph_run('chattr ' . $flag . ' ' . escapeshellarg($path));   // flag is one of two literals, checked above
}

/**
 * Set or clear the immutable attribute on MANY paths at once, and report what actually happened to each.
 *
 * One process per file cost four processes per file - `command -v chattr`, `chattr`, `command -v lsattr`,
 * `lsattr` - measured at ~12ms each on a cPanel box: locking 200 files took 2.4 seconds of almost pure process
 * spawning, against 29ms for the same work batched. It also made force-unprotect quietly INCOMPLETE, because its
 * time budget was spent forking: the sweep stopped after a few thousand files and reported that it had.
 *
 * Success is decided by READING THE ATTRIBUTE BACK, never by an exit code - chattr returns non-zero when any one
 * path in a batch fails, and a filesystem that does not support attributes accepts the command and changes
 * nothing. Paths that are missing, are symlinks, or are already in the wanted state cost no process at all.
 *
 * Returns ok, done (changed + already correct), changed[], already[], skipped[], failed[path => why].
 */
function smpro_ph_chattr_many($flag, array $paths, $chunk = 200) {
    $res = ['ok' => true, 'done' => 0, 'changed' => [], 'already' => [], 'skipped' => [], 'failed' => []];
    if ($flag !== '+i' && $flag !== '-i') { $res['ok'] = false; return $res; }
    $paths = array_values(array_unique(array_filter(array_map('strval', $paths), fn($p) => $p !== '')));
    if (!$paths) return $res;
    if (!smpro_ph_has('chattr') || !smpro_ph_has('lsattr')) {
        $res['ok'] = false;
        foreach ($paths as $p) $res['failed'][$p] = 'chattr/lsattr are not available on this server';
        return $res;
    }
    $want = ($flag === '+i');

    $live = [];
    foreach ($paths as $p) {                       // a stat costs nothing next to a process
        if (is_link($p) || !file_exists($p)) { $res['skipped'][] = $p; continue; }
        $live[] = $p;
    }
    if (!$live) return $res;

    $before = smpro_ph_locked_map($live);          // re-locking a whole set every hour is the common case
    $todo = [];
    foreach ($live as $p) { if ((bool)($before[$p] ?? false) === $want) $res['already'][] = $p; else $todo[] = $p; }
    if ($todo) {
        foreach (array_chunk($todo, max(1, (int)$chunk)) as $c)
            smpro_ph_run('chattr ' . $flag . ' ' . implode(' ', array_map('escapeshellarg', $c)));
        // A folder in a path can be swapped for a link between the check above and the chattr below, and chattr then
        // locks whatever the link leads to - a system file, or another account's site. What was locked is looked at
        // again: a path under a home that now resolves OUTSIDE that home, or to a file of another account, gets the
        // flag taken off at once and is reported as failed.
        if ($want) foreach ($todo as $p) {
            if (!preg_match('#^(/home[0-9]*/[^/]+)(/|$)#', $p, $hm)) continue;                 // only paths inside a home are judged
            $rp = @realpath($p); if ($rp === false) continue;
            $hr = @realpath($hm[1]); $ho = @fileowner($hm[1]); $fo = @fileowner($rp);
            $inside = $hr !== false && ($rp === $hr || strpos($rp, $hr . '/') === 0);
            if ($inside && ($fo === $ho || $fo === 0)) continue;
            smpro_ph_run('chattr -i ' . escapeshellarg($rp));
            if (function_exists('smpro_audit')) smpro_audit('safetylock_lock_escaped', ['asked' => $p, 'landed' => $rp, 'undone' => 1]);
            $res['failed'][$p] = 'the path led outside the account - the lock was taken off again'; $res['ok'] = false;
        }
        $after = smpro_ph_locked_map($todo);
        foreach ($todo as $p) {
            if (isset($res['failed'][$p])) continue;
            if ((bool)($after[$p] ?? !$want) === $want) $res['changed'][] = $p;
            else { $res['failed'][$p] = $want ? 'the lock did not take' : 'the lock could not be removed'; $res['ok'] = false; }
        }
    }
    $res['done'] = count($res['changed']) + count($res['already']);
    return $res;
}

/** True if a path currently carries the immutable (i) attribute. */
function smpro_ph_locked($path) {
    if (!smpro_ph_has('lsattr') || !file_exists($path)) return false;
    [$rc, $out] = smpro_ph_run('lsattr -d ' . escapeshellarg($path));
    if ($rc !== 0) return false;
    $flags = preg_split('/\s+/', trim($out))[0] ?? '';
    return strpos($flags, 'i') !== false;
}

/** Batch lock-status for many paths -> [path => bool]. */
function smpro_ph_locked_map(array $paths) {
    $map = [];
    foreach ($paths as $p) $map[$p] = false;
    if (!$paths || !smpro_ph_has('lsattr')) return $map;
    foreach (array_chunk($paths, 200) as $chunk) {
        $args = implode(' ', array_map('escapeshellarg', $chunk));
        [$rc, $out] = smpro_ph_run('lsattr -d ' . $args);
        foreach (explode("\n", $out) as $line) {
            // lsattr -d prints: "<flags> <path>"
            if (preg_match('/^([-a-zA-Z]+)\s+(.+)$/', trim($line), $mm)) {
                $flags = $mm[1]; $path = $mm[2];
                if (isset($map[$path])) $map[$path] = strpos($flags, 'i') !== false;
            }
        }
    }
    return $map;
}

/* ---------------- web roots ---------------- */
/**
 * Every immutable (i) or append-only (a) flag under the account's home and web roots, WHOEVER set it - this
 * product's own locks, another product's lockdown, or a hand-run chattr. A directory with +i or +a is the usual
 * reason an account "cannot delete its own file" while every lock this product knows of is already clear: the file
 * is free, the folder it lives in is not. Bounded: a depth, a time limit, and the account's own tree only.
 */
function smpro_ph_sweep_attrs($u, $maxDepth = 4, $seconds = 20) {
    $out = ['found' => [], 'cleared' => [], 'failed' => [], 'root_owned' => 0, 'root_owned_sample' => [], 'complete' => true];
    if (!smpro_ph_has('lsattr') || !smpro_ph_has('chattr') || !smpro_ph_has('find')) { $out['complete'] = false; return $out; }
    $home = smpro_ph_home($u); if ($home === '' || !is_dir($home)) { $out['complete'] = false; return $out; }
    $tops = [$home]; foreach (smpro_ph_roots($u) as $r) $tops[] = (string)$r['root'];
    $tops = array_values(array_unique(array_filter($tops, fn($t) => $t !== '' && is_dir($t) && !is_link($t) && smpro_ph_inside($u, $t))));
    $deadline = microtime(true) + max(3, (int)$seconds);
    foreach ($tops as $top) {
        $left = (int)ceil($deadline - microtime(true)); if ($left <= 0) { $out['complete'] = false; break; }
        // the top itself at depth 0 (lsattr -d), then its tree; -xdev keeps it on one filesystem, no symlink is followed
        [$rc, $txt] = smpro_ph_run('timeout ' . $left . ' find ' . escapeshellarg($top) . ' -xdev -maxdepth ' . (int)$maxDepth . ' \( -type f -o -type d \) -print0 2>/dev/null | timeout ' . $left . ' xargs -0 -r lsattr -d -- 2>/dev/null');
        if ($rc === 124) $out['complete'] = false;
        foreach (explode("\n", $txt) as $line) {
            if (!preg_match('/^(\S+)\s+(\/.*)$/', $line, $m)) continue;
            $flags = $m[1]; $path = $m[2];
            if (strpos($flags, 'i') === false && strpos($flags, 'a') === false) continue;
            if (is_link($path) || !smpro_ph_inside($u, $path)) continue;
            $out['found'][] = $path;
        }
        // files the account does not own inside its own web tree: it can see them but not change them
        $left = (int)ceil($deadline - microtime(true)); if ($left <= 0) { $out['complete'] = false; break; }
        [$rc2, $txt2] = smpro_ph_run('timeout ' . $left . ' find ' . escapeshellarg($top) . ' -xdev -maxdepth ' . (int)$maxDepth . ' -user root \( -type f -o -type d \) -print 2>/dev/null | head -n 2000');
        foreach (array_filter(explode("\n", $txt2)) as $path) { if ($path === $home) continue; $out['root_owned']++; if (count($out['root_owned_sample']) < 10) $out['root_owned_sample'][] = $path; }
    }
    $out['found'] = array_values(array_unique($out['found']));
    foreach (array_chunk($out['found'], 100) as $chunk) smpro_ph_run('chattr -i -a -- ' . implode(' ', array_map('escapeshellarg', $chunk)));
    foreach ($out['found'] as $path) {
        [$rc, $txt] = smpro_ph_run('lsattr -d -- ' . escapeshellarg($path));
        $flags = preg_match('/^(\S+)\s/', $txt, $m) ? $m[1] : '';
        if ($rc === 0 && strpos($flags, 'i') === false && strpos($flags, 'a') === false) $out['cleared'][] = $path; else $out['failed'][$path] = $txt !== '' ? $txt : 'still flagged';
    }
    return $out;
}
function smpro_ph_roots($u) {
    $roots = [];
    $main = smpro_ph_home($u) . '/public_html';
    if (is_dir($main)) $roots[$main] = ['domain' => 'main / public_html', 'root' => $main];
    if (is_readable('/etc/userdatadomains')) {
        foreach (file('/etc/userdatadomains', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
            if (strpos($line, ':') === false || strpos($line, '==') === false) continue;
            [$domain, $rest] = explode(':', $line, 2);
            $parts = array_map('trim', explode('==', $rest));
            if (($parts[0] ?? '') !== $u) continue;
            foreach ($parts as $part) if (preg_match('#^/home\d*/#', (string)$part) && is_dir($part)) {
                $real = realpath($part) ?: $part;
                if (function_exists('smpro_ph_inside') && !smpro_ph_inside($u, $real)) continue;   // a docroot outside this home is not this account's to lock
                $roots[$real] = ['domain' => trim($domain), 'root' => $real];
            }
        }
    }
    ksort($roots);
    return array_values($roots);
}

if (!function_exists('smpro_ph_inside')) {
function smpro_ph_inside($u, $path) {
    // Both strings must be non-empty BEFORE realpath() sees them. realpath('') does not return false: it resolves
    // to the current working directory, so an unknown account (home '') compared against an empty path came back
    // equal - "yes, that is inside the user's home" for two values that name nothing at all.
    $h = smpro_ph_home($u);
    if ($h === '' || (string)$path === '') return false;
    $home = realpath($h); $real = realpath($path);
    return $home && $real && ($real === $home || strpos($real, $home . '/') === 0);
}

}

/* ---- state + release engine (moved from the PHP Harden page) ---------------------------------------------------
 * The Safety Lock queue worker grants a permanent release from cron. It called these while they still lived in the
 * page file, which cron never loads - so an automatic grant quietly did nothing. They are here for that reason. */
defined('SMPRO_PH_STATE') || define('SMPRO_PH_STATE',  SMPRO_VARLIB . '/php_harden');
defined('SMPRO_PH_BACKUP') || define('SMPRO_PH_BACKUP', SMPRO_VARLIB . '/php_harden/backups');
defined('SMPRO_PH_AUDIT') || define('SMPRO_PH_AUDIT',  SMPRO_VARLIB . '/php_harden/audit.log');
function smpro_ph_profile($u) {
    $profile = [];
    foreach (smpro_ph_roots($u) as $row) {
        $det = smpro_ph_detect($row['root']);
        $profile[] = [
            'domain' => $row['domain'], 'root' => $row['root'],
            'det' => $det,
            'files' => smpro_ph_standard_files($row['root'], $det['key']),
            'dirs' => smpro_ph_upload_dirs($row['root'], $det['key']),
        ];
    }
    return $profile;
}
function smpro_ph_manifest_path($u) { return SMPRO_PH_STATE . '/' . preg_replace('/[^a-zA-Z0-9._-]/', '', $u) . '.json'; }
function smpro_ph_load($u) { $p = smpro_ph_manifest_path($u); if (!is_file($p)) return null; $j = json_decode((string)@file_get_contents($p), true); return is_array($j) ? $j : null; }
function smpro_ph_save($u, $m) {
    @is_dir(SMPRO_PH_STATE) || @mkdir(SMPRO_PH_STATE, 0700, true);
    $m['updated_at'] = date('c');
    $tmp = smpro_ph_manifest_path($u) . '.tmp'; if (@file_put_contents($tmp, json_encode($m, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX) === false) return false;
    @chmod($tmp, 0600); return @rename($tmp, smpro_ph_manifest_path($u));
}
function smpro_ph_audit_log($u, $action, $message, $extra = []) {
    @is_dir(SMPRO_PH_STATE) || @mkdir(SMPRO_PH_STATE, 0700, true);
    @file_put_contents(SMPRO_PH_AUDIT, json_encode(['time' => date('c'), 'user' => $u, 'action' => $action, 'message' => $message, 'extra' => $extra], JSON_UNESCAPED_SLASHES) . "\n", FILE_APPEND | LOCK_EX);
}
function smpro_ph_remove_htaccess($dir) {
    $ht = rtrim($dir, '/') . '/.htaccess';
    if (is_link($ht)) return false;                                          // not ours to touch (see smpro_ph_apply_htaccess)
    if (!is_file($ht)) return true;
    smpro_ph_chattr('-i', $ht);
    $content = (string)@file_get_contents($ht);
    $new = preg_replace('/\n?# SMPRO_PH_DENY_EXEC_START.*?# SMPRO_PH_DENY_EXEC_END\s*/s', '', $content);
    if (trim((string)$new) === '') { @unlink($ht); return true; }
    $uid = @fileowner($ht); $gid = @filegroup($ht);
    $tmp = $ht . '.smpro-' . bin2hex(random_bytes(6)); $fh = @fopen($tmp, 'xb');
    $ok = $fh !== false && @fwrite($fh, rtrim((string)$new) . "\n") !== false; if ($fh) @fclose($fh);
    if ($ok) { @chmod($tmp, 0644); if ($uid !== false) { @chown($tmp, $uid); @chgrp($tmp, $gid); } $ok = !is_link($ht) && @rename($tmp, $ht); }
    if (!$ok) @unlink($tmp);
    return (bool)$ok;
}
/**
 * Remove EVERY protection this plugin holds over an account, and record that it must stay removed.
 *
 * The ordinary unlock only touches the paths the browser posted, which is right when an operator is unlocking a
 * few files by hand. It is wrong as a way out of trouble: the caller has to already know what is locked, and a
 * path that was locked but is no longer listed stays locked forever with nothing pointing at it. This takes the
 * opposite approach - it unlocks the union of everything recorded in the manifest and everything the live scan
 * can still see locked, and then reports what it could NOT clear rather than reporting a total.
 *
 * That last part is the point. A file with the immutable bit set on a filesystem that has since been remounted
 * read-only cannot be unlocked, and saying "unprotected" when one file is still locked would send the operator
 * to look somewhere else for a problem that is right here.
 */
function smpro_ph_force_unprotect($u, array $profile, $reason, $by, $scope = 'all') {
    $files = []; $dirs = [];

    // Everything the manifest remembers locking - authoritative, and the only record of paths the current scan
    // no longer proposes (a stack that changed, a folder that was renamed).
    $m = smpro_ph_load($u) ?: [];
    // smpro_ph_apply writes these as protected_files[].path and deny_php_dirs[].dir. Reading 'files'/'dirs'
    // instead would find nothing and still report success - the exact failure this function exists to avoid.
    foreach ((array)($m['protected_files'] ?? []) as $f) { $p = is_array($f) ? (string)($f['path'] ?? '') : (string)$f; if ($p !== '') $files[] = $p; }
    foreach ((array)($m['deny_php_dirs']   ?? []) as $d) { $p = is_array($d) ? (string)($d['dir']  ?? '') : (string)$d; if ($p !== '') $dirs[]  = $p; }
    // A locked document root is cleared with the files: chattr treats a directory the same way, and leaving one
    // set would mean the account still cannot create a file while being told it was released.
    foreach ((array)($m['locked_roots'] ?? []) as $d) { $p = is_array($d) ? (string)($d['dir'] ?? '') : (string)$d; if ($p !== '') $files[] = $p; }
    $pr = $m['pending_relock'] ?? null;
    if (is_array($pr)) {
        foreach ((array)($pr['files'] ?? []) as $p) $files[] = (string)$p;
        foreach ((array)($pr['dirs']  ?? []) as $p) $dirs[]  = (string)$p;
    }
    // Plus whatever the live profile still proposes, so a lock applied by an older build is not missed.
    foreach ($profile as $prof) {
        foreach ((array)($prof['files'] ?? []) as $f) $files[] = (string)$f['path'];
        foreach ((array)($prof['dirs']  ?? []) as $d) $dirs[]  = (string)$d['path'];
    }

    $files = array_values(array_unique(array_filter($files, fn($p) => $p !== '' && smpro_ph_inside($u, $p))));
    $dirs  = array_values(array_unique(array_filter($dirs,  fn($p) => $p !== '' && smpro_ph_inside($u, $p))));

    $r = smpro_ph_chattr_many('-i', $files);   // one batch: gone, symlinked and already-clear paths cost nothing
    // "cleared" used to add the paths that were ALREADY clear, so an account with nothing locked reported
    // "12 item(s) cleared" and read as if something had re-protected it. Only real changes count now, and the
    // message says how many were already clear.
    $unlocked = count($r['changed']); $already = count($r['already']); $guards = 0; $stuck = array_keys($r['failed']);
    foreach ($dirs as $d) {
        if (!is_dir($d) || is_link($d)) continue;
        $ht = rtrim($d, '/') . '/.htaccess';
        $had = is_file($ht) && strpos((string)@file_get_contents($ht), 'SMPRO_PH_DENY_EXEC_START') !== false;
        smpro_ph_remove_htaccess($d);
        // The guard is gone when the file is gone, or when the marked block is no longer inside it.
        $left = is_file($ht) ? (string)@file_get_contents($ht) : '';
        if ($left !== '' && strpos($left, 'SMPRO_PH_DENY_EXEC_START') !== false) $stuck[] = $ht; elseif ($had) $guards++;
    }
    // Then everything this product did NOT set: another product's lockdown, a hand-run chattr, a folder left
    // immutable. "Force" means the account comes back able to manage its own files, whoever locked them.
    $sw = function_exists('smpro_ph_sweep_attrs') ? smpro_ph_sweep_attrs($u) : ['found' => [], 'cleared' => [], 'failed' => [], 'root_owned' => 0, 'root_owned_sample' => [], 'complete' => false];
    $others = count($sw['cleared']); foreach (array_keys($sw['failed']) as $sp) $stuck[] = $sp;
    // Paths another HostGuard product listed as its own: cleared (Force means freed), and that product is asked in
    // writing to release and not re-lock while the account stays excluded.
    if (function_exists('smpro_hg_lock_owner') && $sw['cleared']) {
        $owners = []; foreach ($sw['cleared'] as $cp) { $ow = smpro_hg_lock_owner($u, $cp); if ($ow !== '') $owners[$ow] = 1; }
        if ($owners) { smpro_hg_release_request($u, 'Force unprotect by ' . $by . ': ' . $reason, array_keys($owners)); smpro_hg_event_emit('lock_released', ['account' => $u, 'products' => array_keys($owners), 'paths' => array_slice($sw['cleared'], 0, 20)]); }
    }
    if (function_exists('smpro_hg_event_emit')) smpro_hg_event_emit('account_excluded', ['account' => $u, 'scope' => $scope, 'reason' => mb_substr((string)$reason, 0, 160)]);
    if (function_exists('smpro_hg_locks_write')) smpro_hg_locks_write($u, []);
    $cleared = $unlocked + $guards + $others;

    $m = $m ?: ['version' => 'smpro.ph1', 'user' => $u, 'created_at' => date('c')];
    $m['status'] = 'unlocked';
    $m['unlock_until'] = '';
    unset($m['pending_relock']);
    $m['force_unprotected_at'] = date('c');
    smpro_ph_save($u, $m);

    $listed = smpro_ph_ign_add($u, $reason, $by, $scope);

    smpro_ph_audit_log($u, 'php_harden_force_unprotect',
        'Force unprotect — ' . ($cleared ? ($unlocked . ' lock(s) removed' . ($guards ? ', ' . $guards . ' PHP guard(s) removed' : '') . ($others ? ', ' . $others . ' lock(s) set outside this product removed (' . implode(', ', array_map('basename', array_slice($sw['cleared'], 0, 3))) . (count($sw['cleared']) > 3 ? ', ...' : '') . ')' : '')) : 'nothing was locked') . ($already ? ' · ' . $already . ' path(s) were already clear' : '') . (!$sw['complete'] ? ' · the sweep for other locks did not finish (deep tree); run again' : '') . ($sw['root_owned'] ? ' · ' . $sw['root_owned'] . ' root-owned item(s) inside the web root (the account cannot edit them; e.g. ' . basename((string)$sw['root_owned_sample'][0]) . ')' : '') . ($stuck ? ', ' . count($stuck) . ' could NOT be cleared' : '')
        . ($listed ? ' · added to the ignore list' : ' · COULD NOT be added to the ignore list'),
        ['reason' => $reason, 'by' => $by, 'scope' => $scope, 'stuck' => array_slice($stuck, 0, 20), 'other_locks' => array_slice($sw['cleared'], 0, 50), 'root_owned' => $sw['root_owned'], 'root_owned_sample' => $sw['root_owned_sample']]);
    smpro_audit('php_harden_force_unprotect', ['user' => $u, 'cleared' => $cleared, 'already_clear' => $already, 'stuck' => count($stuck), 'listed' => $listed ? 1 : 0]);

    return ['ok' => empty($stuck) && $listed, 'cleared' => $cleared, 'already' => $already, 'stuck' => $stuck, 'listed' => $listed, 'other_locks' => $sw['cleared'], 'root_owned' => $sw['root_owned']];
}
