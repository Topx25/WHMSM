<?php
/**
 * phlock.php — the privileged half of file protection: reading and setting the immutable attribute.
 *
 * These lived in modules/php-harden.php, and a page module cannot be required from cron: it runs its router at
 * include time. bin/sp_queue.php is the worker that actually carries out the protect and release requests
 * accounts make from cPanel, it needs exactly these functions, and its own comment claimed they had already been
 * moved here. They had not. The worker's guard refused to run rather than reporting requests as handled without
 * handling them — which is the right refusal, and it meant Site Protection performed nothing at all on a live
 * server for 29 hours while the page went on offering the feature.
 *
 * WHY NOT includes/phstack.php. That file is copied wholesale into the ACCOUNT-side plugin by
 * build/gen-cpuser-stack.php. Detection — which application is in this web root, which of its files matter — is
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
 * One process per file cost four processes per file — `command -v chattr`, `chattr`, `command -v lsattr`,
 * `lsattr` — measured at ~12ms each on a cPanel box: locking 200 files took 2.4 seconds of almost pure process
 * spawning, against 29ms for the same work batched. It also made force-unprotect quietly INCOMPLETE, because its
 * time budget was spent forking: the sweep stopped after a few thousand files and reported that it had.
 *
 * Success is decided by READING THE ATTRIBUTE BACK, never by an exit code — chattr returns non-zero when any one
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
        $after = smpro_ph_locked_map($todo);
        foreach ($todo as $p) {
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

/** Batch lock-status for many paths → [path => bool]. */
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
            foreach ($parts as $part) if (strpos($part, '/home/') === 0 && is_dir($part)) {
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
    // equal — "yes, that is inside the user's home" for two values that name nothing at all.
    $h = smpro_ph_home($u);
    if ($h === '' || (string)$path === '') return false;
    $home = realpath($h); $real = realpath($path);
    return $home && $real && ($real === $home || strpos($real, $home . '/') === 0);
}

}
