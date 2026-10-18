<?php
/**
 * Safety Monitor Pro — the account-side request queue.
 *
 * The account page cannot set the immutable bit: chattr is root's. So the page does not try. It writes a REQUEST
 * into the account's own home, and a root worker reads the request and performs the work. This is the shape the
 * legacy plugin on the customer's own server already uses ("temporary unlock is auto re-locked by cron"), and it
 * is a better fit than a cPanel admin binary for one reason: an admin binary is a root entry point the account
 * can call directly and synchronously, while a queue is root reading a file at its own pace, on its own terms.
 *
 * The whole security of this rests on one decision: THE REQUEST NEVER CONTAINS A PATH.
 *
 * If the account could name the file, a compromised account would name /etc/shadow, or point a symlink at it, and
 * root would obligingly lock or unlock whatever it was handed. Instead a request carries a verb from a fixed list
 * and nothing else. Root resolves the account's own document roots itself, detects the application itself, and
 * decides which files that verb applies to. The account chooses WHAT SHOULD HAPPEN; root chooses WHERE.
 *
 * The queue lives in the account's own home rather than a shared spool directory. A shared directory writable by
 * every account is a place where one account can overwrite, read, or delete another's requests; a per-home queue
 * gets that isolation for free from ordinary Unix permissions, and cPanel already guarantees it.
 *
 * Everything root does here is also constrained by the two registries in ph_ignore.php: an account the operator
 * force-unprotected is refused, and a path someone permanently unlocked is never re-locked. The customer asking
 * does not outrank the operator's decision.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

/** The verbs an account may ask for. Anything else is refused without being executed. */
function smpro_spq_verbs() {
    return [
        'apply_fast'       => 'Lock the detected application\'s critical files',
        'apply_custom'     => 'Lock the files and folders the account chose',
        'unlock_selected'  => 'Release the chosen items for one hour, then lock them again',
        'unlock_permanent' => 'Release the chosen items and stop protecting this account',
    ];
}

/**
 * Which verbs run on their own, and which wait for the operator.
 *
 * Protecting runs immediately; releasing does not. An account can always make itself SAFER without asking anyone,
 * and refusing that would be friction with no security behind it — nothing bad happens when a customer locks
 * their own files. Taking protection away is the opposite: an account able to release itself is an account that
 * can switch its own protection off the moment somebody breaks into it, which would make the whole thing
 * decorative. The asymmetry is deliberate and runs in exactly one direction.
 */
function smpro_spq_needs_approval($verb) {
    return in_array((string)$verb, ['unlock_selected', 'unlock_permanent'], true);
}

/**
 * Exclusion requests waiting for a decision.
 *
 * An account may ASK to be excluded; it may never exclude itself. The difference is the whole point: a compromised
 * account that could add itself to the ignore list would simply switch its own protection off, and the list would
 * mean nothing. So this queue only records the ask — the operator decides in WHM, and only that decision writes to
 * the real ignore list.
 */
function smpro_spq_asks_path() { return SMPRO_VARLIB . '/php_harden/ignore_requests.json'; }

function smpro_spq_asks_all() {
    $j = json_decode((string)@file_get_contents(smpro_spq_asks_path()), true);
    if (!is_array($j)) return [];
    $out = [];
    foreach ($j as $u => $row) {
        if (!is_array($row) || !preg_match('/^[a-zA-Z0-9._-]{1,64}$/', (string)$u)) continue;
        $out[$u] = ['user' => (string)$u, 'reason' => (string)($row['reason'] ?? ''),
                    'verb' => (string)($row['verb'] ?? 'unlock_permanent'), 'root' => (string)($row['root'] ?? ''),
                    'items' => array_values(array_filter((array)($row['items'] ?? []), 'is_string')),
                    'claimed_ip' => (string)($row['claimed_ip'] ?? ''),
                    'at' => (string)($row['at'] ?? '')];
    }
    ksort($out);
    return $out;
}

function smpro_spq_asks_save(array $list) {
    $d = dirname(smpro_spq_asks_path());
    @is_dir($d) || @mkdir($d, 0700, true);
    $tmp = smpro_spq_asks_path() . '.tmp';
    if (@file_put_contents($tmp, json_encode($list, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX) === false) return false;
    @chmod($tmp, 0600);
    return @rename($tmp, smpro_spq_asks_path());
}

/** Record (or replace) one account's pending ask, together with what it is asking for. */
function smpro_spq_ask_add($user, $reason, $verb = 'unlock_permanent', $root = '', array $items = [], $claimedIp = '') {
    if (!preg_match('/^[a-zA-Z0-9._-]{1,64}$/', (string)$user)) return false;
    $clean = [];
    foreach ($items as $it) {
        $it = trim((string)$it);
        if ($it === '' || $it[0] === '/' || strpos($it, '..') !== false) continue;
        $clean[] = $it;
        if (count($clean) >= 200) break;
    }
    $list = smpro_spq_asks_all();
    $ip = filter_var((string)$claimedIp, FILTER_VALIDATE_IP) ? (string)$claimedIp : '';
    // Account-written text crossing into a root-owned store: bounded and printable only (the account page's own
    // 200-char filter is a courtesy the account can bypass by writing the request file directly).
    $reason = mb_substr(preg_replace('/[^\P{C}\t]/u', '', (string)$reason) ?? '', 0, 200);
    $verb = in_array((string)$verb, ['unlock_permanent', 'unlock_hour', 'ignore', 'relock'], true) ? (string)$verb : 'unlock_permanent';
    $root = substr(preg_replace('/[^\x20-\x7e]/', '', (string)$root), 0, 512);
    $list[(string)$user] = ['user' => (string)$user, 'reason' => (string)$reason, 'verb' => (string)$verb,
                            'root' => (string)$root, 'items' => $clean, 'claimed_ip' => $ip, 'at' => date('c')];
    return smpro_spq_asks_save($list);
}

/** Clear it once the operator has decided, either way. */
function smpro_spq_ask_clear($user) {
    $list = smpro_spq_asks_all();
    if (!isset($list[(string)$user])) return false;
    unset($list[(string)$user]);
    return smpro_spq_asks_save($list);
}

/*
 * The most a request file may be. 200 items (the page's own ceiling) at a generous 300 bytes each, with room for
 * the reason. Bounded so a large file cannot stall the worker; sized so a real request can never hit it - the
 * old value, 4,096, was hit by any selection over roughly 100 files.
 */
if (!defined('SMPRO_SPQ_MAX_BYTES')) define('SMPRO_SPQ_MAX_BYTES', 65536);

function smpro_spq_dir($home)  { return rtrim($home, '/') . '/.siteprotection'; }
function smpro_spq_reqdir($home) { return smpro_spq_dir($home) . '/requests'; }

/**
 * Where root keeps what root must not lose.
 *
 * The re-lock deadline used to live in the account's home, which was wrong and provably so: the account owns the
 * parent directory, so it can rename or replace the whole thing and the deadline simply disappears. Tested on a
 * real account — `mv ~/.siteprotection ~/.sp_real` succeeds, and after it a one-hour unlock never ends. A promise
 * that the site will be protected again in an hour cannot be stored where the site's owner can delete it.
 */
function smpro_spq_state_path() { return SMPRO_VARLIB . '/php_harden/sp_queue_state.json'; }

/** One lock for every writer of the relock state: the page granting an hour and the worker relocking must never
 *  interleave their read-modify-write, or the granted deadline is overwritten by a stale copy and the files stay
 *  unlocked for good. Blocking: a grant waits the few seconds a relock pass takes. */
function smpro_spq_state_lock() {
    $d = dirname(smpro_spq_state_path()); @is_dir($d) || @mkdir($d, 0700, true);
    $h = @fopen(smpro_spq_state_path() . '.lock', 'c'); if (!$h) return null;
    @chmod(smpro_spq_state_path() . '.lock', 0600);
    if (!@flock($h, LOCK_EX)) { @fclose($h); return null; }
    return $h;
}
function smpro_spq_state_unlock($h): void { if ($h) { @flock($h, LOCK_UN); @fclose($h); } }
function smpro_spq_state_load() {
    $j = json_decode((string)@file_get_contents(smpro_spq_state_path()), true);
    return is_array($j) ? $j : [];
}
function smpro_spq_state_save(array $st) {
    $d = dirname(smpro_spq_state_path());
    @is_dir($d) || @mkdir($d, 0700, true);
    $tmp = smpro_spq_state_path() . '.tmp';
    if (@file_put_contents($tmp, json_encode($st, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX) === false) return false;
    @chmod($tmp, 0600);
    return @rename($tmp, smpro_spq_state_path());
}

/**
 * The account's real home, and proof that its queue directory is genuinely a directory it owns.
 *
 * Two things are checked because both were reachable. A home directory is read from the system's own record
 * rather than assumed to be /home/<user>, since a server with a second home partition would otherwise be served
 * silently by a worker that found no queues and reported success. And `.siteprotection` must not be a symlink:
 * the account can replace it with a link to anywhere, and root would then create directories and write files at
 * the far end of it. Tested — the account can do this, so it is refused here rather than trusted.
 *
 * Returns '' when the account's queue must not be touched.
 */
function smpro_spq_safe_home($user) {
    if (!function_exists('posix_getpwnam')) return '';
    $pw = @posix_getpwnam((string)$user);
    $home = is_array($pw) ? (string)($pw['dir'] ?? '') : '';
    if ($home === '' || $home === '/' || strpos($home, '/') !== 0) return '';

    $ls = @lstat($home);
    if (!$ls || ($ls['mode'] & 0170000) !== 0040000) return '';        // must be a real directory, not a link
    if ((int)$ls['uid'] !== (int)($pw['uid'] ?? -1)) return '';        // and the account's own

    $sp = smpro_spq_dir($home);
    if (file_exists($sp) || is_link($sp)) {
        $sl = @lstat($sp);
        if (!$sl) return '';
        if (($sl['mode'] & 0170000) !== 0040000) return '';            // a symlink (or a file) where the queue belongs
        if ((int)$sl['uid'] !== (int)($pw['uid'] ?? -1)) return '';
    }
    return $home;
}

/**
 * Read one account's pending requests.
 *
 * Everything here treats the account's home as hostile territory, because a compromised account owns it: no
 * symlink is followed, nothing outside the queue directory is read, the file must be a plain file owned by that
 * account, and the size is capped so a large file cannot be used to stall the worker.
 */
function smpro_spq_read($user, $home, $max = 10) {
    $dir = smpro_spq_reqdir($home);
    if (!is_dir($dir) || is_link($dir)) return [];

    // The queue directory itself must belong to the account. A directory root created, or one moved in from
    // elsewhere, is not something to act on.
    $st = @lstat($dir);
    $uid = smpro_spq_uid($user);
    if (!$st || $uid === null || (int)$st['uid'] !== $uid) return [];

    $out = [];
    foreach (scandir($dir) ?: [] as $e) {
        if ($e === '.' || $e === '..' || substr($e, -5) !== '.json') continue;
        if (!preg_match('/^[a-f0-9]{8,40}\.json$/', $e)) continue;      // our own naming, nothing else
        $p = $dir . '/' . $e;
        $ls = @lstat($p);
        // Regular files only, never a symlink. This compared ONE bit (0100000) and a symlink's type, 0120000, has
        // that bit set - so a symlink in the queue passed as a regular file and root followed it to read
        // whatever the account pointed it at. Caught by the test that put a symlink there. The whole type field
        // is compared now, the way the directory checks above already did.
        if (!$ls || ($ls['mode'] & 0170000) !== 0100000) continue;
        if ((int)$ls['uid'] !== $uid) continue;                          // must be the account's own file
        /*
         * From here on the file is the account's own, in the account's own queue, and a plain file. Anything wrong
         * with it is now ANSWERED and consumed, not skipped.
         *
         * It was skipped. The cap was 4,096 bytes, the page lets a customer pick up to 200 items, and 200 relative
         * paths are about 8 KB. So a customer who selected a whole folder wrote a request the worker refused to
         * read - silently, every minute, for ever. And because the page allows one request at a time, every request
         * after it was refused too: "A request is already waiting with your host." Two accounts on a production
         * server were stuck exactly like that when this was found; the customers saw "sent", root saw nothing.
         *
         * A file the account cannot have written honestly (a symlink, a foreign owner, a directory) is still
         * skipped without a trace above, because a hostile home must not be able to make root write into it. But a
         * file that IS theirs and is merely too big or malformed is a request that failed, and a failed request
         * gets an answer.
         */
        $reject = '';
        $j = null;
        if ((int)$ls['size'] > SMPRO_SPQ_MAX_BYTES) {
            $reject = 'The request was too large to read (' . (int)$ls['size'] . ' bytes). Select fewer items and try again.';
        } else {
            $j = json_decode((string)@file_get_contents($p), true);
            if (!is_array($j)) $reject = 'The request file could not be read. Try again from this page.';
        }
        $verb = is_array($j) ? (string)($j['verb'] ?? '') : '';
        if ($reject === '' && !isset(smpro_spq_verbs()[$verb])) $reject = 'That is not something this page can ask for.';
        if ($reject !== '') {
            $out[] = ['file' => $p, 'verb' => ($verb !== '' ? $verb : 'unknown'), 'reject' => $reject,
                      'reason' => '', 'root' => '', 'items' => [], 'unlock' => '', 'ip' => '', 'asked' => '',
                      'id' => basename($e, '.json')];
            if (count($out) >= $max) break;
            continue;
        }

        // Everything the request carries must survive to the part that acts on it. root and items were dropped
        // here at first, so a selection arrived at the worker empty: it locked nothing and reported that the
        // items were unusable, which pointed at the account rather than at this function.
        $out[] = ['file' => $p, 'verb' => $verb, 'reason' => (string)($j['reason'] ?? ''),
                  'root' => (string)($j['root'] ?? ''),
                  'items' => array_values(array_filter((array)($j['items'] ?? []), 'is_string')),
                  'unlock' => (string)($j['unlock'] ?? ''),
                  'ip' => (string)($j['ip'] ?? ''),
                  'asked' => (string)($j['at'] ?? ''), 'id' => basename($e, '.json')];
        if (count($out) >= $max) break;                                  // bounded per run, so one account cannot hog it
    }
    return $out;
}

/** Numeric uid of a cPanel account, or null when it cannot be resolved. */
function smpro_spq_uid($user) {
    if (!function_exists('posix_getpwnam')) return null;
    $pw = @posix_getpwnam((string)$user);
    return is_array($pw) && isset($pw['uid']) ? (int)$pw['uid'] : null;
}

/**
 * Write the outcome back where the page will read it. Never follows a symlink.
 *
 * The directories are handed to the ACCOUNT after being created. Root creating them and keeping them is not a
 * detail: `.siteprotection` is the account's own queue, and a root-owned 0700 directory in the middle of it locks
 * the account out of its own home — the page can then no longer write a request, and the only symptom is a button
 * that quietly does nothing. Seen for real: an account that had never opened the page could not use it at all,
 * because the server had already written an answer there first.
 */
function smpro_spq_answer($home, $id, array $result) {
    $base = smpro_spq_dir($home);
    $dir  = $base . '/results';
    if (is_link($base) || is_link($dir)) return false;

    $owner = null;
    {
        $st = @lstat($home);
        if ($st) $owner = ['uid' => (int)$st['uid'], 'gid' => (int)$st['gid']];
    }
    foreach ([$base, $dir] as $d) {
        if (!is_dir($d)) {
            if (!@mkdir($d, 0700, true)) return false;
            // Give it to whoever owns the home directory it sits in.
            if ($owner) { @chown($d, $owner['uid']); @chgrp($d, $owner['gid']); }
        }
    }
    $p = $dir . '/' . preg_replace('/[^a-f0-9]/', '', (string)$id) . '.json';
    $result['at'] = date('c');
    // The account owns this directory, so a link can appear at any moment: write to an O_EXCL temp (never follows
    // a link), set mode and owner on the temp, then rename over the answer path. No step touches $p by name
    // except the final rename, which replaces whatever is there without following it.
    $tmp = $p . '.' . bin2hex(random_bytes(4)) . '.tmp'; $fh = @fopen($tmp, 'xb');
    if ($fh === false) return false;
    $ok = @fwrite($fh, json_encode($result, JSON_UNESCAPED_SLASHES)) !== false; @fclose($fh);
    if ($ok) { @chmod($tmp, 0644); @chown($tmp, 'root'); $ok = @rename($tmp, $p); }
    if (!$ok) @unlink($tmp);
    return (bool)$ok;
}

/**
 * Which files a verb applies to, decided entirely by root.
 *
 * This is the half the account has no influence over. The document roots come from the server's own record of who
 * owns which domain, the application is detected by reading the root, and the file list is the one the WHM plugin
 * already uses — so the account-side and operator-side sides of this product protect exactly the same files.
 */
function smpro_spq_targets($user) {
    if (!function_exists('smpro_ph_roots') || !function_exists('smpro_ph_detect')) return [];
    $targets = [];
    foreach (smpro_ph_roots($user) as $row) {
        $det = smpro_ph_detect($row['root']);
        foreach (smpro_ph_standard_files($row['root'], $det['key']) as $f) {
            // Refuse anything that is not a plain file genuinely inside the account, whatever the detector said.
            if (!is_file($f['path']) || is_link($f['path'])) continue;
            if (!smpro_ph_inside($user, $f['path'])) continue;
            $targets[] = $f['path'];
        }
    }
    return array_values(array_unique($targets));
}

/**
 * Perform one request. Returns the result recorded for the account to read.
 *
 * Refusals are results too: an account that is excluded, or a file someone permanently unlocked, comes back with
 * the reason rather than a silent no-op. A request that appears to vanish is the thing that makes people press
 * the button again and again.
 */
function smpro_spq_run_one($user, array $req) {
    $verb = (string)$req['verb'];

    if (function_exists('smpro_ph_ign_has') && smpro_ph_ign_has($user, 'auto')) {
        return ['ok' => false, 'verb' => $verb, 'done' => 0,
                'msg' => 'Your host has excluded this account from file protection. Nothing was changed.'];
    }

    // A release is never performed straight from the account's request. It becomes a pending decision, and the
    // operator's own rules are then given a chance to make that decision for them.
    if (smpro_spq_needs_approval($verb)) {
        $ok = smpro_spq_ask_add($user, (string)($req['reason'] ?? ''), $verb,
                                (string)($req['root'] ?? ''), (array)($req['items'] ?? []),
                                (string)($req['ip'] ?? ''));
        if (!$ok) {
            return ['ok' => false, 'verb' => $verb, 'done' => 0,
                    'msg' => 'The request could not be recorded, so your host has NOT seen it. Try again, or contact them directly.'];
        }
        $auto = smpro_spq_try_auto($user);
        if (!empty($auto['done'])) {
            return ['ok' => !empty($auto['ok']), 'verb' => $verb, 'done' => (int)($auto['count'] ?? 0),
                    'msg' => (string)$auto['msg']];
        }
        return ['ok' => true, 'verb' => $verb, 'done' => 0,
                'msg' => 'Your request reached your host. Nothing has changed yet — they decide, and the answer appears here.'];
    }

    $targets = ($verb === 'apply_custom')
        ? smpro_spq_resolve($user, (string)($req['root'] ?? ''), (array)($req['items'] ?? []))
        : smpro_spq_targets($user);

    if (!$targets) {
        return ['ok' => false, 'verb' => $verb, 'done' => 0,
                'msg' => $verb === 'apply_custom'
                    ? 'None of the selected items could be used — they were outside your website folder, were links, or are gone.'
                    : 'No application files were found to act on, so nothing was changed.'];
    }

    $done = 0; $skipped = []; $failed = []; $wanted = [];
    foreach ($targets as $pth) {
        // The operator's decision outranks the customer's request.
        if (function_exists('smpro_ph_perm_has') && smpro_ph_perm_has($pth)) { $skipped[] = basename($pth); continue; }
        $wanted[] = $pth;
    }
    // One batch, verified by reading the attributes back. Per file this used to be four processes.
    $r = smpro_ph_chattr_many('+i', $wanted);
    $done = (int)$r['done'];
    foreach (array_keys($r['failed']) as $p) $failed[] = basename($p);
    foreach ($r['skipped'] as $p) $failed[] = basename($p);

    $msg = $done . ' item(s) are now locked.';
    if ($skipped) $msg .= ' ' . count($skipped) . ' left alone because your host excluded them (' . implode(', ', array_slice($skipped, 0, 4)) . ').';
    if ($failed)  $msg .= ' ' . count($failed) . ' could NOT be locked (' . implode(', ', array_slice($failed, 0, 4)) . ') — those are still unprotected.';
    if ($done)    $msg .= ' Releasing them again has to go through your host.';

    return ['ok' => empty($failed), 'verb' => $verb, 'done' => $done, 'msg' => $msg];
}

/**
 * Turn the account's RELATIVE selections into absolute paths root is willing to touch.
 *
 * This is the boundary. The account chose names; root decides what they mean. The document root comes from the
 * server's own records for this account — the `root` field in the request is only MATCHED against that list, never
 * used as a path. Each item must then resolve inside that document root, be a plain file or directory rather than
 * a link, and belong to the account. Anything else is dropped: a request that argues about paths has already gone
 * wrong, and the safe answer is to do less than asked rather than more.
 */
function smpro_spq_resolve($user, $rootKey, array $items) {
    if (!function_exists('smpro_ph_roots')) return [];

    $root = '';
    $want = realpath((string)$rootKey);
    foreach (smpro_ph_roots($user) as $row) {
        $r = realpath($row['root']);
        if ($r !== false && $want !== false && $r === $want) { $root = $r; break; }
    }
    if ($root === '') return [];                     // not one of this account's document roots

    $uid = smpro_spq_uid($user);
    $out = [];
    foreach ($items as $rel) {
        $rel = trim((string)$rel);
        if ($rel === '' || $rel[0] === '/' || strpos($rel, '..') !== false) continue;

        $pth = $root . '/' . $rel;
        $ls  = @lstat($pth);
        if (!$ls) continue;
        $mode = $ls['mode'] & 0170000;
        if ($mode !== 0100000 && $mode !== 0040000) continue;      // regular file or directory only, never a link
        if ($uid !== null && (int)$ls['uid'] !== $uid) continue;   // must belong to the account

        $real = realpath($pth);
        if ($real === false || ($real !== $root && strpos($real, $root . '/') !== 0)) continue;

        $out[] = $real;
        if (count($out) >= 200) break;
    }
    return array_values(array_unique($out));
}

/**
 * One pass over every account. Returns a summary for the audit log.
 *
 * Accounts come from the server's own user list, never from anything an account wrote, so a request file cannot
 * cause the worker to look at a different account than the one whose home it was found in.
 */
function smpro_spq_run($maxAccounts = 500) {
    $seen = 0; $handled = 0; $accounts = 0;
    $dir = '/var/cpanel/users';
    if (!is_dir($dir)) return ['ok' => false, 'accounts' => 0, 'handled' => 0,
                              'why' => 'This does not look like a cPanel server, so no account queues were read.'];

    foreach (scandir($dir) ?: [] as $user) {
        if ($user === '.' || $user === '..') continue;
        if (!preg_match('/^[a-zA-Z0-9._-]{1,64}$/', $user)) continue;
        if ($accounts++ >= $maxAccounts) break;

        $home = smpro_spq_safe_home($user);
        if ($home === '') continue;              // no home, or a queue directory that is not safe to touch

        foreach (smpro_spq_read($user, $home) as $req) {
            $seen++;
            // A request the reader could not accept is answered with the reason and consumed, so the customer
            // sees why and can send another. Left in place it would block their queue for ever.
            $res = ($req['reject'] ?? '') !== ''
                 ? ['ok' => false, 'verb' => (string)$req['verb'], 'done' => 0, 'msg' => (string)$req['reject']]
                 : smpro_spq_run_one($user, $req);
            smpro_spq_answer($home, $req['id'], $res);
            @unlink($req['file']);                       // consumed, so it cannot be run twice
            $handled++;
            if (function_exists('smpro_audit')) {
                smpro_audit('siteprotection_request', ['user' => $user, 'verb' => $req['verb'],
                                                       'ok' => !empty($res['ok']) ? 1 : 0, 'done' => (int)$res['done']]);
            }
        }
    }
    return ['ok' => true, 'accounts' => $accounts, 'seen' => $seen, 'handled' => $handled, 'why' => ''];
}

/**
 * Give the rules another look at what is still waiting. A request lands once and the rules run once; if the
 * rules were switched on afterwards, or the address lookup was fixed by an update (beta265), or the account
 * signed in from home a minute later, the request would otherwise wait for a person for ever. Every ten minutes
 * per request, quietly; a grant is audited by the grant itself.
 */
function smpro_spq_retry_pending(): int {
    if (!function_exists('smpro_spr_decide')) return 0;
    $asks = smpro_spq_asks_all(); if (!$asks) return 0;
    $st = smpro_spq_state_load(); $last = (array)($st['auto_retry'] ?? []); $now = time(); $granted = 0; $changed = false;
    foreach ($asks as $user => $ask) {
        if (($now - (int)($last[$user] ?? 0)) < 600) continue;
        $last[$user] = $now; $changed = true;
        $r = smpro_spq_try_auto((string)$user, true);
        if (!empty($r['done'])) { $granted++; unset($last[$user]); }
    }
    if ($changed) { foreach ($last as $u => $ts) if (!isset($asks[$u])) unset($last[$u]); $st['auto_retry'] = $last; smpro_spq_state_save($st); }
    return $granted;
}

/**
 * Restore locks whose one-hour unlock has run out.
 *
 * Driven entirely by root's own state file. It used to scan the accounts' home directories for the result it had
 * written there, which meant the account could end its own deadline just by moving a directory it owns.
 */
function smpro_spq_relock_due() {
    $lk = smpro_spq_state_lock();
    $st = smpro_spq_state_load();
    if (!$st) { smpro_spq_state_unlock($lk); return 0; }
    $now = time(); $n = 0; $changed = false;

    foreach ($st as $user => $row) {
        $at = (int)($row['relock_at'] ?? 0);
        if ($at === 0 || $at > $now) continue;
        if (!preg_match('/^[a-zA-Z0-9._-]{1,64}$/', (string)$user)) { unset($st[$user]); $changed = true; continue; }

        $again = [];
        foreach (smpro_spq_targets($user) as $p) {
            if (function_exists('smpro_ph_perm_has') && smpro_ph_perm_has($p)) continue;
            $again[] = $p;
        }
        // Most of these are still locked from before the release, and are skipped without spawning anything.
        $done = (int)smpro_ph_chattr_many('+i', $again)['done'];
        unset($st[$user]); $changed = true; $n++;

        // Tell the account what happened, best effort. If its home is gone or unsafe the re-lock still stands —
        // the protection is what matters, and it is not conditional on being able to leave a note.
        $home = smpro_spq_safe_home($user);
        if ($home !== '') {
            smpro_spq_answer($home, 'relock' . substr(sha1($user . $at), 0, 8), [
                'ok' => true, 'verb' => 'relock', 'done' => $done,
                'msg' => 'The one-hour unlock has ended and ' . $done . ' file(s) are locked again.',
            ]);
        }
        if (function_exists('smpro_audit')) smpro_audit('siteprotection_relock', ['user' => $user, 'locked' => $done]);
    }
    if ($changed) smpro_spq_state_save($st);
    smpro_spq_state_unlock($lk);
    return $n;
}

/** Keep the worker scheduled, the same way every other background job here is kept scheduled. */
function smpro_spq_cron_sync() {
    // A test must never install a live cron. The shared writer refuses too, but a test that loads only
    // this file has no shared writer to refuse - function_exists() is false and the fallback writes
    // /etc/cron.d directly. The lab caught exactly that, restored the file, and went red at random.
    if (defined('SMPRO_TEST_SRC')) return true;
    $f = '/etc/cron.d/smpro-siteprotection';
    if (!is_file(SMPRO_BASE . '/bin/sp_queue.php')) { if (is_file($f)) @unlink($f); return; }
    $php   = smpro_php_cli_bin();
    $ld    = SMPRO_VARLIB . '/locks'; @is_dir($ld) || @mkdir($ld, 0700, true);
    $flock = is_executable('/usr/bin/flock') ? '/usr/bin/flock' : 'flock';
    $desired = "# Safety Monitor Pro — Site Protection: perform the file-lock requests accounts make from cPanel\n"
             // Every minute, not every two. The customer presses Protect and then waits for this worker, so the
             // interval IS the response time they experience. A tick that finds nothing costs one directory read plus
             // a lookup and two stats per account and spawns no process at all, and the file work it does when there
             // IS something is now batched — so halving the wait costs nothing worth measuring. `flock -n` still
             // means a slow run can never overlap the next one.
             . "* * * * * root $flock -n " . $ld . "/sp_queue.cron.lock timeout 120 $php " . SMPRO_BASE . "/bin/sp_queue.php >/dev/null 2>&1\n";
    if (is_file($f) && (string)@file_get_contents($f) === $desired) return;
    smpro_cron_install($f, $desired);
}

/**
 * Give the operator's rules a chance to decide a pending release.
 *
 * Kept separate from the request handling on purpose. Approving is the same work whoever triggers it, and a rule
 * that took a different path through the code from a human's click would drift away from it — the two would stop
 * agreeing about what "approved" means, and only one of them would be tested.
 *
 * Returns ['done'=>bool,'ok'=>bool,'count'=>int,'msg'=>string]. done=false simply means it stays pending.
 */
function smpro_spq_try_auto($user, bool $retry = false) {
    if (!function_exists('smpro_spr_decide')) return ['done' => false];
    $ask = smpro_spq_asks_all()[(string)$user] ?? null;
    if (!$ask) return ['done' => false];

    $d = smpro_spr_decide($user, $ask);
    if (empty($d['auto'])) {
        // Recorded even when nothing happens: an operator looking at a queue deserves to know why the rules did
        // not take it, rather than wondering whether they ran at all. (Not on the periodic retry - once is the record.)
        if (!$retry && function_exists('smpro_audit')) {
            smpro_audit('siteprotection_auto_skipped', ['user' => $user, 'why' => (string)($d['why'] ?? '')]);
        }
        return ['done' => false, 'why' => (string)($d['why'] ?? '')];
    }

    $perm = (string)($ask['verb'] ?? '') !== 'unlock_selected';
    $note = 'granted automatically — ' . (string)($d['why'] ?? '');

    if ($perm) {
        if (!function_exists('smpro_ph_force_unprotect')) return ['done' => false];
        $r = smpro_ph_force_unprotect($user, smpro_ph_profile($user),
                'account request (' . (string)($ask['reason'] ?? '') . ') — ' . $note, 'auto-rule', 'all');
        smpro_spq_ask_clear($user);
        if (function_exists('smpro_audit')) {
            smpro_audit('siteprotection_auto_granted', ['user' => $user, 'kind' => 'permanent',
                                                        'cleared' => (int)$r['cleared'], 'ip' => (string)($d['ip'] ?? ''),
                                                        'cc' => (string)($d['cc'] ?? ''), 'why' => (string)($d['why'] ?? '')]);
        }
        $msg = 'Approved by your host\'s rules: protection removed from ' . $r['cleared'] . ' item(s), and this account will not be protected automatically again.';
        if ($r['stuck']) $msg .= ' ' . count($r['stuck']) . ' item(s) could NOT be released and are still protected.';
        return ['done' => true, 'ok' => !empty($r['ok']), 'count' => (int)$r['cleared'], 'msg' => $msg];
    }

    $paths = smpro_spq_resolve($user, (string)($ask['root'] ?? ''), (array)($ask['items'] ?? []));
    if (!$paths) {
        smpro_spq_ask_clear($user);
        return ['done' => true, 'ok' => false, 'count' => 0,
                'msg' => 'None of the items in the request could be used — they were outside your website folder, were links, or are gone.'];
    }
    $r = smpro_ph_chattr_many('-i', $paths);
    $done = (int)$r['done']; $stuck = [];
    foreach (array_keys($r['failed']) as $p) $stuck[] = basename($p);
    $until = time() + 3600;
    $lk = smpro_spq_state_lock();
    $st = smpro_spq_state_load();
    $st[$user] = ['relock_at' => $until, 'set' => date('c')];
    smpro_spq_state_save($st);
    smpro_spq_state_unlock($lk);
    smpro_spq_ask_clear($user);

    if (function_exists('smpro_audit')) {
        smpro_audit('siteprotection_auto_granted', ['user' => $user, 'kind' => '1h', 'released' => $done,
                                                    'ip' => (string)($d['ip'] ?? ''), 'cc' => (string)($d['cc'] ?? ''),
                                                    'why' => (string)($d['why'] ?? '')]);
    }
    $msg = 'Approved by your host\'s rules: ' . $done . ' item(s) released until ' . date('H:i', $until) . ', then locked again by the server.';
    if ($stuck) $msg .= ' ' . count($stuck) . ' could NOT be released (' . implode(', ', array_slice($stuck, 0, 4)) . ').';
    return ['done' => true, 'ok' => empty($stuck), 'count' => $done, 'msg' => $msg];
}
