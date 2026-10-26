<?php
/**
 * modules/php-harden.php - PHP Harden / Safety Lock (per cPanel account).
 *
 * Smart stack detection (WordPress, Laravel, OpenCart, Joomla, Drupal, Magento,
 * CodeIgniter, generic PHP) + two protection modes:
 *   • Fast Protection  - chattr +i the critical files of the detected stack and
 *     drop+lock a .htaccess "deny exec" guard inside upload/cache/log folders.
 *   • Custom Protection - a file/folder browser with live lock status (lsattr),
 *     lock/unlock selected items, permanent or temporary (auto-relock) unlock.
 *
 * Every mutation is POST + CSRF + root + audit, backs up touched files OUTSIDE
 * the account, and is fully reversible (unlock / restore). Read-only on GET.
 * Isolated state under /var/lib/smpro/php_harden (never touches the legacy plugin).
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

define('SMPRO_PH_STATE',  SMPRO_VARLIB . '/php_harden');
define('SMPRO_PH_BACKUP', SMPRO_VARLIB . '/php_harden/backups');
define('SMPRO_PH_AUDIT',  SMPRO_VARLIB . '/php_harden/audit.log');

/* ---------------- low-level helpers ---------------- */
function smpro_ph_valid_user($u) {
    return $u !== '' && preg_match('/^[a-zA-Z0-9._-]{1,64}$/', $u)
        && is_file('/var/cpanel/users/' . $u) && is_dir(smpro_user_home($u));
}

/** Who is doing this, for the audit trail. smpro_current_actor() returns '' for a web request with no
 *  authenticated WHM user; recording that as 'unknown' is honest, whereas defaulting to root would put a
 *  name on a decision nobody can be shown to have made. */
function smpro_ph_actor() { $a = function_exists('smpro_current_actor') ? smpro_current_actor() : ''; return $a !== '' ? $a : 'unknown'; }
// smpro_ph_inside() lives in includes/phlock.php (the cron worker needs it too; it was defined only here, so the
// worker threw "undefined function" on every protect request and every scheduled re-lock).


/* The file-lock helpers (home/run/has/chattr/chattr_many/locked/locked_map/roots) live in
   includes/phlock.php - bin/sp_queue.php needs them from cron, and a page module cannot be required
   from cron because it runs its router at include time. */

/* ---------------- stack detection ---------------- */
/* Stack detection (read_head / de / fe / php_count / detect / standard_files / upload_dirs) moved to
   includes/phstack.php - the account-side plugin needs the same answer and a second copy would drift. */
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

/* ---------------- custom browser tree (navigable, one level at a time) ---------------- */
/** List a single directory $dir (must be inside the account & under $root). */
function smpro_ph_browser($u, $root, $dir, array $suggestFiles, array $suggestDirs) {
    $dir = $dir ?: $root;
    $dirReal = realpath($dir) ?: $dir;
    // safety: never list outside the account or above the web root
    if (!smpro_ph_inside($u, $dirReal) || strpos($dirReal . '/', rtrim($root, '/') . '/') !== 0 && $dirReal !== rtrim($root, '/')) $dirReal = $root;
    $rows = []; $sf = array_flip($suggestFiles); $sd = array_flip($suggestDirs);
    $atRoot = (rtrim($dirReal, '/') === rtrim($root, '/'));
    try {
        foreach (new DirectoryIterator($dirReal) as $f) {
            if ($f->isDot() || $f->isLink()) continue;
            $path = $f->getPathname();
            $isDir = $f->isDir();
            $name = $f->getFilename();
            $rows[$path] = ['name' => $name, 'path' => $path, 'type' => $isDir ? 'dir' : 'file',
                'size' => $isDir ? null : (int)$f->getSize(), 'mtime' => (int)$f->getMTime(),
                'suggested' => $isDir ? isset($sd[$path]) : isset($sf[$path])];
        }
    } catch (Throwable $e) { if (function_exists('smpro_soft_fail')) smpro_soft_fail(basename(__FILE__) . ':' . __LINE__, $e); }
    // at the web root, also surface suggested standard files/dirs that live deeper
    if ($atRoot) {
        foreach ($suggestFiles as $p) if (!isset($rows[$p]) && is_file($p)) {
            $rows[$p] = ['name' => ltrim(substr($p, strlen($root)), '/'), 'path' => $p, 'type' => 'file', 'size' => (int)@filesize($p), 'mtime' => (int)@filemtime($p), 'suggested' => true];
        }
        foreach ($suggestDirs as $p) if (!isset($rows[$p]) && is_dir($p)) {
            $rows[$p] = ['name' => ltrim(substr($p, strlen($root)), '/') . '/', 'path' => $p, 'type' => 'dir', 'size' => null, 'mtime' => (int)@filemtime($p), 'suggested' => true];
        }
    }
    // lock status (batch). For dirs, the guarded item is the .htaccess inside.
    $statPaths = [];
    foreach ($rows as $r) $statPaths[] = $r['type'] === 'dir' ? rtrim($r['path'], '/') . '/.htaccess' : $r['path'];
    $lockMap = smpro_ph_locked_map(array_values(array_unique(array_filter($statPaths, 'file_exists'))));
    foreach ($rows as $p => &$r) {
        $chk = $r['type'] === 'dir' ? rtrim($p, '/') . '/.htaccess' : $p;
        $r['locked'] = $lockMap[$chk] ?? false;
    }
    unset($r);
    uasort($rows, function ($a, $b) { if ($a['type'] !== $b['type']) return $a['type'] === 'dir' ? -1 : 1; return strcasecmp($a['name'], $b['name']); });
    return array_values($rows);
}
/** Render the <tr> rows for the browser table (shared by initial render + AJAX nav). */
function smpro_ph_browser_rows(array $rows) {
    if (!$rows) return '<tr><td colspan="6" style="text-align:center;padding:18px;color:var(--muted)">This folder is empty.</td></tr>';
    $h = '';
    foreach ($rows as $r) {
        $nameCell = $r['type'] === 'dir'
            ? '&#128193; <a href="#" class="ph-dirnav" data-dir="' . smpro_h($r['path']) . '">' . smpro_h($r['name']) . '</a>'
            : '&#128196; ' . smpro_h($r['name']);
        if (!empty($r['suggested'])) $nameCell .= ' <span class="ph-sugg">suggested</span>';
        $h .= '<tr data-sugg="' . (!empty($r['suggested']) ? 1 : 0) . '" data-name="' . smpro_h(strtolower($r['name'])) . '">'
            . '<td><input type="checkbox" class="ph-chk" data-type="' . $r['type'] . '" value="' . smpro_h($r['path']) . '"' . (!empty($r['suggested']) ? ' data-sugg="1"' : '') . '></td>'
            . '<td class="mono">' . $nameCell . '</td>'
            . '<td>' . ($r['type'] === 'dir' ? '<span class="b gray">dir</span>' : '<span class="b gray">file</span>') . '</td>'
            . '<td class="num mono">' . ($r['type'] === 'dir' ? '—' : smpro_h(number_format(($r['size'] ?? 0) / 1024, 1)) . ' KB') . '</td>'
            . '<td class="mono" style="font-size:11px">' . smpro_h(date('Y-m-d H:i', $r['mtime'])) . '</td>'
            . '<td>' . (!empty($r['locked']) ? '<span class="b red">&#128274; locked</span>' : '<span class="b green">writable</span>') . '</td>'
            . '</tr>';
    }
    return $h;
}

/* ---------------- manifest + backups + audit ---------------- */
function smpro_ph_manifest_path($u) { return SMPRO_PH_STATE . '/' . preg_replace('/[^a-zA-Z0-9._-]/', '', $u) . '.json'; }
function smpro_ph_load($u) { $p = smpro_ph_manifest_path($u); if (!is_file($p)) return null; $j = json_decode((string)@file_get_contents($p), true); return is_array($j) ? $j : null; }
function smpro_ph_save($u, $m) {
    @is_dir(SMPRO_PH_STATE) || @mkdir(SMPRO_PH_STATE, 0700, true);
    $m['updated_at'] = date('c');
    $tmp = smpro_ph_manifest_path($u) . '.tmp'; if (@file_put_contents($tmp, json_encode($m, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX) === false) return false;
    @chmod($tmp, 0600); return @rename($tmp, smpro_ph_manifest_path($u));
}
function smpro_ph_backup($src, $dir) {
    @is_dir($dir) || @mkdir($dir, 0700, true);
    $dst = $dir . '/' . sha1($src) . '_' . preg_replace('/[^a-zA-Z0-9._-]+/', '_', basename($src));
    if (is_file($src) && !is_link($src)) { @copy($src, $dst); @chmod($dst, 0600); }   // a link is never copied: its target is not the account's file
    return $dst;
}
function smpro_ph_audit_log($u, $action, $message, $extra = []) {
    @is_dir(SMPRO_PH_STATE) || @mkdir(SMPRO_PH_STATE, 0700, true);
    @file_put_contents(SMPRO_PH_AUDIT, json_encode(['time' => date('c'), 'user' => $u, 'action' => $action, 'message' => $message, 'extra' => $extra], JSON_UNESCAPED_SLASHES) . "\n", FILE_APPEND | LOCK_EX);
}
function smpro_ph_audit_rows($u, $limit = 40) {
    if (!is_file(SMPRO_PH_AUDIT)) return [];
    $lines = []; @exec('tail -n 300 ' . escapeshellarg(SMPRO_PH_AUDIT) . ' 2>/dev/null', $lines);
    $rows = [];
    foreach (array_reverse($lines) as $line) {
        $j = json_decode($line, true); if (!is_array($j) || ($j['user'] ?? '') !== $u) continue;
        $rows[] = $j; if (count($rows) >= $limit) break;
    }
    return $rows;
}

/* ---------------- .htaccess deny-exec guard ---------------- */
function smpro_ph_allowed_exts(array $exts) {
    $allow = ['php', 'phtml', 'phar', 'php[0-9]', 'shtml', 'html', 'htm', 'js', 'mjs', 'cgi', 'pl', 'py'];
    $out = [];
    foreach ($exts as $e) { $e = strtolower(trim((string)$e)); if (in_array($e, $allow, true)) $out[] = $e; }
    return array_values(array_unique($out ?: ['php', 'phtml', 'phar', 'php[0-9]']));
}
function smpro_ph_htaccess_marker(array $exts) {
    $parts = [];
    foreach (smpro_ph_allowed_exts($exts) as $e) $parts[] = str_replace(['[', ']'], ['\[', '\]'], $e);
    $pattern = '\.(' . implode('|', $parts) . ')$';
    return "\n# SMPRO_PH_DENY_EXEC_START\n"
        . "# Safety Monitor Pro: block executable scripts inside this upload/cache/log folder only.\n"
        . "<FilesMatch \"" . $pattern . "\">\n  Require all denied\n</FilesMatch>\n"
        . "# SMPRO_PH_DENY_EXEC_END\n";
}
function smpro_ph_apply_htaccess($dir, array $exts, $backupDir) {
    $ht = rtrim($dir, '/') . '/.htaccess';
    /*
     * The directory was confined to the account, but the LEAF was not: a customer who plants
     *   ln -s /root/.ssh/authorized_keys public_html/wp-content/uploads/.htaccess
     * would have had root write our marker INTO that file and then chown it to the customer - and the automatic
     * re-lock after a timed unlock did this without any operator click. A link is refused outright, and the
     * write goes through an O_EXCL temp file + atomic rename, so nothing here ever follows a link.
     */
    if (is_link($ht) || is_link(rtrim($dir, '/'))) return ['dir' => $dir, 'htaccess' => $ht, 'backup' => '', 'extensions' => smpro_ph_allowed_exts($exts), 'lock_rc' => 1, 'lock_output' => 'refused: .htaccess is a symbolic link'];
    smpro_ph_chattr('-i', $ht);
    $backup = ''; $content = '';
    if (is_file($ht)) { $backup = smpro_ph_backup($ht, $backupDir . '/htaccess'); $content = (string)@file_get_contents($ht); }
    $content = preg_replace('/# SMPRO_PH_DENY_EXEC_START.*?# SMPRO_PH_DENY_EXEC_END\s*/s', '', $content) ?? $content;
    $content = rtrim($content) . smpro_ph_htaccess_marker($exts);
    $uid = @fileowner($dir); $gid = @filegroup($dir);                       // own as the cPanel account, NOT root
    $tmp = $ht . '.smpro-' . bin2hex(random_bytes(6)); $fh = @fopen($tmp, 'xb');   // O_EXCL: a planted link at the temp name fails
    $ok = $fh !== false && @fwrite($fh, $content) !== false; if ($fh) @fclose($fh);
    if ($ok) { @chmod($tmp, 0644); if ($uid !== false) { @chown($tmp, $uid); @chgrp($tmp, $gid); } $ok = !is_link($ht) && @rename($tmp, $ht); }
    if (!$ok) { @unlink($tmp); return ['dir' => $dir, 'htaccess' => $ht, 'backup' => $backup, 'extensions' => smpro_ph_allowed_exts($exts), 'lock_rc' => 1, 'lock_output' => 'write failed']; }
    [$rc, $out] = smpro_ph_chattr('+i', $ht);
    return ['dir' => $dir, 'htaccess' => $ht, 'backup' => $backup, 'extensions' => smpro_ph_allowed_exts($exts), 'lock_rc' => $rc, 'lock_output' => $out];
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

/* ---------------- apply / unlock ---------------- */
/**
 * Apply protection. $postLockRoots names document roots whose FOLDER should also be locked.
 *
 * Locking a folder is a different promise from locking a file: the immutable attribute on a directory stops any
 * new entry being created in it, so a web shell cannot be dropped there at all - a real account takeover
 * began with exactly that, a file added at the top of the site by someone holding the account password. It is not
 * applied by default and never to an arbitrary directory: only to a site's own document root, because that is the
 * only place where "no new file may appear here" is both true and explainable. Uploads live below it and keep
 * working; what stops is creating, renaming or deleting entries at the top level, including by the site itself.
 */
function smpro_ph_apply($u, $mode, array $postFiles, array $postDirs, array $exts, array $postLockRoots = []) {
    $backupDir = SMPRO_PH_BACKUP . '/' . $u . '_' . date('Ymd_His');
    @is_dir($backupDir) || @mkdir($backupDir, 0700, true);
    $files = []; $dirs = [];
    if ($mode === 'fast') {
        foreach (smpro_ph_profile($u) as $p) { foreach ($p['files'] as $f) $files[] = $f['path']; foreach ($p['dirs'] as $d) $dirs[] = $d['path']; }
    } else {
        foreach ($postFiles as $f) { $f = (string)$f; if (is_file($f) && !is_link($f) && smpro_ph_inside($u, $f)) $files[] = realpath($f) ?: $f; }
        foreach ($postDirs as $d) { $d = (string)$d; if (is_dir($d) && !is_link($d) && smpro_ph_inside($u, $d)) $dirs[] = realpath($d) ?: $d; }
    }
    $files = array_values(array_unique($files)); $dirs = array_values(array_unique($dirs));
    $errors = []; $fileRows = []; $dirRows = []; $rootRows = [];

    // Which document roots were asked for as folders. Anything that is not one of THIS account's roots is dropped
    // rather than argued with: the option's meaning is tied to a site's top level.
    $accountRoots = [];
    foreach (smpro_ph_roots($u) as $r) $accountRoots[] = $r['root'];
    $lockRoots = [];
    foreach ($postLockRoots as $d) {
        $d = realpath((string)$d) ?: (string)$d;
        if (in_array($d, $accountRoots, true) && is_dir($d) && !is_link($d)) $lockRoots[] = $d;
    }
    $lockRoots = array_values(array_unique($lockRoots));

    // Open every root before doing anything else. A folder carrying the immutable attribute cannot accept a new
    // .htaccess or a restored file, so without this a second run would fail against the protection the first one
    // applied - and would report those failures as if the files were the problem.
    if ($accountRoots) smpro_ph_chattr_many('-i', $accountRoots);
    // Unlock the whole set, back every file up, then lock the whole set: the same order per file, but two
    // processes for the set instead of two for each file.
    smpro_ph_chattr_many('-i', $files);
    $backups = [];
    foreach ($files as $file) $backups[$file] = smpro_ph_backup($file, $backupDir . '/files');
    $lockRes = smpro_ph_chattr_many('+i', $files);
    foreach ($files as $file) {
        $why = (string)($lockRes['failed'][$file] ?? '');
        if ($why !== '') $errors[] = basename($file) . ': ' . $why;
        $fileRows[] = ['path' => $file, 'rel' => ltrim(substr($file, strlen(smpro_ph_home($u))), '/'), 'backup' => $backups[$file] ?? '', 'lock_rc' => $why === '' ? 0 : 1];
    }
    foreach ($dirs as $dir) {
        $row = smpro_ph_apply_htaccess($dir, $exts, $backupDir);
        if ((int)$row['lock_rc'] !== 0) $errors[] = basename($dir) . '/.htaccess: ' . $row['lock_output'];
        $dirRows[] = ['dir' => $row['dir'], 'rel' => ltrim(substr($dir, strlen(smpro_ph_home($u))), '/'), 'htaccess' => $row['htaccess'], 'backup' => $row['backup'], 'lock_rc' => $row['lock_rc']];
    }
    // Close the chosen roots LAST, once nothing else needs to create a file inside them.
    if ($lockRoots) {
        $lr = smpro_ph_chattr_many('+i', $lockRoots);
        foreach ($lockRoots as $d) {
            $why = (string)($lr['failed'][$d] ?? '');
            if ($why !== '') $errors[] = basename($d) . ' (folder): ' . $why;
            else $rootRows[] = ['dir' => $d, 'rel' => ltrim(substr($d, strlen(smpro_ph_home($u))), '/') ?: 'public_html'];
        }
    }

    $m = smpro_ph_load($u) ?: ['version' => 'smpro.ph1', 'user' => $u, 'created_at' => date('c')];
    $m['locked_roots'] = $rootRows;
    $m['status'] = 'locked'; $m['unlock_until'] = ''; $m['last_harden_at'] = date('c'); $m['last_harden_mode'] = $mode;
    $m['backup_dir'] = $backupDir; $m['protected_files'] = $fileRows; $m['deny_php_dirs'] = $dirRows; $m['blocked_extensions'] = smpro_ph_allowed_exts($exts); $m['errors'] = $errors;
    smpro_ph_save($u, $m);
    smpro_ph_audit_log($u, 'php_harden_' . $mode, 'Applied ' . ucfirst($mode) . ' Protection', ['files' => count($fileRows), 'folders' => count($dirRows), 'blocked' => implode(',', smpro_ph_allowed_exts($exts)), 'errors' => count($errors)]);
    smpro_audit('php_harden_apply', ['user' => $u, 'mode' => $mode, 'files' => count($fileRows), 'dirs' => count($dirRows), 'errors' => count($errors)]);
    return ['ok' => count($errors) === 0, 'files' => count($fileRows), 'dirs' => count($dirRows), 'roots' => count($rootRows), 'errors' => $errors, 'backup_dir' => $backupDir];
}
/** Unlock selected files/folders. $until>0 -> temporary (records auto-relock time). */
function smpro_ph_unlock($u, array $postFiles, array $postDirs, $until = 0) {
    $files = []; $dirs = [];
    foreach ($postFiles as $f) { $f = (string)$f; if (smpro_ph_inside($u, $f) && is_file($f)) $files[] = realpath($f) ?: $f; }
    foreach ($postDirs as $d) { $d = (string)$d; if (smpro_ph_inside($u, $d) && is_dir($d)) $dirs[] = realpath($d) ?: $d; }
    $done = 0;
    $done += (int)smpro_ph_chattr_many('-i', array_unique($files))['done'];
    // A locked folder is part of what "unlock" means. Leaving it set would keep new files impossible while the
    // page reported the account released - the same false statement force-unprotect exists to prevent.
    $mNow = smpro_ph_load($u) ?: [];
    $rootDirs = array_values(array_filter(array_map(fn($r) => is_array($r) ? (string)($r['dir'] ?? '') : (string)$r, (array)($mNow['locked_roots'] ?? []))));
    if ($rootDirs) { $done += (int)smpro_ph_chattr_many('-i', $rootDirs)['done']; }
    foreach (array_unique($dirs) as $dir) { smpro_ph_remove_htaccess($dir); $done++; }
    $m = smpro_ph_load($u) ?: ['version' => 'smpro.ph1', 'user' => $u, 'created_at' => date('c')];
    if ($until > 0) {
        $m['status'] = 'temporary_unlock'; $m['unlock_until'] = date('c', $until);
        $m['pending_relock'] = ['files' => array_values(array_unique($files)), 'dirs' => array_values(array_unique($dirs)), 'exts' => $m['blocked_extensions'] ?? ['php', 'phtml', 'phar', 'php[0-9]'], 'until' => $until];
    } else {
        $m['status'] = 'unlocked'; $m['unlock_until'] = '';
    }
    smpro_ph_save($u, $m);
    smpro_ph_audit_log($u, 'php_harden_unlock', $until > 0 ? 'Temporary unlock until ' . date('Y-m-d H:i', $until) : 'Unlocked (permanent)', ['files' => count($files), 'dirs' => count($dirs)]);
    smpro_audit('php_harden_unlock', ['user' => $u, 'files' => count($files), 'dirs' => count($dirs), 'temporary' => $until > 0]);
    return ['ok' => true, 'count' => $done, 'temporary' => $until > 0, 'until' => $until > 0 ? date('Y-m-d H:i', $until) : ''];
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

/**
 * Enforce expired temporary unlocks: any manifest in `temporary_unlock` whose `pending_relock.until`
 * has passed is re-locked now (chattr +i on files, deny-.htaccess restored on dirs), and its status
 * flipped back to `locked`. Previously nothing ever consumed `pending_relock`, so a "temporary"
 * unlock stayed open forever while the UI promised auto-relock. Returns the number of accounts re-locked.
 * (php-harden's helpers only load when this page is rendered, so this runs at render - the earliest
 * point the functions exist - closing the gap at latest when an admin opens the page.)
 */
function smpro_ph_relock_due() {
    $now = time(); $relocked = 0;
    foreach (glob(SMPRO_PH_STATE . '/*.json') ?: [] as $mf) {
        $m = json_decode((string)@file_get_contents($mf), true);
        if (!is_array($m) || ($m['status'] ?? '') !== 'temporary_unlock') continue;
        $pr = $m['pending_relock'] ?? null;
        if (!is_array($pr) || (int)($pr['until'] ?? 0) === 0 || (int)$pr['until'] > $now) continue;   // not due yet
        $u = (string)($m['user'] ?? basename($mf, '.json'));
        // Force-unprotected since the temporary unlock was granted. Re-locking now would quietly reverse a later,
        // more deliberate decision - so the pending re-lock is dropped and recorded instead of being carried out.
        if (function_exists('smpro_ph_ign_has') && smpro_ph_ign_has($u, 'auto')) {
            $m['status'] = 'unlocked'; $m['unlock_until'] = ''; unset($m['pending_relock']);
            smpro_ph_save($u, $m);
            smpro_ph_audit_log($u, 'php_harden_relock_skipped',
                'Auto re-lock was due but the account is on the force-unprotect ignore list — left unprotected.', []);
            continue;
        }
        $exts = (array)($pr['exts'] ?? ($m['blocked_extensions'] ?? ['php', 'phtml', 'phar', 'php[0-9]']));
        $backupDir = SMPRO_PH_BACKUP . '/' . preg_replace('/[^a-zA-Z0-9._-]/', '', $u) . '_relock_' . date('Ymd_His');
        $relockFiles = [];
        foreach ((array)($pr['files'] ?? []) as $f) {
            $f = (string)$f;
            if (is_file($f) && !is_link($f) && smpro_ph_inside($u, $f)) $relockFiles[] = $f;
        }
        smpro_ph_chattr_many('+i', $relockFiles);   // most are still locked and cost no process at all
        foreach ((array)($pr['dirs'] ?? []) as $d) {
            $d = (string)$d;
            if (is_dir($d) && !is_link($d) && smpro_ph_inside($u, $d)) smpro_ph_apply_htaccess($d, $exts, $backupDir);
        }
        $m['status'] = 'locked'; $m['unlock_until'] = ''; unset($m['pending_relock']);
        $m['last_relock_at'] = date('c');
        smpro_ph_save($u, $m);
        smpro_ph_audit_log($u, 'php_harden_relock', 'Auto re-locked after temporary unlock expired', ['files' => count((array)($pr['files'] ?? [])), 'dirs' => count((array)($pr['dirs'] ?? []))]);
        smpro_audit('php_harden_relock', ['user' => $u, 'auto' => 1]);
        $relocked++;
    }
    return $relocked;
}

/* ---------------- live protected-items count (lsattr truth) ---------------- */
function smpro_ph_protected_count($u, array $profile) {
    $paths = [];
    foreach ($profile as $p) {
        foreach ($p['files'] as $f) $paths[] = $f['path'];
        foreach ($p['dirs'] as $d) { $ht = rtrim($d['path'], '/') . '/.htaccess'; if (is_file($ht)) $paths[] = $ht; }
    }
    $paths = array_values(array_unique(array_filter($paths, 'file_exists')));
    if (!$paths) return ['locked' => 0, 'total' => 0];
    $map = smpro_ph_locked_map($paths);
    $locked = 0; foreach ($map as $v) if ($v) $locked++;
    return ['locked' => $locked, 'total' => count($paths)];
}

/* ---------------- world-writable web files: scan + safe fix ---------------- */
/**
 * Read-only scan: world-writable regular FILES (the o+w bit, e.g. 0666/0777) under
 * every web root of the account. Bounded exactly like the plugin's other scans:
 * timeout + nice + ionice, -maxdepth, head-capped. Never follows symlinks
 * (find does not by default; each hit is re-checked with is_link/is_file in PHP).
 */
function smpro_ph_ww_scan($u, $maxDepth = 6, $limit = 500) {
    $found = [];
    if (!smpro_ph_valid_user($u)) return $found;
    foreach (smpro_ph_roots($u) as $row) {
        if (count($found) >= $limit) break;
        $root = $row['root'];
        if (!smpro_ph_inside($u, $root)) continue;               // defensive: web roots must live inside /home/<u>
        $cmd = 'timeout 30 nice -n ' . SMPRO_SCAN_NICE . ' ionice -c' . SMPRO_SCAN_IONICE_CLASS
             . ' find ' . escapeshellarg($root) . ' -maxdepth ' . (int)$maxDepth
             . ' -type f -perm -0002 2>/dev/null | head -n ' . (int)$limit;
        foreach (explode("\n", trim((string)@shell_exec($cmd))) as $p) {
            $p = trim($p);
            if ($p === '' || isset($found[$p]) || is_link($p) || !is_file($p)) continue;
            $perms = @fileperms($p);
            if ($perms === false || !($perms & 0002)) continue;  // re-verify the o+w bit in PHP
            $found[$p] = ['path' => $p, 'mode' => substr(sprintf('%o', $perms), -4),
                          'size' => (int)@filesize($p), 'mtime' => (int)@filemtime($p)];
            if (count($found) >= $limit) break;
        }
    }
    return array_values($found);
}
/** Render the <tr> rows for the world-writable scan table (initial hint + AJAX result). */
function smpro_ph_ww_rows(array $rows) {
    if (!$rows) return '<tr><td colspan="4" style="text-align:center;padding:16px;color:var(--good)">&#10003; No world-writable files found under this account&#39;s web roots.</td></tr>';
    $h = '';
    foreach ($rows as $r) {
        $h .= '<tr data-ww="1">'
            . '<td class="mono" style="white-space:normal;word-break:break-all">' . smpro_h($r['path']) . '</td>'
            . '<td><span class="b red mono">' . smpro_h($r['mode']) . '</span></td>'
            . '<td class="num mono">' . smpro_h(number_format(($r['size'] ?? 0) / 1024, 1)) . ' KB</td>'
            . '<td class="mono" style="font-size:11px">' . smpro_h(date('Y-m-d H:i', (int)($r['mtime'] ?? 0))) . '</td>'
            . '</tr>';
    }
    return $h;
}
/**
 * SAFE fix: clear ONLY the o+w bit (chmod o-w) on files found by a FRESH server-side
 * scan - a client-supplied path list is never trusted. Runs as root, so EVERY path
 * must pass smpro_path_safe() (rejects symlinks + realpath-confines to /home/<u>)
 * immediately before its own chmod; anything that fails is skipped, never chmod'ed.
 * Per-file on the validated set - never a blanket recursive chmod. Previous modes
 * are saved to a manifest under the backup dir (same reversibility convention as
 * the apply/unlock backups).
 */
function smpro_ph_ww_fix($u) {
    $rows = smpro_ph_ww_scan($u);
    $fixed = 0; $skipped = 0; $failed = 0; $manifest = [];
    $backupDir = SMPRO_PH_BACKUP . '/' . preg_replace('/[^a-zA-Z0-9._-]/', '', $u) . '_ww_' . date('Ymd_His');
    $acctUid = function_exists('posix_getpwnam') ? (int)(@posix_getpwnam($u)['uid'] ?? -1) : -1;
    foreach ($rows as $r) {
        $safe = function_exists('smpro_path_safe') ? smpro_path_safe($r['path'], [smpro_user_home($u)]) : '';
        if ($safe === '' || is_link($safe) || !is_file($safe)) { $skipped++; continue; }  // symlink / escapes the account -> NEVER chmod
        clearstatcache(true, $safe);
        $perms = @fileperms($safe);
        if ($perms === false) { $skipped++; continue; }
        if (!($perms & 0002)) continue;                          // already clean (raced) - nothing to do
        // SECURITY (privesc, race): chmod() follows a symlink. A customer can swap $safe's leaf for a
        // symlink -> /etc/shadow between the checks above and the chmod below, turning a 0000 root file
        // world-readable. Re-verify identity IMMEDIATELY before chmod: still not a symlink, SAME inode as
        // resolve time, and account-owned (never root uid 0, never another account). The owner check also
        // neutralises the hardlink-to-root vector on hosts where fs.protected_hardlinks=0 (a hardlink keeps
        // the root file's uid 0 -> refused), so this no longer depends solely on the kernel's protections.
        $v = @lstat($safe);
        if ($v === false || ($v['mode'] & 0170000) === 0120000) { $skipped++; continue; }   // gone / became a symlink
        if ((int)$v['uid'] === 0 || ($acctUid >= 0 && (int)$v['uid'] !== $acctUid)) { $skipped++; continue; }  // root/foreign-owned -> refuse
        $perms = (int)$v['mode'] & 0777;
        if (!($perms & 0002)) continue;
        if (@chmod($safe, $perms & ~0002)) {
            $fixed++;
            $manifest[] = ['path' => $safe, 'old' => substr(sprintf('%o', $perms), -4), 'new' => substr(sprintf('%o', $perms & ~0002), -4)];
        } else { $failed++; }
    }
    if ($manifest) {
        @is_dir($backupDir) || @mkdir($backupDir, 0700, true);
        @file_put_contents($backupDir . '/ww_modes.json', json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE), LOCK_EX);
        @chmod($backupDir . '/ww_modes.json', 0600);
    }
    smpro_ph_audit_log($u, 'php_harden_ww_fix', 'Removed world-write (chmod o-w) from scanned web files', ['found' => count($rows), 'fixed' => $fixed, 'skipped' => $skipped, 'failed' => $failed]);
    smpro_audit('php_harden_ww_fix', ['user' => $u, 'found' => count($rows), 'fixed' => $fixed, 'skipped' => $skipped, 'failed' => $failed]);
    return ['ok' => $failed === 0, 'found' => count($rows), 'fixed' => $fixed, 'skipped' => $skipped, 'failed' => $failed];
}

/* =====================================================================
 * CONTROLLER
 * ===================================================================== */
$reqMethod = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));
$u = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)($_POST['phuser'] ?? $_GET['phuser'] ?? $_GET['user'] ?? ''));

/* ---- POST: apply / unlock (AJAX JSON) ---- */

if ($reqMethod === 'POST' && in_array(($_POST['ph_action'] ?? ''), ['apply_fast', 'apply_custom', 'unlock', 'ww_fix', 'force_unprotect', 'ign_remove', 'ask_decide', 'rules_save'], true)) {
    smpro_require_valid_csrf('ph_act'); smpro_require_root();
    header('Content-Type: application/json');
    $act = $_POST['ph_action'];
    // Removing a list entry deliberately does NOT require the account to still exist: an account can be
    // terminated while its entry remains, and refusing to clean that up would leave an entry no one can delete.
    if ($act === 'ign_remove') {
        $target = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)($_POST['target'] ?? ''));
        $gone = $target !== '' && smpro_ph_ign_remove($target);
        smpro_ph_audit_log($target, 'php_harden_ignore_remove',
            $gone ? 'Removed from the force-unprotect ignore list — automatic protection applies again.'
                  : 'Removal requested but the account was not on the list.', ['by' => smpro_ph_actor()]);
        if ($gone) smpro_audit('php_harden_ignore_remove', ['user' => $target]);
        echo json_encode(['ok' => $gone, 'msg' => $gone
            ? ($target . ' removed from the ignore list. Automatic hardening applies to it again.')
            : 'That account was not on the ignore list — nothing was changed.'], JSON_UNESCAPED_SLASHES); exit;
    }
    // Server-wide actions that name no account: the approval rules, and deciding a release request. They sat below
    // the account check for a while and were refused with "Invalid cPanel user" - which meant no request from an
    // account's Safety Lock could ever be approved from this page, and every release waited for ever.
    if ($act === 'rules_save') {
        if (!function_exists('smpro_spr_save')) { echo json_encode(['ok' => false, 'msg' => 'The rules engine is missing from this build.']); exit; }
        $cc = preg_split('/[^A-Za-z]+/', (string)($_POST['countries'] ?? ''), -1, PREG_SPLIT_NO_EMPTY);
        $ok = smpro_spr_save([
            'auto_hour'      => ($_POST['auto_hour'] ?? '') === '1',
            'auto_permanent' => ($_POST['auto_permanent'] ?? '') === '1',
            'need_allowlist' => ($_POST['need_allowlist'] ?? '') === '1',
            'countries'      => $cc,
            'max_items'      => (int)($_POST['max_items'] ?? 25),
        ], smpro_ph_actor());
        smpro_audit('siteprotection_rules', ['saved' => $ok ? 1 : 0]);
        echo json_encode(['ok' => $ok, 'msg' => $ok ? smpro_spr_describe() : 'The rules could not be written. Nothing changed.'], JSON_UNESCAPED_SLASHES); exit;
    }
    if ($act === 'ask_decide') {
        $target = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)($_POST['target'] ?? ''));
        $grant  = ($_POST['grant'] ?? '') === '1';
        if ($target === '' || !function_exists('smpro_spq_ask_clear')) {
            echo json_encode(['ok' => false, 'msg' => 'That request could not be read.']); exit;
        }
        $ask = smpro_spq_asks_all()[$target] ?? null;
        if (!$ask) { echo json_encode(['ok' => false, 'msg' => 'That request is no longer pending — someone may have decided it already.']); exit; }

        if (!$grant) {
            smpro_spq_ask_clear($target);
            smpro_ph_audit_log($target, 'php_harden_ask_declined', 'Release request declined by ' . smpro_ph_actor(),
                               ['reason' => $ask['reason'], 'verb' => $ask['verb']]);
            echo json_encode(['ok' => true, 'msg' => 'Declined. ' . $target . ' stays protected and the request is cleared.'], JSON_UNESCAPED_SLASHES); exit;
        }

        // A one-hour release touches only what was chosen and restores itself. A permanent one is the same thing
        // the operator would do with Force unprotect, so it goes through exactly that path and lands on the list.
        if (($ask['verb'] ?? '') === 'unlock_selected') {
            $paths = function_exists('smpro_spq_resolve') ? smpro_spq_resolve($target, (string)$ask['root'], (array)$ask['items']) : [];
            if (!$paths) {
                smpro_spq_ask_clear($target);
                echo json_encode(['ok' => false, 'msg' => 'None of the items in that request could be used — they were outside the account, were links, or are gone. The request was cleared.'], JSON_UNESCAPED_SLASHES); exit;
            }
            // Batched: one chattr for the whole selection and one read-back, not two processes per file (t55).
            $done = 0; $stuck = [];
            smpro_ph_chattr_many('-i', $paths);
            $still = function_exists('smpro_ph_locked_map') ? smpro_ph_locked_map($paths) : [];
            foreach ($paths as $pth) { if (!empty($still[$pth])) $stuck[] = basename($pth); else $done++; }
            $until = time() + 3600;
            if (function_exists('smpro_spq_state_load')) {
                $st = smpro_spq_state_load();
                $st[$target] = ['relock_at' => $until, 'set' => date('c')];
                smpro_spq_state_save($st);
            }
            smpro_spq_ask_clear($target);
            smpro_ph_audit_log($target, 'php_harden_ask_granted_1h',
                'Released ' . $done . ' item(s) for one hour, granted by ' . smpro_ph_actor(), ['reason' => $ask['reason']]);
            $msg = 'Released ' . $done . ' item(s) until ' . date('H:i', $until) . ' — the server locks them again by itself.';
            if ($stuck) $msg .= ' ' . count($stuck) . ' could NOT be released (' . implode(', ', array_slice($stuck, 0, 4)) . ').';
            echo json_encode(['ok' => empty($stuck), 'msg' => $msg], JSON_UNESCAPED_SLASHES); exit;
        }

        $r = smpro_ph_force_unprotect($target, smpro_ph_profile($target),
            'requested by the account: ' . $ask['reason'], smpro_ph_actor(), 'all');
        smpro_spq_ask_clear($target);
        $msg = 'Granted. Protection removed from ' . $r['cleared'] . ' item(s) and ' . $target . ' is on the ignore list.';
        if (!$r['listed']) $msg .= ' WARNING: the ignore list could not be written, so automatic hardening may re-apply.';
        if ($r['stuck'])   $msg .= ' ' . count($r['stuck']) . ' item(s) could NOT be cleared and are still protected.';
        echo json_encode(['ok' => $r['ok'], 'msg' => $msg], JSON_UNESCAPED_SLASHES); exit;
    }
    if (!smpro_ph_valid_user($u)) { echo json_encode(['ok' => false, 'msg' => 'Invalid cPanel user.']); exit; }
    $exts = is_array($_POST['exts'] ?? null) ? $_POST['exts'] : ['php', 'phtml', 'phar', 'php[0-9]', 'shtml', 'html', 'htm'];
    // An account excluded from protection entirely is not protected by accident from the page either. The refusal
    // says where the rule lives, so it can be lifted rather than worked around.
    if (in_array($act, ['apply_fast', 'apply_custom'], true) && smpro_ph_ign_has($u, 'manual')) {
        $ig = smpro_ph_ign_get($u);
        echo json_encode(['ok' => false, 'msg' => $u . ' is on the force-unprotect ignore list'
            . (($ig && $ig['reason'] !== '') ? ' (' . $ig['reason'] . ')' : '')
            . '. Remove it from the list below to protect this account again.'], JSON_UNESCAPED_SLASHES); exit;
    }
    if ($act === 'force_unprotect') {
        $r = smpro_ph_force_unprotect($u, smpro_ph_profile($u),
            (string)($_POST['reason'] ?? ''), smpro_ph_actor(),
            ((string)($_POST['scope'] ?? 'all') === 'auto' ? 'auto' : 'all'));
        $msg = 'Protection removed from ' . $r['cleared'] . ' item(s).';
        if (!$r['listed']) $msg .= ' WARNING: the ignore list could not be written, so automatic hardening may re-apply — check that ' . SMPRO_VARLIB . '/php_harden is writable.';
        else $msg .= ' ' . $u . ' was added to the ignore list' . ((string)($_POST['scope'] ?? 'all') === 'auto' ? ' (automatic passes only).' : '.');
        if ($r['stuck']) $msg .= ' ' . count($r['stuck']) . ' item(s) could NOT be cleared: ' . implode(', ', array_map('basename', array_slice($r['stuck'], 0, 5))) . ' — these are still protected.';
        echo json_encode(['ok' => $r['ok'], 'msg' => $msg, 'errors' => $r['stuck']], JSON_UNESCAPED_SLASHES); exit;
    }
    if ($act === 'apply_fast') {
        $r = smpro_ph_apply($u, 'fast', [], [], $exts, (array)($_POST['lock_roots'] ?? []));
        echo json_encode(['ok' => $r['ok'], 'msg' => 'Fast Protection applied: ' . $r['files'] . ' file(s) locked, ' . $r['dirs'] . ' folder(s) guarded' . ($r['errors'] ? ', ' . count($r['errors']) . ' warning(s)' : '') . '.', 'errors' => $r['errors']], JSON_UNESCAPED_SLASHES); exit;
    }
    if ($act === 'apply_custom') {
        $r = smpro_ph_apply($u, 'custom', (array)($_POST['files'] ?? []), (array)($_POST['dirs'] ?? []), $exts, (array)($_POST['lock_roots'] ?? []));
        echo json_encode(['ok' => $r['ok'], 'msg' => 'Custom Protection applied: ' . $r['files'] . ' file(s) locked, ' . $r['dirs'] . ' folder(s) guarded' . ($r['errors'] ? ', ' . count($r['errors']) . ' warning(s)' : '') . '.', 'errors' => $r['errors']], JSON_UNESCAPED_SLASHES); exit;
    }
    if ($act === 'ww_fix') {
        $r = smpro_ph_ww_fix($u);
        echo json_encode(['ok' => $r['ok'], 'msg' => 'World-write removed (chmod o-w) from ' . $r['fixed'] . ' file(s)'
            . ($r['skipped'] ? ', ' . $r['skipped'] . ' skipped (symlink / outside account)' : '')
            . ($r['failed'] ? ', ' . $r['failed'] . ' failed' : '')
            . '. Previous modes saved for rollback.'], JSON_UNESCAPED_SLASHES); exit;
    }
    // unlock
    $dur = (string)($_POST['duration'] ?? 'permanent');
    $until = 0;
    if ($dur !== 'permanent') { $mins = ['1h' => 60, '6h' => 360, '24h' => 1440, '72h' => 4320]; $until = time() + (($mins[$dur] ?? 60) * 60); }
    $r = smpro_ph_unlock($u, (array)($_POST['files'] ?? []), (array)($_POST['dirs'] ?? []), $until);
    echo json_encode(['ok' => true, 'msg' => $r['temporary'] ? ('Temporarily unlocked ' . $r['count'] . ' item(s) until ' . $r['until'] . ' — re-apply protection to re-lock.') : ('Unlocked ' . $r['count'] . ' item(s) permanently.')], JSON_UNESCAPED_SLASHES); exit;
}

/* ---- AJAX: browse a subfolder (returns table rows HTML) ---- */
if (($_GET['ajax'] ?? '') === 'browse') {
    if (!smpro_ph_valid_user($u)) { echo '<tr><td colspan="6">Invalid user.</td></tr>'; exit; }
    $prof = smpro_ph_profile($u); $root = $prof[0]['root'] ?? '';
    $rows = smpro_ph_browser($u, $root, (string)($_GET['dir'] ?? $root),
        array_map(fn($f) => $f['path'], $prof[0]['files'] ?? []), array_map(fn($d) => $d['path'], $prof[0]['dirs'] ?? []));
    echo smpro_ph_browser_rows($rows); exit;
}

/* ---- AJAX: world-writable files scan (READ-ONLY, returns table rows HTML) ---- */
if (($_GET['ajax'] ?? '') === 'wwscan') {
    if (!smpro_ph_valid_user($u)) { echo '<tr><td colspan="4">Invalid user.</td></tr>'; exit; }
    echo smpro_ph_ww_rows(smpro_ph_ww_scan($u)); exit;
}

/* ---- render ---- */
smpro_ph_relock_due();   // enforce expired temporary unlocks before showing state (see fn docblock)
$valid = smpro_ph_valid_user($u);
$profile = $valid ? smpro_ph_profile($u) : [];
$primary = $profile[0] ?? null;
$man = $valid ? smpro_ph_load($u) : null;
$pcount = $valid ? smpro_ph_protected_count($u, $profile) : ['locked' => 0, 'total' => 0];
$csrf = smpro_csrf_generate('ph_act');
$cphome = rtrim((string)SMPRO_CPSESS, '/') . '/scripts2/listaccts';

smpro_audit('php_harden_view', ['user' => $u, 'valid' => $valid ? 1 : 0]);
smpro_layout_header('PHP Harden');
?>
<div class="svc-kicker">Hardening</div>
<h1 class="h" style="margin:2px 0 4px">PHP Harden — Smart Stack Detection</h1>
<p class="sub">Detect the app type per account and apply anti-write protection to critical files (<code>chattr +i</code>) plus block PHP execution inside upload / cache / log folders — without breaking the site. Read-only until you apply; every action is backed up and reversible.</p>

<form method="get" action="index.cgi" class="card ph-pick">
  <input type="hidden" name="page" value="php-harden">
  <label class="ph-fld">cPanel account<input class="tp-in" name="phuser" value="<?= smpro_h($u) ?>" placeholder="start typing a username…" data-ac="accounts" autocomplete="off"></label>
  <button class="tp-btn primary" type="submit">&#128269; Scan account</button>
</form>
<?php if ($valid && $primary):
  // ---- the overview: the same state the hero below shows, as tiles that jump to their section
  $phOvSt = $man['status'] ?? 'none';
  $phOvStl = ['locked' => ['Protected', 'good'], 'unlocked' => ['Unlocked', 'warn'], 'temporary_unlock' => ['Temp unlock', 'warn'], 'none' => ['Not applied', 'muted']][$phOvSt] ?? ['—', 'muted'];
  $phOv = [
    ['id' => 'phFast', 'l' => 'Status', 'v' => $phOvStl[0], 'cls' => $phOvStl[1], 's' => smpro_ph_ign_get($u) ? ($u . ' · on the ignore list') : $u],
    ['id' => 'phFast', 'l' => 'Locked', 'v' => (int)$pcount['locked'] . ' / ' . (int)$pcount['total'], 'cls' => ((int)$pcount['total'] > 0 && (int)$pcount['locked'] >= (int)$pcount['total']) ? 'good' : ((int)$pcount['locked'] > 0 ? 'warn' : 'muted'), 's' => 'protected items (live)'],
    ['id' => 'phFast', 'l' => 'App', 'v' => (string)$primary['det']['label'], 'cls' => 'brand', 's' => 'confidence: ' . (string)$primary['det']['confidence']],
    ['id' => 'phWwCard', 'l' => 'Web root', 'v' => basename((string)$primary['root']), 'cls' => 'muted', 's' => (string)$primary['root']],
  ];
?>
<div class="fw-kpis">
  <?php foreach ($phOv as $k): ?>
  <a class="fw-kpi <?= $k['cls'] ?>" href="#<?= $k['id'] ?>" data-go="<?= $k['id'] ?>"><div class="l"><?= $k['l'] ?></div><div class="v"><?= smpro_h($k['v']) ?></div><div class="s"><?= smpro_h($k['s']) ?></div></a>
  <?php endforeach; ?>
</div>
<?php endif; ?>
<?php $phOvNav = [['phFast', '&#9889; Preview'], ['phCustom', '&#129513; Browser'], ['phExtsCard', 'Extensions'], ['phWwCard', 'World-writable'], ['phForceCard', '&#128683; Force unprotect'], ['ph-activity', '&#128203; Activity'], ['ph-rules', '&#9881; Auto-approve rules'], ['ph-asks', '&#9993; Release requests'], ['phIgnList', 'Ignore list']]; ?>
<nav class="fw-nav" id="phNav"><?php foreach ($phOvNav as [$id, $lbl]): ?><a href="#<?= $id ?>" data-go="<?= $id ?>"><?= $lbl ?></a><?php endforeach; ?><span class="sp"></span><button type="button" class="fw-navx" id="phOpenAll">expand all</button><button type="button" class="fw-navx" id="phCloseAll">collapse all</button></nav>

<?php if ($u !== '' && !$valid): ?>
  <div class="card ph-bad">&#9888; The cPanel user <b><?= smpro_h($u) ?></b> was not found on this server.</div>
<?php endif; ?>

<?php if ($valid && $primary): $det = $primary['det']; ?>
<div class="ph-hero">
  <div class="ph-hero-row">
    <div class="ph-stat"><div class="l">Detected Stack</div><div class="v"><?= smpro_h($det['label']) ?></div></div>
    <div class="ph-stat"><div class="l">Confidence</div><div class="v"><?= smpro_h($det['confidence']) ?></div></div>
    <div class="ph-stat"><div class="l">Protected Items (live)</div><div class="v"><?= (int)$pcount['locked'] ?><span class="ph-of">/ <?= (int)$pcount['total'] ?></span></div></div>
    <div class="ph-stat ph-status">
      <div class="l">Status</div>
      <div class="v"><?php
        $st = $man['status'] ?? 'none';
        $stl = ['locked' => ['Protected', 'good'], 'unlocked' => ['Unlocked', 'warn'], 'temporary_unlock' => ['Temp unlock', 'warn'], 'none' => ['Not applied', 'muted']][$st] ?? ['—', 'muted'];
        echo '<span class="ph-pill ' . $stl[1] . '">' . smpro_h($stl[0]) . '</span>';
        // Say it here too: a "Not applied" status on an excluded account is not an oversight waiting to be fixed.
        if (smpro_ph_ign_get($u)) echo ' <span class="ph-pill warn" title="Force-unprotected — on the ignore list below.">ignored</span>';
      ?></div>
    </div>
  </div>
  <div class="ph-hero-foot">
    <span class="ph-path"><?= smpro_h($primary['root']) ?></span>
    <span class="ph-ev">Evidence: <?= smpro_h(implode(' · ', $det['evidence'])) ?></span>
    <?php if (!empty($man['unlock_until']) && ($man['status'] ?? '') === 'temporary_unlock'): ?><span class="ph-pill warn">re-lock by <?= smpro_h(date('Y-m-d H:i', strtotime($man['unlock_until']))) ?></span><?php endif; ?>
  </div>
</div>

<?php
/* The state has to be readable where the reader is looking. The "ignored" pill sits in the hero above, and the
   list that explains it was at the very bottom of a long page, past two large tables - so an operator who had
   just excluded an account looked at the top of the page and reasonably concluded nothing had happened. This
   says it in full, in place, and offers the way out from here. */
$igNow = smpro_ph_ign_get($u);
$igBlocksManual = $igNow && $igNow['scope'] !== 'auto';
if ($igNow): ?>
<div class="card ph-ignbanner">
  <div class="ph-ignb-h">&#128683; <b>This account is on the ignore list</b>
    <span class="b <?= $igBlocksManual ? 'red' : 'gray' ?>"><?= $igBlocksManual ? 'excluded from all protection' : 'excluded from automatic passes only' ?></span>
  </div>
  <div class="ph-ignb-b">
    <?= $igNow['reason'] !== '' ? smpro_h($igNow['reason']) : '<span class="meta">No reason was recorded.</span>' ?>
    <div class="meta" style="margin-top:6px;font-size:12px">
      Added by <b><?= smpro_h($igNow['by'] !== '' ? $igNow['by'] : 'unknown') ?></b>
      <?= $igNow['at'] !== '' ? ' on ' . smpro_h(date('Y-m-d H:i', strtotime($igNow['at']))) : '' ?>.
      <?php if ($igBlocksManual): ?>
        Protection will not be applied to it — not by an automatic pass, and not from this page. Locks that appear on it from elsewhere are removed by the hourly sweep and listed in Activity.
      <?php else: ?>
        Automatic passes skip it; you can still apply protection here deliberately.
      <?php endif; ?>
    </div>
  </div>
  <div class="ph-ignb-a">
    <button class="tp-btn ph-ignrm" type="button" data-user="<?= smpro_h($u) ?>">&#10007; Remove from ignore list</button>
    <a class="tp-btn" href="#phIgnList">View the full list</a>
  </div>
</div>
<?php endif; ?>

<script>var PH_CSRF=<?= json_encode($csrf) ?>, PH_USER=<?= json_encode($u) ?>;</script>


<div class="ph-modes<?= $igBlocksManual ? ' ph-off' : '' ?>">
  <label class="ph-mode active" id="phModeFast">
    <input type="radio" name="phmode" value="fast" checked hidden>
    <div class="ph-mode-ic">&#9889;</div>
    <div><div class="ph-mode-t">Fast Protection</div><div class="ph-mode-d">Recommended. Locks the detected stack's critical files and guards upload/cache/log folders. One click, fully reversible.</div></div>
    <span class="ph-check">&#10003;</span>
  </label>
  <label class="ph-mode" id="phModeCustom">
    <input type="radio" name="phmode" value="custom" hidden>
    <div class="ph-mode-ic">&#129513;</div>
    <div><div class="ph-mode-t">Custom Protection</div><div class="ph-mode-d">Open the browser to hand-pick exact files and folders to lock / unlock with <code>chattr</code> and .htaccess guards.</div></div>
    <span class="ph-check">&#10003;</span>
  </label>
</div>

<div class="card ph-fast" id="phFast">
  <div class="ph-card-h"><b>Fast Protection Preview</b>
    <span style="flex:1"></span>
    <?php if ($igBlocksManual): ?>
      <span class="meta" style="font-size:12px">Applying protection is refused while this account is on the ignore list.</span>
      <button class="tp-btn" type="button" id="phApplyFast" disabled title="Remove this account from the ignore list first.">&#9889; Apply Fast Protection</button>
    <?php else: ?>
      <button class="tp-btn green" type="button" id="phApplyFast">&#9889; Apply Fast Protection</button>
    <?php endif; ?>
  </div>
  <?php if ($igBlocksManual): ?>
    <div class="ph-note" style="margin:12px 16px 0">This is what protection <b>would</b> lock. Nothing below is applied, and nothing will be, while the account is on the ignore list.</div>
  <?php endif; ?>
  <?php
  // Locking the FOLDER is a separate decision from locking the files in it, so it is asked separately and is off
  // until it is ticked. The consequence is stated in full, because it is the kind of protection that breaks a
  // site quietly if nobody understood it.
  $phRoots = smpro_ph_roots($u);
  $phLockedRoots = [];
  foreach ((array)($man['locked_roots'] ?? []) as $r) { $p = is_array($r) ? (string)($r['dir'] ?? '') : (string)$r; if ($p !== '') $phLockedRoots[] = $p; }
  ?>
  <?php if ($phRoots): ?>
  <div class="ph-note" style="margin:12px 16px 0;padding:10px 12px;border:1px solid var(--line,#e5e7eb);border-radius:8px">
    <b>&#128193; Also lock the site folder itself</b>
    <div class="meta" style="margin:3px 0 7px">Stops any <b>new</b> file being created at the top level of the site — which is where a stolen password drops a web shell. Existing files keep working and uploads below this folder are unaffected. It also stops the site itself creating files there, so leave it off for a site that installs plugins or writes files into its own root. Reversible: Unlock and Force Unprotect both clear it.</div>
    <?php foreach ($phRoots as $pr): $isOn = in_array($pr['root'], $phLockedRoots, true); ?>
      <label style="display:flex;gap:8px;align-items:center;font-size:13px;margin:3px 0">
        <input type="checkbox" class="ph-lockroot" value="<?= smpro_h($pr['root']) ?>"<?= $isOn ? ' checked' : '' ?><?= $igBlocksManual ? ' disabled' : '' ?>>
        <span><?= smpro_h($pr['domain']) ?> <span class="meta" style="font-size:11.5px">— <?= smpro_h($pr['root']) ?></span><?= $isOn ? ' <span class="ph-pill">locked now</span>' : '' ?></span>
      </label>
    <?php endforeach; ?>
  </div>
  <?php endif; ?>
  <div style="padding:12px 16px 4px"><span class="ph-badge"><?= smpro_h($det['label']) ?></span><span class="ph-badge conf-<?= smpro_h($det['confidence']) ?>">confidence: <?= smpro_h($det['confidence']) ?></span>
    <span class="meta" style="font-size:12px"><?= smpro_h(implode(' / ', $det['evidence'])) ?></span></div>
  <div class="ph-two">
    <div class="ph-col">
      <div class="ph-col-h">Critical files locked with <code>chattr +i</code></div>
      <?php if (!$primary['files']): ?><div class="ph-empty">No standard files found in this root.</div><?php endif; ?>
      <?php foreach ($primary['files'] as $f): ?><div class="ph-item">&#10003; <span class="mono"><?= smpro_h($f['rel']) ?></span></div><?php endforeach; ?>
    </div>
    <div class="ph-col">
      <div class="ph-col-h">Upload / cache / log folders guarded by .htaccess</div>
      <div class="meta" style="font-size:11px;margin:0 0 6px">Blocks script execution inside these folders, then locks the generated .htaccess.</div>
      <?php if (!$primary['dirs']): ?><div class="ph-empty">No writable folders detected for this stack.</div><?php endif; ?>
      <?php foreach ($primary['dirs'] as $d): ?><div class="ph-item">&#10003; <span class="mono"><?= smpro_h($d['rel']) ?>/.htaccess</span></div><?php endforeach; ?>
    </div>
  </div>
  <div class="ph-note">Custom Protection Browser is hidden by default. Choose <b>Custom Protection</b> above to open it.</div>
</div>

<div class="card ph-custom" id="phCustom" style="display:none;padding:0">
  <div class="ph-card-h"><b>Custom Protection Browser</b>
    <span class="meta" id="phSelInfo">0 selected</span>
    <span style="flex:1"></span>
    <input class="tp-in" id="phFilter" placeholder="Filter visible files…" style="max-width:220px">
    <a class="tp-btn" href="index.cgi?page=php-harden&phuser=<?= urlencode($u) ?>">&#8635; Refresh</a>
  </div>
  <div style="padding:8px 16px;display:flex;gap:8px;flex-wrap:wrap;align-items:center;border-bottom:1px solid var(--line)">
    <span class="ph-rootchip">WEB ROOT</span>
    <span class="ph-crumbs mono" id="phCrumbs" data-root="<?= smpro_h($primary['root']) ?>"><a href="#" class="ph-crumb" data-dir="<?= smpro_h($primary['root']) ?>"><?= smpro_h(basename($primary['root'])) ?></a></span>
    <span style="flex:1"></span>
    <button class="tp-btn" type="button" id="phUp" disabled>&#11014; Up</button>
    <button class="tp-btn" type="button" id="phSelVis">Select visible</button>
    <button class="tp-btn" type="button" id="phSelClear">Clear</button>
    <button class="tp-btn" type="button" id="phSelSugg">Select suggested</button>
  </div>
  <div class="ph-tablewrap">
    <table class="smpro-table ph-tbl"><thead><tr>
      <th style="width:30px"><input type="checkbox" id="phChkAll"></th><th>Name</th><th>Type</th><th class="num">Size</th><th>Modified</th><th>Status</th>
    </tr></thead><tbody id="phBody">
    <?php $bt = smpro_ph_browser($u, $primary['root'], $primary['root'], array_map(fn($f) => $f['path'], $primary['files']), array_map(fn($d) => $d['path'], $primary['dirs']));
      echo smpro_ph_browser_rows($bt); ?>
    </tbody></table>
  </div>
  <div class="ph-cust-actions">
    <button class="tp-btn <?= $igBlocksManual ? '' : 'green' ?>" type="button" id="phApplyCustom"<?= $igBlocksManual ? ' disabled title="This account is on the ignore list — remove it first."' : '' ?>>&#128274; Lock selected (Custom Protection)</button>
    <span style="flex:1"></span>
    <select class="tp-sel" id="phUnlockDur"><option value="permanent">Permanent unlock</option><option value="1h">Temp: 1 hour</option><option value="6h">Temp: 6 hours</option><option value="24h">Temp: 24 hours</option><option value="72h">Temp: 72 hours</option></select>
    <button class="tp-btn danger" type="button" id="phUnlock">&#128275; Unlock selected</button>
  </div>
</div>

<div class="card ph-exts" id="phExtsCard">
  <div class="ph-col-h" style="padding:0 0 8px">Blocked extensions inside guarded folders only</div>
  <div class="meta" style="font-size:12px;margin-bottom:8px">Applied via .htaccess <b>only inside selected upload/cache/log folders</b> — never across the whole site.</div>
  <div class="ph-extlist">
    <?php $defExt = ['php', 'phtml', 'phar', 'php[0-9]', 'shtml', 'html', 'htm']; foreach (['php', 'phtml', 'phar', 'php[0-9]', 'shtml', 'html', 'htm', 'js', 'mjs', 'cgi', 'pl', 'py'] as $e): ?>
      <label class="ph-extl"><input type="checkbox" class="ph-ext" value="<?= smpro_h($e) ?>"<?= in_array($e, $defExt, true) ? ' checked' : '' ?>> .<?= smpro_h($e) ?></label>
    <?php endforeach; ?>
  </div>
</div>

<div class="card" style="padding:0;overflow:hidden" id="phWwCard">
  <div class="ph-card-h"><b>World-Writable Web Files</b>
    <span class="meta" id="phWwInfo">not scanned yet</span>
    <span style="flex:1"></span>
    <button class="tp-btn primary" type="button" id="phWwScan">&#128269; Scan web roots</button>
    <button class="tp-btn green" type="button" id="phWwFix" disabled>&#128737; Remove world-write (chmod o-w)</button>
  </div>
  <div class="meta" style="font-size:12px;padding:10px 16px 0">Finds files under this account&#39;s web roots whose mode carries the world-write bit (e.g. <code>0666</code> / <code>0777</code>) — any local user or compromised process can rewrite them (defacement / malware dropper risk). The fix clears <b>only</b> the <code>o+w</code> bit per file (e.g. 0666 &#8594; 0664); owner and group permissions are untouched. Read-only until you click the fix; symlinks are always refused.</div>
  <div class="ph-tablewrap" style="max-height:360px;margin-top:10px">
    <table class="smpro-table"><thead><tr><th>Path</th><th>Mode</th><th class="num">Size</th><th>Modified</th></tr></thead>
    <tbody id="phWwBody"><tr><td colspan="4" style="text-align:center;padding:16px;color:var(--muted)">Click <b>Scan web roots</b> to list world-writable files (read-only; bounded: depth 6, first 500, low priority).</td></tr></tbody></table>
  </div>
</div>

<div class="card ph-force" id="phForceCard">
  <div class="ph-col-h" style="padding:0 0 6px">&#128683; Force unprotect &amp; ignore</div>
  <details class="gl-fold" style="margin:0 0 10px"><summary><span class="gl-chev">&#9656;</span>How this works</summary>
  <div class="meta" style="font-size:12.5px;line-height:1.6;margin:6px 0 0">
    Removes <b>every</b> lock this plugin holds over <b><?= smpro_h($u) ?></b> — not just what is selected above — and records that it must stay removed.
    Use it for an account that cannot take file hardening: a site that updates itself, a deploy that rewrites its own configuration, an owner who edits core files.
    Without the ignore list the next automatic pass would simply lock it again.
    Anything it cannot unlock is reported rather than counted as done.
  </div>
  </details>
  <?php if ($igNow): ?>
    <div class="ph-ignnow">
      Already on the ignore list since <b><?= smpro_h(date('Y-m-d H:i', strtotime($igNow['at'] ?: 'now'))) ?></b>
      <?= $igNow['by'] !== '' ? ' &middot; added by <b>' . smpro_h($igNow['by']) . '</b>' : '' ?>
      <?= $igNow['reason'] !== '' ? ' &middot; ' . smpro_h($igNow['reason']) : '' ?>
      &middot; scope: <b><?= $igNow['scope'] === 'auto' ? 'automatic passes only' : 'all protection' ?></b>.
      Running it again re-clears any lock that came back.
    </div>
  <?php endif; ?>
  <div class="ph-forcerow">
    <input class="tp-in" id="phForceReason" maxlength="160" placeholder="Why is this account excluded? (recorded in the audit trail)" style="flex:1;min-width:240px">
    <select class="tp-sel" id="phForceScope">
      <option value="all">Exclude from all protection</option>
      <option value="auto">Exclude from automatic passes only</option>
    </select>
    <button class="tp-btn danger" type="button" id="phForce">&#128683; Force unprotect</button>
  </div>
  <div class="meta" style="font-size:11.5px;margin-top:8px"><b>Exclude from automatic passes only</b> leaves you able to protect the account by hand from this page; emergency response and auto re-lock still skip it. Cleaning a compromised site is never skipped either way — removing a web shell is not the same promise as locking files the owner writes to.</div>
</div>

<div class="card" id="ph-activity" style="padding:0;overflow:hidden">
  <div class="ph-card-h"><b>Protection Activity</b><span class="meta">last actions for <?= smpro_h($u) ?></span></div>
  <div class="ph-tablewrap" style="max-height:280px">
    <table class="smpro-table"><thead><tr><th>Time</th><th>Action</th><th>Summary</th><th>Details</th></tr></thead><tbody>
    <?php $rows = smpro_ph_audit_rows($u); if (!$rows): ?><tr><td colspan="4" class="ph-empty" style="text-align:center;padding:16px">No activity yet for this account.</td></tr>
    <?php else: foreach ($rows as $a): ?>
      <tr data-row><td class="mono" style="font-size:11px"><?= smpro_h(date('Y-m-d H:i', strtotime($a['time'] ?? 'now'))) ?></td>
        <td><span class="b gray"><?= smpro_h($a['action'] ?? '') ?></span></td>
        <td><?= smpro_h($a['message'] ?? '') ?></td>
        <td class="meta" style="font-size:11px"><?php $ex = $a['extra'] ?? []; $parts = []; foreach ($ex as $k => $v) if (is_scalar($v)) $parts[] = $k . '=' . $v; echo smpro_h(implode(', ', $parts)); ?></td></tr>
    <?php endforeach; endif; ?>
    </tbody></table>
  </div>
</div>
<?php endif; /* valid */ ?>

<?php $rul = function_exists('smpro_spr_get') ? smpro_spr_get() : null; ?>
<?php if ($rul !== null): ?>
<div class="card" id="ph-rules" style="padding:0;overflow:hidden;margin-top:14px">
  <div class="ph-card-h"><b>&#9881; Approve some releases automatically</b>
    <span class="meta">rules you set, applied when a request arrives</span>
    <span style="flex:1"></span>
    <span class="b <?= ($rul['auto_hour'] || $rul['auto_permanent']) ? 'orange' : 'gray' ?>">
      <?= ($rul['auto_hour'] || $rul['auto_permanent']) ? 'active' : 'off' ?></span></div>

  <details class="gl-fold" style="padding:12px 16px 0;margin:0"><summary><span class="gl-chev">&#9656;</span>How this works</summary>
  <div class="meta" style="font-size:12.5px;padding:8px 0 0;line-height:1.65">
    Accounts protect their own files without asking; only a <b>release</b> reaches you. On a busy server that queue
    gets long, so you can let some of it through by itself.
    <br><br>
    <b>Where the request came from is established by this server, not by the account.</b> The page sends the address
    of the customer's cPanel session, but that file is written by the account, so a breached account could put any
    address in it. The rule below is therefore matched against the address in <b>this server's own cPanel login
    records</b> — and a request whose address cannot be established that way is never granted automatically. It
    simply waits for you, which is what would have happened anyway.
    <br><br>
    Rules can only ever <b>approve</b>. Nothing here declines a request, because a request that quietly disappears
    looks exactly like one that was lost.
  </div>
  </details>

  <div style="padding:0 16px 14px">
    <label class="lm-chkl" style="display:block;margin-bottom:9px">
      <input type="checkbox" id="rlHour" <?= $rul['auto_hour'] ? 'checked' : '' ?>>
      <span>Grant <b>one-hour releases</b> automatically <span class="meta">— the server re-locks by itself afterwards, so the exposure ends on its own</span></span>
    </label>
    <label class="lm-chkl" style="display:block;margin-bottom:9px">
      <input type="checkbox" id="rlPerm" <?= $rul['auto_permanent'] ? 'checked' : '' ?>>
      <span>Grant <b>permanent releases</b> automatically <span class="meta">— this also puts the account on the ignore list, so nothing protects it again until you take it off. Leave this off unless you are sure.</span></span>
    </label>
    <label class="lm-chkl" style="display:block;margin-bottom:12px">
      <input type="checkbox" id="rlAllow" <?= $rul['need_allowlist'] ? 'checked' : '' ?>>
      <span>Accept an address that is on your <b>firewall allow-list</b> <span class="meta">— the same lists Firewall Status keeps</span></span>
    </label>

    <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end">
      <label class="ph-fld" style="flex:1;min-width:220px">Countries to accept
        <input class="tp-in" id="rlCC" value="<?= smpro_h(implode(', ', $rul['countries'])) ?>" placeholder="EG, SA, AE — leave empty for none">
        <span class="meta" style="display:flex;gap:6px;flex-wrap:wrap;margin-top:5px;font-size:11.5px">presets:
          <button type="button" class="tp-btn rlPreset" style="padding:1px 8px;font-size:11px" data-cc="EG, SA, AE, KW, QA, BH, OM, JO, LB, SY, IQ, PS, YE, LY, TN, DZ, MA, SD, MR, SO, DJ, KM" title="the 22 members of the Arab League">Arab countries</button>
          <button type="button" class="tp-btn rlPreset" style="padding:1px 8px;font-size:11px" data-cc="SA, AE, KW, QA, BH, OM">Gulf (GCC)</button>
          <button type="button" class="tp-btn rlPreset" style="padding:1px 8px;font-size:11px" data-cc="EG, SA">Egypt + Saudi</button>
          <button type="button" class="tp-btn rlPreset" style="padding:1px 8px;font-size:11px" data-cc="" title="append the current input instead of replacing it: hold Shift">clear</button>
        </span>
      </label>
      <label class="ph-fld" style="width:150px">Most items in one request
        <input class="tp-in" id="rlMax" type="number" min="0" max="500" value="<?= (int)$rul['max_items'] ?>">
      </label>
      <button class="tp-btn primary" type="button" id="rlSave">Save rules</button>
    </div>
    <div class="meta" style="font-size:11.5px;margin-top:9px">
      A country is only accepted when the address resolves to it. An address whose country cannot be resolved is
      never treated as a match &mdash; unknown is not a country.
    </div>
    <div class="meta" id="rlMsg" style="font-size:12.5px;margin-top:9px"><b>Now:</b> <?= smpro_h(function_exists('smpro_spr_describe') ? smpro_spr_describe() : '') ?></div>
  </div>
</div>
<?php endif; ?>

<?php $asks = function_exists('smpro_spq_asks_all') ? smpro_spq_asks_all() : []; ?>
<?php if ($asks): ?>
<div class="card" id="ph-asks" style="padding:0;overflow:hidden;margin-top:14px;border-left:3px solid var(--warn)">
  <div class="ph-card-h"><b>&#9993; Accounts asking to be released</b>
    <span class="meta">sent from Safety Lock in their own cPanel &mdash; protecting needs no approval, releasing does</span>
    <span style="flex:1"></span><span class="b orange"><?= count($asks) ?> waiting</span></div>
  <div class="ph-tablewrap" style="max-height:340px">
    <table class="smpro-table"><thead><tr><th>Account</th><th>Asking for</th><th>Why</th><th>When</th><th></th></tr></thead><tbody>
    <?php foreach ($asks as $a): $exists = smpro_ph_valid_user($a['user']); $perm = ($a['verb'] ?? '') !== 'unlock_selected'; ?>
      <tr>
        <td class="mono"><b><?= smpro_h($a['user']) ?></b><?= $exists ? '' : ' <span class="b gray">gone</span>' ?></td>
        <td>
          <?php if ($perm): ?>
            <span class="b red">stop protecting the account</span>
            <div class="meta" style="font-size:11.5px;margin-top:3px">Not a file selection &mdash; every lock on the whole account comes off and it goes on the ignore list, so nothing automatic protects it again.</div>
          <?php else: ?>
            <span class="b orange">1 hour, then re-lock</span>
            <div class="meta" style="font-size:11.5px;margin-top:3px"><?= count($a['items']) ?> item(s) chosen &middot; the server restores the locks by itself.</div>
          <?php endif; ?>
          <?php if (!empty($a['items'])): ?>
            <div class="meta mono" style="font-size:11px;margin-top:3px"><?= smpro_h(implode(', ', array_slice($a['items'], 0, 6))) ?><?= count($a['items']) > 6 ? ' …' : '' ?></div>
          <?php endif; ?>
        </td>
        <td><?= $a['reason'] !== '' ? smpro_h($a['reason']) : '<span class="meta">no reason given</span>' ?>
          <?php
            $claim = (string)($a['claimed_ip'] ?? '');
            $real  = function_exists('smpro_spr_login_ip') ? smpro_spr_login_ip($a['user']) : '';
          ?>
          <?php if ($claim !== '' || $real !== ''): ?>
            <div class="meta mono" style="font-size:11px;margin-top:4px">
              <?php if ($real !== ''): ?>signed in from <b><?= smpro_h($real) ?></b><?php else: ?>no recent cPanel login on record<?php endif; ?>
              <?php if ($claim !== '' && $real !== '' && $claim !== $real): ?>
                &middot; <span style="color:var(--warn)">the page reported <?= smpro_h($claim) ?> instead</span>
              <?php endif; ?>
            </div>
          <?php endif; ?>
        </td>
        <td class="mono" style="font-size:11px"><?= smpro_h($a['at'] !== '' ? date('Y-m-d H:i', strtotime($a['at'])) : '—') ?></td>
        <td><div class="acts">
          <button class="tp-btn danger ph-askdec" type="button" data-user="<?= smpro_h($a['user']) ?>" data-grant="1" data-perm="<?= $perm ? '1' : '0' ?>">Approve</button>
          <button class="tp-btn ph-askdec" type="button" data-user="<?= smpro_h($a['user']) ?>" data-grant="0" data-perm="<?= $perm ? '1' : '0' ?>">Decline</button>
        </div></td>
      </tr>
    <?php endforeach; ?>
    </tbody></table>
  </div>
  <div class="meta" style="font-size:11.5px;padding:10px 16px">
    Accounts lock their own files without asking &mdash; making yourself safer needs nobody's permission. Only
    taking protection away arrives here, because an account that could release itself could switch its own
    protection off the moment it was broken into.
  </div>
</div>
<?php endif; ?>

<?php $ignAll = smpro_ph_ign_all(); ?>
<div class="card" id="phIgnList" style="padding:0;overflow:hidden;margin-top:14px">
  <div class="ph-card-h"><b>&#128203; Ignore list</b>
    <span class="meta">accounts deliberately left unprotected &mdash; automatic hardening skips them</span>
    <span style="flex:1"></span><span class="b gray"><?= count($ignAll) ?> account(s)</span></div>
  <?php if (!$ignAll): ?>
    <div class="ph-empty" style="padding:16px;text-align:center">Nothing is excluded. Every account can be protected, and automatic passes apply to all of them.</div>
  <?php else: ?>
  <div class="ph-tablewrap" style="max-height:320px">
    <table class="smpro-table"><thead><tr><th>Account</th><th>Scope</th><th>Reason</th><th>Added by</th><th>When</th><th></th></tr></thead><tbody>
    <?php foreach ($ignAll as $row): $exists = smpro_ph_valid_user($row['user']); ?>
      <tr>
        <td class="mono"><b><?= smpro_h($row['user']) ?></b><?= $exists ? '' : ' <span class="b gray" title="The account no longer exists on this server — the entry is kept until you remove it.">gone</span>' ?></td>
        <td><span class="b <?= $row['scope'] === 'auto' ? 'gray' : 'red' ?>"><?= $row['scope'] === 'auto' ? 'automatic only' : 'all protection' ?></span></td>
        <td><?= $row['reason'] !== '' ? smpro_h($row['reason']) : '<span class="meta">no reason recorded</span>' ?></td>
        <td class="mono" style="font-size:11px"><?= smpro_h($row['by'] !== '' ? $row['by'] : 'unknown') ?></td>
        <td class="mono" style="font-size:11px"><?= smpro_h($row['at'] !== '' ? date('Y-m-d H:i', strtotime($row['at'])) : '—') ?></td>
        <td><button class="tp-btn ph-ignrm" type="button" data-user="<?= smpro_h($row['user']) ?>">&#10007; Remove</button></td>
      </tr>
    <?php endforeach; ?>
    </tbody></table>
  </div>
  <div class="meta" style="font-size:11.5px;padding:10px 16px">Removing an entry does not re-protect the account by itself &mdash; it only makes it eligible again. Open the account above and apply protection when you want it back.</div>
  <?php endif; ?>
</div>


<style>
.svc-kicker{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--brand);font-weight:800}
.ph-bad{background:var(--dang-bg);color:var(--dang);border-left:4px solid var(--dang);font-size:14px;margin:14px 0}
.ph-pick{display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap;margin:14px 0}
.ph-fld{display:flex;flex-direction:column;gap:5px;font-size:11px;text-transform:uppercase;color:var(--muted);font-weight:700;flex:1;min-width:220px}
.ph-fld .tp-in{width:100%}
.tp-in,.tp-sel{border:1px solid var(--line);border-radius:9px;padding:9px 12px;font-size:13px}
.tp-btn{border:1px solid var(--line);border-radius:9px;padding:9px 15px;font-size:13px;font-weight:600;cursor:pointer;text-decoration:none;color:var(--ink);background:var(--card);display:inline-block}.tp-btn.green{background:var(--good);color:#fff;border-color:var(--good)}
.ph-hero{background:linear-gradient(135deg,#10213f,#0b172d);color:#fff;border-radius:18px;padding:20px 22px;margin:14px 0}
.ph-hero-row{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}@media(max-width:760px){.ph-hero-row{grid-template-columns:repeat(2,1fr)}}
.ph-stat .l{font-size:11px;text-transform:uppercase;color:#9fb6da;font-weight:700;letter-spacing:.04em}
.ph-stat .v{font-size:21px;font-weight:800;margin-top:4px}.ph-stat .ph-of{font-size:13px;color:#9fb6da;font-weight:600}
.ph-hero-foot{display:flex;gap:12px;flex-wrap:wrap;align-items:center;margin-top:14px;padding-top:12px;border-top:1px solid rgba(255,255,255,.12)}
.ph-path{font-family:ui-monospace,Consolas,monospace;font-size:12px;background:rgba(255,255,255,.1);padding:4px 10px;border-radius:8px}
.ph-ev{font-size:12px;color:#9fb6da}
.ph-pill{display:inline-block;font-size:11px;font-weight:700;padding:3px 10px;border-radius:20px;background:#334155;color:#fff}
.ph-pill.good{background:#16a34a}.ph-pill.warn{background:#d97706}.ph-pill.muted{background:#475569}
.ph-modes{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin:14px 0}@media(max-width:760px){.ph-modes{grid-template-columns:1fr}}
.ph-mode{display:flex;gap:14px;align-items:flex-start;background:var(--card);border:2px solid var(--line);border-radius:16px;padding:18px;cursor:pointer;position:relative}
.ph-mode.active{border-color:var(--brand);box-shadow:0 6px 20px rgba(37,99,235,.12)}
.ph-mode-ic{width:42px;height:42px;border-radius:12px;background:var(--card);display:flex;align-items:center;justify-content:center;font-size:20px;flex-shrink:0}
.ph-mode-t{font-size:16px;font-weight:800}.ph-mode-d{font-size:12.5px;color:var(--muted);margin-top:4px;line-height:1.5}
.ph-check{position:absolute;top:14px;right:14px;width:24px;height:24px;border-radius:50%;background:#e2e8f0;color:#fff;display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:800}
.ph-mode.active .ph-check{background:var(--brand)}
.ph-card-h{display:flex;align-items:center;gap:10px;padding:14px 16px;border-bottom:1px solid var(--line);flex-wrap:wrap}.ph-card-h>b{font-size:14px}.ph-card-h .meta{font-size:12px}
.ph-badge{display:inline-block;font-size:12px;font-weight:700;padding:4px 11px;border-radius:20px;background:var(--brand-bg);color:var(--brand);margin-right:6px}
.ph-badge.conf-high{background:var(--good-bg);color:#166534}.ph-badge.conf-medium{background:var(--warn-bg);color:#92400e}.ph-badge.conf-low{background:var(--dang-bg);color:#991b1b}
.ph-two{display:grid;grid-template-columns:1fr 1fr;gap:16px;padding:14px 16px}@media(max-width:760px){.ph-two{grid-template-columns:1fr}}
.ph-col-h{font-size:13px;font-weight:700;margin-bottom:8px}
.ph-item{font-size:12px;padding:8px 11px;border:1px solid var(--line);border-radius:9px;margin-bottom:6px;background:var(--card)}
.ph-empty{font-size:12px;color:var(--muted);padding:10px 0}
.ph-note{margin:0 16px 16px;background:var(--warn-bg);color:#8a6516;border-radius:10px;padding:10px 12px;font-size:12.5px;font-weight:600}
.ph-rootchip{font-size:11px;font-weight:700;background:#0f172a;color:#fff;padding:5px 11px;border-radius:8px}
.ph-tablewrap{overflow:auto;max-height:520px}
.ph-tablewrap thead th{position:sticky;top:0;background:var(--card);z-index:1;box-shadow:inset 0 -1px 0 var(--line)}
.smpro-table{width:100%;border-collapse:collapse;font-size:12.5px}
.smpro-table th,.smpro-table td{padding:8px 12px;text-align:left;border-bottom:1px solid var(--line);white-space:nowrap}
.smpro-table th{font-size:11px;text-transform:uppercase;color:var(--muted)}.smpro-table td.num,.smpro-table th.num{text-align:right}
.mono{font-family:ui-monospace,Consolas,monospace}
.ph-sugg{display:inline-block;font-size:10px;font-weight:700;color:var(--brand);background:var(--brand-bg);padding:1px 6px;border-radius:10px;margin-left:5px}
.ph-crumbs{font-size:12px;display:flex;align-items:center;gap:5px;flex-wrap:wrap}
.ph-crumb{color:var(--brand);text-decoration:none;font-weight:600}.ph-crumb:hover{text-decoration:underline}
.ph-sep{color:var(--muted)}
.ph-dirnav{color:var(--brand);text-decoration:none;font-weight:600}.ph-dirnav:hover{text-decoration:underline}
.ph-cust-actions{display:flex;gap:8px;align-items:center;padding:12px 16px;border-top:1px solid var(--line);flex-wrap:wrap}
.ph-exts{margin:14px 0}.ph-extlist{display:flex;gap:8px;flex-wrap:wrap}
.ph-extl{font-size:12px;background:var(--card);border:1px solid var(--line);border-radius:20px;padding:6px 11px;cursor:pointer}
.b{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:20px}
.b.red{background:var(--dang-bg);color:var(--dang)}.b.green{background:var(--good-bg);color:var(--good)}.b.gray{background:var(--card);color:#475569}
.meta{color:var(--muted)}
.ph-force{margin:14px 0;border-left:3px solid var(--dang)}
.ph-forcerow{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.ph-ignnow{background:var(--warn-bg);color:#8a6516;border-radius:10px;padding:9px 12px;font-size:12.5px;margin-bottom:10px}
.ph-ignbanner{border-left:3px solid var(--dang);margin:14px 0;display:flex;flex-direction:column;gap:8px}
.ph-ignb-h{display:flex;align-items:center;gap:10px;font-size:14px;flex-wrap:wrap}
.ph-ignb-b{font-size:13px;line-height:1.6}
.ph-ignb-a{display:flex;gap:8px;flex-wrap:wrap}
.ph-off{opacity:.55}.ph-off .ph-mode{cursor:not-allowed}
</style>
<?php if ($valid && $primary): ?>
<script>
(function(){
  function post(fd){return fetch('index.cgi?page=php-harden',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'}).then(function(r){return r.json();});}
  function exts(){return Array.prototype.slice.call(document.querySelectorAll('.ph-ext:checked')).map(function(c){return c.value;});}
  var fast=document.getElementById('phModeFast'),custom=document.getElementById('phModeCustom'),
      fc=document.getElementById('phFast'),cc=document.getElementById('phCustom');
  function setMode(m){var isC=m==='custom';
    fast.classList.toggle('active',!isC);custom.classList.toggle('active',isC);
    fc.style.display=isC?'none':'';cc.style.display=isC?'':'none';
    fast.querySelector('input').checked=!isC;custom.querySelector('input').checked=isC;}
  fast.addEventListener('click',function(){setMode('fast');});
  custom.addEventListener('click',function(){setMode('custom');});

  var bForce=document.getElementById('phForce');
  if(bForce)bForce.addEventListener('click',function(){
    var reason=(document.getElementById('phForceReason').value||'').trim(),
        scope=document.getElementById('phForceScope').value;
    if(!reason){alert('Give a reason first — this entry outlives the session that created it, and an unexplained exclusion is impossible to review later.');document.getElementById('phForceReason').focus();return;}
    if(!confirm('Force unprotect '+PH_USER+'?\n\nEvery lock this plugin holds over the account is removed — including locks not listed above — and the account is added to the ignore list ('+(scope==='auto'?'automatic passes only':'all protection')+').\n\nThe site loses this layer of protection until you remove it from the list.'))return;
    var b=this,old=b.innerHTML;b.disabled=true;b.innerHTML='⏳ Removing protection…';
    var fd=new URLSearchParams();fd.set('ph_action','force_unprotect');fd.set('phuser',PH_USER);fd.set('smpro_csrf',PH_CSRF);
    fd.set('reason',reason);fd.set('scope',scope);
    post(fd).then(function(j){alert((j.ok?'✓ ':'⚠ ')+(j.msg||''));location.reload();})
      .catch(function(){b.disabled=false;b.innerHTML=old;alert('Request failed — nothing was changed.');});
  });

  // The ticked folders travel with either apply action; an empty list means "do not lock any folder", which is
  // also how a previously locked folder is released by re-applying without it.
  function lockRoots(){return Array.prototype.slice.call(document.querySelectorAll('.ph-lockroot:checked')).map(function(c){return c.value;});}
  var bf=document.getElementById('phApplyFast');
  bf.addEventListener('click',function(){
    if(!confirm('Apply Fast Protection to '+PH_USER+'?\n\nLocks the detected stack’s critical files (chattr +i) and guards upload/cache/log folders. Backed up first; reversible from Custom → Unlock.'))return;
    var old=bf.innerHTML;bf.disabled=true;bf.innerHTML='⏳ Applying…';
    var fd=new URLSearchParams();fd.set('ph_action','apply_fast');fd.set('phuser',PH_USER);fd.set('smpro_csrf',PH_CSRF);exts().forEach(function(e){fd.append('exts[]',e);});lockRoots().forEach(function(r){fd.append('lock_roots[]',r);});
    post(fd).then(function(j){bf.disabled=false;bf.innerHTML=old;alert((j.ok?'✅ ':'⚠ ')+(j.msg||'Done'));if(j.ok)location.reload();}).catch(function(){bf.disabled=false;bf.innerHTML=old;alert('Request failed.');});
  });

  var body=document.getElementById('phBody'),info=document.getElementById('phSelInfo');
  function chks(){return Array.prototype.slice.call(body.querySelectorAll('.ph-chk'));}
  function sel(){return chks().filter(function(c){return c.checked&&c.closest('tr').style.display!=='none';});}
  function upd(){info.textContent=sel().length+' selected';}
  body.addEventListener('change',function(e){if(e.target.classList.contains('ph-chk'))upd();});
  document.getElementById('phChkAll').addEventListener('change',function(e){chks().forEach(function(c){if(c.closest('tr').style.display!=='none')c.checked=e.target.checked;});upd();});
  document.getElementById('phSelVis').addEventListener('click',function(){chks().forEach(function(c){if(c.closest('tr').style.display!=='none')c.checked=true;});upd();});
  document.getElementById('phSelClear').addEventListener('click',function(){chks().forEach(function(c){c.checked=false;});upd();});
  document.getElementById('phSelSugg').addEventListener('click',function(){chks().forEach(function(c){c.checked=c.getAttribute('data-sugg')==='1';});upd();});
  var filt=document.getElementById('phFilter');
  filt.addEventListener('input',function(){var q=this.value.toLowerCase();body.querySelectorAll('tr').forEach(function(tr){tr.style.display=(tr.getAttribute('data-name')||'').indexOf(q)>=0?'':'none';});});

  // ---- folder navigation (drill into subfolders) ----
  var ROOT=document.getElementById('phCrumbs').getAttribute('data-root'), curDir=ROOT, upBtn=document.getElementById('phUp');
  function setCrumbs(dir){
    var c=document.getElementById('phCrumbs'), rel=dir.slice(ROOT.length).replace(/^\/+/,''), parts=rel?rel.split('/'):[];
    var html='<a href="#" class="ph-crumb" data-dir="'+ROOT+'">'+(ROOT.split('/').pop()||'root')+'</a>', acc=ROOT;
    parts.forEach(function(p){acc+='/'+p;html+=' <span class="ph-sep">/</span> <a href="#" class="ph-crumb" data-dir="'+acc+'">'+p+'</a>';});
    c.innerHTML=html; upBtn.disabled=(dir===ROOT);
  }
  function nav(dir){
    curDir=dir;
    body.innerHTML='<tr><td colspan="6" style="text-align:center;padding:16px;color:var(--muted)">&#9203; Loading…</td></tr>';
    fetch('index.cgi?page=php-harden&phuser='+encodeURIComponent(PH_USER)+'&ajax=browse&dir='+encodeURIComponent(dir),{cache:'no-store'})
      .then(function(r){return r.text();}).then(function(html){body.innerHTML=html;setCrumbs(dir);upd();if(filt.value)filt.dispatchEvent(new Event('input'));})
      .catch(function(){body.innerHTML='<tr><td colspan="6" style="color:var(--dang);padding:16px">Failed to load folder.</td></tr>';});
  }
  body.addEventListener('click',function(e){var a=e.target.closest('.ph-dirnav');if(a){e.preventDefault();nav(a.getAttribute('data-dir'));}});
  document.getElementById('phCrumbs').addEventListener('click',function(e){var a=e.target.closest('.ph-crumb');if(a){e.preventDefault();nav(a.getAttribute('data-dir'));}});
  upBtn.addEventListener('click',function(){if(curDir===ROOT)return;var up=curDir.replace(/\/[^/]+\/?$/,'');if(up.length<ROOT.length)up=ROOT;nav(up);});

  function collect(){var f=[],d=[];sel().forEach(function(c){(c.getAttribute('data-type')==='dir'?d:f).push(c.value);});return {f:f,d:d};}
  document.getElementById('phApplyCustom').addEventListener('click',function(){
    var s=collect();if(!s.f.length&&!s.d.length){alert('Select at least one file or folder.');return;}
    if(!confirm('Lock '+s.f.length+' file(s) + '+s.d.length+' folder(s) for '+PH_USER+'?\n\nBacked up first; reversible.'))return;
    var b=this,old=b.innerHTML;b.disabled=true;b.innerHTML='⏳ Locking…';
    var fd=new URLSearchParams();fd.set('ph_action','apply_custom');fd.set('phuser',PH_USER);fd.set('smpro_csrf',PH_CSRF);lockRoots().forEach(function(r){fd.append('lock_roots[]',r);});
    s.f.forEach(function(x){fd.append('files[]',x);});s.d.forEach(function(x){fd.append('dirs[]',x);});exts().forEach(function(e){fd.append('exts[]',e);});
    post(fd).then(function(j){b.disabled=false;b.innerHTML=old;alert((j.ok?'✅ ':'⚠ ')+(j.msg||'Done'));if(j.ok)location.reload();}).catch(function(){b.disabled=false;b.innerHTML=old;alert('Request failed.');});
  });
  document.getElementById('phUnlock').addEventListener('click',function(){
    var s=collect();if(!s.f.length&&!s.d.length){alert('Select at least one locked file or folder.');return;}
    var dur=document.getElementById('phUnlockDur').value;
    if(!confirm('Unlock '+s.f.length+' file(s) + '+s.d.length+' folder(s)? ('+dur+')'))return;
    var b=this,old=b.innerHTML;b.disabled=true;b.innerHTML='⏳ Unlocking…';
    var fd=new URLSearchParams();fd.set('ph_action','unlock');fd.set('phuser',PH_USER);fd.set('smpro_csrf',PH_CSRF);fd.set('duration',dur);
    s.f.forEach(function(x){fd.append('files[]',x);});s.d.forEach(function(x){fd.append('dirs[]',x);});
    post(fd).then(function(j){b.disabled=false;b.innerHTML=old;alert((j.ok?'✅ ':'⚠ ')+(j.msg||'Done'));if(j.ok)location.reload();}).catch(function(){b.disabled=false;b.innerHTML=old;alert('Request failed.');});
  });

  // ---- world-writable web files: read-only scan (GET) + safe fix (POST + CSRF) ----
  var wwBody=document.getElementById('phWwBody'),wwInfo=document.getElementById('phWwInfo'),
      wwScan=document.getElementById('phWwScan'),wwFix=document.getElementById('phWwFix');
  function wwRun(){
    wwScan.disabled=true;wwFix.disabled=true;
    wwBody.innerHTML='<tr><td colspan="4" style="text-align:center;padding:16px;color:var(--muted)">&#9203; Scanning web roots…</td></tr>';
    fetch('index.cgi?page=php-harden&phuser='+encodeURIComponent(PH_USER)+'&ajax=wwscan',{cache:'no-store'})
      .then(function(r){return r.text();})
      .then(function(html){
        wwBody.innerHTML=html;wwScan.disabled=false;
        var n=wwBody.querySelectorAll('tr[data-ww="1"]').length;
        wwInfo.textContent=n?(n+' world-writable file(s) found'):'clean — no world-writable files';
        wwFix.disabled=(n===0);
      })
      .catch(function(){wwScan.disabled=false;wwInfo.textContent='scan failed';wwBody.innerHTML='<tr><td colspan="4" style="color:var(--dang);padding:16px">Scan request failed.</td></tr>';});
  }
  wwScan.addEventListener('click',wwRun);
  wwFix.addEventListener('click',function(){
    if(!confirm('Remove world-write (chmod o-w) from all listed files for '+PH_USER+'?\n\nOnly the o+w bit is cleared per file (e.g. 0666 -> 0664); owner/group bits are untouched. Symlinks and any path outside /home/'+PH_USER+' are refused. Previous modes are saved for rollback.'))return;
    var old=wwFix.innerHTML;wwFix.disabled=true;wwFix.innerHTML='⏳ Fixing…';
    var fd=new URLSearchParams();fd.set('ph_action','ww_fix');fd.set('phuser',PH_USER);fd.set('smpro_csrf',PH_CSRF);
    post(fd).then(function(j){wwFix.innerHTML=old;alert((j.ok?'✅ ':'⚠ ')+(j.msg||'Done'));wwRun();})
      .catch(function(){wwFix.disabled=false;wwFix.innerHTML=old;alert('Request failed.');});
  });
})();
</script>
<?php endif; ?>
<script>
/* The ignore list is server-wide, so it renders with or without an account selected - its removal handler
   cannot live inside the per-account script above, which is not emitted when no account is chosen. */
(function(){
  var CSRF=<?= json_encode($csrf) ?>;
  document.querySelectorAll('.rlPreset').forEach(function(b){ b.addEventListener('click',function(e){ var inp=document.getElementById('rlCC'), v=b.getAttribute('data-cc')||''; if(e.shiftKey&&inp.value.trim()&&v){ var have=inp.value.split(/[\s,]+/).filter(Boolean); v.split(/[\s,]+/).forEach(function(x){ if(have.indexOf(x)===-1) have.push(x); }); inp.value=have.join(', '); } else inp.value=v; inp.focus(); }); });
  var rs=document.getElementById('rlSave');
  if(rs)rs.addEventListener('click',function(){
    var perm=document.getElementById('rlPerm').checked;
    if(perm&&!confirm('Grant PERMANENT releases automatically?\n\nAn account that qualifies will have every lock removed and be added to the ignore list without you seeing the request. Nothing will protect it again until you take it off the list.'))return;
    var o=rs.innerHTML;rs.disabled=true;rs.innerHTML='⏳ saving…';
    var f=new URLSearchParams();
    f.set('ph_action','rules_save');f.set('smpro_csrf',CSRF);
    f.set('auto_hour',document.getElementById('rlHour').checked?'1':'');
    f.set('auto_permanent',perm?'1':'');
    f.set('need_allowlist',document.getElementById('rlAllow').checked?'1':'');
    f.set('countries',document.getElementById('rlCC').value);
    f.set('max_items',document.getElementById('rlMax').value);
    fetch('index.cgi?page=php-harden',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:f.toString(),cache:'no-store'})
      .then(function(r){return r.json();})
      .then(function(j){
        rs.disabled=false;rs.innerHTML=o;
        var m=document.getElementById('rlMsg');
        m.innerHTML='<b>Now:</b> '+((j&&j.msg)||'No answer from the server.');
        m.style.color=(j&&j.ok)?'var(--good)':'var(--dang)';
      })
      .catch(function(){rs.disabled=false;rs.innerHTML=o;alert('Request failed — nothing was saved.');});
  });

  document.addEventListener('click',function(ev){
    var d=ev.target.closest?ev.target.closest('.ph-askdec'):null;
    if(d){
      var who=d.getAttribute('data-user')||'', grant=d.getAttribute('data-grant')==='1',
          perm=d.getAttribute('data-perm')==='1';
      var q=grant
        ? (perm
            ? 'Release '+who+' permanently?\n\nEvery lock on the account is removed and it goes on the ignore list, so nothing automatic protects it again until you take it off.'
            : 'Release the chosen items for '+who+' for one hour?\n\nThe server locks them again by itself afterwards.')
        : 'Decline the request from '+who+'?\n\nNothing changes for the account and the request is cleared.';
      if(!confirm(q))return;
      var od=d.innerHTML;d.disabled=true;d.innerHTML='⏳';
      var fa=new URLSearchParams();fa.set('ph_action','ask_decide');fa.set('target',who);fa.set('grant',grant?'1':'0');fa.set('smpro_csrf',CSRF);
      fetch('index.cgi?page=php-harden',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fa.toString(),cache:'no-store'})
        .then(function(r){return r.json();})
        .then(function(j){alert((j&&j.ok?'✓ ':'⚠ ')+((j&&j.msg)||''));location.reload();})
        .catch(function(){d.disabled=false;d.innerHTML=od;alert('Request failed — nothing was changed.');});
      return;
    }
    var b=ev.target.closest?ev.target.closest('.ph-ignrm'):null; if(!b)return;
    var who=b.getAttribute('data-user')||'';
    if(!confirm('Remove '+who+' from the ignore list?\n\nAutomatic hardening will apply to it again. This does not re-protect the account on its own — open it and apply protection when you want it back.'))return;
    var old=b.innerHTML;b.disabled=true;b.innerHTML='⏳';
    var fd=new URLSearchParams();fd.set('ph_action','ign_remove');fd.set('target',who);fd.set('smpro_csrf',CSRF);
    fetch('index.cgi?page=php-harden',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'})
      .then(function(r){return r.json();})
      .then(function(j){alert((j.ok?'✓ ':'⚠ ')+(j.msg||''));location.reload();})
      .catch(function(){b.disabled=false;b.innerHTML=old;alert('Request failed — the list was not changed.');});
  });
})();
</script>
<style>
/* ---- overview strip + sticky navigator + collapsible cards + folds + pager (pattern: firewall-status.php) ---- */
.fw-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:12px 0}
@media(max-width:640px){.fw-kpis{grid-template-columns:repeat(2,1fr)}}
.fw-nav{position:sticky;top:calc(var(--toph,52px) + 6px);z-index:5;display:flex;gap:6px;flex-wrap:wrap;align-items:center;padding:8px 10px;margin:0 0 14px;background:var(--card);border:1px solid var(--line);border-radius:12px;box-shadow:0 2px 10px rgba(0,0,0,.05)}
.fw-nav a{font-size:12px;font-weight:700;text-decoration:none;color:var(--ink);padding:4px 10px;border-radius:20px;border:1px solid var(--line);white-space:nowrap}
.fw-toggle{cursor:pointer;user-select:none}.fw-toggle:hover{background:var(--bg)}
.gl-fold{margin:6px 0}.gl-fold>summary{cursor:pointer;list-style:none;font-size:12.5px;font-weight:700;color:var(--brand);display:flex;align-items:center;gap:6px}
.gl-fold>summary::-webkit-details-marker{display:none}
.gl-fold>summary .gl-chev{display:inline-block;transition:transform .15s;font-weight:800}.gl-fold[open]>summary .gl-chev{transform:rotate(90deg)}
.fw-pg{display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:8px 16px;border-bottom:1px solid var(--line);font-size:12px;color:var(--muted)}
.fw-pg input{border:1px solid var(--line);border-radius:8px;padding:5px 9px;font-size:12.5px;min-width:180px;background:var(--card);color:inherit}
.fw-pg .sp{flex:1}.fw-pg button{font-size:11.5px;font-weight:700;border:1px solid var(--line);border-radius:7px;padding:3px 9px;cursor:pointer;background:var(--card);color:var(--ink)}
.fw-pg button:disabled{opacity:.45;cursor:default}.fw-pg .n{font-variant-numeric:tabular-nums}
tr.fw-pghide{display:none !important}
</style>
<script>
(function(){
  // make every section card collapsible - click its header to open/close; the choice is remembered per section
  var KEY='smpro:php-harden:open', SEL='.card > .ph-card-h', EXTRA='';
  var open={};
  try{ open=JSON.parse(localStorage.getItem(KEY)||'{}')||{}; }catch(err){ open={}; }
  function remember(){ try{ localStorage.setItem(KEY, JSON.stringify(open)); }catch(err){} }
  function toggleOf(card){ for(var i=0;i<card.children.length;i++){ var c=card.children[i]; if(c.classList&&c.classList.contains('fw-toggle')) return c; } return null; }
  function openCard(id, scroll){
    var el=document.getElementById(id); if(!el) return;
    var node=el;
    while(node && node!==document.body){
      if(node.classList && node.classList.contains('card')){ var th=toggleOf(node); if(th && !node.classList.contains('fw-open')){ node.classList.add('fw-open'); th.setAttribute('aria-expanded','true'); open[th.getAttribute('data-fold')]=true; remember(); } }
      if(node.tagName==='DETAILS' && !node.open) node.open=true;
      node=node.parentElement;
    }
    if(el.tagName!=='DETAILS' && el.classList.contains('card') && !toggleOf(el)){ var d=el.querySelector('details'); if(d && !d.open) d.open=true; }
    if(scroll){ el.style.scrollMarginTop='120px'; try{ el.scrollIntoView({behavior:'smooth',block:'start'}); }catch(e2){ el.scrollIntoView(); } }   // the page scrolls inside .smpro-main
  }
  var gos=document.querySelectorAll('[data-go]');
  for(var g=0;g<gos.length;g++){ (function(a){
    var tid=a.getAttribute('data-go');
    if(!document.getElementById(tid)){ if(a.parentElement && a.parentElement.classList.contains('fw-nav')) a.style.display='none'; return; }   // chip for a section this page does not have
    a.addEventListener('click',function(e){ e.preventDefault(); openCard(tid,true); var xs=document.querySelectorAll('.fw-nav a'); for(var i=0;i<xs.length;i++){ xs[i].classList.toggle('on', xs[i].getAttribute('data-go')===tid); } try{ history.replaceState(null,'','#'+tid); }catch(err){} });
  })(gos[g]); }
  function setAll(on){
    var cards=document.querySelectorAll('.smpro-main .card');
    for(var i=0;i<cards.length;i++){ var th=toggleOf(cards[i]); if(!th) continue; cards[i].classList.toggle('fw-open',on); th.setAttribute('aria-expanded',on?'true':'false'); open[th.getAttribute('data-fold')]=on; }
    if(EXTRA){ var ds=document.querySelectorAll(EXTRA); for(var k=0;k<ds.length;k++){ ds[k].open=on; } }
    remember();
  }
  var oa=document.getElementById('phOpenAll'), ca=document.getElementById('phCloseAll');
  if(oa) oa.addEventListener('click',function(){ setAll(true); });
  if(ca) ca.addEventListener('click',function(){ setAll(false); });
  var ths=document.querySelectorAll(SEL);
  for(var t=0;t<ths.length;t++){ (function(th, n){
    var card=th.parentElement; if(!card||!card.classList.contains('card')) return;
    var body=document.createElement('div'); body.className='fw-collapse';
    while(th.nextSibling){ body.appendChild(th.nextSibling); }
    card.appendChild(body);
    th.classList.add('fw-toggle');
    if(!th.querySelector('.fw-chev')) th.insertAdjacentHTML('afterbegin','<span class="fw-chev">&#9656;</span> ');
    // A stable name for this section: its own heading text (position would move every remembered state when a section is added above it).
    var id=(th.textContent||'').replace(/\s+/g,' ').trim().slice(0,60) || ('card'+n);
    th.setAttribute('data-fold', id);
    var closedByDefault=card.hasAttribute('data-fold-closed');
    var isOpen=Object.prototype.hasOwnProperty.call(open,id) ? !!open[id] : !closedByDefault;
    card.classList.toggle('fw-open', isOpen);
    th.setAttribute('role','button'); th.setAttribute('tabindex','0'); th.style.cursor='pointer'; th.setAttribute('aria-expanded', isOpen?'true':'false');
    function toggle(){ var now=card.classList.toggle('fw-open'); th.setAttribute('aria-expanded', now?'true':'false'); open[id]=now; remember(); }
    th.addEventListener('click',function(e){ if(e.target.closest('a,button,input,select,label,textarea,summary')) return; toggle(); });   // header controls keep working
    th.addEventListener('keydown',function(e){ if(e.key===' '||e.key==='Enter'||e.key==='Spacebar'){ e.preventDefault(); toggle(); } });
  })(ths[t], t); }
  if(location.hash && document.getElementById(location.hash.slice(1))) setTimeout(function(){ openCard(location.hash.slice(1), true); }, 150);
  window.smproOpenCard=openCard;

  // client-side filter + paging (50/page) for a PHP-rendered table: rows carry data-row, hidden rows get .fw-pghide
  function smproPager(tbl, opt){
    opt=opt||{}; var per=opt.per||50; if(!tbl||!tbl.tBodies||!tbl.tBodies[0]) return null;
    var tb=tbl.tBodies[0], rows=[], i;
    for(i=0;i<tb.rows.length;i++){ if(tb.rows[i].hasAttribute('data-row')) rows.push(tb.rows[i]); }
    if(rows.length<(opt.min||12)) return null;
    var wrap=tbl.parentElement, bar=document.createElement('div'); bar.className='fw-pg';
    bar.innerHTML=(opt.nofilter?'':'<input type="search" placeholder="'+(opt.ph||'Filter rows\u2026')+'">')+'<span class="sp"></span><span class="n fw-pginfo"></span><button type="button" class="fw-pgprev">&#8249; prev</button><span class="n fw-pgpos"></span><button type="button" class="fw-pgnext">next &#8250;</button>';
    wrap.parentElement.insertBefore(bar, wrap);
    var inp=bar.querySelector('input'), info=bar.querySelector('.fw-pginfo'), pos=bar.querySelector('.fw-pgpos'), prev=bar.querySelector('.fw-pgprev'), next=bar.querySelector('.fw-pgnext');
    var q='', page=0;
    function textOf(tr){ return (tr.getAttribute('data-search')||tr.textContent||'').replace(/\s+/g,' ').toLowerCase(); }
    function hide(tr,h){ tr.classList.toggle('fw-pghide',h); if(opt.follow){ var nx=tr.nextElementSibling; if(nx&&nx.classList.contains(opt.follow)) nx.classList.toggle('fw-pghide',h); } }
    function draw(){
      var view=[]; for(var k=0;k<rows.length;k++){ var tr=rows[k]; var ok=(!q||textOf(tr).indexOf(q)!==-1) && !(opt.skip&&opt.skip(tr)); if(ok) view.push(tr); else hide(tr,true); }
      var pages=Math.max(1,Math.ceil(view.length/per)); if(page>=pages) page=pages-1; if(page<0) page=0;
      for(var j=0;j<view.length;j++){ hide(view[j], j<page*per || j>=(page+1)*per); }
      var a=view.length?page*per+1:0, b=Math.min((page+1)*per,view.length);
      info.textContent=(view.length>per?('showing '+a+'\u2013'+b+' of '):'')+view.length+' of '+rows.length+' rows';
      pos.textContent=(page+1)+' / '+pages; prev.disabled=page<=0; next.disabled=page>=pages-1;
      var ctrl=rows.length>per?'':'none'; prev.style.display=ctrl; next.style.display=ctrl; pos.style.display=ctrl;
    }
    if(inp) inp.addEventListener('input',function(){ q=inp.value.trim().toLowerCase(); page=0; draw(); });
    prev.addEventListener('click',function(){ if(page>0){ page--; draw(); } });
    next.addEventListener('click',function(){ page++; draw(); });
    draw(); return {draw:draw};
  }
  window.smproPager=smproPager;

  var act=document.getElementById('ph-activity'); if(act) smproPager(act.querySelector('table.smpro-table'), {ph:'Filter activity (action, summary)\u2026'});
})();
</script>

<?php
smpro_layout_footer();
