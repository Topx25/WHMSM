<?php
/**
 * modules/php-harden.php — PHP Harden / Safety Lock (per cPanel account).
 *
 * Smart stack detection (WordPress, Laravel, OpenCart, Joomla, Drupal, Magento,
 * CodeIgniter, generic PHP) + two protection modes:
 *   • Fast Protection  — chattr +i the critical files of the detected stack and
 *     drop+lock a .htaccess "deny exec" guard inside upload/cache/log folders.
 *   • Custom Protection — a file/folder browser with live lock status (lsattr),
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
        && is_file('/var/cpanel/users/' . $u) && is_dir('/home/' . $u);
}
function smpro_ph_home($u) { return '/home/' . $u; }
function smpro_ph_inside($u, $path) {
    $home = realpath(smpro_ph_home($u)); $real = realpath($path);
    return $home && $real && ($real === $home || strpos($real, $home . '/') === 0);
}
function smpro_ph_run($cmd) { $out = []; $rc = 0; @exec($cmd . ' 2>&1', $out, $rc); return [$rc, trim(implode("\n", $out))]; }
function smpro_ph_has($cmd) { $o = []; $rc = 1; @exec('command -v ' . escapeshellarg($cmd) . ' 2>/dev/null', $o, $rc); return $rc === 0 && !empty($o); }
function smpro_ph_chattr($flag, $path) {
    if (!smpro_ph_has('chattr')) return [1, 'chattr not available'];
    if (!file_exists($path) || is_link($path)) return [1, 'missing/symlink skipped'];
    if ($flag !== '+i' && $flag !== '-i') return [1, 'invalid flag'];
    return smpro_ph_run('chattr ' . escapeshellarg($flag) . ' ' . escapeshellarg($path));
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
    foreach (array_chunk($paths, 60) as $chunk) {
        $args = implode(' ', array_map('escapeshellarg', $chunk));
        [$rc, $out] = smpro_ph_run('lsattr -d ' . $args);
        foreach (explode("\n", $out) as $line) {
            if (!preg_match('/^(\S+)\s+(.+)$/', trim($line), $m)) continue;
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
                $roots[$real] = ['domain' => trim($domain), 'root' => $real];
            }
        }
    }
    ksort($roots);
    return array_values($roots);
}

/* ---------------- stack detection ---------------- */
function smpro_ph_read_head($file, $max = 200000) {
    if (!is_file($file) || !is_readable($file)) return '';
    $size = @filesize($file); if ($size !== false && $size > 2 * 1024 * 1024) return '';
    return (string)@file_get_contents($file, false, null, 0, $max);
}
function smpro_ph_de($root, $rel) { return is_dir(rtrim($root, '/') . '/' . ltrim($rel, '/')); }
function smpro_ph_fe($root, $rel) { return is_file(rtrim($root, '/') . '/' . ltrim($rel, '/')); }
function smpro_ph_php_count($root) {
    $n = 0; try { foreach (new DirectoryIterator($root) as $f) if ($f->isFile() && preg_match('/\.php$/i', $f->getFilename())) $n++; } catch (Throwable $e) {}
    return $n;
}
/** Returns the BEST single detection: ['label','confidence','evidence'[],'key']. */
function smpro_ph_detect($root) {
    $cands = [];
    // WordPress
    if (smpro_ph_fe($root, 'wp-config.php') || smpro_ph_de($root, 'wp-content')) {
        $ev = array_values(array_filter([
            smpro_ph_fe($root, 'wp-config.php') ? 'wp-config.php' : '',
            smpro_ph_de($root, 'wp-content') ? 'wp-content/' : '',
            smpro_ph_de($root, 'wp-admin') ? 'wp-admin/' : '',
        ]));
        $cands[] = ['key' => 'wordpress', 'label' => 'WordPress', 'confidence' => count($ev) >= 2 ? 'high' : 'medium', 'evidence' => $ev, 'score' => 50 + count($ev)];
    }
    // Laravel
    if (smpro_ph_fe($root, 'artisan') || (smpro_ph_fe($root, 'composer.json') && smpro_ph_de($root, 'app'))) {
        $ev = []; foreach (['artisan', 'composer.json', '.env'] as $f) if (smpro_ph_fe($root, $f)) $ev[] = $f;
        if (smpro_ph_de($root, 'bootstrap')) $ev[] = 'bootstrap/';
        $cands[] = ['key' => 'laravel', 'label' => 'Laravel / Composer app', 'confidence' => smpro_ph_fe($root, 'artisan') ? 'high' : 'medium', 'evidence' => $ev, 'score' => smpro_ph_fe($root, 'artisan') ? 48 : 30];
    }
    // Joomla
    if (smpro_ph_fe($root, 'configuration.php') && (smpro_ph_de($root, 'administrator') || smpro_ph_de($root, 'libraries'))) {
        $ev = ['configuration.php']; foreach (['administrator', 'libraries', 'components'] as $d) if (smpro_ph_de($root, $d)) $ev[] = $d . '/';
        $cands[] = ['key' => 'joomla', 'label' => 'Joomla', 'confidence' => 'high', 'evidence' => $ev, 'score' => 47];
    }
    // Drupal
    if (smpro_ph_de($root, 'core') && smpro_ph_fe($root, 'sites/default/settings.php') || smpro_ph_fe($root, 'sites/default/default.settings.php')) {
        $ev = []; foreach (['core', 'modules', 'sites'] as $d) if (smpro_ph_de($root, $d)) $ev[] = $d . '/';
        if (smpro_ph_fe($root, 'sites/default/settings.php')) $ev[] = 'sites/default/settings.php';
        $cands[] = ['key' => 'drupal', 'label' => 'Drupal', 'confidence' => 'high', 'evidence' => $ev, 'score' => 46];
    }
    // Magento
    if (smpro_ph_fe($root, 'bin/magento') || smpro_ph_fe($root, 'app/etc/env.php')) {
        $ev = []; foreach (['bin/magento', 'app/etc/env.php', 'app/etc/config.php'] as $f) if (smpro_ph_fe($root, $f)) $ev[] = $f;
        $cands[] = ['key' => 'magento', 'label' => 'Magento', 'confidence' => 'high', 'evidence' => $ev, 'score' => 47];
    }
    // OpenCart
    $oc = [];
    $cfg = smpro_ph_read_head($root . '/config.php');
    if ($cfg !== '') foreach (['DIR_SYSTEM', 'DIR_CATALOG', 'DIR_APPLICATION'] as $m) if (strpos($cfg, $m) !== false) $oc[] = 'config.php:' . $m;
    foreach (['system', 'catalog', 'admin'] as $d) if (smpro_ph_de($root, $d)) $oc[] = $d . '/';
    if (smpro_ph_fe($root, 'system/startup.php')) $oc[] = 'system/startup.php';
    if (count($oc) >= 3) $cands[] = ['key' => 'opencart', 'label' => 'OpenCart / derived', 'confidence' => count($oc) >= 5 ? 'high' : 'medium', 'evidence' => array_slice(array_unique($oc), 0, 6), 'score' => 40 + count($oc)];
    // CodeIgniter
    if (smpro_ph_fe($root, 'system/CodeIgniter.php') || smpro_ph_fe($root, 'spark') || smpro_ph_fe($root, 'application/config/config.php')) {
        $ev = []; foreach (['spark', 'system/CodeIgniter.php', 'application/config/config.php'] as $f) if (smpro_ph_fe($root, $f)) $ev[] = $f;
        $cands[] = ['key' => 'codeigniter', 'label' => 'CodeIgniter', 'confidence' => 'medium', 'evidence' => $ev, 'score' => 35];
    }
    // Generic PHP fallback
    $phpN = smpro_ph_php_count($root);
    if (!$cands) {
        if (smpro_ph_fe($root, 'index.php') || $phpN >= 3) {
            $cands[] = ['key' => 'generic', 'label' => 'Generic PHP site', 'confidence' => $phpN >= 10 ? 'high' : 'medium',
                'evidence' => array_values(array_filter([smpro_ph_fe($root, 'index.php') ? 'index.php' : '', $phpN ? $phpN . ' PHP files in root' : ''])), 'score' => 10 + min(10, $phpN)];
        } else {
            $cands[] = ['key' => 'static', 'label' => 'Unknown PHP / static site', 'confidence' => 'low', 'evidence' => ['No strong framework markers'], 'score' => 1];
        }
    }
    usort($cands, fn($a, $b) => $b['score'] <=> $a['score']);
    return $cands[0];
}

/* ---------------- profile: standard files + upload dirs ---------------- */
function smpro_ph_standard_files($root, $key) {
    $rels = ['.htaccess', '.user.ini', 'php.ini', 'index.php'];
    $extra = [
        'wordpress'   => ['wp-config.php', 'wp-load.php', 'wp-settings.php', 'wp-login.php', 'xmlrpc.php'],
        'laravel'     => ['.env', 'artisan', 'composer.json', 'public/index.php', 'public/.htaccess'],
        'joomla'      => ['configuration.php', 'administrator/index.php'],
        'drupal'      => ['sites/default/settings.php', 'web.config'],
        'magento'     => ['app/etc/env.php', 'app/etc/config.php', 'bin/magento'],
        'opencart'    => ['config.php', 'admin/config.php', 'system/startup.php', 'admin/index.php'],
        'codeigniter' => ['application/config/config.php', 'spark', 'index.php'],
    ];
    foreach ($extra[$key] ?? [] as $r) $rels[] = $r;
    $out = [];
    foreach (array_values(array_unique($rels)) as $rel) {
        $path = rtrim($root, '/') . '/' . $rel;
        if (is_file($path) && !is_link($path)) $out[$path] = ['rel' => $rel, 'path' => $path];
    }
    return array_values($out);
}
function smpro_ph_upload_dirs($root, $key) {
    $rels = ['uploads', 'upload', 'cache', 'tmp', 'temp', 'files', 'logs', 'image/cache', 'download'];
    $extra = [
        'wordpress'   => ['wp-content/uploads', 'wp-content/cache', 'wp-content/upgrade'],
        'laravel'     => ['storage', 'storage/logs', 'storage/framework', 'bootstrap/cache', 'public/uploads'],
        'joomla'      => ['images', 'cache', 'administrator/cache', 'tmp', 'logs'],
        'drupal'      => ['sites/default/files', 'sites/default/files/tmp'],
        'magento'     => ['pub/media', 'var/log', 'var/cache', 'var/tmp', 'pub/static'],
        'opencart'    => ['system/storage/logs', 'system/storage/cache', 'image/cache', 'download', 'upload'],
        'codeigniter' => ['writable', 'writable/cache', 'writable/logs', 'writable/uploads'],
    ];
    foreach ($extra[$key] ?? [] as $r) $rels[] = $r;
    $out = [];
    foreach (array_values(array_unique($rels)) as $rel) {
        $path = rtrim($root, '/') . '/' . $rel;
        if (is_dir($path) && !is_link($path)) $out[$path] = ['rel' => $rel, 'path' => $path];
    }
    return array_values($out);
}
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
    } catch (Throwable $e) {}
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
    if (is_file($src)) { @copy($src, $dst); @chmod($dst, 0600); }
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
    smpro_ph_chattr('-i', $ht);
    $backup = ''; $content = '';
    if (is_file($ht)) { $backup = smpro_ph_backup($ht, $backupDir . '/htaccess'); $content = (string)@file_get_contents($ht); }
    $content = preg_replace('/# SMPRO_PH_DENY_EXEC_START.*?# SMPRO_PH_DENY_EXEC_END\s*/s', '', $content) ?? $content;
    $content = rtrim($content) . smpro_ph_htaccess_marker($exts);
    @file_put_contents($ht, $content, LOCK_EX); @chmod($ht, 0644);
    $uid = @fileowner($dir); $gid = @filegroup($dir);                       // own as the cPanel account, NOT root
    if ($uid !== false) { @chown($ht, $uid); @chgrp($ht, $gid); }            // (must run before chattr +i)
    [$rc, $out] = smpro_ph_chattr('+i', $ht);
    return ['dir' => $dir, 'htaccess' => $ht, 'backup' => $backup, 'extensions' => smpro_ph_allowed_exts($exts), 'lock_rc' => $rc, 'lock_output' => $out];
}
function smpro_ph_remove_htaccess($dir) {
    $ht = rtrim($dir, '/') . '/.htaccess';
    if (!is_file($ht)) return true;
    smpro_ph_chattr('-i', $ht);
    $content = (string)@file_get_contents($ht);
    $new = preg_replace('/\n?# SMPRO_PH_DENY_EXEC_START.*?# SMPRO_PH_DENY_EXEC_END\s*/s', '', $content);
    if (trim((string)$new) === '') { @unlink($ht); return true; }
    @file_put_contents($ht, rtrim((string)$new) . "\n", LOCK_EX);
    return true;
}

/* ---------------- apply / unlock ---------------- */
function smpro_ph_apply($u, $mode, array $postFiles, array $postDirs, array $exts) {
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
    $errors = []; $fileRows = []; $dirRows = [];
    foreach ($files as $file) {
        smpro_ph_chattr('-i', $file);
        $backup = smpro_ph_backup($file, $backupDir . '/files');
        [$rc, $out] = smpro_ph_chattr('+i', $file);
        if ($rc !== 0) $errors[] = basename($file) . ': ' . $out;
        $fileRows[] = ['path' => $file, 'rel' => ltrim(substr($file, strlen(smpro_ph_home($u))), '/'), 'backup' => $backup, 'lock_rc' => $rc];
    }
    foreach ($dirs as $dir) {
        $row = smpro_ph_apply_htaccess($dir, $exts, $backupDir);
        if ((int)$row['lock_rc'] !== 0) $errors[] = basename($dir) . '/.htaccess: ' . $row['lock_output'];
        $dirRows[] = ['dir' => $row['dir'], 'rel' => ltrim(substr($dir, strlen(smpro_ph_home($u))), '/'), 'htaccess' => $row['htaccess'], 'backup' => $row['backup'], 'lock_rc' => $row['lock_rc']];
    }
    $m = smpro_ph_load($u) ?: ['version' => 'smpro.ph1', 'user' => $u, 'created_at' => date('c')];
    $m['status'] = 'locked'; $m['unlock_until'] = ''; $m['last_harden_at'] = date('c'); $m['last_harden_mode'] = $mode;
    $m['backup_dir'] = $backupDir; $m['protected_files'] = $fileRows; $m['deny_php_dirs'] = $dirRows; $m['blocked_extensions'] = smpro_ph_allowed_exts($exts); $m['errors'] = $errors;
    smpro_ph_save($u, $m);
    smpro_ph_audit_log($u, 'php_harden_' . $mode, 'Applied ' . ucfirst($mode) . ' Protection', ['files' => count($fileRows), 'folders' => count($dirRows), 'blocked' => implode(',', smpro_ph_allowed_exts($exts)), 'errors' => count($errors)]);
    smpro_audit('php_harden_apply', ['user' => $u, 'mode' => $mode, 'files' => count($fileRows), 'dirs' => count($dirRows), 'errors' => count($errors)]);
    return ['ok' => count($errors) === 0, 'files' => count($fileRows), 'dirs' => count($dirRows), 'errors' => $errors, 'backup_dir' => $backupDir];
}
/** Unlock selected files/folders. $until>0 → temporary (records auto-relock time). */
function smpro_ph_unlock($u, array $postFiles, array $postDirs, $until = 0) {
    $files = []; $dirs = [];
    foreach ($postFiles as $f) { $f = (string)$f; if (smpro_ph_inside($u, $f) && is_file($f)) $files[] = realpath($f) ?: $f; }
    foreach ($postDirs as $d) { $d = (string)$d; if (smpro_ph_inside($u, $d) && is_dir($d)) $dirs[] = realpath($d) ?: $d; }
    $done = 0;
    foreach (array_unique($files) as $file) { [$rc] = smpro_ph_chattr('-i', $file); if ($rc === 0) $done++; }
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

/* =====================================================================
 * CONTROLLER
 * ===================================================================== */
$reqMethod = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));
$u = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)($_POST['phuser'] ?? $_GET['phuser'] ?? $_GET['user'] ?? ''));

/* ---- POST: apply / unlock (AJAX JSON) ---- */
if ($reqMethod === 'POST' && in_array(($_POST['ph_action'] ?? ''), ['apply_fast', 'apply_custom', 'unlock'], true)) {
    smpro_require_valid_csrf('ph_act'); smpro_require_root();
    header('Content-Type: application/json');
    if (!smpro_ph_valid_user($u)) { echo json_encode(['ok' => false, 'msg' => 'Invalid cPanel user.']); exit; }
    $act = $_POST['ph_action'];
    $exts = is_array($_POST['exts'] ?? null) ? $_POST['exts'] : ['php', 'phtml', 'phar', 'php[0-9]', 'shtml', 'html', 'htm'];
    if ($act === 'apply_fast') {
        $r = smpro_ph_apply($u, 'fast', [], [], $exts);
        echo json_encode(['ok' => $r['ok'], 'msg' => 'Fast Protection applied: ' . $r['files'] . ' file(s) locked, ' . $r['dirs'] . ' folder(s) guarded' . ($r['errors'] ? ', ' . count($r['errors']) . ' warning(s)' : '') . '.', 'errors' => $r['errors']], JSON_UNESCAPED_SLASHES); exit;
    }
    if ($act === 'apply_custom') {
        $r = smpro_ph_apply($u, 'custom', (array)($_POST['files'] ?? []), (array)($_POST['dirs'] ?? []), $exts);
        echo json_encode(['ok' => $r['ok'], 'msg' => 'Custom Protection applied: ' . $r['files'] . ' file(s) locked, ' . $r['dirs'] . ' folder(s) guarded' . ($r['errors'] ? ', ' . count($r['errors']) . ' warning(s)' : '') . '.', 'errors' => $r['errors']], JSON_UNESCAPED_SLASHES); exit;
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

/* ---- render ---- */
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
  <a class="tp-btn" href="<?= smpro_h($cphome) ?>" target="_blank">Back to cPanel &#8599;</a>
</form>

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
      ?></div>
    </div>
  </div>
  <div class="ph-hero-foot">
    <span class="ph-path"><?= smpro_h($primary['root']) ?></span>
    <span class="ph-ev">Evidence: <?= smpro_h(implode(' · ', $det['evidence'])) ?></span>
    <?php if (!empty($man['unlock_until']) && ($man['status'] ?? '') === 'temporary_unlock'): ?><span class="ph-pill warn">re-lock by <?= smpro_h(date('Y-m-d H:i', strtotime($man['unlock_until']))) ?></span><?php endif; ?>
  </div>
</div>

<script>var PH_CSRF=<?= json_encode($csrf) ?>, PH_USER=<?= json_encode($u) ?>;</script>

<div class="ph-modes">
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
    <button class="tp-btn green" type="button" id="phApplyFast">&#9889; Apply Fast Protection</button>
  </div>
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
    <button class="tp-btn green" type="button" id="phApplyCustom">&#128274; Lock selected (Custom Protection)</button>
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

<div class="card" style="padding:0;overflow:hidden">
  <div class="ph-card-h"><b>Protection Activity</b><span class="meta">last actions for <?= smpro_h($u) ?></span></div>
  <div class="ph-tablewrap" style="max-height:280px">
    <table class="smpro-table"><thead><tr><th>Time</th><th>Action</th><th>Summary</th><th>Details</th></tr></thead><tbody>
    <?php $rows = smpro_ph_audit_rows($u); if (!$rows): ?><tr><td colspan="4" class="ph-empty" style="text-align:center;padding:16px">No activity yet for this account.</td></tr>
    <?php else: foreach ($rows as $a): ?>
      <tr><td class="mono" style="font-size:11px"><?= smpro_h(date('Y-m-d H:i', strtotime($a['time'] ?? 'now'))) ?></td>
        <td><span class="b gray"><?= smpro_h($a['action'] ?? '') ?></span></td>
        <td><?= smpro_h($a['message'] ?? '') ?></td>
        <td class="meta" style="font-size:11px"><?php $ex = $a['extra'] ?? []; $parts = []; foreach ($ex as $k => $v) if (is_scalar($v)) $parts[] = $k . '=' . $v; echo smpro_h(implode(', ', $parts)); ?></td></tr>
    <?php endforeach; endif; ?>
    </tbody></table>
  </div>
</div>
<?php endif; /* valid */ ?>

<style>
.svc-kicker{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--brand);font-weight:800}
.ph-bad{background:var(--dang-bg);color:var(--dang);border-left:4px solid var(--dang);font-size:14px;margin:14px 0}
.ph-pick{display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap;margin:14px 0}
.ph-fld{display:flex;flex-direction:column;gap:5px;font-size:11px;text-transform:uppercase;color:var(--muted);font-weight:700;flex:1;min-width:220px}
.ph-fld .tp-in{width:100%}
.tp-in,.tp-sel{border:1px solid var(--line);border-radius:9px;padding:9px 12px;font-size:13px}
.tp-btn{border:1px solid var(--line);border-radius:9px;padding:9px 15px;font-size:13px;font-weight:600;cursor:pointer;text-decoration:none;color:var(--ink);background:#fff;display:inline-block}
.tp-btn.primary{background:var(--brand);color:#fff;border-color:var(--brand)}.tp-btn.green{background:var(--good);color:#fff;border-color:var(--good)}
.tp-btn.danger{background:var(--dang-bg);color:var(--dang);border-color:#f3c4c4}.tp-btn.danger:hover{background:var(--dang);color:#fff}
.tp-btn[disabled]{opacity:.5;cursor:not-allowed}
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
.ph-mode{display:flex;gap:14px;align-items:flex-start;background:#fff;border:2px solid var(--line);border-radius:16px;padding:18px;cursor:pointer;position:relative}
.ph-mode.active{border-color:var(--brand);box-shadow:0 6px 20px rgba(37,99,235,.12)}
.ph-mode-ic{width:42px;height:42px;border-radius:12px;background:#f1f5f9;display:flex;align-items:center;justify-content:center;font-size:20px;flex-shrink:0}
.ph-mode-t{font-size:16px;font-weight:800}.ph-mode-d{font-size:12.5px;color:var(--muted);margin-top:4px;line-height:1.5}
.ph-check{position:absolute;top:14px;right:14px;width:24px;height:24px;border-radius:50%;background:#e2e8f0;color:#fff;display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:800}
.ph-mode.active .ph-check{background:var(--brand)}
.ph-card-h{display:flex;align-items:center;gap:10px;padding:14px 16px;border-bottom:1px solid var(--line);flex-wrap:wrap}.ph-card-h>b{font-size:14px}.ph-card-h .meta{font-size:12px}
.ph-badge{display:inline-block;font-size:12px;font-weight:700;padding:4px 11px;border-radius:20px;background:var(--brand-bg);color:var(--brand);margin-right:6px}
.ph-badge.conf-high{background:#dcfce7;color:#166534}.ph-badge.conf-medium{background:#fef3c7;color:#92400e}.ph-badge.conf-low{background:#fee2e2;color:#991b1b}
.ph-two{display:grid;grid-template-columns:1fr 1fr;gap:16px;padding:14px 16px}@media(max-width:760px){.ph-two{grid-template-columns:1fr}}
.ph-col-h{font-size:13px;font-weight:700;margin-bottom:8px}
.ph-item{font-size:12px;padding:8px 11px;border:1px solid var(--line);border-radius:9px;margin-bottom:6px;background:#fbfdff}
.ph-empty{font-size:12px;color:var(--muted);padding:10px 0}
.ph-note{margin:0 16px 16px;background:var(--warn-bg);color:#8a6516;border-radius:10px;padding:10px 12px;font-size:12.5px;font-weight:600}
.ph-rootchip{font-size:11px;font-weight:700;background:#0f172a;color:#fff;padding:5px 11px;border-radius:8px}
.ph-tablewrap{overflow:auto;max-height:520px}
.ph-tablewrap thead th{position:sticky;top:0;background:#fafbfe;z-index:1;box-shadow:inset 0 -1px 0 var(--line)}
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
.ph-extl{font-size:12px;background:#f8fafc;border:1px solid var(--line);border-radius:20px;padding:6px 11px;cursor:pointer}
.b{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:20px}
.b.red{background:var(--dang-bg);color:var(--dang)}.b.green{background:var(--good-bg);color:var(--good)}.b.gray{background:#f1f5f9;color:#475569}
.meta{color:var(--muted)}
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

  var bf=document.getElementById('phApplyFast');
  bf.addEventListener('click',function(){
    if(!confirm('Apply Fast Protection to '+PH_USER+'?\n\nLocks the detected stack’s critical files (chattr +i) and guards upload/cache/log folders. Backed up first; reversible from Custom → Unlock.'))return;
    var old=bf.innerHTML;bf.disabled=true;bf.innerHTML='⏳ Applying…';
    var fd=new URLSearchParams();fd.set('ph_action','apply_fast');fd.set('phuser',PH_USER);fd.set('smpro_csrf',PH_CSRF);exts().forEach(function(e){fd.append('exts[]',e);});
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
    var fd=new URLSearchParams();fd.set('ph_action','apply_custom');fd.set('phuser',PH_USER);fd.set('smpro_csrf',PH_CSRF);
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
})();
</script>
<?php endif; ?>
<?php
smpro_layout_footer();
