<?php
/* GENERATED FILE — do not edit.
 * The detection half of includes/phstack.php, rewritten with the account-side prefix by
 * build/gen-cpuser-stack.php on every build, so the two sides can never disagree about which files are
 * worth protecting. Only the functions that need no privileges are carried over. Edit the source.
 */
function sp_read_head($file, $max = 200000) {
    if (!is_file($file) || !is_readable($file)) return '';
    $size = @filesize($file); if ($size !== false && $size > 2 * 1024 * 1024) return '';
    return (string)@file_get_contents($file, false, null, 0, $max);
}

function sp_de($root, $rel) { return is_dir(rtrim($root, '/') . '/' . ltrim($rel, '/')); }

function sp_fe($root, $rel) { return is_file(rtrim($root, '/') . '/' . ltrim($rel, '/')); }

function sp_php_count($root) {
    $n = 0; try { foreach (new DirectoryIterator($root) as $f) if ($f->isFile() && preg_match('/\.php$/i', $f->getFilename())) $n++; } catch (Throwable $e) { if (function_exists('smpro_soft_fail')) smpro_soft_fail(basename(__FILE__) . ':' . __LINE__, $e); }
    return $n;
}

function sp_detect($root) {
    $cands = [];
    // WordPress
    if (sp_fe($root, 'wp-config.php') || sp_de($root, 'wp-content')) {
        $ev = array_values(array_filter([
            sp_fe($root, 'wp-config.php') ? 'wp-config.php' : '',
            sp_de($root, 'wp-content') ? 'wp-content/' : '',
            sp_de($root, 'wp-admin') ? 'wp-admin/' : '',
        ]));
        $cands[] = ['key' => 'wordpress', 'label' => 'WordPress', 'confidence' => count($ev) >= 2 ? 'high' : 'medium', 'evidence' => $ev, 'score' => 50 + count($ev)];
    }
    // Laravel
    if (sp_fe($root, 'artisan') || (sp_fe($root, 'composer.json') && sp_de($root, 'app'))) {
        $ev = []; foreach (['artisan', 'composer.json', '.env'] as $f) if (sp_fe($root, $f)) $ev[] = $f;
        if (sp_de($root, 'bootstrap')) $ev[] = 'bootstrap/';
        $cands[] = ['key' => 'laravel', 'label' => 'Laravel / Composer app', 'confidence' => sp_fe($root, 'artisan') ? 'high' : 'medium', 'evidence' => $ev, 'score' => sp_fe($root, 'artisan') ? 48 : 30];
    }
    // Joomla
    if (sp_fe($root, 'configuration.php') && (sp_de($root, 'administrator') || sp_de($root, 'libraries'))) {
        $ev = ['configuration.php']; foreach (['administrator', 'libraries', 'components'] as $d) if (sp_de($root, $d)) $ev[] = $d . '/';
        $cands[] = ['key' => 'joomla', 'label' => 'Joomla', 'confidence' => 'high', 'evidence' => $ev, 'score' => 47];
    }
    // Drupal
    if (sp_de($root, 'core') && (sp_fe($root, 'sites/default/settings.php') || sp_fe($root, 'sites/default/default.settings.php'))) {
        $ev = []; foreach (['core', 'modules', 'sites'] as $d) if (sp_de($root, $d)) $ev[] = $d . '/';
        if (sp_fe($root, 'sites/default/settings.php')) $ev[] = 'sites/default/settings.php';
        $cands[] = ['key' => 'drupal', 'label' => 'Drupal', 'confidence' => 'high', 'evidence' => $ev, 'score' => 46];
    }
    // Magento
    if (sp_fe($root, 'bin/magento') || sp_fe($root, 'app/etc/env.php')) {
        $ev = []; foreach (['bin/magento', 'app/etc/env.php', 'app/etc/config.php'] as $f) if (sp_fe($root, $f)) $ev[] = $f;
        $cands[] = ['key' => 'magento', 'label' => 'Magento', 'confidence' => 'high', 'evidence' => $ev, 'score' => 47];
    }
    // OpenCart
    $oc = [];
    $cfg = sp_read_head($root . '/config.php');
    if ($cfg !== '') foreach (['DIR_SYSTEM', 'DIR_CATALOG', 'DIR_APPLICATION'] as $m) if (strpos($cfg, $m) !== false) $oc[] = 'config.php:' . $m;
    foreach (['system', 'catalog', 'admin'] as $d) if (sp_de($root, $d)) $oc[] = $d . '/';
    if (sp_fe($root, 'system/startup.php')) $oc[] = 'system/startup.php';
    if (count($oc) >= 3) $cands[] = ['key' => 'opencart', 'label' => 'OpenCart / derived', 'confidence' => count($oc) >= 5 ? 'high' : 'medium', 'evidence' => array_slice(array_unique($oc), 0, 6), 'score' => 40 + count($oc)];
    // CodeIgniter
    if (sp_fe($root, 'system/CodeIgniter.php') || sp_fe($root, 'spark') || sp_fe($root, 'application/config/config.php')) {
        $ev = []; foreach (['spark', 'system/CodeIgniter.php', 'application/config/config.php'] as $f) if (sp_fe($root, $f)) $ev[] = $f;
        $cands[] = ['key' => 'codeigniter', 'label' => 'CodeIgniter', 'confidence' => 'medium', 'evidence' => $ev, 'score' => 35];
    }
    // Generic PHP fallback
    $phpN = sp_php_count($root);
    if (!$cands) {
        if (sp_fe($root, 'index.php') || $phpN >= 3) {
            $cands[] = ['key' => 'generic', 'label' => 'Generic PHP site', 'confidence' => $phpN >= 10 ? 'high' : 'medium',
                'evidence' => array_values(array_filter([sp_fe($root, 'index.php') ? 'index.php' : '', $phpN ? $phpN . ' PHP files in root' : ''])), 'score' => 10 + min(10, $phpN)];
        } else {
            $cands[] = ['key' => 'static', 'label' => 'Unknown PHP / static site', 'confidence' => 'low', 'evidence' => ['No strong framework markers'], 'score' => 1];
        }
    }
    usort($cands, fn($a, $b) => $b['score'] <=> $a['score']);
    return $cands[0];
}

function sp_standard_files($root, $key) {
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

function sp_upload_dirs($root, $key) {
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

