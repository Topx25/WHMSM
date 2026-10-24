<?php
/**
 * Safety Monitor Pro - which third-party plugins appear inside your customers' cPanel.
 *
 * Nothing in WHM answers this. An account-side plugin can sit in every customer's cPanel for years without the
 * server's owner ever seeing it listed anywhere, and it matters in two directions. Before shipping an account-side
 * plugin of our own we have to know whether one is already there - two tools managing the same file locks fight
 * over the same immutable bits and each reports the other's work as tampering. And for an operator who inherited a
 * server they did not build, "what is my customer actually looking at, and what can it do as root?" is a fair
 * question with no answer today.
 *
 * The detection is cPanel's own registration mechanism rather than a guess from directory names. A third-party
 * plugin registers itself by dropping `dynamicui_<name>.conf` into the theme's dynamicui directory; cPanel's own
 * built-in pages are not registered that way, they live in the theme's single shipped dynamicui.conf. Listing
 * directories instead produced 68 results on a stock server, of which every one was cPanel's own - a list that
 * long is the same as no list at all, because nobody reads it.
 *
 * Each registration is paired with two things that decide how much it can do: the directory it serves from, and
 * whether a root helper exists for it. `/usr/local/cpanel/bin/admin/<Vendor>/<Module>` is the supported way an
 * account-side plugin performs privileged work, so a plugin that ships one can act as root on the account's behalf
 * and a plugin that does not is limited to what the account itself could do.
 *
 * This only LOOKS. Nothing is executed, nothing is changed, and no verdict is passed on somebody else's software.
 * A place that cannot be read is reported as unreadable and NOT as empty: from here the two look identical and
 * only one of them means the server is clear.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

/** Themes that can carry account-side plugin registrations. */
function smpro_cps_themes() {
    $out = [];
    foreach (glob('/usr/local/cpanel/base/frontend/*', GLOB_ONLYDIR) ?: [] as $d) $out[] = $d;
    return $out;
}

/** Parse cPanel's `key=>value,key=>value` conf line into an array. */
function smpro_cps_parse_conf($text) {
    $out = [];
    foreach (explode(',', trim((string)$text)) as $pair) {
        $p = explode('=>', $pair, 2);
        if (count($p) !== 2) continue;
        $out[trim($p[0])] = trim($p[1]);
    }
    return $out;
}

/** Strip cPanel's $LANG{'...'} wrapper (sometimes nested) down to the human label. */
function smpro_cps_label($raw) {
    $s = (string)$raw;
    for ($i = 0; $i < 3 && preg_match("/\\\$LANG\{'(.*)'\}$/s", $s, $m); $i++) $s = $m[1];
    return trim($s) !== '' ? trim($s) : '';
}

/** Root helpers: /usr/local/cpanel/bin/admin/<Vendor>/<Module> - the supported privilege path for a cPanel plugin. */
function smpro_cps_admin_bins() {
    $out = [];
    foreach (glob('/usr/local/cpanel/bin/admin/*', GLOB_ONLYDIR) ?: [] as $vendorDir) {
        $vendor = basename($vendorDir);
        foreach (scandir($vendorDir) ?: [] as $e) {
            if ($e === '.' || $e === '..' || substr($e, -5) === '.conf') continue;
            $p = $vendorDir . '/' . $e;
            if (!is_file($p)) continue;
            $conf = $p . '.conf';
            $out[] = [
                'vendor'  => $vendor,
                'module'  => $e,
                'path'    => $p,
                'mode'    => substr(sprintf('%o', (int)@fileperms($p)), -4),
                'mtime'   => (int)@filemtime($p),
                'conf'    => is_file($conf) ? trim((string)@file_get_contents($conf)) : '',
                'cpanels' => ($vendor === 'Cpanel'),      // cPanel's own helpers, not a third party's
            ];
        }
    }
    return $out;
}

/** Bytes/files under a directory, bounded so a large tree cannot stall a page render. */
function smpro_cps_dir_size($dir, $maxFiles = 3000) {
    $bytes = 0; $files = 0; $newest = 0;
    try {
        $it = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::LEAVES_ONLY
        );
        foreach ($it as $f) {
            if ($files++ >= $maxFiles) break;
            if (!$f->isFile() || $f->isLink()) continue;
            $bytes += (int)$f->getSize();
            $m = (int)$f->getMTime(); if ($m > $newest) $newest = $m;
        }
    } catch (Throwable $e) {
        return ['bytes' => $bytes, 'files' => $files, 'newest' => $newest, 'partial' => true];
    }
    return ['bytes' => $bytes, 'files' => $files, 'newest' => $newest, 'partial' => $files >= $maxFiles];
}

/**
 * Our own account-side plugin, so it is never listed as somebody else's.
 *
 * Read from SMPRO_CPS_SLUG rather than a list kept by hand: the working name is expected to change, and a
 * hand-kept list would keep matching the OLD name after a rename - at which point the plugin would start
 * reporting itself to the operator as a third party's software.
 */
function smpro_cps_is_ours($name) {
    $n = strtolower((string)$name);
    if (defined('SMPRO_CPS_SLUG') && $n === strtolower(SMPRO_CPS_SLUG)) return true;
    return in_array($n, ['smpro', 'smprov1'], true);                    // the WHM addon names, never account-side
}

/** Resolve the directory a registration's url= serves from, if it is a local path under the theme or 3rdparty. */
function smpro_cps_dir_for($theme, $url) {
    $rel = trim((string)$url);
    if ($rel === '' || preg_match('#^[a-z]+://#i', $rel)) return '';
    $rel = ltrim($rel, '/');
    $first = explode('/', $rel)[0];
    if ($first === '' || strpos($first, '.') !== false) return '';        // a bare file, not a directory
    foreach ([$theme . '/' . $first, '/usr/local/cpanel/base/3rdparty/' . $first] as $cand) {
        if (is_dir($cand)) return $cand;
    }
    return '';
}

/**
 * Third-party plugins registered into cPanel on this server.
 *
 * Returns ['ok','plugins'=>[...],'admin_bins'=>[...],'orphan_bins'=>[...],'unreadable'=>[],'why'].
 * `ok` false means somewhere could not be looked at, so the list is incomplete and must not be read as "none".
 */
function smpro_cps_scan() {
    $plugins = []; $unreadable = [];
    $bins = smpro_cps_admin_bins();
    $claimed = [];

    $themes = smpro_cps_themes();
    if (!$themes) $unreadable[] = '/usr/local/cpanel/base/frontend';

    foreach ($themes as $theme) {
        $dui = $theme . '/dynamicui';
        if (!is_dir($dui)) continue;                                      // a theme with no third-party plugin at all
        if (!is_readable($dui)) { $unreadable[] = $dui; continue; }

        foreach (glob($dui . '/dynamicui_*.conf') ?: [] as $conf) {
            $name = preg_replace('/^dynamicui_|\.conf$/', '', basename($conf));
            $c    = smpro_cps_parse_conf((string)@file_get_contents($conf));
            $dir  = smpro_cps_dir_for($theme, $c['url'] ?? '');
            $size = $dir !== '' ? smpro_cps_dir_size($dir) : ['bytes' => 0, 'files' => 0, 'newest' => 0, 'partial' => false];

            // Pair with root helpers. `implements=>` names the admin module outright when the plugin sets it;
            // otherwise fall back to matching the registration name, which is how most of them are named.
            $impl = $c['implements'] ?? '';
            $mine = [];
            foreach ($bins as $b) {
                if ($b['cpanels']) continue;
                $hit = ($impl !== '' && strcasecmp($b['module'], $impl) === 0)
                    || stripos($b['module'], $name) !== false
                    || stripos($name, $b['module']) !== false
                    || stripos($b['vendor'], $name) !== false;
                if ($hit) { $mine[] = $b; $claimed[$b['path']] = true; }
            }

            $plugins[] = [
                'name'       => $name,
                'label'      => smpro_cps_label($c['itemdesc'] ?? ($c['description'] ?? '')) ?: $name,
                'theme'      => basename($theme),
                'group'      => $c['group'] ?? '',
                'url'        => $c['url'] ?? '',
                'feature'    => $c['feature'] ?? '',
                'dir'        => $dir,
                'ours'       => smpro_cps_is_ours($name),
                'files'      => (int)$size['files'],
                'bytes'      => (int)$size['bytes'],
                'newest'     => (int)$size['newest'],
                'partial'    => !empty($size['partial']),
                'admin_bins' => $mine,
                'conf'       => $conf,
            ];
        }
    }

    // A root helper with no registration pointing at it is worth saying out loud: it is privileged code left on the
    // server by something that is no longer offered to the customer, and removal usually forgets it.
    $orphans = [];
    foreach ($bins as $b) if (!$b['cpanels'] && empty($claimed[$b['path']])) $orphans[] = $b;

    usort($plugins, function ($a, $b) {
        return [$a['ours'], empty($a['admin_bins']), $a['name']] <=> [$b['ours'], empty($b['admin_bins']), $b['name']];
    });

    $why = $unreadable
        ? 'These could not be read, so the list is incomplete: ' . implode(', ', $unreadable) . '.'
        : '';

    return ['ok' => empty($unreadable), 'plugins' => $plugins, 'admin_bins' => $bins,
            'orphan_bins' => $orphans, 'unreadable' => $unreadable, 'why' => $why];
}

/** One readable line about a plugin - what it is, and how much it can do. */
function smpro_cps_describe(array $p) {
    $s = $p['label'];
    if (strcasecmp($p['label'], $p['name']) !== 0) $s .= ' (' . $p['name'] . ')';
    $s .= ' — appears in ' . ($p['group'] !== '' ? 'the ' . $p['group'] . ' section of ' : '') . 'cPanel';
    if ($p['files'] > 0) {
        $s .= ', ' . number_format($p['files']) . ' file(s)'
            . ($p['newest'] ? ', last changed ' . date('Y-m-d', $p['newest']) : '');
    }
    if (!empty($p['admin_bins'])) {
        $s .= '. It ships ' . count($p['admin_bins']) . ' root helper(s), so it can act as root on the account\'s behalf.';
    } else {
        $s .= '. No root helper found, so it can only do what the account itself could.';
    }
    return $s;
}
