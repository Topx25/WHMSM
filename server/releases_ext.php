<?php
/**
 * releases_ext.php — "Releases" admin tab.
 * Products shown in tabs (one at a time, via ?product=).
 * Each tab: current-build hero + versioned archive table with multi-select
 * (hide / unhide / delete / push / rollback / download).
 * WP Guard builds (tar.gz) support hide / delete / push (updates latest.json).
 * WP Guard WordPress (zip) is a single download-only artifact.
 */
if (!function_exists('db')) return;

/* ─── directory helpers ─── */
function rel_dir(): string { return '/opt/aitech-license-server/releases'; }
function rel_wpguard_dir(): string { return '/opt/aitech-license-server/public/wpguard'; }

function rel_wpzip_version(string $zip): string {
    $side = $zip . '.ver';
    if (is_file($side)) { $v = trim((string)@file_get_contents($side)); if (preg_match('/^[0-9][0-9.]*$/', $v)) return $v; }
    if (class_exists('ZipArchive')) {
        $z = new ZipArchive();
        if ($z->open($zip) === true) {
            $php = $z->getFromName('wp-guard/wp-guard.php');
            $z->close();
            if (preg_match('/^\s*\*\s*Version:\s*([0-9][0-9.]*)/mi', (string)$php, $m)) return $m[1];
        }
    }
    return '';
}

/** All products and their storage config. */
function rel_products(): array {
    return [
        'safety_monitor'    => ['label' => 'Safety Monitor Pro', 'prefix' => 'smpro',            'dir' => rel_dir(),          'flow' => 'copy'],
        'mailshield'        => ['label' => 'MailShield OSM',      'prefix' => 'mailshield',        'dir' => rel_dir(),          'flow' => 'copy'],
        'wpguard'           => ['label' => 'WP Guard',            'prefix' => 'wpguard',           'dir' => rel_wpguard_dir(),  'flow' => 'json'],
        'wpguard_wordpress' => ['label' => 'WP Guard WordPress',  'prefix' => 'wpguard_wordpress', 'dir' => rel_wpguard_dir(),  'flow' => 'single'],
    ];
}

function rel_cur_product(): string {
    $p = preg_replace('/[^a-z0-9_]/', '', strtolower((string)($_GET['product'] ?? $_POST['product'] ?? 'safety_monitor')));
    return array_key_exists($p, rel_products()) ? $p : 'safety_monitor';
}

function rel_bytes($b): string { $u = ['B','KB','MB','GB']; $i = 0; while ($b >= 1024 && $i < 3) { $b /= 1024; $i++; } return round($b, $i ? 1 : 0) . ' ' . $u[$i]; }
function rel_verfile(string $pfx): string { return rel_dir() . '/' . ($pfx === 'smpro' ? 'VERSION' : $pfx . '-VERSION'); }
function rel_hidden_load(): array { $f = rel_dir() . '/.rel_hidden.json'; $d = is_file($f) ? json_decode((string)@file_get_contents($f), true) : []; return is_array($d) ? $d : []; }
function rel_hidden_save(array $a): void { @file_put_contents(rel_dir() . '/.rel_hidden.json', json_encode(array_values(array_unique($a))), LOCK_EX); }
function rel_state_load(): array { $f = rel_dir() . '/.rel_state.json'; $d = is_file($f) ? json_decode((string)@file_get_contents($f), true) : []; return is_array($d) ? $d : []; }
function rel_state_save(array $s): void { @file_put_contents(rel_dir() . '/.rel_state.json', json_encode($s), LOCK_EX); }

function rel_wg_latest_ver(): string {
    $lj = @json_decode((string)@file_get_contents(rel_wpguard_dir() . '/latest.json'), true);
    return is_array($lj) ? (string)($lj['version'] ?? '') : '';
}

function rel_route(string $path): bool {
    $m = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    if ($path === '/releases' && $m === 'GET')         { rel_page(); return true; }
    if ($path === '/releases/get' && $m === 'GET')     { rel_download(); return true; }
    if ($path === '/releases/action' && $m === 'POST') { rel_action(); return true; }
    return false;
}

/* ─── scan: all versioned tarballs grouped by product ─── */
function rel_scan(string $product = ''): array {
    $dir = rel_dir(); $out = [];
    // SM Pro + MailShield
    foreach (['smpro','mailshield'] as $pfx) {
        $prod = $pfx === 'smpro' ? 'safety_monitor' : 'mailshield';
        if ($product !== '' && $product !== $prod) continue;
        $latestFile = $dir . '/' . $pfx . '-latest.tar.gz';
        $latestSha  = is_file($latestFile) ? @hash_file('sha256', $latestFile) : '';
        foreach (glob($dir . '/' . $pfx . '-*.tar.gz') ?: [] as $f) {
            $b = basename($f);
            if (!preg_match('/^' . preg_quote($pfx, '/') . '-([0-9][0-9.]*)\.tar\.gz$/', $b, $mm)) continue;
            $out[] = ['product' => $prod, 'prefix' => $pfx, 'dir' => $dir,
                'file' => $b, 'version' => $mm[1], 'size' => (int)@filesize($f), 'mtime' => (int)@filemtime($f),
                'is_latest' => ($latestSha !== '' && @hash_file('sha256', $f) === $latestSha),
            ];
        }
    }
    // WP Guard WHM
    if ($product === '' || $product === 'wpguard') {
        $wgdir = rel_wpguard_dir(); $wgLatest = rel_wg_latest_ver();
        foreach (glob($wgdir . '/wpguard-*.tar.gz') ?: [] as $f) {
            $b = basename($f);
            if (!preg_match('/^wpguard-([0-9][0-9.]*)\.tar\.gz$/', $b, $mm)) continue;
            $out[] = ['product' => 'wpguard', 'prefix' => 'wpguard', 'dir' => $wgdir,
                'file' => $b, 'version' => $mm[1], 'size' => (int)@filesize($f), 'mtime' => (int)@filemtime($f),
                'is_latest' => ($mm[1] === $wgLatest),
            ];
        }
    }
    // WP Guard WordPress
    if ($product === '' || $product === 'wpguard_wordpress') {
        $zip = rel_wpguard_dir() . '/wp-guard.zip';
        if (is_file($zip)) {
            $out[] = ['product' => 'wpguard_wordpress', 'prefix' => 'wpguard_wordpress', 'dir' => rel_wpguard_dir(),
                'file' => 'wp-guard.zip', 'version' => (rel_wpzip_version($zip) ?: '—'),
                'size' => (int)@filesize($zip), 'mtime' => (int)@filemtime($zip),
                'is_latest' => true, 'single' => true,
            ];
        }
    }
    usort($out, function ($a, $b) {
        if ($a['product'] !== $b['product']) return strcmp($a['product'], $b['product']);
        return version_compare($b['version'], $a['version']);
    });
    return $out;
}

function rel_log(?string $key, string $action, string $msg = ''): void {
    if (!function_exists('log_event')) return;
    try { log_event($key !== null ? substr($key, 0, 80) : null, substr($action, 0, 80), 'ok', $msg, []); }
    catch (\Throwable $e) {}
}

/** Validated basename list — accepts smpro / mailshield / wpguard versioned tarballs. */
function rel_clean_files($raw): array {
    $out = [];
    foreach ((array)$raw as $f) {
        $f = basename((string)$f);
        if (preg_match('/^(smpro|mailshield|wpguard)-[0-9][0-9.]*\.tar\.gz$/', $f)) $out[] = $f;
    }
    return array_values(array_unique($out));
}

/* ─── action handler ─── */
function rel_action(): void {
    require_admin(); require_csrf();
    $dir  = rel_dir();
    $wgdir = rel_wpguard_dir();
    $op   = (string)($_POST['op'] ?? '');
    $prod = rel_cur_product();

    /* Bulk ops — hide / unhide / delete on multiple files */
    if (isset($_POST['files']) && in_array($op, ['hide','unhide','delete'], true)) {
        $files = rel_clean_files($_POST['files']);
        if (!$files) { redirect('/releases?product=' . $prod); return; }
        if ($op === 'hide') {
            $h = rel_hidden_load(); foreach ($files as $f) $h[] = $f; rel_hidden_save($h);
        } elseif ($op === 'unhide') {
            rel_hidden_save(array_values(array_diff(rel_hidden_load(), $files)));
        } elseif ($op === 'delete') {
            $done = [];
            foreach ($files as $f) {
                $pfx = preg_match('/^wpguard-/', $f) ? 'wpguard' : (preg_match('/^mailshield-/', $f) ? 'mailshield' : 'smpro');
                $fdir = ($pfx === 'wpguard') ? $wgdir : $dir;
                $src = $fdir . '/' . $f;
                // never delete the current/latest build
                if ($pfx === 'wpguard') {
                    $latestVer = rel_wg_latest_ver();
                    if (preg_match('/^wpguard-([0-9][0-9.]*)\.tar\.gz$/', $f, $mm) && $mm[1] === $latestVer) continue;
                } else {
                    $latest = $dir . '/' . $pfx . '-latest.tar.gz';
                    if (@hash_file('sha256', $src) === @hash_file('sha256', $latest)) continue;
                }
                @unlink($src); @unlink($src . '.sig'); $done[] = $f;
            }
            if ($done) rel_hidden_save(array_values(array_diff(rel_hidden_load(), $done)));
            $files = $done;
        }
        if ($files) rel_log($files[0], 'release_bulk_' . $op, count($files) . ' build(s): ' . implode(', ', $files));
        redirect('/releases?product=' . $prod);
        return;
    }

    /* Single-file ops */
    $file = basename((string)($_POST['file'] ?? ''));
    $isWG = (bool)preg_match('/^wpguard-[0-9][0-9.]*\.tar\.gz$/', $file);
    $isSM = (bool)preg_match('/^(smpro|mailshield)-[0-9][0-9.]*\.tar\.gz$/', $file);
    if (!$isWG && !$isSM) { redirect('/releases?product=' . $prod); return; }

    if ($isWG) {
        // WP Guard single-file ops
        preg_match('/^wpguard-([0-9][0-9.]*)\.tar\.gz$/', $file, $mm); $ver = $mm[1]; $src = $wgdir . '/' . $file;
        $latest = $wgdir . '/wpguard-latest.tar.gz';
        if ($op === 'push' && is_file($src)) {
            @copy($src, $latest); @copy($src . '.sig', $latest . '.sig');
            $sha = @hash_file('sha256', $src) ?: '';
            @file_put_contents($wgdir . '/latest.json', json_encode(['version' => $ver, 'sha256' => $sha, 'released' => date('Y-m-d')], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
            rel_log($file, 'release_push', 'wpguard promoted to latest');
        } elseif ($op === 'hide') {
            $h = rel_hidden_load(); $h[] = $file; rel_hidden_save($h);
        } elseif ($op === 'unhide') {
            rel_hidden_save(array_values(array_diff(rel_hidden_load(), [$file])));
        } elseif ($op === 'delete') {
            $latestVer = rel_wg_latest_ver();
            if ($ver !== $latestVer) { @unlink($src); @unlink($src . '.sig'); rel_hidden_save(array_values(array_diff(rel_hidden_load(), [$file]))); rel_log($file, 'release_delete', 'wpguard build deleted'); }
        } elseif ($op === 'rollback') {
            // wpguard rollback: find the next-newest build, promote it
            $versions = [];
            foreach (glob($wgdir . '/wpguard-*.tar.gz') ?: [] as $gf) { $gb = basename($gf); if (preg_match('/^wpguard-([0-9][0-9.]*)\.tar\.gz$/', $gb, $gm)) $versions[] = $gm[1]; }
            usort($versions, fn($a,$b) => version_compare($b,$a));
            $cur = rel_wg_latest_ver(); $prev = '';
            foreach ($versions as $v) { if ($v !== $cur) { $prev = $v; break; } }
            if ($prev !== '') {
                $psrc = $wgdir . '/wpguard-' . $prev . '.tar.gz';
                @copy($psrc, $latest); @copy($psrc . '.sig', $latest . '.sig');
                $sha = @hash_file('sha256', $psrc) ?: '';
                @file_put_contents($wgdir . '/latest.json', json_encode(['version' => $prev, 'sha256' => $sha, 'released' => date('Y-m-d')], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
                rel_log($file, 'release_rollback', 'wpguard reverted to ' . $prev);
            }
        }
        redirect('/releases?product=wpguard'); return;
    }

    // SM Pro / MailShield single-file ops
    $pfx = strpos($file, 'mailshield-') === 0 ? 'mailshield' : 'smpro';
    $ver = ''; preg_match('/-([0-9][0-9.]*)\.tar\.gz$/', $file, $xm); $ver = $xm[1] ?? '';
    $src = $dir . '/' . $file;
    $latest = $dir . '/' . $pfx . '-latest.tar.gz'; $prev = $dir . '/' . $pfx . '-prev.tar.gz';
    $st = rel_state_load();
    if ($op === 'push' && is_file($src)) {
        if (is_file($latest)) { @copy($latest, $prev); if (is_file($latest . '.sig')) @copy($latest . '.sig', $prev . '.sig'); $st[$pfx]['prev'] = $st[$pfx]['latest'] ?? ''; }
        @copy($src, $latest); if (is_file($src . '.sig')) @copy($src . '.sig', $latest . '.sig');
        @file_put_contents(rel_verfile($pfx), $ver);
        $st[$pfx]['latest'] = $ver; rel_state_save($st);
        rel_log($file, 'release_push', 'promoted to latest');
    } elseif ($op === 'rollback' && is_file($prev)) {
        $cur2 = $st[$pfx]['latest'] ?? ''; $back = $st[$pfx]['prev'] ?? '';
        @copy($prev, $latest); if (is_file($prev . '.sig')) @copy($prev . '.sig', $latest . '.sig');
        if ($back !== '') @file_put_contents(rel_verfile($pfx), $back);
        $st[$pfx]['latest'] = $back; $st[$pfx]['prev'] = $cur2; rel_state_save($st);
        rel_log($pfx, 'release_rollback', 'reverted to ' . $back);
    } elseif ($op === 'hide') {
        $h = rel_hidden_load(); $h[] = $file; rel_hidden_save($h);
    } elseif ($op === 'unhide') {
        rel_hidden_save(array_values(array_diff(rel_hidden_load(), [$file])));
    } elseif ($op === 'delete') {
        if (@hash_file('sha256', $src) !== @hash_file('sha256', $latest)) {
            @unlink($src); @unlink($src . '.sig');
            rel_hidden_save(array_values(array_diff(rel_hidden_load(), [$file])));
            rel_log($file, 'release_delete', 'deleted build');
        }
    }
    $prodRedir = $pfx === 'mailshield' ? 'mailshield' : 'safety_monitor';
    redirect('/releases?product=' . $prodRedir);
}

/* ─── row helpers ─── */
function rel_icobtn(string $op, string $file, string $icon, string $tip, string $cls = '', string $confirm = ''): string {
    $oc = $confirm !== '' ? ' onclick="return confirm(' . htmlspecialchars(json_encode($confirm), ENT_QUOTES) . ')"' : '';
    $prod = rel_cur_product();
    return '<form method="post" action="/releases/action" style="display:inline">'
         . '<input type="hidden" name="csrf" value="' . h(csrf_token()) . '">'
         . '<input type="hidden" name="product" value="' . h($prod) . '">'
         . '<input type="hidden" name="file" value="' . h($file) . '">'
         . '<button class="rp-ib ' . $cls . '" name="op" value="' . h($op) . '" title="' . h($tip) . '"' . $oc . '>' . $icon . '</button></form>';
}

function rel_row(array $r, bool $archived, bool $isSingle = false): string {
    $cur  = !empty($r['is_latest']);
    $ver  = $r['version'];
    $file = $r['file'];
    $date = $r['mtime'] ? date('Y-m-d', $r['mtime']) : '—';
    $sz   = rel_bytes($r['size']);

    // Status pill
    if ($cur)      { $pill = '<span class="rp-pill rp-pill-cur">&#9679; Current</span>'; }
    elseif ($archived) { $pill = '<span class="rp-pill rp-pill-arc">Hidden</span>'; }
    else           { $pill = '<span class="rp-pill rp-pill-avl">Available</span>'; }

    // Download link (always)
    $dl = '<a class="rp-ib" href="/releases/get?file=' . urlencode($file) . '" title="Download">&#11015;</a>';

    if ($isSingle) {
        return '<tr><td></td><td class="rp-ver">v' . h($ver) . '</td>'
             . '<td class="rp-dt">' . $date . '</td><td class="rp-sz">' . $sz . '</td>'
             . '<td>' . $pill . '</td><td class="rp-ac">' . $dl . '</td></tr>';
    }

    $cb = $cur
        ? '<td class="rp-cc"></td>'
        : '<td class="rp-cc"><input type="checkbox" class="rel-cb rp-chk" value="' . h($file) . '"></td>';

    $ac = $dl;
    if ($archived) {
        $ac .= rel_icobtn('unhide', $file, '&#128065;', 'Unhide');
        if (!$cur) $ac .= rel_icobtn('delete', $file, '&#128465;', 'Delete permanently', 'rp-ib-del', 'Delete v' . $ver . ' permanently?');
    } else {
        if ($cur) {
            $ac .= rel_icobtn('rollback', $file, '&#8634;', 'Roll back to previous build', '', 'Roll back — revert "latest" to the previous build?');
        } else {
            $ac .= rel_icobtn('push', $file, '&#11014;', 'Promote to latest', 'rp-ib-push', 'Promote v' . $ver . ' to served "latest"?');
            $ac .= rel_icobtn('hide', $file, '&#128269;', 'Move to archive');
            $ac .= rel_icobtn('delete', $file, '&#128465;', 'Delete permanently', 'rp-ib-del', 'Delete v' . $ver . ' permanently?');
        }
    }

    return '<tr>' . $cb . '<td class="rp-ver">v' . h($ver) . '</td>'
         . '<td class="rp-dt">' . $date . '</td><td class="rp-sz">' . $sz . '</td>'
         . '<td>' . $pill . '</td><td class="rp-ac">' . $ac . '</td></tr>';
}

/* ─── main page ─── */
function rel_page(): void {
    require_admin();
    layout_start('Releases');

    $product  = rel_cur_product();
    $products = rel_products();
    $hidden   = rel_hidden_load();

    // Count all products for tab badges
    $allRows = rel_scan('');
    $counts  = [];
    foreach ($allRows as $r) $counts[$r['product']] = ($counts[$r['product']] ?? 0) + 1;

    // Current product rows
    $rows   = array_values(array_filter($allRows, fn($r) => $r['product'] === $product));
    $pInfo  = $products[$product];
    $isSingle = ($pInfo['flow'] === 'single');

    // Stats
    $curVer = ''; $curMtime = 0; $curSize = 0;
    foreach ($rows as $r) { if ($r['is_latest']) { $curVer = $r['version']; $curMtime = $r['mtime']; $curSize = $r['size']; break; } }
    $active = array_values(array_filter($rows, fn($r) => !in_array($r['file'], $hidden, true)));
    $arch   = array_values(array_filter($rows, fn($r) => in_array($r['file'], $hidden, true)));
    $tblA   = 'rptA_' . $product;
    $tblH   = 'rptH_' . $product;

    echo '<section class="hero"><div><h1>&#128230; Releases</h1><p>Push, roll back, archive, or delete builds per product.</p></div></section>';

    /* ── Product tabs ── */
    $prodIcons = ['safety_monitor'=>'&#128737;','mailshield'=>'&#9993;','wpguard'=>'&#128737;','wpguard_wordpress'=>'&#128279;'];
    echo '<div class="rp-tabs">';
    foreach ($products as $code => $info) {
        $n  = $counts[$code] ?? 0;
        $on = $code === $product ? ' rp-tab-on' : '';
        echo '<a class="rp-tab' . $on . '" href="/releases?product=' . h($code) . '">'
           . ($prodIcons[$code] ?? '') . ' ' . h($info['label'])
           . ' <span class="rp-tab-n">' . $n . '</span></a>';
    }
    echo '</div>';

    if (!$rows) {
        echo '<div class="card" style="color:#94a3b8;padding:28px">No builds found for this product.</div>';
        echo rel_page_css(); layout_end(); return;
    }

    /* ── KPI strip ── */
    echo '<div class="rp-kpi">';
    echo '<div class="rp-kc"><div class="rp-kn">' . count($active) . '</div><div class="rp-kl">Active builds</div></div>';
    echo '<div class="rp-kc"><div class="rp-kn rp-kn-gr">' . ($curVer !== '' ? 'v' . h($curVer) : '&mdash;') . '</div><div class="rp-kl">Current</div></div>';
    echo '<div class="rp-kc"><div class="rp-kn">' . ($curMtime ? date('M j, Y', $curMtime) : '&mdash;') . '</div><div class="rp-kl">Published</div></div>';
    echo '<div class="rp-kc"><div class="rp-kn">' . ($curSize ? rel_bytes($curSize) : '&mdash;') . '</div><div class="rp-kl">Package size</div></div>';
    echo '</div>';

    /* ── Active builds ── */
    echo '<div class="card" style="padding:0;overflow:hidden">';
    // Table header row with select-all checkbox
    echo '<div class="rp-th">'
       . '<label class="rp-sall"><input type="checkbox" id="rpAllA" onchange="rpSelAll(this,\'' . $tblA . '\')"> <span>Select all</span></label>'
       . '<span class="rp-thlbl">' . count($active) . ' active build' . (count($active) !== 1 ? 's' : '') . '</span>'
       . '</div>';
    echo '<table id="' . $tblA . '" class="rp-tbl">'
       . '<thead><tr><th class="rp-cc"></th><th>Version</th><th>Published</th><th>Size</th><th>Status</th><th style="text-align:right">Actions</th></tr></thead><tbody>';
    foreach ($active as $r) echo rel_row($r, false, $isSingle);
    echo '</tbody></table>';

    /* ── Archived ── */
    if ($arch && !$isSingle) {
        echo '<details class="rp-arc" id="rpArcDet">'
           . '<summary onclick="rpArcOpen()">'
           . '<span class="rp-arc-arr">&#9658;</span>'
           . '<span class="rp-arc-ico">&#128193;</span> Archived'
           . ' <span class="rp-tab-n" style="background:#e2e8f0;color:#64748b">' . count($arch) . '</span>'
           . '</summary>'
           . '<div class="rp-th" style="border-top:1px solid #f1f5f9">'
           . '<label class="rp-sall"><input type="checkbox" id="rpAllH" onchange="rpSelAll(this,\'' . $tblH . '\')"> <span>Select all</span></label>'
           . '<span class="rp-thlbl">' . count($arch) . ' hidden build' . (count($arch) !== 1 ? 's' : '') . '</span>'
           . '</div>'
           . '<table id="' . $tblH . '" class="rp-tbl">'
           . '<thead><tr><th class="rp-cc"></th><th>Version</th><th>Published</th><th>Size</th><th>Status</th><th style="text-align:right">Actions</th></tr></thead><tbody>';
        foreach ($arch as $r) echo rel_row($r, true);
        echo '</tbody></table></details>';
    }
    echo '</div>'; // .card

    /* ── Floating multi-select bar ── */
    echo '<div class="rp-float" id="rpFloat" style="display:none">'
       . '<span class="rp-float-n"><b id="rpFloatN">0</b> selected</span>'
       . '<div class="rp-float-acts">'
       . '<button type="button" onclick="rpBulk(\'hide\')">&#128193; Archive</button>'
       . '<button type="button" onclick="rpBulk(\'unhide\')">&#128065; Unhide</button>'
       . '<button type="button" class="rp-del" onclick="rpBulk(\'delete\',\'Delete %n% selected build(s) permanently?\')">&#128465; Delete</button>'
       . '</div>'
       . '<button type="button" class="rp-float-x" onclick="rpClearAll()" title="Clear selection">&#10005;</button>'
       . '</div>';

    echo '<input type="hidden" id="REL_CSRF" value="' . h(csrf_token()) . '">';
    echo '<input type="hidden" id="REL_PROD" value="' . h($product) . '">';

    echo rel_page_css();

    echo '<script>'
       . 'function rpSelAll(src,tbl){var t=document.getElementById(tbl);if(!t)return;t.querySelectorAll(".rel-cb").forEach(function(c){c.checked=src.checked;});rpTick();}'
       . 'function rpTick(){'
       . 'var all=Array.prototype.slice.call(document.querySelectorAll(".rel-cb:checked"));'
       . 'var n=all.length;var fb=document.getElementById("rpFloat");var fn=document.getElementById("rpFloatN");'
       . 'if(fb){fb.style.display=n?"flex":"none";}if(fn)fn.textContent=n;'
       . 'document.querySelectorAll(".rel-cb").forEach(function(c){var r=c.closest("tr");if(r)r.classList.toggle("rp-sel",c.checked);});}'
       . 'function rpClearAll(){document.querySelectorAll(".rel-cb").forEach(function(c){c.checked=false;});'
       . 'var a=document.getElementById("rpAllA");var h=document.getElementById("rpAllH");if(a)a.checked=false;if(h)h.checked=false;rpTick();}'
       . 'function rpBulk(op,confirmMsg){'
       . 'var cbs=Array.prototype.slice.call(document.querySelectorAll(".rel-cb:checked"));'
       . 'if(!cbs.length)return;'
       . 'if(confirmMsg&&!confirm(confirmMsg.replace("%n%",cbs.length)))return;'
       . 'var csrf=document.getElementById("REL_CSRF");var prod=document.getElementById("REL_PROD");'
       . 'var f=document.createElement("form");f.method="post";f.action="/releases/action";'
       . 'function add(n,v){var i=document.createElement("input");i.type="hidden";i.name=n;i.value=v;f.appendChild(i);}'
       . 'add("csrf",csrf?csrf.value:"");add("op",op);add("product",prod?prod.value:"safety_monitor");'
       . 'cbs.forEach(function(c){add("files[]",c.value);});document.body.appendChild(f);f.submit();}'
       . 'function rpArcOpen(){setTimeout(function(){rpTick();},50);}'
       . 'document.addEventListener("change",function(e){if(e.target&&e.target.classList.contains("rel-cb"))rpTick();});'
       . '</script>';

    layout_end();
}

function rel_page_css(): string {
    return '<style>'
       /* Tabs */
       . '.rp-tabs{display:flex;gap:4px;flex-wrap:wrap;margin-bottom:20px;background:#f1f5f9;padding:5px;border-radius:13px;width:fit-content}'
       . '.rp-tab{padding:8px 18px;border-radius:9px;font-weight:600;font-size:13px;color:#64748b;text-decoration:none;transition:all .15s;white-space:nowrap}'
       . '.rp-tab:hover{color:#1e293b;background:#e8ecf5}'
       . '.rp-tab-on{background:#fff;color:#1e293b;font-weight:700;box-shadow:0 1px 4px rgba(15,23,42,.1)}'
       . '.rp-tab-n{display:inline-block;min-width:18px;text-align:center;background:#e2e8f0;color:#64748b;border-radius:999px;padding:1px 6px;font-size:11px;margin-left:4px;font-weight:700}'
       . '.rp-tab-on .rp-tab-n{background:#eef2ff;color:#3b5bdb}'
       /* KPI strip */
       . '.rp-kpi{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:18px}'
       . '.rp-kc{background:#fff;border:1px solid #e8ecf3;border-radius:14px;padding:16px 18px;text-align:center}'
       . '.rp-kn{font-size:24px;font-weight:800;color:#0f172a;font-variant-numeric:tabular-nums}'
       . '.rp-kn-gr{color:#15803d}'
       . '.rp-kl{font-size:11.5px;color:#94a3b8;margin-top:4px;font-weight:600;letter-spacing:.02em}'
       /* Table */
       . '.rp-th{display:flex;align-items:center;gap:12px;padding:12px 16px;border-bottom:1px solid #f1f5f9;background:#f8fafc}'
       . '.rp-sall{display:flex;align-items:center;gap:7px;font-size:13px;font-weight:600;color:#475569;cursor:pointer;user-select:none}'
       . '.rp-thlbl{font-size:12px;color:#94a3b8;margin-left:auto}'
       . '.rp-tbl{width:100%;border-collapse:collapse}'
       . '.rp-tbl th{padding:10px 14px;font-size:11px;font-weight:700;color:#94a3b8;text-transform:uppercase;letter-spacing:.06em;border-bottom:1px solid #f1f5f9;background:#f8fafc}'
       . '.rp-tbl td{padding:11px 14px;border-bottom:1px solid #f8fafc;font-size:13px;vertical-align:middle}'
       . '.rp-tbl tbody tr:last-child td{border-bottom:0}'
       . '.rp-tbl tbody tr:hover td{background:#f5f8ff}'
       . '.rp-tbl tbody tr.rp-sel td{background:#eef2ff}'
       . '.rp-ver{font-family:monospace;font-size:13.5px;font-weight:700;color:#0f172a}'
       . '.rp-dt{color:#64748b;font-size:12.5px}'
       . '.rp-sz{color:#64748b;font-size:12.5px;white-space:nowrap}'
       . '.rp-cc{width:36px;text-align:center;padding:0 6px}'
       . '.rp-chk{width:16px;height:16px;cursor:pointer;accent-color:#3b5bdb}'
       . '.rp-ac{text-align:right;white-space:nowrap}'
       /* Status pills */
       . '.rp-pill{display:inline-flex;align-items:center;gap:5px;font-size:11.5px;font-weight:700;padding:3px 10px;border-radius:999px;letter-spacing:.01em}'
       . '.rp-pill-cur{background:#dcfce7;color:#15803d}'
       . '.rp-pill-avl{background:#eff6ff;color:#1d4ed8}'
       . '.rp-pill-arc{background:#f1f5f9;color:#64748b}'
       /* Icon buttons */
       . '.rp-ib{display:inline-flex;align-items:center;justify-content:center;width:32px;height:32px;border-radius:8px;border:1px solid #e2e8f0;background:#fff;color:#475569;font-size:14px;cursor:pointer;text-decoration:none;transition:all .12s;vertical-align:middle;margin-left:3px}'
       . '.rp-ib:hover{background:#f1f5f9;border-color:#cbd5e1;color:#1e293b}'
       . '.rp-ib-push{border-color:#bbf7d0;background:#f0fdf4;color:#16a34a}.rp-ib-push:hover{background:#dcfce7}'
       . '.rp-ib-del{border-color:#fecaca;background:#fff5f5;color:#dc2626}.rp-ib-del:hover{background:#fee2e2}'
       /* Archive accordion */
       . '.rp-arc{border-top:1px solid #f1f5f9}'
       . '.rp-arc summary{display:flex;align-items:center;gap:8px;padding:12px 16px;font-size:13px;font-weight:700;color:#64748b;cursor:pointer;user-select:none;list-style:none}'
       . '.rp-arc summary::-webkit-details-marker{display:none}'
       . '.rp-arc summary:hover{color:#3b5bdb;background:#f8fafc}'
       . '.rp-arc-ico{font-size:15px}'
       . '.rp-arc-arr{font-size:11px;transition:transform .2s;display:inline-block}'
       . 'details[open] .rp-arc-arr{transform:rotate(90deg)}'
       /* Floating multi-select bar */
       . '.rp-float{position:fixed;bottom:24px;left:50%;transform:translateX(-50%);z-index:9999;'
       . 'display:flex;align-items:center;gap:12px;padding:12px 20px;'
       . 'background:#1e293b;color:#fff;border-radius:14px;box-shadow:0 8px 32px rgba(15,23,42,.35);'
       . 'font-size:13.5px;font-weight:600;min-width:360px;max-width:600px}'
       . '.rp-float-n{color:#94a3b8;white-space:nowrap;min-width:80px}'
       . '.rp-float-n b{color:#fff}'
       . '.rp-float-acts{display:flex;gap:6px;flex:1;flex-wrap:wrap}'
       . '.rp-float-acts button{background:#334155;border:0;color:#e2e8f0;border-radius:8px;padding:7px 13px;font-size:12.5px;font-weight:600;cursor:pointer;white-space:nowrap;transition:background .12s}'
       . '.rp-float-acts button:hover{background:#475569}'
       . '.rp-float-acts .rp-del{background:rgba(220,38,38,.7)}.rp-float-acts .rp-del:hover{background:#dc2626}'
       . '.rp-float-x{background:none;border:0;color:#64748b;font-size:18px;cursor:pointer;padding:0 0 0 4px;line-height:1;flex-shrink:0;transition:color .1s}'
       . '.rp-float-x:hover{color:#fff}'
       . '@media(max-width:700px){.rp-kpi{grid-template-columns:1fr 1fr}.rp-float{min-width:90vw;flex-wrap:wrap}}'
       . '</style>';
}

/* ─── admin download ─── */
function rel_download(): void {
    require_admin();
    $file = basename((string)($_GET['file'] ?? ''));
    $ctype = 'application/gzip';
    if (preg_match('/^(smpro|mailshield)-[0-9][0-9.]*\.tar\.gz$/', $file)) {
        $path = rel_dir() . '/' . $file;
    } elseif (preg_match('/^wpguard-[0-9][0-9.]*\.tar\.gz$/', $file)) {
        $path = rel_wpguard_dir() . '/' . $file;
    } elseif ($file === 'wp-guard.zip') {
        $path = rel_wpguard_dir() . '/' . $file; $ctype = 'application/zip';
    } else { http_response_code(400); exit('bad file'); }
    if (!is_file($path)) { http_response_code(404); exit('not found'); }
    rel_log($file, 'admin_download', 'panel release download');
    while (ob_get_level() > 0) { ob_end_clean(); }
    header('Content-Type: ' . $ctype);
    header('Content-Disposition: attachment; filename="' . $file . '"');
    header('Content-Length: ' . (int)filesize($path));
    header('Cache-Control: no-store');
    readfile($path);
    exit;
}
