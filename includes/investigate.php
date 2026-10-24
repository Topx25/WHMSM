<?php
/**
 * investigate.php - Site Doctor: diagnose WHY a domain/account is failing (500/blank/down)
 * and (optionally) apply a SAFE, REVERSIBLE fix. Read paths are root; every fix is backup-first
 * (rename, never delete), path-whitelisted to the account docroot, and recorded for one-click undo.
 * Used by the Forensics module's Site Doctor section.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

function smpro_inv_manifest_path() { return SMPRO_VARLIB . '/quarantine/sitedoctor/manifest.json'; }
function smpro_inv_manifest_load() { $f = smpro_inv_manifest_path(); $d = is_file($f) ? json_decode((string)@file_get_contents($f), true) : []; return is_array($d) ? $d : []; }
function smpro_inv_manifest_add($e) {
    $f = smpro_inv_manifest_path(); @is_dir(dirname($f)) || @mkdir(dirname($f), 0700, true);
    // Serialize the whole read-modify-write under a held lock so two concurrent applies can't clobber
    // each other's undo record (two admin tabs, or the auto-optimize loop overlapping a manual apply).
    @is_dir(SMPRO_LOCKS) || @mkdir(SMPRO_LOCKS, 0700, true);
    $lk = @fopen(SMPRO_LOCKS . '/sitedoctor-manifest.lock', 'c'); if ($lk) @flock($lk, LOCK_EX);
    $m = smpro_inv_manifest_load();
    $e['id'] = substr(md5(($e['to'] ?? '') . microtime(true) . smpro_inv_uniqtag()), 0, 12); $e['ts'] = time(); $e['status'] = 'applied'; $m[] = $e;
    // Cap the file WITHOUT ever dropping a still-reversible ('applied') entry - only trim the oldest 'undone' ones.
    if (count($m) > 500) {
        $keep = array_values(array_filter($m, fn($x) => ($x['status'] ?? '') === 'applied'));
        $undone = array_values(array_filter($m, fn($x) => ($x['status'] ?? '') !== 'applied'));
        $room = max(0, 500 - count($keep));
        $m = array_merge(array_slice($undone, -$room), $keep);
        usort($m, fn($a, $b) => ($a['ts'] ?? 0) <=> ($b['ts'] ?? 0));
    }
    @file_put_contents($f, json_encode($m, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), LOCK_EX); @chmod($f, 0600);
    if ($lk) { @flock($lk, LOCK_UN); @fclose($lk); }
    return $e['id'];
}

/** Resolve a domain/URL (with optional subpath) OR account -> [user, domain, docroot, home, phpver, subpath, url]. */
function smpro_inv_resolve($target) {
    $raw = strtolower(trim((string)$target));
    $raw = preg_replace('#^https?://#', '', $raw);
    $host = preg_replace('#/.*$#', '', $raw);
    $sub = '';
    if (preg_match('#/(.+)$#', $raw, $pm)) { $sub = trim($pm[1], '/'); $sub = preg_replace('#[^a-z0-9._/-]#', '', $sub); $sub = preg_replace('#\.\.+#', '', $sub); }
    $target = $host;
    if ($target === '' || !preg_match('/^[a-z0-9._-]+$/', $target)) return null;
    $user = ''; $domain = '';
    if (strpos($target, '.') !== false && is_readable('/etc/userdomains')) {
        $raw = (string)@shell_exec('grep -iE ' . escapeshellarg('^' . preg_quote($target, '/') . ':') . ' /etc/userdomains 2>/dev/null | head -1');
        if (preg_match('/:\s*(\S+)\s*$/', $raw, $m)) { $user = $m[1]; $domain = $target; }
    }
    if ($user === '' && preg_match('/^[a-z0-9_]+$/', $target) && is_dir(smpro_user_home($target))) $user = $target;
    if ($user === '') return null;
    $home = smpro_user_home($user);
    if ($domain === '' && is_readable('/var/cpanel/users/' . $user)) {
        $raw = (string)@shell_exec('grep -E ' . escapeshellarg('^DNS=') . ' /var/cpanel/users/' . escapeshellarg($user) . ' 2>/dev/null | head -1');
        if (preg_match('/^DNS=(\S+)/', trim($raw), $m)) $domain = strtolower($m[1]);
    }
    $docroot = $home . '/public_html';
    if ($domain !== '') {
        $ud = '/var/cpanel/userdata/' . $user . '/' . $domain;
        if (is_readable($ud)) { $raw = (string)@shell_exec('grep -E ' . escapeshellarg('^documentroot:') . ' ' . escapeshellarg($ud) . ' 2>/dev/null'); if (preg_match('/documentroot:\s*(\S+)/', $raw, $m)) $docroot = $m[1]; }
    }
    $phpver = '';
    if ($domain !== '') { $raw = (string)@shell_exec('timeout 15 /usr/local/cpanel/bin/whmapi1 php_get_vhost_versions 2>/dev/null | grep -iA3 ' . escapeshellarg(preg_quote($domain, '/')) . ' 2>/dev/null'); if (preg_match('/version:\s*(\S+)/', $raw, $m)) $phpver = $m[1]; }
    if ($phpver === '') { foreach ([$docroot . '/.htaccess', smpro_user_home($user) . '/public_html/.htaccess'] as $hf) { if (is_file($hf) && preg_match('/x-httpd-(ea-php\d+|[a-z0-9]*php\d+)/i', (string)@shell_exec('grep -ai "x-httpd" ' . escapeshellarg($hf) . ' 2>/dev/null'), $hm)) { $phpver = $hm[1]; break; } } }
    if ($phpver === '') { $raw = (string)@shell_exec('timeout 8 grep -aoE "ea-php[0-9]+" /var/cpanel/userdata/' . escapeshellarg($user) . '/' . escapeshellarg($domain !== '' ? $domain : 'main') . ' 2>/dev/null | head -1'); if ($raw) $phpver = trim($raw); }
    $docroot = rtrim($docroot, '/');
    // A subpath is a REAL subdirectory install ONLY if the folder exists on disk; otherwise it's a
    // VIRTUAL route (e.g. /ar/ on a multilingual site handled by the root WordPress) -> docroot stays root
    // and RewriteBase must be '/', NOT '/ar/'. (This was the bug that re-wrote the wrong base.)
    $diskSub = '';
    if ($sub !== '' && is_dir($docroot . '/' . $sub)) { $docroot .= '/' . $sub; $diskSub = $sub; }
    $url = $domain !== '' ? ('https://' . $domain . '/' . ($sub !== '' ? $sub . '/' : '')) : '';
    return ['user'=>$user,'domain'=>$domain,'docroot'=>$docroot,'home'=>$home,'phpver'=>$phpver,'subpath'=>$diskSub,'urlpath'=>$sub,'url'=>$url];
}
/** Parse account disk usage into clean stats. */
function smpro_inv_disk($user) {
    // whmapi1 IGNORES a plain `user=` arg on get_disk_usage - it returns EVERY account, and grabbing the
    // first blocks_used gives a random account (Perl hash order). Use the real api.filter mechanism so only
    // this user's row comes back.
    $ua = escapeshellarg($user);
    $raw = (string)@shell_exec('timeout 12 /usr/local/cpanel/bin/whmapi1 get_disk_usage api.filter.enable=1 api.filter.a.field=user api.filter.a.type=eq api.filter.a.arg0=' . $ua . ' user=' . $ua . ' 2>/dev/null');
    $u = preg_match('/blocks_used:\s*(\d+)/', $raw, $m) ? (int)$m[1] : 0;      // 1-KB blocks
    $l = preg_match('/blocks_limit:\s*(\d+)/', $raw, $m2) ? (int)$m2[1] : 0;
    $in = preg_match('/inodes_used:\s*(\d+)/', $raw, $m3) ? (int)$m3[1] : 0;
    if (!$u && !$l) return null;
    return ['used_mb'=>(int)round($u / 1024), 'limit_mb'=>$l ? (int)round($l / 1024) : 0, 'pct'=>$l ? (int)round($u * 100 / $l) : 0, 'inodes'=>$in];
}

/** Pinpoint culprit + fix-ability from a PHP fatal/parse message. Returns kind/component/fix/fix_action. */
function smpro_inv_culprit($msg, $docroot) {
    $comp = ''; $slug = ''; $ctype = '';
    if (preg_match('#wp-content/(plugins|themes)/([^/\'"]+)#', $msg, $m)) { $ctype = ($m[1] === 'plugins') ? 'plugin' : 'theme'; $slug = $m[2]; $comp = $ctype . ' "' . $slug . '"'; }
    $kind = ''; $fix = ''; $fixAction = ''; $fixTarget = '';
    if (stripos($msg, 'Failed opening required') !== false || stripos($msg, 'No such file') !== false || stripos($msg, 'Class ') !== false && stripos($msg, 'not found') !== false || stripos($msg, 'Call to undefined') !== false) {
        $kind = 'Missing file / class — usually a broken or incomplete update.';
        if ($ctype === 'plugin' && $slug !== '') { $fix = 'Disable the broken plugin (its folder is renamed — fully reversible), then reinstall it cleanly.'; $fixAction = 'disable_plugin'; $fixTarget = $docroot . '/wp-content/plugins/' . $slug; }
        elseif ($ctype === 'theme' && $slug !== '') { $fix = 'Switch away from / disable the broken theme, then reinstall it.'; $fixAction = 'disable_theme'; $fixTarget = $docroot . '/wp-content/themes/' . $slug; }
        else $fix = 'Restore the missing file from a backup.';
    } elseif (stripos($msg, 'syntax error') !== false || stripos($msg, 'ParseError') !== false) {
        $kind = 'PHP syntax/parse error (bad edit or corrupt upload).';
        if ($ctype === 'plugin' && $slug !== '') { $fix = 'Disable the offending plugin (reversible), then repair/reinstall it.'; $fixAction = 'disable_plugin'; $fixTarget = $docroot . '/wp-content/plugins/' . $slug; }
        else $fix = 'Revert the recent edit to the named file.';
    } elseif (stripos($msg, 'Allowed memory size') !== false) {
        $kind = 'PHP memory exhausted.'; $fix = 'Raise memory_limit and find the heavy plugin/theme.';
    } elseif (stripos($msg, 'maximum execution time') !== false) {
        $kind = 'Script timeout.'; $fix = 'Raise max_execution_time and find the slow plugin/query.';
    }
    return ['component'=>$comp,'kind'=>$kind,'fix'=>$fix,'fix_action'=>$fixAction,'fix_target'=>$fixTarget];
}

function smpro_inv_fatals($docroot, $home) {
    $out = []; $seen = [];
    foreach (array_unique([$docroot . '/error_log', $home . '/public_html/error_log', $home . '/logs/error_log']) as $lg) {
        if (!is_file($lg) || !is_readable($lg)) continue;
        $raw = (string)@shell_exec('timeout 12 grep -aiE ' . escapeshellarg('PHP (Fatal|Parse) error|Uncaught') . ' ' . escapeshellarg($lg) . ' 2>/dev/null | tail -n 12');
        foreach (array_reverse(explode("\n", trim($raw))) as $l) {
            $l = trim($l); if ($l === '') continue;
            $ts = preg_match('/^\[([^\]]+)\]/', $l, $tm) ? (strtotime($tm[1]) ?: 0) : 0;
            $msg = preg_replace('/^\[[^\]]+\]\s*/', '', $l);
            $file = preg_match('# in (/[^\s:]+\.php)(?::|\son line\s)(\d+)#', $msg, $fm) ? $fm[1] . ':' . $fm[2] : '';
            $sig = substr($msg, 0, 160); if (isset($seen[$sig])) continue; $seen[$sig] = 1;
            $row = ['ts'=>$ts,'msg'=>mb_substr($msg, 0, 400),'file'=>$file] + smpro_inv_culprit($msg, $docroot);
            $row['target_exists'] = !empty($row['fix_target']) ? (is_dir($row['fix_target']) ? 1 : 0) : 0;   // already disabled?
            $out[] = $row;
            if (count($out) >= 6) break 2;
        }
    }
    return $out;
}

function smpro_inv_recent($docroot, $hours = 48, $limit = 25) {
    if (!is_dir($docroot)) return [];
    $cmd = 'timeout 20 nice -n 19 ionice -c3 find ' . escapeshellarg($docroot)
         . ' -maxdepth 4 \( -path "*/cache/*" -o -path "*/wp-content/uploads/*" \) -prune -o'
         . ' -type f \( -name "*.php" -o -name ".htaccess" -o -name "*.ini" \) -mmin -' . (int)($hours * 60)
         . ' -printf "%TY-%Tm-%Td %TH:%TM|%p\n" 2>/dev/null | sort -r | head -n ' . (int)$limit;
    $raw = (string)@shell_exec($cmd); $out = [];
    foreach (explode("\n", trim($raw)) as $l) { if (strpos($l, '|') === false) continue; [$t, $p] = explode('|', $l, 2); $out[] = ['time'=>$t,'path'=>$p]; }
    return $out;
}

/** Parse DB creds + table prefix from a wp-config.php. */
function smpro_inv_wp_db($docroot) {
    $cfg = $docroot . '/wp-config.php'; if (!is_file($cfg) || !is_readable($cfg)) return null;
    $src = (string)@file_get_contents($cfg);
    $g = function ($k) use ($src) { return preg_match('/define\(\s*[\'"]' . $k . '[\'"]\s*,\s*[\'"](.*?)[\'"]\s*\)/s', $src, $m) ? $m[1] : ''; };
    $pfx = preg_match('/\$table_prefix\s*=\s*[\'"]([^\'"]+)[\'"]/', $src, $pm) ? $pm[1] : 'wp_';
    return ['name'=>$g('DB_NAME'),'user'=>$g('DB_USER'),'pass'=>$g('DB_PASSWORD'),'host'=>$g('DB_HOST') ?: 'localhost','prefix'=>$pfx];
}
/** Read WordPress state from the DB: siteurl/home + DB connectivity. Detects the URL-path mismatch. */
function smpro_inv_wp($docroot, $domain) {
    $db = smpro_inv_wp_db($docroot); if (!$db) return null;
    $out = ['db'=>['name'=>$db['name'],'host'=>$db['host'],'connected'=>false,'error'=>''],'siteurl'=>'','home'=>'','expected'=>('https://' . $domain),'url_mismatch'=>0];
    if (!function_exists('mysqli_connect')) { $out['db']['error'] = 'mysqli not available'; return $out; }
    $host = $db['host']; $port = 0; $sock = null;
    if (strpos($host, ':') !== false) { [$host, $p] = explode(':', $host, 2); if (is_numeric($p)) $port = (int)$p; else $sock = $p; }
    $my = @mysqli_connect($host, $db['user'], $db['pass'], $db['name'], $port ?: 0, $sock);
    if (!$my) { $out['db']['error'] = mysqli_connect_error() ?: 'connection failed'; return $out; }
    $out['db']['connected'] = true; $out['theme'] = '';
    $t = preg_replace('/[^A-Za-z0-9_]/', '', $db['prefix']) . 'options';
    if ($res = @mysqli_query($my, "SELECT option_name, option_value FROM `$t` WHERE option_name IN ('siteurl','home','template','stylesheet','blogname')")) {
        while ($row = mysqli_fetch_assoc($res)) { if (in_array($row['option_name'], ['siteurl','home'], true)) $out[$row['option_name']] = $row['option_value']; elseif ($row['option_name'] === 'stylesheet') $out['theme'] = $row['option_value']; elseif ($row['option_name'] === 'blogname') $out['blogname'] = $row['option_value']; }
    }
    if ($sv = @mysqli_get_server_info($my)) $out['db']['version'] = $sv;
    @mysqli_close($my);
    // mismatch: home/siteurl URL has a path segment that is NOT a real folder on disk (e.g. /ar virtual route)
    foreach (['home','siteurl'] as $k) {
        $p = parse_url(rtrim((string)$out[$k], '/'), PHP_URL_PATH);
        if ($p && trim($p, '/') !== '' && !is_dir($docroot . '/' . trim($p, '/'))) $out['url_mismatch'] = 1;
    }
    return $out;
}
/** Fix WordPress siteurl/home in the DB to the correct URL (reversible). */
function smpro_inv_fix_wp_url($r) {
    $docroot = $r['docroot']; if (strpos($docroot, '/home/') !== 0) return ['ok'=>false,'msg'=>'refused'];
    $db = smpro_inv_wp_db($docroot); if (!$db) return ['ok'=>false,'msg'=>'wp-config not found'];
    if (!function_exists('mysqli_connect')) return ['ok'=>false,'msg'=>'mysqli unavailable'];
    $host = $db['host']; $port = 0; $sock = null;
    if (strpos($host, ':') !== false) { [$host, $p] = explode(':', $host, 2); if (is_numeric($p)) $port = (int)$p; else $sock = $p; }
    $my = @mysqli_connect($host, $db['user'], $db['pass'], $db['name'], $port ?: 0, $sock);
    if (!$my) return ['ok'=>false,'msg'=>'DB connect failed: ' . (mysqli_connect_error() ?: '')];
    $t = preg_replace('/[^A-Za-z0-9_]/', '', $db['prefix']) . 'options';
    $want = 'https://' . $r['domain'] . ($r['subpath'] !== '' ? '/' . trim($r['subpath'], '/') : '');
    $old = [];
    if ($res = @mysqli_query($my, "SELECT option_name, option_value FROM `$t` WHERE option_name IN ('siteurl','home')")) while ($row = mysqli_fetch_assoc($res)) $old[$row['option_name']] = $row['option_value'];
    $wantEsc = mysqli_real_escape_string($my, $want);
    $ok = @mysqli_query($my, "UPDATE `$t` SET option_value='$wantEsc' WHERE option_name IN ('siteurl','home')");
    @mysqli_close($my);
    if (!$ok) return ['ok'=>false,'msg'=>'DB update failed'];
    $id = smpro_inv_manifest_add(['user'=>$r['user'],'domain'=>$r['domain'],'action'=>'fix_wp_url','kind'=>'wpurl','from'=>$docroot,'old'=>$old,'new'=>$want]);
    smpro_audit('sitedoctor_fix', ['action'=>'fix_wp_url','user'=>$r['user'],'new'=>$want,'ok'=>true]);
    return ['ok'=>true,'msg'=>'Set WordPress siteurl/home to ' . $want . ' in the database (was ' . implode('/', array_values($old)) . '). Reversible.','undo_id'=>$id];
}

/** Gather domain-relevant lines from ALL server logs (Apache/LiteSpeed/suexec/domlogs/php-fpm/modsec/user logs). */
function smpro_inv_serverlogs($r) {
    $u = $r['user']; $d = $r['domain']; $home = $r['home']; $out = [];
    // The log grep is anchored on the account's REAL home. Half of this line used to be smpro_user_home() and
    // half a hand-built "/home/<user>", so on a server whose accounts live on /home2 the domain branch matched
    // nothing and the investigation reported a quiet account. An empty home is dropped from the alternation
    // rather than left as a bare "/", which would have matched every line in every log.
    $hm  = $home !== '' ? rtrim((string)$home, '/') : smpro_user_home($u);
    $alt = [];
    if ($d !== '')  $alt[] = $d;
    if ($hm !== '') { $alt[] = $hm . '/'; $alt[] = 'cwd=' . $hm; }
    $pat = implode('|', $alt);
    // server-wide error/suexec logs (Apache + LiteSpeed)
    foreach (['/etc/apache2/logs/error_log','/usr/local/apache/logs/error_log','/var/log/apache2/error_log',
              '/usr/local/lsws/logs/error.log','/usr/local/lsws/logs/stderr.log',
              '/etc/apache2/logs/suexec_log','/usr/local/apache/logs/suexec_log','/var/log/apache2/suexec.log'] as $f) {
        if (!is_file($f) || !is_readable($f)) continue;
        $raw = (string)@shell_exec('timeout 8 nice -n 19 grep -aiE ' . escapeshellarg($pat) . ' ' . escapeshellarg($f) . ' 2>/dev/null | tail -n 5');
        foreach (explode("\n", trim($raw)) as $l) { $l = trim($l); if ($l !== '') $out[] = basename($f) . ': ' . mb_substr($l, 0, 230); }
    }
    // the account's own logs dir
    foreach (glob($home . '/logs/*.log') ?: [] as $f) {
        if (!is_readable($f)) continue;
        $raw = (string)@shell_exec('timeout 6 tail -n 4 ' . escapeshellarg($f) . ' 2>/dev/null');
        foreach (explode("\n", trim($raw)) as $l) { $l = trim($l); if ($l !== '') $out[] = 'logs/' . basename($f) . ': ' . mb_substr($l, 0, 230); }
    }
    // domlogs: recent 5xx for this domain (proves server-level failures)
    if ($d !== '') foreach (['/etc/apache2/logs/domlogs','/usr/local/apache/domlogs','/var/log/apache2/domlogs'] as $base) {
        $dl = $base . '/' . $d; if (!is_file($dl)) continue;
        $raw = (string)@shell_exec('timeout 8 nice -n 19 grep -aE \'" (5[0-9][0-9]) \' ' . escapeshellarg($dl) . ' 2>/dev/null | tail -n 5');
        foreach (explode("\n", trim($raw)) as $l) { $l = trim($l); if ($l !== '') $out[] = 'domlog: ' . mb_substr($l, 0, 230); }
        break;
    }
    // ModSecurity audit (WAF blocks can cause 500/403)
    foreach (['/var/log/apache2/modsec_audit.log','/usr/local/apache/logs/modsec_audit.log'] as $f) {
        if (!is_file($f) || !is_readable($f)) continue;
        $raw = (string)@shell_exec('timeout 8 nice -n 19 grep -aiE ' . escapeshellarg($d) . ' ' . escapeshellarg($f) . ' 2>/dev/null | tail -n 4');
        foreach (explode("\n", trim($raw)) as $l) { $l = trim($l); if ($l !== '') $out[] = 'modsec: ' . mb_substr($l, 0, 200); }
    }
    return array_slice($out, 0, 50);
}

/** STEP 1 of every scan: detect the platform/stack, site topology, and (if any) the multilingual mechanism. */
function smpro_inv_detect($docroot, $home) {
    $d = ['platform'=>'unknown','version'=>'','multisite'=>0,'debug'=>0,'multilingual'=>'','plugins'=>0,'installs'=>0,'sites'=>[],'env'=>[],'approot'=>''];
    if (is_file($docroot . '/wp-config.php') || is_file($docroot . '/wp-load.php')) {
        $d['platform'] = 'WordPress';
        $cfg = (string)@file_get_contents($docroot . '/wp-config.php');
        if (preg_match('/[\'"]MULTISITE[\'"].{0,30}(true|1)/i', $cfg)) $d['multisite'] = 1;
        if (preg_match('/[\'"]WP_DEBUG[\'"]\s*,\s*(true)/i', $cfg)) $d['debug'] = 1;
        $vf = $docroot . '/wp-includes/version.php';
        if (is_file($vf) && preg_match('/\$wp_version\s*=\s*[\'"]([^\'"]+)/', (string)@file_get_contents($vf), $vm)) $d['version'] = $vm[1];
        if (is_dir($docroot . '/wp-content/plugins')) $d['plugins'] = count(glob($docroot . '/wp-content/plugins/*', GLOB_ONLYDIR) ?: []);
        $pl = $docroot . '/wp-content/plugins';
        foreach (['sitepress-multilingual-cms'=>'WPML','polylang'=>'Polylang','polylang-pro'=>'Polylang Pro','translatepress-multilingual'=>'TranslatePress','qtranslate-xt'=>'qTranslate-XT','gtranslate'=>'GTranslate','weglot'=>'Weglot'] as $slug => $name)
            if (is_dir($pl . '/' . $slug)) { $d['multilingual'] = $name; break; }
        if ($d['multilingual'] === '' && is_dir($pl)) { // any plugin dir containing transl/multiling/lang?
            foreach (glob($pl . '/*multiling*') ?: [] as $g) { $d['multilingual'] = basename($g); break; }
        }
    } elseif (is_file($docroot . '/artisan') || is_file(dirname($docroot) . '/artisan')) {
        $d['platform'] = 'Laravel';
        $approot = is_file($docroot . '/artisan') ? $docroot : dirname($docroot); $d['approot'] = $approot;
        $cl = $approot . '/composer.lock';
        if (is_file($cl)) { $c = (string)@shell_exec('grep -aA3 ' . escapeshellarg('"name": "laravel/framework"') . ' ' . escapeshellarg($cl) . ' 2>/dev/null'); if (preg_match('/"version":\s*"([^"]+)"/', $c, $lm)) $d['version'] = $lm[1]; }
        $env = $approot . '/.env';
        if (is_file($env)) { $e = (string)@file_get_contents($env);
            foreach (['APP_ENV','APP_DEBUG','DB_CONNECTION','DB_DATABASE'] as $k) if (preg_match('/^' . $k . '\s*=\s*(.*)$/m', $e, $em)) $d['env'][$k] = trim($em[1], " \"'");
            $d['env']['APP_KEY'] = preg_match('/^APP_KEY\s*=\s*\S+/m', $e) ? 'set' : 'MISSING';
        } else $d['env']['(.env)'] = 'MISSING';
        $d['env']['vendor'] = is_dir($approot . '/vendor') ? 'present' : 'MISSING';
    } elseif (is_file($docroot . '/configuration.php') && stripos((string)@file_get_contents($docroot . '/configuration.php'), 'JConfig') !== false) { $d['platform'] = 'Joomla';
    } elseif (is_file($docroot . '/sites/default/settings.php') || is_dir($docroot . '/core/lib/Drupal')) { $d['platform'] = 'Drupal';
    } elseif (is_file($docroot . '/bin/magento')) { $d['platform'] = 'Magento';
    } elseif (is_file($docroot . '/index.php') || glob($docroot . '/*.php')) { $d['platform'] = 'PHP';
    } else { $d['platform'] = 'static'; }
    // topology: how many CMS installs under the account + the REAL domains (from /etc/userdomains, the authority)
    $inst = (string)@shell_exec('timeout 18 nice -n 19 find ' . escapeshellarg($home) . ' -maxdepth 6 -name wp-config.php 2>/dev/null | head -40');
    $d['installs'] = count(array_filter(array_map('trim', explode("\n", trim($inst)))));
    $user = basename($home);
    $dom = (string)@shell_exec('grep -iE ' . escapeshellarg(':[[:space:]]*' . preg_quote($user, '/') . '[[:space:]]*$') . ' /etc/userdomains 2>/dev/null | cut -d: -f1');
    foreach (explode("\n", trim($dom)) as $l) { $l = strtolower(trim($l)); if ($l !== '' && strpos($l, '*') === false) $d['sites'][] = $l; }
    $d['sites'] = array_values(array_unique($d['sites']));
    return $d;
}

/** Theme & plugin health: map every error in the site log to its component (WordPress-specific). */
function smpro_inv_components($docroot) {
    $log = $docroot . '/error_log'; if (!is_file($log)) return [];
    $raw = (string)@shell_exec('timeout 10 nice -n 19 tail -n 800 ' . escapeshellarg($log) . ' 2>/dev/null');
    $agg = [];
    foreach (explode("\n", $raw) as $l) {
        if (!preg_match('#wp-content/(plugins|themes)/([A-Za-z0-9._-]+)#', $l, $cm)) continue;
        if (strpos($cm[2], '.smpro-disabled') !== false) continue;
        $sev = 'warning';
        if (preg_match('/PHP (Fatal|Parse) error|Uncaught/i', $l)) $sev = 'critical';
        elseif (preg_match('/PHP (Notice|Deprecated)/i', $l)) $sev = 'notice';
        elseif (!preg_match('/PHP Warning/i', $l)) continue;                  // only real PHP problems
        $type = $cm[1] === 'plugins' ? 'plugin' : 'theme'; $name = $cm[2]; $key = $type . ':' . $name;
        if (!isset($agg[$key])) { $path = $docroot . '/wp-content/' . $cm[1] . '/' . $name; $agg[$key] = ['type'=>$type,'name'=>$name,'path'=>$path,'sev'=>$sev,'count'=>0,'exists'=>is_dir($path) ? 1 : 0,'sample'=>'']; }
        $agg[$key]['count']++;
        $rank = ['notice'=>1,'warning'=>2,'critical'=>3];
        if ($rank[$sev] > $rank[$agg[$key]['sev']]) $agg[$key]['sev'] = $sev;
        if ($agg[$key]['sample'] === '') $agg[$key]['sample'] = trim(preg_replace('/^\[[^\]]+\]\s*/', '', $l));
    }
    usort($agg, fn($a, $b) => (['notice'=>1,'warning'=>2,'critical'=>3][$b['sev']] <=> ['notice'=>1,'warning'=>2,'critical'=>3][$a['sev']]) ?: ($b['count'] <=> $a['count']));
    return array_slice(array_values($agg), 0, 15);
}

/** This server's main public IP (cPanel mainip, then fallbacks). */
function smpro_inv_server_ip() {
    foreach (['/var/cpanel/mainip'] as $f) { if (is_readable($f)) { $ip = trim((string)@file_get_contents($f)); if (filter_var($ip, FILTER_VALIDATE_IP)) return $ip; } }
    $ip = trim((string)@shell_exec('hostname -I 2>/dev/null')); $ip = trim((string)strtok($ip, ' '));
    return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '';
}
/** STEP 0 - validate the domain itself: does public DNS resolve it, to which IP, and does it point HERE?
 *  This is the first thing to check before any PHP/plugin diagnosis (a domain not pointed here can never load). */
function smpro_inv_dns($domain) {
    $domain = strtolower(trim((string)$domain));
    if ($domain === '') return null;
    $serverIp = smpro_inv_server_ip();
    // resolve via a public resolver (independent of the box's own /etc/hosts); fall back to gethostbyname
    $ips = [];
    $dig = trim((string)@shell_exec('timeout 6 dig +short A ' . escapeshellarg($domain) . ' @1.1.1.1 2>/dev/null'));
    if ($dig === '') $dig = trim((string)@shell_exec('timeout 6 dig +short A ' . escapeshellarg($domain) . ' 2>/dev/null'));
    foreach (explode("\n", $dig) as $line) { $line = trim($line); if (filter_var($line, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) $ips[] = $line; }
    if (!$ips) { $g = @gethostbyname($domain); if ($g && $g !== $domain && filter_var($g, FILTER_VALIDATE_IP)) $ips[] = $g; }
    // Cloudflare/proxy ranges (so "points elsewhere" isn't a false alarm when the site is behind a CDN)
    $cf = ['104.16.','104.17.','104.18.','104.19.','104.2','172.64.','172.65.','172.66.','172.67.','173.245.','188.114.','190.93.','197.234.','198.41.','162.158.','141.101.','108.162.'];
    $proxied = false; foreach ($ips as $ip) foreach ($cf as $p) if (strpos($ip, $p) === 0) { $proxied = true; break 2; }
    $resolves = !empty($ips);
    $here = $serverIp !== '' && in_array($serverIp, $ips, true);
    if (!$resolves)       { $state = 'nxdomain'; $note = 'The domain does not resolve in public DNS — it is unregistered, expired, or its DNS is broken. The site can never load until DNS is fixed.'; }
    elseif ($here)        { $state = 'ok';       $note = 'DNS points to this server (' . $serverIp . ').'; }
    elseif ($proxied)     { $state = 'proxied';  $note = 'DNS points to a Cloudflare/CDN IP (' . implode(', ', $ips) . ') — normal if you use Cloudflare; the origin must still be this server.'; }
    else                  { $state = 'elsewhere';$note = 'DNS points to ' . implode(', ', $ips) . ', NOT this server (' . ($serverIp ?: '?') . '). The domain is pointed at a different host — that is why it does not load here.'; }
    return ['domain'=>$domain,'ips'=>$ips,'server_ip'=>$serverIp,'resolves'=>$resolves,'here'=>$here,'proxied'=>$proxied,'state'=>$state,'note'=>$note];
}
/** HTTP probe that FOLLOWS redirects and detects loops - so a 301/302 (and a redirect loop) is diagnosed,
 *  not mistaken for "up". Returns first code, final code, hop count, final URL, and whether it looped. */
function smpro_inv_http($url) {
    $out = ['code'=>0,'url'=>$url,'first'=>0,'final'=>0,'hops'=>0,'final_url'=>'','loop'=>false,'chain'=>''];
    if ($url === '') return $out;
    $A = '-A ' . escapeshellarg('SafetyMonitorPro/investigate') . ' --connect-timeout 10 -m 20 -ksS';
    // (1) first response WITHOUT following - reveals a 301/302 at the entry
    $first = (int)trim((string)@shell_exec('timeout 22 curl ' . $A . ' -o /dev/null -w "%{http_code}" ' . escapeshellarg($url) . ' 2>/dev/null'));
    // (2) follow up to 10 hops - final code + hop count + effective URL
    $w = (string)@shell_exec('timeout 25 curl ' . $A . ' -L --max-redirs 10 -o /dev/null -w "%{http_code}|%{num_redirects}|%{url_effective}" ' . escapeshellarg($url) . ' 2>/dev/null');
    $p = explode('|', trim($w));
    $final = (int)($p[0] ?? 0); $hops = (int)($p[1] ?? 0); $furl = (string)($p[2] ?? '');
    $loop = ($hops >= 10) || ($final === 0 && $hops > 0);     // hit the hop cap (or curl aborted mid-redirect) = loop
    $out['first'] = $first; $out['final'] = $final; $out['hops'] = $hops; $out['final_url'] = $furl; $out['loop'] = $loop;
    $out['code'] = $loop ? 310 : ($final ?: $first);          // 310 = synthetic "redirect loop"
    // capture the Location chain (reveals the loop pattern, e.g. https->http->https) - diagnostic + AI evidence
    if ($first >= 300 && $first < 400) {
        $hdr = (string)@shell_exec('timeout 25 curl ' . $A . ' -sIL --max-redirs 10 ' . escapeshellarg($url) . ' 2>/dev/null');
        $locs = []; foreach (explode("\n", $hdr) as $ln) { if (stripos($ln, 'location:') === 0) { $loc = trim(substr($ln, 9)); if ($loc !== '') $locs[] = $loc; if (count($locs) >= 6) break; } }
        $out['chain'] = implode(' -> ', $locs);
    }
    return $out;
}

/** Full read-only investigation. */
function smpro_inv_run($target) {
    $r = smpro_inv_resolve($target);
    if (!$r) return ['ok'=>false,'msg'=>'Could not resolve that domain/account on this server.'];
    $domain = $r['domain']; $docroot = $r['docroot']; $home = $r['home']; $url = $r['url'] ?: ($domain ? 'https://' . $domain . '/' : '');
    // STEP 0: domain/DNS validity (first troubleshooting step - is the domain even pointed here?)
    $dns = $domain !== '' ? smpro_inv_dns($domain) : null;
    // HTTP with redirect-follow + loop detection (so 301/302 is handled, not read as "up")
    $http = smpro_inv_http($url);
    $ht = null; $htp = $docroot . '/.htaccess';
    if (is_file($htp)) {
        $head = (string)@shell_exec('head -c 1600 ' . escapeshellarg($htp) . ' 2>/dev/null');
        $issues = [];
        $expectBase = '/' . ($r['subpath'] !== '' ? trim($r['subpath'], '/') . '/' : '');
        if (preg_match('/RewriteBase\s+(\S+)/i', $head, $bm)) {
            $rb = rtrim($bm[1], '/') . '/';
            if (rtrim($rb, '/') !== rtrim($expectBase, '/')) $issues[] = 'RewriteBase is ' . $bm[1] . ' but this site\'s web root is ' . $expectBase . ' — this .htaccess likely belongs to another (sub)site; it can cause 500 / redirect loops.';
        }
        $ht = ['mtime'=>date('Y-m-d H:i', (int)@filemtime($htp)),'head'=>mb_substr($head, 0, 1400),'path'=>$htp,'issues'=>$issues];
    }
    // Last raw log lines (warnings/notices too) - shown when there is no clear fatal, so the tool is never a dead end.
    $logtail = [];
    foreach ([$docroot . '/error_log', $home . '/public_html/error_log'] as $lg) {
        if (!is_file($lg)) continue;
        $raw = (string)@shell_exec('tail -n 15 ' . escapeshellarg($lg) . ' 2>/dev/null');
        foreach (explode("\n", trim($raw)) as $l) { $l = trim($l); if ($l !== '') $logtail[] = mb_substr($l, 0, 300); }
        break;
    }
    $fatals = smpro_inv_fatals($docroot, $home);
    // Reconcile with the LIVE state: the actionable cause is the newest fatal whose culprit still exists.
    $live = null; foreach ($fatals as $f) if (!empty($f['fix_target']) && !empty($f['target_exists'])) { $live = $f; break; }
    // "up" = the FOLLOWED final response is 2xx/3xx AND it is not a redirect loop (a 301 that ends at 200 is up).
    $up = (!$http['loop'] && $http['final'] >= 200 && $http['final'] < 400);
    // STEP-0 gates: a domain that doesn't resolve here, or a redirect loop, is the real cause - surface it first.
    $dnsBad = $dns && in_array($dns['state'], ['nxdomain','elsewhere'], true);
    if     ($dnsBad)                 $status = 'dns';            // domain not pointed here -> nothing else matters
    elseif ($http['loop'])           $status = 'redirect_loop';  // 301/302 loop (e.g. http↔https, really-simple-ssl, wrong siteurl)
    elseif ($up && !$live)           $status = 'up';            // responding + no actionable culprit
    elseif ($live)                   $status = 'down_actionable';// a fixable culprit is present
    elseif ($http['final'] >= 400 || $http['first'] >= 400) $status = 'down';
    else $status = 'unknown';
    $staleFixed = (!$up && !$live && $fatals && empty($fatals[0]['target_exists']) && !empty($fatals[0]['fix_target']));
    $result = ['ok'=>true,'user'=>$r['user'],'domain'=>$domain,'docroot'=>$docroot,'phpver'=>$r['phpver'],'subpath'=>$r['subpath'] ?? '',
            'dns'=>$dns,
            'http'=>$http,'status'=>$status,'fatals'=>$fatals,'live_cause'=>$live,'recent'=>smpro_inv_recent($docroot),
            'htaccess'=>$ht,'logtail'=>$logtail,'serverlogs'=>smpro_inv_serverlogs($r),'wp'=>smpro_inv_wp($docroot, $domain),'disk'=>smpro_inv_disk($r['user']),'hardened'=>smpro_inv_hardened_scan($docroot, $r['user']),
            'undo'=>array_values(array_filter(smpro_inv_manifest_load(), fn($e) => ($e['status'] ?? '') === 'applied' && ($e['user'] ?? '') === $r['user']))];
    $result['detect'] = smpro_inv_detect($docroot, $home);   // platform / topology / multilingual (step 1)
    $result['selfhealers'] = smpro_inv_selfhealers($docroot); // mu-plugins that revert fixes
    $result['components'] = smpro_inv_components($docroot);   // theme/plugin health
    $result['logsize'] = is_file($docroot . '/error_log') ? (int)@filesize($docroot . '/error_log') : 0;
    $result['fixes'] = smpro_inv_fixes($result);   // everything the button can apply on its own (un-harden first)
    return $result;
}

/**
 * SPEED diagnosis - measure the site live (TTFB breakdown) and RANK the real causes of slowness.
 * Read-only, cheap (page-load safe), and graceful: every signal is guarded so a missing tool/file is
 * skipped, never fatal. Returns { ok, user, domain, url, phpver, code, timing{}, server_side, causes[] }.
 */
function smpro_inv_speed($target) {
    $r = smpro_inv_resolve($target);
    if (!$r || ($r['url'] ?? '') === '') return ['ok' => false, 'msg' => 'Could not resolve a live domain for that account/target.'];
    $user = $r['user']; $domain = $r['domain']; $docroot = $r['docroot']; $url = $r['url']; $phpver = (string)$r['phpver'];
    $A = "-A 'SafetyMonitorPro/speed'";

    // 1) one curl for the full latency split (seconds -> ms)
    $wfmt = 'DNS=%{time_namelookup} CONN=%{time_connect} TLS=%{time_appconnect} TTFB=%{time_starttransfer} TOTAL=%{time_total} SIZE=%{size_download} SPEED=%{speed_download} HTTP=%{http_version} CODE=%{http_code}';
    $probe = function ($ua, $maxt) use ($wfmt, $url) {
        $raw = (string)@shell_exec('timeout ' . ((int)$maxt + 6) . ' curl -A ' . escapeshellarg($ua) . ' --connect-timeout 8 -m ' . (int)$maxt . ' -ksSL --max-redirs 5 -o /dev/null -w ' . escapeshellarg($wfmt) . ' ' . escapeshellarg($url) . ' 2>/dev/null');
        $t = []; foreach (['DNS','CONN','TLS','TTFB','TOTAL','SIZE','SPEED','HTTP','CODE'] as $k) if (preg_match('/\b' . $k . '=([0-9.]+)/', $raw, $m)) $t[$k] = (float)$m[1];
        return $t;
    };
    $t = $probe('SafetyMonitorPro/speed', 16);
    // A curl http_code of 0 is NOT proof the site is down - a slow app or a WAF that blocks non-browser User-Agents
    // also yields 0. Retry once with a real browser UA + a longer timeout before concluding anything.
    if ((int)($t['CODE'] ?? 0) === 0) $t = $probe('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36 SafetyMonitorPro', 30);
    $code = (int)($t['CODE'] ?? 0);
    if ($code === 0) {
        $connected = ((float)($t['CONN'] ?? 0)) > 0;   // TCP connected but no HTTP response = slow/hung/UA-blocked, NOT down
        return ['ok' => false, 'connected' => $connected, 'user' => $user, 'domain' => $domain,
            'msg' => $connected
                ? 'The server accepted the connection but returned no page within 30s — the site is reachable but may be very slow, hung, or blocking automated requests. Use “Diagnose” to check for PHP fatals / 5xx / long TTFB.'
                : 'The site did not respond (no TCP connection — DNS failure, firewall block, or the site is down). Use “Diagnose” for failures.'];
    }
    $ms = fn($s) => (int)round(((float)$s) * 1000);
    $dns = $ms($t['DNS'] ?? 0);
    $conn = max(0, $ms(($t['CONN'] ?? 0) - ($t['DNS'] ?? 0)));
    $tls = max(0, $ms(($t['TLS'] ?? 0) - ($t['CONN'] ?? 0)));
    $ttfb = $ms($t['TTFB'] ?? 0);
    $total = $ms($t['TOTAL'] ?? 0);
    $netSetup = max((float)($t['TLS'] ?? 0), (float)($t['CONN'] ?? 0));      // last of connect/TLS before the server thinks
    $think = max(0, $ms(((float)($t['TTFB'] ?? 0)) - $netSetup));            // pure server processing time
    $download = max(0, $total - $ttfb);
    $sizeKb = (int)round(((float)($t['SIZE'] ?? 0)) / 1024);
    $httpv = isset($t['HTTP']) ? ((float)$t['HTTP'] >= 2 ? '2' : ((float)$t['HTTP'] >= 1.1 ? '1.1' : '1.0')) : '?';

    // 2) header-only pass for compression + cache
    $hdr = (string)@shell_exec('timeout 10 curl ' . $A . ' -ksI -H ' . escapeshellarg('Accept-Encoding: gzip, br') . ' -m 8 ' . escapeshellarg($url) . ' 2>/dev/null');
    $compressed = (bool)preg_match('/content-encoding:\s*(gzip|br|zstd)/i', $hdr);
    $cacheStatus = preg_match('/(?:x-litespeed-cache|x-cache|cf-cache-status|x-proxy-cache):\s*([a-z]+)/i', $hdr, $cm) ? strtolower($cm[1]) : '';

    $causes = [];
    $add = function ($sev, $cause, $evidence, $fix, $action = null) use (&$causes) { $causes[] = ['sev' => $sev, 'cause' => $cause, 'evidence' => $evidence, 'fix' => $fix, 'action' => $action]; };
    $serverSide = ($think >= 700);   // server processing dominates -> dig into PHP/DB/limits

    // 3) whole-server overload (reuse the load engine - a slow site may just be a slow box)
    if (function_exists('smpro_load_evidence')) {
        $ev = smpro_load_evidence();
        $lpc = (float)($ev['load_per_core'] ?? 0); $wa = (float)($ev['cpu']['wa'] ?? 0); $stl = (float)($ev['cpu']['st'] ?? 0);
        $swap = (int)($ev['mem']['swap_used_pct'] ?? 0); $memp = (int)($ev['mem']['used_pct'] ?? 0);
        $mine = null; foreach (($ev['swarms'] ?? []) as $s) if (($s['user'] ?? '') === $user) { $mine = $s; break; }
        $loadLink = ['type' => 'link', 'page' => 'load-monitor', 'label' => 'Open Load Investigator'];
        if ($mine && (float)($mine['cpu'] ?? 0) >= 80)
            $add('high', 'This account is overloading the server right now', 'account ' . $user . ' is running ' . (int)$mine['count'] . '× ' . $mine['comm'] . ' (~' . $mine['cpu'] . '% CPU)' . (!empty($mine['wp_cron']) ? ' — mostly wp-cron' : ''), 'Cut concurrent PHP for this account: enable page caching, move wp-cron to a real system cron, or throttle it with the Cooler.', $loadLink);
        elseif ($lpc >= 1.0)
            $add($lpc >= 2.0 ? 'high' : 'medium', 'The whole server is overloaded (every site is affected, not just this one)', 'load per core ' . $lpc . ($wa >= 20 ? ', iowait ' . $wa . '%' : '') . ($stl >= 10 ? ', CPU steal ' . $stl . '% (oversold VPS host)' : ''), 'The box itself is slow. Find the heaviest account in the Load Investigator' . ($stl >= 10 ? '; high steal means the VPS host is oversold — raise it with your provider' : '') . '.', $loadLink);
        elseif ($wa >= 25)
            $add('medium', 'Server is disk-I/O bound', 'iowait ' . $wa . '%', 'A backup or heavy query is saturating the disk. See what’s running in the Load Investigator / Top Processes.', $loadLink);
        if ($swap >= 40) $add('medium', 'Server is swapping (RAM exhausted)', 'swap ' . $swap . '% used · RAM ' . $memp . '%', 'Memory pressure slows everything. Reduce memory use or add RAM.');
    }

    // 4) CloudLinux LVE throttling of THIS account - the #1 shared-hosting slowness cause
    if (is_file('/etc/cloudlinux-release')) {
        $lv = (string)@shell_exec('timeout 8 lveinfo --user=' . escapeshellarg($user) . ' --period=1h --show-columns aCPU,cpuf,epf,mpf,iof --json 2>/dev/null');
        if ($lv === '') $lv = (string)@shell_exec('timeout 8 lveinfo -d --user ' . escapeshellarg($user) . ' --period 1h 2>/dev/null');
        $sum = function ($blob, $keys) { $n = 0; foreach ($keys as $kk) if (preg_match_all('/"?' . $kk . '"?\s*[:=]\s*"?([0-9]+)/i', $blob, $mm)) foreach ($mm[1] as $v) $n += (int)$v; return $n; };
        $cpuf = $sum($lv, ['cpuFault', 'cpuf', 'CPUf']); $epf = $sum($lv, ['ePf', 'epf', 'EPf']); $mpf = $sum($lv, ['mPf', 'mpf', 'memf']); $iof = $sum($lv, ['ioFault', 'iof', 'iopsf']);
        if ($cpuf + $epf + $mpf + $iof > 0) {
            $p = []; if ($cpuf) $p[] = $cpuf . '× CPU'; if ($epf) $p[] = $epf . '× entry-process'; if ($mpf) $p[] = $mpf . '× memory'; if ($iof) $p[] = $iof . '× I/O';
            $add('high', 'This account is hitting its CloudLinux resource limits (throttled)', 'faults in the last hour: ' . implode(', ', $p) . ' — CloudLinux slows/queues the account when it exceeds its cage limits', 'Raise this account’s LVE limits in WHM → CloudLinux LVE Manager (bump CPU% / EP / IO), or cut the load (caching, wp-cron, heavy plugins). This is the top cause of “my site is randomly slow” on shared hosting.');
        }
    }

    // 5) OPcache OFF for the account's PHP - flat tax on every request
    if (preg_match('/php\s*[-_]?\s*(\d)\.?(\d)/i', $phpver, $pv) || preg_match('/(\d)(\d)/', $phpver, $pv)) {
        $bin = '/opt/cpanel/ea-php' . $pv[1] . $pv[2] . '/root/usr/bin/php';
        if (is_executable($bin)) {
            $oc = trim((string)@shell_exec('timeout 8 ' . escapeshellarg($bin) . ' -d error_reporting=0 -r ' . escapeshellarg('echo (int)ini_get("opcache.enable");') . ' 2>/dev/null'));
            if ($oc === '0') $add('high', 'OPcache is OFF for this site’s PHP (' . $phpver . ')', 'every request recompiles PHP from source — a flat penalty on server think-time', 'Turn OPcache on in Server Tune-up (opcache.enable=1) — it usually cuts TTFB noticeably.', ['type' => 'link', 'page' => 'server-tuning', 'label' => 'Open Server Tune-up']);
        }
        $pn = (int)($pv[1] . $pv[2]);
        if ($pn > 0 && $pn <= 74) $add('medium', 'Old, end-of-life PHP (' . $phpver . ')', 'PHP ' . $pv[1] . '.' . $pv[2] . ' is EOL and markedly slower than 8.x', 'Switch the domain to PHP 8.2/8.3 in WHM → MultiPHP Manager (test first — very old plugins may need updates).');
    }

    // 6) Database: WP autoload bloat + slow-query-log visibility (reuse the wp-config creds)
    $db = smpro_inv_wp_db($docroot);
    if ($db && ($db['name'] ?? '') !== '' && function_exists('mysqli_connect')) {
        $h = $db['host']; $port = 0; $sock = null;
        if (strpos($h, ':') !== false) { [$h, $pp] = explode(':', $h, 2); if (is_numeric($pp)) $port = (int)$pp; else $sock = $pp; }
        $my = @mysqli_connect($h, $db['user'], $db['pass'], $db['name'], $port ?: 0, $sock);
        if ($my) {
            $tbl = preg_replace('/[^A-Za-z0-9_]/', '', $db['prefix']) . 'options';
            if ($res = @mysqli_query($my, "SELECT ROUND(SUM(LENGTH(option_value))/1024) kb, COUNT(*) n FROM `$tbl` WHERE autoload='yes'")) {
                if ($row = mysqli_fetch_assoc($res)) { $akb = (int)($row['kb'] ?? 0);
                    if ($akb > 1024) $add($akb > 3072 ? 'high' : 'medium', 'WordPress autoloaded options are bloated (' . $akb . ' KB)', (int)$row['n'] . ' options load on EVERY page (' . $akb . ' KB); WordPress recommends under ~800 KB', 'Find the largest autoloaded options (usually a plugin storing data there) and set them to autoload=no, or clear orphaned transients in Database Cleanup.', ['type' => 'link', 'page' => 'database-cleanup', 'label' => 'Open Database Cleanup']);
                }
            }
            if ($serverSide && ($res = @mysqli_query($my, "SHOW GLOBAL VARIABLES WHERE Variable_name IN ('slow_query_log','long_query_time')"))) {
                $v = []; while ($rw = mysqli_fetch_row($res)) $v[$rw[0]] = $rw[1];
                if (($v['slow_query_log'] ?? 'ON') === 'OFF') $add('low', 'MySQL slow-query log is off — DB slowness is invisible', 'slow_query_log=OFF, so genuinely slow queries for this site can’t be captured', 'Enable the slow-query log (long_query_time=2) in Server Tune-up, reproduce the slow page, then optimize/index the queries it records.', ['type' => 'link', 'page' => 'server-tuning', 'label' => 'Open Server Tune-up']);
            }
            @mysqli_close($my);
        }
    }

    // 7) No page cache on a slow WordPress site
    if ($serverSide && is_file($docroot . '/wp-config.php')) {
        $hasAdv = is_file($docroot . '/wp-content/advanced-cache.php');
        $cacheHit = $cacheStatus !== '' && strpos($cacheStatus, 'hit') !== false;
        if (!$hasAdv && !$cacheHit)
            $add('medium', 'No page cache — every visit is rebuilt with PHP + DB', 'no advanced-cache.php drop-in and the response isn’t served from cache (' . ($cacheStatus ?: 'no cache header') . ')', 'Add a page-cache plugin: LiteSpeed Cache (free) if the server runs LiteSpeed, otherwise WP Super Cache / W3 Total Cache. Caching typically cuts TTFB dramatically.');
    }

    // 8) Frontend + network (from the timing + headers)
    if (!$compressed && $sizeKb > 50) $add('medium', 'Response isn’t compressed', 'the page is ' . $sizeKb . ' KB with no gzip/Brotli', 'Enable gzip/Brotli (mod_deflate, LiteSpeed, or Cloudflare compression) to shrink the HTML.');
    if ($download >= 1500 && $sizeKb > 1024) $add('medium', 'The page is large and slow to download', $sizeKb . ' KB took ' . $download . ' ms to transfer', 'Reduce page weight (optimize/lazy-load images, trim heavy assets) or put a CDN in front.');
    if ($httpv === '1.1' && $tls > 0) $add('low', 'HTTP/2 isn’t enabled', 'served over HTTP/1.1', 'Enable HTTP/2 (Apache/LiteSpeed or Cloudflare) for faster parallel loading.', ['type' => 'link', 'page' => 'server-tuning', 'label' => 'Open Server Tune-up']);
    if ($dns >= 150) $add('low', 'DNS resolution is slow', $dns . ' ms to resolve the domain', 'Consider faster authoritative DNS or Cloudflare in front.');
    if ($tls >= 400) $add('low', 'TLS handshake is slow', $tls . ' ms', 'Enable HTTP/2 + TLS session resumption to speed the handshake.');

    $rank = ['high' => 0, 'medium' => 1, 'low' => 2];
    usort($causes, fn($a, $b) => ($rank[$a['sev']] ?? 3) <=> ($rank[$b['sev']] ?? 3));
    $verdict = $think >= 1500 ? 'very_slow' : ($think >= 700 ? 'slow' : ($ttfb >= 800 ? 'okay' : 'fast'));
    smpro_audit('sitedoctor_speed', ['target' => $target, 'ttfb' => $ttfb, 'think' => $think, 'causes' => count($causes)]);
    return ['ok' => true, 'user' => $user, 'domain' => $domain, 'docroot' => $docroot, 'url' => $url, 'phpver' => $phpver, 'code' => $code,
        'verdict' => $verdict, 'server_side' => $serverSide,
        'timing' => ['dns' => $dns, 'connect' => $conn, 'tls' => $tls, 'think' => $think, 'download' => $download, 'ttfb' => $ttfb, 'total' => $total, 'size_kb' => $sizeKb, 'http' => $httpv, 'compressed' => $compressed, 'cache' => $cacheStatus],
        'causes' => $causes];
}

/* =====================================================================================
 * OPTIMIZE - proactively make a HEALTHY-but-improvable site FASTER (vs. smpro_inv_speed
 * which explains WHY it's slow). Read-only scan surfaces: stack, server flavor, asset
 * sizes (which files need optimizing + how), browser-cache/gzip gaps, and a full catalog
 * of speed scenarios. Every mutation is opt-in, backup-first, docroot-scoped, reversible.
 * ===================================================================================== */

/** Human-readable byte size. */
function smpro_inv_human($b) { $b = (int)$b; if ($b >= 1048576) return round($b / 1048576, 1) . ' MB'; if ($b >= 1024) return round($b / 1024) . ' KB'; return $b . ' B'; }
/** Short unique tag for backup filenames (1-second date resolution alone collides on rapid applies). */
function smpro_inv_uniqtag() { return function_exists('random_bytes') ? bin2hex(random_bytes(3)) : substr(md5(uniqid('', true)), 0, 6); }

/** The exact ASCII fenced .htaccess block for a perf feature. Guaranteed to pass the writer's
 *  8KB / ASCII / no-<?php validator. $which ∈ cache|gzip|keepalive|webp_serve. */
function smpro_inv_optimize_htaccess_block($which) {
    switch ($which) {
        case 'cache':
            return "# BEGIN SMPRO-PERF (browser cache)\n"
                . "<IfModule mod_expires.c>\n"
                . "ExpiresActive On\n"
                . "ExpiresByType image/jpeg \"access plus 1 year\"\n"
                . "ExpiresByType image/png \"access plus 1 year\"\n"
                . "ExpiresByType image/gif \"access plus 1 year\"\n"
                . "ExpiresByType image/webp \"access plus 1 year\"\n"
                . "ExpiresByType image/avif \"access plus 1 year\"\n"
                . "ExpiresByType image/svg+xml \"access plus 1 year\"\n"
                . "ExpiresByType image/x-icon \"access plus 1 year\"\n"
                . "ExpiresByType text/css \"access plus 1 month\"\n"
                . "ExpiresByType application/javascript \"access plus 1 month\"\n"
                . "ExpiresByType application/x-javascript \"access plus 1 month\"\n"
                . "ExpiresByType font/woff2 \"access plus 1 year\"\n"
                . "ExpiresByType font/woff \"access plus 1 year\"\n"
                . "ExpiresByType application/font-woff2 \"access plus 1 year\"\n"
                . "ExpiresByType text/html \"access plus 0 seconds\"\n"
                . "</IfModule>\n"
                . "<IfModule mod_headers.c>\n"
                . "<FilesMatch \"\\.(jpe?g|png|gif|webp|avif|svg|ico|css|js|woff2?)$\">\n"
                . "Header set Cache-Control \"public, max-age=2592000\"\n"
                . "</FilesMatch>\n"
                . "</IfModule>\n"
                . "# END SMPRO-PERF (browser cache)";
        case 'gzip':
            return "# BEGIN SMPRO-PERF (compression)\n"
                . "<IfModule mod_deflate.c>\n"
                . "AddOutputFilterByType DEFLATE text/html text/plain text/xml text/css\n"
                . "AddOutputFilterByType DEFLATE application/javascript application/x-javascript text/javascript\n"
                . "AddOutputFilterByType DEFLATE application/json application/xml application/rss+xml\n"
                . "AddOutputFilterByType DEFLATE image/svg+xml application/vnd.ms-fontobject\n"
                . "AddOutputFilterByType DEFLATE font/ttf font/otf application/font-sfnt\n"
                . "<IfModule mod_headers.c>\n"
                . "Header append Vary Accept-Encoding\n"
                . "</IfModule>\n"
                . "</IfModule>\n"
                . "# END SMPRO-PERF (compression)";
        case 'brotli':
            return "# BEGIN SMPRO-PERF (brotli)\n"
                . "<IfModule mod_brotli.c>\n"
                . "AddOutputFilterByType BROTLI_COMPRESS text/html text/plain text/xml text/css\n"
                . "AddOutputFilterByType BROTLI_COMPRESS application/javascript application/x-javascript text/javascript\n"
                . "AddOutputFilterByType BROTLI_COMPRESS application/json application/xml image/svg+xml\n"
                . "</IfModule>\n"
                . "# END SMPRO-PERF (brotli)";
        case 'webp_serve':
            return "# BEGIN SMPRO-PERF (webp serving)\n"
                . "<IfModule mod_rewrite.c>\n"
                . "RewriteEngine On\n"
                . "RewriteCond %{HTTP_ACCEPT} image/webp\n"
                . "RewriteCond %{REQUEST_FILENAME}\\.webp -f\n"
                . "RewriteRule ^(.+)\\.(jpe?g|png)$ $1.$2.webp [T=image/webp,E=accept:1,L]\n"
                . "</IfModule>\n"
                . "<IfModule mod_headers.c>\n"
                . "Header append Vary Accept env=accept\n"
                . "</IfModule>\n"
                . "# END SMPRO-PERF (webp serving)";
    }
    return '';
}

/** Splice the given SMPRO-PERF blocks into the current .htaccess. Only the SAME feature's fenced
 *  region is stripped (by its "# BEGIN SMPRO-PERF (<label>)" marker) before re-appending - so
 *  applying gzip never removes a previously-applied cache block. Idempotent per feature. */
function smpro_inv_optimize_merge_htaccess($current, $blocks) {
    $cur = (string)$current;
    $blocks = array_values(array_filter($blocks));
    foreach ($blocks as $b) {
        if (preg_match('/# BEGIN SMPRO-PERF \(([^)]+)\)/', $b, $lm)) {
            $lbl = preg_quote($lm[1], '/');
            $cur = preg_replace('/\n*# BEGIN SMPRO-PERF \(' . $lbl . '\).*?# END SMPRO-PERF \(' . $lbl . '\)/s', '', $cur);
        }
    }
    $cur = rtrim($cur, "\n");
    $add = implode("\n\n", $blocks);
    return ($cur === '' ? '' : $cur . "\n\n") . $add;
}

/** Additive .htaccess writer for the Optimize path. Unlike smpro_inv_write_htaccess (which validates
 *  the WHOLE file as strict ASCII - and so refuses any docroot whose cPanel-generated .htaccess already
 *  contains smart-quote comments, i.e. almost all of them), this validates ONLY the block(s) we inject
 *  (we own what we add) and preserves the user's original bytes verbatim. Backup-first, chattr-aware,
 *  chown-to-docroot-owner, manifest kind='file' -> one-click Undo via the existing file-restore branch. */
function smpro_inv_optimize_write_htaccess($r, $merged, $blocks, $run = '') {
    $docroot = rtrim($r['docroot'], '/');
    if (strpos($docroot, '/home/') !== 0) return ['ok' => false, 'msg' => 'refused: docroot outside /home'];
    foreach ((array)$blocks as $b) {   // we are responsible for what we ADD - it must be clean ASCII, small, no PHP
        if (strlen($b) > 8192 || stripos($b, '<?php') !== false || preg_match('/[^\x09\x0a\x0d\x20-\x7e]/', $b))
            return ['ok' => false, 'msg' => 'refused: generated block failed safety validation'];
    }
    if (strlen($merged) > 32768) return ['ok' => false, 'msg' => 'refused: resulting .htaccess is too large'];
    $user = (string)($r['user'] ?? (preg_match('#^/home/([^/]+)#', $docroot, $mu) ? $mu[1] : ''));
    $imm  = smpro_inv_imm($docroot . '/.htaccess');
    // symlink-safe write - a root chown/write can never follow an account-planted symlink out of the account.
    [$ok, $ht, $bak, $err] = smpro_inv_ht_safe_write($docroot . '/.htaccess', $docroot, $user, rtrim($merged, "\n") . "\n");
    if (!$ok) return ['ok' => false, 'msg' => $err];
    $id = smpro_inv_manifest_add(['user' => $r['user'], 'domain' => $r['domain'], 'action' => 'optimize_htaccess', 'kind' => 'file', 'from' => $ht, 'backup' => $bak, 'hardened' => $imm ? 1 : 0, 'run' => (string)$run]);
    return ['ok' => true, 'msg' => 'Updated .htaccess (original backed up).', 'undo_id' => $id];
}

/** The choke-point guard for every asset mutation (image/css/js). Stricter than
 *  smpro_inv_fix_allowed (which only covers wp-content/plugins|themes): realpath must live
 *  under the account docroot, be an editable web asset, and not sit in a build/vendor dir. */
function smpro_inv_optimize_allowed($docroot, $path) {
    $docroot = rtrim((string)$docroot, '/');
    if (strpos($docroot, '/home/') !== 0) return false;
    $rp = @realpath($path); $rd = @realpath($docroot);
    if ($rp === false || $rd === false) return false;
    if (strpos($rp, $rd . '/') !== 0) return false;                          // must be INSIDE docroot (defeats ../ + symlink escape)
    $base = basename($rp);
    if ($base === '' || $base[0] === '.') return false;                       // no dotfiles
    if (!preg_match('/\.(css|js|jpe?g|png|gif|webp)$/i', $base)) return false; // only known web assets
    $rel = substr($rp, strlen($rd) + 1);
    if (preg_match('#(^|/)(node_modules|vendor|cache|\.git|dist|build|wp-admin|wp-includes)(/|$)#i', $rel)) return false;
    return true;
}

/** Run an optimizer on a docroot file AS THE ACCOUNT USER (so output ownership stays correct and,
 *  on CloudLinux, the account's LVE can contain it) - hard-bounded by ulimit CPU-seconds + address
 *  space + wall-clock timeout, and de-prioritized with nice/ionice. Falls back to running as root
 *  (the caller restores ownership afterwards regardless). $inner = the bare tool command with args
 *  already escaped. A root optimizer with only nice/ionice would ESCAPE the tenant's LVE cap and could
 *  load the whole shared box - the ulimit + single-file-at-a-time discipline is the hard safety net. */
function smpro_inv_optimize_run_tool($user, $inner, $timeout) {
    $t = max(5, (int)$timeout);
    $bounded = 'ulimit -t ' . $t . ' 2>/dev/null; ulimit -v 1572864 2>/dev/null; exec nice -n ' . SMPRO_SCAN_NICE . ' ionice -c' . SMPRO_SCAN_IONICE_CLASS . ' ' . $inner;
    static $hasRunuser = null; if ($hasRunuser === null) $hasRunuser = trim((string)@shell_exec('command -v runuser 2>/dev/null')) !== '';
    if (!preg_match('/^[a-z0-9_][a-z0-9_-]*$/', (string)$user) || $user === 'root') return;   // no account to drop to: do not run at all
    if ($hasRunuser) {
        @shell_exec('timeout ' . $t . ' runuser -u ' . escapeshellarg($user) . ' -- /bin/sh -c ' . escapeshellarg($bounded) . ' 2>/dev/null');
        return;
    }
    // su rather than root: between the validation and this call the account can replace the file with a symlink, and a
    // root optimizer would follow it anywhere. As the account it can only reach the account's own files.
    @shell_exec('timeout ' . $t . ' su -s /bin/sh ' . escapeshellarg($user) . ' -c ' . escapeshellarg($bounded) . ' 2>/dev/null');
}
/** Restore a file's ownership + perms to the account user (belt-and-suspenders after any root write). */
function smpro_inv_optimize_fix_owner($path, $uid, $gid, $mode = 0644) {
    if ($path === '' || !file_exists($path)) return;
    @chmod($path, $mode ?: 0644); if ($uid !== false && $uid !== null) @chown($path, $uid); if ($gid !== false && $gid !== null) @chgrp($path, $gid);
}

/** Which asset tools are installed on this box (each asset action is gated on its tool). */
function smpro_inv_optimize_tools() {
    $names = ['jpegoptim','optipng','pngquant','cwebp','gifsicle','convert','identify','terser','uglifyjs','cleancss'];
    $out = array_fill_keys($names, false);
    $raw = (string)@shell_exec('timeout 8 sh -c ' . escapeshellarg('for t in ' . implode(' ', $names) . '; do command -v "$t" >/dev/null 2>&1 && echo "$t"; done') . ' 2>/dev/null');
    foreach (explode("\n", trim($raw)) as $t) { $t = trim($t); if ($t !== '' && isset($out[$t])) $out[$t] = true; }
    return $out;
}

/** READ-ONLY optimize scan: stack, server flavor, asset sizes, htaccess gaps, full scenario catalog.
 *  Writes NOTHING. Cheap (button-triggered): reuse smpro_inv_resolve/detect + one header curl +
 *  one bounded find + the tool probe + (optionally) the smpro_inv_speed server-side causes. */
function smpro_inv_optimize_scan($target) {
    $r = smpro_inv_resolve($target);
    if (!$r) return ['ok' => false, 'msg' => 'Could not resolve that domain/account on this server.'];
    $user = $r['user']; $domain = $r['domain']; $docroot = rtrim($r['docroot'], '/'); $home = $r['home']; $phpver = (string)$r['phpver'];
    $url = $r['url'] ?: ($domain ? 'https://' . $domain . '/' : '');
    if (!is_dir($docroot)) return ['ok' => false, 'msg' => 'Document root not found on disk.'];
    smpro_inv_optimize_gc($docroot);   // prune stale orphaned backups so repeated runs can't fill disk

    // 1) stack / platform (reuse the detector) + installed cache/optimizer plugin (never fight one)
    $detect = smpro_inv_detect($docroot, $home);
    $cachePlugin = ''; $optPlugin = '';
    if ($detect['platform'] === 'WordPress') {
        $pl = $docroot . '/wp-content/plugins';
        foreach (['litespeed-cache'=>'LiteSpeed Cache','wp-rocket'=>'WP Rocket','w3-total-cache'=>'W3 Total Cache','wp-super-cache'=>'WP Super Cache','wp-fastest-cache'=>'WP Fastest Cache'] as $s => $n) if (is_dir($pl . '/' . $s)) { $cachePlugin = $n; break; }
        foreach (['autoptimize'=>'Autoptimize','litespeed-cache'=>'LiteSpeed Cache','wp-rocket'=>'WP Rocket','ewww-image-optimizer'=>'EWWW','shortpixel-image-optimiser'=>'ShortPixel','wp-smushit'=>'Smush'] as $s => $n) if (is_dir($pl . '/' . $s)) { $optPlugin = $n; break; }
    }

    // 2) server flavor + live compression/cache (one header pass)
    $flavor = 'apache'; $compressed = false; $cacheStatus = ''; $httpv = '?';
    if ($url !== '') {
        $hdr = (string)@shell_exec('timeout 10 curl -A ' . escapeshellarg('SafetyMonitorPro/optimize') . ' -ksI -H ' . escapeshellarg('Accept-Encoding: gzip, br') . ' -m 8 ' . escapeshellarg($url) . ' 2>/dev/null');
        $compressed = (bool)preg_match('/content-encoding:\s*(gzip|br|zstd)/i', $hdr);
        $cacheStatus = preg_match('/(?:x-litespeed-cache|x-cache|cf-cache-status|x-proxy-cache):\s*([a-z]+)/i', $hdr, $cm) ? strtolower($cm[1]) : '';
        if (preg_match('/^\s*server:\s*(.+)$/im', $hdr, $sm)) { $sv = strtolower($sm[1]); if (strpos($sv, 'litespeed') !== false) $flavor = 'litespeed'; elseif (strpos($sv, 'cloudflare') !== false) $flavor = 'cloudflare_front'; }
        if (preg_match('/x-litespeed-cache/i', $hdr)) $flavor = 'litespeed';
        if (preg_match('/cf-cache-status/i', $hdr) && $flavor === 'apache') $flavor = 'cloudflare_front';
        if (preg_match('#HTTP/([\d.]+)#', $hdr, $hm)) { $hv = (float)$hm[1]; $httpv = $hv >= 2 ? '2' : ($hv >= 1.1 ? '1.1' : '1.0'); }
    }
    if ($flavor === 'apache' && @is_file('/usr/local/lsws/bin/lshttpd')) $flavor = 'litespeed';

    // 3) tool presence
    $tools = smpro_inv_optimize_tools();

    // 4) .htaccess perf-block presence (file read + live cross-check)
    $ht = $docroot . '/.htaccess'; $htRaw = is_file($ht) ? (string)@file_get_contents($ht) : '';
    $cachePresent = (bool)(preg_match('/ExpiresByType\s+image/i', $htRaw) || preg_match('/<IfModule\s+mod_expires/i', $htRaw) || preg_match('/Header\s+set\s+Cache-Control/i', $htRaw) || strpos($htRaw, '# BEGIN SMPRO-PERF (browser cache)') !== false);
    if (!$cachePresent && $url !== '' && isset($hdr) && preg_match('/cache-control:[^\n]*max-age=(\d+)/i', $hdr, $mc) && (int)$mc[1] >= 86400) $cachePresent = true; // already cached on the wire
    $gzipPresent = (bool)($compressed || preg_match('/AddOutputFilterByType\s+DEFLATE/i', $htRaw) || preg_match('/<IfModule\s+mod_deflate/i', $htRaw) || strpos($htRaw, '# BEGIN SMPRO-PERF (compression)') !== false);

    // 5) asset inventory (one bounded, low-priority find). NOTE: many cPanel docroots are SYMLINKS
    // (e.g. public_html -> app/public), and find won't descend a symlinked start path - resolve it first.
    $assets = []; $imgNoWebp = []; $minifiable = []; $totalScanned = 0;
    $scanRoot = @realpath($docroot); if ($scanRoot === false || $scanRoot === '') $scanRoot = $docroot;
    $prune = "\\( -path '*/node_modules/*' -o -path '*/vendor/*' -o -path '*/cache/*' -o -path '*/.git/*' -o -path '*/dist/*' -o -path '*/build/*' -o -path '*/wp-admin/*' -o -path '*/wp-includes/*' \\) -prune -o";
    $names = "-type f \\( -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.png' -o -iname '*.gif' -o -iname '*.css' -o -iname '*.js' -o -iname '*.webp' \\)";
    $cmd = 'timeout 15 nice -n ' . SMPRO_SCAN_NICE . ' ionice -c' . SMPRO_SCAN_IONICE_CLASS . ' find ' . escapeshellarg($scanRoot) . ' -maxdepth 6 ' . $prune . ' ' . $names . " -printf '%s\\t%p\\n' 2>/dev/null";
    $raw = (string)@shell_exec($cmd);
    $webpSet = [];
    $rows = [];
    foreach (explode("\n", trim($raw)) as $ln) {
        if (strpos($ln, "\t") === false) continue;
        [$sz, $p] = explode("\t", $ln, 2); $sz = (int)$sz; $p = trim($p);
        if ($p === '' || strpos($p, $scanRoot . '/') !== 0) continue;
        $rel = substr($p, strlen($scanRoot) + 1);
        $ext = strtolower(pathinfo($p, PATHINFO_EXTENSION));
        if ($ext === 'webp') { $webpSet[preg_replace('/\.webp$/i', '', $p)] = 1; continue; }
        $rows[] = ['bytes' => $sz, 'path' => $p, 'rel' => $rel, 'ext' => $ext];
        $totalScanned++;
    }
    usort($rows, fn($a, $b) => $b['bytes'] <=> $a['bytes']);
    foreach ($rows as $row) {
        $ext = $row['ext']; $sz = $row['bytes']; $p = $row['path']; $rel = $row['rel']; $base = basename($p);
        $kind = in_array($ext, ['jpg','jpeg','png','gif'], true) ? 'image' : 'asset';
        $status = 'ok'; $why = '';
        if ($kind === 'image') {
            $toolFor = ($ext === 'png') ? ($tools['optipng'] || $tools['pngquant']) : ($ext === 'gif' ? $tools['gifsicle'] : $tools['jpegoptim']);
            if ($sz > 200 * 1024) { $status = 'optimizable'; $why = 'Large ' . strtoupper($ext) . ' (' . smpro_inv_human($sz) . ') — recompress' . ($tools['cwebp'] ? ' / convert to WebP' : '') . ($toolFor ? '' : ' (needs an image tool)'); }
            elseif ($sz > 60 * 1024 && $tools['cwebp'] && !isset($webpSet[$p]) && in_array($ext, ['jpg','jpeg','png'], true)) { $status = 'optimizable'; $why = 'No WebP version — generating one shrinks it for modern browsers'; }
            if (in_array($ext, ['jpg','jpeg','png'], true) && !isset($webpSet[$p]) && $sz > 60 * 1024) $imgNoWebp[] = ['name' => $base, 'rel' => $rel, 'bytes' => $sz, 'human' => smpro_inv_human($sz), 'status' => 'optimizable'];
        } else { // css / js
            $isMin = (bool)preg_match('/[.\-]min\.(css|js)$/i', $base);
            if (!$isMin && $sz > 30 * 1024) { $status = 'optimizable'; $why = 'Unminified ' . strtoupper($ext) . ' (' . smpro_inv_human($sz) . ') — minify to shrink it'; $minifiable[] = ['name' => $base, 'rel' => $rel, 'bytes' => $sz, 'human' => smpro_inv_human($sz), 'ext' => $ext, 'status' => 'optimizable']; }
            elseif ($isMin) $why = 'Already minified';
        }
        if (count($assets) < 40) $assets[] = ['name' => $base, 'rel' => $rel, 'bytes' => $sz, 'human' => smpro_inv_human($sz), 'kind' => $kind, 'ext' => $ext, 'status' => $status, 'why' => $why];
    }
    $bigImages = array_values(array_filter($assets, fn($a) => $a['kind'] === 'image' && $a['status'] === 'optimizable'));

    // 6) build the scenario catalog -----------------------------------------------------------
    $scen = [];
    $lsNote = $flavor === 'litespeed' ? ' LiteSpeed detected — these rules work, but installing LiteSpeed Cache (LSCache) gives page-cache + auto image/CSS/JS optimization and is the bigger win.' : '';
    $cfNote = $flavor === 'cloudflare_front' ? ' Cloudflare is in front — it already compresses/caches at the edge; origin rules still help direct-origin & non-cached hits.' : '';

    // (a) browser cache - safe one-click
    $scen[] = ['id' => 'htaccess:cache', 'title' => 'Add browser caching (Expires / Cache-Control)', 'category' => 'htaccess', 'safety' => 'safe_oneclick',
        'does' => 'Tells browsers to cache images, CSS, JS & fonts so returning visitors don\'t re-download them.',
        'method' => 'Appends a reversible mod_expires + Cache-Control block to .htaccess (HTML stays uncached). Original backed up; one-click Undo.' . $cfNote,
        'impact' => 'high', 'applicable' => !$cachePresent, 'skip_reason' => $cachePresent ? 'Browser caching is already configured (Expires/Cache-Control present).' : '',
        'files' => [['name' => '.htaccess', 'rel' => '.htaccess', 'bytes' => strlen($htRaw), 'human' => smpro_inv_human(strlen($htRaw)), 'status' => 'edit']]];

    // (b) gzip - safe one-click
    $scen[] = ['id' => 'htaccess:gzip', 'title' => 'Enable Gzip compression', 'category' => 'htaccess', 'safety' => 'safe_oneclick',
        'does' => 'Compresses HTML/CSS/JS/SVG/JSON on the way out, cutting transfer size (often 60-80% smaller).',
        'method' => 'Appends a reversible mod_deflate block to .htaccess (binaries like JPG/PNG/WebP are skipped — already compressed). Backup + Undo.' . $lsNote,
        'impact' => 'high', 'applicable' => !$gzipPresent, 'skip_reason' => $gzipPresent ? 'Responses are already gzip/Brotli compressed.' : '',
        'files' => [['name' => '.htaccess', 'rel' => '.htaccess', 'bytes' => strlen($htRaw), 'human' => smpro_inv_human(strlen($htRaw)), 'status' => 'edit']]];

    // a package manager the plugin can drive to auto-install the image tools (turns advisory -> actionable)
    $pkgMgr = trim((string)@shell_exec('command -v dnf 2>/dev/null')) !== '' ? 'dnf' : (trim((string)@shell_exec('command -v yum 2>/dev/null')) !== '' ? 'yum' : (trim((string)@shell_exec('command -v apt-get 2>/dev/null')) !== '' ? 'apt' : ''));

    // (c) image optimization - per-file, needs approval, tool-gated (auto-installable)
    $imgTool = $tools['jpegoptim'] || $tools['optipng'] || $tools['gifsicle'];
    if ($bigImages) $scen[] = ['id' => 'assets:image', 'title' => 'Optimize large images (' . count($bigImages) . ')', 'category' => 'assets', 'safety' => 'needs_approval',
        'does' => 'Recompresses oversized JPG/PNG/GIF images (lossless PNG via optipng, JPEG quality 82) — smaller files, same page.',
        'method' => $imgTool ? 'Per file: original copied to a .smpro-optbak backup, recompressed AS THE ACCOUNT USER, validated smaller & still a valid image, then swapped in. Approve/Reject each; per-file Undo.' : ($pkgMgr ? 'The image tools (jpegoptim, optipng, gifsicle) are not installed — click "Install & enable" and the plugin installs them for you, then this becomes one-click.' : 'No image tool and no package manager — advisory only.'),
        'impact' => 'high', 'applicable' => (bool)$imgTool, 'tool_needed' => 'jpegoptim / optipng / gifsicle', 'tool_present' => (bool)$imgTool,
        'installable' => (!$imgTool && $pkgMgr !== ''), 'install_group' => 'image',
        'skip_reason' => $imgTool ? '' : ($pkgMgr ? 'Image tools not installed yet — install them with one click.' : 'Image tools (jpegoptim/optipng) are not installed and no package manager was found.'),
        'files' => array_slice($bigImages, 0, 25)];

    // (d) WebP generation - additive, per-file, needs approval, tool-gated (auto-installable)
    if ($imgNoWebp) $scen[] = ['id' => 'assets:webp', 'title' => 'Generate WebP versions (' . count($imgNoWebp) . ')', 'category' => 'assets', 'safety' => 'needs_approval',
        'does' => 'Creates a modern WebP copy alongside each JPG/PNG (original untouched) — much smaller for browsers that support it.',
        'method' => $tools['cwebp'] ? 'Per file: cwebp writes a NEW <file>.webp sibling AS THE ACCOUNT USER; the original is never modified. Undo deletes the generated .webp. Pair with the "Serve WebP" rule below.' : ($pkgMgr ? 'cwebp is not installed — click "Install & enable" and the plugin installs libwebp-tools for you, then this becomes one-click.' : 'cwebp is not installed and no package manager — advisory only.'),
        'impact' => 'medium', 'applicable' => (bool)$tools['cwebp'], 'tool_needed' => 'cwebp', 'tool_present' => (bool)$tools['cwebp'],
        'installable' => (!$tools['cwebp'] && $pkgMgr !== ''), 'install_group' => 'image',
        'skip_reason' => $tools['cwebp'] ? '' : ($pkgMgr ? 'cwebp not installed yet — install it with one click.' : 'cwebp (libwebp-tools) is not installed and no package manager was found.'),
        'files' => array_slice($imgNoWebp, 0, 25)];

    // (e) serve WebP via .htaccess - needs approval
    if ($imgNoWebp || preg_match('/\.webp/i', $htRaw)) $scen[] = ['id' => 'htaccess:webp_serve', 'title' => 'Serve WebP to supported browsers', 'category' => 'htaccess', 'safety' => 'needs_approval',
        'does' => 'Automatically serves the .webp version to browsers that accept it, falling back to the original otherwise.',
        'method' => 'Appends a reversible mod_rewrite content-negotiation block to .htaccess. Backup + Undo.' . ($flavor === 'cloudflare_front' ? ' (Cloudflare Polish may already do this at the edge.)' : ''),
        'impact' => 'medium', 'applicable' => $flavor !== 'cloudflare_front', 'skip_reason' => '',
        'files' => [['name' => '.htaccess', 'rel' => '.htaccess', 'bytes' => strlen($htRaw), 'human' => smpro_inv_human(strlen($htRaw)), 'status' => 'edit']]];

    // (f) minify CSS/JS - per-file, needs approval, tool-gated
    $minTool = $tools['terser'] || $tools['uglifyjs'] || $tools['cleancss'];
    if ($minifiable) $scen[] = ['id' => 'assets:minify', 'title' => 'Minify CSS / JS (' . count($minifiable) . ')', 'category' => 'assets', 'safety' => 'needs_approval',
        'does' => 'Strips whitespace/comments from large un-minified CSS & JS files to shrink them.',
        'method' => $minTool ? 'Per file: original backed up, minified with the installed tool, validated non-empty (CSS brace-balanced), swapped in. Approve/Reject each; per-file Undo.' . ($detect['platform'] === 'WordPress' ? ' On WordPress, prefer a cache plugin — theme files get overwritten on update.' : '') : 'No JS/CSS minifier on this server — advisory only. Prefer a cache/optimize plugin (Autoptimize / LiteSpeed).',
        'impact' => 'medium', 'applicable' => (bool)$minTool, 'tool_needed' => 'terser / cleancss', 'tool_present' => (bool)$minTool,
        'skip_reason' => $minTool ? '' : 'CSS/JS minifiers (terser/cleancss) are not installed on this server.',
        'files' => array_slice($minifiable, 0, 25)];

    // (f2) brotli compression - per-account htaccess, offered only when mod_brotli is loaded & not already on & not CF-fronted
    $hasBrotli = stripos((string)@shell_exec('timeout 6 sh -c ' . escapeshellarg('apachectl -M 2>/dev/null; httpd -M 2>/dev/null; /usr/local/apache/bin/httpd -M 2>/dev/null') . ' 2>/dev/null'), 'brotli') !== false;
    $brOnWire = preg_match('/content-encoding:\s*br/i', isset($hdr) ? $hdr : '') === 1;
    if ($hasBrotli && !$brOnWire && $flavor !== 'cloudflare_front' && strpos($htRaw, '# BEGIN SMPRO-PERF (brotli)') === false)
        $scen[] = ['id' => 'htaccess:brotli', 'title' => 'Enable Brotli compression', 'category' => 'htaccess', 'safety' => 'safe_oneclick',
            'does' => 'Brotli compresses text assets smaller than gzip for browsers that support it (mod_brotli is loaded on this server).',
            'method' => 'Appends a reversible mod_brotli block to .htaccess (backed up first; one-click Undo).',
            'impact' => 'medium', 'applicable' => true, 'skip_reason' => '',
            'files' => [['name' => '.htaccess', 'rel' => '.htaccess', 'bytes' => strlen($htRaw), 'human' => smpro_inv_human(strlen($htRaw)), 'status' => 'edit']]];

    // (g) advisory catalog - fold the live speed causes (OPcache/PHP/DB/cache/HTTP2/LVE/CDN...) + stack scenarios.
    // Where a cause maps to a proven, reversible Server Tune-up applier, tag it server_apply=<recId> so the UI
    // can offer a one-click "Apply (server-wide)" alongside the deep-link (gated off behind Cloudflare for edge-served ones).
    $sp = smpro_inv_speed($target);
    $spCauses = (!empty($sp['ok']) && !empty($sp['causes'])) ? $sp['causes'] : [];
    foreach ($spCauses as $c) {
        $sa = null;
        if (stripos($c['cause'], 'OPcache') !== false) $sa = 'php_opcache';                                  // origin PHP - always applicable
        elseif (stripos($c['cause'], 'slow-query') !== false) $sa = 'mysql_slowlog';                          // origin MySQL - always applicable
        elseif (stripos($c['cause'], 'HTTP/2') !== false && $flavor !== 'cloudflare_front') $sa = 'http_h2_apache'; // moot behind CF
        $scen[] = ['id' => 'advisory:' . substr(md5($c['cause']), 0, 8), 'title' => $c['cause'], 'category' => 'advisory', 'safety' => 'advisory_only',
            'does' => $c['evidence'], 'method' => $c['fix'], 'impact' => $c['sev'] === 'high' ? 'high' : ($c['sev'] === 'medium' ? 'medium' : 'low'),
            'applicable' => true, 'files' => [], 'server_apply' => $sa,
            'deep_link' => (!empty($c['action']) && !empty($c['action']['page'])) ? ['page' => $c['action']['page'], 'label' => $c['action']['label'] ?? 'Open'] : ['page' => 'server-tuning', 'label' => 'Open Server Tune-up']];
    }
    // stack-specific advisory scenarios not already covered by a live cause
    $adv = [];
    $hasCause = function ($needle) use ($spCauses) { foreach ($spCauses as $c) if (stripos($c['cause'], $needle) !== false) return true; return false; };
    if ($detect['platform'] === 'WordPress') {
        if ($cachePlugin === '' && !$hasCause('page cache')) $adv[] = ['t' => 'Install a page-cache plugin', 'd' => 'No caching plugin detected. A full-page cache serves HTML without running PHP/DB on every hit — the single biggest WordPress speed win.', 'm' => ($flavor === 'litespeed' ? 'Install LiteSpeed Cache (free, this server runs LiteSpeed).' : 'Install WP Super Cache or W3 Total Cache from wp-admin → Plugins.'), 'i' => 'high'];
        if (!$hasCause('object cache') && $cachePlugin === '') $adv[] = ['t' => 'Add a persistent object cache (Redis)', 'd' => 'WordPress rebuilds objects/queries each request without one. Redis object cache cuts repeated DB work.', 'm' => 'Ask your host to enable Redis, then install the "Redis Object Cache" plugin.', 'i' => 'medium'];
        $adv[] = ['t' => 'Lazy-load images & defer offscreen media', 'd' => 'Loading every image up-front slows first paint.', 'm' => 'Modern WP lazy-loads by default; a cache/optimize plugin (LiteSpeed/Autoptimize) adds JS defer + critical CSS.', 'i' => 'medium'];
        $adv[] = ['t' => 'Move wp-cron to a real system cron', 'd' => 'wp-cron fires on visitor requests, adding latency and duplicate runs under load.', 'm' => 'Set DISABLE_WP_CRON in wp-config.php and add a server cron hitting wp-cron.php every 5 min (per-account).', 'i' => 'low'];
        $adv[] = ['t' => 'Audit heavy / duplicate plugins', 'd' => 'Each active plugin adds PHP work. Page-builders & "kitchen-sink" plugins are common culprits.', 'm' => 'Use Query Monitor to find the slowest plugins; remove or replace the heaviest. (Advisory — never auto-deactivate a working plugin.)', 'i' => 'medium'];
    } elseif ($detect['platform'] === 'Laravel') {
        $adv[] = ['t' => 'Build Laravel caches', 'd' => 'Un-cached config/routes/views are recompiled each request.', 'm' => 'Run php artisan config:cache route:cache view:cache (regenerable). Ensure APP_DEBUG=false in production.', 'i' => 'high'];
        $adv[] = ['t' => 'Enable OPcache + composer optimized autoload', 'd' => 'PHP recompiles on every request without OPcache; unoptimized autoload scans directories.', 'm' => 'Enable OPcache in Server Tune-up and run composer install --optimize-autoloader --no-dev.', 'i' => 'high'];
    }
    if (!$hasCause('HTTP/2') && $httpv === '1.1' && $flavor !== 'cloudflare_front') $adv[] = ['t' => 'Enable HTTP/2', 'd' => 'Served over HTTP/1.1 — one request at a time per connection.', 'm' => 'Enable HTTP/2 (mod_http2 + Protocols h2 http/1.1). One click applies it server-wide via a validated, reversible Apache include.', 'i' => 'medium', 'sa' => 'http_h2_apache'];
    if ($flavor !== 'cloudflare_front') $adv[] = ['t' => 'Enable HTTP Keep-Alive', 'd' => 'Keep-Alive reuses one TCP connection for many assets instead of reconnecting per request.', 'm' => 'One click writes a validated, reversible Apache Keep-Alive include (server-wide).', 'i' => 'low', 'sa' => 'apache_keepalive'];
    if ($flavor !== 'cloudflare_front') $adv[] = ['t' => 'Put a CDN in front (Cloudflare)', 'd' => 'A CDN caches static assets at edge locations near visitors and adds Brotli/HTTP-3.', 'm' => 'Point DNS at Cloudflare (free tier) and enable caching + Brotli. Origin stays this server.', 'i' => 'medium'];
    foreach ($adv as $a) $scen[] = ['id' => 'advisory:' . substr(md5($a['t']), 0, 8), 'title' => $a['t'], 'category' => 'advisory', 'safety' => 'advisory_only', 'does' => $a['d'], 'method' => $a['m'], 'impact' => $a['i'], 'applicable' => true, 'files' => [], 'server_apply' => ($a['sa'] ?? null), 'deep_link' => (!empty($a['sa']) ? ['page' => 'server-tuning', 'label' => 'Open Server Tune-up'] : null)];

    // rank scenarios: actionable (safe -> approval) first, by impact; advisory last
    $safRank = ['safe_oneclick' => 0, 'needs_approval' => 1, 'advisory_only' => 2];
    $impRank = ['high' => 0, 'medium' => 1, 'low' => 2];
    usort($scen, function ($a, $b) use ($safRank, $impRank) {
        return [$safRank[$a['safety']] ?? 3, $impRank[$a['impact']] ?? 3] <=> [$safRank[$b['safety']] ?? 3, $impRank[$b['impact']] ?? 3];
    });

    smpro_audit('sitedoctor_optimize_scan', ['target' => $target, 'assets' => $totalScanned, 'scenarios' => count($scen)]);
    return ['ok' => true, 'user' => $user, 'domain' => $domain, 'docroot' => $docroot, 'url' => $url, 'phpver' => $phpver,
        'stack' => ['platform' => $detect['platform'], 'version' => $detect['version'], 'multisite' => $detect['multisite'], 'plugins' => $detect['plugins'] ?? 0, 'cache_plugin' => $cachePlugin, 'opt_plugin' => $optPlugin, 'flavor' => $flavor, 'http' => $httpv, 'compressed' => $compressed, 'cache_status' => $cacheStatus],
        'tools' => $tools, 'pkg_mgr' => $pkgMgr, 'htaccess' => ['path' => $ht, 'exists' => is_file($ht), 'bytes' => strlen($htRaw), 'cache_present' => $cachePresent, 'gzip_present' => $gzipPresent],
        'assets' => $assets, 'asset_count' => $totalScanned, 'scenarios' => array_values($scen)];
}

/** Bounded GC of orphaned optimize backups (.smpro-optbak-* / .htaccess.smpro-bak-*) that are NOT
 *  referenced by a still-applied manifest entry and are older than $days - so repeated runs can't
 *  slowly fill an account's disk/inodes. Cheap: one bounded find, capped deletes. */
function smpro_inv_optimize_gc($docroot, $days = 7) {
    $docroot = @realpath($docroot); if ($docroot === false || strpos($docroot, '/home/') !== 0) return 0;
    $referenced = [];
    foreach (smpro_inv_manifest_load() as $e) if (($e['status'] ?? '') === 'applied' && !empty($e['backup'])) $referenced[$e['backup']] = 1;
    $mins = (int)($days * 1440);
    $cmd = 'timeout 12 nice -n ' . SMPRO_SCAN_NICE . ' ionice -c' . SMPRO_SCAN_IONICE_CLASS . ' find ' . escapeshellarg($docroot)
         . ' -maxdepth 6 -type f \( -name "*.smpro-optbak-*" -o -name ".htaccess.smpro-bak-*" -o -name "*.smpro-min-tmp-*" \) -mmin +' . $mins . ' 2>/dev/null | head -200';
    $n = 0;
    foreach (explode("\n", trim((string)@shell_exec($cmd))) as $f) { $f = trim($f); if ($f === '' || isset($referenced[$f])) continue; if (strpos($f, $docroot . '/') === 0 && @unlink($f)) $n++; }
    return $n;
}

/** Apply ONE optimize action (id = "type:arg"). Backup-first, docroot-scoped, tool-gated, reversible.
 *  $run = optional client run-id grouping this action for one-click "undo everything from this run".
 *  Returns {ok,msg,undo_id,before,after,files}. Refuses cleanly on any guard/tool miss. */
function smpro_inv_optimize_apply($target, $id, $run = '') {
    $r = smpro_inv_resolve($target);
    if (!$r) return ['ok' => false, 'msg' => 'Could not resolve that target.'];
    $docroot = rtrim($r['docroot'], '/');
    if (strpos($docroot, '/home/') !== 0) return ['ok' => false, 'msg' => 'refused: docroot outside /home'];
    $run = preg_replace('/[^A-Za-z0-9_.-]/', '', (string)$run);
    $id = (string)$id; $sep = strpos($id, ':'); $type = $sep === false ? $id : substr($id, 0, $sep); $arg = $sep === false ? '' : substr($id, $sep + 1);

    /* ---- .htaccess perf blocks (safe, one atomic reversible write) ---- */
    if ($type === 'htaccess') {
        $blocks = [];
        if ($arg === 'cache' || $arg === 'bundle') $blocks[] = smpro_inv_optimize_htaccess_block('cache');
        if ($arg === 'gzip'  || $arg === 'bundle') $blocks[] = smpro_inv_optimize_htaccess_block('gzip');
        if ($arg === 'webp_serve') $blocks[] = smpro_inv_optimize_htaccess_block('webp_serve');
        if ($arg === 'brotli') $blocks[] = smpro_inv_optimize_htaccess_block('brotli');
        if (!$blocks) return ['ok' => false, 'msg' => 'Unknown .htaccess action.'];
        $ht = $docroot . '/.htaccess'; $cur = is_file($ht) ? (string)@file_get_contents($ht) : '';
        $merged = smpro_inv_optimize_merge_htaccess($cur, $blocks);
        if (strlen($merged) > 16384) return ['ok' => false, 'msg' => 'Your .htaccess is large — adding this block would push it past the safe limit. Add it manually (shown below) or trim old rules first.', 'manual' => implode("\n\n", $blocks)];
        $res = smpro_inv_optimize_write_htaccess($r, $merged, $blocks, $run);
        if (!empty($res['ok'])) smpro_audit('sitedoctor_optimize_apply', ['target' => $target, 'id' => $id, 'ok' => true]);
        return $res;
    }

    /* ---- per-file asset actions (needs-approval, backup-first, tool-gated) ---- */
    if ($type === 'assets') {
        $sub = $arg; $rel = ''; $p2 = strpos($sub, ':');
        if ($p2 !== false) { $rel = substr($sub, $p2 + 1); $sub = substr($sub, 0, $p2); }
        $rel = ltrim(preg_replace('#\.\.+#', '', (string)$rel), '/');
        if ($rel === '') return ['ok' => false, 'msg' => 'No file specified.'];
        $abs = $docroot . '/' . $rel;
        if (!smpro_inv_optimize_allowed($docroot, $abs)) return ['ok' => false, 'msg' => 'refused: file is outside the account or not an editable web asset.'];
        if (!is_file($abs) || !is_writable($abs)) return ['ok' => false, 'msg' => 'File not found or not writable.'];
        // ownership guard: only touch files owned BY THE ACCOUNT (never a root-owned / other-tenant file planted in the docroot)
        $acctUid = @fileowner($r['home']); $acctGid = @filegroup($r['home']);
        $stFile = @stat($abs); $fileMode = $stFile ? ($stFile['mode'] & 0777) : 0644;
        if ($acctUid !== false && $stFile && $stFile['uid'] !== $acctUid) return ['ok' => true, 'noop' => 1, 'msg' => basename($abs) . ' is not owned by the account — skipped for safety.', 'files' => [$rel]];
        $before = (int)@filesize($abs); $ext = strtolower(pathinfo($abs, PATHINFO_EXTENSION)); $tools = smpro_inv_optimize_tools();
        // size guard: a 40MP PNG can burn CPU/RAM even bounded - skip huge files on a shared box
        if ($before > 15 * 1024 * 1024) return ['ok' => true, 'noop' => 1, 'msg' => basename($abs) . ' is larger than 15 MB — skipped to protect the shared server.', 'files' => [$rel]];
        // disk/quota guard: don't create backups/.webp when the account is (near) full
        $disk = smpro_inv_disk($r['user']); if ($disk && ($disk['pct'] ?? 0) >= 97) return ['ok' => false, 'msg' => 'The account disk quota is nearly full (' . (int)$disk['pct'] . '%) — free space before optimizing (backups need room).'];
        $ea = escapeshellarg($abs);

        if ($sub === 'webp') {   // ADDITIVE: create <file>.webp, original untouched
            if (!$tools['cwebp']) return ['ok' => false, 'msg' => 'cwebp is not installed on this server.'];
            if (!in_array($ext, ['jpg','jpeg','png'], true)) return ['ok' => false, 'msg' => 'WebP generation only applies to JPG/PNG.'];
            $webp = $abs . '.webp';
            if (is_file($webp)) return ['ok' => false, 'msg' => 'A WebP version already exists.'];
            smpro_inv_optimize_run_tool($r['user'], 'cwebp -quiet -q 80 ' . $ea . ' -o ' . escapeshellarg($webp), 30);
            if (!is_file($webp) || (int)@filesize($webp) < 32) { @unlink($webp); return ['ok' => false, 'msg' => 'WebP generation failed (or produced an empty file).']; }
            $after = (int)@filesize($webp);
            smpro_inv_optimize_fix_owner($webp, $acctUid, $acctGid, 0644);
            $undo = smpro_inv_manifest_add(['user' => $r['user'], 'domain' => $r['domain'], 'action' => 'optimize_webp', 'kind' => 'created', 'from' => $abs, 'to' => $webp, 'run' => $run]);
            smpro_audit('sitedoctor_optimize_apply', ['target' => $target, 'id' => $id, 'ok' => true]);
            return ['ok' => true, 'msg' => 'Created ' . basename($webp) . ' (' . smpro_inv_human($before) . ' → ' . smpro_inv_human($after) . ' WebP).', 'undo_id' => $undo, 'before' => $before, 'after' => $after, 'files' => [$rel]];
        }

        // in-place actions (image recompress, minify) - backup first, validate, swap, keep backup for undo
        $bak = $abs . '.smpro-optbak-' . date('Ymd_His') . '-' . smpro_inv_uniqtag();
        if (!@copy($abs, $bak)) return ['ok' => false, 'msg' => 'Could not create a backup — aborted (nothing changed).'];
        @chown($bak, $acctUid !== false ? $acctUid : @fileowner($abs)); @chgrp($bak, $acctGid !== false ? $acctGid : @filegroup($abs));

        if ($sub === 'image') {
            $ran = false;
            if (in_array($ext, ['jpg','jpeg'], true) && $tools['jpegoptim']) { smpro_inv_optimize_run_tool($r['user'], 'jpegoptim --strip-all --max=82 ' . $ea, 30); $ran = true; }
            elseif ($ext === 'png' && $tools['optipng']) { smpro_inv_optimize_run_tool($r['user'], 'optipng -o2 -quiet ' . $ea, 40); $ran = true; }
            elseif ($ext === 'gif' && $tools['gifsicle']) { smpro_inv_optimize_run_tool($r['user'], 'gifsicle -O2 -b ' . $ea, 30); $ran = true; }
            if (!$ran) { @unlink($bak); return ['ok' => false, 'msg' => 'No image tool available for a ' . strtoupper($ext) . ' file.']; }
            clearstatcache(); $after = (int)@filesize($abs);
            $valid = @getimagesize($abs) !== false;
            if (!$valid || $after <= 0 || $after >= $before) {   // no gain or corrupt -> restore, no manifest
                @copy($bak, $abs); @unlink($bak); smpro_inv_optimize_fix_owner($abs, $acctUid, $acctGid, $fileMode);
                return ['ok' => true, 'msg' => $valid ? ('Already optimal — ' . basename($abs) . ' could not be made smaller (left unchanged).') : ('Optimizer produced an invalid image — restored the original.'), 'before' => $before, 'after' => $before, 'files' => [$rel], 'noop' => 1];
            }
            smpro_inv_optimize_fix_owner($abs, $acctUid, $acctGid, $fileMode);   // FIX: restore ownership (tools may write as root via temp+rename)
        } elseif ($sub === 'minify') {
            $tmp = $abs . '.smpro-min-tmp-' . smpro_inv_uniqtag();
            if ($ext === 'css' && $tools['cleancss']) smpro_inv_optimize_run_tool($r['user'], 'cleancss -o ' . escapeshellarg($tmp) . ' ' . $ea, 25);
            elseif ($ext === 'js' && $tools['terser']) smpro_inv_optimize_run_tool($r['user'], 'terser ' . $ea . ' -c -m -o ' . escapeshellarg($tmp), 25);
            elseif ($ext === 'js' && $tools['uglifyjs']) smpro_inv_optimize_run_tool($r['user'], 'uglifyjs ' . $ea . ' -c -m -o ' . escapeshellarg($tmp), 25);
            else { @unlink($bak); return ['ok' => false, 'msg' => 'No minifier available for a ' . strtoupper($ext) . ' file.']; }
            $min = is_file($tmp) ? (string)@file_get_contents($tmp) : '';
            @unlink($tmp);
            $okMin = $min !== '' && strlen($min) < $before && ($ext !== 'css' || substr_count($min, '{') === substr_count($min, '}'));
            if (!$okMin) { @unlink($bak); return ['ok' => true, 'msg' => 'Minified output failed validation or wasn\'t smaller — left ' . basename($abs) . ' unchanged.', 'before' => $before, 'after' => $before, 'files' => [$rel], 'noop' => 1]; }
            if (@file_put_contents($abs, $min) === false) { @copy($bak, $abs); @unlink($bak); return ['ok' => false, 'msg' => 'Write failed — restored the original.']; }
            smpro_inv_optimize_fix_owner($abs, $acctUid, $acctGid, $fileMode);
            clearstatcache(); $after = (int)@filesize($abs);
        } else { @unlink($bak); return ['ok' => false, 'msg' => 'Unknown asset action.']; }

        $undo = smpro_inv_manifest_add(['user' => $r['user'], 'domain' => $r['domain'], 'action' => 'optimize_' . $sub, 'kind' => 'file', 'from' => $abs, 'backup' => $bak, 'run' => $run]);
        smpro_audit('sitedoctor_optimize_apply', ['target' => $target, 'id' => $id, 'ok' => true]);
        return ['ok' => true, 'msg' => basename($abs) . ' optimized (' . smpro_inv_human($before) . ' → ' . smpro_inv_human($after) . ', saved ' . smpro_inv_human($before - $after) . ').', 'undo_id' => $undo, 'before' => $before, 'after' => $after, 'files' => [$rel]];
    }

    return ['ok' => false, 'msg' => 'Unknown optimize action.'];
}

/** Undo EVERY still-applied action from one auto-optimize run (client run-id), newest first so a
 *  .htaccess/webp-serve rule is reverted before the .webp files it referenced. Continues past
 *  per-item failures and reports a per-item result. */
function smpro_inv_optimize_undo_run($runId) {
    $runId = preg_replace('/[^A-Za-z0-9_.-]/', '', (string)$runId);
    if ($runId === '') return ['ok' => false, 'msg' => 'No run id.'];
    $m = smpro_inv_manifest_load();
    $mine = array_values(array_filter($m, fn($e) => ($e['status'] ?? '') === 'applied' && ($e['run'] ?? '') === $runId));
    usort($mine, fn($a, $b) => ($b['ts'] ?? 0) <=> ($a['ts'] ?? 0));   // newest first
    $done = 0; $fail = 0; $items = [];
    foreach ($mine as $e) { $x = smpro_inv_undo($e['id']); if (!empty($x['ok'])) $done++; else $fail++; $items[] = ['id' => $e['id'], 'action' => $e['action'] ?? '', 'ok' => !empty($x['ok']), 'msg' => $x['msg'] ?? '']; }
    smpro_audit('sitedoctor_undo_run', ['run' => $runId, 'undone' => $done, 'failed' => $fail]);
    return ['ok' => $fail === 0, 'undone' => $done, 'failed' => $fail, 'items' => $items, 'msg' => 'Reverted ' . $done . ' change(s) from this run' . ($fail ? ', ' . $fail . ' could not be undone' : '') . '.'];
}

/** Apply a SERVER-GLOBAL tuning recommendation by REUSING the proven, reversible Server Tune-up engine
 *  (smpro_tun_apply: backup -> change -> validate -> restartsrv, restorable via Server Tune-up). Whitelisted
 *  rec ids only. This affects ALL sites on the box, so the UI gates it behind an explicit confirm; it is
 *  deliberately NOT recorded in the per-account Site Doctor undo list (its undo lives in Server Tune-up). */
function smpro_inv_optimize_apply_server($recId) {
    $recId = (string)$recId;
    if (!in_array($recId, ['php_opcache', 'apache_keepalive', 'http_h2_apache', 'mysql_slowlog'], true)) return ['ok' => false, 'msg' => 'This server change is not available as a one-click action.'];
    if (!function_exists('smpro_tun_apply')) return ['ok' => false, 'msg' => 'Server Tune-up engine unavailable.'];
    $res = smpro_tun_apply($recId);
    smpro_audit('sitedoctor_optimize_apply_server', ['rec' => $recId, 'ok' => !empty($res['ok'])]);
    return $res;
}

/** Is a path immutable (chattr +i) - i.e. hardened so it can't be renamed/edited? */
function smpro_inv_imm($p) {
    $r = (string)@shell_exec('lsattr -d ' . escapeshellarg($p) . ' 2>/dev/null');
    $tok = trim((string)strtok(trim($r), " \t"));
    return $tok !== '' && strpos($tok, 'i') !== false;
}
/** Validate that a fix target is inside the account docroot's wp-content/(plugins|themes). */
function smpro_inv_fix_allowed($docroot, $path) {
    return (bool)preg_match('#^' . preg_quote($docroot, '#') . '/wp-content/(plugins|themes)/[A-Za-z0-9._-]+$#', $path);
}

/** Find hardened/locked items that block the site from self-repairing.
 *  Priority: consult the PHP Harden manifest (authoritative - covers every file it locked);
 *  then fall back to a broad lsattr scan over the docroot's standard files + .htaccess files.
 *  Also flags .htaccess files the SITE user can't write (mode missing owner-write / wrong owner). */
function smpro_inv_hardened_scan($docroot, $user = '') {
    if (!is_dir($docroot) || strpos($docroot, '/home/') !== 0) return [];
    $out = [];
    // ── 1. PHP Harden manifest (most accurate - lists exactly what it locked) ──────────────────
    $u = $user !== '' ? $user : basename(dirname(rtrim($docroot, '/')));
    $mp = SMPRO_VARLIB . '/php_harden/' . preg_replace('/[^a-zA-Z0-9._-]/', '', $u) . '.json';
    if (is_file($mp)) {
        $m = json_decode((string)@file_get_contents($mp), true);
        if (is_array($m) && in_array($m['status'] ?? '', ['locked','temporary_unlock'], true)) {
            foreach ((array)($m['protected_files'] ?? []) as $f) {
                $p = (string)($f['path'] ?? ''); if ($p !== '' && is_file($p) && smpro_inv_imm($p)) $out[$p] = 'php-harden';
            }
            foreach ((array)($m['deny_php_dirs'] ?? []) as $d) {
                $ht = rtrim((string)($d['htaccess'] ?? ''), '/');
                if ($ht === '') $ht = rtrim((string)($d['dir'] ?? ''), '/') . '/.htaccess';
                if ($ht !== '/.htaccess' && is_file($ht) && smpro_inv_imm($ht)) $out[$ht] = 'php-harden exec-deny';
            }
        }
    }
    // ── 2. Broad lsattr scan over known candidates (catches any chattr +i not in the manifest) ─
    $cands = array_filter([
        $docroot, $docroot . '/.htaccess', $docroot . '/.user.ini', $docroot . '/php.ini',
        $docroot . '/index.php', $docroot . '/wp-config.php', $docroot . '/wp-load.php',
        $docroot . '/wp-settings.php', $docroot . '/wp-login.php', $docroot . '/xmlrpc.php',
        $docroot . '/wp-content', $docroot . '/wp-content/.htaccess',
        $docroot . '/wp-content/uploads', $docroot . '/wp-content/uploads/.htaccess',
        $docroot . '/wp-content/cache', $docroot . '/wp-content/cache/.htaccess',
        $docroot . '/wp-content/upgrade', $docroot . '/wp-content/upgrade/.htaccess',
        $docroot . '/wp-content/mu-plugins', $docroot . '/wp-content/mu-plugins/.htaccess',
        // Laravel
        $docroot . '/.env', $docroot . '/artisan', $docroot . '/public/.htaccess',
        $docroot . '/bootstrap/cache', $docroot . '/storage',
        // generic
        $docroot . '/configuration.php', $docroot . '/config.php',
    ], 'file_exists');
    if ($cands) {
        $raw = (string)@shell_exec('timeout 15 nice -n 19 lsattr -d ' . implode(' ', array_map('escapeshellarg', array_values($cands))) . ' 2>/dev/null');
        foreach (explode("\n", trim($raw)) as $l) { if (preg_match('/^(\S+)\s+(\/\S+)$/', $l, $mm) && strpos($mm[1], 'i') !== false && !isset($out[$mm[2]])) $out[$mm[2]] = 'immutable'; }
    }
    // ── 3. .htaccess files wrong owner or missing owner-write bit ────────────────────────────
    $own = @stat($docroot); $ownUid = $own['uid'] ?? -1;
    $raw2 = (string)@shell_exec('timeout 15 nice -n 19 find ' . escapeshellarg($docroot) . ' -maxdepth 3 -name .htaccess -printf "%U|%m|%p\n" 2>/dev/null | head -40');
    foreach (explode("\n", trim($raw2)) as $l) { $parts = explode('|', $l, 3); if (count($parts) < 3) continue; [$uid, $mode, $p] = $parts;
        if ($ownUid >= 0 && (int)$uid !== $ownUid) $out[$p] = $out[$p] ?? 'wrong-owner';
        elseif (!((int)octdec($mode) & 0200)) $out[$p] = $out[$p] ?? 'not-writable';
    }
    return $out;
}

/** Detect "self-healer" mu-plugins that keep reverting our fixes (re-hardening / forcing RewriteBase),
 *  by matching tags in the site error_log (e.g. "[some-mu-plugin] ... auto-fixed (RewriteBase") to mu-plugin
 *  files. The tag is whatever the plugin writes at runtime - no plugin name is hardcoded here. */
function smpro_inv_selfhealers($docroot) {
    $out = []; $log = $docroot . '/error_log'; $mu = $docroot . '/wp-content/mu-plugins';
    if (!is_file($log) || !is_dir($mu)) return $out;
    $raw = (string)@shell_exec('timeout 8 grep -aoE ' . escapeshellarg('\[[A-Za-z0-9_-]+\][^]]*(RewriteBase|hardened|SELF-HEAL|auto-fixed)') . ' ' . escapeshellarg($log) . ' 2>/dev/null | tail -30');
    $tags = [];
    foreach (explode("\n", trim($raw)) as $l) if (preg_match('/^\[([A-Za-z0-9_-]+)\]/', trim($l), $m)) $tags[strtolower($m[1])] = 1;
    if (!$tags) return $out;
    foreach (glob($mu . '/*.php') ?: [] as $f) {
        if (function_exists('smpro_wpguard_trusted') && smpro_wpguard_trusted($f)) continue;   // WP Guard's mu-plugin is a trusted security enforcer, not a fix-reverting self-healer
        $base = strtolower(basename($f)); $c = strtolower((string)@shell_exec('head -c 4000 ' . escapeshellarg($f) . ' 2>/dev/null'));
        foreach (array_keys($tags) as $tag) {
            $alnum = preg_replace('/[^a-z0-9]/', '', $tag);
            if ($alnum !== '' && (strpos(preg_replace('/[^a-z0-9]/', '', $base), $alnum) !== false || strpos($c, $tag) !== false)) { $out[$f] = $tag; break; }
        }
    }
    return $out;
}

/** Disable a self-healing mu-plugin file (rename .php -> .disabled). Reversible. Hardening-aware. */
function smpro_inv_fix_muplugin($r, $path) {
    $docroot = $r['docroot']; $path = rtrim((string)$path, '/');
    if (!preg_match('#^' . preg_quote($docroot, '#') . '/wp-content/mu-plugins/[A-Za-z0-9._-]+\.php$#', $path)) return ['ok'=>false,'msg'=>'refused: not a mu-plugin file'];
    if (!is_file($path)) return ['ok'=>false,'msg'=>'not found (already disabled?): ' . basename($path)];
    $parent = dirname($path); if (is_link($parent) || is_link($path)) return ['ok'=>false,'msg'=>'refused: a symlink in the path'];
    $pImm = smpro_inv_imm($parent); $tImm = smpro_inv_imm($path);
    if ($pImm) @shell_exec('chattr -i ' . escapeshellarg($parent) . ' 2>/dev/null');
    if ($tImm) @shell_exec('chattr -i ' . escapeshellarg($path) . ' 2>/dev/null');
    $to = $path . '.smpro-disabled-' . date('Ymd_His');
    $ok = @rename($path, $to);
    if ($pImm) @shell_exec('chattr +i ' . escapeshellarg($parent) . ' 2>/dev/null');
    if (!$ok) { if ($tImm) @shell_exec('chattr +i ' . escapeshellarg($path) . ' 2>/dev/null'); return ['ok'=>false,'msg'=>'rename failed (permissions/lock)']; }
    $id = smpro_inv_manifest_add(['user'=>$r['user'],'domain'=>$r['domain'],'action'=>'disable_muplugin','from'=>$path,'to'=>$to,'hardened'=>$tImm ? 1 : 0]);
    smpro_audit('sitedoctor_fix', ['action'=>'disable_muplugin','target'=>basename($path),'user'=>$r['user'],'ok'=>true]);
    return ['ok'=>true,'msg'=>'Disabled self-healing mu-plugin ' . basename($path) . ' (it was reverting fixes / forcing the wrong RewriteBase). Reversible.','undo_id'=>$id];
}

/** RULE #1 fix: un-harden - clear immutability (chattr -i) + strip PHP Harden deny-exec blocks +
 *  restore owner-writable perms on ALL locked files/folders PHP Harden (or any other hardener) touched.
 *  Reads the PHP Harden manifest for the user so it unlocks the full set, not just the 5 paths the
 *  old scan checked. Also updates the manifest status to 'unlocked' so the PHP Harden page reflects it. */
function smpro_inv_fix_unharden($r) {
    $docroot = $r['docroot']; $user = $r['user'];
    if (strpos($docroot, '/home/') !== 0) return ['ok'=>false,'msg'=>'refused: docroot outside /home'];
    // Collect targets from the PHP Harden manifest (authoritative) + the broad scan (fallback).
    $items = smpro_inv_hardened_scan($docroot, $user);
    // Also sweep the PHP Harden manifest for deny-exec .htaccess guards in dirs (they may be inside
    // /home/$user but NOT under $docroot if the site has multiple docroots).
    $u = preg_replace('/[^a-zA-Z0-9._-]/', '', $user);
    $mp = SMPRO_VARLIB . '/php_harden/' . $u . '.json';
    $manifest = null;
    if (is_file($mp)) {
        $manifest = json_decode((string)@file_get_contents($mp), true);
        if (is_array($manifest)) {
            foreach ((array)($manifest['protected_files'] ?? []) as $f) {
                $p = (string)($f['path'] ?? ''); if ($p !== '' && is_file($p) && !isset($items[$p])) $items[$p] = 'php-harden';
            }
            foreach ((array)($manifest['deny_php_dirs'] ?? []) as $d) {
                $ht = rtrim((string)($d['htaccess'] ?? ''), '/');
                if ($ht === '') $ht = rtrim((string)($d['dir'] ?? ''), '/') . '/.htaccess';
                if ($ht !== '/.htaccess' && is_file($ht) && !isset($items[$ht])) $items[$ht] = 'php-harden exec-deny';
            }
        }
    }
    if (!$items) return ['ok'=>false,'msg'=>'No hardened/locked files found.'];
    $st = @stat($docroot); $uid = $st['uid'] ?? 0; $gid = $st['gid'] ?? 0; $n = 0; $names = [];
    $confine = [smpro_user_home($user)];
    foreach ($items as $p => $kind) {
        if (strpos($p, smpro_user_home($user) . '/') !== 0 && $p !== smpro_user_home($user)) continue;  // scope to this account
        // SECURITY (privesc): resolve to a realpath confined to the account home BEFORE any root mutation.
        // The manifest/scan paths ($p) are account-controlled; a symlinked DIRECTORY component (e.g. the
        // owner swaps wp-content/uploads -> /root after harden) is caught here (realpath escapes /home/$user
        // -> rejected), and a root-owned resolved file is refused outright - so the chattr/write/chown below
        // can never take ownership of, or write through, a root file. (No race needed for the original bug.)
        $safe = function_exists('smpro_path_safe') ? smpro_path_safe($p, $confine) : '';
        if ($safe === '' || $safe === false) continue;
        clearstatcache(true, $safe);
        if (@fileowner($safe) === 0) continue;   // never touch a root-owned file, even one that sits inside /home
        @shell_exec('chattr -i ' . escapeshellarg($safe) . ' 2>/dev/null');
        if ($kind === 'php-harden exec-deny' && is_file($safe) && !is_link($safe)) {
            // strip the deny-exec block so the .htaccess reverts to its original content
            $c = (string)@file_get_contents($safe);
            $new = preg_replace('/\n?# SMPRO_PH_DENY_EXEC_START.*?# SMPRO_PH_DENY_EXEC_END\s*/s', '', $c);
            // Keep the original before either branch - both destroy it: one rewrites the file, the other
            // deletes it outright. The delete is defensible (if the whole file was ours, removing it restores
            // the state before we touched anything) but only while that regex matches exactly what we wrote.
            // It is a CUSTOMER's .htaccess and there is no second copy of it anywhere on the server.
            smpro_inv_keep_original($safe, $c, 'php-harden exec-deny release');
            if (trim((string)$new) === '') { @unlink($safe); } else { @file_put_contents($safe, rtrim((string)$new) . "\n", LOCK_EX); }
        }
        clearstatcache(true, $safe);
        if (is_file($safe) && !is_link($safe)) { @chmod($safe, 0644); if ($uid) @chown($safe, $uid); if ($gid) @chgrp($safe, $gid); }   // never chown a symlinked target (privesc)
        elseif (is_dir($safe) && !is_link($safe)) { @chmod($safe, 0755); }
        $n++; if (count($names) < 8) $names[] = ltrim(str_replace(smpro_user_home($user), '', $safe), '/') . ' (' . $kind . ')';
    }
    // Update the manifest status so the PHP Harden page shows "Unlocked" immediately.
    if (is_array($manifest) && is_file($mp)) {
        $manifest['status'] = 'unlocked'; $manifest['unlock_until'] = ''; $manifest['updated_at'] = date('c');
        @file_put_contents($mp, json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX);
    }
    smpro_audit('sitedoctor_unharden', ['user'=>$user,'count'=>$n]);
    if (!$n) return ['ok'=>false,'msg'=>'Found locked items in manifest but chattr -i failed on all — check if already unlocked.'];
    return ['ok'=>true,'msg'=>'Un-hardened ' . $n . ' locked item(s) — files writable, deny-exec guards removed: ' . implode(', ', $names) . ($n > count($names) ? '…' : '')];
}

/**
 * Apply a safe, reversible fix. Clears hardening (immutable flag on the target + its parent dir)
 * BEFORE renaming, then re-hardens the parent - so a hardened plugin/theme can still be disabled.
 * Returns ['ok','msg','undo_id'?].
 */
function smpro_inv_fix($action, $target, $path) {
    $r = smpro_inv_resolve($target); if (!$r) return ['ok'=>false,'msg'=>'unresolved target'];
    $docroot = $r['docroot']; $user = $r['user'];
    if ($action === 'disable_muplugin') return smpro_inv_fix_muplugin($r, $path);
    if ($action === 'unharden') return smpro_inv_fix_unharden($r);
    if ($action === 'fix_wp_url') return smpro_inv_fix_wp_url($r);
    if ($action === 'fix_htaccess') return smpro_inv_fix_htaccess($r);
    if ($action === 'neutralize_https') return smpro_inv_fix_neutralize_https($r);
    if ($action === 'fix_htaccess_syntax') return smpro_inv_fix_htaccess_syntax($r);
    if ($action === 'disable_dropin') return smpro_inv_fix_disable_dropin($r, $path);
    if ($action === 'restart_phpfpm') return smpro_inv_fix_restart_phpfpm($r);
    if ($action === 'fix_permissions') return smpro_inv_fix_permissions($r);
    if ($action === 'clear_laravel_cache') return smpro_inv_fix_laravel_cache($r, $path);
    $path = rtrim((string)$path, '/');
    if (!smpro_inv_fix_allowed($docroot, $path)) return ['ok'=>false,'msg'=>'refused: target outside the account plugins/themes'];
    if (!is_dir($path)) return ['ok'=>false,'msg'=>'not found (already removed?): ' . basename($path)];
    if (!in_array($action, ['disable_plugin','disable_theme'], true)) return ['ok'=>false,'msg'=>'unknown fix'];
    $parent = dirname($path); if (is_link($parent) || is_link($path)) return ['ok'=>false,'msg'=>'refused: a symlink in the path'];
    $pImm = smpro_inv_imm($parent); $tImm = smpro_inv_imm($path);   // hardening detection
    if ($pImm) @shell_exec('chattr -i ' . escapeshellarg($parent) . ' 2>/dev/null');
    if ($tImm) @shell_exec('chattr -R -i ' . escapeshellarg($path) . ' 2>/dev/null');
    $to = $path . '.smpro-disabled-' . date('Ymd_His');
    $ok = @rename($path, $to);
    if ($pImm) @shell_exec('chattr +i ' . escapeshellarg($parent) . ' 2>/dev/null');   // re-harden parent
    if (!$ok) { if ($tImm) @shell_exec('chattr -R +i ' . escapeshellarg($path) . ' 2>/dev/null'); return ['ok'=>false,'msg'=>'rename failed even after clearing hardening — check ownership/permissions']; }
    $id = smpro_inv_manifest_add(['user'=>$user,'domain'=>$r['domain'],'action'=>$action,'from'=>$path,'to'=>$to,'hardened'=>$tImm ? 1 : 0]);
    smpro_audit('sitedoctor_fix', ['action'=>$action,'target'=>basename($path),'user'=>$user,'hardened'=>$tImm,'ok'=>true]);
    return ['ok'=>true,'msg'=>'Disabled ' . basename($path) . ($tImm ? ' (was hardened — unlocked, moved, re-locked safely)' : '') . ' — renamed, reversible. Site should load now.','undo_id'=>$id];
}

/**
 * SECURITY (root-context, shared-hosting): safely rewrite an account-owned .htaccess as root.
 * The account owner controls their /home dir, so a plain copy()/file_put_contents()/chown() on
 * docroot/.htaccess follows a symlink they plant (-> read /etc/shadow, or chown a root file to their
 * uid = privesc). This helper: (1) confines the target to /home/<user> and REJECTS a symlink via
 * smpro_path_safe (realpath), (2) writes the backup with O_EXCL (fopen 'xb') so a pre-planted symlink
 * at the backup path can't be followed, (3) writes the new content to an O_EXCL temp then ATOMIC-renames
 * over the target - rename replaces a symlink rather than following it, so the root write + chown can
 * never land outside the account even if the leaf was swapped after the check. Returns [ok, bak, err].
 */
function smpro_inv_ht_safe_write($ht, $docroot, $user, $new) {
    // Confine the PARENT dir (always exists, even when creating a NEW .htaccess) and reject a symlinked leaf.
    // Returns [ok, resolvedPath, backupPath, err].
    $roots  = $user !== '' ? [smpro_user_home($user)] : ['/home'];
    $parent = function_exists('smpro_path_safe') ? smpro_path_safe(dirname($ht), $roots) : '';
    $base   = basename($ht);
    if ($parent === '' || $base === '' || $base === '.' || $base === '..' || strpbrk($base, "/\0") !== false)
        return [false, '', '', 'refused: .htaccess resolves outside the account'];
    $ht = $parent . '/' . $base;
    if (is_link($ht)) return [false, '', '', 'refused: .htaccess is a symlink'];
    $imm = smpro_inv_imm($ht); if ($imm) @shell_exec('chattr -i ' . escapeshellarg($ht) . ' 2>/dev/null');
    $rnd = substr(bin2hex(@random_bytes(4) ?: pack('N', mt_rand())), 0, 8);
    $bak = '';
    if (is_file($ht)) {                                                // back up only an existing file
        $bak = $ht . '.smpro-bak-' . date('Ymd_His') . '-' . $rnd;
        $cur = @file_get_contents($ht);
        $bfh = ($cur !== false) ? @fopen($bak, 'xb') : false;         // O_CREAT|O_EXCL -> fails on a planted symlink/file
        if ($bfh === false) { if ($imm) @shell_exec('chattr +i ' . escapeshellarg($ht) . ' 2>/dev/null'); return [false, $ht, '', 'backup failed (permissions?)']; }
        @fwrite($bfh, $cur); @fclose($bfh); @chmod($bak, 0600);
    }
    $tmp = $ht . '.smpro-tmp-' . $rnd;
    $tfh = @fopen($tmp, 'xb');
    $ok  = $tfh !== false && @fwrite($tfh, $new) !== false;
    if ($tfh) @fclose($tfh);
    if ($ok) {
        @chmod($tmp, 0644);                                            // chown/chmod the file WE created (never a symlink)
        $st = @stat($parent); if ($st) { @chown($tmp, $st['uid']); @chgrp($tmp, $st['gid']); }
        $ok = @rename($tmp, $ht);                                      // atomic; replaces a swapped symlink instead of following it
    }
    if (!$ok) @unlink($tmp);
    if ($imm) @shell_exec('chattr +i ' . escapeshellarg($ht) . ' 2>/dev/null');
    if (!$ok) return [false, $ht, $bak, 'write failed'];
    return [true, $ht, $bak, ''];
}

/** Repair a broken .htaccess: back up the current one, write a clean default WordPress block with the
 *  correct RewriteBase for this (sub)site. Reversible (undo restores the backup). Hardening-aware. */
function smpro_inv_fix_htaccess($r) {
    $docroot = $r['docroot']; $user = (string)($r['user'] ?? '');
    if (strpos($docroot, '/home/') !== 0) return ['ok'=>false,'msg'=>'refused: docroot outside /home'];
    // Confine + reject symlink BEFORE reading (a symlinked .htaccess would otherwise leak /etc/shadow into the backup).
    // Resolve the DOCROOT dir (not the leaf) so a MISSING .htaccess can still be created - realpath() returns
    // false on a non-existent leaf, which used to make these repairs refuse a deleted .htaccess. The leaf's
    // own is_link guard (below) + smpro_inv_ht_safe_write's O_EXCL/rename keep the symlink-leak protection.
    if ($user === '' || !function_exists('smpro_path_safe')) return ['ok'=>false,'msg'=>'.htaccess repair unavailable (no account context)'];
    $dir = smpro_path_safe($docroot, [smpro_user_home($user)]);
    if ($dir === '' || $dir === false) return ['ok'=>false,'msg'=>'docroot is a symlink or resolves outside the account'];
    $ht = $dir . '/.htaccess';
    clearstatcache(true, $ht);
    if (is_link($ht)) return ['ok'=>false,'msg'=>'.htaccess is a symlink — refusing to touch it'];
    $base = '/' . ($r['subpath'] !== '' ? trim($r['subpath'], '/') . '/' : '');
    $full = (string)@file_get_contents($ht);
    // SURGICAL: replace ONLY the WordPress block - preserve the cPanel PHP handler, any security-plugin rules, etc.
    $wp = "# BEGIN WordPress\n<IfModule mod_rewrite.c>\nRewriteEngine On\nRewriteBase " . $base . "\nRewriteRule ^index\\.php$ - [L]\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteCond %{REQUEST_FILENAME} !-d\nRewriteRule . " . $base . "index.php [L]\n</IfModule>\n# END WordPress";
    if (preg_match('/# BEGIN WordPress.*?# END WordPress/s', $full)) { $new = preg_replace('/# BEGIN WordPress.*?# END WordPress/s', $wp, $full, 1); }
    else {
        // m3 FIX - only PREPEND a WordPress front-controller block on an ACTUAL WordPress site; on Laravel/Joomla/etc.
        // a WP rewrite block breaks routing. (Replacing an existing BEGIN WordPress block above is always safe.)
        $home = (string)($r['home'] ?? dirname($docroot));
        $isWp = is_file($docroot . '/wp-config.php') || is_file($home . '/wp-config.php')
             || is_file($docroot . '/wp-load.php')   || is_file($docroot . '/wp-login.php');
        if (!$isWp) return ['ok'=>false,'msg'=>'refused: not a WordPress site — will not inject a WordPress rewrite block (would break routing)'];
        $new = $wp . "\n\n" . $full;                                   // no WP block -> prepend it, keep the rest
    }
    if ($new === $full) return ['ok'=>false,'msg'=>'.htaccess already correct (RewriteBase ' . $base . ')'];
    $imm = smpro_inv_imm($ht);
    [$ok, $ht, $bak, $err] = smpro_inv_ht_safe_write($ht, $docroot, $user, $new);
    if (!$ok) return ['ok'=>false,'msg'=>$err];
    $id = smpro_inv_manifest_add(['user'=>$r['user'],'domain'=>$r['domain'],'action'=>'fix_htaccess','kind'=>'file','from'=>$ht,'backup'=>$bak,'hardened'=>$imm ? 1 : 0]);
    smpro_audit('sitedoctor_fix', ['action'=>'fix_htaccess','user'=>$r['user'],'ok'=>true]);
    return ['ok'=>true,'msg'=>'Fixed the WordPress rewrite block (RewriteBase ' . $base . '), preserving the PHP handler & security rules. Original backed up — reversible.','undo_id'=>$id];
}

/** Does .htaccess contain a force-HTTPS redirect (the classic http<->https loop source, esp. behind a proxy)? */
function smpro_inv_has_force_https($docroot) {
    $ht = $docroot . '/.htaccess'; if (!is_file($ht)) return false;
    $c = (string)@file_get_contents($ht);
    return (bool)(preg_match('/RewriteRule\b[^\n]*https:\/\/[^\n]*\[[^\]]*R/i', $c) || preg_match('/Redirect(Match)?\b[^\n]*\bhttps:\/\//i', $c));
}
/** Comment OUT a force-HTTPS redirect block in .htaccess - the real fix when the site is already https in the DB
 *  but still loops (a force-https rule + an SSL-terminating proxy bounce). Reversible (full backup). */
function smpro_inv_fix_neutralize_https($r) {
    $docroot = $r['docroot']; $user = (string)($r['user'] ?? '');
    if (strpos($docroot, '/home/') !== 0) return ['ok'=>false,'msg'=>'refused: docroot outside /home'];
    // Resolve the DOCROOT dir (not the leaf) so a MISSING .htaccess can still be created - realpath() returns
    // false on a non-existent leaf, which used to make these repairs refuse a deleted .htaccess. The leaf's
    // own is_link guard (below) + smpro_inv_ht_safe_write's O_EXCL/rename keep the symlink-leak protection.
    if ($user === '' || !function_exists('smpro_path_safe')) return ['ok'=>false,'msg'=>'.htaccess repair unavailable (no account context)'];
    $dir = smpro_path_safe($docroot, [smpro_user_home($user)]);
    if ($dir === '' || $dir === false) return ['ok'=>false,'msg'=>'docroot is a symlink or resolves outside the account'];
    $ht = $dir . '/.htaccess';
    clearstatcache(true, $ht);
    if (is_link($ht)) return ['ok'=>false,'msg'=>'.htaccess is a symlink — refusing to touch it'];
    $lines = explode("\n", (string)@file_get_contents($ht)); $out = []; $changed = 0;
    foreach ($lines as $ln) {
        if (preg_match('/^\s*RewriteRule\b.*https:\/\/.*\[[^\]]*R/i', $ln)) {
            for ($k = count($out) - 1; $k >= 0; $k--) {                 // comment the contiguous preceding RewriteCond lines
                if (trim($out[$k]) === '') continue;
                if (preg_match('/^\s*RewriteCond\b/i', $out[$k])) { if (strlen($out[$k]) && $out[$k][0] !== '#') { $out[$k] = '# [smpro] ' . $out[$k]; $changed++; } } else break;
            }
            $out[] = '# [smpro] ' . $ln; $changed++; continue;
        }
        // M4 FIX - only comment whole-HOST scheme forcers (source "/" or a root catch-all regex), NOT content
        // redirects like `Redirect 301 /promo https://host/sale`, which target a specific path and must be kept.
        if (stripos($ln, 'http://') === false
            && (preg_match('#^\s*Redirect\s+(?:permanent\s+|\d{3}\s+)?/\s+https://#i', $ln)
             || preg_match('#^\s*RedirectMatch\s+(?:permanent\s+|\d{3}\s+)?\^?/?\(\.\*\)\$?\s+https://#i', $ln))) {
            $out[] = '# [smpro] ' . $ln; $changed++; continue;
        }
        $out[] = $ln;
    }
    if (!$changed) return ['ok'=>false,'msg'=>'no force-HTTPS redirect rule found in .htaccess'];
    $imm = smpro_inv_imm($ht);
    [$ok, $ht, $bak, $err] = smpro_inv_ht_safe_write($ht, $docroot, $user, implode("\n", $out));
    if (!$ok) return ['ok'=>false,'msg'=>$err];
    $id = smpro_inv_manifest_add(['user'=>$r['user'],'domain'=>$r['domain'],'action'=>'neutralize_https','kind'=>'file','from'=>$ht,'backup'=>$bak,'hardened'=>$imm ? 1 : 0]);
    smpro_audit('sitedoctor_fix', ['action'=>'neutralize_https','user'=>$r['user'],'commented'=>$changed,'ok'=>true]);
    return ['ok'=>true,'msg'=>'Disabled ' . $changed . ' force-HTTPS redirect line(s) in .htaccess (the loop source). Backed up — reversible.','undo_id'=>$id];
}

/** Detect Apache/LiteSpeed .htaccess syntax error in server-log lines. */
function smpro_inv_htaccess_syntax_err(array $serverlogs) {
    foreach ($serverlogs as $l) { $ll = strtolower($l);
        if (strpos($ll, 'invalid command') !== false || strpos($ll, 'ah00526') !== false || strpos($ll, 'ah01626') !== false
            || strpos($ll, 'options not allowed') !== false
            || (strpos($ll, '.htaccess') !== false && (strpos($ll, 'syntax error') !== false || strpos($ll, 'bad ') !== false))) return true;
    }
    return false;
}

/** SCENARIO: .htaccess has an Apache-level syntax error (any platform) - back up the broken file and
 *  write a safe minimal stub so Apache stops rejecting every request. For WordPress, the stub includes
 *  the correct rewrite block; for all other platforms it is a blank placeholder. Reversible (undo -> backup). */
function smpro_inv_fix_htaccess_syntax($r) {
    $docroot = $r['docroot']; $user = (string)($r['user'] ?? '');
    if (strpos($docroot, '/home/') !== 0) return ['ok'=>false,'msg'=>'refused: docroot outside /home'];
    // Resolve the DOCROOT dir (not the leaf) so a MISSING .htaccess can still be created - realpath() returns
    // false on a non-existent leaf, which used to make these repairs refuse a deleted .htaccess. The leaf's
    // own is_link guard (below) + smpro_inv_ht_safe_write's O_EXCL/rename keep the symlink-leak protection.
    if ($user === '' || !function_exists('smpro_path_safe')) return ['ok'=>false,'msg'=>'.htaccess repair unavailable (no account context)'];
    $dir = smpro_path_safe($docroot, [smpro_user_home($user)]);
    if ($dir === '' || $dir === false) return ['ok'=>false,'msg'=>'docroot is a symlink or resolves outside the account'];
    $ht = $dir . '/.htaccess';
    clearstatcache(true, $ht);
    if (is_link($ht)) return ['ok'=>false,'msg'=>'.htaccess is a symlink — refusing to touch it'];
    $imm = smpro_inv_imm($ht);
    $isWp = is_file($docroot . '/wp-config.php') || is_file($docroot . '/wp-load.php');
    if ($isWp) {
        $base = '/' . ($r['subpath'] !== '' ? trim($r['subpath'], '/') . '/' : '');
        $stub = "# BEGIN WordPress\n<IfModule mod_rewrite.c>\nRewriteEngine On\nRewriteBase " . $base . "\nRewriteRule ^index\\.php$ - [L]\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteCond %{REQUEST_FILENAME} !-d\nRewriteRule . " . $base . "index.php [L]\n</IfModule>\n# END WordPress\n";
    } else {
        $stub = "# Original .htaccess had an Apache syntax error and was backed up (restore via Site Doctor → Undo, or add rules below).\n";
    }
    [$ok, $ht, $bak, $err] = smpro_inv_ht_safe_write($ht, $docroot, $user, $stub);
    if (!$ok) return ['ok'=>false,'msg'=>$err];
    $id = smpro_inv_manifest_add(['user'=>$r['user'],'domain'=>$r['domain'],'action'=>'fix_htaccess_syntax','kind'=>'file','from'=>$ht,'backup'=>$bak,'hardened'=>$imm ? 1 : 0]);
    smpro_audit('sitedoctor_fix', ['action'=>'fix_htaccess_syntax','user'=>$r['user'],'ok'=>true]);
    return ['ok'=>true,'msg'=>'Replaced the broken .htaccess (Apache syntax error) with a minimal working version. Original backed up — reversible.','undo_id'=>$id];
}

/** SCENARIO: a WordPress drop-in file (object-cache.php / db.php / advanced-cache.php) is crashing the site.
 *  Rename to disable - WordPress silently falls back to its native handler. Reversible. */
function smpro_inv_fix_disable_dropin($r, $path) {
    $docroot = $r['docroot']; $path = rtrim((string)$path, '/'); $base = basename($path);
    if (!in_array($base, ['object-cache.php','db.php','advanced-cache.php'], true)) return ['ok'=>false,'msg'=>'refused: ' . $base . ' is not a supported drop-in'];
    if (!preg_match('#^' . preg_quote($docroot, '#') . '/wp-content/' . preg_quote($base, '#') . '$#', $path)) return ['ok'=>false,'msg'=>'refused: path must be docroot/wp-content/' . $base];
    if (!is_file($path)) return ['ok'=>false,'msg'=>'not found: ' . $base];
    $imm = smpro_inv_imm($path); if ($imm) @shell_exec('chattr -i ' . escapeshellarg($path) . ' 2>/dev/null');
    $to = $path . '.smpro-disabled-' . date('Ymd_His');
    $ok = @rename($path, $to);
    if (!$ok) { if ($imm) @shell_exec('chattr +i ' . escapeshellarg($path) . ' 2>/dev/null'); return ['ok'=>false,'msg'=>'rename failed']; }
    $id = smpro_inv_manifest_add(['user'=>$r['user'],'domain'=>$r['domain'],'action'=>'disable_dropin','from'=>$path,'to'=>$to,'hardened'=>$imm ? 1 : 0]);
    smpro_audit('sitedoctor_fix', ['action'=>'disable_dropin','target'=>$base,'user'=>$r['user'],'ok'=>true]);
    return ['ok'=>true,'msg'=>'Disabled drop-in ' . $base . ' (renamed — reversible). WordPress will use its native fallback for DB / object-cache.','undo_id'=>$id];
}

/** SCENARIO: PHP-FPM pool is down (HTTP 502/503 + "connect() failed" in server logs).
 *  Restarts the PHP-FPM service. Uses the cPanel restartsrv script when available, then systemctl. */
function smpro_inv_fix_restart_phpfpm($r) {
    $phpver = preg_replace('/[^a-z0-9._-]/', '', strtolower((string)($r['phpver'] ?? '')));
    foreach (['/usr/local/cpanel/scripts/restartsrv_php_fpm','/scripts/restartsrv_php_fpm'] as $s) {
        if (is_executable($s)) {
            @shell_exec('timeout 90 ' . escapeshellarg($s) . ' 2>/dev/null');
            smpro_audit('sitedoctor_fix', ['action'=>'restart_phpfpm','user'=>$r['user'],'phpver'=>$phpver,'via'=>'restartsrv','ok'=>true]);
            return ['ok'=>true,'msg'=>'Restarted PHP-FPM' . ($phpver ? ' (' . $phpver . ')' : '') . ' via cPanel script. Give the site ~15 seconds to recover.'];
        }
    }
    $digits = preg_replace('/[^0-9]/', '', $phpver);
    $svc = $digits ? ('ea-php' . $digits . '-php-fpm') : '';
    if ($svc !== '') {
        @shell_exec('timeout 90 systemctl restart ' . escapeshellarg($svc) . ' 2>/dev/null');
        smpro_audit('sitedoctor_fix', ['action'=>'restart_phpfpm','user'=>$r['user'],'svc'=>$svc,'ok'=>true]);
        return ['ok'=>true,'msg'=>'Restarted ' . $svc . '. Give the site ~15 seconds.'];
    }
    return ['ok'=>false,'msg'=>'PHP-FPM restart script not found — restart manually via WHM → Service Manager → PHP-FPM'];
}

/** SCENARIO: "Permission denied" errors - wrong uid/mode on PHP files (common after a bad upload or chown mishap).
 *  Applies standard cPanel permissions (dirs=755, PHP files=644) and restores correct ownership. Safe: excludes cache/uploads. */
function smpro_inv_fix_permissions($r) {
    $docroot = $r['docroot'];
    if (strpos($docroot, '/home/') !== 0) return ['ok'=>false,'msg'=>'refused: docroot outside /home'];
    if (!is_dir($docroot)) return ['ok'=>false,'msg'=>'docroot not found'];
    $st = @stat($docroot); if (!$st) return ['ok'=>false,'msg'=>'cannot stat docroot'];
    $uid = (int)$st['uid']; $gid = (int)$st['gid'];
    if ($uid < 100) return ['ok'=>false,'msg'=>'refused: docroot uid=' . $uid . ' looks like a system account'];
    $excl = '\\( -path "*/wp-content/cache/*" -o -path "*/wp-content/uploads/*" \\) -prune -o';
    @shell_exec('timeout 90 nice -n 19 ionice -c3 find ' . escapeshellarg($docroot) . ' -maxdepth 8 ' . $excl . ' -type d -exec chmod 755 {} + 2>/dev/null');
    @shell_exec('timeout 90 nice -n 19 ionice -c3 find ' . escapeshellarg($docroot) . ' -maxdepth 8 ' . $excl . ' -type f \\( -name "*.php" -o -name ".htaccess" -o -name "*.ini" \\) -exec chmod 644 {} + 2>/dev/null');
    @shell_exec('timeout 90 nice -n 19 ionice -c3 chown -R ' . $uid . ':' . $gid . ' ' . escapeshellarg($docroot) . ' 2>/dev/null');
    smpro_audit('sitedoctor_fix', ['action'=>'fix_permissions','user'=>$r['user'],'uid'=>$uid,'ok'=>true]);
    return ['ok'=>true,'msg'=>'Reset PHP file permissions (dirs=755, PHP files=644) and ownership (uid=' . $uid . ') in the docroot. Excludes cache/uploads. This fixes "Permission denied" errors from wrong-uid or wrong-mode files.'];
}

/** SCENARIO: Stale Laravel bootstrap/config/routes cache after a deployment causes a PHP fatal on every request.
 *  Clears bootstrap/cache/*.php - Laravel regenerates them automatically on the next request. */
function smpro_inv_fix_laravel_cache($r, $cacheDir = '') {
    $docroot = $r['docroot'];
    if ($cacheDir === '') {
        $approot = is_file(dirname($docroot) . '/artisan') ? dirname($docroot) : $docroot;
        $cacheDir = $approot . '/bootstrap/cache';
    }
    $cacheDir = rtrim((string)$cacheDir, '/');
    if (strpos($cacheDir, '/home/') !== 0 || strpos($cacheDir, '..') !== false) return ['ok'=>false,'msg'=>'refused'];
    // The directory may come from the AI plan, whose evidence includes the account's own logs: confine it to THIS
    // account's home and to a real bootstrap/cache, whatever the plan says.
    $homeReal = function_exists('smpro_user_home') ? @realpath(smpro_user_home((string)$r['user'])) : false; $cacheReal = @realpath($cacheDir);
    if ($homeReal === false || $cacheReal === false || strpos($cacheReal, $homeReal . '/') !== 0 || basename($cacheReal) !== 'cache' || basename(dirname($cacheReal)) !== 'bootstrap') return ['ok'=>false,'msg'=>'refused: not a bootstrap/cache inside this account'];
    $cacheDir = $cacheReal;
    if (!is_dir($cacheDir)) return ['ok'=>false,'msg'=>'bootstrap/cache not found'];
    $files = glob($cacheDir . '/*.php') ?: [];
    if (!$files) return ['ok'=>false,'msg'=>'bootstrap/cache is already empty (no stale files)'];
    $bak = SMPRO_VARLIB . '/quarantine/sitedoctor/laravel_' . preg_replace('/[^a-z0-9_]/', '', strtolower($r['user'])) . '_' . date('Ymd_His');
    @mkdir($bak, 0700, true);
    $n = 0; foreach ($files as $f) { if (@copy($f, $bak . '/' . basename($f)) && @unlink($f)) $n++; }
    if (!$n) return ['ok'=>false,'msg'=>'Could not clear cache files (permissions?)'];
    smpro_audit('sitedoctor_fix', ['action'=>'clear_laravel_cache','user'=>$r['user'],'cleared'=>$n,'ok'=>true]);
    return ['ok'=>true,'msg'=>'Cleared ' . $n . ' stale Laravel cache file(s) from bootstrap/cache. Laravel will regenerate them on the next request.'];
}

/** Deterministic list of fixes the tool can apply right now (existing-culprit disables + .htaccess repair). */
function smpro_inv_fixes($res) {
    $docroot = $res['docroot']; $out = []; $seen = [];
    // FIRST: kill any self-healer mu-plugin that reverts our fixes (else everything below gets undone in ~1s).
    if (!empty($res['selfhealers'])) foreach ($res['selfhealers'] as $f => $tag) $out[] = ['action'=>'disable_muplugin','path'=>$f,'label'=>'Disable self-healing mu-plugin ' . basename($f),'why'=>'"' . $tag . '" keeps re-hardening files and forcing the wrong RewriteBase — it reverts every fix.'];
    if (!empty($res['hardened'])) $out[] = ['action'=>'unharden','path'=>$docroot,'label'=>'Un-harden ' . count($res['hardened']) . ' locked file(s)','why'=>'Hardened/locked files block WordPress from repairing the site (the repeated "not writable" errors).'];
    if (!empty($res['wp']['url_mismatch'])) $out[] = ['action'=>'fix_wp_url','path'=>$docroot,'label'=>'Fix WordPress site URL in DB','why'=>'siteurl/home in the database points to a path that does not exist on disk — this regenerates the wrong .htaccess RewriteBase (the recurring cause).'];
    foreach (($res['fatals'] ?? []) as $f) {
        if (empty($f['fix_target']) || empty($f['target_exists']) || !smpro_inv_fix_allowed($docroot, $f['fix_target'])) continue;
        if (isset($seen[$f['fix_target']])) continue; $seen[$f['fix_target']] = 1;
        $out[] = ['action'=>$f['fix_action'] ?: 'disable_plugin','path'=>$f['fix_target'],'label'=>'Disable ' . basename($f['fix_target']),'why'=>$f['kind']];
    }
    if (!empty($res['htaccess']['issues'])) $out[] = ['action'=>'fix_htaccess','path'=>$docroot . '/.htaccess','label'=>'Repair .htaccess','why'=>implode('; ', $res['htaccess']['issues'])];
    // REDIRECT LOOP (too many redirects): deterministic fixes, safest first. fix_wp_url (http->https) is the most
    // common cure; .htaccess repair clears a stray/duplicate redirect; an SSL-forcing plugin is the last resort.
    if (!empty($res['http']['loop'])) {
        $w = $res['wp'] ?? [];
        if (!empty($w['siteurl']) && stripos((string)$w['siteurl'], 'http://') === 0 && !smpro_inv_fixes_has($out, 'fix_wp_url'))
            $out[] = ['action'=>'fix_wp_url','path'=>$docroot,'label'=>'Set WordPress Site URL to HTTPS','why'=>'siteurl/home is http://'];
        // the real cure when the site is ALREADY https but still loops: an on-server force-HTTPS redirect rule.
        // M3 FIX - only offer this when the site is NOT behind a Cloudflare/CDN proxy AND the redirect chain shows a
        // real plaintext (http://) hop. A Cloudflare Flexible-SSL loop is OFF-server: removing the origin's HTTPS
        // enforcement would degrade security without owning the loop (the correct fix there is CF SSL mode = Full).
        $dnsProxied = !empty($res['dns']['proxied']);
        $httpHop    = stripos((string)($res['http']['chain'] ?? ''), 'http://') !== false;
        if (!$dnsProxied && $httpHop && smpro_inv_has_force_https($docroot))
            $out[] = ['action'=>'neutralize_https','path'=>$docroot . '/.htaccess','label'=>'Disable the force-HTTPS redirect in .htaccess','why'=>'on-server force-HTTPS rule loops with an SSL-terminating front-end (no CDN proxy detected)'];
        if (!smpro_inv_fixes_has($out, 'fix_htaccess'))
            $out[] = ['action'=>'fix_htaccess','path'=>$docroot . '/.htaccess','label'=>'Repair .htaccess rewrite block','why'=>'restore a clean WordPress rewrite block'];
        // LAST resort - an SSL-forcing plugin double-redirecting. Safe: "Fix it" applies fixes one-by-one and stops
        // at the first that works, so a plugin is disabled only if the URL/.htaccess fixes did not break the loop.
        foreach ((glob($docroot . '/wp-content/plugins/*{ssl,https,force-ssl}*', GLOB_BRACE) ?: []) as $pp) {
            if (is_dir($pp)) $out[] = ['action'=>'disable_plugin','path'=>$pp,'label'=>'Disable SSL plugin ' . basename($pp),'why'=>'an SSL-forcing plugin can double-redirect with the server HTTPS rule'];
        }
    }
    // HTACCESS SYNTAX ERROR (any platform): Apache/LiteSpeed rejects all requests when .htaccess has bad syntax.
    if (!smpro_inv_fixes_has($out, 'fix_htaccess') && !smpro_inv_fixes_has($out, 'fix_htaccess_syntax')
        && !empty($res['serverlogs']) && smpro_inv_htaccess_syntax_err($res['serverlogs']))
        $out[] = ['action'=>'fix_htaccess_syntax','path'=>$docroot,'label'=>'Replace broken .htaccess (Apache syntax error)','why'=>'Server logs show an Apache/LiteSpeed .htaccess syntax error — the server rejects every request until the file is replaced.'];
    // PHP-FPM POOL DOWN: HTTP 502/503 + connect-failure in server logs -> restart PHP-FPM.
    if (!smpro_inv_fixes_has($out, 'restart_phpfpm') && in_array((int)($res['http']['code'] ?? 0), [502,503], true)) {
        $hasFpmErr = false;
        foreach (($res['serverlogs'] ?? []) as $l) { $ll = strtolower((string)$l);
            if (strpos($ll, 'connect() failed') !== false || strpos($ll, 'backend unavailable') !== false
                || strpos($ll, 'php-fpm') !== false || strpos($ll, 'upstream timed out') !== false
                || strpos($ll, 'no live upstreams') !== false) { $hasFpmErr = true; break; }
        }
        if ($hasFpmErr) $out[] = ['action'=>'restart_phpfpm','path'=>$docroot,'label'=>'Restart PHP-FPM','why'=>'HTTP ' . $res['http']['code'] . ' + "connect() failed" in server logs — the PHP-FPM pool appears to be down.'];
    }
    // PERMISSION DENIED: wrong uid/mode on PHP files -> normalise 755/644 + ownership.
    if (!smpro_inv_fixes_has($out, 'fix_permissions')) {
        $hasPermErr = false;
        foreach (($res['logtail'] ?? []) as $l) { if (strpos(strtolower((string)$l), 'permission denied') !== false) { $hasPermErr = true; break; } }
        if (!$hasPermErr) foreach (($res['fatals'] ?? []) as $f) { if (strpos(strtolower((string)($f['msg'] ?? '')), 'permission denied') !== false) { $hasPermErr = true; break; } }
        if ($hasPermErr) $out[] = ['action'=>'fix_permissions','path'=>$docroot,'label'=>'Fix file permissions','why'=>'"Permission denied" in error_log — PHP cannot read/execute site files. Normalises dirs=755, PHP files=644, and ownership.'];
    }
    // WP DROP-IN CRASH: object-cache.php / db.php / advanced-cache.php throwing fatals.
    if (!smpro_inv_fixes_has($out, 'disable_dropin')) {
        foreach (['object-cache.php','db.php','advanced-cache.php'] as $di) {
            $dp = $docroot . '/wp-content/' . $di; if (!is_file($dp)) continue;
            $isCulprit = false;
            foreach (($res['fatals'] ?? []) as $f) { if (strpos((string)($f['msg'] ?? ''), $di) !== false) { $isCulprit = true; break; } }
            if (!$isCulprit) foreach (($res['logtail'] ?? []) as $l) { if (strpos((string)$l, $di) !== false) { $isCulprit = true; break; } }
            if ($isCulprit) { $out[] = ['action'=>'disable_dropin','path'=>$dp,'label'=>'Disable WordPress drop-in ' . $di,'why'=>$di . ' is throwing PHP fatal errors — disabling lets WordPress use its native fallback.']; break; }
        }
    }
    // LARAVEL STALE CACHE: stale bootstrap/cache/*.php after a deployment -> clear so Laravel regenerates.
    if (!smpro_inv_fixes_has($out, 'clear_laravel_cache') && !empty($res['fatals'])
        && strtolower((string)($res['detect']['platform'] ?? '')) === 'laravel') {
        $approot = is_file(dirname($docroot) . '/artisan') ? dirname($docroot) : $docroot;
        $cacheDir = $approot . '/bootstrap/cache';
        if (is_dir($cacheDir) && !empty(glob($cacheDir . '/*.php') ?: []))
            $out[] = ['action'=>'clear_laravel_cache','path'=>$cacheDir,'label'=>'Clear stale Laravel bootstrap cache','why'=>'Laravel bootstrap/cache/*.php files are stale after a deployment and causing PHP fatals. Laravel regenerates them automatically after clearing.'];
    }
    return $out;
}
/** Dedup helper: is an action already queued? */
function smpro_inv_fixes_has(array $out, $action) { foreach ($out as $o) if (($o['action'] ?? '') === $action) return true; return false; }
/** BASE RULE for Site Doctor: BEFORE any fix, clear immutable/hardening locks on the files a fix may need to
 *  edit - otherwise PHP Harden / emergency-harden / a security plugin's lock makes the write fail silently and
 *  the "fix" does nothing (exactly the reported symptom). Returns how many locked targets were cleared. */
function smpro_inv_unharden_base($res) {
    $d = rtrim((string)($res['docroot'] ?? ''), '/'); if ($d === '' || strpos($d, '/home/') !== 0) return 0;
    $home = (string)($res['home'] ?? dirname($d));
    $targets = [$d.'/.htaccess', $d.'/wp-config.php', $home.'/wp-config.php', $d.'/wp-content/.htaccess', $d.'/wp-content/uploads/.htaccess', $d.'/wp-content', $d.'/wp-content/plugins'];
    $n = 0;
    foreach ($targets as $t) { if (!is_link($t) && file_exists($t) && smpro_inv_imm($t)) { @shell_exec('chattr -i ' . escapeshellarg($t) . ' 2>/dev/null'); $n++; } }
    if ($n) smpro_audit('sitedoctor_unharden_base', ['cleared'=>$n,'docroot'=>$d]);
    return $n;
}

/** Backup + write a literal .htaccess content (AI-provided, validated). Reversible. Hardening-aware. */
function smpro_inv_write_htaccess($r, $content) {
    $docroot = $r['docroot'];
    if (strpos($docroot, '/home/') !== 0) return ['ok'=>false,'msg'=>'refused: docroot outside /home'];
    if (strlen($content) > 8192 || stripos($content, '<?php') !== false || preg_match('/[^\x09\x0a\x0d\x20-\x7e]/', $content)) return ['ok'=>false,'msg'=>'refused: .htaccess content failed safety validation'];
    $user = (string)($r['user'] ?? (preg_match('#^/home/([^/]+)#', $docroot, $mu) ? $mu[1] : ''));
    $imm  = smpro_inv_imm($docroot . '/.htaccess');
    [$ok, $ht, $bak, $err] = smpro_inv_ht_safe_write($docroot . '/.htaccess', $docroot, $user, rtrim($content, "\n") . "\n");   // symlink-safe
    if (!$ok) return ['ok'=>false,'msg'=>$err];
    $id = smpro_inv_manifest_add(['user'=>$r['user'],'domain'=>$r['domain'],'action'=>'write_htaccess','kind'=>'file','from'=>$ht,'backup'=>$bak,'hardened'=>$imm ? 1 : 0]);
    return ['ok'=>true,'msg'=>'Wrote a new .htaccess (original backed up).','undo_id'=>$id];
}

/**
 * SMART FIX: the AI reads the REAL evidence (incl. live .htaccess content) and returns a PLAN of safe,
 * reversible primitives; the engine validates each against an allowlist + docroot scope and executes it.
 * Ops the AI may use: unharden | disable {path} | write_htaccess {content}. Nothing else runs.
 */
function smpro_inv_ai_plan($target) {
    $res = smpro_inv_run($target); if (empty($res['ok'])) return ['ok'=>false,'msg'=>$res['msg'] ?? 'resolve failed'];
    if (!function_exists('smpro_ai_available') || !smpro_ai_available()) {
        // No AI -> fall back to the deterministic multi-fix.
        return smpro_inv_ai_fix($target);
    }
    $docroot = $res['docroot'];
    $htContent = ($res['htaccess']['head'] ?? '');
    $arExists = is_dir($docroot . '/ar') ? 'yes' : 'no';
    $ev = "FAILING SITE EVIDENCE\n";
    $ev .= "domain=" . ($res['domain'] ?: '?') . " account=" . $res['user'] . " php=" . ($res['phpver'] ?: '?') . " http=" . $res['http']['code'] . " docroot=" . $docroot . "\n";
    $ev .= "subdir '/ar' exists on disk: " . $arExists . "\n";
    if (!empty($res['detect'])) { $dt = $res['detect']; $ev .= "Platform: " . $dt['platform'] . ($dt['multisite'] ? " (multisite)" : "") . ($dt['multilingual'] ? "; multilingual via " . $dt['multilingual'] : "") . "; CMS installs on account=" . $dt['installs'] . "; domains=" . implode(',', array_slice($dt['sites'], 0, 6)) . "\n"; }
    if (!empty($res['selfhealers'])) { $ev .= "SELF-HEALER mu-plugins (REVERT fixes within ~1s — disable FIRST using the exact full_path values below):\n"; foreach ($res['selfhealers'] as $fullPath => $tag) $ev .= "  full_path=" . $fullPath . " tag=" . $tag . "\n"; }
    if (!empty($res['components'])) { $ev .= "Components throwing errors (type:name sev xN): "; foreach (array_slice($res['components'], 0, 10) as $c) $ev .= $c['type'] . ':' . $c['name'] . ' ' . $c['sev'] . 'x' . $c['count'] . '; '; $ev .= "\n"; }
    if (!empty($res['wp'])) { $w = $res['wp'];
        $ev .= "WordPress DB: " . ($w['db']['connected'] ? "connected" : ("NOT CONNECTED — " . $w['db']['error'])) . "; siteurl=" . ($w['siteurl'] ?: '?') . " home=" . ($w['home'] ?: '?') . " (correct should be " . $w['expected'] . ")" . (!empty($w['url_mismatch']) ? " [MISMATCH: URL path not on disk]" : "") . "\n";
    }
    if (!empty($res['dns'])) { $d = $res['dns']; $ev .= "DNS: domain resolves to " . (implode(',', $d['ips']) ?: 'NOTHING') . " (server IP " . ($d['server_ip'] ?: '?') . ") — state=" . $d['state'] . ($d['proxied'] ? " [behind Cloudflare/CDN]" : "") . "\n"; }
    if (!empty($res['http']['loop'])) {
        $ev .= "REDIRECT LOOP: entry HTTP " . (int)$res['http']['first'] . " -> too many redirects (" . (int)$res['http']['hops'] . "+ hops). Location chain: " . ($res['http']['chain'] ?: '(see headers)') . "\n";
        $ev .= "  Loop causes to weigh: siteurl/home http-vs-https mismatch; an SSL-forcing plugin (really-simple-ssl/wp-force-ssl) double-redirecting with a server HTTPS rule; a force-HTTPS block in .htaccess. If DNS is behind Cloudflare with Flexible SSL, the loop is fixed in Cloudflare (SSL=Full), NOT on the server.\n";
    }
    if (!empty($res['hardened'])) { $ev .= "\nLOCKED/HARDENED files (immutable or not-writable):\n"; foreach ($res['hardened'] as $p => $k) $ev .= "  " . $p . " (" . $k . ")\n"; }
    if (!empty($res['fatals'])) { $ev .= "\nPHP FATALS (newest first; [RESOLVED]=component already disabled):\n"; foreach ($res['fatals'] as $f) $ev .= "  " . ((!empty($f['fix_target']) && empty($f['target_exists'])) ? "[RESOLVED] " : "") . mb_substr($f['msg'], 0, 240) . "\n"; }
    if (!empty($res['logtail'])) { $ev .= "\nSITE error_log (recent):\n"; foreach (array_slice($res['logtail'], -10) as $l) $ev .= "  " . mb_substr($l, 0, 200) . "\n"; }
    if (!empty($res['serverlogs'])) { $ev .= "\nSERVER logs mentioning this site (apache/litespeed/suexec/domlog/modsec):\n"; foreach (array_slice($res['serverlogs'], 0, 24) as $l) $ev .= "  " . $l . "\n"; }
    $ev .= "\nCURRENT .htaccess (root of docroot):\n----\n" . $htContent . "\n----\n";
    $sys = "You are a senior cPanel/WordPress engineer FIXING a live site. Use ONLY these safe reversible operations and return STRICT JSON:\n"
         . "{\"cause\":\"one sentence\",\"steps\":[ {\"op\":\"disable_muplugin\",\"path\":\"<EXACT full_path from evidence>\"} | {\"op\":\"unharden\"} | {\"op\":\"fix_wp_url\"} | {\"op\":\"fix_htaccess\"} | {\"op\":\"fix_htaccess_syntax\"} | {\"op\":\"disable\",\"path\":\"<plugins|themes dir>\"} | {\"op\":\"disable_dropin\",\"path\":\"<full absolute wp-content/DROPIN.php>\"} | {\"op\":\"restart_phpfpm\"} | {\"op\":\"fix_permissions\"} | {\"op\":\"clear_laravel_cache\"} | {\"op\":\"write_htaccess\",\"content\":\"<full .htaccess>\"} ]}\n"
         . "Rules:\n"
         . "1. SELF-HEALER mu-plugins: disable_muplugin them FIRST using the EXACT full_path= value from the evidence — NEVER invent or abbreviate paths.\n"
         . "2. LOCKED FILES: use unharden if locked/hardened files are listed.\n"
         . "3. WP URL MISMATCH: use fix_wp_url first (corrects DB), then fix_htaccess.\n"
         . "4. HTACCESS SYNTAX ERROR (server logs show 'invalid command' / 'AH00526' / 'AH01626' / '.htaccess syntax error'): use fix_htaccess_syntax — it backs up the broken .htaccess and writes a safe minimal stub (correct WP rewrite block if WordPress, plain comment if not).\n"
         . "5. PHP-FPM DOWN (HTTP 502/503 + 'connect() failed' / 'backend unavailable' / 'upstream timed out' in server logs): use restart_phpfpm.\n"
         . "6. PERMISSION DENIED in error_log or fatals: use fix_permissions (normalises dirs=755, PHP files=644, ownership).\n"
         . "7. WP DROP-IN CRASH (object-cache.php / db.php / advanced-cache.php named in fatals/error_log): use disable_dropin with the FULL absolute path inside docroot/wp-content/.\n"
         . "8. LARAVEL STALE CACHE (platform=laravel + PHP fatals + bootstrap/cache/*.php exist): use clear_laravel_cache.\n"
         . "9. REDIRECT LOOP: if siteurl/home is http://, use fix_wp_url first; else fix_htaccess or write_htaccess; if behind Cloudflare, do NOT fix on-server — explain in cause.\n"
         . "10. Only disable a plugin/theme that STILL EXISTS (not RESOLVED) and is clearly the culprit. Prefer fix_htaccess over write_htaccess. Prefer fix_htaccess_syntax over write_htaccess for Apache syntax errors.\n"
         . "11. Do not invent file paths. Keep steps minimal. All paths must be inside " . $docroot . ".";
    $r = function_exists('smpro_ai_chat_json') ? smpro_ai_chat_json($sys, smpro_ai_redact($ev), ['max_tokens'=>900,'temperature'=>0.1,'context'=>'sitedoctor_plan']) : ['ok'=>false];
    $j = $r['data'] ?? (function_exists('smpro_ai_json') ? smpro_ai_json((string)($r['text'] ?? '')) : null);
    if (!is_array($j) || empty($j['steps']) || !is_array($j['steps'])) return smpro_inv_ai_verdict($res, 'The AI could not produce a safe fix plan — diagnosis instead:');
    $r2 = smpro_inv_resolve($target);
    $done = []; $any = false;
    foreach ($j['steps'] as $st) {
        $op = strtolower((string)($st['op'] ?? ''));
        if ($op === 'disable_muplugin') { $x = smpro_inv_fix_muplugin($r2, rtrim((string)($st['path'] ?? ''), '/')); }
        elseif ($op === 'unharden') { $x = smpro_inv_fix_unharden($r2); }
        elseif ($op === 'fix_wp_url') { $x = smpro_inv_fix_wp_url($r2); }
        elseif ($op === 'fix_htaccess') { $x = smpro_inv_fix_htaccess($r2); }
        elseif ($op === 'disable') {
            $p = rtrim((string)($st['path'] ?? ''), '/');
            if (!smpro_inv_fix_allowed($docroot, $p)) { $done[] = '✗ disable refused (path not in plugins/themes): ' . basename($p); continue; }
            $x = smpro_inv_fix(strpos($p, '/themes/') !== false ? 'disable_theme' : 'disable_plugin', $target, $p);
        }
        elseif ($op === 'fix_htaccess_syntax') { $x = smpro_inv_fix_htaccess_syntax($r2); }
        elseif ($op === 'disable_dropin') { $x = smpro_inv_fix_disable_dropin($r2, rtrim((string)($st['path'] ?? ''), '/')); }
        elseif ($op === 'restart_phpfpm') { $x = smpro_inv_fix_restart_phpfpm($r2); }
        elseif ($op === 'fix_permissions') { $x = smpro_inv_fix_permissions($r2); }
        elseif ($op === 'clear_laravel_cache') { $x = smpro_inv_fix_laravel_cache($r2, (string)($st['path'] ?? '')); }
        elseif ($op === 'write_htaccess') { $x = smpro_inv_write_htaccess($r2, (string)($st['content'] ?? '')); }
        else { $done[] = '✗ unknown op: ' . $op; continue; }
        if (!empty($x['ok'])) $any = true;
        $done[] = (!empty($x['ok']) ? '✓ ' : '✗ ') . $op . ': ' . ($x['msg'] ?? '');
    }
    // Re-check the site after applying the plan.
    // VERIFY with a real curl before claiming success (give the site a moment to settle).
    $after = 0; if (!empty($res['http']['url'])) { $after = (int)@shell_exec('timeout 15 curl -s -o /dev/null -w "%{http_code}" -A "SafetyMonitorPro/verify" ' . escapeshellarg($res['http']['url']) . ' 2>/dev/null'); }
    $upAfter = ($after >= 200 && $after < 400);
    smpro_audit('sitedoctor_ai_plan', ['user'=>$res['user'],'steps'=>count($j['steps']),'http_before'=>$res['http']['code'],'http_after'=>$after]);
    return ['ok'=>($any && $upAfter),'verified'=>$upAfter,'cause'=>(string)($j['cause'] ?? ''),'steps'=>$done,'http_before'=>$res['http']['code'],'http_after'=>$after,'provider'=>$r['provider'] ?? '',
            'msg'=>implode("\n", $done) . "\n\nVerified by curl — site status: HTTP " . $res['http']['code'] . " → " . ($after ?: '?') . ($upAfter ? ' ✅ working' : ' ⚠ still failing')];
}

/** "Fix it" button: DETERMINISTIC scenario fixes only (no AI). Applies the known fixes in order,
 *  re-checks the site, and flags escalate=true (-> hand off to AI Fix) if it's still failing. */
function smpro_inv_fixit($target) {
    $res = smpro_inv_run($target); if (empty($res['ok'])) return ['ok'=>false,'msg'=>$res['msg'] ?? 'resolve failed'];
    $fixes = $res['fixes'] ?? []; $steps = []; $any = false;
    // BASE RULE: clear hardening/locks on the files we may edit, FIRST (else a fix fails silently on a locked file).
    $unh = smpro_inv_unharden_base($res); if ($unh) $steps[] = '✓ Cleared the immutable flag on ' . $unh . ' protected file(s) first';
    // loop-aware verify: FOLLOW redirects so a still-looping site is correctly seen as not-fixed (310).
    $vurl = $res['http']['url'] ?? '';
    $check = function() use ($vurl) {
        if ($vurl === '') return 0;
        $w = (string)@shell_exec('timeout 25 curl -ksSL --max-redirs 10 -o /dev/null -w "%{http_code}|%{num_redirects}" -A "SafetyMonitorPro/verify" ' . escapeshellarg($vurl) . ' 2>/dev/null');
        $p = explode('|', trim($w)); $code = (int)($p[0] ?? 0); $hops = (int)($p[1] ?? 0);
        return ($hops >= 10) ? 310 : $code;                  // 310 = still looping
    };
    $after = 0;
    // Apply fixes INCREMENTALLY and stop at the first that brings the site up - least-disruptive fix wins, so a
    // security plugin is only disabled if the gentler URL/.htaccess fixes did not break the loop.
    foreach ($fixes as $f) {
        $x = smpro_inv_fix($f['action'], $target, $f['path']);
        $ok = !empty($x['ok']); if ($ok) $any = true;
        $steps[] = ($ok ? '✓ ' : '✗ ') . $f['label'] . ': ' . ($x['msg'] ?? '');
        if ($ok) { $after = $check(); if ($after >= 200 && $after < 400) break; }
    }
    if (!$after) $after = $check();
    $upAfter = ($after >= 200 && $after < 400);
    $escalate = !$upAfter;                                   // still failing -> AI Fix should take over
    if (!$fixes) $steps[] = 'No known deterministic scenario matched.';
    $afterTxt = ($after === 310) ? 'still looping' : ($after ?: '?');
    smpro_audit('sitedoctor_fixit', ['user'=>$res['user'],'applied'=>count($fixes),'http_before'=>$res['http']['code'],'http_after'=>$after]);
    return ['ok'=>$any && $upAfter,'steps'=>$steps,'http_before'=>$res['http']['code'],'http_after'=>($after === 310 ? 'loop' : $after),'escalate'=>$escalate,
            'platform'=>($res['detect']['platform'] ?? ''),
            'msg'=>implode("\n", $steps) . "\nSite: HTTP " . $res['http']['code'] . " → " . $afterTxt . ($escalate ? "\n\n⚠ Still failing — use 🤖 AI Fix to let the AI take over." : '')];
}

/** When there's no safe auto-fix, read the ACTUAL errors and return a precise AI diagnosis + steps. */
function smpro_inv_ai_verdict($res, $intro) {
    $up = ($res['http']['code'] >= 200 && $res['http']['code'] < 400);
    // Build evidence - annotate errors that are ALREADY RESOLVED (culprit component already disabled).
    $ev = "Site " . ($res['domain'] ?: $res['user']) . " currently returns HTTP " . $res['http']['code'] . ($up ? " (UP / responding)" : " (FAILING)") . ". Account " . $res['user'] . ", PHP " . ($res['phpver'] ?: '?') . ", docroot " . $res['docroot'] . ".\n";
    $liveCount = 0;
    if (!empty($res['fatals'])) { $ev .= "\nPHP fatal/parse errors (newest first):\n"; foreach ($res['fatals'] as $f) {
        $resolved = !empty($f['fix_target']) && empty($f['target_exists']);   // its plugin/theme is already disabled
        if (!$resolved) $liveCount++;
        $ev .= "- " . ($resolved ? "[ALREADY RESOLVED — component disabled] " : "") . mb_substr($f['msg'], 0, 260) . "\n";
    } }
    if (!empty($res['logtail'])) { $ev .= "\nRecent site error_log lines:\n"; foreach (array_slice($res['logtail'], -12) as $l) $ev .= "  " . mb_substr($l, 0, 220) . "\n"; }
    if (!empty($res['serverlogs'])) { $ev .= "\nServer logs mentioning this site (apache/litespeed/suexec/domlog/modsec):\n"; foreach (array_slice($res['serverlogs'], 0, 20) as $l) $ev .= "  " . $l . "\n"; }
    if (!empty($res['htaccess']['issues'])) $ev .= "\n.htaccess issues: " . implode('; ', $res['htaccess']['issues']) . "\n";
    if (!empty($res['recent'])) { $ev .= "\nRecently changed files:\n"; foreach (array_slice($res['recent'], 0, 8) as $c) $ev .= "  " . $c['time'] . " " . $c['path'] . "\n"; }
    // If the site is UP and nothing live remains, don't push a fix - say it's working.
    if ($up && $liveCount === 0 && empty($res['htaccess']['issues'])) {
        return ['ok'=>false,'no_fix'=>1,'msg'=>'Good news — the site is currently UP (HTTP ' . $res['http']['code'] . ').','verdict'=>'The errors in the log are historical / already resolved (the broken component was disabled). No action needed right now. If a specific page still fails, open it and re-run on that exact URL.'];
    }
    if (!function_exists('smpro_ai_available') || !smpro_ai_available()) {
        $top = null; foreach (($res['fatals'] ?? []) as $f) { if (empty($f['fix_target']) || !empty($f['target_exists'])) { $top = $f; break; } }
        return ['ok'=>false,'no_fix'=>1,'msg'=>$intro,'verdict'=>$top ? ("Current error:\n" . $top['msg'] . ($top['kind'] ? "\n\nLikely: " . $top['kind'] : '')) : 'No AI provider configured — review the errors above.'];
    }
    $sys = "You are a senior cPanel/WHM support engineer. The evidence shows the CURRENT HTTP status; errors tagged [ALREADY RESOLVED] are fixed already — DO NOT recommend them. If the site is UP and only resolved/warning errors remain, clearly say it is working now and no action is needed. Otherwise identify the single most likely CURRENT root cause (name the specific file/plugin/setting/DB issue), then give numbered concrete fix steps (safest first). Be specific and short.";
    $r = smpro_ai_chat($sys, function_exists('smpro_ai_redact') ? smpro_ai_redact($ev) : $ev, ['max_tokens'=>650,'context'=>'sitedoctor_diag']);
    if (empty($r['ok'])) { $top = $res['fatals'][0] ?? null; return ['ok'=>false,'no_fix'=>1,'msg'=>$intro,'verdict'=>$top ? ("Most recent error:\n" . $top['msg']) : ($r['error'] ?? 'AI request failed')]; }
    return ['ok'=>false,'no_fix'=>1,'msg'=>$intro,'verdict'=>$r['text'],'provider'=>$r['provider'] ?? ''];
}

/**
 * AI Fix: investigate, let the AI pick the single component to disable (constrained to plugins/themes
 * actually implicated in the evidence), then execute the SAME safe reversible fix. Returns the fix result.
 */
function smpro_inv_ai_fix($target) {
    $res = smpro_inv_run($target); if (empty($res['ok'])) return ['ok'=>false,'msg'=>$res['msg'] ?? 'resolve failed'];
    $docroot = $res['docroot'];
    // 1) Deterministic fixes - apply ALL of them in order (un-harden FIRST, then disable culprit, then .htaccess),
    //    all in one click, no AI needed. Each is reversible.
    $fixes = $res['fixes'] ?? [];
    if ($fixes) {
        $msgs = []; $any = false; $ids = [];
        $unh = smpro_inv_unharden_base($res); if ($unh) $msgs[] = '✓ Cleared the immutable flag on ' . $unh . ' protected file(s) first';
        foreach ($fixes as $f) {
            $fx = smpro_inv_fix($f['action'], $target, $f['path']);
            if (!empty($fx['ok'])) { $any = true; $msgs[] = '✓ ' . $fx['msg']; if (!empty($fx['undo_id'])) $ids[] = $fx['undo_id']; }
            else $msgs[] = '✗ ' . ($fx['msg'] ?? 'failed');
        }
        return ['ok'=>$any,'auto'=>1,'multi'=>count($fixes),'undo_ids'=>$ids,'msg'=>implode("\n", $msgs)];
    }
    // 2) Ambiguous: no clear deterministic culprit -> let the AI pick from recently-changed plugins/themes.
    if (!function_exists('smpro_ai_available') || !smpro_ai_available()) return ['ok'=>false,'msg'=>($res['status'] === 'up' ? 'Site is responding — nothing to fix.' : 'No clear automatic fix found. Check the diagnosis below.')];
    $cand = [];
    foreach (($res['recent'] ?? []) as $c) {
        if (!preg_match('#^(' . preg_quote($docroot, '#') . '/wp-content/(plugins|themes)/[A-Za-z0-9._-]+)(?:/|$)#', $c['path'], $m)) continue;
        $p = $m[1]; if (strpos($p, '.smpro-disabled') !== false || !is_dir($p)) continue;
        $act = strpos($p, '/themes/') !== false ? 'disable_theme' : 'disable_plugin'; $cand[$p] = $cand[$p] ?? $act;
    }
    if (!$cand) return smpro_inv_ai_verdict($res, ($res['status'] === 'up' ? 'Site is responding — no safe auto-fix to apply.' : 'No component to disable automatically — here is the AI diagnosis from the actual errors:'));
    $list = ''; $i = 0; $byKey = [];
    foreach ($cand as $p => $act) { $k = 'c' . $i++; $byKey[$k] = ['action'=>$act,'path'=>$p]; $list .= $k . ' | ' . $act . ' | ' . basename($p) . "\n"; }
    $ev = "Failing site " . $res['domain'] . " (HTTP " . $res['http']['code'] . "). Fatals:\n";
    foreach (($res['fatals'] ?? []) as $f) $ev .= "- " . mb_substr($f['msg'], 0, 240) . "\n";
    $ev .= "\nCandidate components to disable (id | action | name):\n" . $list;
    $sys = "You are a cPanel support engineer. From the candidate components, choose the SINGLE one most likely causing the failure, to disable (reversible). If none is clearly the cause, choose none. Respond ONLY strict JSON: {\"id\":\"<id or empty>\",\"why\":\"short\"}";
    $r = function_exists('smpro_ai_chat_json') ? smpro_ai_chat_json($sys, smpro_ai_redact($ev), ['max_tokens'=>300,'context'=>'sitedoctor_fix']) : ['ok'=>false];
    $j = $r['data'] ?? (function_exists('smpro_ai_json') ? smpro_ai_json((string)($r['text'] ?? '')) : null);
    $id = is_array($j) ? trim((string)($j['id'] ?? '')) : '';
    if ($id === '' || !isset($byKey[$id])) return ['ok'=>false,'msg'=>'AI did not pick a confident fix. Review manually.','why'=>is_array($j) ? ($j['why'] ?? '') : ''];
    $pick = $byKey[$id];
    $fx = smpro_inv_fix($pick['action'], $target, $pick['path']);
    $fx['why'] = is_array($j) ? ($j['why'] ?? '') : ''; $fx['picked'] = basename($pick['path']); $fx['provider'] = $r['provider'] ?? '';
    return $fx;
}

/** Undo a fix by manifest id (rename back). */
function smpro_inv_undo($id) {
    $m = smpro_inv_manifest_load(); $hit = null; foreach ($m as $i => $e) if (($e['id'] ?? '') === $id) { $hit = $i; break; }
    if ($hit === null) return ['ok'=>false,'msg'=>'undo entry not found'];
    $e = $m[$hit]; if (($e['status'] ?? '') !== 'applied') return ['ok'=>false,'msg'=>'already undone'];
    if (($e['kind'] ?? '') === 'wpurl') {   // restore WordPress siteurl/home in the DB
        $db = smpro_inv_wp_db($e['from']); if (!$db || !function_exists('mysqli_connect')) return ['ok'=>false,'msg'=>'cannot reach DB'];
        $host = $db['host']; $port = 0; $sock = null; if (strpos($host, ':') !== false) { [$host, $p] = explode(':', $host, 2); if (is_numeric($p)) $port = (int)$p; else $sock = $p; }
        $my = @mysqli_connect($host, $db['user'], $db['pass'], $db['name'], $port ?: 0, $sock); if (!$my) return ['ok'=>false,'msg'=>'DB connect failed'];
        $t = preg_replace('/[^A-Za-z0-9_]/', '', $db['prefix']) . 'options';
        foreach (($e['old'] ?? []) as $k => $v) { $ke = mysqli_real_escape_string($my, $k); $ve = mysqli_real_escape_string($my, $v); @mysqli_query($my, "UPDATE `$t` SET option_value='$ve' WHERE option_name='$ke'"); }
        @mysqli_close($my);
        $m[$hit]['status'] = 'undone'; $m[$hit]['undone_ts'] = time();
        @file_put_contents(smpro_inv_manifest_path(), json_encode($m, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), LOCK_EX);
        smpro_audit('sitedoctor_undo', ['kind'=>'wpurl','ok'=>true]);
        return ['ok'=>true,'msg'=>'Restored WordPress siteurl/home.'];
    }
    if (($e['kind'] ?? '') === 'created') {   // generated artifact (e.g. .webp) -> delete it
        $art = (string)($e['to'] ?? '');
        $dr = @realpath(dirname((string)($e['from'] ?? ''))); $ra = @realpath($art);
        if ($art === '' || $ra === false) { $m[$hit]['status'] = 'undone'; $m[$hit]['undone_ts'] = time(); @file_put_contents(smpro_inv_manifest_path(), json_encode($m, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), LOCK_EX); return ['ok'=>true,'msg'=>'Already removed.']; }
        if (strpos($ra, '/home/') !== 0) return ['ok'=>false,'msg'=>'refused: artifact outside /home'];
        @unlink($art);
        $m[$hit]['status'] = 'undone'; $m[$hit]['undone_ts'] = time();
        @file_put_contents(smpro_inv_manifest_path(), json_encode($m, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), LOCK_EX);
        smpro_audit('sitedoctor_undo', ['target'=>basename($art),'kind'=>'created','ok'=>true]);
        return ['ok'=>true,'msg'=>'Removed ' . basename($art) . '.'];
    }
    if (($e['kind'] ?? '') === 'file') {   // .htaccess repair / asset optimize -> restore the backed-up file
        if (empty($e['backup']) || !is_file($e['backup']) || is_link($e['backup'])) return ['ok'=>false,'msg'=>'backup file missing'];
        // SECURITY: never copy() back through a symlink the account may have planted at the original path
        // since the fix (-> arbitrary root write). Confine the parent to the account and write via O_EXCL temp+rename.
        $user = (string)($e['user'] ?? '');
        $from = (string)($e['from'] ?? '');
        $base = basename($from);
        $parent = function_exists('smpro_path_safe') ? smpro_path_safe(dirname($from), $user !== '' ? [smpro_user_home($user)] : ['/home']) : '';
        if ($parent === '' || $base === '' || $base === '.' || $base === '..' || strpbrk($base, "/\0") !== false) return ['ok'=>false,'msg'=>'refused: unsafe restore path'];
        $dest = $parent . '/' . $base;
        if (is_link($dest)) return ['ok'=>false,'msg'=>'refused: restore target is a symlink'];
        $content = @file_get_contents($e['backup']);
        if ($content === false) return ['ok'=>false,'msg'=>'cannot read backup'];
        $imm = smpro_inv_imm($dest); if ($imm) @shell_exec('chattr -i ' . escapeshellarg($dest) . ' 2>/dev/null');
        $tmp = $dest . '.smpro-rst-' . substr(bin2hex(@random_bytes(4) ?: pack('N', mt_rand())), 0, 8);
        $tfh = @fopen($tmp, 'xb'); $ok = $tfh !== false && @fwrite($tfh, $content) !== false; if ($tfh) @fclose($tfh);
        if ($ok) { @chmod($tmp, 0644); $st = @stat($parent); if ($st) { @chown($tmp, $st['uid']); @chgrp($tmp, $st['gid']); } $ok = @rename($tmp, $dest); }
        if (!$ok) @unlink($tmp);
        if ($imm) @shell_exec('chattr +i ' . escapeshellarg($dest) . ' 2>/dev/null');
        if (!$ok) return ['ok'=>false,'msg'=>'restore failed'];
        @unlink($e['backup']);
        $m[$hit]['status'] = 'undone'; $m[$hit]['undone_ts'] = time();
        @file_put_contents(smpro_inv_manifest_path(), json_encode($m, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), LOCK_EX);
        smpro_audit('sitedoctor_undo', ['target'=>basename($dest),'kind'=>'file','ok'=>true]);
        return ['ok'=>true,'msg'=>'Restored original ' . basename($dest) . '.'];
    }
    if (!file_exists($e['to'])) return ['ok'=>false,'msg'=>'backup item missing'];   // works for dir OR file rename
    if (is_dir($e['from'])) return ['ok'=>false,'msg'=>'original path already exists'];
    $parent = dirname($e['from']); $pImm = smpro_inv_imm($parent);
    if ($pImm) @shell_exec('chattr -i ' . escapeshellarg($parent) . ' 2>/dev/null');
    $ok = @rename($e['to'], $e['from']);
    if ($pImm) @shell_exec('chattr +i ' . escapeshellarg($parent) . ' 2>/dev/null');
    if (!$ok) return ['ok'=>false,'msg'=>'restore rename failed'];
    if (!empty($e['hardened'])) @shell_exec('chattr -R +i ' . escapeshellarg($e['from']) . ' 2>/dev/null');   // restore original hardening
    $m[$hit]['status'] = 'undone'; $m[$hit]['undone_ts'] = time();
    @file_put_contents(smpro_inv_manifest_path(), json_encode($m, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), LOCK_EX);
    smpro_audit('sitedoctor_undo', ['target'=>basename($e['from']),'ok'=>true]);
    return ['ok'=>true,'msg'=>'Restored ' . basename($e['from']) . '.'];
}


/**
 * Keep a copy of a customer file before this plugin rewrites or removes it.
 *
 * Standing rule: nothing on a customer site is cleaned, stripped or deleted without the original being kept
 * first. A cleaned file cannot be un-cleaned, and the file being changed is often also the evidence of how the
 * account was entered. On one server three shops had 12,590-byte index.php files that were malware with the
 * shop's own 453-byte bootstrap appended at the end - deleting them would have taken three shops down, and
 * stripping them without a copy would have destroyed the only record of what the attacker ran. A fourth site
 * had been truncated to zero bytes by someone else's cleanup with no backup anywhere; it served the panel's
 * default page while looking "up", and nothing on the server could reconstruct it.
 *
 * Writes under the plugin's own data dir, root-only, path preserved so its origin is obvious. Never fails the
 * caller - but a backup that could not be written is RECORDED, so a cleanup that ran without one is visible
 * afterwards instead of assumed.
 */
function smpro_inv_keep_original($path, $content = null, $why = '') {
    $path = (string)$path;
    if ($path === '') return '';
    if ($content === null) { if (!@is_file($path)) return ''; $content = (string)@file_get_contents($path); }
    // The mirrored sub-path is SANITISED, not pasted in. dirname() of a relative or non-POSIX path does not
    // begin with '/', which silently produced a malformed destination and no backup at all - the one
    // outcome this function exists to prevent.
    $rel = preg_replace('#[^A-Za-z0-9._/-]+#', '_', str_replace('\\', '/', dirname($path)));
    $rel = preg_replace('#/+#', '/', '/' . ltrim((string)$rel, '/'));
    $dir = SMPRO_VARLIB . '/originals/' . date('Ymd') . $rel;
    if (!@is_dir($dir) && !@mkdir($dir, 0700, true)) {
        if (function_exists('smpro_audit')) @smpro_audit('original_keep_failed', ['path' => $path, 'why' => $why]);
        return '';
    }
    $dest = $dir . '/' . date('His') . '_' . basename($path);
    if (@file_put_contents($dest, (string)$content, LOCK_EX) === false) {
        if (function_exists('smpro_audit')) @smpro_audit('original_keep_failed', ['path' => $path, 'why' => $why]);
        return '';
    }
    @chmod($dest, 0600);
    if (function_exists('smpro_audit')) {
        @smpro_audit('original_kept', ['path' => $path, 'kept' => $dest, 'bytes' => strlen((string)$content),
                                       'sha256' => hash('sha256', (string)$content), 'why' => $why]);
    }
    return $dest;
}
