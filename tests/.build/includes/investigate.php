<?php
/**
 * investigate.php — Site Doctor: diagnose WHY a domain/account is failing (500/blank/down)
 * and (optionally) apply a SAFE, REVERSIBLE fix. Read paths are root; every fix is backup-first
 * (rename, never delete), path-whitelisted to the account docroot, and recorded for one-click undo.
 * Used by the Forensics module's Site Doctor section.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

function smpro_inv_manifest_path() { return SMPRO_VARLIB . '/quarantine/sitedoctor/manifest.json'; }
function smpro_inv_manifest_load() { $f = smpro_inv_manifest_path(); $d = is_file($f) ? json_decode((string)@file_get_contents($f), true) : []; return is_array($d) ? $d : []; }
function smpro_inv_manifest_add($e) {
    $f = smpro_inv_manifest_path(); @is_dir(dirname($f)) || @mkdir(dirname($f), 0700, true);
    $m = smpro_inv_manifest_load(); $e['id'] = substr(md5(($e['to'] ?? '') . microtime(true)), 0, 12); $e['ts'] = time(); $e['status'] = 'applied'; $m[] = $e;
    @file_put_contents($f, json_encode(array_slice($m, -500), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), LOCK_EX); @chmod($f, 0600);
    return $e['id'];
}

/** Resolve a domain/URL (with optional subpath) OR account → [user, domain, docroot, home, phpver, subpath, url]. */
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
    if ($user === '' && preg_match('/^[a-z0-9_]+$/', $target) && is_dir('/home/' . $target)) $user = $target;
    if ($user === '') return null;
    $home = '/home/' . $user;
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
    if ($phpver === '') { foreach ([$docroot . '/.htaccess', '/home/' . $user . '/public_html/.htaccess'] as $hf) { if (is_file($hf) && preg_match('/x-httpd-(ea-php\d+|[a-z0-9]*php\d+)/i', (string)@shell_exec('grep -ai "x-httpd" ' . escapeshellarg($hf) . ' 2>/dev/null'), $hm)) { $phpver = $hm[1]; break; } } }
    if ($phpver === '') { $raw = (string)@shell_exec('timeout 8 grep -aoE "ea-php[0-9]+" /var/cpanel/userdata/' . escapeshellarg($user) . '/' . escapeshellarg($domain !== '' ? $domain : 'main') . ' 2>/dev/null | head -1'); if ($raw) $phpver = trim($raw); }
    $docroot = rtrim($docroot, '/');
    // A subpath is a REAL subdirectory install ONLY if the folder exists on disk; otherwise it's a
    // VIRTUAL route (e.g. /ar/ on a multilingual site handled by the root WordPress) → docroot stays root
    // and RewriteBase must be '/', NOT '/ar/'. (This was the bug that re-wrote the wrong base.)
    $diskSub = '';
    if ($sub !== '' && is_dir($docroot . '/' . $sub)) { $docroot .= '/' . $sub; $diskSub = $sub; }
    $url = $domain !== '' ? ('https://' . $domain . '/' . ($sub !== '' ? $sub . '/' : '')) : '';
    return ['user'=>$user,'domain'=>$domain,'docroot'=>$docroot,'home'=>$home,'phpver'=>$phpver,'subpath'=>$diskSub,'urlpath'=>$sub,'url'=>$url];
}
/** Parse account disk usage into clean stats. */
function smpro_inv_disk($user) {
    $raw = (string)@shell_exec('timeout 12 /usr/local/cpanel/bin/whmapi1 get_disk_usage user=' . escapeshellarg($user) . ' 2>/dev/null');
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
    $pat = $d !== '' ? ($d . '|/home/' . $u . '/|cwd=/home/' . $u) : ('/home/' . $u . '/');
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
/** STEP 0 — validate the domain itself: does public DNS resolve it, to which IP, and does it point HERE?
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
/** HTTP probe that FOLLOWS redirects and detects loops — so a 301/302 (and a redirect loop) is diagnosed,
 *  not mistaken for "up". Returns first code, final code, hop count, final URL, and whether it looped. */
function smpro_inv_http($url) {
    $out = ['code'=>0,'url'=>$url,'first'=>0,'final'=>0,'hops'=>0,'final_url'=>'','loop'=>false,'chain'=>''];
    if ($url === '') return $out;
    $A = '-A ' . escapeshellarg('SafetyMonitorPro/investigate') . ' --connect-timeout 10 -m 20 -ksS';
    // (1) first response WITHOUT following — reveals a 301/302 at the entry
    $first = (int)trim((string)@shell_exec('timeout 22 curl ' . $A . ' -o /dev/null -w "%{http_code}" ' . escapeshellarg($url) . ' 2>/dev/null'));
    // (2) follow up to 10 hops — final code + hop count + effective URL
    $w = (string)@shell_exec('timeout 25 curl ' . $A . ' -L --max-redirs 10 -o /dev/null -w "%{http_code}|%{num_redirects}|%{url_effective}" ' . escapeshellarg($url) . ' 2>/dev/null');
    $p = explode('|', trim($w));
    $final = (int)($p[0] ?? 0); $hops = (int)($p[1] ?? 0); $furl = (string)($p[2] ?? '');
    $loop = ($hops >= 10) || ($final === 0 && $hops > 0);     // hit the hop cap (or curl aborted mid-redirect) = loop
    $out['first'] = $first; $out['final'] = $final; $out['hops'] = $hops; $out['final_url'] = $furl; $out['loop'] = $loop;
    $out['code'] = $loop ? 310 : ($final ?: $first);          // 310 = synthetic "redirect loop"
    // capture the Location chain (reveals the loop pattern, e.g. https→http→https) — diagnostic + AI evidence
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
    // STEP 0: domain/DNS validity (first troubleshooting step — is the domain even pointed here?)
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
    // Last raw log lines (warnings/notices too) — shown when there is no clear fatal, so the tool is never a dead end.
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
    // STEP-0 gates: a domain that doesn't resolve here, or a redirect loop, is the real cause — surface it first.
    $dnsBad = $dns && in_array($dns['state'], ['nxdomain','elsewhere'], true);
    if     ($dnsBad)                 $status = 'dns';            // domain not pointed here → nothing else matters
    elseif ($http['loop'])           $status = 'redirect_loop';  // 301/302 loop (e.g. http↔https, really-simple-ssl, wrong siteurl)
    elseif ($up && !$live)           $status = 'up';            // responding + no actionable culprit
    elseif ($live)                   $status = 'down_actionable';// a fixable culprit is present
    elseif ($http['final'] >= 400 || $http['first'] >= 400) $status = 'down';
    else $status = 'unknown';
    $staleFixed = (!$up && !$live && $fatals && empty($fatals[0]['target_exists']) && !empty($fatals[0]['fix_target']));
    $result = ['ok'=>true,'user'=>$r['user'],'domain'=>$domain,'docroot'=>$docroot,'phpver'=>$r['phpver'],'subpath'=>$r['subpath'] ?? '',
            'dns'=>$dns,
            'http'=>$http,'status'=>$status,'fatals'=>$fatals,'live_cause'=>$live,'recent'=>smpro_inv_recent($docroot),
            'htaccess'=>$ht,'logtail'=>$logtail,'serverlogs'=>smpro_inv_serverlogs($r),'wp'=>smpro_inv_wp($docroot, $domain),'disk'=>smpro_inv_disk($r['user']),'hardened'=>smpro_inv_hardened_scan($docroot),
            'undo'=>array_values(array_filter(smpro_inv_manifest_load(), fn($e) => ($e['status'] ?? '') === 'applied' && ($e['user'] ?? '') === $r['user']))];
    $result['detect'] = smpro_inv_detect($docroot, $home);   // platform / topology / multilingual (step 1)
    $result['selfhealers'] = smpro_inv_selfhealers($docroot); // mu-plugins that revert fixes
    $result['components'] = smpro_inv_components($docroot);   // theme/plugin health
    $result['logsize'] = is_file($docroot . '/error_log') ? (int)@filesize($docroot . '/error_log') : 0;
    $result['fixes'] = smpro_inv_fixes($result);   // everything the button can apply on its own (un-harden first)
    return $result;
}

/** Is a path immutable (chattr +i) — i.e. hardened so it can't be renamed/edited? */
function smpro_inv_imm($p) {
    $r = (string)@shell_exec('lsattr -d ' . escapeshellarg($p) . ' 2>/dev/null');
    $tok = trim((string)strtok(trim($r), " \t"));
    return $tok !== '' && strpos($tok, 'i') !== false;
}
/** Validate that a fix target is inside the account docroot's wp-content/(plugins|themes). */
function smpro_inv_fix_allowed($docroot, $path) {
    return (bool)preg_match('#^' . preg_quote($docroot, '#') . '/wp-content/(plugins|themes)/[A-Za-z0-9._-]+$#', $path);
}

/** Find hardened/locked items in the docroot that block the site from self-repairing:
 *  immutable (chattr +i) files/dirs, and .htaccess files the SITE user can't write (mode missing owner-write). */
function smpro_inv_hardened_scan($docroot) {
    if (!is_dir($docroot) || strpos($docroot, '/home/') !== 0) return [];
    $out = [];
    // immutable (chattr +i) — the hard lock
    $raw = (string)@shell_exec('timeout 15 nice -n 19 lsattr -Rd ' . escapeshellarg($docroot) . ' ' . escapeshellarg($docroot) . '/.htaccess ' . escapeshellarg($docroot) . '/wp-content ' . escapeshellarg($docroot) . '/wp-content/uploads ' . escapeshellarg($docroot) . '/wp-content/uploads/.htaccess 2>/dev/null');
    foreach (explode("\n", trim($raw)) as $l) { if (preg_match('/^(\S+)\s+(\/\S+)$/', $l, $m) && strpos($m[1], 'i') !== false) $out[$m[2]] = 'immutable'; }
    // .htaccess the SITE user can't write: mode lacks owner-write OR owned by a different uid (e.g. root) —
    // this is exactly the "uploads/.htaccess exists but is not writable" wp-efadh loop.
    $own = @stat($docroot); $ownUid = $own['uid'] ?? -1;
    $raw2 = (string)@shell_exec('timeout 15 nice -n 19 find ' . escapeshellarg($docroot) . ' -maxdepth 3 -name .htaccess -printf "%U|%m|%p\n" 2>/dev/null | head -40');
    foreach (explode("\n", trim($raw2)) as $l) { $parts = explode('|', $l, 3); if (count($parts) < 3) continue; [$uid, $mode, $p] = $parts;
        if ($ownUid >= 0 && (int)$uid !== $ownUid) $out[$p] = $out[$p] ?? 'wrong-owner';
        elseif (!((int)octdec($mode) & 0200)) $out[$p] = $out[$p] ?? 'not-writable';
    }
    return $out;
}

/** Detect "self-healer" mu-plugins that keep reverting our fixes (re-hardening / forcing RewriteBase),
 *  by matching tags in the site error_log (e.g. "[wp-efadh] ... auto-fixed (RewriteBase") to mu-plugin files. */
function smpro_inv_selfhealers($docroot) {
    $out = []; $log = $docroot . '/error_log'; $mu = $docroot . '/wp-content/mu-plugins';
    if (!is_file($log) || !is_dir($mu)) return $out;
    $raw = (string)@shell_exec('timeout 8 grep -aoE ' . escapeshellarg('\[[A-Za-z0-9_-]+\][^]]*(RewriteBase|hardened|SELF-HEAL|auto-fixed)') . ' ' . escapeshellarg($log) . ' 2>/dev/null | tail -30');
    $tags = [];
    foreach (explode("\n", trim($raw)) as $l) if (preg_match('/^\[([A-Za-z0-9_-]+)\]/', trim($l), $m)) $tags[strtolower($m[1])] = 1;
    if (!$tags) return $out;
    foreach (glob($mu . '/*.php') ?: [] as $f) {
        $base = strtolower(basename($f)); $c = strtolower((string)@shell_exec('head -c 4000 ' . escapeshellarg($f) . ' 2>/dev/null'));
        foreach (array_keys($tags) as $tag) {
            $alnum = preg_replace('/[^a-z0-9]/', '', $tag);
            if ($alnum !== '' && (strpos(preg_replace('/[^a-z0-9]/', '', $base), $alnum) !== false || strpos($c, $tag) !== false)) { $out[$f] = $tag; break; }
        }
    }
    return $out;
}

/** Disable a self-healing mu-plugin file (rename .php → .disabled). Reversible. Hardening-aware. */
function smpro_inv_fix_muplugin($r, $path) {
    $docroot = $r['docroot']; $path = rtrim((string)$path, '/');
    if (!preg_match('#^' . preg_quote($docroot, '#') . '/wp-content/mu-plugins/[A-Za-z0-9._-]+\.php$#', $path)) return ['ok'=>false,'msg'=>'refused: not a mu-plugin file'];
    if (!is_file($path)) return ['ok'=>false,'msg'=>'not found (already disabled?): ' . basename($path)];
    $parent = dirname($path); $pImm = smpro_inv_imm($parent); $tImm = smpro_inv_imm($path);
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

/** RULE #1 fix: un-harden — clear immutability + restore owner-writable perms on locked files/folders,
 *  so WordPress / wp-efadh can fix the site instead of looping on "not writable". Scoped to the docroot. */
function smpro_inv_fix_unharden($r) {
    $docroot = $r['docroot']; if (strpos($docroot, '/home/') !== 0) return ['ok'=>false,'msg'=>'refused: docroot outside /home'];
    $items = smpro_inv_hardened_scan($docroot); if (!$items) return ['ok'=>false,'msg'=>'No hardened/locked files found.'];
    $st = @stat($docroot); $uid = $st['uid'] ?? 0; $gid = $st['gid'] ?? 0; $n = 0; $names = [];
    foreach ($items as $p => $kind) {
        if (strpos($p, $docroot) !== 0) continue;                       // never act outside the docroot
        @shell_exec('chattr -i ' . escapeshellarg($p) . ' 2>/dev/null');
        if (is_dir($p)) @chmod($p, 0755); elseif (is_file($p)) @chmod($p, 0644);
        if ($uid) @chown($p, $uid); if ($gid) @chgrp($p, $gid);
        $n++; if (count($names) < 6) $names[] = str_replace($docroot . '/', '', $p) . ' (' . $kind . ')';
    }
    smpro_audit('sitedoctor_unharden', ['user'=>$r['user'],'count'=>$n]);
    return ['ok'=>true,'msg'=>'Un-hardened ' . $n . ' locked item(s) — now writable so the site can self-repair: ' . implode(', ', $names) . ($n > count($names) ? '…' : '')];
}

/**
 * Apply a safe, reversible fix. Clears hardening (immutable flag on the target + its parent dir)
 * BEFORE renaming, then re-hardens the parent — so a hardened plugin/theme can still be disabled.
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
    $path = rtrim((string)$path, '/');
    if (!smpro_inv_fix_allowed($docroot, $path)) return ['ok'=>false,'msg'=>'refused: target outside the account plugins/themes'];
    if (!is_dir($path)) return ['ok'=>false,'msg'=>'not found (already removed?): ' . basename($path)];
    if (!in_array($action, ['disable_plugin','disable_theme'], true)) return ['ok'=>false,'msg'=>'unknown fix'];
    $parent = dirname($path);
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

/** Repair a broken .htaccess: back up the current one, write a clean default WordPress block with the
 *  correct RewriteBase for this (sub)site. Reversible (undo restores the backup). Hardening-aware. */
function smpro_inv_fix_htaccess($r) {
    $docroot = $r['docroot']; $ht = $docroot . '/.htaccess';
    if (strpos($docroot, '/home/') !== 0) return ['ok'=>false,'msg'=>'refused: docroot outside /home'];
    if (!is_file($ht)) return ['ok'=>false,'msg'=>'.htaccess not found'];
    $base = '/' . ($r['subpath'] !== '' ? trim($r['subpath'], '/') . '/' : '');
    $full = (string)@file_get_contents($ht);
    // SURGICAL: replace ONLY the WordPress block — preserve the cPanel PHP handler, Wp-Efadh security, etc.
    $wp = "# BEGIN WordPress\n<IfModule mod_rewrite.c>\nRewriteEngine On\nRewriteBase " . $base . "\nRewriteRule ^index\\.php$ - [L]\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteCond %{REQUEST_FILENAME} !-d\nRewriteRule . " . $base . "index.php [L]\n</IfModule>\n# END WordPress";
    if (preg_match('/# BEGIN WordPress.*?# END WordPress/s', $full)) { $new = preg_replace('/# BEGIN WordPress.*?# END WordPress/s', $wp, $full, 1); }
    else {
        // m3 FIX — only PREPEND a WordPress front-controller block on an ACTUAL WordPress site; on Laravel/Joomla/etc.
        // a WP rewrite block breaks routing. (Replacing an existing BEGIN WordPress block above is always safe.)
        $home = (string)($r['home'] ?? dirname($docroot));
        $isWp = is_file($docroot . '/wp-config.php') || is_file($home . '/wp-config.php')
             || is_file($docroot . '/wp-load.php')   || is_file($docroot . '/wp-login.php');
        if (!$isWp) return ['ok'=>false,'msg'=>'refused: not a WordPress site — will not inject a WordPress rewrite block (would break routing)'];
        $new = $wp . "\n\n" . $full;                                   // no WP block → prepend it, keep the rest
    }
    if ($new === $full) return ['ok'=>false,'msg'=>'.htaccess already correct (RewriteBase ' . $base . ')'];
    $imm = smpro_inv_imm($ht); if ($imm) @shell_exec('chattr -i ' . escapeshellarg($ht) . ' 2>/dev/null');
    $bak = $ht . '.smpro-bak-' . date('Ymd_His');
    if (!@copy($ht, $bak)) { if ($imm) @shell_exec('chattr +i ' . escapeshellarg($ht) . ' 2>/dev/null'); return ['ok'=>false,'msg'=>'backup failed (permissions?)']; }
    $ok = @file_put_contents($ht, $new) !== false;
    if ($ok) { @chmod($ht, 0644); $st = @stat($docroot); if ($st) { @chown($ht, $st['uid']); @chgrp($ht, $st['gid']); } }
    if ($imm) @shell_exec('chattr +i ' . escapeshellarg($ht) . ' 2>/dev/null');
    if (!$ok) return ['ok'=>false,'msg'=>'write failed'];
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
/** Comment OUT a force-HTTPS redirect block in .htaccess — the real fix when the site is already https in the DB
 *  but still loops (a force-https rule + an SSL-terminating proxy bounce). Reversible (full backup). */
function smpro_inv_fix_neutralize_https($r) {
    $docroot = $r['docroot']; $ht = $docroot . '/.htaccess';
    if (strpos($docroot, '/home/') !== 0) return ['ok'=>false,'msg'=>'refused: docroot outside /home'];
    if (!is_file($ht)) return ['ok'=>false,'msg'=>'.htaccess not found'];
    $lines = explode("\n", (string)@file_get_contents($ht)); $out = []; $changed = 0;
    foreach ($lines as $ln) {
        if (preg_match('/^\s*RewriteRule\b.*https:\/\/.*\[[^\]]*R/i', $ln)) {
            for ($k = count($out) - 1; $k >= 0; $k--) {                 // comment the contiguous preceding RewriteCond lines
                if (trim($out[$k]) === '') continue;
                if (preg_match('/^\s*RewriteCond\b/i', $out[$k])) { if (strlen($out[$k]) && $out[$k][0] !== '#') { $out[$k] = '# [smpro] ' . $out[$k]; $changed++; } } else break;
            }
            $out[] = '# [smpro] ' . $ln; $changed++; continue;
        }
        // M4 FIX — only comment whole-HOST scheme forcers (source "/" or a root catch-all regex), NOT content
        // redirects like `Redirect 301 /promo https://host/sale`, which target a specific path and must be kept.
        if (stripos($ln, 'http://') === false
            && (preg_match('#^\s*Redirect\s+(?:permanent\s+|\d{3}\s+)?/\s+https://#i', $ln)
             || preg_match('#^\s*RedirectMatch\s+(?:permanent\s+|\d{3}\s+)?\^?/?\(\.\*\)\$?\s+https://#i', $ln))) {
            $out[] = '# [smpro] ' . $ln; $changed++; continue;
        }
        $out[] = $ln;
    }
    if (!$changed) return ['ok'=>false,'msg'=>'no force-HTTPS redirect rule found in .htaccess'];
    $imm = smpro_inv_imm($ht); if ($imm) @shell_exec('chattr -i ' . escapeshellarg($ht) . ' 2>/dev/null');
    $bak = $ht . '.smpro-bak-' . date('Ymd_His');
    if (!@copy($ht, $bak)) { if ($imm) @shell_exec('chattr +i ' . escapeshellarg($ht) . ' 2>/dev/null'); return ['ok'=>false,'msg'=>'backup failed']; }
    $ok = @file_put_contents($ht, implode("\n", $out)) !== false;
    if ($ok) { @chmod($ht, 0644); $st = @stat($docroot); if ($st) { @chown($ht, $st['uid']); @chgrp($ht, $st['gid']); } }
    if ($imm) @shell_exec('chattr +i ' . escapeshellarg($ht) . ' 2>/dev/null');
    if (!$ok) return ['ok'=>false,'msg'=>'write failed'];
    $id = smpro_inv_manifest_add(['user'=>$r['user'],'domain'=>$r['domain'],'action'=>'neutralize_https','kind'=>'file','from'=>$ht,'backup'=>$bak,'hardened'=>$imm ? 1 : 0]);
    smpro_audit('sitedoctor_fix', ['action'=>'neutralize_https','user'=>$r['user'],'commented'=>$changed,'ok'=>true]);
    return ['ok'=>true,'msg'=>'Disabled ' . $changed . ' force-HTTPS redirect line(s) in .htaccess (the loop source). Backed up — reversible.','undo_id'=>$id];
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
    // REDIRECT LOOP (too many redirects): deterministic fixes, safest first. fix_wp_url (http→https) is the most
    // common cure; .htaccess repair clears a stray/duplicate redirect; an SSL-forcing plugin is the last resort.
    if (!empty($res['http']['loop'])) {
        $w = $res['wp'] ?? [];
        if (!empty($w['siteurl']) && stripos((string)$w['siteurl'], 'http://') === 0 && !smpro_inv_fixes_has($out, 'fix_wp_url'))
            $out[] = ['action'=>'fix_wp_url','path'=>$docroot,'label'=>'Set WordPress Site URL to HTTPS','why'=>'siteurl/home is http://'];
        // the real cure when the site is ALREADY https but still loops: an on-server force-HTTPS redirect rule.
        // M3 FIX — only offer this when the site is NOT behind a Cloudflare/CDN proxy AND the redirect chain shows a
        // real plaintext (http://) hop. A Cloudflare Flexible-SSL loop is OFF-server: removing the origin's HTTPS
        // enforcement would degrade security without owning the loop (the correct fix there is CF SSL mode = Full).
        $dnsProxied = !empty($res['dns']['proxied']);
        $httpHop    = stripos((string)($res['http']['chain'] ?? ''), 'http://') !== false;
        if (!$dnsProxied && $httpHop && smpro_inv_has_force_https($docroot))
            $out[] = ['action'=>'neutralize_https','path'=>$docroot . '/.htaccess','label'=>'Disable the force-HTTPS redirect in .htaccess','why'=>'on-server force-HTTPS rule loops with an SSL-terminating front-end (no CDN proxy detected)'];
        if (!smpro_inv_fixes_has($out, 'fix_htaccess'))
            $out[] = ['action'=>'fix_htaccess','path'=>$docroot . '/.htaccess','label'=>'Repair .htaccess rewrite block','why'=>'restore a clean WordPress rewrite block'];
        // LAST resort — an SSL-forcing plugin double-redirecting. Safe: "Fix it" applies fixes one-by-one and stops
        // at the first that works, so a plugin is disabled only if the URL/.htaccess fixes did not break the loop.
        foreach ((glob($docroot . '/wp-content/plugins/*{ssl,https,force-ssl}*', GLOB_BRACE) ?: []) as $pp) {
            if (is_dir($pp)) $out[] = ['action'=>'disable_plugin','path'=>$pp,'label'=>'Disable SSL plugin ' . basename($pp),'why'=>'an SSL-forcing plugin can double-redirect with the server HTTPS rule'];
        }
    }
    return $out;
}
/** Dedup helper: is an action already queued? */
function smpro_inv_fixes_has(array $out, $action) { foreach ($out as $o) if (($o['action'] ?? '') === $action) return true; return false; }
/** BASE RULE for Site Doctor: BEFORE any fix, clear immutable/hardening locks on the files a fix may need to
 *  edit — otherwise PHP Harden / emergency-harden / a security plugin's lock makes the write fail silently and
 *  the "fix" does nothing (exactly the reported symptom). Returns how many locked targets were cleared. */
function smpro_inv_unharden_base($res) {
    $d = rtrim((string)($res['docroot'] ?? ''), '/'); if ($d === '' || strpos($d, '/home/') !== 0) return 0;
    $home = (string)($res['home'] ?? dirname($d));
    $targets = [$d.'/.htaccess', $d.'/wp-config.php', $home.'/wp-config.php', $d.'/wp-content/.htaccess', $d.'/wp-content/uploads/.htaccess', $d.'/wp-content', $d.'/wp-content/plugins'];
    $n = 0;
    foreach ($targets as $t) { if (file_exists($t) && smpro_inv_imm($t)) { @shell_exec('chattr -i ' . escapeshellarg($t) . ' 2>/dev/null'); $n++; } }
    if ($n) smpro_audit('sitedoctor_unharden_base', ['cleared'=>$n,'docroot'=>$d]);
    return $n;
}

/** Backup + write a literal .htaccess content (AI-provided, validated). Reversible. Hardening-aware. */
function smpro_inv_write_htaccess($r, $content) {
    $docroot = $r['docroot']; $ht = $docroot . '/.htaccess';
    if (strpos($docroot, '/home/') !== 0) return ['ok'=>false,'msg'=>'refused: docroot outside /home'];
    if (strlen($content) > 8192 || stripos($content, '<?php') !== false || preg_match('/[^\x09\x0a\x0d\x20-\x7e]/', $content)) return ['ok'=>false,'msg'=>'refused: .htaccess content failed safety validation'];
    $imm = smpro_inv_imm($ht); if ($imm) @shell_exec('chattr -i ' . escapeshellarg($ht) . ' 2>/dev/null');
    $bak = $ht . '.smpro-bak-' . date('Ymd_His'); $had = is_file($ht);
    if ($had && !@copy($ht, $bak)) { if ($imm) @shell_exec('chattr +i ' . escapeshellarg($ht) . ' 2>/dev/null'); return ['ok'=>false,'msg'=>'backup failed']; }
    $ok = @file_put_contents($ht, rtrim($content, "\n") . "\n") !== false;
    if ($ok) { @chmod($ht, 0644); $st = @stat($docroot); if ($st) { @chown($ht, $st['uid']); @chgrp($ht, $st['gid']); } }
    if ($imm) @shell_exec('chattr +i ' . escapeshellarg($ht) . ' 2>/dev/null');
    if (!$ok) return ['ok'=>false,'msg'=>'write failed'];
    $id = smpro_inv_manifest_add(['user'=>$r['user'],'domain'=>$r['domain'],'action'=>'write_htaccess','kind'=>'file','from'=>$ht,'backup'=>$had ? $bak : '','hardened'=>$imm ? 1 : 0]);
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
        // No AI → fall back to the deterministic multi-fix.
        return smpro_inv_ai_fix($target);
    }
    $docroot = $res['docroot'];
    $htContent = ($res['htaccess']['head'] ?? '');
    $arExists = is_dir($docroot . '/ar') ? 'yes' : 'no';
    $ev = "FAILING SITE EVIDENCE\n";
    $ev .= "domain=" . ($res['domain'] ?: '?') . " account=" . $res['user'] . " php=" . ($res['phpver'] ?: '?') . " http=" . $res['http']['code'] . " docroot=" . $docroot . "\n";
    $ev .= "subdir '/ar' exists on disk: " . $arExists . "\n";
    if (!empty($res['detect'])) { $dt = $res['detect']; $ev .= "Platform: " . $dt['platform'] . ($dt['multisite'] ? " (multisite)" : "") . ($dt['multilingual'] ? "; multilingual via " . $dt['multilingual'] : "") . "; CMS installs on account=" . $dt['installs'] . "; domains=" . implode(',', array_slice($dt['sites'], 0, 6)) . "\n"; }
    if (!empty($res['selfhealers'])) { $ev .= "SELF-HEALER mu-plugins (REVERT fixes within ~1s — disable these FIRST): " . implode(', ', array_map('basename', array_keys($res['selfhealers']))) . "\n"; }
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
         . "{\"cause\":\"one sentence\",\"steps\":[ {\"op\":\"disable_muplugin\",\"path\":\"<mu-plugins/x.php>\"} | {\"op\":\"unharden\"} | {\"op\":\"fix_wp_url\"} | {\"op\":\"fix_htaccess\"} | {\"op\":\"disable\",\"path\":\"<plugins|themes dir>\"} | {\"op\":\"write_htaccess\",\"content\":\"<full .htaccess>\"} ]}\n"
         . "Rules: If any SELF-HEALER mu-plugins are listed, disable_muplugin them FIRST (they revert every other fix within a second). Then unharden if locked files are listed. If WordPress siteurl/home is MISMATCHED (URL path not on disk), use fix_wp_url FIRST (it corrects the DB) — that is the ROOT cause of a recurring wrong RewriteBase; THEN fix_htaccess to repair the rewrite block (preserves PHP handler). Only disable a plugin/theme that STILL EXISTS (not RESOLVED) and is clearly the culprit. Prefer fix_htaccess over write_htaccess. If a REDIRECT LOOP is reported: if siteurl/home is http://, use fix_wp_url FIRST (sets HTTPS, breaks the http<->https loop); else fix_htaccess to clear a stray redirect, or write_htaccess to remove a force-HTTPS block; if an SSL plugin (really-simple-ssl/wp-force-ssl) is the culprit, disable it. Do NOT attempt a server fix for a loop when DNS is behind Cloudflare (it is a Cloudflare SSL-mode setting) — say so in cause. Do not invent files. Keep steps minimal. Paths must be inside " . $docroot . ".";
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
 *  re-checks the site, and flags escalate=true (→ hand off to AI Fix) if it's still failing. */
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
    // Apply fixes INCREMENTALLY and stop at the first that brings the site up — least-disruptive fix wins, so a
    // security plugin is only disabled if the gentler URL/.htaccess fixes did not break the loop.
    foreach ($fixes as $f) {
        $x = smpro_inv_fix($f['action'], $target, $f['path']);
        $ok = !empty($x['ok']); if ($ok) $any = true;
        $steps[] = ($ok ? '✓ ' : '✗ ') . $f['label'] . ': ' . ($x['msg'] ?? '');
        if ($ok) { $after = $check(); if ($after >= 200 && $after < 400) break; }
    }
    if (!$after) $after = $check();
    $upAfter = ($after >= 200 && $after < 400);
    $escalate = !$upAfter;                                   // still failing → AI Fix should take over
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
    // Build evidence — annotate errors that are ALREADY RESOLVED (culprit component already disabled).
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
    // If the site is UP and nothing live remains, don't push a fix — say it's working.
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
    // 1) Deterministic fixes — apply ALL of them in order (un-harden FIRST, then disable culprit, then .htaccess),
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
    // 2) Ambiguous: no clear deterministic culprit → let the AI pick from recently-changed plugins/themes.
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
    if (($e['kind'] ?? '') === 'file') {   // .htaccess repair → restore the backed-up file
        if (empty($e['backup']) || !is_file($e['backup'])) return ['ok'=>false,'msg'=>'backup file missing'];
        $imm = smpro_inv_imm($e['from']); if ($imm) @shell_exec('chattr -i ' . escapeshellarg($e['from']) . ' 2>/dev/null');
        $ok = @copy($e['backup'], $e['from']);
        if ($imm) @shell_exec('chattr +i ' . escapeshellarg($e['from']) . ' 2>/dev/null');
        if (!$ok) return ['ok'=>false,'msg'=>'restore copy failed'];
        @unlink($e['backup']);
        $m[$hit]['status'] = 'undone'; $m[$hit]['undone_ts'] = time();
        @file_put_contents(smpro_inv_manifest_path(), json_encode($m, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), LOCK_EX);
        smpro_audit('sitedoctor_undo', ['target'=>basename($e['from']),'kind'=>'file','ok'=>true]);
        return ['ok'=>true,'msg'=>'Restored original ' . basename($e['from']) . '.'];
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
