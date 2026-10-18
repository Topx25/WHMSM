<?php
/**
 * includes/clearcache.php — Site Doctor "Clear application cache" (smpro_inv_clearcache*). Platform-aware,
 * drop-to-user cache clear (never root), shared-store aware, with an OPT-IN targeted CageFS remount.
 * Required after investigate.php (reuses smpro_inv_resolve/detect + smpro_path_safe).
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

/* ============================================================================
 * SITE DOCTOR — CLEAR APPLICATION CACHE (sd_action=clearcache)
 * Engine lives in includes/investigate.php (SMPRO_BOOT already guarded at top).
 * Clears ONLY regenerable cache, RUNNING AS THE SITE USER (privilege-dropped),
 * per-platform whitelisted, shared-store-safe, path-guarded, bounded & audited.
 * Depends on EXISTING helpers (do NOT redefine): smpro_inv_resolve, smpro_inv_detect,
 * smpro_inv_disk, smpro_inv_human, smpro_path_safe, smpro_audit, and constants
 * SMPRO_VARLIB / SMPRO_LOCKS / SMPRO_SCAN_NICE / SMPRO_SCAN_IONICE_CLASS.
 * ==========================================================================*/

/** Resolve the account's php binary from its phpver (e.g. 'ea-php81','8.1').
 *  Inside the cage `php` already selects the right ea-php; off-CloudLinux we
 *  resolve the explicit ea-php path so artisan/magento run under the right PHP. */
function smpro_inv_cc_php($phpver) {
    $nn = '';                                                   // collect the digits: 'ea-php81'->'81', '8.1'->'81'
    if (preg_match_all('/\d/', (string)$phpver, $mm)) $nn = implode('', $mm[0]);
    if ($nn !== '') { $cand = '/opt/cpanel/ea-php' . $nn . '/root/usr/bin/php'; if (is_executable($cand)) return $cand; }
    if (is_executable('/usr/local/bin/php')) return '/usr/local/bin/php';
    return 'php';                                               // last resort — resolved in the user's PATH inside the cage
}

/** Which privilege-drop launcher this box has. We NEVER run cache mutation as root,
 *  so if neither runuser nor su exists the whole action must refuse. Cached per-request. */
function smpro_inv_cc_drop_method() {
    static $m = null;
    if ($m !== null) return $m;
    $has = function ($b) { return trim((string)@shell_exec('command -v ' . $b . ' 2>/dev/null')) !== ''; };
    if ($has('runuser')) { $m = 'runuser'; }                    // preferred: reparents children cleanly under timeout
    elseif ($has('su'))  { $m = 'su'; }                         // fallback
    else { $m = ''; }                                           // neither -> caller REFUSES (never root)
    return $m;
}

/** HARD identity guard. Returns ['uid','gid','home'] for a REAL, non-system, non-suspended
 *  cPanel account, else false. This is the gate that keeps us from ever drop-exec'ing as
 *  (or clearing caches for) root/nobody/mysql/cpanel or a stray /home dir. */
function smpro_inv_cc_user_ok($user) {
    $user = (string)$user;
    // CRITICAL(2): strict account-name shape — first char [a-z0-9_], then up to 30 of [a-z0-9_-].
    if (!preg_match('/^[a-z0-9_][a-z0-9_-]{0,30}$/', $user)) return false;
    // ADDED: refuse SUSPENDED accounts — su/runuser into them is unreliable and pointless.
    if (is_file('/var/cpanel/suspended/' . $user)) return false;
    // CRITICAL(2): POSITIVELY confirm cPanel account-ness (not a hardcoded uid>=1000 that would
    // refuse legit old-cPanel UID 500-999 accounts). /var/cpanel/users/<user> is the authority;
    // fall back to /etc/trueuserdomains.
    if (!is_file('/var/cpanel/users/' . $user)) {
        $ok = false;
        if (is_readable('/etc/trueuserdomains')) {
            $g = (string)@shell_exec('grep -E ' . escapeshellarg(':[[:space:]]*' . preg_quote($user, '/') . '[[:space:]]*$') . ' /etc/trueuserdomains 2>/dev/null | head -1');
            if (trim($g) !== '') $ok = true;
        }
        if (!$ok) return false;
    }
    // Resolve uid/gid/home — posix first, then getent/passwd fallback (posix may be absent on CLI SAPI).
    $uid = -1; $gid = -1; $home = '';
    if (function_exists('posix_getpwnam')) {
        $pw = @posix_getpwnam($user);
        if (is_array($pw)) { $uid = (int)$pw['uid']; $gid = (int)$pw['gid']; $home = (string)$pw['dir']; }
    }
    if ($uid < 0) {
        $line = (string)@shell_exec('getent passwd ' . escapeshellarg($user) . ' 2>/dev/null');
        if (trim($line) === '' && is_readable('/etc/passwd'))
            $line = (string)@shell_exec('grep -E ' . escapeshellarg('^' . preg_quote($user, '/') . ':') . ' /etc/passwd 2>/dev/null | head -1');
        $p = explode(':', trim($line));
        if (count($p) >= 6 && $p[0] === $user) { $uid = (int)$p[2]; $gid = (int)$p[3]; $home = $p[5]; }
    }
    // CRITICAL(2): system cutoff aligned with the codebase convention (uid<100 = system, investigate.php:1384).
    if ($uid < 100) return false;
    // Home MUST be under /home/ and exist and be OWNED by that uid (defeats a hijacked passwd home).
    if ($home === '' || strpos($home, '/home/') !== 0) return false;
    if (!is_dir($home)) return false;
    $st = @stat($home);
    if (!$st || (int)$st['uid'] !== $uid) return false;
    return ['uid' => $uid, 'gid' => $gid, 'home' => rtrim($home, '/')];
}

/** THE single choke-point that executes a shell script AS THE ACCOUNT USER. Never root.
 *  Returns ['out'=>combined stdout+stderr,'rc_note'=>'' or a refusal string].
 *  CRITICAL(1): non-login drop (no .bash_profile ahead of the ulimit/nice line), signal-safe
 *  process-group kill, ulimit -t (CPU) but NO ulimit -v (would OOM-kill Magento/Drupal/large WP). */
function smpro_inv_cc_run($user, $script, $timeout, $cwd = '') {
    $t   = max(5, (int)$timeout);
    $cpu = max(5, $t - 5);                                      // CPU-seconds cap just under the wall clock
    // Inner wrapper — ulimit -t is the FIRST token; cd fails CLOSED; nice/ionice de-prioritize the work.
    // Deliberately NO `ulimit -v` here (unlike smpro_inv_optimize_run_tool) — LVE caps RAM on CloudLinux.
    $inner = 'ulimit -t ' . $cpu . ' 2>/dev/null; ';
    if ($cwd !== '') $inner .= 'cd ' . escapeshellarg($cwd) . ' 2>/dev/null || exit 3; ';
    $inner .= 'nice -n ' . SMPRO_SCAN_NICE . ' ionice -c' . SMPRO_SCAN_IONICE_CLASS . ' ' . $script;
    $method = smpro_inv_cc_drop_method();
    // CRITICAL(1): REFUSE rather than fall back to root if we cannot drop privileges.
    if ($method === '' || !preg_match('/^[a-z0-9_][a-z0-9_-]{0,30}$/', (string)$user))
        return ['out' => '', 'rc_note' => 'refused: cannot drop privileges safely (no runuser/su) — never run as root'];
    $esc = escapeshellarg($inner);                             // the whole wrapper -> one single-quoted -c argument
    // NOTE: NO `setsid` — `timeout` (non-foreground) already creates its own process group and group-kills every
    // descendant on expiry. setsid would move the worker into a NEW session outside timeout's group, so an I/O-bound
    // find or a hung artisan (low CPU, so ulimit -t doesn't bite) would ORPHAN and outlive the timeout. Keep the
    // worker in timeout's killable group (mirrors smpro_inv_optimize_run_tool).
    if ($method === 'runuser') {
        // NON-login (--noprofile --norc) so the user's .bash_profile can't run ahead of ulimit/nice; -k TERM-then-KILL.
        $cmd = 'timeout -k 5 -s TERM ' . $t . ' runuser -u ' . escapeshellarg($user)
             . ' -- /bin/bash --noprofile --norc -c ' . $esc . ' 2>&1';
    } else {
        // `su <user>` WITHOUT `-` is non-login (no .bash_profile); -c is non-interactive (no .bashrc).
        $cmd = 'timeout -k 5 -s TERM ' . $t . ' su ' . escapeshellarg($user)
             . ' -s /bin/bash -c ' . $esc . ' 2>&1';
    }
    return ['out' => (string)@shell_exec($cmd), 'rc_note' => ''];
}

/** Read-only du of a directory (root, bounded, low-priority). Returns bytes (0 if absent/timed out).
 *  Caller MUST smpro_path_safe() the dir first (du follows a command-line symlink). */
function smpro_inv_cc_du($dir) {
    $out = (string)@shell_exec('timeout 40 nice -n ' . SMPRO_SCAN_NICE . ' ionice -c' . SMPRO_SCAN_IONICE_CLASS
         . ' du -sb ' . escapeshellarg($dir) . ' 2>/dev/null');
    return preg_match('/^(\d+)/', trim($out), $m) ? (int)$m[1] : 0;
}

/** Build the AS-USER inner command that empties ONE cache dir and re-creates ONLY its
 *  top-level anti-listing sentinels. CRITICAL(4)/CHANGE-2(b): `-mindepth 1 -delete` drops
 *  EVERYTHING inside (so WP Super Cache's nested index.html page cache is actually cleared),
 *  then we re-create the sentinel at the TOP LEVEL ONLY — never tree-wide. -xdev per CHANGE-7. */
function smpro_inv_cc_fs_inner($dir, $recreate) {
    $e   = escapeshellarg($dir);
    $cmd = 'find ' . $e . ' -mindepth 1 -xdev -delete 2>/dev/null';
    if (!empty($recreate['index_php']))
        $cmd .= '; printf %s ' . escapeshellarg('<?php // Silence is golden.') . ' > ' . escapeshellarg($dir . '/index.php') . ' 2>/dev/null';
    if (!empty($recreate['index_html']))
        $cmd .= '; : > ' . escapeshellarg($dir . '/index.html') . ' 2>/dev/null';
    return $cmd;
}

/** Pure mapping platform -> (filesystem cache dirs to empty) + (CLI cache commands to attempt).
 *  Encodes the per-platform whitelist. CRITICAL(4). Note detect() only emits WordPress/Laravel/
 *  Magento/Drupal/Joomla/PHP/static (match case exactly) — it NEVER returns PrestaShop/OpenCart,
 *  so those branches are intentionally ABSENT (dead code otherwise). Generic PHP/static/unknown
 *  return NOTHING (no auto-clear — opt-in only), per CHANGE-6.
 *  Each cli entry: label,cmd(with @PHP@ token),cwd,store(bool),cond(''|'env'),stack,role,tool[,file]. */
function smpro_inv_cc_targets($platform, $docroot, $approot, $home) {
    $docroot = rtrim((string)$docroot, '/');
    $approot = rtrim((string)($approot !== '' ? $approot : $docroot), '/');
    $dirs = []; $cli = [];
    switch ($platform) {                                       // CRITICAL: exact case from smpro_inv_detect()
        case 'WordPress':
            // Regenerable page/asset caches. uploads/cache is DELIBERATELY excluded (non-regenerable
            // user data — opt-in only), per CRITICAL(4) / CHANGE-2(a).
            foreach (['/wp-content/cache', '/wp-content/cache/wp-rocket', '/wp-content/cache/min',
                      '/wp-content/cache/autoptimize', '/wp-content/litespeed', '/wp-content/et-cache'] as $d)
                $dirs[] = $docroot . $d;
            // Object cache flush — a STORE flush (guarded by the shared-store probe). NO --allow-root.
            $cli[] = ['label' => 'WordPress object cache (wp cache flush)', 'cmd' => 'wp cache flush --path=' . escapeshellarg($docroot), 'cwd' => '', 'store' => true, 'cond' => '', 'stack' => 'wp', 'role' => 'solo', 'tool' => 'wp'];
            // Page-cache plugin purges — optional, non-fatal, file-based (not a shared external store).
            $cli[] = ['label' => 'LiteSpeed cache purge', 'cmd' => 'wp litespeed-purge all --path=' . escapeshellarg($docroot), 'cwd' => '', 'store' => false, 'cond' => '', 'stack' => 'wp-ls', 'role' => 'solo', 'tool' => 'wp'];
            $cli[] = ['label' => 'WP Rocket clean',      'cmd' => 'wp rocket clean --confirm --path=' . escapeshellarg($docroot), 'cwd' => '', 'store' => false, 'cond' => '', 'stack' => 'wp-rk', 'role' => 'solo', 'tool' => 'wp'];
            $cli[] = ['label' => 'W3 Total Cache flush', 'cmd' => 'wp w3-total-cache flush all --path=' . escapeshellarg($docroot), 'cwd' => '', 'store' => false, 'cond' => '', 'stack' => 'wp-w3', 'role' => 'solo', 'tool' => 'wp'];
            break;
        case 'Laravel':
            // CRITICAL(4)/CHANGE-3: NEVER the bare `optimize` verb; every call gets -n (no-interaction).
            $cli[] = ['label' => 'artisan optimize:clear', 'cmd' => '@PHP@ artisan optimize:clear -n', 'cwd' => $approot, 'store' => true,  'cond' => '',    'stack' => 'lar',     'role' => 'primary',  'tool' => 'artisan'];
            $cli[] = ['label' => 'artisan cache:clear',    'cmd' => '@PHP@ artisan cache:clear -n',    'cwd' => $approot, 'store' => true,  'cond' => '',    'stack' => 'lar',     'role' => 'fallback', 'tool' => 'artisan'];
            $cli[] = ['label' => 'artisan view:clear',     'cmd' => '@PHP@ artisan view:clear -n',     'cwd' => $approot, 'store' => false, 'cond' => '',    'stack' => 'lar',     'role' => 'fallback', 'tool' => 'artisan'];
            $cli[] = ['label' => 'artisan event:clear',    'cmd' => '@PHP@ artisan event:clear -n',    'cwd' => $approot, 'store' => false, 'cond' => '',    'stack' => 'lar',     'role' => 'fallback', 'tool' => 'artisan'];
            // config/route cache clear ONLY when a readable .env exists (guards a config:cache-only deploy).
            $cli[] = ['label' => 'artisan config:clear',   'cmd' => '@PHP@ artisan config:clear -n',   'cwd' => $approot, 'store' => false, 'cond' => 'env', 'stack' => 'lar-cfg', 'role' => 'solo',     'tool' => 'artisan'];
            $cli[] = ['label' => 'artisan route:clear',    'cmd' => '@PHP@ artisan route:clear -n',    'cwd' => $approot, 'store' => false, 'cond' => 'env', 'stack' => 'lar-rt',  'role' => 'solo',     'tool' => 'artisan'];
            // Filesystem fallback (artisan absent/broken) — mirrors smpro_inv_fix_laravel_cache (investigate.php:1395).
            foreach (['/storage/framework/cache/data', '/storage/framework/views', '/bootstrap/cache'] as $d)
                $dirs[] = $approot . $d;
            break;
        case 'Magento':
            $cli[] = ['label' => 'bin/magento cache:flush', 'cmd' => '@PHP@ bin/magento cache:flush -n', 'cwd' => $approot, 'store' => true, 'cond' => '', 'stack' => 'mag', 'role' => 'solo', 'tool' => 'magento'];
            // CRITICAL(4): var/cache|var/page_cache|var/view_preprocessed ONLY. generated/ is NEVER deleted
            // (removing it in production mode breaks DI until setup:di:compile).
            foreach (['/var/cache', '/var/page_cache', '/var/view_preprocessed'] as $d) $dirs[] = $approot . $d;
            break;
        case 'Drupal':
            // CHANGE-5: prefer the PROJECT's drush (correct major version) over a system drush.
            $vd = $approot . '/vendor/bin/drush';
            $hasVd = is_file($vd);
            if ($hasVd) $cli[] = ['label' => 'drush cache:rebuild (project)', 'cmd' => escapeshellarg($vd) . ' cache:rebuild', 'cwd' => $approot, 'store' => true, 'cond' => '', 'stack' => 'dru', 'role' => 'primary', 'tool' => 'drushfile', 'file' => $vd];
            $cli[] = ['label' => 'drush cache:rebuild (global)', 'cmd' => 'drush cache:rebuild', 'cwd' => $docroot, 'store' => true, 'cond' => '', 'stack' => 'dru', 'role' => ($hasVd ? 'fallback' : 'primary'), 'tool' => 'drush'];
            // On-disk fallback only clears twig/asset caches; the DB-backed cache_* tables need drush.
            foreach (['/sites/default/files/php', '/sites/default/files/css', '/sites/default/files/js'] as $d)
                $dirs[] = $docroot . $d;
            break;
        case 'Joomla':
            $cli[] = ['label' => 'joomla cache:clean', 'cmd' => '@PHP@ ' . escapeshellarg($docroot . '/cli/joomla.php') . ' cache:clean', 'cwd' => $docroot, 'store' => false, 'cond' => '', 'stack' => 'joo', 'role' => 'solo', 'tool' => 'php'];
            foreach (['/cache', '/administrator/cache'] as $d) $dirs[] = $docroot . $d;
            break;
        default:
            // 'PHP' / 'static' / 'unknown' — NO auto-clear (CHANGE-6). A dir named cache/tmp for an
            // unidentified app may hold sessions, uploads, generated docs or a SQLite store.
            break;
    }
    return ['dirs' => $dirs, 'cli' => $cli];
}

/** SHARED EXTERNAL CACHE/SESSION STORE GUARD (CRITICAL(3)). Returns ['shared'=>bool,'store'=>'redis|memcached|','detail'=>note].
 *  Root-reads the app config to decide whether a global CLI flush would FLUSHDB a co-tenant's cache/sessions/queues. */
function smpro_inv_cc_shared_store_probe($platform, $docroot, $approot) {
    $res = ['shared' => false, 'store' => '', 'detail' => ''];
    if ($platform === 'WordPress') {
        $dropin = $docroot . '/wp-content/object-cache.php';
        if (!is_file($dropin)) return $res;                    // no persistent object cache -> nothing to protect
        $cfg  = is_file($docroot . '/wp-config.php') ? (string)@file_get_contents($docroot . '/wp-config.php') : '';
        $cfg .= is_readable($dropin) ? (string)@file_get_contents($dropin) : '';
        $isRedis = (bool)preg_match('/WP_REDIS_|\bRedis\b/i', $cfg);
        $isMc    = (bool)preg_match('/MEMCACHED_SERVERS|\bMemcached\b/i', $cfg);
        if (!$isRedis && !$isMc) return $res;
        $hasPrefix = (bool)preg_match('/WP_REDIS_PREFIX|WP_CACHE_KEY_SALT/i', $cfg);
        $hasDb     = (bool)preg_match('/WP_REDIS_DATABASE/i', $cfg);
        if (!$hasPrefix && !$hasDb) {
            $res['shared'] = true; $res['store'] = $isRedis ? 'redis' : 'memcached';
            $res['detail'] = "This site's object cache is on a shared " . $res['store'] . " with no key prefix — a global flush would wipe other tenants' cache and log users out; skipped.";
        }
        return $res;
    }
    if ($platform === 'Laravel') {
        $env = $approot . '/.env';
        if (!is_file($env) || !is_readable($env)) return $res;
        $e = (string)@file_get_contents($env);
        $drv = '';
        if (preg_match('/^CACHE_DRIVER\s*=\s*(\S+)/mi', $e, $m)) $drv = strtolower(trim($m[1], " \"'"));
        elseif (preg_match('/^CACHE_STORE\s*=\s*(\S+)/mi', $e, $m2)) $drv = strtolower(trim($m2[1], " \"'"));
        if (!in_array($drv, ['redis', 'memcached'], true)) return $res;
        // A non-empty CACHE_PREFIX does NOT isolate a flush: Laravel's RedisStore::flush()/MemcachedStore::flush()
        // issue an UNSCOPED flushdb()/flush() that ignores the prefix (the prefix only namespaces per-key get/put).
        // A shared REDIS_CACHE_DB index also doesn't distinguish co-tenants (default installs all land on it). So
        // default redis/memcached to SHARED (skip the global flush; filesystem-only) and downgrade ONLY on provable
        // per-tenant isolation — a dedicated per-account unix-socket instance.
        $dedicated = false;
        if ($drv === 'redis' && preg_match('/^REDIS_HOST\s*=\s*(\S+)/mi', $e, $mh)) {
            $host = strtolower(trim($mh[1], " \"'"));
            if ($host !== '' && $host[0] === '/') $dedicated = true;   // per-account unix socket => isolated instance
        }
        if (!$dedicated) {
            $res['shared'] = true; $res['store'] = $drv;
            $res['detail'] = 'Laravel CACHE_DRIVER=' . $drv . ' on a shared ' . $drv . ' — a global flush ignores CACHE_PREFIX (flushdb/flush wipes the whole DB/server) and would destroy co-tenant cache/sessions/queues; skipped (filesystem-only).';
        }
        return $res;
    }
    if ($platform === 'Magento') {
        $env = $approot . '/app/etc/env.php';
        if (!is_file($env)) return $res;
        $e = (string)@file_get_contents($env);
        if (!preg_match('/Cm_Cache_Backend_Redis|[\'"]redis[\'"]/i', $e)) return $res;
        if (!preg_match('/[\'"]id_prefix[\'"]/i', $e)) {       // Redis backend with no id_prefix => shared risk
            $res['shared'] = true; $res['store'] = 'redis';
            $res['detail'] = 'Magento cache backend is Redis with no id_prefix — a global cache:flush would wipe co-tenant cache; skipped (filesystem-only).';
        }
        return $res;
    }
    return $res;
}

/** True only on CloudLinux with cagefsctl AND the user reported ENABLED. Any error/empty -> false (skip). */
function smpro_inv_cagefs_applicable($user) {
    if (!preg_match('/^[a-z0-9_][a-z0-9_-]{0,30}$/', (string)$user)) return false;
    if (!is_file('/etc/cloudlinux-release')) return false;
    if (!is_executable('/usr/sbin/cagefsctl')) return false;
    $out = (string)@shell_exec('timeout 8 /usr/sbin/cagefsctl --user-status ' . escapeshellarg($user) . ' 2>/dev/null');
    return (bool)preg_match('/\benabled\b/i', $out) && !preg_match('/\bdisabled\b/i', $out);
}

/** TARGETED per-user CageFS remount (CRITICAL(6)). NEVER --remount-all. OPT-IN + NON-GATING at the caller.
 *  Returns ['ok'=>bool,'msg'=>string]. A failure is always a soft note, never a hard error. */
function smpro_inv_cagefs_remount($user) {
    if (!smpro_inv_cagefs_applicable($user)) return ['ok' => false, 'msg' => 'CageFS not applicable for this user — skipped'];
    // TARGETED --remount <user> only (the code path that could pass --remount-all does not exist).
    $out = (string)@shell_exec('timeout -k 5 120 /usr/sbin/cagefsctl --remount ' . escapeshellarg($user) . ' 2>&1');
    $ok  = !preg_match('/\b(error|failed|usage:)\b/i', $out);
    return ['ok' => $ok, 'msg' => $ok ? ('CageFS remounted for ' . $user) : ('CageFS remount reported: ' . trim(substr($out, 0, 200)))];
}

/** READ-ONLY plan. Reused by the GET dry-run preview and by the apply. Resolves+detects, computes the
 *  whitelisted cache dirs, path_safe's + sizes each (CRITICAL(5)/CHANGE-7: path_safe BEFORE du), probes
 *  which CLIs the account has, and surfaces the shared-store + stampede warnings. Writes NOTHING. */
function smpro_inv_clearcache_plan($target) {
    $r = smpro_inv_resolve($target);
    if (!$r) return ['ok' => false, 'msg' => 'Could not resolve that domain/account on this server.'];
    $user = $r['user']; $home = rtrim($r['home'], '/'); $docroot = rtrim($r['docroot'], '/');
    // Hard identity guard (never proceed for a system/suspended/non-cPanel account).
    $u = smpro_inv_cc_user_ok($user);
    if ($u === false) return ['ok' => false, 'msg' => 'Refusing: "' . $user . '" is not a valid non-system cPanel account (or it is suspended).'];
    // docroot must live under /home and contain no traversal (matches the fix-engine guard).
    if (strpos($docroot, '/home/') !== 0 || strpos($docroot, '..') !== false) return ['ok' => false, 'msg' => 'Refusing: document root is outside /home.'];
    if (!is_dir($docroot)) return ['ok' => false, 'msg' => 'Document root not found on disk.'];

    $detect = smpro_inv_detect($docroot, $home);
    $platform = $detect['platform'];
    // Resolve the REAL app root. detect() gives approot for Laravel; if a symlinked public_html made it
    // wrong, walk up to the dir that actually contains artisan. Never let approot escape /home.
    $approot = (string)($detect['approot'] ?? '');
    if ($approot === '') {
        if (is_file($docroot . '/artisan')) $approot = $docroot;
        elseif (is_file(dirname($docroot) . '/artisan')) $approot = dirname($docroot);
        else $approot = $docroot;
    }
    $rp = @realpath($docroot);
    if ($approot === $docroot && $rp !== false && is_file($rp . '/artisan')) $approot = $rp; // symlinked docroot -> real app dir
    $approot = rtrim($approot, '/');
    if (strpos($approot, '/home/') !== 0) $approot = $docroot;

    $tg = smpro_inv_cc_targets($platform, $docroot, $approot, $home);
    // Size each EXISTING target — path_safe FIRST so du can't follow a planted symlink out of the account.
    $targets = []; $total = 0;
    foreach ($tg['dirs'] as $dir) {
        $safe = smpro_path_safe($dir, [$home]);
        if ($safe === '' || !is_dir($safe)) continue;
        $b = smpro_inv_cc_du($safe);
        $targets[] = ['path' => $safe, 'rel' => substr($safe, strlen($home) + 1), 'bytes' => $b, 'human' => smpro_inv_human($b)];
        $total += $b;
    }
    // Which CLIs does the account have? (probe AS the user so PATH/cage match the real run).
    $probe = smpro_inv_cc_run($user, 'command -v wp >/dev/null 2>&1 && echo WP; command -v drush >/dev/null 2>&1 && echo DRUSH; command -v php >/dev/null 2>&1 && echo PHP', 12, $home);
    $po = $probe['out'];
    $cli = [
        'wp'      => (bool)preg_match('/\bWP\b/', $po),
        'drush'   => (bool)preg_match('/\bDRUSH\b/', $po),
        'artisan' => is_file($approot . '/artisan'),
        'magento' => is_file($approot . '/bin/magento'),
    ];
    $shared = smpro_inv_cc_shared_store_probe($platform, $docroot, $approot);
    $cacheable = in_array($platform, ['WordPress', 'Laravel', 'Magento', 'Drupal', 'Joomla'], true);
    // Safety note the confirm card shows — DOWNGRADED to a warning when a shared store is detected.
    $note = 'Deletes only regenerable cache inside ' . $home . '/ (never source, config, uploads or the database) and runs as the site user. The app rebuilds its cache on the next request.';
    if ($shared['shared']) $note = 'WARNING: ' . $shared['detail'] . ' Only on-disk cache will be cleared.';
    return [
        'ok' => true, 'user' => $user, 'domain' => $r['domain'], 'docroot' => $docroot, 'approot' => $approot, 'home' => $home,
        'platform' => $platform, 'cacheable' => $cacheable, 'targets' => $targets, 'targets_total' => $total,
        'targets_total_human' => smpro_inv_human($total), 'cli' => $cli, 'cagefs_applicable' => smpro_inv_cagefs_applicable($user),
        'shared_store' => $shared, 'note' => $note,
        'stampede_note' => 'Clearing cache on a busy site briefly increases load while it rebuilds — prefer off-peak. The optional CageFS refresh can briefly interrupt this site\'s running processes.',
        'msg' => $cacheable ? 'Ready.' : 'No automatic cache clear is defined for this platform (opt-in only).',
    ];
}

/** TOP-LEVEL APPLY. Re-runs the read-only plan, validates the user, takes a per-user flock, drops to the
 *  site user to clear the detected platform's cache (CLI-first with the shared-store guard, filesystem
 *  fallback always), measures freed bytes, then does the OPTIONAL, non-gating targeted CageFS remount.
 *  Records NO undo entry (cache is regenerable); audits everything. $doRemount defaults OFF (CRITICAL(6)).
 *  $optDirs = operator-opted-in extra dirs for a generic/unknown platform (CHANGE-6 — no auto-clear). */
function smpro_inv_clearcache($target, $doRemount = false, array $optDirs = array()) {
    $plan = smpro_inv_clearcache_plan($target);
    if (empty($plan['ok'])) return $plan;                      // refusal / not-resolved is passed straight through
    $user = $plan['user']; $home = $plan['home']; $docroot = $plan['docroot']; $approot = $plan['approot'];
    $platform = $plan['platform']; $shared = $plan['shared_store'];
    // Identity was validated in the plan, but re-confirm (defense in depth) before we drop-exec.
    $u = smpro_inv_cc_user_ok($user);
    if ($u === false) return ['ok' => false, 'msg' => 'Refusing: account failed the identity guard.'];
    // CRITICAL(1): if we cannot drop privileges, REFUSE (never clear as root).
    if (smpro_inv_cc_drop_method() === '')
        return ['ok' => false, 'msg' => 'Refusing: cannot drop privileges safely (no runuser/su) — will not clear cache as root.'];

    // CRITICAL(7): per-user LOCK_NB flock — no concurrent double-run (second admin tab / auto-optimize overlap).
    @is_dir(SMPRO_LOCKS) || @mkdir(SMPRO_LOCKS, 0700, true);
    $lockPath = SMPRO_LOCKS . '/sitedoctor-clearcache-' . $user . '.lock';   // $user is regex-validated
    $lk = @fopen($lockPath, 'c');
    if (!$lk || !@flock($lk, LOCK_EX | LOCK_NB)) { if ($lk) @fclose($lk); return ['ok' => false, 'msg' => 'A cache clear for ' . $user . ' is already running.']; }

    $phpPath = smpro_inv_cc_php((string)($plan['domain'] !== '' ? '' : ''));  // resolved below from resolve()'s phpver
    // (phpver is not carried in the plan; re-resolve cheaply so we pick the account's ea-php off-CloudLinux.)
    $rr = smpro_inv_resolve($target); $phpPath = smpro_inv_cc_php((string)($rr['phpver'] ?? ''));
    $phpEsc = escapeshellarg($phpPath);
    $envReadable = is_file($approot . '/.env') && is_readable($approot . '/.env');

    $tg = smpro_inv_cc_targets($platform, $docroot, $approot, $home);
    // Presence map (probe AS the user; file checks as root).
    $probe = smpro_inv_cc_run($user, 'command -v wp >/dev/null 2>&1 && echo WP; command -v drush >/dev/null 2>&1 && echo DRUSH; command -v php >/dev/null 2>&1 && echo PHP', 12, $home);
    $po = $probe['out'];
    $have = [
        'wp'        => (bool)preg_match('/\bWP\b/', $po),
        'drush'     => (bool)preg_match('/\bDRUSH\b/', $po),
        'php'       => (bool)preg_match('/\bPHP\b/', $po) || is_executable($phpPath),
        'artisan'   => is_file($approot . '/artisan'),
        'magento'   => is_file($approot . '/bin/magento'),
        'joomla_cli'=> is_file($docroot . '/cli/joomla.php'),
    ];

    $cleared = []; $cli = ['wp' => false, 'artisan' => false, 'magento' => false, 'drush' => false];
    $anyCliRan = false; $primaryRan = []; $primaryOk = [];

    // ---- CLI cache commands (each its OWN drop so nice/ionice bind to that one tool + clean per-tool notes). ----
    foreach ($tg['cli'] as $c) {
        $tool = $c['tool']; $present = true;
        if ($tool === 'wp')             $present = $have['wp'];
        elseif ($tool === 'drush')      $present = $have['drush'];
        elseif ($tool === 'drushfile')  $present = is_file((string)($c['file'] ?? ''));
        elseif ($tool === 'artisan')    $present = $have['artisan'];
        elseif ($tool === 'magento')    $present = $have['magento'] && $have['php'];
        elseif ($tool === 'php')        $present = $have['php'] && $have['joomla_cli'];
        if (!$present) continue;
        // CRITICAL(3): SHARED STORE GUARD — skip any global store-flush on a shared/unprefixed redis/memcached.
        if (!empty($c['store']) && !empty($shared['shared'])) {
            $cleared[] = ['label' => $c['label'], 'method' => 'cli', 'freed_bytes' => 0, 'human' => '0 B',
                          'note' => 'skipped — object/app cache is on a shared ' . $shared['store'] . ' with no key prefix (a global flush would wipe co-tenants + sessions)'];
            continue;
        }
        // Laravel config:clear/route:clear only when a readable .env exists (else skip with a note).
        if (($c['cond'] ?? '') === 'env' && !$envReadable) {
            $cleared[] = ['label' => $c['label'], 'method' => 'cli', 'freed_bytes' => 0, 'human' => '0 B',
                          'note' => 'skipped — no readable .env (avoids bricking a config:cache-only deploy)'];
            continue;
        }
        // primary/fallback: run fallback ONLY if the stack's primary did not run OR did not succeed.
        $stack = $c['stack']; $role = $c['role'];
        if ($role === 'fallback' && !empty($primaryRan[$stack]) && !empty($primaryOk[$stack])) continue;
        $inner = str_replace('@PHP@', $phpEsc, $c['cmd']);     // @PHP@ -> already-escaped php path (nested-escape safe)
        $res = smpro_inv_cc_run($user, $inner, 120, (string)$c['cwd']);
        if ($res['rc_note'] !== '') {                          // privilege-drop refusal mid-run -> abort safely
            @flock($lk, LOCK_UN); @fclose($lk);
            return ['ok' => false, 'msg' => $res['rc_note']];
        }
        $anyCliRan = true; $out = trim($res['out']); $errLine = '';
        foreach (explode("\n", $out) as $ln) {
            if (preg_match('/error|exception|fatal|not found|could not|permission denied|no such|is not a registered/i', $ln)) { $errLine = trim($ln); break; }
        }
        $success = ($errLine === '');
        if ($role === 'primary') { $primaryRan[$stack] = true; $primaryOk[$stack] = $success; }
        if (isset($cli[$tool])) $cli[$tool] = $cli[$tool] || $success;
        if ($tool === 'drushfile') $cli['drush'] = $cli['drush'] || $success;
        $cleared[] = ['label' => $c['label'], 'method' => 'cli', 'freed_bytes' => 0, 'human' => '0 B',
                      'note' => $success ? ('flushed via ' . ($tool === 'drushfile' ? 'drush' : $tool)) : ('CLI reported: ' . ($errLine !== '' ? $errLine : 'error'))];
    }

    // ---- Filesystem cache dirs (always run — belt-and-suspenders, covers plugins with no CLI). ----
    // For a generic/unknown platform tg['dirs'] is EMPTY (no auto-clear); only operator-opted-in $optDirs apply.
    $fsDirs = $tg['dirs'];
    foreach ($optDirs as $od) { $od = rtrim((string)$od, '/'); if ($od !== '' && strpos($od, $home . '/') === 0) $fsDirs[] = $od; }
    $freedTotal = 0; $rootOwned = false;
    foreach ($fsDirs as $dir) {
        // CRITICAL(5): path_safe BEFORE the delete — rejects a symlink and requires realpath under /home/<user>.
        $safe = smpro_path_safe($dir, [$home]);
        if ($safe === '' || !is_dir($safe)) continue;
        $before = smpro_inv_cc_du($safe);
        // Capture top-level sentinels to re-create afterwards (anti-listing) — top level ONLY, never tree-wide.
        $recreate = ['index_php' => is_file($safe . '/index.php'), 'index_html' => is_file($safe . '/index.html')];
        $res = smpro_inv_cc_run($user, smpro_inv_cc_fs_inner($safe, $recreate), 60, $home);
        if ($res['rc_note'] !== '') { @flock($lk, LOCK_UN); @fclose($lk); return ['ok' => false, 'msg' => $res['rc_note']]; }
        $after = smpro_inv_cc_du($safe);
        $freed = max(0, $before - $after); $freedTotal += $freed;
        $note = '';
        // Root-owned turds: the user-run delete silently skips files it doesn't own -> after stays large.
        if ($after > 65536 && $freed < $before) { $note = 'some cache files may be root-owned and were skipped'; $rootOwned = true; }
        $cleared[] = ['label' => substr($safe, strlen($home) + 1), 'method' => 'filesystem', 'freed_bytes' => $freed, 'human' => smpro_inv_human($freed), 'note' => $note];
    }

    // ---- OPTIONAL CageFS remount (opt-in, OFF by default, NEVER gates ok). CRITICAL(6). ----
    $cage = ['applicable' => smpro_inv_cagefs_applicable($user), 'ok' => false, 'msg' => ''];
    if ($doRemount) {
        if ($cage['applicable']) { $rm = smpro_inv_cagefs_remount($user); $cage['ok'] = $rm['ok']; $cage['msg'] = $rm['msg']; }
        else $cage['msg'] = 'CageFS not applicable for this user — skipped';
    } else {
        $cage['msg'] = $cage['applicable'] ? 'CageFS refresh available but not requested (opt-in)' : 'CageFS not applicable for this user';
    }

    // ---- Result message (freed_total==0 AND no CLI ran => "No cache found", ok:true not an error). ----
    if ($freedTotal === 0 && !$anyCliRan) $msg = 'No cache found to clear.';
    else $msg = 'Cleared ' . $platform . ' cache — freed ' . smpro_inv_human($freedTotal) . '.';
    if (!empty($shared['shared'])) $msg .= ' ' . $shared['detail'];
    if ($rootOwned) $msg .= ' Note: some cache files are root-owned and were skipped — run the root-owned-cache cleanup.';

    $out = [
        'ok' => true, 'platform' => $platform, 'user' => $user, 'domain' => $plan['domain'],
        'cleared' => $cleared, 'freed_total' => $freedTotal, 'freed_total_human' => smpro_inv_human($freedTotal),
        'cli' => $cli, 'cagefs' => $cage, 'shared_store' => $shared, 'msg' => $msg,
    ];
    smpro_audit('sitedoctor_clearcache', [
        'user' => $user, 'domain' => $plan['domain'], 'platform' => $platform, 'freed_total' => $freedTotal,
        'cli' => $cli, 'shared_store' => !empty($shared['shared']), 'cagefs_remount' => ($doRemount ? $cage['ok'] : false), 'ok' => true,
    ]);
    @flock($lk, LOCK_UN); @fclose($lk);
    return $out;
}