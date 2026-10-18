<?php
/**
 * auth.php — WHM context verification (defense-in-depth).
 *
 * Primary auth is enforced by cpsrvd: nothing under whostmgr/docroot/cgi/ runs
 * without an authenticated WHM session (the /cpsessXXXX/ prefix). These helpers
 * add an extra gate and a strong root check for state-changing actions.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

/** True when invoked directly from the shell (maintenance/testing), not the web. */
function smpro_is_cli() {
    if (PHP_SAPI === 'cli' || PHP_SAPI === 'cli-server') {
        // A real WHM web hit always carries a cpsess prefix; CLI maintenance does not.
        return SMPRO_CPSESS === '' && (getenv('REQUEST_URI') === false || getenv('REQUEST_URI') === '');
    }
    return false;
}

/** Actor identity. cpsrvd sets REMOTE_USER for authenticated WHM cgi.
 *  SECURITY: a web request with no authenticated actor must NEVER be assumed to be root —
 *  the euid fallback (which is root under the WHM CGI) is allowed ONLY for CLI maintenance. */
function smpro_current_actor() {
    $u = getenv('REMOTE_USER');
    if ($u !== false && $u !== '') return preg_replace('/[^A-Za-z0-9_.\-]/', '', $u);
    if (smpro_is_cli()) {                                   // shell maintenance only
        if (function_exists('posix_geteuid') && function_exists('posix_getpwuid')) {
            $pw = posix_getpwuid(posix_geteuid());
            if (!empty($pw['name'])) return $pw['name'];
        }
        return 'root';
    }
    return '';                                             // web with no REMOTE_USER → unknown → fail-closed downstream
}

/** Remote IP of the WHM operator, if available. */
function smpro_current_remote_ip() {
    foreach (['REMOTE_ADDR', 'HTTP_X_FORWARDED_FOR'] as $k) {
        $v = $_SERVER[$k] ?? getenv($k);
        if ($v) return preg_replace('/[^0-9a-fA-F:.,\s]/', '', explode(',', $v)[0]);
    }
    return 'cli';
}

/**
 * Verify we are inside a legitimate WHM context.
 * Allow: CLI maintenance, or a web request that arrived through a WHM session.
 */
function smpro_verify_whm_access() {
    if (smpro_is_cli()) return true;
    // Web request (fail-closed): must carry BOTH a cpsrvd-issued session prefix AND an authenticated
    // actor that cpsrvd sets after WHM login. Requiring REMOTE_USER stops a request that merely managed
    // to define SMPRO_CPSESS without a real login.
    if (SMPRO_CPSESS === '') return false;
    $u = getenv('REMOTE_USER');
    return $u !== false && $u !== '';
}

/** Hard gate for pages. Renders a safe 403 and stops on failure. */
function smpro_require_whm_access() {
    if (smpro_verify_whm_access()) return;
    if (function_exists('smpro_audit')) smpro_audit('access_denied', ['actor' => smpro_current_actor(), 'reason' => 'no_whm_context']);
    http_response_code(403);
    // An AJAX caller has to get JSON here too. This gate runs BEFORE the CSRF layer, so it is the first thing an
    // expired session meets — and answering it in HTML is what made a dialog report its own generic "could not
    // load" instead of the real reason. smpro_wants_json() lives in the CSRF module, which may not be loaded this
    // early; if it is absent this simply falls through to the page below.
    if (function_exists('smpro_wants_json') && smpro_wants_json()) {
        header('Content-Type: application/json');
        echo json_encode(['ok' => false, 'auth' => true,
            'msg' => 'Your WHM session is no longer valid. Reload the page and sign in again.'], JSON_UNESCAPED_SLASHES);
        exit;
    }
    header('Content-Type: text/html; charset=utf-8');
    echo '<!doctype html><meta charset="utf-8"><title>Access denied</title>'
       . '<div style="font:14px sans-serif;padding:40px;max-width:520px;margin:auto">'
       . '<h2>Access denied</h2><p>This page must be opened from within an authenticated WHM session.</p>'
       . '<p style="color:#888;font-size:12px">Safety Monitor Pro · code SMPRO-AUTH-403</p></div>';
    exit;
}

/**
 * Strong check for state-changing actions: confirm the actor holds WHM root ACL.
 * Cached for 5 minutes to avoid calling whmapi1 on every request.
 * Returns true/false; CLI is treated as root.
 */
function smpro_actor_has_root() {
    if (smpro_is_cli()) return true;
    $actor = smpro_current_actor();
    if ($actor === '') return false;                       // web request without an authenticated actor → never root
    // cache lives root-only (0700) so a non-root user can't forge a root=true verdict
    @is_dir(SMPRO_CACHE) || @mkdir(SMPRO_CACHE, 0700, true); @chmod(SMPRO_CACHE, 0700);
    $cacheFile = SMPRO_CACHE . '/auth_root_' . preg_replace('/[^A-Za-z0-9_.\-]/', '', $actor) . '.json';

    if (is_file($cacheFile) && (time() - filemtime($cacheFile) < 300)) {
        $c = json_decode((string)@file_get_contents($cacheFile), true);
        if (is_array($c) && array_key_exists('root', $c)) return (bool)$c['root'];
    }

    // PRIMARY, unspoofable signal: the authenticated WHM account is literally 'root'. cpsrvd sets
    // REMOTE_USER from the login session — a reseller can NEVER make it 'root'. We REQUIRE this, so a
    // `whmapi1 myprivs` that reflects the root *process* (not the user) can never grant root to a reseller.
    $isRoot = ($actor === 'root');
    // Defense-in-depth: when it IS the root account, corroborate with the WHM ACL; if WHM reports this
    // account lacks the 'all' privilege, deny. (Only ever RESTRICTS — never grants to a non-root actor.)
    $bin = '/usr/local/cpanel/bin/whmapi1';
    if ($isRoot && is_executable($bin)) {
        $to  = max(1, min(30, (int)SMPRO_TIMEOUT_QUICK));   // constant, but cast defensively
        $cmd = escapeshellcmd($bin) . ' --output=json myprivs 2>/dev/null';
        $raw = @shell_exec('timeout ' . $to . ' ' . $cmd);
        if ($raw) {
            $j = json_decode($raw, true);
            // whmapi1 myprivs => data.privileges is a LIST with one object holding 'all'.
            // Also tolerate data.all or data.privileges.all (older/other shapes).
            $data = $j['data'] ?? $j['result']['data'] ?? [];
            $privs = $data['privileges'] ?? null;
            $first = (is_array($privs) && isset($privs[0]) && is_array($privs[0])) ? $privs[0] : (is_array($privs) ? $privs : []);
            if (empty($data['all']) && empty($first['all'])) {
                $isRoot = false;                            // WHM says this 'root' account lacks full ACL → deny
            }
        }
    }
    @file_put_contents($cacheFile, json_encode(['root' => $isRoot, 'at' => time()]), LOCK_EX);
    @chmod($cacheFile, 0600);
    return $isRoot;
}

/** Hard gate for state-changing actions. */
function smpro_require_root() {
    smpro_require_whm_access();
    if (smpro_actor_has_root()) return;
    if (function_exists('smpro_audit')) smpro_audit('root_required_denied', ['actor' => smpro_current_actor()]);
    if (function_exists('smpro_fail')) smpro_fail(403, 'Root privileges required. (SMPRO-AUTH-ROOT)');
    http_response_code(403);
    echo '<div style="font:14px sans-serif;padding:40px">Root privileges required. (SMPRO-AUTH-ROOT)</div>';
    exit;
}
