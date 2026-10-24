<?php
/**
 * csrf.php - CSRF protection for state-changing (POST) actions.
 * Tokens are bound to actor + action, stored outside docroot, TTL 1 hour,
 * and never appear in URLs (hidden POST field only).
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

define('SMPRO_CSRF_TTL', 3600);
define('SMPRO_CSRF_DIR', SMPRO_CACHE . '/csrf');

/** Per-actor secret used to sign tokens (created once, 0600). */
function smpro_csrf_secret() {
    $f = SMPRO_CSRF_DIR . '/.secret';
    if (is_file($f)) {
        $s = (string)@file_get_contents($f);
        if (strlen($s) >= 32) return $s;
    }
    @is_dir(SMPRO_CSRF_DIR) || @mkdir(SMPRO_CSRF_DIR, 0700, true);
    $s = bin2hex(random_bytes(32));
    @file_put_contents($f, $s, LOCK_EX);
    @chmod($f, 0600);
    return $s;
}

/** Generate a signed token for an action. */
function smpro_csrf_generate($action) {
    $action = preg_replace('/[^a-z0-9_\-]/', '', strtolower($action));
    $actor  = smpro_current_actor();
    $ts     = time();
    $nonce  = bin2hex(random_bytes(8));
    $sig    = hash_hmac('sha256', "$action|$actor|" . (defined('SMPRO_CPSESS') ? (string)SMPRO_CPSESS : '') . "|$ts|$nonce", smpro_csrf_secret());
    return "$ts.$nonce.$sig";
}

/** Verify a token for an action (constant-time, within TTL). */
function smpro_csrf_verify($action, $token) {
    $action = preg_replace('/[^a-z0-9_\-]/', '', strtolower($action));
    $actor  = smpro_current_actor();
    $parts  = explode('.', (string)$token);
    if (count($parts) !== 3) return false;
    [$ts, $nonce, $sig] = $parts;
    if (!ctype_digit($ts) || (time() - (int)$ts) > SMPRO_CSRF_TTL) return false;
    if (!ctype_xdigit($nonce)) return false;
    $expect = hash_hmac('sha256', "$action|$actor|" . (defined('SMPRO_CPSESS') ? (string)SMPRO_CPSESS : '') . "|$ts|$nonce", smpro_csrf_secret());
    return hash_equals($expect, (string)$sig);
}

/** Hidden form field ready to embed in a POST form. */
function smpro_csrf_field($action) {
    return '<input type="hidden" name="smpro_csrf" value="' . smpro_h(smpro_csrf_generate($action)) . '">';
}

/** Is the current request a JSON/AJAX endpoint? (so errors are returned as JSON, not an HTML page) */
function smpro_wants_json() {
    // Explicit per-request flag - set by AJAX handlers up front. Works under the CLI SAPI the CGI wrapper
    // uses, where header()/headers_list() are no-ops (so the header check below never fires in production).
    if (!empty($GLOBALS['SMPRO_FORCE_JSON'])) return true;
    foreach (headers_list() as $h) if (stripos($h, 'content-type:') === 0 && stripos($h, 'application/json') !== false) return true;
    foreach (['update', 'aiprov', 'tuning', 'cooler', 'autoreport', 'tgbot', 'env_install', 'pkg'] as $k) if (($_GET[$k] ?? '') !== '') return true;
    if (($_GET['format'] ?? '') === 'json' || ($_GET['ai_assist'] ?? '') === '1') return true;
    // Last resort: let the REQUEST say so. A POST carrying one of this plugin's *_action fields, from a client
    // that did not ask for HTML, is one of its AJAX endpoints. Both halves matter - the action field is the
    // plugin's own convention for its JSON handlers, and a real browser navigation always lists text/html in
    // Accept while fetch() does not.
    // Why this is needed at all: a handler sets Content-Type: application/json only AFTER the guards run, and
    // the headers_list() check above cannot fire under the CGI wrapper's SAPI. So a REFUSED request - an expired
    // token, most often - answered in HTML, the caller's r.json() rejected, and the dialog showed a generic
    // "could not load" instead of the accurate "your session expired, reload the page" it already knows how to
    // say. Found on the IP profile dialog; the same gap sat in a dozen handlers that would each have had to
    // remember the flag by hand.
    if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST'
        && stripos((string)($_SERVER['HTTP_ACCEPT'] ?? ''), 'text/html') === false) {
        foreach (array_keys($_POST) as $k) if (substr((string)$k, -7) === '_action') return true;
    }
    return false;
}
/** Emit a safe error (JSON for AJAX endpoints, otherwise a small HTML page) and stop. */
function smpro_fail($code, $msg, $extra = []) {
    http_response_code($code);
    if (smpro_wants_json()) {
        header('Content-Type: application/json');
        echo json_encode(['ok' => false, 'msg' => $msg, 'message' => $msg] + $extra, JSON_UNESCAPED_SLASHES);
    } else {
        echo '<div style="font:14px sans-serif;padding:40px">' . smpro_h($msg) . '</div>';
    }
    exit;
}

/** Require a valid CSRF token (and POST method); stop with safe error otherwise.
 *  $liveAuth=false skips the per-action live license round-trip - use ONLY for
 *  READ-ONLY lookups (no state change), so a license-server hiccup can't break a
 *  read (the page-level license gate still applies). */
function smpro_require_valid_csrf($action, $liveAuth = true) {
    smpro_require_post();
    $token = $_POST['smpro_csrf'] ?? '';
    if (!smpro_csrf_verify($action, $token)) {
        smpro_audit('csrf_failed', ['action' => $action, 'actor' => smpro_current_actor()]);
        smpro_fail(400, 'Security token expired — please reload the page and try again.', ['csrf' => true]);
    }
    // 2-way license enforcement: every state-changing action gets a LIVE, replay-proof
    // authorization from the license server. The 'license' action is exempt (it IS the
    // licensing flow). Read-only lookups pass $liveAuth=false. On failure this stops the
    // action and emits the support message.
    if ($liveAuth && $action !== 'license' && function_exists('smpro_lic_require_authorized')) {
        smpro_lic_require_authorized($action);
    }
}

/** Require POST method. */
function smpro_require_post() {
    $m = $_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET';
    if (strtoupper($m) !== 'POST') {
        smpro_fail(405, 'This action requires a POST request. (SMPRO-405)');
    }
}
