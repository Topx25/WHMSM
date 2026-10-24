<?php
/**
 * includes/license.php - Safety Monitor Pro licensing engine.
 *
 * Talks to the AITECH_LICENSE server. The hosts are the two constants below - SMPRO_LIC_BASE (HostGuard
 * brand, Cloudflare-fronted) and SMPRO_LIC_BASE_FALLBACK (direct origin, used when the primary is
 * unreachable or challenged). Do not name a host here: this comment named the old host long after
 * the primary had moved, which reads as the live endpoint and sends anyone auditing the brand to the
 * wrong line. The constants are the single source of truth.
 *   POST /api/activate   {license_key, server_ip, fingerprint, hostname, product, version} -> {ok,status,message,...}
 *   POST /api/check      {license_key, server_ip, fingerprint}                              -> {ok,status,message,...}
 *
 * Local state (key + last verified result) lives under /var/lib/smpro/license,
 * root-only 0600. The plugin re-checks periodically (page load if stale + a daily
 * heartbeat from the notify cron) so a revoked/expired key eventually stops validating.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

define('SMPRO_LIC_BASE',          'https://plugins.hostguard.org'); // primary API host (proxied)
// Fallbacks, tried IN ORDER when the primary is unreachable or answers a proxy challenge.
//
// EVERY host here must be PROXIED. A direct-to-origin name is deliberately not used any more: publishing one
// puts the origin address in public DNS, which is exactly what the proxy exists to prevent, and it also lands
// that address in each customer's cached state the first time the fallback is taken. Losing the "bypass the
// proxy" escape hatch is the accepted trade - the answer to a proxy challenge is a WAF bypass rule for the API
// paths, not a public route around the proxy.
//
// A host that does not resolve fails fast and the loop moves on, so a name may be listed before its DNS record
// exists. SMPRO_LIC_BASE itself must ALWAYS resolve: helpers.php (geoip) and update.php (update download) use
// it directly with no fallback of their own - which is why the primary is the host verified to answer every
// /api/* route, not merely the one that answers a static file.
define('SMPRO_LIC_BASE_FALLBACKS', 'https://dl.hostguard.org');
// Back-compat only: read solely if SMPRO_LIC_BASE_FALLBACKS is undefined, which cannot happen in this build.
// Mirrors the list above so no direct-to-origin host is named anywhere in the source.
define('SMPRO_LIC_BASE_FALLBACK', 'https://dl.hostguard.org');
define('SMPRO_LIC_DIR',     SMPRO_VARLIB . '/license');
define('SMPRO_LIC_STATE',   SMPRO_LIC_DIR . '/state.json');
define('SMPRO_LIC_PRODUCT', 'smpro');
// STABLE hardware-fingerprint salt - intentionally fixed (NOT the slug) so renaming the plugin never
// invalidates existing license bindings. Keep this value forever; it is the product's permanent id.
define('SMPRO_LIC_FP_SALT', 'smprov1');
// 2-way online enforcement: the plugin must "see" the license server continuously.
// Reads use a signed cache kept warm by a background refresh; every state-changing
// ACTION does a blocking, replay-proof challenge-response with the server. If the
// server has not been reached within SMPRO_LIC_GRACE, the whole plugin stops.
define('SMPRO_LIC_REFRESH', 300);           // page-load: warm the cache if older than this (5 min, async)
define('SMPRO_LIC_HEARTBEAT', 300);         // cron/background re-check cadence (5 min)
// Fail-open policy (per product decision): a *reachability* problem must not brick a paying customer.
// As long as we hold a cryptographically valid, server-bound verdict, keep running through outages for
// up to GRACE_OUTAGE. Only a confirmed tamper (forged signature/values) - never a mere outage - arms the
// disable/uninstall path. The old hard 10-minute stop was fail-CLOSED and would brick on any short outage.
define('SMPRO_LIC_GRACE',        600);            // soft: target re-check cadence (warm the cache within 10 min)
define('SMPRO_LIC_GRACE_OUTAGE', 48 * 3600);      // hard ceiling: keep working at most 48h unreachable, then lock (graduated degradation kicks in earlier - see smpro_lic_grace_phase)
define('SMPRO_LIC_TAMPER_KILL',  24 * 3600);      // after a CONFIRMED tamper (forged state OR endpoint redirect): 24h then auto-uninstall unless the license server sends a reset
define('SMPRO_LIC_DORMANT_GRACE', 48 * 3600);     // after the license STOPS (expired/suspended/revoked) for 48h -> disable ALL functions (dormant; resumes on renewal)
// Connection-loss escalation ("sync"): a graduated, per-license, OPT-IN ladder for a server that stops getting a
// fresh SIGNED verdict. Teeth are INERT unless the signed payload carries sync_enabled=true for THIS license, so a
// real outage of OUR license server can never mass-affect customers. Silence alone tops out at a REVERSIBLE stop;
// it NEVER deletes - deletion needs either a confirmed tamper (SMPRO_LIC_TAMPER_KILL path) or, only for a license
// the operator has explicitly flagged suspected-pirate (signed sync_purge=true), a 48h silence purge.
define('SMPRO_SYNC_W1',     1 * 3600);            // stage 1: soft "reconnecting" banner
define('SMPRO_SYNC_W2',     3 * 3600);            // stage 2: stronger banner
define('SMPRO_SYNC_NOTIFY', 6 * 3600);            // stage 3: best-effort notify the customer on their channels
define('SMPRO_SYNC_STOP',  24 * 3600);            // stage 4: reversible FULL STOP (resumes instantly on a fresh exchange)
define('SMPRO_SYNC_PURGE', 48 * 3600);            // stage 5: DELETE - ONLY when signed sync_purge=true for this license
if (!defined('SMPRO_LIC_ENFORCE')) define('SMPRO_LIC_ENFORCE', true);  // true = hard-gate: nothing opens without a valid license

// Pinned RSA public key of the license server. The success response is RSA-SHA256
// signed over its payload; the plugin verifies that signature with THIS key, so a
// fake/MITM server (or a swapped public key) cannot forge a "valid" verdict.
define('SMPRO_LIC_PUBKEY',
    "-----BEGIN PUBLIC KEY-----\n"
  . "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAunb5J4c2tLci4VDOfl+Y\n"
  . "Tejm3YraSVKrG7OmVi8P49reDPRxYw/v69D8eKRTKJ+kDtxhOPkfsiL73fvlVgaA\n"
  . "ZvdmB3lZWcWYSdbrJH4fBXksSzyC4WS8YWgau8AL0DLuAC42JPYf8LXJU13v7orA\n"
  . "hlkTE6ot4kil1KIeApZNd2q0HABVp1fQO28woJ6mFwLh9QVoe9rQ+09bMqALlRNi\n"
  . "6loxJTkzExFGymuL6ymd16NYKuOiQH36PMOjkNL+2vZu9b1YxDPk2vLazbP2/ncy\n"
  . "lqCu8NN8o+SbQTl9sS4kESFQMvXl98AvafUGwu3sBsHcDNea7AUSAsB60gwn//L+\n"
  . "XU4TrWbX/l7iJQwcLSWpiAld68SZRCOnFt+XfoQ798PDyAOfjQATa1ubKHoL4OGJ\n"
  . "sBGTflnqlDaxqhydsajLUfpl0s91mjFXfdBnna3F6dQ1V6bUANyZ8p8UdSIwj9xP\n"
  . "R6kDqa5RppgElTLerNp8Zis17ZRj3yqwttDPw+2Az/vplUzOPVMWUfM6/N/RL0QW\n"
  . "nbmBSxivM9LP2WNXNZhVWxPPws4kZOzByBaBxf+0lR0vQPX/grQpDOKXYA5OlGNT\n"
  . "qj9yNR4wXCrEMLc1+dezSKDspD0vt0nO1LcxOM6HUFGyQV27qcCFb40MyKR5NYFm\n"
  . "dHMXmtMfIhtjdHEhCtxfxPMCAwEAAQ==\n"
  . "-----END PUBLIC KEY-----\n");
/** Verify the RSA-SHA256 signature of a license block against the pinned key. */
function smpro_lic_verify_signature($lic) {
    if (!is_array($lic)) return false;
    $payload = $lic['payload'] ?? null;
    $sig = base64_decode((string)($lic['signature'] ?? ''), true);
    if (!is_array($payload) || $sig === false || $sig === '' || !function_exists('openssl_verify')) return false;
    $data = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    $pk = @openssl_pkey_get_public(SMPRO_LIC_PUBKEY);
    if (!$pk) return false;
    return openssl_verify($data, $sig, $pk, OPENSSL_ALGO_SHA256) === 1;
}

/* ---------------- server identity ---------------- */
/** Stable per-server fingerprint (machine-id + hostname), hashed. */
function smpro_lic_fingerprint() {
    static $fp = null;
    if ($fp !== null) return $fp;
    $mid = '';
    foreach (['/etc/machine-id', '/var/lib/dbus/machine-id'] as $f) { if (is_readable($f)) { $mid = trim((string)@file_get_contents($f)); if ($mid !== '') break; } }
    if ($mid === '') $mid = trim((string)@shell_exec('hostid 2>/dev/null')) . php_uname('n');
    // full 64-char SHA-256 hex - the license server validates /^[a-f0-9]{64}$/ and rejects anything shorter
    return $fp = hash('sha256', $mid . '|' . php_uname('n') . '|' . SMPRO_LIC_FP_SALT);
}
/** The server's main public IP (cPanel mainip -> bound IPs -> hostname lookup). */
function smpro_lic_server_ip() {
    foreach (['/var/cpanel/mainip', '/var/cpanel/mainserverip'] as $f) {
        $ip = trim((string)@file_get_contents($f));
        if (filter_var($ip, FILTER_VALIDATE_IP)) return $ip;
    }
    if (function_exists('smpro_server_ips')) {
        foreach (smpro_server_ips() as $ip) {
            if (filter_var($ip, FILTER_VALIDATE_IP) && !preg_match('/^(127\.|::1|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.)/', $ip)) return $ip;
        }
    }
    $ip = trim((string)@shell_exec("hostname -I 2>/dev/null | awk '{print $1}'"));
    return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '';
}

/* ---------------- state ---------------- */
function smpro_lic_state() {
    if (isset($GLOBALS['_smpro_lic_state'])) return $GLOBALS['_smpro_lic_state'];
    $d = is_file(SMPRO_LIC_STATE) ? json_decode((string)@file_get_contents(SMPRO_LIC_STATE), true) : null;
    return $GLOBALS['_smpro_lic_state'] = is_array($d) ? $d : [];
}
function smpro_lic_state_save($s) {
    $GLOBALS['_smpro_lic_state'] = $s;   // keep the in-request cache consistent with what we just saved
    @is_dir(SMPRO_LIC_DIR) || @mkdir(SMPRO_LIC_DIR, 0700, true); @chmod(SMPRO_LIC_DIR, 0700);
    $tmp = SMPRO_LIC_STATE . '.tmp';
    if (@file_put_contents($tmp, json_encode($s, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX) === false) return false;
    @chmod($tmp, 0600);
    return @rename($tmp, SMPRO_LIC_STATE);
}
function smpro_lic_key() { return (string)(smpro_lic_state()['key'] ?? ''); }

/* ---------------- API ---------------- */
/** POST JSON to the license server. Returns [http_code, decoded|null, raw].
 *  A browser User-Agent is sent because the server sits behind Cloudflare, whose
 *  managed bot-challenge 403s plain curl/library agents. */
function smpro_lic_ua() {
    return 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 SafetyMonitorPro/' . (defined('SMPRO_VERSION') ? SMPRO_VERSION : '1');
}
function smpro_lic_api($path, array $fields, $timeout = 20, $pinIp = '') {
    // The body carries the license key + fingerprint. Inlining it with -d would expose it in the process table
    // (ps / /proc/<pid>/cmdline) to any local user for the life of the curl child. Write it to a 0600 temp file
    // (root-readable only) and feed curl with --data-binary @file so the secret never reaches argv.
    $bodyFile = @tempnam(@sys_get_temp_dir() ?: '/tmp', 'smpl');
    if ($bodyFile === false) $bodyFile = SMPRO_VARLIB . '/.licreq.' . getmypid();
    @file_put_contents($bodyFile, json_encode($fields, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    @chmod($bodyFile, 0600);
    // %{remote_ip} is appended so callers can learn the REAL server IP (cached for later --resolve use). $pinIp,
    // when given, forces curl to connect to that IP regardless of DNS/hosts - lets a report bypass a hosts redirect.
    // Try the primary API host; if it does NOT return an authoritative verdict (timeout, Cloudflare
    // challenge/HTML, transport error) transparently retry the DIRECT fallback host, so a proxy hiccup
    // never turns into a false license failure. An authoritative JSON verdict (even "invalid") is final.
    $bases = [SMPRO_LIC_BASE];
    // Every configured direct fallback, in order, de-duplicated against the primary. A host that does not resolve
    // yet simply fails fast and the loop moves to the next one, so listing a name before its DNS exists is safe.
    $fbRaw = defined('SMPRO_LIC_BASE_FALLBACKS') ? SMPRO_LIC_BASE_FALLBACKS
           : (defined('SMPRO_LIC_BASE_FALLBACK') ? SMPRO_LIC_BASE_FALLBACK : '');
    foreach (explode(',', (string)$fbRaw) as $fb) {
        $fb = rtrim(trim($fb), '/');
        if ($fb === '' || $fb === rtrim(SMPRO_LIC_BASE, '/') || in_array($fb, $bases, true)) continue;
        if (!preg_match('#^https://[a-z0-9.-]+$#i', $fb)) continue;      // hosts only - never a path or scheme-less value
        $bases[] = $fb;
    }
    $code = 0; $j = null; $body = ''; $remoteIp = '';
    foreach ($bases as $base) {
        $host = parse_url($base, PHP_URL_HOST);
        // A pinned IP is an OPTIMISATION for the tamper-report path (it defeats an /etc/hosts redirect), never a
        // requirement. Any cached address goes stale - a proxied host rotates edge IPs, and the origin itself can
        // be renumbered - so when a pinned attempt fails we repeat the SAME host through normal DNS. The hostname
        // is the contract; an IP is only ever a hint.
        $attempts = ($pinIp !== '' && $host !== null && $host !== '') ? [$pinIp, ''] : [''];
        foreach ($attempts as $useIp) {
            $cmd = 'curl -sS -m ' . (int)$timeout . ' -w ' . escapeshellarg("\n%{http_code}\n%{remote_ip}")
                 // curl --resolve is HOST:PORT:ADDRESS, and the ADDRESS is the part that must be bracketed
                 // when it is IPv6 (the host name never is). Unbracketed, curl mis-parses it and the pinned
                 // attempt fails - harmless here only because the unpinned retry follows, but still wrong.
                 . ($useIp !== '' ? ' --resolve ' . escapeshellarg($host . ':443:' . (function_exists('smpro_ip_bracket') ? smpro_ip_bracket($useIp) : $useIp)) : '')
                 . ' -A ' . escapeshellarg(smpro_lic_ua())
                 . ' -X POST ' . escapeshellarg($base . $path)
                 . ' -H ' . escapeshellarg('Content-Type: application/json')
                 . ' -H ' . escapeshellarg('Accept: application/json')
                 . ' --data-binary ' . escapeshellarg('@' . $bodyFile);
            $raw = (string)@shell_exec($cmd . ' 2>/dev/null');
            $parts = explode("\n", $raw);
            $remoteIp = trim((string)array_pop($parts));            // last line
            $code     = (int)trim((string)array_pop($parts));       // second-to-last
            $body     = implode("\n", $parts);
            $j        = json_decode($body, true);
            if ($code > 0) break;                                   // reached something - no point retrying unpinned
        }
        if (smpro_lic_is_authoritative($code, $j)) break;       // final verdict - stop, don't try fallback
    }
    @unlink($bodyFile);
    return [$code, $j, $body, $remoteIp];
}
/** A response is "authoritative" only when the app returned parseable JSON.
 *  Cloudflare blocks (403/503 HTML) and transport errors are NOT a license verdict. */
function smpro_lic_is_authoritative($code, $j) {
    return is_array($j) && $code >= 200 && $code < 500;
}
/** Common request payload for this server. */
/** Lightweight server telemetry sent with the license check (powers the panel's Servers tab). */
function smpro_lic_telemetry() {
    $t = ['version' => defined('SMPRO_VERSION') ? SMPRO_VERSION : ''];
    $la = function_exists('sys_getloadavg') ? sys_getloadavg() : [];
    if ($la) { $t['load1'] = round((float)$la[0], 2); $t['load15'] = round((float)($la[2] ?? $la[0]), 2); }
    $cores = (int)trim((string)@shell_exec('nproc 2>/dev/null'));
    if (!$cores && is_readable('/proc/cpuinfo')) $cores = substr_count((string)@file_get_contents('/proc/cpuinfo'), 'processor');
    if ($cores) $t['cpu_cores'] = $cores;
    if (is_readable('/proc/meminfo') && preg_match('/MemTotal:\s+(\d+)/', (string)@file_get_contents('/proc/meminfo'), $m)) $t['ram_mb'] = (int)round($m[1] / 1024);
    if (is_readable('/proc/uptime')) $t['uptime_sec'] = (int)floatval((string)@file_get_contents('/proc/uptime'));
    foreach (glob('/sys/class/net/*/address') ?: [] as $f) { $if = basename(dirname($f)); if ($if === 'lo' || strpos($if, 'veth') === 0 || strpos($if, 'docker') === 0 || strpos($if, 'br-') === 0) continue; $mac = trim((string)@file_get_contents($f)); if ($mac && $mac !== '00:00:00:00:00:00') { $t['mac'] = $mac; break; } }
    $t['os'] = substr(is_readable('/etc/redhat-release') ? trim((string)@file_get_contents('/etc/redhat-release')) : (php_uname('s') . ' ' . php_uname('r')), 0, 120);
    if (is_readable('/usr/local/cpanel/version')) $t['panel'] = 'cPanel ' . trim((string)@file_get_contents('/usr/local/cpanel/version'));
    // number of hosting accounts on this server (one entry per cPanel user)
    $acc = 0;
    foreach (glob('/var/cpanel/users/*') ?: [] as $f) { $bn = basename($f); if ($bn !== '' && $bn[0] !== '.') $acc++; }
    if (!$acc && is_readable('/etc/trueuserdomains')) $acc = count(array_filter(array_map('trim', explode("\n", (string)@file_get_contents('/etc/trueuserdomains')))));
    if ($acc) $t['accounts'] = $acc;
    // metrics rollup digest (folds host signals into a short integrity hash carried with telemetry)
    if (class_exists('Smpro_Rollup')) { $ms = Smpro_Rollup::sample((string)($t['mac'] ?? '')); if ($ms !== '') $t['m_sig'] = $ms; }
    return $t;
}
function smpro_lic_payload($key) {
    return [
        'license_key' => trim((string)$key),
        'server_ip'   => smpro_lic_server_ip(),
        'fingerprint' => smpro_lic_fingerprint(),
        'hostname'    => php_uname('n'),
        'product'     => SMPRO_LIC_PRODUCT,
        'version'     => defined('SMPRO_VERSION') ? SMPRO_VERSION : '',
        'telemetry'   => smpro_lic_telemetry(),
    ];
}
/** Normalise a server response into our state record.
 *  Reads the signed nested payload (license.payload), VERIFIES its RSA signature
 *  against the pinned key, and only marks "ok" when the signed payload is bound to
 *  THIS server (ip + fingerprint) - so a forged or replayed response cannot validate. */
function smpro_lic_normalise($key, $code, $j) {
    $j = is_array($j) ? $j : [];
    $lic     = is_array($j['license'] ?? null) ? $j['license'] : [];
    $payload = is_array($lic['payload'] ?? null) ? $lic['payload'] : [];
    $sigOk   = smpro_lic_verify_signature($lic);
    $serverIp = smpro_lic_server_ip();
    $fp       = smpro_lic_fingerprint();
    $statusStr = strtolower((string)($payload['status'] ?? $j['status'] ?? ($j['state'] ?? '')));

    // VALID only when: server said ok, the payload's signature verifies, the status is good,
    // and the signed binding matches this exact server (defeats forgery + replay to another box).
    $okFlag = !empty($j['ok'])
        && $sigOk
        && in_array($statusStr, ['active', 'valid', 'licensed'], true)
        && ((string)($payload['bound_ip'] ?? '') === $serverIp)
        && ((string)($payload['fingerprint'] ?? '') === $fp);

    // "bad_request" = the server did not receive our fields - an integration problem, not a verdict.
    $msg = (string)($j['message'] ?? $j['msg'] ?? '');
    if ($statusStr === 'bad_request') {
        $msg = 'The license server did not receive the request fields. This is usually Cloudflare blocking the plugin\'s server-to-server POST — allow the /api/ path (skip Bot Fight Mode / managed challenge) for this server. (server said: ' . $msg . ')';
    }
    // surface a clear reason when the server said ok but verification/binding failed
    if (!empty($j['ok']) && $statusStr !== 'bad_request' && !$okFlag) {
        if (!$sigOk) $msg = 'License response failed signature verification — it may be forged or relayed. ' . $msg;
        elseif ((string)($payload['bound_ip'] ?? '') !== $serverIp || (string)($payload['fingerprint'] ?? '') !== $fp)
            $msg = 'License is bound to a different server (IP/fingerprint mismatch). ' . $msg;
    }
    return [
        'key'           => trim((string)$key),
        'ok'            => (bool)$okFlag,
        'sig_verified'  => (bool)$sigOk,
        'status'        => $statusStr ?: ($okFlag ? 'valid' : 'invalid'),
        'message'       => $msg,
        'expiry'        => (string)($payload['expires_at'] ?? $j['expiry'] ?? $j['expires_at'] ?? ''),
        'plan'          => (string)($payload['plan'] ?? $j['plan'] ?? ''),
        'product'       => (string)($payload['product'] ?? $j['product'] ?? ''),
        'features'      => is_array($payload['features'] ?? null) ? array_values($payload['features']) : [],
        'owner'         => (string)($payload['client_name'] ?? $payload['owner'] ?? $j['owner'] ?? ''),
        'bound_ip'      => (string)($payload['bound_ip'] ?? ''),
        'bound_hostname'=> (string)($payload['bound_hostname'] ?? ''),
        'issued_at'     => (string)($payload['issued_at'] ?? ''),
        'http'          => (int)$code,
        'last_check'    => time(),
        'server_ip'     => $serverIp,
        'fingerprint'   => $fp,
        'raw'           => $j,
    ];
}
/** Activate a key on this server, persist + return state. */
function smpro_lic_activate($key) {
    [$code, $j] = smpro_lic_api('/api/activate', smpro_lic_payload($key));
    // a Cloudflare block / transport failure is not an activation verdict - report it as such
    if (!smpro_lic_is_authoritative($code, $j)) {
        $st = smpro_lic_normalise($key, $code, []);
        $st['ok'] = false; $st['status'] = 'unreachable'; $st['unreachable'] = true;
        $st['message'] = 'Could not reach the license server (HTTP ' . (int)$code . '). It may be behind a Cloudflare challenge — allow /api/* for this server\'s IP.';
        smpro_lic_state_save($st);
        if (function_exists('smpro_audit')) smpro_audit('license_activate', ['ok' => false, 'status' => 'unreachable', 'http' => $code]);
        return $st;
    }
    $st = smpro_lic_normalise($key, $code, $j); $st['unreachable'] = false;
    smpro_lic_state_save($st);
    if (function_exists('smpro_audit')) smpro_audit('license_activate', ['ok' => $st['ok'], 'status' => $st['status'], 'http' => $code]);
    return $st;
}
/** Re-check the stored (or given) key, persist + return state. Keeps last-good within the grace window on transport failure. */
function smpro_lic_check($key = null) {
    $key = $key !== null ? $key : smpro_lic_key();
    if (trim((string)$key) === '') return smpro_lic_state();
    [$code, $j, $body, $remoteIp] = smpro_lic_api('/api/check', smpro_lic_payload($key));
    // not authoritative (Cloudflare HTML block / 5xx / transport) -> keep previous verdict inside the grace window
    if (!smpro_lic_is_authoritative($code, $j)) {
        $prev = smpro_lic_state();
        // ANTI-BYPASS: a FAILED/unreachable check (e.g. customer blackholes the license domain in /etc/hosts)
        // must NOT refresh the "last successful check" clock - otherwise the outage grace never expires and the
        // plugin runs forever. last_check = last ATTEMPT (for display); last_ok = last AUTHORITATIVE success only.
        if (!isset($prev['last_ok'])) $prev['last_ok'] = (int)($prev['last_check'] ?? 0);   // migrate existing installs once
        $prev['last_check'] = time(); $prev['http'] = (int)$code; $prev['unreachable'] = true;   // last_ok deliberately untouched
        if (empty($prev['key'])) $prev['key'] = trim((string)$key);
        smpro_lic_state_save($prev);
        return $prev;
    }
    $st = smpro_lic_normalise($key, $code, $j); $st['unreachable'] = false; $st['last_ok'] = time();   // authoritative success -> advance the grace clock
    // cache the REAL server IP, but ONLY from a signature-verified response (so a fake server can't poison it).
    // Used later to deliver a tamper report via --resolve even when /etc/hosts redirects the license host.
    if (!empty($st['sig_verified']) && $remoteIp !== '' && filter_var($remoteIp, FILTER_VALIDATE_IP)) $st['srv_ip'] = $remoteIp;
    else { $prevIp = (string)(smpro_lic_state()['srv_ip'] ?? ''); if ($prevIp !== '') $st['srv_ip'] = $prevIp; }
    smpro_lic_state_save($st);
    if (function_exists('smpro_audit')) smpro_audit('license_check', ['ok' => $st['ok'], 'status' => $st['status'], 'http' => $code]);
    // Pull-based remote command from the panel's Servers tab - execute ONLY in cron (CLI), never on a web hit.
    if (php_sapi_name() === 'cli' && is_array($j) && !empty($j['command']) && is_array($j['command'])) smpro_lic_run_command($j['command'], $key, !empty($st['sig_verified']));
    return $st;
}
/** Execute a server-issued command. Cron-only; the server delivers each once.
 *  SECURITY: this `command` object is NOT covered by the RSA signature (only license.payload is), so a
 *  compromised/rogue license server or a TLS-terminating relay could forge it. Therefore the channel may ONLY
 *  trigger SAFE, self-verifying actions: `update` is RSA-signature-pinned internally (a forged command cannot
 *  push malicious code - only force a genuinely-signed forward upgrade); `restart` merely re-activates.
 *  It must NEVER DELETE local state - revocation/suspension arrives via the SIGNED status in /api/check
 *  (smpro_lic_is_valid crypto-verifies that), so the destructive `revoke` command is intentionally IGNORED here
 *  (closes the unsigned fleet-wide kill-switch). */
function smpro_lic_run_command($cmd, $key, $signed = false) {
    $op = strtolower((string)($cmd['command'] ?? '')); if ($op === '') return;
    $res = 'noop';
    // SECURITY: the `command` object is NOT covered by the RSA signature, so a rogue/redirected license host or a
    // TLS-terminating relay could forge it. STATE-CHANGING control ops (restart/reset/disable/enable) are therefore
    // honored ONLY when this same /api/check response carried a VALID RSA signature ($signed) - a fake server that
    // the licensee redirected the host to cannot produce one, so it can no longer clear the sticky anti-tamper
    // kill-switch or DoS the plugin. `update` is self-verifying (the package is RSA-pinned to the offline release
    // key), and `revoke` is always ignored (revocation arrives via the signed status).
    if ($op === 'update' && function_exists('smpro_upd_apply')) { $r = smpro_upd_apply(); $res = !empty($r['ok']) ? ('updated:' . ($r['message'] ?? '')) : ('fail:' . ($r['message'] ?? '')); }
    elseif ($op === 'revoke')  { $res = 'ignored_unsigned_revoke'; }   // do NOT blank state from an unsigned network command; revocation comes via the signed status
    elseif (!$signed)          { $res = 'ignored_unsigned:' . $op; }   // reject restart/reset/disable/enable on an unsigned (forgeable) response
    elseif ($op === 'restart') { smpro_lic_activate($key); $res = 'reactivated'; }
    // RESET: the admin investigated a flagged tamper and cleared it on the license server -> cancel the kill clock
    // and resume. This is the ONLY thing that clears a sticky environment-tamper marker (root cannot self-clear it).
    elseif ($op === 'reset')   { smpro_lic_tlm_clear(); smpro_lic_sync_clear(); $s = smpro_lic_state(); unset($s['tamper_at']); smpro_lic_state_save($s); smpro_lic_dormant_clear(); smpro_lic_activate($key); $res = 'reset_cleared'; }
    // DISABLE: admin-forced full stop (folds into smpro_ctl_disabled via the control mode).
    elseif ($op === 'disable' && function_exists('smpro_ctl_save')) { $c = smpro_ctl_get(); $c['mode'] = 'disabled'; $c['updated_at'] = time(); $c['actor'] = 'license-server'; smpro_ctl_save($c); $res = 'disabled'; }
    elseif ($op === 'enable'  && function_exists('smpro_ctl_save')) { $c = smpro_ctl_get(); $c['mode'] = 'enabled'; $c['reenable_at'] = 0; $c['updated_at'] = time(); $c['actor'] = 'license-server'; smpro_ctl_save($c); $res = 'enabled'; }
    if (function_exists('smpro_audit')) smpro_audit('license_command', ['op' => $op, 'id' => (string)($cmd['id'] ?? ''), 'result' => $res]);
}
/** Forget the local license (does not revoke server-side). */
function smpro_lic_deactivate() {
    smpro_lic_state_save([]);
    if (function_exists('smpro_audit')) smpro_audit('license_deactivate', []);
    return [];
}

/* ---------------- channel-endpoint health (deliberate-redirect detection) ----------------
 * Folded into the normal heartbeat (NO dedicated cron, neutral name) and self-throttled to ~3h. Detects a
 * deliberate redirect of the license endpoint - e.g. an /etc/hosts override of the license host to a non-license
 * IP - by requiring TWO independent signals so a plain outage NEVER trips it:
 *   A) the license host is pinned in /etc/hosts to some IP, AND
 *   B) a live check from that path does NOT return a valid RSA-signed verdict (i.e. it's not the real server).
 * On confirmation it sets a STICKY marker that ONLY a server 'reset' (after admin investigation) can clear -
 * root undoing the hosts edit does NOT self-clear it - and reports to the license server. */
function smpro_lic_host() { $h = parse_url(SMPRO_LIC_BASE, PHP_URL_HOST); return is_string($h) ? strtolower($h) : ''; }
/** Signal A - the IP the API host resolves to via a local hosts pin ("" = none). Reads like resolver diagnostics. */
function smpro_lic_resolv_check() {
    $host = smpro_lic_host(); if ($host === '') return '';
    $lines = @file('/etc/hosts', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!is_array($lines)) return '';
    foreach ($lines as $line) {
        $line = trim(preg_replace('/#.*$/', '', (string)$line)); if ($line === '') continue;
        $p = preg_split('/\s+/', $line); if (count($p) < 2) continue;
        $ip = array_shift($p);
        foreach ($p as $name) if (strtolower($name) === $host) return $ip;
    }
    return '';
}
/** Sticky diagnostics flag (unix ts; 0 = clean). Set by the sync probe, cleared ONLY by a server reset. Named
 *  to look like ordinary telemetry state so it doesn't stand out as an enforcement marker. */
function smpro_lic_tlm_at() { return (int)(smpro_lic_state()['tlm_at'] ?? 0); }
function smpro_lic_tlm_set($meta = '') {
    $s = smpro_lic_state();
    if (!empty($s['tlm_at'])) return (int)$s['tlm_at'];                 // keep first-seen
    $s['tlm_at'] = time(); $s['tlm_x'] = substr((string)$meta, 0, 200);
    smpro_lic_state_save($s);
    return (int)$s['tlm_at'];
}
function smpro_lic_tlm_clear() {
    $s = smpro_lic_state();
    if (isset($s['tlm_at']) || isset($s['tlm_x'])) { unset($s['tlm_at'], $s['tlm_x']); smpro_lic_state_save($s); }
}
/** Best-effort telemetry push to the server (admin alert). Sends via the cached REAL server IP using --resolve so
 *  it bypasses a hosts redirect of the license host and actually reaches us. Falls back to normal DNS if no cached
 *  IP. (If the attacker also IP-firewalls us, this won't arrive - the server-side dead-man is the backstop.) */
function smpro_lic_tlm_push($meta) {
    $key = smpro_lic_key(); if (trim((string)$key) === '') return;
    $p = smpro_lic_payload($key); $p['meta'] = substr((string)$meta, 0, 300);
    $pin = (string)(smpro_lic_state()['srv_ip'] ?? '');
    @smpro_lic_api('/api/telemetry', $p, 12, $pin);
}
/** Flag a confirmed endpoint redirect: set the sticky marker (immediate full stop), alert the server, start the
 *  24h kill clock. */
function smpro_lic_tlm_flag($meta) {
    smpro_lic_tlm_set($meta);
    if (function_exists('smpro_audit')) smpro_audit('telemetry_sync', ['meta' => $meta]);
    smpro_lic_tlm_push($meta);
    smpro_lic_kill_tick();
}
/** Sync/diagnostics probe. Cheap on clean systems (returns immediately unless the API host is pinned locally in
 *  /etc/hosts). When it IS pinned, TWO ways to confirm a redirect:
 *   - FAST (no network, runs on web + cron): the host is pinned ELSEWHERE than the real (signature-verified)
 *     server AND the stored signed state no longer verifies -> flag instantly. A pin to the real server, or a
 *     plain outage, NEVER flags - that is what keeps a legit Cloudflare-bypass pin from self-bricking.
 *   - CONFIRM (network, CLI/cron only, light throttle): cache still looks ok but the host is pinned -> do one
 *     live check; if it doesn't return a valid signature, it's a fake server -> flag. CLI-gated so web never blocks. */
function smpro_lic_tlm_sync() {
    if (defined('SMPRO_LIC_ENFORCE') && !SMPRO_LIC_ENFORCE) return;
    $s = smpro_lic_state();
    if (empty($s['key'])) return;                                      // not activated -> nothing to do
    if (!empty($s['tlm_at'])) { smpro_lic_kill_tick(); return; }       // already flagged -> just advance the clock
    $ovr = smpro_lic_resolv_check();
    if ($ovr === '') return;                                           // signal A absent -> nothing (excludes plain outages)
    // B1 FIX - a pin to the REAL, signature-verified server IP is LEGITIMATE (it is exactly the Cloudflare-bypass
    // practice we recommend), NOT a redirect. Only a pin pointing somewhere OTHER than the trusted server IP is a
    // signal. If no trusted srv_ip is cached yet (can't happen post-activation - it is cached from a signed response),
    // never flag on the pin alone; the signature checks below stay the real gate.
    $trust = (string)($s['srv_ip'] ?? '');
    if ($trust === '' || $ovr === $trust) return;                      // no trusted IP, or pinned to the real server -> never flag
    // FAST PATH - no network: host is pinned ELSEWHERE AND the stored signed verdict no longer verifies (a fake
    // server cannot produce a valid signature). A plain OUTAGE no longer flags here - only a real signature failure.
    if (!smpro_lic_verify_state($s)[0]) { smpro_lic_tlm_flag('resolv ' . smpro_lic_host() . '=>' . $ovr . ' (cached)'); return; }
    // CONFIRM PATH - network, CLI/cron only (never block a web request), light 5-min throttle
    if (php_sapi_name() !== 'cli') return;
    $stamp = SMPRO_LIC_DIR . '/.tlm';
    if (is_file($stamp) && (smpro_lic_now() - (int)@filemtime($stamp)) < 300) return;
    @is_dir(SMPRO_LIC_DIR) || @mkdir(SMPRO_LIC_DIR, 0700, true); @touch($stamp); @chmod($stamp, 0600);
    [$code, $j] = smpro_lic_api('/api/check', smpro_lic_payload($s['key']));
    $lic = (is_array($j) && is_array($j['license'] ?? null)) ? $j['license'] : [];
    // M1 FIX - a non-authoritative reply (Cloudflare 403/503/timeout) is an OUTAGE, not a redirect. Never flag on it;
    // let the next authoritative check decide. Only an AUTHORITATIVE reply whose signature fails is a genuine fake.
    if (!smpro_lic_is_authoritative($code, $j)) return;
    if (smpro_lic_verify_signature($lic)) return;                      // authoritative AND validly signed -> still the real server -> fine
    smpro_lic_tlm_flag('resolv ' . smpro_lic_host() . '=>' . $ovr . ' http ' . (int)$code);  // authoritative but bad signature -> fake server
}

/* ---------------- validity ---------------- */
/** Is the expiry in the past? '' / 0 = no expiry. */
function smpro_lic_expired($expiry) {
    $expiry = trim((string)$expiry);
    if ($expiry === '' || $expiry === '0') return false;
    $ts = is_numeric($expiry) ? (int)$expiry : strtotime($expiry);
    return $ts && $ts < smpro_lic_now();                // monotonic now - clock rollback cannot un-expire a license
}
/**
 * Re-verify the SIGNED payload stored in state, cryptographically, on every load.
 * This is what makes state.json non-forgeable: editing "ok":true by hand is useless
 * unless the file also carries a payload whose RSA-SHA256 signature verifies against
 * the pinned key AND is bound to THIS server. Without the private key that cannot be
 * produced, so a hand-written/copied state is rejected. Returns [ok, expiry].
 */
function smpro_lic_verify_state($s) {
    $lic = is_array($s['raw']['license'] ?? null) ? $s['raw']['license'] : null;
    if (!is_array($lic) || !smpro_lic_verify_signature($lic)) return [false, ''];
    $p = is_array($lic['payload'] ?? null) ? $lic['payload'] : [];
    // binding: the signed payload must name THIS exact server (defeats copying a valid
    // state.json from a licensed box onto an unlicensed one)
    if ((string)($p['bound_ip'] ?? '') !== smpro_lic_server_ip())   return [false, ''];
    if ((string)($p['fingerprint'] ?? '') !== smpro_lic_fingerprint()) return [false, ''];
    $status = strtolower((string)($p['status'] ?? ''));
    if (!in_array($status, ['active', 'valid', 'licensed'], true))   return [false, ''];
    // expiry comes from the SIGNED payload, never the mutable top-level field
    return [true, (string)($p['expires_at'] ?? '')];
}
/**
 * The server-SIGNED timestamp of the last genuine check (payload.issued_at, set to date('c') by the
 * license server on every /api/check and covered by the RSA signature). Returns a unix ts, or 0 if absent
 * or the signature does not verify. ROOT CANNOT FORGE OR EXTEND THIS - editing it breaks the signature -
 * so it is the only trustworthy clock for the offline grace ceiling. A blackholed/replayed response keeps
 * its OLD signed issued_at, so grace counts down from the last real contact and cannot be reset locally.
 */
function smpro_lic_signed_ts($s) {
    $lic = is_array($s['raw']['license'] ?? null) ? $s['raw']['license'] : null;
    if (!is_array($lic) || !smpro_lic_verify_signature($lic)) return 0;
    $p = is_array($lic['payload'] ?? null) ? $lic['payload'] : [];
    $t = strtotime((string)($p['issued_at'] ?? ''));
    if ($t) smpro_lic_hwm_bump($t);                      // advance the monotonic clock from a TRUSTED (signed) time
    return $t ?: 0;
}
/** Read a field from the SIGNED payload - returns $default unless the RSA signature verifies. The only
 *  trustworthy source for operator directives (sync_enabled / sync_stop / sync_purge); root cannot forge it. */
function smpro_lic_signed_field($s, $key, $default = null) {
    $lic = is_array($s['raw']['license'] ?? null) ? $s['raw']['license'] : null;
    if (!is_array($lic) || !smpro_lic_verify_signature($lic)) return $default;
    $p = is_array($lic['payload'] ?? null) ? $lic['payload'] : [];
    return array_key_exists($key, $p) ? $p[$key] : $default;
}

/** Server-gated VALUE: the per-license secret from the SIGNED verdict (empty without a valid, server-bound
 *  verdict). Features encrypt their server-delivered data with this; a patched gate can't fabricate it. */
function smpro_lic_feat_key() { return (string)smpro_lic_signed_field(smpro_lic_state(), 'feat_key', ''); }
/* PAIR (Stage 1) - the derived pairing key K + public pair_id arrive INSIDE the signed verdict (server emits them);
 * read them through the verified signed-field accessor so a forged/unsigned state yields nothing. Raw base secret S
 * never reaches the plugin. The rolling code is computed by Smpro_Rollup below and rides the telemetry as "m_sig". */
function smpro_lic_pair_key() { return (string)smpro_lic_signed_field(smpro_lic_state(), 'pair_key', ''); }
function smpro_lic_pair_id()  { return (string)smpro_lic_signed_field(smpro_lic_state(), 'pair_id', ''); }
/* PAIR (Stage 3) - REVERSIBLE soft stop: the server sets a SIGNED pair_stop=true only for an opt-in (pair_enforce)
 * license after a sustained beacon miss. Honored like the sync soft-stop (License/Plugin-Control stay reachable,
 * NEVER destructive); it self-heals - the moment a valid signed verdict returns pair_stop=false the plugin resumes.
 * Default off (server emits false) -> inert. Only ever true via a VERIFIED signed field, so a forged state can't fake it. */
function smpro_lic_pair_stopped() {
    if (defined('SMPRO_LIC_ENFORCE') && !SMPRO_LIC_ENFORCE) return false;
    return smpro_lic_signed_field(smpro_lic_state(), 'pair_stop', false) === true;
}
/** Diagnostics rollup - folds host signals into a short keyed integrity digest carried with telemetry. The keyed
 *  equation lives inside this class (not a loose function) and is scrambled in the obfuscated build; trust still
 *  rests on the key K (from the signed verdict) + RSA, never on the formula being hidden. T uses the monotonic
 *  server-anchored clock and ctx folds MAC|Host - IP is deliberately excluded (it churns and must never gate). */
class Smpro_Rollup {
    public static function sample(string $mac): string {
        $k = function_exists('smpro_lic_pair_key') ? smpro_lic_pair_key() : '';
        if ($k === '') return '';                                                  // no key yet (first boot/unbound) -> emit nothing
        $now = function_exists('smpro_lic_now') ? smpro_lic_now() : time();
        $t   = (int)floor($now / 3600);                                            // 1h step on the monotonic signed clock
        $ctx = hash('sha256', strtolower(trim($mac)) . '|' . strtolower(trim((string)php_uname('n'))));
        return substr(hash_hmac('sha256', 'beat|' . $t . '|' . $ctx, $k), 0, 20);
    }
}

/* ---------------- connection-loss escalation ("sync") - per-license, OPT-IN, brick-safe ----------------
 * INERT unless the SIGNED payload says sync_enabled=true for THIS license, so a real outage of our own license
 * server can never mass-affect customers. Silence tops out at a REVERSIBLE stop (24h) - it NEVER deletes. A
 * 48h-silence DELETE happens ONLY for a license the operator explicitly flagged suspected-pirate (signed
 * sync_purge=true) AND only when BOTH the clamped dark accumulator AND the unforgeable signed-time backstop agree
 * (so a clock jump can't false-delete and a .sync edit can't dodge). Neutral naming; comments stripped in build. */
function smpro_lic_sync_file() { return SMPRO_LIC_DIR . '/.sync'; }
function smpro_lic_sync_get() { $f = smpro_lic_sync_file(); $j = is_file($f) ? json_decode((string)@file_get_contents($f), true) : null; return is_array($j) ? $j : []; }
function smpro_lic_sync_save(array $x) { @is_dir(SMPRO_LIC_DIR) || @mkdir(SMPRO_LIC_DIR, 0700, true); @file_put_contents(smpro_lic_sync_file(), json_encode($x, JSON_UNESCAPED_SLASHES), LOCK_EX); @chmod(smpro_lic_sync_file(), 0600); }
function smpro_lic_sync_clear() { $f = smpro_lic_sync_file(); if (is_file($f)) @unlink($f); }
/** Opted-in (signed) AND not 'hold' AND no competing track (tamper / negative verdict) - else the ladder is OFF. */
function smpro_lic_sync_on($s = null) {
    if (defined('SMPRO_LIC_ENFORCE') && !SMPRO_LIC_ENFORCE) return false;
    $s = $s ?: smpro_lic_state();
    if (!smpro_lic_signed_field($s, 'sync_enabled', false)) return false;
    if ((string)smpro_lic_signed_field($s, 'sync_stop', 'normal') === 'hold') return false;
    if (function_exists('smpro_lic_tamper_at') && smpro_lic_tamper_at() > 0) return false;   // tamper track owns it
    if (function_exists('smpro_lic_tlm_at') && smpro_lic_tlm_at() > 0) return false;
    $st = strtolower((string)($s['status'] ?? ''));
    if (in_array($st, ['suspended','expired','invalid','revoked','tampered','binding_mismatch','not_activated','disabled'], true)) return false;
    return true;
}
/** Clamped, attempt-gated "dark" accumulator (seconds of proven-disconnected time) - resists clock jumps. */
function smpro_lic_sync_dark() { return (int)(smpro_lic_sync_get()['dark'] ?? 0); }
function smpro_lic_sync_advance($fresh) {
    if ($fresh) { smpro_lic_sync_clear(); return 0; }                  // recovered -> reset the whole ladder
    $x = smpro_lic_sync_get(); $now = smpro_lic_now();
    $last = (int)($x['last_tick'] ?? $now);
    $delta = $now - $last; if ($delta < 0) $delta = 0; if ($delta > 3600) $delta = 3600;   // cap one tick at +1h (cron is 15m; bounds a clock jump)
    $x['dark'] = (int)($x['dark'] ?? 0) + $delta; $x['last_tick'] = $now;
    smpro_lic_sync_save($x);
    return (int)$x['dark'];
}
/** Escalation stage 0..4 from the accumulator (0 when not opted-in). 5/purge is decided separately (signed backstop). */
function smpro_lic_sync_stage() {
    if (!smpro_lic_sync_on()) return 0;
    $d = smpro_lic_sync_dark();
    if ($d >= SMPRO_SYNC_STOP)   return 4;
    if ($d >= SMPRO_SYNC_NOTIFY) return 3;
    if ($d >= SMPRO_SYNC_W2)     return 2;
    if ($d >= SMPRO_SYNC_W1)     return 1;
    return 0;
}
/** Reversible full-stop (folds into smpro_ctl_disabled as a SOFT lock - License/Plugin-Control stay reachable). */
function smpro_lic_sync_disabled() { return smpro_lic_sync_on() && smpro_lic_sync_dark() >= SMPRO_SYNC_STOP; }
/** Destructive purge gate - signed suspected-pirate flag AND both clocks (accumulator + signed-time) past 48h. */
function smpro_lic_sync_purge_due() {
    $s = smpro_lic_state();
    if (!smpro_lic_sync_on($s)) return false;
    if (!smpro_lic_signed_field($s, 'sync_purge', false)) return false;
    if (smpro_lic_sync_dark() < SMPRO_SYNC_PURGE) return false;
    $anchor = smpro_lic_signed_ts($s); if ($anchor <= 0) $anchor = (int)($s['last_ok'] ?? $s['last_check'] ?? 0);
    if ($anchor <= 0) return false;
    return (smpro_lic_now() - $anchor) >= SMPRO_SYNC_PURGE;            // signed backstop must ALSO agree
}
/** [level,title,body] for the current stage; page-load safe (no network). null when nothing to show. */
function smpro_lic_sync_banner() {
    $st = smpro_lic_sync_stage();
    if ($st <= 0) return null;
    if ($st <= 2) return ['info', 'Reconnecting to the main server…', 'The plugin is re-trying automatically — no action needed yet.'];
    return ['crit', 'Could not connect to the main server', 'Please contact technical support or verify license integrity.'];
}
/** Driver - cron (CLI: may notify + purge) and page-load (read-only: accumulate + banner only). */
function smpro_lic_sync_tick() {
    if (!smpro_lic_sync_on()) { smpro_lic_sync_clear(); return; }      // not opted-in / tamper / negative -> no ladder
    $fresh = !(function_exists('smpro_lic_is_unreachable') && smpro_lic_is_unreachable());
    $prev = smpro_lic_sync_stage();
    smpro_lic_sync_advance($fresh);
    if ($fresh) return;
    $stage = smpro_lic_sync_stage();
    $cli = (php_sapi_name() === 'cli');
    if ($stage > $prev && function_exists('smpro_audit')) smpro_audit('sync_stage', ['stage' => $stage, 'dark_h' => round(smpro_lic_sync_dark() / 3600, 1)]);
    if ($cli && $stage >= 3) {
        $x = smpro_lic_sync_get(); $bucket = (int)floor(smpro_lic_now() / SMPRO_SYNC_NOTIFY);
        if ((int)($x['notified'] ?? -1) !== $bucket && function_exists('smpro_notify')) {
            @smpro_notify('sync_loss', 'License server unreachable',
                'This server has not reached the main license server for ' . round(smpro_lic_sync_dark() / 3600, 1) . 'h. '
                . 'Please contact technical support or verify license integrity.', ['severity' => 'critical'], true);
            $x['notified'] = $bucket; smpro_lic_sync_save($x);
        }
    }
    if ($cli && smpro_lic_sync_purge_due()) smpro_self_uninstall();    // suspected-pirate + 48h silence (both clocks) -> delete
}
/* ---------------- monotonic clock (anti clock-rollback) ----------------
 * Root controls the system clock (date -s / faketime), so every "X seconds since Y" check that reads time()
 * can be defeated by rolling the clock back (un-expire a license, freeze the grace/dormancy/tamper timers).
 * We keep a forward-only HIGH-WATER MARK of the highest SERVER-SIGNED time ever observed (issued_at, which the
 * server bounds to real time and root cannot forge). smpro_lic_now() never returns a value below that mark, so a
 * backward clock jump cannot shrink any elapsed-time decision. Defense-in-depth: the mark file is unsigned and a
 * determined root can lower it, but the attack now requires editing this file AND rolling the clock AND keeping the
 * domain blackholed - and any single genuine check re-raises the mark. */
function smpro_lic_hwm_file() { return SMPRO_LIC_DIR . '/.hwm'; }
function smpro_lic_hwm_get()  { $f = smpro_lic_hwm_file(); return is_file($f) ? (int)trim((string)@file_get_contents($f)) : 0; }
function smpro_lic_hwm_bump($ts) {
    $ts = (int)$ts; if ($ts <= 0 || $ts > time() + 86400) return;   // ignore absurd future values
    if ($ts > smpro_lic_hwm_get()) {
        @is_dir(SMPRO_LIC_DIR) || @mkdir(SMPRO_LIC_DIR, 0700, true);
        @file_put_contents(smpro_lic_hwm_file(), (string)$ts, LOCK_EX); @chmod(smpro_lic_hwm_file(), 0600);
    }
}
/** Monotonic "now": never earlier than the highest server-signed time ever seen (defeats system-clock rollback). */
function smpro_lic_now() { $t = time(); $h = smpro_lic_hwm_get(); return $h > $t ? $h : $t; }
/**
 * Confirmed-tamper watch. A *forged* state - one that carries a key AND a structured signed
 * licence block but whose RSA signature/binding does NOT verify - can only come from someone
 * editing state.json or copying it from another box. That is the single thing that arms the
 * disable->uninstall path. A fresh/un-activated install (no key) or a plain outage is NOT tamper.
 * Records the first-seen timestamp in state.tamper_at (cleared the moment a valid verdict returns).
 * Returns the tamper_at unix ts (0 = clean). Side-effect-light: only writes when the flag changes.
 */
function smpro_lic_tamper_at() {
    $s = smpro_lic_state();
    $hasKey      = !empty($s['key']);
    $looksSigned = is_array($s['raw']['license']['payload'] ?? null) && isset($s['raw']['license']['signature']);
    [$ok] = $hasKey ? smpro_lic_verify_state($s) : [false];
    $tampered = $hasKey && $looksSigned && !$ok;   // present + structured + fails crypto = forged
    $cur = (int)($s['tamper_at'] ?? 0);
    if ($tampered && $cur === 0)        { $s['tamper_at'] = time(); smpro_lic_state_save($s); return (int)$s['tamper_at']; }
    if (!$tampered && $cur !== 0)       { unset($s['tamper_at']); smpro_lic_state_save($s); return 0; }
    return $tampered ? $cur : 0;
}

/** Current validity from cached state (no network) - fail-OPEN through outages, fail-CLOSED on tamper/expiry. */
/**
 * INDEPENDENT integrity tie (defense-in-depth #4): re-verify the signed manifest + critical-file hashes from a
 * SEPARATE code path than the UI gate (smpro_integrity_gate at index.php). Binding it into is_valid means an
 * attacker who patches OUT the single UI gate call still can't run the plugin - the license itself reports
 * invalid on a critical-file tamper. FAIL-OPEN: no manifest (raw/dev installs) or integrity module not loaded
 * (lean workers) -> returns true, exactly like the existing gate, so nothing legitimate is ever blocked. */
function smpro_lic_integrity_ok() {
    if (!function_exists('smpro_integrity_check')) return true;       // module not loaded (lean worker) -> don't block
    static $c = null; if ($c !== null) return $c;                     // once per request
    $r = smpro_integrity_check(function_exists('smpro_integrity_critical_files') ? smpro_integrity_critical_files() : []);
    return $c = (!empty($r['ok']) || !empty($r['skip']));             // skip = no/blank manifest -> fail-open
}
function smpro_lic_is_valid() {
    if (defined('SMPRO_LIC_ENFORCE') && !SMPRO_LIC_ENFORCE) return true;  // dev-mode bypass
    if (!smpro_lic_integrity_ok()) return false;        // critical-file tamper -> invalid (independent of the UI gate)
    $s = smpro_lic_state();
    if (empty($s['key'])) return false;                 // not activated -> locked (not tampered)
    // AUTHORITATIVE negative verdict from the server (suspended/expired/invalid/revoked/binding) -> lock
    // IMMEDIATELY, no grace. Grace is ONLY for transport outages ($s['unreachable']), never for a real "no".
    if (empty($s['unreachable']) && in_array((string)($s['status'] ?? ''), ['suspended','expired','invalid','revoked','tampered','binding_mismatch','not_activated','disabled'], true)) return false;
    [$ok, $expiry] = smpro_lic_verify_state($s);
    if (!$ok) return false;                             // signature/binding fails -> locked (tamper handled separately)
    if (smpro_lic_expired($expiry)) return false;       // server-signed expiry passed -> locked
    // FAIL-OPEN: a cryptographically valid, server-bound verdict keeps the plugin running through
    // connectivity outages for up to GRACE_OUTAGE. Only after that long a silence do we stop.
    // The grace clock is the server-SIGNED issued_at (unforgeable) - NOT the local last_ok/last_check, which
    // root can edit. A blackholed or replayed response keeps its OLD signed issued_at, so editing local
    // timestamps, freezing state.json, or pointing the license domain at a fake server can no longer extend
    // the grace ceiling. last_ok is only a fallback for very old states signed before issued_at existed.
    $graceTs = smpro_lic_signed_ts($s);
    if ($graceTs <= 0) $graceTs = (int)($s['last_ok'] ?? $s['last_check'] ?? 0);
    if ((smpro_lic_now() - $graceTs) > SMPRO_LIC_GRACE_OUTAGE) return false;
    smpro_lic_dormant_clear();                          // licensed again -> cancel any dormancy clock
    return true;
}
/**
 * DORMANCY: once the license has been INVALID (expired/suspended/revoked/not-activated - a real "no", not a
 * transport outage) continuously for SMPRO_LIC_DORMANT_GRACE (48h), the whole plugin goes dormant - every
 * background tool stops and the UI locks (smpro_ctl_disabled folds this in). It is NOT uninstalled; renewing the
 * license clears the clock and everything resumes automatically. (Tamper has its own separate 24h->uninstall path.)
 */
function smpro_lic_dormant_file() { return SMPRO_LIC_DIR . '/.invalid_since'; }
function smpro_lic_dormant_clear() { $f = smpro_lic_dormant_file(); if (is_file($f)) @unlink($f); }
function smpro_lic_dormant() {
    if (defined('SMPRO_LIC_ENFORCE') && !SMPRO_LIC_ENFORCE) return false;   // dev-mode: never dormant
    if (smpro_lic_is_valid()) return false;                                 // valid (also clears the clock) -> active
    // NOTE: short transport outages are already covered - is_valid() stays TRUE through the 48h outage grace
    // (measured from the SIGNED issued_at), so we only reach here for a REAL stop OR a prolonged outage/blackhole past the
    // ceiling. Both should go dormant. (Blackholing the license domain can no longer keep it running forever.)
    // a CONFIRMED TAMPER has its own separate 24h->uninstall path - leave it to that, don't dormancy-stop it
    if (function_exists('smpro_lic_tamper_at') && smpro_lic_tamper_at() > 0) return false;
    $f = smpro_lic_dormant_file();
    $since = is_file($f) ? (int)trim((string)@file_get_contents($f)) : 0;
    if ($since <= 0) { $since = smpro_lic_now(); @is_dir(SMPRO_LIC_DIR) || @mkdir(SMPRO_LIC_DIR, 0700, true); @file_put_contents($f, (string)$since); @chmod($f, 0600); return false; }   // m1: monotonic clock, matches the compare below
    return (smpro_lic_now() - $since) >= SMPRO_LIC_DORMANT_GRACE;
}
/** True when validity failed ONLY because we could not reach the server (vs. a real invalid/expired/tampered license). */
function smpro_lic_is_unreachable() {
    $s = smpro_lic_state();
    if (empty($s['key'])) return false;
    [$ok] = smpro_lic_verify_state($s);
    if (!$ok) return false;                             // signature/binding problem = tamper, not connectivity
    return !empty($s['unreachable']) || (time() - (int)($s['last_check'] ?? 0)) > SMPRO_LIC_GRACE;
}
/**
 * GRADUATED DEGRADATION during an unreachable grace window. Returns a phase 0..3 measured from the
 * server-SIGNED last-contact timestamp (unforgeable), so a root user cannot reset it locally:
 *   0 = licensed & reachable (or recently so)        -> full functionality, no warning
 *   1 = unreachable, early grace (< 40% of ceiling)  -> subtle "server unreachable" note only
 *   2 = unreachable, mid grace  (40-75%)             -> prominent warning + shed HEAVY/optional background work
 *   3 = unreachable, late grace (> 75%, lock imminent) or grace already expired -> critical warning, only core stays
 * Phase is 0 whenever the license is genuinely valid AND not flagged unreachable - degradation only ever
 * applies while we cannot confirm the license, never to a healthy licensed box.
 */
function smpro_lic_grace_phase() {
    $s = smpro_lic_state();
    if (empty($s['key'])) return 0;
    [$ok] = smpro_lic_verify_state($s);
    if (!$ok) return 0;                                  // tamper/binding handled by their own paths, not here
    if (empty($s['unreachable']) && !( (time() - (int)($s['last_check'] ?? 0)) > SMPRO_LIC_GRACE )) return 0;
    $graceTs = smpro_lic_signed_ts($s);
    if ($graceTs <= 0) $graceTs = (int)($s['last_ok'] ?? $s['last_check'] ?? 0);
    if ($graceTs <= 0) return 0;
    $elapsed = smpro_lic_now() - $graceTs;
    if ($elapsed <= 0) return 0;
    $ceil = SMPRO_LIC_GRACE_OUTAGE;
    if ($elapsed >= $ceil)          return 3;            // grace blown - lock imminent / already locked
    if ($elapsed >= 0.75 * $ceil)   return 3;
    if ($elapsed >= 0.40 * $ceil)   return 2;
    return 1;
}
/** Seconds left before the unreachable grace ceiling locks the plugin (0 if not in a grace window). */
function smpro_lic_grace_remaining() {
    if (smpro_lic_grace_phase() <= 0) return 0;
    $s = smpro_lic_state();
    $graceTs = smpro_lic_signed_ts($s);
    if ($graceTs <= 0) $graceTs = (int)($s['last_ok'] ?? $s['last_check'] ?? 0);
    return max(0, SMPRO_LIC_GRACE_OUTAGE - (smpro_lic_now() - $graceTs));
}
/** Standard "stopped" message shown when the server can't be consulted. */
function smpro_lic_support_message() {
    return 'Could not verify the license with the license server — the plugin is paused. Please contact technical support to check the license.';
}

/* ---------------- tamper kill-switch (fail-open: ONLY a confirmed tamper, never an outage) ----------------
 * Lock message + countdown shown when the signed state was tampered with. */
function smpro_lic_tamper_message() {
    $t = smpro_lic_tamper_at();
    $left = $t > 0 ? max(0, SMPRO_LIC_TAMPER_KILL - (smpro_lic_now() - $t)) : SMPRO_LIC_TAMPER_KILL;
    $h = (int)ceil($left / 3600);
    return 'License integrity check failed (signed values were tampered with). The plugin is disabled and will auto-remove in ~' . $h . 'h unless a valid license is restored. Please contact support.';
}

/**
 * DESTRUCTIVE - fully remove the plugin. Called ONLY by smpro_lic_kill_tick() after a CONFIRMED tamper
 * (forged signed values) has persisted past SMPRO_LIC_TAMPER_KILL (24h). Re-confirms the exact condition
 * here as a second guard, so a stale/cleared flag or a mere outage can never trigger removal. The file
 * deletion runs detached (the running request can't delete its own loaded files cleanly) and is restricted
 * to the plugin's own well-formed `.../smpro` paths.
 */
function smpro_self_uninstall() {
    if (!defined('SMPRO_LIC_ENFORCE') || !SMPRO_LIC_ENFORCE) return false;
    // re-confirm one of the two destructive conditions, each independently re-derived here as a second guard:
    //  (1) a CONFIRMED tamper - forged signed state (tamper_at) OR a deliberate endpoint redirect (tlm_at) - older
    //      than the 24h tamper-kill window; OR (2) a suspected-pirate license (signed sync_purge) that has been
    //      silent past 48h on BOTH the clamped accumulator and the unforgeable signed-time backstop.
    $t  = max((int)smpro_lic_tamper_at(), (int)smpro_lic_tlm_at());
    $tamperDue = ($t > 0 && (smpro_lic_now() - $t) >= SMPRO_LIC_TAMPER_KILL);
    $purgeDue  = (function_exists('smpro_lic_sync_purge_due') && smpro_lic_sync_purge_due());
    if (!$tamperDue && !$purgeDue) return false;
    $base = realpath(SMPRO_BASE) ?: (string)SMPRO_BASE;
    $vl   = (string)SMPRO_VARLIB; $vlog = (string)SMPRO_VARLOG;
    // path sanity - refuse to act unless these are the expected smpro paths (never blank / never '/')
    if (strpos($base, '/smpro') === false || strpos($vl, '/smpro') === false || strlen($base) < 10) return false;

    if (function_exists('smpro_audit')) smpro_audit('self_uninstall', ['reason' => 'license_tamper', 'tamper_at' => $t, 'host' => php_uname('n')]);
    if (function_exists('smpro_notify')) { @smpro_notify('license_tamper', 'Plugin self-removed (license tamper)',
        'A confirmed license tamper persisted past 24h on ' . php_uname('n') . ' — the plugin uninstalled itself.', ['severity' => 'critical'], true); }

    $unreg = '/usr/local/cpanel/bin/unregister_appconfig';
    if (is_executable($unreg)) @shell_exec(escapeshellarg($unreg) . ' ' . escapeshellarg(SMPRO_SLUG) . ' >/dev/null 2>&1');
    foreach (glob('/etc/cron.d/' . SMPRO_SLUG . '-*') ?: [] as $cf) @unlink($cf);   // every cron of the product: the four named here left ~20 others invoking a missing script every minute
    // detached removal of data dirs + the install dir, then rebuild the WHM menu
    // code and crons only: the data directory holds the quarantine (the ONLY copy of a quarantined file), the
    // remediation backups and the emergency-undo book, which belong to the customers, not to the licence
    $rm = 'sleep 3; rm -rf ' . escapeshellarg($base)
        . '; [ -x /usr/local/cpanel/scripts/rebuild_whm_chrome ] && /usr/local/cpanel/scripts/rebuild_whm_chrome >/dev/null 2>&1';
    @shell_exec('nohup sh -c ' . escapeshellarg($rm) . ' >/dev/null 2>&1 &');
    return true;
}

/** Cron/page hook: self-uninstall iff a confirmed tamper (forged signed state OR a flagged diagnostics marker)
 *  has persisted past the kill window. No-op in every other case. */
function smpro_lic_kill_tick() {
    if (!defined('SMPRO_LIC_ENFORCE') || !SMPRO_LIC_ENFORCE) return;
    $t = max((int)smpro_lic_tamper_at(), (int)smpro_lic_tlm_at());
    if ($t > 0 && (smpro_lic_now() - $t) >= SMPRO_LIC_TAMPER_KILL) smpro_self_uninstall();
}

/* ---------------- per-action challenge-response (2-way, replay-proof) ---------------- */
/** Persist just the freshness fields without disturbing other state (bypasses the static cache). */
function smpro_lic_touch_state($patch) {
    $d = is_file(SMPRO_LIC_STATE) ? json_decode((string)@file_get_contents(SMPRO_LIC_STATE), true) : [];
    if (!is_array($d)) $d = [];
    foreach ($patch as $k => $v) $d[$k] = $v;
    smpro_lic_state_save($d);
}
/**
 * Verify a server authorization response for a specific (action, nonce). All of these
 * must hold: app returned ok + the RSA signature verifies against the pinned key + the
 * signed payload echoes OUR nonce (anti-replay) + names THIS action + is bound to THIS
 * server (ip+fingerprint) + status active + not expired. Pure (no I/O) -> unit-testable.
 */
function smpro_lic_verify_authorization($action, $nonce, $code, $j) {
    if (!smpro_lic_is_authoritative($code, $j)) return false;
    $lic = is_array($j['license'] ?? null) ? $j['license'] : [];
    $p   = is_array($lic['payload'] ?? null) ? $lic['payload'] : [];
    return !empty($j['ok'])
        && smpro_lic_verify_signature($lic)
        && (string)$nonce !== '' && hash_equals((string)$nonce, (string)($p['nonce'] ?? '__'))  // anti-replay
        && (string)($p['action'] ?? '') === (string)$action                          // this exact action
        && (string)($p['bound_ip'] ?? '') === smpro_lic_server_ip()                  // this exact server
        && (string)($p['fingerprint'] ?? '') === smpro_lic_fingerprint()
        && in_array(strtolower((string)($p['status'] ?? '')), ['active', 'valid', 'licensed'], true)
        && !smpro_lic_expired($p['expires_at'] ?? '');
}
/**
 * Ask the license server to AUTHORIZE one action, right now. Sends a fresh client
 * nonce; the server returns an RSA-signed payload that must echo that nonce and bind
 * to this server + this action. Verifying all of that defeats replay, forgery and
 * relay. Returns true only on a live, valid, server-issued authorization.
 */
function smpro_lic_authorize($action) {
    if (!defined('SMPRO_LIC_ENFORCE') || !SMPRO_LIC_ENFORCE) return true;
    $key = smpro_lic_key();
    if ($key === '') return false;
    if (!function_exists('random_bytes')) return false;
    $nonce = bin2hex(random_bytes(16));
    $fields = smpro_lic_payload($key);
    $fields['action'] = (string)$action;
    $fields['nonce']  = $nonce;
    [$code, $j] = smpro_lic_api('/api/authorize', $fields, 8);   // short timeout: this is inline with an action
    // No authoritative answer = no authorization. Actions get NO grace (reads do).
    if (!smpro_lic_is_authoritative($code, $j)) {
        smpro_lic_touch_state(['last_action_check' => time(), 'unreachable' => true, 'http' => (int)$code]);
        return false;
    }
    $okFlag = smpro_lic_verify_authorization($action, $nonce, $code, $j);
    // a successful live authorization also counts as "server reached now" -> keeps reads warm
    if ($okFlag) smpro_lic_touch_state(['last_check' => time(), 'last_action_check' => time(), 'unreachable' => false, 'http' => (int)$code]);
    else smpro_lic_touch_state(['last_action_check' => time(), 'http' => (int)$code]);
    return $okFlag;
}
/** Gate an action on a live authorization; on failure, stop with the support message (JSON) and exit. */
function smpro_lic_require_authorized($action) {
    if (!defined('SMPRO_LIC_ENFORCE') || !SMPRO_LIC_ENFORCE) return;
    if (smpro_lic_authorize($action)) return;
    // Resilience grace: a single INLINE authorize can hiccup in the web/CGI context (curl via shell_exec,
    // Cloudflare, or an 8s timeout under high load) even when the license is perfectly valid. If the
    // cryptographically-signed license state still verifies AND was confirmed live recently (the cron
    // heartbeat keeps last_check fresh), allow the action instead of blocking the admin on a transient blip.
    $s = function_exists('smpro_lic_state') ? smpro_lic_state() : [];
    if (!empty($s['ok']) && function_exists('smpro_lic_verify_state')) {
        $v = smpro_lic_verify_state($s); $valid = is_array($v) ? !empty($v[0]) : (bool)$v;
        $grace = defined('SMPRO_LIC_GRACE') ? SMPRO_LIC_GRACE : 600;
        if ($valid && (time() - (int)($s['last_check'] ?? 0)) < $grace) {
            if (function_exists('smpro_audit')) smpro_audit('license_action_grace', ['action' => (string)$action]);
            return;
        }
    }
    if (function_exists('smpro_audit')) smpro_audit('license_action_denied', ['action' => (string)$action]);
    http_response_code(403);
    header('Content-Type: application/json');
    echo json_encode([
        'ok' => false, 'license_required' => true, 'support' => true,
        'error' => smpro_lic_support_message(),
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}
/** Spawn a NON-blocking background re-check so active browsing keeps the cache warm without latency. */
function smpro_lic_refresh_async() {
    $s = smpro_lic_state();
    if (empty($s['key'])) return;
    if ((time() - (int)($s['last_check'] ?? 0)) < SMPRO_LIC_REFRESH) return;       // fresh enough
    $lock = SMPRO_LIC_DIR . '/.refresh.lock';
    if (is_file($lock) && (time() - (int)@filemtime($lock)) < 60) return;          // one refresh per minute max
    @is_dir(SMPRO_LIC_DIR) || @mkdir(SMPRO_LIC_DIR, 0700, true);
    @touch($lock);
    $php = defined('PHP_BINARY') && PHP_BINARY ? PHP_BINARY : '/usr/local/cpanel/3rdparty/bin/php';
    $script = (defined('SMPRO_BASE') ? SMPRO_BASE : __DIR__ . '/..') . '/bin/lic_refresh.php';
    if (is_file($script)) @shell_exec('setsid ' . escapeshellarg($php) . ' ' . escapeshellarg($script) . ' >/dev/null 2>&1 &');
}
/** Bootstrap freshness: block-check only when past the hard window (we're about to gate); else warm async. */
function smpro_lic_ensure_fresh() {
    $s = smpro_lic_state();
    if (empty($s['key'])) return;
    $age = time() - (int)($s['last_check'] ?? 0);
    if ($age > SMPRO_LIC_GRACE)      smpro_lic_check();          // blocking: one call decides stop-or-go
    elseif ($age > SMPRO_LIC_REFRESH) smpro_lic_refresh_async();  // non-blocking warm-up
}
/** Friendly product name for display (the server's internal product codes -> the plugin's name). */
function smpro_lic_product_name($code) {
    $code = strtolower(trim((string)$code));
    static $map = ['safety_monitor' => 'Safety Monitor Pro', 'smpro' => 'Safety Monitor Pro', 'guirkhunter' => 'Safety Monitor Pro'];
    if (isset($map[$code])) return $map[$code];
    return $code !== '' ? ucwords(str_replace(['_', '-'], ' ', $code)) : '';
}
/** "Licensed to" value: the client name, falling back to the bound hostname so it is never blank. */
function smpro_lic_owner_display() {
    $s = smpro_lic_state();
    $owner = trim((string)($s['owner'] ?? ''));
    if ($owner !== '') return $owner;
    return trim((string)($s['bound_hostname'] ?? ''));
}
/** Whether the active license includes a given feature flag (from the signed payload). */
function smpro_lic_has_feature($name) {
    if (!smpro_lic_is_valid()) return false;
    $f = smpro_lic_signed_field(smpro_lic_state(), 'features', []);   // read from the SIGNED verdict, not the mutable state.json copy - a valid-license holder can't unlock unpurchased features by editing state.json
    return is_array($f) && in_array($name, $f, true);
}
/**
 * Is a section allowed? A section with no 'feature' is core (allowed whenever licensed).
 * A section with a 'feature' is allowed only if the license includes that feature.
 * If the license sent no features list at all, don't feature-gate (validity alone suffices).
 */
function smpro_lic_section_allowed($feature) {
    if (!smpro_lic_is_valid()) return false;
    if ($feature === '' || $feature === null) return true;
    $f = smpro_lic_signed_field(smpro_lic_state(), 'features', []);   // read from the SIGNED verdict, not the mutable state.json copy - a valid-license holder can't unlock unpurchased features by editing state.json
    if (!is_array($f) || !$f) return true;            // no feature list -> don't gate by feature
    return in_array($feature, $f, true);
}
/** Refresh the cached state if it is older than $maxAge (used by page load + cron heartbeat). */
function smpro_lic_refresh_if_stale($maxAge = SMPRO_LIC_REFRESH) {
    $s = smpro_lic_state();
    if (empty($s['key'])) return $s;
    if ((time() - (int)($s['last_check'] ?? 0)) < $maxAge) return $s;
    return smpro_lic_check();
}
/** Cron entry point - keep the license fresh. */
function smpro_lic_heartbeat() { return smpro_lic_refresh_if_stale(SMPRO_LIC_HEARTBEAT + mt_rand(0, 150)); }   // +jitter: de-pattern the re-check cadence
