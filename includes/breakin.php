<?php
/**
 * includes/breakin.php - reading failed logins, grouping them by network, and judging what each network is doing.
 *
 * These functions used to live in modules/account-audit.php. Page modules execute a router at include time - a
 * DB query, layout output, an audit write - so nothing in cron or on the CLI can ever require one. That made the
 * whole break-in judgement reachable only from a browser: the rules that block an attack could be pressed by a
 * person on the page and could not run unattended. An attack that starts at 3am ran until somebody opened the
 * page.
 *
 * Moved here verbatim, by PHP's own tokenizer rather than by a text cut, so the page and the worker judge with
 * exactly the same code and can never drift into two opinions about what an attack is.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

/* The ignore list these functions read. It was defined in modules/account-audit.php and stayed there when the
 * functions moved out, so every call from cron died with "Undefined constant SMPRO_AA_BFIGN" - the break-in
 * rules worker has been dying on its first line, every ten minutes, since the move. Guarded, because the page
 * still defines it too and a second define() is a notice.
 *
 * Moving functions without their constants is now the second time in this session; the regression below looks
 * for the whole class rather than this one name. */
if (!defined('SMPRO_AA_BFIGN')) define('SMPRO_AA_BFIGN', SMPRO_VARLIB . '/reports/bf_ignore.json');

/* ---------- small json helpers ---------- */
function smpro_aa_json_load($p) { $d = is_file($p) ? json_decode((string)@file_get_contents($p), true) : null; return is_array($d) ? $d : []; }

function smpro_aa_json_save($p, $d) { @is_dir(dirname($p)) || @mkdir(dirname($p), 0700, true); $t = $p . '.tmp'; @file_put_contents($t, json_encode($d, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE), LOCK_EX); @rename($t, $p); @chmod($p, 0600); }

/** Streams the last $lines of $file (a generator - iterate once). It used to return the whole window as an array,
 *  which at 200k lines cost ~300MB and killed the page under the cPanel CLI's 128M cap. */
function smpro_aa_tail($file, $lines) {
    if (!is_readable($file)) return;
    $n = max(1000, min(500000, (int)$lines));
    yield from smpro_run_lines('tail -n ' . $n . ' ' . escapeshellarg($file), SMPRO_TIMEOUT_NORMAL);
}

/* ---------- cPanel mapping ---------- */
function smpro_aa_user_domains($user) {
    static $c = [];
    if ($user === '' || !smpro_is_cpanel_user($user)) return [];
    if (isset($c[$user])) return $c[$user];
    $d = [];
    $f = '/var/cpanel/users/' . $user;
    if (is_readable($f)) foreach (file($f, FILE_IGNORE_NEW_LINES) ?: [] as $ln)
        if (preg_match('/^(?:DNS\d*|DOMAIN)\s*=\s*(\S+)/i', $ln, $m)) $d[strtolower($m[1])] = true;
    return $c[$user] = array_keys($d);
}

function smpro_aa_needles($wanted) {
    if ($wanted === '') return [];
    $n = [strtolower($wanted)];
    foreach (smpro_aa_user_domains($wanted) as $d) $n[] = $d;
    return $n;
}

function smpro_aa_match($needles, $actor, $evidence) {
    if (!$needles) return true;
    $a = strtolower($actor);
    foreach ($needles as $n) {
        if ($n === '') continue;
        if ($a === $n) return true;
        if (preg_match('/\b' . preg_quote($n, '/') . '\b/i', $evidence)) return true;
    }
    return false;
}

/** Resolve the cPanel account owning an actor (email user@domain -> owner). */
function smpro_aa_resolve_account($actor) {
    static $map = null;
    if ($map === null) {
        $map = [];
        if (is_readable('/etc/userdomains')) foreach (file('/etc/userdomains', FILE_IGNORE_NEW_LINES) ?: [] as $ln)
            if (preg_match('/^([^:]+):\s*(\S+)/', $ln, $m)) $map[strtolower(trim($m[1]))] = trim($m[2]);
    }
    if (strpos($actor, '@') !== false) {
        $dom = strtolower(substr(strrchr($actor, '@'), 1));
        if (isset($map[$dom])) return $map[$dom];
    }
    if (smpro_is_cpanel_user($actor)) return $actor;
    return '';
}

/* ---------- time ---------- */
function smpro_aa_ts($raw) {
    $raw = trim($raw);
    if (preg_match('#^\d{1,2}/\w{1,3}/\d{4}:#', $raw) || preg_match('#^\d{1,2}/\d{1,2}/\d{4}:#', $raw))
        $raw = preg_replace('/:/', ' ', $raw, 1);
    return strtotime($raw) ?: 0;
}

/**
 * IP intelligence for this page.
 *
 * Delegates to the shared smpro_ip_intel() in helpers.php. This page used to carry its own whois-only copy that
 * never consulted the local GeoIP databases, so once its per-page cap was spent every further row rendered
 * "Provider: lookup limit reached" - while the database pulled nightly from the licence server sat fresh and
 * unread on disk. The shared helper reads those databases first and caps only the network enrichment, so there
 * is no longer a second implementation here to drift away from it.
 */
function smpro_aa_ip_intel($ip) {
    // Local databases only. The shared helper's network enrichment is one whois per NEW address with a 4-second
    // timeout, up to forty per request: on a server with hundreds of fresh attacker addresses a day the Account
    // Audit page waited on that chain and "opened with difficulty". Providers for new addresses come from the
    // one bulk call the page makes first (smpro_ip_intel_bulk, 14-second cap for the whole set), never per row.
    $r = smpro_ip_intel($ip, false);
    $scope = (string)($r['scope'] ?? 'external');
    if ($scope === 'invalid' || $scope === 'local') { $r['source'] = $scope; return $r; }
    if (($r['source'] ?? '') === '') $r['source'] = 'unavailable';
    return $r;
}

/* ---------- which events survive to be counted and shown ---------- */

/**
 * Filter events by country using IP intelligence.
 *  'all'     -> no filter
 *  'foreign' -> external IPs outside the configured home region (unknown externals kept,
 *              so suspicious un-resolved foreign IPs are never hidden)
 *  '<CC>'    -> only that 2-letter country
 * Attaches ['intel'] to each surviving event so the view reuses it.
 */
/** Localhost (127.0.0.1 / ::1) events are internal cPanel noise - hidden unless requested. */
function smpro_aa_is_local_ip($ip) { return $ip === '127.0.0.1' || $ip === '::1' || strpos((string)$ip, '127.') === 0; }

function smpro_aa_filter_local($events, $show) {
    if ($show) return $events;
    return array_values(array_filter($events, fn($e) => !smpro_aa_is_local_ip($e['ip'] ?? '')));
}

function smpro_aa_count_local($events) { $n = 0; foreach ($events as $e) if (smpro_aa_is_local_ip($e['ip'] ?? '')) $n++; return $n; }

function smpro_aa_filter_country($events, $country) {
    if ($country === 'all' || $country === '') return $events;
    $out = [];
    foreach ($events as $e) {
        $in = smpro_aa_ip_intel($e['ip'] ?? '');
        $cc = strtoupper((string)($in['country'] ?? ''));
        $e['intel'] = $in;
        if ($country === 'foreign') {
            // foreign = external + NON-Arab (the home region and all Arab countries are trusted, never "foreign")
            if (($in['scope'] ?? '') === 'external' && $cc !== '' && !smpro_cc_is_arab($cc)) $out[] = $e;
        } elseif ($cc === $country) {
            $out[] = $e;
        }
    }
    return $out;
}

/**
 * The columns Account Audit can be ordered by, and the event field each one reads.
 *
 * Whitelisted rather than taken from the URL: a sort key names a field read out of every event, and a URL is not
 * a place to accept arbitrary field names.
 */
function smpro_aa_sort_keys(): array {
    return ['time' => 'ts', 'type' => 'type', 'result' => 'result', 'service' => 'service',
            'ip' => 'ip', 'user' => 'login_user', 'account' => 'account', 'action' => 'action'];
}

/**
 * Order the WHOLE result, before it is counted and cut into pages.
 *
 * This used to happen in the browser, on the rows of the page being looked at. On a result of 15,000 events
 * across 305 pages that sorts fifty of them while the column arrow says the table is sorted - so "order by Type
 * to gather the successful logins" returned the two or three that were already on the page, underneath a counter
 * reading 533. The number and the list were describing different things, and the list looked authoritative.
 */
function smpro_aa_sort_events(array $events, string $key, string $dir = 'desc'): array {
    $map = smpro_aa_sort_keys();
    $f   = $map[$key] ?? 'ts';
    $mul = ($dir === 'asc') ? 1 : -1;
    usort($events, function ($a, $b) use ($f, $mul) {
        $x = $a[$f] ?? ''; $y = $b[$f] ?? '';
        // Time is the one numeric column; every other is a label, compared by name and case-insensitively.
        $c = ($f === 'ts') ? ((int)$x <=> (int)$y) : strcasecmp((string)$x, (string)$y);
        // A tie falls back to newest-first, so the order is total: the same query returns the same page, and a
        // row cannot drift across a page boundary between two loads.
        if ($c === 0) return ((int)($b['ts'] ?? 0)) <=> ((int)($a['ts'] ?? 0));
        return $c * $mul;
    });
    return $events;
}

/* ---------- event collection ---------- */
function smpro_aa_collect($user, $type, $tail, $fromTs, $toTs, $needle = '') {
    $events = []; $hiddenTech = 0;
    // The page filters events by the search text AFTER collecting; applying the same text to the raw line first
    // keeps the event array to the matches only (an IP audit over 200k lines is usually a few dozen events).
    // Skipped when the text could match a derived label ("Failed Login") that is not in the raw line.
    $pre = trim((string)$needle);
    if ($pre !== '' && stripos('successful login failed login attempt login request password change technical http event rejected', $pre) !== false) $pre = '';
    $needles = smpro_aa_needles($user);
    if (!function_exists('smpro_login_line_real')) { $lf = __DIR__ . '/loginfeed.php'; if (@is_file($lf)) require_once $lf; }
    $loginLog  = defined('SMPRO_AA_LOGIN_LOG')  ? SMPRO_AA_LOGIN_LOG  : (function_exists('smpro_lf_login_log') ? smpro_lf_login_log() : '/usr/local/cpanel/logs/login_log');    // overridable for the test lab
    $accessLog = defined('SMPRO_AA_ACCESS_LOG') ? SMPRO_AA_ACCESS_LOG : '/usr/local/cpanel/logs/access_log';
    $wantSuccess = in_array($type, ['all', 'success_login'], true);
    $wantFailed = in_array($type, ['all', 'failed_login'], true);

    // A granted session is recorded in session_log on current cPanel, not in login_log, so this timeline showed
    // "0 successful logins" on every current server - an all-clear it had no way to have earned. The shared feed
    // reads whichever log this cPanel actually uses.
    if ($wantSuccess) {
        if (!function_exists('smpro_lf_success')) { $lf = __DIR__ . '/loginfeed.php'; if (@is_file($lf)) require_once $lf; }
        $feed = function_exists('smpro_lf_success')
              ? smpro_lf_success($fromTs, $tail, ['password', 'operator', 'api', 'unknown', 'other'])
              : ['events' => []];
        foreach ((array)$feed['events'] as $e) {
            $ts = (int)$e['ts']; if ($ts < $fromTs || $ts > $toTs) continue;
            if ($pre !== '' && stripos($e['raw'], $pre) === false) continue;
            if (!smpro_aa_match($needles, $e['user'], $e['raw'])) continue;
            // An operator opening a customer's cPanel from WHM is not the customer signing in, and calling it one
            // turns the reseller's own working day into a page of compromise alerts.
            $op = ($e['kind'] === 'operator' || $e['kind'] === 'api');
            $events[] = [
                'ts' => $ts, 'time' => date('Y-m-d H:i:s O', $ts),
                'type' => $op ? 'Operator Sign-in' : 'Successful Login',
                'kind' => 'success_login',
                'result' => $op ? 'Opened by the operator' : 'Successful Login',
                'service' => (string)$e['service'], 'ip' => (string)$e['ip'],
                'login_user' => (string)$e['user'], 'account' => smpro_aa_resolve_account($e['user']) ?: $e['user'],
                'action' => $op
                    ? ('Session created by ' . ($e['creator'] !== '' ? $e['creator'] : 'the server') . ' — no account password was used')
                    : 'The account password was accepted',
                'status' => '', 'source' => (string)$e['source'], 'evidence' => smpro_redact_sensitive((string)$e['raw']),
            ];
        }
    }
    if ($wantFailed) {
        foreach (smpro_aa_tail($loginLog, $tail) as $raw) {
            $raw = trim($raw); if ($raw === '') continue;
            if (function_exists('smpro_login_line_real')) $raw = smpro_login_line_real($raw);   // the attempt behind WebShield carries the visitor, not 127.0.0.1
            if ($pre !== '' && stripos($raw, $pre) === false && stripos(rawurldecode($raw), $pre) === false) continue;
            // Two formats coexist in login_log:
            //  A) [TIME] level [service] IP - user - RESULT LOGIN service   (cpaneld/WHM account logins)
            //  B) IP - user [date] "METHOD" RESULT LOGIN service            (cpdavd/webmail)
            // cPanel writes  [ts] lvl [svc] IP - user "REQUEST" MSG  - ONE dash before the user. The old
            // two-dash pattern matches nothing on current cPanel, so this timeline showed almost no logins.
            if (preg_match('/^\[([^\]]+)\]\s+\S+\s+\[([^\]]+)\]\s+(\S+)\s+-\s+(\S+)\s+(.+)$/', $raw, $m)) {
                $timeRaw = $m[1]; $svcA = $m[2]; $ip = $m[3]; $actor = rawurldecode($m[4]); $rest = $m[5];
            } elseif (preg_match('/^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*)"\s+(.+)$/', $raw, $m)) {
                $ip = $m[1]; $actor = rawurldecode($m[2]); $timeRaw = $m[3]; $svcA = ''; $rest = $m[5];
            } else {
                continue;
            }
            // Successes from this file are already carried by the feed above, which reads it too.
            $isSuccess = false;
            $isFailed = !(bool)preg_match('/SUCCEEDED\s+LOGIN|SUCCESS\s+LOGIN/i', $rest)
                     && (bool)preg_match('/FAILED\s+LOGIN|DEFERRED\s+LOGIN|AUTHENTICATION\s+FAILED|INVALID|FAILURE/i', $rest);
            if (!$isFailed) continue;
            if (!smpro_aa_match($needles, $actor, $raw)) continue;
            $ts = smpro_aa_ts($timeRaw); if ($ts < $fromTs || $ts > $toTs) continue;
            $service = $svcA !== '' ? $svcA
                     : (preg_match('/\b([a-z0-9_]+):/i', $rest, $sm) ? $sm[1] : (preg_match('/LOGIN\s+(\S+)/i', $rest, $s2) ? $s2[1] : 'cpanel'));
            $events[] = [
                'ts' => $ts, 'time' => date('Y-m-d H:i:s O', $ts),
                'type' => $isSuccess ? 'Successful Login' : 'Failed Login',
                'kind' => $isSuccess ? 'success_login' : 'failed_login',
                'result' => $isSuccess ? 'Successful Login' : 'Failed Login Attempt',
                'service' => $service, 'ip' => $ip,
                'login_user' => $actor, 'account' => smpro_aa_resolve_account($actor) ?: $actor,
                'action' => $isSuccess ? 'cPanel or WHM login event' : 'Rejected cPanel/WHM login attempt',
                'status' => '', 'source' => $loginLog, 'evidence' => smpro_redact_sensitive($raw),
            ];
        }
    }
    if (in_array($type, ['all', 'login_request', 'password_change', 'failed_login', 'technical', 'panel_action'], true)) {
        foreach (smpro_aa_tail($accessLog, $tail) as $raw) {
            $raw = trim($raw); if ($raw === '') continue;
            if ($pre !== '' && stripos($raw, $pre) === false && stripos(rawurldecode($raw), $pre) === false) continue;
            if (!preg_match('/^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d{3})/', $raw, $m)) continue;
            $ip = $m[1]; $actor = rawurldecode($m[2]); if ($actor === '-') $actor = ''; $timeRaw = $m[3]; $request = $m[4]; $status = $m[5];
            $method = ''; $path = ''; $query = '';
            if (preg_match('/^(\S+)\s+(\S+)/', $request, $rm)) { $method = strtoupper($rm[1]); $path = parse_url($rm[2], PHP_URL_PATH) ?? $rm[2]; $query = parse_url($rm[2], PHP_URL_QUERY) ?? ''; }
            $isLogin = strpos($path, '/login') !== false || strpos($query, 'login_only=') !== false || strpos($query, 'user=') !== false;
            // Real password change = an actual change endpoint. Exclude bot file-probes
            // like GET /.htpasswd (404 scans) which merely contain the substring "passwd".
            $isPass = strpos($path, '.htpasswd') === false && (
                strpos($path, 'changepass') !== false ||
                strpos($path, 'change_password') !== false ||
                strpos($path, 'password/change') !== false ||
                strpos($path, 'passwd_pop') !== false ||
                (bool)preg_match('#/passwd(?:/|$)#', $path) ||
                strpos($query, 'emailpass') !== false
            );
            // A genuine password change is a POST that did not error out.
            if ($isPass && ($method !== 'POST' || in_array($status, ['400','401','403','404','429'], true))) {
                $isPass = false;
            }
            // PANEL ACTIONS - API / File Manager / feature calls made inside a session. A takeover that arrives with a
            // stolen password, an API token, or a reseller "log in as" leaves NO login line at all; the only trace is
            // this activity. It is shown when the view is narrowed (search text or an account) or when the type is
            // "panel_action" - never in the unfiltered "all" view, where it would drown the logins.
            $isPanel = false; $panelOp = '';
            if (!$isLogin && !$isPass) {
                if (($pre !== '' || $user !== '' || $type === 'panel_action')
                    && preg_match('#/(json-api|execute)/|/frontend/[^/]+/(?:filemanager|mail|sql|ftp|cron|backup|domains|zone_editor|passwd|security|ssl|php)#i', $path)) {
                    $isPanel = true;
                    if (preg_match('/cpanel_jsonapi_module=([A-Za-z0-9_]+).*?cpanel_jsonapi_func=([A-Za-z0-9_]+)/', $query, $pm)) $panelOp = $pm[1] . '::' . $pm[2];
                    elseif (preg_match('#/execute/([A-Za-z0-9_]+)/([A-Za-z0-9_]+)#', $path, $pm)) $panelOp = $pm[1] . '::' . $pm[2];
                    else $panelOp = preg_replace('#^/cpsess\d+#', '', $path);
                    if (preg_match('/(?:^|&)(?:dir|file|filepath|path|destination)=([^&]+)/', $query, $dm)) $panelOp .= ' ' . substr(rawurldecode($dm[1]), 0, 120);
                }
                if (!$isPanel) continue;
            }
            if ($type === 'panel_action' && !$isPanel) continue;
            if (!smpro_aa_match($needles, $actor, $raw)) continue;
            $ts = smpro_aa_ts($timeRaw); if ($ts < $fromTs || $ts > $toTs) continue;
            if ($isPanel) {
                $events[] = [
                    'ts' => $ts, 'time' => date('Y-m-d H:i:s O', $ts), 'type' => 'Panel Action', 'kind' => 'panel_action', 'result' => 'HTTP ' . $status,
                    'service' => 'cpanel access_log', 'ip' => $ip,
                    'login_user' => $actor, 'account' => smpro_aa_resolve_account($actor) ?: $actor,
                    'action' => $panelOp, 'status' => $status, 'source' => $accessLog, 'evidence' => smpro_redact_sensitive($raw),
                ];
                continue;
            }
            $isFailedHttp = in_array($status, ['400','401','403','429'], true);
            $isTech = in_array($status, ['200','301','302','303','307','308'], true);
            if ($isTech && $type !== 'technical') { $hiddenTech++; continue; }
            if ($type === 'technical' && !$isTech) continue;
            if ($type === 'failed_login' && !$isFailedHttp) continue;
            if ($type === 'login_request' && (!$isLogin || $isFailedHttp || $isTech)) continue;
            if ($type === 'password_change' && (!$isPass || $isFailedHttp || $isTech)) continue;
            if ($isTech) { $kind='technical'; $t='Technical HTTP Event'; $res='HTTP '.$status; $act='Technical web login flow'; }
            elseif ($isFailedHttp) { $kind='failed_login'; $t='Failed Login'; $res='Failed Login Attempt'; $act='Rejected web login attempt'; }
            elseif ($isPass) { $kind='password_change'; $t='Password Change'; $res='HTTP '.$status; $act='Password related action'; }
            else { $kind='login_request'; $t='Login Request'; $res='HTTP '.$status; $act='Web login request'; }
            $events[] = [
                'ts' => $ts, 'time' => date('Y-m-d H:i:s O', $ts), 'type' => $t, 'kind' => $kind, 'result' => $res,
                'service' => 'cpanel access_log', 'ip' => $ip,
                'login_user' => $actor, 'account' => smpro_aa_resolve_account($actor) ?: $actor,
                'action' => $act, 'status' => $status, 'source' => $accessLog, 'evidence' => smpro_redact_sensitive($raw),
            ];
        }
    }
    usort($events, fn($a, $b) => $b['ts'] <=> $a['ts']);
    return [$events, $hiddenTech];
}

function smpro_aa_bf_ign_all() { $d = smpro_aa_json_load(SMPRO_AA_BFIGN); return is_array($d) ? $d : []; }

function smpro_aa_bf_ign_add($key, $label, $by) {
    $key = preg_replace('/[^A-Za-z0-9:_.-]/', '', (string)$key); if ($key === '') return false;
    $d = smpro_aa_bf_ign_all(); $d[$key] = ['label' => substr((string)$label, 0, 120), 'by' => (string)$by, 'at' => time()];
    smpro_aa_json_save(SMPRO_AA_BFIGN, $d); return true;
}

function smpro_aa_bf_ign_remove($key) { $d = smpro_aa_bf_ign_all(); unset($d[preg_replace('/[^A-Za-z0-9:_.-]/', '', (string)$key)]); smpro_aa_json_save(SMPRO_AA_BFIGN, $d); }

/** Network key used by the grouping and by the ignore list: the ASN, else the country. */
/**
 * Failed logins grouped by the NETWORK they came from, the way the Break-in report shows them: foreign (non-Arab)
 * external addresses with more than three failures, allow-listed providers set aside as 'trusted', one row per
 * ASN (or per country when the ASN is unknown), the operator's ignored networks kept apart. Pure over $events
 * (the rows smpro_aa_collect returns); the only lookups are the local IP databases.
 */
function smpro_aa_bf_networks(array $events): array {
    $fail = [];
    foreach ($events as $e) {
        if (($e['kind'] ?? '') !== 'failed_login') continue;
        $ip = (string)($e['ip'] ?? ''); if ($ip === '') continue;
        $in = smpro_aa_ip_intel($ip); $cc = strtoupper((string)($in['country'] ?? ''));
        if (($in['scope'] ?? '') !== 'external' || $cc === '' || $cc === 'N/A' || $cc === 'NA' || (function_exists('smpro_cc_is_arab') && smpro_cc_is_arab($cc))) continue;
        if (!isset($fail[$ip])) $fail[$ip] = ['ip' => $ip, 'cc' => $cc, 'n' => 0, 'users' => [], 'first' => 0, 'last' => 0, 'services' => []];
        $fail[$ip]['n']++;
        $u0 = (string)(($e['account'] ?? '') ?: ($e['login_user'] ?? '')); if ($u0 !== '') $fail[$ip]['users'][$u0] = ($fail[$ip]['users'][$u0] ?? 0) + 1;
        $t0 = (int)($e['ts'] ?? 0); if ($t0) { $fail[$ip]['first'] = $fail[$ip]['first'] ? min($fail[$ip]['first'], $t0) : $t0; $fail[$ip]['last'] = max($fail[$ip]['last'], $t0); }
        $sv = (string)($e['service'] ?? ''); if ($sv !== '') $fail[$ip]['services'][$sv] = 1;
    }
    $brute = array_values(array_filter($fail, fn($x) => $x['n'] > 3));
    usort($brute, fn($a, $b) => $b['n'] <=> $a['n']);
    $trusted = [];
    if (function_exists('smpro_fw_allow_covers_name')) {
        $keep = [];
        foreach ($brute as $bx) { $who = smpro_fw_allow_covers_name($bx['ip']); if ($who !== '') { $bx['who'] = $who; $trusted[] = $bx; } else $keep[] = $bx; }
        $brute = $keep;
    }
    if (function_exists('smpro_ip_intel_bulk') && $brute) smpro_ip_intel_bulk(array_column($brute, 'ip'));
    $nets = [];
    foreach ($brute as $bx) {
        $in = smpro_aa_ip_intel($bx['ip']); $asn = (string)($in['asn'] ?? ''); $key = $asn !== '' ? $asn : ('cc:' . $bx['cc']);
        if (!isset($nets[$key])) $nets[$key] = ['asn' => $asn, 'provider' => (string)($in['provider'] ?? ''), 'cc' => $bx['cc'], 'ips' => [], 'fails' => 0, 'users' => [], 'first' => 0, 'last' => 0, 'services' => [],
                                               'bot' => function_exists('smpro_ip_is_datacenter') ? smpro_ip_is_datacenter($in) : false];
        $nets[$key]['ips'][] = $bx; $nets[$key]['fails'] += (int)$bx['n'];
        foreach ((array)$bx['users'] as $uu => $un) $nets[$key]['users'][$uu] = ($nets[$key]['users'][$uu] ?? 0) + (int)$un;
        foreach ((array)$bx['services'] as $ss => $_1) $nets[$key]['services'][$ss] = 1;
        if (!empty($bx['first'])) $nets[$key]['first'] = $nets[$key]['first'] ? min($nets[$key]['first'], (int)$bx['first']) : (int)$bx['first'];
        if (!empty($bx['last']))  $nets[$key]['last']  = max($nets[$key]['last'], (int)$bx['last']);
        if ($nets[$key]['cc'] !== $bx['cc']) $nets[$key]['cc'] = '';
    }
    foreach ($nets as &$n) { $p = trim($n['provider']); if ($p === '' || strtolower($p) === 'n/a') $n['provider'] = $n['asn'] !== '' ? $n['asn'] : 'unidentified network'; } unset($n);
    uasort($nets, function ($a, $b) { $c = count($b['ips']) <=> count($a['ips']); return $c !== 0 ? $c : ($b['fails'] <=> $a['fails']); });
    $ignored = []; $ign = smpro_aa_bf_ign_all();
    foreach ($nets as $k => $nv) if (isset($ign[$k])) { $nv['ign'] = $ign[$k]; $ignored[$k] = $nv; unset($nets[$k]); }
    return ['nets' => $nets, 'ignored' => $ignored, 'trusted' => $trusted, 'brute' => $brute];
}
function smpro_aa_bf_key(array $nv) { return $nv['asn'] !== '' ? $nv['asn'] : ('cc:' . $nv['cc']); }

/**
 * What a network's failed logins mean, in one verdict + the reasons behind it. Pure: reads the numbers already on
 * the network row (addresses, attempts, accounts targeted, time span, cloud-or-not) and nothing else.
 *   block  - an attack: password spraying, a many-address run, or hammering; blocking is the right call
 *   watch  - could be an attack or a person; look at the addresses/accounts before deciding
 *   normal - one address, one account, a handful of attempts: the shape of a wrong saved password, not an attack
 * A search or archive crawler never attempts a cPanel/webmail/SSH login, so no failed-login group is ever a crawler;
 * the "archive bot" case does not exist here and the text says so when it matters (cloud networks).
 */
function smpro_aa_bf_assess(array $nv) {
    $ips = max(1, count((array)($nv['ips'] ?? []))); $fails = (int)($nv['fails'] ?? 0); $perIp = $fails / $ips;
    $users = (array)($nv['users'] ?? []); $nUsers = count($users); arsort($users); $topUsers = array_slice(array_keys($users), 0, 3);
    $span = max(0, (int)($nv['last'] ?? 0) - (int)($nv['first'] ?? 0)); $bot = !empty($nv['bot']);
    $svc = array_keys((array)($nv['services'] ?? []));
    $rate = $span > 60 ? $fails / ($span / 60) : 0.0;   // attempts per minute, when the span is known
    $why = []; $verdict = 'watch';
    if ($nUsers >= 5) { $verdict = 'block'; $why[] = 'tried ' . $nUsers . ' different accounts — password spraying (a list of names, one or two passwords each); a person forgetting a password does not do this'; }
    elseif ($ips >= 5) { $verdict = 'block'; $why[] = $ips . ' addresses from one network is one actor renting many addresses (a proxy pool or cloud run), not ' . $ips . ' people'; }
    elseif ($perIp >= 30) { $verdict = 'block'; $why[] = 'about ' . (int)round($perIp) . ' attempts per address — hammering, not a forgotten password'; }
    elseif ($bot) { $verdict = 'block'; $why[] = 'a cloud/hosting network: nobody signs in to a panel from a rented server, so this is an automated scanner; harmless to block, and blocking stops the noise'; }
    elseif ($ips === 1 && $fails <= 10 && $nUsers <= 1) { $verdict = 'normal'; $why[] = 'one address, one account, ' . $fails . ' attempts — the shape of a wrong saved password (a phone or mail client retrying), not an attack'; }
    elseif ($ips <= 2 && $fails <= 25) { $why[] = 'small and slow — could be a person who forgot a password or a cautious probe; the accounts and the time of day will tell'; }
    else { $verdict = 'block'; $why[] = $fails . ' failed attempts from ' . $ips . ' address' . ($ips === 1 ? '' : 'es') . ' is beyond what a mistake produces'; }
    if ($rate >= 2 && $verdict !== 'normal') $why[] = 'rate ~' . round($rate, 1) . ' attempts/min over ' . ($span >= 3600 ? round($span / 3600, 1) . ' h' : intdiv($span, 60) . ' min') . ' — scripted';
    if ($span > 0 && $span < 120 && $fails >= 20 && $verdict !== 'normal') $why[] = $fails . ' attempts inside two minutes — a script, not a keyboard';
    if ($topUsers) $why[] = 'target' . ($nUsers === 1 ? '' : 's') . ': ' . implode(', ', $topUsers) . ($nUsers > 3 ? ' … (+' . ($nUsers - 3) . ')' : '');
    if ($svc) $why[] = 'door: ' . implode(', ', array_map(fn($x) => str_replace(['cpaneld', 'webmaild', 'whostmgrd'], ['cPanel', 'webmail', 'WHM'], $x), $svc));
    if ($bot && $verdict === 'block') $why[] = 'search and archive crawlers never attempt a login, so this is not a crawler being over-eager';
    $label = ['block' => 'Attack — block', 'watch' => 'Look first', 'normal' => 'Probably not an attack'][$verdict];
    $what  = $nUsers >= 5 ? 'Password spraying' : ($ips >= 5 ? 'Many-address run' : ($perIp >= 30 ? 'Brute force' : ($bot ? 'Automated scanner' : ($verdict === 'normal' ? 'Wrong saved password' : 'Small probe'))));
    return ['verdict' => $verdict, 'label' => $label, 'what' => $what, 'why' => $why, 'users' => $nUsers, 'per_ip' => round($perIp, 1), 'rate' => round($rate, 1), 'span' => $span];
}


/**
 * The break-in networks, rebuilt from this server's own logs. Usable from cron: nothing here renders, and the
 * page's router is not involved.
 *
 * Deliberately the SAME pipeline the page walks - collect, keep external non-Arab failures, drop anything on the
 * allow-list, group by ASN - so what a rule acts on is what the page would have shown, not an approximation of
 * it built somewhere else.
 *
 * Returns ['ok'=>bool,'nets'=>[...],'trusted'=>[...],'msg'=>string]. 'ok' false means the logs could not be
 * read, which is "not checked" and must never be reported as "no attacks found".
 */
function smpro_bi_networks(int $loglines = 200000, int $windowSec = 86400): array {
    if (!function_exists('smpro_aa_collect')) return ['ok' => false, 'nets' => [], 'trusted' => [], 'msg' => 'the collector is not loaded'];
    [$events, ] = smpro_aa_collect('', 'all', $loglines, time() - max(3600, $windowSec), time() + 60, '');   // a real window: [0,0] dropped every dated line and the armed rules never fired
    if (!is_array($events)) return ['ok' => false, 'nets' => [], 'trusted' => [], 'msg' => 'the login log could not be read — this is "not checked", not "nothing found"'];

    $fail = [];
    foreach ($events as $e) {
        if (($e['kind'] ?? '') !== 'failed_login') continue;
        $in = smpro_aa_ip_intel((string)($e['ip'] ?? ''));
        $cc = strtoupper((string)($in['country'] ?? ''));
        if (($in['scope'] ?? '') !== 'external' || $cc === '' || $cc === 'N/A' || $cc === 'NA') continue;
        if (function_exists('smpro_cc_is_arab') && smpro_cc_is_arab($cc)) continue;
        $ip = (string)$e['ip'];
        if (!isset($fail[$ip])) $fail[$ip] = ['ip' => $ip, 'cc' => $cc, 'n' => 0, 'users' => [], 'first' => 0, 'last' => 0, 'services' => []];
        $fail[$ip]['n']++;
        $u = (string)(($e['account'] ?? '') ?: ($e['login_user'] ?? '')); if ($u !== '') $fail[$ip]['users'][$u] = ($fail[$ip]['users'][$u] ?? 0) + 1;
        $ts = (int)($e['ts'] ?? 0);
        if ($ts) { $fail[$ip]['first'] = $fail[$ip]['first'] ? min($fail[$ip]['first'], $ts) : $ts; $fail[$ip]['last'] = max($fail[$ip]['last'], $ts); }
        $sv = (string)($e['service'] ?? ''); if ($sv !== '') $fail[$ip]['services'][$sv] = 1;
    }
    $brute = array_values(array_filter($fail, fn($x) => $x['n'] > 3));

    // Allow-listed addresses are taken out before anything can act on them. They are in csf.allow precisely
    // because they must never be blocked; leaving them in an attacker list that a rule reads would be handing a
    // rule the one set of addresses the operator has already decided about.
    $trusted = [];
    if (function_exists('smpro_fw_allow_covers_name')) {
        $keep = [];
        foreach ($brute as $bx) {
            $who = smpro_fw_allow_covers_name($bx['ip']);
            if ($who !== '') { $bx['who'] = $who; $trusted[] = $bx; } else { $keep[] = $bx; }
        }
        $brute = $keep;
    }

    $ign = function_exists('smpro_aa_bf_ign_all') ? smpro_aa_bf_ign_all() : [];
    $nets = [];
    foreach ($brute as $bx) {
        $in  = smpro_aa_ip_intel($bx['ip']);
        $asn = (string)($in['asn'] ?? '');
        $key = $asn !== '' ? $asn : ('cc:' . $bx['cc']);
        if (isset($ign[$key])) continue;                       // the operator said to leave this network alone
        if (!isset($nets[$key])) {
            $nets[$key] = ['asn' => $asn, 'provider' => (string)($in['provider'] ?? ''), 'cc' => $bx['cc'],
                           'ips' => [], 'fails' => 0, 'users' => [], 'first' => 0, 'last' => 0, 'services' => [],
                           'bot' => function_exists('smpro_ip_is_datacenter') ? smpro_ip_is_datacenter($in) : false];
        }
        $nets[$key]['ips'][] = $bx;
        $nets[$key]['fails'] += (int)$bx['n'];
        foreach ((array)($bx['users'] ?? []) as $uu => $un) $nets[$key]['users'][$uu] = ($nets[$key]['users'][$uu] ?? 0) + (int)$un;
        foreach ((array)($bx['services'] ?? []) as $ss => $_1) $nets[$key]['services'][$ss] = 1;
        if (!empty($bx['first'])) $nets[$key]['first'] = $nets[$key]['first'] ? min($nets[$key]['first'], (int)$bx['first']) : (int)$bx['first'];
        if (!empty($bx['last']))  $nets[$key]['last']  = max($nets[$key]['last'], (int)$bx['last']);
        if ($nets[$key]['cc'] !== $bx['cc']) $nets[$key]['cc'] = '';
    }
    return ['ok' => true, 'nets' => array_values($nets), 'trusted' => $trusted, 'msg' => ''];
}

/* ------------------------------------------------------------------ the scan cache
 * Account Audit re-read and re-parsed the whole log window on EVERY request: page 2, a column sort, hiding
 * localhost - each one tailed 50,000 lines again, ran the regex on each, and looked every address up. On a busy
 * server that is seconds per click, and the operator's answer was "there has to be pagination" - there was; it
 * was the scan behind it that was repeated. The parsed result is now kept for a few minutes under a key made of
 * everything that changes it, so the first search pays and every click after it reads a file.
 */
if (!defined('SMPRO_AA_CACHE_TTL')) define('SMPRO_AA_CACHE_TTL', 600);

function smpro_aa_cache_key(array $params): string { ksort($params); return 'aa_' . substr(sha1(json_encode($params)), 0, 24); }

function smpro_aa_cache_get(string $key): ?array {
    $f = SMPRO_CACHE . '/' . $key . '.json';
    if (!@is_file($f) || time() - (int)@filemtime($f) > SMPRO_AA_CACHE_TTL) return null;
    $j = json_decode((string)@file_get_contents($f), true);
    return is_array($j) && isset($j['events']) ? $j : null;
}

function smpro_aa_cache_put(string $key, array $data): void {
    @is_dir(SMPRO_CACHE) || @mkdir(SMPRO_CACHE, 0700, true);
    $f = SMPRO_CACHE . '/' . $key . '.json';
    if (@file_put_contents($f . '.tmp', json_encode($data, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE), LOCK_EX) !== false) { @chmod($f . '.tmp', 0600); @rename($f . '.tmp', $f); }
}

/** Run $collect() once per parameter set per SMPRO_AA_CACHE_TTL. Returns [events, hidden, meta]; meta says whether it was cached and how long the scan took. */
function smpro_aa_cached(array $params, callable $collect, bool $fresh = false): array {
    $key = smpro_aa_cache_key($params);
    if (!$fresh) { $c = smpro_aa_cache_get($key); if ($c !== null) return [(array)$c['events'], (int)($c['hidden'] ?? 0), ['cached' => true, 'at' => (int)$c['at'], 'took' => (float)($c['took'] ?? 0)]]; }
    $t0 = microtime(true);
    [$events, $hidden] = $collect();
    $took = round(microtime(true) - $t0, 2);
    smpro_aa_cache_put($key, ['events' => $events, 'hidden' => (int)$hidden, 'at' => time(), 'took' => $took]);
    return [$events, (int)$hidden, ['cached' => false, 'at' => time(), 'took' => $took]];
}
