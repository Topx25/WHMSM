<?php
/**
 * modules/login-monitor.php — UNIFIED "Login & Access" page (read-only + guarded CSF).
 * Merges the former Login Monitor, Login Correlation and Password-Reset auditing
 * into one tabbed page:
 *   tab=overview     → SSH/cPanel failed logins, hardening, cPHulk, risk score, CSF block/allow
 *   tab=correlation  → repeated source IPs correlated across accounts/services, severity
 *   tab=resets       → password change / reset events across all accounts
 * Each tab only runs its own collectors when active, so the page stays fast.
 * All state-changing actions are POST + CSRF + root + audit, and never block the
 * admin's own IP or any private/local address.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

define('SMPRO_LM_BRUTE', 20);   // SSH/cPanel failed attempts that flag a brute-force candidate
define('SMPRO_LC_MULTI', 3);    // distinct accounts hit by one IP = "multi-account"

/* =====================================================================
 * SHARED HELPERS
 * ===================================================================== */
function smpro_lm_tail($file, $lines) {
    if (!is_readable($file)) return [];
    $n = max(1000, min(300000, (int)$lines));
    $raw = @shell_exec('timeout ' . SMPRO_TIMEOUT_NORMAL . ' tail -n ' . $n . ' ' . escapeshellarg($file) . ' 2>/dev/null');
    return $raw === null ? [] : explode("\n", rtrim((string)$raw, "\n"));
}
function smpro_lm_syslog_ts($line) {
    $ts = strtotime(substr($line, 0, 15));
    if ($ts && $ts > time() + 86400) $ts -= 365 * 86400;
    return $ts ?: 0;
}
function smpro_lm_cpanel_ts($raw) {
    if (!preg_match('/\[([^\]]+)\]/', $raw, $m)) return 0;
    $t = $m[1];
    if (preg_match('#^\d{1,2}/\w{1,3}/\d{4}:#', $t) || preg_match('#^\d{1,2}/\d{1,2}/\d{4}:#', $t)) $t = preg_replace('/:/', ' ', $t, 1);
    return strtotime($t) ?: 0;
}
function smpro_lm_csf_bin() {
    foreach (['/usr/sbin/csf', '/usr/local/csf/bin/csf'] as $b) if (is_executable($b)) return $b;
    return '';
}
/** Set of IPs already blocked by CSF (permanent csf.deny + temporary deny). */
function smpro_lm_csf_blocked() {
    $set = [];
    if (is_readable('/etc/csf/csf.deny')) {
        foreach (file('/etc/csf/csf.deny', FILE_IGNORE_NEW_LINES) ?: [] as $l) {
            $l = trim($l);
            if ($l === '' || $l[0] === '#') continue;
            if (preg_match('/^([0-9a-fA-F:.]+)/', $l, $m)) $set[$m[1]] = 'perm';
        }
    }
    $csf = smpro_lm_csf_bin();
    if ($csf !== '') {
        $raw = @shell_exec('timeout ' . SMPRO_TIMEOUT_QUICK . ' ' . escapeshellarg($csf) . ' -t 2>/dev/null');
        foreach (explode("\n", (string)$raw) as $l) {
            if (preg_match('/\b(\d{1,3}(?:\.\d{1,3}){3})\b/', $l, $m) && stripos($l, 'DENY') !== false) {
                if (!isset($set[$m[1]])) $set[$m[1]] = 'temp';
            }
        }
    }
    return $set;
}
function smpro_lm_csf_action($action, $ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return ['ok' => false, 'msg' => 'invalid IP'];
    // prefer the verified CSF helper (validates the end-state in csf.deny/allow + detects TESTING mode) over
    // guessing success from stdout — `csf -d` prints a clean message even when it is a no-op.
    if (function_exists('smpro_csf_do')) { $r = smpro_csf_do($action, $ip); return ['ok' => !empty($r['ok']), 'msg' => (string)($r['msg'] ?? '')]; }
    $csf = smpro_lm_csf_bin();
    if ($csf === '') return ['ok' => false, 'msg' => 'csf not found'];
    $comment = 'smpro Login&Access ' . date('Y-m-d H:i');
    if ($action === 'unblock') $cmd = escapeshellarg($csf) . ' -dr ' . escapeshellarg($ip);
    else { $flag = $action === 'allow' ? '-a' : '-d'; $cmd = escapeshellarg($csf) . ' ' . $flag . ' ' . escapeshellarg($ip) . ' ' . escapeshellarg($comment); }
    $rc = 1; $out = []; @exec('timeout 25 ' . $cmd . ' 2>&1', $out, $rc);   // check exit code, not stdout text
    return ['ok' => $rc === 0, 'msg' => trim(mb_substr(implode("\n", $out), 0, 180))];
}
function smpro_la_audit_ip($ip, $from, $to) {
    return 'index.cgi?page=account-audit&do=search&q=' . urlencode($ip) . '&from=' . $from . '&to=' . $to . '&loglines=200000';
}
function smpro_la_csf_badge($blocked, $ip) {
    if (isset($blocked[$ip])) return '<span class="b red">CSF ' . ($blocked[$ip] === 'temp' ? 'temp' : 'blocked') . '</span>';
    return '<span class="b gray">not blocked</span>';
}

/* =====================================================================
 * POST HANDLERS (all Login&Access tabs) — call from the host before output.
 * Returns true (and exits) when it handled a request; false otherwise.
 * ===================================================================== */
function smpro_la_handle_post() {
    $reqMethod = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));
    if ($reqMethod !== 'POST') return false;
    /* Unified CSF block / allow / unblock (accepts la_action, lm_action or lc_action). */
    $csfAction = $_POST['la_action'] ?? $_POST['lm_action'] ?? $_POST['lc_action'] ?? '';
    if (in_array($csfAction, ['block', 'allow', 'unblock'], true)) {
        smpro_require_valid_csrf('la_csf');
        smpro_require_root();
        header('Content-Type: application/json');
        $myIp = smpro_current_remote_ip();
        $ips  = array_unique(array_filter(array_map('trim', explode(',', (string)($_POST['ips'] ?? '')))));
        $results = [];
        foreach ($ips as $ip) {
            if (!filter_var($ip, FILTER_VALIDATE_IP))     { $results[] = ['ip' => $ip, 'ok' => false, 'msg' => 'invalid IP']; continue; }
            if ($csfAction !== 'allow' && function_exists('smpro_is_server_ip') && smpro_is_server_ip($ip)) { $results[] = ['ip' => $ip, 'ok' => false, 'msg' => 'refused: server / localhost IP']; continue; }
            if (!smpro_ip_is_external($ip))               { $results[] = ['ip' => $ip, 'ok' => false, 'msg' => 'refused: private/local IP']; continue; }
            if ($csfAction !== 'allow' && $ip === $myIp)  { $results[] = ['ip' => $ip, 'ok' => false, 'msg' => 'refused: your own IP (lockout protection)']; continue; }
            $r = smpro_lm_csf_action($csfAction, $ip);
            smpro_audit('login_access_csf_' . $csfAction, ['ip' => $ip, 'ok' => $r['ok'], 'actor' => smpro_current_actor()]);
            $results[] = ['ip' => $ip, 'ok' => $r['ok'], 'msg' => $r['msg'], 'state' => $csfAction === 'unblock' ? 'none' : ($csfAction === 'allow' ? 'allow' : 'perm')];
        }
        echo json_encode(['ok' => true, 'action' => $csfAction, 'results' => $results], JSON_UNESCAPED_SLASHES);
        exit;
    }
    /* Hide / unhide an IP from correlation results (persisted). */
    if (in_array($_POST['lc_view'] ?? '', ['hide', 'unhide'], true)) {
        smpro_require_valid_csrf('la_csf');
        header('Content-Type: application/json');
        $act = $_POST['lc_view'];
        $ips = array_unique(array_filter(array_map('trim', explode(',', (string)($_POST['ips'] ?? '')))));
        $done = [];
        foreach ($ips as $ip) if (smpro_hidden_ip_toggle($ip, $act === 'hide')) { $done[] = $ip; smpro_audit('login_correlation_' . $act, ['ip' => $ip]); }
        echo json_encode(['ok' => true, 'action' => $act, 'ips' => $done], JSON_UNESCAPED_SLASHES);
        exit;
    }
    return false;
}

/* ============================ TAB: OVERVIEW ============================ */
function smpro_lm_sshd() {
    $cfg = []; $files = ['/etc/ssh/sshd_config'];
    foreach (glob('/etc/ssh/sshd_config.d/*.conf') ?: [] as $f) $files[] = $f;
    foreach ($files as $file) {
        if (!is_readable($file)) continue;
        foreach (file($file, FILE_IGNORE_NEW_LINES) ?: [] as $l) {
            $l = trim($l); if ($l === '' || $l[0] === '#') continue;
            if (preg_match('/^(\w+)\s+(.+)$/', $l, $m)) $cfg[strtolower($m[1])] = trim($m[2]);
        }
    }
    return $cfg;
}
function smpro_lm_ssh_events($tail, $fromTs) {
    $file = is_readable('/var/log/secure') ? '/var/log/secure' : '/var/log/auth.log';
    $failIps = []; $failUsers = []; $success = []; $failCount = 0;
    foreach (smpro_lm_tail($file, $tail) as $l) {
        if (strpos($l, 'sshd') === false) continue;
        $ts = smpro_lm_syslog_ts($l);
        if ($ts && $ts < $fromTs) continue;
        if (preg_match('/Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+) port/i', $l, $m)) {
            $failCount++; $failUsers[$m[1]] = ($failUsers[$m[1]] ?? 0) + 1; $failIps[$m[2]] = ($failIps[$m[2]] ?? 0) + 1;
        } elseif (preg_match('/Accepted (\S+) for (\S+) from (\S+) port/i', $l, $m)) {
            $success[] = ['method' => $m[1], 'user' => $m[2], 'ip' => $m[3], 'ts' => $ts];
        }
    }
    arsort($failIps); arsort($failUsers);
    return ['fail_count' => $failCount, 'fail_ips' => $failIps, 'fail_users' => $failUsers, 'success' => array_slice(array_reverse($success), 0, 15), 'source' => $file];
}
function smpro_lm_cpanel_failed($tail, $fromTs) {
    $log = '/usr/local/cpanel/logs/login_log'; $ips = []; $count = 0;
    foreach (smpro_lm_tail($log, $tail) as $raw) {
        if (!preg_match('/FAILED\s+LOGIN|DEFERRED\s+LOGIN|FAILURE/i', $raw)) continue;
        $ts = smpro_lm_cpanel_ts($raw); if ($ts && $ts < $fromTs) continue;
        if (preg_match('/^\[[^\]]+\]\s+\S+\s+\[[^\]]+\]\s+(\S+)\s+-/', $raw, $m)) $ip = $m[1];
        elseif (preg_match('/^(\S+)\s+\S+\s+\S+\s+\[/', $raw, $m)) $ip = $m[1];
        else continue;
        $count++; $ips[$ip] = ($ips[$ip] ?? 0) + 1;
    }
    arsort($ips);
    return ['count' => $count, 'ips' => $ips];
}
function smpro_lm_cphulk() {
    $bin = '/usr/local/cpanel/bin/whmapi1';
    if (!is_executable($bin)) return ['enabled' => null];
    $raw = @shell_exec('timeout ' . SMPRO_TIMEOUT_QUICK . ' ' . $bin . ' --output=json cphulk_status 2>/dev/null');
    $d = json_decode((string)$raw, true)['data'] ?? [];
    $en = $d['is_enabled'] ?? ($d['enabled'] ?? null);
    return ['enabled' => is_null($en) ? null : (bool)$en];
}
function smpro_lm_strip_hidden($ipsAssoc, $cloudflare = true) {
    $out = [];
    foreach ($ipsAssoc as $ip => $c) {
        if (!smpro_ip_is_external($ip)) continue;
        if ($cloudflare) { $in = smpro_ip_intel($ip, false); if (stripos((string)($in['provider'] ?? ''), 'CLOUDFLARE') !== false) continue; }
        $out[$ip] = $c;
    }
    return $out;
}
function smpro_lm_yn($v) {
    $l = strtolower((string)$v);
    if ($l === 'yes') return '<span class="b orange">yes</span>';
    if ($l === 'no')  return '<span class="b green">no</span>';
    return '<span class="b gray">' . smpro_h($v) . '</span>';
}
function smpro_lm_geo_cell($ip) {
    $in = smpro_ip_intel($ip, false);
    if (($in['scope'] ?? '') === 'local') return '<span class="b gray">local</span>';
    $cc = strtoupper((string)($in['country'] ?? '')); $bot = smpro_ip_is_datacenter($in); $out = '';
    if ($cc !== '' && $cc !== 'N/A') $out .= '<b>' . smpro_h($cc) . '</b>';
    if (!empty($in['provider']) && $in['provider'] !== 'n/a') $out .= ' <span class="geo-prov">' . smpro_h($in['provider']) . '</span>';
    if ($bot) $out .= ' <span class="b red" title="Datacenter/cloud network — almost always automated">&#129302; bot</span>';
    return $out !== '' ? $out : '<span class="meta">—</span>';
}
function smpro_lm_iprow($ip, $c, $blocked, $from, $to) {
    $brute = $c >= SMPRO_LM_BRUTE; $local = !smpro_ip_is_external($ip); $isBlocked = isset($blocked[$ip]);
    $in = smpro_ip_intel($ip, false); $cc = strtoupper((string)($in['country'] ?? '')); $bot = smpro_ip_is_datacenter($in) ? 1 : 0;
    $chk = $local ? '' : '<input type="checkbox" class="la-chk" value="' . smpro_h($ip) . '">';
    if ($local) $act = '<span class="meta">local</span>';
    elseif ($isBlocked) $act = '<button class="la-act unblock" data-ip="' . smpro_h($ip) . '">Unblock</button>';
    else $act = '<button class="la-act block" data-ip="' . smpro_h($ip) . '">Block</button> <button class="la-act allow" data-ip="' . smpro_h($ip) . '">Allow</button>';
    echo '<tr data-iprow="' . smpro_h($ip) . '" data-cc="' . smpro_h($cc) . '" data-bot="' . $bot . '" data-blocked="' . ($isBlocked ? 1 : 0) . '"'
       . ' data-search="' . smpro_h(strtolower($ip . ' ' . $cc . ' ' . ($in['provider'] ?? ''))) . '">'
       . '<td>' . $chk . '</td>'
       . '<td class="ipmono">' . smpro_h($ip) . ($brute ? ' <span class="b red">brute-force</span>' : '') . '</td>'
       . '<td class="num">' . (int)$c . '</td>'
       . '<td class="geo">' . smpro_lm_geo_cell($ip) . '</td>'
       . '<td class="csfcell">' . smpro_la_csf_badge($blocked, $ip) . '</td>'
       . '<td class="la-actcell">' . $act . '</td>'
       . '<td><a class="lnk" href="' . smpro_h(smpro_la_audit_ip($ip, $from, $to)) . '">Audit</a></td>'
       . '</tr>';
}
function smpro_lm_report($rows, $from, $to, $print) {
    $h = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    echo "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Login Monitor Report</title><style>
*{box-sizing:border-box}body{font:13px/1.5 -apple-system,Segoe UI,Arial,sans-serif;color:#1f2733;margin:0;padding:28px}
h1{font-size:20px;margin:0 0 4px}.muted{color:#6b7686;font-size:12px;margin:0 0 16px}
table{width:100%;border-collapse:collapse;font-size:12px}th,td{border:1px solid #e6eaf1;padding:6px 9px;text-align:left}
th{background:#f4f6fb;text-transform:uppercase;font-size:10px;color:#475569}
.b{display:inline-block;font-size:10px;font-weight:700;padding:1px 7px;border-radius:20px}
.red{background:#fdecec;color:#d93b3b}.green{background:#e9f8ef;color:#1f9d55}.gray{background:#f1f5f9;color:#475569}
.brand{color:#3b5bdb;font-weight:700;float:right}</style></head><body>";
    echo "<div class=\"brand\">&#128737; Safety Monitor Pro</div>";
    echo "<h1>Login Monitor — Failed Attempts</h1><p class=\"muted\">Window " . $h($from) . " → " . $h($to) . " · generated " . $h(date('Y-m-d H:i:s')) . "</p>";
    echo "<table><thead><tr><th>Source</th><th>IP</th><th>Attempts</th><th>Country</th><th>Provider</th><th>Bot</th><th>Brute-force</th><th>CSF blocked</th></tr></thead><tbody>";
    if (!$rows) echo "<tr><td colspan=\"8\" style=\"text-align:center;color:#6b7686;padding:18px\">No failed attempts.</td></tr>";
    foreach ($rows as $r) {
        $bf = $r['brute'] === 'yes' ? '<span class="b red">yes</span>' : 'no';
        $csf = $r['csf'] !== 'no' ? '<span class="b green">' . $h($r['csf']) . '</span>' : '<span class="b gray">no</span>';
        $bot = ($r['bot'] ?? 'no') === 'yes' ? '<span class="b red">bot</span>' : 'no';
        $cc = ($r['country'] ?? '') !== '' && ($r['country'] ?? '') !== 'n/a' ? $h($r['country']) : '';
        echo "<tr><td>" . $h($r['source']) . "</td><td>" . $h($r['ip']) . "</td><td>" . (int)$r['attempts'] . "</td><td>$cc</td><td>" . $h($r['provider'] ?? '') . "</td><td>$bot</td><td>$bf</td><td>$csf</td></tr>";
    }
    echo "</tbody></table>";
    if ($print) echo "<script>window.onload=function(){setTimeout(function(){window.print();},300);};</script>";
    echo "</body></html>";
}

/* ========================== TAB: CORRELATION ========================== */
function smpro_lc_collect($tail, $fromTs, $toTs) {
    $log = '/usr/local/cpanel/logs/login_log'; $ips = [];
    foreach (smpro_lm_tail($log, $tail) as $raw) {
        $raw = trim($raw); if ($raw === '') continue;
        if (preg_match('/^\[([^\]]+)\]\s+\S+\s+\[([^\]]+)\]\s+(\S+)\s+-\s+(\S+)\s+-\s+(.+)$/', $raw, $m)) {
            $timeRaw = $m[1]; $svc = $m[2]; $ip = $m[3]; $actor = rawurldecode($m[4]); $rest = $m[5];
        } elseif (preg_match('/^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*)"\s+(.+)$/', $raw, $m)) {
            $ip = $m[1]; $actor = rawurldecode($m[2]); $timeRaw = $m[3]; $rest = $m[5];
            $svc = preg_match('/\b([a-z0-9_]+):/i', $rest, $sm) ? $sm[1] : (preg_match('/LOGIN\s+(\S+)/i', $rest, $s2) ? $s2[1] : 'cpanel');
        } else { continue; }
        $success = (bool)preg_match('/SUCCEEDED\s+LOGIN|SUCCESS\s+LOGIN/i', $rest);
        $failed  = !$success && (bool)preg_match('/FAILED\s+LOGIN|DEFERRED\s+LOGIN|AUTHENTICATION\s+FAILED|FAILURE/i', $rest);
        if (!$success && !$failed) continue;
        $ts = smpro_lc_ts($timeRaw); if ($ts && ($ts < $fromTs || $ts > $toTs)) continue;
        if (!isset($ips[$ip])) $ips[$ip] = ['ip' => $ip, 'accounts' => [], 'services' => [], 'success' => 0, 'failed' => 0, 'total' => 0, 'first' => PHP_INT_MAX, 'last' => 0];
        $g = &$ips[$ip];
        $g['total']++; $success ? $g['success']++ : $g['failed']++;
        if ($actor !== '' && $actor !== '-') $g['accounts'][strtolower($actor)] = 1;
        if ($svc !== '') $g['services'][$svc] = 1;
        if ($ts) { if ($ts < $g['first']) $g['first'] = $ts; if ($ts > $g['last']) $g['last'] = $ts; }
        unset($g);
    }
    foreach ($ips as &$g) { $g['acct_count'] = count($g['accounts']); $g['svc_list'] = implode(', ', array_keys($g['services'])); if ($g['first'] === PHP_INT_MAX) $g['first'] = 0; }
    unset($g);
    uasort($ips, fn($a, $b) => ($b['total'] <=> $a['total']) ?: ($b['acct_count'] <=> $a['acct_count']));
    return $ips;
}
function smpro_lc_ts($raw) {
    if (preg_match('#^\d{1,2}/\w{1,3}/\d{4}:#', $raw) || preg_match('#^\d{1,2}/\d{1,2}/\d{4}:#', $raw)) $raw = preg_replace('/:/', ' ', $raw, 1);
    return strtotime($raw) ?: 0;
}
function smpro_lc_severity($g, $bot) {
    $f = $g['failed']; $a = $g['acct_count'];
    if ($f >= 50 && ($a >= SMPRO_LC_MULTI || $bot)) return ['Critical', 'crit', 4];
    if ($f >= 20) return ['High', 'high', 3];
    if ($f >= 5)  return ['Medium', 'med', 2];
    return ['Low', 'low', 1];
}

/* ============================ TAB: RESETS ============================ */
/**
 * Password change / reset events across ALL accounts (read-only). Sources:
 *  - access_log: POST to a real change-password endpoint (non-error) = "Password Change";
 *                requests to reset/lost-password endpoints                = "Reset Request".
 *  - login_log : explicit "RESET" markers.
 * Bot file-probes (e.g. GET /.htpasswd) are excluded.
 */
/** Resolve a user/email/domain identifier to its cPanel account via /etc/userdomains. */
function smpro_pwr_resolve_account($id) {
    static $map = null;
    if ($map === null) {
        $map = [];
        if (is_readable('/etc/userdomains')) foreach (file('/etc/userdomains', FILE_IGNORE_NEW_LINES) ?: [] as $ln)
            if (preg_match('/^([^:]+):\s*(\S+)/', $ln, $m)) $map[strtolower(trim($m[1]))] = trim($m[2]);
    }
    $id = trim((string)$id); if ($id === '' || $id === '-') return '';
    if (strpos($id, '@') !== false) { $dom = strtolower(substr(strrchr($id, '@'), 1)); if (isset($map[$dom])) return $map[$dom]; return $id; }
    $low = strtolower($id);
    if (isset($map[$low])) return $map[$low];                 // it's a domain → owner account
    if (in_array($low, $map, true) || is_dir('/home/' . preg_replace('/[^a-z0-9._-]/', '', $low))) return $id;  // already a cPanel user
    return $id;
}
/** Pull a target account/user/email out of a request's query string or path. */
function smpro_pwr_extract_target($query, $path) {
    foreach (['user', 'username', 'account', 'acct', 'login', 'email', 'to', 'domain', 'user_domain'] as $k) {
        if (preg_match('/(?:^|&)' . $k . '=([^&]+)/i', $query, $m)) { $v = rawurldecode($m[1]); if ($v !== '' && $v !== '-' && $v !== '1') return $v; }
    }
    if (preg_match('#/(?:home|users?)/([a-z0-9._-]{2,})#i', $path, $m)) return $m[1];
    return '';
}
function smpro_pwr_collect($tail, $fromTs, $toTs) {
    $events = [];
    $access = '/usr/local/cpanel/logs/access_log';
    foreach (smpro_lm_tail($access, $tail) as $raw) {
        $raw = trim($raw); if ($raw === '') continue;
        if (!preg_match('/^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d{3})/', $raw, $m)) continue;
        $ip = $m[1]; $actor = rawurldecode($m[2]); if ($actor === '-') $actor = ''; $timeRaw = $m[3]; $request = $m[4]; $status = $m[5];
        $method = ''; $path = ''; $query = '';
        if (preg_match('/^(\S+)\s+(\S+)/', $request, $rm)) { $method = strtoupper($rm[1]); $path = parse_url($rm[2], PHP_URL_PATH) ?? $rm[2]; $query = (string)(parse_url($rm[2], PHP_URL_QUERY) ?? ''); }
        if (strpos($path, '.htpasswd') !== false) continue;
        $isChange = (
            strpos($path, 'changepass') !== false || strpos($path, 'change_password') !== false ||
            strpos($path, 'password/change') !== false || strpos($path, 'passwd_pop') !== false ||
            (bool)preg_match('#/passwd(?:/|$)#', $path) || strpos($query, 'emailpass') !== false
        );
        $isReset = (
            strpos($path, 'resetpass') !== false || strpos($path, 'reset_password') !== false ||
            strpos($path, 'passwordreset') !== false || strpos($path, 'lostpwd') !== false ||
            strpos($path, 'forgotpwd') !== false || strpos($path, 'resetrequest') !== false ||
            strpos($query, 'resetpass') !== false
        );
        if (!$isChange && !$isReset) continue;
        $ts = smpro_lc_ts($timeRaw); if ($ts && ($ts < $fromTs || $ts > $toTs)) continue;
        $err = in_array($status, ['400','401','403','404','429'], true);
        if ($isChange && ($method !== 'POST' || $err)) { if (!$isReset) continue; $isChange = false; }
        $kind = $isChange ? 'change' : 'reset';
        // Identify the account: the logged-in actor, else a target id from the request.
        $target = $actor !== '' ? $actor : smpro_pwr_extract_target($query, $path);
        $account = smpro_pwr_resolve_account($target);
        $ua = preg_match('/"[^"]*"\s+"([^"]*)"\s*$/', $raw, $um) ? $um[1] : '';
        $probe = ($account === '' && (stripos($ua, 'python') !== false || stripos($ua, 'curl') !== false || stripos($ua, 'go-http') !== false || stripos($ua, 'bot') !== false || $ua === '' || $ua === '-'));
        $events[] = [
            'ts' => $ts, 'ip' => $ip, 'account' => $account, 'target' => $target, 'probe' => $probe, 'ua' => $ua,
            'kind' => $kind, 'status' => $status, 'method' => $method,
            'result' => $err ? 'failed (HTTP ' . $status . ')' : 'HTTP ' . $status,
            'evidence' => function_exists('smpro_redact_sensitive') ? smpro_redact_sensitive($raw) : $raw,
        ];
    }
    // login_log explicit RESET markers (these usually carry the cPanel account).
    foreach (smpro_lm_tail('/usr/local/cpanel/logs/login_log', $tail) as $raw) {
        if (stripos($raw, 'RESET') === false) continue;
        $raw = trim($raw); if ($raw === '') continue;
        $ip = preg_match('/(\d{1,3}(?:\.\d{1,3}){3})/', $raw, $im) ? $im[1] : '';
        $ts = smpro_lm_cpanel_ts($raw); if ($ts && ($ts < $fromTs || $ts > $toTs)) continue;
        $actor = preg_match('/\]\s+(\S+)\s+-/', $raw, $am) ? rawurldecode($am[1]) : '';
        $account = smpro_pwr_resolve_account($actor);
        $events[] = ['ts' => $ts, 'ip' => $ip, 'account' => $account, 'target' => $actor, 'probe' => false, 'ua' => '',
                     'kind' => 'reset', 'status' => '', 'method' => '', 'result' => 'reset event',
                     'evidence' => function_exists('smpro_redact_sensitive') ? smpro_redact_sensitive($raw) : $raw];
    }
    usort($events, fn($a, $b) => $b['ts'] <=> $a['ts']);
    return $events;
}

/* =====================================================================
 * EXPORTS (per tab) — call from the host before header; exits on a match.
 * ===================================================================== */
function smpro_la_export($tab, $fmt, $days, $from, $to, $fromTs, $toTs) {
if ($tab === 'overview' && in_array($fmt, ['csv', 'html', 'pdf'], true)) {
    $tail = 120000;
    $ssh = smpro_lm_ssh_events($tail, $fromTs); $cpf = smpro_lm_cpanel_failed($tail, $fromTs); $blocked = smpro_lm_csf_blocked();
    $ssh['fail_ips'] = smpro_lm_strip_hidden($ssh['fail_ips'], false); $cpf['ips'] = smpro_lm_strip_hidden($cpf['ips'], false);
    smpro_ip_intel_bulk(array_merge(array_keys(array_slice($ssh['fail_ips'], 0, 80, true)), array_keys(array_slice($cpf['ips'], 0, 80, true))));
    $ssh['fail_ips'] = smpro_lm_strip_hidden($ssh['fail_ips'], true); $cpf['ips'] = smpro_lm_strip_hidden($cpf['ips'], true);
    $rows = []; $build = function ($src, $ip, $c) use ($blocked) {
        $in = smpro_ip_intel($ip);
        return ['source' => $src, 'ip' => $ip, 'attempts' => $c, 'brute' => $c >= SMPRO_LM_BRUTE ? 'yes' : 'no', 'csf' => $blocked[$ip] ?? 'no',
                'country' => $in['country'] ?? '', 'provider' => $in['provider'] ?? '', 'asn' => $in['asn'] ?? '', 'bot' => smpro_ip_is_datacenter($in) ? 'yes' : 'no'];
    };
    foreach (array_slice($ssh['fail_ips'], 0, 80, true) as $ip => $c) $rows[] = $build('SSH', $ip, $c);
    foreach (array_slice($cpf['ips'], 0, 80, true) as $ip => $c) $rows[] = $build('cPanel', $ip, $c);
    if ($fmt === 'csv') {
        $fh = fopen('php://output', 'w');
        fputcsv($fh, ['source', 'ip', 'attempts', 'brute_force', 'csf_blocked', 'country', 'provider', 'asn', 'bot']);
        foreach ($rows as $r) fputcsv($fh, [$r['source'], $r['ip'], $r['attempts'], $r['brute'], $r['csf'], $r['country'], $r['provider'], $r['asn'], $r['bot']]);
        fclose($fh);
    } else smpro_lm_report($rows, $from, $to, $fmt === 'pdf');
    exit;
}
if ($tab === 'correlation' && $fmt === 'csv') {
    $all = array_filter(smpro_lc_collect(150000, $fromTs, $toTs), fn($g) => smpro_ip_is_external($g['ip']));
    smpro_ip_intel_bulk(array_map(fn($g) => $g['ip'], array_slice($all, 0, 150, true)));
    $blocked = smpro_lm_csf_blocked();
    $rows = array_filter($all, fn($g) => $g['total'] > 1);
    $fh = fopen('php://output', 'w');
    fputcsv($fh, ['ip', 'severity', 'country', 'provider', 'bot', 'accounts', 'success', 'failed', 'total', 'first_seen', 'last_seen', 'services', 'csf']);
    foreach ($rows as $g) {
        $in = smpro_ip_intel($g['ip'], false); $bot = smpro_ip_is_datacenter($in); $sev = smpro_lc_severity($g, $bot);
        fputcsv($fh, [$g['ip'], $sev[0], $in['country'] ?? '', $in['provider'] ?? '', $bot ? 'yes' : 'no', $g['acct_count'], $g['success'], $g['failed'], $g['total'],
            $g['first'] ? date('Y-m-d H:i', $g['first']) : '', $g['last'] ? date('Y-m-d H:i', $g['last']) : '', $g['svc_list'], $blocked[$g['ip']] ?? 'no']);
    }
    fclose($fh); exit;
}
if ($tab === 'resets' && $fmt === 'csv') {
    $evs = smpro_pwr_collect(150000, $fromTs, $toTs);
    $fh = fopen('php://output', 'w');
    fputcsv($fh, ['time', 'type', 'account_or_user', 'ip', 'result', 'evidence']);
    foreach ($evs as $e) fputcsv($fh, [$e['ts'] ? date('Y-m-d H:i:s', $e['ts']) : '', $e['kind'] === 'change' ? 'Password Change' : 'Reset Request', (string)($e['account'] ?? $e['user'] ?? $e['target'] ?? $e['actor'] ?? ''), $e['ip'] ?? '', $e['result'] ?? '', $e['evidence'] ?? '']);
    fclose($fh); exit;
}
}

/** Dispatch a Login&Access tab body (overview|correlation|resets). */
function smpro_la_render_tab($tab, $days, $from, $to, $fromTs, $toTs) {
    if ($tab === 'overview')        smpro_la_render_overview($days, $from, $to, $fromTs);
    elseif ($tab === 'correlation') smpro_la_render_correlation($days, $from, $to, $fromTs, $toTs);
    else                            smpro_la_render_resets($days, $from, $to, $fromTs, $toTs);
}

/** Emit the shared CSRF token + CSS + JS used by every Login&Access tab. */
function smpro_la_assets() {
?>
<script>var LA_CSRF=<?= json_encode(smpro_csrf_generate('la_csf')) ?>;</script>
<style>
.la-toolbar{display:flex;gap:8px;align-items:center;position:relative}
.la-tabs{display:flex;gap:4px;border-bottom:2px solid var(--line);margin:16px 0 18px}
.la-tab{padding:10px 18px;font-size:14px;font-weight:600;color:var(--muted);text-decoration:none;border-bottom:3px solid transparent;margin-bottom:-2px;border-radius:8px 8px 0 0}
.la-tab:hover{color:var(--ink);background:var(--brand-bg)}
.la-tab.active{color:var(--brand);border-bottom-color:var(--brand);background:#fff}
.la-scroll{max-height:520px;overflow:auto}.la-scroll table{margin:0}
.la-scroll thead th{position:sticky;top:0;background:#fafbfe;z-index:1;box-shadow:inset 0 -1px 0 var(--line)}
.lm-ffrow{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.lm-chkl{display:flex;align-items:center;gap:6px;font-size:13px;cursor:pointer}
.lm-ipfilter .tp-sel,.lm-ipfilter .tp-in,.tp-in,.tp-sel{border:1px solid var(--line);border-radius:9px;padding:7px 11px;font-size:13px}
.la-act{font-size:11px;font-weight:600;border:1px solid var(--line);background:#fff;border-radius:7px;padding:3px 9px;cursor:pointer}
.la-act.block{color:var(--dang);border-color:#f3c4c4}.la-act.block:hover{background:var(--dang);color:#fff}
.la-act.allow{color:var(--good);border-color:#bfe6cd}.la-act.allow:hover{background:var(--good);color:#fff}
.la-act.unblock{color:var(--brand);border-color:#c9d4ff}.la-act.unblock:hover{background:var(--brand);color:#fff}
.la-actcell,.lc-actcell{white-space:nowrap}
.hidebtn{font-size:11px;font-weight:600;border:1px solid var(--line);background:#fff;color:var(--muted);border-radius:7px;padding:3px 9px;cursor:pointer}
.hidebtn:hover{background:#f1f5f9;color:var(--ink)}.hidebtn.unhide{color:var(--brand);border-color:#c9d4ff}.hidebtn.unhide:hover{background:var(--brand-bg)}
.la-bulkbar{display:none;position:fixed;left:50%;transform:translateX(-50%);bottom:18px;z-index:40;background:#10182b;color:#fff;border-radius:14px;padding:10px 16px;align-items:center;gap:12px;box-shadow:0 18px 40px rgba(0,0,0,.35)}
.la-bulkbar.show{display:flex}.la-bulkbar .meta{color:#cfd8ef}.la-bulkbar b{color:#fff}
.la-bbtn{font-size:13px;font-weight:600;border:0;border-radius:9px;padding:8px 14px;cursor:pointer}
.la-bbtn.block{background:var(--dang);color:#fff}.la-bbtn.allow{background:var(--good);color:#fff}.la-bbtn.ghost{background:#23304d;color:#cfd8ef}
.lm-overview{padding:18px 20px}
.lm-ohead{display:flex;align-items:flex-start;gap:12px;flex-wrap:wrap;margin-bottom:14px}
.lm-ohead .meta{margin-top:4px;max-width:640px}.lm-otitle{font-size:18px;font-weight:700;color:var(--brand)}.lm-ohead .pill{margin-left:auto}
.lm-cards,.lc-cards{display:grid;grid-template-columns:repeat(7,1fr);gap:12px}
.lc-cards{grid-template-columns:repeat(8,1fr)}
@media(max-width:1300px){.lm-cards,.lc-cards{grid-template-columns:repeat(4,1fr)}}
@media(max-width:760px){.lm-cards,.lc-cards{grid-template-columns:repeat(2,1fr)}}
.geo-prov{color:var(--muted);font-size:12px}td.geo{max-width:260px}
.lm-c{background:#f7f9fc;border:1px solid var(--line);border-radius:14px;padding:14px 16px}
.lm-c .lbl{font-size:11px;color:var(--muted);text-transform:uppercase;font-weight:700;letter-spacing:.03em}
.lm-c .v{font-size:23px;font-weight:800;margin-top:6px;line-height:1.1}
.lm-two{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px}
@media(max-width:900px){.lm-two{grid-template-columns:1fr}}
.lm-notes{margin:0;padding-left:18px;font-size:13px;line-height:1.9}
.lm-empty{padding:18px;color:var(--muted);font-size:13px;text-align:center}
.lc-fld{display:flex;flex-direction:column;gap:4px;font-size:11px;text-transform:uppercase;letter-spacing:.03em;color:var(--muted);font-weight:700}
.lc-toolbar2{display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap}
.lc-banner{border-radius:12px;padding:14px 18px;margin-bottom:14px;font-size:14px}
.lc-banner.crit{background:#5b1212;color:#ffe3e3}
.tp-th{display:flex;align-items:center;gap:10px;padding:12px 16px;border-bottom:1px solid var(--line);flex-wrap:wrap}
.tp-th .meta{color:var(--muted);font-size:12px;margin-left:auto}
.smpro-table{width:100%;border-collapse:collapse;font-size:13px}
.smpro-table th,.smpro-table td{padding:8px 12px;text-align:left;border-bottom:1px solid var(--line)}
.smpro-table.nowrap th,.smpro-table.nowrap td{white-space:nowrap}
.smpro-table th{font-size:11px;text-transform:uppercase;color:var(--muted)}
.smpro-table th[data-sort]{cursor:pointer;user-select:none}.smpro-table th[data-sort]:hover{color:var(--brand)}
.smpro-table th.num,.smpro-table td.num{text-align:right}
.smpro-table th.sorted-asc::after{content:" \25B2";font-size:9px}.smpro-table th.sorted-desc::after{content:" \25BC";font-size:9px}
.lm-kv td:first-child{color:var(--muted)}
.ipmono{font-family:ui-monospace,Consolas,monospace;font-weight:700}
.uname{font-family:ui-monospace,Consolas,monospace;font-weight:600}
.lnk{color:var(--brand);text-decoration:none;font-size:12px;border:1px solid var(--line);padding:3px 9px;border-radius:7px}.lnk:hover{background:var(--brand-bg)}
.tp-btn{border:1px solid var(--line);background:#fff;color:var(--ink);border-radius:9px;padding:8px 12px;font-size:13px;cursor:pointer;font-weight:600;text-decoration:none}
.tp-btn.primary{background:var(--brand);color:#fff;border-color:var(--brand)}.tp-btn.green{background:var(--good);color:#fff;border-color:var(--good)}
.aa-export{position:relative}
.aa-menu{display:none;position:absolute;right:0;top:calc(100% + 4px);background:#fff;border:1px solid var(--line);border-radius:10px;box-shadow:0 12px 28px rgba(15,23,42,.12);z-index:5;min-width:140px;overflow:hidden}
.aa-export.open .aa-menu{display:block}
.aa-menu a{display:block;padding:9px 14px;font-size:13px;color:var(--ink);text-decoration:none}.aa-menu a:hover{background:var(--brand-bg);color:var(--brand)}
.pill{display:inline-block;font-size:11px;font-weight:700;padding:3px 10px;border-radius:20px}
.pill.good{background:var(--good-bg);color:var(--good)}.pill.warn{background:var(--warn-bg);color:var(--warn)}.pill.danger{background:var(--dang-bg);color:var(--dang)}
.b{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:20px}
.b.green{background:var(--good-bg);color:var(--good)}.b.orange{background:var(--warn-bg);color:var(--warn)}.b.red{background:var(--dang-bg);color:var(--dang)}.b.gray{background:#f1f5f9;color:#475569}
.b.crit{background:#fdecec;color:#b91c1c}.b.high{background:#fdeee2;color:#c2410c}.b.med{background:#fdf6e7;color:#a16207}.b.low{background:#eef7ee;color:#15803d}
.b.blue{background:var(--brand-bg);color:var(--brand)}
.meta{color:var(--muted)}
.pwr-ev{font-family:ui-monospace,Consolas,monospace;font-size:11px;color:var(--muted);white-space:normal;word-break:break-all;max-width:520px}
</style>
<?php
/* shared CSF JS used by overview + correlation tabs */
?>
<script>
(function(){var b=document.getElementById('laExportBtn');if(!b)return;var box=b.closest('.aa-export');
 b.addEventListener('click',function(e){e.stopPropagation();box.classList.toggle('open');});
 document.addEventListener('click',function(){box.classList.remove('open');});})();

// Shared CSF block/allow/unblock engine (works for both overview & correlation rows).
window.laCsfRun=function(action,ips){
  if(!ips.length)return;
  var verb=action==='block'?'BLOCK (CSF deny)':action==='allow'?'ALLOW (CSF allow)':'UNBLOCK';
  if(!confirm(verb+' '+ips.length+' IP(s)?\n\n'+ips.join('\n')))return;
  var fd=new URLSearchParams();fd.set('la_action',action);fd.set('ips',ips.join(','));fd.set('smpro_csrf',LA_CSRF);
  fetch('index.cgi?page=account-audit',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'})
    .then(function(r){return r.json();})
    .then(function(j){
      if(!j||!j.ok){alert('Action failed (token may have expired — reload).');return;}
      var fail=[];(j.results||[]).forEach(function(r){if(r.ok&&window.laUpdRow)window.laUpdRow(r.ip,action);else if(!r.ok)fail.push(r.ip+': '+r.msg);});
      if(fail.length)alert('Some IPs were not changed:\n'+fail.join('\n'));
    }).catch(function(){alert('Action failed (network/permission).');});
};
function laBadge(state){if(state==='perm')return '<span class="b red">CSF blocked</span>';if(state==='temp')return '<span class="b red">CSF temp</span>';if(state==='allow')return '<span class="b green">CSF allow</span>';return '<span class="b gray">not blocked</span>';}
function laBtns(ip,state){return state==='none'?'<button class="la-act block" data-ip="'+ip+'">Block</button> <button class="la-act allow" data-ip="'+ip+'">Allow</button>':'<button class="la-act unblock" data-ip="'+ip+'">Unblock</button>';}
window.laUpdRow=function(ip,action){
  var state=action==='unblock'?'none':(action==='allow'?'allow':'perm');
  document.querySelectorAll('tr[data-iprow="'+CSS.escape(ip)+'"]').forEach(function(tr){
    tr.setAttribute('data-blocked',action==='unblock'?'0':'1');
    var csf=tr.querySelector('.csfcell');if(csf)csf.innerHTML=laBadge(state);
    var ac=tr.querySelector('.la-actcell,.lc-actcell');if(ac)ac.innerHTML=laBtns(ip,state);
    var ck=tr.querySelector('.la-chk,.lc-chk');if(ck)ck.checked=false;
  });
  if(window.laUpdateBar)window.laUpdateBar();
};
// Per-row click delegation for any .la-act button.
document.addEventListener('click',function(e){var b=e.target.closest('.la-act');if(!b)return;
  var a=b.classList.contains('block')?'block':b.classList.contains('allow')?'allow':'unblock';window.laCsfRun(a,[b.getAttribute('data-ip')]);});
</script>
<?php
}  /* end smpro_la_assets */

/* =====================================================================
 * RENDER: OVERVIEW
 * ===================================================================== */
function smpro_la_render_overview($days, $from, $to, $fromTs) {
    $tail = 120000;
    $ssh = smpro_lm_ssh_events($tail, $fromTs);
    $cpf = smpro_lm_cpanel_failed($tail, $fromTs);
    $blocked = smpro_lm_csf_blocked();
    $ssh['fail_ips'] = smpro_lm_strip_hidden($ssh['fail_ips'], false);
    $cpf['ips']      = smpro_lm_strip_hidden($cpf['ips'], false);
    $cfg = smpro_lm_sshd(); $cphulk = smpro_lm_cphulk();
    $sshPort = $cfg['port'] ?? '22'; $rootLogin = $cfg['permitrootlogin'] ?? 'not set';
    $passAuth = $cfg['passwordauthentication'] ?? 'not set'; $pubAuth = $cfg['pubkeyauthentication'] ?? 'not set';
    $maxAuth = $cfg['maxauthtries'] ?? 'not set'; $usePam = $cfg['usepam'] ?? 'not set';
    $topIps = array_merge(array_keys(array_slice($ssh['fail_ips'], 0, 30, true)), array_keys(array_slice($cpf['ips'], 0, 30, true)), array_map(fn($s) => $s['ip'], $ssh['success']));
    smpro_ip_intel_bulk($topIps);
    $ssh['fail_ips'] = smpro_lm_strip_hidden($ssh['fail_ips'], true);
    $cpf['ips']      = smpro_lm_strip_hidden($cpf['ips'], true);
    $bruteSsh = array_filter($ssh['fail_ips'], fn($c) => $c >= SMPRO_LM_BRUTE);
    $bruteCp  = array_filter($cpf['ips'], fn($c) => $c >= SMPRO_LM_BRUTE);
    $bruteCount = count($bruteSsh) + count($bruteCp);
    $botCount = 0; $botSeen = [];
    foreach (array_merge(array_keys(array_slice($ssh['fail_ips'], 0, 20, true)), array_keys(array_slice($cpf['ips'], 0, 20, true))) as $ip) {
        if (isset($botSeen[$ip])) continue; $botSeen[$ip] = 1;
        if (smpro_ip_is_datacenter(smpro_ip_intel($ip, false))) $botCount++;
    }
    $risk = 0; $notes = [];
    if ($cpf['count'] > 500) { $risk += 25; $notes[] = 'High cPanel/WHM failed login volume in window.'; }
    elseif ($cpf['count'] > 100) { $risk += 15; $notes[] = 'Elevated cPanel/WHM failed login volume.'; }
    if ($cphulk['enabled'] === false) { $risk += 20; $notes[] = 'cPHulk appears disabled.'; }
    if (strtolower($rootLogin) === 'yes') { $risk += 20; $notes[] = 'SSH PermitRootLogin is enabled.'; }
    if (strtolower($passAuth) === 'yes') { $risk += 10; $notes[] = 'SSH password authentication is explicitly enabled.'; }
    if ($ssh['fail_count'] > 200) { $risk += 15; $notes[] = 'High SSH failed login volume detected.'; }
    if ($bruteCount > 0) { $notes[] = $bruteCount . ' brute-force candidate IP(s) (>=' . SMPRO_LM_BRUTE . ' attempts) — check CSF column.'; }
    if (!$notes) $notes[] = 'No major login risks detected in the current window.';
    $notes[] = 'Review repeated failed IPs before blocking anything manually.';
    $risk = min(100, $risk);
    $riskCls = $risk >= 60 ? 'danger' : ($risk >= 30 ? 'warn' : 'good');
    $riskLabel = $risk >= 60 ? 'WARNING' : ($risk >= 30 ? 'REVIEW' : 'GOOD');
    $passColor = strtolower($passAuth) === 'yes' ? 'var(--warn)' : 'var(--good)';
    $cphulkTxt = $cphulk['enabled'] === null ? 'unknown' : ($cphulk['enabled'] ? 'enabled' : 'disabled');
    $cphulkColor = $cphulk['enabled'] === null ? 'var(--muted)' : ($cphulk['enabled'] ? 'var(--good)' : 'var(--warn)');
    $sshFailColor = $ssh['fail_count'] > 0 ? 'var(--dang)' : 'var(--good)';
    ?>
    <div class="card lm-overview" style="border-left:4px solid var(--<?= $riskCls ?>);margin-bottom:14px">
      <div class="lm-ohead">
        <div><div class="lm-otitle">&#128274; Login Risk Overview</div>
          <div class="meta">Window: <?= smpro_h($from) ?> &rarr; <?= smpro_h($to) ?> · score from failed attempts, cPHulk state &amp; SSH hardening.</div></div>
        <span class="pill <?= $riskCls ?>"><?= $riskLabel ?></span>
      </div>
      <div class="lm-cards">
        <div class="lm-c"><div class="lbl">Risk Score</div><div class="v" style="color:var(--<?= $riskCls ?>)"><?= (int)$risk ?>/100</div></div>
        <div class="lm-c"><div class="lbl">SSH Failed</div><div class="v" style="color:<?= $sshFailColor ?>"><?= (int)$ssh['fail_count'] ?></div></div>
        <div class="lm-c"><div class="lbl">cPanel Failed</div><div class="v" style="color:var(--dang)"><?= (int)$cpf['count'] ?></div></div>
        <div class="lm-c"><div class="lbl">Brute-force IPs</div><div class="v" style="color:<?= $bruteCount?'var(--dang)':'var(--good)' ?>"><?= (int)$bruteCount ?></div></div>
        <div class="lm-c"><div class="lbl">Bot / Datacenter</div><div class="v" style="color:<?= $botCount?'var(--dang)':'var(--good)' ?>"><?= (int)$botCount ?></div></div>
        <div class="lm-c"><div class="lbl">cPHulk</div><div class="v" style="color:<?= $cphulkColor ?>"><?= $cphulkTxt ?></div></div>
        <div class="lm-c"><div class="lbl">SSH Password</div><div class="v" style="color:<?= $passColor ?>"><?= smpro_h($passAuth) ?></div></div>
      </div>
    </div>
    <div class="lm-two">
      <div class="card"><div class="lbl" style="margin-bottom:8px">Risk Notes</div>
        <ul class="lm-notes"><?php foreach ($notes as $n): ?><li><?= smpro_h($n) ?></li><?php endforeach; ?></ul></div>
      <div class="card"><div class="lbl" style="margin-bottom:8px">SSH Hardening Posture</div>
        <table class="smpro-table lm-kv">
          <tr><td>Port</td><td><b><?= smpro_h($sshPort) ?></b></td></tr>
          <tr><td>PermitRootLogin</td><td><?= smpro_lm_yn($rootLogin) ?></td></tr>
          <tr><td>PasswordAuthentication</td><td><?= smpro_lm_yn($passAuth) ?></td></tr>
          <tr><td>PubkeyAuthentication</td><td><?= smpro_lm_yn($pubAuth) ?></td></tr>
          <tr><td>MaxAuthTries</td><td><b><?= smpro_h($maxAuth) ?></b></td></tr>
          <tr><td>UsePAM</td><td><?= smpro_lm_yn($usePam) ?></td></tr>
        </table></div>
    </div>
    <div class="card lm-ipfilter" style="margin-bottom:14px">
      <div class="lbl" style="margin-bottom:8px">Filter failed IPs</div>
      <div class="lm-ffrow">
        <label class="lm-chkl"><input type="checkbox" id="laHideBlocked" checked> Hide blocked</label>
        <select class="tp-sel" id="laScope"><option value="all">All countries</option><option value="bot">Bots / datacenter only</option><option value="nonarab">Non-Arab countries</option><option value="arab">Arab countries only</option></select>
        <input class="tp-in" id="laIpSearch" placeholder="Search IP / country / provider…" style="min-width:220px">
        <span class="meta" id="laFcount"></span>
      </div>
    </div>
    <div class="lm-two">
      <div class="card" style="padding:0;overflow:hidden">
        <div class="tp-th"><b>Top Failed SSH IPs</b><span class="meta">Audit to investigate · CSF = already blocked?</span></div>
        <?php if ($ssh['fail_ips']): ?>
        <div class="la-scroll"><table class="smpro-table nowrap"><thead><tr><th style="width:28px"><input type="checkbox" class="la-chkall"></th><th>IP</th><th class="num">Attempts</th><th>Country / Bot</th><th>CSF</th><th>Action</th><th>Drill</th></tr></thead><tbody>
          <?php foreach (array_slice($ssh['fail_ips'], 0, 60, true) as $ip=>$c) smpro_lm_iprow($ip, $c, $blocked, $from, $to); ?>
        </tbody></table></div>
        <?php else: ?><div class="lm-empty">No failed SSH IPs in this window.</div><?php endif; ?>
      </div>
      <div class="card" style="padding:0;overflow:hidden">
        <div class="tp-th"><b>Top Failed SSH Users</b></div>
        <?php if ($ssh['fail_users']): ?>
        <div class="la-scroll"><table class="smpro-table"><thead><tr><th>User</th><th class="num">Attempts</th></tr></thead><tbody>
          <?php foreach (array_slice($ssh['fail_users'], 0, 60, true) as $u=>$c): ?>
            <tr><td class="uname"><?= smpro_h($u) ?></td><td class="num"><?= (int)$c ?><?= $c>=SMPRO_LM_BRUTE?' <span class="b red">brute</span>':'' ?></td></tr>
          <?php endforeach; ?>
        </tbody></table></div>
        <?php else: ?><div class="lm-empty">No failed SSH users in this window.</div><?php endif; ?>
      </div>
    </div>
    <div class="lm-two">
      <div class="card" style="padding:0;overflow:hidden">
        <div class="tp-th"><b>Top Failed cPanel/WHM IPs</b><span class="meta">CSF cross-reference + drill-down</span></div>
        <?php if ($cpf['ips']): ?>
        <div class="la-scroll"><table class="smpro-table nowrap"><thead><tr><th style="width:28px"><input type="checkbox" class="la-chkall"></th><th>IP</th><th class="num">Attempts</th><th>Country / Bot</th><th>CSF</th><th>Action</th><th>Drill</th></tr></thead><tbody>
          <?php foreach (array_slice($cpf['ips'], 0, 60, true) as $ip=>$c) smpro_lm_iprow($ip, $c, $blocked, $from, $to); ?>
        </tbody></table></div>
        <?php else: ?><div class="lm-empty">No failed cPanel/WHM logins in this window.</div><?php endif; ?>
      </div>
      <div class="card" style="padding:0;overflow:hidden">
        <div class="tp-th"><b>Recent Successful SSH Logins</b></div>
        <?php if ($ssh['success']): ?>
        <div class="la-scroll"><table class="smpro-table nowrap"><thead><tr><th>User</th><th>IP</th><th>Method</th><th>Drill</th></tr></thead><tbody>
          <?php foreach ($ssh['success'] as $s): ?>
            <tr><td class="uname"><?= smpro_h($s['user']) ?></td><td class="ipmono"><?= smpro_h($s['ip']) ?></td><td><?= smpro_h($s['method']) ?></td>
              <td><a class="lnk" href="<?= smpro_h(smpro_la_audit_ip($s['ip'], $from, $to)) ?>">Audit</a></td></tr>
          <?php endforeach; ?>
        </tbody></table></div>
        <?php else: ?><div class="lm-empty">No successful SSH logins in this window.</div><?php endif; ?>
      </div>
    </div>
    <div class="la-bulkbar" id="laBulk">
      <span class="meta"><b id="laBulkN">0</b> IP(s) selected</span>
      <button class="la-bbtn block" id="laBulkBlock">&#128683; Block selected (CSF deny)</button>
      <button class="la-bbtn allow" id="laBulkAllow">&#10003; Allow selected</button>
      <button class="la-bbtn ghost" id="laBulkClear">Clear</button>
    </div>
    <script>
    (function(){
      var bar=document.getElementById('laBulk'),barN=document.getElementById('laBulkN');
      function allChk(){return Array.prototype.slice.call(document.querySelectorAll('.la-chk'));}
      function checked(){return allChk().filter(function(c){return c.checked&&c.closest('tr').style.display!=='none';});}
      window.laUpdateBar=function(){var n=checked().length;barN.textContent=n;bar.classList.toggle('show',n>0);
        document.querySelectorAll('.la-chkall').forEach(function(a){var box=a.closest('table').querySelectorAll('.la-chk');
          var ck=Array.prototype.slice.call(box).filter(function(c){return c.checked;}).length;
          a.checked=box.length>0&&ck===box.length;a.indeterminate=ck>0&&ck<box.length;});};
      var ARAB=['SA','EG','AE','KW','QA','BH','OM','JO','LB','IQ','SY','YE','PS','SD','LY','TN','DZ','MA','MR','SO','DJ','KM'];
      function applyFilter(){
        var hb=document.getElementById('laHideBlocked');if(!hb)return;
        var hideB=hb.checked,scope=document.getElementById('laScope').value,qq=(document.getElementById('laIpSearch').value||'').toLowerCase(),shown=0;
        document.querySelectorAll('tr[data-iprow]').forEach(function(tr){
          var blocked=tr.getAttribute('data-blocked')==='1',bot=tr.getAttribute('data-bot')==='1',cc=tr.getAttribute('data-cc')||'',ok=true;
          if(hideB&&blocked)ok=false; if(scope==='bot'&&!bot)ok=false;
          if(scope==='arab'&&ARAB.indexOf(cc)<0)ok=false; if(scope==='nonarab'&&ARAB.indexOf(cc)>=0)ok=false;
          if(qq){var s=tr.getAttribute('data-search')||'';if(s.indexOf(qq)<0)ok=false;}
          tr.style.display=ok?'':'none'; if(!ok){var ck=tr.querySelector('.la-chk');if(ck)ck.checked=false;} if(ok)shown++;});
        var fc=document.getElementById('laFcount');if(fc)fc.textContent=shown+' shown';window.laUpdateBar();}
      ['laHideBlocked','laScope','laIpSearch'].forEach(function(id){var e=document.getElementById(id);if(e){e.addEventListener('input',applyFilter);e.addEventListener('change',applyFilter);}});
      document.addEventListener('change',function(e){if(e.target.classList.contains('la-chk'))window.laUpdateBar();
        if(e.target.classList.contains('la-chkall')){var t=e.target.closest('table');t.querySelectorAll('.la-chk').forEach(function(c){if(c.closest('tr').style.display!=='none')c.checked=e.target.checked;});window.laUpdateBar();}});
      document.getElementById('laBulkBlock').addEventListener('click',function(){window.laCsfRun('block',checked().map(function(c){return c.value;}));});
      document.getElementById('laBulkAllow').addEventListener('click',function(){window.laCsfRun('allow',checked().map(function(c){return c.value;}));});
      document.getElementById('laBulkClear').addEventListener('click',function(){allChk().forEach(function(c){c.checked=false;});window.laUpdateBar();});
      applyFilter();
    })();
    </script>
    <?php
}

/* =====================================================================
 * RENDER: CORRELATION
 * ===================================================================== */
function smpro_la_render_correlation($days, $from, $to, $fromTs, $toTs) {
    $tail = 150000;
    $showHidden = ($_GET['show_hidden'] ?? '') === '1';
    $all = array_filter(smpro_lc_collect($tail, $fromTs, $toTs), fn($g) => smpro_ip_is_external($g['ip']));
    smpro_ip_intel_bulk(array_map(fn($g) => $g['ip'], array_slice($all, 0, 150, true)));
    $all = array_filter($all, function ($g) { $in = smpro_ip_intel($g['ip'], false); return stripos((string)($in['provider'] ?? ''), 'CLOUDFLARE') === false; });
    $blocked = smpro_lm_csf_blocked();
    $totalEvents = 0; $sumSucc = 0; $sumFail = 0;
    foreach ($all as $g) { $totalEvents += $g['total']; $sumSucc += $g['success']; $sumFail += $g['failed']; }
    $uniqueIps = count($all);
    $repeated = array_filter($all, fn($g) => $g['total'] > 1);
    $repeatedCount = count($repeated);
    $hidden = smpro_hidden_ips(); $hiddenCount = count($hidden);
    $rows = $showHidden ? $repeated : array_filter($repeated, fn($g) => !isset($hidden[$g['ip']]));
    $multiIps = count(array_filter($all, fn($g) => $g['acct_count'] >= SMPRO_LC_MULTI));
    $botIps = 0; $critCount = 0;
    foreach ($rows as $g) { $bot = smpro_ip_is_datacenter(smpro_ip_intel($g['ip'], false)); if ($bot) $botIps++; if (smpro_lc_severity($g, $bot)[1] === 'crit') $critCount++; }
    $banner = $critCount > 0 ? 'Critical risk: ' . $critCount . ' IP(s) show high-volume failed logins against multiple accounts. Immediate investigation is recommended.' : null;
    ?>
    <?php if ($banner): ?><div class="lc-banner crit"><b><?= smpro_h($banner) ?></b></div><?php endif; ?>
    <p class="sub" style="margin:0 0 12px">Repeated IPs only — addresses that appeared more than once, with success/failed counts, accounts hit, provider data &amp; severity.</p>
    <div class="lc-cards">
      <div class="lm-c"><div class="lbl">Window</div><div class="v" style="font-size:18px"><?= (int)$days ?>d</div></div>
      <div class="lm-c"><div class="lbl">Total events</div><div class="v"><?= (int)$totalEvents ?></div></div>
      <div class="lm-c"><div class="lbl">Unique IPs</div><div class="v"><?= (int)$uniqueIps ?></div></div>
      <div class="lm-c"><div class="lbl">Repeated IPs</div><div class="v"><?= (int)$repeatedCount ?></div></div>
      <div class="lm-c"><div class="lbl">Success</div><div class="v" style="color:var(--good)"><?= (int)$sumSucc ?></div></div>
      <div class="lm-c"><div class="lbl">Failed</div><div class="v" style="color:var(--dang)"><?= (int)$sumFail ?></div></div>
      <div class="lm-c"><div class="lbl">Multi-account</div><div class="v" style="color:<?= $multiIps?'var(--dang)':'var(--good)' ?>"><?= (int)$multiIps ?></div></div>
      <div class="lm-c"><div class="lbl">Bot / Datacenter</div><div class="v" style="color:<?= $botIps?'var(--dang)':'var(--good)' ?>"><?= (int)$botIps ?></div></div>
    </div>
    <div class="card lm-ipfilter" style="margin:14px 0">
      <div class="lm-ffrow">
        <label class="lm-chkl"><input type="checkbox" id="lcHideBlocked" checked> Hide blocked</label>
        <label class="lm-chkl"><input type="checkbox" id="lcMulti"> Multi-account only</label>
        <select class="tp-sel" id="lcSev"><option value="all">All severities</option><option value="crit">Critical</option><option value="high">High+</option></select>
        <select class="tp-sel" id="lcScope"><option value="all">All countries</option><option value="bot">Bots / datacenter only</option><option value="nonarab">Non-Arab countries</option><option value="arab">Arab countries only</option></select>
        <input class="tp-in" id="lcSearch" placeholder="Search IP / country / service…" style="min-width:200px">
        <a class="tp-btn<?= $showHidden?' primary':'' ?>" href="index.cgi?page=account-audit&tab=correlation&days=<?= $days ?>&show_hidden=<?= $showHidden?'0':'1' ?>"><?= $showHidden ? 'Back to active' : 'Show hidden (' . (int)$hiddenCount . ')' ?></a>
        <span class="meta" id="lcFcount"></span>
      </div>
    </div>
    <div class="card" style="padding:0;overflow:hidden">
      <div class="tp-th"><b>Repeated IP Addresses</b><span class="meta">click a column header to sort · Audit to investigate</span></div>
      <?php if ($rows): ?>
      <div class="la-scroll"><table class="smpro-table nowrap" id="lcTable">
        <thead><tr>
          <th style="width:28px"><input type="checkbox" class="lc-chkall"></th>
          <th data-sort="ip" data-type="s">IP</th><th data-sort="sev" data-type="n">Severity</th>
          <th data-sort="cc" data-type="s">Country / Bot</th><th data-sort="acct" data-type="n" class="num">Accounts</th>
          <th data-sort="success" data-type="n" class="num">Success</th><th data-sort="failed" data-type="n" class="num">Failed</th>
          <th data-sort="total" data-type="n" class="num sorted-desc">Total</th><th data-sort="first" data-type="n">First seen</th>
          <th data-sort="last" data-type="n">Last seen</th><th data-sort="svc" data-type="s">Services</th>
          <th>CSF</th><th>Action</th><th>Drill</th><th>Hide</th>
        </tr></thead><tbody id="lcBody">
        <?php foreach (array_slice($rows, 0, 250, true) as $g): $ip = $g['ip']; $in = smpro_ip_intel($ip, false);
          $cc = strtoupper((string)($in['country'] ?? '')); $bot = smpro_ip_is_datacenter($in) ? 1 : 0;
          $isBlocked = isset($blocked[$ip]); $multi = $g['acct_count'] >= SMPRO_LC_MULTI; $sev = smpro_lc_severity($g, $bot); ?>
          <tr data-iprow="<?= smpro_h($ip) ?>" data-cc="<?= smpro_h($cc) ?>" data-bot="<?= $bot ?>" data-blocked="<?= $isBlocked?1:0 ?>" data-multi="<?= $multi?1:0 ?>"
              data-sev="<?= (int)$sev[2] ?>" data-acct="<?= (int)$g['acct_count'] ?>" data-success="<?= (int)$g['success'] ?>" data-failed="<?= (int)$g['failed'] ?>"
              data-total="<?= (int)$g['total'] ?>" data-first="<?= (int)$g['first'] ?>" data-last="<?= (int)$g['last'] ?>" data-ip="<?= smpro_h($ip) ?>" data-svc="<?= smpro_h($g['svc_list']) ?>"
              data-search="<?= smpro_h(strtolower($ip.' '.$cc.' '.($in['provider']??'').' '.$g['svc_list'].' '.$sev[0])) ?>">
            <td><input type="checkbox" class="lc-chk" value="<?= smpro_h($ip) ?>"></td>
            <td class="ipmono"><?= smpro_h($ip) ?><?= $multi?' <span class="b red">multi-acct</span>':'' ?></td>
            <td><span class="b <?= $sev[1] ?>"><?= smpro_h($sev[0]) ?></span></td>
            <td class="geo"><?php if ($cc!==''&&$cc!=='N/A'): ?><b><?= smpro_h($cc) ?></b> <span class="geo-prov"><?= smpro_h($in['provider']??'') ?></span><?php endif; ?><?= $bot?' <span class="b red">&#129302; bot</span>':'' ?></td>
            <td class="num"><?= (int)$g['acct_count'] ?></td>
            <td class="num" style="color:var(--good)"><?= (int)$g['success'] ?></td>
            <td class="num" style="color:var(--dang)"><?= (int)$g['failed'] ?></td>
            <td class="num"><b><?= (int)$g['total'] ?></b></td>
            <td class="meta"><?= $g['first']?smpro_h(date('m-d H:i', $g['first'])):'—' ?></td>
            <td class="meta"><?= $g['last']?smpro_h(date('m-d H:i', $g['last'])):'—' ?></td>
            <td class="meta"><?= smpro_h($g['svc_list']) ?: '—' ?></td>
            <td class="csfcell"><?= smpro_la_csf_badge($blocked, $ip) ?></td>
            <td class="lc-actcell"><?php if ($isBlocked): ?><button class="la-act unblock" data-ip="<?= smpro_h($ip) ?>">Unblock</button><?php else: ?><button class="la-act block" data-ip="<?= smpro_h($ip) ?>">Block</button> <button class="la-act allow" data-ip="<?= smpro_h($ip) ?>">Allow</button><?php endif; ?></td>
            <td><a class="lnk" href="<?= smpro_h(smpro_la_audit_ip($ip, $from, $to)) ?>">Audit</a></td>
            <td><?php if (isset($hidden[$ip])): ?><button class="hidebtn unhide" data-ip="<?= smpro_h($ip) ?>" data-act="unhide">Unhide</button><?php else: ?><button class="hidebtn" data-ip="<?= smpro_h($ip) ?>" data-act="hide" title="Hide this IP from results">&#10005; Hide</button><?php endif; ?></td>
          </tr>
        <?php endforeach; ?>
        </tbody></table></div>
      <?php else: ?><div class="lm-empty">No repeated IPs found in this window.</div><?php endif; ?>
    </div>
    <div class="la-bulkbar" id="lcBulk">
      <span class="meta"><b id="lcBulkN">0</b> IP(s) selected</span>
      <button class="la-bbtn block" id="lcBulkBlock">&#128683; Block selected (CSF deny)</button>
      <button class="la-bbtn allow" id="lcBulkAllow">&#10003; Allow selected</button>
      <button class="la-bbtn ghost" id="lcBulkClear">Clear</button>
    </div>
    <script>
    (function(){
      var ARABok=function(cc){return ['SA','EG','AE','KW','QA','BH','OM','JO','LB','IQ','SY','YE','PS','SD','LY','TN','DZ','MA','MR','SO','DJ','KM'].indexOf(cc)>=0;};
      var body=document.getElementById('lcBody');if(!body)return;
      var bar=document.getElementById('lcBulk'),barN=document.getElementById('lcBulkN'),chkAll=document.querySelector('.lc-chkall');
      function checked(){return Array.prototype.slice.call(body.querySelectorAll('.lc-chk:checked')).filter(function(c){return c.closest('tr').style.display!=='none';});}
      window.laUpdateBar=function(){var n=checked().length;barN.textContent=n;bar.classList.toggle('show',n>0);
        if(chkAll){var vis=Array.prototype.slice.call(body.querySelectorAll('.lc-chk')).filter(function(c){return c.closest('tr').style.display!=='none';});
          var ck=vis.filter(function(c){return c.checked;}).length;chkAll.checked=vis.length>0&&ck===vis.length;chkAll.indeterminate=ck>0&&ck<vis.length;}};
      function applyFilter(){
        var hideB=document.getElementById('lcHideBlocked').checked,multi=document.getElementById('lcMulti').checked,
            sev=document.getElementById('lcSev').value,scope=document.getElementById('lcScope').value,q=(document.getElementById('lcSearch').value||'').toLowerCase(),shown=0;
        body.querySelectorAll('tr').forEach(function(tr){
          var blocked=tr.getAttribute('data-blocked')==='1',bot=tr.getAttribute('data-bot')==='1',cc=tr.getAttribute('data-cc')||'',mu=tr.getAttribute('data-multi')==='1',sv=+tr.getAttribute('data-sev'),ok=true;
          if(hideB&&blocked)ok=false; if(multi&&!mu)ok=false; if(sev==='crit'&&sv<4)ok=false; if(sev==='high'&&sv<3)ok=false;
          if(scope==='bot'&&!bot)ok=false; if(scope==='arab'&&!ARABok(cc))ok=false; if(scope==='nonarab'&&ARABok(cc))ok=false;
          if(q){var s=tr.getAttribute('data-search')||'';if(s.indexOf(q)<0)ok=false;}
          tr.style.display=ok?'':'none'; if(!ok){var ck=tr.querySelector('.lc-chk');if(ck)ck.checked=false;} if(ok)shown++;});
        var fc=document.getElementById('lcFcount');if(fc)fc.textContent=shown+' shown';window.laUpdateBar();}
      ['lcHideBlocked','lcMulti','lcSev','lcScope','lcSearch'].forEach(function(id){var e=document.getElementById(id);if(e){e.addEventListener('input',applyFilter);e.addEventListener('change',applyFilter);}});
      var sortKey='total',sortDir='desc';
      function sort(){var rows=Array.prototype.slice.call(body.querySelectorAll('tr'));
        var th=document.querySelector('th[data-sort="'+sortKey+'"]');var type=th?th.getAttribute('data-type'):'n';
        rows.sort(function(a,b){var x=a.getAttribute('data-'+sortKey)||'',y=b.getAttribute('data-'+sortKey)||'';
          if(type==='n'){x=parseFloat(x)||0;y=parseFloat(y)||0;return sortDir==='asc'?x-y:y-x;}
          return sortDir==='asc'?String(x).localeCompare(y):String(y).localeCompare(x);});
        rows.forEach(function(r){body.appendChild(r);});}
      document.querySelectorAll('#lcTable th[data-sort]').forEach(function(th){th.addEventListener('click',function(){
        var k=th.getAttribute('data-sort');if(sortKey===k)sortDir=sortDir==='asc'?'desc':'asc';else{sortKey=k;sortDir=(th.getAttribute('data-type')==='s')?'asc':'desc';}
        document.querySelectorAll('#lcTable th').forEach(function(h){h.classList.remove('sorted-asc','sorted-desc');});
        th.classList.add(sortDir==='asc'?'sorted-asc':'sorted-desc');sort();});});
      function hideIp(ip,act){var fd=new URLSearchParams();fd.set('lc_view',act);fd.set('ips',ip);fd.set('smpro_csrf',LA_CSRF);
        fetch('index.cgi?page=account-audit',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'})
          .then(function(r){return r.json();}).then(function(j){if(j&&j.ok){body.querySelectorAll('tr[data-iprow="'+CSS.escape(ip)+'"]').forEach(function(tr){tr.remove();});applyFilter();}else alert('Failed (reload and retry).');})
          .catch(function(){alert('Failed (network).');});}
      body.addEventListener('change',function(e){if(e.target.classList.contains('lc-chk'))window.laUpdateBar();});
      if(chkAll)chkAll.addEventListener('change',function(){body.querySelectorAll('.lc-chk').forEach(function(c){if(c.closest('tr').style.display!=='none')c.checked=chkAll.checked;});window.laUpdateBar();});
      body.addEventListener('click',function(e){var h=e.target.closest('.hidebtn');if(h){hideIp(h.getAttribute('data-ip'),h.getAttribute('data-act'));return;}});
      document.getElementById('lcBulkBlock').addEventListener('click',function(){window.laCsfRun('block',checked().map(function(c){return c.value;}));});
      document.getElementById('lcBulkAllow').addEventListener('click',function(){window.laCsfRun('allow',checked().map(function(c){return c.value;}));});
      document.getElementById('lcBulkClear').addEventListener('click',function(){body.querySelectorAll('.lc-chk').forEach(function(c){c.checked=false;});window.laUpdateBar();});
      applyFilter();
    })();
    </script>
    <?php
}

/* =====================================================================
 * RENDER: PASSWORD RESETS
 * ===================================================================== */
function smpro_la_render_resets($days, $from, $to, $fromTs, $toTs) {
    $evs = smpro_pwr_collect(150000, $fromTs, $toTs);
    $changes = array_filter($evs, fn($e) => $e['kind'] === 'change');
    $resets  = array_filter($evs, fn($e) => $e['kind'] === 'reset');
    $withAcct = array_filter($evs, fn($e) => ($e['account'] ?? '') !== '');
    $probes   = array_filter($evs, fn($e) => !empty($e['probe']));
    // Distinct accounts that had a password operation.
    $acctSet = [];
    foreach ($withAcct as $e) { $a = strtolower($e['account']); $acctSet[$a] = ($acctSet[$a] ?? 0) + 1; }
    arsort($acctSet);
    $ipBulk = array_values(array_unique(array_map(fn($e) => $e['ip'], array_slice($evs, 0, 120))));
    if ($ipBulk) smpro_ip_intel_bulk(array_filter($ipBulk));
    $pwrIsLocal = fn($ip) => $ip === '' || $ip === '::1' || $ip === 'localhost' || strncmp((string)$ip, '127.', 4) === 0;
    $localCount = 0; foreach ($evs as $e) if ($pwrIsLocal($e['ip'] ?? '')) $localCount++;
    // Same foreign-country rule as Account Audit: a password CHANGE from a non-Arab country is suspicious.
    $foreignChanges = [];
    foreach ($evs as $e) {
        if (($e['kind'] ?? '') !== 'change' || empty($e['ip']) || $pwrIsLocal($e['ip'])) continue;
        $g = function_exists('smpro_geo_foreign') ? smpro_geo_foreign($e['ip']) : ['foreign'=>false];
        if (!empty($g['foreign'])) $foreignChanges[] = ['ip'=>$e['ip'],'cc'=>$g['cc'],'acct'=>$e['account'] ?? '','ts'=>$e['ts']];
    }
    ?>
    <?php if ($foreignChanges): ?>
    <div style="display:flex;gap:12px;align-items:flex-start;padding:12px 14px;border-radius:12px;border:1px solid #f3c9c9;background:#fff5f5;margin:0 0 12px">
      <div style="font-size:20px">&#128681;</div>
      <div style="flex:1">
        <b style="font-size:13.5px"><?= count($foreignChanges) ?> password change(s) from a FOREIGN (non-Arab) country</b>
        <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:7px">
          <?php foreach (array_slice($foreignChanges, 0, 8) as $fc): ?>
          <span style="background:#fff;border:1px solid var(--line);border-radius:20px;padding:3px 10px;font-size:12px;font-family:ui-monospace,Consolas,monospace"><?= smpro_h($fc['cc']) ?> &middot; <?= smpro_h($fc['ip']) ?> &middot; <?= smpro_h($fc['acct'] ?: '—') ?></span>
          <?php endforeach; ?>
        </div>
      </div>
    </div>
    <?php endif; ?>
    <p class="sub" style="margin:0 0 12px">Password change &amp; reset activity across all accounts (cPanel access_log + login_log). The <b>Account</b> column resolves the target to its cPanel account; anonymous bot probes of the reset page (no account, automated user-agents) are tagged and can be filtered out.</p>
    <div class="lc-cards" style="grid-template-columns:repeat(5,1fr)">
      <div class="lm-c"><div class="lbl">Total events</div><div class="v"><?= count($evs) ?></div></div>
      <div class="lm-c"><div class="lbl">Accounts affected</div><div class="v" style="color:<?= count($acctSet)?'var(--brand)':'var(--muted)' ?>"><?= count($acctSet) ?></div></div>
      <div class="lm-c"><div class="lbl">Password changes</div><div class="v" style="color:var(--warn)"><?= count($changes) ?></div></div>
      <div class="lm-c"><div class="lbl">Reset requests</div><div class="v"><?= count($resets) ?></div></div>
      <div class="lm-c"><div class="lbl">Anonymous probes</div><div class="v" style="color:<?= count($probes)?'var(--dang)':'var(--good)' ?>"><?= count($probes) ?></div></div>
    </div>

    <?php if ($acctSet): ?>
    <div class="card" style="padding:0;overflow:hidden;margin:14px 0">
      <div class="tp-th"><b>&#128100; Accounts with a password operation</b><span class="meta"><?= count($acctSet) ?> account(s) · click to filter the table</span></div>
      <div style="display:flex;flex-wrap:wrap;gap:8px;padding:12px 14px">
        <?php foreach (array_slice($acctSet, 0, 40, true) as $a => $n): ?>
          <button type="button" class="pwr-acct" data-acct="<?= smpro_h($a) ?>"><b><?= smpro_h($a) ?></b> <span class="pwr-n"><?= (int)$n ?></span></button>
        <?php endforeach; ?>
      </div>
    </div>
    <?php endif; ?>

    <div class="card lm-ipfilter" style="margin:14px 0">
      <div class="lm-ffrow">
        <select class="tp-sel" id="pwrScope"><option value="acct">With account only</option><option value="all">All events</option><option value="probe">Anonymous probes only</option></select>
        <select class="tp-sel" id="pwrType"><option value="all">All types</option><option value="change">Password changes</option><option value="reset">Reset requests</option></select>
        <input class="tp-in" id="pwrSearch" placeholder="Search account / IP…" style="min-width:240px">
        <label class="meta" style="display:inline-flex;align-items:center;gap:6px;cursor:pointer"><input type="checkbox" id="pwrLocal"> Show local (127.0.0.1)<?= $localCount?' · '.$localCount.' hidden':'' ?></label>
        <span class="meta" id="pwrCount"></span>
      </div>
    </div>
    <div class="card" style="padding:0;overflow:hidden">
      <div class="tp-th"><b>Password Change / Reset Events</b><span class="meta">newest first · Audit to investigate the IP</span></div>
      <?php if ($evs): ?>
      <div class="la-scroll"><table class="smpro-table" id="pwrTable"><thead><tr><th>Time</th><th>Type</th><th>Account</th><th>IP</th><th>Country / Bot</th><th>Result</th><th>Drill</th></tr></thead><tbody>
        <?php foreach (array_slice($evs, 0, 500) as $e):
          $fail = stripos($e['result'], 'failed') !== false;
          $acct = (string)($e['account'] ?? ''); $probe = !empty($e['probe']);
          $acctCell = $acct !== '' ? '<b>' . smpro_h($acct) . '</b>'
                    : ($probe ? '<span class="b gray" title="No account in the request; automated user-agent">bot probe</span>'
                              : ($e['target'] ? '<span class="meta" title="Unresolved target">' . smpro_h($e['target']) . '</span>' : '<span class="meta">&mdash;</span>'));
          $acctKey = strtolower($acct); ?>
          <tr data-type="<?= smpro_h($e['kind']) ?>" data-acct="<?= smpro_h($acctKey) ?>" data-has="<?= $acct!==''?1:0 ?>" data-probe="<?= $probe?1:0 ?>" data-local="<?= $pwrIsLocal($e['ip']??'')?1:0 ?>" data-search="<?= smpro_h(strtolower($acct.' '.($e['target']??'').' '.$e['ip'])) ?>">
            <td class="mono"><?= $e['ts']?smpro_h(date('Y-m-d H:i:s', $e['ts'])):'—' ?></td>
            <td><?= $e['kind']==='change'?'<span class="b orange">Password Change</span>':'<span class="b blue">Reset Request</span>' ?></td>
            <td class="uname"><?= $acctCell ?></td>
            <td class="ipmono"><?= smpro_h($e['ip'] ?: '—') ?></td>
            <td class="geo"><?= $e['ip']?smpro_lm_geo_cell($e['ip']):'<span class="meta">—</span>' ?></td>
            <td><?= $fail?'<span class="b red">'.smpro_h($e['result']).'</span>':'<span class="b green">'.smpro_h($e['result']).'</span>' ?></td>
            <td><?= $e['ip']?'<a class="lnk" href="'.smpro_h(smpro_la_audit_ip($e['ip'], $from, $to)).'">Audit</a>':'—' ?></td>
          </tr>
          <tr class="pwr-evrow" data-type="<?= smpro_h($e['kind']) ?>" data-acct="<?= smpro_h($acctKey) ?>" data-has="<?= $acct!==''?1:0 ?>" data-probe="<?= $probe?1:0 ?>" data-local="<?= $pwrIsLocal($e['ip']??'')?1:0 ?>" data-search="<?= smpro_h(strtolower($acct.' '.($e['target']??'').' '.$e['ip'])) ?>"><td></td><td colspan="6" class="pwr-ev"><?= smpro_h($e['evidence']) ?></td></tr>
        <?php endforeach; ?>
      </tbody></table></div>
      <?php else: ?><div class="lm-empty">No password change/reset events in this window. (If you expected some, widen the time range — access_log rotates.)</div><?php endif; ?>
    </div>
    <script>
    (function(){
      var sc=document.getElementById('pwrScope'),t=document.getElementById('pwrType'),s=document.getElementById('pwrSearch'),lo=document.getElementById('pwrLocal'),tbl=document.getElementById('pwrTable');if(!tbl)return;
      var pinned='';
      function apply(){var scope=sc.value,ty=t.value,q=(s.value||'').toLowerCase(),showLocal=lo&&lo.checked,shown=0;
        tbl.querySelectorAll('tbody tr').forEach(function(tr){
          var ok=true,k=tr.getAttribute('data-type')||'',has=tr.getAttribute('data-has')==='1',probe=tr.getAttribute('data-probe')==='1',ac=tr.getAttribute('data-acct')||'',loc=tr.getAttribute('data-local')==='1';
          if(loc&&!showLocal)ok=false;                 // hide localhost (127.0.0.1) unless "Show local" is on
          if(scope==='acct'&&!has)ok=false; if(scope==='probe'&&!probe)ok=false;
          if(ty!=='all'&&k!==ty)ok=false;
          if(pinned&&ac!==pinned)ok=false;
          if(q){var ss=tr.getAttribute('data-search')||'';if(ss.indexOf(q)<0)ok=false;}
          tr.style.display=ok?'':'none'; if(ok&&!tr.classList.contains('pwr-evrow'))shown++;});
        var c=document.getElementById('pwrCount');if(c)c.textContent=shown+' shown'+(pinned?' · '+pinned:'');}
      sc.addEventListener('change',apply);t.addEventListener('change',apply);s.addEventListener('input',apply);if(lo)lo.addEventListener('change',apply);
      document.querySelectorAll('.pwr-acct').forEach(function(b){b.addEventListener('click',function(){
        var a=b.getAttribute('data-acct');pinned=(pinned===a)?'':a;
        document.querySelectorAll('.pwr-acct').forEach(function(x){x.classList.toggle('on',x.getAttribute('data-acct')===pinned);});
        sc.value='all';apply();});});
      apply();
    })();
    </script>
    <style>.pwr-evrow td{padding-top:0;border-bottom:1px solid var(--line)}.mono{font-family:ui-monospace,Consolas,monospace}
    .pwr-acct{border:1px solid var(--line);background:#fff;border-radius:20px;padding:5px 12px;font-size:12px;cursor:pointer}
    .pwr-acct:hover{background:var(--brand-bg)}.pwr-acct.on{background:var(--brand);color:#fff;border-color:var(--brand)}
    .pwr-acct .pwr-n{display:inline-block;background:#eef1f6;color:#475569;border-radius:12px;padding:0 7px;font-size:11px;margin-left:3px}
    .pwr-acct.on .pwr-n{background:rgba(255,255,255,.25);color:#fff}</style>
    <?php
}
