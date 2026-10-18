<?php
/**
 * includes/geologin.php — Country Login Lock: an account may only be signed into from countries you allow.
 *
 * The threat this closes is the one that has actually happened here: a correct password, used by somebody who is
 * not the customer. Nothing about the login looks wrong — the password IS right — so no brute-force rule fires,
 * no failed-login counter moves, and the first sign of trouble is a defaced site. What IS wrong is the place it
 * came from, and that is knowable at the moment it happens.
 *
 * WHY THIS IS NOT A COUNTRY FIREWALL. Blocking whole countries at the firewall took sites down on this estate
 * once already (CSF's CC_ALLOW_FILTER, which also killed every WhatsApp webhook). So this deliberately does not
 * do that, in three ways:
 *
 *   1. LOGIN PORTS ONLY. Rules are written as port-scoped CSF entries — cPanel, WHM, webmail, mail, FTP, SSH.
 *      Ports 80 and 443 are NEVER touched, so a website stays reachable from every country on earth. A visitor
 *      from a country that may not log in can still read the site, buy from it, and submit its forms.
 *   2. REACTIVE, NOT PRE-EMPTIVE. No country is denied in advance. A rule is written only when a login is
 *      actually SEEN from a country that is not allowed, so the rule set stays small and every single rule can
 *      be traced back to the event that caused it.
 *   3. IT REFUSES TO LOCK YOU OUT. It will not arm unless the operator's own country is on the list, the server's
 *      own addresses and both allow-lists are exempt, and there is a dry run that writes nothing.
 *
 * A SUCCESSFUL login from a country that is not allowed is the serious case: the password is already known to
 * somebody. That is treated as an incident, not as noise, and is reported even in dry run.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

if (!defined('SMPRO_GL_CFG'))   define('SMPRO_GL_CFG',   SMPRO_VARLIB . '/geologin.json');
if (!defined('SMPRO_GL_STATE')) define('SMPRO_GL_STATE', SMPRO_VARLIB . '/geologin_state.json');
if (!defined('SMPRO_GL_DENY'))  define('SMPRO_GL_DENY',  '/etc/csf/csf.deny');
if (!defined('SMPRO_GL_MARK'))  define('SMPRO_GL_MARK',  'smpro-geologin');
// The firewall side lives in a kernel set when the server can keep one (includes/geoset.php); csf.deny lines are the fallback.
if (!function_exists('smpro_gs_available')) { $gsf = __DIR__ . '/geoset.php'; if (is_file($gsf)) require_once $gsf; }
function smpro_gl_use_set(): bool { return function_exists('smpro_gs_available') && smpro_gs_available(); }

/**
 * The doors this locks, and the ones it must never touch.
 *
 * 80 and 443 are absent on purpose and there is no setting that can add them: a country lock that can take a
 * website off the internet is a different, far more dangerous feature than the one this is meant to be.
 */
function smpro_gl_services(): array {
    return [
        'cpanel'  => ['name' => 'cPanel',        'ports' => [2082, 2083]],
        'whm'     => ['name' => 'WHM',           'ports' => [2086, 2087]],
        'webmail' => ['name' => 'Webmail',       'ports' => [2095, 2096]],
        'mail'    => ['name' => 'Mail (IMAP/POP/SMTP)', 'ports' => [110, 143, 465, 587, 993, 995]],
        'ftp'     => ['name' => 'FTP',           'ports' => [21]],
        'ssh'     => ['name' => 'SSH',           'ports' => [22]],
    ];
}

function smpro_gl_defaults(): array {
    return [
        'enabled'    => false,      // never on until somebody turns it on and passes the lock-out guard
        'dryrun'     => true,       // and it starts in report-only even then
        'countries'  => [],         // ISO codes allowed to SIGN IN. Empty = the feature cannot arm.
        'services'   => ['cpanel', 'whm', 'webmail', 'ftp', 'ssh'],   // mail is off by default: phones roam
        // Extra login ports this server uses: an SSH daemon moved off 22, an SMTP submission port that is not
        // 465/587. A door the lock does not know about is a door it leaves open, so the operator names them here.
        'custom_ports' => [],
        'per_account'=> [],         // account => [cc, …] — overrides the list above for that account only
        'on_success' => 'block',    // a correct password from a country not allowed: block | alert
        // End what is already open, not just the next attempt. A correct password from a country you do
        // not allow means somebody is inside NOW; closing the port behind them leaves them working.
        'evict'      => true,
        'on_failed'  => 'ignore',   // a wrong password from there is ordinary noise: ignore | block
        'ttl_days'   => 30,         // how long a rule stands before the sweeper removes it
    ];
}

function smpro_gl_cfg(): array {
    $d = @is_file(SMPRO_GL_CFG) ? json_decode((string)@file_get_contents(SMPRO_GL_CFG), true) : null;
    $c = array_replace(smpro_gl_defaults(), is_array($d) ? $d : []);
    $c['countries'] = smpro_gl_clean_cc((array)$c['countries']);
    $svc = [];
    foreach ((array)$c['services'] as $s) if (isset(smpro_gl_services()[$s])) $svc[] = $s;
    $c['services'] = array_values(array_unique($svc));
    $pa = [];
    foreach ((array)$c['per_account'] as $u => $list) {
        // A mailbox is an identity here too, and '@' is part of its name. Stripping it stored
        // info@example.com as "infoexample.com" - a key the operator cannot recognise in the list they are
        // editing, and one that matches no account and no mailbox anywhere else in the product.
        $u = preg_replace('/[^a-zA-Z0-9._@-]/', '', (string)$u);
        if ($u === '') continue;
        $pa[$u] = smpro_gl_clean_cc((array)$list);
    }
    $c['per_account'] = $pa;
    return $c;
}
function smpro_gl_cfg_save(array $patch): array {
    $c = array_replace(smpro_gl_cfg(), $patch);
    @is_dir(SMPRO_VARLIB) || @mkdir(SMPRO_VARLIB, 0700, true);
    $t = SMPRO_GL_CFG . '.tmp';
    if (@file_put_contents($t, json_encode($c, JSON_UNESCAPED_SLASHES), LOCK_EX) !== false) { @chmod($t, 0600); @rename($t, SMPRO_GL_CFG); }
    // The scheduled run follows the setting immediately, and is removed when the lock is turned off. Saving
    // "armed" without installing anything to act is how this feature spent its life showing ARMED while
    // csf.deny held none of its rules.
    if (function_exists('smpro_gl_cron_sync')) smpro_gl_cron_sync();
    if (!empty($c['enabled']) && !defined('SMPRO_TEST_SRC')) {
        if (smpro_gl_use_set()) smpro_gl_set_up($c);               // the kernel set, its rule, the CSF hook, and any old csf.deny lines moved over
        else smpro_gl_ensure_deny_limit();                          // fallback: the lock's rules need room in csf.deny
    }
    return smpro_gl_cfg();
}
/** Ports typed by the operator: integers 1-65535, never the web ports, deduplicated and sorted. */
function smpro_gl_clean_ports($in): array {
    $out = [];
    foreach (is_array($in) ? $in : preg_split('/[\s,;]+/', (string)$in) as $p) {
        $p = (int)trim((string)$p);
        if ($p >= 1 && $p <= 65535 && $p !== 80 && $p !== 443) $out[$p] = 1;
    }
    $k = array_keys($out); sort($k);
    return $k;
}
function smpro_gl_clean_cc(array $in): array {
    $out = [];
    foreach ($in as $c) { $c = strtoupper(preg_replace('/[^A-Za-z]/', '', (string)$c)); if (strlen($c) === 2) $out[$c] = 1; }
    return array_keys($out);
}
function smpro_gl_state(): array { $d = @is_file(SMPRO_GL_STATE) ? json_decode((string)@file_get_contents(SMPRO_GL_STATE), true) : null; return is_array($d) ? $d : []; }
function smpro_gl_state_save(array $s): void {
    $t = SMPRO_GL_STATE . '.tmp';
    if (@file_put_contents($t, json_encode($s, JSON_UNESCAPED_SLASHES), LOCK_EX) !== false) { @chmod($t, 0600); @rename($t, SMPRO_GL_STATE); }
}

/** Which countries may sign in to THIS account: its own list if it has one, otherwise the server's. */
function smpro_gl_allowed_for(string $account, array $cfg = []): array {
    $cfg = $cfg ?: smpro_gl_cfg();
    $u = preg_replace('/[^a-zA-Z0-9._@-]/', '', $account);   // '@' kept: a mailbox is an identity too
    if ($u !== '' && !empty($cfg['per_account'][$u])) return $cfg['per_account'][$u];
    return $cfg['countries'];
}

/** The country an address is in, or '' when this server cannot tell. '' NEVER counts as "not allowed". */
function smpro_gl_country(string $ip): string {
    if (function_exists('smpro_geo_foreign')) { $g = smpro_geo_foreign($ip); $cc = strtoupper((string)($g['cc'] ?? '')); if (strlen($cc) === 2) return $cc; }
    if (function_exists('smpro_ip_intel')) { $in = (array)smpro_ip_intel($ip); $cc = strtoupper((string)($in['country'] ?? '')); if (strlen($cc) === 2) return $cc; }
    return '';
}

/**
 * Addresses this must never act on.
 *
 * The server's own addresses are in here because a cPanel login proxied through the machine itself arrives FROM
 * the machine: locking that out takes the whole panel down for everyone at once.
 */
function smpro_gl_exempt(string $ip): string {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return 'not an address';
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) return 'private or local';
    static $mine = null;
    if ($mine === null) {
        $mine = [];
        foreach (explode("\n", (string)@shell_exec("hostname -I 2>/dev/null")) as $line)
            foreach (preg_split('/\s+/', trim($line)) as $a) if (filter_var($a, FILTER_VALIDATE_IP)) $mine[$a] = 1;
        foreach ((array)@file('/etc/ips', FILE_IGNORE_NEW_LINES) as $l)
            if (preg_match('/^([0-9a-fA-F:.]+)/', trim((string)$l), $m) && filter_var($m[1], FILTER_VALIDATE_IP)) $mine[$m[1]] = 1;
    }
    if (isset($mine[$ip])) return 'this server\'s own address';
    if (!function_exists('smpro_ip_is_cloudflare')) { $fi = __DIR__ . '/intrusion.php'; if (is_file($fi)) require_once $fi; }
    if (function_exists('smpro_ip_is_cloudflare') && smpro_ip_is_cloudflare($ip)) return 'a Cloudflare edge address (blocking it would cut every proxied site; the real client is behind it)';
    if (function_exists('smpro_fw_allow_covers') && smpro_fw_allow_covers($ip) !== '') return 'on the firewall allow-list';
    if (function_exists('smpro_im_allowlisted') && smpro_im_allowlisted($ip)) return 'on the plugin allow-list';
    if (function_exists('smpro_bg_crawler_shield')) { $cs = smpro_bg_crawler_shield($ip); if (!empty($cs['crawler'])) return 'a verified ' . $cs['name']; }
    return '';
}

/**
 * May this feature be armed at all?
 *
 * Refuses on the three ways it could lock its owner out, and says which. An empty country list is refused
 * outright: it would mean "no country may sign in", which locks out everybody including the person reading this.
 */
function smpro_gl_arm_check(array $cfg, string $operatorIp = ''): array {
    $problems = [];
    if (!$cfg['countries'])  $problems[] = 'No country is on the list. That would mean nobody at all may sign in — including you.';
    if (!$cfg['services'])   $problems[] = 'No service is selected, so the lock would do nothing.';

    $ip = $operatorIp !== '' ? $operatorIp : (string)($_SERVER['REMOTE_ADDR'] ?? '');
    $cc = $ip !== '' ? smpro_gl_country($ip) : '';
    if ($ip !== '' && smpro_gl_exempt($ip) === '') {
        if ($cc === '') $problems[] = 'This server cannot tell which country you are connecting from (' . $ip . '), so it cannot promise not to lock you out. Install or update the GeoIP database first.';
        elseif (!in_array($cc, $cfg['countries'], true))
            $problems[] = 'You are connecting from ' . $cc . ', which is not on the list. Arming this would lock you out of WHM. Add ' . $cc . ', or allow-list ' . $ip . ' first.';
    }
    return ['ok' => !$problems, 'problems' => $problems, 'your_ip' => $ip, 'your_cc' => $cc];
}

/* ----------------------------- the rule ----------------------------- */

/** The csf.deny lines for one address: one per login port, so 80 and 443 stay open. */
function smpro_gl_rule_lines(string $ip, array $ports, string $why): array {
    $out = [];
    foreach ($ports as $p) $out[] = 'tcp|in|d=' . (int)$p . '|s=' . $ip . ' # ' . SMPRO_GL_MARK . ' ' . $why;
    return $out;
}
function smpro_gl_ports_for(array $cfg): array {
    $svc = smpro_gl_services(); $ports = [];
    foreach ((array)$cfg['services'] as $s) foreach ((array)($svc[$s]['ports'] ?? []) as $p) $ports[(int)$p] = 1;
    foreach (smpro_gl_clean_ports($cfg['custom_ports'] ?? []) as $p) $ports[$p] = 1;   // the operator's own SSH / SMTP ports
    // Belt and braces: even if a service list were tampered with, the web ports can never appear here.
    unset($ports[80], $ports[443]);
    return array_keys($ports);
}

/**
 * CSF keeps at most DENY_IP_LIMIT lines in csf.deny and silently drops the oldest beyond it. The lock writes one
 * line per port per address (~11 per address), so twenty addresses exhaust the default 200 - and on a production
 * server csf.deny held 246 lines, the address the lock had "blocked" was no longer in it, and the sign-in got
 * through. The lock raises the limit to what its own rules need before it writes another line.
 */
function smpro_gl_ensure_deny_limit(int $want = 5000): array {
    $f = '/etc/csf/csf.conf';
    if (!@is_file($f) || !@is_writable($f)) return ['ok' => false, 'was' => 0, 'now' => 0, 'msg' => 'csf.conf not writable'];
    $conf = (string)@file_get_contents($f);
    if (!preg_match('/^DENY_IP_LIMIT\s*=\s*"(\d+)"/m', $conf, $m)) return ['ok' => false, 'was' => 0, 'now' => 0, 'msg' => 'DENY_IP_LIMIT not found'];
    $was = (int)$m[1];
    if ($was >= $want) return ['ok' => true, 'was' => $was, 'now' => $was, 'msg' => 'already ' . $was];
    $new = preg_replace('/^DENY_IP_LIMIT\s*=\s*"\d+"/m', 'DENY_IP_LIMIT = "' . $want . '"', $conf, 1);
    if ($new === null || @file_put_contents($f . '.smpro.tmp', $new, LOCK_EX) === false || !@rename($f . '.smpro.tmp', $f)) return ['ok' => false, 'was' => $was, 'now' => $was, 'msg' => 'could not rewrite csf.conf'];
    if (function_exists('smpro_audit')) @smpro_audit('geologin_deny_limit', ['was' => $was, 'now' => $want]);
    return ['ok' => true, 'was' => $was, 'now' => $want, 'msg' => 'DENY_IP_LIMIT raised from ' . $was . ' to ' . $want];
}

/**
 * The kernel's DENYIN chain, read ONCE per request (v4 + v6, every iptables backend present) and kept in memory.
 * `csf -g` costs about a second per address; the Firewall page checked ten rules that way and took twelve
 * seconds to open. One `iptables -S DENYIN` is a few milliseconds and answers for every address at once.
 */
function smpro_gl_denyin_snapshot(bool $refresh = false): array {
    static $snap = null;
    if ($snap !== null && !$refresh) return $snap;
    $snap = [];
    $bins = function_exists('smpro_fw_ipt_bins') ? array_merge(smpro_fw_ipt_bins(false), smpro_fw_ipt_bins(true)) : ['/usr/sbin/iptables', '/usr/sbin/ip6tables'];
    foreach ($bins as $b) {
        if (!@is_executable($b)) continue;
        $out = (string)@shell_exec('timeout 10 ' . escapeshellarg($b) . ' -S DENYIN 2>/dev/null');
        if (preg_match_all('/-s\s+([0-9a-fA-F:.]+)(?:\/\d+)?\s.*?-j\s+DROP/', $out, $m)) foreach ($m[1] as $ip) $snap[strtolower($ip)] = true;
    }
    return $snap;
}

/** Is a written rule really in the kernel? A line in csf.deny alone is a request. */
function smpro_gl_rule_live(string $ip, bool $refresh = false): bool {
    if ($ip === '') return false;
    if (smpro_gl_use_set()) return smpro_gs_has($ip) && smpro_gs_rule_live(smpro_gs_is6($ip));
    $snap = smpro_gl_denyin_snapshot($refresh);
    return isset($snap[strtolower($ip)]);
}

/** Write the rules for one address. Returns ['ok'=>bool,'added'=>int,'msg'=>string]. */
function smpro_gl_block(string $ip, string $cc, string $account, array $cfg): array {
    $ports = smpro_gl_ports_for($cfg);
    if (!$ports) return ['ok' => false, 'added' => 0, 'msg' => 'no login ports selected'];
    if (smpro_gl_use_set()) {
        $why = 'login from ' . ($cc ?: '??') . ' not allowed' . ($account !== '' ? ' for ' . $account : '') . ' ' . date('Y-m-d');
        $r = smpro_gs_add($ip, max(1, (int)($cfg['ttl_days'] ?? 30)) * 86400, $cc, $account, $why, $ports);
        $live = !empty($r['ok']) && smpro_gl_rule_live($ip, true);   // read the kernel back: an entry is only "closed" when the set AND the rule hold
        if (!$live && function_exists('smpro_audit')) @smpro_audit('geologin_block_not_live', ['ip' => $ip, 'backend' => 'set', 'msg' => (string)$r['msg']]);
        return ['ok' => $live, 'added' => $live ? count($ports) : 0, 'live' => $live,
                'msg' => $live ? (count($ports) . ' login port(s) closed for ' . $ip) : ('set entry written for ' . $ip . ' but NOT live in the firewall - ' . (string)$r['msg'])];
    }
    if (!@is_file(SMPRO_GL_DENY) || !@is_writable(SMPRO_GL_DENY)) return ['ok' => false, 'added' => 0, 'msg' => 'csf.deny is not writable'];
    $have = (string)@file_get_contents(SMPRO_GL_DENY);
    $why = 'login from ' . ($cc ?: '??') . ' not allowed' . ($account !== '' ? ' for ' . $account : '') . ' ' . date('Y-m-d');
    $add = [];
    foreach (smpro_gl_rule_lines($ip, $ports, $why) as $line) {
        $head = explode(' #', $line)[0];
        if (strpos($have, $head) !== false) continue;                 // already there
        $add[] = $line;
    }
    if ($add) { smpro_gl_ensure_deny_limit(); @file_put_contents(SMPRO_GL_DENY, implode("\n", $add) . "\n", FILE_APPEND | LOCK_EX); }
    $csf = function_exists('smpro_csf_bin') ? smpro_csf_bin() : '';
    if ($add && $csf !== '') @shell_exec('timeout 60 ' . escapeshellarg($csf) . ' -r >/dev/null 2>&1');
    // Written is not blocked. Read the kernel back and say which it is; a rule CSF dropped must not be reported as
    // "closed" - that is how a server with 246 lines and a 200-line limit reported every sign-in as handled.
    $live = smpro_gl_rule_live($ip, true);   // fresh read: csf -r has just run
    if (!$live && function_exists('smpro_audit')) @smpro_audit('geologin_block_not_live', ['ip' => $ip, 'lines' => count(smpro_gl_active())]);
    return ['ok' => $live, 'added' => count($add), 'live' => $live,
            'msg' => $live ? (count($add) . ' login port(s) closed for ' . $ip) : ('rules written for ' . $ip . ' but NOT live in the firewall - CSF did not apply them (check DENY_IP_LIMIT and csf -r)')];
}

/** Remove every rule this feature wrote — all of them, or just one address. Nothing else is touched. */
function smpro_gl_unblock(string $ip = ''): array {
    $fromSet = smpro_gl_use_set() ? smpro_gs_del($ip) : 0;
    if (!@is_file(SMPRO_GL_DENY) || !@is_writable(SMPRO_GL_DENY)) return ['ok' => $fromSet > 0, 'removed' => $fromSet, 'msg' => $fromSet ? ($fromSet . ' address(es) removed from the kernel set') : 'csf.deny is not writable'];
    $dl = function_exists('smpro_csf_deny_lock') ? smpro_csf_deny_lock() : null;   // held across read -> rewrite
    $lines = file(SMPRO_GL_DENY, FILE_IGNORE_NEW_LINES) ?: [];
    $keep = []; $removed = 0;
    foreach ($lines as $l) {
        $isOurs = strpos($l, SMPRO_GL_MARK) !== false;
        if ($isOurs && ($ip === '' || strpos($l, 's=' . $ip) !== false)) { $removed++; continue; }
        $keep[] = $l;
    }
    if ($removed) {
        @file_put_contents(SMPRO_GL_DENY . '.smpro.tmp', implode("\n", $keep) . "\n", LOCK_EX); @chmod(SMPRO_GL_DENY . '.smpro.tmp', 0600);
        if (!@rename(SMPRO_GL_DENY . '.smpro.tmp', SMPRO_GL_DENY)) @file_put_contents(SMPRO_GL_DENY, implode("\n", $keep) . "\n", LOCK_EX);
        if (function_exists('smpro_csf_deny_unlock')) smpro_csf_deny_unlock($dl);
        $csf = function_exists('smpro_csf_bin') ? smpro_csf_bin() : '';
        if ($csf !== '') @shell_exec('timeout 60 ' . escapeshellarg($csf) . ' -r >/dev/null 2>&1');
    }
    return ['ok' => true, 'removed' => $removed + $fromSet, 'msg' => ($fromSet ? $fromSet . ' address(es) removed from the kernel set' : '') . ($removed ? ($fromSet ? '; ' : '') . $removed . ' rule line(s) removed' : ($fromSet ? '' : 'nothing to remove'))];
}

/** What this feature currently has in the firewall, grouped by address. */
function smpro_gl_active(): array {
    $out = [];
    if (smpro_gl_use_set()) foreach (smpro_gs_active(false) as $r) $out[$r['ip']] = $r;
    foreach ((array)@file(SMPRO_GL_DENY, FILE_IGNORE_NEW_LINES) as $l) {
        if (strpos((string)$l, SMPRO_GL_MARK) === false) continue;
        if (!preg_match('/s=([0-9a-fA-F:.]+)/', (string)$l, $m)) continue;
        $ip = $m[1];
        $out[$ip]['ip'] = $ip;
        $out[$ip]['ports'][] = preg_match('/d=(\d+)/', (string)$l, $pm) ? (int)$pm[1] : 0;
        if (preg_match('/# ' . preg_quote(SMPRO_GL_MARK, '/') . '\s+(.*)$/', (string)$l, $wm)) $out[$ip]['why'] = trim($wm[1]);
        $out[$ip]['backend'] = 'csf.deny';
    }
    return array_values($out);
}

/** The active rules with whether each is really live in the kernel (bounded: the first $max addresses are checked). */
function smpro_gl_active_live(int $max = 500): array {
    $rows = smpro_gl_active(); $n = 0;
    foreach ($rows as &$r) { $r['live'] = ($n++ < $max) ? smpro_gl_rule_live($r['ip']) : null; }
    unset($r);
    return $rows;
}

/* ----------------------------- the sweep ----------------------------- */

/**
 * Read the login log and decide. Returns what it found and what it did — and in dry run, what it WOULD do.
 *
 * An address whose country cannot be determined is never acted on. Geo data is wrong often enough that treating
 * "unknown" as "not allowed" would lock out real customers on the strength of a missing database file.
 */
function smpro_gl_run(bool $force_dryrun = false): array {
    $cfg = smpro_gl_cfg();
    $dry = $force_dryrun || !empty($cfg['dryrun'])
        || (function_exists('smpro_ctl_dry_run') && smpro_ctl_dry_run());
    $res = ['ok' => true, 'dryrun' => $dry, 'enabled' => !empty($cfg['enabled']),
            'hits' => [], 'blocked' => [], 'skipped' => [], 'scanned' => 0, 'msg' => ''];
    if (empty($cfg['enabled'])) { $res['msg'] = 'Country Login Lock is off.'; return $res; }

    $state = smpro_gl_state();
    $done  = is_array($state['acted'] ?? null) ? $state['acted'] : [];
    $cut   = time() - 3600;

    // Successes and failures live in DIFFERENT files on current cPanel. A granted session is a NEW line in
    // session_log; login_log carries the refusals. Reading only login_log, as this did, meant the lock could
    // never see the one event it exists to act on — a correct password used from a country that is not allowed.
    if (!function_exists('smpro_lf_success')) { $lf = __DIR__ . '/loginfeed.php'; if (@is_file($lf)) require_once $lf; }
    $feed = function_exists('smpro_lf_success') ? smpro_lf_success($cut, 4000) : ['ok' => false, 'events' => [], 'msg' => 'login feed unavailable'];

    $log = function_exists('smpro_lf_login_log') ? smpro_lf_login_log() : '/usr/local/cpanel/logs/login_log';
    $raw = @is_readable($log) ? (string)@shell_exec('timeout 20 tail -n 4000 ' . escapeshellarg($log) . ' 2>/dev/null') : '';
    if (function_exists('smpro_login_log_resolve')) $raw = smpro_login_log_resolve($raw);   // a refusal behind WebShield is the visitor's, not the server's
    $failedReadable = ($raw !== '' || (int)@filesize($log) === 0) && @is_readable($log);

    if (empty($feed['ok']) && !$failedReadable) {
        $res['ok'] = false;
        $res['msg'] = 'Neither session_log nor login_log could be read, so nothing was checked — this is "not seen", not "nothing happened".';
        return $res;
    }
    if (empty($feed['ok'])) {
        // Failures can still be acted on, but say plainly that the successes were not looked at.
        $res['msg'] = 'session_log could not be read: successful sign-ins were NOT checked this run.';
    }

    // One list, both kinds, so the decision below is written once.
    $rows = [];
    foreach ((array)$feed['events'] as $e) {
        if ($e['ip'] === '') continue;                                   // a session minted on the box, not a login over the network
        $rows[] = ['ts' => (int)$e['ts'], 'ip' => $e['ip'], 'user' => (string)$e['user'], 'ok' => true];
    }
    foreach (explode("\n", $raw) as $line) {
        $line = trim($line); if ($line === '') continue;
        if (!preg_match('/^\[([^\]]+)\]\s+\S+\s+\[[^\]]+\]\s+(\S+)\s+-\s+(\S+)\s+(.+)$/', $line, $m)) continue;
        if (!filter_var($m[2], FILTER_VALIDATE_IP)) continue;
        if (preg_match('/SUCCEEDED\s+LOGIN|SUCCESS\s+LOGIN/i', $m[4])) continue;   // already carried by the feed
        if (!preg_match('/FAILED\s+LOGIN|DEFERRED\s+LOGIN|AUTHENTICATION\s+FAILED|INVALID/i', $m[4])) continue;
        $lts = smpro_login_ts($m[1]); if ($lts <= 0) continue;   // an unreadable stamp is skipped, never counted as 'now'
        $rows[] = ['ts' => $lts, 'ip' => $m[2], 'user' => rawurldecode($m[3]), 'ok' => false];
    }

    foreach ($rows as $row) {
        $ip = $row['ip']; $ts = (int)$row['ts']; $ok = (bool)$row['ok'];
        if ($ts && $ts < $cut) continue;
        $res['scanned']++;

        $account = preg_replace('/[^a-zA-Z0-9._@-]/', '', (string)$row['user']);
        $allowed = smpro_gl_allowed_for($account, $cfg);
        $cc = smpro_gl_country($ip);

        if ($cc === '') { $res['skipped'][] = ['ip' => $ip, 'why' => 'country unknown — never treated as not allowed']; continue; }
        if (in_array($cc, $allowed, true)) continue;
        if (($why = smpro_gl_exempt($ip)) !== '') { $res['skipped'][] = ['ip' => $ip, 'cc' => $cc, 'why' => $why]; continue; }

        $hit = ['ts' => $ts ?: time(), 'ip' => $ip, 'cc' => $cc, 'account' => $account, 'success' => $ok];
        $res['hits'][] = $hit;

        $action = $ok ? (string)$cfg['on_success'] : (string)$cfg['on_failed'];
        if ($action !== 'block') continue;
        if (isset($done[$ip]) && (time() - (int)($done[$ip]['ts'] ?? 0)) < 6 * 3600) continue;   // already handled recently

        if ($dry) { $res['blocked'][] = $hit + ['dryrun' => true, 'msg' => 'would close the login ports']; continue; }
        // Block AND evict. The rule stops the next connection; the eviction ends the one that is already open,
        // which on a successful sign-in is the only one that matters. Blocking first is deliberate: it closes the
        // door before the socket is dropped, so a script cannot simply reconnect in the gap.
        if (!empty($cfg['evict']) && $ok) {
            $b = smpro_gl_evict($ip, $cc, $account, $cfg);
            $res['blocked'][] = $hit + ['added' => $b['blocked'], 'msg' => $b['msg'], 'evicted' => 1];
        } else {
            $b = smpro_gl_block($ip, $cc, $account, $cfg);
            $res['blocked'][] = $hit + ['added' => $b['added'], 'msg' => $b['msg']];
        }
        $done[$ip] = ['ts' => time(), 'cc' => $cc, 'account' => $account];
        if (function_exists('smpro_audit')) smpro_audit('geologin_block', $hit + ['ports' => $b['added']]);
        // A correct password used from a country that is not allowed is a compromised password, not a scan.
        if ($ok && function_exists('smpro_notify'))
            @smpro_notify('geologin_success', 'Sign-in from ' . $cc . ' — a country not allowed for ' . ($account ?: 'this server'),
                'The password for ' . ($account ?: 'an account') . ' was accepted from ' . $ip . ' (' . $cc . '). The login ports have been '
              . 'closed for that address, but the password is already known to somebody: change it.');
    }

    if (!$dry) { $state['acted'] = array_slice($done, -2000, 2000, true); $state['last_run'] = time(); smpro_gl_state_save($state); }
    $res['msg'] = $dry
        ? (count($res['hits']) . ' sign-in(s) from a country not on the list. Nothing was blocked — this is a dry run.')
        : (count($res['blocked']) . ' address(es) had their login ports closed; ' . count($res['hits']) . ' hit(s) seen.');
    return $res;
}

/** Drop rules older than the configured life, so a one-off from a holiday does not stand forever. */
function smpro_gl_expire(): array {
    $cfg = smpro_gl_cfg();
    $days = max(1, (int)$cfg['ttl_days']);
    $fromSet = smpro_gl_use_set() ? smpro_gs_expire() : 0;   // the kernel already dropped them; this forgets the reasons
    $cutoff = date('Y-m-d', time() - $days * 86400);
    $dl = function_exists('smpro_csf_deny_lock') ? smpro_csf_deny_lock() : null;   // held across read -> rewrite
    $lines = (array)@file(SMPRO_GL_DENY, FILE_IGNORE_NEW_LINES);
    if (!$lines) { if (function_exists('smpro_csf_deny_unlock')) smpro_csf_deny_unlock($dl); return ['ok' => true, 'removed' => 0]; }
    $keep = []; $removed = 0;
    foreach ($lines as $l) {
        if (strpos((string)$l, SMPRO_GL_MARK) !== false && preg_match('/(\d{4}-\d{2}-\d{2})\s*$/', (string)$l, $m) && $m[1] < $cutoff) { $removed++; continue; }
        $keep[] = $l;
    }
    if ($removed && @is_writable(SMPRO_GL_DENY)) {
        @file_put_contents(SMPRO_GL_DENY, implode("\n", $keep) . "\n", LOCK_EX);
        $csf = function_exists('smpro_csf_bin') ? smpro_csf_bin() : '';
        if ($csf !== '') @shell_exec('timeout 60 ' . escapeshellarg($csf) . ' -r >/dev/null 2>&1');
    }
    return ['ok' => true, 'removed' => $removed + $fromSet];
}

/** Arming on a server with a kernel set: the set and its rule, the CSF hook, and any old csf.deny lines moved over. */
function smpro_gl_set_up(array $cfg): array {
    $ports = smpro_gl_ports_for($cfg); $out = [];
    $out['restore'] = smpro_gs_restore($ports);
    $out['hook'] = smpro_gs_hook_install();
    $out['migrate'] = smpro_gs_migrate(SMPRO_GL_DENY, max(1, (int)($cfg['ttl_days'] ?? 30)), $ports);
    return $out;
}


/* ---------------- cron ----------------
 * Without this the lock had no way to act at all: smpro_gl_run() was reachable only from the page's check
 * button, which forces dry run, so no rule could ever be written however the lock was configured. The panel
 * said ARMED and csf.deny stayed empty. A feature that cannot act must not call itself armed.
 *
 * Installed while the lock is on, REMOVED when it is turned off - a cron that survives the setting it belongs
 * to is a job nobody remembers scheduling.
 */
function smpro_gl_cron_sync(): bool {
    // A test must never install a live cron. The shared writer refuses too, but a test that loads only
    // this file has no shared writer to refuse - function_exists() is false and the fallback writes
    // /etc/cron.d directly. The lab caught exactly that, restored the file, and went red at random.
    if (defined('SMPRO_TEST_SRC')) return true;
    $f = '/etc/cron.d/smpro-geologin';
    $cfg = smpro_gl_cfg();
    if (empty($cfg['enabled'])) { if (@is_file($f)) @unlink($f); return true; }
    $bin = SMPRO_BASE . '/bin/geologin_tick.php';
    if (!@is_file($bin)) return false;
    $php = function_exists('smpro_php_cli_bin') ? smpro_php_cli_bin()
         : (is_executable('/usr/local/cpanel/3rdparty/bin/php') ? '/usr/local/cpanel/3rdparty/bin/php' : 'php');
    $lockDir = defined('SMPRO_LOCKS') ? SMPRO_LOCKS : (SMPRO_VARLIB . '/locks');
    @is_dir($lockDir) || @mkdir($lockDir, 0700, true);
    $flock = is_executable('/usr/bin/flock') ? '/usr/bin/flock' : 'flock';
    // Every minute, with three passes inside each run (bin/geologin_tick.php): at two minutes an address that got in
    // kept working long enough to change the password (51 s, measured). The first sign-in still succeeds - the lock reads
    // the log, it does not stand in front of the door - so the only thing that can be shortened is how long the
    // address keeps working afterwards.
    $desired = "# Safety Monitor Pro - Country Login Lock (close login ports for addresses in countries you do not allow)\n"
             . "* * * * * root $flock -n " . $lockDir . "/geologin.lock timeout 110 nice -n 10 $php $bin >/dev/null 2>&1\n";
    return function_exists('smpro_cron_install') ? smpro_cron_install($f, $desired)
         : (@file_put_contents($f, $desired) !== false && @chmod($f, 0644));
}

/** Is the lock actually able to act right now? Armed with no worker is not armed. */
function smpro_gl_active_really(): array {
    $cfg = smpro_gl_cfg();
    if (empty($cfg['enabled'])) return ['ok' => false, 'why' => 'off'];
    if (!@is_file(SMPRO_BASE . '/bin/geologin_tick.php'))
        return ['ok' => false, 'why' => 'the worker is missing from this install, so nothing can apply the lock'];
    if (!@is_file('/etc/cron.d/smpro-geologin'))
        return ['ok' => false, 'why' => 'no scheduled run is installed, so nothing will apply the lock - press Save to install it'];
    if (!empty($cfg['dryrun'])) return ['ok' => false, 'why' => 'dry run - it reports what it would do and writes nothing'];
    return ['ok' => true, 'why' => ''];
}

/* =====================================================================================================
 * ENDING THE SESSION THAT IS ALREADY IN.
 *
 * Closing an address's login ports stops the NEXT connection. It does nothing about the one already open, and
 * that is the one that matters: a correct password used from a country you do not allow means somebody is
 * inside right now. Until this, the lock wrote a firewall rule and left the attacker working.
 *
 * Three things have to go, because "a session" is three different objects on a cPanel server:
 *
 *   1. The TCP connections. `ss -K` asks the kernel to destroy established sockets from that address, which
 *      drops SSH, FTP, IMAP and an open panel page in one move.
 *   2. The cPanel/WHM session tokens. A panel session survives a dropped socket - the browser simply reconnects
 *      with the same token and is still signed in. The session files record the address they were created from,
 *      so the ones belonging to this address are removed.
 *   3. The processes that are serving it. A dropped socket usually takes its sshd/pure-ftpd child with it, but
 *      not always, and a stuck child is a live shell.
 *
 * NOTHING HERE IS GUESSWORK ABOUT OWNERSHIP: each step matches on the address, and a step that cannot run says
 * so rather than being counted as done.
 * ===================================================================================================== */

/** Destroy established sockets from one address. Returns what it could and could not do. */
function smpro_gl_kill_sockets(string $ip): array {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return ['ok' => false, 'n' => 0, 'msg' => 'invalid address'];
    $before = (int)trim((string)@shell_exec('timeout 10 ss -tn state established dst ' . escapeshellarg($ip) . ' 2>/dev/null | grep -c . '));
    if ($before <= 1) return ['ok' => true, 'n' => 0, 'msg' => 'no established connection from that address'];

    // -K needs CONFIG_INET_DIAG_DESTROY. Where the kernel lacks it, ss returns an error and nothing is dropped;
    // that must be reported, not assumed away - the caller is about to tell an operator the session is over.
    $out = (string)@shell_exec('timeout 10 ss -K state established dst ' . escapeshellarg($ip) . ' 2>&1');
    $after = (int)trim((string)@shell_exec('timeout 10 ss -tn state established dst ' . escapeshellarg($ip) . ' 2>/dev/null | grep -c . '));
    $killed = max(0, ($before - 1) - max(0, $after - 1));
    if ($killed === 0 && stripos($out, 'not supported') !== false) {
        return ['ok' => false, 'n' => 0, 'msg' => 'this kernel cannot destroy sockets (no INET_DIAG_DESTROY) — the connection was NOT dropped'];
    }
    return ['ok' => true, 'n' => $killed, 'msg' => $killed . ' connection(s) dropped'];
}

/**
 * Remove the cPanel/WHM session tokens created from one address.
 *
 * A dropped socket does not sign anybody out: the browser reconnects with the same token. The session files
 * record the address they were opened from, so they can be matched exactly rather than by guessing at an owner.
 */
function smpro_gl_kill_panel_sessions(string $ip): array {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return ['ok' => false, 'n' => 0, 'msg' => 'invalid address'];
    $dir = '/var/cpanel/sessions';
    if (!@is_dir($dir)) return ['ok' => false, 'n' => 0, 'msg' => 'no session store on this server'];
    $n = 0; $seen = 0; $parsed = 0; $legacy = 0;
    foreach (['raw', 'cache', 'preauth'] as $sub) {
        $d = $dir . '/' . $sub;
        if (!@is_dir($d)) continue;
        foreach ((array)@scandir($d) as $f) {
            if ($f === '.' || $f === '..') continue;
            $p = $d . '/' . $f;
            if (!@is_file($p)) continue;
            $seen++;
            $body = (string)@file_get_contents($p, false, null, 0, 8192);
            if ($body === '') continue;
            // Matched on the recorded address only. 'local_ip_address' is the SERVER's, and matching that would
            // sign every single user out - so the value is read as a field, never searched for as a substring.
            //
            // TWO formats live here: older cPanel wrote key=value lines, current cPanel writes a single JSON
            // object. Reading only the first meant eviction ended 0 sessions on a current server while reporting
            // that it had worked — the block went up, and whoever was already signed in stayed signed in behind
            // it, on the session that mattered.
            $found = '';
            if (preg_match('/^ip_address=(\S+)/m', $body, $m)) {
                $found = trim($m[1]);
                $legacy++;
            } elseif (isset($body[0]) && $body[0] === '{') {
                $j = json_decode($body, true);
                if (is_array($j) && isset($j['ip_address'])) $found = trim((string)$j['ip_address']);
                $parsed++;
            }
            if ($found === '' || $found !== $ip) continue;
            if (@unlink($p)) $n++;
        }
    }
    // "0 sessions ended" is only good news if the files could actually be understood. If none of them could be,
    // say that instead — it is the difference between nobody being signed in and not having looked.
    $why = '';
    if ($n === 0 && $seen > 0 && $parsed === 0 && !$legacy)
        $why = ' — WARNING: none of the ' . $seen . ' session file(s) were in a format this build understands, so nothing was checked';
    return ['ok' => true, 'n' => $n, 'seen' => $seen, 'understood' => $parsed + $legacy,
            'msg' => $n . ' panel session(s) ended' . ($seen === 0 ? ' (no sessions were readable)' : $why)];
}

/** Terminate the processes still serving one address. */
function smpro_gl_kill_procs(string $ip): array {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return ['ok' => false, 'n' => 0, 'msg' => 'invalid address'];
    $raw = (string)@shell_exec('timeout 10 ss -tnp state established dst ' . escapeshellarg($ip) . ' 2>/dev/null');
    $pids = [];
    if (preg_match_all('/pid=(\d+)/', $raw, $m)) foreach ($m[1] as $p) $pids[(int)$p] = 1;
    $me = getmypid(); unset($pids[$me], $pids[1]);
    $n = 0;
    foreach (array_keys($pids) as $pid) {
        // Never kill something that is not a session server. A match on the address is not a licence to kill an
        // arbitrary root process - a database or a backup agent can hold a connection to the same address.
        $exe = @readlink('/proc/' . $pid . '/exe');
        $base = strtolower(basename((string)$exe));
        if (!in_array($base, ['sshd', 'pure-ftpd', 'proftpd', 'vsftpd', 'cpsrvd', 'cpsrvd.so', 'dovecot', 'imap-login', 'pop3-login'], true)) continue;
        if (function_exists('posix_kill') ? @posix_kill($pid, 15) : (trim((string)@shell_exec('kill -15 ' . (int)$pid . ' 2>/dev/null; echo $?')) === '0')) $n++;
    }
    return ['ok' => true, 'n' => $n, 'msg' => $n . ' session process(es) ended'];
}

/**
 * The whole response to "a correct password was used from a country that is not allowed": end what is open,
 * then close the door behind it.
 *
 * Order matters. The firewall rule goes on FIRST so the address cannot simply reconnect between the socket being
 * dropped and the rule being written - a race an attacker with a script wins every time.
 */
function smpro_gl_evict(string $ip, string $cc, string $account, array $cfg): array {
    $res = ['ip' => $ip, 'blocked' => [], 'sockets' => null, 'panel' => null, 'procs' => null, 'ok' => false];
    if (!filter_var($ip, FILTER_VALIDATE_IP)) { $res['msg'] = 'invalid address'; return $res; }

    // 1. the door first
    $b = smpro_gl_block($ip, $cc, $account, $cfg);
    $res['blocked'] = (array)($b['added'] ?? []);
    $res['block_msg'] = (string)($b['msg'] ?? '');

    // 2. then what is already inside
    $res['sockets'] = smpro_gl_kill_sockets($ip);
    $res['panel']   = smpro_gl_kill_panel_sessions($ip);
    $res['procs']   = smpro_gl_kill_procs($ip);

    $res['ok'] = !empty($res['blocked']) || $res['sockets']['n'] > 0 || $res['panel']['n'] > 0 || $res['procs']['n'] > 0;
    $res['msg'] = trim(($res['block_msg'] ?: '') . ' · ' . $res['sockets']['msg'] . ' · ' . $res['panel']['msg'] . ' · ' . $res['procs']['msg'], ' ·');
    smpro_gl_record_evict($ip, $cc, $account, $res);
    return $res;
}

function smpro_gl_record_evict(string $ip, string $cc, string $account, array $res): void {
    if (function_exists('smpro_audit')) {
        @smpro_audit('geologin_evict', [
            'ip' => $ip, 'cc' => $cc, 'account' => $account,
            'ports'    => count((array)$res['blocked']),
            'sockets'  => (int)($res['sockets']['n'] ?? 0),
            'sessions' => (int)($res['panel']['n'] ?? 0),
            'procs'    => (int)($res['procs']['n'] ?? 0),
            // Recorded even when zero: "nothing was open" and "nothing could be closed" are different facts.
            'socket_msg' => (string)($res['sockets']['msg'] ?? ''),
        ]);
    }
}
