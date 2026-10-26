<?php
/**
 * includes/intrusion.php - Intrusion detection ENGINE (shared by the Intrusion Monitor
 * module AND the notify cron, so detection + alerts run even with no page open).
 *
 * Capabilities:
 *   - ModSecurity audit-log parsing (per-domain web attacks)              [source]
 *   - Persistent SQLite index of attacks (history beyond log rotation)    [index]
 *   - CSF + Cloudflare edge blocking of attacker IPs                       [response]
 *   - Successful-breach correlation (attack 200 + recent docroot change)  [detection]
 *   - Attacker intelligence + coordinated-campaign detection              [intel]
 *   - Real-time alert scan for the notify cron (push as it happens)       [alerts]
 *
 * Only function/const definitions here - no execution at include time.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

define('SMPRO_IM_LIVE_BYTES',   3 * 1024 * 1024);
define('SMPRO_IM_PAGE_BYTES',   9 * 1024 * 1024);
define('SMPRO_IM_REPORT_BYTES', 48 * 1024 * 1024);
define('SMPRO_IM_CAP',          20000);
define('SMPRO_IN_DB',     SMPRO_VARLIB . '/intrusion.db');
define('SMPRO_IN_CFG',    SMPRO_VARLIB . '/intrusion.json');     // settings (CF token, thresholds, auto-block)
define('SMPRO_IN_STATE',  SMPRO_VARLIB . '/intrusion_state.json'); // alert cursor / state
define('SMPRO_IM_QUAR',   SMPRO_VARLIB . '/quarantine');         // quarantined (cleaned) web-shells - restorable
define('SMPRO_IM_EMLOG',  SMPRO_VARLIB . '/emergency.json');     // manifest of emergency actions (reversible)

/* ============================ settings ============================ */
/** Config fields that hold secrets and must be encrypted at rest (vault, AES-256-GCM). */
function smpro_in_secret_keys() { return ['cf_token', 'abuseipdb_key']; }

function smpro_in_cfg($reset = false) {
    static $c = null;
    // The cache used to survive a write inside the same request: the settings page saved protect_regions and then
    // re-rendered from the OLD values, and any check that ran after a save (is a home region configured?) read a
    // stale answer. A write now clears it, so what was just saved is what is read.
    if ($reset) { $c = null; return []; }
    if ($c !== null) return $c;
    $d = is_file(SMPRO_IN_CFG) ? json_decode((string)@file_get_contents(SMPRO_IN_CFG), true) : null;
    $d = is_array($d) ? $d : [];
    // The caution tier is whatever the operator saved; the product ships no region of its own.
    $c = $d + [
        'cf_token' => '', 'cf_account' => '',                 // Cloudflare API (account-level access rules)
        'abuseipdb_key' => '',
        'auto_block' => false, 'auto_block_dryrun' => true,   // auto-response (off by default; dry-run when first enabled)
        'auto_block_threshold' => 30,                          // per-IP attack-count floor for auto-block (non-Arab / datacenter / unknown)
        'protect_arab' => true,                                // home-region residential never auto-blocked; other-Arab residential needs a higher bar
        'ai_block' => false,                                   // let the AI decide which attacker IPs to auto-block
        'emergency' => false,                                  // EMERGENCY mode: auto-harden (+clean) a site the moment it is attacked & files change
        'emergency_dryrun' => true,                            // ships in PREVIEW: the operator turns real emergency actions on after reading one report
        'emergency_harden' => true,                            // disable PHP execution in upload/cache dirs + lock core files
        'emergency_clean' => true,                             // quarantine recently-changed files that look like web-shells
        'emergency_block_scanners' => true,                    // auto-block clear malicious scanners (credential probes / bare-IP scans)
        'emergency_batch' => 3,                                // group emergency (harden/clean) notifications: one message per N actions
        'emergency_block_digest_hours' => 12,                  // routine scanner auto-blocks: one grouped INFO digest per N hours (not per run)
        'use_cloudflare' => true, 'use_csf' => true,
        'allowlist' => [],                                     // never block these IPs/CIDRs
        'caution_regions' => [],                               // tier-2: residential IPs here need 3x the attack count before auto-block. Ships EMPTY (no market assumption); admin sets it (UI has an Arab-countries preset).
        'protect_regions' => [],                               // home regions: RESIDENTIAL IPs here are never auto-blocked. Ships EMPTY - this is a resale product and must not assume a market; the operator sets it (the plugin suggests the server's own country).
        'protect_arab_threshold' => 1,                         // other Arab-country residential IPs: auto-block only when attack is clear & repeated (1=on)
        'breach_exclude' => ['imunify-security', '/wp-content/cache/', '/wp-content/upgrade/', '/wp-content/uploads/cache/', 'wordfence-waf', '/mu-plugins/'],  // breach scan: ignore these (legit, auto-updating). Ships to every server, so keep it to widely-distributed names only - never a single-site one. Built-in security-plugin seeds are ALSO always applied - see smpro_im_breach_exclude_seed(). Files with a WP "Plugin Name:" header are never auto-quarantined.
        'thr_domain_attacks' => 150,                           // alert when a domain crosses N attacks in the window (busy shared server = high baseline noise)
        'thr_ip_domains' => 12,                                // alert when one IP hits N+ distinct domains (distributed scan)
        'thr_upload_cluster_events' => 8,                      // upload-cluster alert: N+ accepted-2xx Malicious-Upload POSTs to one endpoint...
        'thr_upload_cluster_ips' => 4,                         // ...from M+ distinct IPs in the window (fires even when NO .php changed - the harajplastic gap)
        'alert_window_min' => 15,                              // detection window for the cron
        'login_guard' => true,                                 // 24/7 auto-block FOREIGN (non-Arab) login brute-force (cron)
        'login_guard_threshold' => 4,                          // block at this many failed logins (>3)
        'login_guard_window' => 30,                            // failed-login look-back window (minutes)
        'login_guard_cap' => 20,                               // max IPs blocked per cron run (safety)
        // Second rule: catch a scan spread across many addresses of one network, where no single address reaches
        // the threshold above. Off by default - it blocks a whole set at once, which is the operator's call to
        // make, and the per-address rule already runs. The cap above still limits how many go per run.
        'login_guard_net' => false,                            // enable the network rule
        'login_guard_net_ips' => 2,                            // ...when a network fields at least this many addresses
        'login_guard_net_fails' => 10,                         // ...AND they total at least this many failed logins
        'honeytoken_users'      => [],                         // decoy cPanel accounts: ANY login to one = a leaked credential list
    ];
    // Decrypt secrets for callers; migrate any legacy PLAINTEXT value by re-storing it encrypted once.
    $migrate = false;
    if (function_exists('smpro_secret_dec')) {
        foreach (smpro_in_secret_keys() as $k) {
            $v = (string)($c[$k] ?? '');
            if ($v === '') continue;
            if (smpro_secret_is_enc($v)) $c[$k] = smpro_secret_dec($v);   // stored encrypted -> give callers plaintext
            else $migrate = true;                                          // stored plaintext -> needs re-encryption
        }
    }
    if ($migrate) smpro_in_cfg_write($c);                                  // rewrite to disk with secrets encrypted
    return $c;
}
/** Write the config to disk, encrypting secret fields at rest (does NOT mutate the in-memory copy). */
/** Forget the in-request config cache - called after every write, and by tests that rewrite the file directly. */
function smpro_in_cfg_reset(): void { smpro_in_cfg(true); }

function smpro_in_cfg_write(array $c) {
    $w = $c;
    if (function_exists('smpro_secret_enc')) {
        foreach (smpro_in_secret_keys() as $k) {
            if (isset($w[$k]) && $w[$k] !== '') $w[$k] = smpro_secret_enc((string)$w[$k]);
        }
    }
    @is_dir(dirname(SMPRO_IN_CFG)) || @mkdir(dirname(SMPRO_IN_CFG), 0700, true);
    $tmp = SMPRO_IN_CFG . '.tmp';
    @file_put_contents($tmp, json_encode($w, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), LOCK_EX);
    @chmod($tmp, 0600); @rename($tmp, SMPRO_IN_CFG);
    smpro_in_cfg_reset();   // what was just written is what the rest of this request reads
}
function smpro_in_cfg_save($patch) {
    $c = smpro_in_cfg();
    foreach ($patch as $k => $v) $c[$k] = $v;
    smpro_in_cfg_write($c);   // encrypts cf_token/abuseipdb_key before writing
    return $c;
}
function smpro_in_state() { $d = is_file(SMPRO_IN_STATE) ? json_decode((string)@file_get_contents(SMPRO_IN_STATE), true) : null; return is_array($d) ? $d : []; }
function smpro_in_state_save($s) { @is_dir(dirname(SMPRO_IN_STATE)) || @mkdir(dirname(SMPRO_IN_STATE), 0700, true); $t = SMPRO_IN_STATE . '.' . getmypid() . '.tmp';
    // merged under a lock: every writer loads, sets ONE key and saves all - two of them crossing used to drop the other's key (a lost
    // login_guard_blocked re-blocked and re-notified; a lost emergency digest was never reported)
    $lk = @fopen(SMPRO_IN_STATE . '.lock', 'c'); if ($lk) @flock($lk, LOCK_EX);
    $disk = is_file(SMPRO_IN_STATE) ? json_decode((string)@file_get_contents(SMPRO_IN_STATE), true) : null; if (is_array($disk) && is_array($s)) $s = array_merge($disk, $s);
    @file_put_contents($t, json_encode($s, JSON_UNESCAPED_SLASHES), LOCK_EX); @chmod($t, 0600); @rename($t, SMPRO_IN_STATE);
    if ($lk) { @flock($lk, LOCK_UN); @fclose($lk); }   /* released now: held to exit, the next save in the same run deadlocked */
}

/**
 * 24/7 login brute-force auto-block (run from cron). Reads cPanel login_log, counts FAILED logins
 * per source IP inside the window, and firewalls any FOREIGN (non-Arab) IP at/over the threshold.
 * SAFE: Arab + local IPs are never blocked (smpro_geo_foreign), allowlist honoured, deduped via
 * state, capped per run, every block audited. $dryrun=true reports without blocking.
 */
/**
 * Successful cPanel / webmail logins from OUTSIDE the home region, plus per-account travel anomalies.
 *
 * The foreign-login alert existed but read only /var/log/secure - sshd. The break-ins that actually happen on a
 * cPanel server do not come through ssh: they come through the cPanel panel (2083) and webmail (2096), which log
 * to /usr/local/cpanel/logs/login_log and nowhere sshd can see. So the check ran, found no foreign ssh login,
 * and reported "clear" while a real account was being signed into from another continent with a stolen password.
 * This is that same check pointed at the door attackers use - a SUCCESSFUL login is the signal, because a
 * password that is already correct never appears as a failure for any brute-force rule to catch.
 *
 * Returns:
 *   'foreign' => [ ip => [user,cc,service,n] ]                      one entry per outside-region source
 *   'anomaly' => [ user => [countries=>[cc..], ips=>N, services] ]  one account seen from several countries
 * A successful login from EG/SA (or the wider Arab set) is normal and never reported. "Foreign" is exactly the
 * shared smpro_geo_foreign rule the auto-block tiers use, so home region is configured in one place.
 */
/**
 * File Manager writes from outside the home region, and the takeover-tool signature.
 *
 * A takeover of 31 accounts on one server never tripped a single guard because every guard counts FAILED logins
 * and a stolen password does not fail. What the attacker DID leave was a fingerprint in cPanel's own access log:
 * from an outside address, `Fileman/save_file_content` writes a probe file, and `fileop&op=unlink` deletes it a
 * few seconds later (it was testing whether mail() worked before dropping the phishing kit) - 454 times across
 * the accounts. That write->delete pair, seconds apart, from an address outside the region the operator trusts,
 * is not something a real customer does. This reads the same log and reports two things:
 *   'writes'    => File Manager writes from OUTSIDE the home region (one row per ip|user)      - high
 *   'signature' => write followed by unlink from the same ip|user within $pairSecs           - critical
 * "Outside the home region" is the shared smpro_geo_foreign rule, so it is configured in one place.
 */
function smpro_fm_foreign_writes($windowHours = 24, $pairSecs = 120, $tailLines = 60000) {
    $log = '/usr/local/cpanel/logs/access_log';
    if (!is_readable($log) || !function_exists('smpro_geo_foreign'))
        return ['ok' => false, 'why' => 'cPanel access_log unreadable or geo unavailable', 'writes' => [], 'signature' => []];
    if (function_exists('smpro_im_home_configured') && !smpro_im_home_configured())
        return ['ok' => false, 'why' => 'home region not configured', 'writes' => [], 'signature' => []];
    $cutoff = time() - max(1, (int)$windowHours) * 3600;
    // This log is large (hundreds of MB on a busy box): tail a bounded slice, never read the whole file.
    $raw = (string)@shell_exec('timeout 25 tail -n ' . (int)$tailLines . ' ' . escapeshellarg($log) . ' 2>/dev/null');
    if (trim($raw) === '') {
        if ((int)@filesize($log) > 0) return ['ok' => false, 'why' => 'access_log could not be read (tail returned nothing on a non-empty file)', 'writes' => [], 'signature' => []];
        return ['ok' => true, 'writes' => [], 'signature' => []];
    }
    return smpro_fm_foreign_writes_parse($raw, $cutoff, $pairSecs);
}

/** The parse half, separated so it can be driven with a fixture. $raw = cPanel access_log lines. */
function smpro_fm_foreign_writes_parse($raw, $cutoff, $pairSecs = 120) {
    $writes = []; $byKey = [];   // byKey: ip|user => [['t'=>ts,'kind'=>write|unlink,'file'=>..]]
    foreach (explode("\n", (string)$raw) as $line) {
        if ($line === '') continue;
        $isWrite  = strpos($line, 'Fileman/save_file_content') !== false || strpos($line, 'cpanel_jsonapi_func=savefile') !== false;
        $isUnlink = strpos($line, 'op=unlink') !== false && strpos($line, 'Fileman') !== false;
        if (!$isWrite && !$isUnlink) continue;
        // IP - user [MM/DD/YYYY:HH:MM:SS -0000] "REQ"   (cPanel's own access_log shape, US date order)
        if (!preg_match('/^(\S+) - (\S+) \[(\d{2})\/(\d{2})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) [^\]]*\] "/', $line, $m)) continue;
        $ip = $m[1]; $user = $m[2];
        if (!filter_var($ip, FILTER_VALIDATE_IP) || $user === '-') continue;
        $ts = @gmmktime((int)$m[6], (int)$m[7], (int)$m[8], (int)$m[3], (int)$m[4], (int)$m[5]) ?: 0;
        if ($ts && $ts < $cutoff) continue;
        if (function_exists('smpro_is_server_ip') && smpro_is_server_ip($ip)) continue;
        $g = smpro_geo_foreign($ip);
        if (empty($g['foreign'])) continue;                        // home region / Arab set / local -> a customer at work
        $file = '';
        if ($isUnlink && preg_match('/sourcefiles=([^&\s"]+)/', $line, $f)) $file = urldecode($f[1]);
        $k = $ip . '|' . $user;
        $byKey[$k][] = ['t' => $ts, 'kind' => $isWrite ? 'write' : 'unlink', 'file' => $file];
        if ($isWrite) {
            if (!isset($writes[$k])) $writes[$k] = ['ip' => $ip, 'user' => $user, 'cc' => (string)$g['cc'], 'n' => 0, 'last' => 0];
            $writes[$k]['n']++; $writes[$k]['last'] = max($writes[$k]['last'], $ts);
        }
    }
    // The signature: a write, then an unlink from the same ip|user within $pairSecs. One pair is enough.
    $signature = [];
    foreach ($byKey as $k => $ev) {
        usort($ev, fn($a, $b) => $a['t'] <=> $b['t']);
        $lastWrite = null;
        foreach ($ev as $e) {
            if ($e['kind'] === 'write') { $lastWrite = $e['t']; continue; }
            if ($lastWrite !== null && $e['t'] - $lastWrite >= 0 && $e['t'] - $lastWrite <= max(5, (int)$pairSecs)) {
                [$ip, $user] = explode('|', $k, 2);
                if (!isset($signature[$k])) $signature[$k] = ['ip' => $ip, 'user' => $user, 'cc' => $writes[$k]['cc'] ?? '', 'pairs' => 0, 'files' => []];
                $signature[$k]['pairs']++;
                if ($e['file'] !== '' && count($signature[$k]['files']) < 5) $signature[$k]['files'][] = basename($e['file']);
                $lastWrite = null;
            }
        }
    }
    return ['ok' => true, 'writes' => array_values($writes), 'signature' => array_values($signature)];
}

/**
 * Honeytoken (decoy) accounts: cPanel users that exist for no customer, host nothing, and are never logged into.
 *
 * A credential marketplace sells lists in bulk, and a buyer's tool tries every account on the list. A decoy
 * account on that list is the one login that can never be legitimate - so ANY successful login to it is a
 * confirmed leak with zero chance of a false positive, and even a FAILED attempt means the account name is on
 * somebody's list. Both are reported; the successful one is critical. The decoy user names come from the
 * operator's config (`honeytoken_users`) - the plugin never guesses which accounts are decoys.
 */
function smpro_honey_hits($windowHours = 168) {
    $cfg = function_exists('smpro_in_cfg') ? smpro_in_cfg() : [];
    $decoys = array_values(array_filter(array_map('strval', (array)($cfg['honeytoken_users'] ?? [])), fn($u) => (bool)preg_match('/^[a-zA-Z0-9._-]{1,64}$/', $u)));
    if (!$decoys) return ['ok' => true, 'configured' => 0, 'hits' => []];
    if (!function_exists('smpro_login_line_real')) { $lf = __DIR__ . '/loginfeed.php'; if (@is_file($lf)) require_once $lf; }
    $log = function_exists('smpro_lf_login_log') ? smpro_lf_login_log() : '/usr/local/cpanel/logs/login_log';
    if (!is_readable($log)) return ['ok' => false, 'why' => 'login_log unreadable', 'configured' => count($decoys), 'hits' => []];
    $cutoff = time() - max(1, (int)$windowHours) * 3600;
    $raw = (string)@shell_exec('timeout 25 tail -n 40000 ' . escapeshellarg($log) . ' 2>/dev/null'); if (function_exists('smpro_login_log_resolve')) $raw = smpro_login_log_resolve($raw);   // 127.0.0.1 behind WebShield / the cPanel proxy -> the visitor
    if (trim($raw) === '') {
        if ((int)@filesize($log) > 0) return ['ok' => false, 'why' => 'login_log could not be read', 'configured' => count($decoys), 'hits' => []];
        return ['ok' => true, 'configured' => count($decoys), 'hits' => []];
    }
    $r = smpro_honey_hits_parse($raw, $decoys, $cutoff);
    $r['configured'] = count($decoys);
    return $r;
}

/**
 * When an account's password was last changed by this plugin, or 0 if it never was.
 *
 * Read from the password-reset record, which carries the account, the reason, the date and who did it - and
 * deliberately never the password. Memoised: the detectors ask about the same accounts repeatedly while walking
 * a week of log lines.
 *
 * A missing or unreadable record answers 0, which means "no reset known" and leaves every event counted. Failing
 * open is right here: the cost of not suppressing a stale alert is noise, while the cost of wrongly suppressing
 * one is a real compromise going unreported.
 */
/**
 * The most recent successful password reset on this server, whoever it was for.
 *
 * The per-account cutoff below stops a reported login being counted against an account whose password has since
 * changed. It does not stop the REPORT repeating: the window is seven days, so every run re-reads the same week
 * and sends the same list again, and an operator who acted on it yesterday gets it again today with the same
 * names in it.
 *
 * So a reset is also a line in the sand for the report as a whole. After one, the next report starts from there
 * and says what has happened SINCE - which is the only thing anybody can still act on. Everything before it was
 * either dealt with or is on an account that was not reset, and that distinction is what the per-account cutoff
 * already draws.
 */
function smpro_pw_any_reset_at(): int {
    static $ts = null;
    if ($ts !== null) return $ts;
    $ts = 0;
    $f = defined('SMPRO_GR_LOG') ? SMPRO_GR_LOG : (SMPRO_VARLOG . '/password_resets.log');
    if (@is_readable($f)) {
        // Only the tail is read: the newest line that says "changed" is the answer, and these files grow.
        $raw = (string)@shell_exec('timeout 10 tail -n 400 ' . escapeshellarg($f) . ' 2>/dev/null');
        foreach (explode("\n", $raw) as $line) {
            $j = json_decode(trim((string)$line), true);
            if (!is_array($j) || ($j['result'] ?? '') !== 'changed') continue;
            $t2 = @strtotime((string)($j['at'] ?? '')) ?: 0;
            if ($t2 > $ts) $ts = $t2;
        }
    }
    return $ts;
}

/**
 * When was this login's password last changed, according to the SYSTEM (not only this plugin's own reset log):
 * the cPanel account from /etc/shadow (field 3, days since the epoch), a mailbox from the domain's mail shadow
 * file (same layout, cPanel writes it on every mailbox password change). A reset made in WHM, in cPanel or by the
 * customer therefore clears the alert exactly like one made from the Threat Report. Day granularity: a change on
 * the same day as a login counts as AFTER it (the conservative reading - the login stops being evidence).
 */
function smpro_pw_reset_sys(string $account, string $login): int {
    static $memo = [];
    $key = $account . '|' . $login; if (isset($memo[$key])) return $memo[$key];
    $day = 0;
    $lastchg = function (string $file, string $name): int {
        if ($name === '' || !@is_readable($file)) return 0;
        foreach ((array)@file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $l) {
            if (strpos($l, $name . ':') !== 0) continue;
            $p = explode(':', $l); return isset($p[2]) && ctype_digit((string)$p[2]) ? (int)$p[2] : 0;
        }
        return 0;
    };
    if (strpos($login, '@') !== false) {
        [$box, $dom] = explode('@', $login, 2);
        $dom = strtolower(preg_replace('/[^a-z0-9.-]/i', '', $dom)); $box = preg_replace('/[^a-z0-9._-]/i', '', $box);
        $home = function_exists('smpro_user_home') ? smpro_user_home($account) : '';
        if ($home !== '' && $dom !== '') $day = $lastchg($home . '/etc/' . $dom . '/shadow', $box);
    } else {
        $day = $lastchg('/etc/shadow', preg_replace('/[^a-z0-9._-]/i', '', $login));
    }
    return $memo[$key] = $day > 0 ? ($day + 1) * 86400 : 0;   // end of that day: a same-day login is read as before the change
}
function smpro_pw_reset_at($account): int {
    static $map = null;
    if ($map === null) {
        $map = [];
        $f = defined('SMPRO_GR_LOG') ? SMPRO_GR_LOG : (SMPRO_VARLOG . '/password_resets.log');
        if (@is_readable($f)) {
            foreach ((array)@file($f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
                $j = json_decode((string)$line, true);
                if (!is_array($j) || ($j['result'] ?? '') !== 'changed') continue;   // a FAILED reset changed nothing
                $u = (string)($j['user'] ?? ''); if ($u === '') continue;
                $ts = @strtotime((string)($j['at'] ?? '')) ?: 0;
                if ($ts > (int)($map[$u] ?? 0)) $map[$u] = $ts;
            }
        }
    }
    $u = (string)$account;
    // The product's own record first; then cPanel's, because a reset done in WHM or in the account's own cPanel
    // is a reset too. Reading only our log made the alert un-clearable for an operator who reset the password
    // the ordinary way: "still 2 logins from Germany" the morning after, naming an account already dealt with.
    return max((int)($map[$u] ?? 0), smpro_pw_native_reset_at($u));
}

/**
 * When cPanel itself last changed this identity's password, from cPanel's own evidence:
 *   - session_log: "PURGE user:token password_change" - exact time, written when a session was open at the change
 *   - the shadow record: lastchg is the DAY the password last changed (accounts: the system shadow; mailboxes:
 *     the domain's own shadow under ~/etc/DOMAIN/shadow) - day precision, so it is taken as the START of that day
 * The later of the two wins. Day precision errs toward clearing a sign-in from earlier the same day, which is
 * the right direction: a password changed today closes the door on everything that used the old one today.
 */
function smpro_pw_native_reset_at(string $identity): int {
    static $memo = [];
    if (isset($memo[$identity])) return $memo[$identity];
    $ts = 0;
    $identity = trim($identity);
    if ($identity === '' || !preg_match('/^[a-zA-Z0-9._@-]{1,120}$/', $identity)) return $memo[$identity] = 0;
    // 1. session_log PURGE ... password_change (exact)
    $sl = '/usr/local/cpanel/logs/session_log';
    if (@is_readable($sl)) {
        $raw = (string)@shell_exec('timeout 10 grep -a -F ' . escapeshellarg(' PURGE ' . $identity . ':') . ' ' . escapeshellarg($sl) . ' 2>/dev/null | grep -a -F password_change | tail -n 3');
        foreach (explode("\n", $raw) as $ln) {
            if (preg_match('/^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4})\]/', $ln, $m)) { $t2 = (int)@strtotime($m[1]); if ($t2 > $ts) $ts = $t2; }
        }
    }
    // 2. the shadow record's last-change day
    if (strpos($identity, '@') === false) {
        if (function_exists('posix_getpwnam') && @posix_getpwnam($identity)) {
            $line = (string)@shell_exec('timeout 5 getent shadow ' . escapeshellarg($identity) . ' 2>/dev/null');
            $f = explode(':', trim($line));
            if (isset($f[2]) && ctype_digit($f[2]) && (int)$f[2] > 0) { $t2 = (int)$f[2] * 86400; if ($t2 > $ts) $ts = $t2; }
        }
    } else {
        [$local, $dom] = explode('@', $identity, 2);
        $owner = '';
        if (function_exists('smpro_gr_owner_of')) $owner = (string)(smpro_gr_owner_of($identity)['account'] ?? '');
        $home = ($owner !== '' && function_exists('posix_getpwnam')) ? (string)((@posix_getpwnam($owner) ?: [])['dir'] ?? '') : '';
        $shadow = $home !== '' ? $home . '/etc/' . strtolower($dom) . '/shadow' : '';
        if ($shadow !== '' && @is_readable($shadow)) {
            foreach ((array)@file($shadow, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $ln) {
                $f = explode(':', (string)$ln);
                if (($f[0] ?? '') !== $local) continue;
                if (isset($f[2]) && ctype_digit($f[2]) && (int)$f[2] > 0) { $t2 = (int)$f[2] * 86400; if ($t2 > $ts) $ts = $t2; }
                break;
            }
        }
    }
    return $memo[$identity] = $ts;
}

/** The parse half. $raw = login_log lines; $decoys = the decoy user names. */
function smpro_honey_hits_parse($raw, array $decoys, $cutoff) {
    $set = array_flip($decoys); $hits = [];
    foreach (explode("\n", (string)$raw) as $line) {
        $line = trim($line); if ($line === '') continue;
        if (!preg_match('/^\[([^\]]+)\]\s+\S+\s+\[([^\]]+)\]\s+(\S+)\s+-\s+(\S+)/', $line, $m)) continue;
        $user = $m[4]; $svc = $m[2]; $ip = $m[3];
        if (!isset($set[$user])) continue;
        $ts = @strtotime($m[1]) ?: 0; if ($ts && $ts < $cutoff) continue;
        $ok = (bool)preg_match('/SUCCEEDED\s+LOGIN|SUCCESS\s+LOGIN/i', $line);
        $failed = (bool)preg_match('/FAILED\s+LOGIN|DEFERRED\s+LOGIN|AUTHENTICATION\s+FAILED/i', $line);
        if (!$ok && !$failed) continue;
        $cc = '';
        if (function_exists('smpro_geo_foreign')) { $g = smpro_geo_foreign($ip); $cc = (string)($g['cc'] ?? ''); }
        $k = $user . '|' . $ip . '|' . ($ok ? 'ok' : 'fail');
        if (!isset($hits[$k])) $hits[$k] = ['user' => $user, 'ip' => $ip, 'cc' => $cc, 'service' => $svc, 'success' => $ok, 'n' => 0, 'last' => 0];
        $hits[$k]['n']++; $hits[$k]['last'] = max($hits[$k]['last'], $ts);
    }
    usort($hits, fn($a, $b) => [$b['success'], $b['last']] <=> [$a['success'], $a['last']]);
    return ['ok' => true, 'hits' => array_values($hits)];
}

function smpro_foreign_success_logins($windowHours = 168, $anomalyCountries = 2, $anomalyIps = 3) {
    if (!function_exists('smpro_login_line_real')) { $lf = __DIR__ . '/loginfeed.php'; if (@is_file($lf)) require_once $lf; }
    $log = function_exists('smpro_lf_login_log') ? smpro_lf_login_log() : '/usr/local/cpanel/logs/login_log';
    if (!is_readable($log) || !function_exists('smpro_geo_foreign'))
        return ['ok' => false, 'why' => 'login_log unreadable or geo unavailable', 'foreign' => [], 'anomaly' => []];
    // With no home region, EVERY country is "foreign" and this would flag the operator's own logins. That is not
    // a finding, it is a missing setting - report it as such and classify nothing.
    if (function_exists('smpro_im_home_configured') && !smpro_im_home_configured())
        return ['ok' => false, 'why' => 'home region not configured', 'foreign' => [], 'anomaly' => []];
    $cutoff = time() - max(1, (int)$windowHours) * 3600;
    // tail is bounded; a busy panel writes a lot, so read enough to cover the window without scanning the whole file.
    $raw = (string)@shell_exec('timeout 25 tail -n 40000 ' . escapeshellarg($log) . ' 2>/dev/null'); if (function_exists('smpro_login_log_resolve')) $raw = smpro_login_log_resolve($raw);   // 127.0.0.1 behind WebShield / the cPanel proxy -> the visitor
    // An empty read of a log that is NOT empty means the read failed (timeout, permission, tail missing) - that
    // is "nothing was checked", not "nothing was found", and the two must never look the same to the caller.
    if (trim($raw) === '') {
        if ((int)@filesize($log) > 0) return ['ok' => false, 'why' => 'login_log could not be read (tail returned nothing on a non-empty file)', 'foreign' => [], 'anomaly' => []];
        return ['ok' => true, 'foreign' => [], 'anomaly' => []];                    // genuinely empty log
    }

    $foreign = [];                 // ip => [...]
    $seen = [];                    // user => [ cc => true ], and user => [ ip => true ]

    // Current cPanel does not write "SUCCEEDED LOGIN" anywhere. A granted session is a NEW line in session_log,
    // which is why this detector reported no foreign sign-ins on servers that were having them. Both shapes are
    // read now; the feed hands back one record per accepted password whichever file carried it.
    if (!function_exists('smpro_lf_success')) { $lf = __DIR__ . '/loginfeed.php'; if (@is_file($lf)) require_once $lf; }
    $lines = [];
    if (function_exists('smpro_lf_success')) {
        foreach ((array)smpro_lf_success($cutoff, 40000)['events'] as $e) {
            if ($e['ip'] === '' || !in_array($e['service'], ['cpaneld', 'webmaild'], true)) continue;
            $lines[] = ['ts' => (int)$e['ts'], 'ip' => (string)$e['ip'], 'user' => (string)$e['user'],
                        'svc' => (string)$e['service'], 'raw' => (string)$e['raw']];
        }
    }
    foreach (explode("
", $raw) as $line) {
        $line = trim($line); if ($line === '') continue;
        if (!preg_match('/SUCCEEDED\s+LOGIN|SUCCESS\s+LOGIN/i', $line)) continue;
        if (!preg_match('/\[(cpaneld|webmaild)\]/', $line, $sv)) continue;
        if (!preg_match('/^\[([^\]]+)\]\s+\S+\s+\[[^\]]+\]\s+(\S+)\s+-\s+(\S+)/', $line, $m)) continue;
        $lines[] = ['ts' => @strtotime($m[1]) ?: 0, 'ip' => $m[2], 'user' => $m[3], 'svc' => $sv[1], 'raw' => $line];
    }

    $dedupe = [];
    foreach ($lines as $row) {
        $line = $row['raw']; $sv = [1 => $row['svc']]; $m = [1 => '', 2 => $row['ip'], 3 => $row['user']];
        $ts = (int)$row['ts']; if ($ts && $ts < $cutoff) continue;
        // The same sign-in can appear in both files on a server that writes both. One event, once.
        $key = $ts . '|' . $row['ip'] . '|' . strtolower($row['user']);
        if (isset($dedupe[$key])) continue;
        $dedupe[$key] = 1;
        // A reset anywhere on this server starts the report again from that moment. Without it the same seven
        // days are re-read on every run and the same names are sent again, which is how an alert that HAS been
        // acted on becomes indistinguishable from one that has not.
        if ($ts && $ts < smpro_pw_any_reset_at()) continue;
        $ip = $m[2]; $user = $m[3]; $service = $sv[1];
        if (!filter_var($ip, FILTER_VALIDATE_IP)) continue;
        if (function_exists('smpro_is_server_ip') && smpro_is_server_ip($ip)) continue;
        // Webmail logs the mailbox address; cPanel logs the account name. The travel anomaly must group BOTH under
        // one identity or a mailbox login and a panel login for the same account look like two people. cPanel
        // writes the owner as "(possessor: X)" on the webmail line, so that is the account; fall back to the raw
        // token (already the account for a cpaneld line, or the address if no possessor was recorded).
        $account = $user;
        if (preg_match('/\(possessor:\s*([^)]+)\)/', $line, $pm)) $account = trim($pm[1]);
        // Anything from BEFORE the account's password was changed is not evidence any more: the credential those
        // logins used no longer opens the door. Counting them anyway made this alert un-clearable - an operator
        // who did exactly what it asked kept receiving it for the rest of the week, naming the same accounts. An
        // alert that does not stop when the problem is fixed teaches people to ignore it, and the next one it
        // sends is ignored too.
        if ($ts && (smpro_pw_reset_at($account) > $ts || smpro_pw_reset_sys((string)$account, (string)$user) > $ts)) continue;   // a reset made anywhere (WHM, cPanel, the customer) counts
        $g = smpro_geo_foreign($ip);

        /*
         * A CUSTOMER WHO LIVES ABROAD IS NOT A COMPROMISE, AND NO RESET CAN EVER MAKE THEM ONE.
         *
         * This had no allowance of any kind, so a mailbox whose owner lives in Turkey was reported every week,
         * for ever. Resetting its password does nothing: they sign in from Turkey again the next day and the
         * alert returns naming the same account. An alert that cannot be cleared by doing what it asks is the
         * fastest way to teach an operator to ignore it - and to ignore the real one underneath it.
         *
         * The allowance is the one Country Login Lock already keeps per account, not a second list of its own.
         * Two allow-lists that can disagree is a bug waiting for the day they do: the account the report calls
         * compromised would be the account the lock quietly lets through.
         */
        if (!empty($g['cc']) && function_exists('smpro_gl_allowed_for')) {
            static $glCfg = null;
            if ($glCfg === null) $glCfg = function_exists('smpro_gl_cfg') ? smpro_gl_cfg() : ['countries' => [], 'per_account' => []];
            // Asked through the lock's own helper, so the name is normalised exactly once and in one place.
            $allowed = (array)smpro_gl_allowed_for((string)$account, $glCfg);
            if ($allowed && in_array(strtoupper((string)$g['cc']), $allowed, true)) continue;
        }

        if (!empty($g['known']) && !empty($g['cc'])) {
            // The country is remembered for the message, and separately whether it was inside the home region.
            // The count that DECIDES must collapse the home region to one, or two ordinary countries in it read
            // as "travel" - see where $anomaly is built.
            $seen[$account]['cc'][$g['cc']] = true;
            if (empty($g['foreign'])) $seen[$account]['home_cc'][$g['cc']] = true;
            $seen[$account]['ip'][$ip] = true;
        }
        if (empty($g['foreign'])) continue;                        // home region / Arab / local / unplaceable -> fine
        $key = $ip . '|' . $user;
        if (!isset($foreign[$key])) $foreign[$key] = ['ip' => $ip, 'user' => $user, 'account' => $account, 'cc' => $g['cc'], 'service' => $service, 'n' => 0, 'first' => $ts, 'last' => $ts];
        $foreign[$key]['n']++;
        if ($ts) { $foreign[$key]['first'] = $foreign[$key]['first'] ? min($foreign[$key]['first'], $ts) : $ts; $foreign[$key]['last'] = max($foreign[$key]['last'], $ts); }
    }

    // Travel anomaly: one account signed into from several DIFFERENT countries inside the window. This catches a
    // stolen credential even when the attacker rents an in-region address, which the plain foreign test misses.
    $anomaly = [];
    foreach ($seen as $user => $d) {
        $ccs  = array_keys($d['cc'] ?? []);
        $home = array_keys($d['home_cc'] ?? []);
        $ips  = count($d['ip'] ?? []);

        // COUNT THE HOME REGION AS ONE PLACE.
        //
        // This counted every country separately, so an account signed into from two neighbouring countries that
        // are BOTH inside the configured home region was reported as "signed in from several countries - the
        // password is in more than one pair of hands". For a host whose customers live across that region this is
        // simply what an owner and their staff look like, and no password reset can ever change it: the owner
        // keeps signing in from both. The alert therefore could not be cleared by doing what it asked, which is
        // the fastest way to teach an operator to ignore an alert - and the next one, the real one, with it.
        //
        // What the signal is actually about is one identity appearing in places that are not plausibly the same
        // person. Two countries inside the home region are one place for that purpose. One home country plus a
        // foreign one is still two, and still reported.
        $distinct = count(array_diff($ccs, $home)) + (count($home) > 0 ? 1 : 0);

        if ($distinct >= max(2, (int)$anomalyCountries) && $ips >= max(2, (int)$anomalyIps))
            $anomaly[$user] = ['countries' => $ccs, 'ips' => $ips, 'places' => $distinct];
    }
    return ['ok' => true, 'foreign' => array_values($foreign), 'anomaly' => $anomaly];
}

/** Country name for a 2-letter code ("DE" -> "Germany"); the code itself when intl is missing. */
function smpro_cc_name($cc) {
    $cc = strtoupper(trim((string)$cc)); if ($cc === '' || strlen($cc) !== 2) return $cc;
    if (class_exists('Locale')) { $n = (string)@Locale::getDisplayRegion('-' . $cc, 'en'); if ($n !== '' && strtoupper($n) !== $cc) return $n; }
    // cPanel's bundled PHP does not always ship intl; a short table keeps the alert readable there too.
    static $t = ['US'=>'United States','GB'=>'United Kingdom','DE'=>'Germany','FR'=>'France','NL'=>'Netherlands','RU'=>'Russia','CN'=>'China','IN'=>'India','BR'=>'Brazil','TR'=>'Turkey','UA'=>'Ukraine','PL'=>'Poland','IT'=>'Italy','ES'=>'Spain','CA'=>'Canada','AU'=>'Australia','JP'=>'Japan','KR'=>'South Korea','VN'=>'Vietnam','ID'=>'Indonesia','PK'=>'Pakistan','BD'=>'Bangladesh','NG'=>'Nigeria','ZA'=>'South Africa','MX'=>'Mexico','AR'=>'Argentina','CO'=>'Colombia','SE'=>'Sweden','NO'=>'Norway','FI'=>'Finland','DK'=>'Denmark','CH'=>'Switzerland','AT'=>'Austria','BE'=>'Belgium','IE'=>'Ireland','PT'=>'Portugal','CZ'=>'Czechia','RO'=>'Romania','BG'=>'Bulgaria','HU'=>'Hungary','GR'=>'Greece','IL'=>'Israel','IR'=>'Iran','SG'=>'Singapore','HK'=>'Hong Kong','TW'=>'Taiwan','TH'=>'Thailand','MY'=>'Malaysia','PH'=>'Philippines','KZ'=>'Kazakhstan','LT'=>'Lithuania','LV'=>'Latvia','EE'=>'Estonia','MD'=>'Moldova','RS'=>'Serbia','HR'=>'Croatia','SK'=>'Slovakia','SI'=>'Slovenia','IS'=>'Iceland','NZ'=>'New Zealand','FJ'=>'Fiji','SA'=>'Saudi Arabia','EG'=>'Egypt','AE'=>'United Arab Emirates','QA'=>'Qatar','KW'=>'Kuwait','BH'=>'Bahrain','OM'=>'Oman','JO'=>'Jordan','LB'=>'Lebanon','IQ'=>'Iraq','SY'=>'Syria','YE'=>'Yemen','MA'=>'Morocco','DZ'=>'Algeria','TN'=>'Tunisia','LY'=>'Libya','SD'=>'Sudan','PS'=>'Palestine','MR'=>'Mauritania','SO'=>'Somalia','DJ'=>'Djibouti','KM'=>'Comoros','KE'=>'Kenya','ET'=>'Ethiopia','GH'=>'Ghana','SN'=>'Senegal','CL'=>'Chile','PE'=>'Peru','VE'=>'Venezuela','SC'=>'Seychelles','PA'=>'Panama','LU'=>'Luxembourg','CY'=>'Cyprus','MT'=>'Malta','GE'=>'Georgia','AM'=>'Armenia','AZ'=>'Azerbaijan','UZ'=>'Uzbekistan','BY'=>'Belarus','NP'=>'Nepal','LK'=>'Sri Lanka','MM'=>'Myanmar','KH'=>'Cambodia','MN'=>'Mongolia'];
    return $t[$cc] ?? $cc;
}

/**
 * Turn smpro_foreign_success_logins() output into the alert an operator can act on without decoding it. The old
 * text was "user @ ip (CC, cpaneld) xn" capped at 12 rows - for 38 logins it showed a third of them, two-letter
 * codes, no time, no provider, and no way to tell which ACCOUNT the webmail address belonged to. This groups by
 * account, names the country and the network, says which door (cPanel panel / webmail), when it last happened,
 * and what to do. Pure: $intel($ip) supplies provider/ASN (offline lookup in production; a stub in tests).
 * Returns ['title'=>..., 'body'=>..., 'accounts'=>n, 'countries'=>n, 'logins'=>n].
 */
function smpro_foreign_login_report(array $rows, int $windowHours, string $home, ?callable $intel = null, int $now = 0): array {
    $now = $now ?: time();
    $intel = $intel ?: function ($ip) { $i = function_exists('smpro_ip_intel') ? smpro_ip_intel($ip, false) : []; return trim((string)($i['provider'] ?? '') . (($i['asn'] ?? '') !== '' ? ' ' . $i['asn'] : '')); };
    $byAcct = []; $countries = []; $logins = 0;
    foreach ($rows as $r) {
        $a = (string)($r['account'] ?? $r['user'] ?? '?'); $byAcct[$a][] = $r; $countries[(string)$r['cc']] = true; $logins += (int)$r['n'];
    }
    uksort($byAcct, function ($x, $y) use ($byAcct) { $sx = array_sum(array_column($byAcct[$x], 'n')); $sy = array_sum(array_column($byAcct[$y], 'n')); return $sy <=> $sx; });
    $days = max(1, (int)round($windowHours / 24));
    $ago = function ($ts) use ($now) { $ts = (int)$ts; if ($ts <= 0) return ''; $d = $now - $ts; if ($d < 3600) return intdiv($d, 60) . ' min ago'; if ($d < 86400) return intdiv($d, 3600) . ' h ago'; return intdiv($d, 86400) . ' d ago (' . date('D d M H:i', $ts) . ')'; };
    $out = [];
    $out[] = 'Someone signed in SUCCESSFULLY to the cPanel panel or webmail from outside your home region (' . $home . ') in the last ' . $days . ' day(s).';
    $out[] = 'A correct password used from another country is the commonest sign of a leaked credential. Grouped by account, most logins first:';
    $out[] = '';
    $shown = 0; $acctCap = 20; $rowCap = 5; $i = 0;
    foreach ($byAcct as $acct => $list) {
        if (++$i > $acctCap) { $out[] = '… and ' . (count($byAcct) - $acctCap) . ' more account(s) — see Account Audit.'; break; }
        usort($list, fn($a, $b) => ($b['n'] <=> $a['n']) ?: (($b['last'] ?? 0) <=> ($a['last'] ?? 0)));
        $n = array_sum(array_column($list, 'n')); $cc = []; foreach ($list as $r) $cc[(string)$r['cc']] = true;
        $out[] = '▶ ' . $acct . ' — ' . $n . ' login(s) from ' . count($cc) . ' countr' . (count($cc) === 1 ? 'y' : 'ies') . ' (' . implode(', ', array_map('smpro_cc_name', array_keys($cc))) . ')';
        foreach (array_slice($list, 0, $rowCap) as $r) {
            $door = ($r['service'] === 'webmaild') ? 'webmail' : 'cPanel panel';
            $who  = ($r['user'] !== $acct && $r['user'] !== '') ? ' as ' . $r['user'] : '';
            $prov = (string)$intel((string)$r['ip']);
            $out[] = '    ' . smpro_cc_name((string)$r['cc']) . ' · ' . $r['ip'] . ($prov !== '' ? ' (' . $prov . ')' : '') . ' · ' . $door . $who . ' · ×' . (int)$r['n'] . (!empty($r['last']) ? ' · last ' . $ago($r['last']) : '');
            $shown++;
        }
        if (count($list) > $rowCap) $out[] = '    … ' . (count($list) - $rowCap) . ' more address(es) for this account';
    }
    $out[] = '';
    $out[] = 'What to do, per account:';
    $out[] = '  1. If the owner really is abroad (travel, a VPN, a remote developer), allow-list that address in Intrusion Monitor › Settings or set the region as a caution region — the alert stops for it.';
    $out[] = '  2. If not: reset the account password (from the Threat Report here, from WHM, or from the customer in cPanel - all count), end its sessions (WHM › Manage Sessions), then open Account Audit → search the address to see everything it did, and User Investigation for the account.';
    $out[] = '  3. Webmail logins name the mailbox; the account shown is its owner. A mailbox password is enough to send spam from this server — reset it too.';
    $out[] = 'This notice repeats only when the set of addresses/accounts changes.';
    $title = $logins . ' foreign cPanel/webmail login(s): ' . count($byAcct) . ' account(s), ' . count($countries) . ' countr' . (count($countries) === 1 ? 'y' : 'ies');
    return ['title' => $title, 'body' => implode("\n", $out), 'accounts' => count($byAcct), 'countries' => count($countries), 'logins' => $logins];
}

/** Same treatment for the travel anomaly: names the countries, says what it means, says what to do. */
function smpro_geo_anomaly_report(array $an, int $windowHours): array {
    $days = max(1, (int)round($windowHours / 24)); $out = [];
    $out[] = 'These account(s) were signed into SUCCESSFULLY from several different countries within ' . $days . ' day(s):';
    $out[] = '';
    foreach (array_slice($an, 0, 20, true) as $user => $d) $out[] = '▶ ' . $user . ' — ' . implode(', ', array_map('smpro_cc_name', (array)$d['countries'])) . ' · ' . (int)$d['ips'] . ' different addresses';
    if (count($an) > 20) $out[] = '… and ' . (count($an) - 20) . ' more';
    $out[] = '';
    $out[] = 'One account used from several countries in a week rarely means travel — it usually means the password is in more than one pair of hands. Reset it, end the sessions, and review the account in User Investigation.';
    return ['title' => count($an) . ' account(s) signed in from several countries', 'body' => implode("\n", $out)];
}

function smpro_login_guard_run($dryrun = false) {
    if (function_exists('smpro_ctl_dry_run') && smpro_ctl_dry_run()) $dryrun = true;   // global Dry-Run forces report-only
    $cfg = smpro_in_cfg();
    if (empty($cfg['login_guard'])) return ['ok' => false, 'msg' => 'login_guard disabled', 'blocked' => []];
    if (!function_exists('smpro_login_line_real')) { $lf = __DIR__ . '/loginfeed.php'; if (@is_file($lf)) require_once $lf; }
    $log = function_exists('smpro_lf_login_log') ? smpro_lf_login_log() : '/usr/local/cpanel/logs/login_log';
    if (!is_readable($log)) return ['ok' => false, 'msg' => 'login_log unreadable', 'blocked' => []];
    $thresh = max(2, (int)($cfg['login_guard_threshold'] ?? 4));
    $cutoff = time() - max(5, (int)($cfg['login_guard_window'] ?? 30)) * 60;
    $cap    = max(1, (int)($cfg['login_guard_cap'] ?? 20));
    $raw = (string)@shell_exec('timeout 20 tail -n 6000 ' . escapeshellarg($log) . ' 2>/dev/null'); if (function_exists('smpro_login_log_resolve')) $raw = smpro_login_log_resolve($raw);   // 127.0.0.1 behind WebShield / the cPanel proxy -> the visitor
    // Same rule as above: an empty read of a non-empty log is a failed read, and a guard that reports "nothing to
    // block" when it never saw the log would be silently off while looking on.
    if ($raw === '') {
        if ((int)@filesize($log) > 0) return ['ok' => false, 'msg' => 'login_log could not be read (tail returned nothing on a non-empty file)', 'blocked' => []];
        return ['ok' => true, 'blocked' => []];
    }
    $fails = [];
    foreach (explode("\n", $raw) as $line) {
        $line = trim($line); if ($line === '') continue;
        // cPanel login_log is  [ts] level [service] IP - user "REQUEST" MESSAGE  - ONE dash before the user,
        // then a quoted request. The old pattern required a SECOND dash (IP - user - MESSAGE), which current
        // cPanel never writes, so this matched nothing and the brute-force guard silently counted zero while
        // the Login Monitor's own (different, working) regex kept showing thousands of failures.
        if (preg_match('/^\[([^\]]+)\]\s+\S+\s+\[[^\]]+\]\s+(\S+)\s+-\s+(\S+)\s+(.+)$/', $line, $m)) { $timeRaw = $m[1]; $ip = $m[2]; $rest = $m[4]; }
        elseif (preg_match('/^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"[^"]*"\s+(.+)$/', $line, $m)) { $ip = $m[1]; $timeRaw = $m[2]; $rest = $m[3]; }
        else continue;
        if (!filter_var($ip, FILTER_VALIDATE_IP)) continue;
        if (preg_match('/SUCCEEDED\s+LOGIN|SUCCESS\s+LOGIN/i', $rest)) continue;
        if (!preg_match('/FAILED\s+LOGIN|DEFERRED\s+LOGIN|AUTHENTICATION\s+FAILED|INVALID|FAILURE/i', $rest)) continue;
        $ts = smpro_login_ts($timeRaw);
        if ($ts <= 0 || $ts < $cutoff) continue;   // an unreadable stamp (webmail's DD/Mon/YYYY:HH:MM:SS) was counted as a CURRENT failure
        $fails[$ip] = ($fails[$ip] ?? 0) + 1;
    }
    $state = smpro_in_state();
    $done  = is_array($state['login_guard_blocked'] ?? null) ? $state['login_guard_blocked'] : [];
    $allow = (array)($cfg['allowlist'] ?? []);

    // A DISTRIBUTED scan slips past the per-address rule by design: spread the attempts thinly enough and every
    // single address stays under the threshold, so nothing is ever blocked while the account is hammered from
    // hundreds of addresses at once. Rented cloud addresses make that cheap. So a second rule looks at the
    // NETWORK: when one network fields several addresses and they add up to real volume, the whole set counts as
    // one attacker even though no member reached the per-address threshold on its own.
    // Both numbers must be met - several addresses AND real volume. Either alone is ordinary background noise.
    $netMinIps   = max(2, (int)($cfg['login_guard_net_ips']   ?? 2));
    $netMinFails = max(2, (int)($cfg['login_guard_net_fails'] ?? 10));
    $netHit = [];
    if (!empty($cfg['login_guard_net']) && function_exists('smpro_geoip_asn')) {
        $byNet = [];
        foreach ($fails as $ip => $n) {
            $a = smpro_geoip_asn($ip);
            $k = (string)($a['asn'] ?? '');
            if ($k === '') continue;                       // unplaceable: the per-address rule still covers it
            $byNet[$k]['ips'][$ip] = $n;
            $byNet[$k]['fails'] = ($byNet[$k]['fails'] ?? 0) + $n;
            $byNet[$k]['name']  = (string)($a['provider'] ?? $k);
        }
        foreach ($byNet as $k => $g) {
            if (count($g['ips']) < $netMinIps || $g['fails'] < $netMinFails) continue;
            foreach (array_keys($g['ips']) as $ip) $netHit[$ip] = ['asn' => $k, 'name' => $g['name'], 'net_fails' => $g['fails'], 'net_ips' => count($g['ips'])];
        }
    }

    $blocked = []; arsort($fails);
    foreach ($fails as $ip => $n) {
        // Qualify on either rule: enough attempts alone, or membership of a network that qualified as a whole.
        if (($n < $thresh && !isset($netHit[$ip])) || isset($done[$ip]) || in_array($ip, $allow, true)) continue;
        $g = smpro_geo_foreign($ip);
        if (empty($g['foreign'])) continue;                 // FOREIGN (non-Arab) only; Arab/local protected
        if (count($blocked) >= $cap) break;
        $why = isset($netHit[$ip])
            ? ('Distributed login brute-force: ' . $netHit[$ip]['net_ips'] . ' addresses from ' . $netHit[$ip]['name']
               . ' totalling ' . $netHit[$ip]['net_fails'] . ' failed logins (' . $n . ' from this one), ' . $g['cc'])
            : ('Login brute-force: ' . $n . ' failed logins from ' . $g['cc']);
        if (!$dryrun) { smpro_im_block_ip($ip, $why); $done[$ip] = ['ts' => time(), 'n' => $n, 'cc' => $g['cc']]; }
        $blocked[] = ['ip' => $ip, 'fails' => $n, 'cc' => $g['cc'], 'rule' => isset($netHit[$ip]) ? 'network' : 'address',
                      'net' => $netHit[$ip]['name'] ?? ''];
        if (function_exists('smpro_audit')) smpro_audit('login_guard_block', ['ip' => $ip, 'fails' => $n, 'cc' => $g['cc'],
            'rule' => isset($netHit[$ip]) ? 'network' : 'address', 'net' => $netHit[$ip]['asn'] ?? '', 'dryrun' => $dryrun]);
    }
    if ($blocked && !$dryrun) { $state['login_guard_blocked'] = array_slice($done, -3000, 3000, true); smpro_in_state_save($state); }
    return ['ok' => true, 'blocked' => $blocked, 'scanned' => count($fails)];
}

/** Install/refresh (or remove) the per-minute login-guard cron. Idempotent + cheap (writes only on change). */
/** cron_sync entry. */
function smpro_lg_cron_sync(): bool { if (defined('SMPRO_TEST_SRC')) return true; smpro_login_guard_install_cron(); return true; }
function smpro_login_guard_install_cron() {
    $f = '/etc/cron.d/smpro-login-guard';
    $cfg = smpro_in_cfg();
    if (empty($cfg['login_guard'])) { if (is_file($f)) @unlink($f); return; }
    $bin = (defined('SMPRO_BASE') ? SMPRO_BASE : __DIR__ . '/..') . '/bin/login_guard.php';
    if (!is_file($bin)) return;
    $php  = smpro_php_cli_bin();   // canonical: cron's PATH may not resolve a bare `php`
    $lock = (defined('SMPRO_VARLIB') ? SMPRO_VARLIB : '/var/lib/smpro') . '/locks/login_guard.lock';
    @is_dir(dirname($lock)) || @mkdir(dirname($lock), 0700, true);
    $flock = is_executable('/usr/bin/flock') ? '/usr/bin/flock' : 'flock';
    $want = "# Safety Monitor Pro — foreign login brute-force guard (every minute; flock = no overlap)\n"
          . "* * * * * root $flock -n $lock timeout 120 $php $bin >/dev/null 2>&1\n";
    if (is_file($f) && (string)@file_get_contents($f) === $want) return;   // already current
    smpro_cron_install($f, $want);   // verified write: 0644 + trailing newline, or it reports failure
}

/* ============================ sources ============================ */
function smpro_im_modsec_log() {
    foreach (['/etc/apache2/logs/modsec_audit.log', '/usr/local/apache/logs/modsec_audit.log',
              '/var/log/apache2/modsec_audit.log', '/var/log/modsec_audit.log'] as $p) if (is_readable($p)) return $p;
    return '';
}
function smpro_im_userdomains() {
    static $map = null;
    if ($map !== null) return $map;
    $map = [];
    if (is_readable('/etc/userdomains')) foreach (file('/etc/userdomains', FILE_IGNORE_NEW_LINES) ?: [] as $l)
        if (preg_match('/^([^:]+):\s*(\S+)/', $l, $m)) $map[strtolower(trim($m[1]))] = trim($m[2]);
    return $map;
}
/**
 * Is this Host header a site that exists on this server? A wildcard DNS record (*.example.com at the DNS provider)
 * makes ANY invented name land on the parent's site; the attack feed then shows names that are nowhere in the panel.
 * Known = listed in userdomains, exactly or as www. of one. The parent it lands on is what account_for() returns.
 */
function smpro_im_host_known($domain) {
    $map = smpro_im_userdomains(); $d = strtolower(trim((string)$domain));
    return $d !== '' && (isset($map[$d]) || (strpos($d, 'www.') === 0 && isset($map[substr($d, 4)])));
}
/** The name as a person should read it: the host, then "(not a site here; wildcard DNS lands it on <parent>)". */
function smpro_im_host_label($domain) {
    if ($domain === '' || smpro_im_host_known($domain)) return (string)$domain;
    $parts = explode('.', strtolower($domain)); $map = smpro_im_userdomains(); $parent = '';
    while (count($parts) > 2) { array_shift($parts); $cand = implode('.', $parts); if (isset($map[$cand])) { $parent = $cand; break; } }
    return $domain . ' (not a site here' . ($parent !== '' ? '; wildcard DNS lands it on ' . $parent : '') . ')';
}
function smpro_im_account_for($domain) {
    $map = smpro_im_userdomains();
    $d = strtolower(trim((string)$domain));
    if (isset($map[$d])) return $map[$d];
    if (strpos($d, 'www.') === 0 && isset($map[substr($d, 4)])) return $map[substr($d, 4)];
    $parts = explode('.', $d);
    while (count($parts) > 2) { array_shift($parts); $cand = implode('.', $parts); if (isset($map[$cand])) return $map[$cand]; }
    return '';
}
/** A cPanel account's document roots (main + addon/sub), for breach correlation. */
function smpro_im_docroots($account) {
    $account = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)$account);
    if ($account === '' || !is_dir(smpro_user_home($account))) return [];
    $roots = [];
    $base = smpro_user_home($account) . '/public_html';
    if (is_dir($base)) $roots[$base] = 1;
    foreach (glob('/var/cpanel/userdata/' . $account . '/*') ?: [] as $f) {
        if (substr($f, -5) === '.cache' || substr($f, -9) === '_SSL') continue;
        $txt = (string)@file_get_contents($f);
        if (preg_match('/documentroot:\s*(\S+)/', $txt, $m) && is_dir($m[1])) $roots[$m[1]] = 1;
    }
    return array_keys($roots);
}

/* ============================ classification ============================ */
function smpro_im_classify($text) {
    $t = strtolower($text);
    $has = function ($n) use ($t) { foreach ((array)$n as $x) if (strpos($t, $x) !== false) return true; return false; };
    // word-boundary match for SHORT/ambiguous tokens so they don't false-match INSIDE benign words
    // (rce⊂force, sqli⊂mysqli, lfi⊂gulfintel, rfi⊂surfing, shell⊂powershell, login⊂..., session⊂obsession).
    $hasw = function ($n) use ($t) { foreach ((array)$n as $x) if (preg_match('/\b' . preg_quote($x, '/') . '\b/', $t)) return true; return false; };
    if ($has(['sql injection', 'union select', 'attack-sqli']) || $hasw(['sqli']))         return 'SQL Injection';
    if ($has(['cross-site scripting', 'attack-xss']) || $hasw(['xss']))                    return 'XSS';
    if ($has(['remote command', 'os command', 'command injection', 'attack-rce']) || $hasw(['rce'])) return 'Command Injection / RCE';
    if ($has(['remote file inclusion', 'attack-rfi']) || $hasw(['rfi']))                   return 'Remote File Inclusion';
    if ($has(['path traversal', 'directory traversal', 'local file', 'attack-lfi', '../']) || $hasw(['lfi'])) return 'Path Traversal / LFI';
    if ($has(['dotfile', 'sensitive file', '.env', '.git', 'wp-config', 'backup file', 'config file'])) return 'Sensitive File Access';
    if ($has(['php injection', 'attack-php', 'php object', 'deserial']))                  return 'PHP Injection';
    if ($has(['scanner', 'nikto', 'sqlmap', 'nmap', 'masscan', 'attack-scanner']))        return 'Scanner / Recon';
    if ($has(['protocol', 'attack-protocol', 'invalid request', 'malformed']))            return 'Protocol Violation';
    if ($has(['authentication']) || $hasw(['brute', 'login']))                            return 'Brute Force / Auth';
    if ($has(['webshell', 'backdoor', 'upload']) || $hasw(['shell']))                     return 'Malicious Upload';
    if ($has(['fixation']) || $hasw(['session']))                                         return 'Session Attack';
    return 'WAF Block (other)';
}
function smpro_im_sev_rank($s) { static $r = ['critical'=>5,'error'=>4,'warning'=>3,'notice'=>2,'info'=>1]; return $r[strtolower((string)$s)] ?? 2; }
/**
 * The real client, when the connection modsec saw came from THIS machine.
 *
 * With nginx in front of Apache - the cPanel default - modsec records the client as the server's own address,
 * because that is literally who connected to it. Every external attack then looks like it originated ON the
 * server. The panel raised "a process on this server may be compromised and is attacking hosted sites" for
 * ordinary internet scanning, sent the operator hunting for a local compromise that did not exist, and at the
 * same time hid the attacker: their address sat unread in a forwarded-for header, so nothing blocked or even
 * reported it.
 *
 * X-Forwarded-For is NOT trusted in general and must not be: any client can set it, and honouring it would let
 * an attacker pin their attack on a chosen victim and have this software block that victim. Two conditions make
 * it safe here, and both are required:
 *
 *   1. The connection came from this machine or loopback. A remote client cannot produce that.
 *   2. The LAST address in the chain is taken, never the first. nginx appends what IT saw to whatever the client
 *      sent, so the tail is the proxy's own observation and the head is the client's to invent.
 *
 * cPanel's nginx also names the header with a per-server secret (X-Forwarded-For-<token>), which a remote client
 * cannot guess. When that form is present it is preferred, because its NAME is itself the proof of origin.
 */
function smpro_im_proxy_real_ip(string $connIp, string $xffName, string $xff): string {
    if ($xff === '') return '';
    $local = ($connIp === '127.0.0.1' || strpos($connIp, '127.') === 0 || $connIp === '::1')
          || (function_exists('smpro_is_server_ip') && smpro_is_server_ip($connIp));
    if (!$local) return '';                         // a real remote client: its header is its own to forge

    $parts = array_values(array_filter(array_map('trim', explode(',', $xff))));
    if (!$parts) return '';
    $ip = end($parts);                              // what the proxy appended, not what the client claimed
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return '';
    // Never hand back something that is itself local: that would restore the same wrong answer by another route.
    if ($ip === $connIp || strpos($ip, '127.') === 0 || $ip === '::1') return '';
    if (function_exists('smpro_is_server_ip') && smpro_is_server_ip($ip)) return '';
    return $ip;
}


/** Categories that, when the server answered 200, suggest a possible SUCCESSFUL exploit. */
/**
 * A panel service host: cPanel answers autodiscover./autoconfig. (mail client set-up) and the proxy subdomains with a
 * fixed reply for ANY path - a 200 there handed the attacker a mail-config XML, not the file they asked for.
 */
function smpro_im_service_host($domain) {
    return (bool)preg_match('/^(autodiscover|autoconfig|cpanel|whm|webmail|webdisk|cpcalendars|cpcontacts)\./i', (string)$domain);
}
/** Public files every WordPress/CMS ships; a 200 on them tells the scanner what runs there and nothing more. */
function smpro_im_recon_path($uri) {
    return (bool)preg_match('#(?:^|/)(?:wp-includes/wlwmanifest\.xml|readme\.html|license\.txt|wp-links-opml\.php|feed/?|robots\.txt|sitemap[^/]*\.xml|wp-json/?|xmlrpc\.php)(?:\?|$)#i', smpro_im_path_of($uri));
}
/**
 * "Served" means dangerous: the app answered 2xx to an exploit-class request on a real site. A 3xx is a redirect
 * (http to https, to www, to the 404 page) - the request never reached the application, and the replay over https
 * is logged on its own; counting it made a day of plain redirects read as thirteen successful exploits.
 */
function smpro_im_served($e) {
    $code = (int)($e['code'] ?? 0);
    return $code >= 200 && $code < 300 && smpro_im_exploit_kind($e['kind'] ?? '') && !smpro_im_service_host($e['domain'] ?? '');
}
function smpro_im_exploit_kind($kind) {
    return in_array($kind, ['SQL Injection','Command Injection / RCE','Remote File Inclusion','Path Traversal / LFI','PHP Injection','Malicious Upload'], true);
}

/* ============================ ModSecurity parser ============================ */
/**
 * A MONITORING transaction, not an attack: the WAF matched a rule whose action is "pass" (it only wrote the audit
 * record), the request was served (2xx/3xx) and the rule's own severity is NOTICE/DEBUG/INFO. Imunify360 ships
 * hundreds of such rules (file-upload scan triggers, WordPress admin telemetry, weak-password monitoring) that
 * fire on a logged-in editor's ordinary work. Counting them as "Web attack" made a legitimate user in the home
 * region read as an attacker, inflated Bot Guard's bad-request counts, and raised a false "exploit SERVED" alert
 * on every CRM upload. They are kept out of every attack count; the upload-cluster check still sees them.
 */
function smpro_im_is_monitor(array $e): bool {
    if (!empty($e['blocked'])) return false;
    $code = (int)($e['code'] ?? 0);
    if ($code !== 0 && ($code < 200 || $code >= 400)) return false;
    return smpro_im_sev_rank((string)($e['severity'] ?? '')) <= 2;   // notice / debug / info / unknown
}
function smpro_im_parse_modsec($bytes, $cap, $fromTs = 0, bool $withMonitor = false) {
    $log = smpro_im_modsec_log();
    if ($log === '') return [];
    $bytes = max(65536, (int)$bytes);
    $raw = (string)@shell_exec('timeout ' . SMPRO_TIMEOUT_NORMAL . ' tail -c ' . (int)$bytes . ' ' . escapeshellarg($log) . ' 2>/dev/null');
    if ($raw === '') return [];
    $events = []; $sec = ''; $cur = null; $started = false;
    $flush = function () use (&$cur, &$events, $fromTs) {
        if ($cur && !empty($cur['msg']) && ($cur['ts'] === 0 || $cur['ts'] >= $fromTs)) {
            // Resolve the REAL attacker IP: if the connection IP is a Cloudflare edge (or a private/proxy hop) and the
            // request carried a real-client header (CF-Connecting-IP / True-Client-IP / XFF), use that instead.
            $conn = (string)$cur['ip']; $real = (string)($cur['realip'] ?? '');
            if ($real !== '' && smpro_ip_is_external($real) && smpro_ip_is_cloudflare($conn)) $cur['ip'] = $real;   // a private/local peer is handled below with the proxy-appended XFF tail, never with a client-chosen header
            // A LOCAL reverse proxy (nginx in front of Apache - the cPanel default) connects from this machine's
            // OWN address, so every external attack was being recorded as coming from the server itself. That
            // produced a standing "a process on this server is attacking hosted sites" alarm for ordinary
            // internet scanning, and hid the real attacker, whose address was sitting unread in the forwarded
            // header. Trusted only because the connection provably came from this machine, and only the LAST
            // address in the chain is taken - the part the proxy appended, not the part a client can invent.
            elseif ($cur['ip'] === $conn) {
                $viaProxy = smpro_im_proxy_real_ip($conn, (string)($cur['xff_name'] ?? ''), (string)($cur['xff'] ?? ''));
                if ($viaProxy !== '' && smpro_ip_is_external($viaProxy)) { $cur['ip'] = $viaProxy; $cur['via_proxy'] = 1; }
            }
            // Drop noise: an unresolved Cloudflare edge IP or any private/local/loopback IP is not a real attacker.
            if (!smpro_im_is_noise_ip($cur['ip'])) { $cur['kind'] = smpro_im_classify($cur['msg'] . ' ' . $cur['tag']); if ($cur['kind'] === 'WAF Block (other)' && smpro_im_recon_path($cur['uri'])) $cur['kind'] = 'Scanner / Recon'; $cur['monitor'] = smpro_im_is_monitor($cur) ? 1 : 0; $events[] = $cur; }
        }
        $cur = null;
    };
    $tok = null;   // the current transaction's ModSec boundary token - see below
    foreach (explode("\n", $raw) as $ln) {
        if (preg_match('/^--([0-9A-Za-z]+)-([A-Z])--\s*$/', $ln, $m)) {
            $lineTok = $m[1]; $l = $m[2];
            // SECURITY: a ModSec transaction uses ONE random boundary token for ALL its section delimiters,
            // precisely so logged request/response content can never be mistaken for a delimiter. Bind to the
            // token from the opening -A-- and treat ONLY same-token lines as real delimiters. A different-token
            // boundary line is attacker-forged content inside the logged request body (part C) - ignore it
            // (fall through as inert content) so it can't start/populate a fake event with an attacker-chosen
            // IP / domain / severity (-> poisoned feed, false CRITICAL alerts, auto-block of a framed victim IP).
            if ($tok === null) {
                if ($l === 'A') { $flush(); $tok = $lineTok; $started = true; $sec = 'A'; $cur = ['ts'=>0,'ip'=>'','realip'=>'', 'xff' => '', 'xff_name' => '','domain'=>'','method'=>'','uri'=>'','code'=>'','rule'=>'','msg'=>'','tag'=>'','severity'=>'','ua'=>'']; }
                continue;   // stray delimiter outside any transaction -> ignore
            }
            if ($lineTok === $tok) {
                if ($l === 'A')     { $flush(); $tok = $lineTok; $sec = 'A'; $cur = ['ts'=>0,'ip'=>'','realip'=>'','domain'=>'','method'=>'','uri'=>'','code'=>'','rule'=>'','msg'=>'','tag'=>'','severity'=>'','ua'=>'']; }
                elseif ($l === 'Z') { $flush(); $tok = null; $sec = ''; }
                else                { $sec = $l; }
                continue;
            }
            // foreign-token boundary line -> forged body content: do NOT switch sections; fall through as content.
        }
        if (!$started || $cur === null) continue;
        if ($sec === 'A') {
            if ($cur['ts'] === 0 && preg_match('/^\[([^\]]+)\]\s+\S+\s+([0-9a-fA-F:.]+)\s+\d+/', $ln, $a)) {
                $t = $a[1];
                if (preg_match('#^(\d{1,2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?\s*([+\-]\d{4})?#', $t, $tm))
                    $cur['ts'] = strtotime($tm[1].' '.$tm[2].' '.$tm[3].' '.$tm[4].':'.$tm[5].':'.$tm[6].' '.($tm[7]??'')) ?: 0;
                else $cur['ts'] = strtotime($t) ?: 0;
                $cur['ip'] = $a[2];
            }
        } elseif ($sec === 'B') {
            if ($cur['method'] === '' && preg_match('#^([A-Z]+)\s+(\S+)\s+HTTP/#', $ln, $b)) { $cur['method'] = $b[1]; $cur['uri'] = $b[2]; }
            elseif (stripos($ln, 'Host:') === 0) $cur['domain'] = strtolower(trim(substr($ln, 5)));
            elseif ($cur['ua'] === '' && stripos($ln, 'User-Agent:') === 0) $cur['ua'] = trim(substr($ln, 11));
            elseif ($cur['realip'] === '' && stripos($ln, 'CF-Connecting-IP:') === 0) $cur['realip'] = trim(substr($ln, 17));
            elseif ($cur['realip'] === '' && stripos($ln, 'True-Client-IP:') === 0)   $cur['realip'] = trim(substr($ln, 15));
            // A LOCAL reverse proxy's forwarded-for. Captured here, trusted only in flush() and only when the
            // connection itself came from this machine - see smpro_im_proxy_real_ip() for why that distinction
            // is the whole safety of it.
            elseif ($cur['xff'] === '' && stripos($ln, 'X-Forwarded-For') === 0) {
                $c = strpos($ln, ':');
                if ($c !== false) { $cur['xff_name'] = trim(substr($ln, 0, $c)); $cur['xff'] = trim(substr($ln, $c + 1)); }
            }
            // NOTE: X-Forwarded-For is intentionally NOT trusted as the attacker IP - any HTTP client can set it,
            // so honoring it would let an attacker attribute their attack to (and get auto-blocked) an arbitrary
            // victim IP. Only the fronting-layer headers above (CF-Connecting-IP / True-Client-IP) are used, and
            // only when the connection IP is a Cloudflare edge (see the flush() guard).
        } elseif ($sec === 'F') {
            if ($cur['code'] === '' && preg_match('#^HTTP/\d\.\d\s+(\d{3})#', $ln, $f)) $cur['code'] = $f[1];
        } elseif ($sec === 'H') {
            if (stripos($ln, 'Action: Intercepted') === 0 || stripos($ln, 'Message: Access denied') === 0) $cur['blocked'] = 1;   // the WAF stopped it
            if (stripos($ln, 'Message:') === 0) {
                $sv = preg_match('/\[severity "([^"]*)"\]/', $ln, $svm) ? $svm[1] : '';
                if ($cur['msg'] === '' || smpro_im_sev_rank($sv) > smpro_im_sev_rank($cur['severity'])) {
                    if (preg_match('/\[msg "([^"]*)"\]/', $ln, $mm)) $cur['msg'] = trim(explode('||', $mm[1])[0]);
                    else $cur['msg'] = trim(preg_replace('/\[[^\]]*\]/', '', substr($ln, 8)));
                    if (preg_match('/\[id "([^"]*)"\]/', $ln, $idm)) $cur['rule'] = $idm[1];
                    if ($sv !== '') $cur['severity'] = $sv;
                    if (preg_match('/\[tag "([^"]*)"\]/', $ln, $tg)) $cur['tag'] = $tg[1];
                    if ($cur['code'] === '' && preg_match('/code (\d{3})/', $ln, $cm)) $cur['code'] = $cm[1];
                }
            }
        }
        if (count($events) >= $cap) break;
    }
    $flush();
    usort($events, fn($a, $b) => $b['ts'] <=> $a['ts']);
    if (!$withMonitor) $events = array_values(array_filter($events, fn($e) => empty($e['monitor'])));
    return $events;
}
function smpro_im_by_domain($events) {
    $d = [];
    foreach ($events as $e) {
        // tolerate malformed/partial event rows (missing keys) - no warnings on bad input
        $dom = (string)($e['domain'] ?? '') !== '' ? (string)$e['domain'] : '(no host)';
        if (!isset($d[$dom])) $d[$dom] = ['domain'=>$dom,'account'=>smpro_im_account_for($dom),'total'=>0,'ips'=>[],'cats'=>[],'sev'=>0,'sevlabel'=>'','first'=>PHP_INT_MAX,'last'=>0];
        $g = &$d[$dom]; $g['total']++;
        $ip = (string)($e['ip'] ?? ''); if ($ip !== '') $g['ips'][$ip] = ($g['ips'][$ip] ?? 0) + 1;
        $kind = (string)($e['kind'] ?? ''); $g['cats'][$kind] = ($g['cats'][$kind] ?? 0) + 1;
        $sevl = (string)($e['severity'] ?? ''); $r = smpro_im_sev_rank($sevl); if ($r > $g['sev']) { $g['sev'] = $r; $g['sevlabel'] = $sevl; }
        $ts = (int)($e['ts'] ?? 0); if ($ts) { if ($ts < $g['first']) $g['first'] = $ts; if ($ts > $g['last']) $g['last'] = $ts; }
        unset($g);
    }
    foreach ($d as &$g) { arsort($g['ips']); arsort($g['cats']); $g['uniq_ips'] = count($g['ips']); $g['top_cat'] = $g['cats'] ? array_key_first($g['cats']) : ''; if ($g['first'] === PHP_INT_MAX) $g['first'] = 0; }
    unset($g);
    uasort($d, fn($a, $b) => $b['total'] <=> $a['total']);
    return $d;
}

/* ============================ SQLite index (persistent history) ============================ */
function smpro_in_db() {
    static $db = false;
    if ($db !== false) return $db;
    if (!class_exists('PDO') || !in_array('sqlite', PDO::getAvailableDrivers(), true)) return $db = null;
    try {
        @is_dir(dirname(SMPRO_IN_DB)) || @mkdir(dirname(SMPRO_IN_DB), 0700, true);
        $db = new PDO('sqlite:' . SMPRO_IN_DB);
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_SILENT);
        $db->exec('PRAGMA journal_mode=WAL; PRAGMA busy_timeout=4000;');
        $db->exec('CREATE TABLE IF NOT EXISTS attacks(hash TEXT PRIMARY KEY, ts INTEGER, ip TEXT, domain TEXT, account TEXT, kind TEXT, severity TEXT, code TEXT, rule TEXT, uri TEXT)');
        $db->exec('CREATE INDEX IF NOT EXISTS ix_ts ON attacks(ts)');
        $db->exec('CREATE INDEX IF NOT EXISTS ix_dom ON attacks(domain)');
        $db->exec('CREATE INDEX IF NOT EXISTS ix_ip ON attacks(ip)');
        if (PHP_SAPI === 'cli') $db->exec('CREATE INDEX IF NOT EXISTS ix_ts_ip ON attacks(ts, ip)');   // covering index for the window aggregates (1.3M rows: 0.6 s -> ms); built by a worker, never inside a page request
        @chmod(SMPRO_IN_DB, 0600);
    } catch (Throwable $e) { $db = null; }
    return $db;
}
/** Insert events (dedup by content hash). Returns count of NEW rows. */
function smpro_in_ingest($events) {
    $db = smpro_in_db(); if (!$db) return 0;
    $st = $db->prepare('INSERT OR IGNORE INTO attacks(hash,ts,ip,domain,account,kind,severity,code,rule,uri) VALUES(?,?,?,?,?,?,?,?,?,?)');
    $n = 0; $db->beginTransaction();
    foreach ($events as $e) {
        $h = sha1(($e['ts']??0).'|'.($e['ip']??'').'|'.($e['domain']??'').'|'.($e['rule']??'').'|'.substr($e['uri']??'',0,200));
        $st->execute([$h,(int)($e['ts']??0),$e['ip']??'',$e['domain']??'',smpro_im_account_for($e['domain']??''),$e['kind']??'',$e['severity']??'',$e['code']??'',$e['rule']??'',substr($e['uri']??'',0,300)]);
        $n += $st->rowCount();
    }
    $db->commit();
    // retention: keep 30 days
    $db->exec('DELETE FROM attacks WHERE ts < ' . (time() - 30 * 86400));
    return $n;
}
/** Parse the recent tail and persist it. Returns the parsed events. */
function smpro_im_ingest_recent($bytes = SMPRO_IM_LIVE_BYTES, $mins = 120, bool $withMonitor = false) {
    $ev = smpro_im_parse_modsec($bytes, 6000, time() - $mins * 60, $withMonitor);
    $real = $withMonitor ? array_values(array_filter($ev, fn($e) => empty($e['monitor']))) : $ev;
    if ($real) smpro_in_ingest($real);
    smpro_in_sweep_monitor_rows();
    return $ev;
}
/** One-time: rows the old parser indexed from monitoring-only rules (served, NOTICE/DEBUG) are not attacks - remove them. */
function smpro_in_sweep_monitor_rows(): void {
    $flag = SMPRO_VARLIB . '/intrusion_noise_swept';
    if (@is_file($flag)) return;
    $db = smpro_in_db(); if (!$db) return;
    try {
        $n = $db->exec("DELETE FROM attacks WHERE UPPER(COALESCE(severity,'')) IN ('NOTICE','DEBUG','INFO','') AND CAST(code AS INTEGER) BETWEEN 200 AND 399");
        if (function_exists('smpro_audit')) smpro_audit('intrusion_index_noise_swept', ['rows' => (int)$n]);
    } catch (\Throwable $e) { if (function_exists('smpro_soft_fail')) smpro_soft_fail('intrusion_noise_sweep', $e); }
    @touch($flag);
}
function smpro_in_history($sinceTs, $limit = 5000) {
    $db = smpro_in_db(); if (!$db) return [];
    $st = $db->prepare('SELECT * FROM attacks WHERE ts >= ? ORDER BY ts DESC LIMIT ?');
    $st->execute([(int)$sinceTs, (int)$limit]);
    $rows = $st->fetchAll(PDO::FETCH_ASSOC) ?: [];
    return array_values(array_filter($rows, fn($r) => !smpro_im_is_noise_ip((string)($r['ip'] ?? ''))));   // hide CF-edge / local rows
}
/** All indexed attacks from one IP within [sinceTs, untilTs] (untilTs 0 = now). */
function smpro_in_by_ip($ip, $sinceTs = 0, $untilTs = 0, $limit = 400) {
    $db = smpro_in_db(); if (!$db) return [];
    $until = $untilTs ?: time();
    $st = $db->prepare('SELECT * FROM attacks WHERE ip = ? AND ts >= ? AND ts <= ? ORDER BY ts DESC LIMIT ?');
    $st->execute([(string)$ip, (int)$sinceTs, (int)$until, (int)$limit]);
    return $st->fetchAll(PDO::FETCH_ASSOC) ?: [];
}
/** Aggregated attack profile for one IP within a date window (sinceTs 0 = last 30 days). */
function smpro_in_ip_summary($ip, $sinceTs = 0, $untilTs = 0) {
    $since = $sinceTs ?: (time() - 30 * 86400);
    $rows = smpro_in_by_ip($ip, $since, $untilTs ?: time(), 5000);
    $s = ['total'=>count($rows),'domains'=>[],'cats'=>[],'codes'=>[],'first'=>PHP_INT_MAX,'last'=>0,'sev'=>'','sevr'=>0,'recent'=>array_slice($rows,0,40)];
    foreach ($rows as $r) {
        if (($r['domain'] ?? '') !== '') $s['domains'][$r['domain']] = ($s['domains'][$r['domain']] ?? 0) + 1;
        $s['cats'][$r['kind']] = ($s['cats'][$r['kind']] ?? 0) + 1;
        if (($r['code'] ?? '') !== '') $s['codes'][$r['code']] = ($s['codes'][$r['code']] ?? 0) + 1;
        $sr = smpro_im_sev_rank($r['severity'] ?? ''); if ($sr > $s['sevr']) { $s['sevr'] = $sr; $s['sev'] = $r['severity']; }
        $s['first'] = min($s['first'], (int)$r['ts']); $s['last'] = max($s['last'], (int)$r['ts']);
    }
    if ($s['first'] === PHP_INT_MAX) $s['first'] = 0; arsort($s['domains']); arsort($s['cats']); arsort($s['codes']);
    return $s;
}

/** All indexed attacks against a cPanel ACCOUNT's domains within [sinceTs, untilTs] (untilTs 0 = now).
 *  Uses the persisted `account` column (populated on ingest), so it survives ModSec log rotation. [1.1 beta] */
function smpro_in_by_account($account, $sinceTs = 0, $untilTs = 0, $limit = 2000) {
    $db = smpro_in_db(); if (!$db) return [];
    $account = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)$account);
    if ($account === '') return [];
    $until = $untilTs ?: time();
    $st = $db->prepare('SELECT * FROM attacks WHERE account = ? AND ts >= ? AND ts <= ? ORDER BY ts DESC LIMIT ?');
    $st->execute([$account, (int)$sinceTs, (int)$until, (int)$limit]);
    $rows = $st->fetchAll(PDO::FETCH_ASSOC) ?: [];
    return array_values(array_filter($rows, fn($r) => !smpro_im_is_noise_ip((string)($r['ip'] ?? ''))));   // hide CF-edge / local rows
}
/** Aggregated attack profile for one cPanel account within a window (sinceTs 0 = last 30 days). [1.1 beta] */
function smpro_in_account_summary($account, $sinceTs = 0, $untilTs = 0) {
    $since = $sinceTs ?: (time() - 30 * 86400);
    $rows = smpro_in_by_account($account, $since, $untilTs ?: time(), 5000);
    $s = ['account'=>$account,'total'=>count($rows),'domains'=>[],'ips'=>[],'cats'=>[],'codes'=>[],'first'=>PHP_INT_MAX,'last'=>0,'sev'=>'','sevr'=>0,'recent'=>array_slice($rows,0,50)];
    foreach ($rows as $r) {
        if (($r['domain'] ?? '') !== '') $s['domains'][$r['domain']] = ($s['domains'][$r['domain']] ?? 0) + 1;
        if (($r['ip'] ?? '') !== '')     $s['ips'][$r['ip']]        = ($s['ips'][$r['ip']] ?? 0) + 1;
        $s['cats'][$r['kind']] = ($s['cats'][$r['kind']] ?? 0) + 1;
        if (($r['code'] ?? '') !== '')   $s['codes'][$r['code']]    = ($s['codes'][$r['code']] ?? 0) + 1;
        $sr = smpro_im_sev_rank($r['severity'] ?? ''); if ($sr > $s['sevr']) { $s['sevr'] = $sr; $s['sev'] = $r['severity']; }
        $s['first'] = min($s['first'], (int)$r['ts']); $s['last'] = max($s['last'], (int)$r['ts']);
    }
    if ($s['first'] === PHP_INT_MAX) $s['first'] = 0;
    arsort($s['domains']); arsort($s['ips']); arsort($s['cats']); arsort($s['codes']);
    return $s;
}
/** ModSecurity rule-engine state across Apache contexts. cPanel writes SecRuleEngine PER-VHOST in the
 *  generated httpd.conf (plus the global modsec conf.d), so there is no single value - we COUNT them.
 *  Returns ['on'=>int,'off'=>int,'detection'=>int,'blocking'=>bool,'summary'=>str]. Used to warn honestly
 *  when the WAF is logging attacks but NOT blocking them. [1.1 beta] */
function smpro_im_modsec_engine_state() {
    if (function_exists('smpro_memo')) return (array)smpro_memo('im_engine_state', 300, fn() => smpro_im_modsec_engine_state_live());   // ~40 greps over the Apache confs: five minutes old at most
    return smpro_im_modsec_engine_state_live();
}
function smpro_im_modsec_engine_state_live() {
    $out = ['on' => 0, 'off' => 0, 'detection' => 0, 'blocking' => false, 'summary' => ''];
    $targets = array_filter(array_merge(
        ['/etc/apache2/conf/httpd.conf', '/usr/local/apache/conf/httpd.conf'],
        glob('/etc/apache2/conf.d/modsec*') ?: [],
        glob('/etc/apache2/conf.d/modsec/*') ?: []
    ), 'is_readable');
    foreach (array_unique($targets) as $f) {
        $raw = (string)@shell_exec('timeout 10 grep -hiE "^[[:space:]]*SecRuleEngine[[:space:]]+(On|Off|DetectionOnly)" ' . escapeshellarg($f) . ' 2>/dev/null');
        foreach (explode("\n", $raw) as $ln) {
            if (preg_match('/SecRuleEngine\s+(On|Off|DetectionOnly)/i', $ln, $m)) {
                $v = strtolower($m[1]);
                if ($v === 'on') $out['on']++; elseif ($v === 'off') $out['off']++; else $out['detection']++;
            }
        }
    }
    $out['blocking'] = $out['on'] > 0 && ($out['off'] + $out['detection']) === 0;
    if ($out['on'] + $out['off'] + $out['detection'] === 0) $out['summary'] = 'unknown';
    elseif ($out['blocking'])                                $out['summary'] = 'on';
    elseif ($out['on'] === 0)                                $out['summary'] = ($out['detection'] > 0 && $out['off'] === 0) ? 'detectiononly' : 'off';
    else                                                     $out['summary'] = 'mixed';
    return $out;
}

/** ALLOW an IP: add to the plugin allowlist (never auto-blocked) + CSF allow (and lift any deny). */
function smpro_im_allow_ip($ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return ['ok'=>false,'msg'=>'invalid IP'];
    $c = smpro_in_cfg(); $al = (array)($c['allowlist'] ?? []);
    if (!in_array($ip, $al, true)) { $al[] = $ip; smpro_in_cfg_save(['allowlist'=>array_values($al)]); }
    $parts = ['plugin allowlist'];
    $csf = smpro_im_csf_bin();
    if ($csf !== '') {
        @shell_exec('timeout 25 ' . escapeshellarg($csf) . ' -dr ' . escapeshellarg($ip) . ' 2>&1');   // lift any deny
        $out = (string)@shell_exec('timeout 25 ' . escapeshellarg($csf) . ' -a ' . escapeshellarg($ip) . ' ' . escapeshellarg('smpro allow ' . date('Y-m-d H:i')) . ' 2>&1');
        $parts[] = stripos($out, 'error') === false ? 'CSF allow' : 'CSF error';
    }
    if (!empty($c['use_cloudflare']) && function_exists('smpro_cf_unblock_ip') && smpro_cf_configured()) { $r = @smpro_cf_unblock_ip($ip); if (!empty($r['ok'])) $parts[] = 'CF unblock'; }
    // Apply to the LIVE firewall too (top-of-INPUT ACCEPT) so the unblock/allow takes effect even if CSF is
    // disabled/desynced and the old drop rules (incl. Imunify360) are still loaded - otherwise it may not stick.
    if (function_exists('smpro_fw_iptables_allow')) { $live = smpro_fw_iptables_allow($ip); if ($live !== '') $parts[] = 'live iptables'; }
    if (function_exists('smpro_im_blocked_forget')) smpro_im_blocked_forget($ip);   // drop from the blocked set so it no longer shows "✓ Blocked"
    return ['ok'=>true,'msg'=>implode(' · ', $parts)];
}

function smpro_in_stats($sinceTs) {
    // a 30-day window scans the whole index (1.3M rows, 0.4 s): kept for a minute, keyed by the window's minute
    if (function_exists('smpro_memo') && (time() - (int)$sinceTs) > 3 * 86400) return (array)smpro_memo('in_stats_' . intdiv((int)$sinceTs, 60), 60, fn() => smpro_in_stats_live($sinceTs));
    return smpro_in_stats_live($sinceTs);
}
function smpro_in_stats_live($sinceTs) {
    $db = smpro_in_db(); if (!$db) return ['total'=>0,'domains'=>0,'ips'=>0];
    $st = $db->prepare('SELECT COUNT(*) t, COUNT(DISTINCT domain) d, COUNT(DISTINCT ip) i FROM attacks WHERE ts >= ?');
    $st->execute([(int)$sinceTs]); $r = $st->fetch(PDO::FETCH_ASSOC) ?: [];
    return ['total'=>(int)($r['t']??0),'domains'=>(int)($r['d']??0),'ips'=>(int)($r['i']??0)];
}

/* ============================ Cloudflare + CSF response ============================ */
function smpro_im_csf_bin() { foreach (['/usr/sbin/csf', '/usr/local/csf/bin/csf'] as $b) if (is_executable($b)) return $b; return ''; }
function smpro_im_csf_blocked() {
    $set = [];
    if (is_readable('/etc/csf/csf.deny')) foreach (file('/etc/csf/csf.deny', FILE_IGNORE_NEW_LINES) ?: [] as $l) {
        $l = trim($l); if ($l === '' || $l[0] === '#') continue;
        if (preg_match('/^([0-9a-fA-F:.]+)/', $l, $m)) $set[$m[1]] = 'perm';
    }
    return $set;
}
function smpro_im_csf_block($ip) {
    // Robust + VERIFIED block: never trust `csf -d` stdout - confirm the IP actually landed in csf.deny and is
    // enforced. ok=true ONLY when really enforcing (false + actionable msg when CSF is in TESTING mode / absent).
    // Route through the firewall that is ACTUALLY enforcing. On a box where CSF is installed but disabled and
    // Imunify360 owns the rules, writing to csf.deny "succeeded" while blocking nothing - the admin saw the
    // attacker keep hitting the site after pressing Block.
    if (function_exists('smpro_fw_block_ip')) {
        $r = smpro_fw_block_ip($ip, 'smpro Intrusion Monitor');
        return ['ok'=>!empty($r['ok']), 'testing'=>!empty($r['testing']), 'recorded'=>!empty($r['recorded']),
                'engine'=>(string)($r['engine'] ?? ''), 'msg'=>(string)$r['msg']];
    }
    if (function_exists('smpro_csf_deny_add')) {
        $r = smpro_csf_deny_add($ip, 'smpro Intrusion Monitor');
        return ['ok'=>!empty($r['ok']), 'testing'=>!empty($r['testing']), 'recorded'=>!empty($r['recorded']), 'msg'=>(string)$r['msg']];
    }
    $csf = smpro_im_csf_bin();
    if ($csf === '') return ['ok'=>false,'msg'=>'csf not installed'];
    @shell_exec('timeout 25 ' . escapeshellarg($csf) . ' -d ' . escapeshellarg($ip) . ' ' . escapeshellarg('smpro Intrusion Monitor ' . date('Y-m-d H:i')) . ' 2>&1');
    clearstatcache();
    $ok = isset(smpro_im_csf_blocked()[$ip]);
    return ['ok'=>$ok,'msg'=>$ok ? ($ip . ' blocked in CSF') : 'csf -d did not persist to csf.deny'];
}
function smpro_cf_configured() { $c = smpro_in_cfg(); return $c['cf_token'] !== '' && $c['cf_account'] !== ''; }
/** Block an IP at the Cloudflare edge via an account-level access rule. */
function smpro_cf_block_ip($ip, $note = '') {
    $c = smpro_in_cfg();
    if (!smpro_cf_configured()) return ['ok'=>false,'msg'=>'Cloudflare not configured'];
    if (!preg_match('/^[0-9a-f]{32}$/i', (string)$c['cf_account'])) return ['ok'=>false,'msg'=>'Cloudflare account id malformed'];
    $body = json_encode(['mode'=>'block','configuration'=>['target'=>'ip','value'=>$ip],'notes'=>($note ?: 'smpro Intrusion Monitor')], JSON_UNESCAPED_SLASHES);
    $url = 'https://api.cloudflare.com/client/v4/accounts/' . rawurlencode($c['cf_account']) . '/firewall/access_rules/rules';
    $res = smpro_http($url, ['method'=>'POST','timeout'=>15,'body'=>$body,                 // API token stays in-process, not in argv
        'headers'=>['Authorization: Bearer ' . $c['cf_token'], 'Content-Type: application/json']]);
    $raw = $res['body'];
    $j = json_decode($raw, true);
    if (is_array($j) && !empty($j['success'])) return ['ok'=>true,'msg'=>'blocked at Cloudflare edge'];
    $err = is_array($j) && !empty($j['errors'][0]['message']) ? $j['errors'][0]['message'] : 'Cloudflare API error';
    // "already exists" is effectively success
    if (stripos($err, 'already') !== false || stripos($raw, 'duplicate') !== false) return ['ok'=>true,'msg'=>'already blocked at Cloudflare'];
    return ['ok'=>false,'msg'=>$err];
}
function smpro_im_allowlisted($ip) {
    foreach (smpro_in_cfg()['allowlist'] as $a) { $a = trim((string)$a); if ($a !== '' && ($a === $ip || (strpos($a, '/') !== false && smpro_in_cidr_match($ip, $a)))) return true; }
    // Anything the allow-list feature manages counts as allow-listed here too. Those ranges are in csf.allow,
    // which stops CSF acting on them - but this guard read only the manual list above, so an automatic response
    // could still be aimed at Googlebot or an uptime monitor. CSF would refuse the deny because the range is
    // allowed there, and the plugin would record a block that never took effect and present it as done.
    //
    // The module is pulled in HERE rather than relied on being present. Every bin/ worker that can block -
    // notify_check (which is what actually runs the automatic response), login_guard, hub_worker, cooler_tick,
    // autopurge - loads intrusion.php and does NOT load fwallow.php. A plain function_exists() check would have
    // been false in all of them, so this guard would have held in the panel and quietly done nothing in the one
    // place blocking happens without a human watching.
    if (!function_exists('smpro_fw_allow_covers')) {
        $fw = __DIR__ . '/fwallow.php';
        if (@is_file($fw)) { require_once $fw; }
    }
    if (function_exists('smpro_fw_allow_covers') && smpro_fw_allow_covers($ip) !== '') return true;
    return false;
}

/**
 * Shared per-IP login/auth scan across ALL services - SSH (/var/log/secure), mail (exim/dovecot
 * IMAP·POP·SMTP), FTP (pure-ftpd) and cPanel/WHM/webmail (login_log). This is what makes a
 * mail/SSH/FTP brute-forcer that never touches the web or cPanel actually SHOW UP in the IP report
 * (previously only SSH+cPanel were scanned, so a mail brute-force read as "no activity").
 * Bounded + recent-focused (reads a log tail, greps the IP, 32s overall budget) for busy shared boxes.
 * Returns rows [{ts, source, result:failed|success|attempt, user, detail}] newest-first.
 */
function smpro_ip_auth_attempts($ip, $sinceTs = 0, $untilTs = 0, $cap = 400) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return [];
    $ipq = escapeshellarg($ip); $since = $sinceTs ?: 0; $until = $untilTs ?: (time() + 86400);
    $rows = []; $yr = (int)date('Y'); $start = microtime(true);
    $sources = [
        ['/var/log/secure', 'ssh'], ['/var/log/auth.log', 'ssh'],
        ['/var/log/exim_mainlog', 'mail'], ['/var/log/maillog', 'mail'], ['/var/log/mail.log', 'mail'],
        ['/var/log/messages', 'ftp'], ['/usr/local/cpanel/logs/login_log', 'cpanel'],
    ];
    $seenMail = false; $seenFtp = false;
    foreach ($sources as $src) {
        [$file, $hint] = $src;
        if (!is_readable($file)) continue;
        if ($hint === 'mail' && $seenMail) continue;            // first existing maillog is enough
        if (microtime(true) - $start > 32) break;               // hard wall-clock budget
        $raw = (string)@shell_exec('timeout 12 sh -c ' . escapeshellarg('tail -n 250000 ' . escapeshellarg($file) . ' 2>/dev/null | grep -aF ' . $ipq . ' | tail -n 500') . ' 2>/dev/null');
        if ($hint === 'mail' && trim($raw) !== '') $seenMail = true;
        foreach (explode("\n", $raw) as $l) {
            $l = trim($l); if ($l === '' || strpos($l, $ip) === false) continue;
            $svc = $hint;
            if (stripos($l, 'sshd') !== false || stripos($l, 'ssh2') !== false) $svc = 'SSH';
            elseif (preg_match('/pure-?ftpd|proftpd|ftpd|pure-authd/i', $l)) $svc = 'FTP';
            elseif (preg_match('/dovecot|imap-login|pop3-login|authenticator failed|_login authenticator|exim|set_id=/i', $l)) $svc = 'Mail';
            elseif (preg_match('/whostmgrd|cpaneld|webmaild|cpsrvd/i', $l)) $svc = (stripos($l, 'webmail') !== false) ? 'Webmail' : 'cPanel';
            else $svc = strtoupper($hint) === 'SSH' ? 'SSH' : ($hint === 'ftp' ? 'FTP' : ($hint === 'mail' ? 'Mail' : 'cPanel'));
            if ($svc === 'ftp' || $svc === 'FTP') { if (!preg_match('/ftp/i', $l)) continue; }
            $failed = (bool)preg_match('/Failed|Invalid|failure|Incorrect|authentication (failed|error)|rejected|denied|not allowed|refused|FAILED LOGIN|DEFERRED|negativ/i', $l);
            $success = !$failed && (bool)preg_match('/Accepted|SUCCEEDED LOGIN|SUCCESS|authentication succeeded|logged in/i', $l);
            if (!$failed && !$success) { if (!preg_match('/login|auth|password|sshd|ftpd|dovecot|LOGIN/i', $l)) continue; $failed = true; }
            $user = '';
            if ($svc === 'SSH') { if (preg_match('/for (?:invalid user )?([^\s]+) from/i', $l, $um)) $user = $um[1]; elseif (preg_match('/invalid user ([^\s]+)/i', $l, $um)) $user = $um[1]; }
            elseif ($svc === 'Mail') { if (preg_match('/set_id=([^\s)]+)/i', $l, $um)) $user = $um[1]; elseif (preg_match('/U=([^\s]+)/', $l, $um)) $user = $um[1]; elseif (preg_match('/for user \[?([^\]\s]+)/i', $l, $um)) $user = $um[1]; }
            elseif ($svc === 'FTP') { if (preg_match('/user \[([^\]]+)\]/i', $l, $um)) $user = $um[1]; }
            else { if (preg_match('/\]\s+' . preg_quote($ip, '/') . '\s+-\s+([^\s"]+)/', $l, $um)) $user = rawurldecode($um[1]); }
            $user = trim((string)$user, "[]\"' "); if ($user === '-') $user = '';
            $ts = 0;
            if (preg_match('/^\[([^\]]+)\]/', $l, $tm)) $ts = strtotime($tm[1]) ?: 0;
            elseif (preg_match('/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/', $l, $tm)) $ts = strtotime($tm[1]) ?: 0;
            elseif (preg_match('/^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/', $l, $tm)) $ts = smpro_syslog_ts($tm[1], $yr);
            if ($since && $ts && $ts < $since) continue;
            if ($until && $ts && $ts > $until) continue;
            $rows[] = ['ts' => $ts, 'source' => $svc, 'result' => $failed ? 'failed' : ($success ? 'success' : 'attempt'), 'user' => $user, 'detail' => ''];
            if (count($rows) >= 5000) break 2;
        }
    }
    usort($rows, fn($a, $b) => ($b['ts'] ?? 0) <=> ($a['ts'] ?? 0));
    return array_slice($rows, 0, $cap);
}
/**
 * Home-region protection classifier for AUTO/AI blocks (manual admin blocks bypass this).
 * Returns:
 *   'core_protected' - RESIDENTIAL IP in a configured home region: never auto-block, route to manual review.
 *   'arab_caution'   - RESIDENTIAL IP in another Arab country: auto-block only when the attack is clear & repeated.
 *   'normal'         - everything else (incl. ALL datacenter/hosting IPs from anywhere): blockable as usual.
 */
/** The configured home-region country codes. One source of truth - never write a country code inline. */
/** Has the operator set a home region at all? Every geo-based classification is meaningless until they have. */
function smpro_im_home_configured(): bool { return count(smpro_im_home_regions()) > 0; }

/**
 * Suggest a home region from where THIS server is. Used only to pre-fill the setting and to word the setup
 * notice - never applied silently, because a server hosted abroad (a Saudi business on a German box) would then
 * be told its own customers are foreign. Returns '' when it cannot tell.
 */
function smpro_im_home_suggest(): string {
    static $cc = null;
    if ($cc !== null) return $cc;
    $cc = '';
    $mi = is_readable('/var/cpanel/mainip') ? trim((string)@file_get_contents('/var/cpanel/mainip')) : '';
    if (!filter_var($mi, FILTER_VALIDATE_IP) || !function_exists('smpro_ip_intel')) return $cc;
    $g = smpro_ip_intel($mi);
    $c = strtoupper((string)($g['country'] ?? ''));
    if (preg_match('/^[A-Z]{2}$/', $c) && !in_array($c, ['NA', 'N/'], true)) $cc = $c;
    return $cc;
}

function smpro_im_home_regions(): array {
    $c = smpro_in_cfg();
    // Respect an explicitly EMPTY protect_regions (admin cleared it) - do NOT fall back to EG/SA here, or the
    // labels/AI prompts would claim EG/SA are protected while enforcement (region_status/trusted_regions) protects
    // nothing. A fresh install still gets EG/SA from the config DEFAULT, so this only differs when deliberately cleared.
    return array_values(array_filter(array_map('strtoupper', array_map('trim', (array)($c['protect_regions'] ?? [])))));
}
/** Human label for the configured home regions - country name plus code, joined for prose.
 *  Used in admin-facing text AND in AI prompts - the operator's market must come from THEIR config, never from a
 *  literal baked into the product, or every licensed server is told it serves someone else's customers. */
function smpro_im_home_regions_label(bool $withLock = false): string {
    // Names come from ext-intl when it is loaded, otherwise the bare code. No country table is shipped:
    // a hardcoded list would go stale, and the product must not carry one market's geography in its source.
    $hasIntl = class_exists('Locale');
    $out = [];
    $list = smpro_im_home_regions();
    // The foreign-login alert judges against home + the lock's countries, so its label must say the same set -
    // "outside EG and SA" above a sign-in from AU that the lock allows is the sentence that made the alert wrong.
    if ($withLock) $list = array_values(array_unique(array_merge($list, smpro_im_lock_regions())));
    foreach ($list as $cc) {
        $nm = $hasIntl ? (string)@Locale::getDisplayRegion('-' . $cc, 'en') : '';
        $out[] = ($nm !== '' && strtoupper($nm) !== $cc) ? $nm . ' (' . $cc . ')' : $cc;
    }
    if (count($out) <= 1) return $out[0] ?? '';
    $last = array_pop($out);
    return implode(', ', $out) . ' and ' . $last;
}
/** Short form for compact UI: the configured codes joined by "/". */
function smpro_im_home_regions_short(): string { return implode('/', smpro_im_home_regions()); }

/** The operator's TRUSTED country set = home regions ∪ caution regions. This is what "not foreign" means for
 *  login-anomaly classification and the region view-filters - defined by the operator's own market, never a
 *  baked-in list. Empty ⇒ nothing is trusted (every external country reads as foreign/outside). */
function smpro_im_trusted_regions(): array {
    $c = smpro_in_cfg();
    $u = array_merge(
        array_map('strtoupper', array_filter((array)($c['protect_regions'] ?? []))),
        array_map('strtoupper', array_filter((array)($c['caution_regions'] ?? []))),
        smpro_im_lock_regions()
    );
    return array_values(array_unique($u));
}

/**
 * The countries Country Login Lock lets sign in. They are home too.
 *
 * Two lists disagreed. The lock allowed EG, SA and AU; Intrusion Monitor's home region said EG and SA. So a
 * customer in Australia signed in exactly as the lock permits, and the foreign-login alert reported that sign-in
 * as a leaked credential - every week, un-clearable, because the sign-in was allowed and would happen again.
 * A country the operator has told the lock to accept is not "outside the home region" in the next sentence.
 */
function smpro_im_lock_regions(): array {
    if (!function_exists('smpro_gl_cfg')) { $f = __DIR__ . '/geologin.php'; if (@is_file($f)) require_once $f; }
    if (!function_exists('smpro_gl_cfg')) return [];
    $g = smpro_gl_cfg();
    return array_values(array_filter(array_map('strtoupper', array_map('trim', (array)($g['countries'] ?? [])))));
}

/** Parse admin-entered country codes (any separators) into validated uppercase ISO alpha-2, de-duped, capped.
 *  Used by the region settings so home/caution regions are fully operator-configured, not baked in. */
function smpro_im_parse_ccs(string $s): array {
    $out = [];
    foreach (preg_split('/[^A-Za-z]+/', $s) as $t) {
        $t = strtoupper($t);
        if (strlen($t) === 2) $out[$t] = 1;
    }
    return array_slice(array_keys($out), 0, 40);
}
function smpro_im_region_status($ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return 'normal';
    $in = function_exists('smpro_ip_intel') ? smpro_ip_intel($ip, false) : [];
    // Datacenter / hosting networks are fair game regardless of country - abusers rent VMs inside the home region too.
    if (function_exists('smpro_ip_is_datacenter') && smpro_ip_is_datacenter($in)) return 'normal';
    $cc = strtoupper((string)($in['country'] ?? ''));
    if ($cc === '') return 'normal';                                          // unknown geo -> no special protection
    $c = smpro_in_cfg();
    $home = array_map('strtoupper', (array)($c['protect_regions'] ?? []));   // no market fallback: unset means unset
    if (in_array($cc, $home, true)) return 'core_protected';
    // Tier-2 caution regions are a CONFIGURABLE country-code list, not a baked-in market. Ships empty, so out of
    // the box only the admin's home region is special-cased; the operator sets whichever neighbouring/soft-review
    // countries fit their market (an "Arab countries" preset is one click away in the UI). Empty ⇒ no tier-2.
    $caution = array_map('strtoupper', array_filter((array)($c['caution_regions'] ?? [])));
    if ($caution && in_array($cc, $caution, true)) return 'arab_caution';    // internal tier id kept for compat
    return 'normal';
}
function smpro_in_cidr_match($ip, $cidr) {
    if (strpos($cidr, '/') === false) return $ip === $cidr;
    [$net, $bits] = explode('/', $cidr, 2); $bits = (int)$bits;
    // IPv4
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && filter_var($net, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        if ($bits < 0 || $bits > 32) return false;
        $mask = $bits === 0 ? 0 : (~0 << (32 - $bits)) & 0xFFFFFFFF;
        return (ip2long($ip) & $mask) === (ip2long($net) & $mask);
    }
    // IPv6 - compare the packed bytes up to $bits (so IPv6 CIDR allowlist entries actually match)
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) && filter_var($net, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        if ($bits < 0 || $bits > 128) return false;
        $a = @inet_pton($ip); $b = @inet_pton($net); if ($a === false || $b === false) return false;
        $whole = intdiv($bits, 8); $rem = $bits % 8;
        if ($whole > 0 && substr($a, 0, $whole) !== substr($b, 0, $whole)) return false;
        if ($rem === 0) return true;
        $m = (~0 << (8 - $rem)) & 0xFF;
        return (ord($a[$whole]) & $m) === (ord($b[$whole]) & $m);
    }
    return false;   // mixed family -> no match
}
/** Cloudflare edge IP ranges (published CIDRs). Behind CF, ModSecurity logs the EDGE IP as the client - so we
 *  resolve the real attacker from CF-Connecting-IP and never show/block a CF IP (that would block ALL CF traffic). */
function smpro_ip_is_cloudflare($ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return false;
    static $cidrs = ['173.245.48.0/20','103.21.244.0/22','103.22.200.0/22','103.31.4.0/22','141.101.64.0/18',
        '108.162.192.0/18','190.93.240.0/20','188.114.96.0/20','197.234.240.0/22','198.41.128.0/17',
        '162.158.0.0/15','104.16.0.0/13','104.24.0.0/14','172.64.0.0/13','131.0.72.0/22',
        '2400:cb00::/32','2606:4700::/32','2803:f800::/32','2405:b500::/32','2405:8100::/32','2a06:98c0::/29','2c0f:f248::/32'];
    foreach ($cidrs as $c) if (smpro_in_cidr_match($ip, $c)) return true;
    return false;
}
/** A "noise" source IP for the attack feed: empty, a Cloudflare edge, or private/local/reserved - not a real attacker. */
function smpro_im_is_noise_ip($ip) {
    return $ip === '' || smpro_ip_is_cloudflare($ip) || (function_exists('smpro_ip_is_external') && !smpro_ip_is_external($ip));
}

/** Orchestrated block: CSF + Cloudflare (per settings), with safety guards. Returns combined result. */
function smpro_im_block_ip($ip, $note = '') {
    if (!filter_var($ip, FILTER_VALIDATE_IP))                                  return ['ok'=>false,'msg'=>'invalid IP'];
    if (function_exists('smpro_is_server_ip') && smpro_is_server_ip($ip))       return ['ok'=>false,'msg'=>'refused: server IP'];
    if (function_exists('smpro_ip_is_external') && !smpro_ip_is_external($ip))  return ['ok'=>false,'msg'=>'refused: private/local IP'];
    if (smpro_im_allowlisted($ip))                                             return ['ok'=>false,'msg'=>'refused: allowlisted'];
    // NEVER CSF-block a Cloudflare edge IP - it fronts inbound traffic for EVERY site on the box, so a deny would
    // black-hole all of them. The real client is in CF-Connecting-IP (the WAF path already resolves it). Block at CF.
    if (smpro_ip_is_cloudflare($ip))                                           return ['ok'=>false,'msg'=>'refused: Cloudflare edge IP — blocking it would cut ALL inbound traffic to every site. Block the real client (CF-Connecting-IP) at Cloudflare, not CSF.'];
    $c = smpro_in_cfg(); $parts = []; $ok = false;
    if (!empty($c['use_csf']))        { $r = smpro_im_csf_block($ip);     $parts[] = 'CSF:' . ($r['ok'] ? 'ok' : $r['msg']); $ok = $ok || $r['ok']; }
    if (!empty($c['use_cloudflare']) && smpro_cf_configured()) { $r = smpro_cf_block_ip($ip, $note); $parts[] = 'CF:' . ($r['ok'] ? 'ok' : $r['msg']); $ok = $ok || $r['ok']; }
    if ($ok) smpro_im_blocked_record($ip, implode(',', $parts), $note);   // record EVERY successful block (incl. Cloudflare-only, which never lands in csf.deny) so the UI marks it and it doesn't re-appear as a "new" discovery
    return ['ok'=>$ok,'msg'=>implode(' · ', $parts) ?: 'no blocker enabled'];
}

/* Persistent record of IPs SM Pro has blocked (manual / AI / login-guard / emergency), across CSF *and* Cloudflare.
 * The CSF deny list alone misses Cloudflare-only blocks and anything CSF failed to persist - this closes that gap so
 * a blocked IP always shows "✓ Blocked" and never re-surfaces as a fresh find. Dedicated locked file (no state race). */
function smpro_im_blocked_file() { return SMPRO_VARLIB . '/im_blocked.json'; }
function smpro_im_blocked_load() { $d = json_decode((string)@file_get_contents(smpro_im_blocked_file()), true); return is_array($d) ? $d : []; }
function smpro_im_blocked_record($ip, $via, $note = '') {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return;
    $f = smpro_im_blocked_file(); @is_dir(dirname($f)) || @mkdir(dirname($f), 0700, true);
    $fp = @fopen($f, 'c+'); if (!$fp) return;
    if (@flock($fp, LOCK_EX)) {
        $d = json_decode((string)stream_get_contents($fp), true); if (!is_array($d)) $d = [];
        $d[$ip] = ['ts' => time(), 'via' => (string)$via, 'note' => mb_substr((string)$note, 0, 120)];
        if (count($d) > 6000) $d = array_slice($d, -5000, 5000, true);
        smpro_im_blocked_write($f, $d); @flock($fp, LOCK_UN);
    }
    @fclose($fp); @chmod($f, 0600);
}
/** The block book is replaced atomically: a kill between truncate and write used to leave "nothing blocked". */
function smpro_im_blocked_write(string $f, array $d): void {
    $tmp = $f . '.' . getmypid() . '.tmp';
    if (@file_put_contents($tmp, json_encode($d, JSON_UNESCAPED_SLASHES), LOCK_EX) !== false) { @chmod($tmp, 0600); if (!@rename($tmp, $f)) @unlink($tmp); } else @unlink($tmp);
}
function smpro_im_blocked_forget($ip) {
    $f = smpro_im_blocked_file(); $fp = @fopen($f, 'c+'); if (!$fp) return;
    if (@flock($fp, LOCK_EX)) { $d = json_decode((string)stream_get_contents($fp), true); if (is_array($d) && isset($d[$ip])) { unset($d[$ip]); smpro_im_blocked_write($f, $d); if (false) @fwrite($fp, json_encode($d, JSON_UNESCAPED_SLASHES)); @fflush($fp); } @flock($fp, LOCK_UN); }
    @fclose($fp);
}
/** Every IP currently considered blocked: the CSF deny list UNION the IPs SM Pro recorded as blocked (incl. Cloudflare). */
function smpro_im_blocked_set() {
    $set = function_exists('smpro_im_csf_blocked') ? smpro_im_csf_blocked() : [];
    foreach (smpro_im_blocked_load() as $ip => $m) $set[$ip] = true;
    return $set;
}

/* ============================ campaigns / attacker intel ============================ */
function smpro_im_campaigns($events) {
    $byIp = []; $byDom = [];
    foreach ($events as $e) {
        if ($e['ip'] === '') continue;
        $byIp[$e['ip']]['domains'][$e['domain']] = 1; $byIp[$e['ip']]['n'] = ($byIp[$e['ip']]['n'] ?? 0) + 1;
        if ($e['domain'] !== '') $byDom[$e['domain']]['ips'][$e['ip']] = 1;
    }
    $thrIp = (int)smpro_in_cfg()['thr_ip_domains'];
    $distributed = [];
    foreach ($byIp as $ip => $d) { $nd = count($d['domains']); if ($nd >= $thrIp) $distributed[] = ['ip'=>$ip,'domains'=>$nd,'hits'=>$d['n']]; }
    usort($distributed, fn($a, $b) => $b['domains'] <=> $a['domains']);
    $targeted = [];
    foreach ($byDom as $dom => $d) { $ni = count($d['ips']); if ($ni >= 5) $targeted[] = ['domain'=>$dom,'ips'=>$ni]; }
    usort($targeted, fn($a, $b) => $b['ips'] <=> $a['ips']);
    return ['distributed'=>$distributed, 'targeted'=>$targeted];
}
/** Optional AbuseIPDB reputation (0-100), cached best-effort. '' when no key. */
function smpro_im_abuse_score($ip) {
    $c = smpro_in_cfg(); if ($c['abuseipdb_key'] === '' || !filter_var($ip, FILTER_VALIDATE_IP)) return '';
    $url = 'https://api.abuseipdb.com/api/v2/check?' . http_build_query(['ipAddress' => $ip]);
    $res = smpro_http($url, ['timeout' => 8, 'headers' => ['Key: ' . $c['abuseipdb_key'], 'Accept: application/json']]);   // key stays in-process, not in argv
    $j = json_decode($res['body'], true);
    return isset($j['data']['abuseConfidenceScore']) ? (int)$j['data']['abuseConfidenceScore'] : '';
}

/* ============================ breach correlation ============================ */
/**
 * Likely-compromise detection: a domain that received an EXPLOIT-class attack which the
 * server answered with 2xx/3xx AND has PHP files changed very recently in its docroot.
 * Bounded (only domains with a suspicious 200, capped, throttled find).
 */
/** Does a PHP file contain web-shell / obfuscation indicators? (bounded grep, single file) */
function smpro_im_looks_malicious($file) {
    $re = 'eval[[:space:]]*\(|assert[[:space:]]*\(|create_function|gzinflate|gzuncompress|str_rot13|\bshell_exec|\bpassthru|\bproc_open|\bpopen[[:space:]]*\(|\bsystem[[:space:]]*\(|preg_replace[[:space:]]*\([^,]*/e|\$_(POST|GET|REQUEST|COOKIE|SERVER)[[:space:]]*\[[^]]*\][[:space:]]*\(|base64_decode[[:space:]]*\([^)]*\$|move_uploaded_file';
    $cmd = 'timeout 6 grep -lEa ' . escapeshellarg($re) . ' ' . escapeshellarg($file) . ' 2>/dev/null';
    return trim((string)@shell_exec($cmd)) !== '';
}
/** Always-on built-in exclusions: legit security/login plugins routinely contain the SAME dangerous-function
 *  NAMES (eval(, shell_exec(, base64_decode(...) as quoted strings in their own scanners - so a naive regex
 *  false-flags them as web-shells. These are unioned with the admin's breach_exclude so they apply even to
 *  already-saved configs (shipping the build fixes existing installs without the admin editing anything).
 *
 *  EVERY entry here must be a WIDELY-DISTRIBUTED third-party security plugin. A site-specific or single-customer
 *  name must never be seeded: this list ships to every licensed server, so the name becomes a scan-evasion
 *  primitive everywhere - an attacker only has to put the string in a path for the file to skip the breach scan
 *  entirely. Our own WP plugin is deliberately NOT here; it is trusted by verified header via
 *  smpro_wpguard_trusted(), which a name cannot forge. Per-server needs belong in the admin's own
 *  breach_exclude (Intrusion Monitor › "Breach scan - ignore paths"), not in the shipped seed. */
function smpro_im_breach_exclude_seed() {
    return ['imunify-security', 'wordfence', '/wp-content/cache/', '/wp-content/upgrade/', '/wp-content/uploads/cache/',
            '/mu-plugins/', 'ithemes-security', 'better-wp-security', 'sucuri', 'wp-security', 'all-in-one-wp-security', 'ninjafirewall'];
}
/** Is a path excluded from breach scanning (legit, frequently-updated security/cache dirs + known plugins)? */
function smpro_im_breach_excluded($path) {
    // WP Guard (HostGuard's WP security plugin): trust its OWN verified files + quarantine dir + log + .htaccess
    // lockdown - never quarantine what our own product legitimately wrote. Header-verified, not name-only.
    if (function_exists('smpro_wpguard_trusted') && smpro_wpguard_trusted($path)) return true;
    foreach (array_merge(smpro_im_breach_exclude_seed(), (array)(smpro_in_cfg()['breach_exclude'] ?? [])) as $sub) {
        $sub = trim((string)$sub); if ($sub !== '' && stripos($path, $sub) !== false) return true;
    }
    // Whitelist Manager (Forensics) edits reach the detector immediately: a path/glob whitelist entry
    // excludes the file from the breach scan just like a legacy breach_exclude substring.
    if (function_exists('smpro_fe_wl_match')) { $m = smpro_fe_wl_match(smpro_im_account_for_path($path), $path, null, null); if ($m && in_array($m['mode'], ['downgrade', 'silent'], true)) return true; }
    return false;
}
/** cpanel account owning a /home/<user>/... path (cheap, for whitelist account-scoping in the detector). */
function smpro_im_account_for_path($path) { return preg_match('#^/home/([^/]+)/#', (string)$path, $m) ? $m[1] : ''; }
/** Should this candidate be SUPPRESSED from the breach alert / auto-quarantine because the operator
 *  whitelisted it in Forensics? silent = exact-hash; downgrade = path/glob, suppressed UNLESS a NEW
 *  obfuscation/exec family appeared vs the whitelisted fingerprint; rearm = never suppress. Bounded hash. */
function smpro_im_wl_suppress($account, $file) {
    if (!function_exists('smpro_fe_wl_match')) return false;
    $sha  = (is_file($file) && @filesize($file) <= 5 * 1024 * 1024) ? @hash_file('sha256', $file) : null;
    $size = is_file($file) ? (int)@filesize($file) : null;
    $m = smpro_fe_wl_match((string)$account, $file, $sha, $size);
    if (!$m) return false;
    if ($m['mode'] === 'silent') return true;
    if ($m['mode'] === 'downgrade') return !(function_exists('smpro_fe_wl_added_obfuscation') && smpro_fe_wl_added_obfuscation($file, (string)$account));
    return false;   // 'rearm' (e.g. 10x size jump) -> do NOT suppress
}
/** A file carrying a real WordPress plugin header is an admin-installed plugin, not a drive-by web-shell - never
 *  auto-quarantine it (it still gets reported). Real shells don't ship a "Plugin Name:" header; this stops the
 *  whole class of false-positives where a security plugin names dangerous functions in its own signature list. */
function smpro_im_is_wp_plugin($file) {
    $head = (string)@file_get_contents($file, false, null, 0, 8192);
    return $head !== '' && preg_match('/^[ \t\/*#@]*Plugin Name:\s*\S/mi', $head) === 1;
}
/** Count how many INDEPENDENT web-shell indicator families a file trips. A real shell almost always combines several
 *  (e.g. eval(gzinflate(base64_decode(...))) = exec+obfusc); a lone benign match (a stray move_uploaded_file) trips
 *  one. Used to gate UNATTENDED auto-removal behind ≥2 families so a single weak signal never pulls a file by cron. */
function smpro_im_malice_count($file) {
    $fams = [
        'exec'   => 'eval[[:space:]]*\(|assert[[:space:]]*\(|create_function|\bshell_exec|\bpassthru|\bproc_open|\bpopen[[:space:]]*\(|\bsystem[[:space:]]*\(|preg_replace[[:space:]]*\([^,]*/e',
        'obfusc' => 'gzinflate|gzuncompress|str_rot13|base64_decode[[:space:]]*\([^)]*\$',
        'input'  => '\$_(POST|GET|REQUEST|COOKIE|SERVER)[[:space:]]*\[[^]]*\][[:space:]]*\(',
        'upload' => 'move_uploaded_file',
    ];
    $n = 0;
    foreach ($fams as $re) {
        if (trim((string)@shell_exec('timeout 4 grep -lEa ' . escapeshellarg($re) . ' ' . escapeshellarg($file) . ' 2>/dev/null')) !== '') $n++;
    }
    return $n;
}
/**
 * Likely-compromise detection: a domain that received an EXPLOIT-class attack served 2xx/3xx
 * AND has a recently-changed PHP file in its docroot that ALSO contains web-shell indicators.
 * Legit auto-updating paths (Imunify WP plugin, caches) are excluded - so Imunify's own
 * rules.php no longer false-flags. Bounded + throttled.
 */
function smpro_im_breaches($events, $changedWithinMin = 60, $maxDomains = 25) {
    $suspect = [];
    foreach ($events as $e) {
        if ($e['domain'] === '' || !smpro_im_exploit_kind($e['kind'])) continue;
        if (smpro_im_served($e)) {
            $suspect[$e['domain']]['kind'][$e['kind']] = 1;
            $suspect[$e['domain']]['ips'][$e['ip']] = 1;
            $suspect[$e['domain']]['last'] = max($suspect[$e['domain']]['last'] ?? 0, (int)$e['ts']);
        }
    }
    $out = []; $scanned = 0;
    foreach ($suspect as $dom => $s) {
        if ($scanned++ >= $maxDomains) break;
        $acct = smpro_im_account_for($dom); if ($acct === '') continue;
        $bad = [];
        foreach (smpro_im_docroots($acct) as $root) {
            $cmd = 'timeout 14 nice -n ' . SMPRO_SCAN_NICE . ' ionice -c3 find ' . escapeshellarg($root)
                 . ' -maxdepth 6 -type f \\( -name "*.php" -o -name "*.phtml" \\) -mmin -' . (int)$changedWithinMin . ' 2>/dev/null | head -n 60';
            foreach (array_filter(explode("\n", (string)@shell_exec($cmd))) as $f) {
                if (smpro_im_breach_excluded($f)) continue;          // skip Imunify WP plugin, caches, etc.
                if (smpro_im_is_wp_plugin($f)) continue;             // admin-installed plugin (Plugin Name header) -> not a drive-by shell
                if (smpro_im_wl_suppress($acct, $f)) continue;       // operator-whitelisted (Forensics) legit large single-file app -> don't re-alert, unless a NEW obfuscation family appeared
                if (smpro_im_looks_malicious($f)) $bad[] = $f;        // only count files that look like a web-shell
                if (count($bad) >= 12) break;
            }
            if (count($bad) >= 12) break;
        }
        // confirmed compromise only when a recently-changed file actually looks malicious
        if ($bad) $out[] = ['domain'=>$dom,'account'=>$acct,'kinds'=>array_keys($s['kind']),'ips'=>array_keys($s['ips']),'last'=>$s['last'] ?? 0,'changed'=>array_slice($bad, 0, 12)];
    }
    return $out;
}

/* ============================ full attack analysis report ============================ */
function smpro_im_path_of($uri) { $p = (string)parse_url((string)$uri, PHP_URL_PATH); return $p !== '' ? $p : (string)$uri; }
function smpro_im_subnet24($ip) { return preg_match('/^(\d+\.\d+\.\d+)\.\d+$/', (string)$ip, $m) ? $m[1] . '.0/24' : ''; }
/**
 * Comprehensive attack analysis from a set of events: most-targeted PATHS, top source IPs
 * (with their main target + distinct User-Agent count), COORDINATED campaigns (IPs sharing a
 * /24 subnet = likely botnet), UA-ROTATION (one IP cycling many User-Agents to dodge blocks),
 * and attack PHASES (remote-exploit -> brute-force -> spam).
 */
function smpro_im_attack_analysis($events) {
    $paths = []; $ips = []; $subnets = [];
    $phases = ['Remote exploit (xmlrpc/RPC)'=>0,'Brute force (login)'=>0,'Exploit (SQLi/RCE/LFI)'=>0,'Sensitive-file probing'=>0,'Scanner / recon'=>0,'Spam / content (POST 2xx)'=>0,'Other WAF blocks'=>0];
    foreach ($events as $e) {
        $path = smpro_im_path_of($e['uri'] ?? ''); $ip = (string)($e['ip'] ?? ''); $kind = (string)($e['kind'] ?? '');
        if ($path !== '') { if (!isset($paths[$path])) $paths[$path] = ['path'=>$path,'n'=>0,'ips'=>[]]; $paths[$path]['n']++; if ($ip !== '') $paths[$path]['ips'][$ip] = 1; }
        if ($ip !== '') {
            if (!isset($ips[$ip])) $ips[$ip] = ['ip'=>$ip,'n'=>0,'paths'=>[],'uas'=>[]];
            $ips[$ip]['n']++; if ($path !== '') $ips[$ip]['paths'][$path] = ($ips[$ip]['paths'][$path] ?? 0) + 1;
            if (!empty($e['ua'])) $ips[$ip]['uas'][$e['ua']] = 1;
            $sn = smpro_im_subnet24($ip); if ($sn !== '') { if (!isset($subnets[$sn])) $subnets[$sn] = ['subnet'=>$sn,'ips'=>[],'n'=>0]; $subnets[$sn]['ips'][$ip] = 1; $subnets[$sn]['n']++; }
        }
        $pl = strtolower($path . ' ' . $kind);
        if (strpos($pl,'xmlrpc') !== false || strpos($pl,'/rpc') !== false || strpos($pl,'jsonrpc') !== false) $phases['Remote exploit (xmlrpc/RPC)']++;
        elseif (strpos($pl,'wp-login') !== false || strpos($pl,'/login') !== false || strpos($pl,'wp-admin') !== false || strpos($kind,'Brute') !== false) $phases['Brute force (login)']++;
        elseif (smpro_im_exploit_kind($kind)) $phases['Exploit (SQLi/RCE/LFI)']++;
        elseif (strpos($kind,'Sensitive') !== false || strpos($pl,'.env') !== false || strpos($pl,'.git') !== false) $phases['Sensitive-file probing']++;
        elseif (strpos($kind,'Scanner') !== false) $phases['Scanner / recon']++;
        elseif (($e['method'] ?? '') === 'POST' && (int)($e['code'] ?? 0) >= 200 && (int)($e['code'] ?? 0) < 300) $phases['Spam / content (POST 2xx)']++;
        else $phases['Other WAF blocks']++;
    }
    foreach ($paths as &$p) { $p['uniq_ips'] = count($p['ips']); unset($p['ips']); } unset($p);
    foreach ($ips as &$x) { arsort($x['paths']); $x['top_path'] = $x['paths'] ? array_key_first($x['paths']) : ''; $x['ua_count'] = count($x['uas']); unset($x['uas']); } unset($x);
    foreach ($subnets as &$s) { $s['uniq_ips'] = count($s['ips']); unset($s['ips']); } unset($s);
    uasort($paths, fn($a,$b)=>$b['n']<=>$a['n']);
    uasort($ips, fn($a,$b)=>$b['n']<=>$a['n']);
    $camp = array_values(array_filter($subnets, fn($s)=>$s['uniq_ips']>=3)); usort($camp, fn($a,$b)=>$b['uniq_ips']<=>$a['uniq_ips']);
    $rot = array_values(array_filter($ips, fn($x)=>$x['ua_count']>=4)); usort($rot, fn($a,$b)=>$b['ua_count']<=>$a['ua_count']);
    return ['total'=>count($events),'paths'=>array_slice(array_values($paths),0,40),'attackers'=>array_slice(array_values($ips),0,80),
            'campaigns'=>array_slice($camp,0,40),'rotators'=>array_slice($rot,0,25),'phases'=>array_filter($phases)];
}

/* ============================ attacker intel + AI block decision ============================ */
/** Rank attacker IPs from a set of events, enriched with geo/provider/bot for display + decisions. */
function smpro_im_offenders($events, $limit = 25) {
    $o = [];
    foreach ($events as $e) {
        if (($e['ip'] ?? '') === '') continue;
        $ip = $e['ip'];
        if (!isset($o[$ip])) $o[$ip] = ['ip'=>$ip,'hits'=>0,'domains'=>[],'cats'=>[],'sev'=>0,'last'=>0];
        $o[$ip]['hits']++;
        if (($e['domain'] ?? '') !== '') $o[$ip]['domains'][$e['domain']] = 1;
        $o[$ip]['cats'][$e['kind']] = ($o[$ip]['cats'][$e['kind']] ?? 0) + 1;
        $r = smpro_im_sev_rank($e['severity'] ?? ''); if ($r > $o[$ip]['sev']) $o[$ip]['sev'] = $r;
        if (($e['ts'] ?? 0) > $o[$ip]['last']) $o[$ip]['last'] = (int)$e['ts'];
    }
    uasort($o, fn($a, $b) => $b['hits'] <=> $a['hits']);
    $res = [];
    foreach (array_slice($o, 0, $limit, true) as $ip => $d) {
        $in = function_exists('smpro_ip_intel') ? smpro_ip_intel($ip, false) : [];
        $res[] = ['ip'=>$ip,'hits'=>$d['hits'],'domains'=>count($d['domains']),'cats'=>array_keys($d['cats']),
                  'country'=>strtoupper((string)($in['country'] ?? '')),'provider'=>(string)($in['provider'] ?? ''),
                  'asn'=>(string)($in['asn'] ?? ''),'bot'=>(function_exists('smpro_ip_is_datacenter') && smpro_ip_is_datacenter($in)) ? 1 : 0,'last'=>$d['last']];
    }
    return $res;
}
/** Ask the configured AI to decide which attacker IPs to block (applies SOC conditions). */
function smpro_im_ai_block_decide($offenders) {
    if (!function_exists('smpro_ai_available') || !smpro_ai_available()) return ['ok'=>false,'block'=>[],'keep'=>[],'reason'=>'No AI provider configured.'];
    if (!$offenders) return ['ok'=>true,'block'=>[],'keep'=>[],'reason'=>'No attackers to evaluate.'];
    $lines = [];
    foreach ($offenders as $o) $lines[] = $o['ip'] . ' | hits=' . $o['hits'] . ' domains=' . $o['domains'] . ' types=' . implode(',', $o['cats']) . ' geo=' . ($o['country'] ?: '?') . '/' . ($o['provider'] ?: '?') . ($o['bot'] ? ' [datacenter]' : '');
    $sys = "You are a SOC analyst protecting a cPanel/WHM shared-hosting server's WAF. Decide which attacker IPs to BLOCK in the firewall. BLOCK clear web attacks: SQL injection, RCE/command injection, LFI/path traversal, sensitive-file/.env probing, malicious uploads, and high-volume scanners hitting many domains (especially datacenter networks). KEEP (do not block) likely-legitimate traffic: genuine search-engine crawlers from their real ASNs (Google/Bing/etc.), single low-count hits that may be false positives, and known monitoring/uptime services."
         . " HOME-REGION POLICY (critical): the operator's customers are mostly in " . smpro_im_home_regions_label() . ". For a RESIDENTIAL (non-datacenter) IP geolocated in " . smpro_im_home_regions_short() . ", DO NOT block — instead put it in \"review\" for manual approval, even if it looks suspicious (it is most likely a compromised legitimate customer device, not an attacker to firewall). For RESIDENTIAL IPs in other Arab countries, block ONLY when the attack is clear and repeated (multiple distinct attack types or high hit counts); otherwise put them in \"review\". DATACENTER/hosting IPs from ANY country (including the home regions) follow the normal attack rules above — block them when they attack. Each line is tagged with geo=COUNTRY/provider and [datacenter] when it is a hosting network."
         . " Be decisive but conservative about collateral damage. Respond with ONLY strict JSON, no prose: {\"block\":[\"ip\",...],\"keep\":[\"ip\",...],\"review\":[\"ip\",...],\"reason\":\"one short paragraph\"}";
    $user = "Attacker IPs observed on the WAF (decide which to block):\n" . implode("\n", $lines);
    $r = function_exists('smpro_ai_chat_json')
        ? smpro_ai_chat_json($sys, $user, ['max_tokens'=>800,'context'=>'intrusion_block'])
        : smpro_ai_chat($sys, $user, ['max_tokens'=>800,'context'=>'intrusion_block']);
    if (empty($r['ok'])) return ['ok'=>false,'block'=>[],'keep'=>[],'reason'=>$r['error'] ?? 'AI request failed'];
    $j = $r['data'] ?? (function_exists('smpro_ai_json') ? smpro_ai_json((string)($r['text'] ?? '')) : null);
    if (!is_array($j)) return ['ok'=>false,'block'=>[],'keep'=>[],'reason'=>'The AI was busy or replied without a clear decision — try again.','raw'=>$r['text'] ?? ''];
    $block = array_values(array_filter(array_map('trim', (array)($j['block'] ?? [])), fn($ip) => filter_var($ip, FILTER_VALIDATE_IP)));
    $review = array_values(array_filter(array_map('trim', (array)($j['review'] ?? [])), fn($ip) => filter_var($ip, FILTER_VALIDATE_IP)));
    // Safety net: enforce home-region policy in code regardless of what the model returned.
    $hitsOf = []; foreach ($offenders as $o) $hitsOf[$o['ip']] = ['hits'=>(int)$o['hits'],'cats'=>count((array)($o['cats'] ?? []))];
    $keepBlock = [];
    foreach ($block as $ip) {
        $rs = smpro_im_region_status($ip);
        if ($rs === 'core_protected') { $review[] = $ip; continue; }          // home-region residential -> manual review, never auto-block
        if ($rs === 'arab_caution') {
            $h = $hitsOf[$ip] ?? ['hits'=>0,'cats'=>0];
            if ($h['hits'] < 5 && $h['cats'] < 2) { $review[] = $ip; continue; } // not clear & repeated -> review
        }
        $keepBlock[] = $ip;
    }
    $block = array_values(array_unique($keepBlock));
    $review = array_values(array_unique($review));
    // sanitize 'keep' the same way as block/review - never echo back un-validated model output as IPs
    $keep = array_values(array_filter(array_map('trim', (array)($j['keep'] ?? [])), fn($ip) => filter_var($ip, FILTER_VALIDATE_IP)));
    return ['ok'=>true,'block'=>$block,'keep'=>$keep,'review'=>$review,'reason'=>(string)($j['reason'] ?? ''),'provider'=>$r['provider'] ?? ''];
}
/**
 * Does an event count as a genuine attack FROM the server itself / a local process?
 * ANY internal source (loopback ::1/127.0.0.1, private LAN, or the server's own public IP)
 * legitimately makes internal HTTP (wp-cron, cache warmers, health checks, cPanel internals,
 * monitoring) that trips GENERIC WAF rules - those are NOT attacks. A local COMPROMISE shows up
 * as real exploit-class traffic, so:
 *   - flag ONLY real exploit-class kinds (SQLi/RCE/RFI/LFI/PHP-inj/upload), for every internal source;
 *   - never flag wp-cron or generic "WAF Block (other)" noise (e.g. a single ::1 hit).
 */
function smpro_im_is_self_attack($ip, $kind, $uri) {
    if ($ip === '') return false;
    $isServer  = function_exists('smpro_is_server_ip') && smpro_is_server_ip($ip);
    $isPrivate = function_exists('smpro_ip_is_external') && !smpro_ip_is_external($ip);
    if (!$isServer && !$isPrivate) return false;                       // not self / local at all
    if (stripos((string)$uri, 'wp-cron.php') !== false) return false;  // WordPress scheduler = benign
    // Security plugins probe their OWN site from the box to prove a defence works, and the probe looks exactly
    // like the attack it defends against. Really Simple SSL requests /wp-content/uploads/code-execution.php to
    // confirm the uploads folder CANNOT run PHP (it wants that request to fail), and fetches its own
    // ssl-test-page.php. From the server's own IP these are self-tests, not an upload attack - the filename is
    // what trips the Malicious-Upload heuristic. This is scoped to the server's OWN public IP: the identical
    // request from an EXTERNAL address still flags, so a real attacker dropping that file is not whitelisted.
    if ($isServer) {
        $u = strtolower((string)$uri);
        foreach (['/uploads/code-execution.php', 'really-simple-ssl/ssl-test-page.php', 'really-simple-ssl/security/test'] as $probe)
            if (strpos($u, $probe) !== false) return false;
    }
    if (!smpro_im_exploit_kind((string)$kind)) return false;           // internal sources: real exploits only (no generic WAF noise)
    return true;
}
/** Recent GENUINE attacks whose source is the server's own/local IP (possible local compromise). */
function smpro_im_selfattack_recent($hours = 6, $limit = 40) {
    $db = smpro_in_db(); if (!$db) return [];
    $st = $db->prepare('SELECT ip, domain, kind, uri, ts FROM attacks WHERE ts >= ? ORDER BY ts DESC LIMIT 1200');
    $st->execute([time() - (int)$hours * 3600]);
    $out = [];
    foreach (($st->fetchAll(PDO::FETCH_ASSOC) ?: []) as $r) {
        $ip = (string)$r['ip'];
        if (!smpro_im_is_self_attack($ip, (string)$r['kind'], (string)$r['uri'])) continue;
        if (!isset($out[$ip])) $out[$ip] = ['ip'=>$ip,'n'=>0,'domains'=>[],'kind'=>$r['kind'],'last'=>0];
        $out[$ip]['n']++; $out[$ip]['domains'][$r['domain']] = 1; $out[$ip]['last'] = max($out[$ip]['last'], (int)$r['ts']);
        if (count($out) >= $limit) break;
    }
    foreach ($out as &$o) $o['domains'] = count($o['domains']); unset($o);
    return array_values($out);
}

/**
 * CONNECTION SOURCES - answer "which process is doing this?" for a local-source attack.
 *
 * A self-attack means something ON this box generates the traffic, so the useful question is not
 * "which IP" (it is our own) but WHICH PROCESS and WHICH ACCOUNT. This resolves live TCP sockets
 * involving that IP down to pid -> binary -> owning user -> cPanel account, so the alert can name the
 * culprit instead of telling the admin to go hunting.
 *
 * Read-only (`ss`/netstat + /proc) and called ON DEMAND from the JSON endpoint - never on a page
 * render, because the self-attack bar is drawn on every page.
 */
function smpro_im_conn_sources($ip = '', $limit = 60) {
    $bin = '';
    foreach (['/usr/sbin/ss', '/usr/bin/ss', 'ss'] as $b) { if ($b === 'ss' || @is_executable($b)) { $bin = $b; break; } }
    $raw = $bin !== '' ? (string)@shell_exec('timeout 8 ' . escapeshellarg($bin) . ' -tanpH 2>/dev/null') : '';
    $mode = 'ss';
    if (trim($raw) === '') { $raw = (string)@shell_exec('timeout 8 netstat -tanp 2>/dev/null'); $mode = 'netstat'; }
    if (trim($raw) === '') return ['ok' => false, 'msg' => 'Neither ss nor netstat is available, so live sockets cannot be read.', 'rows' => []];

    $ipq = trim((string)$ip);
    $hostOf = function ($a) {
        if (preg_match('/^\[(.+)\]:(\d+)$/', $a, $x)) return [$x[1], (int)$x[2]];
        $p = strrpos($a, ':'); return $p === false ? [$a, 0] : [substr($a, 0, $p), (int)substr($a, $p + 1)];
    };
    $rows = []; $seen = [];
    foreach (explode("\n", $raw) as $line) {
        $line = trim($line); if ($line === '') continue;
        $state = ''; $local = ''; $peer = ''; $procs = '';
        if ($mode === 'ss') {
            if (!preg_match('/^(\S+)\s+\d+\s+\d+\s+(\S+)\s+(\S+)(?:\s+(.*))?$/', $line, $m)) continue;
            $state = $m[1]; $local = $m[2]; $peer = $m[3]; $procs = (string)($m[4] ?? '');
        } else {
            if (stripos($line, 'tcp') !== 0) continue;
            if (!preg_match('#^tcp\S*\s+\d+\s+\d+\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(\S+))?#', $line, $m)) continue;
            $local = $m[1]; $peer = $m[2]; $state = $m[3]; $procs = (string)($m[4] ?? '');
        }
        list($lh, $lp) = $hostOf($local); list($ph, $pp) = $hostOf($peer);
        if ($ipq !== '' && $lh !== $ipq && $ph !== $ipq) continue;   // only sockets involving the flagged IP
        if (strcasecmp($state, 'LISTEN') === 0) continue;            // a listener is not a connection

        $pids = [];
        if (preg_match_all('/pid=(\d+)/', $procs, $pm)) $pids = $pm[1];
        elseif (preg_match('#(\d+)/#', $procs, $pm))    $pids = [$pm[1]];
        if (!$pids) $pids = [0];

        foreach ($pids as $pid) {
            $pid = (int)$pid;
            $k = $pid . '|' . $local . '|' . $peer; if (isset($seen[$k])) continue; $seen[$k] = 1;
            $comm = ''; $user = ''; $cmd = '';
            if ($pid > 0 && @is_dir('/proc/' . $pid)) {
                $comm = trim((string)@file_get_contents('/proc/' . $pid . '/comm'));
                $cmd  = trim(str_replace("\0", ' ', (string)@file_get_contents('/proc/' . $pid . '/cmdline')));
                if (function_exists('smpro_redact_cmd')) $cmd = smpro_redact_cmd($cmd);
                $stt = @stat('/proc/' . $pid); $uid = (int)($stt['uid'] ?? -1);
                if ($uid >= 0 && function_exists('posix_getpwuid')) { $pw = @posix_getpwuid($uid); $user = $pw['name'] ?? (string)$uid; }
            }
            if ($comm === '' && $procs !== '' && preg_match('/"([^"]+)"/', $procs, $nm)) $comm = $nm[1];
            $rows[] = ['state' => $state, 'local' => $lh . ':' . $lp, 'peer' => $ph . ':' . $pp,
                'pid' => $pid, 'process' => $comm !== '' ? $comm : '(unknown)', 'user' => $user,
                'is_cpanel' => ($user !== '' && function_exists('smpro_is_cpanel_user')) ? (bool)smpro_is_cpanel_user($user) : false,
                'cmd' => function_exists('mb_substr') ? mb_substr($cmd, 0, 200) : substr($cmd, 0, 200)];
            if (count($rows) >= $limit) break 2;
        }
    }
    // Owner tally counts only sockets that still HAVE an owning process - a TIME-WAIT socket has
    // already been closed by its process, so it names nobody and must not dominate the summary.
    $byUser = [];
    foreach ($rows as $r) { if ($r['pid'] > 0 && $r['user'] !== '') $byUser[$r['user']] = ($byUser[$r['user']] ?? 0) + 1; }
    arsort($byUser);
    // Actionable rows first: a resolved process beats an orphaned socket; then busiest owner; then cPanel accounts.
    usort($rows, function ($a, $b) use ($byUser) {
        $ra = ($a['pid'] > 0 ? 1 : 0); $rb = ($b['pid'] > 0 ? 1 : 0);
        if ($ra !== $rb) return $rb <=> $ra;
        if ($a['is_cpanel'] !== $b['is_cpanel']) return ($b['is_cpanel'] ? 1 : 0) <=> ($a['is_cpanel'] ? 1 : 0);
        return ($byUser[$b['user']] ?? 0) <=> ($byUser[$a['user']] ?? 0);
    });
    $orphan = 0; foreach ($rows as $r) if ($r['pid'] < 1) $orphan++;
    return ['ok' => true, 'rows' => $rows, 'by_user' => $byUser, 'orphan' => $orphan, 'ip' => $ipq, 'tool' => $mode];
}

/* ============================ EMERGENCY auto-response (harden + clean) ============================ */
function smpro_im_em_manifest_load() { $d = is_file(SMPRO_IM_EMLOG) ? json_decode((string)@file_get_contents(SMPRO_IM_EMLOG), true) : null; return is_array($d) ? $d : []; }
function smpro_im_em_manifest_save($m) { @is_dir(dirname(SMPRO_IM_EMLOG)) || @mkdir(dirname(SMPRO_IM_EMLOG), 0700, true); $t = SMPRO_IM_EMLOG . '.tmp'; @file_put_contents($t, json_encode(array_slice($m, -5000), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), LOCK_EX); @chmod($t, 0600); @rename($t, SMPRO_IM_EMLOG); }
function smpro_im_has_chattr() { return function_exists('smpro_has_bin') ? smpro_has_bin('chattr') : is_executable('/usr/bin/chattr'); }
/** The exact hardening block prepended to upload-dir .htaccess. Shared so undo can strip PRECISELY what it added. */
function smpro_im_harden_rule() {
    return "# smpro Emergency hardening — block script execution (added by Intrusion Monitor)\n"
         . "<FilesMatch \"\\.(?:php|phtml|php[0-9]|phps|pht|pl|py|cgi|asp|aspx|sh)$\">\n  Require all denied\n  SetHandler none\n</FilesMatch>\n"
         . "<IfModule mod_php.c>\nphp_flag engine off\n</IfModule>\n<IfModule mod_php7.c>\nphp_flag engine off\n</IfModule>\n<IfModule mod_php8.c>\nphp_flag engine off\n</IfModule>\nOptions -ExecCGI\n";   // bare php_flag is "Invalid command" (HTTP 500 for every image) on FPM/suPHP/CGI servers
}

/**
 * Symlink-safe .htaccess write for an account-owned dir (root context). The account controls its /home dir,
 * so copy()/file_put_contents()/chown() on <dir>/.htaccess follows a symlink they plant (-> overwrite/chown a
 * root file = privesc). Confine to /home, reject a symlinked leaf, back up with O_EXCL, and write via an
 * O_EXCL temp + atomic rename so the root write/chown can never land outside the account. Returns [ok, bak].
 */
function smpro_im_ht_write($ht, $content) {
    $parent = function_exists('smpro_path_safe') ? smpro_path_safe(dirname($ht), ['/home'])
            : ((!is_link(dirname($ht)) && ($rp = @realpath(dirname($ht))) !== false && strpos($rp, '/home/') === 0) ? $rp : '');
    $base = basename($ht);
    if ($parent === '' || $base === '' || strpbrk($base, "/\0") !== false) return [false, ''];
    $ht = $parent . '/' . $base;
    if (is_link($ht)) return [false, ''];
    $uid = @fileowner($parent); $gid = @filegroup($parent);          // own as the cPanel account, matching the dir
    $rnd = substr(bin2hex(@random_bytes(4) ?: pack('N', mt_rand())), 0, 8);
    $bak = '';
    if (is_file($ht)) {
        $bak = $ht . '.smprobak-' . $rnd; $cur = @file_get_contents($ht);
        $bfh = ($cur !== false) ? @fopen($bak, 'xb') : false;        // O_EXCL: a planted symlink at the backup path fails
        if ($bfh !== false) { @fwrite($bfh, $cur); @fclose($bfh); if ($uid !== false) { @chown($bak, $uid); @chgrp($bak, $gid); } }
    }
    $tmp = $ht . '.smprotmp-' . $rnd; $tfh = @fopen($tmp, 'xb');
    $ok = $tfh !== false && @fwrite($tfh, $content) !== false; if ($tfh) @fclose($tfh);
    if ($ok) { @chmod($tmp, 0644); if ($uid !== false) { @chown($tmp, $uid); @chgrp($tmp, $gid); } $ok = @rename($tmp, $ht); }
    if (!$ok) @unlink($tmp);
    return [$ok, $bak];
}

/** Disable script execution in shell-upload-prone dirs + lock core files. Reversible; backs up. */
function smpro_im_harden_site($account, $dryrun = false) {
    $actions = []; $chattr = smpro_im_has_chattr();
    $rule = smpro_im_harden_rule();
    foreach (smpro_im_docroots($account) as $root) {
        foreach (['wp-content/uploads', 'wp-content/cache', 'wp-content/upgrade', 'wp-includes/uploads', 'uploads', 'images', 'img', 'media', 'files', 'cache', 'tmp', 'temp'] as $sub) {
            $d = $root . '/' . $sub; if (!is_dir($d) || is_link($d)) continue;
            $ht = $d . '/.htaccess';
            if (is_link($ht)) continue;                                              // never operate on a symlinked .htaccess (privesc)
            $cur = is_file($ht) ? (string)@file_get_contents($ht) : '';
            if (strpos($cur, 'smpro Emergency hardening') !== false) continue;        // already hardened
            if (!$dryrun) {
                [$w, $bakPath] = smpro_im_ht_write($ht, $rule . $cur);                // symlink-safe: confine + O_EXCL temp + atomic rename
                if ($w && $chattr) @shell_exec('chattr +i ' . escapeshellarg($ht) . ' 2>/dev/null'); // immutable: a compromised account can't strip it
            }
            $actions[] = ['type' => 'php_off', 'path' => $ht, 'had' => $cur !== '', 'bak' => (!$dryrun && !empty($bakPath)) ? $bakPath : ''];   // the undo needs the exact backup name
        }
        $isWp = is_file($root . '/wp-load.php');
        $core = $isWp ? ['wp-config.php', '.htaccess', 'index.php', 'wp-load.php', 'wp-settings.php', 'wp-blog-header.php', 'wp-config-sample.php']
                      : ['index.php', '.htaccess', 'config.php', 'configuration.php', 'wp-config.php'];
        foreach ($core as $cf) {
            $f = $root . '/' . $cf;
            // The docroot is the account's: wp-config.php could be a symlink to /etc/shadow, and chmod/chattr follow
            // links. Only a regular, non-root-owned file is ever touched.
            if (is_link($f) || !is_file($f)) continue;
            $st = @lstat($f); if (!is_array($st) || (int)$st['uid'] === 0) continue;
            $perm = (int)$st['mode'] & 0777;
            if (!$dryrun) {
                // The inode is re-read in the same breath as the mutation: between the check above and the chmod the
                // account can rename wp-config.php into a symlink to /etc/shadow, and chmod/chattr follow links.
                // Only the very inode that was verified is ever touched.
                clearstatcache(true, $f); $st2 = @lstat($f);
                if (!is_array($st2) || (($st2['mode'] & 0170000) !== 0100000) || $st2['ino'] !== $st['ino'] || $st2['dev'] !== $st['dev'] || (int)$st2['uid'] === 0) continue;
                @chmod($f, 0444); if ($chattr) @shell_exec('chattr +i ' . escapeshellarg($f) . ' 2>/dev/null');
            }
            $actions[] = ['type' => 'lock', 'path' => $f, 'perm' => $perm, 'chattr' => $chattr];
        }
    }
    return $actions;
}
/** Move a malicious file out of the web tree into quarantine (backed up, restorable). */
function smpro_im_quarantine_file($file, $account, $dryrun = false) {
    if (is_link($file) || !is_file($file)) return null;                      // a link is never quarantined: its target is not the file that was listed
    $ls = @lstat($file); if (!$ls || (($ls['mode'] & 0170000) !== 0100000)) return null;   // regular file only (the listing may be seconds old)
    if (function_exists('smpro_wpguard_trusted') && smpro_wpguard_trusted($file)) return null;   // never quarantine WP Guard's own files / what it already quarantined
    if ($dryrun) return ['type' => 'quarantine', 'path' => $file, 'dryrun' => true];
    $acct = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)$account) ?: 'unknown';
    $qdir = SMPRO_IM_QUAR . '/' . $acct; @is_dir($qdir) || @mkdir($qdir, 0700, true);
    $dest = $qdir . '/' . date('Ymd_His') . '_' . substr(sha1($file), 0, 8) . '_' . basename($file);
    clearstatcache(true, $file); $ls2 = @lstat($file);              // the copy follows links: re-verify the inode right before it
    if (!$ls2 || (($ls2['mode'] & 0170000) !== 0100000) || $ls2['ino'] !== $ls['ino'] || $ls2['dev'] !== $ls['dev']) return null;
    clearstatcache(true, $file); $ls2 = @lstat($file);              // the copy follows links: re-verify the inode right before it
    if (!$ls2 || (($ls2['mode'] & 0170000) !== 0100000) || $ls2['ino'] !== $ls['ino'] || $ls2['dev'] !== $ls['dev']) return null;
    clearstatcache(true, $file); $ls2 = @lstat($file);              // the copy follows links: re-verify the inode right before it
    if (!$ls2 || (($ls2['mode'] & 0170000) !== 0100000) || $ls2['ino'] !== $ls['ino'] || $ls2['dev'] !== $ls['dev']) return null;
    clearstatcache(true, $file); $ls2 = @lstat($file);              // the copy follows links: re-verify the inode right before it
    if (!$ls2 || (($ls2['mode'] & 0170000) !== 0100000) || $ls2['ino'] !== $ls['ino'] || $ls2['dev'] !== $ls['dev']) return null;
    clearstatcache(true, $file); $ls2 = @lstat($file);              // the copy follows links: re-verify the inode right before it
    if (!$ls2 || (($ls2['mode'] & 0170000) !== 0100000) || $ls2['ino'] !== $ls['ino'] || $ls2['dev'] !== $ls['dev']) return null;
    @copy($file, $dest . '.bak');                                   // keep a copy for review/restore
    if (smpro_im_has_chattr()) @shell_exec('chattr -i ' . escapeshellarg($file) . ' 2>/dev/null');
    if (is_link($file)) return null;                                 // re-checked right before the first mutation
    @chmod($file, 0600);
    $moved = !is_link($file) && @rename($file, $dest);               // remove from the web tree (preserves the original at $dest)
    if (!$moved) {
        // M5 FIX - rename failed (e.g. cross-device EXDEV, disk full). Only neutralize in place if a VERIFIED non-empty
        // backup exists; otherwise stubbing would overwrite the ONLY copy of a possibly-false-positive file with no way
        // to restore. No backup -> leave the file untouched and report failure so the caller does not record a "cleaned".
        if (@filesize($dest . '.bak') > 0 && !is_link($file)) {
            // neutralise in place through a temp + rename, never by writing into the path itself
            $stub = $file . '.smproq-' . bin2hex(random_bytes(4)); $sh = @fopen($stub, 'xb');
            if ($sh) { @fwrite($sh, "<?php /* quarantined by smpro Intrusion Monitor */\n"); @fclose($sh); @chmod($stub, 0600); @chown($stub, (int)$ls['uid']); @chgrp($stub, (int)$ls['gid']); if (!@rename($stub, $file)) @unlink($stub); }
        }
        else { return ['type' => 'quarantine', 'path' => $file, 'stored' => '', 'backup' => '', 'error' => 'no-backup']; }
    }
    return ['type' => 'quarantine', 'path' => $file, 'backup' => $dest . '.bak', 'stored' => $moved ? $dest : ''];
}
/** Quarantine recently-changed PHP files that look like web-shells (skips legit/excluded paths). */
function smpro_im_clean_site($account, $withinMin = 1440, $dryrun = false, $max = 40, $strict = false) {
    $cleaned = [];
    foreach (smpro_im_docroots($account) as $root) {
        $cmd = 'timeout 18 nice -n ' . SMPRO_SCAN_NICE . ' ionice -c3 find ' . escapeshellarg($root)
             . ' -maxdepth 7 -type f \\( -name "*.php" -o -name "*.phtml" -o -name "*.pht" \\) -mmin -' . (int)$withinMin . ' 2>/dev/null | head -n 300';
        foreach (array_filter(explode("\n", (string)@shell_exec($cmd))) as $f) {
            if (smpro_im_breach_excluded($f) || !smpro_im_looks_malicious($f)) continue;
            if (smpro_im_is_wp_plugin($f)) continue;                 // legit admin-installed plugin (has Plugin Name header) -> never auto-quarantine
            if (smpro_im_wl_suppress($account, $f)) continue;        // CRITICAL: operator-whitelisted (Forensics) legit file -> NEVER auto-quarantine/overwrite it (unless a new obfuscation family appeared). A large single-file app trips the ≥2-family gate below, so without this guard the whitelist's promise fails.
            // M6 FIX - on the UNATTENDED (cron) path require ≥2 independent indicator families before pulling a file
            // from the live web tree; a lone weak match stays REPORTED, not auto-removed. Manual cleans pass strict=false.
            if ($strict && smpro_im_malice_count($f) < 2) continue;
            $r = smpro_im_quarantine_file($f, $account, $dryrun); if ($r) $cleaned[] = $r;
            if (count($cleaned) >= $max) break 2;
        }
    }
    return $cleaned;
}
/** Any recently-changed PHP in an account's docroots (the emergency TRIGGER: attacked + files changed). */
function smpro_im_recent_changed($account, $withinMin = 1440, $cap = 5) {
    $n = 0;
    foreach (smpro_im_docroots($account) as $root) {
        $cmd = 'timeout 12 nice -n ' . SMPRO_SCAN_NICE . ' ionice -c3 find ' . escapeshellarg($root)
             . ' -maxdepth 7 -type f \\( -name "*.php" -o -name "*.phtml" \\) -mmin -' . (int)$withinMin . ' 2>/dev/null | head -n ' . (int)$cap;
        foreach (array_filter(explode("\n", (string)@shell_exec($cmd))) as $f) { if (!smpro_im_breach_excluded($f)) $n++; }
        if ($n >= $cap) break;
    }
    return $n;
}
/* ---- clear-malicious scanner detection (credential probes / bare-IP scans) ---- */
/** True if the request path is a credential/secret-file probe - no legitimate visitor ever requests these. */
function smpro_im_is_secret_probe($uri) {
    $u = strtolower((string)$uri);
    if ($u === '') return false;
    static $needles = ['/.aws/', '/.aws/credentials', '/.aws/config', '/.gcloud/', '/.config/gcloud',
        '/.azure/', '/.credentials', '/credentials.json', '/credentials.db', '/.env', '/.git/config',
        '/.ssh/', '/id_rsa', '/.npmrc', '/.s3cfg', '/.docker/config', '/secrets', '/.htpasswd',
        '/.bash_history', '/wp-config.php.', '/.dockercfg', '/.kube/config', '/server.key', '/.travis.yml', '/.circleci'];
    foreach ($needles as $n) if (strpos($u, $n) !== false) return true;
    return false;
}
/** True if the Host targets the server's OWN bare IP / rDNS - no real visitor or hosted site uses this; only bots scanning the raw IP. */
function smpro_im_is_bareip_host($host) {
    $host = strtolower(trim((string)$host));
    if ($host === '') return false;
    if (filter_var($host, FILTER_VALIDATE_IP)) return true;                          // Host is a literal IP
    if ($host === strtolower((string)@php_uname('n'))) return true;                  // Host is the server hostname
    $ips = function_exists('smpro_server_ips') ? array_keys(smpro_server_ips()) : [];
    foreach ($ips as $ip) {
        if (strpos($ip, '.') === false) continue;                                    // IPv4 only for the rDNS trick
        if (strpos($host, $ip) !== false) return true;                               // Host contains a server IP
        $rev = implode('.', array_reverse(explode('.', $ip)));                       // reversed-octet rDNS (e.g. 1.113.0.203.clients.<provider>.net for 203.0.113.1)
        if ($rev !== $ip && strpos($host, $rev) !== false) return true;
    }
    return false;
}
/**
 * Auto-block clear malicious scanners across the whole server (part of Emergency). High-confidence only:
 * an IP that probes credential/secret files (≥3) OR hammers the server's bare IP/rDNS (≥8) - both near-zero
 * false-positive. Honors allowlist / never-block-self guards, dry-run, and a 6h per-IP cooldown. Reversible
 * via CSF (the same Unblock used everywhere). Returns the list for the admin alert.
 */
/**
 * True only for a LEGITIMATE search-engine crawler, proven by forward-confirmed reverse DNS
 * (rDNS host ends in a known crawler domain AND that host resolves back to the same IP).
 * Note: Google CLOUD VMs (*.bc.googleusercontent.com) are NOT crawlers - they do NOT match, so
 * rented-VM scanners are still blocked. Real Googlebot is *.googlebot.com / 66.249.x (forward-confirmed).
 */
function smpro_im_is_verified_crawler($ip) {
    static $cache = [];
    if (isset($cache[$ip])) return $cache[$ip];
    $cache[$ip] = false;
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return false;
    $rdns = (string)@shell_exec('timeout 3 host ' . escapeshellarg($ip) . ' 2>/dev/null');
    if (!preg_match('/(?:pointer|name)\s+(\S+?)\.?\s*$/im', $rdns, $m)) return false;
    $host = strtolower($m[1]);
    // known legitimate crawler domains (Google search, Bing, Yahoo, DuckDuckGo, Apple, Yandex, Baidu)
    if (!preg_match('/\.(googlebot\.com|google\.com|search\.msn\.com|crawl\.yahoo\.net|duckduckgo\.com|applebot\.apple\.com|yandex\.(?:com|ru|net)|crawl\.baidu\.com)$/', $host)) return false;
    // forward-confirm: the crawler hostname must resolve back to THIS ip
    $fwd = (string)@shell_exec('timeout 3 host ' . escapeshellarg($host) . ' 2>/dev/null');
    $cache[$ip] = (strpos($fwd, ' ' . $ip) !== false) || (bool)preg_match('/\b' . preg_quote($ip, '/') . '\b/', $fwd);
    return $cache[$ip];
}

function smpro_im_emergency_block_scanners($events, $dryrun = false) {
    $cand = [];
    foreach ($events as $e) {
        $ip = (string)($e['ip'] ?? ''); if ($ip === '') continue;
        $probe = smpro_im_is_secret_probe($e['uri'] ?? '');
        $bare  = smpro_im_is_bareip_host($e['domain'] ?? '');
        if (!$probe && !$bare) continue;
        if (!isset($cand[$ip])) $cand[$ip] = ['probe' => 0, 'bare' => 0, 'uas' => []];
        if ($probe) $cand[$ip]['probe']++;
        if ($bare)  $cand[$ip]['bare']++;
        $ua = trim((string)($e['ua'] ?? '')); if ($ua !== '') $cand[$ip]['uas'][$ua] = 1;
    }
    // worst first, and cap per run so a wide manual window doesn't fire hundreds of CSF calls synchronously
    uasort($cand, fn($a, $b) => ($b['probe'] + $b['bare']) <=> ($a['probe'] + $a['bare']));
    $st = smpro_in_state(); $done = $st['emergency_blocked'] ?? []; $now = time(); $out = []; $cap = 50;
    foreach ($cand as $ip => $c) {
        if (count($out) >= $cap) break;
        if ($c['probe'] < 3 && $c['bare'] < 8) continue;                             // high-confidence threshold
        if (isset($done[$ip]) && ($now - (int)$done[$ip]) < 6 * 3600) continue;      // 6h cooldown
        if (!filter_var($ip, FILTER_VALIDATE_IP)) continue;
        if (function_exists('smpro_ip_is_external') && !smpro_ip_is_external($ip)) continue;
        if (function_exists('smpro_is_server_ip') && smpro_is_server_ip($ip)) continue;
        if (smpro_im_allowlisted($ip)) continue;
        if (smpro_im_is_verified_crawler($ip)) continue;                             // never block a verified search crawler (Googlebot/Bing/...)
        $rs = smpro_im_region_status($ip);
        if ($rs === 'core_protected') continue;                                      // home-region residential: never auto-block (manual review only)
        if ($rs === 'arab_caution' && $c['probe'] < 5 && $c['bare'] < 12) continue;  // other Arab residential: only on clear, repeated abuse
        $why = $c['probe'] >= 3
            ? 'credential/secret probing (' . $c['probe'] . ' hits' . (count($c['uas']) >= 4 ? ', ' . count($c['uas']) . ' rotating UAs' : '') . ')'
            : 'scanning the bare server IP (' . $c['bare'] . ' hits' . (count($c['uas']) >= 4 ? ', ' . count($c['uas']) . ' rotating UAs' : '') . ')';
        if (!$dryrun) {
            $r = smpro_im_block_ip($ip, 'emergency/scanner: ' . $why);
            if ($r['ok']) $done[$ip] = $now;
            $out[] = ['ip' => $ip, 'reason' => $why, 'ok' => $r['ok'], 'msg' => $r['msg']];
        } else {
            $out[] = ['ip' => $ip, 'reason' => $why . ' (dry-run)', 'ok' => true, 'msg' => 'dry-run'];
        }
    }
    if ($out && !$dryrun) { $st['emergency_blocked'] = array_slice($done, -1000, 1000, true); smpro_in_state_save($st); }
    return $out;
}

/** Build the grouped scanner-block digest alert (INFO): summarised by /24 subnet, campaign-aware. */
function smpro_im_scanner_digest($ipsMap) {
    $n = count($ipsMap);
    $subnets = [];
    foreach (array_keys($ipsMap) as $ip) { $s = function_exists('smpro_im_subnet24') ? smpro_im_subnet24($ip) : $ip; if ($s === '') $s = $ip; $subnets[$s][] = $ip; }
    uasort($subnets, fn($a, $b) => count($b) <=> count($a));
    $lines = []; $shown = 0; $multi = 0;
    foreach ($subnets as $sub => $ips) { if (count($ips) >= 3) $multi++; if ($shown < 15) { $lines[] = '• ' . $sub . ' — ' . count($ips) . ' IP(s)'; $shown++; } }
    $body = $n . ' malicious scanner IP(s) were auto-blocked in the last window (credential/.env harvesting + bare-IP probing — mostly rented datacenter / cloud VMs with rotating User-Agents).'
          . "\nThis is ROUTINE automated defense — no action needed. Verified search-engine crawlers (Googlebot etc.) are never blocked."
          . ($multi ? "\n\nCoordinated /24 subnets (>=3 IPs each): " . $multi : '')
          . "\n\nTop source subnets:\n" . implode("\n", $lines)
          . "\n\nFull list + restore: Intrusion Monitor -> Emergency.";
    return [
        'sig'     => 'emblk:' . substr(md5(implode(',', array_keys($ipsMap))), 0, 12),
        'subject' => 'Auto-blocked ' . $n . ' malicious scanner IP(s) [digest]',
        'body'    => $body,
    ];
}

/**
 * EMERGENCY run: for each site that is under an exploit-class attack AND has recently-changed files,
 * quarantine any web-shells found and harden upload dirs + core files, then record (reversible) and
 * return a summary for the admin alert. Per-account 1h cooldown. Honors dry-run.
 * Also (when emergency_block_scanners is on) auto-blocks clear malicious scanners server-wide.
 */
function smpro_im_emergency_run($events, $dryrunOverride = null) {
    $cfg = smpro_in_cfg();
    $dryrun = $dryrunOverride !== null ? (bool)$dryrunOverride : !empty($cfg['emergency_dryrun']);
    if (function_exists('smpro_ctl_dry_run') && smpro_ctl_dry_run()) $dryrun = true;   // global Dry-Run forces report-only
    $attacked = [];
    foreach ($events as $e) if ($e['domain'] !== '' && smpro_im_exploit_kind($e['kind']) && (int)($e['code'] ?? 0) >= 200 && (int)($e['code'] ?? 0) < 400) $attacked[$e['domain']] = ($attacked[$e['domain']] ?? 0) + 1;   // a 403-blocked probe is WAF noise, not an attack that reached the site
    arsort($attacked);
    // server-wide: auto-block clear malicious scanners (credential probes / bare-IP scans) - runs even when no site files changed
    $blocked = !empty($cfg['emergency_block_scanners']) ? smpro_im_emergency_block_scanners($events, $dryrun) : [];
    if ($blocked && !$dryrun && function_exists('smpro_audit')) {
        $okIps = array_column(array_filter($blocked, fn($b) => $b['ok']), 'ip');
        if ($okIps) smpro_audit('intrusion_emergency', ['scanners_blocked' => $okIps]);
    }
    $st = smpro_in_state(); $cool = $st['emergency_done'] ?? []; $now = time();
    $man = smpro_im_em_manifest_load(); $hardened = []; $cleaned = []; $seen = 0; $skippedHarden = [];
    foreach (array_keys($attacked) as $dom) {
        if ($seen++ >= 30) break;
        $acct = smpro_im_account_for($dom); if ($acct === '') continue;
        if (isset($cool[$acct]) && ($now - (int)$cool[$acct]) < 3600) continue;     // 1h cooldown per account
        // Force-unprotected on purpose. Hardening this account would undo an operator's explicit decision, and
        // would do it unattended, at the moment the site is already under attack - the worst time to break it.
        // Cleaning still runs: removing a web shell is not the same promise as locking files the owner writes to.
        if (smpro_im_ph_ignored($acct)) { $skippedHarden[] = $acct; continue; }
        if (smpro_im_recent_changed($acct, 1440, 1) < 1) continue;                  // trigger: files actually changed
        $cool[$acct] = $now;
        $c = !empty($cfg['emergency_clean'])  ? smpro_im_clean_site($acct, 1440, $dryrun, 40, true) : [];   // unattended -> strict (≥2 indicator families)
        $h = !empty($cfg['emergency_harden']) ? smpro_im_harden_site($acct, $dryrun)      : [];
        if ($c) $cleaned[]  = ['domain' => $dom, 'account' => $acct, 'files' => $c];
        if ($h) $hardened[] = ['domain' => $dom, 'account' => $acct, 'n' => count($h)];
        if (($c || $h) && !$dryrun) {
            $man[] = ['id' => date('Ymd_His') . '_' . substr(sha1($acct . $now), 0, 6), 'ts' => $now, 'account' => $acct, 'domain' => $dom, 'actions' => array_merge($h, $c)];
            if (function_exists('smpro_audit')) smpro_audit('intrusion_emergency', ['account' => $acct, 'domain' => $dom, 'cleaned' => count($c), 'hardened' => count($h)]);
        }
    }
    $st['emergency_done'] = array_slice($cool, -500, 500, true); smpro_in_state_save($st);
    if (($hardened || $cleaned) && !$dryrun) smpro_im_em_manifest_save($man);
    // Reported, not swallowed: an account that was attacked and deliberately left unhardened is something the
    // operator needs to see in the response summary, otherwise the run reads as if it covered everything.
    return ['hardened' => $hardened, 'cleaned' => $cleaned, 'blocked' => $blocked, 'dryrun' => $dryrun,
            'skipped_harden' => array_values(array_unique($skippedHarden))];
}
/**
 * Is this account on the force-unprotect ignore list?
 *
 * ph_ignore.php is boot-loaded by the page, but the cron workers each require their own short list of includes and
 * do not carry it - so it is pulled in here on demand. Without this the rule would hold in the interface and be
 * ignored by the unattended pass, which is the only pass that matters for this rule.
 */
function smpro_im_ph_ignored($acct) {
    if (!function_exists('smpro_ph_ign_has')) {
        $f = __DIR__ . '/ph_ignore.php';
        if (is_file($f)) require_once $f;
    }
    return function_exists('smpro_ph_ign_has') ? smpro_ph_ign_has($acct, 'auto') : false;
}

/** Reverse one emergency manifest entry: un-lock core files, restore upload .htaccess, restore quarantined files. */
function smpro_im_emergency_undo($id) {
    $id = preg_replace('/[^0-9A-Za-z_]/', '', (string)$id); if ($id === '') return false;
    $man = smpro_im_em_manifest_load(); $keep = []; $done = false;
    foreach ($man as $e) {
        if (($e['id'] ?? '') !== $id) { $keep[] = $e; continue; }
        $done = true;
        foreach (($e['actions'] ?? []) as $a) {
            $p = $a['path'] ?? '';
            if ($a['type'] === 'lock' && $p) { if (is_link($p)) continue; if (smpro_im_has_chattr()) @shell_exec('chattr -i ' . escapeshellarg($p) . ' 2>/dev/null'); @chmod($p, ($a['perm'] ?? 0644) ?: 0644); }
            elseif ($a['type'] === 'php_off' && $p) {
                if (smpro_im_has_chattr()) @shell_exec('chattr -i ' . escapeshellarg($p) . ' 2>/dev/null');
                $bk = (string)($a['bak'] ?? '');
                if ($bk === '' || !is_file($bk)) {   // older manifests carry no name: the newest .smprobak-* beside the file, then the legacy fixed name
                    $cands = glob($p . '.smprobak-*') ?: []; usort($cands, fn($x, $y) => (int)@filemtime($y) <=> (int)@filemtime($x));
                    $bk = $cands[0] ?? ($p . '.smprobak');
                }
                if (!empty($a['had']) && is_file($bk) && !is_link($bk) && dirname($bk) === dirname($p)) { @rename($bk, $p); }   // restore the owner's original
                elseif (is_file($p)) {
                    // m4 FIX - we CREATED this file (had=false). Only delete it if it is still EXACTLY our block; if the
                    // owner appended their own rules after ours, strip just our prefix and KEEP theirs (never delete owner content).
                    $cur = (string)@file_get_contents($p); $rule = smpro_im_harden_rule();
                    if (trim($cur) === trim($rule)) { @unlink($p); }
                    elseif (strpos($cur, $rule) === 0) { $rest = substr($cur, strlen($rule)); if (trim($rest) === '') { @unlink($p); } else { @file_put_contents($p, $rest); @chmod($p, 0644); } }
                    // else: file no longer begins with our block (owner rewrote it entirely) -> leave it untouched
                }
            }
            elseif ($a['type'] === 'quarantine' && $p) {
                if (smpro_im_has_chattr()) @shell_exec('chattr -i ' . escapeshellarg($p) . ' 2>/dev/null');
                if (!empty($a['stored']) && is_file($a['stored'])) { @rename($a['stored'], $p); }      // moved copy -> back to original
                elseif (!empty($a['backup']) && is_file($a['backup'])) { @copy($a['backup'], $p); }     // fallback: restore from the .bak copy
                @chmod($p, 0644);
            }
        }
    }
    if ($done) smpro_im_em_manifest_save($keep);
    return $done;
}

/* ============================ real-time alert scan (cron) ============================ */
/**
 * Called by the notify cron. Ingests recent attacks, then returns alert items for NEW
 * conditions in the window. Optionally auto-blocks the worst offenders. The notify layer
 * turns the returned items into deduped notifications.
 */
/* ===================== upload-breach cluster detector (closes the .php-only breach-scan gap) ===================== */
/** Group the window's parsed events into upload-attack CLUSTERS: many accepted-2xx "Malicious Upload" POST/PUT to one
 *  endpoint from multiple IPs. Pure in-memory over already-parsed events - no new find/grep/log read. Fires even when
 *  no *.php changed (shells land in image dirs with image/blank extensions that smpro_im_breaches never sees). */
function smpro_im_upload_clusters(array $events, $cfg = null) {
    $cfg = is_array($cfg) ? $cfg : smpro_in_cfg();
    $N = max(2, (int)($cfg['thr_upload_cluster_events'] ?? 8));
    $M = max(1, (int)($cfg['thr_upload_cluster_ips'] ?? 4));
    $g = [];
    foreach ($events as $e) {
        if ((string)($e['kind'] ?? '') !== 'Malicious Upload') continue;
        $code = (int)($e['code'] ?? 0); if ($code < 200 || $code >= 300) continue;                       // ACCEPTED only
        $mth = strtoupper((string)($e['method'] ?? '')); if ($mth !== '' && $mth !== 'POST' && $mth !== 'PUT') continue;
        $acct = smpro_im_account_for((string)($e['domain'] ?? '')); if ($acct === '') continue;
        $ep = preg_replace('#/\d+/?$#', '', smpro_im_path_of((string)($e['uri'] ?? '')));                 // fold /.../uploadimage/5
        $k = $acct . '|' . $ep;
        if (!isset($g[$k])) $g[$k] = ['account'=>$acct, 'endpoint'=>$ep, 'ips'=>[], 'n'=>0, 'first'=>PHP_INT_MAX, 'last'=>0, 'samples'=>[]];
        $g[$k]['n']++; if (($e['ip'] ?? '') !== '') $g[$k]['ips'][(string)$e['ip']] = 1;
        $g[$k]['first'] = min($g[$k]['first'], (int)($e['ts'] ?? 0)); $g[$k]['last'] = max($g[$k]['last'], (int)($e['ts'] ?? 0));
        if (count($g[$k]['samples']) < 5) $g[$k]['samples'][(string)($e['uri'] ?? '')] = 1;
    }
    $out = [];
    foreach ($g as $c) { $ipc = count($c['ips']); if ($c['n'] >= $N && $ipc >= $M) { $c['ip_count'] = $ipc; $c['samples'] = array_keys($c['samples']); unset($c['ips']); $out[] = $c; } }
    usort($out, fn($a, $b) => ($b['ip_count'] <=> $a['ip_count']) ?: ($b['n'] <=> $a['n']));
    return array_slice($out, 0, 200);
}
/** Condensed §1+§4 landing status for one account (did a shell land / get executed), bounded by a shared deadline. */
function smpro_im_upload_landed($account, $sinceTs, $deadline = 0) {
    $none = ['worst_band'=>'clean', 'hits'=>[], 'executed'=>false, 'executed_evidence'=>'', 'verdict'=>'attempted_only'];
    if (!function_exists('smpro_ub_scope')) return $none;
    $opts = $deadline ? ['deadline'=>$deadline] : [];
    $scope = smpro_ub_scope($account); if (!is_array($scope)) return $none;
    $sh = smpro_ub_shell_hunt($scope, (int)$sinceTs, $opts);
    $lv = smpro_ub_is_live($scope, $sh, (int)$sinceTs, $opts);
    $verdict = $lv['executed'] ? 'confirmed_live' : ((smpro_ub_band_rank($sh['worst_band']) >= 3 && !empty($lv['php_exec_allowed'])) ? 'planted_inert' : 'attempted_only');
    return ['worst_band'=>$sh['worst_band'], 'hits'=>array_slice($sh['candidates'], 0, 12), 'executed'=>!empty($lv['executed']),
            'executed_evidence'=>!empty($lv['executed']) ? (string)($lv['getback_hits'][0]['uri'] ?? '') : '', 'verdict'=>$verdict];
}
/** Build the upload-cluster alert (or null). Runs the landing check for the top cluster under an ~8s slice. English. */
function smpro_im_upload_cluster_alert(array $recent) {
    $clusters = smpro_im_upload_clusters($recent, smpro_in_cfg());
    if (!$clusters) return null;
    $top = $clusters[0]; $acct = $top['account']; $ep = $top['endpoint'];
    $land = function_exists('smpro_ub_scope') ? smpro_im_upload_landed($acct, time() - 86400, microtime(true) + 8.0) : ['verdict'=>'attempted_only', 'worst_band'=>'clean', 'hits'=>[], 'executed_evidence'=>''];
    if ($land['verdict'] === 'confirmed_live')    { $sev = 'critical'; $subj = 'Web-shell uploaded AND executed — ' . $acct;
        $body = 'CONFIRMED — a web-shell was uploaded to ' . $acct . ' AND later executed (GET-back 2xx to ' . ($land['executed_evidence'] ?: $ep) . '). Band ' . $land['worst_band'] . '. Endpoint ' . $ep . ' — ' . $top['n'] . ' accepted uploads from ' . $top['ip_count'] . ' IPs.'; }
    elseif ($land['verdict'] === 'planted_inert') { $sev = 'high'; $subj = 'Malicious file landed in upload dir — ' . $acct;
        $body = count($land['hits']) . ' suspicious file(s) landed in ' . $acct . "'s upload dir(s) (band " . $land['worst_band'] . ') via ' . $ep . ' — none executed yet (no GET-back). Treat as active; quarantine now. ' . $top['n'] . ' accepted uploads from ' . $top['ip_count'] . ' IPs.'; }
    else                                          { $sev = 'high'; $subj = 'Malicious upload cluster accepted — ' . $acct;
        $body = $acct . ': ' . $top['n'] . ' malicious uploads ACCEPTED (2xx) on ' . $ep . ' from ' . $top['ip_count'] . ' IPs — no shell content found in the upload dirs yet. Fix the handler before one lands.'; }
    return ['sig'=>'ucl:' . $acct . ':' . md5($ep) . ':' . $land['verdict'], 'subject'=>$subj,
            'body'=>$body . "\nOpen User Investigation → \"Collect breach evidence\" for the full report.", 'meta'=>['severity'=>$sev],
            'account'=>$acct, 'endpoint'=>$ep, 'n_hits'=>$top['n'], 'm_ips'=>$top['ip_count']];
}

function smpro_im_alert_scan() {
    $cfg = smpro_in_cfg();
    $win = max(2, (int)$cfg['alert_window_min']);
    $eventsAll = smpro_im_ingest_recent(SMPRO_IM_LIVE_BYTES, max($win, 60), true);
    $events = array_values(array_filter($eventsAll, fn($e) => empty($e['monitor'])));
    $cut = time() - $win * 60;
    $recentAll = array_filter($eventsAll, fn($e) => ($e['ts'] ?? 0) >= $cut);   // for the upload-cluster check only
    $recent = array_filter($events, fn($e) => ($e['ts'] ?? 0) >= $cut);
    $alerts = [];

    // SERVED exploit attempts - the genuinely dangerous ones: an exploit-class attack the app
    // answered with 2xx/3xx (NOT blocked). Blocked probes (403) are routine WAF noise and do
    // NOT raise a critical alert - that is what made the old "223 CRITICAL" alert meaningless.
    $served = array_filter($recent, fn($e) => smpro_im_served($e));
    if ($served) {
        $sd = array_values(array_unique(array_filter(array_map(fn($e) => $e['domain'], $served))));
        $alerts['critical'] = ['sig'=>'served:' . (count($sd) <= 1 ? 1 : (count($sd) <= 5 ? 5 : 99)), 'subject'=>count($served) . ' exploit attempt(s) SERVED 2xx (possible success) in last ' . $win . 'm',
            'body'=>'Domains: ' . implode(', ', array_slice($sd, 0, 12)) . (count($sd) > 12 ? ' +' . (count($sd) - 12) : '') . "\nThese were NOT blocked by the WAF — review immediately."];
    }
    // domain spikes (blocked + served attempts) - high baseline on a busy shared server, so the threshold is high
    $by = smpro_im_by_domain($recent); $thr = (int)$cfg['thr_domain_attacks']; $spiked = []; $phantom = [];
    // A name that is not a site here (a wildcard DNS record lands it on the parent) stays INTERNAL: the panel and the
    // daily report show it, the operator's phone does not. Only real sites make the alert.
    foreach ($by as $g) if ($g['total'] >= $thr) { if (smpro_im_host_known($g['domain'])) $spiked[] = $g['domain'] . ' (' . $g['total'] . ')'; else $phantom[] = smpro_im_host_label($g['domain']) . ' (' . $g['total'] . ')'; }
    if ($phantom && function_exists('smpro_ntf_held')) smpro_ntf_held('intrusion_attack', count($phantom) . ' invented hostname(s) under heavy attack (wildcard DNS)', 'kept internal: not a site on this server; the WAF handles it on the parent site', 'phantom:' . count($phantom));
    // The signature is how WIDE the attack is (a band of the number of domains), never the counts and not the
    // names either: a count changes with every 15-minute window, and a scanner walking one server's vhosts
    // changes the NAMES every window too, so either made the signature new on every run and the same alert went
    // out every five minutes with "only when it changes" switched on. It is sent again when the attack widens or
    // narrows across a band (1, 2, 3-5, 6-10, more), and the body always carries the current list.
    $band = fn(int $n): int => $n <= 1 ? 1 : ($n <= 2 ? 2 : ($n <= 5 ? 5 : ($n <= 10 ? 10 : 99)));
    if ($spiked) $alerts['spike'] = ['sig'=>'spike:' . $band(count($spiked)), 'subject'=>count($spiked) . ' domain(s) under heavy attack (>=' . $thr . ' attempts/' . $win . 'm, mostly blocked)', 'body'=>implode("\n", array_slice($spiked, 0, 15)) . "\n(These are blocked + served attempts; most are blocked WAF noise.)"];
    // distributed scanners
    $camp = smpro_im_campaigns($recent);
    if ($camp['distributed']) {
        $top = array_map(fn($d) => $d['ip'] . ' → ' . $d['domains'] . ' domains', array_slice($camp['distributed'], 0, 10));
        $alerts['distributed'] = ['sig'=>'dist:' . md5(implode(',', array_column($camp['distributed'], 'ip'))), 'subject'=>count($camp['distributed']) . ' IP(s) scanning many domains', 'body'=>implode("\n", $top)];
    }
    // likely breaches
    $breaches = smpro_im_breaches($recent, 90, 20);
    if ($breaches) {
        $lines = array_map(fn($b) => $b['domain'] . ' [' . implode(',', $b['kinds']) . '] files: ' . implode(', ', array_map('basename', array_slice($b['changed'], 0, 3))), $breaches);
        $alerts['breach'] = ['sig'=>'breach:' . md5(implode(',', array_column($breaches, 'domain'))), 'subject'=>'POSSIBLE COMPROMISE on ' . count($breaches) . ' domain(s)', 'body'=>implode("\n", $lines) . "\nOpen Forensics for the listed accounts NOW."];
    }
    // upload-cluster breach (fires on accepted-2xx Malicious-Upload clusters even when NO .php changed - the gap
    // that let an unrestricted-upload attack run silently because smpro_im_breaches only scans *.php/*.phtml)
    if ($u = smpro_im_upload_cluster_alert($recentAll)) $alerts['upload_cluster'] = $u;   // accepted uploads are monitoring records by nature
    // GENUINE attack from the server's OWN / local IP (wp-cron + benign internal traffic excluded)
    $selfIps = [];
    foreach ($recent as $e) if (smpro_im_is_self_attack($e['ip'], $e['kind'], $e['uri'] ?? '')) $selfIps[$e['ip']] = ($selfIps[$e['ip']] ?? 0) + 1;
    if ($selfIps) {
        $l = []; foreach ($selfIps as $ip => $n) $l[] = $ip . ' (' . $n . ' attacks)';
        $alerts['selfattack'] = ['sig'=>'self:' . md5(implode(',', array_keys($selfIps))), 'subject'=>'⚠ Web attack from the SERVER\'S OWN / local IP', 'body'=>implode("\n", $l) . "\nA local process may be compromised and attacking hosted sites. Investigate immediately (Forensics + Top Processes)."];
    }

    // optional auto-response: block the worst attacker IPs (AI-decided when enabled)
    if (!empty($cfg['auto_block'])) {
        $offenders = smpro_im_offenders($recent, 25);
        $minHits = max(5, (int)($cfg['auto_block_threshold'] ?? 30));   // per-IP attack-count floor (default 30)
        $hitsOf  = []; foreach ($offenders as $o) $hitsOf[$o['ip']] = (int)$o['hits'];
        $st = smpro_in_state(); $done = $st['autoblocked'] ?? []; $blocked = []; $how = 'threshold';
        $toBlock = [];
        if (!empty($cfg['ai_block']) && function_exists('smpro_ai_available') && smpro_ai_available()) {
            $ai = smpro_im_ai_block_decide($offenders);
            if ($ai['ok']) { $toBlock = $ai['block']; $how = 'AI'; }
            else foreach ($offenders as $o) if ($o['hits'] >= $minHits) $toBlock[] = $o['ip'];   // fallback if AI failed
        } else {
            foreach ($offenders as $o) if ($o['hits'] >= $minHits) $toBlock[] = $o['ip'];
        }
        foreach ($toBlock as $ip) {
            if (isset($done[$ip]) || !filter_var($ip, FILTER_VALIDATE_IP)) continue;
            if (function_exists('smpro_ip_is_external') && !smpro_ip_is_external($ip)) continue;
            if (smpro_im_allowlisted($ip)) continue;
            // home-region policy (the "any NON-ARAB IP after N attacks -> block" rule):
            //   core_protected = home-region residential -> NEVER auto-block · arab_caution = other-Arab residential -> 3x the floor
            //   normal = non-Arab / datacenter (any country) / unknown geo -> block at the floor. (Datacenter in the home region is still blockable.)
            if (!empty($cfg['protect_arab'])) {
                $rs = smpro_im_region_status($ip);
                if ($rs === 'core_protected') continue;
                if ($rs === 'arab_caution' && ($hitsOf[$ip] ?? 0) < $minHits * 3) continue;
            }
            $globalDry = function_exists('smpro_ctl_dry_run') && smpro_ctl_dry_run();
            if (empty($cfg['auto_block_dryrun']) && !$globalDry) { $r = smpro_im_block_ip($ip, 'auto/' . $how); if ($r['ok']) { $done[$ip] = time(); $blocked[] = $ip; } }
            else $blocked[] = $ip . ' (dry-run)';
        }
        if ($blocked) {
            $st['autoblocked'] = array_slice($done, -500, 500, true); smpro_in_state_save($st);
            $alerts['autoblock'] = ['sig'=>'ab:' . md5(implode(',', $blocked)), 'subject'=>(empty($cfg['auto_block_dryrun']) ? 'Auto-blocked ' : 'Auto-block (dry-run) ') . count($blocked) . ' attacker IP(s) [' . $how . ']', 'body'=>implode("\n", $blocked) . (isset($ai['reason']) && $ai['reason'] !== '' ? "\n\nAI reasoning: " . $ai['reason'] : '')];
        }
    }

    // EMERGENCY auto-response. Two DISTINCT signals, deliberately separated to cut noise:
    //   (a) routine SCANNER auto-blocks (credential/.env probes from datacenter VMs) - high volume,
    //       low urgency -> accumulate and send ONE grouped INFO digest per emergency_block_digest_hours
    //       (default 12h), summarised by /24 subnet (campaign-aware), NOT a CRITICAL on every run.
    //   (b) HARDEN/CLEAN on an actually-compromised site - rare, urgent -> prompt CRITICAL, batched small.
    if (!empty($cfg['emergency'])) {
        $em  = smpro_im_emergency_run($recent);
        $blk = $em['blocked'] ?? [];

        // (a) scanner-block digest
        if ($blk && !$em['dryrun']) {
            $st = smpro_in_state();
            $dg = (isset($st['emergency_block_digest']) && is_array($st['emergency_block_digest'])) ? $st['emergency_block_digest'] : ['ips' => [], 'first_ts' => time()];
            if (empty($dg['ips'])) $dg['first_ts'] = time();
            foreach ($blk as $b) if (!empty($b['ok'])) $dg['ips'][$b['ip']] = $b['reason'];
            $digestH = max(1, (int)($cfg['emergency_block_digest_hours'] ?? 12));
            if ((time() - (int)($dg['first_ts'] ?? time())) >= $digestH * 3600 || count($dg['ips']) >= 250) {
                if ($dg['ips']) $alerts['emergency_blocks'] = smpro_im_scanner_digest($dg['ips']);
                $st['emergency_block_digest'] = ['ips' => [], 'first_ts' => time()];
            } else {
                $st['emergency_block_digest'] = $dg;
            }
            smpro_in_state_save($st);
        }

        // (b) harden/clean prompt batch (the genuinely urgent emergency actions)
        $newLines = [];
        foreach ($em['cleaned'] as $x)  $newLines[] = '🧹 ' . $x['domain'] . ' — quarantined ' . count($x['files']) . ' web-shell file(s)';
        foreach ($em['hardened'] as $x) $newLines[] = '🛡 ' . $x['domain'] . ' — hardened (' . $x['n'] . ' actions: PHP-exec off in uploads + core files locked)';
        if ($newLines) {
            $batchN = max(1, (int)($cfg['emergency_batch'] ?? 3));
            $st   = smpro_in_state();
            $pend = (isset($st['emergency_pending']) && is_array($st['emergency_pending'])) ? $st['emergency_pending'] : ['lines' => [], 'first_ts' => time()];
            if (empty($pend['lines'])) $pend['first_ts'] = time();
            $pend['lines'] = array_merge((array)($pend['lines'] ?? []), $newLines);
            $n = count($pend['lines']);
            $stale = (time() - (int)($pend['first_ts'] ?? time())) > 3600;
            if ($n >= $batchN || $stale) {
                $lines = array_slice($pend['lines'], 0, 80);
                $alerts['emergency'] = [
                    'sig'     => 'em:batch:' . substr(md5(implode(',', $lines)), 0, 12),
                    'subject' => 'Emergency — ' . $n . ' site-protection action(s) [grouped]',
                    'body'    => implode("\n", $lines) . "\n\nGrouped report of the last " . $n . ' emergency site actions. Review/restore in Intrusion Monitor → Emergency.',
                ];
                $st['emergency_pending'] = ['lines' => [], 'first_ts' => time()];
            } else {
                $st['emergency_pending'] = $pend;
            }
            smpro_in_state_save($st);
        }
    }
    return $alerts;
}

/** Weekly index upkeep from a WORKER: the 30-day retention delete runs with every ingest, but the freed pages
 *  never returned to the filesystem (400 MB for 30 days on one server). Never from a page request. */
function smpro_in_maintain(): void {
    if (PHP_SAPI !== 'cli') return;
    $flag = SMPRO_VARLIB . '/intrusion_vacuum_at';
    if (@is_file($flag) && (time() - (int)@filemtime($flag)) < 7 * 86400) return;
    @touch($flag);
    $db = smpro_in_db(); if (!$db) return;
    try {
        $db->exec('DELETE FROM attacks WHERE ts < ' . (time() - 30 * 86400));
        $db->exec('PRAGMA wal_checkpoint(TRUNCATE)');
        $db->exec('VACUUM');
        if (function_exists('smpro_audit')) smpro_audit('intrusion_index_vacuum', ['bytes' => (int)@filesize(SMPRO_IN_DB)]);
    } catch (\Throwable $e) { if (function_exists('smpro_soft_fail')) smpro_soft_fail('intrusion_vacuum', $e); }
}
