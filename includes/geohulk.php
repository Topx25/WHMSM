<?php
/**
 * geohulk.php - the door wall. A sign-in from a country that is not on the allowed list is refused before the
 * password is checked, using cPHulk's own country blacklist.
 *
 * WHY THIS AND NOT THE FIREWALL WALL. Country Login Lock is reactive: it reads the log after a sign-in and then
 * closes the address and ends the session. Measured: 22 to 96 seconds, and once that was long enough for the
 * password to be changed. The firewall country wall (geowall.php) stands in front of the door but drops packets,
 * which is how it once made a server unreachable to its own operator.
 *
 * cPHulk already sits in front of every login door cPanel has (cPanel, WHM, webmail, FTP, SSH through PAM,
 * IMAP/POP, SMTP) and already has a country blacklist: a code list in its config, which its queue task
 * `update_country_ips` expands into address ranges in its own database. A refused login gets "LOGIN DENIED --
 * COUNTRY IS BLACKLISTED" and never reaches the password check. It cannot make the server unreachable: it is
 * a login refusal, not a packet drop, and the way back is `whmapi1 disable_cphulk` from any shell.
 *
 * So the wall is: cPHulk enabled, its country blacklist = every country that is NOT allowed for anyone (the lock's
 * server list, its per-account exceptions, and Intrusion Monitor's home + caution regions), the operator's own
 * address on cPHulk's whitelist before anything is armed, and a sync every minute that keeps the blacklist equal
 * to the list as the operator edits it. OFF by default; armed from the Country Login Lock card.
 *
 * Verified on a production server with cPHulk disabled (no effect while disabled): set -> expand -> 48 ranges
 * for one code -> clear -> 0. The functions below are the same calls.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

if (!defined('SMPRO_GH_CFG')) define('SMPRO_GH_CFG', SMPRO_VARLIB . '/geohulk.json');

function smpro_gh_cfg(): array {
    $j = @is_file(SMPRO_GH_CFG) ? json_decode((string)@file_get_contents(SMPRO_GH_CFG), true) : null;
    $c = is_array($j) ? $j : [];
    $c += ['enabled' => false, 'armed_at' => 0, 'armed_by_ip' => '', 'prev_hulk_enabled' => null, 'prev_blacklist' => null,
           'last_sync' => 0, 'last_blacklist' => '', 'last_error' => ''];
    $c['enabled'] = !empty($c['enabled']);
    return $c;
}

function smpro_gh_cfg_save(array $c): bool {
    @is_dir(SMPRO_VARLIB) || @mkdir(SMPRO_VARLIB, 0700, true);
    $tmp = SMPRO_GH_CFG . '.tmp';
    if (@file_put_contents($tmp, json_encode($c, JSON_PRETTY_PRINT), LOCK_EX) === false) return false;
    @chmod($tmp, 0600);
    return @rename($tmp, SMPRO_GH_CFG);
}

/* ------------------------------------------------------------------ talking to cPHulk (one place, mockable) */

/** Run one whmapi1 call and return its decoded JSON, or null. Tests replace this through $GLOBALS['smpro_gh_api']. */
function smpro_gh_api(string $fn, array $args = []): ?array {
    if (isset($GLOBALS['smpro_gh_api']) && is_callable($GLOBALS['smpro_gh_api'])) return ($GLOBALS['smpro_gh_api'])($fn, $args);
    if (strpos($fn, 'conf:') === 0 || strpos($fn, 'queue:') === 0) return null;   // pseudo-calls exist for the mock only
    $bin = '/usr/local/cpanel/bin/whmapi1';
    if (!@is_executable($bin)) return null;
    $cmd = escapeshellarg($bin) . ' --output=json ' . escapeshellarg($fn);
    foreach ($args as $k => $v) $cmd .= ' ' . escapeshellarg($k . '=' . $v);
    $raw = function_exists('smpro_run') ? smpro_run($cmd, 60, ['stderr' => 'discard']) : (string)@shell_exec('timeout 60 ' . $cmd . ' 2>/dev/null');
    $j = json_decode((string)$raw, true);
    return is_array($j) ? $j : null;
}

function smpro_gh_api_ok(?array $j): bool { return is_array($j) && (int)($j['metadata']['result'] ?? 0) === 1; }

/** cPHulk's state as it is now: enabled?, country blacklist string, number of expanded blacklist ranges. */
function smpro_gh_hulk_state(): array {
    $st = ['enabled' => null, 'blacklist' => null, 'ranges' => null, 'why' => ''];
    $s = smpro_gh_api('cphulk_status');
    if (!smpro_gh_api_ok($s)) { $st['why'] = 'cPHulk did not answer (whmapi1 cphulk_status)'; return $st; }
    $st['enabled'] = !empty($s['data']['is_enabled']);
    // the country keys are not in load_cphulk_config; they live in cPHulk's own conf file (a mock answers conf: calls)
    $mock = smpro_gh_api('conf:country_blacklist');
    if (is_array($mock)) { $st['blacklist'] = (string)($mock['data']['value'] ?? ''); $st['ranges'] = isset($mock['data']['ranges']) ? (int)$mock['data']['ranges'] : null; return $st; }
    foreach (['/var/cpanel/cphulk.conf', '/var/cpanel/hulkd.conf'] as $f) {
        if (!@is_readable($f)) continue;
        foreach ((array)@file($f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $ln) {
            if (preg_match('/^\s*country_blacklist\s*=\s*(.*)$/', (string)$ln, $m)) { $st['blacklist'] = trim($m[1]); break 2; }
        }
        if ($st['blacklist'] === null) $st['blacklist'] = '';
    }
    $db = '/var/cpanel/hulkd/cphulk.sqlite';
    $sq = '';
    foreach (['/usr/bin/sqlite3', '/usr/local/cpanel/3rdparty/bin/sqlite3'] as $b) if (@is_executable($b)) { $sq = $b; break; }
    if ($sq !== '' && @is_readable($db)) {
        $n = trim((string)(function_exists('smpro_memo') ? smpro_memo('gh_ranges_n', 120, fn() => @shell_exec('timeout 10 ' . $sq . ' ' . escapeshellarg($db) . ' "select count(*) from ip_lists where TYPE=4" 2>/dev/null')) : @shell_exec('timeout 10 ' . $sq . ' ' . escapeshellarg($db) . ' "select count(*) from ip_lists where TYPE=4" 2>/dev/null')));   // 0.1 s per render on a large range table
        if (ctype_digit($n)) $st['ranges'] = (int)$n;
    }
    return $st;
}

/* ------------------------------------------------------------------ the list */

/** Every country code cPHulk can expand (from cPanel's own range database), cached for a day. */
function smpro_gh_all_codes(): array {
    $f = SMPRO_VARLIB . '/geohulk_codes.json';
    $j = @is_file($f) && time() - (int)@filemtime($f) < 86400 ? json_decode((string)@file_get_contents($f), true) : null;
    if (is_array($j) && count($j) > 100) return $j;
    $r = smpro_gh_api('get_countries_with_known_ip_ranges');
    $out = [];
    foreach ((array)($r['data']['countries'] ?? []) as $c) { $code = strtoupper((string)($c['code'] ?? '')); if (preg_match('/^[A-Z]{2}$/', $code)) $out[] = $code; }
    sort($out); $out = array_values(array_unique($out));
    if (count($out) > 100) @file_put_contents($f, json_encode($out));
    return $out ?: (is_array($j) ? $j : []);
}

/** The countries somebody is allowed to sign in from: the lock's list, its per-account lists, the home/caution regions. */
function smpro_gh_allowed(): array {
    $a = [];
    if (function_exists('smpro_gl_cfg')) {
        $g = smpro_gl_cfg();
        foreach ((array)($g['countries'] ?? []) as $c) $a[strtoupper((string)$c)] = 1;
        foreach ((array)($g['per_account'] ?? []) as $list) foreach ((array)$list as $c) $a[strtoupper((string)$c)] = 1;
    }
    if (function_exists('smpro_im_trusted_regions')) foreach (smpro_im_trusted_regions() as $c) $a[strtoupper((string)$c)] = 1;
    unset($a['']);
    $out = array_keys($a); sort($out);
    return $out;
}

/** What the blacklist must be: every known code that nobody is allowed from. Sorted, so equal sets compare equal. */
function smpro_gh_blacklist(array $allCodes, array $allowed): string {
    $al = array_flip(array_map('strtoupper', $allowed));
    $b = [];
    foreach ($allCodes as $c) { $c = strtoupper((string)$c); if ($c !== '' && !isset($al[$c])) $b[] = $c; }
    sort($b);
    return implode(',', array_values(array_unique($b)));
}

/* ------------------------------------------------------------------ arm / sync / disarm */

/** Can the wall be armed from this address without locking the operator out? */
function smpro_gh_arm_check(string $operatorIp): array {
    $problems = [];
    $allowed = smpro_gh_allowed();
    if (!$allowed) $problems[] = 'No country is allowed anywhere (Country Login Lock list, per-account exceptions, home region), so the wall would refuse everyone including you.';
    $cc = ($operatorIp !== '' && function_exists('smpro_gl_country')) ? strtoupper((string)smpro_gl_country($operatorIp)) : '';
    if ($operatorIp === '') $problems[] = 'Your own address is unknown to this request, so it cannot be whitelisted first.';
    if ($cc !== '' && !in_array($cc, $allowed, true)) $problems[] = 'You are connecting from ' . $cc . ', which is not allowed. Your address will be whitelisted in cPHulk so this session survives, but the next address you use from ' . $cc . ' will be refused.';
    $codes = smpro_gh_all_codes();
    if (count($codes) < 100) $problems[] = 'cPanel did not return its country list (whmapi1 get_countries_with_known_ip_ranges), so there is nothing to build the blacklist from.';
    $fatal = !$allowed || $operatorIp === '' || count($codes) < 100;
    return ['ok' => !$fatal, 'problems' => $problems, 'allowed' => $allowed, 'your_cc' => $cc, 'codes' => count($codes)];
}

function smpro_gh_arm(string $operatorIp, string $by = ''): array {
    $chk = smpro_gh_arm_check($operatorIp);
    if (!$chk['ok']) return ['ok' => false, 'msg' => 'Not armed - ' . implode(' ', $chk['problems']), 'check' => $chk];
    $cfg = smpro_gh_cfg();
    $st = smpro_gh_hulk_state();
    if ($st['enabled'] === null) return ['ok' => false, 'msg' => 'Not armed - ' . $st['why']];
    if ($cfg['prev_hulk_enabled'] === null) { $cfg['prev_hulk_enabled'] = $st['enabled']; $cfg['prev_blacklist'] = (string)$st['blacklist']; }
    // 1. the operator's own address first, so the arm cannot take the operator down with it
    $w = smpro_gh_api('create_cphulk_record', ['list_name' => 'white', 'ip' => $operatorIp, 'comment' => 'Safety Monitor Pro: operator who armed the door wall', 'skip_enabled_check' => 1]);
    if (!smpro_gh_api_ok($w)) return ['ok' => false, 'msg' => 'Not armed - your address could not be whitelisted in cPHulk (' . (string)($w['metadata']['reason'] ?? 'no answer') . ').'];
    // 2. cPHulk on
    if (!$st['enabled']) { $e = smpro_gh_api('enable_cphulk'); if (!smpro_gh_api_ok($e)) return ['ok' => false, 'msg' => 'Not armed - cPHulk could not be enabled (' . (string)($e['metadata']['reason'] ?? 'no answer') . ').']; }
    $cfg['enabled'] = true; $cfg['armed_at'] = time(); $cfg['armed_by_ip'] = $operatorIp; $cfg['last_error'] = '';
    smpro_gh_cfg_save($cfg);
    // 3. the list
    $s = smpro_gh_sync(true);
    if (function_exists('smpro_audit')) @smpro_audit('geohulk_arm', ['ok' => $s['ok'] ? 1 : 0, 'by' => $by, 'ip' => $operatorIp, 'blacklisted' => $s['count'] ?? 0]);
    return ['ok' => $s['ok'], 'msg' => $s['ok'] ? ('Armed. ' . (int)$s['count'] . ' countries are refused at the door; ' . count($chk['allowed']) . ' allowed (' . implode(', ', $chk['allowed']) . '). Your address ' . $operatorIp . ' is whitelisted in cPHulk.') : ('Armed but the list did not apply: ' . $s['msg']), 'check' => $chk];
}

/**
 * Addresses the door must never refuse: this server's own, everything on the operator's never-block list (csf.allow -
 * the same list the country wall honours), and, on a hub, the members of its fleet. Without this the lock refused a
 * sibling server in another country: every WHM API call it made counted as a failed login, cPHulk banned it for a
 * day, and its nftables set then dropped ALL traffic from that server - replies to this server's own requests too.
 */
function smpro_gh_trusted_ips(): array {
    $out = [];
    if (!function_exists('smpro_gw_always')) { $gf = __DIR__ . '/geowall.php'; if (is_file($gf)) require_once $gf; }
    if (function_exists('smpro_gw_always')) foreach (smpro_gw_always('') as $a) $out[(string)$a] = 1;
    $fl = SMPRO_VARLIB . '/hub/fleet.json';
    if (@is_file($fl)) {
        $j = json_decode((string)@file_get_contents($fl), true);
        foreach (array_slice((array)($j['snaps'] ?? []), 0, 50) as $snap) {
            $h = strtolower(trim((string)($snap['hostname'] ?? ''))); if ($h === '') continue;
            // a panel hostname such as 1-2-3-4.cprapid.com carries the address in its name; anything else is resolved
            $ip = preg_match('/^(\d{1,3})-(\d{1,3})-(\d{1,3})-(\d{1,3})\./', $h, $m) ? ($m[1] . '.' . $m[2] . '.' . $m[3] . '.' . $m[4]) : (string)@gethostbyname($h);
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) $out[$ip] = 1;
        }
    }
    unset($out['127.0.0.0/8']);
    return array_slice(array_keys($out), 0, 300);
}
/** Put every trusted address on cPHulk's white list (white beats the country blacklist) and clear its failure history.
 *  Hourly, or at once when csf.allow changed; each address is added once and remembered. */
function smpro_gh_whitelist_trusted(bool $force = false): array {
    $cfg = smpro_gh_cfg(); if (!$cfg['enabled']) return ['added' => 0, 'skipped' => 'off'];
    $at = (int)($cfg['trusted_at'] ?? 0); $allowM = (int)@filemtime('/etc/csf/csf.allow');
    if (!$force && $at > time() - 3600 && $allowM <= $at) return ['added' => 0, 'skipped' => 'recent'];
    $done = array_flip(array_map('strval', (array)($cfg['trusted_done'] ?? []))); $added = [];
    foreach (smpro_gh_trusted_ips() as $ip) {
        if (isset($done[$ip])) continue;
        $r = smpro_gh_api('create_cphulk_record', ['list_name' => 'white', 'ip' => $ip, 'comment' => 'Safety Monitor Pro: trusted (own address, csf.allow or fleet)', 'skip_enabled_check' => 1]);
        if (smpro_gh_api_ok($r) || stripos((string)($r['metadata']['reason'] ?? ''), 'already') !== false) {
            $done[$ip] = 1; $added[] = $ip;
            smpro_gh_api('flush_cphulk_login_history_for_ips', ['ip' => $ip]);
        }
    }
    $cfg = smpro_gh_cfg(); $cfg['trusted_done'] = array_keys($done); $cfg['trusted_at'] = time(); smpro_gh_cfg_save($cfg);
    if ($added && function_exists('smpro_audit')) @smpro_audit('geohulk_trusted_whitelisted', ['ips' => array_slice($added, 0, 50), 'count' => count($added)]);
    return ['added' => count($added)];
}

/** A country list as a set: upper case, no blanks or repeats, sorted. Two lists that hold the same codes are equal. */
function smpro_gh_norm($csv): string {
    $a = array_values(array_unique(array_filter(array_map(fn($x) => strtoupper(trim((string)$x)), preg_split('/[\s,]+/', (string)$csv)))));
    sort($a); return implode(',', $a);
}

/** Keep cPHulk's blacklist equal to "everything not allowed". Called every minute from the lock's tick; no-op when equal. */
/* ============================ cloud mail providers ============================
 * New Outlook, Gmail ("check mail from other accounts"), iCloud and Yahoo do not connect to IMAP/POP from the
 * customer's computer: the provider's own servers do, from its data centres abroad. With the country lock armed those
 * sign-ins are refused ("country is blacklisted"), the provider retries, and cPHulk then bans its address for a day in
 * nftables - so even after a whitelist the connection never arrives (cPHulk cannot remove a prefix from a set
 * without "flags interval", so the ban of each single address stays). Here: the provider's published ranges go on
 * cPHulk's whitelist, and every address of those ranges already banned (nftables cphulk-TempBan/PermBan) is removed
 * one by one with its failure history. Microsoft is on by default. The choice is shared with the other HostGuard
 * products through /var/lib/hostguard/cloud-mail.json: SM Pro is the one that writes cPHulk; another product adds a
 * provider by listing it in its own "requested" entry of that file, and SM Pro applies it on its next sync.
 */
function smpro_gh_mail_providers(): array {
    return [
        'microsoft' => ['Microsoft (Outlook, Office 365, Hotmail)', ['40.96.0.0/13', '40.104.0.0/15', '52.96.0.0/14', '13.107.6.152/31', '13.107.18.10/31', '13.107.128.0/22', '23.103.160.0/20', '132.245.0.0/16', '150.171.32.0/22', '131.253.33.215/32', '204.79.197.215/32']],
        'google'    => ['Google (Gmail)', ['209.85.128.0/17', '66.249.80.0/20', '74.125.0.0/16', '64.233.160.0/19', '108.177.8.0/21', '172.217.0.0/19', '173.194.0.0/16', '35.190.247.0/24']],
        'apple'     => ['Apple (iCloud Mail)', ['17.0.0.0/8']],
        'yahoo'     => ['Yahoo Mail', ['98.136.0.0/14', '67.195.0.0/16', '74.6.0.0/16']],
    ];
}
/** A name as people type it -> provider key, or ''. */
function smpro_gh_mail_provider_key(string $name): string {
    $n = strtolower(preg_replace('/[^a-z0-9]/i', '', $name));
    $map = ['microsoft' => 'microsoft', 'outlook' => 'microsoft', 'office365' => 'microsoft', 'o365' => 'microsoft', 'hotmail' => 'microsoft', 'live' => 'microsoft', 'exchange' => 'microsoft', 'msn' => 'microsoft',
            'google' => 'google', 'gmail' => 'google', 'gsuite' => 'google', 'workspace' => 'google', 'apple' => 'apple', 'icloud' => 'apple', 'yahoo' => 'yahoo', 'aol' => 'yahoo'];
    return $map[$n] ?? '';
}
function smpro_gh_in_cidr(string $ip, string $cidr): bool {
    if (strpos($cidr, '/') === false || !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return $ip === $cidr;
    [$net, $bits] = explode('/', $cidr, 2); $bits = (int)$bits;
    $mask = $bits === 0 ? 0 : (~0 << (32 - $bits)) & 0xFFFFFFFF;
    return (ip2long($ip) & $mask) === (ip2long($net) & $mask);
}
function smpro_gh_cloudmail_shared(): string { return defined('SMPRO_HG_DIR') ? rtrim(SMPRO_HG_DIR, '/') . '/cloud-mail.json' : '/var/lib/hostguard/cloud-mail.json'; }
/** Providers in force: this server's choice (Microsoft by default) plus what another HostGuard product requested. */
function smpro_gh_cloudmail_enabled(): array {
    $c = smpro_gh_cfg(); $on = isset($c['cloud_mail']) ? (array)$c['cloud_mail'] : ['microsoft'];
    $sh = function_exists('smpro_hg_read_json') ? smpro_hg_read_json(smpro_gh_cloudmail_shared()) : null;
    foreach ((array)($sh['requested'] ?? []) as $prod => $list) if ($prod !== 'smpro') foreach ((array)$list as $p) if (smpro_gh_mail_provider_key((string)$p) !== '') $on[] = smpro_gh_mail_provider_key((string)$p);
    return array_values(array_unique(array_intersect($on, array_keys(smpro_gh_mail_providers()))));
}
/** Whitelist the ranges (once per provider, again when forced) and lift every ban that already caught them. */
function smpro_gh_cloudmail_apply(bool $force = false): array {
    $c = smpro_gh_cfg(); $all = smpro_gh_mail_providers(); $on = smpro_gh_cloudmail_enabled(); $done = (array)($c['cloud_done'] ?? []); $added = 0; $lifted = [];
    $ranges = [];
    foreach ($on as $p) {
        foreach ($all[$p][1] as $r) $ranges[] = $r;
        if (!$force && !empty($done[$p])) continue;
        foreach ($all[$p][1] as $r) { smpro_gh_api('create_cphulk_record', ['list_name' => 'white', 'ip' => $r, 'comment' => 'hostguard-cloudmail:' . $p, 'skip_enabled_check' => 1]); $added++; }
        $done[$p] = time();
    }
    // lift bans inside the ranges (at most every 10 minutes unless forced)
    if ($ranges && ($force || (int)($c['cloud_sweep'] ?? 0) < time() - 600)) {
        foreach (['cphulk-TempBan', 'cphulk-PermBan'] as $set) {
            $o = (string)@shell_exec('timeout 20 nft list set inet filter ' . $set . ' 2>/dev/null');
            if (!preg_match_all('/\b(\d{1,3}(?:\.\d{1,3}){3})\b/', $o, $m)) continue;
            foreach (array_unique($m[1]) as $ip) foreach ($ranges as $r) if (smpro_gh_in_cidr($ip, $r)) {
                @shell_exec('timeout 10 nft delete element inet filter ' . $set . ' ' . escapeshellarg('{ ' . $ip . ' }') . ' 2>/dev/null');
                smpro_gh_api('flush_cphulk_login_history_for_ips', ['ip' => $ip]); $lifted[] = $ip; break;
            }
        }
        $c['cloud_sweep'] = time();
    }
    $c['cloud_done'] = $done; smpro_gh_cfg_save($c);
    if (function_exists('smpro_hg_json_write') && function_exists('smpro_hg_dir')) {
        smpro_hg_dir();
        $sh = (function_exists('smpro_hg_read_json') ? smpro_hg_read_json(smpro_gh_cloudmail_shared()) : null) ?: [];
        $sh['applied_by'] = 'smpro'; $sh['providers'] = $on; $sh['ranges'] = $ranges; $sh['at'] = time();
        $sh['requested'] = (array)($sh['requested'] ?? []); $sh['requested']['smpro'] = isset($c['cloud_mail']) ? (array)$c['cloud_mail'] : ['microsoft'];
        smpro_hg_json_write(smpro_gh_cloudmail_shared(), $sh, 0644);
    }
    if (($added || $lifted) && function_exists('smpro_audit')) smpro_audit('geohulk_cloudmail', ['providers' => $on, 'ranges_added' => $added, 'lifted' => array_slice($lifted, 0, 50)]);
    return ['providers' => $on, 'ranges_added' => $added, 'lifted' => $lifted];
}
/** Allow one more provider by name (page / Telegram bot). */
function smpro_gh_cloudmail_add(string $name): array {
    $k = smpro_gh_mail_provider_key($name);
    if ($k === '') return ['ok' => false, 'msg' => 'Unknown provider "' . $name . '". Known: microsoft (outlook, office365, hotmail), google (gmail), apple (icloud), yahoo.'];
    $c = smpro_gh_cfg(); $on = isset($c['cloud_mail']) ? (array)$c['cloud_mail'] : ['microsoft'];
    if (!in_array($k, $on, true)) $on[] = $k;
    $c['cloud_mail'] = array_values($on); unset($c['cloud_done'][$k]); smpro_gh_cfg_save($c);
    $r = smpro_gh_cloudmail_apply(true);
    return ['ok' => true, 'msg' => smpro_gh_mail_providers()[$k][0] . ' can now sign in to mail despite the country lock: ' . count(smpro_gh_mail_providers()[$k][1]) . ' range(s) whitelisted in cPHulk, ' . count($r['lifted']) . ' banned address(es) released.'];
}

function smpro_gh_sync(bool $force = false): array {
    smpro_gh_whitelist_trusted($force);   // first, and before the cfg read below, so its save is not overwritten
    smpro_gh_cloudmail_apply($force);     // cloud mail providers (Outlook, Gmail...) are not refused by the country lock
    $cfg = smpro_gh_cfg();
    if (!$cfg['enabled']) return ['ok' => true, 'msg' => 'off', 'count' => 0, 'changed' => false];
    $want = smpro_gh_blacklist(smpro_gh_all_codes(), smpro_gh_allowed());
    if ($want === '') { $cfg['last_error'] = 'every known country is allowed - nothing to refuse'; smpro_gh_cfg_save($cfg); return ['ok' => false, 'msg' => $cfg['last_error'], 'count' => 0, 'changed' => false]; }
    $st = smpro_gh_hulk_state();
    $hourly = function (string $k) use (&$cfg) { if ((int)($cfg[$k] ?? 0) >= time() - 3600) return false; $cfg[$k] = time(); return true; };
    if ($st['enabled'] === false && $hourly('last_reenable')) {
        // Someone switched cPHulk off underneath the wall. The wall is a decision the operator made on this page;
        // it is put back (once an hour at most: each enable reloads cPanel's web service), and the event is recorded.
        $e = smpro_gh_api('enable_cphulk');
        if (function_exists('smpro_audit')) @smpro_audit('geohulk_reenabled', ['ok' => smpro_gh_api_ok($e) ? 1 : 0]);
    }
    // ranges === null means the count could not be read (no sqlite); that is not "zero ranges".
    // Every write of cPHulk's config makes cPanel reload its web service (a HUP to cpsrvd), and a reload cuts any
    // upload or download running through cPanel at that moment. On a server where cPHulk's config file is not where it
    // is looked for, the stored list read as "nothing" and the list was rewritten every minute - every File Manager
    // upload longer than a minute failed. So: compare the lists as sets; when the stored list cannot be read, compare
    // with the list this sync applied last; and the two "cannot tell" cases re-apply at most once an hour.
    $have = $st['blacklist'] !== null ? (string)$st['blacklist'] : (string)($cfg['last_blacklist'] ?? '');
    $changed = $force || smpro_gh_norm($have) !== smpro_gh_norm($want)
        || (($st['ranges'] === 0 || $st['blacklist'] === null) && $hourly('last_reapply'));
    if ($changed) {
        $r = smpro_gh_api('set_cphulk_config_key', ['key' => 'country_blacklist', 'value' => $want]);
        if (!smpro_gh_api_ok($r)) { $cfg['last_error'] = 'cPHulk refused the country list: ' . (string)($r['metadata']['reason'] ?? 'no answer'); smpro_gh_cfg_save($cfg); return ['ok' => false, 'msg' => $cfg['last_error'], 'count' => 0, 'changed' => false]; }
        smpro_gh_queue_expand();
    }
    $cfg['last_sync'] = time(); $cfg['last_blacklist'] = $want; $cfg['last_error'] = '';
    smpro_gh_cfg_save($cfg);
    return ['ok' => true, 'msg' => $changed ? 'list applied' : 'unchanged', 'count' => substr_count($want, ',') + 1, 'changed' => $changed];
}

/** Ask cPHulk to expand the code list into ranges now rather than at its next config check. */
function smpro_gh_queue_expand(): void {
    if (isset($GLOBALS['smpro_gh_api']) && is_callable($GLOBALS['smpro_gh_api'])) { ($GLOBALS['smpro_gh_api'])('queue:update_country_ips', []); return; }
    $q = '/usr/local/cpanel/bin/servers_queue';
    if (@is_executable($q)) @shell_exec('timeout 30 ' . $q . ' queue cPHulkTasks update_country_ips >/dev/null 2>&1');
}

function smpro_gh_disarm(string $by = ''): array {
    $cfg = smpro_gh_cfg();
    $prevBl = $cfg['prev_blacklist']; $prevOn = $cfg['prev_hulk_enabled'];
    $r = smpro_gh_api('set_cphulk_config_key', ['key' => 'country_blacklist', 'value' => (string)($prevBl ?? '')]);
    $ok = smpro_gh_api_ok($r);
    if ($ok) smpro_gh_queue_expand();
    if ($ok && $prevOn === false) { smpro_gh_api('disable_cphulk'); }        // it was off before this wall turned it on
    $cfg['enabled'] = false; $cfg['prev_hulk_enabled'] = null; $cfg['prev_blacklist'] = null; $cfg['last_blacklist'] = ''; $cfg['last_error'] = $ok ? '' : 'the country list could not be restored';
    smpro_gh_cfg_save($cfg);
    if (function_exists('smpro_audit')) @smpro_audit('geohulk_disarm', ['ok' => $ok ? 1 : 0, 'by' => $by, 'hulk_left' => $prevOn === false ? 'off (as before)' : 'on']);
    return ['ok' => $ok, 'msg' => $ok ? ('Disarmed. cPHulk\'s country list is back to what it was' . ($prevOn === false ? ' and cPHulk is off again, as it was before.' : '.')) : 'The wall is marked off but cPHulk\'s country list could not be restored - check cPHulk in WHM.'];
}

/** Is the door actually refusing right now? Every "no" carries its reason. */
function smpro_gh_status(): array {
    $cfg = smpro_gh_cfg();
    if (!$cfg['enabled']) return ['ok' => false, 'state' => 'off', 'why' => 'off', 'cfg' => $cfg];
    $st = smpro_gh_hulk_state();
    if ($st['enabled'] === null) return ['ok' => false, 'state' => 'unknown', 'why' => $st['why'], 'cfg' => $cfg];
    if ($st['enabled'] === false) return ['ok' => false, 'state' => 'hulk_off', 'why' => 'cPHulk is switched off, so nothing is refused at the door', 'cfg' => $cfg];
    $want = $cfg['last_blacklist'];
    if ($want !== '' && $st['blacklist'] !== null && $st['blacklist'] !== $want) return ['ok' => false, 'state' => 'drift', 'why' => 'cPHulk\'s country list differs from the wall\'s (' . substr_count((string)$st['blacklist'], ',') . ' vs ' . substr_count($want, ',') . ' codes) - the next sync puts it back', 'cfg' => $cfg];
    if ($st['ranges'] !== null && $st['ranges'] === 0) return ['ok' => false, 'state' => 'unexpanded', 'why' => 'cPHulk has the code list but has not expanded it into address ranges yet (its queue task runs within a minute)', 'cfg' => $cfg];
    if (time() - (int)$cfg['last_sync'] > 600) return ['ok' => false, 'state' => 'stale', 'why' => 'the wall has not been synced for ' . intdiv(time() - (int)$cfg['last_sync'], 60) . ' minutes - is the Country Login Lock tick running?', 'cfg' => $cfg];
    return ['ok' => true, 'state' => 'armed', 'why' => '', 'cfg' => $cfg, 'ranges' => $st['ranges'], 'countries' => substr_count($want, ',') + 1, 'allowed' => smpro_gh_allowed()];
}
