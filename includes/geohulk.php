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

/** Keep cPHulk's blacklist equal to "everything not allowed". Called every minute from the lock's tick; no-op when equal. */
function smpro_gh_sync(bool $force = false): array {
    $cfg = smpro_gh_cfg();
    if (!$cfg['enabled']) return ['ok' => true, 'msg' => 'off', 'count' => 0, 'changed' => false];
    $want = smpro_gh_blacklist(smpro_gh_all_codes(), smpro_gh_allowed());
    if ($want === '') { $cfg['last_error'] = 'every known country is allowed - nothing to refuse'; smpro_gh_cfg_save($cfg); return ['ok' => false, 'msg' => $cfg['last_error'], 'count' => 0, 'changed' => false]; }
    $st = smpro_gh_hulk_state();
    if ($st['enabled'] === false) {
        // Someone switched cPHulk off underneath the wall. The wall is a decision the operator made on this page;
        // it is put back, and the event is recorded so the two decisions can be reconciled by a person.
        $e = smpro_gh_api('enable_cphulk');
        if (function_exists('smpro_audit')) @smpro_audit('geohulk_reenabled', ['ok' => smpro_gh_api_ok($e) ? 1 : 0]);
    }
    // ranges === null means the count could not be read (no sqlite); that is not "zero ranges".
    $changed = $force || $st['blacklist'] !== $want || $st['ranges'] === 0;
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
