<?php
/**
 * includes/geowall.php - real prevention: a login door that a disallowed country cannot reach at all.
 *
 * WHAT THIS IS, AND WHY IT IS NOT THE COUNTRY LOGIN LOCK.
 *
 * Country Login Lock reads the login log and closes an address's login ports AFTERWARDS. The first sign-in from
 * a country that is not allowed always succeeds - an operator armed it, signed in over a VPN in a third country,
 * and was let straight in, exactly as designed. What was wanted is different: the connection must never reach
 * sshd or the panel in the first place, while ordinary web browsing on 80/443 stays open to the whole world.
 *
 * WHY CSF'S OWN SETTING IS NOT ENOUGH.
 *
 * CC_ALLOW_PORTS looks like the answer and is not. Read in csf's source, it appends ACCEPT rules for the listed
 * countries on the listed ports - an early accept. Everything else falls through to the normal TCP_IN rules and
 * is let in as usual. It allows; it does not deny. CC_DENY_PORTS is the mirror image: it denies a list, so
 * getting "everyone except two countries" out of it means naming ~250 countries and leaves every address that is
 * in no zone file allowed anyway.
 *
 * WHAT THIS DOES.
 *
 * One ipset holding the address ranges of the allowed countries, and ONE rule per protocol: on the login ports,
 * anything not in that set is dropped. Default-deny, so an address that cannot be placed in any country is
 * refused rather than waved through - the opposite of the reporting features, and deliberately so. A report that
 * guesses is noise; a door that guesses is an open door.
 *
 * Ports 80 and 443 are never included and cannot be added. A shop stays readable and buyable from every country.
 *
 * THE LOCK-OUT PROBLEM, WHICH IS THE WHOLE DIFFICULTY.
 *
 * This rule can shut the operator out of their own server, SSH included, with no way back except the hosting
 * provider's console. So:
 *
 *   - It is off until it is turned on, and arming is REFUSED unless the operator's current address is inside the
 *     allowed set.
 *   - Every address on csf.allow is added to the set, so existing decisions outrank this.
 *   - It carries a DEAD MAN'S SWITCH. The rule is removed automatically unless something keeps saying the
 *     operator is still there. Lock yourself out and it lets you back in without anyone touching the console.
 *
 * Nothing here names a country, an address or a network: the allowed list is the operator's, and the ranges come
 * from the firewall's own country data.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }
// The country-code cleaner lives in geologin.php. The wall's config read and write used to call it only when it
// happened to be loaded, and on every page except Firewall it was not: the layout's dead-man heartbeat then saved
// the config with countries = [] - the wall disarmed itself at the next tick and re-arms refused ("No country is
// allowed"). The helper is loaded here, and a local cleaner stands in if it ever is not.
if (!function_exists('smpro_gl_clean_cc')) { $glf = __DIR__ . '/geologin.php'; if (is_file($glf)) require_once $glf; }
function smpro_gw_clean_cc(array $in): array {
    if (function_exists('smpro_gl_clean_cc')) return smpro_gl_clean_cc($in);
    $out = []; foreach ($in as $c) { $c = strtoupper(preg_replace('/[^A-Za-z]/', '', (string)$c)); if (strlen($c) === 2) $out[$c] = 1; } return array_keys($out);
}

if (!defined('SMPRO_GW_CFG'))  define('SMPRO_GW_CFG',  SMPRO_VARLIB . '/geowall.json');
if (!defined('SMPRO_GW_LOG'))  define('SMPRO_GW_LOG',  SMPRO_VARLOG . '/geowall.log');
if (!defined('SMPRO_GW_SET'))  define('SMPRO_GW_SET',  'smpro_geo_ok');
if (!defined('SMPRO_GW_MARK')) define('SMPRO_GW_MARK', 'SMPRO_GEOWALL');

/** The login doors. 80 and 443 are absent and smpro_gw_ports() can never return them. */
function smpro_gw_doors(): array {
    return [
        'cpanel'  => ['name' => 'cPanel',                'ports' => [2082, 2083]],
        'whm'     => ['name' => 'WHM',                   'ports' => [2086, 2087]],
        'webmail' => ['name' => 'Webmail',               'ports' => [2095, 2096]],
        'mail'    => ['name' => 'Mail (IMAP/POP/SMTP)',  'ports' => [110, 143, 465, 587, 993, 995]],
        'ftp'     => ['name' => 'FTP (file uploads)',    'ports' => [21]],
        'ssh'     => ['name' => 'SSH / SFTP',            'ports' => [22]],
    ];
}

function smpro_gw_defaults(): array {
    return [
        'enabled'   => false,
        'countries' => [],
        'doors'     => ['cpanel', 'whm', 'webmail', 'ftp', 'ssh'],   // mail off by default: phones roam
        'deadman_minutes' => 60,   // the rule lifts itself if nobody confirms they are still in
        'last_seen' => 0,
        // The address the wall was armed from. A reboot clears ipset and iptables, and the wall has to come
        // back by itself - but re-asserting needs an operator address to prove the set still contains, and
        // cron has no browser. The one proven at arm time is the honest answer; nothing else is.
        'armed_from' => '',
        'set_size'   => 0,    // members the address set had when it was built; the watcher compares the live set with it
    ];
}

function smpro_gw_cfg(): array {
    $d = smpro_gw_defaults();
    $j = @json_decode((string)@file_get_contents(SMPRO_GW_CFG), true);
    if (!is_array($j)) return $d;
    $out = array_replace($d, array_intersect_key($j, $d));
    $out['enabled']   = !empty($j['enabled']);
    $out['countries'] = smpro_gw_clean_cc((array)($j['countries'] ?? []));
    $out['doors']     = array_values(array_intersect((array)($j['doors'] ?? []), array_keys(smpro_gw_doors())));
    $out['deadman_minutes'] = max(5, min(10080, (int)($j['deadman_minutes'] ?? 60)));
    $out['last_seen'] = (int)($j['last_seen'] ?? 0);
    $ip = (string)($j['armed_from'] ?? '');
    $out['armed_from'] = filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '';
    $out['set_size']   = max(0, (int)($j['set_size'] ?? 0));
    return $out;
}

function smpro_gw_save(array $cfg): bool {
    $c = array_replace(smpro_gw_cfg(), $cfg);
    $c['enabled']   = !empty($cfg['enabled']);
    $c['countries'] = smpro_gw_clean_cc((array)($c['countries'] ?? []));
    $c['doors']     = array_values(array_intersect((array)$c['doors'], array_keys(smpro_gw_doors())));
    // Carried explicitly. Every other field is rewritten from the patch, and armed_from is the one value
    // that is written by apply() rather than by the page - so a save that forgot it erased the only
    // record of an address a person had proven.
    $c['armed_from'] = filter_var((string)($cfg['armed_from'] ?? $c['armed_from'] ?? ''), FILTER_VALIDATE_IP)
                     ? (string)($cfg['armed_from'] ?? $c['armed_from']) : (string)($c['armed_from'] ?? '');
    // The first time a wall goes up it may not be left unreachable for a working day. The window can be
    // widened later, once the operator has seen it let them back in.
    $firstTime = ((string)($c['armed_from'] ?? '') === '');
    $c['deadman_minutes'] = max(5, min($firstTime ? 60 : 10080, (int)$c['deadman_minutes']));
    $c['set_size'] = max(0, (int)($cfg['set_size'] ?? $c['set_size'] ?? 0));
    @is_dir(SMPRO_VARLIB) || @mkdir(SMPRO_VARLIB, 0700, true);
    $t = SMPRO_GW_CFG . '.tmp';
    if (@file_put_contents($t, json_encode($c, JSON_UNESCAPED_SLASHES), LOCK_EX) === false) return false;
    @chmod($t, 0600);
    $ok = @rename($t, SMPRO_GW_CFG);
    if ($ok && function_exists('smpro_audit')) smpro_audit('geowall_saved', $c);
    return $ok;
}

/** The ports this configuration covers. 80/443 are removed unconditionally, whatever the stored doors say. */
function smpro_gw_ports(array $cfg): array {
    $all = smpro_gw_doors(); $p = [];
    foreach ((array)$cfg['doors'] as $d) foreach ((array)($all[$d]['ports'] ?? []) as $x) $p[(int)$x] = 1;
    unset($p[80], $p[443]);     // a site must stay readable and buyable from every country on earth
    ksort($p);
    return array_keys($p);
}

/** The firewall's own country ranges. Empty means the data is not there - which is "cannot build", not "allow all". */
function smpro_gw_ranges(array $ccs): array {
    $out = [];
    foreach ($ccs as $cc) {
        $f = '/var/lib/csf/zone/' . strtolower(preg_replace('/[^A-Za-z]/', '', $cc)) . '.zone';
        if (!@is_readable($f)) continue;
        foreach ((array)@file($f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#') continue;
            if (preg_match('#^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$#', $line)) $out[$line] = 1;
        }
    }
    return array_keys($out);
}

/** Which of the configured countries have no range data yet. */
function smpro_gw_missing(array $ccs): array {
    $miss = [];
    foreach ($ccs as $cc) {
        $f = '/var/lib/csf/zone/' . strtolower($cc) . '.zone';
        if (!@is_readable($f) || (int)@filesize($f) < 10) $miss[] = strtoupper($cc);
    }
    return $miss;
}

/**
 * Addresses that must always get through, whatever the country list says.
 *
 * THE SERVER'S OWN ADDRESSES COME FIRST, and they were missing. Armed on a live server this dropped the machine's
 * traffic to itself: cPanel talking to its own services, AutoSSL, mail handed between local daemons - every one
 * of them connects to the public address or to loopback, and neither was in the set. The operator saw "the
 * services fell over". The services were running; the server had been told to refuse itself.
 *
 * A wall that has to be told which countries may reach a door must never need to be told that the door's own
 * house may reach it.
 */
function smpro_gw_always(string $myIp = ''): array {
    $out = ['127.0.0.0/8' => 1];                      // loopback, always, before anything else is considered
    foreach (preg_split('/\s+/', trim((string)@shell_exec('hostname -I 2>/dev/null'))) as $own) {
        $own = trim((string)$own);
        if ($own !== '' && filter_var($own, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) $out[$own] = 1;
    }
    // Belt and braces: hostname -I can be empty in a container or a stripped image, so the addresses the kernel
    // actually holds are read as well. An empty answer here would otherwise wall the machine off from itself.
    foreach (explode("\n", (string)@shell_exec("ip -4 -o addr show scope global 2>/dev/null | awk '{print \$4}'")) as $cidr) {
        $cidr = trim($cidr);
        if ($cidr === '') continue;
        $ip = explode('/', $cidr)[0];
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) $out[$ip] = 1;
    }
    if ($myIp !== '' && filter_var($myIp, FILTER_VALIDATE_IP)) $out[$myIp] = 1;
    foreach ((array)@file('/etc/csf/csf.allow', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $line = trim((string)$line);
        if ($line === '' || $line[0] === '#') continue;
        $tok = preg_split('/[\s#]+/', $line)[0];
        if (preg_match('#^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$#', (string)$tok)) $out[$tok] = 1;
    }
    return array_keys($out);
}

/**
 * Refuse to arm unless the operator is certainly inside. Checked BEFORE anything is written.
 *
 * Being shut out of the panel AND ssh by the same rule is the one failure with no recovery from inside this
 * server. Every other guard in this file exists because of it.
 */
function smpro_gw_arm_check(array $cfg, string $myIp): array {
    $p = [];
    $ccs = (array)$cfg['countries'];
    if (!$ccs) $p[] = 'No country is allowed, so nobody could sign in at all.';
    if (!smpro_gw_ports($cfg)) $p[] = 'No door is selected, so the rule would cover nothing.';

    $miss = smpro_gw_missing($ccs);
    if ($miss) $p[] = 'The firewall has no address ranges yet for ' . implode(', ', $miss)
                    . ' — arming now would shut those countries out too. Press "Fetch the ranges" first.';

    if ($myIp === '' || !filter_var($myIp, FILTER_VALIDATE_IP)) {
        $p[] = 'Your own address could not be determined, so it cannot be proven to survive this rule.';
    } else {
        $ranges = smpro_gw_ranges($ccs); $always = smpro_gw_always($myIp);
        $ok = in_array($myIp, $always, true) || smpro_gw_ip_in($myIp, $ranges);
        if (!$ok) $p[] = 'Your address (' . $myIp . ') is not inside the allowed countries. Arming would lock you out of SSH and the panel at the same time.';
        // csf.allow is honoured by CSF BEFORE this wall's rules and survives a CSF restart; the wall's own set does
        // not. The operator's address must be there, or a firewall restart can shut the operator out.
        $inAllow = false;
        foreach ((array)@file('/etc/csf/csf.allow', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) { $line = trim((string)$line); if ($line === '' || $line[0] === '#') continue; if (preg_split('/[\s#]+/', $line)[0] === $myIp) { $inAllow = true; break; } }
        if (!$inAllow) $p[] = 'Your address (' . $myIp . ') is not in csf.allow. Add it first (Firewall > Allow my IP): csf.allow is honoured before this wall and survives a firewall restart; the wall\'s own set does not.';
        $unc = smpro_gw_uncovered_logins($ccs, $ranges, $always);
        if ($unc) { $lst = []; foreach (array_slice($unc, 0, 5, true) as $ip => $cc) $lst[] = $ip . ' (' . $cc . ')'; $p[] = 'The firewall\'s range list is incomplete: ' . count($unc) . ' address(es) that signed in from an allowed country in the last 7 days would be refused - ' . implode(', ', $lst) . (count($unc) > 5 ? ', ...' : '') . '. Refresh the firewall\'s country data (csf -r) and try again.'; }
    }
    return ['ok' => !$p, 'problems' => $p];
}

/** Members the live set holds right now (0 = empty or missing). */
function smpro_gw_set_size(): int { return (int)trim((string)@shell_exec('ipset list ' . escapeshellarg(SMPRO_GW_SET) . ' 2>/dev/null | grep -c ^[0-9]')); }
/** The LOG rule that sits just above the drop: what the wall refused, rate-limited, read back by the watcher. */
function smpro_gw_log_args(array $ports): string {
    return '-p tcp -m multiport --dports ' . implode(',', $ports) . ' -m conntrack --ctstate NEW -m set ! --match-set ' . SMPRO_GW_SET . ' src'
         . ' -m limit --limit 30/min --limit-burst 60 -m comment --comment ' . SMPRO_GW_MARK . '_LOG -j LOG --log-prefix "SMPRO_GEOWALL_DROP: " --log-level 4';
}
/**
 * The addresses the wall refused in the last $minutes, with what THIS product's own geo database says about each.
 * Read from the kernel log (the LOG rule above). Pure over the lines; the lookup is local.
 * @return array{total:int, allowed:array<string,string>}  allowed = ip => country, for countries the wall is supposed to let in
 */
function smpro_gw_dropped(int $minutes, array $ccs, ?string $raw = null): array {
    if ($raw === null) {
        $raw = (string)@shell_exec('timeout 20 journalctl -k --since ' . escapeshellarg('-' . max(1, $minutes) . 'min') . ' --no-pager 2>/dev/null | grep -a SMPRO_GEOWALL_DROP');
        if (trim($raw) === '' && @is_readable('/var/log/messages')) $raw = (string)@shell_exec('timeout 20 tail -n 20000 /var/log/messages 2>/dev/null | grep -a SMPRO_GEOWALL_DROP');
    }
    $seen = []; foreach (explode("\n", $raw) as $l) if (preg_match('/SRC=(\d{1,3}(?:\.\d{1,3}){3})/', $l, $m)) $seen[$m[1]] = 1;
    $out = ['total' => count($seen), 'allowed' => []];
    $ccs = array_map('strtoupper', $ccs);
    foreach (array_keys($seen) as $ip) {
        $cc = function_exists('smpro_gl_country') ? strtoupper((string)smpro_gl_country($ip)) : '';
        if ($cc !== '' && in_array($cc, $ccs, true)) $out['allowed'][$ip] = $cc;
    }
    return $out;
}
/**
 * The CSF post-start hook: CSF flushes every ipset when it restarts (LF_IPSET), ours included, while the iptables
 * rules that point at the set stay - an empty set behind "drop what is not in the set" drops everyone. Seen on a
 * production server: an overnight LFD restart emptied the set and every customer outside csf.allow lost mail and
 * the panel until a person noticed. The hook re-asserts the wall the moment CSF has finished, and the watcher
 * below is the second line.
 */
function smpro_gw_hook_install(): bool {
    if (defined('SMPRO_TEST_SRC')) return true;
    if (!is_dir('/etc/csf')) return false;
    $f = is_file('/usr/local/csf/bin/csfpost.sh') ? '/usr/local/csf/bin/csfpost.sh' : '/etc/csf/csfpost.sh';
    $php = function_exists('smpro_php_cli_bin') ? smpro_php_cli_bin() : '/usr/local/cpanel/3rdparty/bin/php';
    $tag = '# ' . SMPRO_GW_MARK . ' re-assert';
    $block = $tag . " (Safety Monitor Pro): CSF emptied every ipset on restart; put the country wall's set back now, not at the next tick\n"
           . "timeout 90 $php " . SMPRO_BASE . "/bin/geowall_tick.php >/dev/null 2>&1 || true\n";
    $cur = @is_file($f) ? (string)@file_get_contents($f) : "#!/usr/bin/env bash\n";
    $lines = explode("\n", $cur); $out = []; $i = 0; $had = false;
    while ($i < count($lines)) { if (strpos($lines[$i], $tag) === 0) { $had = true; $i += 2; continue; } $out[] = $lines[$i]; $i++; }
    if ($had && isset($lines[1]) && strpos($lines[1], $tag) === 0) return true;
    $first = ($out && strpos($out[0], '#!') === 0) ? array_shift($out) : '#!/usr/bin/env bash';
    $new = $first . "\n" . trim($block) . "\n" . ltrim(implode("\n", $out), "\n");
    if (@file_put_contents($f, rtrim($new, "\n") . "\n", LOCK_EX) === false) return false;
    @chmod($f, 0700);
    return true;
}
function smpro_gw_hook_present(): bool {
    foreach (['/usr/local/csf/bin/csfpost.sh', '/etc/csf/csfpost.sh'] as $f) if (@is_file($f) && strpos((string)@file_get_contents($f), '# ' . SMPRO_GW_MARK . ' re-assert') !== false) return true;
    return false;
}
/**
 * Would this address set shut out people who signed in from an allowed country lately? The list of ranges comes
 * from the firewall's country data; when it is incomplete for a country (a whole ISP block missing) the only honest
 * test is against addresses that REALLY signed in from there. Returns the uncovered ones (ip => country).
 */
function smpro_gw_uncovered_logins(array $ccs, array $ranges, array $always, int $days = 7): array {
    if (!function_exists('smpro_lf_success')) { $lf = __DIR__ . '/loginfeed.php'; if (@is_file($lf)) require_once $lf; }
    if (!function_exists('smpro_lf_success') || !function_exists('smpro_gl_country')) return [];
    $ccs = array_map('strtoupper', $ccs); $out = [];
    foreach ((array)(smpro_lf_success(time() - $days * 86400, 40000)['events'] ?? []) as $e) {
        $ip = (string)($e['ip'] ?? ''); if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) || isset($out[$ip])) continue;
        if ($ip === '127.0.0.1') continue;
        $cc = strtoupper((string)smpro_gl_country($ip)); if ($cc === '' || !in_array($cc, $ccs, true)) continue;
        if (in_array($ip, $always, true) || smpro_gw_ip_in($ip, $ranges)) continue;
        $out[$ip] = $cc;
    }
    return $out;
}

/** Is an address inside any of these CIDRs? Plain IPv4 arithmetic - no shelling out for a membership test. */
function smpro_gw_ip_in(string $ip, array $cidrs): bool {
    $n = ip2long($ip);
    if ($n === false) return false;
    foreach ($cidrs as $c) {
        if (strpos($c, '/') === false) { if ($c === $ip) return true; continue; }
        [$net, $bits] = explode('/', $c, 2);
        $nn = ip2long($net); $bits = (int)$bits;
        if ($nn === false || $bits < 0 || $bits > 32) continue;
        $mask = $bits === 0 ? 0 : (-1 << (32 - $bits));
        if ((($n & $mask) & 0xFFFFFFFF) === (($nn & $mask) & 0xFFFFFFFF)) return true;
    }
    return false;
}

/** Note that the operator is still reachable. The dead man's switch reads this. */
function smpro_gw_heartbeat(int $at = 0): void {
    $c = smpro_gw_cfg();
    $at = $at ?: time();
    if ($at <= (int)$c['last_seen']) return;
    $c['last_seen'] = $at;
    smpro_gw_save($c);
}

/**
 * Proof the operator can still reach this panel, read from cPanel's own record rather than from one page:
 * the newest WHM session root opened by signing in from OUTSIDE the server (session_log NEW ... app=whostmgrd,
 * method=handle_form_login, an address that is not the machine's own). Any page of this product being rendered
 * for a remote address counts too (the layout calls the heartbeat). The wall used to be fed ONLY by the Firewall
 * page's own two-minute poll, so closing the browser was indistinguishable from being locked out: the wall
 * took itself down a quarter of an hour after every visit.
 */
function smpro_gw_reachability_proof(int $since): int {
    $f = '/usr/local/cpanel/logs/session_log';
    $h = @fopen($f, 'rb'); if (!$h) return 0;
    $size = (int)@filesize($f); $tail = 2 * 1024 * 1024;              // the last 2 MB holds days of sessions on a busy box
    if ($size > $tail) @fseek($h, $size - $tail);
    $best = 0;
    while (($l = fgets($h, 4096)) !== false) {
        if (strpos($l, ' NEW ') === false || strpos($l, 'app=whostmgrd') === false || strpos($l, 'method=handle_form_login') === false) continue;
        if (!preg_match('/^\[([^\]]+)\].*address=([0-9a-fA-F.:]+),/', $l, $m)) continue;
        $ip = $m[2]; if ($ip === '127.0.0.1' || $ip === '::1' || $ip === '') continue;
        if (function_exists('smpro_gl_exempt') && smpro_gl_exempt($ip) === 'this server\'s own address') continue;
        $ts = (int)strtotime($m[1]); if ($ts > $since && $ts > $best) $best = $ts;
    }
    fclose($h);
    return $best;
}

/* =====================================================================================================
 * APPLYING IT. Everything above decides; only this part writes.
 * ===================================================================================================== */

/** The one rule, as iptables would write it. Built in one place so apply, remove and preview cannot disagree. */
/**
 * The rules that must come BEFORE the drop, and why each one exists.
 *
 * Without them the drop rule cuts traffic that was already flowing and traffic that never left the machine. On a
 * live server that is not "logins are blocked": it is sessions dying mid-request and local daemons failing to
 * reach each other, which is what "the services fell over" actually was.
 */
function smpro_gw_pre_rules(array $ports): array {
    $p = '-p tcp -m multiport --dports ' . implode(',', array_map('intval', array_slice($ports, 0, 15)));
    return [
        // Anything already talking keeps talking. A country rule decides who may START a connection; ending the
        // ones in flight is collateral damage with no security value - the decision was already made for them.
        $p . ' -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT -m comment --comment ' . SMPRO_GW_MARK . '_EST',
        // The machine's own traffic never leaves it and has no country.
        '-i lo ' . $p . ' -j ACCEPT -m comment --comment ' . SMPRO_GW_MARK . '_LO',
    ];
}

function smpro_gw_rule_args(array $ports): string {
    // multiport takes at most 15 ports per rule. The door list cannot reach that, and the cap is applied here
    // rather than discovered as a silent iptables error at 3am.
    $ports = array_slice($ports, 0, 15);
    return '-p tcp -m multiport --dports ' . implode(',', array_map('intval', $ports))
         . ' -m set ! --match-set ' . SMPRO_GW_SET . ' src -j DROP'
         . ' -m comment --comment ' . SMPRO_GW_MARK;
}

/** Is the rule live right now? Asked of iptables, never assumed from the config. */
function smpro_gw_live(): bool {
    $out = (string)@shell_exec('timeout 10 iptables -S INPUT 2>/dev/null');
    return strpos($out, SMPRO_GW_MARK) !== false;
}

/**
 * Put the wall up. Returns what it did, and refuses rather than half-applying.
 *
 * Order is the difference between a wall and a lock-out: the SET is filled FIRST and proven to contain the
 * operator, and only then is the DROP rule inserted. Inserting first would leave a window in which the rule is
 * live against an empty set - every address on earth denied, including the one that asked for it.
 */
function smpro_gw_apply(array $cfg, string $myIp, bool $dry = false): array {
    $r = ['ok' => false, 'dry' => $dry, 'ranges' => 0, 'always' => 0, 'ports' => [], 'msg' => ''];
    // Re-asserting from cron has no browser and therefore no address. Fall back to the one this wall was
    // ARMED from - already proven to be inside the set by a human at the time - rather than skipping the
    // check, which would let a reboot bring up a wall nobody has ever been shown to survive.
    if ($myIp === '') $myIp = (string)($cfg['armed_from'] ?? '');
    $chk = smpro_gw_arm_check($cfg, $myIp);
    if (!$chk['ok']) { $r['msg'] = implode(' ', $chk['problems']); return $r; }

    $ports  = smpro_gw_ports($cfg);
    $ranges = smpro_gw_ranges((array)$cfg['countries']);
    $always = smpro_gw_always($myIp);
    $r['ports'] = $ports; $r['ranges'] = count($ranges); $r['always'] = count($always);

    if (!$ranges) { $r['msg'] = 'No address ranges were loaded, so the set would be empty and everything would be denied. Refused.'; return $r; }
    if (!smpro_gw_ip_in($myIp, $ranges) && !in_array($myIp, $always, true)) {
        $r['msg'] = 'Your address is not in the set that would be built. Refused.'; return $r;
    }
    if ($dry) {
        $r['ok'] = true;
        $r['msg'] = count($ranges) . ' range(s) plus ' . count($always) . ' always-allowed address(es), on '
                  . count($ports) . ' port(s). Nothing was changed.';
        return $r;
    }
    if (trim((string)@shell_exec('command -v ipset 2>/dev/null')) === '') {
        $r['msg'] = 'ipset is not installed on this server.'; return $r;
    }

    // Built under a TEMP name and swapped in atomically: a rebuild must never leave the live set half-filled
    // while the DROP rule is already matching against it.
    $tmpSet = SMPRO_GW_SET . '_new';
    @shell_exec('ipset destroy ' . escapeshellarg($tmpSet) . ' 2>/dev/null');
    @shell_exec('ipset create ' . escapeshellarg($tmpSet) . ' hash:net family inet maxelem 262144 2>/dev/null');

    $batch = '';
    foreach (array_merge($ranges, $always) as $c) $batch .= 'add ' . $tmpSet . ' ' . $c . ' -exist' . PHP_EOL;
    $bf = tempnam(sys_get_temp_dir(), 'smprogw');
    @file_put_contents($bf, $batch);
    @shell_exec('ipset restore -exist < ' . escapeshellarg($bf) . ' 2>/dev/null');
    @unlink($bf);

    $n = (int)trim((string)@shell_exec('ipset list ' . escapeshellarg($tmpSet) . ' 2>/dev/null | grep -c ^[0-9]'));
    if ($n < 1) {
        @shell_exec('ipset destroy ' . escapeshellarg($tmpSet) . ' 2>/dev/null');
        $r['msg'] = 'The set came out empty. Refused rather than applied.'; return $r;
    }

    @shell_exec('ipset create ' . escapeshellarg(SMPRO_GW_SET) . ' hash:net family inet maxelem 262144 2>/dev/null');
    @shell_exec('ipset swap ' . escapeshellarg($tmpSet) . ' ' . escapeshellarg(SMPRO_GW_SET) . ' 2>/dev/null');
    @shell_exec('ipset destroy ' . escapeshellarg($tmpSet) . ' 2>/dev/null');
    $keepN = smpro_gw_cfg(); $keepN['set_size'] = $n; smpro_gw_save($keepN);   // what the watcher compares the live set with

    // Record the address this was proven from, so the reboot re-assert has something true to check against.
    if (empty($cfg['armed_from']) || $cfg['armed_from'] !== $myIp) {
        $keep = smpro_gw_cfg(); $keep['armed_from'] = $myIp; $keep['last_seen'] = time(); smpro_gw_save($keep);
    }
    smpro_gw_remove(true);      // never stack two of our rules
    // Inserted at position 1 in reverse order, so they end up ABOVE the drop in the order written here: allow
    // established, allow loopback, then drop the rest. Getting this order wrong is what cut live sessions.
    @shell_exec('timeout 10 iptables -I INPUT 1 ' . smpro_gw_rule_args($ports) . ' 2>/dev/null');
    @shell_exec('timeout 10 iptables -I INPUT 1 ' . smpro_gw_log_args($ports) . ' 2>/dev/null');   // above the drop: what was refused, for the watcher
    foreach (array_reverse(smpro_gw_pre_rules($ports)) as $pre) {
        @shell_exec('timeout 10 iptables -I INPUT 1 ' . $pre . ' 2>/dev/null');
    }

    $live = smpro_gw_live();
    $r['ok'] = $live;
    $panel = $live ? smpro_gw_panel_apply($cfg, $ranges, $always) : ['ok' => false, 'msg' => 'not attempted'];
    $r['panel'] = $panel;
    $r['msg'] = $live
        ? ('Up: ' . $n . ' range(s) may reach ' . count($ports) . ' login port(s); everything else is dropped there. Web ports untouched; ' . ($panel['ok'] ? 'the panel subdomains (cpanel./whm./webmail. over 443) are covered too - ' . $panel['msg'] : 'the panel subdomains are NOT covered: ' . $panel['msg']) . '.')
        : 'The rule did not appear in iptables. Nothing is enforcing.';
    if ($live) smpro_gw_hook_install();
    smpro_gw_record($live ? 'applied' : 'apply_failed', $r['msg']);
    return $r;
}

/* =====================================================================================================
 * THE OTHER DOOR: the panel's proxy subdomains.
 *
 * cPanel serves the panel on cpanel./whm./webmail./webdisk./cpcalendars./cpcontacts.<domain> over ports 80 and
 * 443 as well: the web server (nginx in front of Apache, or Apache alone) forwards those hosts to cpsrvd on
 * 127.0.0.1. The kernel rule above covers the numbered ports only, and 80/443 are deliberately never in it, so a
 * sign-in through cpanel.example.com walked straight past the wall - and past the cPHulk country lock too, which
 * saw 127.0.0.1. Verified on a production server: two foreign sign-ins minutes after the wall went up.
 *
 * Apache sees the visitor's real address behind nginx (mod_remoteip, which cPanel configures for its own proxy),
 * so one Apache rule covers both layouts: when the Host is a panel subdomain, only the wall's own address set may
 * pass. It lives in a file of its own under conf.d (read by every EasyApache build, never touched by a rebuild),
 * is proven by configtest before Apache is asked to reload, and is removed whenever the wall comes down. The
 * prefixes follow the doors: no cPanel door selected, no cpanel./webdisk. prefix; the same for whm and webmail.
 * ===================================================================================================== */
define('SMPRO_GW_HTTPD_FILE', '/etc/apache2/conf.d/smpro-geowall-panel.conf');
function smpro_gw_panel_prefixes(array $cfg): array {
    $doors = (array)($cfg['doors'] ?? []); $p = [];
    if (in_array('cpanel', $doors, true))  $p = array_merge($p, ['cpanel', 'webdisk', 'cpcalendars', 'cpcontacts']);
    if (in_array('whm', $doors, true))     $p[] = 'whm';
    if (in_array('webmail', $doors, true)) $p[] = 'webmail';
    return $p;
}
function smpro_gw_panel_live(): bool { return @is_file(SMPRO_GW_HTTPD_FILE) && (int)@filesize(SMPRO_GW_HTTPD_FILE) > 0; }
function smpro_gw_httpd_run(string $cmd, int $t = 90): array { $o = (string)@shell_exec('timeout ' . $t . ' ' . $cmd . ' 2>&1; echo "__rc=$?"'); preg_match('/__rc=(\d+)\s*$/', $o, $m); return [(int)($m[1] ?? 1), trim(preg_replace('/__rc=\d+\s*$/', '', $o))]; }
/** Write the Apache half from the SAME ranges and always-list the kernel set was built from; refuse and leave nothing behind when Apache does not accept it. */
function smpro_gw_panel_apply(array $cfg, array $ranges, array $always): array {
    $r = ['ok' => false, 'msg' => '', 'prefixes' => smpro_gw_panel_prefixes($cfg)];
    if (!is_dir('/etc/apache2/conf.d') || !is_executable('/usr/sbin/apachectl')) { $r['msg'] = 'no Apache on this server; the panel subdomains are not covered'; return $r; }
    if (!$r['prefixes']) { smpro_gw_panel_remove(true); $r['ok'] = true; $r['msg'] = 'no panel door selected'; return $r; }
    $ips = array_values(array_unique(array_filter(array_merge(['127.0.0.0/8'], $always, $ranges), fn($c) => preg_match('#^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$#', (string)$c))));
    if (count($ips) < 2) { $r['msg'] = 'the address set is empty; refused'; return $r; }
    $lines = ["# Safety Monitor Pro - country wall for the panel's proxy subdomains over 80/443. Generated; do not edit.",
              "# Rewritten whenever the wall is applied, removed when it comes down. Hosts: " . implode('. ', $r['prefixes']) . '.',
              '<If "%{HTTP_HOST} =~ m#^(' . implode('|', $r['prefixes']) . ')\.#i">'];
    foreach (array_chunk($ips, 200) as $chunk) $lines[] = '    Require ip ' . implode(' ', $chunk);
    $lines[] = '</If>';
    $body = implode("\n", $lines) . "\n";
    $prev = @is_file(SMPRO_GW_HTTPD_FILE) ? (string)@file_get_contents(SMPRO_GW_HTTPD_FILE) : null;
    if ($prev === $body) { $r['ok'] = true; $r['msg'] = 'panel subdomains covered (' . count($ips) . ' addresses, unchanged)'; return $r; }
    if (@file_put_contents(SMPRO_GW_HTTPD_FILE . '.tmp', $body, LOCK_EX) === false) { $r['msg'] = 'could not write ' . SMPRO_GW_HTTPD_FILE; return $r; }
    @chmod(SMPRO_GW_HTTPD_FILE . '.tmp', 0644);
    @rename(SMPRO_GW_HTTPD_FILE . '.tmp', SMPRO_GW_HTTPD_FILE);
    [$rc, $o] = smpro_gw_httpd_run('/usr/sbin/apachectl configtest', 60);
    if ($rc !== 0 || stripos($o, 'Syntax OK') === false) {
        // Apache refused the file: put the previous one back (or none) so a broken include never reaches a reload
        if ($prev === null) @unlink(SMPRO_GW_HTTPD_FILE); else @file_put_contents(SMPRO_GW_HTTPD_FILE, $prev, LOCK_EX);
        $r['msg'] = 'Apache configtest refused the panel rule; nothing was changed there: ' . substr($o, -200); return $r;
    }
    [$rc, $o] = smpro_gw_httpd_run('/usr/sbin/apachectl graceful', 60);
    $r['ok'] = $rc === 0; $r['msg'] = $rc === 0 ? ('panel subdomains covered (' . count($ips) . ' addresses)') : ('Apache graceful reload failed: ' . substr($o, -200));
    return $r;
}
/** Remove the Apache half and reload. Idempotent. */
function smpro_gw_panel_remove(bool $quiet = false): array {
    if (!@is_file(SMPRO_GW_HTTPD_FILE)) return ['ok' => true, 'removed' => false];
    @unlink(SMPRO_GW_HTTPD_FILE);
    [$rc, $o] = smpro_gw_httpd_run('/usr/sbin/apachectl configtest', 60);
    if ($rc === 0 && stripos($o, 'Syntax OK') !== false) smpro_gw_httpd_run('/usr/sbin/apachectl graceful', 60);
    if (!$quiet) smpro_gw_record('panel_removed', 'the panel-subdomain rule was removed from Apache');
    return ['ok' => !@is_file(SMPRO_GW_HTTPD_FILE), 'removed' => true];
}

/** Take it down. Idempotent, and safe to call when nothing is up. */
function smpro_gw_remove(bool $quiet = false): array {
    smpro_gw_panel_remove($quiet);
    // Matches on the marker PREFIX, so the accept rules that accompany the drop are removed with it. Leaving
    // them behind would be harmless but untidy; leaving the drop behind would not be harmless at all, so the
    // loop below is bounded and then verified rather than trusted.
    $removed = 0;
    for ($i = 0; $i < 20; $i++) {
        $out = (string)@shell_exec('timeout 10 iptables -S INPUT 2>/dev/null');
        if (strpos($out, SMPRO_GW_MARK) === false) break;
        foreach (explode(PHP_EOL, $out) as $line) {
            if (strpos($line, SMPRO_GW_MARK) === false) continue;
            $del = preg_replace('/^-A INPUT /', '', trim($line));
            // replayed token by token, each quoted: iptables -S prints comments in double quotes, and a comment
            // holding $(...) would otherwise be expanded by the shell
            preg_match_all('/"[^"]*"|\S+/', $del, $tk);
            $del = implode(' ', array_map(fn($x) => escapeshellarg(trim($x, '"')), $tk[0]));
            @shell_exec('timeout 10 iptables -D INPUT ' . $del . ' 2>/dev/null');
            $removed++;
            break;
        }
    }
    if (!$quiet && $removed) smpro_gw_record('removed', $removed . ' rule(s) removed');
    return ['ok' => !smpro_gw_live(), 'removed' => $removed];
}

/**
 * THE DEAD MAN'S SWITCH.
 *
 * If nothing has confirmed the panel is still reachable within the configured window, the rule comes down by
 * itself. A country wall that has locked the operator out cannot be removed from inside the server - it has
 * taken away the panel and ssh at the same time - and the only way back would be the hosting provider's console.
 * So the wall has to keep being re-authorised, and stops on its own when it is not.
 *
 * This is the guard that makes the feature safe to try at all.
 */
function smpro_gw_deadman(): array {
    $cfg = smpro_gw_cfg();
    if (empty($cfg['enabled'])) {
        if (smpro_gw_live()) { smpro_gw_remove(); return ['ok' => true, 'action' => 'removed', 'why' => 'the wall is switched off']; }
        return ['ok' => true, 'action' => 'none', 'why' => 'off'];
    }
    if (smpro_gw_live()) {
        // 1. The set must be whole. CSF flushes every ipset on restart while the rules stay: an empty set behind
        //    "drop what is not in the set" drops everyone. Lift the rules at once, rebuild, and only then enforce.
        $size = smpro_gw_set_size(); $built = (int)$cfg['set_size'];
        if ($size === 0 || ($built > 0 && $size < (int)($built * 0.9))) {
            smpro_gw_remove(true);
            smpro_gw_record('set_lost', 'the address set held ' . $size . ' of ' . $built . ' members - rules lifted, rebuilding');
            $r = smpro_gw_apply($cfg, '', false);
            if (empty($r['ok'])) {
                $cfg['enabled'] = false; smpro_gw_save($cfg);
                smpro_gw_record('set_lost_down', 'the set could not be rebuilt (' . (string)($r['msg'] ?? '') . ') - the wall stays down');
                if (function_exists('smpro_notify')) @smpro_notify('geowall_deadman', 'Country wall taken down: its address set was emptied',
                    'A firewall restart emptied the country wall\'s address set while its rules were still up, which refuses everyone. The rules were lifted at once; the set could not be rebuilt (' . (string)($r['msg'] ?? '') . '), so the wall stays down. Open Firewall and arm it again.');
                return ['ok' => true, 'action' => 'removed', 'why' => 'set lost and not rebuilt'];
            }
            if (function_exists('smpro_notify')) @smpro_notify('geowall_deadman', 'Country wall: address set rebuilt after a firewall restart',
                'The country wall\'s address set had been emptied (a firewall restart does that) while its rules were up. The rules were lifted within the watcher\'s minute and the set was rebuilt (' . (int)($r['ranges'] ?? 0) . ' ranges + ' . (int)($r['always'] ?? 0) . ' always-allowed). Nothing to do; this is the record.', ['severity' => 'info']);
            return ['ok' => true, 'action' => 'rebuilt', 'why' => 'set lost and rebuilt'];
        }
        // 2. The wall must not be hurting people it is meant to let in. The product's own geo database is the judge:
        //    refused addresses it places in an allowed country mean the firewall's range list is incomplete.
        $d = smpro_gw_dropped(10, (array)$cfg['countries']);
        if (count($d['allowed']) >= 3) {
            smpro_gw_remove(true);
            $cfg['enabled'] = false; smpro_gw_save($cfg);
            $lst = []; foreach (array_slice($d['allowed'], 0, 8, true) as $ip => $cc) $lst[] = $ip . ' (' . $cc . ')';
            smpro_gw_record('hurting', count($d['allowed']) . ' address(es) from allowed countries were refused in 10 minutes - the wall took itself down: ' . implode(', ', $lst));
            if (function_exists('smpro_notify')) @smpro_notify('geowall_deadman', 'Country wall taken down: it was refusing allowed-country users',
                'In the last ten minutes the wall refused ' . count($d['allowed']) . ' address(es) that this server\'s own geo database places in an allowed country: ' . implode(', ', $lst) . '. That means the firewall\'s country range list is incomplete for those countries. The wall took itself down so customers are not shut out. Refresh the firewall\'s country data (csf -r), then arm it again - arming now checks recent sign-ins against the list first.', ['severity' => 'critical']);
            return ['ok' => true, 'action' => 'removed', 'why' => 'refusing allowed-country users'];
        }
    }
    // Before judging silence, read cPanel's own record of WHM sign-ins from outside: that is the operator reaching
    // the panel, whether or not this product's pages were open.
    $proof = smpro_gw_reachability_proof((int)$cfg['last_seen']);
    if ($proof > (int)$cfg['last_seen']) { smpro_gw_heartbeat($proof); $cfg = smpro_gw_cfg(); }
    $age = time() - (int)$cfg['last_seen'];
    $max = max(5, (int)$cfg['deadman_minutes']) * 60;
    if ((int)$cfg['last_seen'] > 0 && $age > $max) {
        smpro_gw_remove();
        $cfg['enabled'] = false;
        smpro_gw_save($cfg);
        smpro_gw_record('deadman', 'No confirmation for ' . intdiv($age, 60) . ' minute(s) - the wall took itself down.');
        if (function_exists('smpro_notify')) {
            @smpro_notify('geowall_deadman', 'Country wall taken down automatically',
                'Nothing has confirmed this panel is still reachable for ' . intdiv($age, 60) . ' minutes, so the country wall removed itself.'
                . PHP_EOL . PHP_EOL
                . 'That is what it is for: a wall that locks the operator out cannot be removed from inside the server.'
                . PHP_EOL
                . 'If you were locked out, you can sign in again now. If you were not, open Firewall and arm it again.');
        }
        return ['ok' => true, 'action' => 'removed', 'why' => 'no confirmation for ' . intdiv($age, 60) . ' minute(s)'];
    }
    // A reboot clears ipset and iptables. The wall must come back by itself, or it is on in the settings and
    // absent in the kernel - which is the state this whole file exists to make impossible.
    if (!smpro_gw_live() && !((function_exists('smpro_ctl_disabled') && smpro_ctl_disabled()) || (function_exists('smpro_ctl_dry_run') && smpro_ctl_dry_run()))) {   // Disabled / Dry-Run: never re-armed by itself
        $r = smpro_gw_apply($cfg, '', false);
        return ['ok' => !empty($r['ok']), 'action' => 'reasserted', 'why' => (string)$r['msg']];
    }
    return ['ok' => true, 'action' => 'none', 'why' => 'confirmed ' . intdiv($age, 60) . ' minute(s) ago'];
}

function smpro_gw_record(string $what, string $msg): void {
    @is_dir(dirname(SMPRO_GW_LOG)) || @mkdir(dirname(SMPRO_GW_LOG), 0700, true);
    $gwLine = json_encode(['at' => date('c'), 'what' => $what, 'msg' => $msg], JSON_UNESCAPED_SLASHES) . PHP_EOL;
    if (function_exists('smpro_log_append')) smpro_log_append(SMPRO_GW_LOG, $gwLine, 5242880, 3); else @file_put_contents(SMPRO_GW_LOG, $gwLine, FILE_APPEND | LOCK_EX);
    @chmod(SMPRO_GW_LOG, 0600);
    if (function_exists('smpro_audit')) smpro_audit('geowall_' . $what, ['msg' => $msg]);
}

/** Cron: the dead man's switch must run whether or not anyone opens a page. */
function smpro_gw_cron_sync(): bool {
    // A test must never install a live cron. The shared writer refuses too, but a test that loads only
    // this file has no shared writer to refuse - function_exists() is false and the fallback writes
    // /etc/cron.d directly. The lab caught exactly that, restored the file, and went red at random.
    if (defined('SMPRO_TEST_SRC')) return true;
    $f = '/etc/cron.d/smpro-geowall';
    $cfg = smpro_gw_cfg();
    if (empty($cfg['enabled'])) { if (@is_file($f)) @unlink($f); return true; }
    $bin = SMPRO_BASE . '/bin/geowall_tick.php';
    if (!@is_file($bin)) return false;
    smpro_gw_hook_install();
    $php = function_exists('smpro_php_cli_bin') ? smpro_php_cli_bin()
         : (is_executable('/usr/local/cpanel/3rdparty/bin/php') ? '/usr/local/cpanel/3rdparty/bin/php' : 'php');
    $lockDir = defined('SMPRO_LOCKS') ? SMPRO_LOCKS : (SMPRO_VARLIB . '/locks');
    @is_dir($lockDir) || @mkdir($lockDir, 0700, true);
    $flock = is_executable('/usr/bin/flock') ? '/usr/bin/flock' : 'flock';
    $desired = '# Safety Monitor Pro - country wall: re-assert after a reboot, take it down if nobody confirms' . PHP_EOL
             . '*/2 * * * * root ' . $flock . ' -n ' . $lockDir . '/geowall.lock timeout 120 ' . $php . ' ' . $bin . ' >/dev/null 2>&1' . PHP_EOL;
    return function_exists('smpro_cron_install') ? smpro_cron_install($f, $desired)
         : (@file_put_contents($f, $desired) !== false && @chmod($f, 0644));
}

/**
 * Get the firewall to fetch and keep the address ranges for these countries.
 *
 * There is no separate downloader to call: csf fetches a country's ranges only when one of its own CC_* settings
 * refers to that country, and it does so inside `csf -r`. So the intent is declared to csf in its own terms -
 * CC_ALLOW_PORTS with the same countries and the same login ports - and csf downloads and then MAINTAINS the
 * zone files on its own schedule. This is not borrowing a setting for a side effect: it says exactly what we
 * mean, that these countries may reach these ports. What csf will not do is deny everyone else on those ports -
 * CC_ALLOW_PORTS only appends early ACCEPTs - and that missing half is the ipset rule in this file.
 *
 * csf.conf is backed up before it is touched, and only these two keys are changed.
 */
function smpro_gw_fetch(array $ccs, array $ports): array {
    $r = ['ok' => false, 'msg' => '', 'have' => [], 'missing' => []];
    $ccs = array_values(array_filter(array_map(fn($c) => strtoupper(preg_replace('/[^A-Za-z]/', '', (string)$c)), $ccs),
                                     fn($c) => strlen($c) === 2));
    $ports = array_values(array_filter(array_map('intval', $ports), fn($p) => $p > 0 && $p !== 80 && $p !== 443));
    if (!$ccs)   { $r['msg'] = 'No country given.'; return $r; }
    if (!$ports) { $r['msg'] = 'No login port given.'; return $r; }

    $conf = '/etc/csf/csf.conf';
    if (!@is_writable($conf)) { $r['msg'] = 'csf.conf is not writable — is CSF installed on this server?'; return $r; }

    $src = (string)@file_get_contents($conf);
    if ($src === '') { $r['msg'] = 'csf.conf could not be read.'; return $r; }

    // A copy before the first byte changes. This file decides who can reach the server at all.
    $bk = SMPRO_VARLIB . '/backups/csf.conf.' . date('Ymd_His');
    @is_dir(dirname($bk)) || @mkdir(dirname($bk), 0700, true);
    @file_put_contents($bk, $src, LOCK_EX);
    @chmod($bk, 0600);

    $set = function (string $s, string $key, string $val): string {
        $line = $key . ' = "' . $val . '"';
        if (preg_match('/^' . preg_quote($key, '/') . '\s*=.*$/m', $s)) {
            return preg_replace('/^' . preg_quote($key, '/') . '\s*=.*$/m', $line, $s, 1);
        }
        return rtrim($s) . "\n" . $line . "\n";
    };
    $new = $set($src, 'CC_ALLOW_PORTS', implode(',', $ccs));
    $new = $set($new, 'CC_ALLOW_PORTS_TCP', implode(',', $ports));

    if ($new !== $src && @file_put_contents($conf, $new, LOCK_EX) === false) {
        $r['msg'] = 'csf.conf could not be written.'; return $r;
    }
    smpro_gw_record('fetch', 'declared ' . implode(',', $ccs) . ' on ports ' . implode(',', $ports) . ' to csf; backup at ' . $bk);

    // Reload the rules so the new CC_ALLOW_PORTS takes effect.
    @shell_exec('timeout 240 csf -r >/dev/null 2>&1');

    // AND THEN ACTUALLY FETCH. `csf -r` reloads rules; it does NOT download a country's ranges. The download
    // belongs to lfd, which does it in a scheduled job - so declaring the country and reloading left the zone
    // file absent for up to a day, the button reported failure, and the failure it reported was "check outbound
    // access" on a server whose outbound access was perfectly fine. Restarting lfd makes it run that job now.
    // Nothing about an lfd restart touches the firewall rules; it is the log daemon.
    if (smpro_gw_zones_missing($ccs)) {
        @shell_exec('timeout 120 systemctl restart lfd >/dev/null 2>&1 || timeout 120 service lfd restart >/dev/null 2>&1');
        for ($i = 0; $i < 12 && smpro_gw_zones_missing($ccs); $i++) sleep(5);   // bounded: at most a minute
    }

    foreach ($ccs as $c) {
        if (smpro_gw_zone_has($c)) $r['have'][] = $c; else $r['missing'][] = $c;
    }
    $r['ok'] = !$r['missing'];
    if ($r['ok']) {
        $r['msg'] = 'Ranges are on disk for ' . implode(', ', $r['have']) . ' (' . count(smpro_gw_ranges($r['have'])) . ' range(s)).';
        return $r;
    }

    // Say which of the two it is, because they need opposite things done about them. Reporting a scheduling
    // delay as a network fault sends an operator looking for a problem that is not there.
    $reachable = smpro_gw_source_reachable();
    $r['msg'] = 'Still missing: ' . implode(', ', $r['missing']) . '. '
        . ($reachable === false
            ? 'This server could not reach the range source, so check outbound access and try again.'
            : 'The countries are declared to the firewall, which fetches ranges in its own scheduled job — they '
            . 'should arrive at its next run. Try again after that.')
        . ' Nothing has been walled.';
    return $r;
}

/** Is a country's range file on disk and big enough to be real? */
function smpro_gw_zone_has(string $cc): bool {
    $f = '/var/lib/csf/zone/' . strtolower(preg_replace('/[^A-Za-z]/', '', $cc)) . '.zone';
    return @is_readable($f) && (int)@filesize($f) > 10;
}

/** Are any of these still without ranges? */
function smpro_gw_zones_missing(array $ccs): bool {
    foreach ($ccs as $c) if (!smpro_gw_zone_has($c)) return true;
    return false;
}

/**
 * Can this server reach the place the firewall gets country ranges from?
 *
 * Returns null when the question itself could not be asked, so "we could not check" never passes for "the
 * network is broken" - the same distinction this whole file is built on.
 */
function smpro_gw_source_reachable(): ?bool {
    if (!function_exists('shell_exec')) return null;
    $out = trim((string)@shell_exec(
        'timeout 20 curl -s -o /dev/null -m 15 -w "%{http_code}" https://www.ipdeny.com/ipblocks/ 2>/dev/null'));
    if ($out === '') return null;
    return (int)$out >= 200 && (int)$out < 400;
}
