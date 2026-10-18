<?php
/**
 * includes/bfrules.php — Break-in report: rules that block automatically.
 *
 * The report already says what a network is doing and why, in the operator's words: "tried 141 different
 * accounts — password spraying", "about 79 attempts per address — hammering, not a forgotten password". Those
 * sentences are a judgement that has already been made. Until now a person still had to press a button for each
 * one, which means an attack that starts at 3am runs until somebody opens the page.
 *
 * These rules act on that judgement. They add NO new detection — every decision comes from
 * smpro_aa_bf_assess(), the same function that writes the sentence shown on the page, so what gets blocked is
 * always exactly what the page said was an attack, and the recorded reason is that same sentence.
 *
 * WHAT STOPS THIS FROM BLOCKING THE WRONG THING
 *
 *   - It is OFF, and then DRY RUN, by default. A rule set that starts blocking the moment it is saved is a rule
 *     set nobody can safely try on a live server.
 *   - Arming is refused if the operator's own network would match. Locking the administrator out of the panel
 *     that holds the unblock button is the one failure with no recovery path from inside.
 *   - Allow-listed addresses are never blocked, and neither is the operator's current address.
 *   - Every block goes through smpro_fw_block_ip(), which refuses Cloudflare edge addresses and
 *     forward-confirmed crawlers. A poisoned or mistaken rule still cannot take Googlebot off the server.
 *   - A verdict of 'watch' or 'normal' is never actioned. Those exist precisely because the evidence was not
 *     conclusive, and "not conclusive" must not become "blocked anyway" just because a machine is deciding.
 *   - Each rule carries its own minimum evidence. An operator can demand more than the report's own threshold;
 *     they cannot demand less, because below it the report does not call it an attack in the first place.
 *
 * Nothing here names a country, a network, an address or a customer. The thresholds are numbers about shape.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

if (!defined('SMPRO_BFR_CFG')) define('SMPRO_BFR_CFG', SMPRO_VARLIB . '/bfrules.json');
if (!defined('SMPRO_BFR_LOG')) define('SMPRO_BFR_LOG', SMPRO_VARLOG . '/bfrules.log');

/**
 * The patterns the report can produce, and what each one means.
 *
 * The keys are the exact 'what' values smpro_aa_bf_assess() returns. If that function ever grows a new pattern
 * it will simply not be auto-blocked until it is added here — silence, not a surprise block.
 */
function smpro_bfr_patterns(): array {
    return [
        'Password spraying' => [
            'title' => 'Password spraying',
            'means' => 'a list of account names, one or two passwords each — a person who forgot a password does not try other people\'s accounts',
            'evidence' => 'accounts',                       // which measured number this rule is bounded by
            'unit'  => 'different accounts tried',
            'floor' => 5,                                   // the report's own threshold; a rule may not go below it
            'default_min' => 10,
        ],
        'Many-address run' => [
            'title' => 'Many-address run',
            'means' => 'one actor renting many addresses — a proxy pool or a cloud run, not that many separate people',
            'evidence' => 'addresses',
            'unit'  => 'addresses in the network',
            'floor' => 5,
            'default_min' => 10,
        ],
        'Brute force' => [
            'title' => 'Brute force',
            'means' => 'hammering one door — the attempt count per address is far past what a mistake produces',
            'evidence' => 'per_ip',
            'unit'  => 'attempts per address',
            'floor' => 30,
            'default_min' => 50,
        ],
        'Automated scanner' => [
            'title' => 'Automated scanner (cloud/hosting network)',
            'means' => 'nobody signs in to a control panel from a rented server; search and archive crawlers never attempt a login at all',
            'evidence' => 'attempts',
            'unit'  => 'failed attempts',
            'floor' => 1,
            'default_min' => 20,
        ],
    ];
}

/** Defaults: off, dry run, every pattern enabled but held to a threshold above the report's own. */
function smpro_bfr_defaults(): array {
    $rules = [];
    foreach (smpro_bfr_patterns() as $k => $p) {
        $rules[$k] = ['enabled' => true, 'min' => (int)$p['default_min']];
    }
    return [
        'enabled' => false,     // nothing happens until this is turned on, deliberately
        'dryrun'  => true,      // and then it only reports what it WOULD block
        'rules'   => $rules,
        'max_per_run' => 200,   // a ceiling, so a bad day cannot turn into a thousand firewall rules in one tick
        'min_rate' => 0.0,      // optional extra gate: attempts/min, 0 = not required
    ];
}

function smpro_bfr_cfg(): array {
    $d = smpro_bfr_defaults();
    $j = @json_decode((string)@file_get_contents(SMPRO_BFR_CFG), true);
    if (!is_array($j)) return $d;
    $out = array_replace($d, array_intersect_key($j, $d));
    $out['rules'] = [];
    foreach ($d['rules'] as $k => $def) {
        $r = isset($j['rules'][$k]) && is_array($j['rules'][$k]) ? $j['rules'][$k] : [];
        $floor = (int)smpro_bfr_patterns()[$k]['floor'];
        $out['rules'][$k] = [
            'enabled' => !empty($r['enabled']),
            // A rule may ask for MORE evidence than the report needs, never less: below the floor the report does
            // not call it an attack, so a rule that went lower would be blocking on the report's own "not sure".
            'min' => max($floor, (int)($r['min'] ?? $def['min'])),
        ];
    }
    $out['enabled'] = !empty($j['enabled']);
    $out['dryrun']  = !isset($j['dryrun']) || !empty($j['dryrun']);
    $out['max_per_run'] = max(1, min(2000, (int)($j['max_per_run'] ?? $d['max_per_run'])));
    $out['min_rate'] = max(0.0, min(1000.0, (float)($j['min_rate'] ?? 0)));
    return $out;
}

function smpro_bfr_save(array $cfg): bool {
    $d = smpro_bfr_defaults();
    $clean = ['enabled' => !empty($cfg['enabled']), 'dryrun' => !isset($cfg['dryrun']) || !empty($cfg['dryrun']),
              'max_per_run' => max(1, min(2000, (int)($cfg['max_per_run'] ?? $d['max_per_run']))),
              'min_rate' => max(0.0, min(1000.0, (float)($cfg['min_rate'] ?? 0))), 'rules' => []];
    foreach (smpro_bfr_patterns() as $k => $p) {
        $r = isset($cfg['rules'][$k]) && is_array($cfg['rules'][$k]) ? $cfg['rules'][$k] : [];
        $clean['rules'][$k] = ['enabled' => !empty($r['enabled']),
                               'min' => max((int)$p['floor'], (int)($r['min'] ?? $p['default_min']))];
    }
    @is_dir(dirname(SMPRO_BFR_CFG)) || @mkdir(dirname(SMPRO_BFR_CFG), 0700, true);
    $tmp = SMPRO_BFR_CFG . '.tmp';
    if (@file_put_contents($tmp, json_encode($clean, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX) === false) return false;
    @chmod($tmp, 0600);
    $ok = @rename($tmp, SMPRO_BFR_CFG);
    if ($ok) {
        // The cron follows the setting immediately. A saved 'on' that only starts working after the next
        // page load is a setting the operator cannot trust.
        smpro_bfr_cron_sync();
        if (function_exists('smpro_audit')) smpro_audit('bfrules_saved', $clean);
    }
    return $ok;
}

/**
 * Would this network be blocked, and on what grounds? Pure — decides nothing, touches nothing.
 *
 * Returns ['match' => bool, 'pattern' => string, 'why' => string, 'skip' => string]. 'skip' says why a network
 * that LOOKS like a match was passed over, so the page can show the near-misses instead of only the hits: a rule
 * that quietly does nothing is indistinguishable from a rule that is working, and that is the confusion this
 * codebase keeps having to undo.
 */
function smpro_bfr_match(array $assess, array $nv, array $cfg): array {
    $no = function ($why) { return ['match' => false, 'pattern' => '', 'why' => '', 'skip' => $why]; };

    // Only the report's own "this is an attack" is actionable. 'watch' means the evidence was not conclusive.
    if (($assess['verdict'] ?? '') !== 'block') return $no('the report did not call this an attack (' . (string)($assess['verdict'] ?? '?') . ')');

    $what = (string)($assess['what'] ?? '');
    $pats = smpro_bfr_patterns();
    if (!isset($pats[$what])) return $no('no rule covers the pattern "' . $what . '"');
    $rule = $cfg['rules'][$what] ?? null;
    if (!is_array($rule) || empty($rule['enabled'])) return $no('the rule for "' . $what . '" is off');

    $measured = [
        'accounts'  => (int)($assess['users'] ?? 0),
        'addresses' => (int)count((array)($nv['ips'] ?? [])),
        'per_ip'    => (float)($assess['per_ip'] ?? 0),
        'attempts'  => (int)($nv['fails'] ?? 0),
    ];
    $key = $pats[$what]['evidence'];
    $have = $measured[$key] ?? 0;
    $min  = (int)$rule['min'];
    if ($have < $min) return $no(sprintf('%s: %s %s, rule needs %d', $what, $have, $pats[$what]['unit'], $min));

    $rate = (float)($assess['rate'] ?? 0);
    if (($cfg['min_rate'] ?? 0) > 0 && $rate < (float)$cfg['min_rate'])
        return $no(sprintf('%s: %.1f attempts/min, rule needs %.1f', $what, $rate, (float)$cfg['min_rate']));

    // The recorded reason is the report's OWN sentence, not a restatement of it. Whoever reads the firewall log
    // months later sees the same words the page showed, and can tell what the decision was actually based on.
    $why = $what . ' — ' . implode(' · ', array_slice((array)($assess['why'] ?? []), 0, 3));
    return ['match' => true, 'pattern' => $what, 'why' => $why, 'skip' => ''];
}

/**
 * Refuse to arm if the operator's own address would be caught.
 *
 * Being locked out of the panel that holds the unblock button is the one failure with no way back from inside —
 * it needs console access or the hosting provider. Checked BEFORE arming rather than reported afterwards.
 */
function smpro_bfr_arm_check(array $cfg, string $myIp, array $nets): array {
    $myIp = trim($myIp);
    if ($myIp === '' || !filter_var($myIp, FILTER_VALIDATE_IP))
        return ['ok' => true, 'msg' => 'Your address could not be determined, so it could not be checked against the rules. Turn this on from a machine whose address is visible.', 'warn' => true];

    if (function_exists('smpro_csf_allowlisted') && smpro_csf_allowlisted($myIp))
        return ['ok' => true, 'msg' => 'Your address is allow-listed, so no rule can reach it.'];

    foreach ($nets as $nv) {
        $ips = array_map(fn($x) => (string)($x['ip'] ?? ''), (array)($nv['ips'] ?? []));
        if (!in_array($myIp, $ips, true)) continue;
        $as = function_exists('smpro_aa_bf_assess') ? smpro_aa_bf_assess($nv) : ['verdict' => 'watch'];
        $m  = smpro_bfr_match($as, $nv, $cfg);
        if (!empty($m['match'])) {
            return ['ok' => false, 'msg' => 'Refused: your own address (' . $myIp . ') is in a network these rules would block ('
                    . $m['pattern'] . '). Allow-list it first, or raise the threshold — arming this would lock you out of the page that holds the unblock button.'];
        }
    }
    return ['ok' => true, 'msg' => 'Your address is not in any network these rules would block.'];
}

/**
 * Apply the rules to the networks the report built.
 *
 * $dryrun overrides the saved setting when given, so the page can offer "show me what this would do" without
 * saving anything. Returns what it did AND what it deliberately did not do.
 */
function smpro_bfr_run(array $nets, ?array $cfg = null, ?bool $dryrun = null, string $by = 'auto'): array {
    $cfg = $cfg ?: smpro_bfr_cfg();
    $dry = $dryrun === null ? !empty($cfg['dryrun']) : $dryrun;
    $out = ['ok' => true, 'dryrun' => $dry, 'enabled' => !empty($cfg['enabled']),
            'blocked' => [], 'would' => [], 'refused' => [], 'skipped' => [], 'at' => time()];

    if (empty($cfg['enabled']) && $dryrun === null) {
        $out['ok'] = false; $out['msg'] = 'The rules are off. Nothing was looked at.';
        return $out;
    }
    if (!function_exists('smpro_aa_bf_assess')) {
        $out['ok'] = false; $out['msg'] = 'The break-in assessment is not loaded, so nothing could be judged — this is "not checked", not "nothing found".';
        return $out;
    }

    $myIp = '';
    $myIp = function_exists('smpro_admin_ip') ? smpro_admin_ip() : '';   // REMOTE_ADDR first: cpsrvd is the direct peer, the forwarded headers are what the browser sent

    $budget = (int)$cfg['max_per_run'];
    foreach ($nets as $nv) {
        $as = smpro_aa_bf_assess($nv);
        $m  = smpro_bfr_match($as, $nv, $cfg);
        $label = (string)($nv['provider'] ?? '') . ($nv['asn'] !== '' ? ' (' . $nv['asn'] . ')' : '');
        if (empty($m['match'])) { $out['skipped'][] = ['network' => $label, 'why' => $m['skip']]; continue; }

        foreach ((array)($nv['ips'] ?? []) as $row) {
            $ip = (string)($row['ip'] ?? '');
            if (!filter_var($ip, FILTER_VALIDATE_IP)) continue;
            if ($budget-- <= 0) { $out['refused'][] = ['ip' => $ip, 'why' => 'the per-run ceiling was reached']; continue; }

            if ($myIp !== '' && $ip === $myIp) { $out['refused'][] = ['ip' => $ip, 'why' => 'this is your own address']; continue; }
            if (function_exists('smpro_csf_allowlisted') && smpro_csf_allowlisted($ip)) {
                $out['refused'][] = ['ip' => $ip, 'why' => 'allow-listed']; continue;
            }
            if ($dry) { $out['would'][] = ['ip' => $ip, 'network' => $label, 'why' => $m['why']]; continue; }

            // Through the one chokepoint: it refuses Cloudflare edges and forward-confirmed crawlers, so a
            // mistaken rule still cannot take a search engine off this server.
            $r = function_exists('smpro_fw_block_ip') ? smpro_fw_block_ip($ip, $m['why']) : ['ok' => false, 'msg' => 'no firewall engine'];
            if (!empty($r['ok'])) {
                $out['blocked'][] = ['ip' => $ip, 'network' => $label, 'why' => $m['why'], 'engine' => (string)($r['engine'] ?? '')];
                smpro_bfr_record($ip, $m['pattern'], $m['why'], $by, true, '');
            } else {
                $out['refused'][] = ['ip' => $ip, 'why' => (string)($r['msg'] ?? 'refused')];
                smpro_bfr_record($ip, $m['pattern'], $m['why'], $by, false, (string)($r['msg'] ?? ''));
            }
        }
    }
    $out['msg'] = $dry
        ? count($out['would']) . ' address(es) would be blocked. Nothing was changed.'
        : count($out['blocked']) . ' address(es) blocked'
          . (count($out['refused']) ? ', ' . count($out['refused']) . ' refused' : '') . '.';
    return $out;
}

/** The record: address, pattern, the report's own words, who, when, and whether the firewall took it. */
function smpro_bfr_record(string $ip, string $pattern, string $why, string $by, bool $ok, string $error = ''): bool {
    @is_dir(dirname(SMPRO_BFR_LOG)) || @mkdir(dirname(SMPRO_BFR_LOG), 0700, true);
    $line = json_encode(['at' => date('c'), 'ip' => $ip, 'pattern' => $pattern, 'why' => $why,
                         'by' => $by, 'result' => $ok ? 'blocked' : 'refused', 'error' => $ok ? '' : $error],
                        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n";
    $w = function_exists('smpro_log_append') ? smpro_log_append(SMPRO_BFR_LOG, $line, 10485760, 3) : @file_put_contents(SMPRO_BFR_LOG, $line, FILE_APPEND | LOCK_EX);
    @chmod(SMPRO_BFR_LOG, 0600);
    if (function_exists('smpro_audit')) smpro_audit('bfrules_action', ['ip' => $ip, 'pattern' => $pattern, 'ok' => $ok ? 1 : 0, 'by' => $by]);
    return $w !== false;
}

/** The record, newest first. */
function smpro_bfr_history(int $limit = 200): array {
    if (!@is_readable(SMPRO_BFR_LOG)) return [];
    $raw = (string)@shell_exec('timeout 10 tail -n ' . (int)$limit . ' ' . escapeshellarg(SMPRO_BFR_LOG) . ' 2>/dev/null');
    $out = [];
    foreach (array_reverse(explode("\n", $raw)) as $l) {
        $l = trim($l); if ($l === '') continue;
        $j = json_decode($l, true); if (is_array($j)) $out[] = $j;
    }
    return $out;
}


/* ---------------- cron ----------------
 * The rules only run unattended while they are ON. Turning them off REMOVES the cron rather than leaving a
 * worker that reads a disabled config and exits: a cron entry that exists but does nothing is something an
 * operator has to read the code to understand, and it is the kind of leftover that outlives the feature.
 */
function smpro_bfr_cron_sync(): bool {
    // A test must never install a live cron. The shared writer refuses too, but a test that loads only
    // this file has no shared writer to refuse - function_exists() is false and the fallback writes
    // /etc/cron.d directly. The lab caught exactly that, restored the file, and went red at random.
    if (defined('SMPRO_TEST_SRC')) return true;
    $f = '/etc/cron.d/smpro-bfrules';
    $cfg = smpro_bfr_cfg();
    if (empty($cfg['enabled'])) { if (@is_file($f)) @unlink($f); return true; }
    $bin = SMPRO_BASE . '/bin/bfrules_tick.php';
    if (!@is_file($bin)) return false;
    $php = function_exists('smpro_php_cli_bin') ? smpro_php_cli_bin()
         : (is_executable('/usr/local/cpanel/3rdparty/bin/php') ? '/usr/local/cpanel/3rdparty/bin/php' : 'php');
    $lockDir = defined('SMPRO_LOCKS') ? SMPRO_LOCKS : (SMPRO_VARLIB . '/locks');
    @is_dir($lockDir) || @mkdir($lockDir, 0700, true);
    $flock = is_executable('/usr/bin/flock') ? '/usr/bin/flock' : 'flock';
    // Every 10 minutes: fast enough that a run is stopped while it is still running, slow enough that reading the
    // login log is not itself a load problem on a server with thousands of accounts. niced for the same reason.
    $desired = "# Safety Monitor Pro - Break-in rules (block networks the report already calls an attack)
"
             . "*/10 * * * * root $flock -n " . $lockDir . "/bfrules.lock timeout 600 nice -n 10 $php $bin >/dev/null 2>&1
";
    return function_exists('smpro_cron_install') ? smpro_cron_install($f, $desired)
         : (@file_put_contents($f, $desired) !== false && @chmod($f, 0644));
}
