<?php
/**
 * Safety Monitor Pro — when a release request may be approved without a human.
 *
 * Accounts lock their own files unattended; only RELEASING protection reaches the operator. That queue is the
 * right default and the wrong experience for a host with hundreds of customers, so this lets the operator say in
 * advance which releases they are content to have granted for them — for instance, a one-hour release asked for
 * from a country they already trust in the firewall.
 *
 * THE PART THAT DECIDES WHETHER THIS IS SAFE AT ALL.
 *
 * A rule keyed on where the customer is only means something if the location cannot be chosen by the customer.
 * The request is a file the ACCOUNT writes in its own home, so every field in it is attacker-controlled the moment
 * the account is breached: an address written there could simply be an address from an allowed country, and the
 * approval gate would be worth nothing precisely when it matters. So the address is NEVER read from the request.
 * Root establishes it from the server's own cPanel login records — data the account cannot write — and a request
 * whose address cannot be established that way is never auto-approved. It waits for a person, which is what would
 * have happened anyway.
 *
 * The rules are also deliberately one-sided in what they can do. They can approve a release the operator has
 * already said they are comfortable with; they can never decline one, because a rule that silently refuses looks
 * exactly like a request that was lost.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

function smpro_spr_path() { return SMPRO_VARLIB . '/php_harden/auto_rules.json'; }

/**
 * The operator's rules. Everything defaults to OFF: a server that updates into this feature must not start
 * approving anything on its own until somebody has actually chosen to let it.
 */
function smpro_spr_get() {
    $d = json_decode((string)@file_get_contents(smpro_spr_path()), true);
    if (!is_array($d)) $d = [];
    return [
        'auto_hour'      => !empty($d['auto_hour']),        // grant "one hour, then re-lock" by itself
        'auto_permanent' => !empty($d['auto_permanent']),   // grant a PERMANENT release by itself
        'need_allowlist' => !isset($d['need_allowlist']) ? true : (bool)$d['need_allowlist'],
        'countries'      => array_values(array_filter(array_map(
                                function ($c) {
                                    // Validated as written, not stripped down to something that looks valid:
                                    // stripping turned a typo like "zz9" into the country code ZZ, quietly
                                    // widening the rule to a country nobody chose.
                                    $c = strtoupper(trim((string)$c));
                                    return preg_match('/^[A-Z]{2}$/', $c) ? $c : '';
                                },
                                (array)($d['countries'] ?? [])), function ($c) { return $c !== ''; })),
        'max_items'      => max(0, min(500, (int)($d['max_items'] ?? 25))),
        'updated'        => (string)($d['updated'] ?? ''),
        'by'             => (string)($d['by'] ?? ''),
    ];
}

function smpro_spr_save(array $r, $by = '') {
    $out = [
        'auto_hour'      => !empty($r['auto_hour']),
        'auto_permanent' => !empty($r['auto_permanent']),
        'need_allowlist' => !empty($r['need_allowlist']),
        'countries'      => array_values(array_unique(array_filter(array_map(
                                function ($c) {
                                    // Validated as written, not stripped down to something that looks valid:
                                    // stripping turned a typo like "zz9" into the country code ZZ, quietly
                                    // widening the rule to a country nobody chose.
                                    $c = strtoupper(trim((string)$c));
                                    return preg_match('/^[A-Z]{2}$/', $c) ? $c : '';
                                },
                                (array)($r['countries'] ?? [])), function ($c) { return $c !== ''; }))),
        'max_items'      => max(0, min(500, (int)($r['max_items'] ?? 25))),
        'updated'        => date('c'),
        'by'             => (string)$by,
    ];
    $d = dirname(smpro_spr_path());
    @is_dir($d) || @mkdir($d, 0700, true);
    $tmp = smpro_spr_path() . '.tmp';
    if (@file_put_contents($tmp, json_encode($out, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX) === false) return false;
    @chmod($tmp, 0600);
    return @rename($tmp, smpro_spr_path());
}

/**
 * Where this account last signed in to cPanel from, according to the SERVER.
 *
 * Read from cPanel's own login log, which root owns and the account cannot write. This is the whole reason a
 * location rule can be trusted here. Returns '' when it cannot be established — and that is a real answer, not a
 * failure to paper over: an unknown location must never satisfy a rule about locations.
 */
/**
 * Lines of $file (plain or gzip) containing $needle, newest last, at most $max. Read in PHP rather than through
 * grep/tail: no dependency on PATH, and the test harness shadows those binaries with recording stubs.
 */
function smpro_spr_grep_lines($file, $needle, $max = 200) {
    $out = [];
    $gz = substr($file, -3) === '.gz';
    if ($gz && !function_exists('gzopen')) return $out;   // no zlib: the rotated file is skipped, the worker lives
    if ($gz && !function_exists('gzopen')) return $out;   // no zlib: the rotated file is skipped, the worker lives
    if ($gz && !function_exists('gzopen')) return $out;   // no zlib: the rotated file is skipped, the worker lives
    if ($gz && !function_exists('gzopen')) return $out;   // no zlib: the rotated file is skipped, the worker lives
    $h = $gz ? @gzopen($file, 'rb') : @fopen($file, 'rb');
    if (!$h) return $out;
    while (($line = $gz ? gzgets($h, 8192) : fgets($h, 8192)) !== false) {
        if (strpos($line, $needle) === false) continue;
        $out[] = rtrim($line, "
");
        if (count($out) > $max) array_shift($out);
    }
    $gz ? gzclose($h) : fclose($h);
    return $out;
}

function smpro_spr_login_ip($user, $withinHours = 24, $sessionLog = '/usr/local/cpanel/logs/session_log', $loginLog = '/usr/local/cpanel/logs/login_log') {
    $user = (string)$user;
    if (!preg_match('/^[a-zA-Z0-9._-]{1,64}$/', $user)) return '';
    $cutoff = time() - max(1, $withinHours) * 3600;
    $best = ''; $bestT = 0;
    $take = function ($ip, $t) use (&$best, &$bestT, $cutoff) {
        if (!filter_var($ip, FILTER_VALIDATE_IP) || $t < $cutoff) return;
        if ($ip === '127.0.0.1' || $ip === '::1') return;     // a session opened from the server itself (WHM "log in as user") says nothing about where the customer is
        if ($t >= $bestT) { $bestT = $t; $best = $ip; }
    };
    $files = function ($path) {
        $f = [$path];
        if (function_exists('smpro_log_files')) { $rot = smpro_log_files($path, 2); if ($rot) $f = $rot; }
        return $f;
    };

    // 1. session_log — where cPanel writes a SUCCESSFUL password login on current builds:
    //    "[date] info [cpaneld] 1.2.3.4 NEW user:token address=1.2.3.4,app=cpaneld,creator=user,method=handle_form_login,path=form,possessed=0"
    //    login_log on those builds carries only FAILED attempts, so reading it alone never finds anyone (verified on a
    //    production 11.138 server: 33,000 login_log lines, not one success). creator must be the account itself and
    //    possessed=0: a session root opened on the customer's behalf is not the customer signing in.
    foreach ($files($sessionLog) as $f) {
        if (!@is_readable($f)) continue;
        foreach (smpro_spr_grep_lines($f, ' NEW ' . $user . ':') as $line) {
            if (strpos($line, 'app=cpaneld') === false && strpos($line, 'app=webmaild') === false) continue;
            if (strpos($line, 'creator=' . $user . ',') === false) continue;
            if (strpos($line, 'possessed=1') !== false) continue;
            if (!preg_match('/address=([0-9a-fA-F.:]+),/', $line, $m)) continue;
            $t = 0;
            if (preg_match('/^\[([^\]]+)\]/', $line, $tm)) $t = (int)strtotime($tm[1]);
            if ($t === 0) $t = (int)@filemtime($f);
            $take($m[1], $t);
        }
    }
    if ($best !== '') return $best;

    // 2. login_log — older builds wrote "SUCCESS" lines here. Kept as the fallback; only successes count, since a
    //    failed attempt from anywhere would otherwise set an account's apparent location.
    foreach ($files($loginLog) as $f) {
        if (!@is_readable($f)) continue;
        foreach (smpro_spr_grep_lines($f, ' ' . $user . ' ') as $line) {
            if (stripos($line, 'success') === false) continue;
            if (!preg_match('/\b' . preg_quote($user, '/') . '\b/', $line)) continue;
            if (!preg_match('/\b(\d{1,3}(?:\.\d{1,3}){3})\b/', $line, $m)) continue;
            $t = 0;
            if (preg_match('/^\[([^\]]+)\]/', $line, $tm)) $t = (int)strtotime($tm[1]);
            if ($t === 0) $t = (int)@filemtime($f);
            $take($m[1], $t);
        }
    }
    return $best;
}

/**
 * Should this request be granted without a person?
 *
 * Returns ['auto'=>bool,'why'=>string,'ip'=>string,'cc'=>string]. `why` is written to be read by the operator
 * afterwards: whether a rule fired or not, the reason is recorded, so an approval that happened while nobody was
 * looking can still be accounted for.
 */
function smpro_spr_decide($user, array $ask) {
    $r = smpro_spr_get();
    $perm = (string)($ask['verb'] ?? 'unlock_permanent') !== 'unlock_selected';

    if ($perm && !$r['auto_permanent']) return ['auto' => false, 'why' => 'permanent releases are always decided by hand', 'ip' => '', 'cc' => ''];
    if (!$perm && !$r['auto_hour'])     return ['auto' => false, 'why' => 'automatic approval is switched off', 'ip' => '', 'cc' => ''];

    // The item limit is about how much of a site a single release exposes. A permanent release has no items —
    // it is the whole account — so the limit says nothing about it and must not be read as approval.
    $items = count((array)($ask['items'] ?? []));
    if (!$perm && $r['max_items'] > 0 && $items > $r['max_items']) {
        return ['auto' => false, 'why' => 'the request covers ' . $items . ' items, more than the limit of ' . $r['max_items'], 'ip' => '', 'cc' => ''];
    }

    $ip = smpro_spr_login_ip($user);
    if ($ip === '') {
        return ['auto' => false, 'ip' => '', 'cc' => '',
                'why' => 'the server has no recent cPanel login for this account, so where the request came from could not be established'];
    }

    $onList = function_exists('smpro_fw_allow_covers_name') ? smpro_fw_allow_covers_name($ip) : '';
    $geo    = function_exists('smpro_geo_foreign') ? smpro_geo_foreign($ip) : ['cc' => '', 'known' => false];
    $cc     = strtoupper((string)($geo['cc'] ?? ''));

    if ($onList !== '') {
        return ['auto' => true, 'ip' => $ip, 'cc' => $cc,
                'why' => 'the account signed in from ' . $ip . ', which is on your firewall allow-list (' . $onList . ')'];
    }
    if ($r['need_allowlist'] && !$r['countries']) {
        return ['auto' => false, 'ip' => $ip, 'cc' => $cc,
                'why' => $ip . ' is not on your firewall allow-list, and no countries are allowed either'];
    }
    if ($r['countries']) {
        if (empty($geo['known']) || $cc === '') {
            return ['auto' => false, 'ip' => $ip, 'cc' => '',
                    'why' => 'the country of ' . $ip . ' could not be resolved, and an unknown country never satisfies a country rule'];
        }
        if (in_array($cc, $r['countries'], true)) {
            return ['auto' => true, 'ip' => $ip, 'cc' => $cc,
                    'why' => 'the account signed in from ' . $ip . ' (' . $cc . '), a country you allow'];
        }
        return ['auto' => false, 'ip' => $ip, 'cc' => $cc,
                'why' => $ip . ' resolves to ' . $cc . ', which is not in your allowed list'];
    }

    return ['auto' => false, 'ip' => $ip, 'cc' => $cc, 'why' => 'no rule matched'];
}

/** One line describing the rules as they stand, for the operator's screen. */
function smpro_spr_describe() {
    $r = smpro_spr_get();
    if (!$r['auto_hour'] && !$r['auto_permanent']) return 'Off — every release waits for you.';
    $what = [];
    if ($r['auto_hour'])      $what[] = 'one-hour releases';
    if ($r['auto_permanent']) $what[] = 'PERMANENT releases';
    $when = [];
    if ($r['need_allowlist']) $when[] = 'from an address on your firewall allow-list';
    if ($r['countries'])      $when[] = 'from ' . implode(', ', $r['countries']);
    return 'Granting ' . implode(' and ', $what)
         . ($when ? ' when the account last signed in ' . implode(' or ', $when) : '')
         . ($r['max_items'] > 0 ? ', up to ' . $r['max_items'] . ' items' : '') . '.';
}
