<?php
/**
 * includes/fwblock.php — Recommended block-lists (shared attacker addresses → csf.deny).
 *
 * The mirror image of fwallow.php, and deliberately the same shape: a catalogue of sources, a live fetch, a
 * review, a tagged apply, and an undo that removes only what we added. Nothing here ever blocks anything on its
 * own. The operator ticks a source and presses Add, exactly as they do for Cloudflare's allow-list.
 *
 * Why a shared list at all: every server running this plugin is being hit by the same rented machines. One server
 * learns about an address only after it has already been attacked; a list pooled across servers lets the others
 * refuse it first. Why it is NOT automatic: a shared list is the one feature where somebody else's mistake becomes
 * your outage — a residential address that a hundred customers share, a mail provider, an office NAT. So this
 * carries the same guards the rest of the firewall does, and two more of its own:
 *
 *   - the verified-crawler shield runs over every single address before it is denied, so a poisoned or careless
 *     feed cannot put Googlebot into csf.deny;
 *   - anything this server has ALLOW-listed is skipped, because the operator's own decision outranks the pool.
 *
 * THE SCOPE IS NARROW ON PURPOSE: illegitimate bots that tried to break in, and nothing else. Concretely, an
 * address qualifies only if its network is a datacenter / cloud / hosting provider. That single rule removes
 * every case where a shared list turns into somebody's outage — a residential address a hundred customers share
 * behind one CGNAT, an office NAT, a mobile carrier, a mail provider. Nobody signs in to a control panel from a
 * rented server, so a rented server failing logins is a machine, and a machine is safe to pool. A person's
 * address never is, however badly it behaved here: it is this server's business, not the pool's.
 *
 * Shared by modules/firewall-status.php and bin/fw_block_sync.php.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

if (!defined('SMPRO_FWB_CFG'))   define('SMPRO_FWB_CFG',   SMPRO_VARLIB . '/fw_blocklists.json');  // {ignored:[], contribute:bool}
if (!defined('SMPRO_FWB_CACHE')) define('SMPRO_FWB_CACHE', SMPRO_VARLIB . '/fw_blockfeeds');       // per-source fetched cache
if (!defined('SMPRO_FWB_DENY'))  define('SMPRO_FWB_DENY',  '/etc/csf/csf.deny');

/**
 * The sources this build knows about.
 *
 * 'community' is the pool: addresses that independent servers running this plugin have blocked, served signed by
 * the licence host that already talks to every installation. A source declares the minimum number of DIFFERENT
 * servers that must have blocked an address before it appears — one server's mistake is not evidence.
 */
function smpro_fw_block_sources(): array {
    return [
        'community' => [
            'name' => 'SM Pro community block-list',
            'desc' => 'Addresses that several independent servers running SM Pro have each blocked for the same kind of '
                    . 'attack. Pooled, so a machine that has worked its way through other servers is refused here before '
                    . 'it reaches yours.',
            'note' => 'Every address is checked against the verified-crawler shield before it is denied, and anything on '
                    . 'your own allow-list is skipped — your decisions outrank the pool. Reversible: Remove takes out '
                    . 'exactly the lines this added and nothing else.',
            // Fetched through the licence channel rather than as an open download: the list is built from what
            // licensees reported, so the people who may read it are the people who are part of it.
            'api'   => '/api/blocklist/feed',
            'json'  => 'addresses',
            'min_servers' => 3,
        ],
    ];
}

/**
 * Is this address a machine's, rather than a person's? The pool only ever carries machines.
 *
 * Answered from network intelligence (provider / ASN), the same source the firewall page uses for its
 * cloud/hosting mark. When the intelligence is UNAVAILABLE the answer is NO — an address we cannot classify is
 * treated as a person's and left alone. Failing the other way would pool exactly the addresses we know least
 * about, which is the opposite of careful.
 */
function smpro_fw_block_is_machine(string $ip): bool {
    if (!function_exists('smpro_ip_intel') || !function_exists('smpro_ip_is_datacenter')) return false;
    $in = smpro_ip_intel($ip);
    if (!is_array($in) || (($in['provider'] ?? '') === '' && ($in['asn'] ?? '') === '')) return false;
    return (bool)smpro_ip_is_datacenter($in);
}

function smpro_fw_block_marker(string $key): string { return 'smpro-block:' . preg_replace('/[^a-z0-9]/', '', $key); }
function smpro_fw_block_cache_file(string $key): string { return SMPRO_FWB_CACHE . '/' . preg_replace('/[^a-z0-9]/', '', $key) . '.json'; }

/* ----------------------------- config ----------------------------- */
function smpro_fw_block_cfg(): array {
    $d = @is_file(SMPRO_FWB_CFG) ? json_decode((string)@file_get_contents(SMPRO_FWB_CFG), true) : null;
    $d = is_array($d) ? $d : [];
    return ['ignored' => array_values((array)($d['ignored'] ?? [])), 'contribute' => !empty($d['contribute'])];
}
function smpro_fw_block_cfg_save(array $c): bool {
    @is_dir(SMPRO_VARLIB) || @mkdir(SMPRO_VARLIB, 0700, true);
    $t = SMPRO_FWB_CFG . '.tmp';
    if (@file_put_contents($t, json_encode($c, JSON_UNESCAPED_SLASHES), LOCK_EX) === false) return false;
    @chmod($t, 0600); return @rename($t, SMPRO_FWB_CFG);
}
function smpro_fw_block_ignored(): array { return smpro_fw_block_cfg()['ignored']; }
function smpro_fw_block_set_ignore(string $key, bool $ignore): bool {
    $c = smpro_fw_block_cfg(); $key = preg_replace('/[^a-z0-9_]/', '', $key);
    $c['ignored'] = array_values(array_diff($c['ignored'], [$key]));
    if ($ignore) $c['ignored'][] = $key;
    return smpro_fw_block_cfg_save($c);
}
/** Is this server sharing what it blocks? OFF unless the operator turned it on — see smpro_fw_block_contribution(). */
function smpro_fw_block_contributing(): bool { return smpro_fw_block_cfg()['contribute']; }
function smpro_fw_block_set_contributing(bool $on): bool { $c = smpro_fw_block_cfg(); $c['contribute'] = $on; return smpro_fw_block_cfg_save($c); }

/* ----------------------------- fetch ----------------------------- */
/**
 * Pull a source's current addresses. Each entry must survive validation here, not at the far end: a feed is
 * remote input, and a remote input that reaches csf.deny unchecked is a way to take a server off the internet.
 * Returns rows [ip, servers, kind, first, last]; an entry seen by fewer than the source's minimum is dropped.
 */
function smpro_fw_block_fetch_raw(array $src): array {
    $rows = [];
    $min = max(1, (int)($src['min_servers'] ?? 1));

    // The feeds this build knows about are reached through the licence transport, which already authenticates
    // this server and pins the host. There is no URL from a request anywhere in this path.
    $docs = [];
    if (!empty($src['api']) && function_exists('smpro_lic_api')) {
        $r = smpro_lic_api((string)$src['api'], [], 30);
        if (is_array($r)) $docs[] = $r;
    }
    foreach ((array)($src['fetch'] ?? []) as $url) {
        // https only, and only a URL this build carries as a constant — nothing from a request ever reaches here.
        $u = (string)$url;
        if (stripos($u, 'https://') !== 0 || filter_var($u, FILTER_VALIDATE_URL) === false) continue;
        $body = (string)@shell_exec('timeout 25 curl -fsSL --max-redirs 3 --max-time 20 -A '
            . escapeshellarg('SMPro-fwb/1.0') . ' ' . escapeshellarg($url) . ' 2>/dev/null');
        if ($body === '' || strlen($body) > 8 * 1024 * 1024) continue;                                    // a feed is not a download
        $j = json_decode($body, true);
        if (is_array($j)) $docs[] = $j;
    }

    foreach ($docs as $j) {
        $list = (array)($j[$src['json'] ?? 'addresses'] ?? []);
        foreach ($list as $e) {
            $ip = is_array($e) ? (string)($e['ip'] ?? '') : (string)$e;
            $ip = trim($ip);
            if (!filter_var($ip, FILTER_VALIDATE_IP)) continue;                                           // single addresses only
            if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) continue;
            $n = is_array($e) ? (int)($e['servers'] ?? 0) : 0;
            if ($n < $min) continue;                                                                      // one server is not evidence
            // The feed says it is a machine; this server checks that for itself before the address can be used.
            // A feed's own claim is never the last word on what reaches csf.deny.
            if (is_array($e) && isset($e['machine']) && empty($e['machine'])) continue;
            $rows[$ip] = ['ip' => $ip, 'servers' => $n,
                          'kind'  => preg_replace('/[^a-z_]/', '', strtolower((string)(is_array($e) ? ($e['kind'] ?? '') : ''))),
                          'first' => (int)(is_array($e) ? ($e['first'] ?? 0) : 0),
                          'last'  => (int)(is_array($e) ? ($e['last'] ?? 0) : 0)];
            if (count($rows) >= 50000) break 2;
        }
    }
    return array_values($rows);
}
function smpro_fw_block_fetch(string $key): array {
    $src = smpro_fw_block_sources()[$key] ?? null; if (!$src) return [];
    $rows = smpro_fw_block_fetch_raw($src);
    if ($rows) {
        @is_dir(SMPRO_FWB_CACHE) || @mkdir(SMPRO_FWB_CACHE, 0700, true);
        $f = smpro_fw_block_cache_file($key); $t = $f . '.tmp';
        if (@file_put_contents($t, json_encode(['rows' => $rows, 'fetched_at' => time()], JSON_UNESCAPED_SLASHES), LOCK_EX) !== false) { @chmod($t, 0600); @rename($t, $f); }
    }
    return $rows;
}
/** What is on disk. Never hits the network — the page renders from this. */
function smpro_fw_block_rows(string $key): array {
    $f = smpro_fw_block_cache_file($key);
    if (!@is_file($f)) return [];
    $d = json_decode((string)@file_get_contents($f), true);
    return is_array($d) && is_array($d['rows'] ?? null) ? $d['rows'] : [];
}
function smpro_fw_block_synced_at(string $key): int {
    $f = smpro_fw_block_cache_file($key);
    if (!@is_file($f)) return 0;
    $d = json_decode((string)@file_get_contents($f), true);
    return (int)($d['fetched_at'] ?? @filemtime($f));
}

/* ----------------------------- review ----------------------------- */
/**
 * What applying this source would actually do, decided BEFORE anything is written.
 *
 * This is the review step. Each address is sorted into exactly one bucket and the page shows the counts, so the
 * operator presses Add knowing what it means rather than finding out from csf.deny afterwards.
 *   blocked  — already denied here; nothing to do
 *   allowed  — on this server's allow-list: skipped, because the operator's own decision outranks the pool
 *   crawler  — forward-confirmed as a real crawler: refused outright, whatever the feed says
 *   human    — not a datacenter network, so out of scope: this list is illegitimate BOTS only
 *   add      — what would be added
 */
function smpro_fw_block_review(string $key, int $budget = 0): array {
    $rows = smpro_fw_block_rows($key);
    $out = ['add' => [], 'blocked' => [], 'allowed' => [], 'crawler' => [], 'human' => [], 'checked' => 0, 'total' => count($rows), 'complete' => true];
    if (!$rows) return $out;

    if (!function_exists('smpro_bg_crawler_shield')) { $bg = __DIR__ . '/botguard.php'; if (@is_file($bg)) require_once $bg; }
    $ips = array_column($rows, 'ip');
    // One bulk reverse sweep for the whole list rather than a lookup per address; the shield then re-uses those
    // names. Without this a list of a few thousand would spend its budget waiting on DNS, which is exactly the
    // failure the firewall sweep already had.
    $rdns = function_exists('smpro_bg_rdns_bulk') ? smpro_bg_rdns_bulk($ips, $budget) : [];

    foreach ($rows as $r) {
        $ip = $r['ip'];
        if (function_exists('smpro_csf_denied') && smpro_csf_denied($ip)) { $out['blocked'][] = $r; $out['checked']++; continue; }
        if (function_exists('smpro_fw_allow_covers') && smpro_fw_allow_covers($ip) !== '') { $out['allowed'][] = $r; $out['checked']++; continue; }
        if (function_exists('smpro_im_allowlisted') && smpro_im_allowlisted($ip)) { $out['allowed'][] = $r; $out['checked']++; continue; }
        if (function_exists('smpro_bg_crawler_shield')) {
            // A name the sweep did not reach is NOT treated as "no reverse DNS": that would let a slow resolver
            // turn into a blocked crawler. It is left unchecked and reported as such.
            if (!array_key_exists($ip, $rdns) && $rdns !== []) { $out['complete'] = false; continue; }
            $cs = smpro_bg_crawler_shield($ip, null, $rdns[$ip] ?? null);
            if (!empty($cs['crawler'])) { $out['crawler'][] = $r + ['bot' => $cs['name'], 'host' => $cs['host']]; $out['checked']++; continue; }
        }
        // Re-checked here, against THIS server's own network intelligence, even though the feed already filtered
        // for it. Somewhere a person is behind a residential address, and no amount of agreement between other
        // servers makes blocking one of those the right call on this one.
        if (!smpro_fw_block_is_machine($ip)) { $out['human'][] = $r; $out['checked']++; continue; }
        $out['add'][] = $r; $out['checked']++;
    }
    return $out;
}

/* ----------------------------- apply / undo ----------------------------- */
/** Add what the review says would be added, tagged so it can be taken out again exactly. */
function smpro_fw_block_apply(string $key): array {
    $src = smpro_fw_block_sources()[$key] ?? null;
    if (!$src) return ['ok' => false, 'msg' => 'Unknown block-list.'];
    smpro_fw_block_fetch($key);                                  // review what is current, not what was cached last week
    $rev = smpro_fw_block_review($key);
    if (!$rev['add']) return ['ok' => true, 'added' => 0, 'review' => $rev,
        'msg' => $src['name'] . ': nothing to add — ' . count($rev['blocked']) . ' already blocked, '
               . count($rev['allowed']) . ' on your allow-list, ' . count($rev['crawler']) . ' refused as real crawlers, '
               . count($rev['human']) . ' skipped as not a datacenter network.'];

    $marker = smpro_fw_block_marker($key); $added = 0; $failed = 0;
    foreach ($rev['add'] as $r) {
        // Through the normal chokepoint, so the crawler shield, the Cloudflare refusal and the live-engine choice
        // all apply here exactly as they do to a button press. A feed gets no privileges a person does not have.
        $res = function_exists('smpro_fw_block_ip') ? smpro_fw_block_ip($r['ip'], $marker) : ['ok' => false];
        if (!empty($res['ok'])) $added++; else $failed++;
    }
    if (function_exists('smpro_audit')) smpro_audit('firewall_blocklist_apply',
        ['source' => $key, 'added' => $added, 'failed' => $failed, 'skipped_allowed' => count($rev['allowed']), 'skipped_human' => count($rev['human']),
         'refused_crawler' => count($rev['crawler']), 'actor' => function_exists('smpro_current_actor') ? smpro_current_actor() : 'root']);
    return ['ok' => $added > 0 || $failed === 0, 'added' => $added, 'failed' => $failed, 'review' => $rev,
        'msg' => $src['name'] . ': ' . $added . ' address(es) blocked'
               . ($failed ? ', ' . $failed . ' could not be' : '')
               . ($rev['allowed'] ? ', ' . count($rev['allowed']) . ' skipped as allow-listed' : '')
               . ($rev['crawler'] ? ', ' . count($rev['crawler']) . ' refused as real crawlers' : '')
               . ($rev['human'] ? ', ' . count($rev['human']) . ' skipped as not a datacenter network' : '') . '.'];
}

/** Take out ONLY the lines this source added. Never touches a block made by anyone or anything else. */
function smpro_fw_block_undo(string $key): array {
    $src = smpro_fw_block_sources()[$key] ?? null;
    if (!$src) return ['ok' => false, 'msg' => 'Unknown block-list.'];
    if (!@is_file(SMPRO_FWB_DENY) || !@is_writable(SMPRO_FWB_DENY)) return ['ok' => false, 'msg' => 'csf.deny is not writable.'];
    $marker = smpro_fw_block_marker($key);
    $lines = file(SMPRO_FWB_DENY, FILE_IGNORE_NEW_LINES) ?: [];
    $keep = []; $ours = [];
    foreach ($lines as $l) {
        if (strpos($l, $marker) !== false && preg_match('/^\s*([0-9a-fA-F:.]+)/', $l, $m)) { $ours[] = $m[1]; continue; }
        $keep[] = $l;
    }
    if (!$ours) return ['ok' => true, 'removed' => 0, 'msg' => $src['name'] . ': nothing of ours is in csf.deny.'];
    @file_put_contents(SMPRO_FWB_DENY, implode("\n", $keep) . "\n", LOCK_EX);
    $csf = function_exists('smpro_csf_bin') ? smpro_csf_bin() : '';
    if ($csf !== '') @shell_exec('timeout 60 ' . escapeshellarg($csf) . ' -r >/dev/null 2>&1');
    clearstatcache();
    // Verified, not assumed: report what really left the file.
    $still = 0;
    foreach ($ours as $ip) if (function_exists('smpro_csf_denied') && smpro_csf_denied($ip)) $still++;
    if (function_exists('smpro_audit')) smpro_audit('firewall_blocklist_undo',
        ['source' => $key, 'removed' => count($ours) - $still, 'stuck' => $still, 'actor' => function_exists('smpro_current_actor') ? smpro_current_actor() : 'root']);
    return ['ok' => $still === 0, 'removed' => count($ours) - $still,
        'msg' => $src['name'] . ': ' . (count($ours) - $still) . ' of ' . count($ours) . ' removed from csf.deny' . ($still ? ' — ' . $still . ' could not be removed' : '') . '.'];
}

/** How much of a source is currently in csf.deny under our marker. */
function smpro_fw_block_status(string $key): array {
    $rows = smpro_fw_block_rows($key);
    $marker = smpro_fw_block_marker($key);
    $lines = @is_readable(SMPRO_FWB_DENY) ? (file(SMPRO_FWB_DENY, FILE_IGNORE_NEW_LINES) ?: []) : [];
    $mine = [];
    foreach ($lines as $l) if (strpos($l, $marker) !== false && preg_match('/^\s*([0-9a-fA-F:.]+)/', $l, $m)) $mine[$m[1]] = 1;
    $present = 0;
    foreach ($rows as $r) if (isset($mine[$r['ip']])) $present++;
    return ['total' => count($rows), 'applied' => count($mine), 'present' => $present, 'synced_at' => smpro_fw_block_synced_at($key)];
}

/* ----------------------------- contributing back ----------------------------- */
/**
 * Exactly what this server would send to the pool, built so it can be SHOWN before it is sent.
 *
 * The rule: attacker addresses and what they attacked. Nothing that identifies this server, its customers or
 * their sites — no hostname, no domain, no account name, no log line, no licence key in the payload beyond what
 * the transport already needs to authenticate. There is nothing here to redact because nothing identifying is
 * collected in the first place, which is the only version of that promise that survives contact with a bug.
 *
 * Addresses on this server's own allow-list are excluded: telling the pool to block what we ourselves trust
 * would be exporting a mistake. So are addresses on residential, business, mobile or otherwise non-datacenter
 * networks, and so is anything that turns out to be a real crawler — the pool carries illegitimate BOTS that
 * tried to break in, and nothing else. Sharing a person's address would push one server's judgement about one
 * human onto every other server, where nobody can see the evidence or argue with it.
 */
function smpro_fw_block_contribution(int $max = 2000): array {
    $out = [];
    $lines = @is_readable(SMPRO_FWB_DENY) ? (file(SMPRO_FWB_DENY, FILE_IGNORE_NEW_LINES) ?: []) : [];
    $mineMarker = 'smpro-block:';                                  // never re-share what the pool gave us
    foreach ($lines as $l) {
        $l = trim($l);
        if ($l === '' || $l[0] === '#') continue;
        if (strpos($l, $mineMarker) !== false) continue;
        if (!preg_match('/^([0-9a-fA-F:.]+)\s*(?:#\s*(.*))?$/', $l, $m)) continue;
        $ip = $m[1];
        if (!filter_var($ip, FILTER_VALIDATE_IP)) continue;
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) continue;
        if (function_exists('smpro_fw_allow_covers') && smpro_fw_allow_covers($ip) !== '') continue;
        if (!smpro_fw_block_is_machine($ip)) continue;                 // a person's address is this server's business
        if (function_exists('smpro_bg_crawler_shield') && !empty(smpro_bg_crawler_shield($ip)['crawler'])) continue;
        $why = strtolower((string)($m[2] ?? ''));
        // The KIND only, from words that appear in a firewall comment — never the comment itself, which on a
        // cPanel server names the account and the domain that was attacked.
        $kind = 'other';
        if (strpos($why, 'ssh') !== false)                                   $kind = 'ssh';
        elseif (strpos($why, 'cpanel') !== false || strpos($why, 'webmail') !== false) $kind = 'panel';
        elseif (strpos($why, 'smtp') !== false || strpos($why, 'exim') !== false || strpos($why, 'imap') !== false || strpos($why, 'pop3') !== false) $kind = 'mail';
        elseif (strpos($why, 'ftp') !== false)                               $kind = 'ftp';
        elseif (strpos($why, 'mod_security') !== false || strpos($why, 'modsec') !== false) $kind = 'web';
        $out[$ip] = ['ip' => $ip, 'kind' => $kind, 'machine' => true];
        if (count($out) >= $max) break;
    }
    return array_values($out);
}

/**
 * Send it. Only ever called from an explicit press, and refused unless sharing has been switched on — the same
 * two-step the rest of this page uses: review first, then act.
 */
function smpro_fw_block_contribute(): array {
    if (!smpro_fw_block_contributing())
        return ['ok' => false, 'sent' => 0, 'msg' => 'Sharing is off. Turn it on first — nothing is ever sent without that.'];
    $rows = smpro_fw_block_contribution();
    if (!$rows) return ['ok' => true, 'sent' => 0, 'msg' => 'Nothing to share: nothing blocked here is an illegitimate bot on a datacenter network.'];
    if (!function_exists('smpro_lic_api')) return ['ok' => false, 'sent' => 0, 'msg' => 'The licence transport is unavailable on this server.'];
    $r = smpro_lic_api('/api/blocklist/contribute', ['addresses' => $rows, 'n' => count($rows)], 25);
    $ok = is_array($r) && !empty($r['ok']);
    if (function_exists('smpro_audit')) smpro_audit('firewall_blocklist_contribute',
        ['sent' => count($rows), 'ok' => $ok ? 1 : 0, 'actor' => function_exists('smpro_current_actor') ? smpro_current_actor() : 'root']);
    return ['ok' => $ok, 'sent' => $ok ? count($rows) : 0,
        'msg' => $ok ? (count($rows) . ' address(es) shared with the pool. Nothing identifying this server was sent.')
                     : ('The pool did not accept the upload: ' . (string)($r['error'] ?? $r['message'] ?? 'no answer') . '. Nothing was lost — try again later.')];
}
