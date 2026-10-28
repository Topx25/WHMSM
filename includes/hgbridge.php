<?php
/**
 * includes/hgbridge.php - the HostGuard bridge, this product's side.
 *
 * Several HostGuard products can run on one server (this plugin, a WordPress guard, a mail guard) and each of them
 * writes firewall denies and immutable flags on its own. Without a shared contract they fight: one blocks a
 * customer the other protects, one locks a file the other is asked to free. The contract is a set of plain files
 * under one directory that every product reads before it acts and writes after it acts. No network, no daemon,
 * no product depends on another being installed. The full format is in docs/HOSTGUARD-BRIDGE.md.
 *
 *   policy.json             this product writes it: home regions, allow-list, never-block ranges, excluded accounts
 *   blocks.jsonl            every product appends its blocks and lifts (one JSON object per line)
 *   locks/<account>/<product>.json   the paths a product holds immutable on that account
 *   locks/<account>/release-<product>.json   a request that the named product release its locks there
 *   events/<product>/*.json  what a product saw and wants the others to know (an attack, a lift, an exclusion)
 *
 * Everything here is bounded and tolerant: a missing directory means "no other product", a malformed line is
 * skipped, and nothing is ever deleted that another product wrote except events older than the retention.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

if (!defined('SMPRO_HG_DIR'))     define('SMPRO_HG_DIR', '/var/lib/hostguard');
if (!defined('SMPRO_HG_PRODUCT')) define('SMPRO_HG_PRODUCT', 'smpro');
if (!defined('SMPRO_HG_STATE'))   define('SMPRO_HG_STATE', SMPRO_VARLIB . '/hgbridge.json');   // cursor + last policy hash

function smpro_hg_dir($sub = '') { $d = rtrim(SMPRO_HG_DIR, '/') . ($sub !== '' ? '/' . $sub : ''); if (!is_dir($d)) { @mkdir($d, 0755, true); @chmod(rtrim(SMPRO_HG_DIR, '/'), 0755); } return $d; }
function smpro_hg_state() { $d = @is_file(SMPRO_HG_STATE) ? json_decode((string)@file_get_contents(SMPRO_HG_STATE), true) : null; return is_array($d) ? $d : []; }
function smpro_hg_state_save(array $s) { $f = SMPRO_HG_STATE; @is_dir(dirname($f)) || @mkdir(dirname($f), 0700, true); @file_put_contents($f . '.tmp', json_encode($s), LOCK_EX); @chmod($f . '.tmp', 0600); @rename($f . '.tmp', $f); }
function smpro_hg_json_write($path, array $data) { $t = $path . '.tmp'; if (@file_put_contents($t, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n", LOCK_EX) === false) return false; @chmod($t, 0644); return @rename($t, $path); }
function smpro_hg_read_json($path) { $j = @is_file($path) ? json_decode((string)@file_get_contents($path), true) : null; return is_array($j) ? $j : null; }

/* ============================ policy: what this product knows that the others must honour ============================ */
function smpro_hg_policy_build() {
    $c = function_exists('smpro_in_cfg') ? smpro_in_cfg() : [];
    $never = [];
    if (function_exists('smpro_fw_allow_providers') && function_exists('smpro_fw_allow_ranges')) {
        foreach (smpro_fw_allow_providers() as $k => $pv) if (!empty($pv['never_block'])) $never[$k] = ['name' => (string)($pv['name'] ?? $k), 'ranges' => array_values((array)smpro_fw_allow_ranges($k))];
    }
    $excluded = [];
    if (function_exists('smpro_ph_ign_all')) foreach (smpro_ph_ign_all() as $u => $row) $excluded[] = ['account' => (string)$u, 'scope' => (string)($row['scope'] ?? 'all'), 'reason' => (string)($row['reason'] ?? '')];
    return [
        'format' => 'hostguard-bridge/1', 'written_by' => SMPRO_HG_PRODUCT, 'written_at' => date('c'),
        // residential addresses in these countries are customers: no product auto-blocks them; report to the bridge instead
        'home_regions' => array_values(array_filter(array_map('strtoupper', array_map('trim', (array)($c['protect_regions'] ?? []))))),
        'caution_regions' => array_values(array_filter(array_map('strtoupper', array_map('trim', (array)($c['caution_regions'] ?? []))))),
        'home_shield' => array_key_exists('home_shield', $c) ? !empty($c['home_shield']) : true,
        // never blocked by any product, by hand or by rule
        'allowlist' => array_values(array_filter(array_map('trim', (array)($c['allowlist'] ?? [])))),
        'never_block' => $never,
        // the operator excluded these accounts from file protection: no product sets an immutable flag under them
        'excluded_accounts' => $excluded,
        // how to say "block this" without doing it: drop an event with action_wanted=block; the policy owner decides
        'block_requests' => 'events/<product>/ with action_wanted: block',
    ];
}
/** Write policy.json when it changed. Returns true when a write happened. */
function smpro_hg_policy_write($force = false) {
    $p = smpro_hg_policy_build(); $cmp = $p; unset($cmp['written_at']);
    $h = sha1(json_encode($cmp)); $st = smpro_hg_state();
    if (!$force && ($st['policy_sha'] ?? '') === $h && @is_file(smpro_hg_dir() . '/policy.json')) return false;
    $ok = smpro_hg_json_write(smpro_hg_dir() . '/policy.json', $p);
    if ($ok) { $st['policy_sha'] = $h; $st['policy_at'] = time(); smpro_hg_state_save($st); }
    return $ok;
}
function smpro_hg_policy_read() { return smpro_hg_read_json(smpro_hg_dir() . '/policy.json'); }

/* ============================ blocks ledger: who blocked what, and who lifted it ============================ */
function smpro_hg_blocks_path() { return smpro_hg_dir() . '/blocks.jsonl'; }
/** Append one line: action block|lift, by = product. Other products call their own copy of this. */
function smpro_hg_block_record($ip, $action, $rule = '', $site = '', $evidence = '', $product = SMPRO_HG_PRODUCT) {
    if (!filter_var((string)$ip, FILTER_VALIDATE_IP)) return false;
    $row = ['ts' => time(), 'at' => date('c'), 'product' => (string)$product, 'action' => $action === 'lift' ? 'lift' : 'block', 'ip' => (string)$ip,
            'rule' => mb_substr((string)$rule, 0, 120), 'site' => mb_substr((string)$site, 0, 120), 'evidence' => mb_substr((string)$evidence, 0, 300)];
    $f = smpro_hg_blocks_path();
    $ok = @file_put_contents($f, json_encode($row, JSON_UNESCAPED_SLASHES) . "\n", FILE_APPEND | LOCK_EX) !== false;
    if ($ok) @chmod($f, 0644);
    // keep the ledger bounded: past 20,000 lines the oldest half goes
    clearstatcache(); if ($ok && @filesize($f) > 6000000) { $ls = file($f, FILE_IGNORE_NEW_LINES) ?: []; if (count($ls) > 20000) @file_put_contents($f, implode("\n", array_slice($ls, -10000)) . "\n", LOCK_EX); }
    return $ok;
}
/** Records for one address (newest first) or the last $limit of all, written by ANY product. */
function smpro_hg_blocks_read($ip = '', $limit = 20) {
    $f = smpro_hg_blocks_path(); if (!@is_file($f)) return [];
    $out = [];
    foreach (array_reverse(file($f, FILE_IGNORE_NEW_LINES) ?: []) as $l) {
        $j = json_decode($l, true); if (!is_array($j)) continue;
        if ($ip !== '' && (string)($j['ip'] ?? '') !== (string)$ip) continue;
        $out[] = $j; if (count($out) >= $limit) break;
    }
    return $out;
}
/** The other products' current view of an address: the newest record that is not ours, if its last action was a block. */
function smpro_hg_blocked_by_others($ip) {
    foreach (smpro_hg_blocks_read($ip, 50) as $r) { if (($r['product'] ?? '') === SMPRO_HG_PRODUCT) continue; return ($r['action'] ?? '') === 'block' ? $r : null; }
    return null;
}

/* ============================ locks: who holds an immutable flag where ============================ */
function smpro_hg_locks_dir($account) { $a = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)$account); return $a === '' ? '' : smpro_hg_dir('locks/' . $a); }
/** Write this product's lock list for an account (from the PHP Harden manifest). Empty list = file removed. */
function smpro_hg_locks_write($account, array $paths) {
    $d = smpro_hg_locks_dir($account); if ($d === '') return false;
    $f = $d . '/' . SMPRO_HG_PRODUCT . '.json';
    $paths = array_values(array_unique(array_filter(array_map('strval', $paths))));
    if (!$paths) { if (@is_file($f)) @unlink($f); return true; }
    return smpro_hg_json_write($f, ['format' => 'hostguard-bridge/1', 'product' => SMPRO_HG_PRODUCT, 'account' => (string)$account, 'written_at' => date('c'), 'paths' => $paths]);
}
/** Paths other products hold on this account: [product => [paths]]. */
function smpro_hg_locks_others($account) {
    $d = smpro_hg_locks_dir($account); $out = [];
    if ($d === '' || !is_dir($d)) return $out;
    foreach (glob($d . '/*.json') ?: [] as $f) {
        $b = basename($f, '.json'); if ($b === SMPRO_HG_PRODUCT || strpos($b, 'release-') === 0) continue;
        $j = smpro_hg_read_json($f); if ($j && !empty($j['paths'])) $out[$b] = array_values(array_map('strval', (array)$j['paths']));
    }
    return $out;
}
/** Which other product owns this path on the account, or ''. */
function smpro_hg_lock_owner($account, $path) {
    foreach (smpro_hg_locks_others($account) as $prod => $paths) foreach ($paths as $p) if ($p === $path || strpos($path, rtrim($p, '/') . '/') === 0) return $prod;
    return '';
}
/** Ask the named product(s) to release their locks on an account and not re-apply them; written next to the lock lists. */
function smpro_hg_release_request($account, $reason, array $products = []) {
    $d = smpro_hg_locks_dir($account); if ($d === '') return false;
    if (!$products) $products = array_keys(smpro_hg_locks_others($account));
    $ok = true;
    foreach ($products as $p) {
        $p = preg_replace('/[^a-z0-9_-]/', '', strtolower((string)$p)); if ($p === '' || $p === SMPRO_HG_PRODUCT) continue;
        $ok = smpro_hg_json_write($d . '/release-' . $p . '.json', ['format' => 'hostguard-bridge/1', 'from' => SMPRO_HG_PRODUCT, 'to' => $p, 'account' => (string)$account, 'reason' => mb_substr((string)$reason, 0, 200), 'written_at' => date('c'), 'wanted' => 'release and do not re-lock while this file exists']) && $ok;
    }
    return $ok;
}
/** Release requests addressed to THIS product (another product freed an account and asks us to stay off it). */
function smpro_hg_release_requests_for_me() {
    $out = [];
    foreach (glob(smpro_hg_dir('locks') . '/*/release-' . SMPRO_HG_PRODUCT . '.json') ?: [] as $f) { $j = smpro_hg_read_json($f); if ($j) $out[basename(dirname($f))] = $j; }
    return $out;
}

/* ============================ events: what a product saw ============================ */
function smpro_hg_events_dir($product = SMPRO_HG_PRODUCT) { return smpro_hg_dir('events/' . preg_replace('/[^a-z0-9_-]/', '', strtolower((string)$product))); }
/** Emit one event for the other products. $type: attack | block_lifted | account_excluded | block_declined | ... */
function smpro_hg_event_emit($type, array $data) {
    $d = smpro_hg_events_dir();
    $row = ['format' => 'hostguard-bridge/1', 'product' => SMPRO_HG_PRODUCT, 'ts' => time(), 'at' => date('c'), 'type' => preg_replace('/[^a-z_]/', '', (string)$type)] + $data;
    $f = $d . '/' . $row['ts'] . '-' . substr(sha1(json_encode($row) . mt_rand()), 0, 8) . '.json';
    $ok = smpro_hg_json_write($f, $row);
    // our own events older than 7 days are ours to remove
    foreach (glob($d . '/*.json') ?: [] as $old) if (@filemtime($old) < time() - 7 * 86400) @unlink($old);
    return $ok;
}
/**
 * Read the other products' events this product has not seen yet (a cursor per product in the state file; files are
 * never deleted here, their writer owns them). Returns [['product'=>..., 'file'=>..., + event fields], ...], oldest first.
 */
function smpro_hg_events_new($limit = 200) {
    $st = smpro_hg_state(); $cur = (array)($st['events_cursor'] ?? []); $out = [];
    foreach (glob(smpro_hg_dir('events') . '/*', GLOB_ONLYDIR) ?: [] as $pd) {
        $prod = basename($pd); if ($prod === SMPRO_HG_PRODUCT) continue;
        $files = glob($pd . '/*.json') ?: []; sort($files);
        $last = (string)($cur[$prod] ?? '');
        foreach ($files as $f) {
            if (basename($f) <= $last) continue;
            $j = smpro_hg_read_json($f); if ($j) $out[] = ['product' => $prod, 'file' => basename($f)] + $j;
            $cur[$prod] = basename($f);
            if (count($out) >= $limit) break 2;
        }
    }
    $st['events_cursor'] = $cur; smpro_hg_state_save($st);
    return $out;
}
/**
 * Act on the other products' events by THIS product's policy. An event that wants a block is decided here: a
 * residential home-region address is never blocked (declined, and the decline is an event the sender can read);
 * otherwise it is blocked when auto-block is on and not in dry-run, else held. Every event is audited; a
 * bounded ledger keeps what each product reported per address for the IP report.
 */
function smpro_hg_events_ingest() {
    $ev = smpro_hg_events_new(); if (!$ev) return ['seen' => 0, 'blocked' => 0, 'declined' => 0, 'held' => 0];
    $c = function_exists('smpro_in_cfg') ? smpro_in_cfg() : [];
    $n = ['seen' => 0, 'blocked' => 0, 'declined' => 0, 'held' => 0];
    $led = SMPRO_VARLIB . '/intrusion/hg_events.jsonl'; @is_dir(dirname($led)) || @mkdir(dirname($led), 0700, true);
    foreach ($ev as $e) {
        $n['seen']++;
        $ip = (string)($e['ip'] ?? ''); $want = (string)($e['action_wanted'] ?? 'report'); $decision = 'noted';
        if ($want === 'block' && filter_var($ip, FILTER_VALIDATE_IP)) {
            $rs = function_exists('smpro_im_region_status') ? smpro_im_region_status($ip) : 'normal';
            $allowed = function_exists('smpro_im_allowlisted') ? smpro_im_allowlisted($ip) : false;
            if ($rs === 'core_protected' || $allowed || (function_exists('smpro_ip_is_cloudflare') && smpro_ip_is_cloudflare($ip))) {
                $decision = 'declined'; $n['declined']++;
                smpro_hg_event_emit('block_declined', ['ip' => $ip, 'to' => $e['product'], 'why' => $allowed ? 'on the allow-list' : ($rs === 'core_protected' ? 'residential address in a home region (a customer)' : 'infrastructure address'), 'in_reply_to' => $e['file']]);
            } elseif (!empty($c['auto_block']) && empty($c['auto_block_dryrun']) && function_exists('smpro_im_csf_block')) {
                $r = smpro_im_csf_block($ip); $decision = !empty($r['ok']) ? 'blocked' : 'block_failed'; if (!empty($r['ok'])) $n['blocked']++;
                smpro_hg_block_record($ip, 'block', 'requested by ' . $e['product'] . ': ' . (string)($e['rule'] ?? ''), (string)($e['site'] ?? ''), (string)($e['evidence'] ?? ''));
            } else { $decision = 'held'; $n['held']++; }
        }
        @file_put_contents($led, json_encode(['ts' => time(), 'from' => $e['product'], 'type' => $e['type'] ?? '', 'ip' => $ip, 'site' => (string)($e['site'] ?? ''), 'account' => (string)($e['account'] ?? ''), 'rule' => (string)($e['rule'] ?? ''), 'wanted' => $want, 'decision' => $decision], JSON_UNESCAPED_SLASHES) . "\n", FILE_APPEND | LOCK_EX);
        if (function_exists('smpro_audit')) @smpro_audit('hg_event', ['from' => $e['product'], 'type' => $e['type'] ?? '', 'ip' => $ip, 'wanted' => $want, 'decision' => $decision]);
    }
    clearstatcache(); if (@filesize($led) > 3000000) { $ls = file($led, FILE_IGNORE_NEW_LINES) ?: []; if (count($ls) > 10000) @file_put_contents($led, implode("\n", array_slice($ls, -5000)) . "\n", LOCK_EX); }
    return $n;
}
/** What other products reported about one address (newest first), for the IP report. */
function smpro_hg_events_for_ip($ip, $limit = 5) {
    $led = SMPRO_VARLIB . '/intrusion/hg_events.jsonl'; if (!@is_file($led)) return [];
    $out = []; foreach (array_reverse(file($led, FILE_IGNORE_NEW_LINES) ?: []) as $l) { $j = json_decode($l, true); if (is_array($j) && ($j['ip'] ?? '') === $ip) { $out[] = $j; if (count($out) >= $limit) break; } }
    return $out;
}

/* ============================ the minute tick ============================ */
/** Policy when changed, our lock lists every 10 minutes, the others' events every minute. Cheap when nothing moved. */
function smpro_hg_tick() {
    $out = ['policy' => false, 'locks' => 0, 'events' => []];
    try { $out['policy'] = smpro_hg_policy_write(); } catch (\Throwable $e) { $out['errors'][] = 'policy: ' . $e->getMessage(); }
    $st = smpro_hg_state();
    if ((int)($st['locks_at'] ?? 0) < time() - 600) {
        $dir = SMPRO_VARLIB . '/php_harden'; $n = 0;
        foreach (glob($dir . '/*.json') ?: [] as $f) {
            $m = smpro_hg_read_json($f); if (!$m || (string)($m['version'] ?? '') !== 'smpro.ph1' || empty($m['user'])) continue;   // manifests only
            $paths = [];
            if (($m['status'] ?? '') === 'locked') {
                foreach ((array)($m['protected_files'] ?? []) as $x) { $p = is_array($x) ? (string)($x['path'] ?? '') : (string)$x; if ($p !== '') $paths[] = $p; }
                foreach ((array)($m['locked_roots'] ?? []) as $x) { $p = is_array($x) ? (string)($x['dir'] ?? '') : (string)$x; if ($p !== '') $paths[] = $p; }
            }
            smpro_hg_locks_write((string)$m['user'], $paths); $n++;
        }
        $st = smpro_hg_state(); $st['locks_at'] = time(); smpro_hg_state_save($st); $out['locks'] = $n;
    }
    try { $out['events'] = smpro_hg_events_ingest(); } catch (\Throwable $e) { $out['errors'][] = 'events: ' . $e->getMessage(); }
    return $out;
}
