<?php
/**
 * hub_ext.php — Multi-Server "Hub" RELAY for Safety Monitor Pro.
 *
 * WHM addon CGIs are guarded by cpsrvd (a valid WHM session is required), so a Hub
 * cannot open a direct inbound socket to a Member's plugin. Both installs, however,
 * already authenticate OUTBOUND to this license server. So this file turns the license
 * server into a thin, audited RELAY between a customer's own servers:
 *
 *   - a pairing REGISTRY (hub_links): who is paired with whom, which permissions were
 *     GRANTED by the Member admin, and when it was approved (this is the "approval is
 *     logged on the license server" requirement).
 *   - a per-link MAILBOX (hub_queue): the Hub drops plugin-scoped COMMANDS; the Member
 *     pulls them, executes LOCALLY under the granted permissions only, and posts back
 *     STATUS / RESULTS. The relay never executes anything and never holds root.
 *
 * Trust model: every call is authenticated exactly like /api/check — by license_key +
 * bound fingerprint (RSA-fingerprint-bound). A link binds hub_key <-> member_key; the
 * relay authorises /send + /fetch by checking the caller IS that link's hub or member.
 * The Hub role additionally requires the `multi_server` feature (Ultra plan).
 *
 * Routes (all POST JSON):
 *   /api/hub/init     (Hub)    create a pending pairing + pair_code
 *   /api/hub/lookup   (Member) read a pending pairing by pair_code (to show the consent alert)
 *   /api/hub/approve  (Member) approve with granted perms -> link becomes active, binds member
 *   /api/hub/links    (both)   list my links (role=hub|member)
 *   /api/hub/send     (both)   enqueue a mailbox item (dir=cmd from hub; status|result from member)
 *   /api/hub/fetch    (both)   pull + consume pending mailbox items for a dir
 *   /api/hub/revoke   (both)   revoke a link
 *
 * Reuses panel helpers: db(), json_input(), json_response(), log_event(), license_find(),
 * resolve_features(), normalize_fingerprint().
 */
if (!function_exists('db')) return;

/** Canonical permission catalog the Hub can request / the Member can grant. 'view' is baseline. */
function hub_perms_all(): array {
    return ['view', 'firewall', 'profiles', 'services', 'updates'];
}
function hub_perms_clean($csvOrArr): string {
    $a = is_array($csvOrArr) ? $csvOrArr : explode(',', (string)$csvOrArr);
    $a = array_values(array_intersect(array_map(fn($x) => preg_replace('/[^a-z_]/', '', strtolower((string)$x)), $a), hub_perms_all()));
    if (!in_array('view', $a, true)) array_unshift($a, 'view');   // view is always implied
    return implode(',', array_unique($a));
}

function hub_migrate(): void {
    $flag = __DIR__ . '/../storage/.hub_v1';
    if (!is_file($flag)) {
    try {
        db()->query("CREATE TABLE IF NOT EXISTS hub_links (
            id INT AUTO_INCREMENT PRIMARY KEY,
            pair_code VARCHAR(64) NOT NULL,
            hub_key VARCHAR(64) NOT NULL,
            hub_host VARCHAR(190) NOT NULL DEFAULT '',
            hub_ip VARCHAR(64) NOT NULL DEFAULT '',
            hub_label VARCHAR(120) NOT NULL DEFAULT '',
            member_key VARCHAR(64) NOT NULL DEFAULT '',
            member_host VARCHAR(190) NOT NULL DEFAULT '',
            member_ip VARCHAR(64) NOT NULL DEFAULT '',
            perms_req VARCHAR(255) NOT NULL DEFAULT 'view',
            perms_grant VARCHAR(255) NOT NULL DEFAULT '',
            status ENUM('pending','active','revoked') NOT NULL DEFAULT 'pending',
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            approved_at DATETIME NULL,
            UNIQUE KEY uq_pair (pair_code),
            KEY k_hub (hub_key, status),
            KEY k_member (member_key, status)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        db()->query("CREATE TABLE IF NOT EXISTS hub_queue (
            id INT AUTO_INCREMENT PRIMARY KEY,
            link_id INT NOT NULL,
            dir ENUM('cmd','result','status') NOT NULL,
            body MEDIUMTEXT NOT NULL,
            status ENUM('pending','consumed') NOT NULL DEFAULT 'pending',
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            consumed_at DATETIME NULL,
            KEY k_link (link_id, dir, status)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        @file_put_contents($flag, date('c'));
    } catch (\Throwable $e) { /* retry next request */ }
    }
    // v2 — targeted invitations: the hub can address a pending pairing to a specific member key.
    $flag2 = __DIR__ . '/../storage/.hub_v2';
    if (!is_file($flag2)) {
        try { @db()->query("ALTER TABLE hub_links ADD COLUMN target_member_key VARCHAR(64) NOT NULL DEFAULT ''");
              @db()->query("ALTER TABLE hub_links ADD KEY k_target (target_member_key, status)");
              @file_put_contents($flag2, date('c')); } catch (\Throwable $e) {}
    }
    // v3 — live-session marker: a hub viewing a member sets live_until so the member fast-polls.
    $flag3 = __DIR__ . '/../storage/.hub_v3';
    if (!is_file($flag3)) {
        try { @db()->query("ALTER TABLE hub_links ADD COLUMN live_until INT NOT NULL DEFAULT 0");
              @file_put_contents($flag3, date('c')); } catch (\Throwable $e) {}
    }
    // v4 — link mode: 'monitor' (read-only) or 'control' (full plugin management).
    $flag4 = __DIR__ . '/../storage/.hub_v4';
    if (!is_file($flag4)) {
        try { @db()->query("ALTER TABLE hub_links ADD COLUMN mode VARCHAR(10) NOT NULL DEFAULT 'control'");
              @file_put_contents($flag4, date('c')); } catch (\Throwable $e) {}
    }
    // v5 — ECDH public keys exchanged at pairing so the two servers derive a shared secret the relay
    // never learns; every later message is HMAC-signed with it (relay = blind transport).
    $flag5 = __DIR__ . '/../storage/.hub_v5';
    if (!is_file($flag5)) {
        try { @db()->query("ALTER TABLE hub_links ADD COLUMN hub_pub TEXT NULL");
              @db()->query("ALTER TABLE hub_links ADD COLUMN member_pub TEXT NULL");
              @file_put_contents($flag5, date('c')); } catch (\Throwable $e) {}
    }
}

/** Housekeeping (time-gated ~hourly): expire stale pairings + prune old queue rows. Cheap DoS/bloat guard. */
function hub_prune(): void {
    $stamp = __DIR__ . '/../storage/.hub_prune';
    if (is_file($stamp) && (time() - (int)@filemtime($stamp)) < 3600) return;
    @file_put_contents($stamp, (string)time());
    try {
        @db()->query("DELETE FROM hub_queue WHERE status='consumed' AND consumed_at < (NOW() - INTERVAL 1 DAY)");
        @db()->query("DELETE FROM hub_queue WHERE status='pending'  AND created_at  < (NOW() - INTERVAL 1 DAY)");
        @db()->query("DELETE FROM hub_links WHERE status='pending'  AND created_at  < (NOW() - INTERVAL 25 HOUR)");
        @db()->query("DELETE FROM hub_links WHERE status='revoked'  AND created_at  < (NOW() - INTERVAL 7 DAY)");
    } catch (\Throwable $e) {}
}

/** Authenticate a hub-API caller by license_key + bound fingerprint. Returns the license row or 4xx-exits. */
function hub_auth(array $d, ?string $needFeature = null): array {
    hub_migrate(); hub_prune();
    $key = strtoupper(trim((string)($d['license_key'] ?? '')));
    if ($key === '') json_response(['ok' => false, 'status' => 'bad_request', 'message' => 'license_key required'], 400);
    $lic = license_find($key);
    if (!$lic) json_response(['ok' => false, 'status' => 'invalid', 'message' => 'Invalid license key'], 404);
    $st = strtolower((string)($lic['status'] ?? ''));
    if ($st !== 'active' || license_expired($lic))
        json_response(['ok' => false, 'status' => $st ?: 'invalid', 'message' => 'License is not active'], 403);
    // Bind every relay call to the activated server's fingerprint (same trust as /api/check).
    $bound = strtolower((string)($lic['bound_fingerprint'] ?? ''));
    $fp = normalize_fingerprint((string)($d['fingerprint'] ?? ''));
    if ($bound !== '' && $fp !== $bound)
        json_response(['ok' => false, 'status' => 'binding_mismatch', 'message' => 'Fingerprint does not match this license'], 403);
    if ($needFeature !== null) {
        $feats = resolve_features($lic);
        if (!in_array($needFeature, $feats, true))
            json_response(['ok' => false, 'status' => 'feature_denied', 'message' => 'This requires the ' . $needFeature . ' feature (Ultra plan).'], 403);
    }
    return $lic;
}

function hub_link_find(int $id): ?array {
    $st = db()->prepare("SELECT * FROM hub_links WHERE id=? LIMIT 1");
    $st->bind_param('i', $id); $st->execute();
    return $st->get_result()->fetch_assoc() ?: null;
}

/** HUB: create a pending pairing and return a pair_code the admin carries to the Member. */
function hub_api_init(): never {
    $d = json_input();
    $lic = hub_auth($d, 'multi_server');           // only an Ultra hub may initiate
    $label = substr(trim((string)($d['hub_label'] ?? '')), 0, 120);
    $mode  = (($d['mode'] ?? 'control') === 'monitor') ? 'monitor' : 'control';
    $perms = $mode === 'monitor' ? 'view' : hub_perms_clean($d['perms_req'] ?? 'view');   // monitor = view-only
    $host  = substr((string)($d['hostname'] ?? ''), 0, 190);
    $ip    = (string)($d['server_ip'] ?? ($_SERVER['REMOTE_ADDR'] ?? ''));
    $code  = strtoupper(bin2hex(random_bytes(3))) . '-' . strtoupper(bin2hex(random_bytes(3))) . '-' . strtoupper(bin2hex(random_bytes(3)));
    $hubKey = (string)$lic['license_key'];
    $target = strtoupper(trim((string)($d['target_member_key'] ?? '')));   // optional: invite a SPECIFIC server
    if ($target !== '' && $target === $hubKey) json_response(['ok' => false, 'message' => 'A server cannot invite itself'], 400);
    // rate/quota: cap concurrent pending pairings per hub
    $rc = db()->prepare("SELECT COUNT(*) c FROM hub_links WHERE hub_key=? AND status='pending'");
    $rc->bind_param('s', $hubKey); $rc->execute();
    if ((int)($rc->get_result()->fetch_assoc()['c'] ?? 0) >= 25) json_response(['ok' => false, 'status' => 'rate_limited', 'message' => 'Too many pending pairings — approve them or wait for them to expire.'], 429);
    $hubPub = substr((string)($d['hub_pub'] ?? ''), 0, 2000);
    $st = db()->prepare("INSERT INTO hub_links (pair_code,hub_key,hub_host,hub_ip,hub_label,perms_req,target_member_key,mode,hub_pub,status) VALUES (?,?,?,?,?,?,?,?,?, 'pending')");
    $st->bind_param('sssssssss', $code, $hubKey, $host, $ip, $label, $perms, $target, $mode, $hubPub);
    $st->execute();
    $id = (int)db()->insert_id;
    log_event($hubKey, 'hub_pair_init', 'ok', 'link#' . $id . ' code=' . substr($code, 0, 3) . '***(secret) mode=' . $mode . ' perms=' . $perms . ($target ? ' target=' . $target : ''), []);   // never log the raw pairing token
    json_response(['ok' => true, 'pair_code' => $code, 'link_id' => $id, 'mode' => $mode, 'perms_req' => explode(',', $perms), 'targeted' => $target !== '']);
}

/** MEMBER: read a pending pairing by pair_code (to display the consent alert + requested perms). */
function hub_api_lookup(): never {
    $d = json_input();
    hub_auth($d);
    $code = strtoupper(trim((string)($d['pair_code'] ?? '')));
    if ($code === '') json_response(['ok' => false, 'message' => 'pair_code required'], 400);
    $st = db()->prepare("SELECT * FROM hub_links WHERE pair_code=? LIMIT 1");
    $st->bind_param('s', $code); $st->execute();
    $L = $st->get_result()->fetch_assoc();
    if (!$L) json_response(['ok' => false, 'status' => 'not_found', 'message' => 'No pairing matches that code'], 404);
    if ($L['status'] === 'revoked') json_response(['ok' => false, 'status' => 'revoked', 'message' => 'This pairing was revoked'], 410);
    if ($L['status'] !== 'pending') json_response(['ok' => false, 'status' => 'used', 'message' => 'This pairing code was already used — generate a new one'], 410);   // ONE-TIME: only a still-pending code resolves
    if (strtotime((string)$L['created_at']) < time() - 86400) json_response(['ok' => false, 'status' => 'expired', 'message' => 'This pairing code expired — generate a new one'], 410);
    json_response(['ok' => true, 'link_id' => (int)$L['id'], 'status' => $L['status'], 'mode' => $L['mode'] ?? 'control',
        'hub_label' => $L['hub_label'], 'hub_host' => $L['hub_host'], 'hub_ip' => $L['hub_ip'], 'hub_pub' => $L['hub_pub'] ?? '',
        'perms_req' => explode(',', (string)$L['perms_req']), 'created_at' => $L['created_at']]);
}

/** MEMBER: approve a pairing with the permissions the admin chose -> link becomes active. */
function hub_api_approve(): never {
    $d = json_input();
    $lic = hub_auth($d, 'multi_server');           // Members are Ultra too in this model
    $code = strtoupper(trim((string)($d['pair_code'] ?? '')));
    if ($code === '') json_response(['ok' => false, 'message' => 'pair_code required'], 400);
    $st = db()->prepare("SELECT * FROM hub_links WHERE pair_code=? LIMIT 1");
    $st->bind_param('s', $code); $st->execute();
    $L = $st->get_result()->fetch_assoc();
    if (!$L) json_response(['ok' => false, 'status' => 'not_found', 'message' => 'No pairing matches that code'], 404);
    if ($L['status'] === 'active') json_response(['ok' => true, 'already' => true, 'link_id' => (int)$L['id']]);
    if ($L['status'] === 'revoked') json_response(['ok' => false, 'status' => 'revoked', 'message' => 'This pairing was revoked'], 410);
    if ($L['status'] === 'pending' && strtotime((string)$L['created_at']) < time() - 86400) json_response(['ok' => false, 'status' => 'expired', 'message' => 'This pairing code expired — ask the hub to generate a new one'], 410);
    // a Member cannot pair with itself
    if ((string)$L['hub_key'] === (string)$lic['license_key'])
        json_response(['ok' => false, 'message' => 'A server cannot pair with itself'], 400);
    // a TARGETED invite may be approved ONLY by the addressed server — so a leaked code can't be claimed by another
    $tgt = strtoupper(trim((string)($L['target_member_key'] ?? '')));
    if ($tgt !== '' && $tgt !== strtoupper((string)$lic['license_key']))
        json_response(['ok' => false, 'status' => 'not_targeted', 'message' => 'This invitation is addressed to a different server'], 403);
    $grant = (($L['mode'] ?? 'control') === 'monitor') ? 'view' : hub_perms_clean($d['perms_grant'] ?? $L['perms_req']);   // monitor = view-only, enforced server-side
    $mKey  = (string)$lic['license_key'];
    $mHost = substr((string)($d['hostname'] ?? ''), 0, 190);
    $mIp   = (string)($d['server_ip'] ?? ($_SERVER['REMOTE_ADDR'] ?? ''));
    $mPub = substr((string)($d['member_pub'] ?? ''), 0, 2000);
    $up = db()->prepare("UPDATE hub_links SET member_key=?, member_host=?, member_ip=?, perms_grant=?, member_pub=?, status='active', approved_at=NOW() WHERE id=?");
    $lid = (int)$L['id'];
    $up->bind_param('sssssi', $mKey, $mHost, $mIp, $grant, $mPub, $lid);
    $up->execute();
    log_event($mKey, 'hub_pair_approve', 'ok', 'link#' . $lid . ' hub=' . $L['hub_key'] . ' granted=' . $grant, []);
    log_event((string)$L['hub_key'], 'hub_pair_approved_by_member', 'ok', 'link#' . $lid . ' member=' . $mKey . ' granted=' . $grant, []);
    json_response(['ok' => true, 'link_id' => $lid, 'perms_grant' => explode(',', $grant)]);
}

/** BOTH: list my links. role=hub -> links I initiated; role=member -> links managing me. */
function hub_api_links(): never {
    $d = json_input();
    $lic = hub_auth($d);
    $me = (string)$lic['license_key'];
    $role = ($d['role'] ?? 'hub') === 'member' ? 'member' : 'hub';
    $col = $role === 'member' ? 'member_key' : 'hub_key';
    $st = db()->prepare("SELECT * FROM hub_links WHERE $col=? AND status<>'revoked' ORDER BY id DESC");
    $st->bind_param('s', $me); $st->execute();
    $r = $st->get_result(); $out = [];
    while ($L = $r->fetch_assoc()) {
        // pending count waiting for this side
        $waitDir = $role === 'member' ? 'cmd' : 'status';
        $q = db()->prepare("SELECT COUNT(*) c FROM hub_queue WHERE link_id=? AND dir IN ('status','result') AND status='pending'");
        $lid = (int)$L['id']; $q->bind_param('i', $lid); $q->execute();
        $pend = (int)($q->get_result()->fetch_assoc()['c'] ?? 0);
        $out[] = [
            'link_id' => (int)$L['id'], 'status' => $L['status'],
            'pair_code' => $L['pair_code'],
            'hub_label' => $L['hub_label'], 'hub_host' => $L['hub_host'], 'hub_ip' => $L['hub_ip'], 'hub_key' => $role === 'member' ? $L['hub_key'] : '',
            'member_host' => $L['member_host'], 'member_ip' => $L['member_ip'],
            'perms_req' => explode(',', (string)$L['perms_req']),
            'perms_grant' => $L['perms_grant'] !== '' ? explode(',', (string)$L['perms_grant']) : [],
            'created_at' => $L['created_at'], 'approved_at' => $L['approved_at'],
            'inbox' => $pend, 'live_until' => (int)($L['live_until'] ?? 0), 'mode' => $L['mode'] ?? 'control',
            'hub_pub' => $L['hub_pub'] ?? '', 'member_pub' => $L['member_pub'] ?? '',
        ];
    }
    json_response(['ok' => true, 'role' => $role, 'links' => $out]);
}

/** Authorise that $me is a party of $link in the expected $sendDir direction. */
function hub_link_party(array $L, string $me, string $dir): ?string {
    // cmd is sent by the hub, consumed by the member; status/result the reverse.
    if ($dir === 'cmd')    return (string)$L['hub_key'] === $me ? 'hub' : null;
    /* status|result */    return (string)$L['member_key'] === $me ? 'member' : null;
}

/** BOTH: enqueue a mailbox item. */
function hub_api_send(): never {
    $d = json_input();
    $lic = hub_auth($d);
    $me = (string)$lic['license_key'];
    $lid = (int)($d['link_id'] ?? 0);
    $dir = in_array($d['dir'] ?? '', ['cmd', 'result', 'status'], true) ? (string)$d['dir'] : '';
    $body = (string)($d['body'] ?? '');
    if (!$lid || $dir === '' || $body === '') json_response(['ok' => false, 'message' => 'link_id, dir, body required'], 400);
    if (strlen($body) > 3000000) json_response(['ok' => false, 'message' => 'body too large'], 413);   // allows full rendered remote pages
    $L = hub_link_find($lid);
    if (!$L || $L['status'] !== 'active') json_response(['ok' => false, 'status' => 'no_link', 'message' => 'No active link'], 404);
    if (!hub_link_party($L, $me, $dir)) json_response(['ok' => false, 'status' => 'forbidden', 'message' => 'Not a party of this link / wrong direction'], 403);
    $qc = db()->prepare("SELECT COUNT(*) c FROM hub_queue WHERE link_id=? AND status='pending'");
    $qc->bind_param('i', $lid); $qc->execute();
    if ((int)($qc->get_result()->fetch_assoc()['c'] ?? 0) >= 300) json_response(['ok' => false, 'status' => 'rate_limited', 'message' => 'Mailbox full for this link — consumer is behind.'], 429);
    $st = db()->prepare("INSERT INTO hub_queue (link_id,dir,body,status) VALUES (?,?,?, 'pending')");
    $st->bind_param('iss', $lid, $dir, $body);
    $st->execute();
    json_response(['ok' => true, 'id' => (int)db()->insert_id]);
}

/** BOTH: fetch + consume pending mailbox items addressed to me for a dir. */
function hub_api_fetch(): never {
    $d = json_input();
    $lic = hub_auth($d);
    $me = (string)$lic['license_key'];
    $lid = (int)($d['link_id'] ?? 0);
    $dir = in_array($d['dir'] ?? '', ['cmd', 'result', 'status'], true) ? (string)$d['dir'] : '';
    if (!$lid || $dir === '') json_response(['ok' => false, 'message' => 'link_id, dir required'], 400);
    $L = hub_link_find($lid);
    if (!$L || $L['status'] !== 'active') json_response(['ok' => false, 'status' => 'no_link', 'message' => 'No active link'], 404);
    // a consumer of dir=cmd must be the member; of status/result must be the hub (opposite of send)
    $okParty = ($dir === 'cmd') ? ((string)$L['member_key'] === $me) : ((string)$L['hub_key'] === $me);
    if (!$okParty) json_response(['ok' => false, 'status' => 'forbidden', 'message' => 'Not the intended consumer'], 403);
    $max = max(1, min(50, (int)($d['max'] ?? 20)));
    $st = db()->prepare("SELECT id,body,created_at FROM hub_queue WHERE link_id=? AND dir=? AND status='pending' ORDER BY id ASC LIMIT ?");
    $st->bind_param('isi', $lid, $dir, $max); $st->execute();
    $r = $st->get_result();
    $items = []; $ids = [];
    while ($x = $r->fetch_assoc()) { $items[] = ['id' => (int)$x['id'], 'body' => $x['body'], 'created_at' => $x['created_at']]; $ids[] = (int)$x['id']; }
    if ($ids) {                                                 // ids are all int-cast above; rebuild a placeholder list anyway
        $ph = implode(',', array_fill(0, count($ids), '?'));
        $us = db()->prepare("UPDATE hub_queue SET status='consumed', consumed_at=NOW() WHERE id IN ($ph)");
        $us->bind_param(str_repeat('i', count($ids)), ...$ids); $us->execute();
    }
    json_response(['ok' => true, 'items' => $items, 'perms_grant' => explode(',', (string)$L['perms_grant'])]);
}

/** BOTH: revoke a link (either party may sever it). */
function hub_api_revoke(): never {
    $d = json_input();
    $lic = hub_auth($d);
    $me = (string)$lic['license_key'];
    $lid = (int)($d['link_id'] ?? 0);
    $L = $lid ? hub_link_find($lid) : null;
    if (!$L) json_response(['ok' => false, 'message' => 'link not found'], 404);
    if ((string)$L['hub_key'] !== $me && (string)$L['member_key'] !== $me && (string)($L['target_member_key'] ?? '') !== $me)
        json_response(['ok' => false, 'status' => 'forbidden', 'message' => 'Not a party of this link'], 403);
    $u1 = db()->prepare("UPDATE hub_links SET status='revoked' WHERE id=?"); $u1->bind_param('i', $lid); $u1->execute();
    $u2 = db()->prepare("DELETE FROM hub_queue WHERE link_id=?");            $u2->bind_param('i', $lid); $u2->execute();
    log_event($me, 'hub_revoke', 'ok', 'link#' . $lid, []);
    json_response(['ok' => true, 'link_id' => $lid]);
}

/** MEMBER: pending invitations addressed specifically to ME (target_member_key) — powers the banner alert. */
function hub_api_invites(): never {
    $d = json_input();
    $lic = hub_auth($d);
    $me = (string)$lic['license_key'];
    $st = db()->prepare("SELECT id,pair_code,hub_host,hub_ip,hub_label,perms_req,mode,created_at FROM hub_links WHERE target_member_key=? AND status='pending' ORDER BY id DESC LIMIT 20");
    $st->bind_param('s', $me); $st->execute();
    $r = $st->get_result(); $out = [];
    while ($L = $r->fetch_assoc()) $out[] = [
        'link_id' => (int)$L['id'], 'pair_code' => $L['pair_code'], 'mode' => $L['mode'] ?? 'control',
        'hub_label' => $L['hub_label'], 'hub_host' => $L['hub_host'], 'hub_ip' => $L['hub_ip'],
        'perms_req' => explode(',', (string)$L['perms_req']), 'created_at' => $L['created_at'],
    ];
    json_response(['ok' => true, 'invites' => $out]);
}

/** HUB: mark a member link "live" (member fast-polls for ~2 min) — called while viewing the remote panel. */
function hub_api_live(): never {
    $d = json_input(); $lic = hub_auth($d); $me = (string)$lic['license_key'];
    $lid = (int)($d['link_id'] ?? 0); $L = $lid ? hub_link_find($lid) : null;
    if (!$L || $L['status'] !== 'active') json_response(['ok' => false, 'message' => 'no active link'], 404);
    if ((string)$L['hub_key'] !== $me) json_response(['ok' => false, 'status' => 'forbidden', 'message' => 'not your link'], 403);
    $until = time() + 120;
    $u = db()->prepare("UPDATE hub_links SET live_until=? WHERE id=?"); $u->bind_param('ii', $until, $lid); $u->execute();
    json_response(['ok' => true, 'live_until' => $until]);
}

function hub_route(string $path): bool {
    if (strncmp($path, '/api/hub/', 9) !== 0) return false;
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') json_response(['ok' => false, 'message' => 'POST required'], 405);
    switch ($path) {
        case '/api/hub/init':    hub_api_init();
        case '/api/hub/lookup':  hub_api_lookup();
        case '/api/hub/approve': hub_api_approve();
        case '/api/hub/links':   hub_api_links();
        case '/api/hub/invites': hub_api_invites();
        case '/api/hub/live':    hub_api_live();
        case '/api/hub/send':    hub_api_send();
        case '/api/hub/fetch':   hub_api_fetch();
        case '/api/hub/revoke':  hub_api_revoke();
        case '/api/hub/event':   hub_api_event();
    }
    return false;
}

/** MEMBER -> relay: report a security event (failed control-password attempt / lock) so it is logged centrally
 *  on the license server for BOTH the member and its managing hub. Member-authenticated; member-of-link only. */
function hub_api_event(): never {
    $d = json_input();
    $lic = hub_auth($d);
    $lid = (int)($d['link_id'] ?? 0);
    $kind = preg_replace('/[^a-z_]/', '', strtolower((string)($d['kind'] ?? '')));
    $n = max(0, min(9999, (int)($d['n'] ?? 0)));
    if ($lid <= 0 || !in_array($kind, ['verify_fail', 'verify_lock'], true)) json_response(['ok' => false, 'message' => 'bad event'], 400);
    $st = db()->prepare("SELECT hub_key, member_key, status FROM hub_links WHERE id=? LIMIT 1");
    $st->bind_param('i', $lid); $st->execute();
    $L = $st->get_result()->fetch_assoc();
    if (!$L) json_response(['ok' => false, 'message' => 'no link'], 404);
    if (($L['status'] ?? '') !== 'active') json_response(['ok' => false, 'message' => 'link not active'], 409);
    if (strtoupper((string)$L['member_key']) !== strtoupper((string)$lic['license_key'])) json_response(['ok' => false, 'message' => 'not your link'], 403);
    $msg = $kind === 'verify_lock' ? ('remote control LOCKED (24h) after ' . $n . ' wrong control-password attempts')
                                   : ('wrong control-password attempt #' . $n . ' from the managing hub');
    log_event((string)$L['member_key'], 'hub_' . $kind, 'warn', $msg, []);
    // hub-side entry is MEMBER-ASSERTED (the member is the party defended against), so label it as reported — not a relay-observed fact
    log_event((string)$L['hub_key'],    'hub_' . $kind, 'warn', '[reported by member ' . $L['member_key'] . '] ' . $msg, []);
    json_response(['ok' => true]);
}
