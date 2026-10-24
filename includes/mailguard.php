<?php
/**
 * includes/mailguard.php - living beside MailGuard (the outgoing-mail protection product) on the same server.
 *
 * WHY THIS FILE EXISTS. Both products enforce from ONE sender-block list (/etc/smpro_blocked_senders): MailGuard reads
 * and writes it, and places its own Exim rule that consults it. Until now this plugin only knew MailGuard was "present"
 * and described it as unrelated - so an operator who disabled enforcement here was told nothing is blocked while
 * MailGuard's rule went on blocking, and MailGuard's holds, throttles and verdicts were invisible from this side.
 *
 * Rules of the house:
 *   - READ ONLY. Nothing in MailGuard's folders, lists, database or configuration is ever written by this plugin.
 *     Its database is opened read-only with a short busy timeout; a locked or missing database reads as "unreadable",
 *     which is said as such and never shown as "nothing".
 *   - MailGuard's own files are trusted: never a finding, never quarantined, never "cleaned".
 *   - The Exim rebuild is serialised with MailGuard's own lock, so the two never rebuild at once.
 *   - No account, address or path from any server is written in this code.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit; }

define('SMPRO_MG_ROOT',   '/opt/mailguard');
define('SMPRO_MG_ETC',    '/etc/mailguard');
define('SMPRO_MG_VAR',    '/var/lib/mailguard');
define('SMPRO_MG_LOCK',   SMPRO_MG_VAR . '/exim-rebuild.lock');
/** The rule MailGuard places for the shared list (cPanel merges it inside the named ACL). */
define('SMPRO_MG_HOOK',   '/usr/local/cpanel/etc/exim/acls/ACL_MAIL_BLOCK/shared_sender_blocklist');

/** Installed = its application and its configuration both exist. */
function smpro_mg_present(): bool {
    static $p = null; if ($p !== null) return $p;
    return $p = is_file(SMPRO_MG_ROOT . '/whm/index.php') && is_file(SMPRO_MG_ETC . '/config.json');
}
function smpro_mg_version(): string {
    $v = trim((string)@file_get_contents(SMPRO_MG_ROOT . '/VERSION', false, null, 0, 64));
    return preg_match('/^[0-9][0-9A-Za-z.\-]{0,30}$/', $v) ? $v : '';
}
/** WHM page of MailGuard, from its own app registration (never guessed). */
function smpro_mg_url(): string {
    foreach (glob('/var/cpanel/apps/*.conf') ?: [] as $f) {
        $c = (string)@file_get_contents($f, false, null, 0, 4096);
        if (preg_match('/^name=mailguard\s*$/m', $c) && preg_match('#^url=(/cgi/addons/[A-Za-z0-9_-]+/index\.cgi)\s*$#m', $c, $m)) return $m[1];
    }
    return '';
}
/** True for anything that belongs to MailGuard: its code, state, configuration, WHM entry and Exim rule. */
function smpro_mg_trusted(string $path): bool {
    $n = rtrim(str_replace('\\', '/', $path), '/');
    if ($n === '') return false;
    foreach ([SMPRO_MG_ROOT, SMPRO_MG_ETC, SMPRO_MG_VAR, '/usr/local/cpanel/whostmgr/docroot/cgi/addons/mailguard'] as $d)
        if ($n === $d || strpos($n, $d . '/') === 0) return true;
    return $n === SMPRO_MG_HOOK;
}
/** MailGuard's rule for the shared list is in place (so senders on the list are refused even with this plugin's own
 *  rule removed). */
function smpro_mg_hook_present(): bool {
    return is_file(SMPRO_MG_HOOK) && strpos((string)@file_get_contents(SMPRO_MG_HOOK, false, null, 0, 8192), 'smpro_blocked_senders') !== false;
}
/** Take MailGuard's Exim-rebuild lock (the same file it locks) so two rebuilds never overlap. Returns the handle to
 *  keep until the rebuild is done, or null when the lock could not be had within $wait seconds. Without MailGuard the
 *  lock is a no-op handle. */
function smpro_mg_exim_lock(int $wait = 90) {
    if (!smpro_mg_present() || !is_dir(SMPRO_MG_VAR)) return fopen('php://memory', 'r');
    $h = @fopen(SMPRO_MG_LOCK, 'c'); if (!$h) return fopen('php://memory', 'r');
    $t0 = time();
    while (!@flock($h, LOCK_EX | LOCK_NB)) { if (time() - $t0 >= $wait) { @fclose($h); return null; } usleep(500000); }
    return $h;
}
function smpro_mg_exim_unlock($h): void { if (is_resource($h)) { @flock($h, LOCK_UN); @fclose($h); } }

/** One of MailGuard's list files: entries only (comments and blanks dropped), capped. */
function smpro_mg_list(string $name, int $cap = 500): array {
    if (!preg_match('/^[a-z-]{3,40}\.list$/', $name)) return [];
    $out = [];
    foreach (@file(SMPRO_MG_ETC . '/lists/' . $name, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $l) {
        $l = trim($l); if ($l === '' || $l[0] === '#') continue;
        $out[] = $l; if (count($out) >= $cap) break;
    }
    return $out;
}
/** Read-only query of MailGuard's database through the sqlite3 tool (as for WP Guard). '' when it cannot be read. */
function smpro_mg_query(string $sql): string {
    static $bin = null, $db = null;
    if ($bin === null) { $bin = trim((string)@shell_exec('command -v sqlite3 2>/dev/null')); }
    if ($db === null) {
        $c = json_decode((string)@file_get_contents(SMPRO_MG_ETC . '/config.json'), true);
        $db = (string)($c['paths']['database'] ?? ''); if ($db === '' || !is_file($db)) $db = is_file(SMPRO_MG_VAR . '/mailguard.sqlite3') ? SMPRO_MG_VAR . '/mailguard.sqlite3' : '';
    }
    if ($bin === '' || $db === '') return '';
    return trim((string)@shell_exec('timeout 10 ' . escapeshellarg($bin) . ' -readonly -cmd ' . escapeshellarg('.timeout 3000') . ' ' . escapeshellarg($db) . ' ' . escapeshellarg($sql) . ' 2>/dev/null'));
}
/** What MailGuard is doing right now, for this plugin's pages. null when it is not installed. */
function smpro_mg_status(): ?array {
    if (!smpro_mg_present()) return null;
    $s = ['version' => smpro_mg_version(), 'url' => smpro_mg_url(), 'hook' => smpro_mg_hook_present(), 'read' => false,
          'held' => smpro_mg_list('mailbox-hold.list'), 'throttled' => array_merge(smpro_mg_list('throttle.list'), smpro_mg_list('mailbox-throttle.list')),
          'trusted_senders' => count(smpro_mg_list('trusted-senders.list')), 'trusted_domains' => count(smpro_mg_list('trusted-domains.list')),
          'open_incidents' => null, 'active_actions' => null, 'actions' => []];
    $n = smpro_mg_query("SELECT COUNT(*) FROM incidents WHERE status IN ('open','investigating')");
    if ($n !== '' && ctype_digit($n)) { $s['open_incidents'] = (int)$n; $s['read'] = true; }
    $n = smpro_mg_query("SELECT COUNT(*) FROM enforcement_actions WHERE status='active'");
    if ($n !== '' && ctype_digit($n)) $s['active_actions'] = (int)$n;
    foreach (explode("\n", smpro_mg_query("SELECT action, target_type, target, applied_at FROM enforcement_actions WHERE status='active' ORDER BY applied_at DESC LIMIT 20")) as $l) {
        $p = explode('|', $l); if (count($p) === 4) $s['actions'][] = ['action' => $p[0], 'type' => $p[1], 'target' => $p[2], 'at' => $p[3]];
    }
    return $s;
}
/** Folders and scripts MailGuard attributed outgoing mail to, from its enforcement record (last $days days), with the
 *  message counts it recorded. Read-only; paths are reported only when they exist. [[path, messages, actions], ...] */
function smpro_mg_script_origins(int $days = 60): array {
    if (!smpro_mg_present()) return [];
    $out = [];
    $rows = smpro_mg_query("SELECT evidence FROM enforcement_actions WHERE applied_at > datetime('now','-" . max(1, min(365, $days)) . " days') ORDER BY id DESC LIMIT 2000");
    if ($rows === '') return [];
    foreach (explode("\n", $rows) as $l) {
        $e = json_decode($l, true); if (!is_array($e) || ($e['origin_type'] ?? '') !== 'script') continue;
        $p = (string)($e['origin'] ?? ''); if ($p === '' || $p[0] !== '/' || strpos($p, '..') !== false || !file_exists($p) || is_link($p)) continue;
        if (!isset($out[$p])) $out[$p] = ['path' => $p, 'messages' => 0, 'actions' => 0];
        $out[$p]['messages'] = max($out[$p]['messages'], (int)($e['messages'] ?? 0)); $out[$p]['actions']++;
    }
    uasort($out, fn($a, $b) => $b['actions'] <=> $a['actions']);
    return array_values(array_slice($out, 0, 50));
}
