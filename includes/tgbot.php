<?php
/**
 * tgbot.php — Telegram control bot. Poll getUpdates (from a 1-min cron), authorize ONLY the admin
 * chat id(s), dispatch commands, log every one. Reuses the Notifications Telegram token + chat id.
 * Commands: /help /status /health /attacks /blocked /sites /report /scan /services
 *           /block <ip> /unblock <ip> /allow <ip> /harden <account>
 *           /restart <service> /update /emergency on|off
 * Control commands are restricted to the configured admin chat — never act on an unknown sender.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

define('SMPRO_TG_STATE', SMPRO_VARLIB . '/tgbot.json');
define('SMPRO_TG_LOCK',  SMPRO_VARLIB . '/locks/tgbot.lock');

function smpro_tg_state(): array { $d = is_file(SMPRO_TG_STATE) ? json_decode((string)@file_get_contents(SMPRO_TG_STATE), true) : null; return is_array($d) ? $d : []; }
function smpro_tg_state_save(array $patch): void {
    $s = array_merge(smpro_tg_state(), $patch);
    @is_dir(dirname(SMPRO_TG_STATE)) || @mkdir(dirname(SMPRO_TG_STATE), 0700, true);
    @file_put_contents(SMPRO_TG_STATE . '.tmp', json_encode($s, JSON_UNESCAPED_SLASHES), LOCK_EX); @chmod(SMPRO_TG_STATE . '.tmp', 0600); @rename(SMPRO_TG_STATE . '.tmp', SMPRO_TG_STATE);
}
function smpro_tg_cfg(): array {
    $ntf = function_exists('smpro_ntf_load') ? smpro_ntf_load() : [];
    $s = smpro_tg_state();
    $admin = (string)($ntf['telegram']['chat_id'] ?? '');
    $allowed = array_values(array_filter(array_map('strval', (array)($s['allowed'] ?? []))));
    if (!$allowed && $admin !== '') $allowed = [$admin];
    return ['enabled' => !empty($s['enabled']), 'token' => (string)($ntf['telegram']['token'] ?? ''), 'admin' => $admin, 'allowed' => $allowed, 'offset' => (int)($s['offset'] ?? 0)];
}

function smpro_tg_api(string $token, string $method, array $params = [], int $timeout = 25): array {
    if ($token === '') return [];
    $qs = [];
    foreach ($params as $k => $v) $qs[$k] = is_array($v) ? json_encode($v) : $v;
    $url = 'https://api.telegram.org/bot' . $token . '/' . $method . ($qs ? '?' . http_build_query($qs) : '');
    $res = function_exists('smpro_http')                                    // bot token (in URL) stays in-process, not in argv
        ? smpro_http($url, ['timeout' => (int)$timeout])
        : ['body' => (string)@shell_exec('curl -sS -m ' . (int)$timeout . ' ' . escapeshellarg($url) . ' 2>/dev/null')];
    $j = json_decode($res['body'], true);
    return is_array($j) ? $j : [];
}
function smpro_tg_send(string $token, $chat, string $text): void {
    smpro_tg_api($token, 'sendMessage', ['chat_id' => $chat, 'text' => mb_substr($text, 0, 4000), 'parse_mode' => 'HTML', 'disable_web_page_preview' => 'true'], 15);
}

/* ---------------- enable/disable (+ per-minute cron) ---------------- */
function smpro_tg_install_cron(bool $on): void {
    $cron = '/etc/cron.d/smpro-tgbot';
    if (!$on) { @unlink($cron); return; }
    $php = smpro_php_cli_bin();
    $script = realpath(SMPRO_BASE . '/bin/tgbot_poll.php') ?: (SMPRO_BASE . '/bin/tgbot_poll.php');
    if ($php === '' || !is_file($script)) return;
    $lockDir = defined('SMPRO_LOCKS') ? SMPRO_LOCKS : (SMPRO_VARLIB . '/locks'); @is_dir($lockDir) || @mkdir($lockDir, 0700, true); $flock = is_executable('/usr/bin/flock') ? '/usr/bin/flock' : 'flock';
    smpro_cron_install($cron, "# Safety Monitor Pro — Telegram control bot (every minute)\n* * * * * root $flock -n $lockDir/tgbot-cron.lock timeout 55 $php $script >/dev/null 2>&1\n");
}
/** cron_sync entry. */
function smpro_tg_cron_sync(): bool { if (defined('SMPRO_TEST_SRC')) return true; $c = smpro_tg_cfg(); smpro_tg_install_cron(!empty($c['enabled'])); return true; }
function smpro_tg_enable(bool $on): array {
    $cfg = smpro_tg_cfg();
    if ($on && ($cfg['token'] === '' || $cfg['admin'] === '')) return ['ok' => false, 'msg' => 'Configure the Telegram token + chat id in Notifications first.'];
    smpro_tg_state_save(['enabled' => $on]);
    smpro_tg_install_cron($on);
    if ($on) smpro_tg_send($cfg['token'], $cfg['admin'], "✅ <b>Safety Monitor Pro</b> control bot enabled. Send /help for commands.");
    if (function_exists('smpro_audit')) smpro_audit('tgbot_enable', ['on' => $on]);
    return ['ok' => true, 'enabled' => $on];
}
function smpro_tg_test(): array {
    $cfg = smpro_tg_cfg();
    if ($cfg['token'] === '' || $cfg['admin'] === '') return ['ok' => false, 'msg' => 'Set the Telegram token + chat id in Notifications first.'];
    smpro_tg_send($cfg['token'], $cfg['admin'], "🔔 Test from Safety Monitor Pro control bot. If you see this, replies work.");
    return ['ok' => true];
}

/* ---------------- poll + dispatch (called from cron) ---------------- */
function smpro_tg_poll(): void {
    $cfg = smpro_tg_cfg();
    if (!$cfg['enabled'] || $cfg['token'] === '' || !$cfg['allowed']) return;
    // single-flight (lock stale after 2 min)
    @is_dir(dirname(SMPRO_TG_LOCK)) || @mkdir(dirname(SMPRO_TG_LOCK), 0700, true);
    if (is_file(SMPRO_TG_LOCK) && (time() - (int)@filemtime(SMPRO_TG_LOCK)) < 120) return;
    @file_put_contents(SMPRO_TG_LOCK, (string)time());
    register_shutdown_function(function () { @unlink(SMPRO_TG_LOCK); });   // released on every exit path, not only the happy one

    smpro_tg_watch_services();                              // proactive service-down alerts (same minute cadence)
    if (function_exists('smpro_cool_tick')) smpro_cool_tick();  // safety-net revert if a cooler timer was missed

    $res = smpro_tg_api($cfg['token'], 'getUpdates', ['offset' => $cfg['offset'], 'timeout' => 20, 'allowed_updates' => ['message']], 25);
    $offset = $cfg['offset'];
    foreach (($res['result'] ?? []) as $u) {
        $offset = max($offset, (int)($u['update_id'] ?? 0) + 1);
        $msg = $u['message'] ?? null; if (!$msg) continue;
        $chat = (string)($msg['chat']['id'] ?? ''); $from = (string)($msg['from']['id'] ?? '');
        $text = trim((string)($msg['text'] ?? ''));
        if ($text === '' || $text[0] !== '/') continue;
        // Authorize by SENDER id, or by chat id ONLY in a private 1:1 chat. In a group/supergroup the chat id
        // is shared by every member, so a chat-id match alone must NOT let an arbitrary member run root control
        // commands — require the sender to be explicitly allow-listed there.
        $isPrivate = ((string)($msg['chat']['type'] ?? '') === 'private') || ($chat !== '' && $chat === $from);
        $authorized = in_array($from, $cfg['allowed'], true) || ($isPrivate && in_array($chat, $cfg['allowed'], true));
        if (!$authorized) {
            smpro_tg_send($cfg['token'], $chat, '⛔ Unauthorized. This bot only responds to the configured admin.');
            if (function_exists('smpro_audit')) smpro_audit('tgbot_denied', ['chat' => $chat, 'from' => $from]);
            continue;
        }
        // the offset is committed BEFORE the command runs: a crash or the cron's kill inside the handler used to
        // replay the same /restart, /block or /harden batch at the next poll
        smpro_tg_state_save(['offset' => $offset]); $cfg['offset'] = $offset;
        try { $reply = smpro_tg_handle($text); }
        catch (\Throwable $e) { $reply = 'That command failed: ' . $e->getMessage(); if (function_exists('smpro_soft_fail')) smpro_soft_fail('tgbot_cmd', $e); }
        smpro_tg_send($cfg['token'], $chat, $reply);
        if (function_exists('smpro_audit')) smpro_audit('tgbot_cmd', ['cmd' => strtok($text, ' '), 'chat' => $chat]);
    }
    @unlink(SMPRO_TG_LOCK);
    if ($offset !== $cfg['offset']) smpro_tg_state_save(['offset' => $offset]);
}

/* ---------------- service control (whitelisted) ---------------- */
// friendly name -> candidate systemd units (first present one wins). Only these may be restarted.
function smpro_tg_services(): array {
    return [
        'apache'   => ['httpd', 'apache2'],
        'nginx'    => ['nginx'],
        'mysql'    => ['mariadb', 'mysql', 'mysqld'],
        'exim'     => ['exim'],
        'dovecot'  => ['dovecot'],
        'dns'      => ['pdns', 'named', 'nsd', 'pdns-recursor'],   // smart: PowerDNS / BIND / NSD — whichever is the active resolver
        'ftp'      => ['pure-ftpd', 'proftpd'],
        'lfd'      => ['lfd'],
        'cpanel'   => ['cpanel'],
        'cron'     => ['crond', 'cron'],
    ];
}
// does a systemd unit exist on this box? (status rc 4 = no such unit)
function smpro_tg_unit_exists(string $unit): bool {
    if (trim((string)@shell_exec('systemctl cat ' . escapeshellarg($unit) . ' >/dev/null 2>&1; echo $?')) === '0') return true;
    return trim((string)@shell_exec('systemctl status ' . escapeshellarg($unit) . ' >/dev/null 2>&1; echo $?')) !== '4';
}
function smpro_tg_unit_active(string $unit): string {
    return trim((string)@shell_exec('systemctl is-active ' . escapeshellarg($unit) . ' 2>/dev/null')) ?: 'unknown';
}
// smart pick among candidate units: prefer the one that's RUNNING (handles mysql-vs-mariadb where the
// stale alias unit still "exists" but is inactive); else the first that exists; else '' (not installed).
function smpro_tg_pick_unit(array $cands): string {
    $present = [];
    foreach ($cands as $u) if (smpro_tg_unit_exists($u)) $present[$u] = smpro_tg_unit_active($u);
    if (!$present) return '';
    foreach ($present as $u => $st) if ($st === 'active') return $u;
    foreach ($present as $u => $st) if ($st === 'activating' || $st === 'reloading') return $u;
    return (string)array_key_first($present);
}
// resolve a friendly name (or a raw unit that's in the whitelist) -> the live unit, or '' if not allowed/found.
function smpro_tg_resolve_unit(string $name): string {
    $name = strtolower(trim($name));
    $map = smpro_tg_services();
    $cands = $map[$name] ?? null;
    if ($cands === null) {                                  // allow a raw unit only if it's whitelisted somewhere
        foreach ($map as $u) if (in_array($name, $u, true)) { $cands = [$name]; break; }
    }
    if (!$cands) return '';
    return smpro_tg_pick_unit($cands) ?: $cands[0];
}
// short "why did it stop" hint from journald (last lines for the unit).
function smpro_tg_unit_reason(string $unit): string {
    $out = trim((string)@shell_exec('journalctl -u ' . escapeshellarg($unit) . ' -n 6 --no-pager -o cat 2>/dev/null'));
    if ($out === '') $out = trim((string)@shell_exec('systemctl status ' . escapeshellarg($unit) . ' --no-pager 2>/dev/null | tail -n 4'));
    return mb_substr($out, 0, 350);
}

// Watch managed services for active->down transitions and alert once per outage (called from the poll cron).
function smpro_tg_watch_services(): void {
    $cfg = smpro_tg_cfg();
    if (!$cfg['enabled'] || $cfg['token'] === '' || $cfg['admin'] === '') return;
    $prev = (array)(smpro_tg_state()['svc_state'] ?? []);
    $now = [];
    foreach (smpro_tg_services() as $name => $cands) {
        $unit = smpro_tg_pick_unit($cands);
        if ($unit === '') continue;
        $act = smpro_tg_unit_active($unit);
        $now[$name] = $act;
        $was = (string)($prev[$name] ?? '');
        $down = in_array($act, ['failed', 'inactive', 'deactivating'], true);
        $wasUp = $was === 'active';
        if ($down && $wasUp) {                              // just went down → alert once
            $reason = smpro_tg_unit_reason($unit);
            smpro_tg_send($cfg['token'], $cfg['admin'],
                "🔴 <b>Service down: " . htmlspecialchars($name) . "</b> (" . htmlspecialchars($unit) . ")\n"
                . "State: <b>" . htmlspecialchars($act) . "</b>\n"
                . "<code>" . htmlspecialchars($reason) . "</code>\n"
                . "Reply <b>/restart " . htmlspecialchars($name) . "</b> to bring it back up.");
            if (function_exists('smpro_audit')) smpro_audit('svc_down', ['unit' => $unit, 'state' => $act]);
        } elseif ($act === 'active' && in_array($was, ['failed', 'inactive', 'deactivating'], true)) {
            smpro_tg_send($cfg['token'], $cfg['admin'], "🟢 <b>Service recovered: " . htmlspecialchars($name) . "</b> (" . htmlspecialchars($unit) . ") is active again.");
        }
    }
    smpro_tg_state_save(['svc_state' => $now]);
}

/* ---------------- command handlers ---------------- */
function smpro_tg_handle(string $text): string {
    $parts = preg_split('/\s+/', $text, 3);
    $cmd = strtolower(ltrim(strtok($parts[0], '@'), '/'));      // strip /cmd@botname
    $arg = trim((string)($parts[1] ?? ''));
    $arg2 = trim((string)($parts[2] ?? ''));
    switch ($cmd) {
        case 'start': case 'help':
            return "<b>🛡 Safety Monitor Pro</b>\nCommands:\n"
                 . "/status — server health\n/services — service status\n/attacks — recent web attacks\n/blocked — auto-blocked IPs\n/sites — most-attacked domains\n/report — security digest\n/scan — quick compromise scan\n"
                 . "/block &lt;ip&gt; · /unblock &lt;ip&gt; · /allow &lt;ip&gt;\n/harden &lt;account&gt; — lock an account\n/restart &lt;service&gt; — restart a service\n/cooler [min] — throttle the load source\n/cooler guard 18 — keep load under a ceiling\n/update — check for updates\n/emergency on|off";
        case 'status': case 'health':
            $h = function_exists('smpro_sv_snapshot') ? smpro_sv_snapshot() : [];
            $m = function_exists('smpro_collect_metrics') ? smpro_collect_metrics() : [];
            return "<b>🖥 Server health: " . htmlspecialchars(strtoupper((string)($m['health_label'] ?? $h['level'] ?? 'n/a'))) . "</b>\n"
                 . "Load: " . htmlspecialchars(is_array($m['load'] ?? null) ? implode(' / ', $m['load']) : (string)($m['load'] ?? '?')) . "\n"
                 . "CPU: " . round((float)($m['cpu']['pct'] ?? 0), 1) . "% · RAM: " . round((float)($m['ram']['pct'] ?? 0), 0) . "% · Disk: " . round((float)($m['disk']['pct'] ?? 0), 0) . "%";
        case 'attacks':
            if (!function_exists('smpro_im_ingest_recent')) return 'Intrusion engine unavailable.';
            $ev = smpro_im_ingest_recent(SMPRO_IM_LIVE_BYTES ?? 3000000, 60);
            $n = count($ev); $ips = []; $dom = [];
            foreach ($ev as $e) { if (!empty($e['ip'])) $ips[$e['ip']] = 1; if (!empty($e['domain'])) $dom[$e['domain']] = ($dom[$e['domain']] ?? 0) + 1; }
            arsort($dom); $top = array_slice($dom, 0, 5, true); $tl = [];
            foreach ($top as $d => $c) $tl[] = "• " . htmlspecialchars($d) . " ($c)";
            return "<b>⚔️ Attacks (last 60m):</b> $n from " . count($ips) . " IPs\n" . (implode("\n", $tl) ?: 'none');
        case 'blocked':
            $st = function_exists('smpro_in_state') ? smpro_in_state() : [];
            $b = array_merge(array_keys($st['emergency_blocked'] ?? []), array_keys($st['autoblocked'] ?? []));
            $b = array_slice(array_values(array_unique($b)), -20);
            return "<b>🚫 Recently blocked (" . count($b) . "):</b>\n" . (htmlspecialchars(implode(', ', $b)) ?: 'none');
        case 'sites':
            if (!function_exists('smpro_im_ingest_recent')) return 'unavailable';
            $ev = smpro_im_ingest_recent(SMPRO_IM_LIVE_BYTES ?? 3000000, 1440); $dom = [];
            foreach ($ev as $e) if (!empty($e['domain'])) $dom[$e['domain']] = ($dom[$e['domain']] ?? 0) + 1;
            arsort($dom); $l = [];
            foreach (array_slice($dom, 0, 10, true) as $d => $c) $l[] = "• " . htmlspecialchars($d) . " ($c)";
            return "<b>🎯 Most-attacked (24h):</b>\n" . (implode("\n", $l) ?: 'none');
        case 'report':
            if (!function_exists('smpro_rep_generate')) return 'Reports unavailable.';
            $rep = smpro_rep_generate(time() - 86400);
            return "<pre>" . htmlspecialchars(smpro_rep_render_text($rep)) . "</pre>";
        case 'scan':
            if (!function_exists('smpro_im_breaches') || !function_exists('smpro_im_ingest_recent')) return 'Scan engine unavailable.';
            $br = smpro_im_breaches(smpro_im_ingest_recent(SMPRO_IM_PAGE_BYTES ?? 9000000, 1440), 120, 20);
            if (!$br) return "✅ <b>Scan:</b> no likely compromises detected in the last 24h.";
            $l = []; foreach (array_slice($br, 0, 10) as $x) $l[] = "• " . htmlspecialchars($x['domain']) . " [" . htmlspecialchars(implode(',', $x['kinds'] ?? [])) . "]";
            return "⚠️ <b>Scan — " . count($br) . " possible compromise(s):</b>\n" . implode("\n", $l) . "\nOpen Forensics to investigate.";
        case 'block': case 'unblock': case 'allow':
            if ($arg === '' || !filter_var($arg, FILTER_VALIDATE_IP)) return "Usage: /$cmd &lt;ip&gt;";
            if ($cmd === 'block')   { $r = function_exists('smpro_im_block_ip') ? smpro_im_block_ip($arg, 'telegram') : ['ok' => false, 'msg' => 'n/a']; return ($r['ok'] ? "✅ Blocked " : "❌ ") . htmlspecialchars($arg) . " — " . htmlspecialchars($r['msg'] ?? ''); }
            if ($cmd === 'allow')   { $r = function_exists('smpro_im_allow_ip') ? smpro_im_allow_ip($arg) : ['ok' => false]; return (!empty($r['ok']) ? "✅ Allowlisted " : "❌ ") . htmlspecialchars($arg); }
            $out = (string)@shell_exec('csf -dr ' . escapeshellarg($arg) . ' 2>&1'); return "✅ Unblock " . htmlspecialchars($arg) . "\n<code>" . htmlspecialchars(mb_substr(trim($out), 0, 200)) . "</code>";
        case 'services': case 'svc':
            $lines = [];
            foreach (smpro_tg_services() as $name => $cands) {
                $unit = smpro_tg_pick_unit($cands);
                if ($unit === '') continue;                 // not installed on this server
                $act = smpro_tg_unit_active($unit);
                $ic = $act === 'active' ? '🟢' : ($act === 'inactive' ? '⚪️' : '🔴');
                $lines[] = "$ic <b>" . htmlspecialchars($name) . "</b> — " . htmlspecialchars($act) . " (" . htmlspecialchars($unit) . ")";
            }
            return "<b>🧩 Services:</b>\n" . (implode("\n", $lines) ?: 'no managed services detected');
        case 'restart':
            if ($arg === '') return "Usage: /restart &lt;service&gt;\nAllowed: " . htmlspecialchars(implode(', ', array_keys(smpro_tg_services())));
            $unit = smpro_tg_resolve_unit($arg);
            if ($unit === '') return "❌ Not a managed service: <b>" . htmlspecialchars($arg) . "</b>\nAllowed: " . htmlspecialchars(implode(', ', array_keys(smpro_tg_services())));
            $before = smpro_tg_unit_active($unit);
            @shell_exec('systemctl restart ' . escapeshellarg($unit) . ' >/dev/null 2>&1');
            $after = smpro_tg_unit_active($unit);
            if (function_exists('smpro_audit')) smpro_audit('tgbot_restart', ['unit' => $unit, 'before' => $before, 'after' => $after]);
            if ($after === 'active') return "✅ Restarted <b>" . htmlspecialchars($unit) . "</b> — now <b>active</b> (was " . htmlspecialchars($before) . ").";
            return "⚠️ <b>" . htmlspecialchars($unit) . "</b> did not come up (state: " . htmlspecialchars($after) . ").\n<code>" . htmlspecialchars(smpro_tg_unit_reason($unit)) . "</code>";
        case 'cooler': case 'cool':
            if (!function_exists('smpro_cool_status')) return 'Cooler unavailable.';
            $a = strtolower($arg);
            if ($a === 'guard') {
                if (!function_exists('smpro_cool_guard_save')) return 'Guard unavailable.';
                $sub = strtolower($arg2);
                if ($sub === 'off' || $sub === 'stop') { smpro_cool_guard_save(['enabled' => false]); return "🌡 <b>Load guard disabled.</b>"; }
                if ($sub !== '' && is_numeric($sub)) {
                    $g = smpro_cool_guard_save(['enabled' => true, 'ceiling' => (float)$sub])['guard'];
                    return "🌡 <b>Load guard ON</b> — keeps 1-min load under <b>" . $g['ceiling'] . "</b> (cools top " . (int)$g['topk'] . " runaway process(es), " . (int)$g['minutes'] . " min). Services &amp; customer-site PHP are never throttled.";
                }
                $g = smpro_cool_guard();
                return "🌡 <b>Load guard:</b> " . (!empty($g['enabled']) ? ('ON — ceiling <b>' . $g['ceiling'] . '</b>') : 'off')
                     . "\nSet: <b>/cooler guard 18</b> · disable: <b>/cooler guard off</b>";
            }
            if ($a === 'off' || $a === 'stop') { $r = smpro_cool_stop(); return "❄️ " . htmlspecialchars($r['msg'] ?? 'stopped'); }
            if ($a !== '' && ctype_digit($a)) {
                $r = smpro_cool_auto((int)$a, 50);
                if (empty($r['ok'])) return "❌ " . htmlspecialchars($r['msg'] ?? 'failed');
                $s = $r['source'] ?? []; return "❄️ Cooling <b>" . htmlspecialchars($s['comm'] ?? '?') . "</b> (pid " . (int)($s['pid'] ?? 0) . ", " . round((float)($s['cpu'] ?? 0), 1) . "% CPU) for " . (int)$a . " min. " . htmlspecialchars($r['msg'] ?? '');
            }
            $st = smpro_cool_status();
            $g = function_exists('smpro_cool_guard') ? smpro_cool_guard() : [];
            $gline = !empty($g['enabled']) ? ("\n🌡 Guard ON — ceiling " . $g['ceiling'] . (isset($st['load1']) ? ", load now " . $st['load1'] : '')) : "\n🌡 Guard off — enable with /cooler guard 18";
            if (empty($st['active'])) return "❄️ <b>Cooler:</b> idle. Send <b>/cooler 15</b> to cool the top runaway for 15 min, or /cooler off to stop." . $gline;
            $names = []; foreach ($st['targets'] as $t) $names[] = htmlspecialchars(($t['comm'] ?? '?') . ' (' . (int)$t['pid'] . ')');
            return "❄️ <b>Cooler active:</b> " . implode(', ', $names) . " · " . ceil($st['remaining'] / 60) . " min left. /cooler off to stop.";
        case 'harden':
            if ($arg === '' || !preg_match('/^[a-z0-9_]{1,32}$/i', $arg)) return "Usage: /harden &lt;cpanel-account&gt;";
            if (!is_dir('/var/cpanel/users') || !is_file('/var/cpanel/users/' . $arg)) return "❌ Account not found: " . htmlspecialchars($arg);
            if (!function_exists('smpro_im_harden_site')) return 'Harden engine unavailable.';
            $h = smpro_im_harden_site($arg, false);
            return "🛡 Hardened <b>" . htmlspecialchars($arg) . "</b> — " . count($h) . " action(s) (PHP-exec off in upload dirs + core files locked).";
        case 'update':
            if (!function_exists('smpro_upd_check')) return 'Updates unavailable.';
            $c = smpro_upd_check();
            if (empty($c['ok'])) return "❌ " . htmlspecialchars($c['message'] ?? 'check failed');
            return !empty($c['available']) ? ("⬆️ Update available: <b>" . htmlspecialchars($c['latest']) . "</b> (you have " . htmlspecialchars($c['current']) . "). Apply from the Updates page.") : ("✅ Up to date (" . htmlspecialchars($c['current']) . ").");
        case 'emergency':
            if (!function_exists('smpro_in_cfg') || !function_exists('smpro_in_cfg_save')) return 'unavailable';
            if (!in_array(strtolower($arg), ['on', 'off'], true)) { $c = smpro_in_cfg(); return "Emergency is " . (!empty($c['emergency']) ? 'ON' : 'OFF') . ". Use /emergency on|off."; }
            smpro_in_cfg_save(['emergency' => strtolower($arg) === 'on']);
            return "🚨 Emergency auto-response turned <b>" . strtoupper($arg) . "</b>.";
        default:
            return "Unknown command. Send /help.";
    }
}
