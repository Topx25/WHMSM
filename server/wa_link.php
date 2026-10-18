<?php
/**
 * wa_link.php — WhatsApp "text the gateway → get the admin login link".
 * The gateway (botx) pushes inbound messages to POST /api/wa-hook?t=<token> (message.received event).
 * When the message is from the registered admin number, we reply with the secret knock URL.
 * Reachable via the direct host dl.iptvpro.org (no Cloudflare). Token-gated; admin-number only; 20s cooldown.
 * Depends on mailer.php (wa_* + settings_*) and storage/.gate (+ storage/.wahook token).
 */
if (!function_exists('settings_get')) return;   // must load after mailer.php

/** Recursively find the first non-empty scalar value for any of $keys (format-agnostic webhook parsing). */
function wa_hook_pick($node, array $keys): string {
    if (is_array($node)) {
        foreach ($keys as $k) if (isset($node[$k]) && is_scalar($node[$k]) && (string)$node[$k] !== '') return (string)$node[$k];
        foreach ($node as $v) { $r = wa_hook_pick($v, $keys); if ($r !== '') return $r; }
    }
    return '';
}

function wa_link_route(string $path): bool {
    if ($path !== '/api/wa-hook') return false;
    header('Content-Type: application/json');
    $want = trim((string)@file_get_contents(dirname(__DIR__) . '/storage/.wahook'));
    $tok  = (string)($_GET['t'] ?? '');
    if ($want === '' || !hash_equals($want, $tok)) { http_response_code(404); echo '{"ok":false}'; return true; }

    $raw = file_get_contents('php://input');
    $j = json_decode((string)$raw, true);
    if (!is_array($j)) { echo '{"ok":true,"skip":"nojson"}'; return true; }

    $event = strtolower(wa_hook_pick($j, ['event', 'type']));
    if ($event !== '' && strpos($event, 'received') === false && strpos($event, 'message') === false) { echo '{"ok":true,"skip":"event"}'; return true; }

    $fromMe = strtolower(wa_hook_pick($j, ['fromMe', 'isFromMe']));
    if ($fromMe === '1' || $fromMe === 'true') { echo '{"ok":true,"skip":"self"}'; return true; }   // ignore our own outbound

    // Inbound DMs may arrive as the admin's phone (@c.us) OR their privacy LID (@lid) — accept either.
    $admin  = preg_replace('/\D/', '', settings_get('wa_chat_id'));      // phone number
    $admLid = preg_replace('/\D/', '', settings_get('wa_admin_lid'));    // device LID (paired)
    $from   = preg_replace('/\D/', '', wa_hook_pick($j, ['from', 'sender', 'author', 'participant', 'remoteJid', 'chatId']));
    $isAdmin = $from !== '' && (($admin !== '' && $from === $admin) || ($admLid !== '' && $from === $admLid));
    if (!$isAdmin) { echo '{"ok":true,"skip":"not-admin"}'; return true; }

    // ON-DEMAND only: reply just when the admin explicitly asks (keyword), not on any random message.
    $body = mb_strtolower(wa_hook_pick($j, ['body', 'text', 'message', 'caption']));
    $hit = false;
    foreach (['login', 'link', 'لوجن', 'رابط', 'دخول'] as $kw) if ($body !== '' && mb_strpos($body, $kw) !== false) { $hit = true; break; }
    if (!$hit) { echo '{"ok":true,"skip":"no-keyword"}'; return true; }

    if (time() - (float)settings_get('wa_hook_last') < 20) { echo '{"ok":true,"skip":"cooldown"}'; return true; }
    settings_set('wa_hook_last', (string)time());

    // DYNAMIC one-time login link: a fresh token, single-use, valid 10 minutes (stored hashed).
    $tok  = bin2hex(random_bytes(16));
    $otlf = dirname(__DIR__) . '/storage/.gate_otl';
    $now  = time();
    $list = is_file($otlf) ? (json_decode((string)@file_get_contents($otlf), true) ?: []) : [];
    $list = array_values(array_filter($list, fn($x) => is_array($x) && (int)($x['exp'] ?? 0) > $now));  // prune expired
    $list[] = ['h' => hash('sha256', $tok), 'exp' => $now + 600];
    if (count($list) > 20) $list = array_slice($list, -20);
    @file_put_contents($otlf, json_encode($list), LOCK_EX); @chmod($otlf, 0600);
    $url = 'https://plugins.iptvpro.org/?k=' . $tok;
    $err = '';
    wa_send("🔐 *Safety Monitor Pro — Admin access*\nرابط دخول لمرة واحدة (صالح 10 دقائق):\n" . $url . "\n\nبعدها سجّل الدخول من /login-pw.", $err);
    echo '{"ok":true,"sent":1}'; return true;
}
