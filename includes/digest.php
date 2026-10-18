<?php
/**
 * digest.php — "Grouped alerts" / quiet mode. Instead of one message per event (noise), routine
 * alerts are queued and delivered as ONE aggregated digest every interval the admin chooses.
 * Exceptions that ALWAYS send immediately (never batched):
 *   - server load (load_high) and the mandatory license_expiry — hard-coded,
 *   - whatever the AI classifies as "maximum danger" (active compromise/malware/breach/emergency…),
 *   - any alert whose severity is 'critical' (safety net).
 * The notify cron flushes the queue when the interval elapses.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

define('SMPRO_DG_CFG',   SMPRO_VARLIB . '/digest.json');
define('SMPRO_DG_QUEUE', SMPRO_VARLIB . '/digest_queue.json');

function smpro_dg_cfg() {
    $d = is_file(SMPRO_DG_CFG) ? json_decode((string)@file_get_contents(SMPRO_DG_CFG), true) : null;
    if (!is_array($d)) $d = [];
    return $d + ['enabled' => false, 'interval_hours' => 6, 'ai_critical' => null, 'ai_at' => 0, 'last_flush' => 0];
}
function smpro_dg_cfg_save($c) {
    @is_dir(dirname(SMPRO_DG_CFG)) || @mkdir(dirname(SMPRO_DG_CFG), 0700, true);
    $t = SMPRO_DG_CFG . '.tmp';
    @file_put_contents($t, json_encode($c, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX); @chmod($t, 0600); @rename($t, SMPRO_DG_CFG);
}

/* Load is ALWAYS immediate (user rule); license expiry is mandatory. Never batched. */
function smpro_dg_always_immediate() { return ['load_high', 'license_expiry']; }

/* Types that bypass the digest (= "maximum danger"). Uses the AI-classified set when present,
 * otherwise falls back to the built-in 'critical'-severity types. */
function smpro_dg_critical_types() {
    $cfg = smpro_dg_cfg();
    if (is_array($cfg['ai_critical'])) return $cfg['ai_critical'];
    $crit = [];
    foreach (smpro_ntf_types() as $k => $v) if (($v[2] ?? '') === 'critical') $crit[] = $k;
    return $crit;
}

/* Should this alert be HELD (queued for the digest) instead of sent now? */
function smpro_dg_hold($type, array $meta = []) {
    $cfg = smpro_dg_cfg();
    if (empty($cfg['enabled'])) return false;
    if (in_array($type, smpro_dg_always_immediate(), true)) return false;     // load / license → immediate
    if (($meta['severity'] ?? '') === 'critical') return false;               // critical severity → immediate
    if (in_array($type, smpro_dg_critical_types(), true)) return false;       // AI "maximum danger" → immediate
    return true;                                                              // routine → batch
}

function smpro_dg_queue($type, $subject, $body, array $meta = []) {
    $q = is_file(SMPRO_DG_QUEUE) ? json_decode((string)@file_get_contents(SMPRO_DG_QUEUE), true) : [];
    if (!is_array($q)) $q = [];
    $q[] = ['ts' => time(), 'type' => (string)$type, 'sev' => (string)($meta['severity'] ?? ''), 'subject' => (string)$subject, 'body' => mb_substr((string)$body, 0, 600)];
    if (count($q) > 500) $q = array_slice($q, -500);
    @is_dir(dirname(SMPRO_DG_QUEUE)) || @mkdir(dirname(SMPRO_DG_QUEUE), 0700, true);
    @file_put_contents(SMPRO_DG_QUEUE . '.tmp', json_encode($q, JSON_UNESCAPED_SLASHES), LOCK_EX); @chmod(SMPRO_DG_QUEUE . '.tmp', 0600); @rename(SMPRO_DG_QUEUE . '.tmp', SMPRO_DG_QUEUE);
}
function smpro_dg_queue_count() { $q = is_file(SMPRO_DG_QUEUE) ? json_decode((string)@file_get_contents(SMPRO_DG_QUEUE), true) : []; return is_array($q) ? count($q) : 0; }

/* Build + deliver the aggregated digest (grouped by alert type). */
function smpro_dg_flush($force = false) {
    $cfg = smpro_dg_cfg();
    if (empty($cfg['enabled'])) return ['ok' => false, 'skip' => 'disabled'];
    $due = (time() - (int)$cfg['last_flush']) >= max(1, (int)$cfg['interval_hours']) * 3600;
    if (!$force && !$due) return ['ok' => false, 'skip' => 'not due'];
    // the queue is taken aside atomically first: an alert queued while this flush is building the digest lands in a NEW queue
    // and goes out next time, instead of being deleted unsent with the old one
    $taken = SMPRO_DG_QUEUE . '.' . getmypid() . '.flushing';
    if (!is_file(SMPRO_DG_QUEUE) || !@rename(SMPRO_DG_QUEUE, $taken)) { $cfg['last_flush'] = time(); smpro_dg_cfg_save($cfg); return ['ok' => false, 'skip' => 'empty']; }
    $q = json_decode((string)@file_get_contents($taken), true);
    if (!is_array($q) || !$q) { @unlink($taken); $cfg['last_flush'] = time(); smpro_dg_cfg_save($cfg); return ['ok' => false, 'skip' => 'empty']; }

    $tt = smpro_ntf_types(); $byType = [];
    foreach ($q as $e) if (is_array($e) && isset($e['type'])) $byType[(string)$e['type']][] = $e;
    $since = (int)$cfg['last_flush'] ?: (int)($q[0]['ts'] ?? time());
    $L = [SMPRO_NAME . ' — grouped alerts digest'];
    $L[] = count($q) . ' event(s) since ' . date('Y-m-d H:i', $since);
    $L[] = str_repeat('—', 32);
    foreach ($byType as $type => $items) {
        $L[] = strtoupper($tt[$type][0] ?? $type) . '  ×' . count($items);
        foreach (array_slice($items, -5) as $it) $L[] = '  • ' . date('m-d H:i', (int)$it['ts']) . '  ' . $it['subject'];
        if (count($items) > 5) $L[] = '  …+' . (count($items) - 5) . ' more';
        $L[] = '';
    }
    $text = rtrim(implode("\n", $L));
    $subject = SMPRO_NAME . ' — grouped alerts (' . count($q) . ')';
    $sent = smpro_dg_deliver($subject, $text);

    @unlink($taken);
    $cfg['last_flush'] = time(); smpro_dg_cfg_save($cfg);
    if (function_exists('smpro_audit')) smpro_audit('digest_flush', ['n' => count($q), 'channels' => implode(',', $sent)]);
    return ['ok' => true, 'count' => count($q), 'channels' => $sent];
}

/* Deliver to every enabled notification channel (mirrors the report delivery). */
function smpro_dg_deliver($subject, $text) {
    $ntf = function_exists('smpro_ntf_load') ? smpro_ntf_load() : []; $done = [];
    if (!empty($ntf['email']['enabled']) && !empty($ntf['email']['to']) && function_exists('smpro_ntf_send_email')) {
        [$ok] = smpro_ntf_send_email((array)$ntf['email']['to'], $ntf['email']['from'] ?? '', '[SMPro] ' . $subject, $text); if ($ok) $done[] = 'email';
    }
    if (!empty($ntf['telegram']['enabled']) && ($ntf['telegram']['token'] ?? '') !== '' && ($ntf['telegram']['chat_id'] ?? '') !== '' && function_exists('smpro_ntf_send_telegram')) {
        [$ok] = smpro_ntf_send_telegram($ntf['telegram']['token'], $ntf['telegram']['chat_id'], '<b>' . htmlspecialchars($subject) . "</b>\n<pre>" . htmlspecialchars($text) . '</pre>'); if ($ok) $done[] = 'telegram';
    }
    if (!empty($ntf['pushbullet']['enabled']) && ($ntf['pushbullet']['token'] ?? '') !== '' && function_exists('smpro_ntf_send_pushbullet')) {
        [$ok] = smpro_ntf_send_pushbullet($ntf['pushbullet']['token'], $subject, $text); if ($ok) $done[] = 'pushbullet';
    }
    if (!empty($ntf['whatsapp']['enabled']) && !empty($ntf['whatsapp']['base_url']) && function_exists('smpro_ntf_send_whatsapp')) {
        [$ok] = smpro_ntf_send_whatsapp($ntf, '*' . $subject . "*\n" . $text); if ($ok) $done[] = 'whatsapp';
    }
    return $done;
}

/* AI decides which indicators are "maximum danger" (immediate) vs routine (digest). */
function smpro_dg_ai_classify() {
    if (!function_exists('smpro_ai_available') || !smpro_ai_available()) return ['ok' => false, 'msg' => 'Configure an AI provider first (AI Providers page).'];
    $always = smpro_dg_always_immediate(); $types = [];
    foreach (smpro_ntf_types() as $k => $v) { if ($k === 'test' || in_array($k, $always, true)) continue; $types[$k] = ['label' => $v[0], 'desc' => $v[1], 'severity' => $v[2]]; }
    $sys = "You are a hosting security operations expert. The admin wants to cut alert noise by batching routine alerts into a periodic digest, while still being paged IMMEDIATELY for MAXIMUM-DANGER events. "
         . "Classify each alert type as \"immediate\" (active compromise, malware, confirmed breach, emergency response, data-loss or other security-critical events that must not wait) or \"digest\" (routine / informational / can wait for the next batch). "
         . "Respond with STRICT JSON ONLY: {\"immediate\":[\"type\",...],\"digest\":[\"type\",...]}. Use the EXACT type keys given. Do not include any other text.";
    $user = "Alert types:\n" . json_encode($types, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    $r = smpro_ai_chat($sys, $user, ['max_tokens' => 600, 'context' => 'alert_triage']);
    if (empty($r['ok'])) return ['ok' => false, 'msg' => $r['error'] ?? 'AI request failed'];
    $j = preg_match('/\{.*\}/s', (string)($r['text'] ?? ''), $m) ? json_decode($m[0], true) : null;
    if (!is_array($j) || !isset($j['immediate'])) return ['ok' => false, 'msg' => 'AI returned no usable classification.'];
    $valid = array_keys(smpro_ntf_types());
    $crit = array_values(array_intersect(array_map('strval', (array)$j['immediate']), $valid));
    $cfg = smpro_dg_cfg(); $cfg['ai_critical'] = $crit; $cfg['ai_at'] = time(); smpro_dg_cfg_save($cfg);
    if (function_exists('smpro_audit')) smpro_audit('digest_ai_classify', ['immediate' => $crit]);
    return ['ok' => true, 'immediate' => $crit, 'provider' => $r['provider'] ?? ''];
}
