<?php
/**
 * reports.php - scheduled periodic reports. The admin picks a cadence (daily / 3-day / weekly /
 * monthly / custom N days) and delivery channels (panel view + email / Telegram / WhatsApp).
 * The notify cron calls smpro_rep_run() which generates a security+health digest for the period
 * when one is due, saves it (for panel viewing) and delivers it on the chosen channels.
 * Channel credentials are reused from the Notifications config (smpro_ntf_load).
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

define('SMPRO_REP_CFG', SMPRO_VARLIB . '/autoreports.json');
define('SMPRO_REP_DIR', SMPRO_VARLIB . '/reports/auto');

/* ---------------- config ---------------- */
function smpro_rep_cfg() {
    $d = is_file(SMPRO_REP_CFG) ? json_decode((string)@file_get_contents(SMPRO_REP_CFG), true) : null;
    if (!is_array($d)) $d = [];
    $d += ['enabled' => false, 'interval' => 'weekly', 'custom_days' => 7, 'last_run' => 0, 'last_id' => ''];
    $d['channels'] = ($d['channels'] ?? []) + ['panel' => true, 'email' => false, 'telegram' => false, 'whatsapp' => false];
    return $d;
}
function smpro_rep_cfg_save($c) {
    @is_dir(dirname(SMPRO_REP_CFG)) || @mkdir(dirname(SMPRO_REP_CFG), 0700, true);
    $t = SMPRO_REP_CFG . '.tmp';
    @file_put_contents($t, json_encode($c, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX);
    @chmod($t, 0600); @rename($t, SMPRO_REP_CFG);
}
function smpro_rep_days($cfg) {
    switch ($cfg['interval'] ?? 'weekly') {
        case 'daily':   return 1;
        case '3days':   return 3;
        case 'weekly':  return 7;
        case 'monthly': return 30;
        case 'custom':  return max(1, min(365, (int)($cfg['custom_days'] ?? 7)));
        default:        return 7;
    }
}
function smpro_rep_period_label($cfg) {
    return ['daily' => 'daily', '3days' => '3-day', 'weekly' => 'weekly', 'monthly' => 'monthly',
            'custom' => smpro_rep_days($cfg) . '-day'][$cfg['interval'] ?? 'weekly'] ?? 'periodic';
}
function smpro_rep_due($cfg) {
    if (empty($cfg['enabled'])) return false;
    return (time() - (int)($cfg['last_run'] ?? 0)) >= smpro_rep_days($cfg) * 86400;
}

/* ---------------- generate ---------------- */
function smpro_rep_generate($sinceTs) {
    $now = time();
    $health = function_exists('smpro_sv_snapshot') ? smpro_sv_snapshot() : [];
    $m      = function_exists('smpro_collect_metrics') ? smpro_collect_metrics() : [];

    $sec = ['total' => 0, 'domains' => 0, 'ips' => 0, 'top_domains' => [], 'top_ips' => []];
    try {
        $db = function_exists('smpro_in_db') ? smpro_in_db() : null;
        if ($db) {
            $st = $db->prepare('SELECT COUNT(*) t, COUNT(DISTINCT domain) d, COUNT(DISTINCT ip) i FROM attacks WHERE ts>=?');
            $st->execute([$sinceTs]); $r = $st->fetch(PDO::FETCH_ASSOC) ?: [];
            $sec['total'] = (int)($r['t'] ?? 0); $sec['domains'] = (int)($r['d'] ?? 0); $sec['ips'] = (int)($r['i'] ?? 0);
            $st = $db->prepare('SELECT domain, COUNT(*) c FROM attacks WHERE ts>=? AND domain<>"" GROUP BY domain ORDER BY c DESC LIMIT 5');
            $st->execute([$sinceTs]); $sec['top_domains'] = $st->fetchAll(PDO::FETCH_ASSOC) ?: [];
            $st = $db->prepare('SELECT ip, COUNT(*) c FROM attacks WHERE ts>=? AND ip<>"" GROUP BY ip ORDER BY c DESC LIMIT 5');
            $st->execute([$sinceTs]); $sec['top_ips'] = $st->fetchAll(PDO::FETCH_ASSOC) ?: [];
        }
    } catch (\Throwable $e) { if (function_exists('smpro_soft_fail')) smpro_soft_fail(basename(__FILE__) . ':' . __LINE__, $e); }

    $blocked = 0;
    if (function_exists('smpro_in_state')) { $s = smpro_in_state(); $blocked = count($s['autoblocked'] ?? []) + count($s['emergency_blocked'] ?? []); }

    return [
        'period_days' => max(1, (int)round(($now - $sinceTs) / 86400)),
        'from' => $sinceTs, 'to' => $now,
        'health' => $health, 'metrics' => $m, 'security' => $sec, 'blocked_total' => $blocked,
    ];
}

/* ---------------- render ---------------- */
function smpro_rep_render_text($rep) {
    $m = $rep['metrics'] ?? []; $s = $rep['security'] ?? [];
    $L = [];
    $L[] = SMPRO_NAME . ' — ' . $rep['period_days'] . '-day report';
    $L[] = date('Y-m-d H:i', (int)$rep['from']) . '  →  ' . date('Y-m-d H:i', (int)$rep['to']);
    $L[] = str_repeat('—', 32);
    $L[] = 'SERVER HEALTH: ' . strtoupper((string)($m['health_label'] ?? $m['health'] ?? 'n/a'));
    if (isset($m['load'])) $L[] = '  load ' . (is_array($m['load']) ? implode('/', array_map('strval', $m['load'])) : $m['load']) . (isset($m['cpu']['pct']) ? '  ·  cpu ' . round((float)$m['cpu']['pct'], 1) . '%' : '');
    if (isset($m['ram']['pct']))  $L[] = '  ram '  . round((float)$m['ram']['pct'], 0) . '%' . (isset($m['ram']['used']) ? ' (' . $m['ram']['used'] . '/' . ($m['ram']['total'] ?? '?') . ')' : '');
    if (isset($m['disk']['pct'])) $L[] = '  disk ' . round((float)$m['disk']['pct'], 0) . '%' . (isset($m['disk']['used']) ? ' (' . $m['disk']['used'] . '/' . ($m['disk']['total'] ?? '?') . ')' : '');
    $L[] = '';
    $L[] = 'SECURITY (last ' . $rep['period_days'] . 'd):';
    $L[] = '  ' . (int)($s['total'] ?? 0) . ' web-attack attempts · ' . (int)($s['ips'] ?? 0) . ' source IPs · ' . (int)($s['domains'] ?? 0) . ' targeted domains';
    $L[] = '  ' . (int)($rep['blocked_total'] ?? 0) . ' IP(s) currently auto/emergency-blocked';
    if (!empty($s['top_domains'])) { $L[] = '  Most-targeted:'; foreach ($s['top_domains'] as $d) $L[] = '    • ' . $d['domain'] . ' (' . $d['c'] . ')'; }
    if (!empty($s['top_ips']))     { $L[] = '  Top attackers:'; foreach ($s['top_ips'] as $d) $L[] = '    • ' . $d['ip'] . ' (' . $d['c'] . ')'; }
    return implode("\n", $L);
}
function smpro_rep_render_html($rep) {
    $esc = fn($v) => htmlspecialchars((string)$v, ENT_QUOTES, 'UTF-8');
    $m = $rep['metrics'] ?? []; $s = $rep['security'] ?? [];
    $o  = '<div style="font-family:system-ui,Arial,sans-serif;max-width:680px">';
    $o .= '<h2 style="margin:0 0 4px">' . $esc(SMPRO_NAME) . ' — ' . (int)$rep['period_days'] . '-day report</h2>';
    $o .= '<p style="color:#64748b;margin:0 0 12px">' . $esc(date('Y-m-d H:i', (int)$rep['from'])) . ' → ' . $esc(date('Y-m-d H:i', (int)$rep['to'])) . '</p>';
    $o .= '<h3 style="margin:12px 0 4px">Server health: ' . $esc(strtoupper((string)($m['health_label'] ?? $m['health'] ?? 'n/a'))) . '</h3><ul>';
    if (isset($m['load']))        $o .= '<li>Load: ' . $esc(is_array($m['load']) ? implode(' / ', array_map('strval', $m['load'])) : $m['load']) . '</li>';
    if (isset($m['cpu']['pct']))  $o .= '<li>CPU: ' . $esc(round((float)$m['cpu']['pct'], 1)) . '%</li>';
    if (isset($m['ram']['pct']))  $o .= '<li>RAM: ' . $esc(round((float)$m['ram']['pct'], 0)) . '%' . (isset($m['ram']['used']) ? ' (' . $esc($m['ram']['used']) . '/' . $esc($m['ram']['total'] ?? '?') . ')' : '') . '</li>';
    if (isset($m['disk']['pct'])) $o .= '<li>Disk: ' . $esc(round((float)$m['disk']['pct'], 0)) . '% (' . $esc($m['disk']['used'] ?? '?') . '/' . $esc($m['disk']['total'] ?? '?') . ')</li>';
    $o .= '</ul>';
    $o .= '<h3 style="margin:12px 0 4px">Security (last ' . (int)$rep['period_days'] . ' days)</h3><ul>';
    $o .= '<li><b>' . (int)($s['total'] ?? 0) . '</b> web-attack attempts from <b>' . (int)($s['ips'] ?? 0) . '</b> IPs on <b>' . (int)($s['domains'] ?? 0) . '</b> domains</li>';
    $o .= '<li>' . (int)($rep['blocked_total'] ?? 0) . ' IP(s) currently blocked</li></ul>';
    if (!empty($s['top_domains'])) { $o .= '<p style="margin:6px 0 2px"><b>Most-targeted domains</b></p><ul>'; foreach ($s['top_domains'] as $d) $o .= '<li>' . $esc($d['domain']) . ' — ' . (int)$d['c'] . '</li>'; $o .= '</ul>'; }
    if (!empty($s['top_ips']))     { $o .= '<p style="margin:6px 0 2px"><b>Top attacker IPs</b></p><ul>'; foreach ($s['top_ips'] as $d) $o .= '<li>' . $esc($d['ip']) . ' — ' . (int)$d['c'] . '</li>'; $o .= '</ul>'; }
    $o .= '</div>';
    return $o;
}

/* ---------------- run + deliver + store ---------------- */
function smpro_rep_run($force = false) {
    $cfg = smpro_rep_cfg();
    if (!$force && !smpro_rep_due($cfg)) return ['ok' => false, 'skipped' => 'not due'];
    $days = smpro_rep_days($cfg);
    $rep = smpro_rep_generate(time() - $days * 86400);
    $id  = date('Ymd_His');
    $rep['id'] = $id; $rep['generated'] = time(); $rep['interval'] = $cfg['interval'];

    @is_dir(SMPRO_REP_DIR) || @mkdir(SMPRO_REP_DIR, 0700, true);
    @file_put_contents(SMPRO_REP_DIR . '/' . $id . '.json', json_encode($rep, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    @chmod(SMPRO_REP_DIR . '/' . $id . '.json', 0600);
    $files = glob(SMPRO_REP_DIR . '/*.json') ?: [];
    if (count($files) > 60) { sort($files); foreach (array_slice($files, 0, count($files) - 60) as $f) @unlink($f); }

    $delivered = smpro_rep_deliver($rep, $cfg);
    $cfg['last_run'] = time(); $cfg['last_id'] = $id; smpro_rep_cfg_save($cfg);
    if (function_exists('smpro_audit')) smpro_audit('auto_report', ['id' => $id, 'days' => $days, 'channels' => implode(',', $delivered)]);
    return ['ok' => true, 'id' => $id, 'delivered' => $delivered];
}

function smpro_rep_deliver($rep, $cfg) {
    $ch = $cfg['channels'] ?? []; $done = [];
    if (!empty($ch['panel'])) $done[] = 'panel';                        // always stored for the panel
    $subject = SMPRO_NAME . ' — ' . smpro_rep_period_label($cfg) . ' report';
    $text = smpro_rep_render_text($rep);
    $ntf = function_exists('smpro_ntf_load') ? smpro_ntf_load() : [];
    if (!empty($ch['email']) && function_exists('smpro_ntf_send_email')) {
        $to = $ntf['email']['to'] ?? [];
        if (!empty($to)) { [$ok] = smpro_ntf_send_email((array)$to, $ntf['email']['from'] ?? '', $subject, $text); if ($ok) $done[] = 'email'; }
    }
    if (!empty($ch['telegram']) && function_exists('smpro_ntf_send_telegram')) {
        $tk = $ntf['telegram']['token'] ?? ''; $cid = $ntf['telegram']['chat_id'] ?? '';
        if ($tk !== '' && $cid !== '') { [$ok] = smpro_ntf_send_telegram($tk, $cid, '<b>' . htmlspecialchars($subject) . "</b>\n<pre>" . htmlspecialchars($text) . '</pre>'); if ($ok) $done[] = 'telegram'; }
    }
    if (!empty($ch['whatsapp']) && function_exists('smpro_ntf_send_whatsapp')) {
        if (!empty($ntf['whatsapp']['base_url']) && !empty($ntf['whatsapp']['chat_id'])) { [$ok] = smpro_ntf_send_whatsapp($ntf, '*' . $subject . "*\n" . $text); if ($ok) $done[] = 'whatsapp'; }
    }
    return $done;
}

/* ---------------- panel access ---------------- */
function smpro_rep_list() {
    $out = [];
    foreach (array_reverse(glob(SMPRO_REP_DIR . '/*.json') ?: []) as $f) {
        $j = json_decode((string)@file_get_contents($f), true);
        if (is_array($j)) $out[] = ['id' => $j['id'] ?? basename($f, '.json'), 'generated' => $j['generated'] ?? @filemtime($f), 'days' => $j['period_days'] ?? 0, 'attacks' => $j['security']['total'] ?? 0];
    }
    return $out;
}
function smpro_rep_get($id) {
    $id = preg_replace('/[^0-9_]/', '', (string)$id); if ($id === '') return null;
    $f = SMPRO_REP_DIR . '/' . $id . '.json';
    if (!is_file($f)) return null;
    $j = json_decode((string)@file_get_contents($f), true);
    return is_array($j) ? $j : null;
}
