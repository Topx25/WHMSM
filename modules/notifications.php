<?php
/**
 * modules/notifications.php — Notifications Center.
 * Configure delivery channels (Email + Telegram), choose which alert types are
 * on and which channel each uses, link/test the channels, run the live event
 * checker on demand or on a schedule, and review the send log.
 * All writes are POST + CSRF + root + audit. Reads use includes/notify.php.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

define('SMPRO_NTF_CRON', '/etc/cron.d/smpro-notify');

$reqMethod = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));

/* ---------------- POST actions (AJAX JSON) ---------------- */
if ($reqMethod === 'POST' && ($_POST['ntf_action'] ?? '') !== '') {
    smpro_require_valid_csrf('ntf_act'); smpro_require_root();
    header('Content-Type: application/json');
    $act = $_POST['ntf_action'];

    if ($act === 'save') {
        $cfg = smpro_ntf_load();
        $cfg['email']['enabled']  = !empty($_POST['email_enabled']);
        $cfg['email']['method']   = ($_POST['email_method'] ?? 'sendmail') === 'smtp' ? 'smtp' : 'sendmail';
        $cfg['email']['from']     = trim((string)($_POST['email_from'] ?? $cfg['email']['from']));
        $cfg['email']['to']       = array_values(array_filter(array_map('trim', preg_split('/[\s,;]+/', (string)($_POST['email_to'] ?? ''))), fn($a) => filter_var($a, FILTER_VALIDATE_EMAIL)));
        $cfg['email']['smtp'] = [
            'host'   => trim((string)($_POST['smtp_host'] ?? '')),
            'port'   => max(1, (int)($_POST['smtp_port'] ?? 587)),
            'secure' => in_array($_POST['smtp_secure'] ?? 'tls', ['tls', 'ssl', 'none'], true) ? $_POST['smtp_secure'] : 'tls',
            'user'   => trim((string)($_POST['smtp_user'] ?? '')),
            'pass'   => trim((string)($_POST['smtp_pass'] ?? '')) !== '' ? (string)$_POST['smtp_pass'] : (string)($cfg['email']['smtp']['pass'] ?? ''),  // keep existing if left blank
        ];
        $cfg['telegram']['enabled'] = !empty($_POST['tg_enabled']);
        $cfg['telegram']['token']   = trim((string)($_POST['tg_token'] ?? '')) !== '' ? (string)$_POST['tg_token'] : (string)($cfg['telegram']['token'] ?? '');  // keep existing if left blank
        $cfg['telegram']['chat_id'] = trim((string)($_POST['tg_chat'] ?? $cfg['telegram']['chat_id']));
        $cfg['pushbullet']['enabled'] = !empty($_POST['pb_enabled']);
        $cfg['pushbullet']['token']   = trim((string)($_POST['pb_token'] ?? '')) !== '' ? (string)$_POST['pb_token'] : (string)($cfg['pushbullet']['token'] ?? '');  // keep existing if left blank
        // Keep existing values when a field is submitted blank (this card is a secondary
        // editor — never let an empty box wipe what the WhatsApp section saved).
        $cfg['whatsapp']['enabled']  = !empty($_POST['wa_enabled']);
        $waB = rtrim(trim((string)($_POST['wa_base'] ?? '')), '/');     if ($waB !== '') $cfg['whatsapp']['base_url'] = $waB;
        $waK = trim((string)($_POST['wa_key'] ?? ''));                  if ($waK !== '') $cfg['whatsapp']['api_key'] = $waK;
        $waS = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)($_POST['wa_session'] ?? '')); if ($waS !== '') $cfg['whatsapp']['session'] = $waS;
        $waC = trim((string)($_POST['wa_chat'] ?? ''));                 if ($waC !== '') $cfg['whatsapp']['chat_id'] = $waC;
        foreach (array_keys(smpro_ntf_types()) as $k) {
            $cfg['types'][$k] = [
                'on'         => !empty($_POST['t_on'][$k] ?? null),
                'email'      => !empty($_POST['t_email'][$k] ?? null),
                'telegram'   => !empty($_POST['t_tg'][$k] ?? null),
                'pushbullet' => !empty($_POST['t_pb'][$k] ?? null),
                'whatsapp'   => !empty($_POST['t_wa'][$k] ?? null),
                'mute_until' => (int)($cfg['types'][$k]['mute_until'] ?? 0),   // preserve an active snooze across a settings save
                'only_changes' => !empty($cfg['types'][$k]['only_changes']),   // preserved too: it has its own button
            ];
        }
        foreach (['disk_pct', 'load', 'failed_logins', 'spam_events',
                  'mail_out_hour', 'mail_out_12h', 'remind_hours', 'inbound_spam_min', 'inbound_spam_remind_hours'] as $tk)
            if (isset($_POST['thr'][$tk])) $cfg['thresholds'][$tk] = max(0, (int)$_POST['thr'][$tk]);
        smpro_ntf_save($cfg);
        // Keep the WhatsApp gateway reachable — allowlist its IP(s) so our auto-block / CSF never blocks it.
        $waAllow = ($waB !== '' && function_exists('smpro_ntf_wa_allowlist')) ? smpro_ntf_wa_allowlist($cfg['whatsapp']['base_url']) : [];
        smpro_audit('notify_config_save', ['email' => $cfg['email']['enabled'], 'telegram' => $cfg['telegram']['enabled'], 'wa_allowlisted' => $waAllow]);
        echo json_encode(['ok' => true, 'msg' => 'Settings saved.' . ($waAllow ? ' WhatsApp gateway allow-listed: ' . implode(', ', $waAllow) . '.' : '')]); exit;
    }

    if ($act === 'only_changes') {
        $cfg = smpro_ntf_load();
        $types = smpro_ntf_types();
        $k = (string)($_POST['type'] ?? '');
        if (!isset($types[$k])) { echo json_encode(['ok' => false, 'msg' => 'unknown alert type']); exit; }
        if (!isset($cfg['types'][$k]) || !is_array($cfg['types'][$k])) $cfg['types'][$k] = ['on' => true];
        $on = !empty($_POST['on']);
        $cfg['types'][$k]['only_changes'] = $on;
        smpro_ntf_save($cfg);
        smpro_audit('notify_only_changes', ['type' => $k, 'on' => $on ? 1 : 0]);
        echo json_encode(['ok' => true, 'on' => $on,
            'msg' => $on ? ('"' . $types[$k][0] . '" will not be repeated while its report is unchanged - it is sent again when a new account, address or finding appears.')
                         : ('"' . $types[$k][0] . '" is repeated every remind window again while the condition lasts.')]); exit;
    }
    if ($act === 'snooze') {
        $cfg = smpro_ntf_load();
        $types = smpro_ntf_types();
        $k = (string)($_POST['type'] ?? '');
        if (!isset($types[$k])) { echo json_encode(['ok' => false, 'msg' => 'unknown alert type']); exit; }
        $hours = min(168.0, max(0.0, (float)($_POST['hours'] ?? 0)));    // 0 = clear; cap at 7 days
        $until = $hours > 0 ? time() + (int)round($hours * 3600) : 0;
        if (!isset($cfg['types'][$k]) || !is_array($cfg['types'][$k])) $cfg['types'][$k] = ['on' => true];
        $cfg['types'][$k]['mute_until'] = $until;
        smpro_ntf_save($cfg);
        smpro_audit('notify_snooze', ['type' => $k, 'hours' => $hours, 'until' => $until]);
        echo json_encode(['ok' => true, 'until' => $until,
            'label' => $until ? ('until ' . date('H:i', $until)) : '',
            'msg' => $until ? ('Snoozed "' . $types[$k][0] . '" for ' . rtrim(rtrim(number_format($hours, 1), '0'), '.') . 'h (until ' . date('H:i', $until) . ').') : ('Snooze cleared for "' . $types[$k][0] . '".')]); exit;
    }
    if ($act === 'test_email') {
        $cfg = smpro_ntf_load();
        [$ok, $d] = smpro_ntf_send_email($cfg['email']['to'] ?? [], $cfg['email']['from'] ?? '', '[SMPro] Test email', "This is a test notification from Safety Monitor Pro.\nIf you received it, email alerts are working.");
        echo json_encode(['ok' => $ok, 'msg' => $ok ? 'Test email sent to: ' . implode(', ', $cfg['email']['to'] ?? []) : ('Failed: ' . $d)], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;   // $d embeds the raw SMTP banner (arbitrary bytes)
    }
    if ($act === 'test_tg') {
        $cfg = smpro_ntf_load();
        [$ok, $d] = smpro_ntf_send_telegram($cfg['telegram']['token'] ?? '', $cfg['telegram']['chat_id'] ?? '', '<b>✅ Safety Monitor Pro</b>' . "\nTest message — Telegram alerts are working.");
        echo json_encode(['ok' => $ok, 'msg' => $ok ? 'Test message sent to Telegram.' : ('Failed: ' . $d)]); exit;
    }
    if ($act === 'test_pb') {
        $cfg = smpro_ntf_load();
        [$ok, $d] = smpro_ntf_send_pushbullet($cfg['pushbullet']['token'] ?? '', 'Safety Monitor Pro', 'Test push — Pushbullet alerts are working.');
        echo json_encode(['ok' => $ok, 'msg' => $ok ? 'Test push sent to Pushbullet.' : ('Failed: ' . $d)]); exit;
    }
    if ($act === 'test_wa') {
        $cfg = smpro_ntf_load();
        [$ok, $d] = smpro_ntf_send_whatsapp($cfg, 'Test message — WhatsApp alerts from Safety Monitor Pro are working. ✅');
        echo json_encode(['ok' => $ok, 'msg' => $ok ? 'Test message sent to WhatsApp.' : ('Failed: ' . $d . ' — link a session in the WhatsApp section first.')], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;   // $d embeds raw gateway response bytes
    }
    if ($act === 'tg_chats') {
        $tgTok = trim((string)($_POST['tg_token'] ?? ''));                                  // blank input → use the saved token
        if ($tgTok === '') $tgTok = (string)(smpro_ntf_load()['telegram']['token'] ?? '');
        $chats = smpro_ntf_telegram_chats($tgTok);
        echo json_encode(['ok' => true, 'chats' => $chats, 'msg' => $chats ? '' : 'No chats yet — send any message to your bot first, then retry.']); exit;
    }
    if ($act === 'run_checks') {
        $r = smpro_notify_run_checks();
        echo json_encode(['ok' => true, 'msg' => $r['fired'] ? ('Fired: ' . implode(', ', $r['fired'])) : 'Checks ran — no new alert conditions.', 'fired' => $r['fired'], 'checked' => $r['checked']], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
    }
    if ($act === 'cron') {
        $on = !empty($_POST['on']);
        if ($on) {
            $php = is_executable('/usr/local/cpanel/3rdparty/bin/php') ? '/usr/local/cpanel/3rdparty/bin/php' : trim((string)@shell_exec('command -v php'));
            $bin = dirname(__DIR__) . '/bin/notify_check.php';
            // flock -n: if a previous run is still going, SKIP this tick — never let runs overlap/pile up
            // (a long run + no lock = stacking processes every 15 min → resource exhaustion). A hard outer
            // `timeout` is a second backstop so a wedged run can never live forever and block all future ticks.
            $lock = SMPRO_VARLIB . '/locks/notify.lock';
            @is_dir(dirname($lock)) || @mkdir(dirname($lock), 0700, true);
            $flock = is_executable('/usr/bin/flock') ? '/usr/bin/flock' : 'flock';
            $line = "*/15 * * * * root " . $flock . " -n " . $lock . " timeout 600 " . $php . " " . $bin . " >/dev/null 2>&1\n";
            @file_put_contents(SMPRO_NTF_CRON, "# Safety Monitor Pro — notification checker (every 15 min; flock = no overlap)\n" . $line);
            @chmod(SMPRO_NTF_CRON, 0644);
        } else {
            // The checker is the detection engine and stays scheduled while the plugin is enabled (see
            // smpro_ntf_cron_wanted). Turning "off" here no longer removes it: disable the delivery channels to stop
            // messages, or Plugin Control → Disabled to stop everything. Saying so beats silently unscheduling detection.
            smpro_audit('notify_cron', ['on' => 0, 'kept' => 1]);
            echo json_encode(['ok' => true, 'msg' => 'Detection keeps running every 15 min — it is what finds foreign logins, File Manager writes from abroad and breaches. To stop messages, switch the channels off; to stop everything, use Plugin Control → Disabled.']); exit;
        }
        smpro_audit('notify_cron', ['on' => $on]);
        echo json_encode(['ok' => true, 'msg' => 'Auto-checks enabled (every 15 min).']); exit;
    }
    echo json_encode(['ok' => false, 'msg' => 'Unknown action.']); exit;
}

/* ---------------- render ---------------- */
$cfg = smpro_ntf_load();
$types = smpro_ntf_types();
$csrf = smpro_csrf_generate('ntf_act');
$cronOn = is_file(SMPRO_NTF_CRON);
$recent = smpro_ntf_recent(30);
$sevcls = ['critical' => 'red', 'high' => 'orange', 'medium' => 'blue', 'info' => 'gray'];

smpro_audit('notifications_view', []);
smpro_layout_header('Notifications');
?>
<div class="svc-kicker">Alerting</div>
<h1 class="h" style="margin:2px 0 4px">Notifications Center</h1>
<p class="sub">Get alerted by <b>Email</b> and/or <b>Telegram</b> when something needs attention. Choose which events fire and on which channel, link your Telegram bot, and run the live checker on demand or every 15 minutes.</p>

<script>var NTF_CSRF=<?= json_encode($csrf) ?>;</script>

<div class="nt-two">
  <!-- Email channel -->
  <?php $em = $cfg['email']; $smtp = $em['smtp'] ?? []; $isSmtp = ($em['method'] ?? 'sendmail') === 'smtp'; ?>
  <div class="card nt-ch">
    <div class="nt-ch-h"><span class="nt-ic">&#9993;</span><b>Email</b>
      <label class="nt-sw"><input type="checkbox" id="emEnabled" <?= !empty($em['enabled'])?'checked':'' ?>><span></span></label>
    </div>
    <label class="nt-l">Recipient address(es) <span class="meta">comma or space separated</span>
      <input class="tp-in" id="emTo" value="<?= smpro_h(implode(', ', $em['to'] ?? [])) ?>" placeholder="admin@example.com, ops@example.com"></label>
    <label class="nt-l">From address
      <input class="tp-in" id="emFrom" value="<?= smpro_h($em['from'] ?? '') ?>" placeholder="safety-monitor@<?= smpro_h(gethostname()) ?>"></label>
    <label class="nt-l">Delivery method
      <select class="tp-sel" id="emMethod">
        <option value="sendmail"<?= $isSmtp?'':' selected' ?>>Server sendmail (local)</option>
        <option value="smtp"<?= $isSmtp?' selected':'' ?>>External SMTP server</option>
      </select></label>
    <div id="emSmtp" class="nt-smtp" style="<?= $isSmtp?'':'display:none' ?>">
      <div class="nt-smtp-row">
        <label class="nt-l" style="flex:2">SMTP host<input class="tp-in" id="smtpHost" value="<?= smpro_h($smtp['host'] ?? '') ?>" placeholder="smtp.gmail.com"></label>
        <label class="nt-l" style="flex:1">Port<input class="tp-in" id="smtpPort" type="number" value="<?= (int)($smtp['port'] ?? 587) ?>"></label>
        <label class="nt-l" style="flex:1">Security<select class="tp-sel" id="smtpSecure">
          <?php foreach (['tls'=>'STARTTLS','ssl'=>'SSL/TLS','none'=>'None'] as $k=>$v): ?><option value="<?= $k ?>"<?= ($smtp['secure']??'tls')===$k?' selected':'' ?>><?= $v ?></option><?php endforeach; ?>
        </select></label>
      </div>
      <div class="nt-smtp-row">
        <label class="nt-l" style="flex:1">Username<input class="tp-in" id="smtpUser" value="<?= smpro_h($smtp['user'] ?? '') ?>" placeholder="user@example.com" autocomplete="off"></label>
        <label class="nt-l" style="flex:1">Password<input class="tp-in" id="smtpPass" type="password" value="" placeholder="<?= !empty($smtp['pass'])?'•••••• (saved — leave blank to keep)':'app password' ?>" autocomplete="new-password"></label>
      </div>
    </div>
    <button class="tp-btn" type="button" id="emTest">&#9993; Send test email</button>
    <div class="nt-res" id="emRes"></div>
  </div>

  <!-- Telegram channel -->
  <div class="card nt-ch">
    <div class="nt-ch-h"><span class="nt-ic">&#9993;</span><b>Telegram</b>
      <label class="nt-sw"><input type="checkbox" id="tgEnabled" <?= !empty($cfg['telegram']['enabled'])?'checked':'' ?>><span></span></label>
    </div>
    <label class="nt-l">Bot token <span class="meta">from @BotFather</span>
      <input class="tp-in mono" id="tgToken" type="password" value="" placeholder="<?= !empty($cfg['telegram']['token'])?'•••••• (saved — leave blank to keep)':'123456789:AAE...' ?>" autocomplete="new-password"></label>
    <label class="nt-l">Chat ID
      <div style="display:flex;gap:8px"><input class="tp-in mono" id="tgChat" value="<?= smpro_h($cfg['telegram']['chat_id'] ?? '') ?>" placeholder="e.g. 123456789 or -100…" style="flex:1">
        <button class="tp-btn" type="button" id="tgFetch">Find chats</button></div></label>
    <div class="nt-res" id="tgChats"></div>
    <button class="tp-btn" type="button" id="tgTest">&#9993; Send test message</button>
    <div class="nt-res" id="tgRes"></div>
    <div class="nt-help">How to link: 1) open <b>@BotFather</b> in Telegram → <code>/newbot</code> → copy the token here. 2) send any message to your new bot (or add it to a group). 3) click <b>Find chats</b> and pick the chat id. 4) Save.</div>
  </div>

  <!-- Pushbullet channel -->
  <div class="card nt-ch">
    <div class="nt-ch-h"><span class="nt-ic">&#128241;</span><b>Pushbullet</b>
      <label class="nt-sw"><input type="checkbox" id="pbEnabled" <?= !empty($cfg['pushbullet']['enabled'])?'checked':'' ?>><span></span></label>
    </div>
    <label class="nt-l">Access token <span class="meta">Pushbullet → Settings → Account → Create Access Token</span>
      <input class="tp-in mono" id="pbToken" type="password" value="" placeholder="<?= !empty($cfg['pushbullet']['token'])?'•••••• (saved — leave blank to keep)':'o.xxxxxxxxxxxxxxxx' ?>" autocomplete="new-password"></label>
    <button class="tp-btn" type="button" id="pbTest">&#128241; Send test push</button>
    <div class="nt-res" id="pbRes"></div>
    <div class="nt-help">Install the Pushbullet app on your phone/desktop and sign in. Create an <b>Access Token</b> in your account settings, paste it here, Save — alerts arrive as push notifications on every signed-in device.</div>
  </div>

  <!-- WhatsApp channel -->
  <?php $wa = $cfg['whatsapp'] ?? []; ?>
  <div class="card nt-ch">
    <div class="nt-ch-h"><span class="nt-ic">&#128241;</span><b>WhatsApp</b>
      <label class="nt-sw"><input type="checkbox" id="waEnabled" <?= !empty($wa['enabled'])?'checked':'' ?>><span></span></label>
    </div>
    <label class="nt-l">Gateway URL<input class="tp-in mono" id="waBase" value="<?= smpro_h($wa['base_url'] ?? '') ?>" placeholder="http://your-gateway-host:3000"></label>
    <label class="nt-l">API key (X-API-Key)<input class="tp-in mono" id="waKey" type="password" value="" placeholder="<?= ($wa['api_key'] ?? '') !== '' ? '•••••• saved — leave blank to keep' : 'your api key' ?>" autocomplete="off"></label>
    <div style="display:flex;gap:8px">
      <label class="nt-l" style="flex:1">Session<input class="tp-in mono" id="waSession" value="<?= smpro_h($wa['session'] ?? 'default') ?>" placeholder="default"></label>
      <label class="nt-l" style="flex:2">Recipient number<input class="tp-in mono" id="waChat" value="<?= smpro_h($wa['chat_id'] ?? '') ?>" placeholder="201234567890"></label>
    </div>
    <button class="tp-btn" type="button" id="waTest">&#128241; Send test message</button>
    <div class="nt-res" id="waRes"></div>
    <div class="nt-help">Link a phone (scan QR) and manage sessions in the <a href="index.cgi?page=whatsapp"><b>WhatsApp</b> section</a>. Recipient is the destination number (digits + country code, no <code>+</code>).</div>
  </div>
</div>

<!-- event types -->
<?php $sevOrder = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3, 'info' => 4]; $sevCount = [];
      foreach ($types as $k => $info) { $sevCount[$info[2]] = ($sevCount[$info[2]] ?? 0) + 1; }
      uksort($types, fn($a, $b) => ($sevOrder[$types[$a][2]] ?? 9) <=> ($sevOrder[$types[$b][2]] ?? 9) ?: strcmp($types[$a][0], $types[$b][0])); ?>
<div class="card nt-types" style="padding:0;overflow:hidden;margin-top:14px">
  <div class="nt-card-h"><b>Alert types &amp; channels</b><span class="meta">choose what fires and where it goes &middot; tick several rows and change them together</span>
    <span class="sp"></span><span class="meta" id="ntDirty" hidden style="color:var(--warn);font-weight:700">unsaved changes &middot; press Save settings</span></div>
  <div class="nt-tools">
    <input type="search" class="tp-in" id="ntFind" placeholder="find an alert&hellip;" style="max-width:220px">
    <div class="nt-sevs"><button type="button" class="nt-sev on" data-sev="">all <b><?= count($types) ?></b></button>
      <?php foreach ($sevOrder as $sv => $_): if (empty($sevCount[$sv])) continue; ?><button type="button" class="nt-sev" data-sev="<?= $sv ?>"><span class="b <?= $sevcls[$sv] ?? 'gray' ?>"><?= $sv ?></span> <b><?= (int)$sevCount[$sv] ?></b></button><?php endforeach; ?>
    </div>
  </div>
  <div class="nt-bulk" id="ntBulk" hidden>
    <b><span id="ntSelN">0</span> selected</b>
    <span class="grp"><span class="lbl">Enabled</span><button type="button" class="tp-btn" data-bulk="on:1">on</button><button type="button" class="tp-btn" data-bulk="on:0">off</button></span>
    <span class="grp"><span class="lbl">&#9993; Email</span><button type="button" class="tp-btn" data-bulk="email:1">on</button><button type="button" class="tp-btn" data-bulk="email:0">off</button></span>
    <span class="grp"><span class="lbl">Telegram</span><button type="button" class="tp-btn" data-bulk="tg:1">on</button><button type="button" class="tp-btn" data-bulk="tg:0">off</button></span>
    <span class="grp"><span class="lbl">Pushbullet</span><button type="button" class="tp-btn" data-bulk="pb:1">on</button><button type="button" class="tp-btn" data-bulk="pb:0">off</button></span>
    <span class="grp"><span class="lbl">WhatsApp</span><button type="button" class="tp-btn" data-bulk="wa:1">on</button><button type="button" class="tp-btn" data-bulk="wa:0">off</button></span>
    <span class="grp"><span class="lbl">Snooze</span><button type="button" class="tp-btn" data-bulkx="snooze:1">1h</button><button type="button" class="tp-btn" data-bulkx="snooze:4">4h</button><button type="button" class="tp-btn" data-bulkx="snooze:24">24h</button><button type="button" class="tp-btn" data-bulkx="snooze:0">resume</button></span>
    <span class="grp"><span class="lbl">Repeat</span><button type="button" class="tp-btn" data-bulkx="only:0">&#128257; daily</button><button type="button" class="tp-btn" data-bulkx="only:1">&#128276; only on change</button></span>
    <button type="button" class="tp-btn" id="ntSelClear" style="margin-left:auto">clear selection</button>
  </div>
  <div class="ph-tablewrap">
    <table class="smpro-table nt-tbl"><thead><tr>
      <th style="width:28px"><input type="checkbox" id="ntAll" title="select every visible row"></th>
      <th>Event</th><th>Severity</th><th style="text-align:center">Enabled</th><th style="text-align:center">&#9993; Email</th><th style="text-align:center">Telegram</th><th style="text-align:center">Pushbullet</th><th style="text-align:center">WhatsApp</th>
      <th style="text-align:center" title="Snooze silences this alert for N hours. Repeat decides whether an UNCHANGED report is sent again every remind window.">Snooze &middot; Repeat</th></tr></thead><tbody>
    <?php foreach ($types as $k => $info): $t = $cfg['types'][$k] ?? ['on'=>true,'email'=>true,'telegram'=>true,'pushbullet'=>true,'whatsapp'=>true];
          $mu = (int)($t['mute_until'] ?? 0); $muted = $mu > time(); $oc = !empty($t['only_changes']); ?>
      <tr class="nt-row<?= empty($t['on']) ? ' off' : '' ?>" data-k="<?= smpro_h($k) ?>" data-sev="<?= smpro_h($info[2]) ?>" data-name="<?= smpro_h(strtolower($info[0] . ' ' . $info[1])) ?>">
        <td><input type="checkbox" class="nt-pick"></td>
        <td><b><?= smpro_h($info[0]) ?></b><div class="meta" style="font-size:11.5px"><?= smpro_h($info[1]) ?></div></td>
        <td><span class="b <?= $sevcls[$info[2]] ?? 'gray' ?>"><?= smpro_h($info[2]) ?></span></td>
        <td style="text-align:center"><input type="checkbox" class="t-on" data-k="<?= smpro_h($k) ?>" <?= !empty($t['on'])?'checked':'' ?>></td>
        <td style="text-align:center"><input type="checkbox" class="t-email" data-k="<?= smpro_h($k) ?>" <?= !empty($t['email'])?'checked':'' ?>></td>
        <td style="text-align:center"><input type="checkbox" class="t-tg" data-k="<?= smpro_h($k) ?>" <?= !empty($t['telegram'])?'checked':'' ?>></td>
        <td style="text-align:center"><input type="checkbox" class="t-pb" data-k="<?= smpro_h($k) ?>" <?= !empty($t['pushbullet'])?'checked':'' ?>></td>
        <td style="text-align:center"><input type="checkbox" class="t-wa" data-k="<?= smpro_h($k) ?>" <?= !empty($t['whatsapp'])?'checked':'' ?>></td>
        <td style="text-align:center;white-space:nowrap">
          <select class="t-snooze tp-in" data-k="<?= smpro_h($k) ?>" style="width:auto;padding:2px 4px;font-size:11.5px">
            <option value="-1" selected><?= $muted ? '&#128564; until ' . date('H:i', $mu) : 'Active' ?></option>
            <?php if ($muted): ?><option value="0">Resume now</option><?php endif; ?>
            <option value="1">Snooze 1h</option>
            <option value="4">Snooze 4h</option>
            <option value="24">Snooze 24h</option>
          </select>
          <button type="button" class="tp-btn t-onlychg<?= $oc ? ' on' : '' ?>" data-k="<?= smpro_h($k) ?>" data-on="<?= $oc ? 1 : 0 ?>" style="padding:2px 8px;font-size:11.5px;margin-left:4px<?= $oc ? ';border-color:var(--brand);color:var(--brand)' : '' ?>"
                  title="Daily repeat: an unchanged report is sent again every remind window. Only on change: it is sent again only when a new account, address or finding appears."><?= $oc ? '&#128276; only on change' : '&#128257; repeats daily' ?></button>
        </td>
      </tr>
    <?php endforeach; ?>
    </tbody></table>
    <div class="nt-empty" id="ntNone" hidden>No alert matches.</div>
  </div>
  <div class="nt-thr">
    <b>Thresholds:</b>
    <label>Disk %<input class="tp-in" id="thr_disk_pct" type="number" value="<?= (int)($cfg['thresholds']['disk_pct'] ?? 90) ?>"></label>
    <label>Load<input class="tp-in" id="thr_load" type="number" value="<?= (int)($cfg['thresholds']['load'] ?? 20) ?>"><span class="meta" style="display:block;font-weight:400"><?php $ntCores = function_exists('smpro_cpu_cores') ? max(1, (int)smpro_cpu_cores()) : 1; $ntEff = max((int)($cfg['thresholds']['load'] ?? 20), $ntCores / 2); ?>on this server (<?= (int)$ntCores ?> cores) anything under <?= (int)($ntCores / 2) ?> is not high, so the alert fires at <?= (int)$ntEff ?></span></label>
    <label>Failed logins<input class="tp-in" id="thr_failed_logins" type="number" value="<?= (int)($cfg['thresholds']['failed_logins'] ?? 60) ?>"></label>
  </div>
  <div class="nt-thr" style="margin-top:8px">
    <b>&#128231; Outbound mail:</b>
    <label title="More than this many emails sent by one account in a single hour = bulk/spam alert">Max / hour<input class="tp-in" id="thr_mail_out_hour" type="number" value="<?= (int)($cfg['thresholds']['mail_out_hour'] ?? 100) ?>"></label>
    <label title="At least this many emails over 12 hours = bulk/spam alert. Below this is treated as normal mail.">Max / 12h<input class="tp-in" id="thr_mail_out_12h" type="number" value="<?= (int)($cfg['thresholds']['mail_out_12h'] ?? 300) ?>"></label>
    <label title="How often a persisting outbound-spam condition is re-alerted">Re-alert (h)<input class="tp-in" id="thr_remind_hours" type="number" value="<?= (int)($cfg['thresholds']['remind_hours'] ?? 12) ?>"></label>
  </div>
  <div class="nt-thr" style="margin-top:8px">
    <b>&#128229; Inbound spam:</b>
    <label title="Alert when at least this many incoming spam-scored / spam-rejected messages are seen in the window">Min spam mails<input class="tp-in" id="thr_inbound_spam_min" type="number" value="<?= (int)($cfg['thresholds']['inbound_spam_min'] ?? 1) ?>"></label>
    <label title="Re-alert about inbound spam at most this often (hours)">Re-alert (h)<input class="tp-in" id="thr_inbound_spam_remind_hours" type="number" value="<?= (int)($cfg['thresholds']['inbound_spam_remind_hours'] ?? 6) ?>"></label>
  </div>
</div>

<div class="nt-bar">
  <button class="tp-btn primary" type="button" id="ntSave">&#128190; Save settings</button>
  <button class="tp-btn" type="button" id="ntRun">&#9889; Run checks now</button>
  <label class="nt-cron"><input type="checkbox" id="ntCron" <?= $cronOn?'checked':'' ?>> Auto-check every 15 min</label>
  <span class="nt-res" id="ntBarRes"></span>
</div>

<!-- send log -->
<div class="card" style="padding:0;overflow:hidden;margin-top:14px">
  <div class="nt-card-h"><b>Recent notifications</b><span class="meta"><?= count($recent) ?> shown</span></div>
  <div class="ph-tablewrap" style="max-height:340px">
    <table class="smpro-table"><thead><tr><th>Time</th><th>Type</th><th>Subject</th><th>Channels</th><th>Result</th></tr></thead><tbody>
    <?php if (!$recent): ?><tr><td colspan="5" style="text-align:center;padding:16px;color:var(--muted)">No notifications sent yet.</td></tr>
    <?php else: foreach ($recent as $r): $res = $r['results'] ?? []; $allok = $res && !in_array(false, array_map(fn($x)=>!empty($x['ok']), $res), true); ?>
      <tr><td class="mono" style="font-size:11px"><?= smpro_h(date('Y-m-d H:i', (int)($r['ts'] ?? time()))) ?></td>
        <td><span class="b gray"><?= smpro_h($r['type'] ?? '') ?></span></td>
        <td><?= smpro_h($r['subject'] ?? '') ?></td>
        <td class="meta"><?= smpro_h(implode(', ', $r['channels'] ?? [])) ?></td>
        <td><?php foreach ($res as $ch=>$x): ?><span class="b <?= !empty($x['ok'])?'green':'red' ?>" title="<?= smpro_h($x['detail']??'') ?>"><?= smpro_h($ch) ?> <?= !empty($x['ok'])?'&#10003;':'&#10005;' ?></span> <?php endforeach; ?></td></tr>
    <?php endforeach; endif; ?>
    </tbody></table>
  </div>
</div>

<style>
.svc-kicker{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--brand);font-weight:800}
.nt-two{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:14px}@media(max-width:820px){.nt-two{grid-template-columns:1fr}}
.nt-ch{display:flex;flex-direction:column;gap:10px}
.nt-ch-h{display:flex;align-items:center;gap:10px;font-size:15px}.nt-ch-h b{font-size:15px}.nt-ic{font-size:18px}
.nt-sw{margin-left:auto;position:relative;display:inline-block;width:42px;height:24px}
.nt-sw input{opacity:0;width:0;height:0}
.nt-sw span{position:absolute;inset:0;background:#cbd5e1;border-radius:20px;transition:.2s;cursor:pointer}
.nt-sw span:before{content:"";position:absolute;height:18px;width:18px;left:3px;top:3px;background:var(--card);border-radius:50%;transition:.2s}
.nt-sw input:checked+span{background:var(--good)}.nt-sw input:checked+span:before{transform:translateX(18px)}
.nt-l{display:flex;flex-direction:column;gap:5px;font-size:12px;font-weight:700;color:var(--muted)}
.tp-in,.tp-sel{border:1px solid var(--line);border-radius:9px;padding:9px 12px;font-size:13px;font-weight:400;color:var(--ink)}
.tp-btn{border:1px solid var(--line);border-radius:9px;padding:9px 14px;font-size:13px;font-weight:600;cursor:pointer;background:var(--card);color:var(--ink);align-self:flex-start}
.tp-btn.primary{background:var(--brand);color:#fff;border-color:var(--brand)}
.nt-res{font-size:12px;min-height:0}
.nt-card-h .sp{flex:1}
.nt-tools{display:flex;gap:10px;align-items:center;flex-wrap:wrap;padding:10px 14px;border-bottom:1px solid var(--line)}
.nt-sevs{display:flex;gap:6px;flex-wrap:wrap}
.nt-sev{border:1px solid var(--line);background:var(--card);border-radius:20px;padding:3px 10px;font-size:12px;cursor:pointer;color:var(--text)}
.nt-sev b{margin-left:3px;color:var(--muted)}.nt-sev.on{border-color:var(--brand);box-shadow:inset 0 0 0 1px var(--brand)}
.nt-bulk{display:flex;gap:12px;align-items:center;flex-wrap:wrap;padding:8px 14px;background:var(--brand-bg);border-bottom:1px solid var(--line);font-size:12.5px}
.nt-bulk .grp{display:inline-flex;align-items:center;gap:4px}.nt-bulk .lbl{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);margin-right:2px}
.nt-bulk .tp-btn{padding:2px 8px;font-size:11.5px}
.nt-tbl tr.off td{opacity:.55}.nt-tbl tr.off td:first-child,.nt-tbl tr.off td:nth-child(4){opacity:1}
.nt-tbl tr.sel td{background:var(--brand-bg)}
.nt-tbl tr[hidden]{display:none}
.nt-empty{padding:16px;color:var(--muted);font-size:13px}
.nt-res.ok{color:var(--good)}.nt-res.err{color:var(--dang)}
.nt-help{font-size:11.5px;color:var(--muted);background:var(--brand-bg);border-radius:9px;padding:9px 11px;line-height:1.6}
.nt-smtp{display:flex;flex-direction:column;gap:8px;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:11px}
.nt-smtp-row{display:flex;gap:10px;flex-wrap:wrap}.nt-smtp-row .nt-l{min-width:120px}
.nt-card-h{display:flex;align-items:center;gap:10px;padding:14px 16px;border-bottom:1px solid var(--line)}.nt-card-h .meta{margin-left:auto;font-size:12px}
.ph-tablewrap{overflow:auto}.ph-tablewrap thead th{position:sticky;top:0;background:var(--card);z-index:1;box-shadow:inset 0 -1px 0 var(--line)}
.smpro-table{width:100%;border-collapse:collapse;font-size:12.5px}
.smpro-table th,.smpro-table td{padding:9px 12px;text-align:left;border-bottom:1px solid var(--line)}
.smpro-table th{font-size:11px;text-transform:uppercase;color:var(--muted)}
.nt-thr{display:flex;gap:14px;align-items:center;flex-wrap:wrap;padding:12px 16px;border-top:1px solid var(--line);font-size:12px}
.nt-thr label{display:flex;flex-direction:column;gap:3px;font-weight:700;color:var(--muted)}.nt-thr .tp-in{width:90px;padding:6px 9px}
.nt-bar{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin:14px 0}
.nt-cron{display:flex;align-items:center;gap:7px;font-size:13px;font-weight:600}
.mono{font-family:ui-monospace,Consolas,monospace}
.b{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:20px}
.b.red{background:var(--dang-bg);color:var(--dang)}.b.orange{background:var(--warn-bg);color:var(--warn)}.b.blue{background:var(--brand-bg);color:var(--brand)}.b.green{background:var(--good-bg);color:var(--good)}.b.gray{background:var(--card);color:#475569}
.meta{color:var(--muted)}
</style>
<script>
(function(){
  function post(fd){return fetch('index.cgi?page=notifications',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'}).then(function(r){return r.json();});}
  function res(el,j){el.className='nt-res '+(j&&j.ok?'ok':'err');el.textContent=(j&&j.ok?'✅ ':'⚠ ')+((j&&j.msg)||'');}
  function gather(){
    var fd=new URLSearchParams();fd.set('ntf_action','save');fd.set('smpro_csrf',NTF_CSRF);
    if(document.getElementById('emEnabled').checked)fd.set('email_enabled','1');
    fd.set('email_to',document.getElementById('emTo').value);fd.set('email_from',document.getElementById('emFrom').value);
    fd.set('email_method',document.getElementById('emMethod').value);
    fd.set('smtp_host',document.getElementById('smtpHost').value);fd.set('smtp_port',document.getElementById('smtpPort').value);
    fd.set('smtp_secure',document.getElementById('smtpSecure').value);fd.set('smtp_user',document.getElementById('smtpUser').value);
    fd.set('smtp_pass',document.getElementById('smtpPass').value);
    if(document.getElementById('tgEnabled').checked)fd.set('tg_enabled','1');
    fd.set('tg_token',document.getElementById('tgToken').value);fd.set('tg_chat',document.getElementById('tgChat').value);
    if(document.getElementById('pbEnabled').checked)fd.set('pb_enabled','1');
    fd.set('pb_token',document.getElementById('pbToken').value);
    if(document.getElementById('waEnabled').checked)fd.set('wa_enabled','1');
    fd.set('wa_base',document.getElementById('waBase').value);fd.set('wa_key',document.getElementById('waKey').value);
    fd.set('wa_session',document.getElementById('waSession').value);fd.set('wa_chat',document.getElementById('waChat').value);
    document.querySelectorAll('.t-on').forEach(function(c){if(c.checked)fd.append('t_on['+c.getAttribute('data-k')+']','1');});
    document.querySelectorAll('.t-email').forEach(function(c){if(c.checked)fd.append('t_email['+c.getAttribute('data-k')+']','1');});
    document.querySelectorAll('.t-tg').forEach(function(c){if(c.checked)fd.append('t_tg['+c.getAttribute('data-k')+']','1');});
    document.querySelectorAll('.t-pb').forEach(function(c){if(c.checked)fd.append('t_pb['+c.getAttribute('data-k')+']','1');});
    document.querySelectorAll('.t-wa').forEach(function(c){if(c.checked)fd.append('t_wa['+c.getAttribute('data-k')+']','1');});
    ['disk_pct','load','failed_logins','spam_events','mail_out_hour','mail_out_12h','remind_hours','inbound_spam_min','inbound_spam_remind_hours'].forEach(function(k){var el=document.getElementById('thr_'+k);if(el)fd.set('thr['+k+']',el.value||'0');});
    return fd;
  }
  var waT=document.getElementById('waTest');
  if(waT)waT.addEventListener('click',function(){post(gather()).then(function(){var f2=new URLSearchParams();f2.set('ntf_action','test_wa');f2.set('smpro_csrf',NTF_CSRF);return post(f2);}).then(function(j){res(document.getElementById('waRes'),j);});});
  // SMTP fields toggle
  var emM=document.getElementById('emMethod');
  if(emM)emM.addEventListener('change',function(){document.getElementById('emSmtp').style.display=this.value==='smtp'?'':'none';});
  // Pushbullet test (save first so the token is current)
  var pbT=document.getElementById('pbTest');
  if(pbT)pbT.addEventListener('click',function(){post(gather()).then(function(){var f2=new URLSearchParams();f2.set('ntf_action','test_pb');f2.set('smpro_csrf',NTF_CSRF);return post(f2);}).then(function(j){res(document.getElementById('pbRes'),j);});});
  document.getElementById('ntSave').addEventListener('click',function(){var b=this,o=b.innerHTML;b.disabled=true;post(gather()).then(function(j){b.disabled=false;res(document.getElementById('ntBarRes'),j);}).catch(function(){b.disabled=false;});});
  document.getElementById('emTest').addEventListener('click',function(){var fd=gather();fd.set('ntf_action','save');post(fd).then(function(){var f2=new URLSearchParams();f2.set('ntf_action','test_email');f2.set('smpro_csrf',NTF_CSRF);return post(f2);}).then(function(j){res(document.getElementById('emRes'),j);});});
  document.getElementById('tgTest').addEventListener('click',function(){var fd=gather();post(fd).then(function(){var f2=new URLSearchParams();f2.set('ntf_action','test_tg');f2.set('smpro_csrf',NTF_CSRF);return post(f2);}).then(function(j){res(document.getElementById('tgRes'),j);});});
  document.getElementById('tgFetch').addEventListener('click',function(){
    var f2=new URLSearchParams();f2.set('ntf_action','tg_chats');f2.set('smpro_csrf',NTF_CSRF);f2.set('tg_token',document.getElementById('tgToken').value);
    var box=document.getElementById('tgChats');box.className='nt-res';box.textContent='⏳ Looking…';
    post(f2).then(function(j){
      if(!j.ok||!j.chats||!Object.keys(j.chats).length){box.className='nt-res err';box.textContent='⚠ '+(j.msg||'No chats.');return;}
      box.className='nt-res';box.innerHTML='Click to use: ';
      Object.keys(j.chats).forEach(function(id){var a=document.createElement('button');a.className='tp-btn';a.style.cssText='padding:3px 9px;font-size:12px;margin:2px';a.textContent=j.chats[id]+' ('+id+')';a.onclick=function(){document.getElementById('tgChat').value=id;};box.appendChild(a);});
    }).catch(function(){box.className='nt-res err';box.textContent='⚠ Request failed — try again.';});   // no .catch → box was stuck on "Looking…" forever
  });
  document.getElementById('ntRun').addEventListener('click',function(){var b=this,o=b.innerHTML;b.disabled=true;b.innerHTML='⏳ Checking…';var fd=new URLSearchParams();fd.set('ntf_action','run_checks');fd.set('smpro_csrf',NTF_CSRF);post(fd).then(function(j){b.disabled=false;b.innerHTML=o;res(document.getElementById('ntBarRes'),j);}).catch(function(){b.disabled=false;b.innerHTML=o;});});
  document.getElementById('ntCron').addEventListener('change',function(){var fd=new URLSearchParams();fd.set('ntf_action','cron');fd.set('smpro_csrf',NTF_CSRF);if(this.checked)fd.set('on','1');post(fd).then(function(j){res(document.getElementById('ntBarRes'),j);});});
  // per-type snooze — fires immediately (no Save needed); option value -1 is just the current-state display
  // ---- selection, filter and bulk actions over the alert rows ----
  (function(){
    var rows=Array.prototype.slice.call(document.querySelectorAll('.nt-row')), all=document.getElementById('ntAll'), bulk=document.getElementById('ntBulk'), selN=document.getElementById('ntSelN'), dirty=document.getElementById('ntDirty'), none=document.getElementById('ntNone');
    var sev='', q='';
    function visible(r){return !r.hidden;}
    function picked(){return rows.filter(function(r){return visible(r)&&r.querySelector('.nt-pick').checked;});}
    function refresh(){var p=picked(); rows.forEach(function(r){r.classList.toggle('sel',r.querySelector('.nt-pick').checked);}); if(selN)selN.textContent=p.length; if(bulk)bulk.hidden=p.length===0; var vis=rows.filter(visible); if(all)all.checked=vis.length>0&&vis.every(function(r){return r.querySelector('.nt-pick').checked;}); if(none)none.hidden=vis.length>0;}
    function filter(){rows.forEach(function(r){var ok=(!sev||r.getAttribute('data-sev')===sev)&&(!q||r.getAttribute('data-name').indexOf(q)!==-1); r.hidden=!ok; if(!ok)r.querySelector('.nt-pick').checked=false;}); refresh();}
    document.querySelectorAll('.nt-sev').forEach(function(b){b.addEventListener('click',function(){document.querySelectorAll('.nt-sev').forEach(function(x){x.classList.remove('on');}); b.classList.add('on'); sev=b.getAttribute('data-sev'); filter();});});
    var find=document.getElementById('ntFind'); if(find)find.addEventListener('input',function(){q=find.value.trim().toLowerCase(); filter();});
    if(all)all.addEventListener('change',function(){rows.filter(visible).forEach(function(r){r.querySelector('.nt-pick').checked=all.checked;}); refresh();});
    rows.forEach(function(r){r.querySelector('.nt-pick').addEventListener('change',refresh); r.querySelector('.t-on').addEventListener('change',function(){r.classList.toggle('off',!this.checked);});});
    document.addEventListener('change',function(e){if(e.target.matches&&e.target.matches('.t-on,.t-email,.t-tg,.t-pb,.t-wa')&&dirty)dirty.hidden=false;});
    var clr=document.getElementById('ntSelClear'); if(clr)clr.addEventListener('click',function(){rows.forEach(function(r){r.querySelector('.nt-pick').checked=false;}); refresh();});
    // checkbox bulks: change the boxes, the usual Save settings commits them
    var cls={on:'.t-on',email:'.t-email',tg:'.t-tg',pb:'.t-pb',wa:'.t-wa'};
    document.querySelectorAll('[data-bulk]').forEach(function(b){b.addEventListener('click',function(){var p=b.getAttribute('data-bulk').split(':'), sel=cls[p[0]], v=p[1]==='1'; picked().forEach(function(r){var c=r.querySelector(sel); if(c){c.checked=v; if(p[0]==='on')r.classList.toggle('off',!v);}}); if(dirty)dirty.hidden=false;});});
    // immediate bulks: snooze and repeat go to the server row by row, like their own controls do
    document.querySelectorAll('[data-bulkx]').forEach(function(b){b.addEventListener('click',function(){var p=b.getAttribute('data-bulkx').split(':'), list=picked(); if(!list.length)return; b.disabled=true; var i=0, ok=0;
      (function next(){ if(i>=list.length){b.disabled=false; res(document.getElementById('ntBarRes'),{ok:true,msg:(p[0]==='snooze'?'Snooze':'Repeat mode')+' applied to '+ok+' of '+list.length+' alert(s).'}); return; }
        var r=list[i++], k=r.getAttribute('data-k'), fd=new URLSearchParams(); fd.set('smpro_csrf',NTF_CSRF); fd.set('type',k);
        if(p[0]==='snooze'){fd.set('ntf_action','snooze'); fd.set('hours',p[1]);} else {fd.set('ntf_action','only_changes'); fd.set('on',p[1]);}
        post(fd).then(function(j){ if(j&&j.ok){ok++; if(p[0]==='snooze'){var sl=r.querySelector('.t-snooze'), d=sl&&sl.querySelector('option[value="-1"]'); if(d)d.innerHTML=j.until?('&#128564; '+j.label):'Active';} else {var ob=r.querySelector('.t-onlychg'); if(ob){var on=p[1]==='1'; ob.setAttribute('data-on',on?'1':'0'); ob.innerHTML=on?'&#128276; only on change':'&#128257; repeats daily'; ob.style.borderColor=on?'var(--brand)':''; ob.style.color=on?'var(--brand)':'';}}} next(); }).catch(next);
      })();
    });});
    refresh();
  })();
  document.querySelectorAll('.t-onlychg').forEach(function(b){
    b.addEventListener('click',function(){
      var k=b.getAttribute('data-k'), on=b.getAttribute('data-on')==='1'?0:1;
      var fd=new URLSearchParams();fd.set('ntf_action','only_changes');fd.set('smpro_csrf',NTF_CSRF);fd.set('type',k);fd.set('on',String(on));
      b.disabled=true;
      post(fd).then(function(j){ b.disabled=false; res(document.getElementById('ntBarRes'),j);
        if(j&&j.ok){ b.setAttribute('data-on',String(on)); b.innerHTML=on?'&#128276; only on change':'&#128257; repeats daily'; b.style.borderColor=on?'var(--brand)':''; b.style.color=on?'var(--brand)':''; }
      }).catch(function(){ b.disabled=false; });
    });
  });
  document.querySelectorAll('.t-snooze').forEach(function(sel){
    sel.addEventListener('change',function(){
      var v=this.value; if(v==='-1')return;
      var k=this.getAttribute('data-k'), el=this;
      var fd=new URLSearchParams();fd.set('ntf_action','snooze');fd.set('smpro_csrf',NTF_CSRF);fd.set('type',k);fd.set('hours',v==='0'?'0':v);
      post(fd).then(function(j){
        res(document.getElementById('ntBarRes'),j);
        var disp=el.querySelector('option[value="-1"]'), resume=el.querySelector('option[value="0"]');
        if(j&&j.ok){
          if(j.until){ disp.innerHTML='&#128564; '+(j.label||'snoozed'); if(!resume){resume=document.createElement('option');resume.value='0';resume.textContent='Resume now';disp.insertAdjacentElement('afterend',resume);} }
          else { disp.textContent='Active'; if(resume)resume.remove(); }
        }
        el.value='-1';
      }).catch(function(){el.value='-1';});
    });
  });
})();
</script>
<?php
smpro_layout_footer();
