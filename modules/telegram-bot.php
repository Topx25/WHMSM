<?php
/**
 * modules/telegram-bot.php — Telegram control bot: enable/disable, test, command reference.
 * Reuses the Telegram token + chat id from the Notifications page. Actions via ?tgbot=1.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

$cfg  = smpro_tg_cfg();
$csrf = smpro_csrf_generate('tgbot');
$ready = $cfg['token'] !== '' && $cfg['admin'] !== '';
smpro_audit('tgbot_view', ['enabled' => $cfg['enabled']]);
smpro_layout_header('Telegram Bot');
?>
<script>var TGB_CSRF=<?= json_encode($csrf) ?>;</script>
<div class="svc-kicker">Remote Control</div>
<h1 class="h" style="margin:2px 0 4px">&#129302; Telegram control bot</h1>
<p class="sub">Control Safety Monitor Pro from Telegram with commands. It reuses the bot token + admin chat id from the <b>Notifications</b> page, polls every minute, and obeys <b>only</b> your admin chat.</p>

<div class="card" style="max-width:680px">
  <div class="lic-grid" style="display:grid;grid-template-columns:repeat(2,1fr);gap:10px">
    <div><span class="l">Status</span><b style="color:<?= $cfg['enabled'] ? '#16a34a' : '#64748b' ?>"><?= $cfg['enabled'] ? '&#9679; RUNNING' : '&#9675; stopped' ?></b></div>
    <div><span class="l">Bot token</span><b style="color:<?= $cfg['token'] !== '' ? '#16a34a' : '#b91c1c' ?>"><?= $cfg['token'] !== '' ? 'configured' : 'missing' ?></b></div>
    <div><span class="l">Admin chat id</span><b><?= $cfg['admin'] !== '' ? smpro_h($cfg['admin']) : '<span style="color:#b91c1c">not set</span>' ?></b></div>
    <div><span class="l">Authorized chats</span><b><?= (int)count($cfg['allowed']) ?></b></div>
  </div>

  <?php if (!$ready): ?>
    <p style="color:#b45309;margin:12px 0 0">&#9888; Set the Telegram <b>token</b> and <b>chat id</b> on the <a href="index.cgi?page=notifications">Notifications</a> page first, then enable the bot here.</p>
  <?php endif; ?>

  <div id="tgbMsg" class="meta" style="margin:14px 0;min-height:18px"></div>
  <div style="display:flex;gap:10px;flex-wrap:wrap">
    <label class="sw" style="display:inline-flex"><input type="checkbox" id="tgbEnable" <?= $cfg['enabled'] ? 'checked' : '' ?> <?= $ready ? '' : 'disabled' ?>><span class="track"></span><span class="lbl"><b>Enable control bot</b></span><span class="st"></span></label>
    <button class="btn" id="tgbTest" <?= $ready ? '' : 'disabled' ?>>&#128276; Send test message</button>
  </div>
</div>

<div class="card" style="max-width:680px;margin-top:14px">
  <h3 style="margin:0 0 8px">Commands</h3>
  <table style="width:100%;font-size:13px">
    <tr><td><code>/status</code></td><td>Server health (load, CPU, RAM, disk)</td></tr>
    <tr><td><code>/attacks</code></td><td>Web attacks in the last 60 minutes</td></tr>
    <tr><td><code>/blocked</code></td><td>Recently auto-blocked IPs</td></tr>
    <tr><td><code>/sites</code></td><td>Most-attacked domains (24h)</td></tr>
    <tr><td><code>/report</code></td><td>Security + health digest</td></tr>
    <tr><td><code>/scan</code></td><td>Quick compromise scan</td></tr>
    <tr><td><code>/block &lt;ip&gt;</code> · <code>/unblock &lt;ip&gt;</code> · <code>/allow &lt;ip&gt;</code></td><td>Firewall control</td></tr>
    <tr><td><code>/harden &lt;account&gt;</code></td><td>Lock a cPanel account (PHP-exec off + core files locked)</td></tr>
    <tr><td><code>/update</code></td><td>Check for plugin updates</td></tr>
    <tr><td><code>/emergency on|off</code></td><td>Toggle emergency auto-response</td></tr>
  </table>
  <p style="color:#64748b;font-size:12.5px;margin-top:10px">Only your configured admin chat can run commands; every command is logged. Control actions (block/harden/update/emergency) are restricted to that chat.</p>
</div>

<script>(function(){
  function P(id){return document.getElementById(id);}
  function call(extra){var fd=new URLSearchParams();fd.set('smpro_csrf',TGB_CSRF);Object.keys(extra).forEach(function(k){fd.set(k,extra[k]);});
    return fetch('index.cgi?tgbot=1',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'}).then(function(r){return r.json();});}
  function msg(t,c){P('tgbMsg').innerHTML=t;P('tgbMsg').style.color=c||'#475569';}
  P('tgbEnable').addEventListener('change',function(){var on=this.checked;msg(on?'Enabling…':'Disabling…');call({tgb_action:on?'enable':'disable'}).then(function(j){if(j&&j.ok){msg(on?'✓ Bot enabled — check Telegram for the welcome message.':'○ Bot disabled.','#047857');}else{P('tgbEnable').checked=!on;msg('✗ '+((j&&j.msg)||'failed'),'#b91c1c');}});});
  P('tgbTest').addEventListener('click',function(){msg('Sending…');call({tgb_action:'test'}).then(function(j){msg(j&&j.ok?'✓ Test sent — check Telegram.':'✗ '+((j&&j.msg)||'failed'),j&&j.ok?'#047857':'#b91c1c');});});
})();</script>
<?php
smpro_layout_footer();
