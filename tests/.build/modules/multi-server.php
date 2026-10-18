<?php
/**
 * modules/multi-server.php — Multi-Server "Hub" console (Ultra / multi_server feature).
 * A server is EITHER a Master (manages others) OR a Slave/Member (managed by one hub) — never both.
 * The Hub can be turned off on this server, and pairings can always be removed (which frees the
 * server to become a Master again).
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

$enabled     = function_exists('smpro_hub_enabled') && smpro_hub_enabled();          // Ultra licensed
$locDisabled = function_exists('smpro_hub_locally_disabled') && smpro_hub_locally_disabled();
$active      = $enabled && !$locDisabled;
$HUBCSRF     = smpro_csrf_generate('hub');
$permsAll    = smpro_hub_perms_all();

smpro_layout_header('Multi-Server Hub');
echo '<div class="svc-kicker">Fleet</div><h1 class="h" style="margin:2px 0 4px">&#127760; Multi-Server Hub</h1>';

// --- not Ultra: locked ---
if (!$enabled) {
    echo '<p class="sub">Manage several servers from one panel.</p>';
    echo '<div class="card"><div class="hb-lock"><div class="hb-lock-i">&#128274;</div><div><b>This is an Ultra feature.</b><div class="meta" style="margin-top:4px">Pair this server with your other Safety Monitor servers and run plugin actions on all of them from here. Upgrade to <b>Ultra</b> to unlock the Hub.</div></div></div></div>';
    echo '<style>.hb-lock{display:flex;gap:14px;align-items:center}.hb-lock-i{font-size:30px;opacity:.7}</style>';
    smpro_layout_footer();
    return;
}

$hubLinks = $active ? smpro_hub_links('hub') : [];
$memLinks = $active ? smpro_hub_links('member') : [];
$activeMem  = array_values(array_filter($memLinks, fn($l) => ($l['status'] ?? '') === 'active'));
$activeHub  = array_values(array_filter($hubLinks, fn($l) => in_array(($l['status'] ?? ''), ['active','pending'], true)));
$isSlave  = count($activeMem) > 0;                 // managed by a hub
$isMaster = count($activeHub) > 0;                 // manages (or is pairing with) others
$role     = $isSlave ? 'slave' : ($isMaster ? 'master' : 'free');
$masterName = $isSlave ? ($activeMem[0]['hub_label'] ?: ($activeMem[0]['hub_host'] ?: 'a hub')) : '';
$invites  = ($active && $role !== 'master' && function_exists('smpro_hub_invites')) ? smpro_hub_invites() : [];
$myKey    = function_exists('smpro_lic_key') ? smpro_lic_key() : '';
$cpassSet      = function_exists('smpro_hub_cpass_isset') && smpro_hub_cpass_isset();
$cpassUnlocked = !function_exists('smpro_hub_cpass_unlocked') || smpro_hub_cpass_unlocked();
$ctlLock       = function_exists('smpro_hub_lock_state') ? smpro_hub_lock_state() : [];
?>
<p class="sub">Pair this server with your other Safety Monitor servers and manage their plugin from here. Pairing is approved on <b>both</b> sides, and a Hub only gets the permissions the other server grants — never full root.</p>

<!-- on/off toggle (option) -->
<div class="hb-toggle">
  <div><b>Multi-Server Hub on this server:</b>
    <span class="pill <?= $active ? 'good' : 'warn' ?>"><?= $active ? 'ON' : 'OFF' ?></span></div>
  <button class="tp-btn <?= $active ? '' : 'success' ?>" type="button" id="hbToggle" data-on="<?= $active ? '0' : '1' ?>"><?= $active ? 'Turn off' : 'Turn on' ?></button>
</div>

<?php if ($locDisabled): ?>
  <div class="card"><p class="meta" style="margin:0">Multi-Server is <b>turned off</b> on this server. Turn it on above to pair with other servers or be managed by a hub. (Your license still includes it.)</p></div>
  <?php
  echo '<style>.hb-toggle{display:flex;justify-content:space-between;align-items:center;gap:12px;background:var(--bg);border:1px solid var(--line);border-radius:11px;padding:11px 14px;margin-bottom:14px}.pill{display:inline-block;font-size:10.5px;font-weight:700;padding:2px 9px;border-radius:20px;text-transform:uppercase;margin-left:6px}.pill.good{background:var(--good-bg);color:var(--good)}.pill.warn{background:var(--warn-bg);color:var(--warn)}</style>';
  ?>
  <script>
  (function(){var b=document.getElementById('hbToggle');if(!b)return;b.addEventListener('click',function(){
    var fd=new URLSearchParams();fd.set('smpro_csrf',<?= json_encode($HUBCSRF) ?>);fd.set('hub_action','set_enabled');fd.set('on',b.getAttribute('data-on'));
    fetch('index.cgi?hub_ajax=1',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString()}).then(function(){location.href='index.cgi?page=multi-server';});
  });})();
  </script>
  <?php smpro_layout_footer(); return; ?>
<?php endif; ?>

<!-- control password (independent of root) — the single shared secret across the fleet -->
<div class="hb-toggle">
  <div><b>&#128273; Control password</b>
    <span class="pill <?= $cpassSet ? 'good' : 'warn' ?>"><?= $cpassSet ? 'SET' : 'not set' ?></span>
    <span class="meta" style="margin-left:6px">extra password (&ne; root) required to manage remote servers — set the <b>same</b> one on every server you pair</span></div>
  <div style="display:flex;gap:6px">
    <input id="hbCpass" type="password" class="hb-in" style="max-width:200px;min-width:140px" placeholder="<?= $cpassSet ? 'new password' : 'set a password' ?>">
    <button class="tp-btn primary" type="button" id="hbCpassSave">Save</button>
    <?php if ($cpassSet): ?><button class="tp-btn danger" type="button" id="hbCpassClear">Remove</button><?php endif; ?>
  </div>
</div>

<?php if (!empty($ctlLock['until'])): ?>
<div class="hb-lock" role="alert">
  <div class="hb-lock-i">&#128274;</div>
  <div style="flex:1">
    <div class="hb-lock-h">Remote control is LOCKED on this server</div>
    <div class="hb-lock-b">Too many wrong control-password attempts from a managing hub. Remote control is blocked until <b><?= smpro_h(date('Y-m-d H:i', (int)$ctlLock['until'])) ?></b>. You can reset it now (allowed once every 24h).
    <br><b>If this was not you:</b> change the server <b>root</b> password, change the <b>control</b> password above, and re-create the pairing <b>token</b> (remove the pairing and pair again).</div>
  </div>
  <button class="tp-btn danger" type="button" id="hbLockReset">Reset lock</button>
</div>
<?php endif; ?>

<!-- role banner -->
<?php if ($role === 'slave'): ?>
  <div class="hb-role hb-role-slave"><div class="hb-role-i">&#128274;</div><div>
    <div class="hb-role-h">This server is MANAGED — Paired with <b><?= smpro_h($masterName) ?></b></div>
    <div class="hb-role-t">While it is paired, this server <b>cannot manage other servers</b> (a Slave can't be a Master). Remove the pairing below to make it independent again.</div>
  </div></div>
<?php elseif ($role === 'master'): ?>
  <?php $nActive = count(array_filter($hubLinks, fn($l)=>($l['status']??'')==='active')); $nPend = count($activeHub) - $nActive; ?>
  <div class="hb-role hb-role-master"><div class="hb-role-i">&#128225;</div><div>
    <div class="hb-role-h">This server is a HUB (Master) — <?= $nActive>0 ? ('managing '.$nActive.' server'.($nActive>1?'s':'')) : 'pairing in progress' ?><?= $nPend>0 ? (', '.$nPend.' pending') : '' ?></div>
    <div class="hb-role-t">A Hub can't also be managed by another hub. Remove all paired servers below if you want to change this server's role.</div>
  </div></div>
<?php else: ?>
  <div class="hb-role hb-role-free"><div class="hb-role-i">&#127760;</div><div>
    <div class="hb-role-h">This server is independent</div>
    <div class="hb-role-t">Choose a role: make it a <b>Hub</b> (manage your other servers) OR let another hub <b>manage this one</b>. Once paired, it locks to that role until you remove the pairing.</div>
  </div></div>
<?php endif; ?>

<!-- ===== HUB section (only when NOT a slave) ===== -->
<?php if ($role !== 'slave'): ?>
<?php $fleet = ($isMaster && function_exists('smpro_hub_fleet')) ? smpro_hub_fleet() : []; if ($fleet): ?>
<div class="card hb-card">
  <div class="hb-head"><span class="hb-ic">&#128202;</span><h3 class="hb-title">Fleet overview — live vitals</h3><span class="hb-count"><?= count($fleet) ?> servers</span></div>
  <div class="hb-fleet">
    <?php foreach ($fleet as $F): $L=$F['link']; $s=$F['snap']; $lid=(int)$L['link_id']; $nm=$L['member_host'] ?: ('Server #'.$lid); $mon=($L['mode']??'control')==='monitor'; $iss=function_exists('smpro_hub_snap_issues')?smpro_hub_snap_issues($s):[]; ?>
    <div class="hb-fcard<?= $iss?' hb-fbad':'' ?>">
      <div class="hb-fh"><b><?= smpro_h($nm) ?></b> <span class="pill <?= $mon?'mon':'ctl' ?>"><?= $mon?'monitor':'control' ?></span></div>
      <?php if ($iss): ?><div class="hb-fiss">&#9888; <?= smpro_h(implode(' · ', $iss)) ?></div><?php endif; ?>
      <?php if (!$s): ?><div class="meta" style="margin:6px 0">Waiting for first report (~60s)…</div>
      <?php else: $ld=is_array($s['load']??null)?($s['load']['1m']??'?'):($s['load']??'?'); ?>
        <div class="hb-fgrid">
          <div><span>Load</span><b><?= smpro_h(is_numeric($ld)?round((float)$ld,2):$ld) ?></b></div>
          <div><span>CPU</span><b><?= isset($s['cpu'])&&$s['cpu']!==null?round((float)$s['cpu']).'%':'?' ?></b></div>
          <div><span>RAM</span><b><?= isset($s['mem'])&&$s['mem']!==null?round((float)$s['mem']).'%':'?' ?></b></div>
          <div><span>Disk</span><b><?= isset($s['disk'])&&$s['disk']!==null?round((float)$s['disk']).'%':'?' ?></b></div>
        </div>
        <div class="hb-fsub">v<?= smpro_h($s['version']??'?') ?> &middot; up <?= smpro_h($s['uptime']??'?') ?><?= isset($s['blocked'])?(' &middot; '.(int)$s['blocked'].' blocked'):'' ?><?= !empty($s['svc_failed'])?(' &middot; <span style="color:var(--dang)">'.(int)$s['svc_failed'].' failed</span>'):'' ?><?= (isset($s['csf_on'])&&!$s['csf_on'])?' &middot; <span style="color:var(--warn)">CSF off</span>':'' ?><?= !empty($s['rebooted'])?' &middot; <span style="color:var(--dang)">&#8635; rebooted</span>':'' ?></div>
      <?php endif; ?>
      <div class="hb-fact">
        <?php $fp = smpro_h(implode(',', (array)($L['perms_grant'] ?? []))); ?>
        <button class="tp-btn" type="button" onclick="hubPanel(<?= $lid ?>,'<?= smpro_h(addslashes($nm)) ?>','dashboard','<?= $fp ?>')">&#128421; Open</button>
        <button class="tp-btn" type="button" onclick="hubPanel(<?= $lid ?>,'<?= smpro_h(addslashes($nm)) ?>','reports-center','<?= $fp ?>')">&#128202; Reports</button>
      </div>
    </div>
    <?php endforeach; ?>
  </div>
</div>
<?php endif; ?>
<div class="card hb-card">
  <div class="hb-head"><span class="hb-ic">&#128225;</span><h3 class="hb-title">Servers managed from this Hub</h3>
    <span class="hb-count"><?= count($activeHub) ?> linked</span></div>

  <div class="hb-form">
    <div class="hb-explain">&#128161; <b>How pairing works:</b> the server where you press <b>Generate pairing code</b> (this one) becomes the <b>Master</b> that manages the other. The server where you paste the code and <b>Approve</b> becomes the <b>Member</b> (managed). One Master manages many servers; a Member is managed by only one Master, and a Member can’t manage others until you remove its pairing.</div>
    <div class="hb-mode">
      <label><input type="radio" name="hbmode" value="control" checked> <b>Full control</b> — manage the remote plugin (actions)</label>
      <label><input type="radio" name="hbmode" value="monitor"> <b>Monitor only</b> — read-only (no actions)</label>
    </div>
    <div class="hb-form-row">
      <input id="hbLabel" class="hb-in" placeholder="Label for the server you want to add (e.g. Web-2, Mail)" maxlength="120">
      <button class="tp-btn primary" id="hbAdd" type="button">&#10133; Generate pairing code</button>
    </div>
    <div class="hb-form-row" style="margin-top:8px">
      <input id="hbTarget" class="hb-in hb-mono" placeholder="Optional: the other server's LICENSE KEY — it gets a notification, no code needed" maxlength="60">
    </div>
    <div class="meta" style="font-size:11.5px;margin-top:4px">Leave the key empty to get a code you paste on the other server. Fill it to send a direct invitation that appears as a banner on that server (find its key on its <b>License</b> page).</div>
    <div class="hb-perms-wrap" id="hbPermsWrap">
      <div class="hb-perms-lbl">Permissions this Hub may use on the other server:</div>
      <div class="hb-perms" id="hbPerms">
        <?php foreach ($permsAll as $code => $label): ?>
          <label class="hb-perm <?= $code==='view'?'is-locked':'' ?>"><input type="checkbox" value="<?= smpro_h($code) ?>" <?= $code==='view'?'checked disabled':'checked' ?>><span><?= smpro_h($label) ?></span></label>
        <?php endforeach; ?>
      </div>
    </div>
    <div id="hbAddOut" class="hb-out"></div>
  </div>

  <?php $nActiveHub = count(array_filter($hubLinks, fn($l)=>($l['status']??'')==='active')); ?>
  <?php if ($nActiveHub > 1): ?>
  <div class="hb-bulkbar">
    <label class="hb-selall"><input type="checkbox" id="hbAll"> Select all (<?= $nActiveHub ?>)</label>
    <span class="hb-bulkn meta" id="hbBulkN">0 selected</span>
    <span style="flex:1"></span>
    <button class="tp-btn" type="button" onclick="hubBulk('status')">&#128202; Status</button>
    <button class="tp-btn" type="button" onclick="hubBulk('block_ip')">&#9940; Block IP</button>
    <button class="tp-btn" type="button" onclick="hubBulk('apply_profile')">&#128737; Profile</button>
    <button class="tp-btn" type="button" onclick="hubBulk('restart_service')">&#9881; Restart</button>
    <button class="tp-btn" type="button" onclick="hubBulk('update')">&#8635; Update all</button>
    <div class="hb-bulkmsg" id="hbBulkMsg"></div>
  </div>
  <?php endif; ?>
  <div id="hubList" class="hb-list">
    <?php if (!$hubLinks): ?>
      <div class="hb-empty">No servers paired yet. Generate a code above, then on the other server open <b>Multi-Server Hub &rarr; Review request</b> and paste it.</div>
    <?php else: foreach ($hubLinks as $L): $st=$L['status']; $lid=(int)$L['link_id']; $pillCls=$st==='active'?'good':'warn'; ?>
      <div class="hb-item">
        <?php if ($st==='active'): ?><input type="checkbox" class="hb-sel" data-lid="<?= $lid ?>" title="select for bulk action" style="margin-top:5px"><?php endif; ?>
        <span class="hb-dot <?= $st==='active'?'on':'wait' ?>"></span>
        <div class="hb-body">
          <div class="hb-name">
            <?php if ($st==='active'): ?>Paired with <b><?= smpro_h($L['member_host'] ?: ($L['hub_label'] ?: 'Server #'.$lid)) ?></b><?php else: ?><?= smpro_h($L['hub_label'] ?: 'Server #'.$lid) ?><?php endif; ?>
            <span class="pill <?= $pillCls ?>"><?= smpro_h($st) ?></span>
            <span class="pill <?= ($L['mode']??'control')==='monitor'?'mon':'ctl' ?>"><?= ($L['mode']??'control')==='monitor'?'monitor':'control' ?></span></div>
          <div class="hb-sub">
            <?php if ($st==='pending'): ?>
              Waiting for the other server to approve — the pairing code was shown once when you generated it.
            <?php else: ?>
              <?= smpro_h($L['member_host'] ?: '—') ?> &middot; <?= smpro_h($L['member_ip'] ?: '—') ?>
              <?php if ($L['perms_grant']): ?><span class="hb-perms-chips"><?php foreach ((array)$L['perms_grant'] as $p) echo '<span class="hb-chip">'.smpro_h($p).'</span>'; ?></span><?php endif; ?>
            <?php endif; ?>
          </div>
          <div class="hb-stat" id="stat<?= $lid ?>"></div>
        </div>
        <div class="hb-actions">
          <?php if ($st==='active'): ?>
            <button class="tp-btn primary" type="button" onclick="hubPanel(<?= $lid ?>,'<?= smpro_h(addslashes($L['member_host'] ?: ('Server #'.$lid))) ?>','dashboard','<?= smpro_h(implode(',', (array)($L['perms_grant'] ?? []))) ?>')">&#128421; Open panel</button>
            <button class="tp-btn" type="button" onclick="hubStat(<?= $lid ?>)">&#128202; Status</button>
            <?php if (in_array('firewall',(array)$L['perms_grant'],true)): ?>
              <button class="tp-btn" type="button" onclick="hubAct(<?= $lid ?>,'block_ip')">&#9940; Block IP</button>
              <button class="tp-btn" type="button" onclick="hubAct(<?= $lid ?>,'unblock_ip')">&#9989; Unblock</button>
            <?php endif; ?>
            <?php if (in_array('profiles',(array)$L['perms_grant'],true)): ?>
              <button class="tp-btn" type="button" onclick="hubAct(<?= $lid ?>,'apply_profile')">&#128737; Profile</button>
            <?php endif; ?>
            <?php if (in_array('services',(array)$L['perms_grant'],true)): ?>
              <button class="tp-btn" type="button" onclick="hubAct(<?= $lid ?>,'restart_service')">&#9881; Restart</button>
            <?php endif; ?>
            <?php if (in_array('updates',(array)$L['perms_grant'],true)): ?>
              <button class="tp-btn" type="button" onclick="hubAct(<?= $lid ?>,'update')">&#8635; Update</button>
            <?php endif; ?>
          <?php endif; ?>
          <button class="tp-btn danger" type="button" onclick="hubRevoke(<?= $lid ?>)">&#128465; Remove server</button>
        </div>
      </div>
    <?php endforeach; endif; ?>
  </div>
</div>
<?php else: ?>
<div class="card"><p class="meta" style="margin:0">&#128274; This server is managed by a hub, so it can't manage other servers. Remove the pairing below to turn it into a Hub.</p></div>
<?php endif; ?>

<!-- ===== MEMBER section (hubs managing this server) ===== -->
<div class="card hb-card">
  <div class="hb-head"><span class="hb-ic">&#128274;</span><h3 class="hb-title">Hubs allowed to manage this server</h3>
    <span class="hb-count"><?= count($activeMem) ?> active</span></div>

  <?php if ($invites): ?>
  <div class="hb-invites">
    <div class="hb-inv-h">&#9888; Pairing request<?= count($invites)>1?'s':'' ?> for this server (<?= count($invites) ?>)</div>
    <?php foreach ($invites as $iv): ?>
    <div class="hb-item hb-inv" data-code="<?= smpro_h($iv['pair_code']) ?>" data-link="<?= (int)$iv['link_id'] ?>" data-perms="<?= smpro_h(implode(',', (array)$iv['perms_req'])) ?>">
      <span class="hb-dot wait"></span>
      <div class="hb-body">
        <div class="hb-name"><b><?= smpro_h($iv['hub_label'] ?: 'A hub') ?></b> wants to manage this server</div>
        <div class="hb-sub"><?= smpro_h($iv['hub_host'] ?: '—') ?> &middot; <?= smpro_h($iv['hub_ip'] ?: '—') ?> &middot; can: <?php foreach ((array)$iv['perms_req'] as $p) echo '<span class="hb-chip">'.smpro_h($p).'</span>'; ?></div>
        <div class="hb-inv-msg" style="font-size:12.5px;margin-top:5px"></div>
      </div>
      <div class="hb-actions">
        <button class="tp-btn success hb-inv-ok" type="button">&#10003; Approve</button>
        <button class="tp-btn danger hb-inv-no" type="button">&#10005; Decline</button>
      </div>
    </div>
    <?php endforeach; ?>
  </div>
  <?php endif; ?>

  <?php if ($role !== 'master'): ?>
  <div class="hb-form">
    <div class="hb-explain">&#128161; Paste a code generated on another server to let it <b>manage this one</b>. After you approve, <b>this server becomes a Member</b> (managed by that hub) and can’t manage others until you remove the pairing.</div>
    <div class="hb-form-row">
      <input id="jnCode" class="hb-in hb-mono" placeholder="Paste the pairing code from your Hub" maxlength="40">
      <button class="tp-btn" id="jnLookup" type="button">&#128269; Review request</button>
    </div>
    <div id="jnConsent" class="hb-consent" style="display:none"></div>
    <div id="jnOut" class="hb-out"></div>
  </div>
  <?php else: ?>
  <div class="hb-empty" style="margin-bottom:8px">&#128225; This server is a Hub (Master). A Master can't be managed by another hub. Remove its paired servers above first if you want to change that.</div>
  <?php endif; ?>

  <div id="memList" class="hb-list">
    <?php if (!$memLinks): ?>
      <div class="hb-empty">No hub manages this server — that's the safe default. A hub appears here only after you review and approve its request above.</div>
    <?php else: foreach ($memLinks as $L): $lid=(int)$L['link_id']; ?>
      <div class="hb-item">
        <span class="hb-dot on"></span>
        <div class="hb-body">
          <div class="hb-name">Paired with <b><?= smpro_h($L['hub_label'] ?: ($L['hub_host'] ?: 'Hub #'.$lid)) ?></b> <span class="pill good">managing</span> <span class="pill <?= ($L['mode']??'control')==='monitor'?'mon':'ctl' ?>"><?= ($L['mode']??'control')==='monitor'?'monitor':'control' ?></span></div>
          <div class="hb-sub"><?= smpro_h($L['hub_host'] ?: '—') ?> &middot; <?= smpro_h($L['hub_ip'] ?: '—') ?>
            <span class="hb-perms-chips"><?php foreach ((array)$L['perms_grant'] as $p) echo '<span class="hb-chip">'.smpro_h($p).'</span>'; ?></span></div>
        </div>
        <div class="hb-actions">
          <button class="tp-btn danger" type="button" onclick="hubRevoke(<?= $lid ?>)">&#128465; Remove pairing</button>
        </div>
      </div>
    <?php endforeach; endif; ?>
  </div>
</div>

<?php $hist = function_exists('smpro_hub_history') ? smpro_hub_history(40) : []; ?>
<div class="card hb-card">
  <div class="hb-head"><span class="hb-ic">&#128220;</span><h3 class="hb-title">Hub activity</h3><span class="hb-count"><?= count($hist) ?> recent</span></div>
  <?php if (!$hist): ?>
    <div class="hb-empty">No hub actions recorded yet — pairings, pushed commands and executions will appear here.</div>
  <?php else: ?>
  <table class="smpro-table" style="margin:0"><tbody>
    <?php foreach ($hist as $h): $d=(array)$h['details']; $info='';
      if(isset($d['action']))$info=$d['action'].(array_key_exists('ok',$d)?($d['ok']?' ✓':' ✗'):'').(isset($d['msg'])?(' — '.$d['msg']):'');
      elseif(isset($d['granted']))$info='granted: '.(is_array($d['granted'])?implode(',',$d['granted']):$d['granted']);
      elseif(isset($d['code']))$info='pairing code generated'; elseif(isset($d['by']))$info='by '.$d['by']; elseif(isset($d['link']))$info='link #'.$d['link']; ?>
      <tr><td class="meta" style="white-space:nowrap"><?= smpro_h(str_replace('T',' ',substr($h['t'],0,16))) ?></td>
          <td><b><?= smpro_h(ucfirst(trim(str_replace('_',' ',preg_replace('/^hub_/','',$h['action']))))) ?></b></td>
          <td class="meta"><?= smpro_h($info) ?></td></tr>
    <?php endforeach; ?>
  </tbody></table>
  <?php endif; ?>
</div>

<style>
.hb-bulkbar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;background:var(--brand-bg);border:1px solid var(--line);border-radius:10px;padding:9px 12px;margin-bottom:10px}
.hb-selall{font-size:12.5px;font-weight:700;display:flex;gap:6px;align-items:center;cursor:pointer}
.hb-bulkmsg{flex-basis:100%;font-size:12px;color:var(--muted);margin-top:2px}
.hb-sel{flex:0 0 auto}
.hb-toggle{display:flex;justify-content:space-between;align-items:center;gap:12px;background:var(--bg);border:1px solid var(--line);border-radius:11px;padding:11px 14px;margin-bottom:14px}
.hb-role{display:flex;gap:12px;align-items:flex-start;border:1px solid var(--line);border-left-width:4px;border-radius:11px;padding:12px 15px;margin-bottom:14px;background:var(--card)}
.hb-role-i{font-size:20px;line-height:1}
.hb-role-h{font-weight:800;font-size:14px;color:var(--ink)}
.hb-role-t{font-size:12.5px;color:var(--muted);margin-top:3px;line-height:1.55}
.hb-role-slave{border-left-color:var(--warn);background:var(--warn-bg)}
.hb-role-master{border-left-color:var(--brand);background:var(--brand-bg)}
.hb-role-free{border-left-color:var(--good)}
.hb-card{margin-bottom:16px}
.hb-head{display:flex;align-items:center;gap:9px;margin-bottom:14px}
.hb-ic{font-size:18px}
.hb-title{margin:0;font-size:15px;font-weight:700;color:var(--ink)}
.hb-count{margin-left:auto;font-size:11px;font-weight:700;color:var(--muted);background:var(--bg);border:1px solid var(--line);padding:2px 10px;border-radius:20px}
.hb-form{background:var(--bg);border:1px solid var(--line);border-radius:11px;padding:14px;margin-bottom:14px}
.hb-form-row{display:flex;gap:8px;flex-wrap:wrap}
.hb-in{flex:1;min-width:240px;padding:9px 12px;border:1px solid var(--line);border-radius:9px;font-size:13.5px;background:var(--card);color:var(--ink)}
.hb-mono{font-family:ui-monospace,Menlo,Consolas,monospace;letter-spacing:.06em;text-transform:uppercase}
.hb-perms-wrap{margin-top:12px}
.hb-perms-lbl{font-size:12px;font-weight:700;color:var(--muted);margin-bottom:7px}
.hb-perms{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:7px}
.hb-perm{display:flex;gap:8px;align-items:center;font-size:12.5px;color:var(--ink);background:var(--card);border:1px solid var(--line);border-radius:8px;padding:7px 10px;cursor:pointer}
.hb-perm input{width:auto;margin:0}
.hb-perm.is-locked{opacity:.65;cursor:default}
.hb-out{font-size:13px;margin-top:10px;min-height:0}
.hb-list{display:flex;flex-direction:column}
.hb-item{display:flex;gap:12px;align-items:flex-start;padding:13px 2px;border-top:1px solid var(--line)}
.hb-item:first-child{border-top:0}
.hb-dot{flex:0 0 auto;width:9px;height:9px;border-radius:50%;margin-top:6px}
.hb-dot.on{background:var(--good);box-shadow:0 0 0 3px var(--good-bg)}
.hb-dot.wait{background:var(--warn);box-shadow:0 0 0 3px var(--warn-bg)}
.hb-body{flex:1;min-width:0}
.hb-name{font-size:14px;font-weight:700;color:var(--ink);display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.hb-sub{color:var(--muted);font-size:12.5px;margin-top:4px;display:flex;align-items:center;gap:7px;flex-wrap:wrap}
.hb-stat{font-size:12px;color:var(--muted);margin-top:6px}
.hb-perms-chips{display:inline-flex;gap:4px;flex-wrap:wrap}
.hb-chip{display:inline-block;background:var(--brand-bg);color:var(--brand);font-size:10.5px;font-weight:700;padding:1px 9px;border-radius:7px}
.hb-code{display:inline-block;background:var(--brand-bg);color:var(--brand);font-family:ui-monospace,Menlo,Consolas,monospace;padding:2px 9px;border-radius:7px;font-size:12.5px;letter-spacing:.05em}
.hb-codebox{display:inline-flex;align-items:center;gap:9px;cursor:pointer;border:1px dashed var(--brand);background:var(--brand-bg);border-radius:9px;padding:6px 11px;user-select:all}
.hb-codebox.done{cursor:default;border-style:solid;border-color:var(--good);background:var(--good-bg)}
.hb-codebox .hb-code{background:transparent;padding:0;font-size:14px;letter-spacing:.1em}
.hb-copyhint{font-size:11px;font-weight:700;color:var(--brand);text-transform:uppercase;letter-spacing:.03em}
.hb-codebox.done .hb-copyhint{color:var(--good)}
.hb-codetip{font-size:12px;color:var(--muted);margin-top:7px;line-height:1.5}
.hb-lock{display:flex;gap:12px;align-items:flex-start;background:var(--dang-bg);border:1px solid var(--dang);border-radius:11px;padding:12px 14px;margin-bottom:14px}
.hb-lock-i{font-size:22px;line-height:1}
.hb-lock-h{font-weight:800;color:var(--dang);font-size:13.5px;margin-bottom:3px}
.hb-lock-b{font-size:12.5px;color:var(--ink);line-height:1.55}
.hb-lockrow{margin-top:8px;font-size:12px;color:var(--dang);display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.hb-vover{position:fixed;inset:0;z-index:10000;background:rgba(8,12,22,.55);display:flex;align-items:center;justify-content:center}
.hb-vcard{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:22px 26px;display:flex;gap:13px;align-items:center;max-width:420px;box-shadow:0 10px 40px rgba(0,0,0,.35)}
.hb-vspin{width:30px;height:30px;border-radius:50%;border:3px solid var(--line);border-top-color:var(--brand);animation:hbpspin .8s linear infinite;flex:none}
.hb-vtxt{font-size:13px;color:var(--ink);line-height:1.5}
.hb-actions{display:flex;gap:6px;flex-wrap:wrap;align-items:center;justify-content:flex-end}
.hb-empty{color:var(--muted);font-size:13px;padding:6px 2px}
.pill{display:inline-block;font-size:10.5px;font-weight:700;padding:2px 9px;border-radius:20px;text-transform:uppercase;letter-spacing:.03em}
.pill.good{background:var(--good-bg);color:var(--good)}.pill.warn{background:var(--warn-bg);color:var(--warn)}
.pill.mon{background:var(--warn-bg);color:var(--warn)}.pill.ctl{background:var(--brand-bg);color:var(--brand)}
.hb-explain{background:var(--brand-bg);border:1px solid var(--line);border-radius:9px;padding:10px 12px;margin-bottom:11px;font-size:12.5px;line-height:1.6;color:var(--ink)}
.hb-mode{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:10px;font-size:12.5px}
.hb-mode label{display:flex;gap:6px;align-items:center;cursor:pointer}
.hb-fleet{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:10px}
.hb-fcard{border:1px solid var(--line);border-radius:11px;padding:11px 12px;background:var(--bg)}
.hb-fh{display:flex;align-items:center;gap:7px;font-size:13.5px;margin-bottom:7px;flex-wrap:wrap}
.hb-fgrid{display:grid;grid-template-columns:repeat(4,1fr);gap:6px;text-align:center}
.hb-fgrid>div{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:5px 2px}
.hb-fgrid span{display:block;font-size:9.5px;text-transform:uppercase;color:var(--muted);letter-spacing:.03em}
.hb-fgrid b{font-size:14px;color:var(--ink)}
.hb-fsub{font-size:11.5px;color:var(--muted);margin-top:7px;line-height:1.5}
.hb-fcard.hb-fbad{border-color:var(--dang);box-shadow:0 0 0 1px var(--dang) inset}
.hb-fiss{font-size:11.5px;color:var(--dang);font-weight:600;margin:5px 0}
.hb-fact{display:flex;gap:6px;margin-top:9px}
.hb-consent{background:var(--warn-bg);border:1px solid var(--line);border-radius:10px;padding:13px;margin-top:10px}
.hb-consent h4{margin:0 0 7px;font-size:13.5px;color:var(--ink)}
.hb-consent .hb-perm{background:var(--card)}
@media(max-width:640px){.hb-item{flex-wrap:wrap}.hb-actions{justify-content:flex-start;width:100%}}
</style>
<script>
var HUB_CSRF = <?= json_encode($HUBCSRF) ?>;
var HUB_CPASS_SET = <?= $cpassSet?'true':'false' ?>, HUB_CPASS_UNLOCKED = <?= $cpassUnlocked?'true':'false' ?>;
function hubPostRaw(data){
  var b=new URLSearchParams(); b.set('smpro_csrf',HUB_CSRF);
  for(var k in data){ if(Array.isArray(data[k])) data[k].forEach(function(v){b.append(k+'[]',v);}); else b.set(k,data[k]); }
  return fetch('index.cgi?hub_ajax=1',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:b.toString()}).then(function(r){return r.json();});
}
// step-up: if the server asks to re-verify (a security rule fired — the rule itself is never disclosed),
// ask once for the MANAGED server's control password, prove it, then transparently retry the original call.
function hbVerifyOverlay(on){
  var id='hbVover',e=document.getElementById(id);
  if(on){ if(!e){e=document.createElement('div');e.id=id;e.className='hb-vover';e.innerHTML='<div class="hb-vcard"><div class="hb-vspin"></div><div class="hb-vtxt">Verifying authorization with the managed server…<br><span style="color:var(--muted)">first contact can take up to ~1 min</span></div></div>';document.body.appendChild(e);} }
  else if(e){ e.remove(); }
}
function hubPost(data,_retried){
  return hubPostRaw(data).then(function(j){
    if(!j||!j.needverify||!data.link_id||_retried) return j;
    var pw=prompt('🔐 '+(j.msg||'Security check — enter the managed server\'s control password to continue.'));
    if(!pw) return j;
    hbVerifyOverlay(true);
    return hubPostRaw({hub_action:'verify',link_id:data.link_id,pw:pw}).then(function(v){
      hbVerifyOverlay(false);
      if(v&&v.ok) return hubPost(data,true);
      alert((v&&v.msg)||'Verification failed.'); return v||j;
    },function(e){ hbVerifyOverlay(false); throw e; });
  });
}
function hubMsg(el,ok,t){ el.innerHTML='<span style="color:'+(ok?'var(--good)':'var(--dang)')+';font-weight:600">'+(ok?'✓ ':'✗ ')+hbEsc(t)+'</span>'; }
// HTML-escape any remote/member-supplied value before it touches innerHTML (hub label/host/ip, process names, versions)
function hbEsc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
// control-password gate: ensure unlocked before any action on a remote server
function hubEnsureUnlock(cb){
  if(!HUB_CPASS_SET || HUB_CPASS_UNLOCKED){ cb(); return; }
  var pw=prompt('🔐 Enter the control password to act on remote servers:'); if(!pw)return;
  hubPost({hub_action:'cpass_unlock',pw:pw}).then(function(r){ if(r&&r.ok){HUB_CPASS_UNLOCKED=true;cb();} else alert('Wrong control password.'); });
}
(function(){
  var s=document.getElementById('hbCpassSave'); if(s)s.addEventListener('click',function(){
    var v=document.getElementById('hbCpass').value; if(v===''){alert('Type a password first.');return;}
    if(!confirm('Set the control password? Use the SAME password on every server you pair, or paired servers will stop talking to each other until they match. It is required before acting on remote servers.'))return;
    hubPost({hub_action:'cpass_set',pw:v}).then(function(){location.href='index.cgi?page=multi-server';});
  });
  var c=document.getElementById('hbCpassClear'); if(c)c.addEventListener('click',function(){
    if(!confirm('Remove the control password? Remove it on every paired server too, or they will stop talking to each other.'))return;
    hubPost({hub_action:'cpass_set',pw:''}).then(function(){location.href='index.cgi?page=multi-server';});
  });
  var lr=document.getElementById('hbLockReset'); if(lr)lr.addEventListener('click',function(){
    if(!confirm('Reset the remote-control lock now? This is allowed only once every 24h.'))return;
    lr.disabled=true;lr.textContent='Resetting…';
    hubPost({hub_action:'reset_lock'}).then(function(r){ if(r&&r.ok){location.href='index.cgi?page=multi-server';} else {alert((r&&r.msg)||'Could not reset the lock.');lr.disabled=false;lr.textContent='Reset lock';} });
  });
})();
var hbTog=document.getElementById('hbToggle');
if(hbTog)hbTog.addEventListener('click',function(){
  if(hbTog.getAttribute('data-on')==='0' && !confirm('Turn OFF Multi-Server on this server? It will stop responding to its hub and stop managing others until turned back on.'))return;
  var fd={hub_action:'set_enabled',on:hbTog.getAttribute('data-on')};
  hubPost(fd).then(function(){location.href='index.cgi?page=multi-server';});
});
function hbMode(){var r=document.querySelector('input[name=hbmode]:checked');return r?r.value:'control';}
document.querySelectorAll('input[name=hbmode]').forEach(function(r){r.addEventListener('change',function(){
  var pw=document.getElementById('hbPermsWrap'); if(pw)pw.style.display=(hbMode()==='monitor')?'none':'';
});});
var hbAddB=document.getElementById('hbAdd');
if(hbAddB)hbAddB.addEventListener('click',function(){
  var self=this; if(HUB_CPASS_SET&&!HUB_CPASS_UNLOCKED){hubEnsureUnlock(function(){self.click();});return;}
  var perms=[].slice.call(document.querySelectorAll('#hbPerms input:checked')).map(function(c){return c.value;});
  var tgt=(document.getElementById('hbTarget')||{}).value||'';
  var out=document.getElementById('hbAddOut'); out.textContent='Generating…';
  hubPost({hub_action:'init',label:document.getElementById('hbLabel').value,perms:perms,target:tgt.trim(),mode:hbMode()}).then(function(j){
    if(!j.ok){hubMsg(out,false,j.msg||j.message||'Failed');return;}
    if(j.targeted){ out.innerHTML='✓ Invitation sent to that server — it will see a banner to approve within ~30s. <a href="index.cgi?page=multi-server">refresh</a>'; }
    else {
      // SECRET token: show it ONCE as click-to-copy, then mask it. It is single-use and expires in 24h.
      var code=j.pair_code;
      out.innerHTML='<div class="hb-codebox" id="hbCodeBox" title="Click to copy — it is hidden afterwards">'
        +'<span class="hb-code" id="hbCodeVal">'+hbEsc(code)+'</span><span class="hb-copyhint" id="hbCopyHint">📋 click to copy</span></div>'
        +'<div class="hb-codetip">Shown <b>once</b>. It is <b>single-use</b> and expires in <b>24h</b>. Copy it now and paste it on the other server (<b>Multi-Server Hub → Review request</b>). <a href="index.cgi?page=multi-server">refresh</a></div>';
      var box=document.getElementById('hbCodeBox');
      box.addEventListener('click',function(){
        if(box.getAttribute('data-done'))return;
        var fin=function(){box.setAttribute('data-done','1');document.getElementById('hbCodeVal').textContent='•••••• — copied & hidden';document.getElementById('hbCopyHint').textContent='✓ copied';box.classList.add('done');};
        if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(code).then(fin,fin);}
        else{try{var t=document.createElement('textarea');t.value=code;document.body.appendChild(t);t.select();document.execCommand('copy');document.body.removeChild(t);}catch(e){}fin();}
        code='';
      });
    }
  });
});
function hubStat(lid){
  var el=document.getElementById('stat'+lid); el.textContent='Loading status…';
  hubPost({hub_action:'pull',link_id:lid,dir:'status'}).then(function(j){
    var it=(j.items||[]); if(!it.length){el.textContent='No status reported yet (the member reports within ~90s).';return;}
    var s=it[it.length-1];
    var ld=(s.load&&typeof s.load==='object')?(s.load['1m']!=null?s.load['1m']:'?'):(s.load!=null?s.load:'?');
    var r1=function(n){return (typeof n==='number')?Math.round(n*100)/100:n;};
    var line1='<b>v'+hbEsc(s.version||'?')+'</b> · load '+r1(ld)+' · cpu '+(s.cpu!=null?Math.round(s.cpu)+'%':'?')+' · mem '+(s.mem!=null?Math.round(s.mem)+'%':'?')+' · disk '+(s.disk!=null?Math.round(s.disk)+'%':'?')+(s.uptime?(' · up '+hbEsc(s.uptime)):'')+' <span style="opacity:.6">('+hbEsc(s._at||'')+')</span>';
    var flags='';
    if(s.rebooted) flags+='<span class="hb-flag bad">⟳ rebooted '+hbEsc(s.rebooted)+'</span>';
    if(s.svc_failed) flags+='<span class="hb-flag '+(s.svc_failed>0?'bad':'')+'">'+s.svc_failed+' failed service'+(s.svc_failed>1?'s':'')+'</span>';
    if(s.csf_on===false) flags+='<span class="hb-flag warn">CSF off</span>';
    if(s.blocked!=null) flags+='<span class="hb-flag">'+s.blocked+' blocked IPs</span>';
    if(s.ctl_locked) flags+='<span class="hb-flag bad">🔒 remote-control LOCKED</span>';
    var top='';
    if(s.top&&s.top.length){ top='<div class="hb-top">Top CPU: '+s.top.map(function(t){return '<span class="hb-chip">'+hbEsc(t.cmd||'?')+' '+r1(t.cpu)+'%</span>';}).join(' ')+'</div>'; }
    var lockrow = s.ctl_locked ? '<div class="hb-lockrow">This server locked remote control after too many wrong control-password attempts'+(s.ctl_lock_until?(' (until '+hbEsc(new Date(s.ctl_lock_until*1000).toLocaleString())+')'):'')+'. <button class="tp-btn danger" type="button" onclick="hubResetLock('+lid+')">Reset its lock</button></div>' : '';
    el.innerHTML=line1+(flags?'<div class="hb-flags">'+flags+'</div>':'')+top+lockrow;
  });
}
function hubResetLock(lid){
  if(!confirm('Ask this managed server to reset its remote-control lock? Allowed once every 24h on that server.'))return;
  var el=document.getElementById('stat'+lid); if(el){var b=el.querySelector('button');if(b){b.disabled=true;b.textContent='Resetting…';}}
  hubPost({hub_action:'hub_reset_lock',link_id:lid}).then(function(r){ alert((r&&r.msg)||(r&&r.ok?'Lock reset.':'Could not reset the lock.')); hubStat(lid); });
}
function hubAct(lid,action){
  if(HUB_CPASS_SET&&!HUB_CPASS_UNLOCKED){hubEnsureUnlock(function(){hubAct(lid,action);});return;}
  var args={};
  if(action==='block_ip'||action==='unblock_ip'){var ip=prompt('IP address to '+(action==='block_ip'?'block':'unblock')+':');if(!ip)return;args.ip=ip.trim();}
  else if(action==='apply_profile'){var p=prompt('Profile to apply (medium / maximum / ai / custom):');if(!p)return;args.profile=p.trim().toLowerCase();}
  else if(action==='restart_service'){var sv=prompt('Service to restart (e.g. httpd, exim, mysql, lfd):');if(!sv)return;args.service=sv.trim().toLowerCase();}
  else if(action==='update'){if(!confirm('Push a plugin update to this server now?'))return;}
  var el=document.getElementById('stat'+lid); el.textContent='Queuing '+action+'…';
  hubPost({hub_action:'push',link_id:lid,cmd:action,args:args}).then(function(j){
    if(!j.ok){hubMsg(el,false,j.msg||j.message||'Failed');return;}
    el.innerHTML='✓ '+action+' queued — the member runs it within ~90s. <a href="#" onclick="hubStat('+lid+');return false;">check status</a>';
  });
}
function hubRevoke(lid){ if(!confirm('Remove this pairing? The link is deleted on both servers.'))return;
  hubPost({hub_action:'revoke',link_id:lid}).then(function(){ location.href='index.cgi?page=multi-server'; }); }
var jnB=document.getElementById('jnLookup');
if(jnB)jnB.addEventListener('click',function(){
  var code=document.getElementById('jnCode').value.trim().toUpperCase(); if(!code)return;
  var box=document.getElementById('jnConsent'); var out=document.getElementById('jnOut'); out.textContent='Looking up…';
  hubPost({hub_action:'lookup',code:code}).then(function(j){
    out.textContent='';
    if(!j.ok){hubMsg(out,false,j.message||j.msg||'Not found');box.style.display='none';return;}
    var isMon=(j.mode==='monitor'); var perms=j.perms_req||['view']; var labels=<?= json_encode($permsAll) ?>; var rows='';
    if(!isMon) perms.forEach(function(p){ rows+='<label class="hb-perm '+(p==='view'?'is-locked':'')+'"><input type="checkbox" value="'+hbEsc(p)+'" '+(p==='view'?'checked disabled':'checked')+'><span>'+hbEsc(labels[p]||p)+'</span></label>'; });
    var hl=hbEsc(j.hub_label||'A hub'), hh=hbEsc(j.hub_host||'?'), hi=hbEsc(j.hub_ip||'?');
    var modeLine = isMon
      ? '<div class="pill mon" style="margin-bottom:8px">MONITOR ONLY</div><div class="meta" style="margin-bottom:9px"><b>'+hl+'</b> ('+hh+' · '+hi+') wants to <b>monitor</b> this server — read-only, it can VIEW metrics/incidents but <b>cannot perform any action</b>.</div>'
      : '<div class="pill ctl" style="margin-bottom:8px">FULL CONTROL</div><div class="meta" style="margin-bottom:9px"><b>'+hl+'</b> ('+hh+' · '+hi+') wants to <b>manage</b> this server’s plugin. After you approve, this server becomes a Member and can no longer manage others. Choose what the hub may do:</div><div class="hb-perms">'+rows+'</div>';
    box.innerHTML='<h4>⚠ Pairing request</h4>'+modeLine+'<div style="margin-top:10px;display:flex;gap:6px"><button class="tp-btn success" type="button" id="jnApprove">✓ Approve pairing</button> <button class="tp-btn" type="button" onclick="document.getElementById(\'jnConsent\').style.display=\'none\'">Cancel</button></div>';
    box.style.display='block';
    document.getElementById('jnApprove').addEventListener('click',function(){
      var self=this; if(HUB_CPASS_SET&&!HUB_CPASS_UNLOCKED){hubEnsureUnlock(function(){self.click();});return;}
      var grant=[].slice.call(box.querySelectorAll('input:checked')).map(function(c){return c.value;});
      this.disabled=true;this.textContent='Approving…';
      hubPost({hub_action:'approve',code:code,perms:grant}).then(function(r){
        if(!r.ok){hubMsg(out,false,r.message||r.msg||'Failed');return;}
        location.href='index.cgi?page=multi-server';
      });
    });
  });
});
document.querySelectorAll('.hb-inv-ok').forEach(function(b){b.addEventListener('click',function(){
  if(HUB_CPASS_SET&&!HUB_CPASS_UNLOCKED){hubEnsureUnlock(function(){b.click();});return;}
  var c=b.closest('.hb-inv'),code=c.getAttribute('data-code'),perms=(c.getAttribute('data-perms')||'view').split(',');
  if(!confirm('Approve this hub to manage this server? It becomes a Member and can no longer manage other servers.'))return;
  b.disabled=true;b.textContent='Approving…';
  hubPost({hub_action:'approve',code:code,perms:perms}).then(function(r){
    if(!r.ok){c.querySelector('.hb-inv-msg').innerHTML='<span style="color:var(--dang);font-weight:600">'+(r.message||r.msg||'Failed')+'</span>';b.disabled=false;b.innerHTML='✓ Approve';return;}
    location.href='index.cgi?page=multi-server';
  });
});});
document.querySelectorAll('.hb-inv-no').forEach(function(b){b.addEventListener('click',function(){
  var c=b.closest('.hb-inv'),lid=c.getAttribute('data-link');
  if(!confirm('Decline this pairing request?'))return;
  hubPost({hub_action:'revoke',link_id:lid}).then(function(){location.href='index.cgi?page=multi-server';});
});});
// ---- bulk actions across selected members ----
function hbSelected(){return [].slice.call(document.querySelectorAll('.hb-sel:checked')).map(function(c){return c.getAttribute('data-lid');});}
function hbCount(){var n=document.querySelectorAll('.hb-sel:checked').length;var el=document.getElementById('hbBulkN');if(el)el.textContent=n+' selected';}
var hbAll=document.getElementById('hbAll');
if(hbAll)hbAll.addEventListener('change',function(){document.querySelectorAll('.hb-sel').forEach(function(c){c.checked=hbAll.checked;});hbCount();});
document.querySelectorAll('.hb-sel').forEach(function(c){c.addEventListener('change',hbCount);});
function hubBulk(action){
  var ids=hbSelected(); if(!ids.length){alert('Select at least one server first.');return;}
  if(action==='status'){ ids.forEach(function(id){hubStat(id);}); return; }
  if(HUB_CPASS_SET&&!HUB_CPASS_UNLOCKED){hubEnsureUnlock(function(){hubBulk(action);});return;}
  var args={};
  if(action==='block_ip'){var ip=prompt('Block this IP on '+ids.length+' server(s):');if(!ip)return;args.ip=ip.trim();}
  else if(action==='apply_profile'){var p=prompt('Apply profile to '+ids.length+' server(s) (medium / maximum / ai / custom):');if(!p)return;args.profile=p.trim().toLowerCase();}
  else if(action==='restart_service'){var s=prompt('Restart service on '+ids.length+' server(s) (httpd / exim / mysql / lfd):');if(!s)return;args.service=s.trim().toLowerCase();}
  else if(action==='update'){if(!confirm('Push a plugin update to '+ids.length+' server(s)?'))return;}
  var msg=document.getElementById('hbBulkMsg'); msg.textContent='Queuing on '+ids.length+' server(s)…';
  var done=0,ok=0;
  ids.forEach(function(id){ hubPost({hub_action:'push',link_id:id,cmd:action,args:args}).then(function(j){done++;if(j&&j.ok)ok++;
    msg.innerHTML='✓ Queued on '+ok+'/'+ids.length+' server(s) — each runs it within ~60s.'; }); });
}
</script>
<style>
.hb-invites{background:var(--warn-bg);border:1px solid var(--line);border-radius:11px;padding:10px 13px;margin-bottom:14px}
.hb-inv-h{font-weight:800;font-size:13px;color:var(--ink);margin-bottom:4px}
.hb-flags{margin-top:6px;display:flex;gap:5px;flex-wrap:wrap}
.hb-flag{font-size:11px;font-weight:700;padding:1px 8px;border-radius:7px;background:var(--bg);border:1px solid var(--line);color:var(--muted)}
.hb-flag.bad{background:var(--dang-bg);color:var(--dang);border-color:var(--dang-bg)}
.hb-flag.warn{background:var(--warn-bg);color:var(--warn);border-color:var(--warn-bg)}
.hb-top{margin-top:6px;font-size:11.5px;color:var(--muted)}
</style>
<!-- ===== Remote panel overlay (view the whole remote server, live) ===== -->
<div id="hbPanel" class="hb-panel" style="display:none">
  <div class="hb-pbar">
    <b>&#128421; <span id="hbpName">Remote server</span></b>
    <span id="hbpState" class="hb-pstate">Connecting…</span>
    <nav id="hbpNav" class="hb-pnav"></nav>
    <span style="flex:1"></span>
    <nav id="hbpAct" class="hb-pact" style="display:none"></nav>
    <button class="tp-btn" type="button" onclick="hubPanelReload()">&#8635; Refresh</button>
    <button class="tp-btn danger" type="button" onclick="hubPanelClose()">&#10005; Close</button>
  </div>
  <div class="hb-pbody"><iframe id="hbpFrame" class="hb-pframe" sandbox="allow-scripts allow-popups"></iframe>
    <div id="hbpMsg" class="hb-pmsg"></div></div>
</div>
<style>
.hb-panel{position:fixed;inset:0;z-index:9999;background:var(--bg);display:flex;flex-direction:column}
.hb-pbar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding:8px 12px;background:var(--side);color:#fff;border-bottom:1px solid #1d2740}
.hb-pbar .tp-btn{padding:5px 10px}
.hb-pstate{font-size:11px;font-weight:700;padding:2px 9px;border-radius:20px;background:#23304d;color:#cfe0ff}
.hb-pstate.live{background:rgba(31,157,85,.25);color:#7ef0b0}
.hb-pnav{display:flex;gap:4px;flex-wrap:wrap;margin-left:8px}
.hb-pnav button{background:#23304d;color:#cdd9f0;border:0;border-radius:7px;padding:4px 9px;font-size:12px;cursor:pointer}
.hb-pnav button.on{background:var(--brand);color:#fff}
.hb-pact{display:flex;gap:4px;flex-wrap:wrap;margin-right:8px}
.hb-pact button{background:#2a3a5e;color:#fff;border:0;border-radius:7px;padding:4px 9px;font-size:12px;cursor:pointer}
.hb-pact button:hover{filter:brightness(1.1)}
.hb-pbody{flex:1;position:relative;background:var(--card)}
.hb-pframe{width:100%;height:100%;border:0;background:#fff}
.hb-pmsg{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;text-align:center;padding:30px;color:var(--muted);font-size:14px;background:var(--card)}
.hb-pstate.off{background:rgba(217,59,59,.22);color:#ffb4b4}
.hbp-load{display:flex;flex-direction:column;align-items:center;gap:10px;max-width:420px}
.hbp-spin{width:46px;height:46px;border-radius:50%;border:4px solid var(--line);border-top-color:var(--brand);animation:hbpspin .8s linear infinite}
@keyframes hbpspin{to{transform:rotate(360deg)}}
.hbp-ic{font-size:42px;opacity:.85}
.hbp-lt{font-size:16px;font-weight:800;color:var(--ink)}
.hbp-ls{font-size:13px;color:var(--muted);line-height:1.6}
.hbp-bar{width:220px;height:5px;border-radius:5px;background:var(--line);overflow:hidden;margin-top:2px}
.hbp-bar>i{display:block;height:100%;background:var(--brand);transition:width .4s ease}
</style>
<script>
(function(){
  var PAGES=[['dashboard','Dashboard'],['reports-center','Reports'],['analytics-reports','Analytics'],['intrusion-monitor','Intrusion'],['firewall-status','Firewall'],['forensics-audit','Forensics'],['site-doctor','Site Doctor'],['security-health','Security'],['load-monitor','Server Health'],['top-processes','Processes'],['disk-storage','Disk'],['network','Network'],['backup-monitor','Backup'],['cpanel-services','Services']];
  var curLid=0,curPage='dashboard',curName='';
  function hbpLoader(title,sub,n){
    var bar = n ? '<div class="hbp-bar"><i style="width:'+Math.min(100,Math.round(n/6*100))+'%"></i></div>' : '';
    return '<div class="hbp-load"><div class="hbp-spin"></div><div class="hbp-lt">'+title+'</div><div class="hbp-ls">'+sub+'</div>'+bar+'</div>';
  }
  // injected into the remote page. The iframe is a SANDBOXED unique origin (no allow-same-origin), so it
  // can NEVER touch the hub's page/cookies — it talks to the parent ONLY via postMessage, both ways.
  var HB_SHIM = '\n<script>(function(){var P=parent;var cb={};'+
    'window.addEventListener("message",function(e){if(e.source!==P)return;var d=e.data||{};if(d.hbresp&&cb[d.id]){cb[d.id](d.html||"");delete cb[d.id];}});'+
    'function send(q,fn){var id="r"+Math.random().toString(36).slice(2);cb[id]=fn;P.postMessage({hbproxy:1,id:id,q:q},"*");}'+
    'var of=window.fetch;window.fetch=function(u,o){o=o||{};var m=((o.method||"GET")+"").toUpperCase();u=""+u;'+
    'if(m==="GET"&&u.indexOf("index.cgi")>=0){var q=u.split("?")[1]||"";return new Promise(function(res){send(q,function(t){res(new Response(t,{status:200,headers:{"Content-Type":(/^\\s*[\\{\\[]/.test(t)?"application/json":"text/html")}}));});});}'+
    'if(m!=="GET")return Promise.reject(new Error("blocked"));return of.apply(window,arguments);};'+
    'document.addEventListener("click",function(e){var a=e.target.closest&&e.target.closest("a[href]");if(!a)return;var h=a.getAttribute("href")||"";if(h.indexOf("index.cgi")>=0){e.preventDefault();P.postMessage({hbnav:1,q:(h.split("?")[1]||"")},"*");}},true);'+
    'document.addEventListener("submit",function(e){var f=e.target;var m=((f.method||"GET")+"").toUpperCase();e.preventDefault();if(m==="GET"){var p=[];[].forEach.call(f.elements,function(el){if(el.name&&!el.disabled&&el.type!=="submit"){if((el.type==="checkbox"||el.type==="radio")&&!el.checked)return;p.push(encodeURIComponent(el.name)+"="+encodeURIComponent(el.value));}});P.postMessage({hbnav:1,q:p.join("&")},"*");}else{alert("Actions inside the remote view are disabled here — use the toolbar at the top.");}},true);'+
    '})();<\/script>';
  function hbpApply(html){var fr=document.getElementById("hbpFrame");fr.srcdoc=html+HB_SHIM;fr.style.visibility="visible";document.getElementById("hbpMsg").style.display="none";var st=document.getElementById("hbpState");st.textContent="● Live";st.className="hb-pstate live";}
  // parent: serve the sandboxed iframe's routed GET requests — verify the message really came from OUR iframe,
  // then reply via postMessage (we never touch the iframe's internals, it never touches ours).
  window.addEventListener("message",function(e){
    var fr=document.getElementById("hbpFrame"); if(!fr||e.source!==fr.contentWindow) return;   // only our panel iframe
    var d=e.data||{};
    if(d.hbproxy){ hubPost({hub_action:'proxy',link_id:curLid,q:d.q}).then(function(j){ try{fr.contentWindow.postMessage({hbresp:1,id:d.id,html:(j&&j.html)||""},"*");}catch(x){} }); }
    else if(d.hbnav){ window.hubPanelLoadQuery(d.q); }
  });
  window.hubPanelLoadQuery=function(q){var msg=document.getElementById("hbpMsg"),fr=document.getElementById("hbpFrame");fr.style.visibility="hidden";msg.style.display="flex";msg.innerHTML=hbpLoader("Loading…","",0);
    hubPost({hub_action:'proxy',link_id:curLid,q:q}).then(function(j){ if(j&&j.ok&&j.html)hbpApply(j.html); else {msg.innerHTML=hbpLoader("Loading…","retrying…",0);setTimeout(function(){window.hubPanelLoadQuery(q);},3000);} });
  };
  window.hubPanel=function(lid,name,page,perms){ curLid=lid; curName=name||('Server #'+lid);
    document.getElementById('hbpName').textContent=curName;
    var nav=document.getElementById('hbpNav'); nav.innerHTML='';
    PAGES.forEach(function(p){var b=document.createElement('button');b.textContent=p[1];b.setAttribute('data-pg',p[0]);b.onclick=function(){hubPanelLoad(p[0]);};nav.appendChild(b);});
    // action toolbar — only the permissions this member granted (monitor links = none)
    var act=document.getElementById('hbpAct'); act.innerHTML=''; perms=perms?(''+perms).split(','):[];
    var amap=[['firewall','&#9940; Block IP','block_ip'],['firewall','&#9989; Unblock','unblock_ip'],['profiles','&#128737; Profile','apply_profile'],['services','&#9881; Restart','restart_service'],['updates','&#8635; Update','update']];
    amap.forEach(function(a){ if(perms.indexOf(a[0])>=0){ var b=document.createElement('button'); b.innerHTML=a[1]; b.onclick=function(){hubAct(curLid,a[2]);}; act.appendChild(b); } });
    act.style.display=act.children.length?'flex':'none';
    document.getElementById('hbPanel').style.display='flex';
    hubPanelLoad(page||'dashboard');
  };
  window.hubPanelClose=function(){document.getElementById('hbPanel').style.display='none';document.getElementById('hbpFrame').srcdoc='';};
  window.hubPanelReload=function(){hubPanelLoad(curPage);};
  window.hubPanelLoad=function(page){ curPage=page;
    document.querySelectorAll('#hbpNav button').forEach(function(b){b.classList.toggle('on',b.getAttribute('data-pg')===page);});
    var fr=document.getElementById('hbpFrame'),msg=document.getElementById('hbpMsg'),st=document.getElementById('hbpState');
    fr.style.visibility='hidden'; msg.style.display='flex';
    msg.innerHTML=hbpLoader('Connecting to '+curName,'Establishing a secure live session through the hub. The first page can take up to ~60s; after that it’s instant.',0);
    st.textContent='Connecting…'; st.className='hb-pstate';
    var tries=0;
    function attempt(){ tries++;
      hubPost({hub_action:'render',link_id:curLid,rpage:page}).then(function(j){
        if(j&&j.ok&&j.html){ hbpApply(j.html); }
        else if(tries<6){ msg.innerHTML=hbpLoader('Waking '+curName+'…','The remote server checks in every ~60s — connecting now.',tries); setTimeout(attempt,4000); }
        else { msg.innerHTML='<div class="hbp-load"><div class="hbp-ic">&#128268;</div><div class="hbp-lt">'+curName+' is not responding yet</div><div class="hbp-ls">It comes online within ~60s of opening, or it may be offline / Multi-Server turned off there.</div><button class="tp-btn primary" style="margin-top:12px" onclick="hubPanelReload()">&#8635; Try again</button></div>'; st.textContent='Offline'; st.className='hb-pstate off'; }
      }).catch(function(){ if(tries<6){ setTimeout(attempt,4000);} else { msg.innerHTML='<div class="hbp-load"><div class="hbp-ic">&#9888;</div><div class="hbp-lt">Request failed</div><button class="tp-btn primary" style="margin-top:12px" onclick="hubPanelReload()">&#8635; Try again</button></div>'; st.textContent='Error'; } });
    }
    attempt();
  };
})();
</script>
<?php smpro_layout_footer(); ?>
