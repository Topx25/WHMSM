<?php
/**
 * modules/cpanel-services.php — cPanel Services: Installed Services & Controls.
 * Card grid matching the legacy page: per-service status, facts, recommendation,
 * and safe controls (Restart/Start/Stop) for runtime services. Security products
 * (Imunify/CloudLinux/CageFS/LVE/ModSecurity/ClamAV/KernelCare) are detected and
 * advised. Controls are POST + CSRF + root + confirmation + audit.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

function smpro_svc_run($cmd, $t = null) { return (string)@shell_exec('timeout ' . ($t ?: SMPRO_TIMEOUT_QUICK) . ' ' . $cmd . ' 2>&1'); }
function smpro_svc_restartsrv($s) { foreach ($s['restart_scripts'] ?? [] as $p) if (is_executable($p)) return $p; return ''; }

function smpro_svc_registry() {
    return [
        'cpsrvd' => ['label'=>'cPanel / WHM','category'=>'cPanel Core','description'=>'WHM/cPanel web service. Restarting may briefly refresh your WHM session.','units'=>['cpanel','cpsrvd'],'commands'=>['cpsrvd','whostmgrd'],'restart_scripts'=>['/usr/local/cpanel/scripts/restartsrv_cpsrvd','/scripts/restartsrv_cpsrvd'],'critical'=>true,'install'=>'Repair cPanel RPMs'],
        'apache' => ['label'=>'Apache / HTTPD','category'=>'Web Stack','description'=>'Primary cPanel web server layer.','units'=>['httpd','apache2'],'commands'=>['httpd','apachectl'],'restart_scripts'=>['/usr/local/cpanel/scripts/restartsrv_httpd','/scripts/restartsrv_httpd'],'critical'=>true,'install'=>'Install ea-apache24'],
        'nginx' => ['label'=>'Nginx / ea-nginx','category'=>'Web Stack','description'=>'Optional cPanel reverse proxy / static cache layer.','units'=>['nginx'],'commands'=>['nginx'],'restart_scripts'=>['/usr/local/cpanel/scripts/restartsrv_nginx','/scripts/restartsrv_nginx'],'critical'=>false,'install'=>'Install ea-nginx'],
        'mysql' => ['label'=>'MariaDB / MySQL','category'=>'Database','description'=>'Database service used by hosted accounts and cPanel features.','units'=>['mariadb','mysql','mysqld'],'commands'=>['mysql','mariadb'],'restart_scripts'=>['/usr/local/cpanel/scripts/restartsrv_mysql','/scripts/restartsrv_mysql'],'critical'=>true,'install'=>'Repair cPanel RPMs'],
        'exim' => ['label'=>'Exim Mail Server','category'=>'Mail','description'=>'SMTP mail transfer service.','units'=>['exim'],'commands'=>['exim'],'restart_scripts'=>['/usr/local/cpanel/scripts/restartsrv_exim','/scripts/restartsrv_exim'],'critical'=>true,'install'=>'Repair cPanel RPMs'],
        'dovecot' => ['label'=>'Dovecot IMAP/POP3','category'=>'Mail','description'=>'Mailbox access service for IMAP/POP3.','units'=>['dovecot'],'commands'=>['dovecot'],'restart_scripts'=>['/usr/local/cpanel/scripts/restartsrv_dovecot','/scripts/restartsrv_dovecot'],'critical'=>true,'install'=>'Repair cPanel RPMs'],
        'dns' => ['label'=>'DNS Service','category'=>'DNS','description'=>'cPanel DNS service (named or PowerDNS).','units'=>['named','pdns'],'commands'=>['named','pdns_control'],'restart_scripts'=>['/usr/local/cpanel/scripts/restartsrv_named','/scripts/restartsrv_named'],'critical'=>false,'install'=>'Repair cPanel RPMs'],
        'sshd' => ['label'=>'SSH Service','category'=>'Access','description'=>'Remote shell access. Stop is intentionally blocked here (lock-out protection).','units'=>['sshd','ssh'],'commands'=>['sshd'],'restart_scripts'=>[],'critical'=>true,'no_stop'=>true,'install'=>'Install openssh-server'],
        'cron' => ['label'=>'Cron / crond','category'=>'Automation','description'=>'Scheduled jobs service.','units'=>['crond','cron'],'commands'=>['crond','cron'],'restart_scripts'=>[],'critical'=>false,'install'=>'Install cronie'],
        'lfd' => ['label'=>'CSF / LFD','category'=>'Firewall','description'=>'ConfigServer Security & Firewall login-failure daemon.','units'=>['lfd'],'commands'=>['csf','lfd'],'restart_scripts'=>[],'critical'=>true,'install'=>'Install CSF/LFD'],
        'firewalld' => ['label'=>'firewalld','category'=>'Firewall','description'=>'Alternative OS firewall. On cPanel, CSF/LFD is usually preferred.','units'=>['firewalld'],'commands'=>['firewall-cmd'],'restart_scripts'=>[],'critical'=>false,'install'=>'Install firewalld'],
        'cphulk' => ['label'=>'cPHulk Brute Force','category'=>'Access Security','description'=>'cPanel brute-force protection for WHM/cPanel/mail/SSH logins.','units'=>['cphulkd'],'commands'=>['cphulkd'],'restart_scripts'=>['/usr/local/cpanel/scripts/restartsrv_cphulkd','/scripts/restartsrv_cphulkd'],'critical'=>true,'install'=>'Repair cPanel RPMs'],
        'imunify' => ['label'=>'Imunify Security','category'=>'Security','description'=>'Malware scanner & web protection (Imunify360 / ImunifyAV).','units'=>['imunify360','imunify-antivirus'],'commands'=>['imunify360-agent','imunify-antivirus','imunifyav'],'restart_scripts'=>[],'critical'=>true,'product'=>true,'install'=>'Install ImunifyAV/360'],
        'cloudlinux' => ['label'=>'CloudLinux OS','category'=>'Security / Isolation','description'=>'Shared-hosting isolation and resource control base layer.','units'=>[],'commands'=>['cldetect','lvectl'],'restart_scripts'=>[],'critical'=>true,'product'=>true,'install'=>'Install CloudLinux'],
        'cagefs' => ['label'=>'CageFS','category'=>'Security / Isolation','description'=>'User filesystem isolation for shared-hosting accounts.','units'=>[],'commands'=>['cagefsctl'],'restart_scripts'=>[],'critical'=>true,'product'=>true,'install'=>'Install/Enable CageFS'],
        'lve_manager' => ['label'=>'LVE Manager','category'=>'Security / Limits','description'=>'CloudLinux per-account CPU/RAM/IO resource limits.','units'=>[],'commands'=>['lvectl'],'restart_scripts'=>[],'critical'=>false,'product'=>true,'install'=>'Install LVE'],
        'mysql_governor' => ['label'=>'MySQL Governor','category'=>'Database Protection','description'=>'Limits abusive MySQL usage per account (CloudLinux).','units'=>[],'commands'=>['dbctl'],'restart_scripts'=>[],'critical'=>false,'product'=>true,'install'=>'Install Governor'],
        'modsecurity' => ['label'=>'ModSecurity (WAF)','category'=>'Web Security','description'=>'Apache web application firewall for HTTP attack filtering.','units'=>[],'commands'=>[],'modsec'=>true,'restart_scripts'=>[],'critical'=>true,'product'=>true,'install'=>'Install/Enable ModSecurity'],
        'clamav' => ['label'=>'ClamAV Scanner','category'=>'Mail / Malware','description'=>'Antivirus scanner for malware and mail attachments.','units'=>['clamd','clamd@scan','cpanel-clamd'],'commands'=>['clamscan','clamdscan'],'restart_scripts'=>[],'critical'=>false,'product'=>true,'install'=>'Install ClamAV'],
        'kernelcare' => ['label'=>'KernelCare','category'=>'Kernel Security','description'=>'Rebootless kernel security patching (needs a KernelCare license).','units'=>['kcare'],'commands'=>['kcarectl'],'restart_scripts'=>[],'critical'=>false,'product'=>true,'install'=>'Install KernelCare'],
    ];
}

function smpro_svc_cmd_exists($c) { return trim((string)@shell_exec('command -v ' . escapeshellarg($c) . ' 2>/dev/null')) !== ''; }

function smpro_svc_status($s) {
    $units = $s['units'] ?? []; $cmds = $s['commands'] ?? [];
    $matched = ''; $active = false; $enabled = 'n/a'; $state = '';
    foreach ($units as $u) {
        $st = trim(smpro_svc_run('systemctl is-active ' . escapeshellarg($u), 8));
        if ($st === 'active') { $active = true; $matched = $u; $enabled = trim(smpro_svc_run('systemctl is-enabled ' . escapeshellarg($u), 8)); $state = 'active'; break; }
        if ($matched === '' && in_array($st, ['inactive', 'failed', 'activating'], true)) { $matched = $u; $state = $st; $enabled = trim(smpro_svc_run('systemctl is-enabled ' . escapeshellarg($u), 8)); }
    }
    $cmdPresent = false; foreach ($cmds as $c) if (smpro_svc_cmd_exists($c)) { $cmdPresent = true; break; }
    if (!empty($s['modsec'])) { $cmdPresent = trim(smpro_svc_run("grep -rliE 'modsec' /etc/apache2 /usr/local/apache/conf /etc/httpd 2>/dev/null | head -1")) !== ''; $active = $cmdPresent; }
    $rs = smpro_svc_restartsrv($s);
    $installed = $matched !== '' || $cmdPresent || $rs !== '';
    if (!empty($s['product']) || empty($units)) { $active = $active || $cmdPresent; $state = $active ? 'present' : 'absent'; $enabled = $enabled === 'n/a' && $active ? 'product' : $enabled; }
    return ['installed' => $installed, 'active' => $active, 'enabled' => $enabled === '' ? 'n/a' : $enabled, 'unit' => $matched ?: ($units[0] ?? '—'), 'state' => $state ?: ($active ? 'active' : 'inactive')];
}

/** State label + visual level + recommendation. */
function smpro_svc_assess($s, $st) {
    $crit = !empty($s['critical']);
    if ($st['active']) return ['ACTIVE', 'good', 'good', 'Running normally.' . ($crit ? ' Keep this core service enabled.' : '')];
    if ($st['installed']) {
        if ($crit) return ['INACTIVE', 'danger', 'danger', 'This important service is installed but not running — start it.'];
        return ['OK DISABLED', 'ok', 'info', 'Installed but inactive. Fine if intentionally disabled on this server.'];
    }
    if ($crit) return ['MISSING', 'danger', 'danger', 'Recommended: ' . ($s['install'] ?? 'install this service') . '. Important on cPanel servers.'];
    return ['NOT INSTALLED', 'muted', 'info', 'Optional. Install only if you need it: ' . ($s['install'] ?? '—') . '.'];
}

/* ---------- POST control ---------- */
$reqMethod = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));
if ($reqMethod === 'POST' && ($_POST['svc_action'] ?? '') !== '') {
    smpro_require_valid_csrf('svc_ctl'); smpro_require_root();
    $action = preg_replace('/[^a-z]/', '', (string)$_POST['svc_action']);
    $key = preg_replace('/[^a-z0-9_]/', '', (string)($_POST['svc'] ?? ''));
    if (!in_array($action, ['restart','start','stop'], true)) { echo json_encode(['ok'=>false,'msg'=>'bad action']); exit; }
    $reg = smpro_svc_registry(); $svc = $reg[$key] ?? null;
    if (!$svc) { echo json_encode(['ok'=>false,'msg'=>'unknown service']); exit; }
    if ($action === 'stop' && !empty($svc['no_stop'])) { echo json_encode(['ok'=>false,'msg'=>'refused: stopping this service here is blocked']); exit; }
    if (!empty($svc['product'])) { echo json_encode(['ok'=>false,'msg'=>'this product has no runtime control here']); exit; }
    $rs = smpro_svc_restartsrv($svc); $unit = $svc['units'][0] ?? '';
    if ($action === 'restart' && $rs !== '') $cmd = escapeshellarg($rs);
    elseif ($unit !== '') $cmd = 'systemctl ' . $action . ' ' . escapeshellarg($unit);
    else { echo json_encode(['ok'=>false,'msg'=>'no control method']); exit; }
    $out = smpro_svc_run($cmd, 45); sleep(1);
    $st = smpro_svc_status($svc);
    $ok = $action === 'stop' ? !$st['active'] : $st['active'];
    smpro_audit('cpanel_service_' . $action, ['svc'=>$key,'ok'=>$ok,'actor'=>smpro_current_actor()]);
    $a = smpro_svc_assess($svc, $st);
    echo json_encode(['ok'=>$ok,'active'=>$st['active'],'state_label'=>$a[0],'cls'=>$a[1],'msg'=>trim(mb_substr($out,0,200))], JSON_UNESCAPED_SLASHES);
    exit;
}

/* ---------- gather ---------- */
$rows = [];
foreach (smpro_svc_registry() as $key => $s) { $st = smpro_svc_status($s); $a = smpro_svc_assess($s, $st); $rows[] = ['key'=>$key,'s'=>$s,'st'=>$st,'a'=>$a]; }
$instN = count(array_filter($rows, fn($r)=>$r['st']['installed']));
$actN  = count(array_filter($rows, fn($r)=>$r['st']['active']));
$attnN = count(array_filter($rows, fn($r)=>$r['a'][1]==='danger'));

smpro_audit('cpanel_services_view', ['installed'=>$instN,'active'=>$actN,'attention'=>$attnN]);
smpro_layout_header('cPanel Services');
?>
<div style="display:flex;justify-content:space-between;align-items:flex-start;gap:14px;flex-wrap:wrap">
  <div>
    <div class="svc-kicker">cPanel Services</div>
    <h1 class="h" style="margin:2px 0 4px">Installed Services &amp; Controls</h1>
    <p class="sub">Start, restart, or stop core services, and review recommended security products. Controls run cPanel/systemctl actions server-side and are logged.</p>
  </div>
  <div style="display:flex;gap:8px;align-items:center">
    <a class="svc-top" href="index.cgi?page=server-health">Server Health</a>
    <a class="svc-top" href="index.cgi?page=firewall-status">Firewall</a>
  </div>
</div>

<div class="svc-cards3">
  <div class="card svc-sc"><div class="lbl">Installed</div><div class="v"><?= (int)$instN ?></div><div class="meta">of <?= count($rows) ?> known</div></div>
  <div class="card svc-sc"><div class="lbl">Active</div><div class="v" style="color:var(--good)"><?= (int)$actN ?></div></div>
  <div class="card svc-sc"><div class="lbl">Needs attention</div><div class="v" style="color:<?= $attnN?'var(--dang)':'var(--good)' ?>"><?= (int)$attnN ?></div><div class="meta">core down / missing</div></div>
</div>
<script>var SVC_CSRF=<?= json_encode(smpro_csrf_generate('svc_ctl')) ?>;</script>

<div class="svc-grid">
  <?php foreach ($rows as $r): $s=$r['s']; $st=$r['st']; [$stateLabel,$cls,$recLevel,$recText]=$r['a']; $key=$r['key'];
    $runtime = empty($s['product']); $u = !empty($s['units']);
    $showStart = $runtime && $st['installed'] && !$st['active'] && $u;
    $showRestart = $runtime && $st['installed'] && $st['active'] && ($u || smpro_svc_restartsrv($s)!=='');
    $showStop = $runtime && $st['installed'] && $st['active'] && empty($s['no_stop']) && $u;
  ?>
  <article class="svc-card <?= $cls ?>" data-svc="<?= smpro_h($key) ?>" data-warn="<?= smpro_h($s['description']) ?>" data-label="<?= smpro_h($s['label']) ?>">
    <div class="svc-cardtop">
      <div><span class="svc-cat"><?= smpro_h($s['category']) ?></span><h3><?= smpro_h($s['label']) ?></h3></div>
      <span class="svc-state <?= $cls ?>" data-state><?= smpro_h($stateLabel) ?></span>
    </div>
    <p class="svc-desc"><?= smpro_h($s['description']) ?></p>
    <div class="svc-facts">
      <div><span>Installed</span><b><?= $st['installed']?'Yes':'No' ?></b></div>
      <div><span>State</span><b><?= smpro_h($st['state']) ?></b></div>
      <div><span>Enabled</span><b><?= smpro_h($st['enabled']) ?></b></div>
      <div><span>Unit</span><b><?= smpro_h($st['unit']) ?></b></div>
    </div>
    <div class="svc-rec <?= $recLevel ?>"><?= smpro_h($recText) ?></div>
    <div class="svc-ctl" data-ctl>
      <?php if ($showStart): ?><button class="svc-btn start" data-a="start">Start</button><?php endif; ?>
      <?php if ($showRestart): ?><button class="svc-btn restart" data-a="restart">Restart</button><?php endif; ?>
      <?php if ($showStop): ?><button class="svc-btn stop" data-a="stop">Stop</button><?php endif; ?>
      <?php if (!empty($s['no_stop']) && $st['active']): ?><span class="svc-blocked">Stop blocked</span><?php endif; ?>
      <?php if (!$runtime): ?><span class="svc-note">Detected by presence — no runtime control here.</span><?php endif; ?>
      <?php if (!$st['installed']): ?><span class="svc-note">Install: <?= smpro_h($s['install'] ?? '—') ?> (manual)</span><?php endif; ?>
    </div>
  </article>
  <?php endforeach; ?>
</div>

<style>
.svc-kicker{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--brand);font-weight:800}
.svc-top{font-size:13px;color:var(--brand);text-decoration:none;border:1px solid var(--line);padding:6px 12px;border-radius:8px}.svc-top:hover{background:var(--brand-bg)}
.svc-cards3{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin:14px 0}
@media(max-width:600px){.svc-cards3{grid-template-columns:1fr}}
.svc-sc{padding:14px 16px}.svc-sc .lbl{font-size:11px;color:var(--muted);text-transform:uppercase;font-weight:700}.svc-sc .v{font-size:26px;font-weight:800;margin-top:4px}.svc-sc .meta{font-size:11px;color:var(--muted)}
.svc-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(330px,1fr));gap:14px}
.svc-card{background:#fff;border:1px solid var(--line);border-radius:14px;padding:16px;border-top:4px solid var(--line);display:flex;flex-direction:column}
.svc-card.good{border-top-color:var(--good)}.svc-card.danger{border-top-color:var(--dang)}.svc-card.ok{border-top-color:var(--good)}.svc-card.muted{border-top-color:#cbd5e1}
.svc-cardtop{display:flex;justify-content:space-between;align-items:flex-start;gap:10px}
.svc-cat{font-size:10px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);font-weight:700}
.svc-cardtop h3{margin:3px 0 0;font-size:15px}
.svc-state{font-size:10px;font-weight:800;padding:3px 9px;border-radius:20px;white-space:nowrap}
.svc-state.good,.svc-state.ok{background:var(--good-bg);color:var(--good)}.svc-state.danger{background:var(--dang-bg);color:var(--dang)}.svc-state.muted{background:#f1f5f9;color:#475569}
.svc-desc{font-size:12px;color:var(--muted);margin:10px 0;line-height:1.5;flex:1}
.svc-facts{display:grid;grid-template-columns:1fr 1fr;gap:6px 12px;font-size:12px;margin-bottom:10px}
.svc-facts span{color:var(--muted);font-size:10px;text-transform:uppercase;display:block}.svc-facts b{font-weight:700}
.svc-rec{font-size:12px;border-radius:8px;padding:8px 10px;line-height:1.5;margin-bottom:10px}
.svc-rec.good{background:var(--good-bg);color:#15803d}.svc-rec.info{background:var(--brand-bg);color:#26408b}.svc-rec.warning{background:var(--warn-bg);color:var(--warn)}.svc-rec.danger{background:var(--dang-bg);color:var(--dang)}
.svc-ctl{display:flex;gap:6px;align-items:center;flex-wrap:wrap}
.svc-btn{font-size:12px;font-weight:600;border:1px solid var(--line);background:#fff;border-radius:8px;padding:5px 14px;cursor:pointer}
.svc-btn.restart{color:var(--brand);border-color:#c9d4ff}.svc-btn.restart:hover{background:var(--brand);color:#fff}
.svc-btn.start{color:var(--good);border-color:#bfe6cd}.svc-btn.start:hover{background:var(--good);color:#fff}
.svc-btn.stop{color:var(--dang);border-color:#f3c4c4}.svc-btn.stop:hover{background:var(--dang);color:#fff}
.svc-btn:disabled{opacity:.4;cursor:not-allowed}
.svc-blocked,.svc-note{font-size:11px;color:var(--muted)}
.meta{color:var(--muted)}
</style>
<script>
(function(){
  document.addEventListener('click',function(e){
    var b=e.target.closest('.svc-btn');if(!b||b.disabled)return;
    var card=b.closest('.svc-card'),svc=card.getAttribute('data-svc'),action=b.getAttribute('data-a'),label=card.getAttribute('data-label'),warn=card.getAttribute('data-warn')||'';
    if(!confirm(action.toUpperCase()+' '+label+'?\n\n'+warn+'\n\nRuns the real control command and is logged. Continue?'))return;
    card.querySelectorAll('.svc-btn').forEach(function(x){x.disabled=true;});b.textContent='…';
    var fd=new URLSearchParams();fd.set('svc_action',action);fd.set('svc',svc);fd.set('smpro_csrf',SVC_CSRF);
    fetch('index.cgi?page=cpanel-services',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'})
      .then(function(r){return r.json();}).then(function(j){
        if(j&&j.state_label){var s=card.querySelector('[data-state]');s.textContent=j.state_label;s.className='svc-state '+(j.cls||'');card.className='svc-card '+(j.cls||'');}
        card.querySelectorAll('.svc-btn').forEach(function(x){x.disabled=false;x.textContent=x.getAttribute('data-a').replace(/^./,function(m){return m.toUpperCase();});});
        alert((j&&j.ok)?(label+': '+action+' OK.'):((action+' did not confirm. '+((j&&j.msg)||'')).trim()));
      }).catch(function(){card.querySelectorAll('.svc-btn').forEach(function(x){x.disabled=false;});alert('Failed (network/permission). If you restarted cpsrvd, just reload.');});
  });
})();
</script>
<?php
smpro_layout_footer();
