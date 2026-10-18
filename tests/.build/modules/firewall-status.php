<?php
/**
 * modules/firewall-status.php — Firewall intelligence (read-only views +
 * controlled CSF deny management). CSF/LFD/firewalld/nftables state, layers,
 * decision & maintenance plan, recommendations, counters, important config,
 * listening ports, and a managed view of blocked IPs (with Unblock).
 * Read-only by default; Unblock is POST+CSRF+root, applied via csf -dr (no restart).
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

function smpro_fw_run($cmd, $t = null) { return (string)@shell_exec('timeout ' . ($t ?: SMPRO_TIMEOUT_QUICK) . ' ' . $cmd . ' 2>/dev/null'); }
function smpro_fw_active($svc) { $s = trim(smpro_fw_run('systemctl is-active ' . escapeshellarg($svc))); return $s === '' ? 'unknown' : $s; }
function smpro_fw_enabled($svc) { $s = trim(smpro_fw_run('systemctl is-enabled ' . escapeshellarg($svc))); return $s === '' ? 'unknown' : $s; }
function smpro_fw_csf_bin() { foreach (['/usr/sbin/csf', '/usr/local/csf/bin/csf'] as $b) if (is_executable($b)) return $b; return ''; }

/** Parse csf.deny → [ ['ip'=>, 'comment'=>], ... ] (skip comment lines). */
function smpro_fw_deny_list() {
    $rows = [];
    if (!is_readable('/etc/csf/csf.deny')) return $rows;
    foreach (file('/etc/csf/csf.deny', FILE_IGNORE_NEW_LINES) ?: [] as $l) {
        $l = trim($l);
        if ($l === '' || $l[0] === '#') continue;
        if (preg_match('/^([0-9a-fA-F:.\/]+)\s*(?:#\s*(.*))?$/', $l, $m)) $rows[] = ['ip' => $m[1], 'comment' => trim($m[2] ?? '')];
    }
    return $rows;
}

/* ---------- controlled action: unblock (csf -dr), POST+CSRF+root ---------- */
$reqMethod = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));
if ($reqMethod === 'POST' && ($_POST['fw_action'] ?? '') === 'unblock') {
    smpro_require_valid_csrf('fw_csf');
    smpro_require_root();
    $csf = smpro_fw_csf_bin();
    $ips = array_unique(array_filter(array_map('trim', explode(',', (string)($_POST['ips'] ?? '')))));
    $results = [];
    foreach ($ips as $ip) {
        $bare = explode('/', $ip)[0];
        if (!filter_var($bare, FILTER_VALIDATE_IP)) { $results[] = ['ip' => $ip, 'ok' => false, 'msg' => 'invalid IP']; continue; }
        $out = $csf === '' ? 'csf not found' : smpro_fw_run(escapeshellarg($csf) . ' -dr ' . escapeshellarg($ip), 25);
        $ok = $csf !== '' && stripos($out, 'error') === false;
        smpro_audit('firewall_unblock', ['ip' => $ip, 'ok' => $ok, 'actor' => smpro_current_actor()]);
        $results[] = ['ip' => $ip, 'ok' => $ok, 'msg' => trim(mb_substr($out, 0, 160))];
    }
    echo json_encode(['ok' => true, 'results' => $results], JSON_UNESCAPED_SLASHES);
    exit;
}

/* ---------- controlled action: service start/stop/enable/disable (POST+CSRF+root) ---------- */
if ($reqMethod === 'POST' && ($_POST['fw_action'] ?? '') === 'service') {
    smpro_require_valid_csrf('fw_csf'); smpro_require_root();
    header('Content-Type: application/json');
    $svc = preg_replace('/[^a-z0-9_-]/', '', strtolower((string)($_POST['svc'] ?? '')));
    $op  = (string)($_POST['op'] ?? '');
    if (!in_array($svc, ['lfd', 'firewalld', 'nftables'], true)) { echo json_encode(['ok'=>false,'msg'=>'Service not allowed.']); exit; }
    if (!in_array($op, ['start', 'stop', 'restart', 'enable', 'disable'], true)) { echo json_encode(['ok'=>false,'msg'=>'Operation not allowed.']); exit; }
    // LFD is managed by CSF — prefer csf --lfd for start/stop/restart when csf is present.
    $out = '';
    $csf = smpro_fw_csf_bin();
    if ($svc === 'lfd' && $csf !== '' && in_array($op, ['start','stop','restart'], true)) {
        $out = smpro_fw_run(escapeshellarg($csf) . ' --lfd ' . escapeshellarg($op), 30);
    }
    if (trim($out) === '') {
        $sysop = $op === 'start' ? 'restart' : $op;   // start→restart is idempotent & recovers a failed unit
        $out = smpro_fw_run('systemctl ' . escapeshellarg($sysop) . ' ' . escapeshellarg($svc), 30);
    }
    // verify
    $now = smpro_fw_active($svc); $nowEn = smpro_fw_enabled($svc);
    $ok = in_array($op, ['start','restart'], true) ? ($now === 'active')
        : (in_array($op, ['stop','disable'], true) ? ($now !== 'active' || $op === 'disable')
        : ($op === 'enable' ? ($nowEn === 'enabled') : true));
    smpro_audit('firewall_service', ['svc'=>$svc, 'op'=>$op, 'active'=>$now, 'enabled'=>$nowEn, 'actor'=>smpro_current_actor()]);
    echo json_encode(['ok'=>$ok, 'active'=>$now, 'enabled'=>$nowEn, 'msg'=>($ok?ucfirst($svc).' '.$op.' → active='.$now:('Could not '.$op.' '.$svc.' (active='.$now.'). '.trim(mb_substr($out,0,140))))], JSON_UNESCAPED_SLASHES); exit;
}

/* ---------- controlled action: CSF control (production / enable / disable / restart) ---------- */
if ($reqMethod === 'POST' && ($_POST['fw_action'] ?? '') === 'csf_ctl') {
    smpro_require_valid_csrf('fw_csf'); smpro_require_root();
    header('Content-Type: application/json');
    $csf = smpro_fw_csf_bin();
    if ($csf === '') { echo json_encode(['ok'=>false,'msg'=>'CSF not installed.']); exit; }
    $op = (string)($_POST['op'] ?? '');
    if ($op === 'production') {
        $conf = '/etc/csf/csf.conf';
        if (!is_writable($conf)) { echo json_encode(['ok'=>false,'msg'=>'csf.conf not writable.']); exit; }
        $c = (string)@file_get_contents($conf);
        $c2 = preg_replace('/^(\s*TESTING\s*=\s*)"?\d+"?/m', '$1"0"', $c, 1);
        if ($c2 === null || $c2 === $c) { /* still write to be safe */ $c2 = $c; }
        @copy($conf, $conf . '.smpro.bak');
        @file_put_contents($conf, $c2, LOCK_EX);
        $out = smpro_fw_run(escapeshellarg($csf) . ' -r', 45);
        $ok = stripos($out, 'error') === false;
        smpro_audit('firewall_csf_production', ['ok'=>$ok, 'actor'=>smpro_current_actor()]);
        echo json_encode(['ok'=>$ok, 'msg'=>$ok ? 'CSF switched to production (TESTING=0) and reloaded. Backup: csf.conf.smpro.bak' : 'csf reload reported an error.'], JSON_UNESCAPED_SLASHES); exit;
    }
    if (in_array($op, ['enable', 'disable', 'restart'], true)) {
        $flag = $op === 'enable' ? '-e' : ($op === 'disable' ? '-x' : '-r');
        $out = smpro_fw_run(escapeshellarg($csf) . ' ' . $flag, 45);
        $ok = stripos($out, 'error') === false && trim($out) !== '';
        smpro_audit('firewall_csf_' . $op, ['ok'=>$ok, 'actor'=>smpro_current_actor()]);
        $msg = $op === 'disable' ? 'CSF DISABLED (firewall is now OFF — re-enable to restore protection).' : ($op === 'enable' ? 'CSF enabled.' : 'CSF reloaded.');
        echo json_encode(['ok'=>$ok, 'msg'=>$ok ? $msg : ('csf ' . $flag . ' failed: ' . trim(mb_substr($out,0,140)))], JSON_UNESCAPED_SLASHES); exit;
    }
    echo json_encode(['ok'=>false,'msg'=>'Unknown CSF operation.']); exit;
}

/* ---------- gather ---------- */
/* ---------- controlled action: country never-block (CC_ALLOW), POST+CSRF+root ---------- */
function smpro_fw_csf_set(&$content, $key, $value) {
    $line = $key . ' = "' . $value . '"';
    if (preg_match('/^[ \t]*' . preg_quote($key, '/') . '[ \t]*=.*$/m', $content))
        $content = preg_replace('/^[ \t]*' . preg_quote($key, '/') . '[ \t]*=.*$/m', $line, $content, 1);
    else
        $content .= "\n" . $line . "\n";
}
if ($reqMethod === 'POST' && ($_POST['fw_action'] ?? '') === 'cc_allow') {
    smpro_require_valid_csrf('fw_csf'); smpro_require_root();
    header('Content-Type: application/json');
    $csf = smpro_fw_csf_bin();
    if ($csf === '') { echo json_encode(['ok'=>false,'msg'=>'CSF not installed.']); exit; }
    $conf = '/etc/csf/csf.conf';
    if (!is_writable($conf)) { echo json_encode(['ok'=>false,'msg'=>'csf.conf is not writable.']); exit; }
    $mode = (($_POST['mode'] ?? 'allow') === 'filter') ? 'filter' : 'allow';
    $codes = [];
    foreach (explode(',', (string)($_POST['countries'] ?? '')) as $c) {
        $c = strtoupper(preg_replace('/[^A-Za-z]/', '', $c));
        if (strlen($c) === 2) $codes[$c] = 1;
    }
    $codes = array_keys($codes); sort($codes);
    if (count($codes) > 60) { echo json_encode(['ok'=>false,'msg'=>'Too many countries selected.']); exit; }
    $val = implode(',', $codes);
    $content = (string)file_get_contents($conf);
    @copy($conf, $conf . '.smpro.ccbak');
    // GeoIP needs a clean MM_LICENSE_KEY — strip stray spaces so CC_* features actually work
    if (preg_match('/^[ \t]*MM_LICENSE_KEY[ \t]*=[ \t]*"([^"]*)"/m', $content, $mm))
        smpro_fw_csf_set($content, 'MM_LICENSE_KEY', trim($mm[1]));
    if ($mode === 'filter') { smpro_fw_csf_set($content, 'CC_ALLOW_FILTER', $val); smpro_fw_csf_set($content, 'CC_ALLOW', ''); }
    else                    { smpro_fw_csf_set($content, 'CC_ALLOW', $val);        smpro_fw_csf_set($content, 'CC_ALLOW_FILTER', ''); }
    if (file_put_contents($conf, $content) === false) { echo json_encode(['ok'=>false,'msg'=>'Failed to write csf.conf.']); exit; }
    $out = smpro_fw_run(escapeshellarg($csf) . ' -r', 60);
    $ok = stripos($out, 'error') === false;
    smpro_audit('firewall_cc_allow', ['mode'=>$mode, 'countries'=>$val, 'ok'=>$ok, 'actor'=>smpro_current_actor()]);
    echo json_encode(['ok'=>$ok, 'msg'=>$ok ? ('Never-block applied (' . $mode . ') for: ' . ($val ?: '(none)') . '. CSF reloaded. Backup: csf.conf.smpro.ccbak') : ('csf -r reported an error: ' . trim(mb_substr($out, 0, 140)))], JSON_UNESCAPED_SLASHES);
    exit;
}

/* ---------- controlled action: add an IP to allow (whitelist) or deny (block), POST+CSRF+root ---------- */
if ($reqMethod === 'POST' && ($_POST['fw_action'] ?? '') === 'ipadd') {
    smpro_require_valid_csrf('fw_csf'); smpro_require_root();
    header('Content-Type: application/json');
    $csf = smpro_fw_csf_bin();
    if ($csf === '') { echo json_encode(['ok'=>false,'msg'=>'CSF not installed.']); exit; }
    $ip = trim((string)($_POST['ip'] ?? ''));
    if (!filter_var($ip, FILTER_VALIDATE_IP)) { echo json_encode(['ok'=>false,'msg'=>'Enter a valid IP address.']); exit; }
    $op = (($_POST['op'] ?? '') === 'block') ? 'block' : 'allow';
    $reason = preg_replace('/[^A-Za-z0-9 ._\-\/:]/', '', mb_substr(trim((string)($_POST['reason'] ?? '')), 0, 80));
    if ($op === 'allow' && function_exists('smpro_csf_allow_add')) {
        // robust allow: verifies against csf.allow + falls back to a direct file write when CSF is disabled
        $r = smpro_csf_allow_add($ip, $reason ?: 'manual allow');
        smpro_audit('firewall_ip_allow', ['ip'=>$ip, 'reason'=>$reason, 'ok'=>!empty($r['ok']), 'actor'=>smpro_current_actor()]);
        echo json_encode(['ok'=>!empty($r['ok']), 'msg'=>(string)$r['msg']], JSON_UNESCAPED_SLASHES); exit;
    }
    $out = smpro_fw_run(escapeshellarg($csf) . ' -d ' . escapeshellarg($ip) . ($reason !== '' ? ' ' . escapeshellarg($reason) : ''), 25);
    $low = strtolower($out);
    $ok = strpos($low, 'error') === false;
    $already = strpos($low, 'already') !== false;
    smpro_audit('firewall_ip_block', ['ip'=>$ip, 'reason'=>$reason, 'ok'=>$ok, 'actor'=>smpro_current_actor()]);
    echo json_encode(['ok'=>$ok, 'msg'=>$ok ? ($already ? ($ip . ' is already blocked (csf.deny).') : ($ip . ' blocked (csf.deny).')) : ('csf -d failed: ' . trim(mb_substr($out, 0, 140)))], JSON_UNESCAPED_SLASHES);
    exit;
}

$csfBin = smpro_fw_csf_bin();
$csfInstalled = $csfBin !== '';
$csfVer = $csfInstalled ? trim(smpro_fw_run(escapeshellarg($csfBin) . ' -v')) : '';
if (preg_match('/v?[\d.]+/', $csfVer, $vm)) $csfVer = $vm[0];

$lfd = smpro_fw_active('lfd'); $lfdEn = smpro_fw_enabled('lfd');
$firewalld = smpro_fw_active('firewalld'); $firewalldEn = smpro_fw_enabled('firewalld');
$nftables = smpro_fw_active('nftables'); $nftablesEn = smpro_fw_enabled('nftables');

$deny = smpro_fw_deny_list();
$denyCount = count($deny);
$allowCount = 0;
if (is_readable('/etc/csf/csf.allow')) foreach (file('/etc/csf/csf.allow', FILE_IGNORE_NEW_LINES) ?: [] as $l) { $l = trim($l); if ($l !== '' && $l[0] !== '#') $allowCount++; }
$tempRaw = $csfInstalled ? smpro_fw_run(escapeshellarg($csfBin) . ' -t') : '';
$tempDeny = 0; foreach (explode("\n", $tempRaw) as $l) if (stripos($l, 'DENY') !== false) $tempDeny++;
$iptRules = (int)trim(smpro_fw_run('iptables -S | wc -l'));
$nftLines = (int)trim(smpro_fw_run('nft list ruleset | wc -l'));

$cfg = [];
if (is_readable('/etc/csf/csf.conf')) foreach (file('/etc/csf/csf.conf', FILE_IGNORE_NEW_LINES) ?: [] as $l)
    if (preg_match('/^\s*([A-Z0-9_]+)\s*=\s*"?([^"#]*)"?/', $l, $m)) $cfg[$m[1]] = trim($m[2]);
$testing = ($cfg['TESTING'] ?? '') === '1';

// listening ports
$ports = []; $seen = [];
foreach (explode("\n", smpro_fw_run('ss -tulnHp', SMPRO_TIMEOUT_NORMAL)) as $l) {
    $l = trim($l); if ($l === '') continue;
    $p = preg_split('/\s+/', $l); if (count($p) < 5) continue;
    $proc = preg_match('/users:\(\("([^"]+)",pid=(\d+)/', $l, $pm) ? $pm[1] . ' (pid ' . $pm[2] . ')' : '';
    $k = $p[0] . $p[4]; if (isset($seen[$k])) continue; $seen[$k] = 1;
    $ports[] = ['proto' => $p[0], 'state' => $p[1], 'local' => $p[4], 'proc' => $proc];
}

// resolve country/bot for blocked IPs
smpro_ip_intel_bulk(array_map(fn($r) => explode('/', $r['ip'])[0], array_slice($deny, 0, 120)));

// overall status
$status = 'good'; $statusLabel = 'GOOD';
if (!$csfInstalled) { $status = 'danger'; $statusLabel = 'NO FIREWALL'; }
elseif ($lfd !== 'active') { $status = 'warn'; $statusLabel = 'REVIEW'; }
elseif ($testing) { $status = 'warn'; $statusLabel = 'TESTING MODE'; }

// layers (req = required for protection?)
$layers = [
    ['name' => 'CSF', 'req' => true, 'status' => $csfInstalled ? 'installed' : 'missing', 'enabled' => $csfInstalled ? 'yes' : 'no', 'note' => 'ConfigServer Security &amp; Firewall — primary cPanel firewall manager', 'ok' => $csfInstalled],
    ['name' => 'LFD', 'req' => true, 'status' => $lfd, 'enabled' => $lfdEn, 'note' => 'Login Failure Daemon — brute-force / login monitoring', 'ok' => $lfd === 'active'],
    ['name' => 'firewalld', 'req' => false, 'status' => $firewalld, 'enabled' => $firewalldEn, 'note' => 'Alternative firewall — normally inactive when CSF manages iptables', 'ok' => $firewalld !== 'failed'],
    ['name' => 'nftables', 'req' => false, 'status' => $nftables, 'enabled' => $nftablesEn, 'note' => 'Modern packet filter — usually idle under CSF/iptables', 'ok' => $nftables !== 'failed'],
];
/** Build Fix / Enable / Disable buttons for a firewall component per the action rule. */
function smpro_fw_actions($name, $status, $required, $testing) {
    $comp = strtolower($name); $st = strtolower((string)$status); $b = [];
    if ($comp === 'csf') {
        if ($st === 'missing') { $b[] = '<button class="fw-act fix" type="button" data-fwop="csf:enable">&#9889; Enable CSF</button>'; return implode(' ', $b); }
        if ($testing) $b[] = '<button class="fw-act fix" type="button" data-fwop="csf:production" data-confirm="Switch CSF to PRODUCTION (TESTING=0) and reload? Make sure your IP is allowed so you are not locked out.">&#9889; Switch to production</button>';
        $b[] = '<button class="fw-act danger" type="button" data-fwop="csf:disable" data-confirm="DISABLE CSF? This turns the firewall OFF — your server loses CSF protection until re-enabled.">&#9940; Disable CSF</button>';
        return implode(' ', $b);
    }
    $active = ($st === 'active');
    if (!$active) {
        if ($required) $b[] = '<button class="fw-act fix" type="button" data-fwop="svc:start" data-fwsvc="' . $comp . '" data-confirm="Start ' . strtoupper($comp) . ' now to restore protection?">&#9889; Start (Fix)</button>';
        else           $b[] = '<button class="fw-act ghost" type="button" data-fwop="svc:start" data-fwsvc="' . $comp . '" data-confirm="Enable ' . strtoupper($comp) . '? Running two firewall managers can conflict with CSF.">&#9658; Enable</button>';
    } else {
        if ($required) $b[] = '<button class="fw-act danger" type="button" data-fwop="svc:stop" data-fwsvc="' . $comp . '" data-confirm="STOP ' . strtoupper($comp) . '? It is REQUIRED — stopping it reduces protection.">&#9940; Stop</button>';
        else           $b[] = '<button class="fw-act warn" type="button" data-fwop="svc:stop" data-fwsvc="' . $comp . '" data-confirm="Disable ' . strtoupper($comp) . '? It is active alongside CSF which can conflict.">&#9209; Disable</button>';
    }
    return implode(' ', $b);
}
$fwCsrf = smpro_csrf_generate('fw_csf');

// decision & maintenance plan (informational; maintenance stays manual / no restarts)
$plan = [
    ['comp' => 'CSF', 'cur' => $csfInstalled ? 'installed' : 'missing', 'req' => 'Yes', 'alt' => 'No',
     'decision' => $csfInstalled ? 'Primary firewall layer. Keep installed and active.' : 'Install CSF — no active firewall manager detected.'],
    ['comp' => 'LFD', 'cur' => $lfd, 'req' => 'Yes', 'alt' => 'No',
     'decision' => $lfd === 'active' ? 'Required and working. Keep running.' : 'LFD not active — start it manually to restore login-failure protection.'],
    ['comp' => 'firewalld', 'cur' => $firewalld, 'req' => 'No', 'alt' => 'Yes (covered by CSF/iptables)',
     'decision' => $firewalld === 'active' ? 'Active alongside CSF — review for rule precedence.' : 'Inactive is acceptable when CSF is active. No action needed.'],
    ['comp' => 'nftables', 'cur' => $nftables, 'req' => 'No', 'alt' => 'Yes',
     'decision' => $nftables === 'failed' ? 'Failed but typically harmless under CSF. Repair only if you intend to use it.' : 'Idle under CSF. No action needed.'],
];

// recommendations
$rec = [];
if (!$csfInstalled) $rec[] = 'No active firewall manager detected — install and enable CSF.';
if ($lfd !== 'active') $rec[] = 'LFD is not active — start it to restore brute-force protection.';
if ($testing) $rec[] = 'CSF is in TESTING mode (TESTING=1) — rules are not enforced. Switch to production after verifying config.';
if ($firewalld === 'active' && $csfInstalled) $rec[] = 'Both firewalld and CSF are active — avoid running two firewall managers unless intentional.';
if (!$rec) $rec[] = 'Firewall coverage looks healthy in this read-only sample.';
$rec[] = 'Use the Blocked IPs table below to review and remove (Unblock) deny entries safely.';

smpro_audit('firewall_status_view', ['csf' => $csfInstalled, 'lfd' => $lfd, 'deny' => $denyCount, 'testing' => $testing]);

smpro_layout_header('Firewall Status');
function smpro_fw_badge($s) {
    $map = ['active'=>'green','installed'=>'green','enabled'=>'green','yes'=>'green','inactive'=>'gray','disabled'=>'gray','no'=>'gray','masked'=>'gray','unknown'=>'gray','failed'=>'red','missing'=>'red'];
    return '<span class="b ' . ($map[strtolower($s)] ?? 'gray') . '">' . smpro_h($s) . '</span>';
}
$showCfg = ['TESTING','RESTRICT_SYSLOG','TCP_IN','TCP_OUT','UDP_IN','UDP_OUT','LF_DAEMON','SYNFLOOD','PORTFLOOD','CONNLIMIT','CT_LIMIT','DENY_IP_LIMIT','DENY_TEMP_IP_LIMIT'];
// current admin connecting IP (so the operator can whitelist it and never get locked out)
$smAdminIp = '';
foreach (['HTTP_X_FORWARDED_FOR','HTTP_X_REAL_IP','REMOTE_ADDR'] as $k) {
    $v = trim((string)($_SERVER[$k] ?? '')); if ($v === '') continue;
    $v = trim(explode(',', $v)[0]);
    if (filter_var($v, FILTER_VALIDATE_IP) && $v !== '127.0.0.1' && $v !== '::1') { $smAdminIp = $v; break; }
}
$smAdminIntel   = ($smAdminIp && function_exists('smpro_ip_intel')) ? smpro_ip_intel($smAdminIp) : [];
$smAdminCC      = strtoupper((string)($smAdminIntel['country'] ?? ''));
$smAdminAllowed = $smAdminIp && ((function_exists('smpro_csf_allowlisted') && smpro_csf_allowlisted($smAdminIp)) || (function_exists('smpro_im_allowlisted') && smpro_im_allowlisted($smAdminIp)));
?>
<h1 class="h">Firewall Status</h1>
<p class="sub">CSF/LFD intelligence, layers, decision plan, recommendations, counters, config &amp; listening ports. Manage blocked IPs safely (Unblock). No service restarts.</p>

<?php if ($smAdminIp): ?>
<div class="card" style="border-left:4px solid var(--brand,#3b5bdb);margin-bottom:14px;display:flex;align-items:center;gap:14px;flex-wrap:wrap">
  <div style="font-size:24px">&#128100;</div>
  <div style="flex:1;min-width:220px">
    <div class="lbl" style="font-size:11px;text-transform:uppercase;letter-spacing:.03em;color:var(--muted)">Your admin IP (this session)</div>
    <div style="font-size:19px;font-weight:800;margin-top:2px">
      <code><?= smpro_h($smAdminIp) ?></code>
      <?php if ($smAdminCC): ?><span class="b" style="margin-left:6px"><?= smpro_h($smAdminCC) ?></span><?php endif; ?>
      <?php if ($smAdminAllowed): ?><span class="b green" style="margin-left:4px">&#10003; allow-listed</span><?php else: ?><span class="b high" style="margin-left:4px">not allow-listed</span><?php endif; ?>
    </div>
    <div class="meta" style="margin-top:2px">Whitelist your own IP so the firewall can never lock you out.</div>
  </div>
  <?php if (!$smAdminAllowed): ?>
    <button class="fw-act fix" type="button" id="fwAllowMine" data-ip="<?= smpro_h($smAdminIp) ?>">&#9989; Allow my IP</button>
  <?php endif; ?>
</div>
<?php endif; ?>

<div class="card" style="border-left:4px solid var(--<?= $status ?>);margin-bottom:14px">
  <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
    <div class="fw-otitle">&#9873; Firewall Overview</div><span class="pill <?= $status ?>"><?= $statusLabel ?></span>
    <span style="flex:1"></span><span class="meta">Primary: CSF + LFD</span>
  </div>
  <div class="fw-cards">
    <div class="fw-sc"><div class="lbl">CSF</div><div class="v"><?= $csfInstalled?'<span class="b green">installed '.smpro_h($csfVer).'</span>':'<span class="b red">missing</span>' ?></div></div>
    <div class="fw-sc"><div class="lbl">LFD</div><div class="v"><?= smpro_fw_badge($lfd) ?></div></div>
    <div class="fw-sc"><div class="lbl">firewalld</div><div class="v"><?= smpro_fw_badge($firewalld) ?></div></div>
    <div class="fw-sc"><div class="lbl">nftables</div><div class="v"><?= smpro_fw_badge($nftables) ?></div></div>
  </div>
</div>

<?php
$ARAB = ['SA'=>'Saudi Arabia','EG'=>'Egypt','AE'=>'UAE','KW'=>'Kuwait','QA'=>'Qatar','BH'=>'Bahrain','OM'=>'Oman','JO'=>'Jordan','LB'=>'Lebanon','IQ'=>'Iraq','SY'=>'Syria','YE'=>'Yemen','PS'=>'Palestine','SD'=>'Sudan','LY'=>'Libya','TN'=>'Tunisia','DZ'=>'Algeria','MA'=>'Morocco','MR'=>'Mauritania','SO'=>'Somalia','DJ'=>'Djibouti','KM'=>'Comoros'];
$FOREIGN = ['US'=>'United States','GB'=>'United Kingdom','DE'=>'Germany','FR'=>'France','NL'=>'Netherlands','CA'=>'Canada','IT'=>'Italy','ES'=>'Spain','SE'=>'Sweden','CH'=>'Switzerland','RU'=>'Russia','CN'=>'China','IN'=>'India','TR'=>'Turkey','BR'=>'Brazil','JP'=>'Japan','AU'=>'Australia','SG'=>'Singapore','UA'=>'Ukraine','PL'=>'Poland','RO'=>'Romania','ID'=>'Indonesia','PK'=>'Pakistan','IR'=>'Iran','NG'=>'Nigeria','ZA'=>'South Africa','MX'=>'Mexico','KR'=>'South Korea','VN'=>'Vietnam','PH'=>'Philippines'];
$ccMode = (trim($cfg['CC_ALLOW_FILTER'] ?? '') !== '') ? 'filter' : 'allow';
$ccCurrentStr = $ccMode === 'filter' ? trim($cfg['CC_ALLOW_FILTER'] ?? '') : trim($cfg['CC_ALLOW'] ?? '');
$ccCurrent = array_values(array_filter(array_map('trim', explode(',', $ccCurrentStr))));
$ccChecked = $ccCurrent ?: array_keys($ARAB);   // default: all Arab countries when nothing is set yet
?>
<div class="card" style="margin-bottom:14px;border-left:4px solid var(--brand)">
  <div class="tp-th"><b>&#127757; Country Block-Prevention</b><span class="meta">Chosen countries are added to CSF allow so the firewall never blocks them</span></div>
  <div style="padding:12px 14px">
    <p class="meta" style="margin:0 0 10px">Pick the countries that must <b>never</b> be blocked by the firewall. Your home region (Arab countries) is preselected. Applying writes the codes to CSF and reloads it — no service restart.</p>

    <div class="cc-dd" id="ccDD">
      <button type="button" class="cc-ddbtn" id="ccDDbtn"><span id="ccDDlabel">Select countries…</span><i class="cc-ddcar">&#9662;</i></button>
      <div class="cc-ddpanel" id="ccDDpanel" hidden>
        <input type="text" id="ccSearch" class="cc-ddsearch" placeholder="&#128269; Search country or code…">
        <div class="cc-ddscroll">
          <div class="cc-ddgrp">
            <div class="cc-ddgh"><b>&#127759; Arab countries</b><span><button type="button" class="cc-mini" data-grp="arab" data-on="1">All</button><button type="button" class="cc-mini" data-grp="arab" data-on="0">Clear</button></span></div>
            <?php foreach ($ARAB as $code => $name): ?>
              <label class="cc-opt" data-grp="arab" data-s="<?= smpro_h(strtolower($name.' '.$code)) ?>"><input type="checkbox" class="cc-cb" value="<?= $code ?>" <?= in_array($code, $ccChecked, true) ? 'checked' : '' ?>><span><?= smpro_h($name) ?> <em>(<?= $code ?>)</em></span></label>
            <?php endforeach; ?>
          </div>
          <div class="cc-ddgrp">
            <div class="cc-ddgh"><b>&#127758; Other / foreign</b><span><button type="button" class="cc-mini" data-grp="foreign" data-on="1">All</button><button type="button" class="cc-mini" data-grp="foreign" data-on="0">Clear</button></span></div>
            <?php foreach ($FOREIGN as $code => $name): ?>
              <label class="cc-opt" data-grp="foreign" data-s="<?= smpro_h(strtolower($name.' '.$code)) ?>"><input type="checkbox" class="cc-cb" value="<?= $code ?>" <?= in_array($code, $ccChecked, true) ? 'checked' : '' ?>><span><?= smpro_h($name) ?> <em>(<?= $code ?>)</em></span></label>
            <?php endforeach; ?>
          </div>
        </div>
      </div>
    </div>

    <div style="margin-top:12px;padding:10px 12px;background:rgba(59,91,219,.06);border:1px solid rgba(59,91,219,.18);border-radius:9px">
      <label style="font-size:13px;display:block;margin-bottom:4px"><input type="radio" name="ccmode" value="allow" <?= $ccMode !== 'filter' ? 'checked' : '' ?>> <b>Full allow</b> (CC_ALLOW) — traffic from these countries is fully trusted and <b>skips ALL firewall blocks</b> (incl. LFD bans). Best for your own region (EG/SA).</label>
      <label style="font-size:13px;display:block"><input type="radio" name="ccmode" value="filter" <?= $ccMode === 'filter' ? 'checked' : '' ?>> <b>Filtered allow</b> (CC_ALLOW_FILTER) — these countries are only exempt from <b>country-level blocking</b>; the normal firewall still applies (port filtering + LFD brute-force bans). Safer for large/foreign lists.</label>
    </div>

    <div style="display:flex;gap:14px;align-items:center;flex-wrap:wrap;margin-top:12px">
      <button class="fw-act fix" id="ccApply" type="button">&#9889; Apply never-block</button>
      <span class="meta"><span id="ccCount">0</span> selected · Current: <code><?= smpro_h($ccCurrentStr ?: '(none set)') ?></code></span>
    </div>
  </div>
</div>

<div class="card" style="margin-bottom:14px">
  <div class="tp-th"><b>&#128272; Add IP &mdash; allow or block</b><span class="meta">Whitelist (csf.allow) or block (csf.deny) a specific IP — applied immediately, no restart</span></div>
  <div style="padding:12px 14px;display:flex;gap:8px;flex-wrap:wrap;align-items:center">
    <input id="ipAddInput" class="tp-in" placeholder="IP address (e.g. 1.2.3.4)" style="min-width:200px">
    <input id="ipAddReason" class="tp-in" placeholder="Reason (optional)" style="min-width:200px">
    <button class="fw-act fix" type="button" id="ipAllowBtn">&#9989; Allow (whitelist)</button>
    <button class="fw-act danger" type="button" id="ipBlockBtn">&#9940; Block</button>
  </div>
</div>

<div class="fw-two">
  <div class="card" style="padding:0;overflow:hidden">
    <div class="tp-th"><b>Firewall Layers</b><span class="meta">Fix / Enable / Disable — actions are guarded &amp; audited</span></div>
    <table class="smpro-table"><thead><tr><th>Layer</th><th>Status</th><th>Enabled</th><th>Notes</th><th>Action</th></tr></thead><tbody>
      <?php foreach ($layers as $L): $acts = smpro_fw_actions($L['name'], $L['status'], !empty($L['req']), $testing); ?>
        <tr><td class="uname"><?= smpro_h($L['name']) ?></td><td><?= smpro_fw_badge($L['status']) ?></td><td><?= smpro_fw_badge($L['enabled']) ?></td><td class="meta"><?= $L['note'] ?></td>
          <td class="fw-actcell"><?= $acts ?: '<span class="meta">—</span>' ?></td></tr>
      <?php endforeach; ?>
    </tbody></table>
  </div>
  <div class="card">
    <div class="lbl" style="margin-bottom:8px">Recommendations</div>
    <ul class="fw-rec"><?php foreach ($rec as $r): ?><li><?= smpro_h($r) ?></li><?php endforeach; ?></ul>
  </div>
</div>

<div class="card" style="padding:0;overflow:hidden;margin-bottom:14px">
  <div class="tp-th"><b>Firewall Decision &amp; Maintenance Plan</b><span class="meta">maintenance is manual — no automatic restarts</span></div>
  <table class="smpro-table"><thead><tr><th>Component</th><th>Current</th><th>Required?</th><th>Covered by alt?</th><th>Decision</th></tr></thead><tbody>
    <?php foreach ($plan as $P): ?>
      <tr><td class="uname"><?= smpro_h($P['comp']) ?></td><td><?= smpro_fw_badge($P['cur']) ?></td><td><?= smpro_h($P['req']) ?></td><td><?= smpro_h($P['alt']) ?></td><td class="meta"><?= smpro_h($P['decision']) ?></td></tr>
    <?php endforeach; ?>
  </tbody></table>
</div>

<div class="card" style="margin-bottom:14px">
  <div class="lbl" style="margin-bottom:10px">CSF Counters</div>
  <div class="fw-counters">
    <div class="fw-ct"><div class="n"><?= (int)$allowCount ?></div><div class="l">csf.allow</div></div>
    <div class="fw-ct"><div class="n"><?= (int)$denyCount ?></div><div class="l">csf.deny</div></div>
    <div class="fw-ct"><div class="n"><?= (int)$tempDeny ?></div><div class="l">temp deny</div></div>
    <div class="fw-ct"><div class="n"><?= (int)$iptRules ?></div><div class="l">iptables rules</div></div>
    <div class="fw-ct"><div class="n"><?= (int)$nftLines ?></div><div class="l">nftables lines</div></div>
  </div>
</div>

<?php
  // Build display rows: skip localhost/private and Cloudflare proxy IPs (rule).
  $denyRows = [];
  foreach ($deny as $d) {
      $bare = explode('/', $d['ip'])[0];
      if (!smpro_ip_is_external($bare)) continue;
      $in = smpro_ip_intel($bare, false);
      if (stripos((string)($in['provider'] ?? ''), 'CLOUDFLARE') !== false) continue;
      $denyRows[] = ['raw' => $d, 'bare' => $bare, 'in' => $in,
          'cc' => strtoupper((string)($in['country'] ?? '')), 'bot' => smpro_ip_is_datacenter($in)];
  }
?>
<div class="card" style="padding:0;overflow:hidden;margin-bottom:14px">
  <div class="tp-th"><b>Blocked IPs (csf.deny)</b><span class="meta"><?= count($denyRows) ?> shown · select to unblock</span>
    <span style="flex:1"></span>
    <select id="fwScope" class="tp-in"><option value="all">All</option><option value="bot">Bots only</option><option value="nonarab">Non-Arab</option><option value="arab">Arab only</option></select>
    <input id="fwSearch" class="tp-in" placeholder="Filter IP / comment / country…" style="max-width:220px">
  </div>
  <?php if ($denyRows): ?>
  <div class="lm-scroll" style="max-height:520px">
    <table class="smpro-table" id="fwDenyTable">
      <thead><tr>
        <th style="width:28px"><input type="checkbox" id="fwChkAll"></th>
        <th data-sort="ip" data-type="s">IP</th><th data-sort="cc" data-type="s">Country / Bot</th>
        <th data-sort="comment" data-type="s">Comment</th><th>Action</th>
      </tr></thead>
      <tbody id="fwDenyBody">
      <?php foreach ($denyRows as $r): $d = $r['raw']; $in = $r['in']; $cc = $r['cc']; $bot = $r['bot']; ?>
        <tr data-fwrow="<?= smpro_h($d['ip']) ?>" data-cc="<?= smpro_h($cc) ?>" data-bot="<?= $bot?1:0 ?>"
            data-ip="<?= smpro_h($d['ip']) ?>" data-comment="<?= smpro_h(strtolower($d['comment'])) ?>"
            data-search="<?= smpro_h(strtolower($d['ip'].' '.$d['comment'].' '.$cc.' '.($in['provider']??''))) ?>">
          <td><input type="checkbox" class="fw-chk" value="<?= smpro_h($d['ip']) ?>"></td>
          <td class="ipmono"><?= smpro_h($d['ip']) ?></td>
          <td class="geo"><?php if ($cc!=='' && $cc!=='N/A'): ?><b><?= smpro_h($cc) ?></b> <span class="geo-prov"><?= smpro_h($in['provider']??'') ?></span><?php endif; ?><?= $bot?' <span class="b red">&#129302; bot</span>':'' ?></td>
          <td class="meta"><?= smpro_h($d['comment']) ?: '—' ?></td>
          <td><button class="fw-act unblock" data-ip="<?= smpro_h($d['ip']) ?>">Unblock</button></td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
  </div>
  <?php else: ?><div class="fw-empty">No blocked IPs to show (Cloudflare/local entries are hidden).</div><?php endif; ?>
</div>

<div class="card" style="padding:0;overflow:hidden;margin-bottom:14px">
  <div class="tp-th"><b>Important CSF Configuration</b></div>
  <table class="smpro-table"><thead><tr><th>Config</th><th>Value</th></tr></thead><tbody>
    <?php foreach ($showCfg as $k): if (!isset($cfg[$k])) continue; $v = $cfg[$k]; $warn = ($k==='TESTING' && $v==='1'); ?>
      <tr><td class="uname"><?= smpro_h($k) ?></td><td<?= $warn?' style="color:var(--warn);font-weight:700"':'' ?>><?= smpro_h($v!==''?$v:'(empty)') ?><?= $warn?' ⚠ testing mode':'' ?></td></tr>
    <?php endforeach; ?>
  </tbody></table>
</div>

<div class="card" style="padding:0;overflow:hidden;margin-bottom:14px">
  <div class="tp-th"><b>Listening Ports</b><span class="meta"><?= count($ports) ?> sockets</span>
    <span style="flex:1"></span><input id="fwPortSearch" class="tp-in" placeholder="Filter port / process…" style="max-width:220px"></div>
  <div class="smpro-tablewrap">
    <table class="smpro-table" id="fwPortTable"><thead><tr><th>Proto</th><th>State</th><th>Local Address</th><th>Process</th></tr></thead><tbody>
      <?php foreach ($ports as $p): ?>
        <tr data-search="<?= smpro_h(strtolower($p['local'].' '.$p['proc'].' '.$p['proto'])) ?>"><td><?= smpro_h($p['proto']) ?></td><td><?= smpro_h($p['state']) ?></td><td class="ipmono"><?= smpro_h($p['local']) ?></td><td><?= $p['proc']!==''?smpro_h($p['proc']):'<span class="meta">—</span>' ?></td></tr>
      <?php endforeach; ?>
    </tbody></table>
  </div>
</div>

<div class="card">
  <div class="lbl" style="margin-bottom:8px">Firewall Program Status Explanation</div>
  <div class="fw-explain">
    <p><b>CSF</b> is the preferred firewall manager on most cPanel/WHM servers. When installed and active it manages iptables/IPSET rules and login protection.</p>
    <p><b>LFD</b> watches login failures and suspicious activity. If CSF is installed but LFD is inactive, brute-force protection is incomplete.</p>
    <p><b>firewalld</b> being inactive is acceptable when CSF is active. If CSF is missing, firewalld can be used as an alternative.</p>
    <p><b>nftables</b> failed is not automatically dangerous when CSF/iptables is the active filter. Repair it only if you intend to use it directly.</p>
  </div>
</div>

<div class="fw-bulkbar" id="fwBulk">
  <span class="meta"><b id="fwBulkN">0</b> selected</span>
  <button class="fw-bbtn" id="fwBulkUnblock">Unblock selected</button>
  <button class="fw-bbtn ghost" id="fwBulkClear">Clear</button>
</div>
<script>var FW_CSRF=<?= json_encode(smpro_csrf_generate('fw_csf')) ?>;</script>
<style>
.fw-otitle{font-size:18px;font-weight:700;color:var(--brand)}
.fw-cards{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-top:12px}
@media(max-width:760px){.fw-cards{grid-template-columns:repeat(2,1fr)}}
.fw-sc{background:#f7f9fc;border:1px solid var(--line);border-radius:14px;padding:14px 16px}
.fw-sc .lbl{font-size:11px;color:var(--muted);text-transform:uppercase;font-weight:700}.fw-sc .v{margin-top:6px}
.fw-two{display:grid;grid-template-columns:1.4fr 1fr;gap:14px;margin-bottom:14px}
@media(max-width:900px){.fw-two{grid-template-columns:1fr}}
.fw-counters{display:grid;grid-template-columns:repeat(5,1fr);gap:12px}
@media(max-width:760px){.fw-counters{grid-template-columns:repeat(2,1fr)}}
.fw-ct{border:1px solid var(--line);border-radius:12px;padding:14px;text-align:center}
.fw-ct .n{font-size:24px;font-weight:700}.fw-ct .l{font-size:11px;color:var(--muted);text-transform:uppercase;margin-top:4px}
.fw-rec{margin:0;padding-left:18px;font-size:13px;line-height:1.9}
.fw-explain p{margin:0 0 8px;font-size:13px;color:#3a4759}.fw-explain b{color:var(--ink)}
.fw-empty{padding:18px;color:var(--muted);text-align:center;font-size:13px}
.tp-th{display:flex;align-items:center;gap:10px;padding:12px 16px;border-bottom:1px solid var(--line);flex-wrap:wrap}
.tp-th .meta{color:var(--muted);font-size:12px}
.smpro-tablewrap{overflow-x:auto}.smpro-table{width:100%;border-collapse:collapse;font-size:13px}
.smpro-table th,.smpro-table td{padding:8px 12px;text-align:left;border-bottom:1px solid var(--line)}
.smpro-table th{font-size:11px;text-transform:uppercase;color:var(--muted)}
.lm-scroll{max-height:520px;overflow:auto}.lm-scroll thead th{position:sticky;top:0;background:#fafbfe;z-index:1;box-shadow:inset 0 -1px 0 var(--line)}
.smpro-table th[data-sort]{cursor:pointer;user-select:none}.smpro-table th[data-sort]:hover{color:var(--brand)}
.smpro-table th.sorted-asc::after{content:" ▲";font-size:9px}.smpro-table th.sorted-desc::after{content:" ▼";font-size:9px}
.uname{font-family:ui-monospace,Consolas,monospace;font-weight:600}.ipmono{font-family:ui-monospace,Consolas,monospace}
.geo-prov{color:var(--muted);font-size:12px}
.tp-in{border:1px solid var(--line);border-radius:9px;padding:7px 11px;font-size:13px}
.fw-act{font-size:11px;font-weight:600;border:1px solid #c9d4ff;color:var(--brand);background:#fff;border-radius:7px;padding:3px 10px;cursor:pointer}.fw-act:hover{background:var(--brand);color:#fff}
.fw-bulkbar{display:none;position:fixed;left:50%;transform:translateX(-50%);bottom:18px;z-index:40;background:#10182b;color:#fff;border-radius:14px;padding:10px 16px;align-items:center;gap:12px;box-shadow:0 18px 40px rgba(0,0,0,.35)}
.fw-bulkbar.show{display:flex}.fw-bulkbar .meta{color:#cfd8ef}.fw-bulkbar b{color:#fff}
.fw-bbtn{font-size:13px;font-weight:600;border:0;border-radius:9px;padding:8px 14px;cursor:pointer;background:var(--brand);color:#fff}.fw-bbtn.ghost{background:#23304d;color:#cfd8ef}
.pill{display:inline-block;font-size:11px;font-weight:700;padding:3px 10px;border-radius:20px}
.pill.good{background:var(--good-bg);color:var(--good)}.pill.warn{background:var(--warn-bg);color:var(--warn)}.pill.danger{background:var(--dang-bg);color:var(--dang)}
.b{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:20px}
.b.green{background:var(--good-bg);color:var(--good)}.b.red{background:var(--dang-bg);color:var(--dang)}.b.gray{background:#f1f5f9;color:#475569}
.meta{color:var(--muted)}
/* country block-prevention — dropdown multi-select */
.cc-dd{position:relative;max-width:420px}
.cc-ddbtn{width:100%;display:flex;align-items:center;justify-content:space-between;gap:8px;border:1px solid var(--line);border-radius:9px;padding:9px 12px;background:var(--card,#fff);color:var(--ink);font-size:13.5px;cursor:pointer}
.cc-dd.open .cc-ddbtn{border-color:var(--brand);box-shadow:0 0 0 3px var(--brand-bg)}
.cc-ddcar{font-size:11px;color:var(--muted);transition:transform .15s}.cc-dd.open .cc-ddcar{transform:rotate(180deg)}
.cc-ddpanel{position:absolute;z-index:40;top:calc(100% + 4px);left:0;right:0;background:var(--card,#fff);border:1px solid var(--line);border-radius:11px;box-shadow:0 12px 30px rgba(2,8,23,.18);padding:8px}
.cc-ddsearch{width:100%;border:1px solid var(--line);border-radius:8px;padding:8px 10px;font-size:13px;margin-bottom:6px;background:var(--bg);color:var(--ink)}
.cc-ddscroll{max-height:280px;overflow:auto}
.cc-ddgh{display:flex;align-items:center;gap:8px;font-size:12.5px;padding:6px 4px;position:sticky;top:0;background:var(--card,#fff)}
.cc-ddgh span{margin-left:auto;display:flex;gap:5px}
.cc-mini{font-size:11px;border:1px solid var(--line);background:var(--bg);border-radius:6px;padding:2px 9px;cursor:pointer;color:var(--brand)}
.cc-mini:hover{background:var(--brand);color:#fff;border-color:var(--brand)}
.cc-opt{display:flex;align-items:center;gap:9px;padding:6px 8px;border-radius:7px;font-size:13px;cursor:pointer;color:var(--ink)}
.cc-opt:hover{background:var(--brand-bg)}
.cc-opt input{width:auto;margin:0}
.cc-opt em{color:var(--muted);font-style:normal;font-size:11.5px}
</style>
<script>
// Blocked IPs: search + scope filter + column sorting
(function(){
  var ARABok=function(cc){return ['SA','EG','AE','KW','QA','BH','OM','JO','LB','IQ','SY','YE','PS','SD','LY','TN','DZ','MA','MR','SO','DJ','KM'].indexOf(cc)>=0;};
  var body=document.getElementById('fwDenyBody');if(!body)return;
  function applyFilter(){var q=(document.getElementById('fwSearch').value||'').toLowerCase(),scope=document.getElementById('fwScope').value;
    body.querySelectorAll('tr').forEach(function(tr){var cc=tr.getAttribute('data-cc')||'',bot=tr.getAttribute('data-bot')==='1',ok=true;
      if(scope==='bot'&&!bot)ok=false;if(scope==='arab'&&!ARABok(cc))ok=false;if(scope==='nonarab'&&ARABok(cc))ok=false;
      if(q){var s=tr.getAttribute('data-search')||'';if(s.indexOf(q)<0)ok=false;}
      tr.style.display=ok?'':'none';if(!ok){var ck=tr.querySelector('.fw-chk');if(ck)ck.checked=false;}});}
  ['fwSearch','fwScope'].forEach(function(id){var e=document.getElementById(id);if(e){e.addEventListener('input',applyFilter);e.addEventListener('change',applyFilter);}});
  var sk='ip',sd='asc';
  function sort(){var rows=Array.prototype.slice.call(body.querySelectorAll('tr'));var th=document.querySelector('#fwDenyTable th[data-sort="'+sk+'"]');var t=th?th.getAttribute('data-type'):'s';
    rows.sort(function(a,b){var x=a.getAttribute('data-'+sk)||'',y=b.getAttribute('data-'+sk)||'';if(t==='n'){x=parseFloat(x)||0;y=parseFloat(y)||0;return sd==='asc'?x-y:y-x;}return sd==='asc'?String(x).localeCompare(y):String(y).localeCompare(x);});
    rows.forEach(function(r){body.appendChild(r);});}
  document.querySelectorAll('#fwDenyTable th[data-sort]').forEach(function(th){th.addEventListener('click',function(){var k=th.getAttribute('data-sort');if(sk===k)sd=sd==='asc'?'desc':'asc';else{sk=k;sd='asc';}
    document.querySelectorAll('#fwDenyTable th').forEach(function(h){h.classList.remove('sorted-asc','sorted-desc');});th.classList.add(sd==='asc'?'sorted-asc':'sorted-desc');sort();});});
})();
(function(){var i=document.getElementById('fwPortSearch');if(!i)return;i.addEventListener('input',function(){var q=this.value.toLowerCase();
  document.querySelectorAll('#fwPortTable tbody tr').forEach(function(tr){var s=tr.getAttribute('data-search')||'';tr.style.display=s.indexOf(q)>=0?'':'none';});});})();
// unblock (AJAX, POST+CSRF)
(function(){
  var body=document.getElementById('fwDenyBody');if(!body)return;
  var bar=document.getElementById('fwBulk'),barN=document.getElementById('fwBulkN'),chkAll=document.getElementById('fwChkAll');
  // SAFETY: only ever act on rows that are currently VISIBLE (not filtered out).
  function vis(c){return c.closest('tr').style.display!=='none';}
  function checked(){return Array.prototype.slice.call(body.querySelectorAll('.fw-chk:checked')).filter(vis);}
  function upd(){var n=checked().length;barN.textContent=n;bar.classList.toggle('show',n>0);
    var visAll=Array.prototype.slice.call(body.querySelectorAll('.fw-chk')).filter(vis);
    if(chkAll){chkAll.checked=visAll.length>0&&n===visAll.length;chkAll.indeterminate=n>0&&n<visAll.length;}}
  function unblock(ips){if(!ips.length)return;if(!confirm('Unblock (remove from CSF deny) '+ips.length+' IP(s)?\n\n'+ips.join('\n')))return;
    var fd=new URLSearchParams();fd.set('fw_action','unblock');fd.set('ips',ips.join(','));fd.set('smpro_csrf',FW_CSRF);
    fetch('index.cgi?page=firewall-status',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'})
      .then(function(r){return r.json();}).then(function(j){if(!j||!j.ok){alert('Failed (token may have expired — reload).');return;}
        var fail=[];(j.results||[]).forEach(function(r){if(r.ok){var tr=body.querySelector('tr[data-fwrow="'+CSS.escape(r.ip)+'"]');if(tr)tr.remove();}else fail.push(r.ip+': '+r.msg);});
        if(fail.length)alert('Not removed:\n'+fail.join('\n'));upd();})
      .catch(function(){alert('Failed (network/permission).');});}
  body.addEventListener('change',function(e){if(e.target.classList.contains('fw-chk'))upd();});
  body.addEventListener('click',function(e){var b=e.target.closest('.fw-act');if(b)unblock([b.getAttribute('data-ip')]);});
  if(chkAll)chkAll.addEventListener('change',function(){body.querySelectorAll('.fw-chk').forEach(function(c){if(vis(c))c.checked=chkAll.checked;});upd();});
  document.getElementById('fwBulkUnblock').addEventListener('click',function(){unblock(checked().map(function(c){return c.value;}));});
  document.getElementById('fwBulkClear').addEventListener('click',function(){body.querySelectorAll('.fw-chk').forEach(function(c){c.checked=false;});upd();});
})();
</script>
<style>
.fw-toggle{cursor:pointer;user-select:none}
.fw-chev{display:inline-block;transition:transform .15s;color:var(--brand);font-weight:800;margin-right:2px}
.card.fw-open>.fw-toggle .fw-chev{transform:rotate(90deg)}
.fw-collapse{display:none}.card.fw-open>.fw-collapse{display:block}
.fw-toggle:hover{background:#fafbff}
</style>
<style>
.fw-actcell{white-space:nowrap}
.fw-act{font-size:11px;font-weight:700;border:1px solid var(--line);border-radius:7px;padding:4px 10px;cursor:pointer;margin:1px;background:#fff}
.fw-act.fix{border-color:#bfe6cd;color:var(--good)}.fw-act.fix:hover{background:var(--good);color:#fff}
.fw-act.danger{border-color:#f3c4c4;color:var(--dang)}.fw-act.danger:hover{background:var(--dang);color:#fff}
.fw-act.warn{border-color:#f0d9a7;color:#a16207}.fw-act.warn:hover{background:var(--warn);color:#fff}
.fw-act.ghost{border-color:#c9d4ff;color:var(--brand)}.fw-act.ghost:hover{background:var(--brand);color:#fff}
.fw-act:disabled{opacity:.6;cursor:default}
</style>
<script>var FW_CSRF=<?= json_encode($fwCsrf) ?>;</script>
<script>
(function(){
  // Fix / Enable / Disable actions on firewall components (svc:* and csf:*)
  document.addEventListener('click',function(e){
    var b=e.target.closest('.fw-act');if(!b)return;
    var op=b.getAttribute('data-fwop'),svc=b.getAttribute('data-fwsvc')||'',conf=b.getAttribute('data-confirm');
    if(conf&&!confirm(conf))return;
    var old=b.innerHTML;b.disabled=true;b.innerHTML='⏳ Working…';
    var fd=new URLSearchParams();fd.set('smpro_csrf',FW_CSRF);
    if(op.indexOf('csf:')===0){fd.set('fw_action','csf_ctl');fd.set('op',op.slice(4));}
    else if(op.indexOf('svc:')===0){fd.set('fw_action','service');fd.set('svc',svc);fd.set('op',op.slice(4));}
    else{b.disabled=false;b.innerHTML=old;return;}
    fetch('index.cgi?page=firewall-status',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'})
      .then(function(r){return r.json();}).then(function(j){
        alert((j&&j.ok?'✅ ':'⚠ ')+((j&&j.msg)||'Done'));
        if(j&&j.ok){setTimeout(function(){location.reload();},800);}else{b.disabled=false;b.innerHTML=old;}
      }).catch(function(){b.disabled=false;b.innerHTML=old;alert('Request failed.');});
  });
})();
</script>
<script>
(function(){
  var btn=document.getElementById('ccApply'); if(!btn) return;
  var cbs=function(){return [].slice.call(document.querySelectorAll('.cc-cb'));};
  function selected(){return cbs().filter(function(c){return c.checked;}).map(function(c){return c.value;});}
  function ccCount(){var n=selected().length; var el=document.getElementById('ccCount'); if(el)el.textContent=n;
    var lbl=document.getElementById('ccDDlabel'); if(lbl)lbl.textContent=n?(n+' countr'+(n>1?'ies':'y')+' selected'):'Select countries…';}
  // open/close dropdown
  var dd=document.getElementById('ccDD'),ddb=document.getElementById('ccDDbtn'),ddp=document.getElementById('ccDDpanel');
  ddb.addEventListener('click',function(e){e.stopPropagation();ddp.hidden=!ddp.hidden;dd.classList.toggle('open',!ddp.hidden);});
  document.addEventListener('click',function(e){if(dd&&!dd.contains(e.target)){ddp.hidden=true;dd.classList.remove('open');}});
  // search filter
  var srch=document.getElementById('ccSearch');
  if(srch)srch.addEventListener('input',function(){var q=this.value.toLowerCase();document.querySelectorAll('.cc-opt').forEach(function(o){o.style.display=(o.getAttribute('data-s').indexOf(q)>=0)?'':'none';});});
  // All / Clear per group
  document.querySelectorAll('.cc-mini').forEach(function(m){m.addEventListener('click',function(e){e.stopPropagation();
    var g=m.getAttribute('data-grp'),on=m.getAttribute('data-on')==='1';
    document.querySelectorAll('.cc-opt[data-grp="'+g+'"] .cc-cb').forEach(function(c){c.checked=on;}); ccCount();
  });});
  cbs().forEach(function(c){c.addEventListener('change',ccCount);});
  ccCount();
  btn.addEventListener('click',function(){
    var codes=selected();
    var mr=document.querySelector('input[name=ccmode]:checked'); var mode=mr?mr.value:'allow';
    if(!confirm('Apply never-block ('+mode+') for '+codes.length+' country(ies) and reload CSF?\nThis updates csf.conf (CC_ALLOW).')) return;
    var old=btn.innerHTML; btn.disabled=true; btn.innerHTML='⏳ Working…';
    var fd=new URLSearchParams(); fd.set('smpro_csrf',FW_CSRF); fd.set('fw_action','cc_allow'); fd.set('mode',mode); fd.set('countries',codes.join(','));
    fetch('index.cgi?page=firewall-status',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'})
      .then(function(r){return r.json();}).then(function(j){ alert((j&&j.ok?'✅ ':'⚠ ')+((j&&j.msg)||'Done')); if(j&&j.ok)setTimeout(function(){location.reload();},900); else {btn.disabled=false;btn.innerHTML=old;} })
      .catch(function(){btn.disabled=false;btn.innerHTML=old;alert('Request failed.');});
  });
})();
</script>
<script>
(function(){
  function ipact(op){
    var ip=(document.getElementById('ipAddInput').value||'').trim();
    var reason=(document.getElementById('ipAddReason').value||'').trim();
    if(!ip){alert('Enter an IP address');return;}
    if(!confirm((op==='block'?'Block':'Whitelist')+' '+ip+'?'))return;
    var btn=document.getElementById(op==='block'?'ipBlockBtn':'ipAllowBtn');var old=btn.innerHTML;btn.disabled=true;btn.innerHTML='⏳';
    var fd=new URLSearchParams();fd.set('smpro_csrf',FW_CSRF);fd.set('fw_action','ipadd');fd.set('op',op);fd.set('ip',ip);fd.set('reason',reason);
    fetch('index.cgi?page=firewall-status',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'})
     .then(function(r){return r.json();}).then(function(j){alert((j&&j.ok?'✅ ':'⚠ ')+((j&&j.msg)||'Done'));if(j&&j.ok)setTimeout(function(){location.reload();},900);else{btn.disabled=false;btn.innerHTML=old;}})
     .catch(function(){btn.disabled=false;btn.innerHTML=old;alert('Request failed.');});
  }
  var a=document.getElementById('ipAllowBtn'),b=document.getElementById('ipBlockBtn');
  if(a)a.addEventListener('click',function(){ipact('allow');});
  if(b)b.addEventListener('click',function(){ipact('block');});
  // "Allow my IP" banner button
  var mine=document.getElementById('fwAllowMine');
  if(mine)mine.addEventListener('click',function(){
    var ip=mine.getAttribute('data-ip');if(!ip)return;
    if(!confirm('Whitelist your admin IP '+ip+' (csf.allow)?'))return;
    var old=mine.innerHTML;mine.disabled=true;mine.innerHTML='⏳';
    var fd=new URLSearchParams();fd.set('smpro_csrf',FW_CSRF);fd.set('fw_action','ipadd');fd.set('op','allow');fd.set('ip',ip);fd.set('reason','admin IP (self)');
    fetch('index.cgi?page=firewall-status',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'})
     .then(function(r){return r.json();}).then(function(j){alert((j&&j.ok?'✅ ':'⚠ ')+((j&&j.msg)||'Done'));if(j&&j.ok)setTimeout(function(){location.reload();},900);else{mine.disabled=false;mine.innerHTML=old;}})
     .catch(function(){mine.disabled=false;mine.innerHTML=old;alert('Request failed.');});
  });
})();
</script>
<script>
(function(){
  // make every section card collapsible — click its title (or chevron) to open/close
  document.querySelectorAll('.smpro-main .card > .tp-th').forEach(function(th){
    var card=th.parentElement;
    var body=document.createElement('div'); body.className='fw-collapse';
    while(th.nextSibling){ body.appendChild(th.nextSibling); }
    card.appendChild(body);
    th.classList.add('fw-toggle');
    if(!th.querySelector('.fw-chev')) th.insertAdjacentHTML('afterbegin','<span class="fw-chev">&#9656;</span> ');
    card.classList.add('fw-open');                 // start expanded
    th.addEventListener('click',function(e){
      if(e.target.closest('a,button,input,select,label,.fw-chk'))return;   // don't toggle when using header controls
      card.classList.toggle('fw-open');
    });
  });
})();
</script>
<?php
smpro_layout_footer();
