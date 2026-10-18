<?php
/**
 * modules/user-investigation.php — per-account incident TIMELINE (feature-flagged BETA).
 * Read-only: pick an account + window → a merged, confidence-labeled timeline (panel/API actions,
 * logins, web attacks). Premium layout: read-only callout, icon stat cards, expandable rows,
 * pagination, column toggles, CSV export, right-side coverage panel, summary insight. No actions taken.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

/* ---- Upload-breach forensics: one-click READ-ONLY evidence report + confirm-gated response actions
 *      (POST + CSRF + root, JSON). Runs before any output. Actions reuse the proven-safe helpers
 *      (smpro_im_quarantine_file refuses WP-Guard-trusted + keeps a backup; smpro_im_block_ip refuses
 *      server/Cloudflare/allowlisted IPs). The collector itself never mutates an account file. ---- */
if (($reqMethod ?? ($_SERVER['REQUEST_METHOD'] ?? 'GET')) === 'POST' && ($_POST['ub_action'] ?? '') !== '') {
    smpro_require_valid_csrf('ub_action'); smpro_require_root();
    header('Content-Type: application/json');
    $act  = (string)$_POST['ub_action'];
    $acct = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)($_POST['user'] ?? ''));
    if ($act === 'report') {
        if (!function_exists('smpro_ub_report')) { echo json_encode(['ok'=>false, 'msg'=>'Upload-breach engine unavailable.']); exit; }
        $since = (int)($_POST['since'] ?? 0); if ($since <= 0 || $since > time()) $since = time() - 7 * 86400;
        $rep = smpro_ub_report($acct, $since, ['budget_ms'=>20000]);
        if (function_exists('smpro_audit')) smpro_audit('upload_breach_report', ['user'=>$acct, 'verdict'=>$rep['verdict'] ?? '']);
        echo json_encode(['ok'=>true, 'report'=>$rep], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
    }
    if ($act === 'quarantine_shell') {
        $file = (string)($_POST['file'] ?? '');
        if (!preg_match('#^/home/([^/]+)/.+#', $file, $m) || !is_file($file)) { echo json_encode(['ok'=>false, 'msg'=>'Refused: must be an existing path under /home/<account>/.']); exit; }
        if (!function_exists('smpro_im_quarantine_file')) { echo json_encode(['ok'=>false, 'msg'=>'Quarantine engine unavailable.']); exit; }
        $r = smpro_im_quarantine_file($file, $m[1], false);
        if (function_exists('smpro_audit')) smpro_audit('upload_breach_quarantine', ['file'=>$file, 'ok'=>(bool)$r]);
        echo json_encode($r ? ['ok'=>true, 'msg'=>'Quarantined — moved out of the web tree; a restorable backup is kept.'] : ['ok'=>false, 'msg'=>'Refused (WP-Guard-trusted or not removable).'], JSON_UNESCAPED_SLASHES); exit;
    }
    if ($act === 'block_ip') {
        if (!function_exists('smpro_im_block_ip')) { echo json_encode(['ok'=>false, 'msg'=>'Block engine unavailable.']); exit; }
        $r = smpro_im_block_ip((string)($_POST['ip'] ?? ''), 'SM Pro upload-breach report');
        if (function_exists('smpro_audit')) smpro_audit('upload_breach_block_ip', ['ip'=>(string)($_POST['ip'] ?? ''), 'ok'=>!empty($r['ok'])]);
        echo json_encode(['ok'=>!empty($r['ok']), 'msg'=>(string)($r['msg'] ?? '')], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
    }
    if ($act === 'disable_php_dir') {
        if (!function_exists('smpro_ub_harden_dir')) { echo json_encode(['ok'=>false, 'msg'=>'Hardening unavailable.']); exit; }
        $r = smpro_ub_harden_dir($acct, (string)($_POST['dir'] ?? ''));
        echo json_encode($r, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
    }
    if ($act === 'block_subnet') {   // present-to-admin decision: block a whole /16 or /24 that the operator judged hostile
        $cidr = (string)($_POST['cidr'] ?? '');
        if (!preg_match('#^(\d{1,3}\.){3}\d{1,3}/(16|24)$#', $cidr) || !filter_var(explode('/', $cidr)[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) { echo json_encode(['ok'=>false, 'msg'=>'Refused: only a /16 or /24 IPv4 CIDR.']); exit; }
        // SAFETY: a /16 is 65,536 addresses — 256x the /24 blocker's blast radius, so it gets the SAME guard
        // suite that smpro_im_block_subnet24() uses. Without these a single click could deny the server's own
        // network (black-holing the box), the Cloudflare edge (cutting inbound traffic to EVERY site), or a
        // whole residential home-region range full of real customers.
        $netIp = explode('/', $cidr)[0];
        $refuse = '';
        if (function_exists('smpro_ip_is_external') && !smpro_ip_is_external($netIp))    $refuse = 'private/local range';
        elseif (function_exists('smpro_ip_is_cloudflare') && smpro_ip_is_cloudflare($netIp)) $refuse = 'Cloudflare edge range — denying it would cut inbound traffic to every site on this server';
        elseif (function_exists('smpro_im_allowlisted') && smpro_im_allowlisted($netIp)) $refuse = 'allowlisted range';
        if ($refuse === '' && function_exists('smpro_server_ips') && function_exists('smpro_in_cidr_match')) {
            foreach (array_keys(smpro_server_ips()) as $sip) if (smpro_in_cidr_match($sip, $cidr)) { $refuse = "this server's own IP is inside " . $cidr . ' — blocking it would cut the server off'; break; }
        } elseif ($refuse === '' && function_exists('smpro_is_server_ip') && smpro_is_server_ip($netIp)) $refuse = 'the server\'s own IP';
        if ($refuse === '' && function_exists('smpro_im_region_status') && smpro_im_region_status($netIp) === 'core_protected')
            $refuse = 'home-region (' . smpro_im_home_regions_short() . ') residential range — that is thousands of likely-real customers; block the individual attacker IPs instead';
        if ($refuse !== '') { echo json_encode(['ok'=>false, 'msg'=>'Refused: ' . $refuse . '.'], JSON_UNESCAPED_SLASHES); exit; }
        // Use the firewall that actually enforces here — and never claim success from stdout text alone.
        // ONE block path (helpers.php): engine detection + Cloudflare refusal.
        $r = smpro_fw_block_ip($cidr, 'SM Pro upload-breach');
        smpro_audit('upload_breach_block_subnet', ['cidr'=>$cidr, 'ok'=>!empty($r['ok']), 'engine'=>(string)($r['engine'] ?? '')]);
        echo json_encode(['ok'=>!empty($r['ok']), 'msg'=>(string)($r['msg'] ?? '')], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
    }
    echo json_encode(['ok'=>false, 'msg'=>'Unknown action.']); exit;
}
$ubTok = function_exists('smpro_csrf_generate') ? smpro_csrf_generate('ub_action') : '';

/* ---------------- Deleted-files evidence (read-only) ----------------
 * Collected on demand rather than on every page load: it greps several large logs and walks the account's
 * directories, which is worth doing when somebody asks "who deleted this" and pure waste otherwise. */
require_once SMPRO_INCLUDES . '/uidelete.php';
if (is_file(SMPRO_INCLUDES . '/fileaudit.php')) require_once SMPRO_INCLUDES . '/fileaudit.php';   // who changed which file, through which door, from where
if (is_file(SMPRO_INCLUDES . '/uistory.php'))   require_once SMPRO_INCLUDES . '/uistory.php';     // the same evidence, told in plain words
if (strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET')) === 'POST'
    && ($_POST['ui_action'] ?? '') === 'deleted') {
    smpro_require_valid_csrf('ub_action'); smpro_require_root();
    header('Content-Type: application/json');
    $acct = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)($_POST['user'] ?? ''));
    $days = max(1, min(90, (int)($_POST['days'] ?? 7)));
    $out = ['ok' => false, 'msg' => 'No account given.'];
    if ($acct !== '') {
        try {
            $rep = smpro_uid_report($acct, time() - $days * 86400, time() + 300);
            $rep['verdict_text'] = smpro_uid_verdict_text($rep);
            $rep['ok'] = true;
            $out = $rep;
        } catch (\Throwable $e) {
            if (function_exists('smpro_soft_fail')) smpro_soft_fail('ui_deleted', $e);
            $out = ['ok' => false, 'msg' => 'The collection hit an error: ' . $e->getMessage()];
        }
        smpro_audit('user_investigation_deleted', ['user' => $acct, 'days' => $days,
            'events' => (int)($out['counts']['events'] ?? 0), 'actors' => (int)($out['counts']['actors'] ?? 0)]);
    }
    echo json_encode($out, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

$accounts = smpro_ui_accounts();
$user = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)($_GET['user'] ?? ''));
if ($user !== '' && !in_array($user, $accounts, true)) $user = '';
$winDays = (int)($_GET['win'] ?? 7); if (!in_array($winDays, [1, 7, 30], true)) $winDays = 7;
$to = time(); $from = $to - $winDays * 86400;
$data = $user !== '' ? smpro_ui_collect($user, $from, $to) : null;
// File changes with actor, door and address. Its own source, kept apart from the timeline on purpose: the
// timeline is what the server's logs happened to say; this is evidence the product made so the question
// "who deleted / changed the files" has an answer. ok=false is "could not look", and is shown as such.
$fa = ($user !== '' && function_exists('smpro_fa_events')) ? smpro_fa_events($user, $from, $to, 500) : null;
$story = ($data && function_exists('smpro_ui_story')) ? smpro_ui_story($data['events'], $fa, $from, $to) : null;
// The report as a text file: the same story, for a ticket or a customer. No new data, so nothing to get wrong.
if ($story && isset($_GET['report']) && function_exists('smpro_ui_story_text')) {
    if (function_exists('smpro_audit')) smpro_audit('user_investigation_report', ['user' => $user, 'win' => $winDays]);
    // index.cgi has already sent text/html, so header() cannot make this a download; that is done in the browser
    // (the button below). This path serves a direct link readably.
    echo '<!doctype html><meta charset="utf-8"><title>Investigation report - ' . smpro_h($user) . '</title>'
       . '<pre style="font:13px/1.5 ui-monospace,Menlo,Consolas,monospace;white-space:pre-wrap;padding:16px">'
       . smpro_h(smpro_ui_story_text($user, $from, $to, $story)) . '</pre>';
    exit;
}
if (function_exists('smpro_audit')) smpro_audit('user_investigation_view', ['user' => $user, 'win' => $winDays]);

smpro_layout_header('User Investigation');

$srcMeta = [
    'web_attack'       => ['Web attack',    'var(--dang)'],
    'cpanel_panel'     => ['Panel action',  'var(--brand)'],
    'login'            => ['Login',         '#0891b2'],
    'outbound_mail'    => ['Outbound mail', '#b45309'],
    'webshell_suspect' => ['Web-shell?',    'var(--dang)'],
];
$sevBadge = function ($s) {
    $s = strtolower((string)$s);
    if (in_array($s, ['critical', 'high', 'error'], true)) return ['#fee2e2', '#b91c1c'];
    if (in_array($s, ['medium', 'warning', 'warn'], true)) return ['#fff7ed', '#b45309'];
    if (in_array($s, ['low', 'notice'], true))             return ['#eff6ff', '#1d4ed8'];
    return ['#f1f5f9', '#475569'];
};
// Forensic per-event badge (HTML) from the enrichment fx subset; '' when the row has no forensic outcome.
$fxBadge = function ($fx) {
    if (!is_array($fx) || empty($fx['outcome'])) return '';
    $o = $fx['outcome']; $lb = (string)($fx['label'] ?? '');
    if ($o === 'blocked') return '<span class="fx-badge fxg-block" title="' . smpro_h($lb) . '">&#128737; Blocked</span>';
    if ($o === 'impact') {
        $hi = in_array((string)($fx['band'] ?? ''), ['high', 'critical'], true);
        $bn = ($fx['file'] ?? '') !== '' ? basename((string)$fx['file']) : 'file';
        return '<span class="fx-badge ' . ($hi ? 'fxg-mal' : 'fxg-susp') . '" title="' . smpro_h($lb) . '">&#9888; ' . smpro_h($bn) . ' (' . ($hi ? 'Malicious' : 'Suspicious') . ')</span>';
    }
    if ($o === 'reached') return stripos($lb, 'admin action') !== false
        ? '<span class="fx-badge fxg-admin" title="' . smpro_h($lb) . '">Admin action</span>'
        : '<span class="fx-badge fxg-reach" title="' . smpro_h($lb) . '">Reached app</span>';
    return '';   // 'other' → no badge
};
$vtitle = ['compromise_confirmed'=>'Compromise confirmed', 'compromise_suspected'=>'Compromise suspected', 'suspicious_file'=>'Suspicious file changed', 'attacks_reached'=>'Attacks reached the app', 'attacks_blocked'=>'Attacks blocked', 'reconnaissance'=>'Reconnaissance only', 'clean'=>'No attacks of consequence'];

$summary = ''; $failedIps = []; $recs = [];
if ($data) {
    $st = $data['stats'];
    $fxr = $data['forensic'] ?? ['ok' => false];
    foreach ($data['events'] as $e) if ($e['action'] === 'Failed login' && $e['actor_ip'] !== '') $failedIps[$e['actor_ip']] = ($failedIps[$e['actor_ip']] ?? 0) + 1;
    arsort($failedIps);
    $bits = [];
    if ($st['failed_logins']) $bits[] = $st['failed_logins'] . ' failed login' . ($st['failed_logins'] > 1 ? 's' : '') . ' from ' . count($failedIps) . ' IP' . (count($failedIps) > 1 ? 's' : '');
    $bits[] = $st['attacks'] ? ($st['attacks'] . ' web attack' . ($st['attacks'] > 1 ? 's' : '')) : 'no web attacks';
    if ($st['panel']) $bits[] = $st['panel'] . ' panel action' . ($st['panel'] > 1 ? 's' : '');
    $summary = 'We found ' . implode(' · ', $bits) . ' in the last ' . $winDays . ' day(s).';
    foreach (array_slice($failedIps, 0, 3, true) as $ip => $n) $recs[] = 'Review <a href="index.cgi?page=reports-center&ip=' . urlencode($ip) . '">' . smpro_h($ip) . '</a> (' . (int)$n . ' failed login' . ($n > 1 ? 's' : '') . ') in Reports Center / Login Monitor';
    if ($st['attacks']) $recs[] = 'Open <a href="index.cgi?page=intrusion-monitor">Intrusion Monitor</a> for this account\'s domains';
    if ($failedIps) $recs[] = 'Check <a href="index.cgi?page=firewall-status">CSF / LFD</a> blocks for the IPs above';
    $recs[] = 'Scan recent file changes: <a href="index.cgi?page=forensics-audit&user=' . urlencode($user) . '">Forensics / Audit</a>';
}
?>
<div class="svc-kicker">Security &amp; Access</div>
<h1 class="h" style="margin:2px 0 4px">User Investigation Timeline <?= smpro_beta_badge() ?></h1>
<p class="sub">A <b>read-only forensic timeline</b> for a selected cPanel account, built from server logs — panel/API activity, login attempts, web-attack signals, <b>outbound-mail attribution</b> (which script sent mail, and whether it was a compromised app or a stolen mailbox password), and <b>suspected web shells</b> spotted in the access logs. Every event includes its <b>source</b> and <b>confidence</b> level.</p>

<div class="card ui-toolbar">
  <form method="get" action="index.cgi" class="ui-tbrow">
    <input type="hidden" name="page" value="user-investigation">
    <label class="ui-fld">cPanel account
      <input type="text" name="user" class="tp-in" value="<?= smpro_h($user) ?>" placeholder="start typing an account…" data-ac="accounts" autocomplete="off" spellcheck="false" style="min-width:230px">
    </label>
    <label class="ui-fld">Time window
      <select name="win" class="tp-sel"><?php foreach ([1=>'Last 24 hours', 7=>'Last 7 days', 30=>'Last 30 days'] as $k => $v): ?><option value="<?= $k ?>"<?= $winDays === $k ? ' selected' : '' ?>><?= $v ?></option><?php endforeach; ?></select>
    </label>
    <button class="tp-btn primary ui-go" type="submit" data-scan="Assembling the account timeline from server logs…">&#128269; Investigate</button>
  </form>
  <div class="ui-ro"><div class="ui-ro-ic">&#128737;</div><div><b>Read-only mode</b><span>This page never changes anything. Response actions live on their own pages.</span></div></div>
</div>

<?php if ($data === null): ?>
  <div class="card" style="padding:18px;color:var(--muted)">Choose a cPanel account and a time window, then click <b>Investigate</b> to build its timeline.</div>
<?php else: ?>
  <div class="ui-grid">
    <div class="ui-main">
      <div class="card ub-card" id="ui-deleted">
        <div class="ub-head"><b>&#128465;&#65039; Deleted files &mdash; who, from where, and when</b>
          <details class="gl-fold"><summary><span class="fw-chev gl-chev">&#9656;</span>How this works</summary><span class="meta">
          Files vanish and nobody owns up. This collects every record on the server that could show a deletion &mdash;
          cPanel File Manager, FTP, SSH/SFTP, <b>mailboxes</b>, <b>this plugin's own actions</b>, and the account's own files &mdash;
          then names each address behind them, says whether the account has ever signed in from it before, and shows
          everything else that address did. Read-only.</span></details></div>
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
          <label class="ui-fld" style="margin:0">Look back
            <select id="delDays" class="tp-sel">
              <option value="1">24 hours</option><option value="7" selected>7 days</option>
              <option value="30">30 days</option><option value="90">90 days</option>
            </select>
          </label>
          <button id="delGo" type="button" class="tp-btn primary ub-go" data-user="<?= smpro_h($user) ?>">&#128269; Collect deletion evidence</button>
          <span id="delStatus" class="meta ub-status"></span>
        </div>
        <div id="delReport" class="ub-report" hidden></div>
      </div>
      <div class="card ub-card" id="ui-upload">
        <div class="ub-head"><b>&#128300; Upload-breach forensics</b><span class="meta">One-click, read-only evidence collection for file-upload attacks — hunts planted shells (any extension), finds the vulnerable upload endpoint, pulls the ModSec payloads, and decides whether a shell is actually <b>live</b>.</span></div>
        <button id="ubGo" type="button" class="tp-btn primary ub-go" data-user="<?= smpro_h($user) ?>" data-since="<?= (int)$from ?>">&#128300; Collect breach evidence</button>
        <span id="ubStatus" class="meta ub-status"></span>
        <div id="ubReport" class="ub-report" hidden></div>
      </div>
      <?php if (!empty($fxr['ok'])):
          $bcls = ['red'=>'fxb-red','amber'=>'fxb-amber','green'=>'fxb-green','neutral'=>'fxb-neutral'][$fxr['color']] ?? 'fxb-neutral';
          $bico = ['red'=>'&#128680;','amber'=>'&#9888;','green'=>'&#128737;','neutral'=>'&#128269;'][$fxr['color']] ?? '&#128269;'; ?>
      <div class="card fx-banner <?= $bcls ?>">
        <div class="fx-banner-ic"><?= $bico ?></div>
        <div class="fx-banner-body">
          <b><?= smpro_h($vtitle[$fxr['verdict']] ?? 'Forensic verdict') ?></b>
          <p><?= smpro_h($fxr['headline']) ?></p>
          <?php if (in_array($fxr['modsec'], ['off','detectiononly'], true)): ?><p class="fx-modsec">&#9888; ModSecurity is <?= $fxr['modsec']==='off' ? 'OFF' : 'in Detection-Only mode' ?> on some vhosts — attacks may be logged but not blocked.</p><?php endif; ?>
          <?php if (!empty($fxr['truncated'])): ?><p class="meta" style="font-style:italic">Analysis truncated at the time budget — some changed files were not deep-scanned.</p><?php endif; ?>
        </div>
        <?php if (in_array($fxr['verdict'], ['compromise_confirmed','compromise_suspected','suspicious_file','attacks_reached'], true)): ?>
          <a class="tp-btn primary" href="index.cgi?page=forensics-audit&user=<?= urlencode($user) ?>">Open Forensics / Audit &#8250;</a>
        <?php endif; ?>
      </div>
      <?php endif; ?>
      <div class="card ui-covbar" id="ui-coverage">
        <div class="tp-th"><b>&#128737; Coverage &mdash; what this timeline does and does not include</b></div>
        <div class="ui-cov">
          <b class="ui-cov-h" style="color:var(--brand)">&#128737; What this timeline covers</b>
          <details class="gl-fold"><summary><span class="fw-chev gl-chev">&#9656;</span>What each row type means</summary>
          <ul class="ui-cov-yes">
            <li><b>Panel actions</b> = cPanel/WHM API operations by this account (who/when/what kind + IP).</li>
            <li><b>Logins</b> = successful / failed / deferred cPanel logins for this account.</li>
            <li><b>Web attacks</b> = ModSecurity-detected attacks on this account's domains (from the persistent index).</li>
            <li><b>File-impact correlation</b> = when an exploit-class request reached the app, recently-changed webroot files near that time are deep-scanned and the outcome is labeled (bounded, read-only).</li>
            <li>Every row shows an <b>outcome</b> + <b>confidence</b>. Retention is limited by the server logs (typically a few days to a few weeks).</li>
          </ul>
          </details>
        </div>
        <div class="ui-cov">
          <b class="ui-cov-h" style="color:var(--dang)">&#128721; What it does not cover</b>
          <ul class="ui-cov-no">
            <li>Full malware / backdoor deep sweep (lives in Forensics / Audit)</li>
            <li>Outbound-mail evidence</li>
            <li>Backup / WordPress checksums</li>
          </ul>
          <p class="meta" style="font-style:italic;margin:6px 0 0">Coming next in this beta.</p>
        </div>
      </div>
      <div class="ui-kpis<?= !empty($fxr['ok']) ? ' fx6' : '' ?>">
        <?php
        // Each card is a control: it filters the timeline to its own rows (or jumps to its section). They looked
        // clickable and did nothing, so "Panel actions: 37" was a number with no way to see the 37.
        // Colour is a STATE (good / warn / dang / brand / muted), not a hex pair, so the cards follow the theme.
        $kpis = [
            ['&#128197;', $st['total'],         'Timeline events', 'Click: all events',        'brand', 'src:'],
            ['&#128272;', $st['failed_logins'], 'Failed logins',   'Click: failed sign-ins',   'warn',  'act:Failed login'],
            ['&#128737;', $st['attacks'],       'Web attacks',     'Click: ModSecurity rows',  'dang',  'src:web_attack'],
            ['&#9776;',   $st['panel'],         'Panel actions',   'Click: cPanel operations', 'brand', 'src:cpanel_panel'],
            ['&#128273;', $st['logins'],        'Sign-ins',        'Click: who got in + what they did', 'good', 'jump:uiSignins'],
            ['&#127760;', $st['ips'],           'Distinct IPs',    'Click: group by address',  'brand', 'group:actor_ip'],
        ];
        if (($st['mail'] ?? 0) > 0)     $kpis[] = ['&#128231;', $st['mail'],     'Outbound mail',      'Click: mail rows',       'warn', 'src:outbound_mail'];
        if (($st['webshell'] ?? 0) > 0) $kpis[] = ['&#128126;', $st['webshell'], 'Web-shell suspects',  'Click: suspect rows',    'dang', 'src:webshell_suspect'];
        if (is_array($fa)) {
            $nfa = count($fa['events']);
            $sub = !empty($fa['ok']) ? ($nfa ? ('Click: ' . count($fa['doors']) . ' door(s), ' . (int)$fa['ips'] . ' address(es)') : 'None recorded in the window') : 'Could not look';
            $kpis[] = ['&#128196;', $nfa, 'File changes', $sub, !empty($fa['ok']) ? ($nfa ? 'warn' : 'good') : 'dang', 'jump:uiFileChanges'];
        }
        if (!empty($fxr['ok'])) {
            $ci = (int)($fxr['kpi']['confirmed_impact'] ?? 0);
            $sub = $ci > 0 ? 'Correlated file impact' : (!empty($fxr['scanned']) ? 'None found in scan' : 'Scan not needed');
            $kpis[] = ['&#128300;', $ci, 'File impact', $sub, $ci > 0 ? 'dang' : 'good', 'src:web_attack'];
        }
        foreach ($kpis as [$ic, $n, $lbl, $sub, $cls, $go]): ?>
          <div class="card ui-kpi <?= $cls ?>" role="button" tabindex="0" data-go="<?= smpro_h($go) ?>" style="cursor:pointer" title="<?= smpro_h($sub) ?>"><div class="ui-kpi-ic"><?= $ic ?></div><div class="ui-kpi-n"><?= number_format((int)$n) ?></div><div class="ui-kpi-l"><?= $lbl ?></div><div class="ui-kpi-s"><?= smpro_h($sub) ?></div></div>
        <?php endforeach; ?>
      </div>
      <nav class="fw-nav" id="uiNav"><a href="#ui-deleted" data-go="ui-deleted">&#128465;&#65039; Deleted files</a><a href="#ui-upload" data-go="ui-upload">&#128300; Upload breach</a><a href="#ui-coverage" data-go="ui-coverage">Coverage</a><a href="#uiStory" data-go="uiStory">&#128214; Story</a><a href="#uiSignins" data-go="uiSignins">&#128273; Sign-ins</a><a href="#ui-timeline" data-go="ui-timeline">&#128203; Timeline</a><a href="#uiFileChanges" data-go="uiFileChanges">&#128196; File changes</a><a href="#ui-summary" data-go="ui-summary">&#128161; Summary</a><span class="sp"></span><button type="button" class="fw-navx" id="uiOpenAll">expand all</button><button type="button" class="fw-navx" id="uiCloseAll">collapse all</button></nav>

      <?php if (is_array($story)): $sb = $story['bottom']; $CLS = ['owner'=>['Password holder','#b45309'],'operator'=>['Server-side access','#0891b2'],'person'=>['Person','#0f766e'],'machine'=>['Site code / cron','#64748b'],'reached'=>['Attack reached the site','#b91c1c'],'bruteforce'=>['Password guessing','#c2410c'],'mail'=>['Outbound mail','#b45309'],'failed'=>['Failed sign-ins','#64748b'],'other'=>['Other','#64748b']]; ?>
      <div class="card" style="padding:0;overflow:hidden;margin:14px 0" id="uiStory">
        <div class="tp-th" style="display:flex;align-items:center;justify-content:space-between;gap:10px;padding:12px 16px;border-bottom:1px solid var(--line)">
          <div><b>&#128214; What happened — in plain words</b> <span class="meta" style="margin-left:8px">the same evidence as the tables, told by address and by episode</span></div>
          <span><button id="uiReportDl" type="button" class="tp-btn">&#8595; Download report (.txt)</button>
          <a class="meta" style="margin-left:8px" href="index.cgi?page=user-investigation&amp;user=<?= rawurlencode($user) ?>&amp;win=<?= (int)$winDays ?>&amp;report=1" target="_blank">open as text</a></span>
        </div>
        <div style="padding:12px 16px;border-bottom:1px solid var(--line);line-height:1.6">
          <b>Bottom line.</b>
          <?= (int)$sb['people'] ?> person session<?= $sb['people'] === 1 ? '' : 's' ?> from <?= (int)$sb['addrs'] ?> address<?= $sb['addrs'] === 1 ? '' : 'es' ?><?= $sb['ccs'] ? ' in ' . smpro_h(implode(', ', $sb['ccs'])) : '' ?>.
          <?= (int)$sb['files'] ?> file change<?= $sb['files'] === 1 ? '' : 's' ?><?php if ($sb['file_by']): ?> (<?= smpro_h(implode(', ', array_map(fn($k, $v) => "$v via " . (['cpanel'=>'File Manager','ftp'=>'FTP','sftp'=>'SFTP','shell'=>'SSH','web'=>'PHP','cron'=>'cron','system'=>'system'][$k] ?? $k), array_keys($sb['file_by']), $sb['file_by']))) ?>)<?php endif; ?>.
          <?= number_format((int)$sb['blocked']) ?> attack request<?= $sb['blocked'] === 1 ? '' : 's' ?> blocked from <?= (int)$sb['blocked_ips'] ?> address<?= $sb['blocked_ips'] === 1 ? '' : 'es' ?>;
          <b style="color:<?= $sb['reached'] ? '#b91c1c' : '#047857' ?>"><?= (int)$sb['reached'] ?> reached the site</b>; <?= (int)$sb['failed'] ?> failed sign-in<?= $sb['failed'] === 1 ? '' : 's' ?>.
          <?php foreach ($story['blind'] as $x): ?><div style="color:#991b1b;margin-top:4px"><b>Could not look:</b> <?= smpro_h($x) ?></div><?php endforeach; ?>
        </div>
        <?php if (!$story['episodes'] && $story['blocked']['n'] === 0): ?>
          <div style="padding:14px 16px;color:var(--muted)">Nothing recorded for this account in the window.</div>
        <?php endif; ?>
        <ol style="margin:0;padding:6px 16px 6px 34px">
        <?php foreach ($story['episodes'] as $i => $ep): [$cl, $cc] = $CLS[$ep['class']] ?? ['Other', '#64748b']; ?>
          <li style="padding:8px 0;border-bottom:1px solid var(--line)">
            <span class="ub-band" style="background:<?= $cc ?>22;color:<?= $cc ?>;margin-right:6px"><?= smpro_h($cl) ?></span>
            <?= smpro_h($ep['sentence']) ?>
            <?php if ($ep['ip'] !== '' && !$ep['self']): ?><button class="ui-copy" data-ip="<?= smpro_h($ep['ip']) ?>" type="button" title="copy address">&#128203;</button><?php endif; ?>
            <?php if ($ep['verdict'] !== ''): ?><div class="meta" style="margin-top:2px">&rarr; <?= smpro_h($ep['verdict']) ?></div><?php endif; ?>
            <?php if ($ep['paths']): ?><div class="meta" style="margin-top:2px"><?php foreach ($ep['paths'] as $p): ?><code style="display:block"><?= smpro_h($p) ?></code><?php endforeach; ?></div><?php endif; ?>
            <?php if ($ep['ip'] !== ''): ?><div class="meta" style="margin-top:2px"><a href="#uiMainWrap" class="ui-storyfilter" data-ip="<?= smpro_h($ep['ip']) ?>">show these rows in the timeline &#8250;</a></div><?php endif; ?>
          </li>
        <?php endforeach; ?>
        </ol>
        <?php if ($story['blocked']['n'] > 0): $bl = $story['blocked']; ?>
          <div style="padding:10px 16px;border-top:1px solid var(--line);line-height:1.6">
            <span class="ub-band" style="background:#64748b22;color:#64748b;margin-right:6px">Blocked at the door</span>
            <?= number_format($bl['n']) ?> attack request<?= $bl['n'] === 1 ? '' : 's' ?> from <?= count($bl['ips']) ?> address<?= count($bl['ips']) === 1 ? '' : 'es' ?>
            between <?= gmdate('d M H:i', $bl['first']) ?> and <?= gmdate('d M H:i', $bl['last']) ?> UTC — all refused; nothing reached the site.
            <div class="meta">what they tried: <?= smpro_h(implode('; ', array_map(fn($k, $v) => "$k ($v)", array_slice(array_keys($bl['targets']), 0, 5), array_slice($bl['targets'], 0, 5)))) ?></div>
            <div class="meta">top addresses: <?= smpro_h(implode(', ', array_map(fn($k, $v) => "$k ($v)", array_slice(array_keys($bl['ips']), 0, 8), array_slice($bl['ips'], 0, 8)))) ?><?= $bl['cc'] ? ' · countries: ' . smpro_h(implode(', ', array_map(fn($k, $v) => "$k ($v)", array_keys($bl['cc']), $bl['cc']))) : '' ?></div>
          </div>
        <?php endif; ?>
      </div>
      <?php endif; ?>

      <?php if (is_array($story)): $si = (array)($story['signins'] ?? []); ?>
      <div class="card" style="padding:0;overflow:hidden;margin:14px 0" id="uiSignins">
        <div class="tp-th" style="display:flex;align-items:center;justify-content:space-between;gap:10px;padding:12px 16px;border-bottom:1px solid var(--line)">
          <div><b>&#128273; Who signed in — and everything each address did</b> <span class="meta" style="margin-left:8px">successful sign-ins only; every action of that address across the whole window</span></div>
          <span class="meta"><?= count($si) ?> address<?= count($si) === 1 ? '' : 'es' ?> got in</span>
        </div>
        <?php if (!$si): ?>
          <div style="padding:14px 16px;color:var(--muted)">No successful sign-in to this account in the window<?= !empty($story['blind']) ? ' (see "could not look" above)' : '' ?>.</div>
        <?php else: ?>
        <div style="overflow-x:auto"><table class="smpro-table" data-serversort="1" style="margin:0">
          <thead><tr><th>Address</th><th>Signed in</th><th>Panel operations</th><th>File changes</th><th>Other</th><th></th></tr></thead>
          <tbody>
          <?php foreach ($si as $k => $s): ?>
            <tr>
              <td><code><?= smpro_h($s['ip']) ?></code><?= $s['cc'] !== '' ? ' <span class="meta">' . smpro_h($s['cc']) . '</span>' : '' ?><?= $s['self'] ? ' <span class="meta">(the server itself)</span>' : '' ?>
                  <?php if (!$s['self']): ?><button class="ui-copy" data-ip="<?= smpro_h($s['ip']) ?>" type="button" title="copy address">&#128203;</button><?php endif; ?></td>
              <td style="white-space:nowrap"><?php foreach (array_slice($s['logins'], 0, 6) as $g): ?><div><span class="mono" style="font-size:11px"><?= gmdate('d M H:i', $g['ts']) ?></span> <span class="ub-band" style="background:<?= $g['kind'] === 'password' ? '#b4530922;color:#b45309' : '#0891b222;color:#0891b2' ?>"><?= $g['kind'] === 'password' ? 'password' : 'from WHM' ?></span> <span class="meta"><?= smpro_h($g['service']) ?></span></div><?php endforeach; ?>
                  <?php if (count($s['logins']) > 6): ?><div class="meta">+<?= count($s['logins']) - 6 ?> more</div><?php endif; ?></td>
              <td><b><?= count($s['panel']) ?></b><?php if ($s['modules']): ?> <span class="meta"><?= smpro_h(implode(', ', array_map(fn($m, $n) => "$m ×$n", array_slice(array_keys($s['modules']), 0, 5), array_slice($s['modules'], 0, 5)))) ?><?= count($s['modules']) > 5 ? ', …' : '' ?></span><?php endif; ?></td>
              <td><b style="color:<?= count($s['files']) ? '#b45309' : 'inherit' ?>"><?= count($s['files']) ?></b></td>
              <td class="meta"><?= count($s['mail']) ? count($s['mail']) . ' mail' : '' ?><?= $s['attacks']['reached'] ? ' <b style="color:#b91c1c">' . $s['attacks']['reached'] . ' attack reached</b>' : '' ?><?= $s['attacks']['blocked'] ? ' ' . $s['attacks']['blocked'] . ' blocked' : '' ?></td>
              <td><button class="fa-lnk uisi-view" type="button" data-k="<?= (int)$k ?>">View all &#8250;</button></td>
            </tr>
            <tr class="uisi-det" data-k="<?= (int)$k ?>" hidden><td colspan="6" style="padding:0">
              <div class="uig-sub">
                <?php
                  // one merged, time-ordered list of everything this address did
                  $rows = [];
                  foreach ($s['logins'] as $g) $rows[] = [$g['ts'], 'sign-in', ($g['kind'] === 'password' ? 'with the account password' : 'opened from WHM (no password)') . ' · ' . $g['service'], '#0f766e'];
                  foreach ($s['panel'] as $p)  $rows[] = [$p['ts'], 'panel', $p['op'] . ' · ' . $p['detail'], '#0891b2'];
                  foreach ($s['files'] as $f)  $rows[] = [$f['ts'], $f['op'], $f['path'] . ' · via ' . $f['door'] . ($f['actor'] !== '' ? ' as ' . $f['actor'] : ''), '#b45309'];
                  foreach ($s['mail'] as $m)   $rows[] = [$m['ts'], 'mail', $m['detail'], '#b45309'];
                  usort($rows, fn($a, $b) => $a[0] <=> $b[0]);
                  foreach (array_slice($rows, 0, 400) as [$ts, $what, $det, $col]):
                ?>
                  <div class="uig-subrow"><span class="mono uig-t"><?= gmdate('Y-m-d H:i:s', $ts) ?></span><span class="ui-chip2" style="color:<?= $col ?>"><?= smpro_h($what) ?></span><span class="mono uig-d" style="word-break:break-all"><?= smpro_h($det) ?></span></div>
                <?php endforeach; if (count($rows) > 400): ?><div class="meta" style="padding:4px 8px">… and <?= count($rows) - 400 ?> more (the text report holds the file changes; use Download CSV for the rest)</div><?php endif; ?>
              </div>
            </td></tr>
          <?php endforeach; ?>
          </tbody></table></div>
        <?php endif; ?>
      </div>
      <?php endif; ?>

      <div class="card" style="padding:0;overflow:hidden;margin:14px 0" id="ui-timeline">
        <div class="ui-thead">
          <b>&#128203; Timeline — <?= smpro_h($user) ?></b>
          <span class="meta">last <?= $winDays ?> day(s) · newest first</span>
          <span class="ui-thead-btns">
            <label class="ui-grp"><span class="meta">Group by</span>
              <span id="uiFilterLbl" class="ub-band" style="display:none;background:#0891b222;color:#0891b2"></span>
              <button id="uiFilterClear" type="button" class="tp-btn ui-sm" style="display:none">&#10005; clear filter</button>
              <select id="uiGroupBy" class="ui-gsel">
                <option value="">None — timeline</option>
                <option value="actor_ip">Actor IP</option>
                <option value="action">Action</option>
                <option value="source">Source</option>
                <option value="severity">Severity</option>
                <option value="day">Day</option>
              </select>
            </label>
            <button id="uiCsv" type="button" class="tp-btn ui-sm">&#11123; Download CSV</button>
            <span class="ui-colswrap">
              <button id="uiCols" type="button" class="tp-btn ui-sm">&#9881; Columns</button>
              <div id="uiColsMenu" class="ui-colsmenu" hidden>
                <?php foreach (['detail'=>'Detail','ip'=>'Actor IP','conf'=>'Confidence'] as $ck=>$cl): ?><label><input type="checkbox" class="ui-colck" data-col="<?= $ck ?>" checked> <?= $cl ?></label><?php endforeach; ?>
              </div>
            </span>
          </span>
        </div>
        <?php if (!$data['events']): ?>
          <div class="ui-empty"><div style="font-size:34px">&#128269;</div><b>No events found for this account in the selected window.</b><p>No panel actions, logins, or web attacks were recorded. This does <b>not</b> prove the account is safe — server-log retention is limited, so widen the window or check the dedicated pages.</p></div>
        <?php else: $EV = $data['events']; $per = 25; $total = count($EV); ?>
        <div id="uiMainWrap" class="fa-tablewrap"><table class="smpro-table ui-tbl"><thead><tr>
          <th>Time (UTC)</th><th>Source</th><th>Severity</th><th class="col-ip">Actor IP</th><th>Action</th><th class="col-detail">Detail</th><th class="col-conf">Confidence</th><th></th>
        </tr></thead><tbody>
          <?php /* rows are rendered in the browser, one page at a time, from EV (see uiBuildRow): 873 events used to be 900 KB of HTML */ ?>
        </tbody></table></div>
        <div id="uiGroupWrap" class="fa-tablewrap" hidden><table class="smpro-table ui-gtbl"><thead><tr>
          <th class="ui-gth">Group</th><th>Events</th><th>Severity mix</th><th>First seen (UTC)</th><th>Last seen (UTC)</th><th></th>
        </tr></thead><tbody id="uiGroupBody"></tbody></table></div>
        <div id="uiPager" class="ui-pager"><span id="uiPgInfo" class="meta"></span><span class="ui-pg-btns"><button id="uiPrev" class="tp-btn ui-sm" type="button">&#8249;</button><span id="uiPgNum" class="ui-pgnum">1</span><button id="uiNext" class="tp-btn ui-sm" type="button">&#8250;</button></span></div>
        <?php endif; ?>
      </div>

      <?php if (is_array($fa)): ?>
      <?php
        // ---- File changes: who, through which door, from which address, when ----
        $faDoor = ['cpanel' => ['File Manager', '#0891b2'], 'ftp' => ['FTP', '#6d28d9'], 'sftp' => ['SFTP', '#6d28d9'], 'shell' => ['SSH / shell', '#b45309'],
                   'web' => ['Web (PHP)', '#b91c1c'], 'cron' => ['Cron', '#64748b'], 'system' => ['System', '#64748b'], 'other' => ['Other', '#64748b']];
        $faOp   = ['deleted' => '#b91c1c', 'renamed' => '#b45309', 'created' => '#047857', 'modified' => '#1d4ed8'];
        $faSt   = (array)($fa['status'] ?? []);
        $faRows = (array)$fa['events'];
        $faShow = array_slice($faRows, 0, 300);
      ?>
      <div class="card" style="padding:0;overflow:hidden;margin:14px 0" id="uiFileChanges">
        <div class="ui-tl-head" style="display:flex;align-items:center;justify-content:space-between;gap:10px;padding:12px 16px;border-bottom:1px solid var(--line)">
          <div><b>&#128196; File changes — <?= smpro_h($user) ?></b>
            <span class="meta" style="margin-left:8px">who · door · address · when</span></div>
          <div class="meta">
            <?php if (!empty($fa['ok'])): ?>
              recording since <?= $fa['covered_from'] ? gmdate('Y-m-d H:i', (int)$fa['covered_from']) . ' UTC' : '—' ?>
              · <?= (int)($faSt['rules'] ?? 0) ?> kernel rule(s) live
            <?php endif; ?>
          </div>
        </div>
        <?php if (empty($fa['ok'])): ?>
          <div style="padding:14px 16px;background:#fef2f2;color:#991b1b;border-bottom:1px solid #fecaca">
            <b>Could not look.</b> <?= smpro_h((string)$fa['why']) ?>
            <div class="meta" style="color:#991b1b;margin-top:4px">This is not "no changes". The evidence for this window was not being made or collected, so the table below can only show what exists.</div>
          </div>
        <?php elseif (!empty($fa['partial'])): ?>
          <div style="padding:10px 16px;background:#fffbeb;color:#92400e;border-bottom:1px solid #fde68a" class="meta">
            Recording began <?= gmdate('Y-m-d H:i', (int)$fa['covered_from']) ?> UTC, inside this window. Changes before that moment were never recorded anywhere on this server and cannot be shown.
          </div>
        <?php endif; ?>
        <?php if (!$faRows): ?>
          <div style="padding:16px;color:var(--muted)"><?= !empty($fa['ok']) ? 'No file changes through a person\'s door (File Manager, FTP, SFTP, SSH) and no deletions by anything in this window.' : 'Nothing to show.' ?></div>
        <?php else: ?>
        <div style="padding:8px 16px;display:flex;gap:14px;flex-wrap:wrap" class="meta">
          <?php foreach ((array)$fa['ops'] as $op => $n): ?><span><b style="color:<?= $faOp[$op] ?? '#64748b' ?>"><?= (int)$n ?></b> <?= smpro_h($op) ?></span><?php endforeach; ?>
          <span style="margin-left:auto">by door:
          <?php foreach ((array)$fa['doors'] as $d => $n): ?><span style="margin-left:8px"><b><?= (int)$n ?></b> <?= smpro_h($faDoor[$d][0] ?? $d) ?></span><?php endforeach; ?></span>
        </div>
        <div style="overflow-x:auto"><table class="smpro-table" data-serversort="1" style="margin:0">
          <thead><tr><th>When (UTC)</th><th>Door</th><th>Who</th><th>Address</th><th>Change</th><th>Path</th><th>How the address was found</th></tr></thead>
          <tbody>
          <?php foreach ($faShow as $r): [$dl, $dc] = $faDoor[$r['door']] ?? [$r['door'], '#64748b']; ?>
            <tr>
              <td style="white-space:nowrap"><?= gmdate('Y-m-d H:i:s', (int)$r['ts']) ?></td>
              <td><span class="ub-band" style="background:<?= $dc ?>22;color:<?= $dc ?>"><?= smpro_h($dl) ?></span></td>
              <td><code><?= smpro_h((string)$r['actor']) ?></code><?php if ($r['login'] !== '' && $r['login'] !== $r['actor']): ?> <span class="meta">(logged in as <?= smpro_h($r['login']) ?>)</span><?php endif; ?></td>
              <td><?php if ($r['ip'] !== ''): ?><code><?= smpro_h($r['ip']) ?></code><?php elseif (in_array($r['door'], ['web', 'cron', 'system'], true)): ?><span class="meta">no network door</span><?php else: ?><span class="meta" style="color:#b45309">not found</span><?php endif; ?></td>
              <td><b style="color:<?= $faOp[$r['op']] ?? '#64748b' ?>"><?= smpro_h($r['op']) ?></b></td>
              <td style="word-break:break-all"><code><?= smpro_h((string)$r['path']) ?></code><?php if ($r['from'] !== ''): ?><div class="meta">from <code><?= smpro_h($r['from']) ?></code></div><?php endif; ?>
                  <?php if (!empty($r['chroot'])): ?><div class="meta">path is relative to the FTP login's folder</div><?php endif; ?></td>
              <td class="meta"><?= smpro_h((string)$r['ip_how']) ?><?php if ($r['ip_how'] === '' && $r['door'] === 'web'): ?>a web request; see the timeline for the request at this second<?php endif; ?></td>
            </tr>
          <?php endforeach; ?>
          </tbody></table></div>
        <?php if (count($faRows) > count($faShow)): ?><div class="meta" style="padding:8px 16px">Showing the newest <?= count($faShow) ?> of <?= count($faRows) ?>. Narrow the window for the rest.</div><?php endif; ?>
        <?php endif; ?>
      </div>
      <?php endif; ?>

      <div class="card ui-insight" id="ui-summary">
        <div><b>&#128161; Summary insight</b><p><?= $summary !== '' ? smpro_h($summary) : 'No activity recorded for this account in the window.' ?></p></div>
        <?php if ($recs): ?><button id="uiRecBtn" type="button" class="tp-btn">See recommended next checks &#8250;</button><?php endif; ?>
      </div>
      <?php if ($recs): ?>
      <div id="uiRecBox" class="card ui-recs" hidden>
        <b>&#128161; Recommended next checks <span class="meta" style="font-weight:600">(advice only — nothing runs automatically)</span></b>
        <ul><?php foreach ($recs as $r): ?><li><?= $r ?></li><?php endforeach; ?></ul>
      </div>
      <?php endif; ?>
    </div>
  </div>

  <script>
  (function(){
    var EV = <?= json_encode($data['events'], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE) ?>;
    var SRC = <?= json_encode(array_map(fn($m) => $m[0], $srcMeta), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    var UUSER = <?= json_encode($user, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    var SRCC = <?= json_encode(array_map(fn($m) => $m[1], $srcMeta), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    function uiCap(s){ s=String(s==null?'':s); return s.charAt(0).toUpperCase()+s.slice(1); }
    function uiSevBadge(s){ s=String(s||'').toLowerCase(); if(s==='critical'||s==='high'||s==='error')return['#fee2e2','#b91c1c']; if(s==='medium'||s==='warning'||s==='warn')return['#fff7ed','#b45309']; if(s==='low'||s==='notice')return['#eff6ff','#1d4ed8']; return['#f1f5f9','#475569']; }
    function uiFxBadge(fx){
      if(!fx||typeof fx!=='object'||!fx.outcome) return '';
      var o=fx.outcome, lb=uiEsc(fx.label||'');
      if(o==='blocked') return '<span class="fx-badge fxg-block" title="'+lb+'">&#128737; Blocked</span>';
      if(o==='impact'){ var hi=(fx.band==='high'||fx.band==='critical'); var bn=fx.file?String(fx.file).split('/').pop():'file'; return '<span class="fx-badge '+(hi?'fxg-mal':'fxg-susp')+'" title="'+lb+'">&#9888; '+uiEsc(bn)+' ('+(hi?'Malicious':'Suspicious')+')</span>'; }
      if(o==='reached') return (String(fx.label||'').toLowerCase().indexOf('admin action')!==-1) ? '<span class="fx-badge fxg-admin" title="'+lb+'">Admin action</span>' : '<span class="fx-badge fxg-reach" title="'+lb+'">Reached app</span>';
      return '';
    }
    function uiBuildRow(i){
      var e=EV[i]; var tr=document.createElement('tr'); tr.className='ui-row'; tr.setAttribute('data-i',String(i));
      var sc=SRCC[e.source]||'var(--muted)', sl=SRC[e.source]||e.source, sb=uiSevBadge(e.severity), cf=String(e.confidence||'');
      var cfc = cf==='compromise' ? 'var(--dang)' : (cf.indexOf('reached')===0 ? 'var(--warn)' : ((cf==='confirmed · blocked'||cf==='confirmed'||cf==='cleared') ? 'var(--good)' : (cf==='likely' ? 'var(--warn)' : 'var(--muted)')));
      var bdg=uiFxBadge(e.fx);
      tr.innerHTML = '<td class="mono" style="font-size:11px;white-space:nowrap">'+(e.ts?uiEsc(uiFmtTs(e.ts)):'—')+'</td>'
        +'<td><span class="ui-chip" style="background:'+sc+'1a;color:'+sc+'">&#9679; '+uiEsc(sl)+'</span></td>'
        +'<td><span class="ui-chip" style="background:'+sb[0]+';color:'+sb[1]+'">'+uiEsc(uiCap(e.severity))+'</span></td>'
        +'<td class="mono col-ip" style="font-size:11px;white-space:nowrap">'+(e.actor_ip?uiEsc(e.actor_ip)+' <button class="ui-copy" data-ip="'+uiEsc(e.actor_ip)+'" type="button" title="copy">&#128203;</button>':'—')+'</td>'
        +'<td style="font-size:12px">'+uiEsc(e.action)+(e.domain?' <span class="meta">· '+uiEsc(e.domain)+'</span>':'')+(bdg?' '+bdg:'')+'</td>'
        +'<td class="mono col-detail ui-detcell">'+(e.target?uiEsc(e.target):'—')+'</td>'
        +'<td class="col-conf"><span style="font-size:10px;font-weight:800;text-transform:uppercase;color:'+cfc+'">&#9679; '+uiEsc(cf)+'</span></td>'
        +'<td><button class="fa-lnk ui-view" type="button" data-i="'+i+'">View details &#8250;</button></td>';
      return tr;
    }
    function uiEsc(s){ return String(s == null ? '' : s).replace(/[&<>"']/g, function(ch){ return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]; }); }
    function uiFmtTs(ts){ if(!ts) return 'unparsed'; var d=new Date(ts*1000); function p(n){return (n<10?'0':'')+n;} return d.getUTCFullYear()+'-'+p(d.getUTCMonth()+1)+'-'+p(d.getUTCDate())+' '+p(d.getUTCHours())+':'+p(d.getUTCMinutes())+':'+p(d.getUTCSeconds()); }
    function uiBuildDet(i){
      var e = EV[i]; if(!e) return null;
      var fx = (e.fx && typeof e.fx === 'object' && e.fx.outcome) ? e.fx : null;
      var h = '<div class="ui-detbox">';
      h += '<div><span class="ui-dk">Time (UTC)</span><span class="mono">'+uiEsc(uiFmtTs(e.ts))+'</span></div>';
      h += '<div><span class="ui-dk">Source</span>'+uiEsc(SRC[e.source]||e.source)+'</div>';
      h += '<div><span class="ui-dk">Severity</span>'+uiEsc(String(e.severity||'').charAt(0).toUpperCase()+String(e.severity||'').slice(1))+'</div>';
      h += '<div><span class="ui-dk">Confidence</span>'+uiEsc(e.confidence)+'</div>';
      h += '<div><span class="ui-dk">Actor IP</span><span class="mono">'+(e.actor_ip?uiEsc(e.actor_ip):'—')+'</span>'+(e.actor_ip?' <button class="fa-lnk ui-copy" data-ip="'+uiEsc(e.actor_ip)+'" type="button" title="Copy IP">&#128203;</button> <a class="fa-lnk" href="index.cgi?page=reports-center&ip='+encodeURIComponent(e.actor_ip)+'">IP report &#8250;</a>':'')+'</div>';
      if (e.domain) h += '<div><span class="ui-dk">Domain</span><span class="mono">'+uiEsc(e.domain)+'</span></div>';
      if (fx) {
        h += '<div><span class="ui-dk">Attack outcome</span>'+uiEsc(fx.label||String(fx.outcome).charAt(0).toUpperCase()+String(fx.outcome).slice(1))+'</div>';
        if (fx.outcome === 'impact' && fx.file) {
          var hi = (fx.band === 'high' || fx.band === 'critical');
          h += '<div><span class="ui-dk">Deep verdict</span><span class="fx-badge '+(hi?'fxg-mal':'fxg-susp')+'">'+uiEsc(String(fx.band||'').charAt(0).toUpperCase()+String(fx.band||'').slice(1))+'</span></div>';
          if (fx.note) h += '<div><span class="ui-dk">Whitelist</span>'+uiEsc(fx.note)+'</div>';
          h += '<div style="grid-column:1/-1"><span class="ui-dk">Impact file</span><span class="mono" style="word-break:break-all">'+uiEsc(fx.file)+'</span></div>';
          h += '<div style="grid-column:1/-1"><span class="ui-dk">Forensic actions</span><span>'
             + '<a class="fa-lnk" style="display:inline-block;border:1px solid var(--brand);color:var(--brand);padding:2px 9px;border-radius:6px" href="index.cgi?page=forensics-audit&fx_user='+encodeURIComponent(UUSER)+'&fx_file='+encodeURIComponent(fx.file)+'">&#128269; Examine file &#8250;</a>'
             + '<a class="fa-lnk" style="display:inline-block;border:1px solid var(--line);color:var(--muted);padding:2px 9px;border-radius:6px;margin-left:6px" href="index.cgi?page=forensics-audit&fx_wl=1&user='+encodeURIComponent(UUSER)+'">&#128272; Whitelist Manager &#8250;</a></span></div>';
        }
      }
      h += '<div style="grid-column:1/-1"><span class="ui-dk">Full detail</span><span class="mono" style="white-space:pre-wrap;word-break:break-all">'+(e.target?uiEsc(e.target):'—')+'</span></div>';
      h += '</div>';
      var tr = document.createElement('tr'); tr.className='ui-detrow'; tr.setAttribute('data-i', String(i)); tr.setAttribute('hidden','');
      var td = document.createElement('td'); td.colSpan = 8; td.innerHTML = h; tr.appendChild(td);
      return tr;
    }
    var acct = <?= json_encode($user, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    var STORY_TXT = <?= json_encode(is_array($story) && function_exists('smpro_ui_story_text') ? smpro_ui_story_text($user, $from, $to, $story) : '', JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE) ?>;
    var rdl=document.getElementById('uiReportDl');
    if(rdl)rdl.addEventListener('click',function(){
      var bl=new Blob([STORY_TXT],{type:'text/plain;charset=utf-8'});var a=document.createElement('a');a.href=URL.createObjectURL(bl);
      a.download='investigation-'+acct+'-'+(new Date().toISOString().slice(0,10))+'.txt';document.body.appendChild(a);a.click();document.body.removeChild(a);
    });
    var PER = 25, page = 0, pages = Math.max(1, Math.ceil(EV.length / PER));
    // ---- filter: which event indices are in view. The KPI cards and the story set it; the table and the
    // grouped view both read it, so a count clicked is a count shown.
    var IDX = EV.map(function(_, i){ return i; });
    function setFilter(fn, label){
      IDX = []; EV.forEach(function(e, i){ if(!fn || fn(e)) IDX.push(i); });
      page = 0; pages = Math.max(1, Math.ceil(IDX.length / PER));
      var fl=document.getElementById('uiFilterLbl'); if(fl){ fl.textContent = label ? ('Filter: '+label+' ('+IDX.length+')') : ''; fl.style.display = label ? '' : 'none'; }
      var fx=document.getElementById('uiFilterClear'); if(fx) fx.style.display = label ? '' : 'none';
      document.querySelectorAll('.ui-kpi').forEach(function(k){ k.classList.toggle('active', label && k.getAttribute('data-go')===currentGo); });
      applyView();
    }
    var currentGo = '';
    function goCard(go){
      currentGo = go;
      var p = go.indexOf(':'), kind = go.slice(0,p), val = go.slice(p+1);
      if(kind==='jump'){ var el=document.getElementById(val); if(el) el.scrollIntoView({behavior:'smooth',block:'start'}); return; }
      if(kind==='group'){ if(gsel){ gsel.value=val; } setFilter(null, ''); if(gsel){ gsel.value=val; applyView(); } return; }
      if(gsel) gsel.value='';
      if(kind==='src'){ if(val==='') { currentGo=''; setFilter(null,''); } else setFilter(function(e){ return e.source===val; }, val.replace('_',' ')); }
      if(kind==='act'){ setFilter(function(e){ return e.action===val; }, val); }
      var w=document.getElementById('uiMainWrap'); if(w && kind!=='group') w.scrollIntoView({behavior:'smooth',block:'start'});
    }
    document.querySelectorAll('.ui-kpi[data-go]').forEach(function(k){
      var h=function(){ goCard(k.getAttribute('data-go')||''); };
      k.addEventListener('click', h); k.addEventListener('keydown', function(e){ if(e.key==='Enter'||e.key===' '){ e.preventDefault(); h(); } });
    });
    document.addEventListener('click', function(e){
      var a=e.target.closest&&e.target.closest('.ui-storyfilter'); if(!a) return; e.preventDefault();
      var ip=a.getAttribute('data-ip'); currentGo='ip:'+ip; if(gsel) gsel.value='';
      setFilter(function(ev){ return ev.actor_ip===ip; }, ip);
      var w=document.getElementById('uiMainWrap'); if(w) w.scrollIntoView({behavior:'smooth',block:'start'});
    });
    var clr=document.getElementById('uiFilterClear'); if(clr) clr.addEventListener('click', function(){ currentGo=''; setFilter(null,''); });
    function showPage(){
      // reset expand state each render so a row expanded on another page returns collapsed + correctly labeled
      // only this page's rows exist in the document: built from EV here, thrown away on the next page
      var tb=document.querySelector('#uiMainWrap table tbody');
      if(tb){ var frag=document.createDocumentFragment(); IDX.slice(page*PER,(page+1)*PER).forEach(function(i){ frag.appendChild(uiBuildRow(i)); }); tb.innerHTML=''; tb.appendChild(frag); }
      var a = page*PER+1, b = Math.min((page+1)*PER, IDX.length);
      var el = document.getElementById('uiPgInfo'); if (el) el.textContent = IDX.length ? ('Showing '+a+' to '+b+' of '+IDX.length+' events') : 'No events match';
      var pn = document.getElementById('uiPgNum'); if (pn) pn.textContent = (page+1)+' / '+pages;
    }
    var pv=document.getElementById('uiPrev'), nx=document.getElementById('uiNext');
    if(pv)pv.addEventListener('click',function(){if(page>0){page--;showPage();}});
    if(nx)nx.addEventListener('click',function(){if(page<pages-1){page++;showPage();}});
    showPage();
    // expand
    document.addEventListener('click',function(e){
      var v=e.target.closest&&e.target.closest('.ui-view'); if(!v)return;
      var i=v.getAttribute('data-i'); var d=document.querySelector('.ui-detrow[data-i="'+i+'"]');
      if(!d){ var row=document.querySelector('.ui-row[data-i="'+i+'"]'); d=uiBuildDet(parseInt(i,10)); if(!row||!d)return; row.parentNode.insertBefore(d, row.nextSibling); }
      if(d.hasAttribute('hidden')){d.removeAttribute('hidden');v.innerHTML='Hide &#8249;';}else{d.setAttribute('hidden','');v.innerHTML='View details &#8250;';}
    });
    // copy IP
    document.addEventListener('click',function(e){var b=e.target.closest&&e.target.closest('.ui-copy');if(!b)return;e.stopPropagation();var ip=b.getAttribute('data-ip');if(navigator.clipboard)navigator.clipboard.writeText(ip);var t=b.innerHTML;b.innerHTML='&#10003;';setTimeout(function(){b.innerHTML=t;},1000);});
    // columns
    var cb=document.getElementById('uiCols'), cm=document.getElementById('uiColsMenu');
    if(cb)cb.addEventListener('click',function(e){e.stopPropagation();if(cm)cm.toggleAttribute('hidden');});
    document.addEventListener('click',function(){if(cm&&!cm.hasAttribute('hidden'))cm.setAttribute('hidden','');});
    if(cm)cm.addEventListener('click',function(e){e.stopPropagation();});
    document.querySelectorAll('.ui-colck').forEach(function(ck){ck.addEventListener('change',function(){
      var col=ck.getAttribute('data-col'); document.querySelectorAll('.col-'+col).forEach(function(c){c.style.display=ck.checked?'':'none';});
    });});
    // recommended
    var rb=document.getElementById('uiRecBtn'), rx=document.getElementById('uiRecBox');
    if(rb&&rx)rb.addEventListener('click',function(){rx.toggleAttribute('hidden');if(!rx.hasAttribute('hidden'))rx.scrollIntoView({behavior:'smooth',block:'nearest'});});
    // CSV
    var btn=document.getElementById('uiCsv');
    if(btn)btn.addEventListener('click',function(){
      var rows=[['time_utc','source','severity','actor_ip','domain','action','detail','confidence','attack_outcome','impact_file','deep_band']];
      EV.forEach(function(e){var t=e.ts?new Date(e.ts*1000).toISOString().replace('T',' ').slice(0,19):'';var fx=e.fx||{};rows.push([t,e.source,e.severity,e.actor_ip,e.domain,e.action,e.target,e.confidence,fx.outcome||'',fx.file||'',fx.band||'']);});
      var csv=rows.map(function(r){return r.map(function(c){c=String(c==null?'':c);if(/^[=+\-@\t\r]/.test(c))c="'"+c;return '"'+c.replace(/"/g,'""')+'"';}).join(',');}).join('\r\n');
      var bl=new Blob([csv],{type:'text/csv'});var a=document.createElement('a');a.href=URL.createObjectURL(bl);a.download='investigation-'+acct+'-'+(new Date().toISOString().slice(0,10))+'.csv';document.body.appendChild(a);a.click();document.body.removeChild(a);
    });
    // ---- Group by / count (read-only aggregation of the same events) ----
    var gsel=document.getElementById('uiGroupBy'), mainWrap=document.getElementById('uiMainWrap'),
        groupWrap=document.getElementById('uiGroupWrap'), groupBody=document.getElementById('uiGroupBody'),
        pager=document.getElementById('uiPager'), thGroup=document.querySelector('.ui-gth');
    function he(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');}
    function fmtTs(ts){return ts?new Date(ts*1000).toISOString().replace('T',' ').slice(0,19):'—';}
    var SEV=[['critical','#b91c1c','crit'],['high','#c2410c','high'],['medium','#b45309','med'],['warning','#a16207','warn'],['notice','#0369a1','notice'],['info','#64748b','info'],['low','#64748b','low'],['deferred','#64748b','deferred']];
    var GLAB={actor_ip:'Actor IP',action:'Action',source:'Source',severity:'Severity',day:'Day'};
    function keyOf(e,by){
      if(by==='actor_ip')return (e.actor_ip==null||e.actor_ip==='')?'—':String(e.actor_ip);
      if(by==='day')return e.ts?new Date(e.ts*1000).toISOString().slice(0,10):'unknown';
      return (e[by]==null||e[by]==='')?'—':String(e[by]);
    }
    function renderGrouped(by){
      var map={};
      IDX.map(function(i){return EV[i];}).forEach(function(e){var k=keyOf(e,by),g=map[k];if(!g){g={key:k,n:0,first:Infinity,last:0,sev:{},ev:[]};map[k]=g;}
        g.n++;if(e.ts){if(e.ts<g.first)g.first=e.ts;if(e.ts>g.last)g.last=e.ts;}
        var sv=(e.severity||'').toLowerCase();g.sev[sv]=(g.sev[sv]||0)+1;g.ev.push(e);});
      var arr=Object.keys(map).map(function(k){return map[k];}).sort(function(a,b){return b.n-a.n||b.last-a.last;});
      if(thGroup)thGroup.textContent=GLAB[by]||'Group';
      var html='';
      arr.forEach(function(g,gi){
        var mix=SEV.map(function(s){var c=g.sev[s[0]];return c?'<span class="ui-sevpill" style="background:'+s[1]+'22;color:'+s[1]+'">'+c+' '+s[2]+'</span>':'';}).join('');
        var kdisp=g.key==='—'?'<span class="meta">(none)</span>':he(g.key);
        var cp=(by==='actor_ip'&&g.key!=='—')?' <button class="ui-copy" data-ip="'+he(g.key)+'" type="button" title="copy">&#128203;</button>':'';
        html+='<tr class="uig-row" data-g="'+gi+'"><td class="mono ui-gkey">'+kdisp+cp+'</td>'
          +'<td><b>'+g.n+'</b> <span class="meta">event'+(g.n===1?'':'s')+'</span></td>'
          +'<td>'+(mix||'<span class="meta">—</span>')+'</td>'
          +'<td class="mono" style="font-size:11px">'+fmtTs(g.first===Infinity?0:g.first)+'</td>'
          +'<td class="mono" style="font-size:11px">'+fmtTs(g.last)+'</td>'
          +'<td><button class="fa-lnk uig-view" type="button" data-g="'+gi+'">View '+g.n+' &#8250;</button></td></tr>';
        var sub='<div class="uig-sub">';
        g.ev.slice(0,200).forEach(function(e){
          sub+='<div class="uig-subrow"><span class="mono uig-t">'+fmtTs(e.ts)+'</span>'
            +'<span class="ui-chip2">'+he(e.source||'')+'</span><span class="ui-chip2">'+he(e.severity||'')+'</span>'
            +'<span class="uig-a">'+he(e.action||'')+(e.domain?' · '+he(e.domain):'')+'</span>'
            +'<span class="mono uig-d">'+he(e.target||'')+'</span></div>';});
        if(g.ev.length>200)sub+='<div class="meta" style="padding:4px 8px">… and '+(g.ev.length-200)+' more (use Download CSV for the full list)</div>';
        sub+='</div>';
        html+='<tr class="uig-det" data-g="'+gi+'" hidden><td colspan="6" style="padding:0">'+sub+'</td></tr>';
      });
      groupBody.innerHTML=html||'<tr><td colspan="6" class="meta" style="padding:14px">No events.</td></tr>';
    }
    function applyView(){var by=gsel?gsel.value:'';
      if(!by){if(mainWrap)mainWrap.hidden=false;if(pager)pager.style.display='';if(groupWrap)groupWrap.hidden=true;showPage();}
      else{if(mainWrap)mainWrap.hidden=true;if(pager)pager.style.display='none';if(groupWrap)groupWrap.hidden=false;renderGrouped(by);}}
    if(gsel)gsel.addEventListener('change',applyView);
    document.addEventListener('click',function(e){var v=e.target.closest&&e.target.closest('.uisi-view');if(!v)return;
      var k=v.getAttribute('data-k'),d=document.querySelector('.uisi-det[data-k="'+k+'"]');if(!d)return;
      if(d.hasAttribute('hidden')){d.removeAttribute('hidden');v.innerHTML='Hide &#8249;';}else{d.setAttribute('hidden','');v.innerHTML='View all &#8250;';}});
    document.addEventListener('click',function(e){var v=e.target.closest&&e.target.closest('.uig-view');if(!v)return;
      var g=v.getAttribute('data-g'),d=document.querySelector('.uig-det[data-g="'+g+'"]');if(!d)return;
      if(d.hasAttribute('hidden')){d.removeAttribute('hidden');v.innerHTML=v.innerHTML.replace('View','Hide');}else{d.setAttribute('hidden','');v.innerHTML=v.innerHTML.replace('Hide','View');}});
  })();
  </script>
  <script>
  (function(){
    var UBTOK=<?= json_encode($ubTok, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT) ?>;
    var go=document.getElementById('ubGo'), box=document.getElementById('ubReport'), st=document.getElementById('ubStatus');
    if(!go)return;
    function he(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
    function band(b){var c={clean:'#64748b',info:'#64748b',low:'#1d4ed8',medium:'#b45309',high:'#c2410c',critical:'#b91c1c'}[b]||'#64748b';return '<span class="ub-band" style="background:'+c+'22;color:'+c+'">'+he(b)+'</span>';}
    function ts(t){return t?new Date(t*1000).toISOString().replace('T',' ').slice(0,19):'—';}
    function post(fd,btn,okd){var old=btn.innerHTML;btn.disabled=true;btn.textContent='…';fd.set('smpro_csrf',UBTOK);
      return fetch(location.pathname+location.search,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'}).then(function(r){return r.json();}).then(function(j){
        if(j&&j.ok){btn.textContent=okd||'✓';btn.style.color='var(--good)';}else{btn.disabled=false;btn.innerHTML=old;}
        if(j&&j.msg)alert((j.ok?'✅ ':'⚠ ')+j.msg);return j;}).catch(function(){btn.disabled=false;btn.innerHTML=old;alert('Request failed.');});}
    var VB={live_compromise:['fxb-red','&#128680;','CONFIRMED live compromise'],planted_inert:['fxb-amber','&#9888;','Shell planted — not yet executed'],attempted_only:['fxb-amber','&#9888;','Attempts accepted — nothing landed yet'],clean:['fxb-green','&#10003;','No breach evidence in window'],error:['fxb-neutral','&#128269;','Could not scan this account']};
    function render(r){
      var v=VB[r.verdict]||VB.error, s=r.sections||{};
      var h='<div class="fx-banner '+v[0]+'" style="margin:10px 0 12px"><div class="fx-banner-ic">'+v[1]+'</div><div class="fx-banner-body"><b>'+v[2]+'</b><p>'+he(r.verdict_reason||'')+'</p>'+(r.truncated?'<p class="meta" style="font-style:italic">Partial — the '+(r.budget_ms_used||0)+'ms budget was reached; some directories were not fully scanned.</p>':'')+'</div></div>';
      var sh=s.shell_hunt||{}, cs=sh.candidates||[];
      h+='<div class="ub-sec"><b>1 &middot; Planted shells</b> <span class="meta">'+cs.length+' suspect file(s), worst '+he(sh.worst_band||'clean')+'</span>';
      if(cs.length){h+='<div class="fa-tablewrap"><table class="smpro-table"><thead><tr><th>File</th><th>Verdict</th><th>Modified</th><th>Owner</th><th></th></tr></thead><tbody>';
        cs.forEach(function(c){h+='<tr><td class="mono" style="word-break:break-all;font-size:11px">'+he(c.path)+(c.in_upload_dir?' <span class="ub-tag">upload dir</span>':'')+'</td><td>'+band(c.band)+(c.nested_chain?' <span class="ub-tag">nested</span>':'')+'</td><td class="mono" style="font-size:11px">'+ts(c.mtime)+'</td><td>'+he(c.owner_ok)+'</td><td><button class="fa-lnk ub-q" data-file="'+he(c.path)+'" style="color:var(--dang)">&#128465; Quarantine</button></td></tr>';});
        h+='</tbody></table></div>';}else h+='<p class="meta">No files with shell content found in the scanned directories since the window start.</p>';
      h+='</div>';
      var ec=s.endpoint_code||{};
      var rmsg={raw_move:'&#9888; Raw move_uploaded_file with NO server-side type check — direct upload / RCE vector',unrestricted_ext:'&#9888; Saves files using the CLIENT-supplied extension with no type whitelist — unrestricted upload',reencoded:'Re-encodes images (Image::make) — strips embedded PHP; still force a safe extension + check any raw handler',validated:'Validates file type server-side (content/MIME check found)',unknown:'No clear upload handler / validation found'}[ec.risk||'unknown']||'';
      h+='<div class="ub-sec"><b>2 &middot; Vulnerable endpoint</b> <span class="meta">'+rmsg+'</span>';
      if((ec.hits||[]).length){h+='<div class="fa-tablewrap"><table class="smpro-table"><tbody>';(ec.hits||[]).slice(0,30).forEach(function(x){h+='<tr><td class="mono" style="font-size:11px;white-space:nowrap">'+he(x.file)+':'+x.line+'</td><td class="mono" style="font-size:11px;word-break:break-all">'+he(x.snippet)+'</td></tr>';});h+='</tbody></table></div>';}else h+='<p class="meta">No obvious upload handler located in the app code.</p>';
      h+='</div>';
      var mp=s.modsec_payload||{}, epc=mp.endpoint_counts||{}, eps=Object.keys(epc);
      h+='<div class="ub-sec"><b>3 &middot; What was sent</b> <span class="meta">'+(mp.accepted_2xx||0)+' accepted 2xx &middot; '+(mp.blocked||0)+' blocked</span>';
      if(eps.length)h+='<p class="meta">Endpoints: '+eps.slice(0,8).map(function(k){return he(k)+' ('+epc[k]+')';}).join(', ')+'</p>';h+='</div>';
      var lv=s.is_live||{}, gb=lv.getback_hits||[];
      h+='<div class="ub-sec ub-decider"><b>4 &middot; Is it live?</b> <span class="meta">'+(lv.executed?'EXECUTED — an uploaded file was requested and ran':((lv.php_exec_allowed||[]).length?'PHP can execute in the upload dir(s) — no execution seen yet':'PHP execution appears blocked in the upload dir(s)'))+'</span>';
      if(gb.length){h+='<div class="fa-tablewrap"><table class="smpro-table"><thead><tr><th>Time</th><th>IP</th><th>Requested</th><th>Status</th></tr></thead><tbody>';gb.slice(0,20).forEach(function(g){h+='<tr><td class="mono" style="font-size:11px">'+ts(g.ts)+'</td><td class="mono">'+he(g.ip)+'</td><td class="mono" style="font-size:11px;word-break:break-all">'+he(g.uri)+'</td><td>'+g.status+'</td></tr>';});h+='</tbody></table></div>';}
      (lv.php_exec_allowed||[]).slice(0,10).forEach(function(d){h+='<div class="meta" style="margin:3px 0">&#9888; '+he(d.dir)+' — '+he(d.reason)+' <button class="fa-lnk ub-h" data-dir="'+he(d.dir)+'" style="color:var(--dang);border:1px solid #f3c4c4;border-radius:6px;padding:1px 8px">&#128274; Disable PHP here</button></div>';});h+='</div>';
      var br=s.blast_radius||{};
      h+='<div class="ub-sec"><b>5 &middot; Blast radius</b> <span class="meta">'+(br.changed_files_count||0)+' file(s) changed in window</span>';
      if((br.authorized_keys||[]).length)h+='<div class="meta">SSH authorized_keys: '+br.authorized_keys.length+(br.authorized_keys.some(function(k){return k.new;})?' <span class="ub-tag" style="color:var(--dang)">NEW in window</span>':'')+'</div>';
      if((br.cron_lines||[]).length)h+='<div class="meta">Cron entries: '+br.cron_lines.length+'</div>';
      if((br.outbound||[]).length)h+='<div class="meta">Established outbound connections: '+br.outbound.length+'</div>';h+='</div>';
      var ap=s.attacker_profile||{};
      h+='<div class="ub-sec"><b>6 &middot; Attackers</b> <span class="meta">'+(ap.total_posts||0)+' upload requests &middot; '+(ap.distinct_ips||0)+' IPs &middot; '+(ap.distinct_subnets||0)+' /16 subnets</span>';
      if((ap.top_ips||[]).length){h+='<div class="fa-tablewrap"><table class="smpro-table"><thead><tr><th>IP</th><th>Hits</th><th>Country / Provider</th><th></th></tr></thead><tbody>';(ap.top_ips||[]).slice(0,15).forEach(function(x){h+='<tr><td class="mono">'+he(x.ip)+'</td><td class="num">'+x.n+'</td><td class="meta">'+he(x.country)+' '+he(x.provider)+(x.datacenter?' <span class="ub-tag">bot</span>':'')+'</td><td><button class="fa-lnk ub-b" data-ip="'+he(x.ip)+'" style="color:var(--dang)">&#128683; Block</button></td></tr>';});h+='</tbody></table></div>';}
      if((ap.top_subnets_16||[]).length){h+='<div class="ub-subnets"><b class="meta">Top /16 subnets — block a whole range only if YOU judge it hostile:</b><br>';(ap.top_subnets_16||[]).slice(0,8).forEach(function(x){h+='<span class="ub-subnet">'+he(x.net)+' <span class="meta">('+x.n+' hits)</span> <button class="fa-lnk ub-bs" data-cidr="'+he(x.net)+'">&#128683; block /16</button></span>';});h+='</div>';}
      h+='</div>';
      box.innerHTML=h; box.hidden=false; box.scrollIntoView({behavior:'smooth',block:'nearest'});
    }
    go.addEventListener('click',function(){
      var fd=new URLSearchParams();fd.set('ub_action','report');fd.set('user',go.getAttribute('data-user'));fd.set('since',go.getAttribute('data-since'));fd.set('smpro_csrf',UBTOK);
      go.disabled=true;if(st)st.textContent='Scanning (read-only, up to ~20s)…';box.hidden=true;
      fetch(location.pathname+location.search,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'}).then(function(r){return r.json();}).then(function(j){
        go.disabled=false;if(st)st.textContent='';if(j&&j.ok&&j.report)render(j.report);else alert('⚠ '+((j&&j.msg)||'Failed'));
      }).catch(function(){go.disabled=false;if(st)st.textContent='';alert('Request failed.');});
    });
    document.addEventListener('click',function(e){
      var q=e.target.closest&&e.target.closest('.ub-q');
      if(q){var f=q.getAttribute('data-file');if(!confirm('Quarantine this file?\n'+f+'\n\nMoves it out of the web tree; a restorable backup is kept.'))return;var fd=new URLSearchParams();fd.set('ub_action','quarantine_shell');fd.set('file',f);post(fd,q,'✓ quarantined');return;}
      var b=e.target.closest&&e.target.closest('.ub-b');
      if(b){var ip=b.getAttribute('data-ip');if(!confirm('Block '+ip+' in the CSF firewall?'))return;var fd=new URLSearchParams();fd.set('ub_action','block_ip');fd.set('ip',ip);post(fd,b,'✓ blocked');return;}
      var hh=e.target.closest&&e.target.closest('.ub-h');
      if(hh){var dd=hh.getAttribute('data-dir');if(!confirm('Disable PHP execution in this upload directory?\n'+dd+'\n\nDrops a reversible .htaccess (php_flag engine off + deny .php). Any existing .htaccess is backed up. Images keep working.'))return;var fd=new URLSearchParams();fd.set('ub_action','disable_php_dir');fd.set('dir',dd);post(fd,hh,'✓ hardened');return;}
      var bs=e.target.closest&&e.target.closest('.ub-bs');
      if(bs){var cd=bs.getAttribute('data-cidr');if(!confirm('Block the ENTIRE subnet '+cd+' in CSF?\n\nThis denies up to 65,536 addresses. Do this only if you judge the whole range hostile — it can block legitimate visitors on that network.'))return;var fd=new URLSearchParams();fd.set('ub_action','block_subnet');fd.set('cidr',cd);post(fd,bs,'✓ blocked');return;}
    });
  })();
  </script>
<?php endif; ?>

<style>
/* The `hidden` attribute must win over the flex/grid/table display rules below, or a toggled element
 * (the Columns menu, the Group table, the Recommendations box, a collapsed detail row) stays stuck
 * open — the UA `[hidden]{display:none}` loses to an author `.class{display:flex}`. */
.ui-colsmenu[hidden],#uiGroupWrap[hidden],#uiRecBox[hidden],#uiMainWrap[hidden],.ui-detrow[hidden]{display:none!important}
.ui-toolbar{display:flex;align-items:center;gap:18px;flex-wrap:wrap;padding:16px 18px;margin:12px 0}
.ui-tbrow{display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end}
.ui-fld{display:flex;flex-direction:column;gap:5px;font-size:11px;letter-spacing:.04em;text-transform:uppercase;color:var(--muted);font-weight:700}
.ui-ro{display:flex;align-items:center;gap:10px;margin-left:auto;padding-left:18px;border-left:1px solid var(--line)}
.ui-ro-ic{font-size:20px;color:var(--brand)}
.ui-ro b{display:block;font-size:13px}
.ui-ro span{font-size:11.5px;color:var(--muted)}
.ui-grid{display:block}
.ui-covbar{display:grid;grid-template-columns:1fr 1fr;gap:0;padding:0;margin-bottom:14px;overflow:hidden}
.ui-covbar .ui-cov{padding:16px 22px}
.ui-covbar .ui-cov+.ui-cov{border-left:1px solid var(--line)}
@media(max-width:760px){.ui-covbar{grid-template-columns:1fr}.ui-covbar .ui-cov+.ui-cov{border-left:0;border-top:1px solid var(--line)}}
.ui-kpis{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:14px}
@media(max-width:1000px){.ui-kpis{grid-template-columns:repeat(3,1fr)}}
@media(max-width:560px){.ui-kpis{grid-template-columns:repeat(2,1fr)}}
.ui-kpi{position:relative;padding:16px 16px 15px;overflow:hidden;transition:transform .16s ease,box-shadow .16s ease}
.ui-kpi:before{content:"";position:absolute;top:0;left:0;right:0;height:3px;background:var(--kpi-c,var(--brand))}
.ui-kpi:hover{transform:translateY(-2px)}
.ui-kpi.active{outline:2px solid var(--kpi-c,var(--brand));outline-offset:-2px}
.ui-kpi:focus-visible{outline:2px solid var(--brand)}
.ui-kpi-ic{width:36px;height:36px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:17px;margin-bottom:11px}
.ui-kpi-n{font-size:27px;font-weight:800;line-height:1;font-variant-numeric:tabular-nums;color:var(--ink)}
.ui-kpi-l{font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:.04em;margin-top:8px;color:var(--ink)}
.ui-kpi-s{font-size:11px;color:var(--muted);margin-top:2px}
.ui-thead{position:relative;padding:14px 18px;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:12px;flex-wrap:wrap;font-weight:800;font-size:14.5px}
.ui-thead .meta{color:var(--muted);font-size:12px;font-weight:500}
.ui-thead-btns{margin-left:auto;display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.ui-sm{padding:7px 13px;font-size:12px;border-radius:9px}
.ui-colswrap{position:relative;display:inline-flex}
.ui-colsmenu{position:absolute;top:calc(100% + 6px);right:0;z-index:30;background:var(--card);border:1px solid var(--line);border-radius:11px;box-shadow:0 12px 28px rgba(2,8,23,.16);padding:10px 14px;display:flex;flex-direction:column;gap:9px;font-size:13px;white-space:nowrap}
.ui-colsmenu label{display:flex;align-items:center;gap:8px;cursor:pointer;font-weight:600}
.ui-tbl thead th{background:var(--brand-bg);font-size:10.5px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);font-weight:800;padding:10px 12px}
.ui-chip{display:inline-block;font-size:11px;font-weight:700;border-radius:20px;padding:2px 9px;white-space:nowrap}
.ui-row:hover{background:var(--brand-bg)}
.ui-view{font-size:12px;white-space:nowrap}
.ui-copy{border:0;background:transparent;cursor:pointer;font-size:11px;opacity:.5}
.ui-copy:hover{opacity:1}
.ui-detcell{font-size:11px;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ui-detbox{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px 22px;padding:15px 18px;background:var(--brand-bg);font-size:12px;border-top:1px solid var(--line)}
.ui-detbox > div{display:flex;flex-direction:column;gap:2px}
.ui-dk{font-size:10px;text-transform:uppercase;letter-spacing:.03em;color:var(--muted);font-weight:700}
.ui-pager{display:flex;align-items:center;justify-content:space-between;padding:11px 16px;border-top:1px solid var(--line)}
.ui-pg-btns{display:flex;align-items:center;gap:8px}
.ui-pgnum{font-size:12px;color:var(--muted);min-width:52px;text-align:center;font-weight:600}
/* Group by / count view */
.ui-grp{display:inline-flex;align-items:center;gap:6px}
.ui-gsel{border:1px solid var(--line);background:var(--card);color:var(--ink);border-radius:9px;padding:7px 10px;font-size:12px;font-weight:600;cursor:pointer}
.ui-gtbl thead th{background:var(--brand-bg);font-size:10.5px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);font-weight:800;padding:10px 12px}
.uig-row:hover{background:var(--brand-bg)}
.ui-gkey{font-size:12px;font-weight:600}
.ui-sevpill{display:inline-block;font-size:10px;font-weight:800;border-radius:20px;padding:1px 7px;margin:1px}
.uig-sub{background:var(--brand-bg);padding:6px 12px}
.uig-subrow{display:flex;gap:10px;align-items:baseline;padding:4px 0;border-bottom:1px dashed var(--line);flex-wrap:wrap}
.uig-subrow:last-child{border-bottom:0}
.uig-t{font-size:11px;color:var(--muted);white-space:nowrap}
.ui-chip2{font-size:10px;font-weight:700;text-transform:uppercase;background:var(--line);border-radius:10px;padding:1px 6px;color:var(--muted);white-space:nowrap}
.uig-a{font-size:12px;font-weight:600}
.uig-d{font-size:11px;color:var(--muted);word-break:break-all;flex:1 1 220px}
.ui-empty{padding:40px 20px;text-align:center;color:var(--muted)}
.ui-empty b{color:var(--ink);display:block;margin:8px 0 4px}
.ui-empty p{font-size:12.5px;max-width:520px;margin:0 auto}
.ui-insight{display:flex;align-items:center;gap:16px;justify-content:space-between;flex-wrap:wrap;padding:16px 20px;margin:14px 0;border-left:3px solid var(--brand)}
.ui-insight p{margin:4px 0 0;font-size:13px;color:var(--muted)}
.ui-recs{padding:14px 18px;margin:0 0 14px;border-left:3px solid #f59e0b}
.ui-recs ul{margin:8px 0 0;padding-left:18px;font-size:13px;line-height:1.7}
.ui-cov-h{display:block;font-size:12px;font-weight:800;text-transform:uppercase;letter-spacing:.04em;margin-bottom:11px}
.ui-cov ul{margin:0;padding-left:0;list-style:none;font-size:12.5px;line-height:1.5}
.ui-cov-yes li,.ui-cov-no li{padding-left:22px;position:relative;margin-bottom:8px}
.ui-cov-yes li:before{content:"\2713";position:absolute;left:0;color:var(--good);font-weight:800}
.ui-cov-no li:before{content:"\2717";position:absolute;left:0;color:var(--dang);font-weight:800}
/* Forensic enrichment — verdict banner, extra KPI column, per-row badges */
.fx-banner{display:flex;align-items:center;gap:14px;padding:15px 18px;margin:12px 0 14px;border-left:4px solid var(--muted)}
.fx-banner-ic{font-size:26px;line-height:1;flex:0 0 auto}
.fx-banner-body{flex:1;min-width:0}
.fx-banner-body b{font-size:14.5px;display:block;color:var(--ink)}
.fx-banner-body p{margin:3px 0 0;font-size:12.5px;color:var(--muted)}
.fx-banner .tp-btn{white-space:nowrap;flex:0 0 auto}
.fx-modsec{color:#b45309!important;font-weight:600}
.fxb-red{border-left-color:var(--dang);background:var(--dang-bg)}
.fxb-red .fx-banner-ic{color:var(--dang)}
.fxb-amber{border-left-color:#d97706;background:var(--warn-bg)}
.fxb-amber .fx-banner-ic{color:#d97706}
.fxb-green{border-left-color:var(--good);background:var(--good-bg)}
.fxb-green .fx-banner-ic{color:var(--good)}
.fxb-neutral{border-left-color:var(--brand);background:var(--brand-bg)}
.fxb-neutral .fx-banner-ic{color:var(--brand)}
.ui-kpis.fx6{grid-template-columns:repeat(6,1fr)}
@media(max-width:1000px){.ui-kpis.fx6{grid-template-columns:repeat(3,1fr)}}
@media(max-width:560px){.ui-kpis.fx6{grid-template-columns:repeat(2,1fr)}}
.fx-badge{display:inline-block;font-size:10px;font-weight:800;border-radius:20px;padding:1px 8px;margin-left:6px;white-space:nowrap;vertical-align:middle;letter-spacing:.02em}
.fxg-block{background:var(--good-bg);color:var(--good)}
.fxg-reach{background:#fff7ed;color:#b45309}
.fxg-admin{background:#f1f5f9;color:#475569}
.fxg-susp{background:#fff7ed;color:#b45309}
.fxg-mal{background:var(--dang-bg);color:var(--dang)}
/* the timeline table must scroll horizontally inside its card on narrow screens (self-contained — do not
   depend on another module's .fa-tablewrap rule) */
.fa-tablewrap{overflow-x:auto}
/* dark-mode surfaces for the hardcoded-color badges so they don't glare on a dark table */
html[data-theme=dark] .fxg-reach,html[data-theme=dark] .fxg-susp{background:#3a2a12;color:#fbbf24}
html[data-theme=dark] .fxg-admin{background:#1e293b;color:#94a3b8}
/* Upload-breach forensics card + report */
.ub-card{padding:16px 18px;margin:12px 0;border-left:3px solid #7c3aed}
.ub-head{margin-bottom:10px}
.ub-head b{font-size:14.5px;display:block}
.ub-head .meta{font-size:12px;color:var(--muted)}
.ub-go{margin-top:2px}
.ub-status{margin-left:10px;font-style:italic}
.ub-report{margin-top:14px}
.ub-sec{border-top:1px solid var(--line);padding:12px 0 4px;margin-top:10px}
.ub-sec>b{font-size:13px}
.ub-sec .fa-tablewrap{margin-top:8px;overflow-x:auto}
.ub-decider{background:var(--brand-bg);border-radius:10px;padding:12px 14px;border-top:0;margin-top:12px}
.ub-band{display:inline-block;font-size:10px;font-weight:800;border-radius:12px;padding:1px 8px;text-transform:uppercase;letter-spacing:.02em}
.ub-tag{display:inline-block;font-size:9.5px;font-weight:800;background:var(--line);color:var(--muted);border-radius:8px;padding:0 6px;text-transform:uppercase}
.ub-subnets{margin-top:10px;font-size:12px;line-height:2}
.ub-subnet{display:inline-block;background:var(--brand-bg);border:1px solid var(--line);border-radius:8px;padding:2px 8px;margin:2px 4px 2px 0;font-family:ui-monospace,Consolas,monospace}
.ub-subnet .fa-lnk{color:var(--dang);margin-left:4px}
/* ---- navigator / collapsible cards (pattern: firewall-status.php) ---- */
/* .fw-kpis / .fw-nav / .fw-collapse / pager styles: shared, in includes/layout.php */
.tp-th{display:flex;align-items:center;gap:10px;padding:12px 16px;border-bottom:1px solid var(--line);flex-wrap:wrap}
.tp-th .meta{color:var(--muted);font-size:12px}
.ui-kpi.good{--kpi-c:var(--good)}.ui-kpi.good .ui-kpi-ic{background:var(--good-bg);color:var(--good)}
.ui-kpi.warn{--kpi-c:var(--warn)}.ui-kpi.warn .ui-kpi-ic{background:var(--warn-bg);color:var(--warn)}
.ui-kpi.dang{--kpi-c:var(--dang)}.ui-kpi.dang .ui-kpi-ic{background:var(--dang-bg);color:var(--dang)}
.ui-kpi.brand{--kpi-c:var(--brand)}.ui-kpi.brand .ui-kpi-ic{background:var(--brand-bg);color:var(--brand)}
.ui-kpi.muted{--kpi-c:var(--muted)}.ui-kpi.muted .ui-kpi-ic{background:var(--line);color:var(--muted)}
.ui-covbar{display:block}.card.ui-covbar.fw-open>.fw-collapse{display:grid;grid-template-columns:1fr 1fr}
@media(max-width:760px){.card.ui-covbar.fw-open>.fw-collapse{grid-template-columns:1fr}}
.ub-head .fw-chev{float:left;margin-right:6px}.ub-head .gl-fold{margin-top:4px}.ub-head .gl-fold>summary{font-size:12px}
</style>
<script>
/* Deleted-files evidence. Everything the server found is rendered here; nothing is inferred in the browser.
   A source that could not be read is shown as loudly as a source that was, because "not seen" and "did not
   happen" are opposite findings and the difference is the whole point of this panel. */
(function(){
  // Its own token: the upload-breach block above declares UBTOK inside its own closure, so it is not visible here.
  var UBTOK=<?= json_encode($ubTok, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT) ?>;
  var b=document.getElementById('delGo'); if(!b) return;
  var out=document.getElementById('delReport'), st=document.getElementById('delStatus');
  function esc(x){return String(x==null?'':x).replace(/[<>&"]/g,function(c){return {'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;'}[c];});}
  function when(ts){ if(!ts) return '—'; try{ return new Date(ts*1000).toLocaleString('en-GB',{dateStyle:'medium',timeStyle:'medium'}); }catch(e){ return String(ts); } }

  b.addEventListener('click',function(){
    var user=b.getAttribute('data-user')||'';
    if(!user){ out.hidden=false; out.innerHTML='<b>Pick an account first.</b>'; return; }
    var days=document.getElementById('delDays').value;
    var ot=b.innerHTML; b.disabled=true; b.innerHTML='Collecting…';
    st.textContent='Reading the panel, FTP, SSH and plugin logs, and walking the account\u2019s directories. This takes a moment.';
    out.hidden=false; out.innerHTML='<span class="meta">Working…</span>';
    var fd=new URLSearchParams();
    fd.set('ui_action','deleted'); fd.set('user',user); fd.set('days',days); fd.set('smpro_csrf',UBTOK);
    fetch('index.cgi?page=user-investigation',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString()})
      .then(function(r){return r.json();}).then(function(j){
        b.disabled=false; b.innerHTML=ot; st.textContent='';
        if(!j||!j.ok){ out.innerHTML='<b style="color:var(--dang)">Could not collect.</b> <span class="meta">'+esc(j&&j.msg)+'</span>'; return; }
        var h='';

        /* the finding, in one sentence */
        h+='<div style="padding:10px 12px;border-radius:9px;margin-bottom:10px;background:rgba(127,127,127,.08)"><b>'+esc(j.verdict_text)+'</b></div>';

        /* what was searched — first, not last */
        h+='<div style="margin:10px 0 4px"><b>Sources searched</b></div><div style="font-size:12.5px;line-height:1.7">';
        (j.sources||[]).forEach(function(sc){
          var col = sc.state==='read' ? '#059669' : (sc.state==='unreadable' ? '#dc2626' : 'var(--muted)');
          var lbl = sc.state==='read' ? 'read' : (sc.state==='unreadable' ? 'COULD NOT READ' : sc.state);
          h+='<div><span style="color:'+col+';font-weight:800">'+esc(lbl)+'</span> &middot; '+esc(sc.name)
            +(sc.path?' <span class="meta">'+esc(sc.path)+'</span>':'')
            +(sc.why?' <span class="meta">— '+esc(sc.why)+'</span>':'')+'</div>';
        });
        h+='</div>';

        /* who */
        if((j.actors||[]).length){
          h+='<div style="margin:14px 0 4px"><b>Addresses behind these events</b></div>';
          h+='<div style="overflow-x:auto"><table class="smpro-table"><thead><tr><th>Address</th><th>Where it is</th><th>Events</th><th>First</th><th>Last</th><th>Standing</th></tr></thead><tbody>';
          j.actors.forEach(function(a){
            var flags=[];
            flags.push(a.known?'<span style="color:#059669">signed in before</span>':'<span style="color:#dc2626;font-weight:700">never signed in from here before</span>');
            if(a.machine) flags.push('rented server');
            if(a.blocked) flags.push('blocked');
            if(a.allowed) flags.push('allow-listed');
            h+='<tr><td class="ipmono">'+esc(a.ip)+'</td>'
              +'<td>'+esc([a.country,a.provider,a.asn].filter(Boolean).join(' · ')||'not known')+'</td>'
              +'<td><b>'+a.n+'</b> <span class="meta">'+esc((a.sources||[]).join(', '))+'</span></td>'
              +'<td>'+esc(when(a.first))+'</td><td>'+esc(when(a.last))+'</td>'
              +'<td>'+flags.join(' · ')+'</td></tr>';
            if((a.activity||[]).length){
              h+='<tr><td colspan="6"><div class="meta">Everything else this address did on the server: '
                +a.activity.slice(0,12).map(function(x){return esc(when(x.ts))+' '+esc(x.source)+' '+esc(x.result)+(x.user?' ('+esc(x.user)+')':'');}).join(' &middot; ')
                +(a.activity.length>12?' &hellip; and '+(a.activity.length-12)+' more':'')+'</div></td></tr>';
            }
          });
          h+='</tbody></table></div>';
        }

        /* what */
        if((j.rows||[]).length){
          h+='<div style="margin:14px 0 4px"><b>The records themselves</b></div>';
          h+='<div style="overflow-x:auto"><table class="smpro-table"><thead><tr><th>When</th><th>Source</th><th>Who</th><th>Address</th><th>What</th><th>Target</th><th>Confidence</th></tr></thead><tbody>';
          j.rows.slice(0,200).forEach(function(r){
            h+='<tr><td>'+esc(when(r.ts))+'</td><td>'+esc(r.source)+'</td><td>'+esc(r.actor)+'</td>'
              +'<td class="ipmono">'+esc(r.actor_ip)+'</td><td>'+esc(r.action)+'</td>'
              +'<td style="word-break:break-all">'+esc(r.target)+'</td>'
              +'<td>'+(r.confidence==='confirmed'?'<b style="color:#dc2626">confirmed</b>':'<span class="meta">circumstantial</span>')+'</td></tr>';
          });
          h+='</tbody></table></div>';
          if(j.rows.length>200) h+='<div class="meta">Showing the newest 200 of '+j.rows.length+'.</div>';
        }

        /* mail: its own trail, and the one where the server may know the count but not the names */
        var ml=j.mail||{};
        if(ml.sources){
          var mlog=ml.maillog||{};
          if(!mlog.on){
            h+='<div style="margin:14px 0 4px;padding:9px 11px;border-radius:8px;border:1px solid rgba(180,83,9,.35);background:rgba(180,83,9,.07);font-size:12.5px;line-height:1.65">'
              +'<b>&#9888; Mail: this server records how many, not which.</b> Dovecot logs the number of messages each '
              +'IMAP/POP session removed, which is enough to name the session, the mailbox owner, the address and the '
              +'time &mdash; but naming the individual messages needs the <span class="ipmono">mail_log</span> plugin, '
              +'which is not enabled here. Enabling it makes future deletions report the mailbox, subject and sender per '
              +'message. It cannot recover what is already gone: it changes what gets recorded from now on.</div>';
          } else {
            h+='<div style="margin:14px 0 4px;font-size:12.5px;color:#059669"><b>Mail: per-message logging is on</b> '
              +'<span class="meta">('+esc(mlog.where)+') &mdash; individual messages are named below where they were removed.</span></div>';
          }
          /* the two losses people actually report: a folder, and a whole address */
          var fl=ml.folders||{}, ac=ml.accounts||{};
          if((fl.named||[]).length){
            h+='<div style="margin:12px 0 4px"><b>Mail folders deleted</b> <span class="meta">named by Dovecot, with the session behind them</span></div>';
            h+='<div style="overflow-x:auto"><table class="smpro-table"><thead><tr><th>When</th><th>Folder</th><th>Mailbox</th><th>Address</th></tr></thead><tbody>';
            fl.named.forEach(function(f){ h+='<tr><td>'+esc(when(f.ts))+'</td><td><b>'+esc(f.folder)+'</b></td><td>'+esc(f.mailbox)+'</td><td class="ipmono">'+esc(f.ip)+'</td></tr>'; });
            h+='</tbody></table></div>';
          }
          if((fl.missing||[]).length){
            h+='<div style="margin:12px 0 4px"><b>Folders the mailbox still lists but that are gone from disk</b> '
              +'<span class="meta">every folder a mail client subscribed to is named in the mailbox\u2019s own list, so a name still '
              +'listed with no folder behind it is a folder that used to exist. This names it without dating it: the only '
              +'timestamp available is when that list last changed.</span></div>';
            h+='<div style="overflow-x:auto"><table class="smpro-table"><thead><tr><th>Folder</th><th>Mailbox</th><th>Folder list last changed</th><th></th></tr></thead><tbody>';
            fl.missing.slice(0,60).forEach(function(f){
              h+='<tr><td><b>'+esc(f.folder)+'</b></td><td>'+esc(f.mailbox)+'</td><td>'+esc(when(f.list_changed))+'</td>'
                +'<td>'+(f.in_window?'<b style="color:#dc2626">changed inside the window you asked about</b>':'<span class="meta">changed outside the window</span>')+'</td></tr>';
            });
            h+='</tbody></table></div>';
          }
          if((ac.deleted||[]).length){
            h+='<div style="margin:12px 0 4px"><b>Email accounts deleted</b> <span class="meta">cPanel puts its arguments in the request line, so unlike a file delete this one names what it removed</span></div>';
            h+='<div style="overflow-x:auto"><table class="smpro-table"><thead><tr><th>When</th><th>Address</th><th>What</th><th>By</th><th>From</th></tr></thead><tbody>';
            ac.deleted.forEach(function(a){
              h+='<tr><td>'+esc(when(a.ts))+'</td><td><b>'+esc(a.address||'(not in this log line)')+'</b></td><td>'+esc(a.kind)+'</td>'
                +'<td>'+esc(a.actor)+'</td><td class="ipmono">'+esc(a.ip)+'</td></tr>';
            });
            h+='</tbody></table></div>';
          }
          if((ac.orphan_maildirs||[]).length){
            h+='<div style="margin:12px 0 4px"><b>Addresses whose mail is still on disk but which no longer exist</b> '
              +'<span class="meta">the address is gone from the account\u2019s own list while its mail directory is still there \u2014 '
              +'so the mailbox was deleted and this is everything it held, still recoverable</span></div>';
            h+='<div style="overflow-x:auto"><table class="smpro-table"><thead><tr><th>Address</th><th>Its mail is still here</th><th>Last changed</th><th></th></tr></thead><tbody>';
            ac.orphan_maildirs.slice(0,60).forEach(function(o){
              h+='<tr><td><b>'+esc(o.address)+'</b></td><td class="ipmono">'+esc(o.path)+'</td><td>'+esc(when(o.ts))+'</td>'
                +'<td>'+(o.in_window?'<b style="color:#dc2626">inside the window</b>':'<span class="meta">outside the window</span>')+'</td></tr>';
            });
            h+='</tbody></table></div>';
          }
          if((ml.trash||[]).length){
            h+='<div style="margin:10px 0 4px"><b>Still in a mailbox Trash</b> <span class="meta">a webmail delete usually moves the message here first, so these may simply be recoverable</span></div>';
            h+='<div style="font-size:12.5px;line-height:1.7">'+ml.trash.slice(0,25).map(function(f){return esc(when(f.ts))+' &middot; '+f.size+' bytes &middot; <span class="ipmono">'+esc(f.path)+'</span>';}).join('<br>')+'</div>';
          }
        }

        /* the filesystem, which still speaks after the files are gone */
        var fs=j.filesystem||{};
        if((fs.dirs||[]).length){
          h+='<div style="margin:14px 0 4px"><b>Directories that changed in this window</b> <span class="meta">a directory\u2019s timestamp is the moment its last entry was created, renamed or removed &mdash; so it dates a deletion even when no log names one</span></div>';
          h+='<div style="font-size:12.5px;line-height:1.7">'+fs.dirs.slice(0,25).map(function(d){return esc(when(d.ts))+' &middot; <span class="ipmono">'+esc(d.dir)+'</span>';}).join('<br>')+'</div>';
        }
        if((fs.trash||[]).length){
          h+='<div style="margin:14px 0 4px"><b>Still in the account\u2019s trash</b> <span class="meta">cPanel\u2019s File Manager moves to '+esc(fs.trash_dir)+' rather than unlinking, so these may be recoverable as they are</span></div>';
          h+='<div style="font-size:12.5px;line-height:1.7">'+fs.trash.slice(0,25).map(function(f){return esc(when(f.ts))+' &middot; '+f.size+' bytes &middot; <span class="ipmono">'+esc(f.path)+'</span>';}).join('<br>')+'</div>';
        }

        out.innerHTML=h;
      }).catch(function(){ b.disabled=false; b.innerHTML=ot; st.textContent=''; out.innerHTML='<b style="color:var(--dang)">Request failed.</b>'; });
  });
})();
</script>
<script>
(function(){
  /* collapsible section cards + sticky navigator (pattern: modules/firewall-status.php). The header of every
     card is a real toggle (role=button, keyboard), the open/closed choice is remembered per section. */
  var KEY='smpro:user-investigation:open', HSEL='.smpro-main .card > .tp-th, .smpro-main .card > .ui-thead, .smpro-main .card > .ui-tl-head, .smpro-main .card > .ub-head', PFX='ui', open={};
  try{ open=JSON.parse(localStorage.getItem(KEY)||'{}')||{}; }catch(err){ open={}; }
  function remember(){ try{ localStorage.setItem(KEY, JSON.stringify(open)); }catch(err){} }
  function toggleOf(card){ for(var i=0;i<card.children.length;i++){ if(card.children[i].classList.contains('fw-toggle')) return card.children[i]; } return null; }
  function setOpen(card,on){ var th=toggleOf(card); if(!th) return; card.classList.toggle('fw-open',on); th.setAttribute('aria-expanded',on?'true':'false'); open[th.getAttribute('data-fold')]=on; }
  function openCard(id,scroll){ var card=document.getElementById(id); if(!card) return;
    if(toggleOf(card)&&!card.classList.contains('fw-open')){ setOpen(card,true); remember(); }
    if(scroll){ card.style.scrollMarginTop='120px'; card.scrollIntoView({behavior:'smooth',block:'start'}); } }
  function init(){
    if(!document.getElementById(PFX+'Nav')) return;   /* only on a page that carries this navigator */
    var heads=document.querySelectorAll(HSEL), i;
    for(i=0;i<heads.length;i++){ (function(th,idx){
      var card=th.parentElement; if(!card||th.classList.contains('fw-toggle')) return;
      var body=document.createElement('div'); body.className='fw-collapse';
      while(th.nextSibling){ body.appendChild(th.nextSibling); }
      card.appendChild(body);
      th.classList.add('fw-toggle');
      if(!th.querySelector('.fw-chev')) th.insertAdjacentHTML('afterbegin','<span class="fw-chev">&#9656;</span> ');
      var lab=th.querySelector('b');
      var id=((lab?lab.textContent:th.textContent)||'').replace(/\s+/g,' ').replace(/^\s+|\s+$/g,'').slice(0,60) || ('card'+idx);
      th.setAttribute('data-fold',id);
      var isOpen=Object.prototype.hasOwnProperty.call(open,id)?!!open[id]:true;
      card.classList.toggle('fw-open',isOpen);
      th.setAttribute('role','button'); th.setAttribute('tabindex','0'); th.style.cursor='pointer'; th.setAttribute('aria-expanded',isOpen?'true':'false');
      function toggle(){ setOpen(card,!card.classList.contains('fw-open')); remember(); }
      th.addEventListener('click',function(e){ if(e.target.closest('a,button,input,select,label,textarea,details,summary')) return; toggle(); });
      th.addEventListener('keydown',function(e){ if(e.target!==th) return; if(e.key===' '||e.key==='Enter'||e.key==='Spacebar'){ e.preventDefault(); toggle(); } });
    })(heads[i],i); }
    var gos=document.querySelectorAll('.fw-nav [data-go], .fw-kpis [data-go]');
    for(i=0;i<gos.length;i++){ (function(a){ a.addEventListener('click',function(e){ e.preventDefault(); var id=a.getAttribute('data-go'); openCard(id,true);
      var ch=document.querySelectorAll('.fw-nav a'); for(var j=0;j<ch.length;j++) ch[j].classList.toggle('on', ch[j].getAttribute('data-go')===id);
      try{ history.replaceState(null,'','#'+id); }catch(err){} }); })(gos[i]); }
    function all(on){ var cs=document.querySelectorAll('.smpro-main .card'); for(var j=0;j<cs.length;j++){ if(toggleOf(cs[j])) setOpen(cs[j],on); } remember(); }
    var oa=document.getElementById(PFX+'OpenAll'), ca=document.getElementById(PFX+'CloseAll');
    if(oa) oa.addEventListener('click',function(){ all(true); });
    if(ca) ca.addEventListener('click',function(){ all(false); });
    if(location.hash && document.getElementById(location.hash.slice(1))) setTimeout(function(){ openCard(location.hash.slice(1), true); },150);
    /* a KPI that jumps to a section, and the story's "show these rows" links, must land on an OPEN card */
    var jk=document.querySelectorAll('.ui-kpi[data-go^="jump:"]'), j;
    for(j=0;j<jk.length;j++){ (function(k){ k.addEventListener('click',function(){ openCard(k.getAttribute('data-go').slice(5), false); }); })(jk[j]); }
    document.addEventListener('click',function(e){ if(e.target.closest && e.target.closest('.ui-storyfilter')) openCard('ui-timeline', false); });
  }
  window[PFX+'OpenCard']=openCard;
  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',init); else init();
})();
</script>
<?php smpro_layout_footer(); ?>
