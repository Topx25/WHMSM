<?php
/**
 * modules/compromise-check.php - Compromise Check: the marks a break-in leaves, at server level and per account.
 * Reads are in includes/compcheck.php (what is looked at and why); the fixes and the scheduled scan are in
 * includes/ccfix.php. Every fix backs up first and is audited; the page never runs one without a CSRF token.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }
require_once SMPRO_INCLUDES . '/compcheck.php';
require_once SMPRO_INCLUDES . '/ccfix.php';
smpro_require_root();

$reqMethod = (string)($_SERVER['REQUEST_METHOD'] ?? 'GET');
$act = (string)($_POST['cc_action'] ?? '');

/* ---------- POST: a fix (JSON answer) ---------- */
if ($reqMethod === 'POST' && $act === 'fix') {
    smpro_require_valid_csrf('cc_fix');
    header('Content-Type: application/json');
    $op = (string)($_POST['op'] ?? ''); $args = [];
    foreach ((array)($_POST['args'] ?? []) as $k => $v) if (preg_match('/^[a-z_]{1,20}$/', (string)$k)) $args[$k] = (string)$v;
    echo json_encode(smpro_cx_apply($op, $args, smpro_current_actor()));
    exit;
}
/* ---------- POST: the schedule ---------- */
if ($reqMethod === 'POST' && in_array($act, ['sched_save', 'sched_run'], true)) {
    smpro_require_valid_csrf('cc_sched');
    if ($act === 'sched_save') {
        $c = smpro_cx_sched_cfg();
        $c['enabled'] = !empty($_POST['enabled']);
        $c['every'] = (string)($_POST['every'] ?? 'daily'); $c['hour'] = (int)($_POST['hour'] ?? 4); $c['dow'] = (int)($_POST['dow'] ?? 1);
        $c['scope'] = (string)($_POST['scope'] ?? 'both'); $c['days'] = (int)($_POST['days'] ?? 30); $c['tell'] = (string)($_POST['tell'] ?? 'issues');
        $c['users'] = array_values(array_unique(array_filter(array_map('trim', preg_split('/[\s,;]+/', (string)($_POST['users'] ?? ''))))));
        $c = smpro_cx_sched_normalize($c);
        $ok = smpro_cx_sched_save($c);
        smpro_audit('compromise_sched_save', ['enabled' => $c['enabled'] ? 1 : 0, 'every' => $c['every'], 'hour' => $c['hour'], 'scope' => $c['scope'], 'users' => count($c['users']), 'ok' => $ok ? 1 : 0]);
        $flash = $ok ? ($c['enabled'] ? 'Schedule saved and the cron is installed.' : 'Schedule saved (off); the cron is removed.') : 'The schedule could not be saved (or the cron could not be written) - nothing is scheduled.';
        $flashOk = $ok;
    } else {
        $rep = smpro_cx_run_scheduled(smpro_cx_sched_cfg(), true);
        $flash = 'Ran now: ' . smpro_h($rep['summary']['critical'] . ' critical, ' . $rep['summary']['warning'] . ' warning; ' . $rep['summary']['flagged_accounts'] . ' account(s) with ' . $rep['summary']['doors'] . ' door(s)') . '. Stored as report ' . date('Ymd_His', $rep['at']) . '.';
        $flashOk = true;
    }
}

$days = (int)($_GET['days'] ?? 30); if (!in_array($days, [7, 30, 90, 365], true)) $days = 30;
$usersIn = array_values(array_unique(array_filter(array_map(fn($u) => preg_replace('/[^a-zA-Z0-9._-]/', '', $u), preg_split('/[\s,;]+/', (string)($_GET['user'] ?? ''))))));
$showAll = !empty($_GET['all']);
$repId = preg_replace('/[^0-9_]/', '', (string)($_GET['report'] ?? ''));

if (isset($_GET['csv'])) {
    $scan = smpro_cc_scan_accounts($days, 50);
    header('Content-Type: text/csv; charset=utf-8'); header('Content-Disposition: attachment; filename="compromise-check-' . date('Ymd-Hi') . '.csv"');
    $fh = fopen('php://output', 'w'); fputcsv($fh, ['account', 'domain', 'kind', 'finding', 'when', 'detail', 'flagged']);
    foreach ($scan['rows'] as $r) foreach ($r['findings'] as $f) fputcsv($fh, [$r['user'], $r['domain'], $f['kind'], $f['label'], $f['when'] ? date('Y-m-d H:i', $f['when']) : '', $f['detail'], $f['flag'] ? 'yes' : '']);
    fclose($fh); exit;
}

$allAccts = smpro_cc_accounts();
$stored = $repId !== '' ? smpro_cx_report_get($repId) : null;
if ($stored) {
    $server = (array)$stored['server']; $scan = ['rows' => (array)$stored['accounts'], 'scanned' => (int)$stored['scanned'], 'partial' => !empty($stored['partial']), 'took' => '-']; $rows = (array)$stored['accounts']; $days = (int)$stored['days'];
} else {
    $server = smpro_cc_server_checks();
    if ($usersIn) {
        $since = time() - $days * 86400; $rows = [];
        foreach ($usersIn as $u) if (isset($allAccts[$u])) $rows[] = smpro_cc_account_doors($allAccts[$u], $since);
        $scan = ['rows' => $rows, 'scanned' => count($rows), 'partial' => false, 'took' => '-'];
    } else {
        $scan = smpro_cc_scan_accounts($days, 40); $rows = (array)$scan['rows'];
    }
}
if (function_exists('smpro_audit')) smpro_audit('compromise_check_view', ['days' => $days, 'users' => $usersIn, 'report' => $repId]);

$crit = count(array_filter($server, fn($c) => $c['status'] === 'critical'));
$warn = count(array_filter($server, fn($c) => $c['status'] === 'warning'));
$flaggedRows = array_values(array_filter($rows, fn($r) => $r['flags'] > 0));
$quietRows   = array_values(array_filter($rows, fn($r) => $r['flags'] === 0 && $r['findings']));
$doorCounts = [];
foreach ($flaggedRows as $r) foreach ($r['findings'] as $f) if ($f['flag']) $doorCounts[$f['kind']] = ($doorCounts[$f['kind']] ?? 0) + 1;
$KIND = ['ftp' => ['FTP sub-account', '#6d28d9'], 'forwarder' => ['Forwarder', '#b45309'], 'cron' => ['Cron', '#0891b2'], 'sshkey' => ['SSH key', '#b91c1c'],
         'contact' => ['Contact e-mail', '#b91c1c'], 'mailbox' => ['Mailbox', '#0f766e'], 'token' => ['API token', '#b91c1c'], 'shellrc' => ['Shell start-up', '#b91c1c']];
// What each kind of door IS, in one sentence - the chip alone ("Shell start-up") tells an operator nothing.
$KIND_WHAT = [
    'ftp'       => 'A second FTP login into the account, with its own password and its own folder, so it keeps working after the main password is changed. Removing it deletes the LOGIN only - the files stay where they are.',
    'forwarder' => 'A rule that sends a copy of every mail for an address to another address. The usual way a break-in keeps reading password-reset mail after it is locked out.',
    'cron'      => 'A scheduled command of the account. A line that fetches or decodes code re-installs the break-in minutes after it is cleaned.',
    'sshkey'    => 'A key authorised for SSH/SFTP login into the account. A key is not touched by a password change.',
    'contact'   => 'The address cPanel sends the mail of this account to - "forgot password" links above all. Changed to an address the intruder holds, every reset you do lands in their inbox, so this one is read before anything else is fixed.',
    'mailbox'   => 'A mailbox created in the account: a way back in, and a place to send spam from.',
    'token'     => 'An API token: a password for the API that no password change rotates and that usually never expires. Revoke removes it; Disable gives it an expiry in the past so it opens nothing but keeps its name and history (for an account token this goes through the store cPanel itself writes, and is read back to confirm).',
    'shellrc'   => 'A line added to the shell start-up files of the account (~/.bashrc, ~/.bash_profile, ~/.profile). Those run on EVERY shell the account opens - including cron and SSH - so a line that fetches or decodes code there runs again and again, long after the files it installed are deleted.',
];
$STATUS = ['ok' => ['good', 'OK'], 'info' => ['blue', 'INFO'], 'warning' => ['warn', 'WARNING'], 'critical' => ['danger', 'CRITICAL']];
$RANK = ['critical' => 0, 'warning' => 1, 'info' => 2, 'ok' => 3];
$vs = smpro_cc_version_state(); $vs2 = smpro_cc_version_state('', 1); $bothOk = ($vs['ok'] === true && $vs2['ok'] === true);
// the tree: server checks in three branches
$GROUPS = [
    'build'   => ['Build & protections', 'is the software past the known holes, and are the guards on', ['cve', 'cve2', 'cphulk', 'im_comp', 'sshd', 'ioc']],
    'persist' => ['What root would have left', 'the persistence every post-compromise checklist starts with', ['preload', 'sudoers', 'syscron', 'shellrc', 'tmpl', 'sorry', 'listen', 'hidden']],
    'access'  => ['Who else opens root', 'keys, tokens, uid 0, resellers', ['rootkeys', 'roottok', 'uid0', 'resellers']],
];
$byId = []; foreach ($server as $c) $byId[$c['id']][] = $c;
$OPS = smpro_cx_ops();
$sched = smpro_cx_sched_cfg();
$reports = smpro_cx_reports();
$csrfFix = smpro_csrf_generate('cc_fix');
$worst = function (array $items) use ($RANK): string { $w = 'ok'; foreach ($items as $c) if (($RANK[$c['status']] ?? 3) < $RANK[$w]) $w = $c['status']; return $w; };

smpro_layout_header('Compromise Check');
?>
<style>
.pill.blue{background:var(--brand-bg);color:var(--brand)}.pill.gray{background:var(--muted-bg,rgba(148,163,184,.15));color:var(--muted)}
.cc-head{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;flex-wrap:wrap;margin-bottom:14px}
.cc-head .h{margin:0}
.cc-intro{max-width:880px;color:var(--muted);line-height:1.6;margin:6px 0 0}
.cc-kpis{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:10px;margin:0 0 16px}
@media(max-width:1100px){.cc-kpis{grid-template-columns:repeat(3,1fr)}}
@media(max-width:600px){.cc-kpis{grid-template-columns:repeat(2,1fr)}}
.cc-kpi{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px 14px;min-width:0}
.cc-kpi .l{font-size:11px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.cc-kpi .v{font-size:22px;font-weight:800;line-height:1.15;margin-top:6px;font-variant-numeric:tabular-nums}
.cc-kpi .s{font-size:11.5px;color:var(--muted);margin-top:3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.cc-grid{display:grid;grid-template-columns:minmax(0,1fr);gap:16px}
.cc-card{background:var(--card);border:1px solid var(--line);border-radius:14px;overflow:hidden}
.cc-ch{display:flex;align-items:center;gap:10px;padding:12px 16px;border-bottom:1px solid var(--line);flex-wrap:wrap}
.cc-ch b{font-size:14px}.cc-ch .meta{font-size:12px}.cc-ch .sp{flex:1}
.cc-ch .xa{font-size:12px;color:var(--brand);cursor:pointer;background:none;border:0;padding:0}
/* tree */
.cc-tree{list-style:none;margin:0;padding:0}
.cc-br>.cc-bh{display:flex;align-items:center;gap:10px;padding:11px 16px;cursor:pointer;user-select:none;border-bottom:1px solid var(--line)}
.cc-br>.cc-bh:hover{background:var(--bg)}
.cc-arr{width:16px;height:16px;display:inline-flex;align-items:center;justify-content:center;color:var(--muted);transition:transform .15s;flex:none;font-size:12px}
.open>.cc-bh>.cc-arr,.cc-n.open>.cc-nh>.cc-arr{transform:rotate(90deg)}
.cc-bh .t{font-weight:700;font-size:13.5px}.cc-bh .m{font-size:12px;color:var(--muted)}
.cc-cnt{display:inline-flex;gap:6px;margin-left:auto;font-size:11px;font-weight:700}
.cc-cnt span{padding:2px 8px;border-radius:10px}
.cc-cnt .c{background:var(--dang-bg);color:var(--dang)}.cc-cnt .w{background:var(--warn-bg);color:var(--warn)}.cc-cnt .i{background:var(--brand-bg);color:var(--brand)}.cc-cnt .o{background:var(--good-bg);color:var(--good)}
.cc-br>.cc-bb{display:none}.cc-br.open>.cc-bb{display:block}
.cc-n{border-bottom:1px solid var(--line)}
.cc-n:last-child{border-bottom:0}
.cc-nh{display:grid;grid-template-columns:16px 96px minmax(0,1fr) minmax(0,38%);gap:10px;align-items:center;padding:9px 16px 9px 30px;cursor:pointer;user-select:none;font-size:13px}
.cc-nh:hover{background:var(--bg)}
.cc-nh .f{font-size:12.5px;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.cc-n.critical .f{color:var(--dang)}.cc-n.warning .f{color:var(--warn)}
.cc-nb{display:none;padding:4px 16px 12px 152px;font-size:12.5px;color:var(--muted);line-height:1.55}
.cc-n.open .cc-nb{display:block}
.cc-nb .ev{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11px;margin-top:6px;word-break:break-all;background:var(--bg);padding:8px 10px;border-radius:8px}
.cc-fix{margin-top:8px;padding:7px 10px;border-left:3px solid var(--brand);background:var(--brand-bg);color:var(--text);font-size:12px;line-height:1.5;border-radius:0 6px 6px 0}.cc-fix b{color:var(--brand)}
.cc-acts{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px;align-items:center}
.cc-btn{font-size:12px;font-weight:700;padding:5px 11px;border-radius:8px;border:1px solid var(--dang);background:transparent;color:var(--dang);cursor:pointer}
.cc-btn:hover{background:var(--dang-bg)}.cc-btn[disabled]{opacity:.5;cursor:default}
.cc-btn .w{font-weight:400;opacity:.8}
.cc-res{font-size:12px;margin-top:6px;padding:6px 10px;border-radius:6px}
.cc-res.ok{background:var(--good-bg);color:var(--good)}.cc-res.bad{background:var(--dang-bg);color:var(--dang)}
@media(max-width:900px){.cc-nh{grid-template-columns:16px 80px minmax(0,1fr)}.cc-nh .f{grid-column:3;white-space:normal}.cc-nb{padding-left:30px}}
/* accounts */
.cc-ah{display:grid;grid-template-columns:16px minmax(0,1fr) 70px minmax(0,45%) 120px;gap:10px;align-items:center;padding:9px 16px;cursor:pointer;user-select:none;font-size:13px}
.cc-ah:hover{background:var(--bg)}
.cc-ah .u{font-weight:700}.cc-ah .dom{font-size:11.5px;color:var(--muted);font-weight:400}
.cc-ah .num{text-align:right;font-variant-numeric:tabular-nums}
.cc-ah .chips{overflow:hidden;white-space:nowrap;text-overflow:ellipsis}
.cc-ab{display:none;padding:2px 16px 12px 42px}
.cc-a.open .cc-ab{display:block}
.cc-a{border-bottom:1px solid var(--line)}.cc-a:last-child{border-bottom:0}
.cc-chip{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:12px;margin:0 6px 0 0;white-space:nowrap}
.cc-door{padding:7px 0;border-top:1px dashed var(--line);font-size:12.5px}
.cc-door:first-child{border-top:0}
.cc-door .n{font-weight:700}.cc-door .d{color:var(--muted);margin-left:6px}
.cc-door .fx{display:block;font-size:11.5px;color:var(--muted);margin:3px 0 0 0;padding-left:8px;border-left:2px solid var(--brand)}
.cc-door .lnk{font-size:11.5px}
.cc-cron{margin:6px 0 0 8px;border-left:2px solid var(--line);padding-left:8px;display:flex;flex-direction:column;gap:4px}
.cc-cl{display:flex;flex-wrap:wrap;gap:6px 10px;align-items:center;font-size:12px}
.cc-cl .st{font-size:10.5px;font-weight:700;text-transform:uppercase;letter-spacing:.03em;min-width:118px}
.cc-cl code{flex:1 1 320px;font-size:11.5px;word-break:break-all;white-space:pre-wrap;background:var(--bg);padding:2px 6px;border-radius:5px}
.cc-cl.off code{opacity:.55;text-decoration:line-through}
.cc-cl .ops{display:flex;gap:6px}.cc-cl .ops .cc-btn{padding:3px 9px;font-size:11px}
@media(max-width:900px){.cc-ah{grid-template-columns:16px minmax(0,1fr) 60px}.cc-ah .chips,.cc-ah .when{display:none}.cc-ab{padding-left:16px}}
.cc-bar{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.cc-empty{padding:18px 16px;color:var(--muted)}
.cc-note{padding:10px 16px;border-top:1px solid var(--line);font-size:12.5px;color:var(--muted);line-height:1.55}
.cc-warnbar{padding:8px 16px;background:var(--warn-bg);color:var(--warn);font-size:12.5px;border-bottom:1px solid var(--line)}
.cc-flash{padding:9px 14px;border-radius:10px;margin-bottom:14px;font-size:13px}
.cc-flash.ok{background:var(--good-bg);color:var(--good)}.cc-flash.bad{background:var(--dang-bg);color:var(--dang)}
/* schedule */
.cc-sf{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px 14px;padding:14px 16px}
.cc-sf label{display:block;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);margin-bottom:4px}
.cc-sf .tp-sel,.cc-sf .tp-in{width:100%}
.cc-sf .full{grid-column:1/-1}
.cc-sw{display:flex;align-items:center;gap:8px;font-size:13px;font-weight:700}
.cc-sf .foot{grid-column:1/-1;display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding-top:4px}
.cc-rep{font-size:12.5px;padding:0 16px 12px}
.cc-rep a{color:var(--brand);text-decoration:none}
.cc-rep .r{display:flex;gap:10px;padding:5px 0;border-top:1px dashed var(--line);flex-wrap:wrap}
.cc-rep .r:first-child{border-top:0}
.cc-stored{padding:8px 16px;background:var(--brand-bg);color:var(--brand);font-size:12.5px;border-bottom:1px solid var(--line)}
</style>

<div class="cc-head">
  <div>
    <h1 class="h">Compromise Check <?= smpro_beta_badge() ?></h1>
    <p class="cc-intro">A break-in leaves <b>doors</b>, not only a login &mdash; an FTP sub-account nobody made, a forwarder that copies mail off the server, a cron entry that fetches code, an SSH key, an API token. Everything below is read from cPanel's own files; every branch opens with its arrow, every finding says what to do, and the fixes that a program can do safely have a button (the original is backed up first, every time).
      <details style="display:inline"><summary style="display:inline;cursor:pointer;color:var(--brand)">Where this comes from</summary>
        <span> cPanel's own guidance for a compromised account (restore a clean backup, rotate <i>every</i> credential), the WebPros / Plesk post-compromise checklist (ld.so.preload first), hosting providers' 2026 cPanel compromise guides (ransomware markers, shell start-up injection, login-template tampering), the CVE-2026-41940 and CVE-2026-65643 advisories, and cPanel's own session IOC script.</span>
      </details>
    </p>
  </div>
  <form method="get" action="index.cgi" class="cc-bar"><input type="hidden" name="page" value="compromise-check">
    <select name="days" class="tp-sel"><?php foreach ([7, 30, 90, 365] as $d): ?><option value="<?= $d ?>"<?= $d === $days ? ' selected' : '' ?>>last <?= $d ?> days</option><?php endforeach; ?></select>
    <input type="text" name="user" class="tp-in" list="ccUsers" placeholder="whole server - or type accounts, comma-separated" value="<?= smpro_h(implode(', ', $usersIn)) ?>" style="min-width:290px" autocomplete="off" id="ccUserIn">
    <datalist id="ccUsers"><?php foreach ($allAccts as $u => $a): ?><option value="<?= smpro_h($u) ?>"><?= smpro_h($a['domain']) ?></option><?php endforeach; ?></datalist>
    <button class="tp-btn primary" type="submit">Scan</button>
    <a class="tp-btn" href="index.cgi?page=compromise-check&amp;days=<?= $days ?>&amp;csv=1" title="every finding, one row each">CSV</a>
  </form>
</div>

<?php if (!empty($flash)): ?><div class="cc-flash <?= !empty($flashOk) ? 'ok' : 'bad' ?>"><?= $flash ?></div><?php endif; ?>

<div class="cc-kpis">
  <div class="cc-kpi"><div class="l">cPanel build</div><div class="v" style="font-size:18px"><?= smpro_h($vs['version'] ?: '?') ?></div><div class="s" style="color:<?= $bothOk ? 'var(--good)' : 'var(--dang)' ?>"><?= $bothOk ? 'past both 2026 critical fixes' : (($vs['ok'] === false || $vs2['ok'] === false) ? 'UNPATCHED - see Server' : 'unknown') ?></div></div>
  <div class="cc-kpi"><div class="l">Server critical</div><div class="v" style="color:<?= $crit ? 'var(--dang)' : 'var(--good)' ?>"><?= $crit ?></div><div class="s">must be fixed</div></div>
  <div class="cc-kpi"><div class="l">Server warnings</div><div class="v" style="color:<?= $warn ? 'var(--warn)' : 'var(--good)' ?>"><?= $warn ?></div><div class="s">worth a decision</div></div>
  <div class="cc-kpi"><div class="l"><?= $usersIn ? 'Accounts chosen' : 'Accounts scanned' ?></div><div class="v"><?= (int)$scan['scanned'] ?></div><div class="s"><?= $scan['partial'] ? 'partial - time budget hit' : ($usersIn ? 'of ' . count($allAccts) . ' on the server' : 'in ' . smpro_h((string)$scan['took']) . ' s') ?></div></div>
  <div class="cc-kpi"><div class="l">Accounts with new doors</div><div class="v" style="color:<?= $flaggedRows ? 'var(--warn)' : 'var(--good)' ?>"><?= count($flaggedRows) ?></div><div class="s">in the last <?= $days ?> days</div></div>
  <div class="cc-kpi"><div class="l">Doors flagged</div><div class="v"><?= array_sum($doorCounts) ?></div><div class="s"><?= $doorCounts ? smpro_h(implode(', ', array_map(fn($k, $n) => ($KIND[$k][0] ?? $k) . ' ' . $n, array_keys($doorCounts), $doorCounts))) : 'none' ?></div></div>
</div>

<div class="cc-grid">
  <div class="cc-card">
    <div class="cc-ch"><b>Server</b><span class="meta">what an intruder with root would have left, and whether the door they used is closed</span><span class="sp"></span><button class="xa" type="button" data-xa="srv">expand all</button></div>
    <?php if ($stored): ?><div class="cc-stored">Stored report <?= smpro_h($repId) ?> from <?= date('Y-m-d H:i', (int)$stored['at']) ?> &mdash; only the rows that were not OK were kept. <a href="index.cgi?page=compromise-check">Back to a live scan</a></div><?php endif; ?>
    <ul class="cc-tree" id="srv">
    <?php foreach ($GROUPS as $gid => [$gt, $gm, $ids]):
        $items = []; foreach ($ids as $id) foreach ($byId[$id] ?? [] as $c) $items[] = $c;
        if (!$items) continue;
        $cnt = ['critical' => 0, 'warning' => 0, 'info' => 0, 'ok' => 0]; foreach ($items as $c) $cnt[$c['status']] = ($cnt[$c['status']] ?? 0) + 1;
        $gw = $worst($items); ?>
      <li class="cc-br<?= $gw === 'critical' ? ' open' : '' ?>" id="br-<?= $gid ?>">
        <div class="cc-bh"><span class="cc-arr">&#9654;</span><span class="t"><?= smpro_h($gt) ?></span><span class="m"><?= smpro_h($gm) ?></span>
          <span class="cc-cnt"><?php if ($cnt['critical']): ?><span class="c"><?= $cnt['critical'] ?> critical</span><?php endif; ?><?php if ($cnt['warning']): ?><span class="w"><?= $cnt['warning'] ?> warning</span><?php endif; ?><?php if ($cnt['info']): ?><span class="i"><?= $cnt['info'] ?> info</span><?php endif; ?><span class="o"><?= $cnt['ok'] ?> ok</span></span></div>
        <div class="cc-bb">
        <?php foreach ($items as $i => $c): [$cls, $lbl] = $STATUS[$c['status']] ?? ['gray', strtoupper($c['status'])]; $fixes = (array)($c['fixes'] ?? []); $fx = $c['status'] !== 'ok' ? smpro_cc_fix($c['id']) : ''; ?>
          <div class="cc-n <?= smpro_h($c['status']) ?>" id="n-<?= $gid ?>-<?= $i ?>">
            <div class="cc-nh"><span class="cc-arr">&#9654;</span><span><span class="pill <?= $cls ?>"><?= $lbl ?></span></span><span><?= smpro_h($c['title']) ?><?php if ($fixes && $c['status'] !== 'ok'): ?> <span class="cc-chip" style="background:var(--dang-bg);color:var(--dang)">fix available</span><?php endif; ?></span><span class="f"><?= smpro_h($c['finding']) ?></span></div>
            <div class="cc-nb">
              <div><b style="color:var(--text)">Finding:</b> <?= smpro_h($c['finding']) ?></div>
              <?php if ($c['why'] !== ''): ?><div style="margin-top:4px"><b style="color:var(--text)">Why it matters:</b> <?= smpro_h($c['why']) ?></div><?php endif; ?>
              <?php if ($c['evidence']): ?><div class="ev"><?php foreach ($c['evidence'] as $e): ?><div><?= smpro_h($e) ?></div><?php endforeach; ?></div><?php endif; ?>
              <?php if ($fx !== ''): ?><div class="cc-fix"><b>What to do:</b> <?= smpro_h($fx) ?></div><?php endif; ?>
              <?php if ($fixes && $c['status'] !== 'ok' && !$stored): ?>
              <div class="cc-acts"><?php foreach ($fixes as $f): $op = (string)($f['op'] ?? ''); if (!isset($OPS[$op])) continue; $args = array_diff_key($f, ['op' => 1, 'what' => 1]); ?>
                <button type="button" class="cc-btn" data-op="<?= smpro_h($op) ?>" data-args="<?= smpro_h(json_encode($args)) ?>" data-confirm="<?= smpro_h($OPS[$op]['confirm']) ?>"><?= smpro_h($OPS[$op]['label']) ?><?php if (!empty($f['what'])): ?> <span class="w">&middot; <?= smpro_h($f['what']) ?></span><?php endif; ?></button>
              <?php endforeach; ?><span class="meta" style="font-size:11.5px">backs up first, audited</span></div>
              <?php endif; ?>
            </div>
          </div>
        <?php endforeach; ?>
        </div>
      </li>
    <?php endforeach; ?>
    </ul>
  </div>

  <div class="cc-card">
    <div class="cc-ch"><b>Accounts &mdash; doors added</b>
      <span class="meta">flagged = created in the window (from cPanel's own log, with the address that did it) or suspicious by name</span>
      <span class="sp"></span>
      <?php foreach ($KIND as $k => [$kl, $kc]): ?><span class="cc-chip" style="background:<?= $kc ?>22;color:<?= $kc ?>"><?= $kl ?></span><?php endforeach; ?>
      <button class="xa" type="button" data-xa="acc">expand all</button>
    </div>
    <?php if ($usersIn && !$rows): ?><div class="cc-empty">No such account<?= count($usersIn) > 1 ? 's' : '' ?>: <?= smpro_h(implode(', ', $usersIn)) ?>.</div><?php endif; ?>
    <?php if ($scan['partial']): ?><div class="cc-warnbar">Scanned <?= (int)$scan['scanned'] ?> accounts in the time budget. Narrow to some accounts for the rest, or run again.</div><?php endif; ?>
    <?php $list = $usersIn ? $rows : ($showAll ? array_merge($flaggedRows, $quietRows) : $flaggedRows); ?>
    <?php if (!$list && $rows === [] && !$usersIn): ?>
      <div class="cc-empty">No account gained a door in the last <?= $days ?> days.</div>
    <?php elseif (!$list): ?>
      <div class="cc-empty"><?= $usersIn ? 'No doors at all on the chosen account(s): no FTP sub-accounts, forwarders, cron, keys or tokens.' : 'No account gained a door in the last ' . $days . ' days.' ?></div>
    <?php else: ?>
    <div id="acc">
      <?php foreach ($list as $ri => $r): $newFlag = $r['flags'] > 0; ?>
      <div class="cc-a" id="a-<?= $ri ?>">
        <div class="cc-ah"><span class="cc-arr">&#9654;</span>
          <span><span class="u"><?= smpro_h($r['user']) ?></span> <span class="dom"><?= smpro_h($r['domain']) ?></span></span>
          <span class="num"><?= $newFlag ? '<b style="color:var(--dang)">' . (int)$r['flags'] . ' flagged</b>' : '<span class="meta">0</span>' ?></span>
          <span class="chips"><?php $seen = []; foreach ($r['findings'] as $f) { if (isset($seen[$f['kind']])) continue; $seen[$f['kind']] = 1; [$kl, $kc] = $KIND[$f['kind']] ?? [$f['kind'], '#64748b']; ?><span class="cc-chip" style="background:<?= $kc ?>22;color:<?= $kc ?>"><?= smpro_h($kl) ?></span><?php } ?></span>
          <span class="when meta" style="font-size:11.5px;text-align:right"><?= $r['newest'] ? date('Y-m-d H:i', $r['newest']) : '—' ?></span>
        </div>
        <div class="cc-ab">
          <div class="lnk" style="font-size:11.5px;margin:2px 0 6px"><a href="index.cgi?page=user-investigation&amp;user=<?= smpro_h($r['user']) ?>&amp;win=7">investigate this account &#8250;</a> &nbsp;&middot;&nbsp; <a href="index.cgi?page=firewall-status&amp;tab=report">reset its passwords (Threat Report) &#8250;</a></div>
          <?php foreach ($r['findings'] as $f): [$kl, $kc] = $KIND[$f['kind']] ?? [$f['kind'], '#64748b']; $fix = (array)($f['fix'] ?? []); $op = (string)($fix['op'] ?? ''); $fx = $f['flag'] ? smpro_cc_fix($f['kind'] === 'shellrc' ? 'shellrc_acct' : $f['kind']) : ''; ?>
            <div class="cc-door<?= $f['flag'] ? ' flag' : '' ?>"><span class="cc-chip" style="background:<?= $kc ?>22;color:<?= $kc ?>"><?= smpro_h($kl) ?></span><span class="n"><?= smpro_h($f['label']) ?></span><span class="d"><?= smpro_h($f['detail']) ?></span>
              <?php if ($fx !== ''): ?><span class="fx">What to do: <?= smpro_h($fx) ?></span><?php endif; ?>
              <?php if (($f['flag'] || $f['kind'] === 'token') && $op !== '' && isset($OPS[$op]) && !$stored): $alt = is_array($fix['alt'] ?? null) ? $fix['alt'] : null; $args = array_diff_key($fix, ['op' => 1, 'alt' => 1]); ?>
              <div class="cc-acts"><button type="button" class="cc-btn" data-op="<?= smpro_h($op) ?>" data-args="<?= smpro_h(json_encode($args)) ?>" data-confirm="<?= smpro_h($OPS[$op]['confirm']) ?>"><?= smpro_h($OPS[$op]['label']) ?></button><?php if ($alt && isset($OPS[$alt['op']])): $aargs = array_diff_key($alt, ['op' => 1]); ?> <button type="button" class="cc-btn" data-op="<?= smpro_h($alt['op']) ?>" data-args="<?= smpro_h(json_encode($aargs)) ?>" data-confirm="<?= smpro_h($OPS[$alt['op']]['confirm']) ?>"><?= smpro_h($OPS[$alt['op']]['label']) ?></button><?php endif; ?><span class="meta" style="font-size:11.5px">backs up first, audited</span></div>
              <?php endif; ?>
              <?php if ($f['kind'] === 'cron' && !empty($f['lines'])): $cl = ['sus' => ['fetches / decodes code', 'var(--dang)'], 'routine' => ['routine', 'var(--muted)'], 'off' => ['switched off', 'var(--warn, #b45309)']]; ?>
              <div class="cc-cron">
                <?php foreach ((array)$f['lines'] as $ln): [$sl, $sc] = $cl[$ln['state']] ?? $cl['routine']; $la = json_encode(['user' => $r['user'], 'sha' => $ln['sha']]); ?>
                <div class="cc-cl <?= smpro_h($ln['state']) ?>"><span class="st" style="color:<?= $sc ?>"><?= smpro_h($sl) ?></span><code><?= smpro_h($ln['text']) ?></code>
                  <?php if (!$stored): ?><span class="ops"><?php if ($ln['state'] === 'off'): ?><button type="button" class="cc-btn" data-op="cron_line_on" data-args="<?= smpro_h($la) ?>" data-confirm="<?= smpro_h($OPS['cron_line_on']['confirm']) ?>"><?= smpro_h($OPS['cron_line_on']['label']) ?></button><?php else: ?><button type="button" class="cc-btn" data-op="cron_line_off" data-args="<?= smpro_h($la) ?>" data-confirm="<?= smpro_h($OPS['cron_line_off']['confirm']) ?>"><?= smpro_h($OPS['cron_line_off']['label']) ?></button> <button type="button" class="cc-btn" data-op="cron_line_rm" data-args="<?= smpro_h($la) ?>" data-confirm="<?= smpro_h($OPS['cron_line_rm']['confirm']) ?>"><?= smpro_h($OPS['cron_line_rm']['label']) ?></button><?php endif; ?></span><?php endif; ?>
                </div>
                <?php endforeach; ?>
                <div class="meta" style="font-size:11.5px">Switch off = kept as a comment, reversible here · Remove = taken out, crontab backed up first · to change the wording, edit it in cPanel &gt; Cron Jobs of the account.</div>
              </div>
              <?php endif; ?>
            </div>
          <?php endforeach; ?>
        </div>
      </div>
      <?php endforeach; ?>
    </div>
    <?php endif; ?>
    <details class="cc-legend" style="margin:10px 0 2px"><summary style="cursor:pointer;color:var(--brand);font-size:12.5px">What each kind of door is</summary>
      <table class="smpro-table" style="margin:8px 0 0">
        <tbody><?php foreach ($KIND_WHAT as $kw => $txt): [$kl2, $kc2] = $KIND[$kw] ?? [$kw, '#64748b']; ?>
          <tr><td style="white-space:nowrap;vertical-align:top"><span class="cc-chip" style="background:<?= $kc2 ?>22;color:<?= $kc2 ?>"><?= smpro_h($kl2) ?></span></td><td style="font-size:12.5px;line-height:1.6"><?= smpro_h($txt) ?></td></tr>
        <?php endforeach; ?></tbody>
      </table>
    </details>
    <div class="cc-note">
      <?php if (!$usersIn && !$showAll && $quietRows): ?><?= count($quietRows) ?> more account(s) have doors that are older than the window &mdash; <a href="index.cgi?page=compromise-check&amp;days=<?= $days ?>&amp;all=1">show them too</a>. <?php endif; ?>
      A flagged door the customer did not add: remove it (button, or in their cPanel) <b>and</b> reset every password of the account from Firewall &rsaquo; Threat Report. A reset alone leaves the door open.
    </div>
  </div>

  <div class="cc-card" id="sched">
    <div class="cc-ch"><b>Scheduled scan</b><span class="meta">runs by itself, stores the report here, and tells you through your notification channels (type "Compromise Check")</span><span class="sp"></span>
      <?php if ($sched['enabled']): ?><span class="pill good">ON &middot; <?= $sched['every'] === 'weekly' ? ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'][$sched['dow']] . ' ' : 'daily ' ?><?= sprintf('%02d:00', $sched['hour']) ?></span><?php else: ?><span class="pill gray">OFF</span><?php endif; ?>
    </div>
    <form method="post" action="index.cgi?page=compromise-check#sched" class="cc-sf">
      <?= smpro_csrf_field('cc_sched') ?><input type="hidden" name="cc_action" value="sched_save">
      <div class="full cc-sw"><label style="margin:0"><input type="checkbox" name="enabled" value="1"<?= $sched['enabled'] ? ' checked' : '' ?>> Enabled</label></div>
      <div><label>How often</label><select name="every" class="tp-sel"><option value="daily"<?= $sched['every'] === 'daily' ? ' selected' : '' ?>>every day</option><option value="weekly"<?= $sched['every'] === 'weekly' ? ' selected' : '' ?>>every week</option></select></div>
      <div><label>Day (weekly)</label><select name="dow" class="tp-sel"><?php foreach (['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'] as $i => $dn): ?><option value="<?= $i ?>"<?= $i === $sched['dow'] ? ' selected' : '' ?>><?= $dn ?></option><?php endforeach; ?></select></div>
      <div><label>Hour (server time)</label><select name="hour" class="tp-sel"><?php for ($h = 0; $h < 24; $h++): ?><option value="<?= $h ?>"<?= $h === $sched['hour'] ? ' selected' : '' ?>><?= sprintf('%02d:00', $h) ?></option><?php endfor; ?></select></div>
      <div><label>What</label><select name="scope" class="tp-sel"><option value="both"<?= $sched['scope'] === 'both' ? ' selected' : '' ?>>server + accounts</option><option value="server"<?= $sched['scope'] === 'server' ? ' selected' : '' ?>>server only</option><option value="accounts"<?= $sched['scope'] === 'accounts' ? ' selected' : '' ?>>accounts only</option></select></div>
      <div><label>Window</label><select name="days" class="tp-sel"><?php foreach ([7, 30, 90, 365] as $d): ?><option value="<?= $d ?>"<?= $d === $sched['days'] ? ' selected' : '' ?>>last <?= $d ?> days</option><?php endforeach; ?></select></div>
      <div><label>Tell me</label><select name="tell" class="tp-sel"><option value="issues"<?= $sched['tell'] === 'issues' ? ' selected' : '' ?>>when anything is not OK</option><option value="critical"<?= $sched['tell'] === 'critical' ? ' selected' : '' ?>>only critical / new doors</option><option value="always"<?= $sched['tell'] === 'always' ? ' selected' : '' ?>>after every run</option></select></div>
      <div class="full"><label>Accounts (empty = all <?= count($allAccts) ?>)</label><input type="text" name="users" class="tp-in" list="ccUsers" autocomplete="off" placeholder="whole server - or accounts, comma-separated" value="<?= smpro_h(implode(', ', $sched['users'])) ?>"></div>
      <div class="foot"><button class="tp-btn primary" type="submit">Save schedule</button>
        <button class="tp-btn" type="submit" name="cc_action" value="sched_run" formaction="index.cgi?page=compromise-check#sched">Run now</button>
        <span class="meta" style="font-size:12px"><?= $sched['last_run'] ? 'Last run ' . date('Y-m-d H:i', (int)$sched['last_run']) . ': ' . smpro_h($sched['last_summary']) : 'Never run yet.' ?> &nbsp;Channels: <a href="index.cgi?page=notifications">Notifications</a>.</span></div>
    </form>
    <?php if ($reports): ?>
    <div class="cc-rep"><b style="font-size:12px">Stored reports</b>
      <?php foreach (array_slice($reports, 0, 12) as $rp): $s = $rp['summary']; ?>
      <div class="r"><a href="index.cgi?page=compromise-check&amp;report=<?= smpro_h($rp['id']) ?>"><?= date('Y-m-d H:i', $rp['at']) ?></a><span class="meta"><?= smpro_h($rp['scope']) ?></span>
        <span style="color:<?= ($s['critical'] ?? 0) ? 'var(--dang)' : 'var(--muted)' ?>"><?= (int)($s['critical'] ?? 0) ?> critical</span><span style="color:<?= ($s['warning'] ?? 0) ? 'var(--warn)' : 'var(--muted)' ?>"><?= (int)($s['warning'] ?? 0) ?> warning</span>
        <span style="color:<?= ($s['flagged_accounts'] ?? 0) ? 'var(--warn)' : 'var(--muted)' ?>"><?= (int)($s['flagged_accounts'] ?? 0) ?> account(s), <?= (int)($s['doors'] ?? 0) ?> door(s)</span></div>
      <?php endforeach; ?>
    </div>
    <?php endif; ?>
  </div>
</div>
<script>
(function(){
  var CSRF = <?= json_encode($csrfFix) ?>;
  // the tree: a click on a branch or node header toggles it; the arrows turn
  document.querySelectorAll('.cc-bh,.cc-nh,.cc-ah').forEach(function(h){ h.addEventListener('click', function(e){ if (e.target.closest('a,button')) return; h.parentNode.classList.toggle('open'); }); });
  document.querySelectorAll('[data-xa]').forEach(function(b){ b.addEventListener('click', function(){ var root=document.getElementById(b.getAttribute('data-xa')); if(!root) return; var all=root.querySelectorAll('.cc-br,.cc-n,.cc-a'); var open=b.textContent.indexOf('expand')===0; all.forEach(function(x){ x.classList.toggle('open', open); }); b.textContent = open ? 'collapse all' : 'expand all'; }); });
  // fixes
  document.querySelectorAll('.cc-btn[data-op]').forEach(function(b){
    b.addEventListener('click', function(){
      if (!confirm(b.getAttribute('data-confirm') || 'Apply this fix?')) return;
      b.disabled = true; var old = b.innerHTML; b.textContent = 'working…';
      /* url-encoded on purpose: index.cgi reads POST bodies with parse_str and refuses multipart (FormData) outright */
      var fd = new URLSearchParams(); fd.append('cc_action','fix'); fd.append('smpro_csrf', CSRF); fd.append('op', b.getAttribute('data-op'));
      var args = {}; try { args = JSON.parse(b.getAttribute('data-args')||'{}'); } catch(e){}
      Object.keys(args).forEach(function(k){ fd.append('args['+k+']', args[k]); });
      fetch('index.cgi?page=compromise-check', {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:fd.toString(), credentials:'same-origin'}).then(function(r){ return r.json(); }).then(function(j){
        var res = document.createElement('div'); res.className = 'cc-res ' + (j.ok ? 'ok' : 'bad');
        res.textContent = (j.ok ? 'Done: ' : 'Not done: ') + (j.msg || '') + (j.backup ? '  [backup: ' + j.backup + ']' : '');
        b.parentNode.insertAdjacentElement('afterend', res);
        if (j.ok) { b.textContent = 'done'; } else { b.disabled = false; b.innerHTML = old; }
      }).catch(function(){ b.disabled = false; b.innerHTML = old; alert('The request did not complete. Reload the page and look at the row again.'); });
    });
  });
})();
</script>
<?php smpro_layout_footer();
