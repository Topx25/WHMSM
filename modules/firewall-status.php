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
function smpro_fw_active($svc) { $s = trim((string)smpro_memo('fw_act_' . $svc, 15, fn() => smpro_fw_run('systemctl is-active ' . escapeshellarg($svc)))); return $s === '' ? 'unknown' : $s; }   // 15 s: the page asked systemd ~26 times per render
function smpro_fw_enabled($svc) { $s = trim((string)smpro_memo('fw_en_' . $svc, 60, fn() => smpro_fw_run('systemctl is-enabled ' . escapeshellarg($svc)))); return $s === '' ? 'unknown' : $s; }
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

/* Recommended firewall allow-lists + live fetch + auto-update live in includes/fwallow.php (shared with the
 * bin/fw_allow_sync.php cron worker): smpro_fw_allow_providers/ranges/status/apply/undo/reconcile, the ignore +
 * auto-update config, and smpro_fw_allow_cron_sync(). This module only wires the UI + POST actions to them. */

/* ---------- controlled action: unblock (csf -dr), POST+CSRF+root ---------- */
$reqMethod = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: 'GET'));

/* ---------- read-only: export blocked (external) IPs as an IOC list (GET; behind WHM/root page access) ----------
 * index.cgi wraps ?format=ioc with text/plain + Content-Disposition, so here we just emit one bare IP per line and
 * exit. Comment lines are skipped by smpro_fw_deny_list(); private/loopback/reserved ranges by smpro_ip_is_external().
 * Read-only — no CSRF needed for a read; still gated by WHM/root page access. */
if (($_GET['fw_ioc'] ?? '') === '1') {
    $ioc = [];
    foreach (smpro_fw_deny_list() as $d) {
        $bare = explode('/', $d['ip'])[0];
        if (smpro_ip_is_external($bare)) $ioc[$bare] = 1;   // dedupe + drop private/loopback/reserved
    }
    echo implode("\n", array_keys($ioc));
    if ($ioc) echo "\n";
    exit;
}

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
    echo json_encode(['ok' => true, 'results' => $results], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

/* ---------- controlled action: service start/stop/enable/disable (POST+CSRF+root) ---------- */
/**
 * Look through addresses that are ALREADY blocked and find any that is a real, forward-confirmed crawler.
 *
 * The shield refuses new blocks aimed at a crawler, but says nothing about what is already in csf.deny — entries
 * put there by lfd, by another admin, or by this plugin before the shield existed. A wrongly blocked Googlebot
 * produces no error and no log line; the site just stops being crawled. So the only way to find one is to go and
 * look, which is what this does.
 */
if (!function_exists('smpro_fw_block_sources')) { $__fwb = SMPRO_INCLUDES . '/fwblock.php'; if (is_file($__fwb)) require_once $__fwb; }

/* ---------------- Country Login Lock ----------------
 * An account may only be signed into from countries you allow. Everything here is a press: the lock does not arm
 * itself, does not widen itself, and refuses to arm at all if doing so would lock the operator out. */
require_once SMPRO_INCLUDES . '/geologin.php';

/* ---------------- Accounts signed into from countries you do not allow ----------------
 * The report, and the one action that actually ends it. The new passwords are returned ONCE and stored nowhere;
 * what is kept on disk is the account, the reason, the date and who did it. */
require_once SMPRO_INCLUDES . '/georeport.php';
if (!function_exists('smpro_ntf_load') && is_file(SMPRO_INCLUDES . '/notify.php')) require_once SMPRO_INCLUDES . '/notify.php';
// The threat report's archives are readable from a link (root, same session), so an archived report can be opened later.
if (isset($_GET['gr_archive']) && function_exists('smpro_gr_archive_get')) {
    smpro_require_root();
    $ga = smpro_gr_archive_get((string)$_GET['gr_archive']);
    echo '<!doctype html><meta charset="utf-8"><title>Threat report archive</title><pre style="font:13px/1.5 ui-monospace,Menlo,Consolas,monospace;white-space:pre-wrap;padding:16px">'
       . ($ga ? smpro_h(smpro_gr_archive_text($ga)) : 'No such archive.') . '</pre>';
    exit;
}
if ($reqMethod === 'POST' && (string)($_POST['fw_action'] ?? '') === 'gr_counter_reset') {
    smpro_require_valid_csrf('fw_csf'); smpro_require_root();
    header('Content-Type: application/json');
    $rep = json_decode((string)($_POST['report'] ?? ''), true);
    $out = (is_array($rep) && isset($rep['accounts']) && function_exists('smpro_gr_counter_reset'))
         ? smpro_gr_counter_reset($rep, smpro_current_actor())
         : ['ok' => false, 'msg' => 'Run the report first - the counter is reset only after the current report is archived.'];
    echo json_encode($out, JSON_UNESCAPED_SLASHES); exit;
}
if ($reqMethod === 'POST' && in_array((string)($_POST['fw_action'] ?? ''), ['gr_scan', 'gr_reset'], true)) {
    smpro_require_valid_csrf('fw_csf'); smpro_require_root();
    header('Content-Type: application/json');
    $out = ['ok' => false, 'msg' => 'Unknown action.'];
    try {
        if ($_POST['fw_action'] === 'gr_scan') {
            // Every account there is evidence for, not only the ones seen signing in from a country outside
            // the list. That one source is silent until an allow-list is configured, and it is blind to the
            // commonest case of all - the correct password used from an ordinary country, which is exactly what
            // a stolen password looks like. During a live incident this report offered zero accounts to reset
            // while malware was sitting in dozens of them.
            $days = max(1, min(90, (int)($_POST['days'] ?? 7)));
            $out  = smpro_gr_scan($days);
            $cmp  = function_exists('smpro_gr_compromised') ? smpro_gr_compromised($days) : ['accounts' => [], 'sources' => [], 'blind' => false];

            // A source that could not run must not be reported as a source that found nothing. If ANY source was
            // blind the answer is partial, and the page says so even when the list below is long.
            $out['blind']   = !empty($cmp['blind']) || empty($out['ok']);
            $out['sources'] = (array)($cmp['sources'] ?? []);

            // Merge on the account name: a foreign-login row keeps its sign-in detail and gains the extra
            // evidence, rather than the same account appearing twice with half the story each time.
            $byUser = [];
            foreach ((array)($out['accounts'] ?? []) as $a) {
                if (!is_array($a) || empty($a['user'])) continue;
                $byUser[(string)$a['user']] = $a;
            }
            foreach ((array)($cmp['accounts'] ?? []) as $u => $c) {
                $u = (string)$u;
                if (!isset($byUser[$u])) {
                    $byUser[$u] = ['user' => $u, 'ok' => 0, 'failed' => 0, 'ips' => [], 'ccs' => [],
                                   'first' => (int)($c['newest'] ?? 0), 'last' => (int)($c['newest'] ?? 0), 'allowed' => []];
                }
                $byUser[$u]['reasons'] = (array)($c['reasons'] ?? []);
                $byUser[$u]['why']     = (string)($c['why'] ?? '');
                $byUser[$u]['live']    = (int)($c['live'] ?? 0);
                $byUser[$u]['last']    = max((int)($byUser[$u]['last'] ?? 0), (int)($c['newest'] ?? 0));
            }
            // A password actually accepted from outside, or malware still on disk, arrives pre-ticked.
            foreach ($byUser as $u => $a) {
                $sev = (string)($a['severity'] ?? '');
                if ($sev === '') $sev = ((int)($a['ok'] ?? 0) > 0 || (int)($a['live'] ?? 0) > 0) ? 'compromised' : 'attempts';
                $byUser[$u]['severity'] = $sev;
                $byUser[$u]['live']     = (int)($a['live'] ?? 0);
                if (empty($byUser[$u]['why'])) {
                    $byUser[$u]['why'] = (int)($a['ok'] ?? 0) > 0
                        ? 'password accepted from a country outside the list'
                        : 'sign-in attempts from a country outside the list';
                }
            }
            uasort($byUser, function ($x, $y) {
                $sx = ($x['severity'] === 'compromised') ? 1 : 0; $sy = ($y['severity'] === 'compromised') ? 1 : 0;
                if ($sx !== $sy) return $sy <=> $sx;
                if ((int)$x['live'] !== (int)$y['live']) return (int)$y['live'] <=> (int)$x['live'];
                return (int)$y['last'] <=> (int)$x['last'];
            });
            $out['accounts'] = array_values($byUser);

            // The list can be non-empty even when the sign-in scan itself failed, so 'ok' must mean "there is
            // something to show", not "the sign-in scan succeeded" - otherwise the page hides real findings.
            if (empty($out['ok']) && $out['accounts']) { $out['ok'] = true; $out['msg'] = ''; }
            $out['history'] = smpro_gr_history(50);
        } else {
            $users  = array_values(array_filter(array_map('strval', (array)($_POST['users'] ?? []))));
            $reason = (string)($_POST['reason'] ?? '');
            $r = smpro_gr_reset_bulk($users, $reason, smpro_current_actor(), (string)($_POST['all_mailboxes'] ?? '') === '1');   // exactly the ticked identities; every mailbox of a ticked account only on an explicit request
            // The export is built here and handed back in this response. It is never written to this server.
            $r['export'] = !empty($r['secrets']) ? smpro_gr_export($r['secrets'], trim($reason), smpro_current_actor()) : '';
            $r['filename'] = 'smpro-password-reset-' . date('Ymd-His') . '.csv';
            $r['msg'] = ($r['msg'] ?? '') ?: (count($r['done']) . ' account(s) reset'
                      . (count($r['failed']) ? ', ' . count($r['failed']) . ' failed' : '') . '.');
            $out = $r;
        }
    } catch (\Throwable $e) {
        if (function_exists('smpro_soft_fail')) smpro_soft_fail('georeport', $e);
        $out = ['ok' => false, 'msg' => 'That hit an error: ' . $e->getMessage()];
    }
    echo json_encode($out, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

/* ---------------------------------------------------------------------------------------------------------
 * Country wall — the one thing in this product that can make the server unreachable to its own operator.
 *
 * Every write below is preceded by a check that the operator survives it, and the check is done on THIS
 * request's address, not on anything the browser sent. A page can lie about a country; it cannot lie about
 * where its own connection came from.
 * ------------------------------------------------------------------------------------------------------- */
if ($reqMethod === 'POST' && in_array((string)($_POST['fw_action'] ?? ''), ['gw_save', 'gw_fetch', 'gw_preview', 'gw_apply', 'gw_remove', 'gw_beat'], true)) {
    smpro_require_valid_csrf('fw_csf'); smpro_require_root();
    header('Content-Type: application/json');
    if (!function_exists('smpro_gw_cfg')) { $gwf = SMPRO_BASE . '/includes/geowall.php'; if (@is_file($gwf)) require_once $gwf; }
    if (!function_exists('smpro_gh_cfg')) { $ghf = SMPRO_BASE . '/includes/geohulk.php'; if (@is_file($ghf)) require_once $ghf; }
    $act = (string)$_POST['fw_action'];
    $out = ['ok' => false, 'msg' => 'The country wall is not installed on this server.'];

    $gwIp = '';
    $gwIp = function_exists('smpro_admin_ip') ? smpro_admin_ip() : '';   // REMOTE_ADDR first: cpsrvd is the direct peer, the forwarded headers are what the browser sent

    try {
        if (function_exists('smpro_gw_cfg')) {
            if ($act === 'gw_beat') {
                // The dead man's switch is fed from here, and ONLY from here: the proof that matters is that a
                // request arrived from outside and was answered. A worker feeding it would prove nothing.
                smpro_gw_heartbeat();
                $out = ['ok' => true, 'msg' => 'still reachable'];
            } elseif ($act === 'gw_save') {
                $in = json_decode((string)($_POST['cfg'] ?? '{}'), true);
                $cfg = array_replace(smpro_gw_cfg(), is_array($in) ? $in : []);
                $cfg['enabled'] = false;                       // saving settings never arms; arming is its own press
                $ok = smpro_gw_save($cfg);
                $out = ['ok' => $ok, 'msg' => $ok ? 'Saved. Nothing is walled yet.' : 'Could not write the settings.', 'cfg' => smpro_gw_cfg()];
            } elseif ($act === 'gw_fetch') {
                $cfg = smpro_gw_cfg();
                $r = smpro_gw_fetch((array)$cfg['countries'], smpro_gw_ports($cfg));
                $out = $r;
            } elseif ($act === 'gw_preview') {
                $cfg = smpro_gw_cfg();
                $out = smpro_gw_apply($cfg, $gwIp, true);
                $out['check'] = smpro_gw_arm_check($cfg, $gwIp);
            } elseif ($act === 'gw_apply') {
                $cfg = smpro_gw_cfg();
                $cfg['enabled'] = true;
                $cfg['last_seen'] = time();
                $r = smpro_gw_apply($cfg, $gwIp, false);
                if (!empty($r['ok'])) {
                    // Re-read before saving. apply() records the address it was proven from; writing back the
                    // copy that was read BEFORE it ran wiped that value, and the reboot re-assert then had
                    // nothing to check against - the wall would simply never come back. Seen on a live server.
                    $fresh = smpro_gw_cfg();
                    $fresh['enabled'] = true; $fresh['last_seen'] = time();
                    smpro_gw_save($fresh);
                    if (function_exists('smpro_gw_cron_sync')) smpro_gw_cron_sync();
                }
                $out = $r;
            } else {
                $rm = smpro_gw_remove();
                $cfg = smpro_gw_cfg(); $cfg['enabled'] = false; smpro_gw_save($cfg);
                if (function_exists('smpro_gw_cron_sync')) smpro_gw_cron_sync();
                $out = ['ok' => !empty($rm['ok']), 'msg' => $rm['removed'] . ' rule(s) removed. Nothing is walled.'];
            }
        }
    } catch (\Throwable $e) {
        // A throw while a DROP rule may be half-applied is the worst moment to leave things as they are.
        if (function_exists('smpro_gw_remove')) @smpro_gw_remove();
        if (function_exists('smpro_soft_fail')) smpro_soft_fail('geowall_endpoint', $e);
        $out = ['ok' => false, 'msg' => 'The wall hit an error and was taken down: ' . $e->getMessage()];
    }
    smpro_audit('geowall_action', ['action' => $act, 'ok' => !empty($out['ok'])]);
    echo json_encode($out, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

// The door wall: sign-ins from countries nobody is allowed from are refused by cPHulk before the password is
// checked. Armed and disarmed here, next to the list it follows.
if ($reqMethod === 'POST' && in_array((string)($_POST['fw_action'] ?? ''), ['gh_arm', 'gh_disarm'], true)) {
    smpro_require_valid_csrf('fw_csf'); smpro_require_root();
    header('Content-Type: application/json');
    if (!function_exists('smpro_gh_cfg')) { $ghf = SMPRO_BASE . '/includes/geohulk.php'; if (@is_file($ghf)) require_once $ghf; }
    $out = ['ok' => false, 'msg' => 'The door wall is not available in this build.'];
    try {
        if (function_exists('smpro_gh_arm')) {
            $out = ((string)$_POST['fw_action'] === 'gh_arm')
                 ? smpro_gh_arm((string)($_SERVER['REMOTE_ADDR'] ?? ''), smpro_current_actor())
                 : smpro_gh_disarm(smpro_current_actor());
            $out['status'] = smpro_gh_status();
        }
    } catch (\Throwable $e) {
        if (function_exists('smpro_soft_fail')) smpro_soft_fail('geohulk_endpoint', $e);
        $out = ['ok' => false, 'msg' => 'The wall could not be changed: ' . $e->getMessage()];
    }
    echo json_encode($out, JSON_UNESCAPED_SLASHES); exit;
}
if ($reqMethod === 'POST' && in_array((string)($_POST['fw_action'] ?? ''), ['gl_save', 'gl_scan', 'gl_unblock', 'gl_expire'], true)) {
    smpro_require_valid_csrf('fw_csf'); smpro_require_root();
    header('Content-Type: application/json');
    $act = (string)$_POST['fw_action'];
    $out = ['ok' => false, 'msg' => 'Unknown action.'];
    try {
        if ($act === 'gl_save') {
            $patch = [
                'countries'  => smpro_gl_clean_cc(preg_split('/[\s,]+/', (string)($_POST['countries'] ?? ''))),
                'services'   => array_values(array_intersect((array)($_POST['services'] ?? []), array_keys(smpro_gl_services()))),
                'on_success' => in_array((string)($_POST['on_success'] ?? ''), ['block', 'alert'], true) ? (string)$_POST['on_success'] : 'block',
                'on_failed'  => in_array((string)($_POST['on_failed'] ?? ''), ['block', 'ignore'], true) ? (string)$_POST['on_failed'] : 'ignore',
                'ttl_days'   => max(1, min(365, (int)($_POST['ttl_days'] ?? 30))),
                'dryrun'     => !empty($_POST['dryrun']),
                'evict'      => !empty($_POST['evict']),
                'custom_ports' => smpro_gl_clean_ports((string)($_POST['custom_ports'] ?? '')),
            ];
            // Per-account overrides, one per line: account = CC,CC
            $pa = [];
            foreach (preg_split('/\r?\n/', (string)($_POST['per_account'] ?? '')) as $line) {
                $line = trim($line); if ($line === '' || strpos($line, '=') === false) continue;
                [$u, $cc] = array_map('trim', explode('=', $line, 2));
                $u = preg_replace('/[^a-zA-Z0-9._-]/', '', $u);
                $cc = smpro_gl_clean_cc(preg_split('/[\s,]+/', $cc));
                if ($u !== '' && $cc) $pa[$u] = $cc;
            }
            $patch['per_account'] = $pa;

            // The lock-out guard runs BEFORE enabling, never after. A refusal here leaves the previous state
            // exactly as it was — a half-armed lock is how somebody loses their own panel.
            $wantOn = !empty($_POST['enabled']);
            $probe  = array_replace(smpro_gl_cfg(), $patch, ['enabled' => $wantOn]);
            $chk    = smpro_gl_arm_check($probe, (string)($_SERVER['REMOTE_ADDR'] ?? ''));
            if ($wantOn && !$chk['ok']) {
                $out = ['ok' => false, 'armed' => false, 'problems' => $chk['problems'],
                        'msg' => 'Not armed — ' . implode(' ', $chk['problems'])];
            } else {
                $patch['enabled'] = $wantOn;
                $cfg = smpro_gl_cfg_save($patch);
                smpro_audit('geologin_settings', ['on' => $cfg['enabled'] ? 1 : 0, 'dryrun' => $cfg['dryrun'] ? 1 : 0,
                    'countries' => count($cfg['countries']), 'services' => count($cfg['services']),
                    'per_account' => count($cfg['per_account']), 'actor' => smpro_current_actor()]);
                $out = ['ok' => true, 'armed' => $cfg['enabled'], 'cfg' => $cfg, 'check' => $chk,
                        'msg' => !$cfg['enabled'] ? 'Saved. The lock is off.'
                               : ($cfg['dryrun'] ? 'Saved and armed in DRY RUN — it will report what it would block and write nothing.'
                                                 : 'Saved and ARMED. Login ports will be closed for sign-ins from countries not on the list.')];
            }
        } elseif ($act === 'gl_scan') {
            $out = smpro_gl_run(!empty($_POST['dryrun']));
            $out['active'] = smpro_gl_active();
        } elseif ($act === 'gl_unblock') {
            $ip = trim((string)($_POST['ip'] ?? ''));
            $out = smpro_gl_unblock($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '');
            smpro_audit('geologin_unblock', ['ip' => $ip ?: 'all', 'removed' => (int)($out['removed'] ?? 0), 'actor' => smpro_current_actor()]);
        } elseif ($act === 'gl_expire') {
            $out = smpro_gl_expire();
            $out['msg'] = (int)$out['removed'] . ' expired rule line(s) removed.';
        }
    } catch (\Throwable $e) {
        if (function_exists('smpro_soft_fail')) smpro_soft_fail('geologin', $e);
        $out = ['ok' => false, 'msg' => 'That hit an error: ' . $e->getMessage()];
    }
    echo json_encode($out, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

/* Recommended block-lists: refresh, review, apply, remove, and sharing. Every one of these is a press; nothing
 * on this page blocks anything on a timer. */
if ($reqMethod === 'POST' && in_array((string)($_POST['fw_action'] ?? ''), ['bl_review', 'bl_apply', 'bl_undo', 'bl_share_set', 'bl_share_preview', 'bl_share_send'], true)) {
    smpro_require_valid_csrf('fw_csf'); smpro_require_root();
    header('Content-Type: application/json');
    if (!function_exists('smpro_fw_block_sources')) { echo json_encode(['ok' => false, 'msg' => 'The block-list engine is not installed on this server.']); exit; }
    $act = (string)$_POST['fw_action'];
    $key = preg_replace('/[^a-z0-9_]/', '', (string)($_POST['key'] ?? ''));
    $out = ['ok' => false, 'msg' => 'Unknown action.'];
    try {
        if ($act === 'bl_review') {
            if (!empty($_POST['refresh'])) smpro_fw_block_fetch($key);
            $rev = smpro_fw_block_review($key);
            // Counts and a short sample — never the whole list down the wire. The decision needs the shape of it.
            $samp = fn(array $l) => array_slice(array_map(fn($r) => ['ip' => $r['ip'], 'servers' => (int)($r['servers'] ?? 0), 'kind' => (string)($r['kind'] ?? ''), 'bot' => (string)($r['bot'] ?? '')], $l), 0, 25);
            $out = ['ok' => true, 'total' => $rev['total'], 'complete' => $rev['complete'],
                    'n' => ['add' => count($rev['add']), 'blocked' => count($rev['blocked']), 'allowed' => count($rev['allowed']),
                            'crawler' => count($rev['crawler']), 'human' => count($rev['human'])],
                    'sample' => ['add' => $samp($rev['add']), 'crawler' => $samp($rev['crawler'])],
                    'synced_at' => smpro_fw_block_synced_at($key)];
        } elseif ($act === 'bl_apply')  { $out = smpro_fw_block_apply($key); unset($out['review']); }
        elseif ($act === 'bl_undo')     { $out = smpro_fw_block_undo($key); }
        elseif ($act === 'bl_share_set') {
            $on = !empty($_POST['on']);
            smpro_fw_block_set_contributing($on);
            smpro_audit('firewall_blocklist_share', ['on' => $on ? 1 : 0, 'actor' => smpro_current_actor()]);
            $out = ['ok' => true, 'on' => smpro_fw_block_contributing(),
                    'msg' => $on ? 'Sharing is on. Nothing is sent until you press Share now — this only permits it.' : 'Sharing is off.'];
        } elseif ($act === 'bl_share_preview') {
            // The review half of sharing: this is exactly what WOULD be sent, shown before anything leaves.
            $rows = smpro_fw_block_contribution();
            $out = ['ok' => true, 'n' => count($rows), 'sample' => array_slice($rows, 0, 25), 'on' => smpro_fw_block_contributing()];
        } elseif ($act === 'bl_share_send') { $out = smpro_fw_block_contribute(); }
    } catch (\Throwable $e) {
        if (function_exists('smpro_soft_fail')) smpro_soft_fail('fw_blocklist', $e);
        $out = ['ok' => false, 'msg' => 'That hit an error: ' . $e->getMessage()];
    }
    echo json_encode($out, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

if ($reqMethod === 'POST' && ($_POST['fw_action'] ?? '') === 'crawler_audit') {
    smpro_require_valid_csrf('fw_csf'); smpro_require_root();
    header('Content-Type: application/json');
    if (!function_exists('smpro_bg_crawler_shield')) { $bg = SMPRO_BASE . '/includes/botguard.php'; if (@is_file($bg)) require_once $bg; }
    if (!function_exists('smpro_bg_crawler_shield')) { echo json_encode(['ok'=>false,'error'=>'Bot Guard is not installed on this server.']); exit; }

    $ips = [];
    foreach (explode(',', (string)($_POST['ips'] ?? '')) as $x) { $x = trim($x); if (filter_var($x, FILTER_VALIDATE_IP)) $ips[$x] = 1; }
    // No arbitrary cap: the list is whatever is blocked on THIS server, which is the number that matters. What
    // bounds the work is the time budget below, and anything it does not reach is reported as not reached.
    $ips = array_keys($ips);

    // All of them at once. Resolving one address at a time waited out the resolver's timeout on every miss, so a
    // list of 199 got through 30 before the budget ran out — a check nobody runs seven times to finish. The
    // answers are cached for a week, so a second run over the same list is instant.
    // Derived from how many of these are actually unresolved and from the server's own sweep settings, so a list
    // of forty and a list of four thousand each get the time they need instead of a number picked in advance.
    $rdns = smpro_bg_rdns_bulk($ips);
    $checked = 0; $found = []; $complete = true;
    foreach ($ips as $ip) {
        if (!array_key_exists($ip, $rdns)) { $complete = false; continue; }   // the sweep did not reach this one
        $checked++;
        // The forward confirmation costs a second lookup, but it only runs when the reverse name already sits
        // under a publisher's domain — which for a list of attackers is almost never.
        $cs = smpro_bg_crawler_shield($ip, null, $rdns[$ip]);
        if (!empty($cs['crawler'])) $found[] = ['ip'=>$ip, 'name'=>$cs['name'], 'kind'=>$cs['kind'], 'host'=>$cs['host']];
    }
    smpro_audit('firewall_crawler_audit', ['checked'=>$checked, 'found'=>count($found), 'complete'=>$complete]);
    echo json_encode(['ok'=>true, 'checked'=>$checked, 'total'=>count($ips), 'complete'=>$complete, 'found'=>$found],
        JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

if ($reqMethod === 'POST' && ($_POST['fw_action'] ?? '') === 'service') {
    smpro_require_valid_csrf('fw_csf'); smpro_require_root();
    header('Content-Type: application/json');
    $svc = preg_replace('/[^a-z0-9_-]/', '', strtolower((string)($_POST['svc'] ?? '')));
    $op  = (string)($_POST['op'] ?? '');
    if (!in_array($svc, ['lfd', 'firewalld', 'nftables'], true)) { echo json_encode(['ok'=>false,'msg'=>'Service not allowed.']); exit; }
    if (!in_array($op, ['start', 'stop', 'restart', 'enable', 'disable'], true)) { echo json_encode(['ok'=>false,'msg'=>'Operation not allowed.']); exit; }
    // A FAILED unit (or one that hit its systemd start-limit) refuses to start again until its failed state is
    // cleared — reset-failed FIRST so the start/restart below can actually recover it.
    if (in_array($op, ['start','restart'], true)) @shell_exec('timeout 10 systemctl reset-failed ' . escapeshellarg($svc) . ' 2>/dev/null');
    // LFD is managed by CSF — prefer csf --lfd for start/stop/restart when csf is present.
    $out = '';
    $csf = smpro_fw_csf_bin();
    if ($svc === 'lfd' && $csf !== '' && in_array($op, ['start','stop','restart'], true)) {
        $out = smpro_fw_run(escapeshellarg($csf) . ' --lfd ' . escapeshellarg($op), 30);
        // csf --lfd can print a message yet leave systemd in 'failed' → if LFD still isn't active, fall through to systemctl.
        if (in_array($op, ['start','restart'], true) && trim(smpro_fw_run('systemctl is-active lfd')) !== 'active') $out = '';
    }
    if (trim($out) === '') {
        $sysop = $op === 'start' ? 'restart' : $op;   // start→restart is idempotent & recovers a failed unit
        $out = smpro_fw_run('systemctl ' . escapeshellarg($sysop) . ' ' . escapeshellarg($svc), 30);
    }
    // verify
    $now = trim(smpro_fw_run('systemctl is-active ' . escapeshellarg($svc))) ?: 'unknown'; $nowEn = trim(smpro_fw_run('systemctl is-enabled ' . escapeshellarg($svc))) ?: 'unknown';   // fresh: this is the answer to the button just pressed
    $ok = in_array($op, ['start','restart'], true) ? ($now === 'active')
        : (in_array($op, ['stop','disable'], true) ? ($now !== 'active' || $op === 'disable')
        : ($op === 'enable' ? ($nowEn === 'enabled') : true));
    // On a FAILED start/restart, capture WHY (systemd status + lfd.log) so the admin sees the real cause instead of a
    // bare "could not restart" — a persistently-failing LFD is a config problem the restart itself cannot fix.
    $why = '';
    if (in_array($op, ['start','restart'], true) && $now !== 'active') {
        $why = trim((string)@shell_exec('timeout 10 systemctl status ' . escapeshellarg($svc) . ' --no-pager --lines=8 2>&1'));
        if ($svc === 'lfd') {
            $lg = trim((string)@shell_exec('timeout 10 tail -n 10 /var/log/lfd.log 2>/dev/null'));
            if ($lg !== '') $why .= "\n\nlfd.log (last lines):\n" . $lg;
        }
    }
    smpro_audit('firewall_service', ['svc'=>$svc, 'op'=>$op, 'active'=>$now, 'enabled'=>$nowEn, 'actor'=>smpro_current_actor()]);
    $reason = $why !== '' ? $why : trim((string)$out);
    echo json_encode(['ok'=>$ok, 'active'=>$now, 'enabled'=>$nowEn,
        'msg'=>($ok ? ucfirst($svc) . ' ' . $op . ' → active=' . $now
                    : ('Could not ' . $op . ' ' . $svc . ' (active=' . $now . ").\n\nReason:\n" . trim(mb_substr($reason, 0, 800))))],
        JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
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
        echo json_encode(['ok'=>$ok, 'msg'=>$ok ? 'CSF switched to production (TESTING=0) and reloaded. Backup: csf.conf.smpro.bak' : 'csf reload reported an error.'], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
    }
    if (in_array($op, ['enable', 'disable', 'restart'], true)) {
        $flag = $op === 'enable' ? '-e' : ($op === 'disable' ? '-x' : '-r');
        $out = smpro_fw_run(escapeshellarg($csf) . ' ' . $flag, 45);
        $ok = stripos($out, 'error') === false && trim($out) !== '';
        smpro_audit('firewall_csf_' . $op, ['ok'=>$ok, 'actor'=>smpro_current_actor()]);
        $msg = $op === 'disable' ? 'CSF DISABLED (firewall is now OFF — re-enable to restore protection).' : ($op === 'enable' ? 'CSF enabled.' : 'CSF reloaded.');
        echo json_encode(['ok'=>$ok, 'msg'=>$ok ? $msg : ('csf ' . $flag . ' failed: ' . trim(mb_substr($out,0,140)))], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
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
    echo json_encode(['ok'=>$ok, 'msg'=>$ok ? ('Never-block applied (' . $mode . ') for: ' . ($val ?: '(none)') . '. CSF reloaded. Backup: csf.conf.smpro.ccbak') : ('csf -r reported an error: ' . trim(mb_substr($out, 0, 140)))], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

/* ---------- EMERGENCY: allow an IP on the LIVE firewall right now (anti-lockout). Works even if CSF is
 *            disabled/TESTING/desynced, and even if the IP is already in csf.allow (which may NOT be applied
 *            to the loaded rules). Inserts a top-of-INPUT ACCEPT (beats imunify360/CSF/LOCALINPUT drops) AND
 *            persists to csf.allow. POST+CSRF+root. Does NOT require CSF to be installed. ---------- */
if ($reqMethod === 'POST' && ($_POST['fw_action'] ?? '') === 'allow_live') {
    smpro_require_valid_csrf('fw_csf'); smpro_require_root();
    header('Content-Type: application/json');
    $ip = trim((string)($_POST['ip'] ?? ''));
    if ($ip === 'self' || $ip === '') $ip = function_exists('smpro_admin_ip') ? smpro_admin_ip() : '';
    if (!filter_var($ip, FILTER_VALIDATE_IP)) { echo json_encode(['ok'=>false,'msg'=>'No valid IP to allow.']); exit; }
    $live    = function_exists('smpro_fw_iptables_allow') ? smpro_fw_iptables_allow($ip) : '';    // ALWAYS apply live (even if already in csf.allow)
    $persist = function_exists('smpro_csf_allow_add') ? smpro_csf_allow_add($ip, 'admin emergency allow (live)') : ['ok'=>false];
    $ok = ($live !== '') || !empty($persist['ok']);
    smpro_audit('firewall_allow_live', ['ip'=>$ip, 'live'=>$live !== '' ? 1 : 0, 'actor'=>smpro_current_actor()]);
    $msg = ($live !== '' ? '✓ Applied to the LIVE firewall now (' . $live . ') — access is protected immediately.' : '⚠ Could not insert a live iptables rule (no iptables?).');
    if (!empty($persist['ok'])) $msg .= ' Saved to csf.allow for persistence.';
    echo json_encode(['ok'=>$ok, 'msg'=>$msg], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

/* ---------- Re-sync a desynced firewall: re-enable CSF (removes /etc/csf/csf.disable) + reload so the LIVE rules are
 *            rebuilt from csf.conf/csf.allow/csf.deny — closing the "disabled CSF but stale DROP rules" gap. ---------- */
if ($reqMethod === 'POST' && ($_POST['fw_action'] ?? '') === 'fw_resync') {
    smpro_require_valid_csrf('fw_csf'); smpro_require_root();
    header('Content-Type: application/json');
    $csf = smpro_fw_csf_bin();
    if ($csf === '') { echo json_encode(['ok'=>false,'msg'=>'CSF is not installed — nothing to re-sync.']); exit; }
    @shell_exec('timeout 30 ' . escapeshellarg($csf) . ' -e 2>&1');            // enable (drops the csf.disable marker)
    $out = (string)@shell_exec('timeout 90 ' . escapeshellarg($csf) . ' -r 2>&1');   // restart → rebuild rules from config
    $ok = !@is_file('/etc/csf/csf.disable');
    smpro_audit('firewall_resync', ['ok'=>$ok ? 1 : 0, 'actor'=>smpro_current_actor()]);
    echo json_encode(['ok'=>$ok, 'msg'=>$ok ? '✓ CSF re-enabled &amp; reloaded — the live firewall now matches your allow/deny lists (your whitelist is applied).' : 'CSF is still disabled after the attempt — open WHM › ConfigServer Security &amp; Firewall.'], JSON_UNESCAPED_SLASHES); exit;
}

/* ---------- controlled action: add an IP to allow (whitelist) or deny (block), POST+CSRF+root ---------- */
if ($reqMethod === 'POST' && ($_POST['fw_action'] ?? '') === 'ipadd') {
    smpro_require_valid_csrf('fw_csf'); smpro_require_root();
    header('Content-Type: application/json');
    // NOTE: no longer requires CSF. Allows/blocks are routed to whatever firewall is actually running (CSF and/or
    // Imunify) PLUS a live iptables rule, so adding an IP works even when CSF is not installed/active.
    $ip = trim((string)($_POST['ip'] ?? ''));
    if (!filter_var($ip, FILTER_VALIDATE_IP)) { echo json_encode(['ok'=>false,'msg'=>'Enter a valid IP address.']); exit; }
    $op = (($_POST['op'] ?? '') === 'block') ? 'block' : 'allow';
    $reason = preg_replace('/[^A-Za-z0-9 ._\-\/:]/', '', mb_substr(trim((string)($_POST['reason'] ?? '')), 0, 80));
    if ($op === 'allow') {
        // works WITH or WITHOUT CSF: CSF allow-list and/or Imunify whitelist + a live iptables INPUT ACCEPT
        $r = function_exists('smpro_fw_live_allow') ? smpro_fw_live_allow($ip, $reason ?: 'manual allow')
           : (function_exists('smpro_csf_allow_add') ? smpro_csf_allow_add($ip, $reason ?: 'manual allow') : ['ok'=>false,'msg'=>'No allow method available.']);
        smpro_audit('firewall_ip_allow', ['ip'=>$ip, 'reason'=>$reason, 'ok'=>!empty($r['ok']), 'actor'=>smpro_current_actor()]);
        echo json_encode(['ok'=>!empty($r['ok']), 'msg'=>(string)$r['msg']], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
    }
    // block: an optional non-permanent DURATION uses CSF's native temp-deny (auto-expires in TTL seconds) instead of a
    // permanent csf.deny entry. Permanent keeps the existing csf.deny path unchanged.
    $csf = smpro_fw_csf_bin();
    $ttlMap = ['1h' => 3600, '6h' => 21600, '24h' => 86400, '72h' => 259200];   // allowed TTLs — clamps the client value
    $dur = (string)($_POST['dur'] ?? 'permanent');
    if ($dur !== 'permanent' && isset($ttlMap[$dur])) {
        // CSF temp-deny: `csf -td <ip> <ttl_seconds> -c "<comment>"`. NOTE: in csf's CLI -d is the DIRECTION flag
        // (in/out) and -c is the COMMENT flag, so the "SM Pro temp block" label is passed with -c. IP was validated
        // above (filter_var); ttl is a clamped int (no shell metachars); ip + comment are escapeshellarg'd.
        if ($csf === '') { echo json_encode(['ok'=>false,'msg'=>'Temporary blocks require CSF, which is not installed. Use a permanent block instead.'], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit; }
        // Same safety guard the permanent path (smpro_csf_deny_add) enforces: NEVER block a Cloudflare edge IP —
        // it fronts inbound traffic for every site, so a deny black-holes all of them.
        if (function_exists('smpro_ip_is_cloudflare') && smpro_ip_is_cloudflare($ip)) {
            echo json_encode(['ok'=>false,'msg'=>'Refused: ' . $ip . ' is a Cloudflare edge IP — blocking it would cut ALL inbound traffic. Block the real client at Cloudflare, not CSF.'], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
        }
        $ttl = (int)$ttlMap[$dur];
        $cmt = 'SM Pro temp block' . ($reason !== '' ? ': ' . $reason : '');
        smpro_fw_run(escapeshellarg($csf) . ' -td ' . escapeshellarg($ip) . ' ' . $ttl . ' -c ' . escapeshellarg($cmt), 30);
        // VERIFY from CSF's own temp-ban list instead of trusting stdout — smpro_fw_run runs with 2>/dev/null,
        // so a stderr-only csf failure would leave empty output and be mis-read as success. Honor TESTING mode too.
        $tlist    = (string)smpro_memo('fw_csf_t', 20, fn() => smpro_fw_run(escapeshellarg($csf) . ' -t', 15), true);   // fresh: refreshes the render memo too
        $recorded = strpos($tlist, $ip) !== false;
        $testing  = function_exists('smpro_csf_testing') && smpro_csf_testing();
        $ok  = $recorded && !$testing;
        $msg = !$recorded ? ('CSF did not record the temporary block for ' . $ip . ' — check CSF and try a permanent block.')
             : ($testing ? ($ip . ' temp-blocked in csf.tempban, but CSF is in TESTING mode — NOT enforced. Set TESTING=0 (Server Tune-up).')
                         : ($ip . ' temporarily blocked for ' . $dur . ' (auto-expires) via CSF temp-deny.'));
        smpro_audit('firewall_ip_block', ['ip'=>$ip, 'reason'=>$reason, 'temp'=>$dur, 'ttl'=>$ttl, 'ok'=>$ok, 'actor'=>smpro_current_actor()]);
        echo json_encode(['ok'=>$ok, 'msg'=>$msg], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
        exit;
    }
    // permanent block: prefer CSF (csf.deny, verified + Cloudflare-safe); if CSF is absent, block via Imunify + live iptables DROP
    if ($csf !== '' && function_exists('smpro_csf_deny_add')) $r = smpro_csf_deny_add($ip, $reason ?: 'manual block');
    elseif (function_exists('smpro_fw_live_block'))           $r = smpro_fw_live_block($ip, $reason ?: 'manual block');
    else                                                      $r = ['ok'=>false, 'msg'=>'No block method available.'];
    smpro_audit('firewall_ip_block', ['ip'=>$ip, 'reason'=>$reason, 'ok'=>!empty($r['ok']), 'actor'=>smpro_current_actor()]);
    echo json_encode(['ok'=>!empty($r['ok']), 'msg'=>(string)$r['msg']], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

/* ---------- controlled action: add/remove a recommended provider allow-list (POST+CSRF+root) ---------- */
if ($reqMethod === 'POST' && ($_POST['fw_action'] ?? '') === 'allow_provider') {
    smpro_require_valid_csrf('fw_csf'); smpro_require_root();
    header('Content-Type: application/json');
    $key = preg_replace('/[^a-z0-9]/', '', strtolower((string)($_POST['provider'] ?? '')));
    if (!isset(smpro_fw_allow_providers()[$key])) { echo json_encode(['ok'=>false,'msg'=>'Unknown provider.']); exit; }
    // apply() fetches the current ranges from the live feed first (Cloudflare/UptimeRobot/Google/Bing) then adds them.
    $r = (($_POST['op'] ?? '') === 'remove') ? smpro_fw_allow_undo($key) : smpro_fw_allow_apply($key);
    echo json_encode($r, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}
/* ---------- controlled action: sync a provider from its live feed now (POST+CSRF+root) ---------- */
if ($reqMethod === 'POST' && ($_POST['fw_action'] ?? '') === 'provider_sync') {
    smpro_require_valid_csrf('fw_csf'); smpro_require_root();
    header('Content-Type: application/json');
    $key = preg_replace('/[^a-z0-9]/', '', strtolower((string)($_POST['provider'] ?? '')));
    if (!isset(smpro_fw_allow_providers()[$key])) { echo json_encode(['ok'=>false,'msg'=>'Unknown provider.']); exit; }
    $r = smpro_fw_allow_reconcile($key);
    smpro_audit('firewall_allow_sync', ['provider'=>$key, 'added'=>$r['added'] ?? 0, 'removed'=>$r['removed'] ?? 0, 'actor'=>smpro_current_actor()]);
    echo json_encode(['ok'=>!isset($r['err']), 'msg'=>isset($r['err']) ? ('Sync: ' . $r['err']) : ('Synced from the live feed — added ' . ($r['added'] ?? 0) . ', removed ' . ($r['removed'] ?? 0) . ' stale.')], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}
/* ---------- controlled action: toggle auto-update for a provider (POST+CSRF+root) ---------- */
if ($reqMethod === 'POST' && ($_POST['fw_action'] ?? '') === 'rec_autoupdate') {
    smpro_require_valid_csrf('fw_csf'); smpro_require_root();
    header('Content-Type: application/json');
    $key = preg_replace('/[^a-z0-9]/', '', strtolower((string)($_POST['key'] ?? '')));
    $on  = (($_POST['on'] ?? '') === '1');
    $ok  = ($key !== '') && smpro_fw_allow_set_autoupdate($key, $on);
    if ($ok && $on) smpro_fw_allow_reconcile($key);   // apply immediately on enable so it is in sync right away
    smpro_audit('firewall_allow_autoupdate_cfg', ['provider'=>$key, 'on'=>$on ? 1 : 0, 'actor'=>smpro_current_actor()]);
    echo json_encode(['ok'=>$ok, 'msg'=>$ok ? ($on ? 'Auto-update ON — SM Pro will keep these IPs current automatically (every 6h), no need to come back.' : 'Auto-update OFF.') : 'Could not update.'], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

/* ---------- controlled action: add MULTIPLE providers at once (multi-select) (POST+CSRF+root) ---------- */
if ($reqMethod === 'POST' && ($_POST['fw_action'] ?? '') === 'allow_batch') {
    smpro_require_valid_csrf('fw_csf'); smpro_require_root();
    header('Content-Type: application/json');
    $providers = smpro_fw_allow_providers();
    $keys = array_values(array_unique(array_filter(array_map(fn($k)=>preg_replace('/[^a-z0-9]/', '', strtolower((string)$k)), (array)($_POST['providers'] ?? [])))));
    if (!$keys) { echo json_encode(['ok'=>false,'msg'=>'Select at least one provider first.']); exit; }
    $done = 0; $parts = [];
    foreach ($keys as $key) {
        if (!isset($providers[$key])) continue;
        $r = smpro_fw_allow_apply($key);              // fetches the live feed then adds, per provider
        if (!empty($r['ok'])) $done++;
        $parts[] = $r['msg'] ?? ($key . ': done');
    }
    echo json_encode(['ok'=>$done > 0, 'msg'=>($done . ' of ' . count($keys) . ' provider(s) applied. ') . implode(' | ', $parts)], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

/* ---------- read-only: current per-provider allow-list state (lets the card refresh in place, no page reload) ---------- */
if (($_POST['fw_action'] ?? $_GET['fw_action'] ?? '') === 'allow_states') {
    header('Content-Type: application/json');
    $out = []; $auto = smpro_fw_allow_autoupdate(); $ign = smpro_fw_rec_ignored();
    foreach (smpro_fw_allow_providers() as $k => $pv) {
        $ranges = smpro_fw_allow_ranges($k); $st = smpro_fw_allow_status($ranges, $k); $sy = smpro_fw_allow_synced_at($k);
        $out[$k] = ['present'=>$st['present'], 'total'=>$st['total'], 'marked'=>$st['marked'],
                    'full'=>($st['total'] > 0 && $st['present'] >= $st['total']),
                    'auto'=>in_array($k, $auto, true), 'ignored'=>in_array($k, $ign, true),
                    'synced'=>$sy ? date('M j, H:i', $sy) : ''];
    }
    echo json_encode(['ok'=>true, 'states'=>$out], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

/* ---------- controlled action: ignore / restore a recommendation (POST+CSRF+root) ---------- */
if ($reqMethod === 'POST' && ($_POST['fw_action'] ?? '') === 'rec_ignore') {
    smpro_require_valid_csrf('fw_csf'); smpro_require_root();
    header('Content-Type: application/json');
    $key = preg_replace('/[^a-z0-9_]/', '', strtolower((string)($_POST['key'] ?? '')));
    $ignore = (($_POST['op'] ?? 'ignore') !== 'unignore');
    $ok = ($key !== '') && smpro_fw_rec_set_ignore($key, $ignore);
    smpro_audit('firewall_rec_ignore', ['key'=>$key, 'ignore'=>$ignore ? 1 : 0, 'actor'=>smpro_current_actor()]);
    echo json_encode(['ok'=>$ok, 'msg'=>$ok ? ($ignore ? 'Recommendation hidden.' : 'Recommendation restored.') : 'Could not update.'], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

$csfBin = smpro_fw_csf_bin();
$csfInstalled = $csfBin !== '';
// CSF DISABLED (`csf -x`) drops the marker /etc/csf/csf.disable; while it exists, lfd starts then immediately exits
// ("csf and lfd have been disabled") and systemd marks it failed — so a "failed LFD" here is usually a DISABLED CSF.
$csfDisabled = $csfInstalled && @is_file('/etc/csf/csf.disable');
// The four slow probes on the render path (about 0.9 s together on a busy box) are memoised: the version for an
// hour, rule counts and the temp-ban list for 20 s; a temp block made on this page refreshes the ban memo itself.
$csfVer = $csfInstalled ? (string)smpro_memo('fw_csf_ver', 3600, fn() => trim(smpro_fw_run(escapeshellarg($csfBin) . ' -v'))) : '';
if (preg_match('/v?[\d.]+/', $csfVer, $vm)) $csfVer = $vm[0];

$lfd = smpro_fw_active('lfd'); $lfdEn = smpro_fw_enabled('lfd');
$firewalld = smpro_fw_active('firewalld'); $firewalldEn = smpro_fw_enabled('firewalld');
$nftables = smpro_fw_active('nftables'); $nftablesEn = smpro_fw_enabled('nftables');

$deny = smpro_fw_deny_list();
$denyCount = count($deny);

/* ---- csf.deny rows: built once, filtered / sorted / paged on the SERVER. 4,828 entries rendered as one 744 KB table made this
 *      the heaviest page of the product; a page is 50 rows and the filter box asks for the next 50. ---- */
$fwBuildDenyRows = function (array $deny): array {
    $rows = [];
    foreach ($deny as $d) {
        $bare = explode('/', $d['ip'])[0];
        if (!smpro_ip_is_external($bare)) continue;
        $in = smpro_ip_intel($bare, false);
        if (stripos((string)($in['provider'] ?? ''), 'CLOUDFLARE') !== false) continue;
        $rows[] = ['raw' => $d, 'bare' => $bare, 'in' => $in, 'cc' => strtoupper((string)($in['country'] ?? '')), 'bot' => smpro_ip_is_datacenter($in)];
    }
    return $rows;
};
$fwDenyFilter = function (array $rows, string $scope, string $q, string $sk, string $sd): array {
    $home = function_exists('smpro_im_trusted_regions') ? array_flip(array_map('strtoupper', (array)smpro_im_trusted_regions())) : [];
    $q = strtolower(trim($q));
    $out = [];
    foreach ($rows as $r) {
        if ($scope === 'bot' && empty($r['bot'])) continue;
        if ($scope === 'arab' && !isset($home[$r['cc']])) continue;
        if ($scope === 'nonarab' && isset($home[$r['cc']])) continue;
        if ($q !== '' && strpos(strtolower($r['raw']['ip'] . ' ' . $r['raw']['comment'] . ' ' . $r['cc'] . ' ' . ($r['in']['provider'] ?? '')), $q) === false) continue;
        $out[] = $r;
    }
    if (in_array($sk, ['ip', 'cc', 'comment'], true)) {
        $key = fn($r) => $sk === 'ip' ? $r['raw']['ip'] : ($sk === 'cc' ? $r['cc'] : (string)$r['raw']['comment']);
        usort($out, fn($x, $y) => $sd === 'desc' ? strcmp($key($y), $key($x)) : strcmp($key($x), $key($y)));
    }
    return $out;
};
$fwDenyHtml = function (array $rows): string {
    ob_start();
    foreach ($rows as $r) { $d = $r['raw']; $in = $r['in']; $cc = $r['cc']; $bot = $r['bot']; ?>
        <tr data-fwrow="<?= smpro_h($d['ip']) ?>" data-cc="<?= smpro_h($cc) ?>" data-bot="<?= $bot?1:0 ?>"
            data-ip="<?= smpro_h($d['ip']) ?>" data-comment="<?= smpro_h(strtolower($d['comment'])) ?>"
            data-search="<?= smpro_h(strtolower($d['ip'].' '.$d['comment'].' '.$cc.' '.($in['provider']??''))) ?>">
          <td><input type="checkbox" class="fw-chk" value="<?= smpro_h($d['ip']) ?>"></td>
          <td class="ipmono"><?= smpro_h($d['ip']) ?></td>
          <td class="geo"><?php if ($cc!=='' && $cc!=='N/A'): ?><b><?= smpro_h($cc) ?></b> <span class="geo-prov"><?= smpro_h($in['provider']??'') ?></span><?php endif; ?><?= $bot?' <span class="b amber" title="This means the address belongs to a CLOUD OR HOSTING network (a rented server) — not that it is a search engine. Googlebot and the other crawlers live on their own ranges and never attempt a login. Use &quot;Check for real crawlers&quot; above to find any genuine crawler in this list.">&#9729;&#65039; cloud/hosting</span>':'' ?></td>
          <td class="meta"><?= smpro_h($d['comment']) ?: '—' ?></td>
          <td><button class="fw-act unblock" data-ip="<?= smpro_h($d['ip']) ?>">Unblock</button></td>
        </tr>
<?php }
    return (string)ob_get_clean();
};
if ($reqMethod === 'POST' && ($_POST['fw_action'] ?? '') === 'deny_rows') {
    smpro_require_valid_csrf('fw_csf'); smpro_require_root();
    header('Content-Type: application/json; charset=utf-8');
    $rows = $fwDenyFilter($fwBuildDenyRows($deny), preg_replace('/[^a-z]/', '', (string)($_POST['scope'] ?? 'all')), mb_substr((string)($_POST['q'] ?? ''), 0, 80),
                          preg_replace('/[^a-z]/', '', (string)($_POST['sk'] ?? '')), (string)($_POST['sd'] ?? '') === 'desc' ? 'desc' : 'asc');
    $off = max(0, (int)($_POST['off'] ?? 0)); $page = array_slice($rows, $off, 50);
    echo json_encode(['ok' => true, 'total' => count($rows), 'offset' => $off, 'count' => count($page), 'html' => $fwDenyHtml($page)], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}
$allowCount = 0;
if (is_readable('/etc/csf/csf.allow')) foreach (file('/etc/csf/csf.allow', FILE_IGNORE_NEW_LINES) ?: [] as $l) { $l = trim($l); if ($l !== '' && $l[0] !== '#') $allowCount++; }
$tempRaw = $csfInstalled ? (function_exists('smpro_memo_cmd') ? smpro_memo_cmd('fw_csf_t', 60, escapeshellarg($csfBin) . ' -t', 20, 3600, true) : (string)smpro_memo('fw_csf_t', 20, fn() => smpro_fw_run(escapeshellarg($csfBin) . ' -t'))) : '';   // refreshed behind the page, never waited for
$tempDeny = 0; foreach (explode("\n", $tempRaw) as $l) if (stripos($l, 'DENY') !== false) $tempDeny++;
$iptRules = (int)smpro_memo('fw_ipt_n', 120, fn() => (int)trim(smpro_fw_run('iptables -S | wc -l')));
$nftLines = function_exists('smpro_memo_cmd') ? (int)trim(smpro_memo_cmd('fw_nft_n', 300, 'nft list ruleset | wc -l', 30, 86400, true)) : (int)smpro_memo('fw_nft_n', 20, fn() => (int)trim(smpro_fw_run('nft list ruleset | wc -l')));   // 22k rules took up to 2.8 s on every miss: a count only, five minutes old at most, computed behind the page

$cfg = [];
if (is_readable('/etc/csf/csf.conf')) foreach (file('/etc/csf/csf.conf', FILE_IGNORE_NEW_LINES) ?: [] as $l)
    if (preg_match('/^\s*([A-Z0-9_]+)\s*=\s*"?([^"#]*)"?/', $l, $m)) $cfg[$m[1]] = trim($m[2]);
$testing = ($cfg['TESTING'] ?? '') === '1';

// listening ports
$ports = []; $seen = [];
foreach (explode("\n", (string)smpro_memo('fw_ss', 20, fn() => smpro_fw_run('ss -tulnHp', SMPRO_TIMEOUT_NORMAL))) as $l) {   // listening sockets change rarely; 20 s is fresh enough for a status page
    $l = trim($l); if ($l === '') continue;
    $p = preg_split('/\s+/', $l); if (count($p) < 5) continue;
    $proc = preg_match('/users:\(\("([^"]+)",pid=(\d+)/', $l, $pm) ? $pm[1] . ' (pid ' . $pm[2] . ')' : '';
    $k = $p[0] . $p[4]; if (isset($seen[$k])) continue; $seen[$k] = 1;
    $ports[] = ['proto' => $p[0], 'state' => $p[1], 'local' => $p[4], 'proc' => $proc];
}

// resolve country/bot for blocked IPs
smpro_ip_intel_bulk(array_map(fn($r) => explode('/', $r['ip'])[0], array_slice($deny, 0, 120)), true);

// overall status
$status = 'good'; $statusLabel = 'GOOD';
if (!$csfInstalled) { $status = 'danger'; $statusLabel = 'NO FIREWALL'; }
elseif ($csfDisabled) { $status = 'danger'; $statusLabel = 'CSF DISABLED'; }
elseif ($lfd !== 'active') { $status = 'warn'; $statusLabel = 'REVIEW'; }
elseif ($testing) { $status = 'warn'; $statusLabel = 'TESTING MODE'; }

// layers (req = required for protection?)
$layers = [
    ['name' => 'CSF', 'req' => true, 'status' => !$csfInstalled ? 'missing' : ($csfDisabled ? 'disabled' : 'installed'), 'enabled' => ($csfInstalled && !$csfDisabled) ? 'yes' : 'no', 'note' => 'ConfigServer Security &amp; Firewall — primary cPanel firewall manager', 'ok' => $csfInstalled && !$csfDisabled],
    ['name' => 'LFD', 'req' => true, 'status' => $lfd, 'enabled' => $lfdEn, 'note' => 'Login Failure Daemon — brute-force / login monitoring', 'ok' => $lfd === 'active'],
    ['name' => 'firewalld', 'req' => false, 'status' => $firewalld, 'enabled' => $firewalldEn, 'note' => 'Alternative firewall — normally inactive when CSF manages iptables', 'ok' => $firewalld !== 'failed'],
    ['name' => 'nftables', 'req' => false, 'status' => $nftables, 'enabled' => $nftablesEn, 'note' => 'Modern packet filter — usually idle under CSF/iptables', 'ok' => $nftables !== 'failed'],
];
/** Build Fix / Enable / Disable buttons for a firewall component per the action rule. */
function smpro_fw_actions($name, $status, $required, $testing) {
    $comp = strtolower($name); $st = strtolower((string)$status); $b = [];
    if ($comp === 'csf') {
        if ($st === 'missing' || $st === 'disabled') { $b[] = '<button class="fw-act fix" type="button" data-fwop="csf:enable"' . ($st === 'disabled' ? ' data-confirm="Re-enable CSF + LFD now to restore firewall protection?"' : '') . '>&#9889; Enable CSF' . ($st === 'disabled' ? ' (Fix)' : '') . '</button>'; return implode(' ', $b); }
        if ($testing) $b[] = '<button class="fw-act fix" type="button" data-fwop="csf:production" data-confirm="Switch CSF to PRODUCTION (TESTING=0) and reload? Make sure your IP is allowed so you are not locked out.">&#9889; Switch to production</button>';
        $b[] = '<button class="fw-act danger" type="button" data-fwop="csf:disable" data-confirm="DISABLE CSF? This turns the firewall OFF — your server loses CSF protection until re-enabled.">&#9940; Disable CSF</button>';
        return implode(' ', $b);
    }
    $active = ($st === 'active');
    // A FAILED / activating / deactivating unit needs a RESTART (start alone can no-op or be blocked by the
    // systemd start-limit); a cleanly-stopped unit just needs a START.
    $failed = in_array($st, ['failed', 'activating', 'deactivating', 'reloading'], true);
    if (!$active) {
        $op = $failed ? 'restart' : 'start';
        if ($required) $b[] = '<button class="fw-act fix" type="button" data-fwop="svc:' . $op . '" data-fwsvc="' . $comp . '" data-confirm="' . ($failed ? 'Restart' : 'Start') . ' ' . strtoupper($comp) . ' now to restore protection?">&#9889; ' . ($failed ? 'Restart (Fix)' : 'Start (Fix)') . '</button>';
        else           $b[] = '<button class="fw-act ghost" type="button" data-fwop="svc:' . $op . '" data-fwsvc="' . $comp . '" data-confirm="' . ($failed ? 'Restart' : 'Enable') . ' ' . strtoupper($comp) . '? Running two firewall managers can conflict with CSF.">&#9658; ' . ($failed ? 'Restart' : 'Enable') . '</button>';
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
if ($csfDisabled) $rec[] = 'CSF is DISABLED (csf -x) — the firewall is OFF and LFD cannot run. Click “Enable CSF” to restore both.';
if ($lfd !== 'active' && !$csfDisabled) $rec[] = 'LFD is not active — start it to restore brute-force protection.';
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
$smAdminIp = function_exists('smpro_admin_ip') ? smpro_admin_ip() : '';   // REMOTE_ADDR first (see helpers)
$smAdminIntel   = ($smAdminIp && function_exists('smpro_ip_intel')) ? smpro_ip_intel($smAdminIp) : [];
$smAdminCC      = strtoupper((string)($smAdminIntel['country'] ?? ''));
$smAdminAllowed = $smAdminIp && ((function_exists('smpro_csf_allowlisted') && smpro_csf_allowlisted($smAdminIp)) || (function_exists('smpro_im_allowlisted') && smpro_im_allowlisted($smAdminIp)));
$fwSync = function_exists('smpro_fw_sync_state') ? smpro_fw_sync_state() : [];   // desync detection (disabled CSF but stale DROP rules)
?>

<?php if (!empty($fwSync['desync'])): ?>
<div class="card" style="border-left:4px solid var(--dang,#dc2626);background:var(--dang-bg);margin-bottom:14px">
  <div style="font-weight:800;color:var(--dang);font-size:15px">&#9888; Firewall is de-synced — you can get locked out</div>
  <div class="meta" style="margin:6px 0;line-height:1.6;color:#7f1d1d">
    CSF shows <b><?= $fwSync['csf_disabled'] ? 'DISABLED' : ($fwSync['csf_testing'] ? 'TESTING' : 'not actively managing') ?></b>, but the old firewall rules are still loaded: INPUT policy is <b><?= smpro_h($fwSync['input_policy'] ?: '?') ?></b> with <b><?= (int)$fwSync['rule_count'] ?></b> rules<?= $fwSync['chains'] ? ' (chains: ' . smpro_h(implode(', ', $fwSync['chains'])) . ')' : '' ?><?= !empty($fwSync['imunify']) ? ' and Imunify360 is present' : '' ?>. In this state a whitelist you add to CSF is <b>not applied to the live rules</b>, and incoming SYN packets are dropped (e.g. inside INPUT_imunify360 / LOCALINPUT) before reaching the port-22 allow — so SSH/panel access can be lost.
  </div>
  <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:6px">
    <?php if ($smAdminIp): ?><button class="fw-act fix" type="button" id="fwAllowLiveTop" data-ip="<?= smpro_h($smAdminIp) ?>">&#128737;&#65039; Allow MY IP on the live firewall NOW</button><?php endif; ?>
    <?php if ($csfInstalled): ?><button class="fw-act" type="button" id="fwResync">&#8635; Re-sync firewall (re-enable CSF)</button><?php endif; ?>
  </div>
</div>
<?php endif; ?>
<?php
// ---- the overview: one line per protection, read from the same state the cards below use (cheap config reads only)
$ovLock = function_exists('smpro_gl_cfg') ? smpro_gl_cfg() : []; $ovLockN = function_exists('smpro_gl_active') ? count(smpro_gl_active()) : 0;
$ovDoor = function_exists('smpro_gh_cfg') ? smpro_gh_cfg() : [];
$ovDenyLimit = (preg_match('/^DENY_IP_LIMIT\s*=\s*"(\d+)"/m', (string)@file_get_contents('/etc/csf/csf.conf'), $ovDm)) ? (int)$ovDm[1] : 0; $ovWall = function_exists('smpro_gw_cfg') ? smpro_gw_cfg() : []; $ovWallUp = function_exists('smpro_gw_live') ? smpro_gw_live() : false;
$ovCards = [
  ['id' => 'fwstate', 'l' => 'Firewall', 'v' => $statusLabel, 'cls' => $status === 'good' ? 'good' : ($status === 'warn' ? 'warn' : 'dang'), 's' => $csfInstalled ? ('LFD ' . $lfd . ($testing ? ' · TESTING' : '')) : 'CSF not installed'],
  ['id' => 'deny', 'l' => 'Blocked addresses', 'v' => (string)$denyCount, 'cls' => 'brand', 's' => 'csf.deny' . ($ovDenyLimit ? ' · limit ' . $ovDenyLimit : '')],
  ['id' => 'gl', 'l' => 'Country Login Lock', 'v' => !empty($ovLock['enabled']) ? 'ON' : 'off', 'cls' => !empty($ovLock['enabled']) ? 'good' : 'muted', 's' => !empty($ovLock['enabled']) ? ($ovLockN . ' address(es) closed · ' . implode(', ', (array)($ovLock['countries'] ?? []))) : 'acts after a foreign sign-in'],
  ['id' => 'gh', 'l' => 'The door (cPHulk)', 'v' => !empty($ovDoor['enabled']) ? 'ARMED' : 'off', 'cls' => !empty($ovDoor['enabled']) ? 'good' : 'muted', 's' => 'refuses other countries before the password'],
  ['id' => 'gw', 'l' => 'Country wall', 'v' => $ovWallUp ? 'UP' : (!empty($ovWall['enabled']) ? 'enabled, not live' : 'off'), 'cls' => $ovWallUp ? 'good' : (!empty($ovWall['enabled']) ? 'warn' : 'muted'), 's' => !empty($ovWall['enabled']) ? ('takes itself down after ' . (int)($ovWall['deadman_minutes'] ?? 0) . ' min without proof') : 'a login door other countries cannot reach'],
  ['id' => 'gr', 'l' => 'Your address', 'v' => $smAdminIp ? ($smAdminAllowed ? 'allow-listed' : 'NOT allow-listed') : '?', 'cls' => $smAdminIp ? ($smAdminAllowed ? 'good' : 'warn') : 'muted', 's' => $smAdminIp ? ($smAdminIp . ($smAdminCC ? ' · ' . $smAdminCC : '')) : 'could not be read'],
];
$ovNav = [['gr', '&#128273; Threat report'], ['gl', '&#127757; Login Lock'], ['gh', '&#128682; The door'], ['gw', '&#128721; Country wall'], ['cbp', '&#127757; Block-prevention'], ['addip', '&#128272; Add IP'], ['layers', 'Layers'], ['plan', 'Plan'], ['deny', 'Blocked IPs'], ['cfg', 'CSF config'], ['ports', 'Ports']];
?>
<h1 class="h">Firewall Status</h1>
<p class="sub">CSF/LFD intelligence, layers, decision plan, recommendations, counters, config &amp; listening ports. Manage blocked IPs safely (Unblock). No service restarts.</p>
<div class="fw-kpis">
  <?php foreach ($ovCards as $k): ?>
  <a class="fw-kpi <?= $k['cls'] ?>" href="#<?= $k['id'] ?>" data-go="<?= $k['id'] ?>"><div class="l"><?= $k['l'] ?></div><div class="v"><?= smpro_h($k['v']) ?></div><div class="s"><?= smpro_h($k['s']) ?></div></a>
  <?php endforeach; ?>
</div>
<nav class="fw-nav" id="fwNav"><?php foreach ($ovNav as [$id, $lbl]): ?><a href="#<?= $id ?>" data-go="<?= $id ?>"><?= $lbl ?></a><?php endforeach; ?><span class="sp"></span><button type="button" class="fw-navx" id="fwOpenAll">expand all</button><button type="button" class="fw-navx" id="fwCloseAll">collapse all</button></nav>
<p style="margin:-8px 0 14px"><a class="fa-lnk" href="index.cgi?page=firewall-status&amp;format=ioc&amp;fw_ioc=1">&#11015; Export blocked IPs (IOC)</a> <span class="meta">— external csf.deny IPs as a plain-text list (one per line)</span></p>

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
    <div class="meta" style="margin-top:2px">Whitelist your own IP so the firewall can never lock you out. <b>Allow LIVE</b> applies it to the running iptables immediately (works even if CSF is disabled).</div>
  </div>
  <div style="display:flex;gap:8px;flex-wrap:wrap">
    <?php if (!$smAdminAllowed): ?><button class="fw-act fix" type="button" id="fwAllowMine" data-ip="<?= smpro_h($smAdminIp) ?>">&#9989; Allow my IP</button><?php endif; ?>
    <button class="fw-act fix" type="button" id="fwAllowLive" data-ip="<?= smpro_h($smAdminIp) ?>">&#128737;&#65039; Allow my IP LIVE (now)</button>
  </div>
</div>
<?php endif; ?>

<?php
/* ---------------- Foreign sign-in report ---------------- */
$grReady = function_exists('smpro_gl_cfg') && (smpro_gl_cfg()['countries'] || smpro_gl_cfg()['per_account']);
?>
<div class="card" id="gr" style="padding:0;overflow:hidden;margin:0 0 14px">
  <div class="tp-th"><b>&#128273; Compromised accounts &mdash; bulk password reset</b>
    <span class="meta">Every account there is evidence for, and a password reset for the ones you pick.</span>
  </div>
  <div style="padding:14px 16px">
    <p class="meta" style="margin:0 0 10px;line-height:1.7">
      Blocking the address stops <b>that address</b>. It does not stop the person, because what they have is the
      <b>password</b> &mdash; and a password that is known stays known. So this report exists to be acted on: pick the
      accounts, reset them, and hand each owner their new one.
      <br><br>
      <b>A sign-in that SUCCEEDED is a finding, and so is malware found inside the account.</b> Failed attempts from
      anywhere are background noise and are counted separately &mdash; somebody knocking is not somebody inside.
      <br><br>
      This used to ask only one question: did anyone sign in from a country outside your list? That question is silent
      until a country list exists, and it is blind to the ordinary case &mdash; the <b>correct</b> password used from an
      <b>ordinary</b> country, which is exactly what a stolen password looks like. So it now also asks whether there is
      malware inside the account. Something put it there, and whatever did still has whatever it used to get in, which
      is why the password has to change even when the file has already been cleaned.
    </p>

    <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
      <label class="ui-fld" style="margin:0">Look back
        <select id="grDays" class="tp-sel">
          <option value="1">24 hours</option><option value="7" selected>7 days</option>
          <option value="30">30 days</option><option value="90">90 days</option>
        </select>
        <?php $grSince = function_exists('smpro_gr_counter_since') ? smpro_gr_counter_since() : 0; $grArch = function_exists('smpro_gr_archives') ? smpro_gr_archives() : []; ?>
        <?php if ($grSince): ?><span class="meta">counter reset <?= smpro_h(date('Y-m-d H:i', $grSince)) ?> &mdash; sign-ins before that are in the archive, not the count</span><?php endif; ?>
        <?php if ($grArch): ?>
          <span class="meta">&middot; archived reports:
          <?php foreach (array_slice($grArch, 0, 6) as $ga): ?>
            <a href="index.cgi?page=firewall-status&amp;gr_archive=<?= smpro_h($ga['id']) ?>" target="_blank" title="<?= (int)$ga['accounts'] ?> account(s), <?= (int)$ga['signed_in'] ?> signed in"><?= smpro_h(date('d M H:i', (int)$ga['at'])) ?></a>
          <?php endforeach; ?><?= count($grArch) > 6 ? ' &hellip;' : '' ?></span>
        <?php endif; ?>
      </label>
      <button class="tp-btn primary" id="grScan" type="button">&#128269; Build the report</button>
      <?php if (!$grReady): ?><span class="meta">No country list is set, so the <b>sign-in</b> source is off &mdash; set one in <b>Country Login Lock</b> above to add it.
        Malware evidence does not need a country list, so the report still runs.</span><?php endif; ?>
    </div>

    <div id="grOut" hidden style="margin-top:12px"></div>
  </div>
</div>
<?php
/* ---------------- Country Login Lock ---------------- */
$glCfg   = smpro_gl_cfg();
$glCheck = smpro_gl_arm_check(array_replace($glCfg, ['enabled' => true]), (string)($_SERVER['REMOTE_ADDR'] ?? ''));
$glOn    = !empty($glCfg['enabled']);
$glActive= function_exists('smpro_gl_active_live') ? smpro_gl_active_live() : smpro_gl_active();
$glDenyLimit = (preg_match('/^DENY_IP_LIMIT\s*=\s*"(\d+)"/m', (string)@file_get_contents('/etc/csf/csf.conf'), $glDm)) ? (int)$glDm[1] : 0;
$glDenyLines = count((array)@file('/etc/csf/csf.deny'));
$glUseSet = function_exists('smpro_gl_use_set') && smpro_gl_use_set();   // kernel set: no csf.deny lines, no limit to hit
$glLegacyLines = $glUseSet ? count(array_filter($glActive, fn($a) => ($a['backend'] ?? '') === 'csf.deny')) : 0;
?>
<div class="card" id="gl" style="padding:0;overflow:hidden;margin:0 0 14px">
  <div class="tp-th"><b>&#127757; Country Login Lock</b>
    <span class="meta">Sign-ins are only accepted from countries you allow. <b>Websites are never affected</b> &mdash;
      only the login doors.</span>
    <span style="flex:1"></span>
    <?php /* The badge reports whether the lock can actually ACT, not merely whether a box is ticked. It said
         ARMED while nothing on the server was able to apply it — no worker, no schedule — and csf.deny held
         none of its rules. A label that outruns the capability behind it is worse than no label. */
       $glReal = function_exists('smpro_gl_active_really') ? smpro_gl_active_really() : ['ok' => $glOn && empty($glCfg['dryrun']), 'why' => '']; ?>
    <span class="ph-badge" style="background:<?= !empty($glReal['ok']) ? 'rgba(220,38,38,.12)' : ($glOn ? 'rgba(180,83,9,.14)' : 'rgba(107,114,128,.16)') ?>">
      <?= !empty($glReal['ok']) ? 'ARMED' : ($glOn ? 'not acting' : 'off') ?></span>
    <?php if ($glOn && empty($glReal['ok'])): ?>
      <span class="meta" style="color:var(--dang)">&#9888;&#65039; <?= smpro_h((string)$glReal['why']) ?></span>
    <?php endif; ?>
  </div>
  <div style="padding:14px 16px">
    <p class="meta" style="margin:0 0 10px;line-height:1.7">
      The attack this stops is a <b>correct password used by the wrong person</b>. Nothing about that login looks
      wrong &mdash; no failed attempts, no brute force, nothing for any other rule to catch. What is wrong is where
      it came from.
      <br><br>
      <b>It is not a country firewall.</b> Rules are written per login port only &mdash; cPanel, WHM, webmail, mail,
      FTP, SSH. <b>Ports 80 and 443 are never touched and no setting can add them</b>, so a site stays readable and
      buyable from every country on earth. And no country is blocked in advance: a rule appears only when a sign-in
      is actually seen from a country that is not allowed, so every rule can be traced to the event that caused it.
    </p>

    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:12px">
      <label class="ui-fld">Countries allowed to sign in
        <input type="text" id="glCC" class="tp-in" placeholder="EG, SA, AE" value="<?= smpro_h(implode(', ', $glCfg['countries'])) ?>">
        <?php /* The codes are what the rules are written from, so the field stays codes. But "EG, SA" is not
             something an operator can check at a glance, and a wrong pair of letters here decides who can sign
             in to every account on the server - CA is Canada, not Cairo. The names are spelled out underneath,
             from the same list the lock itself uses, and an unknown code is called out rather than ignored. */
           $glNames = [];
           foreach ((array)$glCfg['countries'] as $glC) {
               $glN = function_exists('smpro_cc_name') ? smpro_cc_name($glC) : $glC;
               $glNames[] = ($glN !== '' && strtoupper($glN) !== strtoupper($glC))
                          ? ($glC . ' — ' . $glN) : ($glC . ' — (unknown code)');
           } ?>
        <div id="glCCNames" class="meta" style="margin-top:4px;line-height:1.6"><?= $glNames
              ? smpro_h(implode(' · ', $glNames))
              : 'Nothing listed — the lock will refuse to arm.' ?></div>
        <span class="meta">Two-letter codes. Empty means nobody may sign in, so it will refuse to arm.</span>
      </label>
      <label class="ui-fld">A rule lasts
        <select id="glTtl" class="tp-sel">
          <?php foreach ([7, 30, 90, 365] as $d): ?><option value="<?= $d ?>"<?= (int)$glCfg['ttl_days'] === $d ? ' selected' : '' ?>><?= $d ?> days</option><?php endforeach; ?>
        </select>
        <span class="meta">One trip abroad should not lock an address out forever.</span>
      </label>
      <label class="ui-fld">A correct password from a country not allowed
        <select id="glOnOk" class="tp-sel">
          <option value="block"<?= $glCfg['on_success'] === 'block' ? ' selected' : '' ?>>Close its login ports and alert</option>
          <option value="alert"<?= $glCfg['on_success'] === 'alert' ? ' selected' : '' ?>>Alert only</option>
        </select>
        <span class="meta">This one means the password is already known to somebody.</span>
      </label>
      <label class="ui-fld">A wrong password from there
        <select id="glOnBad" class="tp-sel">
          <option value="ignore"<?= $glCfg['on_failed'] === 'ignore' ? ' selected' : '' ?>>Ignore &mdash; ordinary noise</option>
          <option value="block"<?= $glCfg['on_failed'] === 'block' ? ' selected' : '' ?>>Close its login ports too</option>
        </select>
      </label>
    </div>

    <div style="margin:12px 0 4px"><b style="font-size:13px">Which doors</b></div>
    <div style="display:flex;gap:14px;flex-wrap:wrap">
      <?php foreach (smpro_gl_services() as $k => $v): ?>
        <label class="lm-chkl" style="font-size:13px"><input type="checkbox" class="glSvc" value="<?= smpro_h($k) ?>"<?= in_array($k, $glCfg['services'], true) ? ' checked' : '' ?>>
          <span><?= smpro_h($v['name']) ?> <span class="meta">(<?= implode(', ', $v['ports']) ?>)</span></span></label>
      <?php endforeach; ?>
      <span class="meta">80 / 443 are not on this list and cannot be added.</span>
    </div>
    <label class="ui-fld" style="margin-top:10px">Custom login ports <span class="meta">this server's own SSH or SMTP port if it is not the standard one, e.g. <code>2200, 2525</code> &mdash; closed by the lock exactly like the doors above; 80 and 443 are refused</span>
      <input type="text" id="glPorts" class="tp-in" placeholder="2200, 2525" value="<?= smpro_h(implode(', ', (array)($glCfg['custom_ports'] ?? []))) ?>" style="max-width:320px">
    </label>

    <label class="ui-fld" style="margin-top:12px">Per-account exceptions <span class="meta">one per line: <code>account = EG,DE</code> &mdash; that account uses its own list instead of the one above</span>
      <textarea id="glPA" rows="3" class="tp-in" style="width:100%;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px"><?php
        $ln = []; foreach ($glCfg['per_account'] as $u => $cc) $ln[] = $u . ' = ' . implode(',', $cc);
        echo smpro_h(implode("\n", $ln)); ?></textarea>
    </label>

    <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:12px">
      <label class="lm-chkl"><input type="checkbox" id="glOn"<?= $glOn ? ' checked' : '' ?>> <span><b>Arm the lock</b></span></label>
      <label class="lm-chkl"><input type="checkbox" id="glDry"<?= !empty($glCfg['dryrun']) ? ' checked' : '' ?>> <span>Dry run &mdash; report only, write nothing</span></label>
      <?php /* Closing the port stops the NEXT connection. On a successful sign-in the one that matters is the one
           already open - somebody is inside now, and a firewall rule behind them leaves them working. */ ?>
      <label class="lm-chkl"><input type="checkbox" id="glEvict"<?= !empty($glCfg['evict']) ? ' checked' : '' ?>>
        <span><b>End the session too</b> &mdash; drop the connection, sign the panel session out and stop the process, not just close the port</span></label>
      <button class="tp-btn primary" id="glSave" type="button">Save</button>
      <button class="tp-btn" id="glScan" type="button">&#128269; Check the last hour</button>
      <button class="tp-btn" id="glExpire" type="button" title="Remove rules older than the life set above">Clear expired rules</button>
      <?php if ($glActive): ?><button class="tp-btn danger" id="glClear" type="button">Remove all <?= count($glActive) ?> address rule(s)</button><?php endif; ?>
    </div>

    <?php if (!$glCheck['ok']): ?>
    <div style="margin-top:10px;padding:9px 11px;border-radius:8px;border:1px solid rgba(180,83,9,.4);background:rgba(180,83,9,.07);font-size:12.5px;line-height:1.65">
      <b>&#9888; It will refuse to arm as configured:</b>
      <?php foreach ($glCheck['problems'] as $p): ?><div>&bull; <?= smpro_h($p) ?></div><?php endforeach; ?>
      <div class="meta" style="margin-top:4px">You are connecting from <?= smpro_h($glCheck['your_ip'] ?: 'an unknown address') ?><?= $glCheck['your_cc'] ? ' (' . smpro_h($glCheck['your_cc']) . ')' : '' ?>.</div>
    </div>
    <?php endif; ?>

    <?php if ($glActive): ?>
    <details class="gl-fold" style="margin-top:12px">
      <summary style="cursor:pointer;font-size:13px;font-weight:700;list-style:none;display:flex;align-items:center;gap:8px"><span class="fw-chev gl-chev">&#9656;</span>Addresses whose login ports are closed by this lock <span class="meta" style="font-weight:400">(<?= count($glActive) ?> address<?= count($glActive) === 1 ? '' : 'es' ?> &middot; click to show)</span></summary>
    <?php if ($glUseSet): ?>
      <div class="meta" style="margin:6px 0;font-size:12px">&#10003; Held in a kernel set (<?= count($glActive) - $glLegacyLines ?> address<?= (count($glActive) - $glLegacyLines) === 1 ? '' : 'es' ?>, one firewall rule per 15 ports, each entry expires on its own) &mdash; nothing is written to csf.deny, so this lock cannot fill it or push other blocks out.<?= $glLegacyLines ? ' ' . (int)$glLegacyLines . ' old csf.deny line(s) are still waiting to be moved over (Save does it).' : '' ?></div>
    <?php endif; ?>
    <?php if ($glDenyLimit && $glDenyLines >= $glDenyLimit && !$glUseSet): ?>
      <div style="margin:6px 0;padding:9px 11px;border-radius:8px;border:1px solid rgba(220,38,38,.4);background:rgba(220,38,38,.07);font-size:12.5px">
        <b>&#9888; csf.deny has <?= (int)$glDenyLines ?> lines and CSF's DENY_IP_LIMIT is <?= (int)$glDenyLimit ?>.</b> CSF silently drops the oldest lines beyond the limit, so rules written here can disappear. The lock raises the limit the next time it writes a rule; to do it now, press Save on the lock.
      </div>
    <?php endif; ?>
    <div style="overflow-x:auto"><table class="smpro-table"><thead><tr><th>Address</th><th>Live?</th><th>Ports closed</th><th>Why</th><th>Action</th></tr></thead><tbody>
      <?php foreach ($glActive as $a): ?>
      <tr><td class="ipmono"><?= smpro_h($a['ip']) ?></td>
          <td><?php if (!array_key_exists('live', $a) || $a['live'] === null): ?><span class="meta">not checked</span><?php elseif ($a['live']): ?><span class="b green">live</span><?php else: ?><span class="b red" title="Written in csf.deny but CSF did not apply it - the address is NOT blocked">NOT live</span><?php endif; ?></td>
          <td><?= smpro_h(implode(', ', array_filter((array)($a['ports'] ?? [])))) ?></td>
          <td class="meta"><?= smpro_h((string)($a['why'] ?? '')) ?></td>
          <td><button class="tp-btn glUn" type="button" data-ip="<?= smpro_h($a['ip']) ?>">Let it back in</button></td></tr>
      <?php endforeach; ?>
    </tbody></table></div>
    </details>
    <?php endif; ?>

    <div id="glOut" hidden style="margin-top:11px;padding:10px 12px;border-radius:9px;background:rgba(127,127,127,.07);font-size:12.5px;line-height:1.7"></div>
  </div>
</div>
<?php
/* ---------------- The door wall (cPHulk country blacklist) ---------------- */
if (!function_exists('smpro_gh_status')) { $ghf = SMPRO_BASE . '/includes/geohulk.php'; if (@is_file($ghf)) require_once $ghf; }
if (function_exists('smpro_gh_status')):
  $ghSt  = smpro_gh_status();
  $ghChk = smpro_gh_arm_check((string)($_SERVER['REMOTE_ADDR'] ?? ''));
  $ghOn  = !empty($ghSt['cfg']['enabled']);
?>
<div class="card" id="gh" style="padding:0;overflow:hidden;margin:0 0 14px">
  <div class="tp-th"><b>&#128682; The door: refuse sign-ins from other countries before the password</b>
    <span class="meta">the same list as the lock above &mdash; the lock acts after a sign-in, this refuses it at the door</span>
    <span style="flex:1"></span>
    <span class="ph-badge" style="background:<?= !empty($ghSt['ok']) ? 'rgba(220,38,38,.12)' : ($ghOn ? 'rgba(180,83,9,.14)' : 'rgba(107,114,128,.16)') ?>">
      <?= !empty($ghSt['ok']) ? 'ARMED' : ($ghOn ? 'not acting' : 'off') ?></span>
    <?php if ($ghOn && empty($ghSt['ok'])): ?><span class="meta" style="color:var(--dang)">&#9888;&#65039; <?= smpro_h((string)$ghSt['why']) ?></span><?php endif; ?>
  </div>
  <div style="padding:14px 16px">
    <p class="meta" style="margin:0 0 10px;line-height:1.7">
      Uses cPHulk's own country blacklist: every country that <b>nobody</b> is allowed from (the list above, the
      per-account exceptions, and Intrusion Monitor's home and caution regions) is refused at cPanel, WHM, webmail,
      FTP, SSH and mail sign-in <b>before the password is checked</b>. The list is kept in step every minute as you
      edit the lock above. Websites are not affected. It is a login refusal, not a firewall rule: it cannot make the
      server unreachable, and the way back from any shell is <code>whmapi1 disable_cphulk</code>.
      Your own address is put on cPHulk's whitelist before the wall is armed.
    </p>
    <?php if (!empty($ghSt['ok'])): ?>
      <div class="meta" style="margin-bottom:8px"><b><?= (int)$ghSt['countries'] ?></b> countries refused &middot; <b><?= (int)($ghSt['ranges'] ?? 0) ?></b> address ranges in cPHulk &middot; allowed: <?= smpro_h(implode(', ', (array)$ghSt['allowed'])) ?></div>
    <?php elseif (!$ghChk['ok'] || $ghChk['problems']): ?>
      <div style="margin-bottom:8px;padding:9px 11px;border-radius:8px;border:1px solid rgba(180,83,9,.4);background:rgba(180,83,9,.07);font-size:12.5px;line-height:1.65">
        <?php foreach ($ghChk['problems'] as $p): ?><div>&bull; <?= smpro_h($p) ?></div><?php endforeach; ?>
        <div class="meta" style="margin-top:4px">Allowed right now: <?= $ghChk['allowed'] ? smpro_h(implode(', ', $ghChk['allowed'])) : 'nothing' ?> &middot; you are connecting from <?= smpro_h($ghChk['your_cc'] ?: 'an unknown country') ?>.</div>
      </div>
    <?php endif; ?>
    <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
      <?php if (!$ghOn): ?>
        <button class="tp-btn danger" id="ghArm" type="button"<?= $ghChk['ok'] ? '' : ' disabled' ?>>Arm the door</button>
      <?php else: ?>
        <button class="tp-btn" id="ghDisarm" type="button">Disarm &mdash; restore cPHulk as it was</button>
      <?php endif; ?>
    </div>
    <div id="ghOut" hidden style="margin-top:11px;padding:10px 12px;border-radius:9px;background:rgba(127,127,127,.07);font-size:12.5px;line-height:1.7"></div>
  </div>
</div>
<?php endif; ?>
<?php
/* ---------------- Recommended BLOCK-lists — the mirror of the allow-list card below ---------------- */
$fwbSources = function_exists('smpro_fw_block_sources') ? smpro_fw_block_sources() : [];
$fwbIgnored = function_exists('smpro_fw_block_ignored') ? smpro_fw_block_ignored() : [];
$fwbShare   = function_exists('smpro_fw_block_contributing') && smpro_fw_block_contributing();
?>
<?php
/* ---------------- Country wall (real prevention) ---------------- */
if (function_exists('smpro_gw_cfg')):
  $gwCfg  = smpro_gw_cfg();
  $gwUp   = function_exists('smpro_gw_live') ? (bool)smpro_memo('fw_gw_live', 15, fn() => smpro_gw_live() ? 1 : 0) : false;   // the page's own view; the wall's decisions read the kernel directly
  $gwMiss = smpro_gw_missing((array)$gwCfg['countries']);
  $gwCnt  = count(smpro_gw_ranges((array)$gwCfg['countries']));
?>
<div class="card" id="gw" style="padding:0;overflow:hidden;margin:0 0 14px">
  <div class="tp-th"><b>&#128721; Country wall &mdash; a login door other countries cannot reach</b>
    <span class="meta">Browsing stays open to the world. Signing in and uploading do not.</span>
    <span style="flex:1"></span>
    <span class="ph-badge" style="background:<?= $gwUp ? 'rgba(220,38,38,.12)' : 'rgba(107,114,128,.16)' ?>"><?= $gwUp ? 'UP' : 'off' ?></span>
  </div>
  <div style="padding:14px 16px">
    <p class="meta" style="margin:0 0 10px;line-height:1.7">
      <b>This is not Country Login Lock.</b> That one reads the login log and closes an address&rsquo;s ports
      <i>afterwards</i>, so the first sign-in from a country you do not allow always succeeds. This refuses the
      connection before it reaches SSH or the panel at all.
      <br><br>
      <b>Ports 80 and 443 are never included and cannot be added</b>, so a shop stays readable and buyable from
      every country on earth. What is covered is the doors people sign in and upload through.
      <br><br>
      <b style="color:var(--dang)">This can lock you out of your own server &mdash; panel and SSH together.</b>
      So: arming is refused unless your own address is proven to be inside; every address on your allow-list is
      added; and the wall <b>takes itself down</b> if nothing confirms this panel is still reachable. Leave that
      last one short until you trust it.
    </p>

    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:12px">
      <label class="ui-fld">Countries allowed to sign in
        <input type="text" id="gwCC" class="tp-in" placeholder="EG, SA" value="<?= smpro_h(implode(', ', (array)$gwCfg['countries'])) ?>">
        <span class="meta">Ranges on disk: <b><?= (int)$gwCnt ?></b><?= $gwMiss ? ' &middot; <span style="color:var(--dang)">no data yet for ' . smpro_h(implode(', ', $gwMiss)) . '</span>' : '' ?></span>
      </label>
      <label class="ui-fld">Take itself down after
        <select id="gwDead" class="tp-sel">
          <?php foreach ([15 => '15 minutes', 30 => '30 minutes', 60 => '1 hour', 240 => '4 hours', 1440 => '24 hours', 4320 => '3 days', 10080 => '7 days'] as $mv => $ml): ?>
          <option value="<?= $mv ?>"<?= (int)$gwCfg['deadman_minutes'] === $mv ? ' selected' : '' ?>><?= smpro_h($ml) ?></option>
          <?php endforeach; ?>
        </select>
        <span class="meta">without proof the panel is still reachable (any WHM sign-in from outside, or any page of this product opened, counts)</span>
      </label>
    </div>

    <div style="margin-top:10px"><b style="font-size:13px">Which doors</b>
      <div style="display:flex;gap:14px;flex-wrap:wrap;margin-top:5px">
      <?php foreach (smpro_gw_doors() as $gk => $gd): ?>
        <label style="font-size:13px"><input type="checkbox" class="gwDoor" value="<?= smpro_h($gk) ?>"<?= in_array($gk, (array)$gwCfg['doors'], true) ? ' checked' : '' ?>>
          <?= smpro_h($gd['name']) ?> <span class="meta">(<?= smpro_h(implode(', ', $gd['ports'])) ?>)</span></label>
      <?php endforeach; ?>
      </div>
      <div class="meta" style="margin-top:4px">80 / 443 are not on this list and cannot be added.</div>
    </div>

    <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:12px">
      <button class="tp-btn" id="gwSave" type="button">Save settings</button>
      <button class="tp-btn" id="gwFetch" type="button">&#11015; Fetch the ranges</button>
      <button class="tp-btn" id="gwPrev" type="button">&#128269; What would happen</button>
      <span style="flex:1"></span>
      <button class="tp-btn danger" id="gwArm" type="button">&#128721; Put the wall up</button>
      <button class="tp-btn" id="gwOff" type="button">Take it down</button>
    </div>
    <div id="gwOut" hidden style="margin-top:10px"></div>
  </div>
</div>
<?php endif; ?>
<?php if ($fwbSources): ?>
<div class="card fwrec fwblk">
  <div class="fwrec-hd">&#128683; Recommended block-lists <span class="fwrec-hd-s">&mdash; optional; illegitimate bots that tried to break in</span></div>
  <div class="fwrec-body">
    <p class="fwrec-intro">The mirror of the allow-list below, and it works the same way: pick a list, <b>Review</b> it to
      see exactly what it would do on this server, then <b>Add</b>. Nothing here blocks anything on its own and nothing
      runs on a timer. <b>Remove</b> takes out exactly the lines this added and nothing else.</p>
    <p class="fwrec-intro"><b>What these lists carry:</b> only addresses on datacenter / cloud / hosting networks &mdash;
      machines, not people. Nobody signs in to a control panel from a rented server, so a rented server failing logins is
      a bot. A residential, office or mobile address is never pooled, however badly it behaved: one address there can be a
      hundred customers behind one connection, and blocking it on every server would turn one operator's judgement into
      everybody's outage. Verified search and archive crawlers are refused outright, whatever a list says.</p>
    <?php foreach ($fwbSources as $bk => $bs): if (in_array($bk, $fwbIgnored, true)) continue;
      $bst = function_exists('smpro_fw_block_status') ? smpro_fw_block_status($bk) : ['total'=>0,'applied'=>0,'synced_at'=>0]; ?>
    <div class="fwb-src" data-key="<?= smpro_h($bk) ?>">
      <div class="fwb-hd"><b><?= smpro_h($bs['name']) ?></b>
        <span class="meta"><?= (int)$bst['total'] ?> in the list &middot; <?= (int)$bst['applied'] ?> applied here
          <?= $bst['synced_at'] ? ' &middot; refreshed ' . smpro_h(date('Y-m-d H:i', (int)$bst['synced_at'])) : ' &middot; never refreshed' ?></span>
      </div>
      <div class="meta" style="margin:2px 0 6px"><?= smpro_h($bs['desc']) ?></div>
      <div class="meta" style="margin:0 0 8px"><?= smpro_h($bs['note']) ?></div>
      <div class="fwb-acts">
        <button type="button" class="fwrec-add fwbReview" data-key="<?= smpro_h($bk) ?>">&#128269; Review</button>
        <button type="button" class="fwrec-add fwbApply" data-key="<?= smpro_h($bk) ?>" disabled title="Review first — this button turns on once you have seen what it would do">&#10003; Add reviewed addresses</button>
        <button type="button" class="fwrec-add fwbUndo" data-key="<?= smpro_h($bk) ?>" style="background:transparent;color:var(--muted);border:1px solid var(--line,#e5e7eb)">Remove what this added</button>
      </div>
      <div class="fwb-out" hidden></div>
    </div>
    <?php endforeach; ?>

    <div class="fwb-share">
      <div class="fwb-hd"><b>&#129309; Share what this server blocks</b>
        <span class="meta"><?= $fwbShare ? 'on' : 'off' ?></span></div>
      <div class="meta" style="margin:2px 0 8px">Off unless you turn it on, and even then nothing is sent until you press
        <b>Share now</b>. What would go: the attacker's address and which door it tried (SSH, panel, mail, FTP, web) &mdash;
        machines on datacenter networks only. What never goes: your hostname, your domains, your account names, your log
        lines. <b>Preview</b> shows you the exact payload before anything leaves this server.</div>
      <div class="fwb-acts">
        <label class="fwrec-selall"><input type="checkbox" id="fwbShareOn"<?= $fwbShare ? ' checked' : '' ?>> <span>Allow sharing</span></label>
        <button type="button" class="fwrec-add" id="fwbPreview">&#128065; Preview what would be sent</button>
        <button type="button" class="fwrec-add" id="fwbSend"<?= $fwbShare ? '' : ' disabled' ?>>&#8593; Share now</button>
      </div>
      <div class="fwb-out" id="fwbShareOut" hidden></div>
    </div>
  </div>
</div>
<?php endif; ?>

<?php $fwProviders = smpro_fw_allow_providers(); ?>
<div class="card fwrec">
  <div class="fwrec-hd">&#128737; Recommended allow-lists <span class="fwrec-hd-s">— optional; never-block trusted provider IP ranges in CSF</span></div>
  <div class="fwrec-body">
    <p class="fwrec-intro">Tick the providers you want and press <b>Add selected</b> — SM Pro fetches each one's current IP ranges from its official feed and adds them to <span class="mono">csf.allow</span> so LFD/CSF never blocks them. Fully reversible. Each provider below also has its own <b>Auto-update</b> (keep the IPs current automatically), <b>Sync now</b>, <b>Ignore</b> and <b>Remove</b> controls. Nothing reloads the page.</p>
    <?php $fwIgnored = smpro_fw_rec_ignored(); $fwAuto = smpro_fw_allow_autoupdate(); $fwHidden = []; $fwVisible = 0;
      foreach ($fwProviders as $k => $p) if (!in_array($k, $fwIgnored, true)) $fwVisible++; ?>
    <?php if ($fwVisible): ?>
    <div class="fwrec-bar">
      <label class="fwrec-selall"><input type="checkbox" id="fwSelAll"> <span>Select all</span></label>
      <button type="button" class="fwrec-add" id="fwAddSel" disabled>&#10003; Add selected to firewall <span id="fwSelN" class="fwrec-cnt">0</span></button>
      <span class="fwrec-barhint">Multi-select — pick any combination</span>
    </div>
    <?php endif; ?>
    <div class="fwrec-list">
    <?php foreach ($fwProviders as $key => $pv):
      if (in_array($key, $fwIgnored, true)) { $fwHidden[$key] = $pv['name']; continue; }
      $ranges = smpro_fw_allow_ranges($key);
      $st = smpro_fw_allow_status($ranges, $key); $full = $st['total'] > 0 && $st['present'] >= $st['total'];
      $canFetch = !empty($pv['fetch']); $auto = in_array($key, $fwAuto, true); $syncedAt = smpro_fw_allow_synced_at($key); ?>
      <div class="fwrec-item <?= $full ? 'is-full' : '' ?>" data-prov="<?= smpro_h($key) ?>">
        <label class="fwrec-pick" title="<?= $full ? 'Already fully allow-listed' : 'Select this provider' ?>">
          <input type="checkbox" class="fwProvChk" value="<?= smpro_h($key) ?>" <?= $full ? 'disabled' : '' ?>>
        </label>
        <div class="fwrec-main">
          <div class="fwrec-itop">
            <b><?= smpro_h($pv['name']) ?></b>
            <span class="b <?= $full ? 'good' : ($st['present'] > 0 ? 'orange' : 'gray') ?> fwrec-badge" data-badge><?= $full ? '&#10003; all ' . (int)$st['total'] . ' ranges allow-listed' : ((int)$st['present'] . ' of ' . (int)$st['total'] . ' allow-listed') ?></span>
            <span class="b good fwrec-badge fwrec-autobadge" data-autobadge <?= $auto ? '' : 'hidden' ?>>&#8635; AUTO-UPDATE ON</span>
          </div>
          <?php if ($full): ?>
          <?php // A finished provider used to render as a row of dead controls: the tickbox disabled, "Select all"
                // doing nothing and the counter stuck at zero. Nothing said the work was already done, so a
                // complete state and a broken one looked identical. Say which it is. ?>
          <div class="fwrec-done">Nothing to do here — every range this provider publishes is already in
            <span class="mono">csf.allow</span><?= $syncedAt ? ', last refreshed ' . smpro_h(date('M j, H:i', $syncedAt)) : '' ?>.
            The tickbox is inactive because there is nothing left to add<?= $auto ? '; auto-update keeps it that way as the provider changes its ranges' : '. Turn on auto-update below so it stays current when the provider changes its ranges' ?>.
            <?php if ($st['marked'] < $st['total']): ?>
            <br><span class="fwrec-done-s"><?= (int)($st['total'] - $st['marked']) ?> of them were already on this server before SM Pro — those are left exactly as they are, and Remove will not touch them.</span>
            <?php endif; ?>
          </div>
          <?php endif; ?>
          <div class="fwrec-desc"><?= smpro_h($pv['desc']) ?></div>
          <?php if (!empty($pv['note'])): ?><div class="fwrec-note">&#9888; <?= smpro_h($pv['note']) ?></div><?php endif; ?>
          <div class="fwrec-ctl">
            <?php if ($canFetch): ?>
            <label class="fwrec-auto" title="SM Pro fetches the latest ranges from the official feed every 6h and applies them automatically — no need to come back.">
              <input type="checkbox" class="fwProvAuto" data-key="<?= smpro_h($key) ?>" <?= $auto ? 'checked' : '' ?>>
              <span>Auto-update these IPs</span>
            </label>
            <button class="fwrec-cbtn fwProvSync" type="button" data-prov="<?= smpro_h($key) ?>" title="Fetch the current ranges from the official feed and apply now">&#8635; Sync now</button>
            <?php else: ?><span class="fwrec-static">Built-in fixed list (no live feed)</span><?php endif; ?>
            <button class="fwrec-cbtn fwProvRm" type="button" data-prov="<?= smpro_h($key) ?>" data-rm <?= $st['marked'] > 0 ? '' : 'hidden' ?>>Remove</button>
            <button class="fwrec-cbtn ghost fwRecIgnore" type="button" data-key="<?= smpro_h($key) ?>" title="Hide this recommendation without applying it">&#10005; Ignore</button>
            <span class="fwrec-synced" data-synced><?= $canFetch ? ($syncedAt ? ('Feed synced ' . smpro_h(date('M j, H:i', $syncedAt))) : 'Feed not fetched yet') : '' ?></span>
          </div>
          <details class="fwrec-det"><summary class="fa-lnk">Show <?= count($ranges) ?> range(s)</summary><div class="mono fwrec-ranges"><?= smpro_h(implode('   ', $ranges)) ?></div></details>
        </div>
      </div>
    <?php endforeach; ?>
    </div>
    <?php if ($fwHidden): ?>
      <details class="fwrec-ignored" id="fwIgnoredWrap"><summary class="fa-lnk">Ignored (<?= count($fwHidden) ?>) — show</summary>
        <div class="fwrec-ignored-list">
          <?php foreach ($fwHidden as $ik => $iname): ?>
            <div class="fwrec-ignrow"><span><?= smpro_h($iname) ?></span><button class="fwrec-cbtn fwRecUnignore" type="button" data-key="<?= smpro_h($ik) ?>">Restore</button></div>
          <?php endforeach; ?>
        </div>
      </details>
    <?php endif; ?>
    <div id="fwProvMsg" class="fwrec-msg"></div>
  </div>
</div>
<style>
.fwrec{padding:0;overflow:hidden;margin-bottom:14px}
.fwrec-hd{padding:12px 16px;border-bottom:1px solid var(--line);font-weight:700;display:flex;align-items:center;gap:8px;flex-wrap:wrap;user-select:none}
.fwb-src,.fwb-share{border:1px solid var(--line,#e5e7eb);border-radius:10px;padding:11px 13px;margin:10px 0}
.fwb-hd{display:flex;align-items:baseline;gap:10px;flex-wrap:wrap}
.fwb-acts{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:4px}
.fwb-out{margin-top:9px;padding:9px 11px;border-radius:8px;background:rgba(127,127,127,.07);font-size:12.5px;line-height:1.65}
.fwb-out b{font-weight:800}
.fwb-n{display:inline-block;padding:2px 8px;border-radius:999px;font-weight:800;font-size:11px;margin-right:5px}
.fwb-n.add{background:rgba(220,38,38,.12);color:#dc2626}.fwb-n.skip{background:rgba(107,114,128,.16);color:#4b5563}
.fwb-n.crawl{background:rgba(5,150,105,.14);color:#059669}
.fwb-ips{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11.5px;word-break:break-all;opacity:.85;margin-top:5px}
.fwrec-hd:hover{background:rgba(127,127,127,.06)}
.fwrec-hd:focus-visible{outline:2px solid var(--brand);outline-offset:-2px}
/* Closed, the bottom rule would float under nothing. */
.card:not(.fw-open)>.fwrec-hd{border-bottom:0}
.fwrec-hd-s{font-weight:400;color:var(--muted);font-size:12px}
.fwrec-body{padding:14px 16px}
.fwrec-intro{margin:0 0 12px;font-size:12.5px;color:var(--muted);line-height:1.6}
.fwrec-bar{display:flex;align-items:center;gap:14px;flex-wrap:wrap;background:var(--brand-bg);border:1px solid var(--line);border-radius:11px;padding:10px 14px;margin-bottom:12px}
.fwrec-selall{display:flex;align-items:center;gap:7px;cursor:pointer;font-size:13px;font-weight:600}
.fwrec-selall input{width:16px;height:16px;accent-color:var(--brand)}
.fwrec-add{background:var(--brand);color:#fff;border:none;border-radius:9px;padding:9px 18px;font-weight:700;font-size:13px;cursor:pointer;display:inline-flex;align-items:center;gap:8px;transition:.12s}
.fwrec-add:hover{filter:brightness(1.07)}
.fwrec-add:disabled{opacity:.45;cursor:not-allowed}
.fwrec-cnt{background:rgba(255,255,255,.28);border-radius:20px;font-size:11px;min-width:18px;text-align:center;padding:1px 7px}
.fwrec-barhint{font-size:11.5px;color:var(--muted);margin-left:auto}
.fwrec-list{display:flex;flex-direction:column;gap:10px}
.fwrec-item{display:flex;gap:12px;border:1px solid var(--line);border-radius:12px;padding:13px 15px;transition:.12s}
.fwrec-item:hover{border-color:var(--brand)}
.fwrec-item.is-full{background:var(--good-bg);border-color:#bfe6cd}
.fwrec-pick{flex:none;display:flex;align-items:flex-start;padding-top:2px}
.fwrec-pick input{width:18px;height:18px;accent-color:var(--brand);cursor:pointer}
.fwrec-main{flex:1;min-width:0}
.fwrec-itop{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.fwrec-badge{font-size:11px;padding:2px 8px;border-radius:20px}
.fwrec-desc{font-size:12px;color:var(--muted);margin-top:6px;line-height:1.5}
.fwrec-note{font-size:12px;color:#92702a;background:var(--warn-bg);border-radius:8px;padding:8px 11px;margin-top:8px}
.fwrec-done{font-size:12px;color:#1c6b45;background:var(--good-bg,#eaf7ef);border:1px solid #b7e3c7;border-radius:8px;padding:8px 11px;margin-top:8px;line-height:1.65}
.fwrec-done-s{color:#4a7a63;font-size:11.5px}
.fwrec-ctl{display:flex;align-items:center;gap:9px;flex-wrap:wrap;margin-top:10px;padding-top:10px;border-top:1px dashed var(--line)}
.fwrec-auto{display:flex;align-items:center;gap:7px;cursor:pointer;font-size:12px;font-weight:600;background:var(--card);border:1px solid var(--line);border-radius:8px;padding:5px 10px}
.fwrec-auto input{width:15px;height:15px;accent-color:var(--brand)}
.fwrec-cbtn{font-size:12px;font-weight:600;border:1px solid var(--line);background:var(--card);color:var(--brand);border-radius:8px;padding:5px 12px;cursor:pointer}
.fwrec-cbtn:hover{background:var(--brand);color:#fff;border-color:var(--brand)}
.fwrec-cbtn.ghost{color:var(--muted)}.fwrec-cbtn.ghost:hover{background:var(--muted);color:#fff;border-color:var(--muted)}
.fwrec-cbtn.fwProvRm{color:var(--dang);border-color:#f3c4c4}.fwrec-cbtn.fwProvRm:hover{background:var(--dang);color:#fff}
.fwrec-static{font-size:11.5px;color:var(--muted)}
.fwrec-synced{font-size:11.5px;color:var(--muted);margin-left:auto}
.fwrec-det{margin-top:8px}
.fwrec-det summary{cursor:pointer;display:inline-block}
.fwrec-ranges{font-size:11.5px;color:var(--muted);margin-top:6px;white-space:pre-wrap;word-break:break-all}
.fwrec-ignored{margin-top:10px}
.fwrec-ignored summary{cursor:pointer;display:inline-block}
.fwrec-ignored-list{margin-top:8px}
.fwrec-ignrow{display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid var(--line)}
.fwrec-ignrow span{color:var(--muted)}.fwrec-ignrow button{margin-left:auto}
.fwrec-msg{margin-top:8px;min-height:18px;font-size:12.5px}
.fa-lnk{background:none;border:none;color:var(--brand);cursor:pointer;font-size:12px;padding:0;text-decoration:underline}
.b.good{background:var(--good-bg);color:var(--good)}.b.orange{background:var(--warn-bg);color:var(--warn)}.b.gray{background:var(--card);color:var(--muted);border:1px solid var(--line)}
</style>
<script>(function(){
  var CSRF=<?= json_encode($fwCsrf) ?>;
  function msg(t,ok){var m=document.getElementById('fwProvMsg');if(m){m.innerHTML=t;m.style.color=ok?'var(--good)':'var(--dang)';}}
  function e(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
  function post(fields){var fd=new URLSearchParams();fd.set('smpro_csrf',CSRF);for(var k in fields){if(Array.isArray(fields[k]))fields[k].forEach(function(v){fd.append(k,v);});else fd.set(k,fields[k]);}
    return fetch('index.cgi?page=firewall-status',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'}).then(function(r){return r.json();});}
  var chks=function(){return Array.prototype.slice.call(document.querySelectorAll('.fwProvChk:not(:disabled)'));};
  function selected(){return chks().filter(function(c){return c.checked;}).map(function(c){return c.value;});}
  function refreshBar(){var n=selected().length;var b=document.getElementById('fwAddSel'),c=document.getElementById('fwSelN');if(c)c.textContent=n;if(b)b.disabled=n===0;
    var all=document.getElementById('fwSelAll');if(all){var tot=chks().length;all.checked=tot>0&&n===tot;all.indeterminate=n>0&&n<tot;}}
  /* refresh every provider row in place from the server — no page reload */
  function refreshStates(){
    return fetch('index.cgi?page=firewall-status&fw_action=allow_states',{cache:'no-store'}).then(function(r){return r.json();}).then(function(j){
      if(!j||!j.states)return;
      Array.prototype.slice.call(document.querySelectorAll('.fwrec-item')).forEach(function(it){
        var k=it.getAttribute('data-prov'),st=j.states[k];if(!st)return;
        var badge=it.querySelector('[data-badge]');if(badge){badge.textContent=st.present+'/'+st.total+' allow-listed';badge.className='b '+(st.full?'good':(st.present>0?'orange':'gray'))+' fwrec-badge';}
        var ab=it.querySelector('[data-autobadge]');if(ab){ if(st.auto)ab.removeAttribute('hidden'); else ab.setAttribute('hidden',''); }
        var ac=it.querySelector('.fwProvAuto');if(ac)ac.checked=!!st.auto;
        var sy=it.querySelector('[data-synced]');if(sy&&(''+sy.textContent).indexOf('Feed')===0)sy.textContent=st.synced?('Feed synced '+st.synced):'Feed not fetched yet';
        var rm=it.querySelector('[data-rm]');if(rm){ if(st.marked>0)rm.removeAttribute('hidden'); else rm.setAttribute('hidden',''); }
        var cb=it.querySelector('.fwProvChk');if(cb){cb.disabled=!!st.full;if(st.full){cb.checked=false;it.classList.add('is-full');}else it.classList.remove('is-full');}
      });
      refreshBar();
    });
  }
  function addSelected(btn){var keys=selected();if(!keys.length)return;
    if(!confirm('Add the selected provider IP ranges to the firewall allow-list (csf.allow)?\n\n'+keys.join(', ')+'\n\nOptional and reversible.'))return;
    var o=btn.innerHTML;btn.disabled=true;btn.innerHTML='… applying';
    post({fw_action:'allow_batch','providers[]':keys}).then(function(j){msg((j&&j.ok?'✓ ':'✗ ')+e((j&&j.msg)||'Failed'),j&&j.ok);btn.innerHTML=o;return refreshStates();}).catch(function(){btn.disabled=false;btn.innerHTML=o;msg('✗ Request failed.',false);});}
  function single(prov,op,btn){var o=btn.innerHTML;btn.disabled=true;btn.innerHTML='…';
    post({fw_action:'allow_provider',provider:prov,op:op}).then(function(j){msg((j&&j.ok?'✓ ':'✗ ')+e((j&&j.msg)||'Failed'),j&&j.ok);btn.disabled=false;btn.innerHTML=o;return refreshStates();}).catch(function(){btn.disabled=false;btn.innerHTML=o;msg('✗ Request failed.',false);});}
  function syncProv(prov,btn){var o=btn.innerHTML;btn.disabled=true;btn.innerHTML='… syncing';
    post({fw_action:'provider_sync',provider:prov}).then(function(j){msg((j&&j.ok?'✓ ':'✗ ')+e((j&&j.msg)||'Failed'),j&&j.ok);btn.disabled=false;btn.innerHTML=o;return refreshStates();}).catch(function(){btn.disabled=false;btn.innerHTML=o;msg('✗ Request failed.',false);});}
  function autoToggle(cb){var on=cb.checked?'1':'0';cb.disabled=true;
    post({fw_action:'rec_autoupdate',key:cb.getAttribute('data-key'),on:on}).then(function(j){msg((j&&j.ok?'✓ ':'✗ ')+e((j&&j.msg)||'Failed'),j&&j.ok);cb.disabled=false;if(!(j&&j.ok))cb.checked=!cb.checked;return refreshStates();}).catch(function(){cb.disabled=false;cb.checked=!cb.checked;msg('✗ Request failed.',false);});}
  function ignoreRec(key,op,btn){var o=btn.innerHTML;btn.disabled=true;btn.innerHTML='…';
    post({fw_action:'rec_ignore',key:key,op:op}).then(function(j){msg((j&&j.ok?'✓ ':'✗ ')+e((j&&j.msg)||'Failed'),j&&j.ok);
      if(j&&j.ok&&op==='ignore'){var it=document.querySelector('.fwrec-item[data-prov="'+key+'"]');if(it){it.style.transition='opacity .3s';it.style.opacity=0;setTimeout(function(){if(it.parentNode)it.parentNode.removeChild(it);refreshBar();},320);}}
      else if(j&&j.ok&&op==='unignore'){var row=btn.closest('.fwrec-ignrow');if(row&&row.parentNode)row.parentNode.removeChild(row);}
      else{btn.disabled=false;btn.innerHTML=o;}
    }).catch(function(){btn.disabled=false;btn.innerHTML=o;msg('✗ Request failed.',false);});}
  document.addEventListener('click',function(ev){
    var add=ev.target.closest&&ev.target.closest('#fwAddSel'); if(add){addSelected(add);return;}
    var r=ev.target.closest&&ev.target.closest('.fwProvRm'); if(r){if(!confirm('Remove the '+r.getAttribute('data-prov')+' allow-list ranges that SM Pro added?'))return;single(r.getAttribute('data-prov'),'remove',r);return;}
    var sy=ev.target.closest&&ev.target.closest('.fwProvSync'); if(sy){syncProv(sy.getAttribute('data-prov'),sy);return;}
    var ig=ev.target.closest&&ev.target.closest('.fwRecIgnore'); if(ig){ignoreRec(ig.getAttribute('data-key'),'ignore',ig);return;}
    var un=ev.target.closest&&ev.target.closest('.fwRecUnignore'); if(un){ignoreRec(un.getAttribute('data-key'),'unignore',un);return;}
  });
  document.addEventListener('change',function(ev){
    var a=ev.target.closest&&ev.target.closest('.fwProvAuto'); if(a){autoToggle(a);return;}
    var sa=ev.target.closest&&ev.target.closest('#fwSelAll'); if(sa){chks().forEach(function(c){c.checked=sa.checked;});refreshBar();return;}
    var c=ev.target.closest&&ev.target.closest('.fwProvChk'); if(c){refreshBar();return;}
  });
  refreshBar();
})();</script>

<div class="card" style="border-left:4px solid var(--<?= $status ?>);margin-bottom:14px">
  <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
    <div class="fw-otitle">&#9873; Firewall Overview</div><span class="pill <?= $status ?>"><?= $statusLabel ?></span>
    <span style="flex:1"></span><span class="meta">Primary: CSF + LFD</span>
  </div>
  <div class="fw-cards">
    <div class="fw-sc"><div class="lbl">CSF</div><div class="v"><?php
      if (!$csfInstalled) echo '<span class="b red">missing</span>';
      elseif ($csfDisabled) echo '<span class="b red">DISABLED</span><button class="fw-act fix" type="button" style="display:block;margin-top:8px" data-fwop="csf:enable" data-confirm="Re-enable CSF + LFD now to restore firewall protection?">&#9889; Enable CSF (Fix)</button>';
      else echo '<span class="b green">installed ' . smpro_h($csfVer) . '</span>';
    ?></div></div>
    <div class="fw-sc"><div class="lbl">LFD</div><div class="v"><?= smpro_fw_badge($lfd) ?>
      <?php if ($lfd !== 'active'): ?>
        <?php if ($csfDisabled): ?>
          <div style="font-size:11px;color:#92702a;margin-top:6px">Failed because CSF is disabled — enable CSF to fix it.</div>
          <button class="fw-act fix" type="button" style="display:block;margin-top:6px" data-fwop="csf:enable" data-confirm="Re-enable CSF + LFD now to restore firewall protection?">&#9889; Enable CSF (fixes LFD)</button>
        <?php else: $lfdFail = in_array($lfd, ['failed','activating','deactivating','reloading'], true); ?>
          <button class="fw-act fix" type="button" style="display:block;margin-top:8px" data-fwop="svc:<?= $lfdFail ? 'restart' : 'start' ?>" data-fwsvc="lfd" data-confirm="<?= $lfdFail ? 'Restart' : 'Start' ?> LFD now to restore brute-force protection?">&#9889; <?= $lfdFail ? 'Restart LFD (Fix)' : 'Start LFD (Fix)' ?></button>
        <?php endif; ?>
      <?php endif; ?>
    </div></div>
    <div class="fw-sc"><div class="lbl">firewalld</div><div class="v"><?= smpro_fw_badge($firewalld) ?></div></div>
    <div class="fw-sc"><div class="lbl">nftables</div><div class="v"><?= smpro_fw_badge($nftables) ?></div></div>
  </div>
</div>

<?php
// No baked country tables: this ships to every market. The convenience lists are the operator's OWN configured
// regions (home ∪ caution, from Intrusion Monitor) and whatever CSF already allows — named through ext-intl when
// it is loaded, otherwise shown as the bare code. Any other country goes in the free-text box below.
$ccName = function ($code) {
    $code = strtoupper((string)$code);
    if (class_exists('Locale')) { $n = (string)@Locale::getDisplayRegion('-' . $code, 'en'); if ($n !== '' && strtoupper($n) !== $code) return $n; }
    return $code;
};
$cfgRegions = function_exists('smpro_im_trusted_regions') ? smpro_im_trusted_regions() : [];
$CONFIGURED = []; foreach ($cfgRegions as $c) { $c = strtoupper((string)$c); if (preg_match('/^[A-Z]{2}$/', $c)) $CONFIGURED[$c] = $ccName($c); }
$ccMode = (trim($cfg['CC_ALLOW_FILTER'] ?? '') !== '') ? 'filter' : 'allow';
$ccCurrentStr = $ccMode === 'filter' ? trim($cfg['CC_ALLOW_FILTER'] ?? '') : trim($cfg['CC_ALLOW'] ?? '');
$ccCurrent = array_values(array_filter(array_map('trim', explode(',', $ccCurrentStr))));
// Only what the admin has actually configured is pre-checked — NO market default. This ships to every reseller
// in any market, so it must not assume a home region. Codes already set but not in the convenience menu below
// are surfaced in the free-text box so they are visible and preserved on the next apply.
$ccChecked = array_map('strtoupper', $ccCurrent);
$CURRENT = []; foreach ($ccChecked as $c) if (preg_match('/^[A-Z]{2}$/', $c) && !isset($CONFIGURED[$c])) $CURRENT[$c] = $ccName($c);
$ccKnown   = array_merge(array_keys($CONFIGURED), array_keys($CURRENT));
$ccExtra   = array_values(array_diff($ccChecked, $ccKnown));
?>
<div class="card" id="cbp" style="margin-bottom:14px;border-left:4px solid var(--brand)">
  <div class="tp-th"><b>&#127757; Country Block-Prevention</b><span class="meta">Chosen countries are added to CSF allow so the firewall never blocks them</span></div>
  <div style="padding:12px 14px">
    <p class="meta" style="margin:0 0 10px">Pick the countries that must <b>never</b> be blocked by the firewall — choose the ones for your own market. Nothing is preselected; the two lists below are just a convenience, and you can type any other ISO country codes in the box underneath. Applying writes the codes to CSF and reloads it — no service restart.</p>

    <div class="cc-dd" id="ccDD">
      <button type="button" class="cc-ddbtn" id="ccDDbtn"><span id="ccDDlabel">Select countries…</span><i class="cc-ddcar">&#9662;</i></button>
      <div class="cc-ddpanel" id="ccDDpanel" hidden>
        <input type="text" id="ccSearch" class="cc-ddsearch" placeholder="&#128269; Search country or code…">
        <div class="cc-ddscroll">
          <div class="cc-ddgrp">
            <div class="cc-ddgh"><b>&#127968; Your configured regions</b><span><button type="button" class="cc-mini" data-grp="arab" data-on="1">All</button><button type="button" class="cc-mini" data-grp="arab" data-on="0">Clear</button></span></div>
            <?php if (!$CONFIGURED): ?><div class="cc-opt" style="color:var(--muted)">No home/caution regions set yet — configure them in Intrusion Monitor, or type codes below.</div><?php endif; ?>
            <?php foreach ($CONFIGURED as $code => $name): ?>
              <label class="cc-opt" data-grp="arab" data-s="<?= smpro_h(strtolower($name.' '.$code)) ?>"><input type="checkbox" class="cc-cb" value="<?= $code ?>" <?= in_array($code, $ccChecked, true) ? 'checked' : '' ?>><span><?= smpro_h($name) ?> <em>(<?= $code ?>)</em></span></label>
            <?php endforeach; ?>
          </div>
          <div class="cc-ddgrp">
            <div class="cc-ddgh"><b>&#128274; Currently allowed in CSF</b><span><button type="button" class="cc-mini" data-grp="foreign" data-on="1">All</button><button type="button" class="cc-mini" data-grp="foreign" data-on="0">Clear</button></span></div>
            <?php foreach ($CURRENT as $code => $name): ?>
              <label class="cc-opt" data-grp="foreign" data-s="<?= smpro_h(strtolower($name.' '.$code)) ?>"><input type="checkbox" class="cc-cb" value="<?= $code ?>" <?= in_array($code, $ccChecked, true) ? 'checked' : '' ?>><span><?= smpro_h($name) ?> <em>(<?= $code ?>)</em></span></label>
            <?php endforeach; ?>
          </div>
        </div>
      </div>
    </div>

    <div style="margin-top:10px">
      <label for="ccExtra" style="font-size:12.5px;color:var(--muted);display:block;margin-bottom:4px">Or add any country codes — ISO 3166-1 alpha-2, comma-separated (e.g. <span class="mono">DE, FR, PL</span>). Works for any country, not just the lists above.</label>
      <input type="text" id="ccExtra" class="tp-in" placeholder="DE, FR, PL" value="<?= smpro_h(implode(', ', $ccExtra)) ?>" style="max-width:360px" autocomplete="off" spellcheck="false">
    </div>

    <div style="margin-top:12px;padding:10px 12px;background:rgba(59,91,219,.06);border:1px solid rgba(59,91,219,.18);border-radius:9px">
      <label style="font-size:13px;display:block;margin-bottom:4px"><input type="radio" name="ccmode" value="allow" <?= $ccMode !== 'filter' ? 'checked' : '' ?>> <b>Full allow</b> (CC_ALLOW) — traffic from these countries is fully trusted and <b>skips ALL firewall blocks</b> (incl. LFD bans). Best for your own region.</label>
      <label style="font-size:13px;display:block"><input type="radio" name="ccmode" value="filter" <?= $ccMode === 'filter' ? 'checked' : '' ?>> <b>Filtered allow</b> (CC_ALLOW_FILTER) — these countries are only exempt from <b>country-level blocking</b>; the normal firewall still applies (port filtering + LFD brute-force bans). Safer for large/foreign lists.</label>
    </div>

    <div style="display:flex;gap:14px;align-items:center;flex-wrap:wrap;margin-top:12px">
      <button class="fw-act fix" id="ccApply" type="button">&#9889; Apply never-block</button>
      <span class="meta"><span id="ccCount">0</span> selected · Current: <code><?= smpro_h($ccCurrentStr ?: '(none set)') ?></code></span>
    </div>
  </div>
</div>

<div class="card" id="addip" style="margin-bottom:14px">
  <div class="tp-th"><b>&#128272; Add IP &mdash; allow or block</b><span class="meta">Applied to whatever firewall is running — CSF <i>and/or</i> Imunify — <b>plus a live iptables rule</b>, so it works even with no CSF and takes effect immediately (no restart). A temporary Block duration uses CSF temp-deny and auto-expires.</span></div>
  <div style="padding:12px 14px;display:flex;gap:8px;flex-wrap:wrap;align-items:center">
    <input id="ipAddInput" class="tp-in" placeholder="IP address or CIDR" style="min-width:200px">
    <input id="ipAddReason" class="tp-in" placeholder="Reason (optional)" style="min-width:200px">
    <select id="ipBlockTtl" class="tp-in" title="Block duration (applies to Block only) — a temporary block auto-expires via CSF temp-deny" style="min-width:150px">
      <option value="permanent">Block: permanent</option>
      <option value="1h">Block: 1 hour (temp)</option>
      <option value="6h">Block: 6 hours (temp)</option>
      <option value="24h">Block: 24 hours (temp)</option>
      <option value="72h">Block: 72 hours (temp)</option>
    </select>
    <button class="fw-act fix" type="button" id="ipAllowBtn">&#9989; Allow (whitelist)</button>
    <button class="fw-act danger" type="button" id="ipBlockBtn">&#9940; Block</button>
  </div>
</div>

<div class="fw-two">
  <div class="card" id="layers" style="padding:0;overflow:hidden">
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

<div class="card" id="plan" style="padding:0;overflow:hidden;margin-bottom:14px">
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
  $denyRows = $fwBuildDenyRows($deny);   // built once; the table shows the first 50, the rest come by request
?>
<div class="card" id="deny" style="padding:0;overflow:hidden;margin-bottom:14px">
  <div class="tp-th"><b>Blocked IPs (csf.deny)</b><span class="meta"><span id="fwDenyInfo"><?= count($denyRows) ?> blocked · showing <?= min(50, count($denyRows)) ?></span> · select to unblock</span>
    <span style="flex:1"></span>
    <button class="fw-act" id="fwCrawlerAudit" type="button" title="Resolve every address shown and confirm it both ways in DNS. Anything that turns out to be a real search, archive or monitoring crawler is flagged here — blocking one of those has no error message and no symptom except the site quietly leaving the index.">&#128269; Check for real crawlers</button>
    <select id="fwScope" class="tp-in"><option value="all">All</option><option value="bot">Bots only</option><option value="nonarab">Outside my regions</option><option value="arab">My regions only</option></select>
    <input id="fwSearch" class="tp-in" placeholder="Filter IP / comment / country…" style="max-width:220px">
  </div>
  <div id="fwCrawlerOut" hidden style="margin:0 14px 10px;padding:9px 12px;border-radius:9px;font-size:13px;border:1px solid var(--line,#e5e7eb)"></div>
  <?php if ($denyRows): ?>
  <div class="lm-scroll" style="max-height:520px">
    <table class="smpro-table" id="fwDenyTable" data-nopage="1">
      <thead><tr>
        <th style="width:28px"><input type="checkbox" id="fwChkAll"></th>
        <th data-sort="ip" data-type="s">IP</th><th data-sort="cc" data-type="s">Country / Bot</th>
        <th data-sort="comment" data-type="s">Comment</th><th>Action</th>
      </tr></thead>
      <tbody id="fwDenyBody">
      <?= $fwDenyHtml(array_slice($denyRows, 0, 50)) ?>
      </tbody>
    </table>
  </div>
  <?php else: ?><div class="fw-empty">No blocked IPs to show (Cloudflare/local entries are hidden).</div><?php endif; ?>
</div>

<div class="card" id="cfg" style="padding:0;overflow:hidden;margin-bottom:14px">
  <div class="tp-th"><b>Important CSF Configuration</b></div>
  <table class="smpro-table"><thead><tr><th>Config</th><th>Value</th></tr></thead><tbody>
    <?php foreach ($showCfg as $k): if (!isset($cfg[$k])) continue; $v = $cfg[$k]; $warn = ($k==='TESTING' && $v==='1'); ?>
      <tr><td class="uname"><?= smpro_h($k) ?></td><td<?= $warn?' style="color:var(--warn);font-weight:700"':'' ?>><?= smpro_h($v!==''?$v:'(empty)') ?><?= $warn?' ⚠ testing mode':'' ?></td></tr>
    <?php endforeach; ?>
  </tbody></table>
</div>

<div class="card" id="ports" style="padding:0;overflow:hidden;margin-bottom:14px">
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
.fw-sc{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px 16px}
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
.lm-scroll{max-height:520px;overflow:auto}.lm-scroll thead th{position:sticky;top:0;background:var(--card);z-index:1;box-shadow:inset 0 -1px 0 var(--line)}
.smpro-table th[data-sort]{cursor:pointer;user-select:none}.smpro-table th[data-sort]:hover{color:var(--brand)}
.smpro-table th.sorted-asc::after{content:" ▲";font-size:9px}.smpro-table th.sorted-desc::after{content:" ▼";font-size:9px}
.uname{font-family:ui-monospace,Consolas,monospace;font-weight:600}.ipmono{font-family:ui-monospace,Consolas,monospace}
.geo-prov{color:var(--muted);font-size:12px}
.tp-in{border:1px solid var(--line);border-radius:9px;padding:7px 11px;font-size:13px}
.fw-act{font-size:11px;font-weight:600;border:1px solid #c9d4ff;color:var(--brand);background:var(--card);border-radius:7px;padding:3px 10px;cursor:pointer}.fw-act:hover{background:var(--brand);color:#fff}
.fw-bulkbar{display:none;position:fixed;left:50%;transform:translateX(-50%);bottom:18px;z-index:40;background:#10182b;color:#fff;border-radius:14px;padding:10px 16px;align-items:center;gap:12px;box-shadow:0 18px 40px rgba(0,0,0,.35)}
.fw-bulkbar.show{display:flex}.fw-bulkbar .meta{color:#cfd8ef}.fw-bulkbar b{color:#fff}
.fw-bbtn{font-size:13px;font-weight:600;border:0;border-radius:9px;padding:8px 14px;cursor:pointer;background:var(--brand);color:#fff}.fw-bbtn.ghost{background:#23304d;color:#cfd8ef}
.pill{display:inline-block;font-size:11px;font-weight:700;padding:3px 10px;border-radius:20px}
.pill.good{background:var(--good-bg);color:var(--good)}.pill.warn{background:var(--warn-bg);color:var(--warn)}.pill.danger{background:var(--dang-bg);color:var(--dang)}
.b{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:20px}
.b.green{background:var(--good-bg);color:var(--good)}.b.red{background:var(--dang-bg);color:var(--dang)}.b.gray{background:var(--card);color:#475569}
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
// Find real crawlers among addresses that are already blocked. Flags them in place; unblocking stays a decision
// the operator makes with the button that was always there.
(function(){
  var b=document.getElementById('fwCrawlerAudit');if(!b)return;
  b.addEventListener('click',function(){
    var rows=Array.prototype.slice.call(document.querySelectorAll('#fwDenyBody tr[data-ip]'));
    var out=document.getElementById('fwCrawlerOut');out.hidden=false;
    if(!rows.length){out.innerHTML='<b>Nothing blocked to check.</b>';return;}
    var ips=rows.map(function(r){return r.getAttribute('data-ip');});
    var ot=b.textContent;b.disabled=true;b.textContent='Resolving '+ips.length+'…';
    out.innerHTML='<span class="meta">Reverse-resolving each address and confirming it forward again. This takes a moment.</span>';
    var fd=new URLSearchParams();fd.set('fw_action','crawler_audit');fd.set('ips',ips.join(','));fd.set('smpro_csrf',FW_CSRF);
    fetch('index.cgi?page=firewall-status',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString()})
      .then(function(r){return r.json();}).then(function(j){
        b.disabled=false;b.textContent=ot;
        if(!j||!j.ok){out.innerHTML='<b style="color:var(--dang,#dc2626)">Check failed.</b> <span class="meta">'+String((j&&j.error)||'Request failed.').replace(/[<>&]/g,'')+'</span>';return;}
        var f=j.found||[];
        f.forEach(function(x){
          var tr=document.querySelector('#fwDenyBody tr[data-ip="'+String(x.ip).replace(/"/g,'')+'"]');if(!tr)return;
          tr.style.background='rgba(220,38,38,.09)';
          var cell=tr.children[2];if(!cell)return;
          if(cell.querySelector('.fw-realbot'))return;
          var sp=document.createElement('div');sp.className='fw-realbot';sp.style.cssText='margin-top:3px;font-size:11.5px;font-weight:700;color:#dc2626';
          sp.textContent='\u26A0 really '+x.name+' — '+x.host;
          cell.appendChild(sp);
        });
        var scope=(j.complete?'':' (stopped after '+j.checked+' of '+j.total+' — the resolver was slow. Run it again: what was resolved is cached for a week, so the next run picks up where this one stopped.)');
        out.innerHTML=f.length
          ? '<b style="color:#dc2626">'+f.length+' genuine crawler'+(f.length===1?'':'s')+' found in the block list.</b> '
            +'<span class="meta">Each is marked in the table below. Blocking these produces no error — the site simply stops being crawled. Unblock the ones you did not mean to block, then allow-list them so it cannot happen again.</span>'+scope
          : '<b style="color:#059669">No genuine crawler is blocked.</b> <span class="meta">'+j.checked+' address(es) checked, both ways in DNS. The &#9729;&#65039; cloud/hosting marks are rented servers, not search engines — blocking those costs nothing in search.</span>'+scope;
      }).catch(function(){b.disabled=false;b.textContent=ot;out.innerHTML='<b style="color:var(--dang,#dc2626)">Request failed.</b>';});
  });
})();

// Blocked IPs: search + scope filter + column sorting + paging — all on the server (50 rows a page)
(function(){
  var body=document.getElementById('fwDenyBody'),tbl=document.getElementById('fwDenyTable');if(!body||!tbl)return;
  var st={off:0,scope:'all',q:'',sk:'',sd:'asc',total:<?= (int)count($denyRows) ?>},tm=null,busy=false;
  var bar=document.createElement('div');bar.className='fw-pgbar';
  bar.innerHTML='<span class="fw-pginfo"></span><span class="sp"></span><button type="button" class="fw-pgbtn" data-d="-1">&#8249; prev</button><span class="fw-pgnum"></span><button type="button" class="fw-pgbtn" data-d="1">next &#8250;</button>';
  var box=tbl.parentNode;box.parentNode.insertBefore(bar,box.nextSibling);
  function paint(){var pages=Math.max(1,Math.ceil(st.total/50)),p=Math.floor(st.off/50);
    bar.querySelector('.fw-pginfo').textContent=st.total?('Showing '+(st.off+1)+'\u2013'+Math.min(st.total,st.off+50)+' of '+st.total+(st.q||st.scope!=='all'?' matching':'')):'No rows match';
    bar.querySelector('.fw-pgnum').textContent=(p+1)+' / '+pages;var bt=bar.querySelectorAll('.fw-pgbtn');bt[0].disabled=p<=0;bt[1].disabled=p>=pages-1;
    bar.style.display=(pages>1||st.q||st.scope!=='all')?'':'none';
    var inf=document.getElementById('fwDenyInfo');if(inf)inf.textContent=st.total+' blocked · showing '+Math.min(50,Math.max(0,st.total-st.off));}
  function load(){if(busy)return;busy=true;
    var fd=new URLSearchParams();fd.set('fw_action','deny_rows');fd.set('smpro_csrf',FW_CSRF);fd.set('off',String(st.off));fd.set('scope',st.scope);fd.set('q',st.q);fd.set('sk',st.sk);fd.set('sd',st.sd);
    fetch('index.cgi?page=firewall-status',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString()})
      .then(function(r){return r.json();}).then(function(j){busy=false;if(!j||!j.ok)return;st.total=j.total;st.off=j.offset;body.innerHTML=j.html;paint();
        var ev=document.createEvent('Event');ev.initEvent('fwrows',true,false);body.dispatchEvent(ev);})
      .catch(function(){busy=false;});}
  bar.addEventListener('click',function(e){var b=e.target.closest('.fw-pgbtn');if(!b||b.disabled)return;st.off=Math.max(0,st.off+parseInt(b.getAttribute('data-d'),10)*50);load();});
  var s=document.getElementById('fwSearch'),sc=document.getElementById('fwScope');
  if(s)s.addEventListener('input',function(){clearTimeout(tm);tm=setTimeout(function(){st.q=s.value||'';st.off=0;load();},250);});
  if(sc)sc.addEventListener('change',function(){st.scope=sc.value;st.off=0;load();});
  document.querySelectorAll('#fwDenyTable th[data-sort]').forEach(function(th){th.addEventListener('click',function(){var k=th.getAttribute('data-sort');if(st.sk===k)st.sd=st.sd==='asc'?'desc':'asc';else{st.sk=k;st.sd='asc';}
    document.querySelectorAll('#fwDenyTable th').forEach(function(h){h.classList.remove('sorted-asc','sorted-desc');});th.classList.add(st.sd==='asc'?'sorted-asc':'sorted-desc');st.off=0;load();});});
  paint();
})();
(function(){var i=document.getElementById('fwPortSearch');if(!i)return;i.addEventListener('input',function(){var q=this.value.toLowerCase();
  document.querySelectorAll('#fwPortTable tbody tr').forEach(function(tr){var s=tr.getAttribute('data-search')||'';tr.style.display=s.indexOf(q)>=0?'':'none';});});})();
// unblock (AJAX, POST+CSRF)
(function(){
  var body=document.getElementById('fwDenyBody');if(!body)return;
  var bar=document.getElementById('fwBulk'),barN=document.getElementById('fwBulkN'),chkAll=document.getElementById('fwChkAll');
  // SAFETY: only ever act on rows that are currently VISIBLE (not filtered out).
  function vis(c){return c.closest('tr').style.display!=='none';}
  body.addEventListener('fwrows',function(){upd();});
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
.smpro-main .card{border-radius:14px}
.smpro-main .card>.tp-th{padding:12px 16px}
.smpro-main .card>.tp-th>b{font-size:14px}
.gr-tools{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:6px 0 8px;font-size:12.5px}
.gr-chips{display:inline-flex;gap:6px;flex-wrap:wrap}
.gr-chip{border:1px solid var(--line);background:var(--card);border-radius:20px;padding:3px 10px;font-size:12px;cursor:pointer;color:var(--text)}.gr-chip b{margin-left:3px;color:var(--muted)}.gr-chip.on{border-color:var(--brand);box-shadow:inset 0 0 0 1px var(--brand)}
.gr-tools2{padding:8px 10px;background:var(--bg);border:1px solid var(--line);border-radius:10px}
.gr-tools2 .tp-in,.gr-tools2 .tp-sel{padding:4px 8px;font-size:12.5px}
table.gr-tbl{font-size:13px}table.gr-tbl td{padding:9px 12px;vertical-align:top}table.gr-tbl th{font-size:11px}
table.gr-tbl tr.gr-live td{background:rgba(220,38,38,.06)}
.gr-acct{word-break:break-all}.gr-acct b{font-weight:700}
.gr-chipx{display:inline-block;font-size:10px;font-weight:800;letter-spacing:.04em;padding:1px 7px;border-radius:10px;vertical-align:middle;margin-left:4px}
.gr-chipx.dang{background:var(--dang-bg);color:var(--dang)}.gr-chipx.muted{background:rgba(148,163,184,.18);color:var(--muted)}
.gr-ev{font-size:12.5px;line-height:1.5}.gr-ev.dang{color:var(--dang)}.gr-ev.muted{color:var(--muted)}.gr-ev .n{font-variant-numeric:tabular-nums;color:var(--muted)}
.gr-when{white-space:nowrap;text-align:right;font-variant-numeric:tabular-nums;color:var(--muted);font-size:12.5px}
</style>
<style>
.fw-actcell{white-space:nowrap}
.fw-act{font-size:11px;font-weight:700;border:1px solid var(--line);border-radius:7px;padding:4px 10px;cursor:pointer;margin:1px;background:var(--card)}
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
  var extraEl=document.getElementById('ccExtra');
  // free-text codes: uppercase 2-letter tokens, de-duplicated
  function extraCodes(){ if(!extraEl) return [];
    var seen={},out=[]; (extraEl.value||'').split(/[^A-Za-z]+/).forEach(function(t){ t=t.toUpperCase();
      if(t.length===2 && !seen[t]){ seen[t]=1; out.push(t); } }); return out; }
  function boxCodes(){return cbs().filter(function(c){return c.checked;}).map(function(c){return c.value.toUpperCase();});}
  // union of checkboxes + free-text, de-duplicated (a code typed AND checked counts once)
  function selected(){var seen={},out=[]; boxCodes().concat(extraCodes()).forEach(function(c){ if(!seen[c]){seen[c]=1;out.push(c);} }); return out;}
  function ccCount(){var n=selected().length; var el=document.getElementById('ccCount'); if(el)el.textContent=n;
    var lbl=document.getElementById('ccDDlabel'); if(lbl)lbl.textContent=n?(n+' countr'+(n>1?'ies':'y')+' selected'):'Select countries…';}
  if(extraEl)extraEl.addEventListener('input',ccCount);
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
    var ttlEl=document.getElementById('ipBlockTtl');
    var dur=(op==='block'&&ttlEl)?ttlEl.value:'permanent';
    var DLBL={'1h':'1 hour','6h':'6 hours','24h':'24 hours','72h':'72 hours'};
    var q=(op==='block')
      ?((dur!=='permanent'&&DLBL[dur])?('Temporarily block '+ip+' for '+DLBL[dur]+'? It auto-expires.'):('Block '+ip+' permanently (csf.deny)?'))
      :('Whitelist '+ip+'?');
    if(!confirm(q))return;
    var btn=document.getElementById(op==='block'?'ipBlockBtn':'ipAllowBtn');var old=btn.innerHTML;btn.disabled=true;btn.innerHTML='⏳';
    var fd=new URLSearchParams();fd.set('smpro_csrf',FW_CSRF);fd.set('fw_action','ipadd');fd.set('op',op);fd.set('ip',ip);fd.set('reason',reason);fd.set('dur',dur);
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
  // EMERGENCY: allow an IP on the LIVE firewall now (works even if CSF disabled/desynced, and even if already in csf.allow)
  function allowLive(btn){
    var ip=btn.getAttribute('data-ip');if(!ip){alert('No admin IP detected for this session.');return;}
    if(!confirm('Apply a LIVE firewall ALLOW for '+ip+' right now?\n\nInserts a top-of-INPUT ACCEPT into the running iptables (and saves it to csf.allow). This takes effect IMMEDIATELY even if CSF is disabled or its old rules are still dropping — it protects your access from a lock-out.'))return;
    var old=btn.innerHTML;btn.disabled=true;btn.innerHTML='⏳';
    var fd=new URLSearchParams();fd.set('smpro_csrf',FW_CSRF);fd.set('fw_action','allow_live');fd.set('ip',ip);
    fetch('index.cgi?page=firewall-status',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'})
     .then(function(r){return r.json();}).then(function(j){alert((j&&j.ok?'✅ ':'⚠ ')+((j&&j.msg)||'Done'));if(j&&j.ok)setTimeout(function(){location.reload();},1100);else{btn.disabled=false;btn.innerHTML=old;}})
     .catch(function(){btn.disabled=false;btn.innerHTML=old;alert('Request failed.');});
  }
  ['fwAllowLive','fwAllowLiveTop'].forEach(function(id){var el=document.getElementById(id);if(el)el.addEventListener('click',function(){allowLive(el);});});
  // Re-sync firewall (re-enable CSF so the live rules match the allow/deny lists)
  var rs=document.getElementById('fwResync');
  if(rs)rs.addEventListener('click',function(){
    if(!confirm('Re-enable CSF and reload the firewall?\n\nThis rebuilds the LIVE rules from CSF config (applying your allow-list). Make sure your IP is allow-listed first (use “Allow my IP LIVE” above). Continue?'))return;
    var old=rs.innerHTML;rs.disabled=true;rs.innerHTML='⏳ Re-syncing…';
    var fd=new URLSearchParams();fd.set('smpro_csrf',FW_CSRF);fd.set('fw_action','fw_resync');
    fetch('index.cgi?page=firewall-status',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'})
     .then(function(r){return r.json();}).then(function(j){alert((j&&j.ok?'✅ ':'⚠ ')+((j&&j.msg)||'Done'));if(j&&j.ok)setTimeout(function(){location.reload();},1200);else{rs.disabled=false;rs.innerHTML=old;}})
     .catch(function(){rs.disabled=false;rs.innerHTML=old;alert('Request failed.');});
  });
})();
</script>
<script>
(function(){
  // Block-lists. Review is a separate press from Add on purpose: Add stays disabled until this server has said
  // what the list would actually do here, so nobody applies a pooled list sight-unseen.
  function post(fd,cb){
    fd.set('smpro_csrf',FW_CSRF);
    fetch('index.cgi?page=firewall-status',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString()})
      .then(function(r){return r.json();}).then(cb).catch(function(){cb({ok:false,msg:'Request failed.'});});
  }
  function esc(x){return String(x==null?'':x).replace(/[<>&"]/g,function(c){return {'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;'}[c];});}
  function box(el){el.hidden=false;return el;}

  document.querySelectorAll('.fwbReview').forEach(function(b){
    b.addEventListener('click',function(){
      var card=b.closest('.fwb-src'), out=box(card.querySelector('.fwb-out')), add=card.querySelector('.fwbApply');
      var ot=b.innerHTML; b.disabled=true; b.innerHTML='Reviewing…'; add.disabled=true;
      out.innerHTML='<span class="meta">Refreshing the list and checking every address against this server.</span>';
      var fd=new URLSearchParams(); fd.set('fw_action','bl_review'); fd.set('key',b.getAttribute('data-key')); fd.set('refresh','1');
      post(fd,function(j){
        b.disabled=false; b.innerHTML=ot;
        if(!j||!j.ok){out.innerHTML='<b style="color:var(--dang,#dc2626)">Review failed.</b> <span class="meta">'+esc(j&&j.msg)+'</span>';return;}
        var n=j.n||{};
        var h='<div><span class="fwb-n add">'+n.add+'</span>would be blocked'
             +' <span class="fwb-n skip">'+n.blocked+'</span>already blocked here'
             +' <span class="fwb-n skip">'+n.allowed+'</span>on your allow-list'
             +' <span class="fwb-n skip">'+n.human+'</span>not a datacenter network'
             +' <span class="fwb-n crawl">'+n.crawler+'</span>refused as real crawlers</div>';
        if(n.human) h+='<div class="meta" style="margin-top:4px">Addresses that are not on a datacenter network are skipped here even though the list carries them &mdash; somewhere a person is behind one of those.</div>';
        if(n.crawler) h+='<div class="meta" style="margin-top:4px">A verified crawler is never blocked from a list, whatever the list says.</div>';
        if(!j.complete) h+='<div class="meta" style="margin-top:4px"><b>Not every address was checked</b> &mdash; the resolver was slow. Review again to continue; what was resolved is cached.</div>';
        if(j.sample&&j.sample.add&&j.sample.add.length){
          h+='<div class="fwb-ips">'+j.sample.add.map(function(r){return esc(r.ip)+(r.servers?' ('+r.servers+' servers)':'');}).join(' &middot; ')
            +(n.add>j.sample.add.length?' &hellip; and '+(n.add-j.sample.add.length)+' more':'')+'</div>';
        }
        out.innerHTML=h;
        add.disabled = !n.add;
        add.title = n.add ? ('Block the '+n.add+' address(es) above') : 'Nothing to add';
      });
    });
  });

  document.querySelectorAll('.fwbApply').forEach(function(b){
    b.addEventListener('click',function(){
      var card=b.closest('.fwb-src'), out=box(card.querySelector('.fwb-out'));
      if(!confirm('Block the reviewed addresses on this server?\n\nThey are added to csf.deny tagged as coming from this list, so "Remove what this added" can take out exactly these and nothing else.')) return;
      var ot=b.innerHTML; b.disabled=true; b.innerHTML='Blocking…';
      var fd=new URLSearchParams(); fd.set('fw_action','bl_apply'); fd.set('key',b.getAttribute('data-key'));
      post(fd,function(j){ b.innerHTML=ot; b.disabled=true;   // a completed apply needs a fresh review before another
        out.innerHTML=(j&&j.ok?'<b style="color:#059669">Done.</b> ':'<b style="color:var(--dang,#dc2626)">Failed.</b> ')+esc(j&&j.msg); });
    });
  });

  document.querySelectorAll('.fwbUndo').forEach(function(b){
    b.addEventListener('click',function(){
      var card=b.closest('.fwb-src'), out=box(card.querySelector('.fwb-out'));
      if(!confirm('Remove every address this list added to csf.deny?\n\nBlocks made by you, by lfd or by anything else are left alone.')) return;
      var ot=b.innerHTML; b.disabled=true; b.innerHTML='Removing…';
      var fd=new URLSearchParams(); fd.set('fw_action','bl_undo'); fd.set('key',b.getAttribute('data-key'));
      post(fd,function(j){ b.disabled=false; b.innerHTML=ot;
        out.innerHTML=(j&&j.ok?'<b style="color:#059669">Done.</b> ':'<b style="color:var(--dang,#dc2626)">Partly done.</b> ')+esc(j&&j.msg); });
    });
  });

  var so=document.getElementById('fwbShareOn'), sp=document.getElementById('fwbPreview'), ss=document.getElementById('fwbSend'), sout=document.getElementById('fwbShareOut');
  if(so) so.addEventListener('change',function(){
    var fd=new URLSearchParams(); fd.set('fw_action','bl_share_set'); fd.set('on',so.checked?'1':'');
    post(fd,function(j){ box(sout).innerHTML=esc(j&&j.msg); if(ss) ss.disabled=!(j&&j.on); });
  });
  if(sp) sp.addEventListener('click',function(){
    var ot=sp.innerHTML; sp.disabled=true; sp.innerHTML='Building…';
    var fd=new URLSearchParams(); fd.set('fw_action','bl_share_preview');
    post(fd,function(j){
      sp.disabled=false; sp.innerHTML=ot; box(sout);
      if(!j||!j.ok){sout.innerHTML='<b style="color:var(--dang,#dc2626)">Could not build the preview.</b> '+esc(j&&j.msg);return;}
      if(!j.n){sout.innerHTML='<b>Nothing would be sent.</b> <span class="meta">Nothing blocked here is an illegitimate bot on a datacenter network.</span>';return;}
      sout.innerHTML='<b>'+j.n+' address(es) would be sent</b>, each as address + door only:'
        +'<div class="fwb-ips">'+j.sample.map(function(r){return esc(r.ip)+' ['+esc(r.kind)+']';}).join(' &middot; ')
        +(j.n>j.sample.length?' &hellip; and '+(j.n-j.sample.length)+' more':'')+'</div>'
        +'<div class="meta" style="margin-top:5px">This is the whole payload. No hostname, no domain, no account name and no log line is part of it.</div>';
    });
  });
  if(ss) ss.addEventListener('click',function(){
    if(!confirm('Share these addresses with the pool?\n\nAddress and door only. Nothing identifying this server, its sites or its customers is included.')) return;
    var ot=ss.innerHTML; ss.disabled=true; ss.innerHTML='Sending…';
    var fd=new URLSearchParams(); fd.set('fw_action','bl_share_send');
    post(fd,function(j){ ss.disabled=false; ss.innerHTML=ot;
      box(sout).innerHTML=(j&&j.ok?'<b style="color:#059669">Sent.</b> ':'<b style="color:var(--dang,#dc2626)">Not sent.</b> ')+esc(j&&j.msg); });
  });
})();

(function(){
  // make every section card collapsible — click its title (or chevron) to open/close
  // Recommended allow-lists carries its own header class, so it was never part of this and had no way to close.
  // It is a long optional list that most visits scroll past to reach the blocked addresses below, so it is the one
  // section that starts CLOSED. Whether each section is open is remembered per section, so a choice made once is
  // not undone by the next page load.
  var KEY='smpro:fw:open';
  var open={};
  try{ open=JSON.parse(localStorage.getItem(KEY)||'{}')||{}; }catch(err){ open={}; }
  function remember(){ try{ localStorage.setItem(KEY, JSON.stringify(open)); }catch(err){} }

  function openCard(id, scroll){ var card=document.getElementById(id); if(!card) return; if(!card.classList.contains('fw-open')){ card.classList.add('fw-open'); var th=card.querySelector('.fw-toggle'); if(th){ open[th.getAttribute('data-fold')]=true; remember(); } } if(scroll){ card.style.scrollMarginTop='120px'; card.scrollIntoView({behavior:'smooth',block:'start'}); } }   // the page scrolls inside .smpro-main, not the window
  document.querySelectorAll('[data-go]').forEach(function(a){ a.addEventListener('click',function(e){ e.preventDefault(); var id=a.getAttribute('data-go'); openCard(id,true); document.querySelectorAll('.fw-nav a').forEach(function(x){ x.classList.toggle('on', x.getAttribute('data-go')===id); }); history.replaceState(null,'','#'+id); }); });
  var oa=document.getElementById('fwOpenAll'), ca=document.getElementById('fwCloseAll');
  if(oa) oa.addEventListener('click',function(){ document.querySelectorAll('.smpro-main .card').forEach(function(cd){ var th=cd.querySelector('.fw-toggle'); if(th){ cd.classList.add('fw-open'); open[th.getAttribute('data-fold')]=true; } }); remember(); });
  if(ca) ca.addEventListener('click',function(){ document.querySelectorAll('.smpro-main .card').forEach(function(cd){ var th=cd.querySelector('.fw-toggle'); if(th){ cd.classList.remove('fw-open'); open[th.getAttribute('data-fold')]=false; } }); remember(); });
  if(location.hash && document.getElementById(location.hash.slice(1))) setTimeout(function(){ openCard(location.hash.slice(1), true); }, 150);
  document.querySelectorAll('.smpro-main .card > .tp-th, .smpro-main .card > .fwrec-hd').forEach(function(th){
    var card=th.parentElement;
    var body=document.createElement('div'); body.className='fw-collapse';
    while(th.nextSibling){ body.appendChild(th.nextSibling); }
    card.appendChild(body);
    th.classList.add('fw-toggle');
    if(!th.querySelector('.fw-chev')) th.insertAdjacentHTML('afterbegin','<span class="fw-chev">&#9656;</span> ');

    // A stable name for this section: its own heading text. Falling back to the position would move every
    // remembered state the moment a section is added above it.
    var id=(th.textContent||'').replace(/\s+/g,' ').trim().slice(0,60) || ('card'+Math.random());
    th.setAttribute('data-fold', id);
    var closedByDefault = card.classList.contains('fwrec');
    var isOpen = Object.prototype.hasOwnProperty.call(open, id) ? !!open[id] : !closedByDefault;
    card.classList.toggle('fw-open', isOpen);

    // Keyboard and screen readers get the same control the mouse has: it is a real toggle, not a clickable div.
    th.setAttribute('role','button');
    th.setAttribute('tabindex','0');
    th.style.cursor='pointer';
    th.setAttribute('aria-expanded', isOpen ? 'true' : 'false');

    function toggle(){
      var nowOpen=card.classList.toggle('fw-open');
      th.setAttribute('aria-expanded', nowOpen ? 'true' : 'false');
      open[id]=nowOpen; remember();
    }
    th.addEventListener('click',function(e){
      if(e.target.closest('a,button,input,select,label,.fw-chk'))return;   // don't toggle when using header controls
      toggle();
    });
    th.addEventListener('keydown',function(e){
      if(e.key===' '||e.key==='Enter'||e.key==='Spacebar'){ e.preventDefault(); toggle(); }
    });
  });
})();
</script>
<?php if (function_exists('smpro_gw_cfg')): ?>
<script>
/* Country wall. Every confirm() string is ONE line: a raw newline inside a single-quoted JS string is a
   SyntaxError, and a SyntaxError throws away the whole block — leaving buttons that do nothing, silently. That
   has shipped twice in this codebase. */
(function(){
  var out=document.getElementById('gwOut'); if(!out) return;
  function esc(x){return String(x==null?'':x).replace(/[<>&"]/g,function(c){return {'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;'}[c];});}
  function show(h){out.hidden=false;out.innerHTML=h;}
  function post(fd,cb){
    fd.set('smpro_csrf',FW_CSRF);
    return fetch('index.cgi?page=firewall-status',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString()})
      .then(function(r){return r.json();}).then(cb).catch(function(e){show('<b style="color:var(--dang)">'+esc(e)+'</b>');});
  }
  function cfg(){
    return {countries:(document.getElementById('gwCC').value||'').toUpperCase().split(/[\s,]+/).filter(function(c){return c.length===2;}),
            doors:Array.prototype.slice.call(document.querySelectorAll('.gwDoor:checked')).map(function(c){return c.value;}),
            deadman_minutes:parseInt(document.getElementById('gwDead').value||'60',10)||60};
  }
  function busy(b,txt){var o=b.innerHTML;b.disabled=true;b.innerHTML=txt;return function(){b.disabled=false;b.innerHTML=o;};}

  document.getElementById('gwSave').addEventListener('click',function(){
    var done=busy(this,'Saving…');
    var fd=new URLSearchParams();fd.set('fw_action','gw_save');fd.set('cfg',JSON.stringify(cfg()));
    post(fd,function(j){done();show('<b'+(j&&j.ok?'':' style="color:var(--dang)"')+'>'+esc(j&&j.msg||'')+'</b>');});
  });

  document.getElementById('gwFetch').addEventListener('click',function(){
    var done=busy(this,'Fetching…');
    /* Saved first on purpose: the fetch asks the firewall for the ranges of the countries that are SAVED, so
       fetching what is merely typed would download one list and wall another. */
    var fd=new URLSearchParams();fd.set('fw_action','gw_save');fd.set('cfg',JSON.stringify(cfg()));
    post(fd,function(){
      var f2=new URLSearchParams();f2.set('fw_action','gw_fetch');
      post(f2,function(j){done();show('<b'+(j&&j.ok?'':' style="color:var(--dang)"')+'>'+esc(j&&j.msg||'')+'</b>');});
    });
  });

  document.getElementById('gwPrev').addEventListener('click',function(){
    var done=busy(this,'Checking…');
    var fd=new URLSearchParams();fd.set('fw_action','gw_save');fd.set('cfg',JSON.stringify(cfg()));
    post(fd,function(){
      var f2=new URLSearchParams();f2.set('fw_action','gw_preview');
      post(f2,function(j){
        done();
        if(!j){show('<b style="color:var(--dang)">No answer.</b>');return;}
        var h='<b'+(j.ok?'':' style="color:var(--dang)"')+'>'+esc(j.msg||'')+'</b>';
        if(j.check&&j.check.problems&&j.check.problems.length){
          h+='<ul class="meta" style="margin:6px 0 0 18px">';
          j.check.problems.forEach(function(p){h+='<li>'+esc(p)+'</li>';});
          h+='</ul>';
        }
        if(j.ports&&j.ports.length) h+='<div class="meta" style="margin-top:4px">Ports: '+esc(j.ports.join(', '))+'</div>';
        show(h);
      });
    });
  });

  document.getElementById('gwArm').addEventListener('click',function(){
    if(!confirm('Put the wall up? Only the countries listed will be able to reach the login and upload doors. Websites are not affected. Your own address is checked first and arming is refused if it would not survive.')) return;
    var done=busy(this,'Putting it up…');
    var fd=new URLSearchParams();fd.set('fw_action','gw_save');fd.set('cfg',JSON.stringify(cfg()));
    post(fd,function(){
      var f2=new URLSearchParams();f2.set('fw_action','gw_apply');
      post(f2,function(j){
        done();
        show('<b'+(j&&j.ok?'':' style="color:var(--dang)"')+'>'+esc(j&&j.msg||'')+'</b>');
        if(j&&j.ok) setTimeout(function(){location.reload();},1200);
      });
    });
  });

  document.getElementById('gwOff').addEventListener('click',function(){
    var done=busy(this,'Removing…');
    var fd=new URLSearchParams();fd.set('fw_action','gw_remove');
    post(fd,function(j){done();show('<b>'+esc(j&&j.msg||'')+'</b>');setTimeout(function(){location.reload();},900);});
  });

  /* The dead man's switch is fed from the browser, and only from the browser. What it has to prove is that a
     request still arrives from outside and is answered — a worker on the server could never prove that, because
     a locked-out operator and a working server look identical from the inside. */
  function gwBeat(){ var fd=new URLSearchParams(); fd.set('fw_action','gw_beat'); post(fd,function(){}); }
  gwBeat();
  setInterval(gwBeat, 120000);
})();
</script>
<?php endif; ?>
<script>
/* The door wall. Arm and disarm are single presses; the server refuses to arm when it would refuse the operator. */
(function(){
  var out=document.getElementById('ghOut'); if(!out) return;
  function esc(x){return String(x==null?'':x).replace(/[<>&"]/g,function(c){return {'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;'}[c];});}
  function post(fd,cb){fd.set('smpro_csrf',FW_CSRF);
    fetch('index.cgi?page=firewall-status',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString()})
      .then(function(r){return r.json();}).then(cb).catch(function(){cb({ok:false,msg:'Request failed.'});});}
  function show(h){out.hidden=false;out.innerHTML=h;}
  var a=document.getElementById('ghArm'), d=document.getElementById('ghDisarm');
  if(a)a.addEventListener('click',function(){
    if(!confirm('Arm the door?\n\nFrom now on a sign-in from a country not allowed for anyone is refused before the password is checked - at cPanel, WHM, webmail, FTP, SSH and mail. Your own address is whitelisted in cPHulk first.\n\nWay back from any shell: whmapi1 disable_cphulk')) return;
    a.disabled=true; a.textContent='Arming…';
    var fd=new URLSearchParams(); fd.set('fw_action','gh_arm');
    post(fd,function(j){ if(j&&j.ok){show('<b style="color:#059669">'+esc(j.msg)+'</b>'); setTimeout(function(){location.reload();},1200);} else {a.disabled=false;a.textContent='Arm the door';show('<b style="color:var(--dang)">'+esc((j&&j.msg)||'Failed')+'</b>');} });
  });
  if(d)d.addEventListener('click',function(){
    if(!confirm('Disarm the door?\n\ncPHulk\'s country list goes back to what it was before the wall, and cPHulk is switched off again if it was off before.')) return;
    d.disabled=true; d.textContent='Disarming…';
    var fd=new URLSearchParams(); fd.set('fw_action','gh_disarm');
    post(fd,function(j){ show('<b style="color:'+(j&&j.ok?'#059669':'var(--dang)')+'">'+esc((j&&j.msg)||'Failed')+'</b>'); setTimeout(function(){location.reload();},1200); });
  });
})();
/* Country Login Lock. Every action is a press. The arm check runs on the server before anything is saved, so a
   configuration that would lock the operator out is refused rather than applied and regretted. */
(function(){
  var out=document.getElementById('glOut'); if(!out) return;
  function esc(x){return String(x==null?'':x).replace(/[<>&"]/g,function(c){return {'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;'}[c];});}
  function post(fd,cb){fd.set('smpro_csrf',FW_CSRF);
    fetch('index.cgi?page=firewall-status',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString()})
      .then(function(r){return r.json();}).then(cb).catch(function(){cb({ok:false,msg:'Request failed.'});});}
  function show(h){out.hidden=false;out.innerHTML=h;}
  function svcs(){return Array.prototype.slice.call(document.querySelectorAll('.glSvc:checked')).map(function(c){return c.value;});}

  /* The names follow what is typed, so a wrong code is visible before Save rather than after a sign-in was
     allowed or refused by it. The table is small on purpose: it covers what this product's operators actually
     use, and anything outside it is shown as unknown instead of guessed. */
  var GLCC = <?= json_encode((function () {
      $t = [];
      foreach (['EG','SA','AE','KW','QA','BH','OM','JO','LB','IQ','SY','YE','PS','SD','LY','TN','DZ','MA','MR','SO','DJ','KM',
                'US','GB','DE','FR','NL','IT','ES','PT','BE','CH','AT','SE','NO','DK','FI','IE','PL','CZ','RO','BG','GR','HU',
                'TR','RU','UA','CN','IN','PK','BD','ID','MY','SG','PH','TH','VN','JP','KR','AU','NZ','CA','BR','MX','AR','ZA','NG','KE','PA'] as $c) {
          $n = function_exists('smpro_cc_name') ? smpro_cc_name($c) : $c;
          if ($n !== '' && strtoupper($n) !== strtoupper($c)) $t[$c] = $n;
      }
      return $t;
  })(), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?>;
  (function(){
    var box=document.getElementById('glCC'), out=document.getElementById('glCCNames');
    if(!box||!out) return;
    function paint(){
      var codes=(box.value||'').toUpperCase().split(/[\s,]+/).filter(function(c){return c.length===2;});
      if(!codes.length){out.textContent='Nothing listed — the lock will refuse to arm.';return;}
      out.textContent=codes.map(function(c){return c+' — '+(GLCC[c]||'(unknown code)');}).join(' · ');
    }
    box.addEventListener('input',paint); paint();
  })();

  document.getElementById('glSave').addEventListener('click',function(){
    var on=document.getElementById('glOn').checked, dry=document.getElementById('glDry').checked;
    if(on && !dry && !confirm('Arm the lock for real?\n\nFrom now on a sign-in from a country not on your list has its login ports closed. Websites are not affected. You can undo any rule from the table below.')) return;
    var fd=new URLSearchParams();
    fd.set('fw_action','gl_save');
    fd.set('countries',document.getElementById('glCC').value);
    fd.set('ttl_days',document.getElementById('glTtl').value);
    fd.set('on_success',document.getElementById('glOnOk').value);
    fd.set('on_failed',document.getElementById('glOnBad').value);
    fd.set('per_account',document.getElementById('glPA').value);
    if(on) fd.set('enabled','1'); if(dry) fd.set('dryrun','1');
    fd.set('evict',document.getElementById('glEvict').checked?'1':'0');
    var gp=document.getElementById('glPorts'); if(gp) fd.set('custom_ports',gp.value);
    svcs().forEach(function(v){fd.append('services[]',v);});
    post(fd,function(j){
      if(j&&j.ok){show('<b style="color:#059669">'+esc(j.msg)+'</b>'); setTimeout(function(){location.reload();},900);}
      else show('<b style="color:var(--dang)">'+esc((j&&j.msg)||'Failed')+'</b>');
    });
  });

  document.getElementById('glScan').addEventListener('click',function(){
    var b=this, ot=b.textContent; b.disabled=true; b.textContent='Checking…';
    var fd=new URLSearchParams(); fd.set('fw_action','gl_scan'); fd.set('dryrun','1');   // a check never writes
    post(fd,function(j){
      b.disabled=false; b.textContent=ot;
      if(!j){show('<b style="color:var(--dang)">Request failed.</b>');return;}
      if(!j.ok){show('<b style="color:var(--dang)">'+esc(j.msg)+'</b>');return;}
      var h='<b>'+esc(j.msg)+'</b>';
      if((j.hits||[]).length){
        h+='<div style="margin-top:6px"><table class="smpro-table"><thead><tr><th>Address</th><th>Country</th><th>Account</th><th>Password</th></tr></thead><tbody>';
        j.hits.forEach(function(x){h+='<tr><td class="ipmono">'+esc(x.ip)+'</td><td>'+esc(x.cc)+'</td><td>'+esc(x.account)+'</td><td>'
          +(x.success?'<b style="color:#dc2626">ACCEPTED — this password is already known to somebody</b>':'rejected')+'</td></tr>';});
        h+='</tbody></table></div>';
      }
      if((j.skipped||[]).length) h+='<div class="meta" style="margin-top:6px">Left alone: '+j.skipped.slice(0,12).map(function(x){return esc(x.ip)+' ('+esc(x.why)+')';}).join(' · ')+'</div>';
      show(h);
    });
  });

  document.getElementById('glExpire').addEventListener('click',function(){
    var fd=new URLSearchParams(); fd.set('fw_action','gl_expire');
    post(fd,function(j){show('<b>'+esc((j&&j.msg)||'done')+'</b>');});
  });

  var clr=document.getElementById('glClear');
  if(clr) clr.addEventListener('click',function(){
    if(!confirm('Remove every rule this lock has written?\n\nOnly rules written by the Country Login Lock are touched — blocks made by you, by lfd or by anything else are left alone.')) return;
    var fd=new URLSearchParams(); fd.set('fw_action','gl_unblock');
    post(fd,function(j){show('<b>'+esc((j&&j.msg)||'done')+'</b>'); setTimeout(function(){location.reload();},900);});
  });

  document.addEventListener('click',function(e){
    var u=e.target.closest&&e.target.closest('.glUn'); if(!u) return;
    var fd=new URLSearchParams(); fd.set('fw_action','gl_unblock'); fd.set('ip',u.getAttribute('data-ip'));
    u.disabled=true; post(fd,function(j){show('<b>'+esc((j&&j.msg)||'done')+'</b>'); setTimeout(function(){location.reload();},700);});
  });
})();
</script>
<script>
/* Foreign sign-in report + bulk password reset.
   The new passwords arrive once, in the reset response. They are shown and offered as a download here and then
   they are gone — nothing on the server can produce them again, which is the point. */
(function(){
  var out=document.getElementById('grOut'); if(!out) return;
  function esc(x){return String(x==null?'':x).replace(/[<>&"]/g,function(c){return {'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;'}[c];});}
  function post(fd,cb){fd.set('smpro_csrf',FW_CSRF);
    fetch('index.cgi?page=firewall-status',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString()})
      .then(function(r){return r.json();}).then(cb).catch(function(){cb({ok:false,msg:'Request failed.'});});}
  function when(ts){ if(!ts) return '\u2014'; try{ return new Date(ts*1000).toLocaleString('en-GB',{dateStyle:'medium',timeStyle:'short'}); }catch(e){ return String(ts); } }

  var GR_REPEAT=<?= json_encode((function () { $c = function_exists('smpro_ntf_load') ? smpro_ntf_load() : []; return ['foreign_login' => !empty($c['types']['foreign_login']['only_changes']), 'malware_active' => !empty($c['types']['malware_active']['only_changes'])]; })()) ?>;
  var NTF_CSRF2=<?= json_encode(smpro_csrf_generate('ntf_act')) ?>;
  document.getElementById('grScan').addEventListener('click',function(){
    var b=this, ot=b.innerHTML; b.disabled=true; b.innerHTML='Building\u2026';
    out.hidden=false; out.innerHTML='<span class="meta">Reading the login log and placing every address\u2026</span>';
    var LAST_REPORT=null;
    var fd=new URLSearchParams(); fd.set('fw_action','gr_scan'); fd.set('days',document.getElementById('grDays').value);
    post(fd,function(j){
      b.disabled=false; b.innerHTML=ot;
      if(!j){out.innerHTML='<b style="color:var(--dang)">Request failed.</b>';return;}
      if(!j.ok){out.innerHTML='<b style="color:var(--dang)">'+esc(j.msg||'Could not build the report.')+'</b>';return;}
      var A=j.accounts||[];
      // What the scan could and could not see, stated before anything else. A list that is short because a
      // source could not run must never look like a list that is short because little was found.
      var h='<div class="meta">Allowed: <b>'+esc((j.allowed||[]).join(', ')||'(none)')+'</b> &middot; '
           +(j.scanned||0)+' sign-in event(s) read over '+(j.days||0)+' day(s)'
           +(j.unknown_cc?' &middot; '+j.unknown_cc+' address(es) could not be placed and were left alone':'')+'</div>';
      var S=j.sources||{}, blind=[];
      Object.keys(S).forEach(function(k){ if(S[k]&&!S[k].ok&&S[k].msg) blind.push(esc(S[k].msg)); });
      if(blind.length) h+='<div class="meta" style="margin-top:6px;color:var(--dang)"><b>&#9888;&#65039; Partial &mdash; '
           +blind.length+' source could not be consulted.</b> '+blind.join(' ')+'</div>';

      if(!A.length){
        out.innerHTML=h+'<div style="margin-top:8px">'+(blind.length
          ? '<b style="color:var(--dang)">Nothing to show &mdash; but a check above could not run, so this is NOT an all-clear.</b>'
          : '<b style="color:#059669">No account shows evidence of being under someone else&rsquo;s control.</b>')+'</div>';
        return;
      }

      var nLive=0, nIn=0; A.forEach(function(a){ if((a.live||0)>0) nLive++; else if(a.severity==='compromised') nIn++; });
      LAST_REPORT=j;
      // class of each row: malware on disk first, then an accepted foreign password, then attempts only
      A.forEach(function(a,i){ a._i=i; a._cls=(a.live||0)>0?'live':(a.severity==='compromised'?'in':'tries'); a._rank=a._cls==='live'?0:(a._cls==='in'?1:2); });
      h+='<div style="margin:10px 0 4px"><b>'+A.length+' account(s) with evidence</b>'
        +(j.counter_since?' <span class="meta">&middot; counting since '+esc(when(j.counter_since))+'</span>':'')
        +(nLive?' &middot; <b style="color:var(--dang)">'+nLive+' still carrying malware on disk</b>':'')
        +(nIn?' &middot; <b style="color:var(--dang)">'+nIn+' signed in from outside</b>':'')
        +' &mdash; tick the ones to reset</div>';
      h+='<div class="gr-tools gr-tools2">'
        +'<span class="gr-chips"><button type="button" class="gr-chip on" data-f="">all <b>'+A.length+'</b></button>'
        +'<button type="button" class="gr-chip" data-f="live" style="color:var(--dang)">&#9888; malware on disk <b>'+nLive+'</b></button>'
        +'<button type="button" class="gr-chip" data-f="in">signed in from outside <b>'+nIn+'</b></button>'
        +'<button type="button" class="gr-chip" data-f="tries">attempts only <b>'+(A.length-nLive-nIn)+'</b></button></span>'
        +'<input type="search" id="grFind" class="tp-in" placeholder="account or country\u2026" style="max-width:200px">'
        +'<select id="grSort" class="tp-sel"><option value="rank">worst first</option><option value="last">latest evidence</option><option value="ok">most accepted</option><option value="failed">most failed</option><option value="user">account A\u2013Z</option></select>'
        +'<select id="grPer" class="tp-sel"><option value="50">50 / page</option><option value="100">100 / page</option><option value="250">250 / page</option></select>'
        +'<span class="meta" id="grInfo"></span>'
        +'<span style="margin-left:auto"><button type="button" class="tp-btn ui-sm" id="grPrev">&#8249;</button> <span id="grPg" class="mono"></span> <button type="button" class="tp-btn ui-sm" id="grNext">&#8250;</button></span></div>';
      h+='<div style="overflow-x:auto"><table class="smpro-table gr-tbl"><thead><tr><th style="width:28px"><input type="checkbox" id="grAll" title="tick every account that matches the filter (all pages)"></th>'
        +'<th style="width:30%">Account</th><th>Evidence</th><th style="width:120px;text-align:right">Last seen</th></tr></thead><tbody id="grBody"></tbody></table></div>';
      h+='<div style="margin-top:12px;display:flex;gap:10px;align-items:center;flex-wrap:wrap">'
        +'<input type="text" id="grReason" class="tp-in" style="flex:1;min-width:260px" maxlength="200" placeholder="Why are these being reset? (kept in the record, without the password)">'
        +'<label class="meta" style="display:flex;gap:6px;align-items:center" title="Off: each ticked name changes only itself - a ticked mailbox changes that mailbox, a ticked account changes the account password. On: every mailbox of each ticked ACCOUNT gets a new password too (never the siblings of a ticked mailbox)."><input type="checkbox" id="grAllBoxes"> also every mailbox of the ticked accounts</label>'
        +'<button class="tp-btn danger" id="grReset" type="button">&#128273; Reset the ticked passwords <span id="grTickN" class="mono"></span></button>'
        +'<button class="tp-btn" id="grCounter" type="button" title="Archives this report to the reports store, then counts from now. The logs are not touched.">&#128451; Archive &amp; reset the counter</button></div>'
        +'<div class="meta" style="margin-top:6px">The new passwords are shown <b>once</b> and offered as a download. '
        +'They are not stored on this server and cannot be shown again &mdash; a lost export means resetting again, which is '
        +'the right trade against a file of working passwords sitting on the disk. '
        +'<b>Reset one account first</b> to confirm the change works on this server before doing the rest.</div>';
      h+='<div class="meta" style="margin-top:8px">The alerts this report feeds: '
        +'<span class="gr-rep" data-type="foreign_login">Foreign successful login: <button type="button" class="tp-btn ui-sm grRepBtn">\u2026</button></span> &nbsp; '
        +'<span class="gr-rep" data-type="malware_active">Active malware: <button type="button" class="tp-btn ui-sm grRepBtn">\u2026</button></span>'
        +' <span title="Only on change: an unchanged report is not sent again every remind window; a new account, address or finding sends it at once.">&#9432;</span></div>';
      out.innerHTML=h;

      // ---- selection lives in a set keyed by account, so it survives filtering and paging ----
      var picked={}; A.forEach(function(a){ if(a.severity==='compromised') picked[a.user]=true; }); window.GR_PICKED=picked; window.GR_ALL=A.map(function(a){return a.user;});
      var F='', Q='', SORT='rank', PER=50, page=0, view=[];
      function matches(a){ if(F&&a._cls!==F) return false; if(!Q) return true; var s=(a.user+' '+Object.keys(a.ccs_ok||{}).join(' ')+' '+Object.keys(a.ccs_failed||{}).join(' ')+' '+(a.why||'')).toLowerCase(); return s.indexOf(Q)!==-1; }
      function cmp(x,y){ if(SORT==='user') return x.user<y.user?-1:(x.user>y.user?1:0); if(SORT==='last') return (y.last||0)-(x.last||0); if(SORT==='ok') return (y.ok||0)-(x.ok||0)||(y.last||0)-(x.last||0); if(SORT==='failed') return (y.failed||0)-(x.failed||0)||(y.last||0)-(x.last||0); return x._rank-y._rank||(y.last||0)-(x.last||0); }
      function ccList(obj, max){ var ks=Object.keys(obj||{}).sort(function(x,y){return (obj[y]||0)-(obj[x]||0);}); var shown=ks.slice(0,max).map(function(k){return esc(k)+' <span class="n">'+obj[k]+'</span>';}).join(', '); var more=ks.length-max; return shown+(more>0?' <span class="meta" title="'+esc(ks.slice(max).map(function(k){return k+' ('+obj[k]+')';}).join(', '))+'">+'+more+' more</span>':''); }
      function whenShort(ts){ if(!ts) return '\u2014'; var d=new Date(ts*1000), now=new Date(); var opt=(d.getFullYear()===now.getFullYear())?{day:'numeric',month:'short',hour:'2-digit',minute:'2-digit'}:{day:'numeric',month:'short',year:'numeric'}; try{ return d.toLocaleString('en-GB',opt); }catch(e){ return String(ts); } }
      function rowHtml(a){
        var chip=a._cls==='live' ? '<span class="gr-chipx dang" title="malware is still on disk in this account">LIVE</span>'
                : (a._cls==='in' ? '<span class="gr-chipx dang" title="a correct password was accepted from a country outside the list">IN</span>' : '<span class="gr-chipx muted">attempts</span>');
        var ev=[];
        if((a.live||0)>0) ev.push('<div class="gr-ev dang">&#9888; '+a.live+' malware file'+(a.live>1?'s':'')+' still on disk</div>');
        else if(/malware/i.test(a.why||'') && a._cls!=='in') ev.push('<div class="gr-ev">'+esc(a.why)+'</div>');
        if(a.ok) ev.push('<div class="gr-ev dang"><b>'+a.ok+' accepted</b> from '+ccList(a.ccs_ok,4)+'</div>');
        if(a.failed) ev.push('<div class="gr-ev muted">'+a.failed+' failed from '+ccList(a.ccs_failed,4)+'</div>');
        if(!ev.length) ev.push('<div class="gr-ev muted">'+esc(a.why||'')+'</div>');
        return '<tr class="gr-'+a._cls+'"><td><input type="checkbox" class="grPick" value="'+esc(a.user)+'"'+(picked[a.user]?' checked':'')+'></td>'
          +'<td class="gr-acct"><b>'+esc(a.user)+'</b> '+chip+'</td>'
          +'<td>'+ev.join('')+'</td>'
          +'<td class="gr-when">'+esc(whenShort(a.last))+'</td></tr>';
      }
      function draw(){
        view=A.filter(matches).sort(cmp); var pages=Math.max(1,Math.ceil(view.length/PER)); if(page>=pages) page=pages-1;
        var tb=document.getElementById('grBody'); tb.innerHTML=view.slice(page*PER,(page+1)*PER).map(rowHtml).join('')||'<tr><td colspan="7" class="meta">No account matches.</td></tr>';
        var a=view.length?page*PER+1:0,b=Math.min((page+1)*PER,view.length);
        document.getElementById('grInfo').textContent=(a?'showing '+a+'\u2013'+b+' of ':'')+view.length+' matching';
        document.getElementById('grPg').textContent=(page+1)+' / '+pages;
        var n=Object.keys(picked).filter(function(u){return picked[u];}).length; document.getElementById('grTickN').textContent=n?'('+n+')':'';
        var all=document.getElementById('grAll'); if(all) all.checked=view.length>0&&view.every(function(x){return picked[x.user];});
      }
      Array.prototype.forEach.call(document.querySelectorAll('.gr-chip'),function(b){ b.addEventListener('click',function(){ Array.prototype.forEach.call(document.querySelectorAll('.gr-chip'),function(x){x.classList.remove('on');}); b.classList.add('on'); F=b.getAttribute('data-f'); page=0; draw(); }); });
      document.getElementById('grFind').addEventListener('input',function(){ Q=this.value.trim().toLowerCase(); page=0; draw(); });
      document.getElementById('grSort').addEventListener('change',function(){ SORT=this.value; page=0; draw(); });
      document.getElementById('grPer').addEventListener('change',function(){ PER=parseInt(this.value,10)||50; page=0; draw(); });
      document.getElementById('grPrev').addEventListener('click',function(){ if(page>0){page--;draw();} });
      document.getElementById('grNext').addEventListener('click',function(){ page++; draw(); });
      document.getElementById('grBody').addEventListener('change',function(e){ if(e.target.classList.contains('grPick')){ picked[e.target.value]=e.target.checked; draw(); } });
      var all=document.getElementById('grAll');
      if(all) all.addEventListener('change',function(){ view.forEach(function(x){ picked[x.user]=all.checked; }); draw(); });
      // the "repeat" state of the alerts this report feeds, read and toggled through the Notifications endpoint
      Array.prototype.forEach.call(document.querySelectorAll('.gr-rep'),function(sp){
        var type=sp.getAttribute('data-type'), btn=sp.querySelector('.grRepBtn'), on=!!(GR_REPEAT[type]);
        function paint(){ btn.innerHTML=on?'&#128276; only on change':'&#128257; repeats daily'; btn.style.borderColor=on?'var(--brand)':''; btn.style.color=on?'var(--brand)':''; }
        paint();
        btn.addEventListener('click',function(){ var fd=new URLSearchParams(); fd.set('ntf_action','only_changes'); fd.set('smpro_csrf',NTF_CSRF2); fd.set('type',type); fd.set('on',on?'0':'1'); btn.disabled=true;
          fetch('index.cgi?page=notifications',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString()}).then(function(r){return r.json();}).then(function(r){ btn.disabled=false; if(r&&r.ok){ on=!on; paint(); } else alert((r&&r.msg)||'Could not change it.'); }).catch(function(){ btn.disabled=false; }); });
      });
      draw();

      document.getElementById('grReset').addEventListener('click',doReset);
      document.getElementById('grCounter').addEventListener('click',function(){
        if(!confirm('Archive this report and reset the counter?\n\nThe report as it stands is saved to the reports store (JSON + text) and can be opened later. From now on the report counts only new sign-ins. No log file is deleted or changed.')) return;
        var b=this, ot=b.innerHTML; b.disabled=true; b.innerHTML='Archiving\u2026';
        var fd=new URLSearchParams(); fd.set('fw_action','gr_counter_reset'); fd.set('report',JSON.stringify(LAST_REPORT||{}));
        post(fd,function(r){ b.disabled=false; b.innerHTML=ot; out.innerHTML='<div style="padding:10px 12px;border-radius:9px;background:rgba(127,127,127,.07)"><b style="color:'+(r&&r.ok?'#059669':'var(--dang)')+'">'+esc((r&&r.msg)||'Failed')+'</b></div>'+out.innerHTML; if(r&&r.ok) setTimeout(function(){location.reload();},1500); });
      });
    });
  });

  function doReset(){
    var users=(window.GR_PICKED?Object.keys(window.GR_PICKED).filter(function(u){return window.GR_PICKED[u];}):Array.prototype.slice.call(document.querySelectorAll('.grPick:checked')).map(function(c){return c.value;}));
    var reason=(document.getElementById('grReason').value||'').trim();
    if(!users.length){ alert('Tick at least one account.'); return; }
    if(!reason){ alert('Give a reason. It is what the record is for — the password itself is never kept, so the reason is all that explains this later.'); document.getElementById('grReason').focus(); return; }
    /* The count of what is being reset is stated against the count of what is LISTED. An operator ticked the
       pre-ticked rows, reset 8 accounts, believed the whole report had been dealt with, and kept receiving it -
       correctly, because twelve other accounts in the same list still had their original passwords. The dialog
       now says what is being left alone, by name where the list is short. */
    var all=(window.GR_ALL||Array.prototype.slice.call(document.querySelectorAll('.grPick')).map(function(c){return c.value;}));
    var skipped=all.filter(function(u){return users.indexOf(u)<0;});
    var warn='';
    /* Every one of these strings is on ONE line. A real newline inside a JS string literal is a SyntaxError,
       and a SyntaxError throws away the whole <script> block - every button in it silently stops working.
       Writing this message across lines is exactly how that happens, and r23 caught it here. */
    if(skipped.length) warn='\n\nNOT being reset ('+skipped.length+' of '+all.length+' listed): '+(skipped.length<=12?skipped.join(', '):skipped.slice(0,12).join(', ')+' and '+(skipped.length-12)+' more')+'\nTheir passwords stay as they are, and this report will keep naming them.';
    var allBoxes=!!(document.getElementById('grAllBoxes')&&document.getElementById('grAllBoxes').checked);
    var boxes=users.filter(function(u){return u.indexOf('@')>=0;}), accts=users.filter(function(u){return u.indexOf('@')<0;});
    var exact='\n\nExactly these change, nothing else:'+(accts.length?'\n  accounts (account password only): '+accts.join(', '):'')+(boxes.length?'\n  mailboxes (that mailbox only): '+boxes.join(', '):'')+(allBoxes&&accts.length?'\n  PLUS every mailbox on the ticked accounts (you chose it)':'');
    if(!confirm('Reset the password for '+users.length+' of '+all.length+' listed identit'+(users.length===1?'y':'ies')+'?'+exact+warn+'\n\nA ticked mailbox does not change its account, and a ticked account does not change its mailboxes unless the box below the reason is ticked.\n\nEach owner is locked out until you send them the new one. The new passwords are shown ONCE and are never recoverable.')) return;
    var b=document.getElementById('grReset'), ot=b.innerHTML; b.disabled=true; b.innerHTML='Resetting\u2026';
    var fd=new URLSearchParams(); fd.set('fw_action','gr_reset'); fd.set('reason',reason); fd.set('all_mailboxes',allBoxes?'1':'0');
    users.forEach(function(u){ fd.append('users[]',u); });
    post(fd,function(j){
      b.disabled=false; b.innerHTML=ot;
      if(!j){ alert('Request failed.'); return; }
      var h='<div style="padding:12px 14px;border-radius:10px;border:2px solid #dc2626;background:rgba(220,38,38,.06)">'
           +'<b style="font-size:14px">'+esc(j.msg||'')+'</b>'
           +'<div class="meta" style="margin:6px 0 10px"><b>This is the only copy.</b> Save it now — the server did not keep these.</div>';
      if((j.secrets||[]).length){
        h+='<div style="overflow-x:auto"><table class="smpro-table"><thead><tr><th>Account</th><th>New password</th></tr></thead><tbody>';
        j.secrets.forEach(function(s){ h+='<tr><td><b>'+esc(s.user)+'</b></td><td class="ipmono" style="user-select:all">'+esc(s.password)+'</td></tr>'; });
        h+='</tbody></table></div>';
        h+='<div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap">'
          +'<button class="tp-btn primary" id="grDl" type="button">&#11015; Download the export</button>'
          +'<button class="tp-btn" id="grCopy" type="button">Copy all</button></div>';
      }
      // A mailbox is reset through its owner. Say which identity led to which account, or the operator sees an
      // account they did not tick and a mailbox they did tick missing from the list.
      if((j.done||[]).length){
        h+='<div style="margin-top:10px"><b>Changed ('+j.done.length+'):</b><div class="meta">'+j.done.map(esc).join(', ')+'</div></div>';
      }
      if((j.failed||[]).length){
        h+='<div style="margin-top:10px"><b>Not changed:</b><div class="meta">'
          +j.failed.map(function(f){return esc(f.user)+' — '+esc(f.msg);}).join('<br>')+'</div></div>';
      }
      h+='</div>';
      out.innerHTML=h+out.innerHTML;

      var dl=document.getElementById('grDl');
      if(dl) dl.addEventListener('click',function(){
        var blob=new Blob([j.export||''],{type:'text/csv'});
        var a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download=j.filename||'passwords.csv';
        document.body.appendChild(a); a.click(); document.body.removeChild(a);
        setTimeout(function(){ URL.revokeObjectURL(a.href); },2000);
      });
      var cp=document.getElementById('grCopy');
      if(cp) cp.addEventListener('click',function(){
        try{ navigator.clipboard.writeText(j.export||''); cp.textContent='Copied'; }catch(e){ alert('Copy failed — use the download.'); }
      });
    });
  }
})();
</script>
<?php
smpro_layout_footer();
