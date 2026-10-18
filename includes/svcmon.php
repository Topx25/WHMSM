<?php
/**
 * includes/svcmon.php — Service catalog + status + controls + the background SERVICE MONITOR.
 * Boot-loaded so the cron worker (bin/svcmon.php), the Dashboard cards, and the cPanel Services module all
 * share ONE service catalog and one control path. The monitor (opt-in) watches the admin's chosen services and,
 * if one stops, restarts it automatically and/or sends a notification through the existing Notifications channels.
 * Controls are POST+CSRF+root+confirm-gated in the module; the cron path is root already.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

if (!defined('SMPRO_SVCMON_CFG'))   define('SMPRO_SVCMON_CFG',   SMPRO_VARLIB . '/svcmon.json');        // {enabled,monitor[],autorestart,notify,recovery}
if (!defined('SMPRO_SVCMON_STATE')) define('SMPRO_SVCMON_STATE', SMPRO_VARLIB . '/svcmon_state.json');  // per-service down/restart bookkeeping
if (!defined('SMPRO_SVC_SNAP'))     define('SMPRO_SVC_SNAP',     SMPRO_VARLIB . '/svc_scan.json');       // cached scan snapshot (cheap dashboard reads)
if (!defined('SMPRO_SVC_IGNORE'))   define('SMPRO_SVC_IGNORE',   SMPRO_VARLIB . '/svc_ignore.json');     // {key: ts} — services the admin muted (never flagged down, never alerted)

/* ============================ ignore / mute list ============================
 * When the admin clicks "Ignore" on a stopped service, its key is stored here. An ignored service is not counted
 * as "down", is dropped from the Stopped-services drill-in, and is skipped by the monitor (no auto-restart, no
 * notification) — so a service that is intentionally off stops nagging. Un-ignore removes it and it reappears. */
function smpro_svc_ignored() {
    $d = @is_file(SMPRO_SVC_IGNORE) ? json_decode((string)@file_get_contents(SMPRO_SVC_IGNORE), true) : null;
    return is_array($d) ? $d : [];
}
function smpro_svc_set_ignore($key, $on) {
    $key = preg_replace('/[^a-z0-9_]/', '', (string)$key);
    if ($key === '' || !isset(smpro_svc_registry()[$key])) return false;
    $ig = smpro_svc_ignored();
    if ($on) $ig[$key] = time(); else unset($ig[$key]);
    $f = SMPRO_SVC_IGNORE; $dir = dirname($f); if (!is_dir($dir)) @mkdir($dir, 0700, true);
    $t = $f . '.tmp'; if (@file_put_contents($t, json_encode($ig), LOCK_EX) === false) return false;
    @chmod($t, 0600); return @rename($t, $f);
}
/** Pick the ONE contextual primary action for a stopped service: failed → Fix, disabled → Enable, else → Start. */
function smpro_svc_fix_action($row, $reg = null) {
    $reg = $reg ?? (smpro_svc_registry()[$row['key']] ?? []);
    $state = (string)($row['state'] ?? '');
    $en    = strtolower((string)($row['enabled'] ?? ''));
    $hasScript = smpro_svc_restartsrv($reg) !== '';
    if ($state === 'failed') return ['a' => 'restart', 'label' => 'Fix',    'icon' => "\xF0\x9F\x94\xA7", 'cls' => 'restart']; // 🔧 failed → Fix
    if ($en === 'disabled')  return ['a' => 'enable',  'label' => 'Enable', 'icon' => "\xE2\x96\xB6",     'cls' => 'enable'];  // ▶ disabled → Enable (+start)
    return ['a' => $hasScript ? 'restart' : 'start', 'label' => 'Start', 'icon' => "\xE2\x9A\xA1", 'cls' => 'start'];          // ⚡ stopped → Start
}

/* ============================ catalog + status (shared) ============================ */
function smpro_svc_run($cmd, $t = null) { return smpro_run((string)$cmd, (int)($t ?: SMPRO_TIMEOUT_QUICK)); }
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

/** Service names cPanel records as DISABLED in /etc/chkserv.d/chkservd.conf ("name:0").
 *  That file is cPanel's own enabled/disabled registry (WHM › Service Manager writes it), so it is the
 *  portable way to tell "the admin turned this off on this server" from "it crashed" — on ANY cPanel box,
 *  whatever role that box plays. Cached per request; absent file simply yields no disabled names. */
function smpro_svc_chkservd_disabled(): array {
    static $c = null;
    if ($c !== null) return $c;
    $c = [];
    foreach (@file('/etc/chkserv.d/chkservd.conf', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $ln) {
        $ln = trim($ln);
        if ($ln === '' || $ln[0] === '#') continue;
        if (preg_match('/^([A-Za-z0-9._-]+)\s*:\s*0\s*$/', $ln, $m)) $c[] = strtolower($m[1]);
    }
    return $c;
}

function smpro_svc_status($s) {
    $units = $s['units'] ?? []; $cmds = $s['commands'] ?? [];
    $matched = ''; $active = false; $enabled = 'n/a'; $state = '';
    foreach ($units as $u) {
        $st = trim(smpro_svc_run('systemctl is-active ' . escapeshellarg($u), 8));
        // activating / reloading / deactivating are TRANSITIONS, not outages: a MariaDB in crash recovery sits in
        // "activating" for minutes, and restarting it there sends recovery back to zero - four times an hour.
        if ($st === 'active' || in_array($st, ['activating', 'reloading', 'deactivating'], true)) { $active = true; $matched = $u; $enabled = trim(smpro_svc_run('systemctl is-enabled ' . escapeshellarg($u), 8)); $state = $st; break; }
        if ($matched === '' && in_array($st, ['inactive', 'failed'], true)) { $matched = $u; $state = $st; $enabled = trim(smpro_svc_run('systemctl is-enabled ' . escapeshellarg($u), 8)); }
    }
    $cmdPresent = false; foreach ($cmds as $c) if (smpro_svc_cmd_exists($c)) { $cmdPresent = true; break; }
    if (!empty($s['modsec'])) { $cmdPresent = trim(smpro_svc_run("grep -rliE 'modsec' /etc/apache2 /usr/local/apache/conf /etc/httpd 2>/dev/null | head -1")) !== ''; $active = $cmdPresent; }
    $rs = smpro_svc_restartsrv($s);
    $installed = $matched !== '' || $cmdPresent || $rs !== '';
    if (!empty($s['product']) || empty($units)) { $active = $active || $cmdPresent; $state = $active ? 'present' : 'absent'; $enabled = $enabled === 'n/a' && $active ? 'product' : $enabled; }
    // ADMINISTRATIVELY DISABLED — the service is installed and healthy but its own tooling has been told to
    // stand down, so systemd can never start it. CSF writes /etc/csf/csf.disable; `lfd` then prints
    // "csf and lfd have been disabled" and exits 0, and because the unit is Type=forking systemd reports
    // "failed (Result: protocol)". Restarting is guaranteed to fail, so the UI must say WHY instead of
    // offering an action that cannot work and then showing a scary systemd error.
    // Two sources, in order of specificity. Both are GENERAL mechanisms present on any cPanel server —
    // nothing here is tied to one host's setup.
    $offReason = '';
    // 1. cPanel's own service registry: /etc/chkserv.d/chkservd.conf lists "<service>:1|0". A 0 means the
    //    admin turned it off in WHM > Service Manager, which is a deliberate choice on THIS server — a
    //    mail-only box legitimately runs no httpd, a DNS-only box no exim. Reporting that as a fault
    //    would make the page cry wolf on every specialised server.
    $chk = smpro_svc_chkservd_disabled();
    foreach (array_merge($units, $s['commands'] ?? []) as $n) {
        if (in_array(strtolower($n), $chk, true)) {
            $offReason = 'Turned off in WHM &rsaquo; Service Manager (chkservd lists it as disabled). Re-enable it there if this server should run it.';
            break;
        }
    }
    // 2. CSF's own kill-switch is more specific than the registry entry, so it wins the message.
    if (in_array('lfd', $units, true) && @is_file('/etc/csf/csf.disable')) {
        $offReason = 'CSF is disabled (/etc/csf/csf.disable exists). Re-enable it with `csf -e`; until then lfd cannot start.';
    }
    return ['installed' => $installed, 'active' => $active, 'enabled' => $enabled === '' ? 'n/a' : $enabled, 'unit' => $matched ?: ($units[0] ?? '—'), 'state' => $state ?: ($active ? 'active' : 'inactive'), 'off_reason' => $offReason];
}

/** State label + visual level + recommendation. */
function smpro_svc_assess($s, $st) {
    $crit = !empty($s['critical']);
    if ($st['active']) return ['ACTIVE', 'good', 'good', 'Running normally.' . ($crit ? ' Keep this core service enabled.' : '')];
    // Turned off through its own tooling, not broken: a restart cannot succeed, so say what to do instead.
    if (!empty($st['off_reason'])) return ['DISABLED', 'warn', 'warning', $st['off_reason']];
    if ($st['installed']) {
        if ($crit) return ['INACTIVE', 'danger', 'danger', 'This important service is installed but not running — start it.'];
        return ['OK DISABLED', 'ok', 'info', 'Installed but inactive. Fine if intentionally disabled on this server.'];
    }
    if ($crit) return ['MISSING', 'danger', 'danger', 'Recommended: ' . ($s['install'] ?? 'install this service') . '. Important on cPanel servers.'];
    return ['NOT INSTALLED', 'muted', 'info', 'Optional. Install only if you need it: ' . ($s['install'] ?? '—') . '.'];
}

/** A service is "runtime" (has a start/stop control here) when it is not a detected-only product and has a unit or restart script. */
function smpro_svc_is_runtime($s) { return empty($s['product']) && (!empty($s['units']) || smpro_svc_restartsrv($s) !== ''); }
/** Keys the monitor is allowed to watch/restart: runtime services with a systemd unit. */
function smpro_svc_monitorable() {
    $out = []; foreach (smpro_svc_registry() as $k => $s) if (smpro_svc_is_runtime($s) && !empty($s['units'])) $out[] = $k; return $out;
}
/** Sensible default watch-set: the CRITICAL runtime services. */
function smpro_svcmon_default_monitor() {
    $out = []; foreach (smpro_svc_registry() as $k => $s) if (smpro_svc_is_runtime($s) && !empty($s['units']) && !empty($s['critical'])) $out[] = $k; return $out;
}
/** Is a service RECOMMENDED to monitor/auto-restart? (the critical always-on core services). */
function smpro_svc_monitor_recommended($key) { $s = smpro_svc_registry()[$key] ?? []; return !empty($s['critical']); }
/** A caution string for services that are NOT recommended to blindly monitor/auto-restart — so the admin avoids
 *  turning auto-restart into a fight against an intentionally-disabled or optional service. '' = no caution. */
function smpro_svc_monitor_caution($key, $row = null) {
    $s = smpro_svc_registry()[$key] ?? [];
    static $notes = [
        'nginx'     => 'Optional — watch only if you actually run Nginx as a reverse proxy.',
        'firewalld' => 'On cPanel, CSF/LFD is usually the firewall — watch firewalld only if it is your chosen firewall (running both can conflict).',
        'dns'       => 'Only if this server runs DNS (named / PowerDNS).',
        'cron'      => 'Optional — cron rarely stops on its own.',
    ];
    if (!empty($s['critical'])) return '';                                              // core service → always fine to watch
    if (isset($notes[$key])) return $notes[$key];
    // installed but currently stopped + non-critical → likely disabled on purpose
    if (is_array($row) && !empty($row['installed']) && empty($row['active']))
        return 'Currently stopped — if you disabled it on purpose, auto-restart will keep starting it. Watch only if it should always run.';
    return 'Optional service — watch only if you rely on it.';
}

/** Full scan of every catalog service → normalized rows (used by the module, dashboard, and monitor). */
function smpro_svc_scan() {
    $rows = [];
    $ignored = smpro_svc_ignored();
    foreach (smpro_svc_registry() as $key => $s) {
        $st = smpro_svc_status($s); $a = smpro_svc_assess($s, $st); $runtime = smpro_svc_is_runtime($s);
        $isIg = isset($ignored[$key]);
        $rows[$key] = [
            'key'=>$key, 'label'=>$s['label'], 'category'=>$s['category'], 'critical'=>!empty($s['critical']),
            'runtime'=>$runtime, 'installed'=>$st['installed'], 'active'=>$st['active'], 'state'=>$st['state'],
            'enabled'=>$st['enabled'], 'unit'=>$st['unit'], 'state_label'=>$a[0], 'cls'=>$a[1], 'ignored'=>$isIg,
            'off_reason'=>$st['off_reason'] ?? '',
            // "down" = a controllable service that is installed but not running (so Start/Fix makes sense). Muted → not down.
            // An ADMINISTRATIVELY DISABLED service is not down: it was switched off on purpose, starting it is
            // refused, and counting it here would put it in the "problems" list and hand it to the auto-restart
            // monitor to retry forever on every server that legitimately does not run it.
            'down'=>($runtime && $st['installed'] && !$st['active'] && !empty($s['units']) && !$isIg && empty($st['off_reason'])),
        ];
    }
    return $rows;
}
/** Cached scan for cheap reads (dashboard). Returns [rows, ts, cached]. Re-scans when the snapshot is older than $ttl. */
function smpro_svc_scan_cached($ttl = 45) {
    if (@is_file(SMPRO_SVC_SNAP)) {
        $d = json_decode((string)@file_get_contents(SMPRO_SVC_SNAP), true);
        if (is_array($d) && !empty($d['rows']) && (time() - (int)($d['ts'] ?? 0)) < $ttl) return [$d['rows'], (int)$d['ts'], true];
    }
    $rows = smpro_svc_scan();
    smpro_svc_snap_write($rows);
    return [$rows, time(), false];
}
function smpro_svc_snap_write($rows) {
    $dir = dirname(SMPRO_SVC_SNAP); if (!is_dir($dir)) @mkdir($dir, 0700, true);
    $t = SMPRO_SVC_SNAP . '.tmp';
    if (@file_put_contents($t, json_encode(['rows'=>$rows, 'ts'=>time()]), LOCK_EX) !== false) { @chmod($t, 0600); @rename($t, SMPRO_SVC_SNAP); }
}

/* ============================ control (shared by module POST + monitor) ============================ */
/** Start / restart / stop a service. Returns ['ok','active','state_label','cls','msg']. Runs reset-failed first so a failed unit can recover. */
function smpro_svcmon_control($key, $action) {
    $action = preg_replace('/[^a-z]/', '', (string)$action);
    if (!in_array($action, ['restart','start','stop','enable'], true)) return ['ok'=>false,'msg'=>'bad action'];
    $reg = smpro_svc_registry(); $svc = $reg[$key] ?? null;
    if (!$svc) return ['ok'=>false,'msg'=>'unknown service'];
    if (!smpro_svc_is_runtime($svc)) return ['ok'=>false,'msg'=>'this product has no runtime control here'];
    if ($action === 'stop' && !empty($svc['no_stop'])) return ['ok'=>false,'msg'=>'refused: stopping this service here is blocked'];
    // Administratively disabled (e.g. CSF's csf.disable): starting can only fail — systemd would report an
    // opaque "Result: protocol" because lfd exits immediately. Explain the cause and the one-line fix instead
    // of running a doomed command and surfacing the daemon's own confusing failure.
    if (in_array($action, ['start','restart','enable'], true)) {
        $pre = smpro_svc_status($svc);
        // 'refused' tells the UI this was never attempted — so it reports the reason plainly instead of
        // framing a deliberate configuration state as a failed action.
        if (!empty($pre['off_reason'])) return ['ok'=>false, 'refused'=>true, 'msg'=>$pre['off_reason'], 'active'=>false];
    }
    $rs = smpro_svc_restartsrv($svc); $unit = $svc['units'][0] ?? '';
    if (in_array($action, ['start','restart','enable'], true) && $unit !== '') @shell_exec('timeout 10 systemctl reset-failed ' . escapeshellarg($unit) . ' 2>/dev/null');
    if ($action === 'enable')                    $cmd = ($unit !== '') ? 'systemctl enable --now ' . escapeshellarg($unit) : ($rs !== '' ? escapeshellarg($rs) : ''); // enable at boot + start now
    elseif ($action === 'restart' && $rs !== '') $cmd = escapeshellarg($rs);
    elseif ($unit !== '')                        $cmd = 'systemctl ' . $action . ' ' . escapeshellarg($unit);
    else                                         $cmd = '';
    if ($cmd === '') return ['ok'=>false,'msg'=>'no control method'];
    $out = smpro_svc_run($cmd, 45); sleep(1);
    $st = smpro_svc_status($svc);
    $ok = $action === 'stop' ? !$st['active'] : $st['active'];
    $a = smpro_svc_assess($svc, $st);
    return ['ok'=>$ok, 'active'=>$st['active'], 'state_label'=>$a[0], 'cls'=>$a[1], 'msg'=>trim(mb_substr($out, 0, 200))];
}

/* ============================ uninstall an installed add-on (the plugin DOES it) ============================
 * The admin asked SM Pro to actually REMOVE an add-on it installed (CSF, Imunify, …), not just print a command.
 * So this is a real engine: it runs an ORDERED set of removal strategies (vendor uninstaller → package manager →
 * network installer --uninstall) and stops as soon as the add-on is no longer detected, then ALWAYS runs a purge
 * pass to wipe leftover files / systemd units / iptables chains, and finally verifies. Everything is double-confirmed
 * in the UI + audited. Base-OS layers (CloudLinux) are still executed but flagged high-risk (a kernel swap needs a
 * reboot the plugin can't do in one request). Commands are FIXED here (no user input reaches the shell). */
function smpro_svc_pm() { foreach (['dnf', 'yum', 'apt-get'] as $p) if (smpro_svc_cmd_exists($p)) return $p; return ''; }
function smpro_svc_bash() { foreach (['/bin/bash', '/usr/bin/bash'] as $b) if (@is_executable($b)) return $b; $c = trim((string)@shell_exec('command -v bash 2>/dev/null')); return $c !== '' ? $c : 'sh'; }
/** UI plan: label + risk + one-line note (all items are auto-executed now; risk drives the confirmation strength). */
function smpro_svc_uninstall_plan($key) {
    $reg = smpro_svc_registry()[$key] ?? []; $label = $reg['label'] ?? $key;
    $high = ['cloudlinux'=>1, 'cagefs'=>1, 'lve_manager'=>1, 'mysql_governor'=>1];
    $notes = [
        'lfd'         => "Runs CSF's official uninstaller, else removes the package, then wipes /etc/csf, its units and its iptables chains and re-opens the INPUT policy so you are not left locked out.",
        'imunify'     => 'Runs the local Imunify uninstaller, else the package manager, else the official network uninstaller — then wipes its dirs, units and iptables chains.',
        'clamav'      => 'Removes the ClamAV package and its data.',
        'kernelcare'  => 'Removes the KernelCare package and its files.',
        'modsecurity' => 'Removes the EasyApache-4 ModSecurity module and rebuilds/reloads Apache.',
        'cloudlinux'  => 'Removes CageFS/LVE/Governor components. FULL CloudLinux removal also needs a reboot into a stock kernel — do that from your provider console afterwards.',
        'cagefs'      => 'Disables + removes CageFS for all users and the package.',
        'lve_manager' => 'Removes the LVE Manager package.',
        'mysql_governor'=>'Removes the MySQL Governor package.',
    ];
    return ['label'=>$label, 'risk'=>isset($high[$key]) ? 'high' : 'normal', 'note'=>$notes[$key] ?? 'Removes this add-on and cleans up its files.'];
}
/** Ordered removal strategies (run until the add-on is gone) + purge steps (always run). Each step: [name, bash, timeout]. */
function smpro_svc_uninstall_steps($key) {
    $pm = smpro_svc_pm(); $rm = $pm ? $pm . ' -y remove' : 'true';
    switch ($key) {
        case 'lfd': return ['verify'=>['cmds'=>['csf', 'lfd'], 'paths'=>['/etc/csf', '/usr/local/csf/bin/csf', '/usr/sbin/csf', '/etc/chkserv.d/lfd']], 'remove'=>[
                ['CSF official uninstaller', 'for u in /etc/csf/uninstall.sh /etc/csf/uninstall.cpanel.sh /etc/csf/uninstall.generic.sh /usr/local/csf/bin/uninstall.sh; do if [ -f "$u" ]; then sh "$u"; break; fi; done; true', 180],
                ['Package removal', ($pm ? $rm . ' cpanel-csf csf 2>/dev/null; true' : 'true'), 300],
            ], 'purge'=>[
                ['Stop lfd/csf', 'systemctl disable --now lfd 2>/dev/null; systemctl disable --now csf 2>/dev/null; systemctl stop lfd 2>/dev/null; pkill -x lfd 2>/dev/null; true', 40],
                ['Remove files + symlinks', 'rm -rf /etc/csf /usr/local/csf /var/lib/csf /var/lib/lfd 2>/dev/null; rm -f /etc/cron.d/csf* /etc/cron.d/lfd* /etc/logrotate.d/csf* 2>/dev/null; rm -f /usr/sbin/csf /usr/bin/csf /sbin/csf /usr/sbin/lfd /usr/bin/lfd /sbin/lfd 2>/dev/null; rm -f /etc/chkserv.d/lfd 2>/dev/null; true', 40],
                ['Remove units', 'rm -f /etc/systemd/system/lfd.service /etc/systemd/system/csf.service /usr/lib/systemd/system/lfd.service /usr/lib/systemd/system/csf.service /etc/init.d/lfd /etc/init.d/csf 2>/dev/null; systemctl daemon-reload 2>/dev/null; systemctl reset-failed lfd 2>/dev/null; systemctl reset-failed csf 2>/dev/null; true', 30],
                ['Flush CSF iptables chains + open policy', 'for c in $(iptables -S 2>/dev/null | sed -n "s/^-N //p" | grep -E "LOCALINPUT|LOCALOUTPUT|ALLOWIN|ALLOWOUT|DENYIN|DENYOUT|LOGDROPIN|LOGDROPOUT|INVALID|SPOOF"); do iptables -F "$c" 2>/dev/null; done; iptables -P INPUT ACCEPT 2>/dev/null; iptables -P OUTPUT ACCEPT 2>/dev/null; iptables -P FORWARD ACCEPT 2>/dev/null; true', 40],
            ]];
        case 'imunify': return ['verify'=>['cmds'=>['imunify360-agent', 'imunify-antivirus', 'imunifyav'], 'paths'=>['/etc/imunify360', '/usr/bin/imunify360-agent', '/opt/imunify360']], 'remove'=>[
                ['Local Imunify uninstaller', 'for u in /usr/share/imunify360/uninstall.sh /opt/imunify360/uninstall.sh; do if [ -f "$u" ]; then bash "$u"; break; fi; done; [ -f /usr/share/av-userside-plugin.sh ] && bash /usr/share/av-userside-plugin.sh --uninstall 2>/dev/null; true', 240],
                ['Package removal', ($pm ? $rm . ' imunify360-firewall imunify360 imunify-antivirus imunifyav imunify360-webshield imunify360-ossec 2>/dev/null; true' : 'true'), 300],
                ['Official network uninstaller', 'if command -v curl >/dev/null 2>&1; then d=' . escapeshellarg(SMPRO_VARLIB) . '; mkdir -p "$d" && chmod 700 "$d" && t=$(mktemp "$d/i360un.XXXXXX") && curl -fsSL --max-redirs 5 --max-time 60 -o "$t" https://repo.imunify360.cloudlinux.com/defence360/i360deploy.sh && bash "$t" --uninstall; rm -f "$t"; fi; true', 300],   // a private, root-only, unpredictable path: a file pre-planted in sticky /tmp by any account was executed by root
            ], 'purge'=>[
                ['Stop units', 'systemctl disable --now imunify360 2>/dev/null; systemctl disable --now imunify-antivirus 2>/dev/null; systemctl disable --now imunify360-webshield 2>/dev/null; true', 40],
                ['Remove files', 'rm -rf /etc/imunify360 /var/imunify360 /opt/imunify360 /usr/share/imunify360 /var/lib/imunify360 /var/log/imunify360* /etc/sysconfig/imunify360 2>/dev/null; true', 60],
                ['Flush Imunify iptables chains', 'for c in $(iptables -S 2>/dev/null | sed -n "s/^-N //p" | grep -i imunify); do iptables -F "$c" 2>/dev/null; done; true', 40],
            ]];
        case 'clamav': return ['remove'=>[
                ['Package removal', ($pm ? $rm . ' cpanel-clamav 2>/dev/null; true' : 'true'), 300],
            ], 'purge'=>[
                ['Stop + remove files', 'systemctl disable --now clamd@scan 2>/dev/null; rm -rf /var/lib/clamav /etc/clamd.d 2>/dev/null; true', 40],
            ]];
        case 'kernelcare': return ['remove'=>[
                ['Package removal', ($pm ? $rm . ' kernelcare 2>/dev/null; true' : 'true'), 300],
            ], 'purge'=>[
                ['Remove files', 'rm -rf /usr/lib64/kcare /etc/sysconfig/kcare /var/cache/kcare 2>/dev/null; rm -f /usr/bin/kcarectl 2>/dev/null; true', 30],
            ]];
        case 'modsecurity': return ['remove'=>[
                ['Remove EA4 module', ($pm ? $rm . ' ea-apache24-mod_security2 2>/dev/null; true' : 'true'), 300],
            ], 'purge'=>[
                ['Rebuild + reload Apache', '/usr/local/cpanel/scripts/rebuildhttpdconf 2>/dev/null; /usr/local/cpanel/scripts/restartsrv_httpd --graceful 2>/dev/null; true', 90],
            ]];
        case 'cagefs': return ['remove'=>[
                ['Disable + remove CageFS', '[ -x /usr/sbin/cagefsctl ] && (/usr/sbin/cagefsctl --disable-all 2>/dev/null; /usr/sbin/cagefsctl --remove-all 2>/dev/null); true', 300],
                ['Package removal', ($pm ? $rm . ' cagefs 2>/dev/null; true' : 'true'), 300],
            ], 'purge'=>[
                ['Remove files', 'rm -rf /usr/share/cagefs /var/cagefs /etc/cagefs 2>/dev/null; true', 40],
            ]];
        case 'lve_manager':    return ['remove'=>[['Package removal', ($pm ? $rm . ' lvemanager 2>/dev/null; true' : 'true'), 300]], 'purge'=>[]];
        case 'mysql_governor': return ['remove'=>[['Package removal', ($pm ? $rm . ' governor-mysql 2>/dev/null; true' : 'true'), 300]], 'purge'=>[]];
        case 'cloudlinux': return ['reboot'=>true, 'remove'=>[
                ['Remove CloudLinux components', ($pm ? $rm . ' cagefs lvemanager governor-mysql 2>/dev/null; true' : 'true'), 300],
            ], 'purge'=>[
                ['Note kernel', 'true', 5],
            ]];
        default: return null;
    }
}
/** Execute the uninstall for $key: run removal strategies until it's gone, then purge traces, then verify. */
function smpro_svc_uninstall($key) {
    $key = preg_replace('/[^a-z0-9_]/', '', (string)$key);
    $reg = smpro_svc_registry()[$key] ?? null;
    if (!$reg) return ['ok'=>false, 'msg'=>'Unknown service.'];
    $label = $reg['label'] ?? $key;
    $steps = smpro_svc_uninstall_steps($key);
    if (!$steps || (empty($steps['remove']) && empty($steps['purge']))) return ['ok'=>false, 'msg'=>$label . ': no automated uninstall method is known for this item.'];
    $bash = smpro_svc_bash(); $log = [];
    $run = function ($name, $sh, $t) use ($bash, &$log) {
        $out = trim((string)@shell_exec('timeout ' . (int)$t . ' ' . escapeshellarg($bash) . ' -c ' . escapeshellarg($sh) . ' 2>&1'));
        $log[] = $name . ($out === '' ? '' : ': ' . trim(mb_substr(preg_replace('/\s+/', ' ', $out), 0, 140)));
    };
    // accurate "still installed?" check for THIS add-on: real residue (binaries + key dirs), not systemctl is-active
    // (a removed unit still reports "inactive", which would falsely read as installed). Falls back to the generic scan.
    $verify = $steps['verify'] ?? null;
    $stillThere = function () use ($reg, $verify) {
        if (is_array($verify)) {
            foreach ((array)($verify['cmds'] ?? []) as $c) if (smpro_svc_cmd_exists($c)) return true;
            foreach ((array)($verify['paths'] ?? []) as $p) { clearstatcache(); if (@file_exists($p)) return true; }
            return false;
        }
        return !empty(smpro_svc_status($reg)['installed']);
    };
    foreach ((array)($steps['remove'] ?? []) as $st) {                        // strategies, escalating — stop when gone
        if (!$stillThere()) break;
        $run($st[0], $st[1], $st[2]);
    }
    foreach ((array)($steps['purge'] ?? []) as $st) $run($st[0], $st[1], $st[2]);   // always wipe traces
    if (function_exists('smpro_audit')) @smpro_audit('svc_uninstall', ['svc'=>$key, 'actor'=>function_exists('smpro_current_actor') ? smpro_current_actor() : 'root']);
    sleep(1); clearstatcache();
    $gone = !$stillThere();
    $reboot = !empty($steps['reboot']) ? ' NOTE: fully removing the CloudLinux kernel requires a reboot into a stock kernel — schedule that from your provider console.' : '';
    return ['ok'=>true, 'gone'=>$gone, 'log'=>$log,
            'msg'=>$label . ($gone ? ' — UNINSTALLED. It is no longer detected on this server, and its files / units / firewall chains were cleaned up.' : ' — ran ' . count($log) . ' removal step(s); it may still be partially present. Re-scan; if it persists, check the step log below.') . $reboot];
}

/* ============================ monitor config ============================ */
function smpro_svcmon_cfg() {
    $d = @is_file(SMPRO_SVCMON_CFG) ? json_decode((string)@file_get_contents(SMPRO_SVCMON_CFG), true) : null;
    if (!is_array($d)) $d = [];
    $mon = (isset($d['monitor']) && is_array($d['monitor'])) ? array_values(array_intersect(array_map('strval', $d['monitor']), smpro_svc_monitorable())) : null;
    return [
        'enabled'     => !empty($d['enabled']),
        'monitor'     => $mon !== null ? $mon : smpro_svcmon_default_monitor(),
        'autorestart' => array_key_exists('autorestart', $d) ? !empty($d['autorestart']) : true,
        'notify'      => array_key_exists('notify', $d) ? !empty($d['notify']) : true,
        'recovery'    => !empty($d['recovery']),   // also notify when a watched service comes back up
    ];
}
function smpro_svcmon_cfg_save($c) {
    $mon = array_values(array_intersect(array_map('strval', (array)($c['monitor'] ?? [])), smpro_svc_monitorable()));
    $out = ['enabled'=>!empty($c['enabled']), 'monitor'=>$mon, 'autorestart'=>!empty($c['autorestart']), 'notify'=>!empty($c['notify']), 'recovery'=>!empty($c['recovery'])];
    $f = SMPRO_SVCMON_CFG; $dir = dirname($f); if (!is_dir($dir)) @mkdir($dir, 0700, true);
    $t = $f . '.tmp'; if (@file_put_contents($t, json_encode($out, JSON_PRETTY_PRINT), LOCK_EX) === false) return false;
    @chmod($t, 0600); $ok = @rename($t, $f);
    if (function_exists('smpro_svcmon_cron_sync')) smpro_svcmon_cron_sync();
    return $ok;
}

/* ============================ monitor run (cron) ============================ */
function smpro_svcmon_state_load() { $d = @is_file(SMPRO_SVCMON_STATE) ? json_decode((string)@file_get_contents(SMPRO_SVCMON_STATE), true) : null; return is_array($d) ? $d : []; }
function smpro_svcmon_state_save($st) {
    $f = SMPRO_SVCMON_STATE; $dir = dirname($f); if (!is_dir($dir)) @mkdir($dir, 0700, true);
    $t = $f . '.tmp'; if (@file_put_contents($t, json_encode($st), LOCK_EX) !== false) { @chmod($t, 0600); @rename($t, $f); }
}
/** The monitor body. For each watched service that is down: auto-restart (rate-limited) and/or notify once per outage. */
function smpro_svcmon_run() {
    $cfg = smpro_svcmon_cfg();
    // Always refresh the cheap scan snapshot so the dashboard stays current even when monitoring is off.
    $rows = smpro_svc_scan(); smpro_svc_snap_write($rows);
    if (!$cfg['enabled'] || !$cfg['monitor']) return;
    $reg = smpro_svc_registry(); $state = smpro_svcmon_state_load(); $now = time(); $acted = 0;
    $ignored = smpro_svc_ignored();
    foreach ($cfg['monitor'] as $key) {
        if (isset($ignored[$key])) { unset($state[$key]); continue; }   // admin muted this service → no auto-restart, no alert
        $svc = $reg[$key] ?? null; if (!$svc || !smpro_svc_is_runtime($svc) || empty($svc['units'])) continue;
        $row = $rows[$key] ?? null; if (!$row || !$row['installed']) { unset($state[$key]); continue; }
        // ADMINISTRATIVELY DISABLED (chkservd name:0, or CSF's csf.disable) — switched off on purpose, so it is
        // not down and must not be alerted on. The page already excludes these; the MONITOR did not, so on a
        // specialised server (mail-only, DNS-only) it kept firing "Service DOWN" for a service the admin
        // deliberately turned off, and burned the crash-loop budget on restarts that are refused anyway —
        // eventually reporting "auto-restart PAUSED, manual attention needed" about a non-problem.
        if (!empty($row['off_reason'])) { unset($state[$key]); continue; }
        if (!empty($row['active'])) {   // healthy (or recovered)
            if (!empty($state[$key]['notified']) && $cfg['recovery'] && $cfg['notify'] && function_exists('smpro_notify')) {
                $downFor = $now - (int)($state[$key]['downSince'] ?? $now);
                @smpro_notify('service_up', 'Service recovered: ' . $svc['label'], $svc['label'] . ' is running again (was down for ~' . max(1, (int)round($downFor / 60)) . ' min).', ['severity'=>'info']);
            }
            unset($state[$key]); continue;
        }
        // DOWN
        $s = $state[$key] ?? ['downSince'=>$now, 'restarts'=>[], 'notified'=>false];
        if (empty($s['downSince'])) $s['downSince'] = $now;
        $s['restarts'] = array_values(array_filter((array)($s['restarts'] ?? []), fn($t) => $t > $now - 3600));   // keep last hour
        $restartMsg = '';
        if ($cfg['autorestart'] && ($now - (int)$s['downSince']) >= 300) {   // down on two consecutive ticks (>= 5 min) before the first restart, never on one sample
            if (count($s['restarts']) < 4) {                                   // crash-loop guard: max 4 auto-restarts/hour
                $r = smpro_svcmon_control($key, smpro_svc_restartsrv($svc) !== '' ? 'restart' : 'start');
                $s['restarts'][] = $now; $acted++;
                if (function_exists('smpro_audit')) @smpro_audit('svcmon_autorestart', ['svc'=>$key, 'ok'=>!empty($r['ok'])]);
                if (!empty($r['ok'])) {                                        // recovered by us
                    if (!empty($s['notified']) && $cfg['recovery'] && $cfg['notify'] && function_exists('smpro_notify'))
                        @smpro_notify('service_up', 'Service recovered: ' . $svc['label'], $svc['label'] . ' was down and SM Pro restarted it successfully.', ['severity'=>'info']);
                    unset($state[$key]); continue;
                }
                $restartMsg = ' Auto-restart was attempted but the service did not come back.';
            } else {
                $s['paused'] = true;
                $restartMsg = ' Auto-restart is PAUSED for this service (it failed to stay up after 4 attempts in the last hour) — manual attention needed.';
            }
        }
        if ($cfg['notify'] && empty($s['notified']) && function_exists('smpro_notify')) {
            @smpro_notify('service_down', 'Service DOWN: ' . $svc['label'],
                $svc['label'] . ' (' . ($row['unit'] ?? $key) . ') is not running on this server.' . $restartMsg,
                ['severity'=>!empty($svc['critical']) ? 'critical' : 'warning']);
            $s['notified'] = true; $s['lastNotify'] = $now;
        }
        $state[$key] = $s;
    }
    smpro_svcmon_state_save($state);
    if (function_exists('smpro_audit') && $acted) @smpro_audit('svcmon_run', ['restarts'=>$acted]);
}

/* ============================ cron self-heal ============================ */
function smpro_svcmon_cron_sync() {
    // A test must never install a live cron. The shared writer refuses too, but a test that loads only
    // this file has no shared writer to refuse - function_exists() is false and the fallback writes
    // /etc/cron.d directly. The lab caught exactly that, restored the file, and went red at random.
    if (defined('SMPRO_TEST_SRC')) return true;
    $f = '/etc/cron.d/smpro-svcmon';
    $cfg = smpro_svcmon_cfg();
    if (!$cfg['enabled'] || !$cfg['monitor']) { if (@is_file($f)) @unlink($f); return; }
    $bin = SMPRO_BASE . '/bin/svcmon.php'; if (!@is_file($bin)) return;
    $php = smpro_php_cli_bin();
    $lockDir = defined('SMPRO_LOCKS') ? SMPRO_LOCKS : (SMPRO_VARLIB . '/locks'); @is_dir($lockDir) || @mkdir($lockDir, 0700, true);
    $flock = is_executable('/usr/bin/flock') ? '/usr/bin/flock' : 'flock';
    $desired = "# Safety Monitor Pro — service monitor (watch chosen services; auto-restart + notify when one stops)\n"
             . "*/3 * * * * root $flock -n " . $lockDir . "/svcmon.lock timeout 120 $php $bin >/dev/null 2>&1\n";
    if (@is_file($f) && (string)@file_get_contents($f) === $desired) return;
    smpro_cron_install($f, $desired);   // verified write: 0644 + trailing newline, or it reports failure
}
