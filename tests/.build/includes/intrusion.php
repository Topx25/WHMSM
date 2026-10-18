<?php
/**
 * includes/intrusion.php — Intrusion detection ENGINE (shared by the Intrusion Monitor
 * module AND the notify cron, so detection + alerts run even with no page open).
 *
 * Capabilities:
 *   - ModSecurity audit-log parsing (per-domain web attacks)              [source]
 *   - Persistent SQLite index of attacks (history beyond log rotation)    [index]
 *   - CSF + Cloudflare edge blocking of attacker IPs                       [response]
 *   - Successful-breach correlation (attack 200 + recent docroot change)  [detection]
 *   - Attacker intelligence + coordinated-campaign detection              [intel]
 *   - Real-time alert scan for the notify cron (push as it happens)       [alerts]
 *
 * Only function/const definitions here — no execution at include time.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

define('SMPRO_IM_LIVE_BYTES',   3 * 1024 * 1024);
define('SMPRO_IM_PAGE_BYTES',   9 * 1024 * 1024);
define('SMPRO_IM_REPORT_BYTES', 48 * 1024 * 1024);
define('SMPRO_IM_CAP',          20000);
define('SMPRO_IN_DB',     SMPRO_VARLIB . '/intrusion.db');
define('SMPRO_IN_CFG',    SMPRO_VARLIB . '/intrusion.json');     // settings (CF token, thresholds, auto-block)
define('SMPRO_IN_STATE',  SMPRO_VARLIB . '/intrusion_state.json'); // alert cursor / state
define('SMPRO_IM_QUAR',   SMPRO_VARLIB . '/quarantine');         // quarantined (cleaned) web-shells — restorable
define('SMPRO_IM_EMLOG',  SMPRO_VARLIB . '/emergency.json');     // manifest of emergency actions (reversible)

/* ============================ settings ============================ */
/** Config fields that hold secrets and must be encrypted at rest (vault, AES-256-GCM). */
function smpro_in_secret_keys() { return ['cf_token', 'abuseipdb_key']; }

function smpro_in_cfg() {
    static $c = null;
    if ($c !== null) return $c;
    $d = is_file(SMPRO_IN_CFG) ? json_decode((string)@file_get_contents(SMPRO_IN_CFG), true) : null;
    $d = is_array($d) ? $d : [];
    $c = $d + [
        'cf_token' => '', 'cf_account' => '',                 // Cloudflare API (account-level access rules)
        'abuseipdb_key' => '',
        'auto_block' => false, 'auto_block_dryrun' => true,   // auto-response (off by default; dry-run when first enabled)
        'auto_block_threshold' => 30,                          // per-IP attack-count floor for auto-block (non-Arab / datacenter / unknown)
        'protect_arab' => true,                                // EG/SA residential never auto-blocked; other-Arab residential needs a higher bar
        'ai_block' => false,                                   // let the AI decide which attacker IPs to auto-block
        'emergency' => false,                                  // EMERGENCY mode: auto-harden (+clean) a site the moment it is attacked & files change
        'emergency_dryrun' => false,                           // preview emergency actions without touching files
        'emergency_harden' => true,                            // disable PHP execution in upload/cache dirs + lock core files
        'emergency_clean' => true,                             // quarantine recently-changed files that look like web-shells
        'emergency_block_scanners' => true,                    // auto-block clear malicious scanners (credential probes / bare-IP scans)
        'emergency_batch' => 3,                                // group emergency (harden/clean) notifications: one message per N actions
        'emergency_block_digest_hours' => 12,                  // routine scanner auto-blocks: one grouped INFO digest per N hours (not per run)
        'use_cloudflare' => true, 'use_csf' => true,
        'allowlist' => [],                                     // never block these IPs/CIDRs
        'protect_regions' => ['EG', 'SA'],                     // home regions: RESIDENTIAL IPs here are never auto-blocked (manual review only)
        'protect_arab_threshold' => 1,                         // other Arab-country residential IPs: auto-block only when attack is clear & repeated (1=on)
        'breach_exclude' => ['imunify-security', '/wp-content/cache/', '/wp-content/upgrade/', '/wp-content/uploads/cache/', 'wordfence-waf', 'wp-efadh', '/mu-plugins/'],  // breach scan: ignore these (legit, auto-updating). Built-in security-plugin seeds are ALSO always applied — see smpro_im_breach_exclude_seed(). Files with a WP "Plugin Name:" header are never auto-quarantined.
        'thr_domain_attacks' => 150,                           // alert when a domain crosses N attacks in the window (busy shared server = high baseline noise)
        'thr_ip_domains' => 12,                                // alert when one IP hits N+ distinct domains (distributed scan)
        'alert_window_min' => 15,                              // detection window for the cron
        'login_guard' => true,                                 // 24/7 auto-block FOREIGN (non-Arab) login brute-force (cron)
        'login_guard_threshold' => 4,                          // block at this many failed logins (>3)
        'login_guard_window' => 30,                            // failed-login look-back window (minutes)
        'login_guard_cap' => 20,                               // max IPs blocked per cron run (safety)
    ];
    // Decrypt secrets for callers; migrate any legacy PLAINTEXT value by re-storing it encrypted once.
    $migrate = false;
    if (function_exists('smpro_secret_dec')) {
        foreach (smpro_in_secret_keys() as $k) {
            $v = (string)($c[$k] ?? '');
            if ($v === '') continue;
            if (smpro_secret_is_enc($v)) $c[$k] = smpro_secret_dec($v);   // stored encrypted → give callers plaintext
            else $migrate = true;                                          // stored plaintext → needs re-encryption
        }
    }
    if ($migrate) smpro_in_cfg_write($c);                                  // rewrite to disk with secrets encrypted
    return $c;
}
/** Write the config to disk, encrypting secret fields at rest (does NOT mutate the in-memory copy). */
function smpro_in_cfg_write(array $c) {
    $w = $c;
    if (function_exists('smpro_secret_enc')) {
        foreach (smpro_in_secret_keys() as $k) {
            if (isset($w[$k]) && $w[$k] !== '') $w[$k] = smpro_secret_enc((string)$w[$k]);
        }
    }
    @is_dir(dirname(SMPRO_IN_CFG)) || @mkdir(dirname(SMPRO_IN_CFG), 0700, true);
    $tmp = SMPRO_IN_CFG . '.tmp';
    @file_put_contents($tmp, json_encode($w, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), LOCK_EX);
    @chmod($tmp, 0600); @rename($tmp, SMPRO_IN_CFG);
}
function smpro_in_cfg_save($patch) {
    $c = smpro_in_cfg();
    foreach ($patch as $k => $v) $c[$k] = $v;
    smpro_in_cfg_write($c);   // encrypts cf_token/abuseipdb_key before writing
    return $c;
}
function smpro_in_state() { $d = is_file(SMPRO_IN_STATE) ? json_decode((string)@file_get_contents(SMPRO_IN_STATE), true) : null; return is_array($d) ? $d : []; }
function smpro_in_state_save($s) { @is_dir(dirname(SMPRO_IN_STATE)) || @mkdir(dirname(SMPRO_IN_STATE), 0700, true); $t = SMPRO_IN_STATE . '.tmp'; @file_put_contents($t, json_encode($s, JSON_UNESCAPED_SLASHES), LOCK_EX); @chmod($t, 0600); @rename($t, SMPRO_IN_STATE); }

/**
 * 24/7 login brute-force auto-block (run from cron). Reads cPanel login_log, counts FAILED logins
 * per source IP inside the window, and firewalls any FOREIGN (non-Arab) IP at/over the threshold.
 * SAFE: Arab + local IPs are never blocked (smpro_geo_foreign), allowlist honoured, deduped via
 * state, capped per run, every block audited. $dryrun=true reports without blocking.
 */
function smpro_login_guard_run($dryrun = false) {
    if (function_exists('smpro_ctl_dry_run') && smpro_ctl_dry_run()) $dryrun = true;   // global Dry-Run forces report-only
    $cfg = smpro_in_cfg();
    if (empty($cfg['login_guard'])) return ['ok' => false, 'msg' => 'login_guard disabled', 'blocked' => []];
    $log = '/usr/local/cpanel/logs/login_log';
    if (!is_readable($log)) return ['ok' => false, 'msg' => 'login_log unreadable', 'blocked' => []];
    $thresh = max(2, (int)($cfg['login_guard_threshold'] ?? 4));
    $cutoff = time() - max(5, (int)($cfg['login_guard_window'] ?? 30)) * 60;
    $cap    = max(1, (int)($cfg['login_guard_cap'] ?? 20));
    $raw = (string)@shell_exec('timeout 20 tail -n 6000 ' . escapeshellarg($log) . ' 2>/dev/null');
    if ($raw === '') return ['ok' => true, 'blocked' => []];
    $fails = [];
    foreach (explode("\n", $raw) as $line) {
        $line = trim($line); if ($line === '') continue;
        if (preg_match('/^\[([^\]]+)\]\s+\S+\s+\[[^\]]+\]\s+(\S+)\s+-\s+\S+\s+-\s+(.+)$/', $line, $m)) { $timeRaw = $m[1]; $ip = $m[2]; $rest = $m[3]; }
        elseif (preg_match('/^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"[^"]*"\s+(.+)$/', $line, $m)) { $ip = $m[1]; $timeRaw = $m[2]; $rest = $m[3]; }
        else continue;
        if (!filter_var($ip, FILTER_VALIDATE_IP)) continue;
        if (preg_match('/SUCCEEDED\s+LOGIN|SUCCESS\s+LOGIN/i', $rest)) continue;
        if (!preg_match('/FAILED\s+LOGIN|DEFERRED\s+LOGIN|AUTHENTICATION\s+FAILED|INVALID|FAILURE/i', $rest)) continue;
        $ts = @strtotime($timeRaw) ?: 0;
        if ($ts && $ts < $cutoff) continue;
        $fails[$ip] = ($fails[$ip] ?? 0) + 1;
    }
    $state = smpro_in_state();
    $done  = is_array($state['login_guard_blocked'] ?? null) ? $state['login_guard_blocked'] : [];
    $allow = (array)($cfg['allowlist'] ?? []);
    $blocked = []; arsort($fails);
    foreach ($fails as $ip => $n) {
        if ($n < $thresh || isset($done[$ip]) || in_array($ip, $allow, true)) continue;
        $g = smpro_geo_foreign($ip);
        if (empty($g['foreign'])) continue;                 // FOREIGN (non-Arab) only; Arab/local protected
        if (count($blocked) >= $cap) break;
        if (!$dryrun) { smpro_im_block_ip($ip, 'Login brute-force: ' . $n . ' failed logins from ' . $g['cc']); $done[$ip] = ['ts' => time(), 'n' => $n, 'cc' => $g['cc']]; }
        $blocked[] = ['ip' => $ip, 'fails' => $n, 'cc' => $g['cc']];
        if (function_exists('smpro_audit')) smpro_audit('login_guard_block', ['ip' => $ip, 'fails' => $n, 'cc' => $g['cc'], 'dryrun' => $dryrun]);
    }
    if ($blocked && !$dryrun) { $state['login_guard_blocked'] = array_slice($done, -3000, 3000, true); smpro_in_state_save($state); }
    return ['ok' => true, 'blocked' => $blocked, 'scanned' => count($fails)];
}

/** Install/refresh (or remove) the per-minute login-guard cron. Idempotent + cheap (writes only on change). */
function smpro_login_guard_install_cron() {
    $f = '/etc/cron.d/smpro-login-guard';
    $cfg = smpro_in_cfg();
    if (empty($cfg['login_guard'])) { if (is_file($f)) @unlink($f); return; }
    $bin = (defined('SMPRO_BASE') ? SMPRO_BASE : __DIR__ . '/..') . '/bin/login_guard.php';
    if (!is_file($bin)) return;
    $php  = is_executable('/usr/local/cpanel/3rdparty/bin/php') ? '/usr/local/cpanel/3rdparty/bin/php' : (trim((string)@shell_exec('command -v php')) ?: 'php');
    $lock = (defined('SMPRO_VARLIB') ? SMPRO_VARLIB : '/var/lib/smpro') . '/locks/login_guard.lock';
    @is_dir(dirname($lock)) || @mkdir(dirname($lock), 0700, true);
    $flock = is_executable('/usr/bin/flock') ? '/usr/bin/flock' : 'flock';
    $want = "# Safety Monitor Pro — foreign login brute-force guard (every minute; flock = no overlap)\n"
          . "* * * * * root $flock -n $lock timeout 120 $php $bin >/dev/null 2>&1\n";
    if (is_file($f) && (string)@file_get_contents($f) === $want) return;   // already current
    @file_put_contents($f, $want); @chmod($f, 0644);
}

/* ============================ sources ============================ */
function smpro_im_modsec_log() {
    foreach (['/etc/apache2/logs/modsec_audit.log', '/usr/local/apache/logs/modsec_audit.log',
              '/var/log/apache2/modsec_audit.log', '/var/log/modsec_audit.log'] as $p) if (is_readable($p)) return $p;
    return '';
}
function smpro_im_userdomains() {
    static $map = null;
    if ($map !== null) return $map;
    $map = [];
    if (is_readable('/etc/userdomains')) foreach (file('/etc/userdomains', FILE_IGNORE_NEW_LINES) ?: [] as $l)
        if (preg_match('/^([^:]+):\s*(\S+)/', $l, $m)) $map[strtolower(trim($m[1]))] = trim($m[2]);
    return $map;
}
function smpro_im_account_for($domain) {
    $map = smpro_im_userdomains();
    $d = strtolower(trim((string)$domain));
    if (isset($map[$d])) return $map[$d];
    if (strpos($d, 'www.') === 0 && isset($map[substr($d, 4)])) return $map[substr($d, 4)];
    $parts = explode('.', $d);
    while (count($parts) > 2) { array_shift($parts); $cand = implode('.', $parts); if (isset($map[$cand])) return $map[$cand]; }
    return '';
}
/** A cPanel account's document roots (main + addon/sub), for breach correlation. */
function smpro_im_docroots($account) {
    $account = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)$account);
    if ($account === '' || !is_dir('/home/' . $account)) return [];
    $roots = [];
    $base = '/home/' . $account . '/public_html';
    if (is_dir($base)) $roots[$base] = 1;
    foreach (glob('/var/cpanel/userdata/' . $account . '/*') ?: [] as $f) {
        if (substr($f, -5) === '.cache' || substr($f, -9) === '_SSL') continue;
        $txt = (string)@file_get_contents($f);
        if (preg_match('/documentroot:\s*(\S+)/', $txt, $m) && is_dir($m[1])) $roots[$m[1]] = 1;
    }
    return array_keys($roots);
}

/* ============================ classification ============================ */
function smpro_im_classify($text) {
    $t = strtolower($text);
    $has = function ($n) use ($t) { foreach ((array)$n as $x) if (strpos($t, $x) !== false) return true; return false; };
    if ($has(['sql injection', 'sqli', 'union select', 'attack-sqli']))                  return 'SQL Injection';
    if ($has(['xss', 'cross-site scripting', 'attack-xss']))                              return 'XSS';
    if ($has(['remote command', 'os command', 'command injection', 'rce', 'attack-rce'])) return 'Command Injection / RCE';
    if ($has(['remote file inclusion', 'rfi', 'attack-rfi']))                             return 'Remote File Inclusion';
    if ($has(['path traversal', 'directory traversal', 'lfi', 'local file', 'attack-lfi', '../'])) return 'Path Traversal / LFI';
    if ($has(['dotfile', 'sensitive file', '.env', '.git', 'wp-config', 'backup file', 'config file'])) return 'Sensitive File Access';
    if ($has(['php injection', 'attack-php', 'php object', 'deserial']))                  return 'PHP Injection';
    if ($has(['scanner', 'nikto', 'sqlmap', 'nmap', 'masscan', 'attack-scanner']))        return 'Scanner / Recon';
    if ($has(['protocol', 'attack-protocol', 'invalid request', 'malformed']))            return 'Protocol Violation';
    if ($has(['brute', 'login', 'authentication']))                                      return 'Brute Force / Auth';
    if ($has(['upload', 'webshell', 'shell', 'backdoor']))                               return 'Malicious Upload';
    if ($has(['fixation', 'session']))                                                   return 'Session Attack';
    return 'WAF Block (other)';
}
function smpro_im_sev_rank($s) { static $r = ['critical'=>5,'error'=>4,'warning'=>3,'notice'=>2,'info'=>1]; return $r[strtolower((string)$s)] ?? 2; }
/** Categories that, when the server answered 200, suggest a possible SUCCESSFUL exploit. */
function smpro_im_exploit_kind($kind) {
    return in_array($kind, ['SQL Injection','Command Injection / RCE','Remote File Inclusion','Path Traversal / LFI','PHP Injection','Malicious Upload'], true);
}

/* ============================ ModSecurity parser ============================ */
function smpro_im_parse_modsec($bytes, $cap, $fromTs = 0) {
    $log = smpro_im_modsec_log();
    if ($log === '') return [];
    $bytes = max(65536, (int)$bytes);
    $raw = (string)@shell_exec('timeout ' . SMPRO_TIMEOUT_NORMAL . ' tail -c ' . (int)$bytes . ' ' . escapeshellarg($log) . ' 2>/dev/null');
    if ($raw === '') return [];
    $events = []; $sec = ''; $cur = null; $started = false;
    $flush = function () use (&$cur, &$events, $fromTs) {
        if ($cur && !empty($cur['msg']) && ($cur['ts'] === 0 || $cur['ts'] >= $fromTs)) {
            $cur['kind'] = smpro_im_classify($cur['msg'] . ' ' . $cur['tag']); $events[] = $cur;
        }
        $cur = null;
    };
    foreach (explode("\n", $raw) as $ln) {
        if (preg_match('/^--[0-9A-Za-z]+-([A-Z])--\s*$/', $ln, $m)) {
            $l = $m[1];
            if ($l === 'A') { $flush(); $started = true; $cur = ['ts'=>0,'ip'=>'','domain'=>'','method'=>'','uri'=>'','code'=>'','rule'=>'','msg'=>'','tag'=>'','severity'=>'','ua'=>'']; }
            elseif ($l === 'Z') $flush();
            $sec = $l; continue;
        }
        if (!$started || $cur === null) continue;
        if ($sec === 'A') {
            if ($cur['ts'] === 0 && preg_match('/^\[([^\]]+)\]\s+\S+\s+([0-9a-fA-F:.]+)\s+\d+/', $ln, $a)) {
                $t = $a[1];
                if (preg_match('#^(\d{1,2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?\s*([+\-]\d{4})?#', $t, $tm))
                    $cur['ts'] = strtotime($tm[1].' '.$tm[2].' '.$tm[3].' '.$tm[4].':'.$tm[5].':'.$tm[6].' '.($tm[7]??'')) ?: 0;
                else $cur['ts'] = strtotime($t) ?: 0;
                $cur['ip'] = $a[2];
            }
        } elseif ($sec === 'B') {
            if ($cur['method'] === '' && preg_match('#^([A-Z]+)\s+(\S+)\s+HTTP/#', $ln, $b)) { $cur['method'] = $b[1]; $cur['uri'] = $b[2]; }
            elseif (stripos($ln, 'Host:') === 0) $cur['domain'] = strtolower(trim(substr($ln, 5)));
            elseif ($cur['ua'] === '' && stripos($ln, 'User-Agent:') === 0) $cur['ua'] = trim(substr($ln, 11));
        } elseif ($sec === 'F') {
            if ($cur['code'] === '' && preg_match('#^HTTP/\d\.\d\s+(\d{3})#', $ln, $f)) $cur['code'] = $f[1];
        } elseif ($sec === 'H') {
            if (stripos($ln, 'Message:') === 0) {
                $sv = preg_match('/\[severity "([^"]*)"\]/', $ln, $svm) ? $svm[1] : '';
                if ($cur['msg'] === '' || smpro_im_sev_rank($sv) > smpro_im_sev_rank($cur['severity'])) {
                    if (preg_match('/\[msg "([^"]*)"\]/', $ln, $mm)) $cur['msg'] = trim(explode('||', $mm[1])[0]);
                    else $cur['msg'] = trim(preg_replace('/\[[^\]]*\]/', '', substr($ln, 8)));
                    if (preg_match('/\[id "([^"]*)"\]/', $ln, $idm)) $cur['rule'] = $idm[1];
                    if ($sv !== '') $cur['severity'] = $sv;
                    if (preg_match('/\[tag "([^"]*)"\]/', $ln, $tg)) $cur['tag'] = $tg[1];
                    if ($cur['code'] === '' && preg_match('/code (\d{3})/', $ln, $cm)) $cur['code'] = $cm[1];
                }
            }
        }
        if (count($events) >= $cap) break;
    }
    $flush();
    usort($events, fn($a, $b) => $b['ts'] <=> $a['ts']);
    return $events;
}
function smpro_im_by_domain($events) {
    $d = [];
    foreach ($events as $e) {
        $dom = $e['domain'] !== '' ? $e['domain'] : '(no host)';
        if (!isset($d[$dom])) $d[$dom] = ['domain'=>$dom,'account'=>smpro_im_account_for($dom),'total'=>0,'ips'=>[],'cats'=>[],'sev'=>0,'sevlabel'=>'','first'=>PHP_INT_MAX,'last'=>0];
        $g = &$d[$dom]; $g['total']++;
        if ($e['ip'] !== '') $g['ips'][$e['ip']] = ($g['ips'][$e['ip']] ?? 0) + 1;
        $g['cats'][$e['kind']] = ($g['cats'][$e['kind']] ?? 0) + 1;
        $r = smpro_im_sev_rank($e['severity']); if ($r > $g['sev']) { $g['sev'] = $r; $g['sevlabel'] = $e['severity']; }
        if ($e['ts']) { if ($e['ts'] < $g['first']) $g['first'] = $e['ts']; if ($e['ts'] > $g['last']) $g['last'] = $e['ts']; }
        unset($g);
    }
    foreach ($d as &$g) { arsort($g['ips']); arsort($g['cats']); $g['uniq_ips'] = count($g['ips']); $g['top_cat'] = $g['cats'] ? array_key_first($g['cats']) : ''; if ($g['first'] === PHP_INT_MAX) $g['first'] = 0; }
    unset($g);
    uasort($d, fn($a, $b) => $b['total'] <=> $a['total']);
    return $d;
}

/* ============================ SQLite index (persistent history) ============================ */
function smpro_in_db() {
    static $db = false;
    if ($db !== false) return $db;
    if (!class_exists('PDO') || !in_array('sqlite', PDO::getAvailableDrivers(), true)) return $db = null;
    try {
        @is_dir(dirname(SMPRO_IN_DB)) || @mkdir(dirname(SMPRO_IN_DB), 0700, true);
        $db = new PDO('sqlite:' . SMPRO_IN_DB);
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_SILENT);
        $db->exec('PRAGMA journal_mode=WAL; PRAGMA busy_timeout=4000;');
        $db->exec('CREATE TABLE IF NOT EXISTS attacks(hash TEXT PRIMARY KEY, ts INTEGER, ip TEXT, domain TEXT, account TEXT, kind TEXT, severity TEXT, code TEXT, rule TEXT, uri TEXT)');
        $db->exec('CREATE INDEX IF NOT EXISTS ix_ts ON attacks(ts)');
        $db->exec('CREATE INDEX IF NOT EXISTS ix_dom ON attacks(domain)');
        $db->exec('CREATE INDEX IF NOT EXISTS ix_ip ON attacks(ip)');
        @chmod(SMPRO_IN_DB, 0600);
    } catch (Throwable $e) { $db = null; }
    return $db;
}
/** Insert events (dedup by content hash). Returns count of NEW rows. */
function smpro_in_ingest($events) {
    $db = smpro_in_db(); if (!$db) return 0;
    $st = $db->prepare('INSERT OR IGNORE INTO attacks(hash,ts,ip,domain,account,kind,severity,code,rule,uri) VALUES(?,?,?,?,?,?,?,?,?,?)');
    $n = 0; $db->beginTransaction();
    foreach ($events as $e) {
        $h = sha1(($e['ts']??0).'|'.($e['ip']??'').'|'.($e['domain']??'').'|'.($e['rule']??'').'|'.substr($e['uri']??'',0,200));
        $st->execute([$h,(int)($e['ts']??0),$e['ip']??'',$e['domain']??'',smpro_im_account_for($e['domain']??''),$e['kind']??'',$e['severity']??'',$e['code']??'',$e['rule']??'',substr($e['uri']??'',0,300)]);
        $n += $st->rowCount();
    }
    $db->commit();
    // retention: keep 30 days
    $db->exec('DELETE FROM attacks WHERE ts < ' . (time() - 30 * 86400));
    return $n;
}
/** Parse the recent tail and persist it. Returns the parsed events. */
function smpro_im_ingest_recent($bytes = SMPRO_IM_LIVE_BYTES, $mins = 120) {
    $ev = smpro_im_parse_modsec($bytes, 6000, time() - $mins * 60);
    if ($ev) smpro_in_ingest($ev);
    return $ev;
}
function smpro_in_history($sinceTs, $limit = 5000) {
    $db = smpro_in_db(); if (!$db) return [];
    $st = $db->prepare('SELECT * FROM attacks WHERE ts >= ? ORDER BY ts DESC LIMIT ?');
    $st->execute([(int)$sinceTs, (int)$limit]);
    return $st->fetchAll(PDO::FETCH_ASSOC) ?: [];
}
/** All indexed attacks from one IP within [sinceTs, untilTs] (untilTs 0 = now). */
function smpro_in_by_ip($ip, $sinceTs = 0, $untilTs = 0, $limit = 400) {
    $db = smpro_in_db(); if (!$db) return [];
    $until = $untilTs ?: time();
    $st = $db->prepare('SELECT * FROM attacks WHERE ip = ? AND ts >= ? AND ts <= ? ORDER BY ts DESC LIMIT ?');
    $st->execute([(string)$ip, (int)$sinceTs, (int)$until, (int)$limit]);
    return $st->fetchAll(PDO::FETCH_ASSOC) ?: [];
}
/** Aggregated attack profile for one IP within a date window (sinceTs 0 = last 30 days). */
function smpro_in_ip_summary($ip, $sinceTs = 0, $untilTs = 0) {
    $since = $sinceTs ?: (time() - 30 * 86400);
    $rows = smpro_in_by_ip($ip, $since, $untilTs ?: time(), 5000);
    $s = ['total'=>count($rows),'domains'=>[],'cats'=>[],'codes'=>[],'first'=>PHP_INT_MAX,'last'=>0,'sev'=>'','sevr'=>0,'recent'=>array_slice($rows,0,40)];
    foreach ($rows as $r) {
        if (($r['domain'] ?? '') !== '') $s['domains'][$r['domain']] = ($s['domains'][$r['domain']] ?? 0) + 1;
        $s['cats'][$r['kind']] = ($s['cats'][$r['kind']] ?? 0) + 1;
        if (($r['code'] ?? '') !== '') $s['codes'][$r['code']] = ($s['codes'][$r['code']] ?? 0) + 1;
        $sr = smpro_im_sev_rank($r['severity'] ?? ''); if ($sr > $s['sevr']) { $s['sevr'] = $sr; $s['sev'] = $r['severity']; }
        $s['first'] = min($s['first'], (int)$r['ts']); $s['last'] = max($s['last'], (int)$r['ts']);
    }
    if ($s['first'] === PHP_INT_MAX) $s['first'] = 0; arsort($s['domains']); arsort($s['cats']); arsort($s['codes']);
    return $s;
}

/** ALLOW an IP: add to the plugin allowlist (never auto-blocked) + CSF allow (and lift any deny). */
function smpro_im_allow_ip($ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return ['ok'=>false,'msg'=>'invalid IP'];
    $c = smpro_in_cfg(); $al = (array)($c['allowlist'] ?? []);
    if (!in_array($ip, $al, true)) { $al[] = $ip; smpro_in_cfg_save(['allowlist'=>array_values($al)]); }
    $parts = ['plugin allowlist'];
    $csf = smpro_im_csf_bin();
    if ($csf !== '') {
        @shell_exec('timeout 25 ' . escapeshellarg($csf) . ' -dr ' . escapeshellarg($ip) . ' 2>&1');   // lift any deny
        $out = (string)@shell_exec('timeout 25 ' . escapeshellarg($csf) . ' -a ' . escapeshellarg($ip) . ' ' . escapeshellarg('smpro allow ' . date('Y-m-d H:i')) . ' 2>&1');
        $parts[] = stripos($out, 'error') === false ? 'CSF allow' : 'CSF error';
    }
    return ['ok'=>true,'msg'=>implode(' · ', $parts)];
}

function smpro_in_stats($sinceTs) {
    $db = smpro_in_db(); if (!$db) return ['total'=>0,'domains'=>0,'ips'=>0];
    $st = $db->prepare('SELECT COUNT(*) t, COUNT(DISTINCT domain) d, COUNT(DISTINCT ip) i FROM attacks WHERE ts >= ?');
    $st->execute([(int)$sinceTs]); $r = $st->fetch(PDO::FETCH_ASSOC) ?: [];
    return ['total'=>(int)($r['t']??0),'domains'=>(int)($r['d']??0),'ips'=>(int)($r['i']??0)];
}

/* ============================ Cloudflare + CSF response ============================ */
function smpro_im_csf_bin() { foreach (['/usr/sbin/csf', '/usr/local/csf/bin/csf'] as $b) if (is_executable($b)) return $b; return ''; }
function smpro_im_csf_blocked() {
    $set = [];
    if (is_readable('/etc/csf/csf.deny')) foreach (file('/etc/csf/csf.deny', FILE_IGNORE_NEW_LINES) ?: [] as $l) {
        $l = trim($l); if ($l === '' || $l[0] === '#') continue;
        if (preg_match('/^([0-9a-fA-F:.]+)/', $l, $m)) $set[$m[1]] = 'perm';
    }
    return $set;
}
function smpro_im_csf_block($ip) {
    // Robust + VERIFIED block: never trust `csf -d` stdout — confirm the IP actually landed in csf.deny and is
    // enforced. ok=true ONLY when really enforcing (false + actionable msg when CSF is in TESTING mode / absent).
    if (function_exists('smpro_csf_deny_add')) {
        $r = smpro_csf_deny_add($ip, 'smpro Intrusion Monitor');
        return ['ok'=>!empty($r['ok']), 'testing'=>!empty($r['testing']), 'recorded'=>!empty($r['recorded']), 'msg'=>(string)$r['msg']];
    }
    $csf = smpro_im_csf_bin();
    if ($csf === '') return ['ok'=>false,'msg'=>'csf not installed'];
    @shell_exec('timeout 25 ' . escapeshellarg($csf) . ' -d ' . escapeshellarg($ip) . ' ' . escapeshellarg('smpro Intrusion Monitor ' . date('Y-m-d H:i')) . ' 2>&1');
    clearstatcache();
    $ok = isset(smpro_im_csf_blocked()[$ip]);
    return ['ok'=>$ok,'msg'=>$ok ? ($ip . ' blocked in CSF') : 'csf -d did not persist to csf.deny'];
}
function smpro_cf_configured() { $c = smpro_in_cfg(); return $c['cf_token'] !== '' && $c['cf_account'] !== ''; }
/** Block an IP at the Cloudflare edge via an account-level access rule. */
function smpro_cf_block_ip($ip, $note = '') {
    $c = smpro_in_cfg();
    if (!smpro_cf_configured()) return ['ok'=>false,'msg'=>'Cloudflare not configured'];
    if (!preg_match('/^[0-9a-f]{32}$/i', (string)$c['cf_account'])) return ['ok'=>false,'msg'=>'Cloudflare account id malformed'];
    $body = json_encode(['mode'=>'block','configuration'=>['target'=>'ip','value'=>$ip],'notes'=>($note ?: 'smpro Intrusion Monitor')], JSON_UNESCAPED_SLASHES);
    $url = 'https://api.cloudflare.com/client/v4/accounts/' . rawurlencode($c['cf_account']) . '/firewall/access_rules/rules';
    $res = smpro_http($url, ['method'=>'POST','timeout'=>15,'body'=>$body,                 // API token stays in-process, not in argv
        'headers'=>['Authorization: Bearer ' . $c['cf_token'], 'Content-Type: application/json']]);
    $raw = $res['body'];
    $j = json_decode($raw, true);
    if (is_array($j) && !empty($j['success'])) return ['ok'=>true,'msg'=>'blocked at Cloudflare edge'];
    $err = is_array($j) && !empty($j['errors'][0]['message']) ? $j['errors'][0]['message'] : 'Cloudflare API error';
    // "already exists" is effectively success
    if (stripos($err, 'already') !== false || stripos($raw, 'duplicate') !== false) return ['ok'=>true,'msg'=>'already blocked at Cloudflare'];
    return ['ok'=>false,'msg'=>$err];
}
function smpro_im_allowlisted($ip) {
    foreach (smpro_in_cfg()['allowlist'] as $a) { $a = trim((string)$a); if ($a !== '' && ($a === $ip || (strpos($a, '/') !== false && smpro_in_cidr_match($ip, $a)))) return true; }
    return false;
}
/**
 * Home-region protection classifier for AUTO/AI blocks (manual admin blocks bypass this).
 * Returns:
 *   'core_protected' — RESIDENTIAL IP in a configured home region (EG/SA): never auto-block, route to manual review.
 *   'arab_caution'   — RESIDENTIAL IP in another Arab country: auto-block only when the attack is clear & repeated.
 *   'normal'         — everything else (incl. ALL datacenter/hosting IPs from anywhere): blockable as usual.
 */
function smpro_im_region_status($ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return 'normal';
    $in = function_exists('smpro_ip_intel') ? smpro_ip_intel($ip, false) : [];
    // Datacenter / hosting networks are fair game regardless of country — abusers rent VMs in EG/SA too.
    if (function_exists('smpro_ip_is_datacenter') && smpro_ip_is_datacenter($in)) return 'normal';
    $cc = strtoupper((string)($in['country'] ?? ''));
    if ($cc === '') return 'normal';                                          // unknown geo → no special protection
    $c = smpro_in_cfg();
    $home = array_map('strtoupper', (array)($c['protect_regions'] ?? ['EG', 'SA']));
    if (in_array($cc, $home, true)) return 'core_protected';
    static $arab = ['AE','KW','QA','BH','OM','JO','LB','SY','IQ','YE','PS','DZ','MA','TN','LY','SD','MR','SO','DJ','KM'];
    if (in_array($cc, $arab, true)) return 'arab_caution';
    return 'normal';
}
function smpro_in_cidr_match($ip, $cidr) {
    if (strpos($cidr, '/') === false) return $ip === $cidr;
    [$net, $bits] = explode('/', $cidr, 2); $bits = (int)$bits;
    // IPv4
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && filter_var($net, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        if ($bits < 0 || $bits > 32) return false;
        $mask = $bits === 0 ? 0 : (~0 << (32 - $bits)) & 0xFFFFFFFF;
        return (ip2long($ip) & $mask) === (ip2long($net) & $mask);
    }
    // IPv6 — compare the packed bytes up to $bits (so IPv6 CIDR allowlist entries actually match)
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) && filter_var($net, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        if ($bits < 0 || $bits > 128) return false;
        $a = @inet_pton($ip); $b = @inet_pton($net); if ($a === false || $b === false) return false;
        $whole = intdiv($bits, 8); $rem = $bits % 8;
        if ($whole > 0 && substr($a, 0, $whole) !== substr($b, 0, $whole)) return false;
        if ($rem === 0) return true;
        $m = (~0 << (8 - $rem)) & 0xFF;
        return (ord($a[$whole]) & $m) === (ord($b[$whole]) & $m);
    }
    return false;   // mixed family → no match
}
/** Orchestrated block: CSF + Cloudflare (per settings), with safety guards. Returns combined result. */
function smpro_im_block_ip($ip, $note = '') {
    if (!filter_var($ip, FILTER_VALIDATE_IP))                                  return ['ok'=>false,'msg'=>'invalid IP'];
    if (function_exists('smpro_is_server_ip') && smpro_is_server_ip($ip))       return ['ok'=>false,'msg'=>'refused: server IP'];
    if (function_exists('smpro_ip_is_external') && !smpro_ip_is_external($ip))  return ['ok'=>false,'msg'=>'refused: private/local IP'];
    if (smpro_im_allowlisted($ip))                                             return ['ok'=>false,'msg'=>'refused: allowlisted'];
    $c = smpro_in_cfg(); $parts = []; $ok = false;
    if (!empty($c['use_csf']))        { $r = smpro_im_csf_block($ip);     $parts[] = 'CSF:' . ($r['ok'] ? 'ok' : $r['msg']); $ok = $ok || $r['ok']; }
    if (!empty($c['use_cloudflare']) && smpro_cf_configured()) { $r = smpro_cf_block_ip($ip, $note); $parts[] = 'CF:' . ($r['ok'] ? 'ok' : $r['msg']); $ok = $ok || $r['ok']; }
    return ['ok'=>$ok,'msg'=>implode(' · ', $parts) ?: 'no blocker enabled'];
}

/* ============================ campaigns / attacker intel ============================ */
function smpro_im_campaigns($events) {
    $byIp = []; $byDom = [];
    foreach ($events as $e) {
        if ($e['ip'] === '') continue;
        $byIp[$e['ip']]['domains'][$e['domain']] = 1; $byIp[$e['ip']]['n'] = ($byIp[$e['ip']]['n'] ?? 0) + 1;
        if ($e['domain'] !== '') $byDom[$e['domain']]['ips'][$e['ip']] = 1;
    }
    $thrIp = (int)smpro_in_cfg()['thr_ip_domains'];
    $distributed = [];
    foreach ($byIp as $ip => $d) { $nd = count($d['domains']); if ($nd >= $thrIp) $distributed[] = ['ip'=>$ip,'domains'=>$nd,'hits'=>$d['n']]; }
    usort($distributed, fn($a, $b) => $b['domains'] <=> $a['domains']);
    $targeted = [];
    foreach ($byDom as $dom => $d) { $ni = count($d['ips']); if ($ni >= 5) $targeted[] = ['domain'=>$dom,'ips'=>$ni]; }
    usort($targeted, fn($a, $b) => $b['ips'] <=> $a['ips']);
    return ['distributed'=>$distributed, 'targeted'=>$targeted];
}
/** Optional AbuseIPDB reputation (0-100), cached best-effort. '' when no key. */
function smpro_im_abuse_score($ip) {
    $c = smpro_in_cfg(); if ($c['abuseipdb_key'] === '' || !filter_var($ip, FILTER_VALIDATE_IP)) return '';
    $url = 'https://api.abuseipdb.com/api/v2/check?' . http_build_query(['ipAddress' => $ip]);
    $res = smpro_http($url, ['timeout' => 8, 'headers' => ['Key: ' . $c['abuseipdb_key'], 'Accept: application/json']]);   // key stays in-process, not in argv
    $j = json_decode($res['body'], true);
    return isset($j['data']['abuseConfidenceScore']) ? (int)$j['data']['abuseConfidenceScore'] : '';
}

/* ============================ breach correlation ============================ */
/**
 * Likely-compromise detection: a domain that received an EXPLOIT-class attack which the
 * server answered with 2xx/3xx AND has PHP files changed very recently in its docroot.
 * Bounded (only domains with a suspicious 200, capped, throttled find).
 */
/** Does a PHP file contain web-shell / obfuscation indicators? (bounded grep, single file) */
function smpro_im_looks_malicious($file) {
    $re = 'eval[[:space:]]*\(|assert[[:space:]]*\(|create_function|gzinflate|gzuncompress|str_rot13|\bshell_exec|\bpassthru|\bproc_open|\bpopen[[:space:]]*\(|\bsystem[[:space:]]*\(|preg_replace[[:space:]]*\([^,]*/e|\$_(POST|GET|REQUEST|COOKIE|SERVER)[[:space:]]*\[[^]]*\][[:space:]]*\(|base64_decode[[:space:]]*\([^)]*\$|move_uploaded_file';
    $cmd = 'timeout 6 grep -lEa ' . escapeshellarg($re) . ' ' . escapeshellarg($file) . ' 2>/dev/null';
    return trim((string)@shell_exec($cmd)) !== '';
}
/** Always-on built-in exclusions: legit security/login plugins routinely contain the SAME dangerous-function
 *  NAMES (eval(, shell_exec(, base64_decode(…) as quoted strings in their own scanners — so a naive regex
 *  false-flags them as web-shells. These are unioned with the admin's breach_exclude so they apply even to
 *  already-saved configs (shipping the build fixes existing installs without the admin editing anything). */
function smpro_im_breach_exclude_seed() {
    return ['imunify-security', 'wordfence', '/wp-content/cache/', '/wp-content/upgrade/', '/wp-content/uploads/cache/',
            'wp-efadh', '/mu-plugins/', 'ithemes-security', 'better-wp-security', 'sucuri', 'wp-security', 'all-in-one-wp-security', 'ninjafirewall'];
}
/** Is a path excluded from breach scanning (legit, frequently-updated security/cache dirs + known plugins)? */
function smpro_im_breach_excluded($path) {
    foreach (array_merge(smpro_im_breach_exclude_seed(), (array)(smpro_in_cfg()['breach_exclude'] ?? [])) as $sub) {
        $sub = trim((string)$sub); if ($sub !== '' && stripos($path, $sub) !== false) return true;
    }
    return false;
}
/** A file carrying a real WordPress plugin header is an admin-installed plugin, not a drive-by web-shell — never
 *  auto-quarantine it (it still gets reported). Real shells don't ship a "Plugin Name:" header; this stops the
 *  whole class of false-positives where a security plugin names dangerous functions in its own signature list. */
function smpro_im_is_wp_plugin($file) {
    $head = (string)@file_get_contents($file, false, null, 0, 8192);
    return $head !== '' && preg_match('/^[ \t\/*#@]*Plugin Name:\s*\S/mi', $head) === 1;
}
/** Count how many INDEPENDENT web-shell indicator families a file trips. A real shell almost always combines several
 *  (e.g. eval(gzinflate(base64_decode(...))) = exec+obfusc); a lone benign match (a stray move_uploaded_file) trips
 *  one. Used to gate UNATTENDED auto-removal behind ≥2 families so a single weak signal never pulls a file by cron. */
function smpro_im_malice_count($file) {
    $fams = [
        'exec'   => 'eval[[:space:]]*\(|assert[[:space:]]*\(|create_function|\bshell_exec|\bpassthru|\bproc_open|\bpopen[[:space:]]*\(|\bsystem[[:space:]]*\(|preg_replace[[:space:]]*\([^,]*/e',
        'obfusc' => 'gzinflate|gzuncompress|str_rot13|base64_decode[[:space:]]*\([^)]*\$',
        'input'  => '\$_(POST|GET|REQUEST|COOKIE|SERVER)[[:space:]]*\[[^]]*\][[:space:]]*\(',
        'upload' => 'move_uploaded_file',
    ];
    $n = 0;
    foreach ($fams as $re) {
        if (trim((string)@shell_exec('timeout 4 grep -lEa ' . escapeshellarg($re) . ' ' . escapeshellarg($file) . ' 2>/dev/null')) !== '') $n++;
    }
    return $n;
}
/**
 * Likely-compromise detection: a domain that received an EXPLOIT-class attack served 2xx/3xx
 * AND has a recently-changed PHP file in its docroot that ALSO contains web-shell indicators.
 * Legit auto-updating paths (Imunify WP plugin, caches) are excluded — so Imunify's own
 * rules.php no longer false-flags. Bounded + throttled.
 */
function smpro_im_breaches($events, $changedWithinMin = 60, $maxDomains = 25) {
    $suspect = [];
    foreach ($events as $e) {
        if ($e['domain'] === '' || !smpro_im_exploit_kind($e['kind'])) continue;
        $code = (int)$e['code'];
        if ($code >= 200 && $code < 400) {
            $suspect[$e['domain']]['kind'][$e['kind']] = 1;
            $suspect[$e['domain']]['ips'][$e['ip']] = 1;
            $suspect[$e['domain']]['last'] = max($suspect[$e['domain']]['last'] ?? 0, (int)$e['ts']);
        }
    }
    $out = []; $scanned = 0;
    foreach ($suspect as $dom => $s) {
        if ($scanned++ >= $maxDomains) break;
        $acct = smpro_im_account_for($dom); if ($acct === '') continue;
        $bad = [];
        foreach (smpro_im_docroots($acct) as $root) {
            $cmd = 'timeout 14 nice -n ' . SMPRO_SCAN_NICE . ' ionice -c3 find ' . escapeshellarg($root)
                 . ' -maxdepth 6 -type f \\( -name "*.php" -o -name "*.phtml" \\) -mmin -' . (int)$changedWithinMin . ' 2>/dev/null | head -n 60';
            foreach (array_filter(explode("\n", (string)@shell_exec($cmd))) as $f) {
                if (smpro_im_breach_excluded($f)) continue;          // skip Imunify WP plugin, caches, etc.
                if (smpro_im_is_wp_plugin($f)) continue;             // admin-installed plugin (Plugin Name header) → not a drive-by shell
                if (smpro_im_looks_malicious($f)) $bad[] = $f;        // only count files that look like a web-shell
                if (count($bad) >= 12) break;
            }
            if (count($bad) >= 12) break;
        }
        // confirmed compromise only when a recently-changed file actually looks malicious
        if ($bad) $out[] = ['domain'=>$dom,'account'=>$acct,'kinds'=>array_keys($s['kind']),'ips'=>array_keys($s['ips']),'last'=>$s['last'] ?? 0,'changed'=>array_slice($bad, 0, 12)];
    }
    return $out;
}

/* ============================ full attack analysis report ============================ */
function smpro_im_path_of($uri) { $p = (string)parse_url((string)$uri, PHP_URL_PATH); return $p !== '' ? $p : (string)$uri; }
function smpro_im_subnet24($ip) { return preg_match('/^(\d+\.\d+\.\d+)\.\d+$/', (string)$ip, $m) ? $m[1] . '.0/24' : ''; }
/**
 * Comprehensive attack analysis from a set of events: most-targeted PATHS, top source IPs
 * (with their main target + distinct User-Agent count), COORDINATED campaigns (IPs sharing a
 * /24 subnet = likely botnet), UA-ROTATION (one IP cycling many User-Agents to dodge blocks),
 * and attack PHASES (remote-exploit → brute-force → spam).
 */
function smpro_im_attack_analysis($events) {
    $paths = []; $ips = []; $subnets = [];
    $phases = ['Remote exploit (xmlrpc/RPC)'=>0,'Brute force (login)'=>0,'Exploit (SQLi/RCE/LFI)'=>0,'Sensitive-file probing'=>0,'Scanner / recon'=>0,'Spam / content (POST 2xx)'=>0,'Other WAF blocks'=>0];
    foreach ($events as $e) {
        $path = smpro_im_path_of($e['uri'] ?? ''); $ip = (string)($e['ip'] ?? ''); $kind = (string)($e['kind'] ?? '');
        if ($path !== '') { if (!isset($paths[$path])) $paths[$path] = ['path'=>$path,'n'=>0,'ips'=>[]]; $paths[$path]['n']++; if ($ip !== '') $paths[$path]['ips'][$ip] = 1; }
        if ($ip !== '') {
            if (!isset($ips[$ip])) $ips[$ip] = ['ip'=>$ip,'n'=>0,'paths'=>[],'uas'=>[]];
            $ips[$ip]['n']++; if ($path !== '') $ips[$ip]['paths'][$path] = ($ips[$ip]['paths'][$path] ?? 0) + 1;
            if (!empty($e['ua'])) $ips[$ip]['uas'][$e['ua']] = 1;
            $sn = smpro_im_subnet24($ip); if ($sn !== '') { if (!isset($subnets[$sn])) $subnets[$sn] = ['subnet'=>$sn,'ips'=>[],'n'=>0]; $subnets[$sn]['ips'][$ip] = 1; $subnets[$sn]['n']++; }
        }
        $pl = strtolower($path . ' ' . $kind);
        if (strpos($pl,'xmlrpc') !== false || strpos($pl,'/rpc') !== false || strpos($pl,'jsonrpc') !== false) $phases['Remote exploit (xmlrpc/RPC)']++;
        elseif (strpos($pl,'wp-login') !== false || strpos($pl,'/login') !== false || strpos($pl,'wp-admin') !== false || strpos($kind,'Brute') !== false) $phases['Brute force (login)']++;
        elseif (smpro_im_exploit_kind($kind)) $phases['Exploit (SQLi/RCE/LFI)']++;
        elseif (strpos($kind,'Sensitive') !== false || strpos($pl,'.env') !== false || strpos($pl,'.git') !== false) $phases['Sensitive-file probing']++;
        elseif (strpos($kind,'Scanner') !== false) $phases['Scanner / recon']++;
        elseif (($e['method'] ?? '') === 'POST' && (int)($e['code'] ?? 0) >= 200 && (int)($e['code'] ?? 0) < 300) $phases['Spam / content (POST 2xx)']++;
        else $phases['Other WAF blocks']++;
    }
    foreach ($paths as &$p) { $p['uniq_ips'] = count($p['ips']); unset($p['ips']); } unset($p);
    foreach ($ips as &$x) { arsort($x['paths']); $x['top_path'] = $x['paths'] ? array_key_first($x['paths']) : ''; $x['ua_count'] = count($x['uas']); unset($x['uas']); } unset($x);
    foreach ($subnets as &$s) { $s['uniq_ips'] = count($s['ips']); unset($s['ips']); } unset($s);
    uasort($paths, fn($a,$b)=>$b['n']<=>$a['n']);
    uasort($ips, fn($a,$b)=>$b['n']<=>$a['n']);
    $camp = array_values(array_filter($subnets, fn($s)=>$s['uniq_ips']>=3)); usort($camp, fn($a,$b)=>$b['uniq_ips']<=>$a['uniq_ips']);
    $rot = array_values(array_filter($ips, fn($x)=>$x['ua_count']>=4)); usort($rot, fn($a,$b)=>$b['ua_count']<=>$a['ua_count']);
    return ['total'=>count($events),'paths'=>array_slice(array_values($paths),0,40),'attackers'=>array_slice(array_values($ips),0,80),
            'campaigns'=>array_slice($camp,0,40),'rotators'=>array_slice($rot,0,25),'phases'=>array_filter($phases)];
}

/* ============================ attacker intel + AI block decision ============================ */
/** Rank attacker IPs from a set of events, enriched with geo/provider/bot for display + decisions. */
function smpro_im_offenders($events, $limit = 25) {
    $o = [];
    foreach ($events as $e) {
        if (($e['ip'] ?? '') === '') continue;
        $ip = $e['ip'];
        if (!isset($o[$ip])) $o[$ip] = ['ip'=>$ip,'hits'=>0,'domains'=>[],'cats'=>[],'sev'=>0,'last'=>0];
        $o[$ip]['hits']++;
        if (($e['domain'] ?? '') !== '') $o[$ip]['domains'][$e['domain']] = 1;
        $o[$ip]['cats'][$e['kind']] = ($o[$ip]['cats'][$e['kind']] ?? 0) + 1;
        $r = smpro_im_sev_rank($e['severity'] ?? ''); if ($r > $o[$ip]['sev']) $o[$ip]['sev'] = $r;
        if (($e['ts'] ?? 0) > $o[$ip]['last']) $o[$ip]['last'] = (int)$e['ts'];
    }
    uasort($o, fn($a, $b) => $b['hits'] <=> $a['hits']);
    $res = [];
    foreach (array_slice($o, 0, $limit, true) as $ip => $d) {
        $in = function_exists('smpro_ip_intel') ? smpro_ip_intel($ip, false) : [];
        $res[] = ['ip'=>$ip,'hits'=>$d['hits'],'domains'=>count($d['domains']),'cats'=>array_keys($d['cats']),
                  'country'=>strtoupper((string)($in['country'] ?? '')),'provider'=>(string)($in['provider'] ?? ''),
                  'asn'=>(string)($in['asn'] ?? ''),'bot'=>(function_exists('smpro_ip_is_datacenter') && smpro_ip_is_datacenter($in)) ? 1 : 0,'last'=>$d['last']];
    }
    return $res;
}
/** Ask the configured AI to decide which attacker IPs to block (applies SOC conditions). */
function smpro_im_ai_block_decide($offenders) {
    if (!function_exists('smpro_ai_available') || !smpro_ai_available()) return ['ok'=>false,'block'=>[],'keep'=>[],'reason'=>'No AI provider configured.'];
    if (!$offenders) return ['ok'=>true,'block'=>[],'keep'=>[],'reason'=>'No attackers to evaluate.'];
    $lines = [];
    foreach ($offenders as $o) $lines[] = $o['ip'] . ' | hits=' . $o['hits'] . ' domains=' . $o['domains'] . ' types=' . implode(',', $o['cats']) . ' geo=' . ($o['country'] ?: '?') . '/' . ($o['provider'] ?: '?') . ($o['bot'] ? ' [datacenter]' : '');
    $sys = "You are a SOC analyst protecting a cPanel/WHM shared-hosting server's WAF. Decide which attacker IPs to BLOCK in the firewall. BLOCK clear web attacks: SQL injection, RCE/command injection, LFI/path traversal, sensitive-file/.env probing, malicious uploads, and high-volume scanners hitting many domains (especially datacenter networks). KEEP (do not block) likely-legitimate traffic: genuine search-engine crawlers from their real ASNs (Google/Bing/etc.), single low-count hits that may be false positives, and known monitoring/uptime services."
         . " HOME-REGION POLICY (critical): the operator's customers are mostly in Egypt (EG) and Saudi Arabia (SA). For a RESIDENTIAL (non-datacenter) IP geolocated in EG or SA, DO NOT block — instead put it in \"review\" for manual approval, even if it looks suspicious (it is most likely a compromised legitimate customer device, not an attacker to firewall). For RESIDENTIAL IPs in other Arab countries, block ONLY when the attack is clear and repeated (multiple distinct attack types or high hit counts); otherwise put them in \"review\". DATACENTER/hosting IPs from ANY country (including EG/SA) follow the normal attack rules above — block them when they attack. Each line is tagged with geo=COUNTRY/provider and [datacenter] when it is a hosting network."
         . " Be decisive but conservative about collateral damage. Respond with ONLY strict JSON, no prose: {\"block\":[\"ip\",...],\"keep\":[\"ip\",...],\"review\":[\"ip\",...],\"reason\":\"one short paragraph\"}";
    $user = "Attacker IPs observed on the WAF (decide which to block):\n" . implode("\n", $lines);
    $r = function_exists('smpro_ai_chat_json')
        ? smpro_ai_chat_json($sys, $user, ['max_tokens'=>800,'context'=>'intrusion_block'])
        : smpro_ai_chat($sys, $user, ['max_tokens'=>800,'context'=>'intrusion_block']);
    if (empty($r['ok'])) return ['ok'=>false,'block'=>[],'keep'=>[],'reason'=>$r['error'] ?? 'AI request failed'];
    $j = $r['data'] ?? (function_exists('smpro_ai_json') ? smpro_ai_json((string)($r['text'] ?? '')) : null);
    if (!is_array($j)) return ['ok'=>false,'block'=>[],'keep'=>[],'reason'=>'The AI was busy or replied without a clear decision — try again.','raw'=>$r['text'] ?? ''];
    $block = array_values(array_filter(array_map('trim', (array)($j['block'] ?? [])), fn($ip) => filter_var($ip, FILTER_VALIDATE_IP)));
    $review = array_values(array_filter(array_map('trim', (array)($j['review'] ?? [])), fn($ip) => filter_var($ip, FILTER_VALIDATE_IP)));
    // Safety net: enforce home-region policy in code regardless of what the model returned.
    $hitsOf = []; foreach ($offenders as $o) $hitsOf[$o['ip']] = ['hits'=>(int)$o['hits'],'cats'=>count((array)($o['cats'] ?? []))];
    $keepBlock = [];
    foreach ($block as $ip) {
        $rs = smpro_im_region_status($ip);
        if ($rs === 'core_protected') { $review[] = $ip; continue; }          // EG/SA residential → manual review, never auto-block
        if ($rs === 'arab_caution') {
            $h = $hitsOf[$ip] ?? ['hits'=>0,'cats'=>0];
            if ($h['hits'] < 5 && $h['cats'] < 2) { $review[] = $ip; continue; } // not clear & repeated → review
        }
        $keepBlock[] = $ip;
    }
    $block = array_values(array_unique($keepBlock));
    $review = array_values(array_unique($review));
    return ['ok'=>true,'block'=>$block,'keep'=>array_values((array)($j['keep'] ?? [])),'review'=>$review,'reason'=>(string)($j['reason'] ?? ''),'provider'=>$r['provider'] ?? ''];
}
/**
 * Does an event count as a genuine attack FROM the server itself / a local process?
 * ANY internal source (loopback ::1/127.0.0.1, private LAN, or the server's own public IP)
 * legitimately makes internal HTTP (wp-cron, cache warmers, health checks, cPanel internals,
 * monitoring) that trips GENERIC WAF rules — those are NOT attacks. A local COMPROMISE shows up
 * as real exploit-class traffic, so:
 *   - flag ONLY real exploit-class kinds (SQLi/RCE/RFI/LFI/PHP-inj/upload), for every internal source;
 *   - never flag wp-cron or generic "WAF Block (other)" noise (e.g. a single ::1 hit).
 */
function smpro_im_is_self_attack($ip, $kind, $uri) {
    if ($ip === '') return false;
    $isServer  = function_exists('smpro_is_server_ip') && smpro_is_server_ip($ip);
    $isPrivate = function_exists('smpro_ip_is_external') && !smpro_ip_is_external($ip);
    if (!$isServer && !$isPrivate) return false;                       // not self / local at all
    if (stripos((string)$uri, 'wp-cron.php') !== false) return false;  // WordPress scheduler = benign
    if (!smpro_im_exploit_kind((string)$kind)) return false;           // internal sources: real exploits only (no generic WAF noise)
    return true;
}
/** Recent GENUINE attacks whose source is the server's own/local IP (possible local compromise). */
function smpro_im_selfattack_recent($hours = 6, $limit = 40) {
    $db = smpro_in_db(); if (!$db) return [];
    $st = $db->prepare('SELECT ip, domain, kind, uri, ts FROM attacks WHERE ts >= ? ORDER BY ts DESC LIMIT 1200');
    $st->execute([time() - (int)$hours * 3600]);
    $out = [];
    foreach (($st->fetchAll(PDO::FETCH_ASSOC) ?: []) as $r) {
        $ip = (string)$r['ip'];
        if (!smpro_im_is_self_attack($ip, (string)$r['kind'], (string)$r['uri'])) continue;
        if (!isset($out[$ip])) $out[$ip] = ['ip'=>$ip,'n'=>0,'domains'=>[],'kind'=>$r['kind'],'last'=>0];
        $out[$ip]['n']++; $out[$ip]['domains'][$r['domain']] = 1; $out[$ip]['last'] = max($out[$ip]['last'], (int)$r['ts']);
        if (count($out) >= $limit) break;
    }
    foreach ($out as &$o) $o['domains'] = count($o['domains']); unset($o);
    return array_values($out);
}

/* ============================ EMERGENCY auto-response (harden + clean) ============================ */
function smpro_im_em_manifest_load() { $d = is_file(SMPRO_IM_EMLOG) ? json_decode((string)@file_get_contents(SMPRO_IM_EMLOG), true) : null; return is_array($d) ? $d : []; }
function smpro_im_em_manifest_save($m) { @is_dir(dirname(SMPRO_IM_EMLOG)) || @mkdir(dirname(SMPRO_IM_EMLOG), 0700, true); $t = SMPRO_IM_EMLOG . '.tmp'; @file_put_contents($t, json_encode(array_slice($m, -1000), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), LOCK_EX); @chmod($t, 0600); @rename($t, SMPRO_IM_EMLOG); }
function smpro_im_has_chattr() { return function_exists('smpro_has_bin') ? smpro_has_bin('chattr') : is_executable('/usr/bin/chattr'); }
/** The exact hardening block prepended to upload-dir .htaccess. Shared so undo can strip PRECISELY what it added. */
function smpro_im_harden_rule() {
    return "# smpro Emergency hardening — block script execution (added by Intrusion Monitor)\n"
         . "<FilesMatch \"\\.(?:php|phtml|php[0-9]|phps|pht|pl|py|cgi|asp|aspx|sh)$\">\n  Require all denied\n  SetHandler none\n</FilesMatch>\n"
         . "php_flag engine off\nOptions -ExecCGI\n";
}

/** Disable script execution in shell-upload-prone dirs + lock core files. Reversible; backs up. */
function smpro_im_harden_site($account, $dryrun = false) {
    $actions = []; $chattr = smpro_im_has_chattr();
    $rule = smpro_im_harden_rule();
    foreach (smpro_im_docroots($account) as $root) {
        foreach (['wp-content/uploads', 'wp-content/cache', 'wp-content/upgrade', 'wp-includes/uploads', 'uploads', 'images', 'img', 'media', 'files', 'cache', 'tmp', 'temp'] as $sub) {
            $d = $root . '/' . $sub; if (!is_dir($d)) continue;
            $ht = $d . '/.htaccess'; $cur = is_file($ht) ? (string)@file_get_contents($ht) : '';
            if (strpos($cur, 'smpro Emergency hardening') !== false) continue;        // already hardened
            if (!$dryrun) {
                $uid = @fileowner($d); $gid = @filegroup($d);                          // own as the cPanel account, NOT root
                if ($cur !== '') { @copy($ht, $ht . '.smprobak'); if ($uid !== false) { @chown($ht . '.smprobak', $uid); @chgrp($ht . '.smprobak', $gid); } }
                @file_put_contents($ht, $rule . $cur); @chmod($ht, 0644);
                if ($uid !== false) { @chown($ht, $uid); @chgrp($ht, $gid); }            // match the surrounding files (the account user)
                if ($chattr) @shell_exec('chattr +i ' . escapeshellarg($ht) . ' 2>/dev/null'); // immutable: a compromised account can't strip it
            }
            $actions[] = ['type' => 'php_off', 'path' => $ht, 'had' => $cur !== ''];
        }
        $isWp = is_file($root . '/wp-load.php');
        $core = $isWp ? ['wp-config.php', '.htaccess', 'index.php', 'wp-load.php', 'wp-settings.php', 'wp-blog-header.php', 'wp-config-sample.php']
                      : ['index.php', '.htaccess', 'config.php', 'configuration.php', 'wp-config.php'];
        foreach ($core as $cf) {
            $f = $root . '/' . $cf; if (!is_file($f)) continue;
            $perm = @fileperms($f) & 0777;
            if (!$dryrun) { @chmod($f, 0444); if ($chattr) @shell_exec('chattr +i ' . escapeshellarg($f) . ' 2>/dev/null'); }
            $actions[] = ['type' => 'lock', 'path' => $f, 'perm' => $perm, 'chattr' => $chattr];
        }
    }
    return $actions;
}
/** Move a malicious file out of the web tree into quarantine (backed up, restorable). */
function smpro_im_quarantine_file($file, $account, $dryrun = false) {
    if (!is_file($file)) return null;
    if ($dryrun) return ['type' => 'quarantine', 'path' => $file, 'dryrun' => true];
    $acct = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)$account) ?: 'unknown';
    $qdir = SMPRO_IM_QUAR . '/' . $acct; @is_dir($qdir) || @mkdir($qdir, 0700, true);
    $dest = $qdir . '/' . date('Ymd_His') . '_' . substr(sha1($file), 0, 8) . '_' . basename($file);
    @copy($file, $dest . '.bak');                                   // keep a copy for review/restore
    if (smpro_im_has_chattr()) @shell_exec('chattr -i ' . escapeshellarg($file) . ' 2>/dev/null');
    @chmod($file, 0600);
    $moved = @rename($file, $dest);                                  // remove from the web tree (preserves the original at $dest)
    if (!$moved) {
        // M5 FIX — rename failed (e.g. cross-device EXDEV, disk full). Only neutralize in place if a VERIFIED non-empty
        // backup exists; otherwise stubbing would overwrite the ONLY copy of a possibly-false-positive file with no way
        // to restore. No backup → leave the file untouched and report failure so the caller does not record a "cleaned".
        if (@filesize($dest . '.bak') > 0) { @file_put_contents($file, "<?php /* quarantined by smpro Intrusion Monitor */\n"); }
        else { return ['type' => 'quarantine', 'path' => $file, 'stored' => '', 'backup' => '', 'error' => 'no-backup']; }
    }
    return ['type' => 'quarantine', 'path' => $file, 'backup' => $dest . '.bak', 'stored' => $moved ? $dest : ''];
}
/** Quarantine recently-changed PHP files that look like web-shells (skips legit/excluded paths). */
function smpro_im_clean_site($account, $withinMin = 1440, $dryrun = false, $max = 40, $strict = false) {
    $cleaned = [];
    foreach (smpro_im_docroots($account) as $root) {
        $cmd = 'timeout 18 nice -n ' . SMPRO_SCAN_NICE . ' ionice -c3 find ' . escapeshellarg($root)
             . ' -maxdepth 7 -type f \\( -name "*.php" -o -name "*.phtml" -o -name "*.pht" \\) -mmin -' . (int)$withinMin . ' 2>/dev/null | head -n 300';
        foreach (array_filter(explode("\n", (string)@shell_exec($cmd))) as $f) {
            if (smpro_im_breach_excluded($f) || !smpro_im_looks_malicious($f)) continue;
            if (smpro_im_is_wp_plugin($f)) continue;                 // legit admin-installed plugin (has Plugin Name header) → never auto-quarantine
            // M6 FIX — on the UNATTENDED (cron) path require ≥2 independent indicator families before pulling a file
            // from the live web tree; a lone weak match stays REPORTED, not auto-removed. Manual cleans pass strict=false.
            if ($strict && smpro_im_malice_count($f) < 2) continue;
            $r = smpro_im_quarantine_file($f, $account, $dryrun); if ($r) $cleaned[] = $r;
            if (count($cleaned) >= $max) break 2;
        }
    }
    return $cleaned;
}
/** Any recently-changed PHP in an account's docroots (the emergency TRIGGER: attacked + files changed). */
function smpro_im_recent_changed($account, $withinMin = 1440, $cap = 5) {
    $n = 0;
    foreach (smpro_im_docroots($account) as $root) {
        $cmd = 'timeout 12 nice -n ' . SMPRO_SCAN_NICE . ' ionice -c3 find ' . escapeshellarg($root)
             . ' -maxdepth 7 -type f \\( -name "*.php" -o -name "*.phtml" \\) -mmin -' . (int)$withinMin . ' 2>/dev/null | head -n ' . (int)$cap;
        foreach (array_filter(explode("\n", (string)@shell_exec($cmd))) as $f) { if (!smpro_im_breach_excluded($f)) $n++; }
        if ($n >= $cap) break;
    }
    return $n;
}
/* ---- clear-malicious scanner detection (credential probes / bare-IP scans) ---- */
/** True if the request path is a credential/secret-file probe — no legitimate visitor ever requests these. */
function smpro_im_is_secret_probe($uri) {
    $u = strtolower((string)$uri);
    if ($u === '') return false;
    static $needles = ['/.aws/', '/.aws/credentials', '/.aws/config', '/.gcloud/', '/.config/gcloud',
        '/.azure/', '/.credentials', '/credentials.json', '/credentials.db', '/.env', '/.git/config',
        '/.ssh/', '/id_rsa', '/.npmrc', '/.s3cfg', '/.docker/config', '/secrets', '/.htpasswd',
        '/.bash_history', '/wp-config.php.', '/.dockercfg', '/.kube/config', '/server.key', '/.travis.yml', '/.circleci'];
    foreach ($needles as $n) if (strpos($u, $n) !== false) return true;
    return false;
}
/** True if the Host targets the server's OWN bare IP / rDNS — no real visitor or hosted site uses this; only bots scanning the raw IP. */
function smpro_im_is_bareip_host($host) {
    $host = strtolower(trim((string)$host));
    if ($host === '') return false;
    if (filter_var($host, FILTER_VALIDATE_IP)) return true;                          // Host is a literal IP
    if ($host === strtolower((string)@php_uname('n'))) return true;                  // Host is the server hostname
    $ips = function_exists('smpro_server_ips') ? array_keys(smpro_server_ips()) : [];
    foreach ($ips as $ip) {
        if (strpos($ip, '.') === false) continue;                                    // IPv4 only for the rDNS trick
        if (strpos($host, $ip) !== false) return true;                               // Host contains a server IP
        $rev = implode('.', array_reverse(explode('.', $ip)));                       // reversed-octet rDNS (….16.134.63.178.clients.your-server.de)
        if ($rev !== $ip && strpos($host, $rev) !== false) return true;
    }
    return false;
}
/**
 * Auto-block clear malicious scanners across the whole server (part of Emergency). High-confidence only:
 * an IP that probes credential/secret files (≥3) OR hammers the server's bare IP/rDNS (≥8) — both near-zero
 * false-positive. Honors allowlist / never-block-self guards, dry-run, and a 6h per-IP cooldown. Reversible
 * via CSF (the same Unblock used everywhere). Returns the list for the admin alert.
 */
/**
 * True only for a LEGITIMATE search-engine crawler, proven by forward-confirmed reverse DNS
 * (rDNS host ends in a known crawler domain AND that host resolves back to the same IP).
 * Note: Google CLOUD VMs (*.bc.googleusercontent.com) are NOT crawlers — they do NOT match, so
 * rented-VM scanners are still blocked. Real Googlebot is *.googlebot.com / 66.249.x (forward-confirmed).
 */
function smpro_im_is_verified_crawler($ip) {
    static $cache = [];
    if (isset($cache[$ip])) return $cache[$ip];
    $cache[$ip] = false;
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return false;
    $rdns = (string)@shell_exec('timeout 3 host ' . escapeshellarg($ip) . ' 2>/dev/null');
    if (!preg_match('/(?:pointer|name)\s+(\S+?)\.?\s*$/im', $rdns, $m)) return false;
    $host = strtolower($m[1]);
    // known legitimate crawler domains (Google search, Bing, Yahoo, DuckDuckGo, Apple, Yandex, Baidu)
    if (!preg_match('/\.(googlebot\.com|google\.com|search\.msn\.com|crawl\.yahoo\.net|duckduckgo\.com|applebot\.apple\.com|yandex\.(?:com|ru|net)|crawl\.baidu\.com)$/', $host)) return false;
    // forward-confirm: the crawler hostname must resolve back to THIS ip
    $fwd = (string)@shell_exec('timeout 3 host ' . escapeshellarg($host) . ' 2>/dev/null');
    $cache[$ip] = (strpos($fwd, ' ' . $ip) !== false) || (bool)preg_match('/\b' . preg_quote($ip, '/') . '\b/', $fwd);
    return $cache[$ip];
}

function smpro_im_emergency_block_scanners($events, $dryrun = false) {
    $cand = [];
    foreach ($events as $e) {
        $ip = (string)($e['ip'] ?? ''); if ($ip === '') continue;
        $probe = smpro_im_is_secret_probe($e['uri'] ?? '');
        $bare  = smpro_im_is_bareip_host($e['domain'] ?? '');
        if (!$probe && !$bare) continue;
        if (!isset($cand[$ip])) $cand[$ip] = ['probe' => 0, 'bare' => 0, 'uas' => []];
        if ($probe) $cand[$ip]['probe']++;
        if ($bare)  $cand[$ip]['bare']++;
        $ua = trim((string)($e['ua'] ?? '')); if ($ua !== '') $cand[$ip]['uas'][$ua] = 1;
    }
    // worst first, and cap per run so a wide manual window doesn't fire hundreds of CSF calls synchronously
    uasort($cand, fn($a, $b) => ($b['probe'] + $b['bare']) <=> ($a['probe'] + $a['bare']));
    $st = smpro_in_state(); $done = $st['emergency_blocked'] ?? []; $now = time(); $out = []; $cap = 50;
    foreach ($cand as $ip => $c) {
        if (count($out) >= $cap) break;
        if ($c['probe'] < 3 && $c['bare'] < 8) continue;                             // high-confidence threshold
        if (isset($done[$ip]) && ($now - (int)$done[$ip]) < 6 * 3600) continue;      // 6h cooldown
        if (!filter_var($ip, FILTER_VALIDATE_IP)) continue;
        if (function_exists('smpro_ip_is_external') && !smpro_ip_is_external($ip)) continue;
        if (function_exists('smpro_is_server_ip') && smpro_is_server_ip($ip)) continue;
        if (smpro_im_allowlisted($ip)) continue;
        if (smpro_im_is_verified_crawler($ip)) continue;                             // never block a verified search crawler (Googlebot/Bing/…)
        $rs = smpro_im_region_status($ip);
        if ($rs === 'core_protected') continue;                                      // EG/SA residential: never auto-block (manual review only)
        if ($rs === 'arab_caution' && $c['probe'] < 5 && $c['bare'] < 12) continue;  // other Arab residential: only on clear, repeated abuse
        $why = $c['probe'] >= 3
            ? 'credential/secret probing (' . $c['probe'] . ' hits' . (count($c['uas']) >= 4 ? ', ' . count($c['uas']) . ' rotating UAs' : '') . ')'
            : 'scanning the bare server IP (' . $c['bare'] . ' hits' . (count($c['uas']) >= 4 ? ', ' . count($c['uas']) . ' rotating UAs' : '') . ')';
        if (!$dryrun) {
            $r = smpro_im_block_ip($ip, 'emergency/scanner: ' . $why);
            if ($r['ok']) $done[$ip] = $now;
            $out[] = ['ip' => $ip, 'reason' => $why, 'ok' => $r['ok'], 'msg' => $r['msg']];
        } else {
            $out[] = ['ip' => $ip, 'reason' => $why . ' (dry-run)', 'ok' => true, 'msg' => 'dry-run'];
        }
    }
    if ($out && !$dryrun) { $st['emergency_blocked'] = array_slice($done, -1000, 1000, true); smpro_in_state_save($st); }
    return $out;
}

/** Build the grouped scanner-block digest alert (INFO): summarised by /24 subnet, campaign-aware. */
function smpro_im_scanner_digest($ipsMap) {
    $n = count($ipsMap);
    $subnets = [];
    foreach (array_keys($ipsMap) as $ip) { $s = function_exists('smpro_im_subnet24') ? smpro_im_subnet24($ip) : $ip; if ($s === '') $s = $ip; $subnets[$s][] = $ip; }
    uasort($subnets, fn($a, $b) => count($b) <=> count($a));
    $lines = []; $shown = 0; $multi = 0;
    foreach ($subnets as $sub => $ips) { if (count($ips) >= 3) $multi++; if ($shown < 15) { $lines[] = '• ' . $sub . ' — ' . count($ips) . ' IP(s)'; $shown++; } }
    $body = $n . ' malicious scanner IP(s) were auto-blocked in the last window (credential/.env harvesting + bare-IP probing — mostly rented datacenter / cloud VMs with rotating User-Agents).'
          . "\nThis is ROUTINE automated defense — no action needed. Verified search-engine crawlers (Googlebot etc.) are never blocked."
          . ($multi ? "\n\nCoordinated /24 subnets (>=3 IPs each): " . $multi : '')
          . "\n\nTop source subnets:\n" . implode("\n", $lines)
          . "\n\nFull list + restore: Intrusion Monitor -> Emergency.";
    return [
        'sig'     => 'emblk:' . substr(md5(implode(',', array_keys($ipsMap))), 0, 12),
        'subject' => 'Auto-blocked ' . $n . ' malicious scanner IP(s) [digest]',
        'body'    => $body,
    ];
}

/**
 * EMERGENCY run: for each site that is under an exploit-class attack AND has recently-changed files,
 * quarantine any web-shells found and harden upload dirs + core files, then record (reversible) and
 * return a summary for the admin alert. Per-account 1h cooldown. Honors dry-run.
 * Also (when emergency_block_scanners is on) auto-blocks clear malicious scanners server-wide.
 */
function smpro_im_emergency_run($events, $dryrunOverride = null) {
    $cfg = smpro_in_cfg();
    $dryrun = $dryrunOverride !== null ? (bool)$dryrunOverride : !empty($cfg['emergency_dryrun']);
    if (function_exists('smpro_ctl_dry_run') && smpro_ctl_dry_run()) $dryrun = true;   // global Dry-Run forces report-only
    $attacked = [];
    foreach ($events as $e) if ($e['domain'] !== '' && smpro_im_exploit_kind($e['kind'])) $attacked[$e['domain']] = ($attacked[$e['domain']] ?? 0) + 1;
    arsort($attacked);
    // server-wide: auto-block clear malicious scanners (credential probes / bare-IP scans) — runs even when no site files changed
    $blocked = !empty($cfg['emergency_block_scanners']) ? smpro_im_emergency_block_scanners($events, $dryrun) : [];
    if ($blocked && !$dryrun && function_exists('smpro_audit')) {
        $okIps = array_column(array_filter($blocked, fn($b) => $b['ok']), 'ip');
        if ($okIps) smpro_audit('intrusion_emergency', ['scanners_blocked' => $okIps]);
    }
    $st = smpro_in_state(); $cool = $st['emergency_done'] ?? []; $now = time();
    $man = smpro_im_em_manifest_load(); $hardened = []; $cleaned = []; $seen = 0;
    foreach (array_keys($attacked) as $dom) {
        if ($seen++ >= 30) break;
        $acct = smpro_im_account_for($dom); if ($acct === '') continue;
        if (isset($cool[$acct]) && ($now - (int)$cool[$acct]) < 3600) continue;     // 1h cooldown per account
        if (smpro_im_recent_changed($acct, 1440, 1) < 1) continue;                  // trigger: files actually changed
        $cool[$acct] = $now;
        $c = !empty($cfg['emergency_clean'])  ? smpro_im_clean_site($acct, 1440, $dryrun, 40, true) : [];   // unattended → strict (≥2 indicator families)
        $h = !empty($cfg['emergency_harden']) ? smpro_im_harden_site($acct, $dryrun)      : [];
        if ($c) $cleaned[]  = ['domain' => $dom, 'account' => $acct, 'files' => $c];
        if ($h) $hardened[] = ['domain' => $dom, 'account' => $acct, 'n' => count($h)];
        if (($c || $h) && !$dryrun) {
            $man[] = ['id' => date('Ymd_His') . '_' . substr(sha1($acct . $now), 0, 6), 'ts' => $now, 'account' => $acct, 'domain' => $dom, 'actions' => array_merge($h, $c)];
            if (function_exists('smpro_audit')) smpro_audit('intrusion_emergency', ['account' => $acct, 'domain' => $dom, 'cleaned' => count($c), 'hardened' => count($h)]);
        }
    }
    $st['emergency_done'] = array_slice($cool, -500, 500, true); smpro_in_state_save($st);
    if (($hardened || $cleaned) && !$dryrun) smpro_im_em_manifest_save($man);
    return ['hardened' => $hardened, 'cleaned' => $cleaned, 'blocked' => $blocked, 'dryrun' => $dryrun];
}
/** Reverse one emergency manifest entry: un-lock core files, restore upload .htaccess, restore quarantined files. */
function smpro_im_emergency_undo($id) {
    $id = preg_replace('/[^0-9A-Za-z_]/', '', (string)$id); if ($id === '') return false;
    $man = smpro_im_em_manifest_load(); $keep = []; $done = false;
    foreach ($man as $e) {
        if (($e['id'] ?? '') !== $id) { $keep[] = $e; continue; }
        $done = true;
        foreach (($e['actions'] ?? []) as $a) {
            $p = $a['path'] ?? '';
            if ($a['type'] === 'lock' && $p) { if (smpro_im_has_chattr()) @shell_exec('chattr -i ' . escapeshellarg($p) . ' 2>/dev/null'); @chmod($p, ($a['perm'] ?? 0644) ?: 0644); }
            elseif ($a['type'] === 'php_off' && $p) {
                if (smpro_im_has_chattr()) @shell_exec('chattr -i ' . escapeshellarg($p) . ' 2>/dev/null');
                if (!empty($a['had']) && is_file($p . '.smprobak')) { @rename($p . '.smprobak', $p); }   // restore the owner's original
                elseif (is_file($p)) {
                    // m4 FIX — we CREATED this file (had=false). Only delete it if it is still EXACTLY our block; if the
                    // owner appended their own rules after ours, strip just our prefix and KEEP theirs (never delete owner content).
                    $cur = (string)@file_get_contents($p); $rule = smpro_im_harden_rule();
                    if (trim($cur) === trim($rule)) { @unlink($p); }
                    elseif (strpos($cur, $rule) === 0) { $rest = substr($cur, strlen($rule)); if (trim($rest) === '') { @unlink($p); } else { @file_put_contents($p, $rest); @chmod($p, 0644); } }
                    // else: file no longer begins with our block (owner rewrote it entirely) → leave it untouched
                }
            }
            elseif ($a['type'] === 'quarantine' && $p) {
                if (smpro_im_has_chattr()) @shell_exec('chattr -i ' . escapeshellarg($p) . ' 2>/dev/null');
                if (!empty($a['stored']) && is_file($a['stored'])) { @rename($a['stored'], $p); }      // moved copy → back to original
                elseif (!empty($a['backup']) && is_file($a['backup'])) { @copy($a['backup'], $p); }     // fallback: restore from the .bak copy
                @chmod($p, 0644);
            }
        }
    }
    if ($done) smpro_im_em_manifest_save($keep);
    return $done;
}

/* ============================ real-time alert scan (cron) ============================ */
/**
 * Called by the notify cron. Ingests recent attacks, then returns alert items for NEW
 * conditions in the window. Optionally auto-blocks the worst offenders. The notify layer
 * turns the returned items into deduped notifications.
 */
function smpro_im_alert_scan() {
    $cfg = smpro_in_cfg();
    $win = max(2, (int)$cfg['alert_window_min']);
    $events = smpro_im_ingest_recent(SMPRO_IM_LIVE_BYTES, max($win, 60));
    $cut = time() - $win * 60;
    $recent = array_filter($events, fn($e) => ($e['ts'] ?? 0) >= $cut);
    $alerts = [];

    // SERVED exploit attempts — the genuinely dangerous ones: an exploit-class attack the app
    // answered with 2xx/3xx (NOT blocked). Blocked probes (403) are routine WAF noise and do
    // NOT raise a critical alert — that is what made the old "223 CRITICAL" alert meaningless.
    $served = array_filter($recent, fn($e) => smpro_im_exploit_kind($e['kind']) && (int)$e['code'] >= 200 && (int)$e['code'] < 400);
    if ($served) {
        $sd = array_values(array_unique(array_filter(array_map(fn($e) => $e['domain'], $served))));
        $alerts['critical'] = ['sig'=>'served:' . count($served), 'subject'=>count($served) . ' exploit attempt(s) SERVED 2xx (possible success) in last ' . $win . 'm',
            'body'=>'Domains: ' . implode(', ', array_slice($sd, 0, 12)) . (count($sd) > 12 ? ' +' . (count($sd) - 12) : '') . "\nThese were NOT blocked by the WAF — review immediately."];
    }
    // domain spikes (blocked + served attempts) — high baseline on a busy shared server, so the threshold is high
    $by = smpro_im_by_domain($recent); $thr = (int)$cfg['thr_domain_attacks']; $spiked = [];
    foreach ($by as $g) if ($g['total'] >= $thr) $spiked[] = $g['domain'] . ' (' . $g['total'] . ')';
    if ($spiked) $alerts['spike'] = ['sig'=>'spike:' . md5(implode(',', $spiked)), 'subject'=>count($spiked) . ' domain(s) under heavy attack (>=' . $thr . ' attempts/' . $win . 'm, mostly blocked)', 'body'=>implode("\n", array_slice($spiked, 0, 15)) . "\n(These are blocked + served attempts; most are blocked WAF noise.)"];
    // distributed scanners
    $camp = smpro_im_campaigns($recent);
    if ($camp['distributed']) {
        $top = array_map(fn($d) => $d['ip'] . ' → ' . $d['domains'] . ' domains', array_slice($camp['distributed'], 0, 10));
        $alerts['distributed'] = ['sig'=>'dist:' . md5(implode(',', array_column($camp['distributed'], 'ip'))), 'subject'=>count($camp['distributed']) . ' IP(s) scanning many domains', 'body'=>implode("\n", $top)];
    }
    // likely breaches
    $breaches = smpro_im_breaches($recent, 90, 20);
    if ($breaches) {
        $lines = array_map(fn($b) => $b['domain'] . ' [' . implode(',', $b['kinds']) . '] files: ' . implode(', ', array_map('basename', array_slice($b['changed'], 0, 3))), $breaches);
        $alerts['breach'] = ['sig'=>'breach:' . md5(implode(',', array_column($breaches, 'domain'))), 'subject'=>'POSSIBLE COMPROMISE on ' . count($breaches) . ' domain(s)', 'body'=>implode("\n", $lines) . "\nOpen Forensics for the listed accounts NOW."];
    }
    // GENUINE attack from the server's OWN / local IP (wp-cron + benign internal traffic excluded)
    $selfIps = [];
    foreach ($recent as $e) if (smpro_im_is_self_attack($e['ip'], $e['kind'], $e['uri'] ?? '')) $selfIps[$e['ip']] = ($selfIps[$e['ip']] ?? 0) + 1;
    if ($selfIps) {
        $l = []; foreach ($selfIps as $ip => $n) $l[] = $ip . ' (' . $n . ' attacks)';
        $alerts['selfattack'] = ['sig'=>'self:' . md5(implode(',', array_keys($selfIps))), 'subject'=>'⚠ Web attack from the SERVER\'S OWN / local IP', 'body'=>implode("\n", $l) . "\nA local process may be compromised and attacking hosted sites. Investigate immediately (Forensics + Top Processes)."];
    }

    // optional auto-response: block the worst attacker IPs (AI-decided when enabled)
    if (!empty($cfg['auto_block'])) {
        $offenders = smpro_im_offenders($recent, 25);
        $minHits = max(5, (int)($cfg['auto_block_threshold'] ?? 30));   // per-IP attack-count floor (default 30)
        $hitsOf  = []; foreach ($offenders as $o) $hitsOf[$o['ip']] = (int)$o['hits'];
        $st = smpro_in_state(); $done = $st['autoblocked'] ?? []; $blocked = []; $how = 'threshold';
        $toBlock = [];
        if (!empty($cfg['ai_block']) && function_exists('smpro_ai_available') && smpro_ai_available()) {
            $ai = smpro_im_ai_block_decide($offenders);
            if ($ai['ok']) { $toBlock = $ai['block']; $how = 'AI'; }
            else foreach ($offenders as $o) if ($o['hits'] >= $minHits) $toBlock[] = $o['ip'];   // fallback if AI failed
        } else {
            foreach ($offenders as $o) if ($o['hits'] >= $minHits) $toBlock[] = $o['ip'];
        }
        foreach ($toBlock as $ip) {
            if (isset($done[$ip]) || !filter_var($ip, FILTER_VALIDATE_IP)) continue;
            if (function_exists('smpro_ip_is_external') && !smpro_ip_is_external($ip)) continue;
            if (smpro_im_allowlisted($ip)) continue;
            // home-region policy (the "any NON-ARAB IP after N attacks → block" rule):
            //   core_protected = EG/SA residential → NEVER auto-block · arab_caution = other-Arab residential → 3× the floor
            //   normal = non-Arab / datacenter (any country) / unknown geo → block at the floor. (Datacenter EG/SA still blockable.)
            if (!empty($cfg['protect_arab'])) {
                $rs = smpro_im_region_status($ip);
                if ($rs === 'core_protected') continue;
                if ($rs === 'arab_caution' && ($hitsOf[$ip] ?? 0) < $minHits * 3) continue;
            }
            $globalDry = function_exists('smpro_ctl_dry_run') && smpro_ctl_dry_run();
            if (empty($cfg['auto_block_dryrun']) && !$globalDry) { $r = smpro_im_block_ip($ip, 'auto/' . $how); if ($r['ok']) { $done[$ip] = time(); $blocked[] = $ip; } }
            else $blocked[] = $ip . ' (dry-run)';
        }
        if ($blocked) {
            $st['autoblocked'] = array_slice($done, -500, 500, true); smpro_in_state_save($st);
            $alerts['autoblock'] = ['sig'=>'ab:' . md5(implode(',', $blocked)), 'subject'=>(empty($cfg['auto_block_dryrun']) ? 'Auto-blocked ' : 'Auto-block (dry-run) ') . count($blocked) . ' attacker IP(s) [' . $how . ']', 'body'=>implode("\n", $blocked) . (isset($ai['reason']) && $ai['reason'] !== '' ? "\n\nAI reasoning: " . $ai['reason'] : '')];
        }
    }

    // EMERGENCY auto-response. Two DISTINCT signals, deliberately separated to cut noise:
    //   (a) routine SCANNER auto-blocks (credential/.env probes from datacenter VMs) — high volume,
    //       low urgency → accumulate and send ONE grouped INFO digest per emergency_block_digest_hours
    //       (default 12h), summarised by /24 subnet (campaign-aware), NOT a CRITICAL on every run.
    //   (b) HARDEN/CLEAN on an actually-compromised site — rare, urgent → prompt CRITICAL, batched small.
    if (!empty($cfg['emergency'])) {
        $em  = smpro_im_emergency_run($recent);
        $blk = $em['blocked'] ?? [];

        // (a) scanner-block digest
        if ($blk && !$em['dryrun']) {
            $st = smpro_in_state();
            $dg = (isset($st['emergency_block_digest']) && is_array($st['emergency_block_digest'])) ? $st['emergency_block_digest'] : ['ips' => [], 'first_ts' => time()];
            if (empty($dg['ips'])) $dg['first_ts'] = time();
            foreach ($blk as $b) if (!empty($b['ok'])) $dg['ips'][$b['ip']] = $b['reason'];
            $digestH = max(1, (int)($cfg['emergency_block_digest_hours'] ?? 12));
            if ((time() - (int)($dg['first_ts'] ?? time())) >= $digestH * 3600 || count($dg['ips']) >= 250) {
                if ($dg['ips']) $alerts['emergency_blocks'] = smpro_im_scanner_digest($dg['ips']);
                $st['emergency_block_digest'] = ['ips' => [], 'first_ts' => time()];
            } else {
                $st['emergency_block_digest'] = $dg;
            }
            smpro_in_state_save($st);
        }

        // (b) harden/clean prompt batch (the genuinely urgent emergency actions)
        $newLines = [];
        foreach ($em['cleaned'] as $x)  $newLines[] = '🧹 ' . $x['domain'] . ' — quarantined ' . count($x['files']) . ' web-shell file(s)';
        foreach ($em['hardened'] as $x) $newLines[] = '🛡 ' . $x['domain'] . ' — hardened (' . $x['n'] . ' actions: PHP-exec off in uploads + core files locked)';
        if ($newLines) {
            $batchN = max(1, (int)($cfg['emergency_batch'] ?? 3));
            $st   = smpro_in_state();
            $pend = (isset($st['emergency_pending']) && is_array($st['emergency_pending'])) ? $st['emergency_pending'] : ['lines' => [], 'first_ts' => time()];
            if (empty($pend['lines'])) $pend['first_ts'] = time();
            $pend['lines'] = array_merge((array)($pend['lines'] ?? []), $newLines);
            $n = count($pend['lines']);
            $stale = (time() - (int)($pend['first_ts'] ?? time())) > 3600;
            if ($n >= $batchN || $stale) {
                $lines = array_slice($pend['lines'], 0, 80);
                $alerts['emergency'] = [
                    'sig'     => 'em:batch:' . substr(md5(implode(',', $lines)), 0, 12),
                    'subject' => 'Emergency — ' . $n . ' site-protection action(s) [grouped]',
                    'body'    => implode("\n", $lines) . "\n\nGrouped report of the last " . $n . ' emergency site actions. Review/restore in Intrusion Monitor → Emergency.',
                ];
                $st['emergency_pending'] = ['lines' => [], 'first_ts' => time()];
            } else {
                $st['emergency_pending'] = $pend;
            }
            smpro_in_state_save($st);
        }
    }
    return $alerts;
}
