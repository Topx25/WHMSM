<?php
/**
 * includes/forensics-upload-breach.php — one-click UPLOAD-BREACH forensic collector (smpro_ub_*).
 *
 * READ-ONLY evidence collection for the unrestricted-file-upload attack class — e.g. POST /…/uploadimage
 * accepted with HTTP 200, web-shells dropped into an image dir with image/blank extensions that the
 * *.php-only breach scan (smpro_im_breaches) never sees. Six bounded sections + an orchestrator that reaches
 * an HONEST verdict (live_compromise | planted_inert | attempted_only | clean).
 *
 * The ONLY write is a report JSON under SMPRO_CACHE — NO account files are changed, NO services restarted.
 * Response actions (quarantine / block IP / harden dir) live in the module, POST+CSRF+confirm-gated, never here.
 * Every shell command is wrapped by smpro_fx_wrap (timeout+nice+ionice) with escapeshellarg on every argument.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

/** web-shell token set (mirror of smpro_im_looks_malicious) + the raw "<?php" open tag, for content-scanning
 *  files of ANY extension. Passed to grep -Ea (escapeshellarg'd at the call site). */
function smpro_ub_token_re() {
    return 'eval[[:space:]]*\(|assert[[:space:]]*\(|create_function|gzinflate|gzuncompress|str_rot13'
         . '|\bshell_exec|\bpassthru|\bproc_open|\bpopen[[:space:]]*\(|\bsystem[[:space:]]*\('
         . '|preg_replace[[:space:]]*\([^,]*/e|\$_(POST|GET|REQUEST|COOKIE|SERVER)[[:space:]]*\[[^]]*\][[:space:]]*\('
         . '|base64_decode[[:space:]]*\([^)]*\$|move_uploaded_file|<\?php';
}
function smpro_ub_deadline_hit($opts) { return !empty($opts['deadline']) && microtime(true) >= $opts['deadline']; }
/** severity rank of a deepfile band. */
function smpro_ub_band_rank($b) { static $r = ['clean'=>0,'info'=>1,'low'=>2,'medium'=>3,'high'=>4,'critical'=>5]; return $r[strtolower((string)$b)] ?? 0; }
function smpro_ub_band_name($n) { static $r = [0=>'clean',1=>'info',2=>'low',3=>'medium',4=>'high',5=>'critical']; return $r[$n] ?? 'clean'; }
/** a path is truly under the account home (realpath, string-prefix). */
function smpro_ub_under_home($path, $home) { $rp = @realpath((string)$path); $home = rtrim((string)$home, '/'); return $rp && $home !== '' && strpos($rp . '/', $home . '/') === 0 ? $rp : ''; }

/** §0 scope — reuse smpro_fx_scope, then discover the account's upload/image directories. Null if account gone. */
function smpro_ub_scope($account) {
    if (!function_exists('smpro_fx_scope')) return null;
    $s = smpro_fx_scope($account); if (!is_array($s)) return null;
    $home = rtrim((string)($s['home'] ?? ''), '/'); $ud = [];
    foreach (array_slice((array)($s['docroots'] ?? []), 0, 4) as $root) {
        $rp = smpro_ub_under_home($root, $home); if (!$rp) continue;
        $cmd = smpro_fx_wrap('find ' . escapeshellarg($rp) . ' -maxdepth 4 -type d \\( -iname uploads -o -iname upload -o -iname images -o -iname img -o -iname files -o -iname media -o -iname storage \\) 2>/dev/null | head -n 40', 8);
        foreach (array_filter(explode("\n", (string)@shell_exec($cmd))) as $d) $ud[$d] = 1;
        foreach ([$rp . '/storage/app/public', $rp . '/public/uploads'] as $p) if (is_dir($p)) $ud[$p] = 1;
    }
    $s['upload_dirs'] = array_slice(array_keys($ud), 0, 40);
    return $s;
}

/** §1 SHELL HUNT (impact) — content-match files (ANY extension) changed since $sinceTs; deep-verdict each. */
function smpro_ub_shell_hunt(array $scope, $sinceTs, array $opts = []) {
    $out = ['candidates'=>[], 'counts'=>['matched'=>0,'deepfiled'=>0,'malicious_band'=>0], 'worst_band'=>'clean', 'truncated'=>false];
    $home = rtrim((string)($scope['home'] ?? ''), '/'); $tokRe = smpro_ub_token_re();
    $uploads = (array)($scope['upload_dirs'] ?? []);
    $roots = array_values(array_unique(array_merge($uploads, (array)($scope['docroots'] ?? []))));
    $worst = 0; $deepCap = 60;
    foreach ($roots as $root) {
        if (count($out['candidates']) >= $deepCap || smpro_ub_deadline_hit($opts)) { $out['truncated'] = true; break; }
        $rp = smpro_ub_under_home($root, $home); if (!$rp) continue;
        // STAGE A (enumerate changed files, any extension) piped into STAGE B (content grep for shell tokens)
        $pipe = 'find ' . escapeshellarg($rp) . ' -maxdepth 6 -type f -newermt ' . escapeshellarg('@' . (int)$sinceTs)
              . " -size -3M ! -path '*/vendor/*' ! -path '*/node_modules/*' ! -path '*/wp-content/cache/*' ! -path '*/wp-content/upgrade/*' -print0 2>/dev/null | head -z -n 4000"
              . ' | xargs -0 -r grep -lEa ' . escapeshellarg($tokRe) . ' 2>/dev/null | head -n 120';   // NUL-delimited: a newline in a file name is not a grep option
        foreach (array_filter(explode("\n", (string)@shell_exec(smpro_fx_wrap($pipe, 20)))) as $f) {
            $out['counts']['matched']++;
            if (count($out['candidates']) >= $deepCap || smpro_ub_deadline_hit($opts)) { $out['truncated'] = true; break 2; }
            if (function_exists('smpro_im_breach_excluded') && smpro_im_breach_excluded($f)) continue;   // security-plugin/cache/WP-Guard/whitelist
            if (function_exists('smpro_im_is_wp_plugin')   && smpro_im_is_wp_plugin($f))   continue;     // admin-installed plugin (Plugin Name header)
            if (function_exists('smpro_im_wl_suppress')    && smpro_im_wl_suppress((string)($scope['user'] ?? ''), $f)) continue;
            $deep = function_exists('smpro_fx_deepfile') ? smpro_fx_deepfile($f, $scope) : ['band'=>'medium'];
            if (empty($deep['exists']) && !@is_file($f)) continue;
            $out['counts']['deepfiled']++;
            $band = (string)($deep['band'] ?? 'medium'); $rank = smpro_ub_band_rank($band);
            $inUp = false; foreach ($uploads as $ud) if (strpos($f . '/', rtrim($ud, '/') . '/') === 0) { $inUp = true; break; }
            $head = smpro_fx_redact((string)@shell_exec(smpro_fx_wrap('head -c 512 ' . escapeshellarg($f), 5)));
            $out['candidates'][] = ['path'=>$f, 'mtime'=>(int)($deep['mtime'] ?? @filemtime($f)), 'size'=>(int)($deep['size'] ?? @filesize($f)),
                'uid'=>(int)($deep['uid'] ?? 0), 'band'=>$band, 'families_seen'=>array_values((array)($deep['families_seen'] ?? [])),
                'nested_chain'=>!empty($deep['nested_chain']), 'sha256'=>(string)($deep['sha256'] ?? ''), 'owner_ok'=>(string)($deep['owner_ok'] ?? 'unknown'),
                'in_upload_dir'=>$inUp, 'head_excerpt'=>mb_substr((string)$head, 0, 512)];
            if ($rank >= 3) $out['counts']['malicious_band']++;
            if ($rank > $worst) $worst = $rank;
        }
    }
    // worst first
    usort($out['candidates'], fn($a, $b) => smpro_ub_band_rank($b['band']) <=> smpro_ub_band_rank($a['band']) ?: $b['mtime'] <=> $a['mtime']);
    $out['worst_band'] = smpro_ub_band_name($worst);
    return $out;
}

/** §2 ENDPOINT CODE (how) — locate the upload handler + assess whether it REALLY validates the file. Read-only.
 *  IMPORTANT: getClientOriginalExtension() is NOT validation — using it to build the saved filename TRUSTS the
 *  attacker's extension (upload x.php → saved as <time>.php). Real validation = a server-side content/type check
 *  (getimagesize / finfo / mimes: whitelist). Re-encoding (Image::make) strips embedded PHP and is a mitigation. */
function smpro_ub_endpoint_code(array $scope, array $opts = []) {
    $out = ['hits'=>[], 'handlers_found'=>[], 'has_extension_check'=>false, 'uses_client_extension'=>false, 'raw_move'=>false, 'reencode'=>false, 'risk'=>'unknown'];
    $home = rtrim((string)($scope['home'] ?? ''), '/');
    $sym = 'uploadimage|move_uploaded_file|getClientOriginalExtension|->store\(|Image::make|mimes:|getimagesize|mime_content_type|finfo|exif_imagetype';
    $dirs = []; foreach ((array)($scope['docroots'] ?? []) as $root) { $rp = smpro_ub_under_home($root, $home); if (!$rp) continue; $dirs[$rp] = 1; foreach ([dirname($rp) . '/app', dirname($rp) . '/routes'] as $a) if (is_dir($a)) $dirs[$a] = 1; }
    foreach (array_slice(array_keys($dirs), 0, 3) as $dir) {
        if (smpro_ub_deadline_hit($opts)) { break; }
        $cmd = smpro_fx_wrap('grep -rnIEa --include=*.php ' . escapeshellarg($sym) . ' ' . escapeshellarg($dir) . ' --exclude-dir=vendor --exclude-dir=node_modules --exclude-dir=cache 2>/dev/null | head -n 140', 15);
        foreach (array_filter(explode("\n", (string)@shell_exec($cmd))) as $ln) {
            if (!preg_match('/^([^:]+):(\d+):(.*)$/', $ln, $m)) continue;
            $code = $m[3];
            $out['hits'][] = ['file'=>$m[1], 'line'=>(int)$m[2], 'snippet'=>mb_substr((string)smpro_fx_redact(trim($code)), 0, 200)];
            if (preg_match('/getimagesize|exif_imagetype|mime_content_type|finfo_file|->isValid\(|->guessExtension\(|mimes:\s*[a-z0-9,|]*(jpe?g|png|gif|webp)|in_array\([^;]*(jpe?g|png|gif|webp)/i', $code)) $out['has_extension_check'] = true;   // REAL server-side type check
            if (preg_match('/getClientOriginalExtension/i', $code)) $out['uses_client_extension'] = true;         // saved name follows the attacker extension
            if (preg_match('/\bmove_uploaded_file\b/i', $code))     $out['raw_move'] = true;                       // raw move, no re-encode
            if (preg_match('/Image::make|->fit\(|->resize\(|->encode\(/i', $code)) $out['reencode'] = true;        // re-encode strips embedded PHP (mitigation)
            if (preg_match('/uploadimage/i', $code)) $out['handlers_found'][$m[1] . ':' . $m[2]] = 1;
            if (count($out['hits']) >= 140) break 2;
        }
    }
    $out['handlers_found'] = array_keys($out['handlers_found']);
    // honest risk summary (first match): a raw move with no type check is the real RCE vector; getClientOriginalExtension
    // without a check is unrestricted-upload; re-encoding paths are largely mitigated (still worth forcing a safe ext).
    if ($out['raw_move'] && !$out['has_extension_check'])                    $out['risk'] = 'raw_move';
    elseif ($out['uses_client_extension'] && !$out['has_extension_check'])   $out['risk'] = 'unrestricted_ext';
    elseif ($out['has_extension_check'])                                     $out['risk'] = 'validated';
    elseif ($out['reencode'])                                                $out['risk'] = 'reencoded';
    return $out;
}

/** §3 MODSEC PAYLOAD (what) — the flagged upload requests + acceptance counts. */
function smpro_ub_modsec_payload(array $scope, $sinceTs, array $opts = []) {
    $out = ['entries'=>[], 'endpoint_counts'=>[], 'accepted_2xx'=>0, 'blocked'=>0];
    $user = (string)($scope['user'] ?? ''); $rows = [];
    if (function_exists('smpro_im_parse_modsec')) foreach ((array)@smpro_im_parse_modsec(4 * 1024 * 1024, 800, (int)$sinceTs, true) as $e) {   // accepted uploads are monitoring records: keep them here
        $acct = function_exists('smpro_im_account_for') ? smpro_im_account_for((string)($e['domain'] ?? '')) : '';
        if ($acct !== '' && $acct !== $user) continue;
        $rows[] = ['ts'=>(int)($e['ts'] ?? 0), 'ip'=>(string)($e['ip'] ?? ''), 'domain'=>(string)($e['domain'] ?? ''), 'uri'=>(string)($e['uri'] ?? ''), 'rule'=>(string)($e['rule'] ?? ''), 'msg'=>(string)($e['msg'] ?? ''), 'code'=>(string)($e['code'] ?? ''), 'ua'=>(string)($e['ua'] ?? '')];
    }
    // union the persisted attacks index (history beyond the modsec log tail)
    if (function_exists('smpro_in_by_account')) foreach (smpro_in_by_account($user, (int)$sinceTs, 0, 2000) as $a)
        $rows[] = ['ts'=>(int)($a['ts'] ?? 0), 'ip'=>(string)($a['ip'] ?? ''), 'domain'=>(string)($a['domain'] ?? ''), 'uri'=>(string)($a['uri'] ?? ''), 'rule'=>'', 'msg'=>(string)($a['kind'] ?? ''), 'code'=>(string)($a['code'] ?? ''), 'ua'=>''];
    foreach ($rows as $e) {
        $isUpload = stripos($e['uri'], 'uploadimage') !== false || (function_exists('smpro_im_exploit_kind') && smpro_im_exploit_kind($e['msg']));
        if (!$isUpload) continue;
        $code = (int)$e['code']; $path = function_exists('smpro_im_path_of') ? smpro_im_path_of($e['uri']) : $e['uri'];
        $out['endpoint_counts'][$path] = ($out['endpoint_counts'][$path] ?? 0) + 1;
        if ($code >= 200 && $code < 400) $out['accepted_2xx']++; elseif ($code >= 400) $out['blocked']++;
        $out['entries'][] = $e;
    }
    usort($out['entries'], fn($a, $b) => $b['ts'] <=> $a['ts']);
    $out['entries'] = array_slice($out['entries'], 0, 200);
    arsort($out['endpoint_counts']);
    return $out;
}

/** §4 IS IT LIVE (the decider) — can PHP execute in the upload dirs, and was any uploaded file GET-executed? */
function smpro_ub_is_live(array $scope, array $shellHunt, $sinceTs, array $opts = []) {
    $out = ['php_exec_allowed'=>[], 'protected_dirs'=>[], 'getback_hits'=>[], 'executed'=>false, 'decider'=>'exec_blocked'];
    foreach (array_slice((array)($scope['upload_dirs'] ?? []), 0, 20) as $dir) {
        $ht = (string)@file_get_contents(rtrim($dir, '/') . '/.htaccess', false, null, 0, 65536);
        $denied = (bool)preg_match('/php_flag\s+engine\s+off|RemoveHandler\s+.*php|SetHandler\s+None|Require\s+all\s+denied|Deny\s+from\s+all/i', $ht);
        $allowed = (bool)preg_match('/php_flag\s+engine\s+on|AddHandler\s+.*php|AddType\s+.*php|SetHandler\s+.*php|php_admin/i', $ht);
        if ($denied) $out['protected_dirs'][] = ['dir'=>$dir, 'reason'=>'explicit deny/handler-off in .htaccess'];
        else $out['php_exec_allowed'][] = ['dir'=>$dir, 'reason'=>$allowed ? 'php handler enabled in .htaccess' : 'no .htaccess restriction (PHP may execute)'];
    }
    // GET-back: a request to a php/phtml/phar/pht INSIDE an upload/img/storage path that returned 2xx
    $base = function_exists('smpro_fw_domlogs_base') ? smpro_fw_domlogs_base() : '';
    $reGet = 'GET [^ ]*/(uploads?|images?|img|files|media|storage)/[^ ]*\.(php|phtml|phar|pht)';
    if ($base !== '') foreach (array_slice((array)($scope['domains'] ?? []), 0, 8) as $dom) {
        if (smpro_ub_deadline_hit($opts)) { break; }
        foreach ([$base . '/' . $dom, $base . '/' . $dom . '-ssl_log'] as $lf) {
            if (!is_readable($lf)) continue;
            $cmd = smpro_fx_wrap('tail -n 200000 ' . escapeshellarg($lf) . ' 2>/dev/null | grep -aE ' . escapeshellarg($reGet) . ' | head -n 200', 12);
            foreach (array_filter(explode("\n", (string)@shell_exec($cmd))) as $l) {
                if (!preg_match('/\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+[^"]*"\s+(\d{3})/', $l, $m)) continue;
                $ts = function_exists('smpro_fw_alog_ts') ? smpro_fw_alog_ts($m[1]) : 0; $st = (int)$m[4];
                if ($ts < (int)$sinceTs || $st < 200 || $st >= 300) continue;
                $ip = strtok(ltrim($l), " \t"); $ip = filter_var($ip, FILTER_VALIDATE_IP) ? $ip : (string)($m[0] ? '' : '');
                $out['getback_hits'][] = ['ts'=>$ts, 'ip'=>$ip, 'uri'=>$m[3], 'status'=>$st, 'dom'=>$dom];
                if (count($out['getback_hits']) >= 100) break 3;
            }
        }
    }
    $out['executed'] = !empty($out['getback_hits']);
    $out['decider'] = $out['executed'] ? 'getback_confirmed' : (!empty($out['php_exec_allowed']) ? 'exec_allowed_no_getback' : 'exec_blocked');
    return $out;
}

/** §5 BLAST RADIUS + persistence — changed files, cron, authorized_keys, processes, outbound. Read-only. */
function smpro_ub_blast_radius(array $scope, $sinceTs, array $opts = []) {
    $out = ['changed_files_count'=>0, 'changed_sample'=>[], 'cron_lines'=>[], 'authorized_keys'=>[], 'changed_dotfiles'=>[], 'processes'=>[], 'outbound'=>[]];
    $home = rtrim((string)($scope['home'] ?? ''), '/'); $user = (string)($scope['user'] ?? '');
    if ($home === '' || $user === '') return $out;
    $chg = array_filter(explode("\n", (string)@shell_exec(smpro_fx_wrap('find ' . escapeshellarg($home) . ' -maxdepth 8 -type f -newermt ' . escapeshellarg('@' . (int)$sinceTs) . " ! -path '*/vendor/*' ! -path '*/cache/*' 2>/dev/null | head -n 500", 15))));
    $out['changed_files_count'] = count($chg); $out['changed_sample'] = array_slice($chg, 0, 60);
    if (!smpro_ub_deadline_hit($opts)) {
        foreach (array_filter(explode("\n", (string)@shell_exec(smpro_fx_wrap('crontab -l -u ' . escapeshellarg($user) . ' 2>/dev/null | head -n 40', 5)))) as $c) if ($c !== '' && $c[0] !== '#') $out['cron_lines'][] = $c;
        $sp = '/var/spool/cron/' . $user; if (is_readable($sp)) foreach (array_slice((array)@file($sp, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES), 0, 40) as $c) if ($c !== '' && $c[0] !== '#') $out['cron_lines'][] = $c;
        foreach (['/.ssh/authorized_keys', '/.ssh/authorized_keys2'] as $kf) {
            $p = $home . $kf; if (!is_file($p)) continue;
            $mt = (int)@filemtime($p);
            foreach (array_slice((array)@file($p, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES), 0, 20) as $k)
                $out['authorized_keys'][] = ['line_redacted'=>preg_replace('/\S{20,}/', '…[key]…', (string)$k), 'mtime'=>$mt, 'new'=>($mt >= (int)$sinceTs)];
        }
        foreach (array_filter(explode("\n", (string)@shell_exec(smpro_fx_wrap('find ' . escapeshellarg($home) . " -maxdepth 2 -name '.*' -newermt " . escapeshellarg('@' . (int)$sinceTs) . ' 2>/dev/null | head -n 60', 8)))) as $d) $out['changed_dotfiles'][] = $d;
        $out['processes'] = array_slice(array_filter(explode("\n", (string)@shell_exec(smpro_fx_wrap('ps -u ' . escapeshellarg($user) . ' -o pid,pcpu,etime,args 2>/dev/null | head -n 40', 5)))), 0, 40);
        if (($scope['uid'] ?? null) !== null) $out['outbound'] = array_slice(array_filter(explode("\n", (string)@shell_exec(smpro_fx_wrap('ss -tnp 2>/dev/null | grep ESTAB | grep -a ' . escapeshellarg('uid=' . (int)$scope['uid']) . ' | head -n 40', 5)))), 0, 40);
    }
    return $out;
}

/** §6 ATTACKER PROFILE — top IPs / /16 subnets / user-agents on the upload endpoints. */
function smpro_ub_attacker_profile(array $scope, $sinceTs, array $opts = []) {
    $out = ['top_ips'=>[], 'top_subnets_16'=>[], 'top_uas'=>[], 'total_posts'=>0, 'distinct_ips'=>0, 'distinct_subnets'=>0];
    $user = (string)($scope['user'] ?? ''); $ips = []; $subs = []; $uas = []; $n = 0;
    if (function_exists('smpro_in_by_account')) foreach (smpro_in_by_account($user, (int)$sinceTs, 0, 2000) as $a) {
        if (stripos((string)($a['uri'] ?? ''), 'uploadimage') === false) continue;
        $ip = (string)($a['ip'] ?? ''); if ($ip === '') continue; $n++;
        $ips[$ip] = ($ips[$ip] ?? 0) + 1;
        if (preg_match('/^(\d+\.\d+)\./', $ip, $m)) $subs[$m[1] . '.0.0/16'] = ($subs[$m[1] . '.0.0/16'] ?? 0) + 1;
    }
    // fall back to domlogs only when the index is sparse
    if ($n < 20) { $base = function_exists('smpro_fw_domlogs_base') ? smpro_fw_domlogs_base() : '';
        if ($base !== '') foreach (array_slice((array)($scope['domains'] ?? []), 0, 8) as $dom) {
            if (smpro_ub_deadline_hit($opts)) break;
            $lf = $base . '/' . $dom; if (!is_readable($lf)) continue;
            $cmd = smpro_fx_wrap('grep -aE ' . escapeshellarg('(POST|GET) [^ ]*uploadimage') . ' ' . escapeshellarg($lf) . ' 2>/dev/null | tail -n 20000', 12);
            foreach (array_filter(explode("\n", (string)@shell_exec($cmd))) as $l) {
                $ip = strtok(ltrim($l), " \t"); if (!filter_var($ip, FILTER_VALIDATE_IP)) continue; $n++;
                $ips[$ip] = ($ips[$ip] ?? 0) + 1;
                if (preg_match('/^(\d+\.\d+)\./', $ip, $m)) $subs[$m[1] . '.0.0/16'] = ($subs[$m[1] . '.0.0/16'] ?? 0) + 1;
                if (preg_match('/"[^"]*"\s+\d{3}\s+\S+\s+"[^"]*"\s+"([^"]*)"/', $l, $um)) $uas[$um[1]] = ($uas[$um[1]] ?? 0) + 1;
            }
        }
    }
    arsort($ips); arsort($subs); arsort($uas);
    $out['total_posts'] = $n; $out['distinct_ips'] = count($ips); $out['distinct_subnets'] = count($subs);
    $topIps = array_slice($ips, 0, 25, true);
    if (function_exists('smpro_ip_intel_bulk')) @smpro_ip_intel_bulk(array_keys($topIps));   // one bulk whois
    foreach ($topIps as $ip => $c) { $in = function_exists('smpro_ip_intel') ? smpro_ip_intel($ip, false) : [];
        $out['top_ips'][] = ['ip'=>$ip, 'n'=>$c, 'country'=>(string)($in['country'] ?? ''), 'provider'=>(string)($in['provider'] ?? ''), 'datacenter'=>function_exists('smpro_ip_is_datacenter') && smpro_ip_is_datacenter($in)]; }
    foreach (array_slice($subs, 0, 10, true) as $net => $c) $out['top_subnets_16'][] = ['net'=>$net, 'n'=>$c];
    foreach (array_slice($uas, 0, 25, true) as $ua => $c) $out['top_uas'][] = ['ua'=>mb_substr((string)$ua, 0, 180), 'n'=>$c];
    return $out;
}

/** ORCHESTRATOR — run all six sections under a shared wall-clock budget, reach a verdict, persist a report JSON. */
function smpro_ub_report($account, $sinceTs, array $opts = []) {
    $account = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)$account);
    $budgetMs = (int)($opts['budget_ms'] ?? 20000);
    $opts['deadline'] = microtime(true) + $budgetMs / 1000.0;
    $t0 = microtime(true);
    $scope = smpro_ub_scope($account);
    if (!is_array($scope)) return ['account'=>$account, 'verdict'=>'error', 'verdict_reason'=>'account/scope not found', 'generated_at'=>time()];
    $sinceTs = (int)$sinceTs ?: (time() - 7 * 86400);

    $sh  = smpro_ub_shell_hunt($scope, $sinceTs, $opts);
    $ec  = smpro_ub_endpoint_code($scope, $opts);
    $mp  = smpro_ub_modsec_payload($scope, $sinceTs, $opts);
    $lv  = smpro_ub_is_live($scope, $sh, $sinceTs, $opts);
    $br  = smpro_ub_blast_radius($scope, $sinceTs, $opts);
    $ap  = smpro_ub_attacker_profile($scope, $sinceTs, $opts);

    // VERDICT (precedence, first match). live_compromise REQUIRES GET-back proof (never content-match alone).
    $worstRank = smpro_ub_band_rank($sh['worst_band']);
    if ($lv['executed']) { $verdict = 'live_compromise'; $reason = 'A file inside an upload dir was requested (GET) and returned 2xx — the shell is reachable and was executed.'; }
    elseif ($worstRank >= 3 && !empty($lv['php_exec_allowed'])) { $verdict = 'planted_inert'; $reason = 'A malicious-band file is present in an upload dir where PHP can execute, but no execution (GET-back) was seen yet — treat as active and quarantine now.'; }
    elseif ((int)$mp['accepted_2xx'] > 0 && (int)$sh['counts']['malicious_band'] === 0) { $verdict = 'attempted_only'; $reason = 'Malicious uploads were accepted (2xx) but no shell content was found in the upload dirs in this window — fix the handler before one lands.'; }
    else { $verdict = 'clean'; $reason = 'No breach evidence in this window (no accepted-2xx cluster, no malicious-band file, no execution).'; }

    $out = ['account'=>$account, 'since'=>$sinceTs, 'generated_at'=>time(), 'scope'=>['home'=>$scope['home'] ?? '', 'domains'=>array_values((array)($scope['domains'] ?? [])), 'docroots'=>array_values((array)($scope['docroots'] ?? [])), 'upload_dirs'=>array_values((array)($scope['upload_dirs'] ?? []))],
        'sections'=>['shell_hunt'=>$sh, 'endpoint_code'=>$ec, 'modsec_payload'=>$mp, 'is_live'=>$lv, 'blast_radius'=>$br, 'attacker_profile'=>$ap],
        'verdict'=>$verdict, 'verdict_reason'=>$reason, 'worst_band'=>$sh['worst_band'],
        'budget_ms_used'=>(int)round((microtime(true) - $t0) * 1000), 'truncated'=>!empty($sh['truncated'])];

    // persist (the ONLY write; a report cache under SMPRO_CACHE — never an account file)
    $dir = SMPRO_CACHE . '/upload_breach'; @is_dir($dir) || @mkdir($dir, 0700, true);
    $rid = $account . '-' . gmdate('Ymd_His', $out['generated_at']) . '.json';
    $tmp = @tempnam($dir, 'ub'); if ($tmp) { @file_put_contents($tmp, json_encode($out, JSON_UNESCAPED_SLASHES)); @chmod($tmp, 0600); @rename($tmp, $dir . '/' . $rid); }
    // prune old reports (keep dir bounded)
    foreach (array_slice((array)@glob($dir . '/*.json') ?: [], 0, 400) as $f) if ((time() - (int)@filemtime($f)) > 30 * 86400) @unlink($f);
    $out['report_id'] = $rid;
    return $out;
}

/** RESPONSE ACTION (NOT part of collection) — drop a REVERSIBLE .htaccess that disables PHP execution in an upload
 *  dir, so any planted (or future) shell can't run. Confined to the account's OWN docroots via realpath; backs up any
 *  existing .htaccess to SMPRO_VARLIB first; idempotent. Caller must gate this behind POST+CSRF+root+confirm. */
function smpro_ub_harden_dir($account, $dir) {
    $account = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)$account);
    $scope = smpro_ub_scope($account); if (!is_array($scope)) return ['ok'=>false, 'msg'=>'account/scope not found'];
    $home = rtrim((string)($scope['home'] ?? ''), '/');
    $rp = @realpath((string)$dir); if (!$rp || !is_dir($rp)) return ['ok'=>false, 'msg'=>'directory not found'];
    // must resolve INSIDE one of the account's docroots (tightest confine), or at least under its home
    $under = false; foreach ((array)($scope['docroots'] ?? []) as $droot) { $dr = @realpath($droot); if ($dr && strpos($rp . '/', rtrim($dr, '/') . '/') === 0) { $under = true; break; } }
    if (!$under && !($home !== '' && strpos($rp . '/', $home . '/') === 0)) return ['ok'=>false, 'msg'=>"refused: directory is not inside this account's web root"];
    $ht = $rp . '/.htaccess';
    $existing = is_file($ht) ? (string)@file_get_contents($ht) : '';
    if (strpos($existing, 'Safety Monitor Pro — disable PHP execution') !== false) return ['ok'=>true, 'msg'=>'Already hardened — SM Pro .htaccess is present in this directory.'];
    if (is_file($ht)) { $b = SMPRO_VARLIB . '/quarantine'; @is_dir($b) || @mkdir($b, 0700, true); @copy($ht, $b . '/htaccess-' . $account . '-' . substr(md5($rp), 0, 10) . '-' . gmdate('Ymd_His') . '.bak'); }
    $block = "# Added by Safety Monitor Pro — disable PHP execution in this upload directory (reversible: delete this block)\n"
           . "php_flag engine off\n"
           . "RemoveHandler .php .phtml .phar .pht .php3 .php4 .php5 .php7 .pgif\n"
           . "RemoveType .php .phtml .phar .pht\n"
           . "<FilesMatch \"\\.(php|phtml|phar|pht|php[3457]|pgif)$\">\n  SetHandler None\n  Require all denied\n</FilesMatch>\n";
    $new = ($existing !== '' ? rtrim($existing, "\n") . "\n\n" : '') . $block;
    if (@file_put_contents($ht, $new) === false) return ['ok'=>false, 'msg'=>'could not write .htaccess (permissions)'];
    @chmod($ht, 0644);
    if (function_exists('smpro_audit')) smpro_audit('upload_breach_harden_dir', ['dir'=>$rp]);
    return ['ok'=>true, 'msg'=>'PHP execution disabled in ' . $rp . ' — a planted shell can no longer run here. Reversible; any prior .htaccess was backed up.'];
}

/** Re-open a saved report by id (basename-confined to the upload_breach cache dir). Null if not found/invalid. */
function smpro_ub_report_load($reportId) {
    $rid = basename((string)$reportId); if (!preg_match('/^[a-zA-Z0-9._-]+\.json$/', $rid)) return null;
    $p = SMPRO_CACHE . '/upload_breach/' . $rid; if (!is_file($p)) return null;
    $d = json_decode((string)@file_get_contents($p), true); return is_array($d) ? $d : null;
}
