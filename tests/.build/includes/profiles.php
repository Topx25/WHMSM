<?php
/**
 * includes/profiles.php — Protection Profiles engine.
 *
 * A "profile" is a named snapshot of the plugin's PROTECTION behaviour (Intrusion Monitor
 * automation + alert thresholds). Applying a profile writes those values into the live
 * config, adapted to the server's environment. Secrets (Cloudflare/AI tokens), the IP
 * allowlist and breach-exclude paths are NEVER touched by a profile.
 *
 * Built-ins: medium, maximum. Plus: AI profile (generated from the environment), the
 * current/custom settings ("Profile 1"), and an ARCHIVE — every apply first snapshots the
 * current settings (named after the server + date) so you can always roll back.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

define('SMPRO_PROF_DIR',  SMPRO_VARLIB . '/profiles');
define('SMPRO_PROF_IDX',  SMPRO_PROF_DIR . '/index.json');   // archive + saved profiles index
define('SMPRO_PROF_CUR',  SMPRO_PROF_DIR . '/active.json');  // which profile is active

/* The exact set of settings a profile controls (everything else is left as-is). */
function smpro_prof_keys_intrusion() {
    return ['alert_window_min','thr_domain_attacks','thr_ip_domains','auto_block','auto_block_dryrun','ai_block',
            'use_csf','use_cloudflare','emergency','emergency_dryrun','emergency_harden','emergency_clean'];
}
function smpro_prof_keys_notify_thr() { return ['disk_pct','load','failed_logins','spam_events','db_injections','remind_hours']; }

/* ---------------- environment detection ---------------- */
function smpro_prof_env() {
    static $e = null; if ($e !== null) return $e;
    $sites = 0;
    foreach (glob('/var/cpanel/users/*') ?: [] as $f) if (is_file($f)) $sites++;
    if ($sites === 0 && is_readable('/etc/userdomains')) $sites = count(file('/etc/userdomains', FILE_IGNORE_NEW_LINES) ?: []);
    return $e = [
        'hostname'   => php_uname('n'),
        'cores'      => function_exists('smpro_cpu_cores') ? max(1, (int)smpro_cpu_cores()) : 1,
        'ram_gb'     => function_exists('smpro_memory') ? round(((float)(smpro_memory()['total_mb'] ?? 0)) / 1024, 1) : 0,
        'imunify'    => function_exists('smpro_has_bin') ? smpro_has_bin('imunify360-agent') : is_executable('/usr/bin/imunify360-agent'),
        'csf'        => function_exists('smpro_im_csf_bin') && smpro_im_csf_bin() !== '',
        'cloudflare' => function_exists('smpro_cf_configured') && smpro_cf_configured(),
        'modsec'     => function_exists('smpro_im_modsec_log') && smpro_im_modsec_log() !== '',
        'ai'         => function_exists('smpro_ai_available') && smpro_ai_available(),
        'sites'      => $sites,
    ];
}

/* ---------------- built-in profile definitions ---------------- */
function smpro_prof_builtin() {
    return [
        'medium' => [
            'label' => 'Medium protection',
            'desc'  => 'Full visibility with SAFE automation. Alerts on; attacker auto-block runs in DRY-RUN (reviewed, not enforced); Emergency auto-response OFF; balanced thresholds. Lowest risk of false positives / site impact — the recommended default.',
            'intrusion' => ['alert_window_min'=>15,'thr_domain_attacks'=>150,'thr_ip_domains'=>12,'auto_block'=>true,'auto_block_dryrun'=>true,'ai_block'=>false,
                            'use_csf'=>true,'use_cloudflare'=>true,'emergency'=>false,'emergency_dryrun'=>true,'emergency_harden'=>true,'emergency_clean'=>true],
            'notify_thr' => ['disk_pct'=>90,'load'=>20,'failed_logins'=>60,'spam_events'=>300,'db_injections'=>1,'remind_hours'=>12],
        ],
        'maximum' => [
            'label' => 'Maximum protection',
            'desc'  => 'Full automated defense. Attacker auto-block ENFORCED (+ AI decision if available); Emergency auto-response ON (hardens & quarantines web-shells the moment an attacked site changes files); sensitive thresholds. Higher chance of false positives / site impact — for high-threat servers. Everything is reversible from the archive.',
            'intrusion' => ['alert_window_min'=>10,'thr_domain_attacks'=>80,'thr_ip_domains'=>8,'auto_block'=>true,'auto_block_dryrun'=>false,'ai_block'=>true,
                            'use_csf'=>true,'use_cloudflare'=>true,'emergency'=>true,'emergency_dryrun'=>false,'emergency_harden'=>true,'emergency_clean'=>true],
            'notify_thr' => ['disk_pct'=>85,'load'=>15,'failed_logins'=>40,'spam_events'=>200,'db_injections'=>1,'remind_hours'=>6],
        ],
    ];
}

/* Adapt a profile's raw values to THIS server's environment. */
function smpro_prof_adapt($p) {
    $env = smpro_prof_env();
    // load threshold scales with core count (absolute load is meaningless without cores)
    if (isset($p['notify_thr']['load'])) $p['notify_thr']['load'] = max((int)$p['notify_thr']['load'], (int)round($env['cores'] * 0.6));
    // attack-spike threshold scales with how many sites are hosted (more sites = higher baseline noise)
    if (isset($p['intrusion']['thr_domain_attacks']) && $env['sites'] > 0) {
        $scale = max(1.0, $env['sites'] / 100);
        $p['intrusion']['thr_domain_attacks'] = (int)round($p['intrusion']['thr_domain_attacks'] * $scale);
    }
    // only enable Cloudflare blocking if it is actually configured; AI block only if an AI provider exists
    if (!$env['cloudflare']) $p['intrusion']['use_cloudflare'] = false;
    if (!$env['ai'] && isset($p['intrusion']['ai_block'])) $p['intrusion']['ai_block'] = false;
    $p['_adapted'] = true;
    return $p;
}

/* ---------------- current settings <-> profile ---------------- */
function smpro_prof_current() {
    $cfg = function_exists('smpro_in_cfg') ? smpro_in_cfg() : [];
    $ntf = function_exists('smpro_ntf_load') ? smpro_ntf_load() : [];
    $intr = []; foreach (smpro_prof_keys_intrusion() as $k) $intr[$k] = $cfg[$k] ?? null;
    $thr = []; foreach (smpro_prof_keys_notify_thr() as $k) $thr[$k] = $ntf['thresholds'][$k] ?? null;
    return ['intrusion' => $intr, 'notify_thr' => $thr];
}
/** Resolve a profile key to its (adapted) value set. */
function smpro_prof_resolve($key) {
    if ($key === 'current') return ['label'=>'Current (custom)','desc'=>'Your current live settings.'] + smpro_prof_current();
    $b = smpro_prof_builtin();
    if (isset($b[$key])) return smpro_prof_adapt($b[$key]);
    // saved/AI profile from the index
    foreach (smpro_prof_index() as $r) if (($r['id'] ?? '') === $key) return $r['profile'] ?? [];
    return [];
}
/** Friendly (non-technical) name + plain-language explanation for every setting a profile can change. */
function smpro_prof_field_meta() {
    return [
        // intrusion automation
        'alert_window_min'   => ['name'=>'Alert window',                 'help'=>'How many recent minutes of activity are looked at when deciding whether a site is under attack. A shorter window reacts faster but is noisier.'],
        'thr_domain_attacks' => ['name'=>'Attacks per site before alert','help'=>'How many blocked web-attacks against a single site within the window trigger an alert. This is auto-scaled up for servers hosting many sites.'],
        'thr_ip_domains'     => ['name'=>'Sites one IP may hit',         'help'=>'If a single IP attacks more than this many of your sites, it is treated as a scanner and flagged for blocking.'],
        'auto_block'         => ['name'=>'Auto-block attackers',         'help'=>'Automatically block IPs that cross the attack thresholds, instead of only alerting you.'],
        'auto_block_dryrun'  => ['name'=>'Preview blocks only (dry-run)','help'=>'When on, attacker blocks are only SIMULATED and logged for review — nothing is actually blocked. Turn off to enforce real blocks.'],
        'ai_block'           => ['name'=>'AI-assisted blocking',         'help'=>'Let the configured AI double-check borderline cases before an IP is blocked, to reduce false positives. Needs an AI provider.'],
        'use_csf'            => ['name'=>'Block via CSF firewall',       'help'=>'Apply blocks at the server firewall (CSF/LFD) when available.'],
        'use_cloudflare'     => ['name'=>'Block via Cloudflare',         'help'=>'Also block attackers at the Cloudflare edge when Cloudflare is configured for your sites.'],
        'emergency'          => ['name'=>'Emergency auto-response',      'help'=>'When a site that is actively under attack suddenly changes its files, automatically step in (see hardening / clean-up below). Powerful but more aggressive.'],
        'emergency_dryrun'   => ['name'=>'Emergency preview only',       'help'=>'When on, emergency actions are only simulated and reported, not actually performed.'],
        'emergency_harden'   => ['name'=>'Emergency hardening',          'help'=>'During an emergency, lock down the affected site (block PHP execution in upload folders, protect core files). Reversible.'],
        'emergency_clean'    => ['name'=>'Emergency clean-up',           'help'=>'During an emergency, move detected web-shells / malicious uploads to quarantine. Reversible from the archive.'],
        // notification thresholds
        'disk_pct'           => ['name'=>'Disk-full alert',              'help'=>'Send an alert when disk usage reaches this percentage.'],
        'load'               => ['name'=>'High-load alert',              'help'=>'Send an alert when the server load reaches this value. Auto-scaled to the number of CPU cores.'],
        'failed_logins'      => ['name'=>'Failed-login alert',           'help'=>'Send an alert after this many failed logins are seen in the window — a sign of a brute-force attempt.'],
        'spam_events'        => ['name'=>'Spam-activity alert',          'help'=>'Send an alert when outgoing spam/mail-abuse events reach this count.'],
        'db_injections'      => ['name'=>'Database-injection alert',     'help'=>'Send an alert when this many likely SQL-injection attempts are detected.'],
        'remind_hours'       => ['name'=>'Reminder interval',            'help'=>'How often (in hours) an unresolved issue is re-sent as a reminder.'],
    ];
}
/** Humanise a value for display (on/off, with units where helpful). */
function smpro_prof_val_human($k, $norm) {
    if ($norm === 'on')  return 'On';
    if ($norm === 'off') return 'Off';
    if ($k === 'alert_window_min') return $norm . ' min';
    if ($k === 'remind_hours')     return $norm . ' h';
    if ($k === 'disk_pct')         return $norm . '%';
    return (string)$norm;
}
/** Diff target profile vs current: list of changes with FRIENDLY name + explanation (balloon). */
function smpro_prof_diff($key) {
    $cur = smpro_prof_current(); $t = smpro_prof_resolve($key);
    $meta = smpro_prof_field_meta();
    $out = [];
    foreach (['intrusion','notify_thr'] as $grp) foreach (($t[$grp] ?? []) as $k => $v) {
        if ($v === null) continue;
        $from = $cur[$grp][$k] ?? null;
        $norm = fn($x) => is_bool($x) ? ($x ? 'on' : 'off') : (string)$x;
        if ($norm($from) !== $norm($v)) $out[] = [
            'k'     => $grp.'.'.$k,
            'label' => $meta[$k]['name'] ?? ucfirst(str_replace('_', ' ', $k)),   // friendly name, never the raw key
            'help'  => $meta[$k]['help'] ?? '',
            'from'  => smpro_prof_val_human($k, $norm($from)),
            'to'    => smpro_prof_val_human($k, $norm($v)),
        ];
    }
    return $out;
}
/** Write a resolved profile into the live config. Snapshots current first (archive). */
function smpro_prof_apply($key, $note = '') {
    $t = smpro_prof_resolve($key);
    if (!$t || (empty($t['intrusion']) && empty($t['notify_thr']))) return ['ok'=>false,'msg'=>'Unknown or empty profile'];
    // 1) BACK UP current settings (named after the server + date) BEFORE applying anything
    $backupId = smpro_prof_archive_snapshot('Backup before applying "' . ($t['label'] ?? $key) . '"');
    $backupName = '';
    foreach (smpro_prof_index() as $r) if (($r['id'] ?? '') === $backupId) { $backupName = (string)($r['name'] ?? ''); break; }
    // 2) apply intrusion subset (non-secret)
    if (!empty($t['intrusion']) && function_exists('smpro_in_cfg_save')) {
        $patch = []; foreach (smpro_prof_keys_intrusion() as $k) if (array_key_exists($k, $t['intrusion']) && $t['intrusion'][$k] !== null) $patch[$k] = $t['intrusion'][$k];
        if ($patch) smpro_in_cfg_save($patch);
    }
    // 3) apply notify thresholds + ensure security alert types are on
    if (function_exists('smpro_ntf_load') && function_exists('smpro_ntf_save')) {
        $n = smpro_ntf_load();
        foreach (smpro_prof_keys_notify_thr() as $k) if (isset($t['notify_thr'][$k]) && $t['notify_thr'][$k] !== null) $n['thresholds'][$k] = $t['notify_thr'][$k];
        foreach (['intrusion_attack','intrusion_breach','intrusion_autoblock','intrusion_emergency','malware_active','db_injection'] as $ty)
            if (isset($n['types'][$ty])) $n['types'][$ty]['on'] = true;
        smpro_ntf_save($n);
    }
    smpro_prof_set_active($key, $t['label'] ?? $key);
    if (function_exists('smpro_audit')) smpro_audit('profile_apply', ['profile'=>$key,'note'=>$note,'backup'=>$backupId]);
    return ['ok'=>true,'msg'=>'Applied "' . ($t['label'] ?? $key) . '"','active'=>$key,'backup_id'=>$backupId,'backup_name'=>$backupName];
}

/* ---------------- active profile ---------------- */
function smpro_prof_active() { $d = is_file(SMPRO_PROF_CUR) ? json_decode((string)@file_get_contents(SMPRO_PROF_CUR), true) : null; return is_array($d) ? $d : []; }
function smpro_prof_set_active($key, $label) { @is_dir(SMPRO_PROF_DIR) || @mkdir(SMPRO_PROF_DIR, 0700, true); $t = SMPRO_PROF_CUR.'.tmp'; @file_put_contents($t, json_encode(['key'=>$key,'label'=>$label,'ts'=>time(),'at'=>date('c')], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE), LOCK_EX); @chmod($t,0600); @rename($t, SMPRO_PROF_CUR); }

/* ---------------- archive + saved profiles ---------------- */
function smpro_prof_index() { $d = is_file(SMPRO_PROF_IDX) ? json_decode((string)@file_get_contents(SMPRO_PROF_IDX), true) : null; return is_array($d) ? $d : []; }
function smpro_prof_index_save($i) { @is_dir(SMPRO_PROF_DIR) || @mkdir(SMPRO_PROF_DIR, 0700, true); $t = SMPRO_PROF_IDX.'.tmp'; @file_put_contents($t, json_encode(array_slice($i, 0, 300), JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE), LOCK_EX); @chmod($t,0600); @rename($t, SMPRO_PROF_IDX); }
/** Save a named profile record (snapshot of given profile data) into the index. */
function smpro_prof_store($name, $profile, $kind = 'saved') {
    $id = $kind . '_' . date('Ymd_His') . '_' . substr(sha1($name . microtime()), 0, 6);
    $idx = smpro_prof_index();
    array_unshift($idx, ['id'=>$id,'name'=>$name,'kind'=>$kind,'ts'=>time(),'at'=>date('Y-m-d H:i:s'),'profile'=>$profile]);
    smpro_prof_index_save($idx);
    return $id;
}
/** Snapshot the CURRENT live settings as a server-named, dated archive entry (rollback point). */
function smpro_prof_archive_snapshot($why = '') {
    $env = smpro_prof_env();
    $name = $env['hostname'] . ' — ' . date('Y-m-d H:i') . ($why !== '' ? ' (' . $why . ')' : '');
    return smpro_prof_store($name, smpro_prof_current(), 'archive');
}

/* ---------------- recommended (auto-setup) ---------------- */
/** The recommended profile for a fresh server (Medium, adapted). Used by "Auto-setup". */
function smpro_prof_recommended_key() { return 'medium'; }

/* ---------------- AI profile ---------------- */
function smpro_prof_ai_generate() {
    if (!function_exists('smpro_ai_available') || !smpro_ai_available()) return ['ok'=>false,'msg'=>'No AI provider configured.'];
    $env = smpro_prof_env();
    $sys = "You are a security engineer tuning a WHM/cPanel shared-hosting protection plugin. Given the server environment, output the SAFEST EFFECTIVE protection settings. Respond with ONLY strict JSON: "
         . '{"intrusion":{"alert_window_min":int,"thr_domain_attacks":int,"thr_ip_domains":int,"auto_block":bool,"auto_block_dryrun":bool,"ai_block":bool,"use_csf":bool,"use_cloudflare":bool,"emergency":bool,"emergency_dryrun":bool,"emergency_harden":bool,"emergency_clean":bool},'
         . '"notify_thr":{"disk_pct":int,"load":int,"failed_logins":int,"spam_events":int,"db_injections":int,"remind_hours":int},"rationale":"2-3 sentences"}. '
         . "Rules: scale thr_domain_attacks to site count and load to core count; only set use_cloudflare/ai_block true if those are available; prefer auto_block_dryrun=true and emergency=false unless the server clearly needs aggressive defense.";
    $user = "Server environment:\n" . json_encode($env, JSON_UNESCAPED_SLASHES|JSON_PRETTY_PRINT);
    $r = smpro_ai_chat($sys, $user, ['max_tokens'=>700,'context'=>'protection_profile']);
    if (empty($r['ok'])) return ['ok'=>false,'msg'=>$r['error'] ?? 'AI request failed'];
    $j = preg_match('/\{.*\}/s', (string)($r['text'] ?? ''), $m) ? json_decode($m[0], true) : null;
    if (!is_array($j) || (empty($j['intrusion']) && empty($j['notify_thr']))) return ['ok'=>false,'msg'=>'AI returned no parseable profile','raw'=>$r['text'] ?? ''];
    // sanitize to known keys/types
    $intr = []; foreach (smpro_prof_keys_intrusion() as $k) if (isset($j['intrusion'][$k])) $intr[$k] = in_array($k,['auto_block','auto_block_dryrun','ai_block','use_csf','use_cloudflare','emergency','emergency_dryrun','emergency_harden','emergency_clean'],true) ? (bool)$j['intrusion'][$k] : (int)$j['intrusion'][$k];
    $thr = []; foreach (smpro_prof_keys_notify_thr() as $k) if (isset($j['notify_thr'][$k])) $thr[$k] = (int)$j['notify_thr'][$k];
    $prof = smpro_prof_adapt(['label'=>'AI profile','desc'=>(string)($j['rationale'] ?? 'AI-tailored to this server.'),'intrusion'=>$intr,'notify_thr'=>$thr]);
    return ['ok'=>true,'profile'=>$prof,'provider'=>$r['provider'] ?? ''];
}
