<?php
/**
 * includes/ai.php — central AI access layer for Safety Monitor Pro.
 *
 * Reuses the (independent) AI Providers engine + config at /var/lib/smpro/ai:
 * active provider, decrypted API key, base URL and model. All providers are
 * OpenAI-compatible (POST <base>/chat/completions). One function — smpro_ai_chat()
 * — is what every module calls; nothing else needs to know about providers.
 *
 * Privacy: callers must redact sensitive data before passing it in, and AI is
 * only ever invoked on an explicit user action (button), never automatically.
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

require_once __DIR__ . '/ai_catalog.php';   // provider catalog (free-first) + usage tracking

/** Lazily load the heavy provider engine only when AI is actually used. */
function smpro_ai_engine_loaded(): bool {
    if (function_exists('mspro_ai304_load_config')) return true;
    $eng = SMPRO_MODULES . '/ai_providers_engine.php';
    if (is_file($eng)) { require_once $eng; }
    return function_exists('mspro_ai304_load_config');
}

/** Resolve the active provider/model/key/base, or a reason it is not ready. */
function smpro_ai_ready(): array {
    if (!smpro_ai_engine_loaded()) return ['ok' => false, 'reason' => 'AI engine is not installed. Open the AI Providers page first.'];
    $cfg = mspro_ai304_load_config();
    // prefer an ACTIVE provider that has a saved key (the one the operator enabled),
    // falling back to the page's selected provider.
    $provider = '';
    foreach ((array)($cfg['active_providers'] ?? []) as $p) {
        if (is_string($p) && function_exists('mspro_ai304_get_secret') && mspro_ai304_get_secret($p) !== '') { $provider = $p; break; }
    }
    if ($provider === '') $provider = (string)($cfg['provider'] ?? 'qwen');
    $key = function_exists('mspro_ai304_get_secret') ? (string)mspro_ai304_get_secret($provider) : '';
    if ($key === '') return ['ok' => false, 'provider' => $provider, 'reason' => 'No API key saved for ' . $provider . '. Configure it in AI Providers.'];
    $base = rtrim((string)($cfg[$provider]['base_url'] ?? ($provider === 'openrouter' ? 'https://openrouter.ai/api/v1' : '')), '/');
    if ($base === '' || strpos($base, '{') !== false) return ['ok' => false, 'provider' => $provider, 'reason' => 'Base URL for ' . $provider . ' is missing/incomplete.'];
    $model = function_exists('mspro_ai304_pick_live_model') ? (string)mspro_ai304_pick_live_model($provider, $cfg) : (string)($cfg[$provider]['model'] ?? '');
    if ($model === '') $model = (string)($cfg[$provider]['model'] ?? '');   // catalog providers carry their own model
    if ($model === '') $model = $provider === 'qwen' ? 'qwen-plus' : ($provider === 'openrouter' ? 'openrouter/free' : 'deepseek-v4-flash-free');
    return ['ok' => true, 'provider' => $provider, 'model' => $model, 'base' => $base, 'key' => $key, 'cfg' => $cfg];
}

/** True if at least one provider is configured with a key. */
function smpro_ai_available(): bool { $r = smpro_ai_ready(); return !empty($r['ok']); }

/** Production execution mode: 'series' (fallback chain — recommended, quota-safe) or 'parallel' (rotate to spread load). */
function smpro_ai_exec_mode(): string {
    if (!smpro_ai_engine_loaded()) return 'series';
    $cfg = mspro_ai304_load_config();
    $m = (string)($cfg['exec_mode'] ?? 'series');
    return in_array($m, ['series', 'parallel'], true) ? $m : 'series';
}
function smpro_ai_set_exec_mode(string $mode): array {
    $mode = in_array($mode, ['series', 'parallel'], true) ? $mode : 'series';
    if (!smpro_ai_engine_loaded()) return ['ok' => false, 'msg' => 'engine unavailable'];
    $cfg = mspro_ai304_load_config(); $cfg['exec_mode'] = $mode;
    if (function_exists('smpro_ai_cfg_write')) smpro_ai_cfg_write($cfg);
    if (function_exists('smpro_audit')) smpro_audit('ai_exec_mode', ['mode' => $mode]);
    return ['ok' => true, 'mode' => $mode];
}

/** Build the candidate chain from every enabled provider, INTERLEAVED across providers so a provider-wide
 *  rate-limit (e.g. all Gemini models 429 on one key) falls straight through to the NEXT provider instead
 *  of burning the whole chain on one rate-limited provider. Caps a few models per provider. */
function smpro_ai_candidates(array $cfg): array {
    $active = (array)($cfg['active_providers'] ?? []);
    if (!$active && !empty($cfg['provider'])) $active = [$cfg['provider']];
    $perProvCap = 3;                                                       // 3 models per provider is plenty — if 3 fail the key/provider is down
    $byProv = [];                                                          // provider => [cand, cand, ...]
    foreach ($active as $p) {
        if (!is_string($p)) continue;
        $key = function_exists('mspro_ai304_get_secret') ? (string)mspro_ai304_get_secret($p) : '';
        if ($key === '') continue;
        $base = rtrim((string)($cfg[$p]['base_url'] ?? ''), '/');
        if ($base === '' || strpos($base, '{') !== false) continue;
        $models = is_array($cfg[$p]['models'] ?? null) ? array_values(array_filter(array_map('strval', $cfg[$p]['models']))) : [];
        if (!$models && !empty($cfg[$p]['model'])) $models = [(string)$cfg[$p]['model']];
        $list = [];
        foreach (array_slice($models, 0, $perProvCap) as $mdl) if ($mdl !== '') $list[] = ['provider' => $p, 'model' => $mdl, 'base' => $base, 'key' => $key];
        if ($list) $byProv[] = $list;
    }
    // round-robin interleave: provA-m1, provB-m1, provC-m1, provA-m2, …  → other providers reached fast
    $cands = []; $i = 0; $more = true;
    while ($more && count($cands) < 12) {
        $more = false;
        foreach ($byProv as $list) { if (isset($list[$i])) { $cands[] = $list[$i]; $more = true; } }
        $i++;
    }
    return $cands;
}
/** Round-robin offset (so 'parallel' mode spreads load across models and no single token is exhausted). */
function smpro_ai_rr_next(int $n): int {
    if ($n <= 1) return 0;
    $f = SMPRO_VARLIB . '/ai/rr.txt';
    $i = (int)@file_get_contents($f);
    @is_dir(dirname($f)) || @mkdir(dirname($f), 0700, true);
    @file_put_contents($f, (string)(($i + 1) % $n), LOCK_EX);
    return $i % $n;
}

/**
 * Send a chat request to the active provider.
 * @return array ['ok'=>bool,'text'=>string,'error'=>string,'provider'=>,'model'=>,'http'=>int]
 */
function smpro_ai_chat(string $system, string $user, array $opts = []): array {
    $r = smpro_ai_ready();
    if (empty($r['ok'])) return ['ok' => false, 'text' => '', 'error' => (string)($r['reason'] ?? 'AI not ready')];
    if (!function_exists('mspro_ai304_http_post_json')) return ['ok' => false, 'text' => '', 'error' => 'AI transport unavailable.'];

    $cfg = $r['cfg'];
    // Candidate chain across every enabled provider + selected model. Falling back to the next on a
    // failure (rate-limit / error) is what keeps a single token from being exhausted ("tokens stopped").
    $cands = smpro_ai_candidates($cfg);
    if (!$cands) $cands = [['provider' => $r['provider'], 'model' => $r['model'], 'base' => $r['base'], 'key' => $r['key']]];

    // 'series' = always start at the preferred model (fast, consistent). 'parallel' = rotate the start
    // each call to spread load across free models so no single provider's quota gets hit.
    if (smpro_ai_exec_mode() === 'parallel' && count($cands) > 1) {
        $off = smpro_ai_rr_next(count($cands));
        $cands = array_merge(array_slice($cands, $off), array_slice($cands, 0, $off));
    }

    $messages = [];
    if (trim($system) !== '') $messages[] = ['role' => 'system', 'content' => $system];
    $messages[] = ['role' => 'user', 'content' => $user];
    $temp = isset($opts['temperature']) ? (float)$opts['temperature'] : 0.2;
    $maxt = (int)($opts['max_tokens'] ?? 900);

    $lastErr = 'request failed'; $lastHttp = 0; $lastProvider = $cands[0]['provider']; $lastModel = $cands[0]['model']; $tried = [];
    foreach ($cands as $c) {
        $timeout = (int)($opts['timeout'] ?? ($cfg[$c['provider']]['timeout_seconds'] ?? 45));
        if ($timeout < 5) $timeout = 5; if ($timeout > 120) $timeout = 120;
        $payload = ['model' => $c['model'], 'messages' => $messages, 'temperature' => $temp, 'max_tokens' => $maxt];
        $res = mspro_ai304_http_post_json($c['base'] . '/chat/completions', $c['key'], $payload, $timeout);
        if (!empty($res['ok'])) {
            $text = '';
            if (is_array($res['data'] ?? null)) {
                $msg = $res['data']['choices'][0]['message'] ?? [];
                $text = (string)($msg['content'] ?? '');
                if (trim($text) === '') $text = (string)($msg['reasoning_content'] ?? '');
            }
            $tokens = (int)($res['data']['usage']['total_tokens'] ?? 0);
            if (function_exists('smpro_ai_usage_bump')) smpro_ai_usage_bump($c['provider'], $tokens);
            if (function_exists('smpro_audit')) smpro_audit('ai_chat', ['provider' => $c['provider'], 'model' => $c['model'], 'out_chars' => mb_strlen($text), 'tokens' => $tokens, 'fellback' => count($tried), 'context' => (string)($opts['context'] ?? '')]);
            return ['ok' => true, 'text' => trim($text), 'provider' => $c['provider'], 'model' => $c['model'], 'http' => (int)($res['http_code'] ?? 0), 'fellback' => count($tried)];
        }
        $lastErr = function_exists('mspro_ai307_sanitize_provider_message') ? mspro_ai307_sanitize_provider_message((string)($res['error'] ?? 'request failed')) : (string)($res['error'] ?? 'request failed');
        $lastHttp = (int)($res['http_code'] ?? 0); $lastProvider = $c['provider']; $lastModel = $c['model'];
        $tried[] = $c['provider'] . '/' . $c['model'];
        // only keep falling back on rate-limit / transient / auth issues; a 400 bad-request won't fix itself
        if (!in_array($lastHttp, [0, 401, 402, 403, 408, 409, 429, 500, 502, 503, 504], true)) break;
    }
    if (function_exists('smpro_audit')) smpro_audit('ai_chat_fail', ['tried' => implode(',', $tried), 'http' => $lastHttp, 'context' => (string)($opts['context'] ?? '')]);
    // Friendlier message when every provider/model was rate-limited or auth-blocked, instead of a bare "HTTP 429".
    if ($lastHttp === 429) $lastErr = 'All configured AI models are rate-limited right now (tried ' . count($tried) . '). Add another free provider in AI Providers, or try again shortly.';
    elseif (in_array($lastHttp, [401, 402, 403], true)) $lastErr = 'AI provider rejected the API key (HTTP ' . $lastHttp . ') — check the key in AI Providers.';
    return ['ok' => false, 'text' => '', 'error' => $lastErr, 'provider' => $lastProvider, 'model' => $lastModel, 'http' => $lastHttp, 'tried' => count($tried)];
}

/* =====================================================================
 * EXECUTABLE DECISIONS
 * Builds a concrete, section-specific list of actionable items (the "pack")
 * so the global "Recommend decisions" button can return NAMED, EXECUTABLE
 * buttons (Block / Delete / Clean / Suspend …) wired to the real endpoints —
 * not free text. The AI only chooses WHICH item + action; the target and the
 * exec descriptor (URL + fields + freshly-minted CSRF token) come from here,
 * so the model can never invent a target or bypass a guard.
 * ===================================================================== */

/** Map a page/context slug to one of: malware | login | spam | '' (none). */
function smpro_ai_decide_kind(string $ctx): string {
    if (in_array($ctx, ['forensics-audit','forensics','forensics_audit','imunify360-reports','imunify-reports','imunify360'], true)) return 'malware';
    if (in_array($ctx, ['login-monitor','login_monitor','login-correlation','login_correlation','login-access','firewall-status','firewall_status','account-audit','account_audit'], true)) return 'login';
    if (in_array($ctx, ['spam-phishing','spam_phishing','spam','phishing'], true)) return 'spam';
    if (in_array($ctx, ['intrusion-monitor','intrusion_monitor','intrusion'], true)) return 'intrusion';
    return '';
}

/** Build the actionable item pack for a section (read-only, bounded). */
function smpro_ai_decide_pack(string $ctx): array {
    $kind = smpro_ai_decide_kind($ctx);
    $items = [];
    if ($kind === 'malware') {
        $bin = is_executable('/usr/bin/imunify360-agent') ? '/usr/bin/imunify360-agent'
             : (is_executable('/usr/local/bin/imunify360-agent') ? '/usr/local/bin/imunify360-agent' : '');
        if ($bin !== '') {
            $raw = (string)@shell_exec('timeout 40 ' . escapeshellarg($bin) . ' malware malicious list --limit 200 --json 2>/dev/null');
            $j = json_decode($raw, true); $list = is_array($j) ? ($j['items'] ?? []) : [];
            $i = 0;
            foreach ($list as $r) {
                if (($r['resource_type'] ?? '') === 'db') continue;          // file actions here
                $file = (string)($r['file'] ?? ''); if ($file === '' || strpos($file, '/home/') !== 0) continue;
                $acct = (string)($r['username'] ?? (preg_match('#^/home/([^/]+)/#', $file, $mm) ? $mm[1] : ''));
                $items[] = ['id' => 'm' . $i, 'kind' => 'malware', 'file' => $file, 'account' => $acct,
                    'hash' => (string)($r['hash'] ?? ''), 'imid' => (string)($r['id'] ?? ''),
                    'label' => 'malware ' . basename($file) . ($acct ? ' · ' . $acct : ''),
                    'detail' => 'file=' . $file . ' account=' . $acct . ' family=' . (string)($r['type'] ?? ''),
                    'actions' => ['delete', 'clean', 'suspend', 'investigate']];
                if (++$i >= 15) break;
            }
        }
    } elseif ($kind === 'login') {
        $log = '/usr/local/cpanel/logs/login_log'; $ips = [];
        if (is_readable($log)) {
            $raw = (string)@shell_exec('timeout 20 tail -n 60000 ' . escapeshellarg($log) . ' 2>/dev/null');
            foreach (explode("\n", $raw) as $line) {
                if (!preg_match('/FAILED\s+LOGIN|DEFERRED\s+LOGIN/i', $line)) continue;
                if (preg_match('/^\[[^\]]+\]\s+\S+\s+\[[^\]]+\]\s+(\S+)\s+-/', $line, $m)) $ip = $m[1];
                elseif (preg_match('/^(\S+)\s+\S+\s+\S+\s+\[/', $line, $m)) $ip = $m[1];
                else continue;
                if (!function_exists('smpro_ip_is_external') || !smpro_ip_is_external($ip)) continue;
                $ips[$ip] = ($ips[$ip] ?? 0) + 1;
            }
        }
        arsort($ips);
        $top = array_slice($ips, 0, 15, true);
        if (function_exists('smpro_ip_intel_bulk')) smpro_ip_intel_bulk(array_keys($top));
        $i = 0;
        foreach ($top as $ip => $c) {
            if ($c < 5) break;
            $in = function_exists('smpro_ip_intel') ? smpro_ip_intel($ip, false) : [];
            $cc = strtoupper((string)($in['country'] ?? '')); $bot = function_exists('smpro_ip_is_datacenter') && smpro_ip_is_datacenter($in);
            $items[] = ['id' => 'ip' . $i, 'kind' => 'ip', 'ip' => $ip, 'account' => '',
                'label' => $ip . ' · ' . (int)$c . ' failed' . ($cc ? ' · ' . $cc : '') . ($bot ? ' · bot' : ''),
                'detail' => 'ip=' . $ip . ' failed_attempts=' . (int)$c . ' country=' . $cc . ' datacenter_bot=' . ($bot ? 'yes' : 'no'),
                'actions' => ['block', 'allow', 'investigate']];
            if (++$i >= 15) break;
        }
    } elseif ($kind === 'intrusion') {
        // Live WAF attackers (ModSecurity), region-aware: home-region (EG/SA) residential IPs are
        // offered only allow/investigate (never auto-block) — matches smpro_im_region_status policy.
        if (function_exists('smpro_im_parse_modsec') && function_exists('smpro_im_offenders') && defined('SMPRO_IM_PAGE_BYTES')) {
            $ev  = smpro_im_parse_modsec(SMPRO_IM_PAGE_BYTES, defined('SMPRO_IM_CAP') ? SMPRO_IM_CAP : 4000, time() - 6 * 3600);
            $off = smpro_im_offenders($ev, 25);
            $i = 0;
            foreach ($off as $o) {
                $ip = (string)($o['ip'] ?? ''); if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) continue;
                $rs  = function_exists('smpro_im_region_status') ? smpro_im_region_status($ip) : 'normal';
                $cc  = strtoupper((string)($o['country'] ?? '')); $bot = !empty($o['bot']);
                $acts = ($rs === 'core_protected') ? ['allow', 'investigate'] : ['block', 'allow', 'investigate'];
                $items[] = ['id' => 'at' . $i, 'kind' => 'ip', 'ip' => $ip, 'account' => '',
                    'label' => $ip . ' · ' . (int)($o['hits'] ?? 0) . ' attacks' . ($cc ? ' · ' . $cc : '') . ($bot ? ' · bot' : '') . ($rs === 'core_protected' ? ' · 🛡 protected' : ($rs === 'arab_caution' ? ' · ⚠ caution' : '')),
                    'detail' => 'ip=' . $ip . ' attacks=' . (int)($o['hits'] ?? 0) . ' domains=' . (int)($o['domains'] ?? 0) . ' types=' . implode(',', (array)($o['cats'] ?? [])) . ' country=' . $cc . ' datacenter=' . ($bot ? 'yes' : 'no') . ' region_policy=' . $rs,
                    'actions' => $acts];
                if (++$i >= 15) break;
            }
        }
    } elseif ($kind === 'spam') {
        $log = '/var/log/exim_mainlog'; $acct = [];
        if (is_readable($log)) {
            $raw = (string)@shell_exec('timeout 25 tail -n 200000 ' . escapeshellarg($log) . ' 2>/dev/null | grep -aoE "cwd=/home/[^/ ]+" 2>/dev/null');
            foreach (explode("\n", $raw) as $l) if (preg_match('#cwd=/home/([^/ ]+)#', $l, $m)) $acct[$m[1]] = ($acct[$m[1]] ?? 0) + 1;
        }
        arsort($acct);
        $i = 0;
        foreach (array_slice($acct, 0, 15, true) as $a => $c) {
            if ($c < 50) break;                                   // only real bulk senders
            $items[] = ['id' => 'sp' . $i, 'kind' => 'account', 'account' => $a,
                'label' => $a . ' · ' . (int)$c . ' outbound mail events',
                'detail' => 'account=' . $a . ' outbound_mail_events=' . (int)$c,
                'actions' => ['suspend', 'investigate']];
            if (++$i >= 15) break;
        }
    }
    return $items;
}

/** Build an exec descriptor (URL + POST fields + minted CSRF) for an item+action, or null. */
function smpro_ai_decide_exec(array $it, string $action): ?array {
    $tok = fn($a) => function_exists('smpro_csrf_generate') ? smpro_csrf_generate($a) : '';
    $kind = $it['kind'] ?? '';
    switch ($action) {
        case 'delete':
            if ($kind !== 'malware' || empty($it['file'])) return null;
            return ['label' => '🗑 Delete file', 'cls' => 'danger', 'url' => 'index.cgi?page=imunify360-reports',
                'fields' => ['im_action' => 'delete_file', 'file' => $it['file'], 'smpro_csrf' => $tok('im_remediate')],
                'confirm' => "DELETE this malware file for real?\n" . $it['file'] . "\n\nBacked up outside the account first; an action report is written; restorable from Forensics."];
        case 'clean':
            if ($kind !== 'malware' || ($it['imid'] ?? '') === '') return null;
            return ['label' => '🧹 Clean (Imunify)', 'cls' => 'warn', 'url' => 'index.cgi?page=forensics-audit',
                'fields' => ['fa_action' => 'remediate', 'act' => 'malware_quarantine', 'imid' => $it['imid'], 'file' => $it['file'] ?? '', 'smpro_csrf' => $tok('fa_remediate')],
                'confirm' => "Queue an Imunify360 cleanup for this file (async, keeps an original backup)?"];
        case 'suspend':
            $acct = $it['account'] ?? ''; if ($acct === '') return null;
            return ['label' => '⛔ Suspend ' . $acct, 'cls' => 'danger', 'url' => 'index.cgi?page=forensics-audit',
                'fields' => ['fa_action' => 'suspend', 'account' => $acct, 'smpro_csrf' => $tok('fa_remediate')],
                'confirm' => "SUSPEND account \"" . $acct . "\"?\n\nDisables the whole site. Reversible — unsuspend anytime."];
        case 'block':
            if ($kind !== 'ip' || empty($it['ip'])) return null;
            return ['label' => '🚫 Block ' . $it['ip'], 'cls' => 'danger', 'url' => 'index.cgi?page=login-monitor',
                'fields' => ['la_action' => 'block', 'ips' => $it['ip'], 'smpro_csrf' => $tok('la_csf')],
                'confirm' => "BLOCK IP " . $it['ip'] . " in CSF firewall (immediate, no service restart)?"];
        case 'allow':
            if ($kind !== 'ip' || empty($it['ip'])) return null;
            return ['label' => '✅ Allow ' . $it['ip'], 'cls' => 'good', 'url' => 'index.cgi?page=login-monitor',
                'fields' => ['la_action' => 'allow', 'ips' => $it['ip'], 'smpro_csrf' => $tok('la_csf')],
                'confirm' => "ALLOW IP " . $it['ip'] . " in CSF (whitelist)?"];
        case 'investigate':
            $q = $it['ip'] ?? ($it['account'] ?? ''); if ($q === '') return null;
            return ['label' => '🔎 Investigate', 'cls' => 'ghost', 'nav' => 'index.cgi?page=account-audit&do=search&q=' . rawurlencode($q) . '&loglines=200000'];
    }
    return null;
}

/**
 * Turn a section context into a structured decision plan with executable buttons.
 * Returns ['ok'=>bool,'summary'=>,'decisions'=>[{action,label,why,exec}],'fallback'=>?text].
 * If there are no actionable items, returns ok=true with empty decisions (+ optional note).
 */
/**
 * Robustly extract a JSON object/array from a model reply. Handles: clean JSON, ```json fenced blocks,
 * JSON wrapped in prose, and trailing commas. Returns array or null. This replaces fragile
 * preg_match('/\{.*\}/s') parsing that broke whenever the model added a code fence or a sentence.
 */
function smpro_ai_json(string $txt) {
    $txt = trim($txt);
    if ($txt === '') return null;
    if (preg_match('/```(?:json)?\s*([\s\S]*?)```/i', $txt, $m)) $txt = trim($m[1]);   // strip code fences
    $d = json_decode($txt, true);
    if (is_array($d)) return $d;
    // pull the first balanced {...} or [...] block (string-aware, so braces inside strings don't fool it)
    foreach (['{' => '}', '[' => ']'] as $open => $close) {
        $s = strpos($txt, $open); if ($s === false) continue;
        $depth = 0; $inStr = false; $esc = false;
        for ($i = $s, $n = strlen($txt); $i < $n; $i++) {
            $c = $txt[$i];
            if ($inStr) { if ($esc) $esc = false; elseif ($c === '\\') $esc = true; elseif ($c === '"') $inStr = false; continue; }
            if ($c === '"') { $inStr = true; continue; }
            if ($c === $open) $depth++;
            elseif ($c === $close && --$depth === 0) { $d = json_decode(substr($txt, $s, $i - $s + 1), true); if (is_array($d)) return $d; break; }
        }
    }
    $d = json_decode(preg_replace('/,\s*([}\]])/', '$1', $txt), true);   // last resort: drop trailing commas
    return is_array($d) ? $d : null;
}

/**
 * Ask the model for JSON and parse it robustly, with ONE stricter retry if the first reply doesn't parse
 * (common when a model is chatty or returns a rate-limited/empty body). Returns
 * ['ok'=>bool,'data'=>array|null,'text','error','provider','model']. Every "decide/plan" button uses this.
 */
function smpro_ai_chat_json(string $sys, string $usr, array $opts = []) {
    $r = smpro_ai_chat($sys, $usr, $opts);
    if (empty($r['ok'])) return ['ok' => false, 'data' => null, 'error' => $r['error'] ?? 'AI request failed', 'provider' => $r['provider'] ?? '', 'model' => $r['model'] ?? ''];
    $data = smpro_ai_json((string)($r['text'] ?? ''));
    if ($data === null) {                                                // retry once, harder
        $r2 = smpro_ai_chat($sys, $usr . "\n\nIMPORTANT: Output ONLY the raw JSON. No prose, no explanation, no markdown code fences.",
            ['max_tokens' => (int)($opts['max_tokens'] ?? 800), 'temperature' => 0, 'context' => (string)($opts['context'] ?? 'json') . '_retry']);
        if (!empty($r2['ok'])) { $d2 = smpro_ai_json((string)($r2['text'] ?? '')); if ($d2 !== null) { $data = $d2; $r = $r2; } }
    }
    return ['ok' => $data !== null, 'data' => $data, 'text' => $r['text'] ?? '',
            'error' => $data === null ? 'The AI was busy or replied without a clear decision — try again.' : '',
            'provider' => $r['provider'] ?? '', 'model' => $r['model'] ?? ''];
}

function smpro_ai_decide_plan(string $ctx): array {
    $pack = smpro_ai_decide_pack($ctx);
    $kind = smpro_ai_decide_kind($ctx);
    if ($kind === '') return ['ok' => true, 'decisions' => [], 'note' => 'This section has no auto-executable targets. Use “Think” for guidance, or open Forensics / Login & Access / Imunify360 Reports where actions live.'];
    if (!$pack) return ['ok' => true, 'decisions' => [], 'note' => 'Good news — no actionable ' . ($kind === 'ip' ? 'offenders' : $kind . ' targets') . ' found right now in this section.'];

    // Ask the model to pick item+action from the pack only.
    $lines = '';
    foreach ($pack as $it) $lines .= $it['id'] . ' | ' . $it['detail'] . ' | allowed_actions=' . implode(',', $it['actions']) . "\n";
    $sys = "You are the decision engine of Safety Monitor Pro (WHM/cPanel security). You are given a list of REAL actionable items on this server, each with an id and the only allowed actions. Choose the best action for the items that genuinely need one, in priority order. NEVER invent ids or actions. Prefer safe reversible actions; only suspend an account or delete a file when the evidence clearly warrants it. Respond with STRICT JSON only, no prose: {\"summary\":\"one short sentence\",\"decisions\":[{\"id\":\"<id>\",\"action\":\"<allowed action>\",\"why\":\"short reason\"}]}";
    $usr = "Items:\n" . $lines . "\nReturn the JSON now.";
    $r = smpro_ai_chat_json($sys, smpro_ai_redact($usr), ['max_tokens' => 900, 'temperature' => 0.1, 'context' => 'decide_' . $ctx]);
    if (empty($r['ok'])) return ['ok' => false, 'error' => $r['error'] ?? 'AI request failed', 'provider' => $r['provider'] ?? '', 'model' => $r['model'] ?? ''];
    $obj = $r['data'];
    $byId = []; foreach ($pack as $it) $byId[$it['id']] = $it;
    $decisions = []; $seen = [];
    foreach ((array)($obj['decisions'] ?? []) as $d) {
        $id = (string)($d['id'] ?? ''); $act = strtolower((string)($d['action'] ?? ''));
        if (!isset($byId[$id])) continue;
        $it = $byId[$id];
        if (!in_array($act, $it['actions'], true)) continue;
        $sig = $id . ':' . $act; if (isset($seen[$sig])) continue; $seen[$sig] = 1;
        $exec = smpro_ai_decide_exec($it, $act);
        if (!$exec) continue;
        $decisions[] = ['action' => $act, 'label' => $exec['label'], 'why' => trim((string)($d['why'] ?? '')),
            'target' => $it['label'], 'exec' => $exec];
    }
    return ['ok' => true, 'summary' => (string)($obj['summary'] ?? ''), 'decisions' => $decisions,
            'provider' => $r['provider'] ?? '', 'model' => $r['model'] ?? '',
            'note' => $decisions ? '' : 'The AI did not select any action for the current items — they may not require intervention.'];
}

/** Light redaction before sending text to an external model. */
function smpro_ai_redact(string $s): string {
    if (function_exists('smpro_redact_sensitive')) $s = smpro_redact_sensitive($s);
    // strip obvious secrets the model never needs (this text is sent to a THIRD-PARTY AI endpoint)
    $s = preg_replace('/\b(cpsess\d+)\b/i', 'cpsessXXXX', $s);
    $s = preg_replace('/(password|passwd|secret|api[_-]?key|token|bearer|authorization)\s*[=:]\s*\S+/i', '$1=REDACTED', $s);
    // PEM / SSH / cert key blocks → drop entirely (never leak key material off-box)
    $s = preg_replace('/-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----/s', '[REDACTED PRIVATE KEY]', $s);
    $s = preg_replace('/-----BEGIN (?:OPENSSH|RSA|EC|DSA|PGP)[^-]*-----.*?-----END [^-]*-----/s', '[REDACTED KEY BLOCK]', $s);
    $s = preg_replace('/\bssh-(?:rsa|ed25519|dss)\s+[A-Za-z0-9+\/=]{40,}/', '[REDACTED SSH KEY]', $s);
    // /etc/shadow-style password hashes ($6$…/$2y$…/$y$…) + long base64 blobs (keys/tokens)
    $s = preg_replace('/\$(?:1|2[aby]?|5|6|y|gy)\$[^\s:]{8,}/', '[REDACTED HASH]', $s);
    $s = preg_replace('/\b[A-Za-z0-9+\/]{120,}={0,2}/', '[REDACTED BLOB]', $s);
    return $s;
}
