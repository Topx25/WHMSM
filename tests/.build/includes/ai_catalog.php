<?php
/**
 * ai_catalog.php — selectable AI providers (free-first) with signup/API-key links, a paid/free/limited
 * badge + the free limit, and local usage (consumed today vs the limit + remaining). All providers are
 * OpenAI-compatible (POST <base>/chat/completions), so saving a key + activating one is enough for
 * smpro_ai_chat() to use it. Keys/config reuse the AI Providers engine vault (mspro_ai304_*).
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

define('SMPRO_AI_USAGE', SMPRO_VARLIB . '/ai/usage.json');

/** id => provider metadata. tier: free | free_limited | paid. req_day = approx free request/day cap (null = token-based/unknown). */
function smpro_ai_catalog(): array {
    return [
        'groq' => [
            'label' => 'Groq', 'tier' => 'free', 'req_day' => 14400,
            'limit' => 'Free — about 14,400 requests/day (30/min). Very fast Llama/Mixtral models.',
            'base_url' => 'https://api.groq.com/openai/v1', 'model' => 'llama-3.3-70b-versatile',
            'free_models' => ['llama-3.3-70b-versatile', 'llama-3.1-8b-instant', 'gemma2-9b-it'], 'paid_models' => [],
            'signup' => 'https://console.groq.com', 'keys' => 'https://console.groq.com/keys',
        ],
        'cerebras' => [
            'label' => 'Cerebras', 'tier' => 'free', 'req_day' => null,
            'limit' => 'Free — about 1 million tokens/day, extremely fast (Llama 3.3 70B).',
            'base_url' => 'https://api.cerebras.ai/v1', 'model' => 'llama-3.3-70b',
            'free_models' => ['llama-3.3-70b', 'llama3.1-8b'], 'paid_models' => [],
            'signup' => 'https://cloud.cerebras.ai', 'keys' => 'https://cloud.cerebras.ai/platform',
        ],
        'gemini' => [
            'label' => 'Google Gemini', 'tier' => 'free_limited', 'req_day' => 1500,
            'limit' => 'Free tier — about 1,500 requests/day on Gemini Flash. Higher caps are paid.',
            'base_url' => 'https://generativelanguage.googleapis.com/v1beta/openai', 'model' => 'gemini-2.0-flash',
            'free_models' => ['gemini-2.0-flash', 'gemini-1.5-flash', 'gemini-1.5-flash-8b'], 'paid_models' => ['gemini-1.5-pro'],
            'signup' => 'https://aistudio.google.com', 'keys' => 'https://aistudio.google.com/apikey',
        ],
        'openrouter' => [
            'label' => 'OpenRouter', 'tier' => 'free_limited', 'req_day' => 1000,
            'limit' => 'Free models (":free") — roughly 50–1000 requests/day depending on account credit.',
            'base_url' => 'https://openrouter.ai/api/v1', 'model' => 'meta-llama/llama-3.3-70b-instruct:free',
            'free_models' => ['meta-llama/llama-3.3-70b-instruct:free', 'google/gemma-2-9b-it:free', 'mistralai/mistral-7b-instruct:free'],
            'paid_models' => ['openai/gpt-4o-mini', 'google/gemini-flash-1.5'],
            'signup' => 'https://openrouter.ai', 'keys' => 'https://openrouter.ai/keys',
        ],
        'mistral' => [
            'label' => 'Mistral AI', 'tier' => 'free_limited', 'req_day' => null,
            'limit' => 'Free "Experiment" plan — rate-limited (about 1 req/sec, monthly token cap).',
            'base_url' => 'https://api.mistral.ai/v1', 'model' => 'mistral-small-latest',
            'free_models' => ['mistral-small-latest', 'open-mistral-7b'], 'paid_models' => ['mistral-large-latest'],
            'signup' => 'https://console.mistral.ai', 'keys' => 'https://console.mistral.ai/api-keys',
        ],
        'qwen' => [
            'label' => 'Alibaba Qwen', 'tier' => 'free_limited', 'req_day' => null,
            'limit' => 'Free quota on DashScope (international) for new accounts, then pay-as-you-go.',
            'base_url' => 'https://dashscope-intl.aliyuncs.com/compatible-mode/v1', 'model' => 'qwen-turbo',
            'free_models' => ['qwen-turbo', 'qwen-plus'], 'paid_models' => ['qwen-max'],
            'signup' => 'https://modelstudio.console.alibabacloud.com', 'keys' => 'https://modelstudio.console.alibabacloud.com/?tab=playground#/api-key',
        ],
        'openai' => [
            'label' => 'OpenAI', 'tier' => 'paid', 'req_day' => null,
            'limit' => 'Paid (pay-as-you-go). No permanent free tier — you are billed per token.',
            'base_url' => 'https://api.openai.com/v1', 'model' => 'gpt-4o-mini',
            'free_models' => [], 'paid_models' => ['gpt-4o-mini', 'gpt-4o', 'gpt-3.5-turbo'],
            'signup' => 'https://platform.openai.com/signup', 'keys' => 'https://platform.openai.com/api-keys',
        ],
    ];
}

/** Per-provider state: has a key saved? is it enabled (in active_providers)? which model is selected? */
function smpro_ai_provider_state(string $id): array {
    $cat = smpro_ai_catalog(); $p = $cat[$id] ?? [];
    if (function_exists('smpro_ai_engine_loaded')) smpro_ai_engine_loaded();
    $key = function_exists('mspro_ai304_get_secret') ? (string)mspro_ai304_get_secret($id) : '';
    $hasKey = $key !== '';
    $mask = $hasKey ? (mb_substr($key, 0, 5) . str_repeat('•', 6)) : '';   // show first 5 chars + 6 dots
    $cfg = function_exists('mspro_ai304_load_config') ? mspro_ai304_load_config() : [];
    $active = is_array($cfg['active_providers'] ?? null) ? $cfg['active_providers'] : [];
    $model = (string)($cfg[$id]['model'] ?? ($p['model'] ?? ''));
    $models = is_array($cfg[$id]['models'] ?? null) ? array_values(array_filter(array_map('strval', $cfg[$id]['models']))) : [];
    if (!$models && $model !== '') $models = [$model];                    // back-compat: single model -> list of one
    $live = is_array($cfg[$id]['models_live'] ?? null) ? array_values(array_filter(array_map('strval', $cfg[$id]['models_live']))) : [];
    $apiLimit = is_array($cfg[$id]['api_limit'] ?? null) ? $cfg[$id]['api_limit'] : null;
    return ['has_key' => $hasKey, 'enabled' => in_array($id, $active, true) && $hasKey, 'model' => $model, 'models' => $models, 'live' => $live, 'mask' => $mask, 'api_limit' => $apiLimit];
}

/** Fetch the REAL model list from the provider's API (GET <base>/models with the saved key) and cache it. */
function smpro_ai_provider_models(string $id): array {
    $cat = smpro_ai_catalog(); if (!isset($cat[$id])) return ['ok' => false, 'msg' => 'unknown provider'];
    if (function_exists('smpro_ai_engine_loaded')) smpro_ai_engine_loaded();
    $key = function_exists('mspro_ai304_get_secret') ? (string)mspro_ai304_get_secret($id) : '';
    if ($key === '') return ['ok' => false, 'msg' => 'Save an API key first'];
    $url = rtrim($cat[$id]['base_url'], '/') . '/models';
    // in-process curl (smpro_http) so the Bearer API key stays in memory, NOT on the command line (/proc leak)
    $res = function_exists('smpro_http')
        ? smpro_http($url, ['timeout' => 20, 'follow' => true, 'headers' => ['Authorization: Bearer ' . $key, 'Accept: application/json']])
        : ['code' => 0, 'body' => ''];
    $code = (int)$res['code']; $j = json_decode((string)$res['body'], true);
    if ($code < 200 || $code >= 300 || !is_array($j)) {
        $err = is_array($j) && isset($j['error']) ? (is_array($j['error']) ? ($j['error']['message'] ?? 'error') : $j['error']) : ('HTTP ' . $code);
        return ['ok' => false, 'msg' => (string)$err];
    }
    // OpenAI-compatible: {data:[{id:...}]}. Some return {models:[{name|id}]} or a bare list.
    $list = $j['data'] ?? $j['models'] ?? (array_is_list($j) ? $j : []);
    // exclude non-chat model families (speech/TTS/embeddings/rerank/image) — they can't do chat completions
    $nonchat = '~(whisper|orpheus|[\-_/]tts$|[\-_/]tts[\-_/]|^tts|playai-tts|embed|rerank|bark|stable-diffusion|sdxl|flux\.1|dall-?e|moderation|distil-whisper|guard-stream)~i';
    $models = []; $total = 0; $dropped = 0;
    foreach ((array)$list as $m) {
        $total++;
        $mid = is_array($m) ? (string)($m['id'] ?? $m['name'] ?? '') : (string)$m;
        $mid = preg_replace('~^models/~', '', $mid);                      // gemini prefixes "models/"
        if (is_array($m) && array_key_exists('active', $m) && $m['active'] === false) { $dropped++; continue; }  // decommissioned/inactive
        if ($mid === '' || !preg_match('~^[A-Za-z0-9._:/\-]{1,80}$~', $mid)) { $dropped++; continue; }
        if (preg_match($nonchat, $mid)) { $dropped++; continue; }          // audio / TTS / embedding / image — not chat
        $models[$mid] = 1;
        if (count($models) >= 2000) break;                                 // cap — a hostile provider can't bloat our config
    }
    $models = array_keys($models); sort($models, SORT_NATURAL | SORT_FLAG_CASE);
    if (!$models) return ['ok' => false, 'msg' => 'No chat-capable models returned by the provider.'];
    $cfg = mspro_ai304_load_config();                                     // cache the live list
    $cfg[$id] = array_merge((array)($cfg[$id] ?? []), ['models_live' => $models, 'models_live_at' => time()]);
    smpro_ai_cfg_write($cfg);
    return ['ok' => true, 'models' => $models, 'count' => count($models), 'filtered' => $dropped, 'total' => $total];
}

/** Set MULTIPLE selected models for a provider (multi-select). First one becomes the primary model. */
function smpro_ai_provider_setmodels(string $id, array $models): array {
    $cat = smpro_ai_catalog(); if (!isset($cat[$id])) return ['ok' => false, 'msg' => 'unknown provider'];
    $clean = [];
    foreach ($models as $m) { $m = trim((string)$m); if ($m !== '' && preg_match('~^[A-Za-z0-9._:/\-]{1,80}$~', $m)) $clean[$m] = 1; }
    $clean = array_keys($clean);
    if (!$clean) return ['ok' => false, 'msg' => 'Select at least one model'];
    if (function_exists('smpro_ai_engine_loaded')) smpro_ai_engine_loaded();
    $cfg = mspro_ai304_load_config();
    $cfg[$id] = array_merge((array)($cfg[$id] ?? []), ['models' => $clean, 'model' => $clean[0]]);
    smpro_ai_cfg_write($cfg);
    $paid = array_values(array_intersect($clean, $cat[$id]['paid_models'] ?? []));
    return ['ok' => true, 'models' => $clean, 'primary' => $clean[0], 'paid' => $paid];
}

/** Enable/disable a provider (add/remove from active_providers) without touching its key. */
function smpro_ai_provider_toggle(string $id, bool $on): array {
    if (!isset(smpro_ai_catalog()[$id])) return ['ok' => false, 'msg' => 'unknown provider'];
    if (function_exists('smpro_ai_engine_loaded')) smpro_ai_engine_loaded();
    if (!function_exists('mspro_ai304_load_config')) return ['ok' => false, 'msg' => 'engine unavailable'];
    if ($on && (string)mspro_ai304_get_secret($id) === '') return ['ok' => false, 'msg' => 'Save an API key first'];
    $cfg = mspro_ai304_load_config();
    $act = is_array($cfg['active_providers'] ?? null) ? array_values($cfg['active_providers']) : [];
    $act = array_values(array_filter($act, fn($x) => $x !== $id));
    if ($on) { array_unshift($act, $id); $cfg['provider'] = $id; }
    $cfg['active_providers'] = $act;
    smpro_ai_cfg_write($cfg);
    return ['ok' => true, 'enabled' => $on];
}

/** Set the model for a provider (used by the free-model dropdown; paid models require an explicit pick). */
function smpro_ai_provider_setmodel(string $id, string $model): array {
    $cat = smpro_ai_catalog(); if (!isset($cat[$id])) return ['ok' => false, 'msg' => 'unknown provider'];
    $allowed = array_merge($cat[$id]['free_models'] ?? [], $cat[$id]['paid_models'] ?? []);
    if ($model === '' || !in_array($model, $allowed, true)) return ['ok' => false, 'msg' => 'unknown model'];
    if (function_exists('smpro_ai_engine_loaded')) smpro_ai_engine_loaded();
    $cfg = mspro_ai304_load_config();
    $cfg[$id] = array_merge((array)($cfg[$id] ?? []), ['model' => $model]);
    smpro_ai_cfg_write($cfg);
    $paid = in_array($model, $cat[$id]['paid_models'] ?? [], true);
    return ['ok' => true, 'model' => $model, 'paid' => $paid];
}

/** Send a tiny live request to a provider+model and report ok/latency or the error. */
function smpro_ai_provider_test(string $id, string $model = ''): array {
    $cat = smpro_ai_catalog(); if (!isset($cat[$id])) return ['ok' => false, 'msg' => 'unknown provider'];
    if (function_exists('smpro_ai_engine_loaded')) smpro_ai_engine_loaded();
    $key = function_exists('mspro_ai304_get_secret') ? (string)mspro_ai304_get_secret($id) : '';
    if ($key === '') return ['ok' => false, 'msg' => 'No API key saved'];
    $model = $model !== '' ? $model : (smpro_ai_provider_state($id)['model'] ?: $cat[$id]['model']);
    $payload = ['model' => $model, 'max_tokens' => 5, 'messages' => [['role' => 'user', 'content' => 'ping']]];
    $t0 = microtime(true);
    $res = mspro_ai304_http_post_json(rtrim($cat[$id]['base_url'], '/') . '/chat/completions', $key, $payload, 20);
    $ms = (int)round((microtime(true) - $t0) * 1000);
    if (!empty($res['ok'])) return ['ok' => true, 'model' => $model, 'ms' => $ms];
    $code = (int)($res['http_code'] ?? 0);
    // A 429 (rate-limited) or a transient 408/5xx does NOT mean the model is broken — the endpoint accepted
    // the model, it just throttled/hiccuped this instant. Report it as WORKING (throttled) so it is neither
    // shown as failed nor pruned from the list. Only a hard reject (400/404/501) or an auth error
    // (401/402/403) means the model is genuinely unusable for chat.
    if (in_array($code, [429, 408, 500, 502, 503, 504], true)) {
        return ['ok' => true, 'throttled' => true, 'model' => $model, 'ms' => $ms,
                'msg' => $code === 429 ? 'rate-limited (working)' : 'transient HTTP ' . $code . ' (working)'];
    }
    $err = function_exists('mspro_ai307_sanitize_provider_message') ? mspro_ai307_sanitize_provider_message((string)($res['error'] ?? 'failed')) : (string)($res['error'] ?? 'failed');
    return ['ok' => false, 'model' => $model, 'ms' => $ms, 'msg' => 'HTTP ' . $code . ' ' . $err];
}

/** Write the engine config JSON (shared helper). */
function smpro_ai_cfg_write(array $cfg): void {
    $path = function_exists('mspro_ai304_config_path') ? mspro_ai304_config_path() : (SMPRO_VARLIB . '/ai/config/ai_providers.json');
    @is_dir(dirname($path)) || @mkdir(dirname($path), 0700, true);
    @file_put_contents($path, json_encode($cfg, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX); @chmod($path, 0600);
}

/* ---------------- per-day usage (requests + tokens sent from THIS plugin) ---------------- */
function smpro_ai_usage_load(): array { $d = is_file(SMPRO_AI_USAGE) ? json_decode((string)@file_get_contents(SMPRO_AI_USAGE), true) : null; return is_array($d) ? $d : []; }
function smpro_ai_usage_bump(string $provider, int $tokens = 0): void {
    if ($provider === '') return;
    $u = smpro_ai_usage_load();
    if (($u['_day'] ?? '') !== date('Y-m-d')) $u = ['_day' => date('Y-m-d')];        // reset at midnight
    $u[$provider]['req'] = (int)($u[$provider]['req'] ?? 0) + 1;
    $u[$provider]['tok'] = (int)($u[$provider]['tok'] ?? 0) + max(0, $tokens);
    @is_dir(dirname(SMPRO_AI_USAGE)) || @mkdir(dirname(SMPRO_AI_USAGE), 0700, true);
    @file_put_contents(SMPRO_AI_USAGE, json_encode($u, JSON_UNESCAPED_SLASHES), LOCK_EX); @chmod(SMPRO_AI_USAGE, 0600);
}
function smpro_ai_usage(string $provider): array {
    $u = smpro_ai_usage_load();
    if (($u['_day'] ?? '') !== date('Y-m-d')) return ['req' => 0, 'tok' => 0];
    return ['req' => (int)($u[$provider]['req'] ?? 0), 'tok' => (int)($u[$provider]['tok'] ?? 0)];
}

/* ---------------- save a catalog provider's key + activate it ---------------- */
function smpro_ai_provider_save(string $id, string $key): array {
    $cat = smpro_ai_catalog();
    if (!isset($cat[$id])) return ['ok' => false, 'msg' => 'Unknown provider'];
    if (function_exists('smpro_ai_engine_loaded')) smpro_ai_engine_loaded();                          // lazy-load the engine (vault/config)
    if (!function_exists('mspro_ai304_save_secret') || !function_exists('mspro_ai304_load_config')) return ['ok' => false, 'msg' => 'AI engine unavailable'];
    if ($key !== '') mspro_ai304_save_secret($id, $key);
    if ($key === '' && (string)mspro_ai304_get_secret($id) === '') return ['ok' => false, 'msg' => 'Enter the API key first'];
    $cfg = mspro_ai304_load_config();
    $cfg[$id] = array_merge((array)($cfg[$id] ?? []), ['base_url' => $cat[$id]['base_url'], 'model' => $cat[$id]['model'], 'timeout_seconds' => 45]);
    $act = is_array($cfg['active_providers'] ?? null) ? $cfg['active_providers'] : [];
    $act = array_values(array_unique(array_merge([$id], $act)));                          // prefer the just-saved provider
    $cfg['active_providers'] = $act; $cfg['provider'] = $id;
    $path = function_exists('mspro_ai304_config_path') ? mspro_ai304_config_path() : (SMPRO_VARLIB . '/ai/config/ai_providers.json');
    @is_dir(dirname($path)) || @mkdir(dirname($path), 0700, true);
    @file_put_contents($path, json_encode($cfg, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX); @chmod($path, 0600);
    return ['ok' => true];
}

/* ---------------- ROOT model validation: probe each model live + read the API's own rate limits ----------------
 * A model is only "usable for chat" if a real /chat/completions ping is accepted. We classify by the
 * provider's HTTP code — dropping ONLY hard rejections (400/404/501 = decommissioned, no chat support,
 * terms required), and KEEPING success/rate-limit/transient (200/429/5xx). The provider's own limit is
 * read from the standard x-ratelimit-* response headers — the real per-model limit, not our hit count. */
function smpro_ai_http_chat_probe(string $base, string $key, string $model, int $timeout = 12): array {
    $payload = json_encode(['model' => $model, 'max_tokens' => 1, 'messages' => [['role' => 'user', 'content' => 'ping']]], JSON_UNESCAPED_SLASHES);
    // in-process curl (key stays off the command line); capture response headers for the x-ratelimit-* reads
    $res = function_exists('smpro_http')
        ? smpro_http(rtrim($base, '/') . '/chat/completions', ['method' => 'POST', 'timeout' => (int)$timeout, 'follow' => true, 'want_headers' => true,
            'headers' => ['Authorization: Bearer ' . $key, 'Content-Type: application/json'], 'body' => $payload])
        : ['code' => 0, 'hdr' => ''];
    $code = (int)$res['code']; $raw = (string)($res['hdr'] ?? '');
    $h = function ($n) use ($raw) { return preg_match('~^' . preg_quote($n, '~') . ':\s*(.+)$~im', $raw, $m) ? trim($m[1]) : ''; };
    return [
        'code' => $code,
        'limit_tokens'   => $h('x-ratelimit-limit-tokens'),     'remaining_tokens'   => $h('x-ratelimit-remaining-tokens'),
        'limit_requests' => $h('x-ratelimit-limit-requests'),   'remaining_requests' => $h('x-ratelimit-remaining-requests'),
        'reset_tokens'   => $h('x-ratelimit-reset-tokens'),     'retry_after'        => $h('retry-after'),
    ];
}
/** Fetch + probe every (filtered) model for a provider; keep only the ones the API accepts; save them + the real limit. */
function smpro_ai_provider_verify(string $id): array {
    $cat = smpro_ai_catalog(); if (!isset($cat[$id])) return ['ok' => false, 'msg' => 'unknown provider'];
    if (function_exists('smpro_ai_engine_loaded')) smpro_ai_engine_loaded();
    $key = function_exists('mspro_ai304_get_secret') ? (string)mspro_ai304_get_secret($id) : '';
    if ($key === '') return ['ok' => false, 'msg' => 'Save an API key first'];
    $base = rtrim((string)$cat[$id]['base_url'], '/');
    $fetch = smpro_ai_provider_models($id);                                 // name/active-filtered live list (or error)
    $models = !empty($fetch['ok']) ? $fetch['models'] : array_values($cat[$id]['free_models'] ?? []);
    $models = array_slice($models, 0, 40);
    if (!$models) return ['ok' => false, 'msg' => 'No models to verify (fetch failed?).'];

    $working = []; $results = []; $limit = null;
    foreach ($models as $m) {
        $p = smpro_ai_http_chat_probe($base, $key, $m);
        $code = $p['code'];
        $keep = in_array($code, [200, 201, 429, 408, 500, 502, 503, 504], true);   // drop only hard rejects (400/404/501…)
        if ($keep) $working[] = $m;
        if ($limit === null && ($p['limit_tokens'] !== '' || $p['limit_requests'] !== '')) {
            $limit = ['tokens' => $p['limit_tokens'], 'rem_tokens' => $p['remaining_tokens'], 'requests' => $p['limit_requests'], 'rem_requests' => $p['remaining_requests']];
        }
        $results[] = ['model' => $m, 'code' => $code, 'keep' => $keep, 'reason' => $code === 429 ? 'rate-limited (ok)' : ($keep ? 'ok' : 'rejected ' . $code)];
    }
    if (!$working) return ['ok' => false, 'msg' => 'No model passed validation — the provider rejected all of them.', 'results' => $results];

    $cfg = mspro_ai304_load_config();
    $cfg[$id] = array_merge((array)($cfg[$id] ?? []), ['base_url' => $base, 'models' => array_values($working), 'model' => $working[0], 'timeout_seconds' => 45, 'api_limit' => $limit, 'api_limit_at' => time()]);
    $act = is_array($cfg['active_providers'] ?? null) ? $cfg['active_providers'] : [];
    if (!in_array($id, $act, true)) $act[] = $id;
    $cfg['active_providers'] = array_values(array_unique($act));
    if (empty($cfg['provider'])) $cfg['provider'] = $id;
    smpro_ai_cfg_write($cfg);
    if (function_exists('smpro_audit')) smpro_audit('ai_verify', ['provider' => $id, 'kept' => count($working), 'total' => count($models)]);
    return ['ok' => true, 'kept' => count($working), 'total' => count($models), 'dropped' => count($models) - count($working), 'limit' => $limit, 'results' => $results];
}

/* ---------------- hourly auto-health: re-probe every active provider's saved models ----------------
 * Runs from the notify cron (self-gated to once per hour). For each provider that has a key, it pings each
 * saved model and removes ONLY the genuinely-dead ones (HTTP 400/404/501 = decommissioned / no chat / terms
 * required) and the auth-dead ones (401/402/403). Models returning 200/429/5xx are KEPT — a 429 means the
 * model works but is throttled right now, so dropping it would wrongly shrink the fallback chain. The result
 * (so the UI only ever shows currently-usable models) and the real per-model API limit are saved. */
define('SMPRO_AI_PRUNE_STATE', SMPRO_VARLIB . '/ai/health.json');
function smpro_ai_autoprune(bool $force = false): array {
    if (function_exists('smpro_ai_engine_loaded')) smpro_ai_engine_loaded();
    if (!function_exists('mspro_ai304_load_config')) return ['ok' => false, 'msg' => 'engine unavailable'];

    // self-gate: at most once per hour unless forced (UI button / manual run)
    $state = is_file(SMPRO_AI_PRUNE_STATE) ? (array)json_decode((string)@file_get_contents(SMPRO_AI_PRUNE_STATE), true) : [];
    if (!$force && (time() - (int)($state['last_run'] ?? 0)) < 3600) return ['ok' => true, 'skipped' => 'not_due'];

    $cat = smpro_ai_catalog(); $cfg = mspro_ai304_load_config();
    $active = is_array($cfg['active_providers'] ?? null) ? array_values($cfg['active_providers']) : [];
    $report = []; $touched = false;

    // HARD wall-clock budget for the whole sweep so this can NEVER dominate the 15-min notify cron and
    // cause runs to pile up (the cause of the 1.0.56 hang). Each probe also gets a short timeout and the
    // per-run model count is capped; anything not reached this hour is simply re-checked next hour.
    $deadline   = time() + 90;          // stop probing after ~90s total, no matter what
    $probeTo    = 6;                     // seconds per model probe (was 12)
    $perProvCap = $force ? 25 : 10;      // models probed per provider per run (manual "Check now" can do more)

    foreach ($active as $id) {
        if (time() >= $deadline) break;                                         // budget spent → finish next hour
        if (!isset($cat[$id])) continue;
        $key = function_exists('mspro_ai304_get_secret') ? (string)mspro_ai304_get_secret($id) : '';
        if ($key === '') continue;                                              // no key → can't probe; leave as-is
        $base = rtrim((string)($cfg[$id]['base_url'] ?? $cat[$id]['base_url']), '/');
        $models = array_values((array)($cfg[$id]['models'] ?? []));
        if (!$models) continue;
        $allModels = $models;                                                   // keep the full list; only PROBE a slice
        $models = array_slice($models, 0, $perProvCap);

        $keep = []; $dropped = []; $limit = null;
        foreach ($models as $m) {
            if (time() >= $deadline) { $keep[] = $m; continue; }                // out of budget → keep unprobed as-is
            $p = smpro_ai_http_chat_probe($base, $key, $m, $probeTo);
            $code = (int)$p['code'];
            // keep success + rate-limit + transient; drop hard rejects and auth-dead
            if (in_array($code, [200, 201, 429, 408, 500, 502, 503, 504], true)) {
                $keep[] = $m;
            } elseif (in_array($code, [400, 401, 402, 403, 404, 501], true)) {
                $dropped[] = ['model' => $m, 'code' => $code];
            } else {
                $keep[] = $m;                                                   // 0/unknown (network blip) → keep, retry next hour
            }
            if ($limit === null && ($p['limit_tokens'] !== '' || $p['limit_requests'] !== '')) {
                $limit = ['tokens' => $p['limit_tokens'], 'rem_tokens' => $p['remaining_tokens'], 'requests' => $p['limit_requests'], 'rem_requests' => $p['remaining_requests']];
            }
        }
        // final list = probed-survivors + the unprobed tail (models beyond the per-run cap are PRESERVED,
        // never silently dropped — they get probed in a future run).
        $finalModels = array_merge(array_values($keep), array_slice($allModels, $perProvCap));
        if ($finalModels) {
            // only rewrite when something actually changed (avoid needless disk writes / config churn)
            $changed = (array_values($finalModels) !== $allModels) || ($limit !== null);
            if ($changed) {
                $cfg[$id] = array_merge((array)($cfg[$id] ?? []), ['models' => array_values($finalModels), 'model' => $finalModels[0]]);
                if ($limit !== null) { $cfg[$id]['api_limit'] = $limit; $cfg[$id]['api_limit_at'] = time(); }
                $touched = true;
            }
        }
        $report[$id] = ['kept' => count($finalModels), 'dropped' => count($dropped), 'dead' => $dropped];
    }

    if ($touched) smpro_ai_cfg_write($cfg);
    @is_dir(dirname(SMPRO_AI_PRUNE_STATE)) || @mkdir(dirname(SMPRO_AI_PRUNE_STATE), 0700, true);
    @file_put_contents(SMPRO_AI_PRUNE_STATE, json_encode(['last_run' => time(), 'report' => $report], JSON_UNESCAPED_SLASHES), LOCK_EX);
    @chmod(SMPRO_AI_PRUNE_STATE, 0600);
    if (function_exists('smpro_audit') && $touched) smpro_audit('ai_autoprune', ['report' => $report]);
    return ['ok' => true, 'report' => $report];
}

/* ---------------- select ALL free models on every provider that has a key (one click) ---------------- */
function smpro_ai_enable_all_free(): array {
    if (function_exists('smpro_ai_engine_loaded')) smpro_ai_engine_loaded();
    if (!function_exists('mspro_ai304_load_config')) return ['ok' => false, 'msg' => 'engine unavailable'];
    $cat = smpro_ai_catalog(); $cfg = mspro_ai304_load_config();
    $active = is_array($cfg['active_providers'] ?? null) ? array_values($cfg['active_providers']) : [];
    $enabled = 0; $models = 0; $noKey = [];
    foreach ($cat as $id => $p) {
        $free = array_values($p['free_models'] ?? []);
        if (!$free) continue;                                              // paid-only provider (e.g. openai) → skip
        $key = function_exists('mspro_ai304_get_secret') ? (string)mspro_ai304_get_secret($id) : '';
        if ($key === '') { $noKey[] = $p['label']; continue; }             // only providers with a saved key
        $cfg[$id] = array_merge((array)($cfg[$id] ?? []), ['base_url' => $p['base_url'], 'models' => $free, 'model' => $free[0], 'timeout_seconds' => 45]);
        if (!in_array($id, $active, true)) $active[] = $id;
        $enabled++; $models += count($free);
    }
    if (!$enabled) return ['ok' => false, 'msg' => 'Save an API key for at least one free provider first' . ($noKey ? ' (e.g. ' . implode(', ', array_slice($noKey, 0, 3)) . ')' : '') . '.'];
    $cfg['active_providers'] = array_values(array_unique($active));
    if (empty($cfg['provider'])) $cfg['provider'] = $active[0] ?? '';
    smpro_ai_cfg_write($cfg);
    if (function_exists('smpro_audit')) smpro_audit('ai_all_free', ['providers' => $enabled, 'models' => $models]);
    return ['ok' => true, 'providers' => $enabled, 'models' => $models, 'msg' => 'Enabled ' . $models . ' free model(s) across ' . $enabled . ' provider(s).'];
}

/* ---------------- render the catalog panel ---------------- */
function smpro_ai_catalog_render(): void {
    $cat  = smpro_ai_catalog();
    $csrf = smpro_csrf_generate('aiprov');
    $badge = ['free' => ['#16a34a', '&#9679; FREE'], 'free_limited' => ['#b45309', '&#9679; FREE (limited)'], 'paid' => ['#b91c1c', '&#9679; PAID']];

    echo '<script>var AIPROV_CSRF=' . json_encode($csrf) . ';</script>';
    echo '<div class="card" style="margin-bottom:14px"><h2 style="margin:0 0 4px">&#129518; Choose an AI provider</h2>';
    echo '<p class="sub" style="margin:0 0 12px">Create an account + API key from a provider&#39;s links, paste the key &amp; Save. Add as many <b>free</b> providers as you can — the plugin uses them as a fallback chain so you never run out. Click <b>&#8635; Fetch live models</b> to load the real models with your token, pick one or more, and <b>Test</b> to verify.</p>';

    $mode = function_exists('smpro_ai_exec_mode') ? smpro_ai_exec_mode() : 'series';
    echo '<div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:0 0 14px">';
    echo '<button class="btn" onclick="aiAllFree(this)" style="background:#16a34a;color:#fff;font-weight:700">&#9989; Select all free models</button>';
    echo '<button class="btn" onclick="aiHealthNow(this)" title="Re-probe every active provider and model now; remove the ones the API no longer accepts">&#129658; Check all providers &amp; models now</button>';
    echo '<span class="meta" style="font-size:11.5px">runs automatically every hour · only working models are kept</span></div>';
    // last hourly health summary (so the operator can see what was pruned and when)
    $hs = is_file(SMPRO_AI_PRUNE_STATE) ? (array)json_decode((string)@file_get_contents(SMPRO_AI_PRUNE_STATE), true) : [];
    if (!empty($hs['last_run'])) {
        $drop = 0; foreach ((array)($hs['report'] ?? []) as $rp) $drop += (int)($rp['dropped'] ?? 0);
        echo '<div class="meta" style="font-size:11.5px;margin:-6px 0 12px">&#10003; Last health check: ' . smpro_h(date('Y-m-d H:i', (int)$hs['last_run'])) . ' · ' . $drop . ' dead model(s) removed</div>';
    }

    echo '<div style="background:#f7f9fc;border:1px solid rgba(148,163,184,.4);border-radius:12px;padding:12px 14px;margin:0 0 14px">';
    echo '<div style="font-weight:800;color:#0f2657;font-size:13px;margin-bottom:2px">&#9881;&#65039; Working mode <span style="font-weight:500;color:#64748b">— how the plugin queries your models</span></div>';
    echo '<p class="sub" style="margin:4px 0 10px;font-size:12.5px">Every request tries your preferred model first and <b>automatically falls back</b> to the next free model/provider if one is rate-limited or fails — so a single token is never exhausted.</p>';
    echo '<div style="display:flex;gap:10px;flex-wrap:wrap">';
    $opt = function ($val, $title, $desc, $rec) use ($mode) {
        $on = $mode === $val;
        echo '<label style="flex:1;min-width:240px;cursor:pointer;border:2px solid ' . ($on ? '#16a34a' : 'rgba(148,163,184,.4)') . ';border-radius:10px;padding:10px 12px;background:' . ($on ? 'rgba(22,163,74,.06)' : '#fff') . '">';
        echo '<div style="display:flex;align-items:center;gap:7px"><input type="radio" name="aiExecMode" value="' . $val . '"' . ($on ? ' checked' : '') . ' onchange="aiExecSave(this)"><b style="font-size:13px">' . $title . '</b>';
        if ($rec) echo ' <span style="font-size:10px;font-weight:900;color:#16a34a;background:#dcfce7;padding:1px 7px;border-radius:20px">RECOMMENDED</span>';
        echo '</div><div style="font-size:11.5px;color:#64748b;margin-top:4px;padding-left:22px">' . $desc . '</div></label>';
    };
    $opt('series', 'Series (one after another)', 'Always start with your fastest preferred model; fall back only if it fails. Best results, lowest token use — safest against rate limits.', true);
    $opt('parallel', 'Parallel (spread the load)', 'Rotate the starting model on each request to distribute usage across all your free models — useful when you make many calls and want to balance quotas.', false);
    echo '</div></div>';
    echo '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(330px,1fr));gap:12px">';
    foreach ($cat as $id => $p) {
        [$bc, $bl] = $badge[$p['tier']] ?? ['#64748b', $p['tier']];
        $st = smpro_ai_provider_state($id);
        $use = smpro_ai_usage($id);
        $border = $st['enabled'] ? '#16a34a' : 'rgba(148,163,184,.35)';
        $shadow = $st['enabled'] ? 'box-shadow:0 4px 18px rgba(22,163,74,.12);' : 'box-shadow:0 1px 4px rgba(15,23,42,.05);';
        echo '<div style="border:1px solid ' . $border . ';border-top:3px solid ' . $bc . ';border-radius:14px;padding:13px 15px;background:#fff;' . $shadow . 'transition:.15s">';
        // header: name + status + tier
        echo '<div style="display:flex;justify-content:space-between;align-items:center;gap:8px">';
        $statusTxt = $st['enabled'] ? '<span style="color:#16a34a;font-size:11px;font-weight:900">&#9679; ENABLED</span>'
                   : ($st['has_key'] ? '<span style="color:#64748b;font-size:11px;font-weight:800">&#9675; off</span>' : '<span style="color:#94a3b8;font-size:11px">no key</span>');
        echo '<b style="font-size:15px">' . smpro_h($p['label']) . '</b> ' . $statusTxt;
        echo '<span style="color:' . $bc . ';font-weight:900;font-size:11px;white-space:nowrap;margin-left:auto">' . $bl . '</span></div>';
        echo '<p style="color:#475569;font-size:12px;margin:6px 0 8px;min-height:30px">' . smpro_h($p['limit']) . '</p>';
        // usage
        if ($p['req_day']) {
            $rem = max(0, (int)$p['req_day'] - $use['req']); $pct = min(100, $use['req'] * 100 / max(1, (int)$p['req_day']));
            echo '<div style="font-size:12px;color:#0f2657;font-weight:700">Used today: ' . (int)$use['req'] . ' / ' . (int)$p['req_day'] . ' · remaining ' . $rem . '</div>';
            echo '<div style="height:6px;background:#e2e8f0;border-radius:6px;margin:4px 0 8px;overflow:hidden"><div style="height:6px;width:' . round($pct) . '%;background:' . ($pct > 85 ? '#b91c1c' : ($pct > 60 ? '#b45309' : '#16a34a')) . '"></div></div>';
        } else {
            echo '<div style="font-size:12px;color:#0f2657;font-weight:700;margin-bottom:8px">Sent today: ' . (int)$use['req'] . ' req · ' . number_format($use['tok']) . ' tokens</div>';
        }
        // REAL provider limit (read from the API rate-limit headers during Auto-pick) — not our local count
        if (!empty($st['api_limit'])) {
            $al = $st['api_limit']; $parts = [];
            if (!empty($al['tokens']))   $parts[] = 'tokens ' . smpro_h(($al['rem_tokens'] !== '' ? $al['rem_tokens'] . '/' : '') . $al['tokens']) . '/min';
            if (!empty($al['requests'])) $parts[] = 'req ' . smpro_h(($al['rem_requests'] !== '' ? $al['rem_requests'] . '/' : '') . $al['requests']) . '/min';
            if ($parts) echo '<div style="font-size:11.5px;color:#0369a1;font-weight:700;margin:-4px 0 8px">&#128246; API limit: ' . implode(' · ', $parts) . ' <span style="color:#94a3b8;font-weight:400">(from provider)</span></div>';
        }
        // links
        echo '<div style="display:flex;gap:8px;flex-wrap:wrap;font-size:12px;margin-bottom:8px">';
        echo '<a class="btn" style="padding:5px 9px" href="' . smpro_h($p['signup']) . '" target="_blank" rel="noopener">Create account &#8599;</a>';
        echo '<a class="btn" style="padding:5px 9px" href="' . smpro_h($p['keys']) . '" target="_blank" rel="noopener">Get API key &#8599;</a></div>';
        // key + save
        if ($st['has_key']) echo '<div style="font-size:11.5px;color:#16a34a;margin-bottom:4px;font-weight:700">&#10003; Token saved: <code>' . smpro_h($st['mask']) . '</code></div>';
        echo '<div style="display:flex;gap:6px;margin-bottom:8px">';
        echo '<input type="password" id="aik_' . $id . '" placeholder="' . ($st['has_key'] ? 'saved — leave blank to keep' : 'paste API key') . '" autocomplete="new-password" style="flex:1;padding:7px 10px;border-radius:10px;border:1px solid rgba(148,163,184,.5);font-size:13px">';
        echo '<button class="btn" style="background:#16a34a;color:#fff" onclick="aiProvSave(\'' . $id . '\')">Save key</button></div>';
        // multi-select model picker — real models can be fetched live via the token; free preselected, paid flagged.
        $selSet = array_flip($st['models']);
        $opts = [];
        foreach (($p['free_models'] ?? []) as $m) $opts[$m] = ['tag' => 'free', 'paid' => false];
        foreach (($p['paid_models'] ?? []) as $m) $opts[$m] = ['tag' => 'PAID', 'paid' => true];
        foreach ($st['live'] as $m)   if (!isset($opts[$m])) $opts[$m] = ['tag' => 'live', 'paid' => in_array($m, $p['paid_models'] ?? [], true)];
        foreach ($st['models'] as $m) if (!isset($opts[$m])) $opts[$m] = ['tag' => 'saved', 'paid' => in_array($m, $p['paid_models'] ?? [], true)];
        echo '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:3px;gap:8px;flex-wrap:wrap">';
        echo '<label style="font-size:12px;font-weight:700;color:#0f2657">Models</label>';
        echo '<span style="display:flex;gap:10px;flex-wrap:wrap"><a href="#" onclick="aiProvVerify(\'' . $id . '\');return false" style="font-size:11.5px;font-weight:800;color:#16a34a" title="Probe every model live and keep only the ones the API accepts">&#10003; Auto-pick working</a>';
        echo '<a href="#" onclick="aiProvAllFree(\'' . $id . '\');return false" style="font-size:11.5px;font-weight:700;color:#0f766e">All free</a>';
        echo '<a href="#" onclick="aiProvFetch(\'' . $id . '\');return false" style="font-size:11.5px;font-weight:700">&#8635; Fetch live</a></span></div>';
        echo '<select multiple id="aim_' . $id . '" size="5" onchange="aiProvModels(\'' . $id . '\')" style="width:100%;padding:5px;border-radius:9px;border:1px solid rgba(148,163,184,.5);font-size:12.5px">';
        foreach ($opts as $m => $meta) {
            $lab = $meta['paid'] ? ' — PAID' : ' (' . $meta['tag'] . ')';
            echo '<option value="' . smpro_h($m) . '"' . ($meta['paid'] ? ' data-paid="1"' : '') . (isset($selSet[$m]) ? ' selected' : '') . '>' . smpro_h($m) . $lab . '</option>';
        }
        echo '</select>';
        echo '<div id="aimsg_' . $id . '" style="font-size:11px;color:#64748b;margin:3px 0"></div>';
        echo '<div style="display:flex;gap:10px;align-items:center;margin-top:8px;flex-wrap:wrap">';
        echo '<label class="sw" style="display:inline-flex"><input type="checkbox" id="aie_' . $id . '" ' . ($st['enabled'] ? 'checked' : '') . ' onchange="aiProvToggle(\'' . $id . '\')"><span class="track"></span><span class="lbl" style="font-size:12px">Enable</span><span class="st"></span></label>';
        echo '<button class="btn" style="padding:5px 10px;font-size:12px" onclick="aiProvTestSel(\'' . $id . '\')">&#9889; Test selected</button>';
        echo '<span id="ait_' . $id . '" style="font-size:11.5px"></span>';
        echo '</div>';
        echo '<div id="aitres_' . $id . '" style="font-size:11.5px;margin-top:6px"></div>';
        if ($p['tier'] === 'paid') echo '<p style="color:#b91c1c;font-size:11px;margin:8px 0 0">&#9888; Paid provider — billed per use.</p>';
        echo '</div>';
    }
    echo '</div><div id="aiProvMsg" class="meta" style="margin-top:10px;min-height:18px"></div></div>';
    echo "<script>
function aiProvCall(extra){var fd=new URLSearchParams();fd.set('smpro_csrf',AIPROV_CSRF);Object.keys(extra).forEach(function(k){fd.set(k,extra[k]);});
  return fetch('index.cgi?aiprov=1',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString(),cache:'no-store'}).then(function(r){return r.json();});}
function aiMsg(t,c){var m=document.getElementById('aiProvMsg');m.innerHTML=t;m.style.color=c||'#475569';}
function aiProvSave(id){var k=document.getElementById('aik_'+id).value;aiMsg('Saving key…');aiProvCall({ar_action:'save',provider:id,key:k}).then(function(j){if(j&&j.ok){aiMsg('✓ Key saved & '+id+' activated. Reloading…','#047857');setTimeout(function(){location.reload();},800);}else{aiMsg('✗ '+((j&&j.msg)||'Failed'),'#b91c1c');}});}
function aiProvToggle(id){var on=document.getElementById('aie_'+id).checked;aiProvCall({ar_action:'toggle',provider:id,on:on?'1':''}).then(function(j){if(j&&j.ok){aiMsg((on?'✓ Enabled ':'○ Disabled ')+id+'. Reloading…','#047857');setTimeout(function(){location.reload();},700);}else{document.getElementById('aie_'+id).checked=!on;aiMsg('✗ '+((j&&j.msg)||'Failed'),'#b91c1c');}});}
function aiAllFree(btn){btn.disabled=true;var o=btn.innerHTML;btn.innerHTML='Enabling…';aiProvCall({ar_action:'allfree'}).then(function(j){btn.disabled=false;btn.innerHTML=o;
  if(j&&j.ok){aiMsg('✓ '+(j.msg||('Enabled '+j.models+' free models'))+' Reloading…','#047857');setTimeout(function(){location.reload();},800);}else{aiMsg('✗ '+((j&&j.msg)||'Failed'),'#b91c1c');}});}
function aiHealthNow(btn){btn.disabled=true;var o=btn.innerHTML;btn.innerHTML='Checking…';aiProvCall({ar_action:'autoprune'}).then(function(j){btn.disabled=false;btn.innerHTML=o;
  if(j&&j.ok){var d=0;Object.keys(j.report||{}).forEach(function(k){d+=(j.report[k].dropped||0);});aiMsg('✓ Health check done · '+d+' dead model(s) removed. Reloading…','#047857');setTimeout(function(){location.reload();},1000);}
  else{aiMsg('✗ '+((j&&j.msg)||'failed'),'#b91c1c');}});}
function aiExecSave(r){aiProvCall({ar_action:'execmode',mode:r.value}).then(function(j){aiMsg(j&&j.ok?('✓ Working mode: '+r.value):'✗ failed',j&&j.ok?'#047857':'#b91c1c');
  document.querySelectorAll('input[name=aiExecMode]').forEach(function(x){var l=x.closest('label');if(l){l.style.borderColor=x.checked?'#16a34a':'rgba(148,163,184,.4)';l.style.background=x.checked?'rgba(22,163,74,.06)':'#fff';}});});}
function aiProvAllFree(id){var sel=document.getElementById('aim_'+id);if(!sel)return;var n=0;
  [].forEach.call(sel.options,function(o){if(!o.getAttribute('data-paid')){o.selected=true;n++;}});
  if(!n){document.getElementById('aimsg_'+id).textContent='No free models listed — Fetch live first.';return;}
  aiProvModels(id);}
function aiSelected(id){return [].slice.call(document.getElementById('aim_'+id).selectedOptions).map(function(o){return o.value;});}
function aiExecMode(){var r=document.querySelector('input[name=aiExecMode]:checked');return r?r.value:'parallel';}
function aiProvModels(id){var sel=document.getElementById('aim_'+id);var chosen=aiSelected(id);
  var paid=[].slice.call(sel.selectedOptions).filter(function(o){return o.getAttribute('data-paid');});
  if(paid.length&&!confirm(paid.length+' PAID model(s) selected — you will be billed per use. Keep them?')){paid.forEach(function(o){o.selected=false;});chosen=aiSelected(id);}
  if(!chosen.length){return;}
  var fd={ar_action:'setmodels',provider:id};chosen.forEach(function(m,i){fd['models['+i+']']=m;});
  aiProvCall(fd).then(function(j){var m=document.getElementById('aimsg_'+id);if(j&&j.ok){m.textContent='✓ '+j.models.length+' model(s) saved · primary: '+j.primary;m.style.color='#16a34a';}else{m.textContent='✗ '+((j&&j.msg)||'Failed');m.style.color='#b91c1c';}});}
function aiProvFetch(id){var m=document.getElementById('aimsg_'+id);m.textContent='Fetching live models with your token…';m.style.color='#64748b';
  aiProvCall({ar_action:'models',provider:id}).then(function(j){var sel=document.getElementById('aim_'+id);
    if(!j||!j.ok){m.textContent='✗ '+((j&&j.msg)||'Could not fetch models');m.style.color='#b91c1c';return;}
    var keep={};aiSelected(id).forEach(function(v){keep[v]=1;});sel.innerHTML='';
    j.models.forEach(function(mid){var o=document.createElement('option');o.value=mid;o.textContent=mid+' (live)';if(keep[mid])o.selected=true;sel.appendChild(o);});
    m.textContent='✓ '+j.count+' chat models loaded'+(j.filtered?(' ('+j.filtered+' non-chat/inactive hidden)'):'')+' — pick, or use “All free”.';m.style.color='#16a34a';});}
function aiTestOne(id,model){return aiProvCall({ar_action:'test',provider:id,model:model}).then(function(j){return{model:model,ok:j&&j.ok,throttled:j&&j.throttled,ms:j&&j.ms,msg:(j&&j.msg)||''};});}
function aiProvVerify(id){var m=document.getElementById('aimsg_'+id);m.innerHTML='<span class=\"sm-scanning\">Probing every model live (keeping only what the API accepts)…</span>';m.style.color='#64748b';
  aiProvCall({ar_action:'verify',provider:id}).then(function(j){
    if(j&&j.ok){m.textContent='✓ Kept '+j.kept+' working model(s)'+(j.dropped?(' · dropped '+j.dropped+' rejected'):'')+(j.limit&&j.limit.tokens?(' · API limit '+j.limit.tokens+' tok/min'):'')+'. Reloading…';m.style.color='#047857';setTimeout(function(){location.reload();},900);}
    else{m.textContent='✗ '+((j&&j.msg)||'verify failed');m.style.color='#b91c1c';}}).catch(function(){m.textContent='Request failed';m.style.color='#b91c1c';});}
function aiKeepWorking(id){var ms=(window.aiOK||{})[id]||[];var sel=document.getElementById('aim_'+id);if(!sel)return;
  [].forEach.call(sel.options,function(o){o.selected=ms.indexOf(o.value)>=0;});aiProvModels(id);}
function aiProvTestSel(id){var models=aiSelected(id);var box=document.getElementById('aitres_'+id);var s=document.getElementById('ait_'+id);
  if(!models.length){box.innerHTML='<span style=\"color:#b45309\">Select at least one model first.</span>';return;}
  s.textContent='testing '+models.length+'…';s.style.color='#64748b';box.innerHTML='';
  function row(r){var col=r.throttled?'#b45309':(r.ok?'#16a34a':'#b91c1c');var tail=r.ok?(r.throttled?('· '+(r.msg||'rate-limited')):('· '+r.ms+'ms')):('· '+(r.msg||'failed'));
    return '<div style=\"color:'+col+'\">'+(r.ok?'✓':'✗')+' '+r.model+' '+tail+'</div>';}
  var mode=aiExecMode(),okN=0,okList=[];
  function tally(r){if(r.ok){okN++;okList.push(r.model);}}
  function fin(){s.textContent=okN+'/'+models.length+' OK ('+mode+')';s.style.color=okN===models.length?'#16a34a':(okN?'#b45309':'#b91c1c');
    window.aiOK=window.aiOK||{};window.aiOK[id]=okList;
    if(okN<models.length&&okN>0){box.innerHTML+='<button class=\"btn\" style=\"margin-top:8px;padding:4px 10px;font-size:12px;background:#16a34a;color:#fff\" onclick=\"aiKeepWorking(\''+id+'\')\">&#10003; Keep only the '+okN+' working model(s)</button>';}}
  if(mode==='parallel'){Promise.all(models.map(function(mo){return aiTestOne(id,mo);})).then(function(rs){rs.forEach(function(r){tally(r);box.innerHTML+=row(r);});fin();});}
  else{(function next(i){if(i>=models.length){fin();return;}aiTestOne(id,models[i]).then(function(r){tally(r);box.innerHTML+=row(r);next(i+1);});})(0);}}
</script>";
}
