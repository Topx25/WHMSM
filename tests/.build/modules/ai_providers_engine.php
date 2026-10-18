<?php
declare(strict_types=1);

if (!function_exists('mspro_ai304_bootstrap_request')) {
    function mspro_ai304_bootstrap_request(): void
    {
        $query = (string)($_SERVER['QUERY_STRING'] ?? getenv('QUERY_STRING') ?: '');
        if ($query !== '' && empty($_GET)) {
            $g = [];
            parse_str($query, $g);
            if (is_array($g)) {
                $_GET = $g;
            }
        }

        $method = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? getenv('REQUEST_METHOD') ?: ''));
        if ($method !== '') {
            $_SERVER['REQUEST_METHOD'] = $method;
        }

        if ($method === 'POST' && empty($_POST)) {
            $len = (int)($_SERVER['CONTENT_LENGTH'] ?? getenv('CONTENT_LENGTH') ?: 0);
            $type = strtolower((string)($_SERVER['CONTENT_TYPE'] ?? getenv('CONTENT_TYPE') ?: ''));

            if ($len > 0 && $len <= 1048576) {
                $raw = file_get_contents('php://stdin');
                if (is_string($raw) && $raw !== '') {
                    if (strpos($type, 'application/x-www-form-urlencoded') !== false || strpos($raw, '=') !== false) {
                        $p = [];
                        parse_str($raw, $p);
                        if (is_array($p)) {
                            $_POST = $p;
                        }
                    }
                }
            }
        }

        $_REQUEST = array_merge($_GET, $_POST);
    }
}
mspro_ai304_bootstrap_request();

function mspro_ai304_e(string $v): string { return htmlspecialchars($v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function mspro_ai304_config_dir(): string { return '/var/lib/smpro/ai/config'; }
function mspro_ai304_vault_dir(): string { return '/var/lib/smpro/ai/vault'; }
function mspro_ai304_key_dir(): string { return '/var/lib/smpro/ai/keys'; }
function mspro_ai304_log_dir(): string { return '/var/log/smpro'; }
function mspro_ai304_config_path(): string { return mspro_ai304_config_dir() . '/ai_providers.json'; }
function mspro_ai304_catalog_path(): string { return mspro_ai304_config_dir() . '/ai_model_catalog.json'; }
function mspro_ai304_revision_path(): string { return mspro_ai304_config_dir() . '/revision.json'; }
function mspro_ai304_master_key_path(): string { return mspro_ai304_key_dir() . '/smpro_master.key'; }

function mspro_ai304_provider_labels(): array
{
    return [
        'qwen' => 'Alibaba Qwen',
        'openrouter' => 'OpenRouter',
        'opencode_ai' => 'opencode.ai',
    ];
}

function mspro_ai304_read_json(string $path, array $default = []): array
{
    if (!is_readable($path)) return $default;
    $raw = file_get_contents($path);
    if (!is_string($raw) || trim($raw) === '') return $default;
    $data = json_decode($raw, true);
    return is_array($data) ? $data : $default;
}

function mspro_ai304_write_json(string $path, array $data): bool
{
    $dir = dirname($path);
    if (!is_dir($dir)) @mkdir($dir, 0750, true);
    $data['updated_at'] = date('c');
    $ok = @file_put_contents($path, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n", LOCK_EX);
    if ($ok === false) return false;
    @chmod($path, 0600);
    return true;
}

function mspro_ai304_log(string $event, array $data = []): void
{
    unset($data['api_key'], $data['qwen_api_key'], $data['openrouter_api_key'], $data['opencode_ai_api_key']);
    $dir = mspro_ai304_log_dir();
    if (!is_dir($dir)) @mkdir($dir, 0750, true);
    @file_put_contents(
        $dir . '/ai_provider_page.log',
        json_encode(['time' => date('c'), 'event' => $event, 'data' => $data], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n",
        FILE_APPEND | LOCK_EX
    );
}

function mspro_ai304_default_config(): array
{
    return [
        'provider' => 'qwen',
        'provider_label' => 'Alibaba Qwen',
        'active_providers' => [],
        'enabled' => false,
        'external_calls' => false,
        'data_mode' => 'masked_headers_only',
        'decision_mode' => 'recommend_only',
        'read_body' => false,
        'enforcement' => false,
        'qwen' => [
            'enabled' => false,
            'region' => 'singapore_workspace',
            'region_label' => 'Singapore / ap-southeast-1 workspace',
            'workspace_id' => '',
            'base_url' => 'https://{WorkspaceId}.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1',
            'default_model' => 'qwen-plus',
            'active_models' => [],
            'daily_token_limit' => 50000,
            'max_headers_per_run' => 50,
            'timeout_seconds' => 20,
        ],
        'openrouter' => [
            'enabled' => false,
            'base_url' => 'https://openrouter.ai/api/v1',
            'default_model' => 'openrouter/free',
            'active_models' => [],
            'daily_token_limit' => 50000,
            'max_headers_per_run' => 50,
            'timeout_seconds' => 20,
        ],
        'opencode_ai' => [
            'enabled' => false,
            'base_url' => 'https://opencode.ai/zen/v1',
            'default_model' => 'deepseek-v4-flash-free',
            'active_models' => [],
            'daily_token_limit' => 50000,
            'max_headers_per_run' => 50,
            'timeout_seconds' => 20,
        ],
    ];
}

function mspro_ai304_load_config(): array
{
    return array_replace_recursive(mspro_ai304_default_config(), mspro_ai304_read_json(mspro_ai304_config_path(), []));
}

function mspro_ai304_qwen_static_models(): array
{
    $ids = ['qwen-flash','qwen-turbo','qwen-turbo-latest','qwen-plus','qwen-plus-latest','qwen-long','qwen-max','qwen-max-latest','qwen3-coder-plus','qwq-plus'];
    $out = [];
    foreach ($ids as $id) {
        $out[] = [
            'id' => $id,
            'name' => $id,
            'availability' => 'free_quota_or_paid',
            'selectable' => true,
            'requires_key' => true,
            'context_length' => 0,
            'input_price' => 'workspace/account dependent',
            'output_price' => 'workspace/account dependent',
            'limit' => 'Quota depends on Alibaba workspace and model entitlement',
            'description' => 'Qwen candidate model. Exact free quota depends on Alibaba Model Studio.',
        ];
    }
    return $out;
}

function mspro_ai304_opencode_ai_static_models(): array
{
    return [[
        'id' => 'deepseek-v4-flash-free',
        'name' => 'opencode.ai default',
        'availability' => 'provider_catalog',
        'selectable' => true,
        'requires_key' => true,
        'context_length' => 0,
        'input_price' => 'provider/account dependent',
        'output_price' => 'provider/account dependent',
        'limit' => 'Limits depend on opencode.ai account/provider configuration',
        'description' => 'Fallback entry. Use Test Connection / Fetch Models if the endpoint supports /models.',
    ]];
}

function mspro_ai304_default_catalog(): array
{
    return [
        'qwen' => [
            'fetched_at' => null,
            'source' => 'static_qwen_candidates',
            'models' => mspro_ai304_qwen_static_models(),
            'error' => null,
        ],
        'openrouter' => [
            'fetched_at' => null,
            'source' => 'not_fetched',
            'models' => [],
            'error' => null,
        ],
        'opencode_ai' => [
            'fetched_at' => null,
            'source' => 'static_opencode_ai_fallback',
            'models' => mspro_ai304_opencode_ai_static_models(),
            'error' => 'opencode.ai catalog not fetched yet.',
        ],
    ];
}

function mspro_ai304_load_catalog(): array
{
    return array_replace_recursive(mspro_ai304_default_catalog(), mspro_ai304_read_json(mspro_ai304_catalog_path(), []));
}

function mspro_ai304_provider_slug(string $provider): string
{
    $safe = preg_replace('/[^a-z0-9_\-]/i', '', strtolower($provider));
    return $safe !== '' ? $safe : 'unknown';
}

function mspro_ai304_get_master_key(): string
{
    $dir = mspro_ai304_key_dir();
    if (!is_dir($dir)) @mkdir($dir, 0700, true);
    @chmod($dir, 0700);

    $path = mspro_ai304_master_key_path();
    if (!is_readable($path)) {
        $key = random_bytes(32);
        @file_put_contents($path, base64_encode($key) . "\n", LOCK_EX);
        @chmod($path, 0400);
        return $key;
    }

    $raw = trim((string)file_get_contents($path));
    $key = base64_decode($raw, true);
    if (!is_string($key) || strlen($key) !== 32) {
        throw new RuntimeException('Invalid master key.');
    }
    return $key;
}

function mspro_ai304_vault_file(string $provider): string
{
    return mspro_ai304_vault_dir() . '/ai_' . mspro_ai304_provider_slug($provider) . '.enc.json';
}

function mspro_ai304_encrypt_secret(string $provider, string $plain): array
{
    if (!function_exists('openssl_encrypt')) throw new RuntimeException('OpenSSL extension is required.');
    $key = mspro_ai304_get_master_key();
    $iv = random_bytes(12);
    $tag = '';
    $aad = 'smpro-ai-secret:' . mspro_ai304_provider_slug($provider);

    $ciphertext = openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, $aad, 16);
    if (!is_string($ciphertext) || $ciphertext === '') throw new RuntimeException('Encryption failed.');

    return [
        'version' => 1,
        'provider' => mspro_ai304_provider_slug($provider),
        'cipher' => 'aes-256-gcm',
        'aad' => $aad,
        'iv' => base64_encode($iv),
        'tag' => base64_encode($tag),
        'ciphertext' => base64_encode($ciphertext),
        'updated_at' => date('c'),
    ];
}

function mspro_ai304_decrypt_secret_payload(array $payload): string
{
    if (!function_exists('openssl_decrypt')) return '';
    if (($payload['cipher'] ?? '') !== 'aes-256-gcm') return '';

    $iv = base64_decode((string)($payload['iv'] ?? ''), true);
    $tag = base64_decode((string)($payload['tag'] ?? ''), true);
    $ciphertext = base64_decode((string)($payload['ciphertext'] ?? ''), true);
    $aad = (string)($payload['aad'] ?? '');

    if (!is_string($iv) || !is_string($tag) || !is_string($ciphertext)) return '';

    $plain = openssl_decrypt($ciphertext, 'aes-256-gcm', mspro_ai304_get_master_key(), OPENSSL_RAW_DATA, $iv, $tag, $aad);
    return is_string($plain) ? $plain : '';
}

function mspro_ai304_get_secret(string $provider): string
{
    $path = mspro_ai304_vault_file($provider);
    if (!is_readable($path)) return '';
    return mspro_ai304_decrypt_secret_payload(mspro_ai304_read_json($path, []));
}

function mspro_ai304_secret_exists(string $provider): bool
{
    return mspro_ai304_get_secret($provider) !== '';
}

function mspro_ai304_save_secret(string $provider, string $value): bool
{
    $value = trim($value);
    if ($value === '') return true;

    try {
        $dir = mspro_ai304_vault_dir();
        if (!is_dir($dir)) @mkdir($dir, 0700, true);
        @chmod($dir, 0700);

        $payload = mspro_ai304_encrypt_secret($provider, $value);
        $path = mspro_ai304_vault_file($provider);
        $ok = @file_put_contents($path, json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n", LOCK_EX);
        if ($ok === false) return false;
        @chmod($path, 0600);
        return true;
    } catch (Throwable $e) {
        mspro_ai304_log('secret_save_error', ['provider' => $provider, 'error' => $e->getMessage()]);
        return false;
    }
}

function mspro_ai304_clear_secret(string $provider): void
{
    $path = mspro_ai304_vault_file($provider);
    if (is_file($path)) @unlink($path);
}

function mspro_ai304_secret_meta(string $provider): array
{
    $secret = mspro_ai304_get_secret($provider);
    $payload = mspro_ai304_read_json(mspro_ai304_vault_file($provider), []);
    return [
        'exists' => $secret !== '',
        'length' => strlen($secret),
        'sha256_16' => $secret !== '' ? substr(hash('sha256', $secret), 0, 16) : '',
        'updated_at' => (string)($payload['updated_at'] ?? ''),
        'vault_file' => basename(mspro_ai304_vault_file($provider)),
    ];
}

function mspro_ai304_secret_status_html(string $provider): string
{
    $meta = mspro_ai304_secret_meta($provider);
    if (empty($meta['exists'])) {
        return '<div class="ai304-secret-status warn"><b>No encrypted key saved</b><span>Paste a key and save. The value will be hidden after saving.</span></div>';
    }

    return '<div class="ai304-secret-status good">'
        . '<b>Encrypted key saved</b>'
        . '<span>Leave the field blank to keep it. Paste a new key to replace it.</span>'
        . '<small>Vault: ' . mspro_ai304_e((string)$meta['vault_file'])
        . ' · Length: ' . mspro_ai304_e((string)$meta['length'])
        . ' · Fingerprint: ' . mspro_ai304_e((string)$meta['sha256_16'])
        . ($meta['updated_at'] !== '' ? ' · Updated: ' . mspro_ai304_e((string)$meta['updated_at']) : '')
        . '</small></div>';
}

function mspro_ai304_ui_secret(): string
{
    $path = mspro_ai304_config_dir() . '/ui_secret';
    if (!is_readable($path) || trim((string)@file_get_contents($path)) === '') {
        $secret = bin2hex(random_bytes(32));
        @file_put_contents($path, $secret . "\n");
        @chmod($path, 0600);
        return $secret;
    }
    return trim((string)file_get_contents($path));
}

/** SSRF guard for an operator-set provider base URL: must be http(s) to a PUBLIC host, else fall back to default.
 *  Stops a tampered/typo'd base_url from pointing the root-context fetch at 127.0.0.1 / 169.254.169.254 / LAN. */
function mspro_ai304_safe_base(string $url, string $fallback): string
{
    $url = trim($url);
    if ($url === '') return $fallback;
    $p = @parse_url($url);
    if (!is_array($p) || empty($p['scheme']) || empty($p['host'])) return $fallback;
    if (!in_array(strtolower($p['scheme']), ['http', 'https'], true)) return $fallback;
    $host = $p['host'];
    $ips = filter_var($host, FILTER_VALIDATE_IP) ? [$host] : (@gethostbynamel($host) ?: []);
    foreach ($ips as $ip) {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) return $fallback;
        if (strpos($ip, '169.254.') === 0 || strpos($ip, '127.') === 0 || $ip === '::1') return $fallback;
    }
    return $url;
}
function mspro_ai304_actor(): string
{
    return function_exists('smpro_current_actor') ? (string)smpro_current_actor() : (string)(getenv('REMOTE_USER') ?: '');
}
function mspro_ai304_token(): string
{
    return hash_hmac('sha256', 'ai304-' . mspro_ai304_actor() . '-' . gmdate('YmdH'), mspro_ai304_ui_secret());
}

function mspro_ai304_valid_token(string $token): bool
{
    $secret = mspro_ai304_ui_secret(); $a = mspro_ai304_actor();   // bind to the actor → not valid for a different WHM user
    $current  = hash_hmac('sha256', 'ai304-' . $a . '-' . gmdate('YmdH', time()), $secret);
    $previous = hash_hmac('sha256', 'ai304-' . $a . '-' . gmdate('YmdH', time() - 3600), $secret);
    return hash_equals($current, $token) || hash_equals($previous, $token);
}

function mspro_ai304_qwen_regions(): array
{
    return [
        'singapore_workspace' => [
            'label' => 'Singapore / ap-southeast-1 workspace',
            'template' => 'https://{WorkspaceId}.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1',
            'requires_workspace_id' => true,
        ],
        'germany_frankfurt' => [
            'label' => 'Germany / Frankfurt',
            'template' => 'https://{WorkspaceId}.eu-central-1.maas.aliyuncs.com/compatible-mode/v1',
            'requires_workspace_id' => true,
        ],
        'us_virginia' => [
            'label' => 'US / Virginia',
            'template' => 'https://dashscope-us.aliyuncs.com/compatible-mode/v1',
            'requires_workspace_id' => false,
        ],
        'china_beijing' => [
            'label' => 'China / Beijing',
            'template' => 'https://dashscope.aliyuncs.com/compatible-mode/v1',
            'requires_workspace_id' => false,
        ],
        'hongkong_workspace' => [
            'label' => 'China / Hong Kong workspace',
            'template' => 'https://{WorkspaceId}.cn-hongkong.maas.aliyuncs.com/compatible-mode/v1',
            'requires_workspace_id' => true,
        ],
    ];
}

function mspro_ai304_clean_workspace(string $value): string
{
    $value = preg_replace('/[^A-Za-z0-9_\-]/', '', trim($value));
    return substr((string)$value, 0, 120);
}

function mspro_ai304_qwen_base(string $region, string $workspace): string
{
    $regions = mspro_ai304_qwen_regions();
    $info = $regions[$region] ?? $regions['singapore_workspace'];
    $template = (string)$info['template'];
    if (!empty($info['requires_workspace_id']) && $workspace !== '') {
        return str_replace('{WorkspaceId}', $workspace, $template);
    }
    return $template;
}

function mspro_ai304_http_json(string $url, string $apiKey, int $timeout, array $extraHeaders = []): array
{
    if (!function_exists('curl_init')) return ['ok' => false, 'error' => 'cURL unavailable', 'data' => null, 'http_code' => 0];

    $headers = ['Accept: application/json', 'Content-Type: application/json'];
    if ($apiKey !== '') $headers[] = 'Authorization: Bearer ' . $apiKey;
    foreach ($extraHeaders as $h) $headers[] = $h;

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_CONNECTTIMEOUT => min(10, $timeout),
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_USERAGENT => 'Safety-Monitor-Pro/1.0',
    ]);

    $body = curl_exec($ch);
    $err = curl_error($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);

    if (!is_string($body) || $body === '') return ['ok' => false, 'error' => $err ?: 'Empty response', 'data' => null, 'http_code' => $code];

    $json = json_decode($body, true);
    if (!is_array($json)) return ['ok' => false, 'error' => 'Invalid JSON response', 'data' => null, 'http_code' => $code];

    if ($code < 200 || $code >= 300) {
        $msg = 'HTTP ' . $code;
        if (isset($json['error']['message'])) $msg .= ': ' . (string)$json['error']['message'];
        elseif (isset($json['message'])) $msg .= ': ' . (string)$json['message'];
        return ['ok' => false, 'error' => $msg, 'data' => $json, 'http_code' => $code];
    }

    return ['ok' => true, 'error' => null, 'data' => $json, 'http_code' => $code];
}

function mspro_ai304_http_post_json(string $url, string $apiKey, array $payload, int $timeout): array
{
    if (!function_exists('curl_init')) return ['ok' => false, 'error' => 'cURL unavailable', 'data' => null, 'http_code' => 0];

    $headers = ['Accept: application/json', 'Content-Type: application/json'];
    if ($apiKey !== '') $headers[] = 'Authorization: Bearer ' . $apiKey;

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_CONNECTTIMEOUT => min(10, $timeout),
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
        CURLOPT_USERAGENT => 'Safety-Monitor-Pro/1.0',
    ]);

    $body = curl_exec($ch);
    $err = curl_error($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);

    if (!is_string($body) || $body === '') return ['ok' => false, 'error' => $err ?: 'Empty response', 'data' => null, 'http_code' => $code];

    $json = json_decode($body, true);
    if (!is_array($json)) return ['ok' => false, 'error' => 'Invalid JSON response', 'data' => ['raw' => substr($body, 0, 300)], 'http_code' => $code];

    if ($code < 200 || $code >= 300) {
        $msg = 'HTTP ' . $code;
        if (isset($json['error']['message'])) $msg .= ': ' . (string)$json['error']['message'];
        elseif (isset($json['message'])) $msg .= ': ' . (string)$json['message'];
        return ['ok' => false, 'error' => $msg, 'data' => $json, 'http_code' => $code];
    }

    return ['ok' => true, 'error' => null, 'data' => $json, 'http_code' => $code];
}

function mspro_ai304_price_zero($v): bool
{
    if ($v === null || $v === '') return false;
    if (is_numeric($v)) return (float)$v == 0.0;
    return in_array(strtolower(trim((string)$v)), ['0', '0.0', '0.00', 'free'], true);
}

function mspro_ai304_fetch_openrouter_models(array $cfg): array
{
    $base = rtrim((string)($cfg['openrouter']['base_url'] ?? 'https://openrouter.ai/api/v1'), '/');
    $timeout = (int)($cfg['openrouter']['timeout_seconds'] ?? 20);
    $key = mspro_ai304_get_secret('openrouter');

    $res = mspro_ai304_http_json($base . '/models', $key, $timeout, [
        'HTTP-Referer: https://localhost/safety-monitor-pro',
        'X-Title: Safety Monitor Pro',
    ]);

    if (!$res['ok']) return ['ok' => false, 'models' => [], 'error' => $res['error'], 'source' => 'openrouter_models_api_failed'];

    $rows = $res['data']['data'] ?? [];
    if (!is_array($rows)) return ['ok' => false, 'models' => [], 'error' => 'Unexpected OpenRouter response', 'source' => 'openrouter_models_api_unexpected'];

    $models = [];
    foreach ($rows as $row) {
        if (!is_array($row)) continue;
        $id = (string)($row['id'] ?? '');
        if ($id === '') continue;

        $pricing = is_array($row['pricing'] ?? null) ? $row['pricing'] : [];
        $prompt = (string)($pricing['prompt'] ?? '');
        $completion = (string)($pricing['completion'] ?? '');
        $isFree = substr($id, -5) === ':free' || stripos($id, 'free') !== false || (mspro_ai304_price_zero($prompt) && mspro_ai304_price_zero($completion));

        $models[] = [
            'id' => $id,
            'name' => (string)($row['name'] ?? $id),
            'availability' => $isFree ? 'free' : 'paid',
            'selectable' => $isFree,
            'requires_key' => true,
            'context_length' => (int)($row['context_length'] ?? 0),
            'input_price' => $prompt !== '' ? $prompt : ($isFree ? '0' : 'not provided'),
            'output_price' => $completion !== '' ? $completion : ($isFree ? '0' : 'not provided'),
            'limit' => isset($row['context_length']) ? 'Context: ' . (int)$row['context_length'] : 'Not provided',
            'description' => substr((string)($row['description'] ?? ''), 0, 220),
        ];
    }

    usort($models, fn(array $a, array $b): int => (($a['availability'] ?? '') === ($b['availability'] ?? '')) ? strcmp((string)$a['id'], (string)$b['id']) : ((($a['availability'] ?? '') === 'free') ? -1 : 1));
    return ['ok' => true, 'models' => $models, 'error' => null, 'source' => 'openrouter_models_api_all_models'];
}

function mspro_ai304_fetch_qwen_models(array $cfg): array
{
    $base = rtrim((string)($cfg['qwen']['base_url'] ?? ''), '/');
    $timeout = (int)($cfg['qwen']['timeout_seconds'] ?? 20);
    $key = mspro_ai304_get_secret('qwen');

    if ($base === '' || strpos($base, '{WorkspaceId}') !== false || $key === '') {
        return ['ok' => false, 'models' => mspro_ai304_qwen_static_models(), 'error' => 'Qwen live /models unavailable. Static candidates loaded.', 'source' => 'qwen_static_fallback'];
    }

    $res = mspro_ai304_http_json($base . '/models', $key, $timeout);
    if (!$res['ok']) return ['ok' => false, 'models' => mspro_ai304_qwen_static_models(), 'error' => 'Qwen /models failed: ' . (string)$res['error'] . '. Static candidates loaded.', 'source' => 'qwen_static_fallback_models_api_failed'];

    $rows = [];
    if (is_array($res['data']['data'] ?? null)) $rows = $res['data']['data'];
    elseif (is_array($res['data']['models'] ?? null)) $rows = $res['data']['models'];
    elseif (is_array($res['data'] ?? null)) $rows = $res['data'];

    $models = [];
    foreach ($rows as $row) {
        if (is_string($row)) {
            $id = $row; $name = $row;
        } elseif (is_array($row)) {
            $id = (string)($row['id'] ?? $row['model'] ?? $row['name'] ?? '');
            $name = (string)($row['name'] ?? $id);
        } else continue;
        if ($id === '') continue;

        $models[] = [
            'id' => $id,
            'name' => $name ?: $id,
            'availability' => 'available_or_quota',
            'selectable' => true,
            'requires_key' => true,
            'context_length' => 0,
            'input_price' => 'workspace/account dependent',
            'output_price' => 'workspace/account dependent',
            'limit' => 'Limits depend on Alibaba workspace and model entitlement',
            'description' => 'Model returned by Qwen-compatible /models endpoint.',
        ];
    }

    if (!$models) return ['ok' => false, 'models' => mspro_ai304_qwen_static_models(), 'error' => 'Qwen /models returned no readable list. Static candidates loaded.', 'source' => 'qwen_static_fallback_empty'];
    usort($models, fn(array $a, array $b): int => strcmp((string)$a['id'], (string)$b['id']));
    return ['ok' => true, 'models' => $models, 'error' => null, 'source' => 'qwen_models_api_live'];
}

function mspro_ai304_fetch_opencode_ai_models(array $cfg): array
{
    $base = rtrim((string)($cfg['opencode_ai']['base_url'] ?? ''), '/');
    $timeout = (int)($cfg['opencode_ai']['timeout_seconds'] ?? 20);
    $key = mspro_ai304_get_secret('opencode_ai');

    if ($base === '') {
        return ['ok' => false, 'models' => mspro_ai304_opencode_ai_static_models(), 'error' => 'opencode.ai Base URL is empty. Static fallback loaded.', 'source' => 'opencode_ai_static_fallback_empty_base_url'];
    }

    $res = mspro_ai304_http_json($base . '/models', $key, $timeout);
    if (!$res['ok']) {
        return ['ok' => false, 'models' => mspro_ai304_opencode_ai_static_models(), 'error' => 'opencode.ai /models failed: ' . (string)$res['error'] . '. Static fallback loaded.', 'source' => 'opencode_ai_static_fallback_models_api_failed'];
    }

    $rows = [];
    if (is_array($res['data']['data'] ?? null)) $rows = $res['data']['data'];
    elseif (is_array($res['data']['models'] ?? null)) $rows = $res['data']['models'];
    elseif (is_array($res['data'] ?? null)) $rows = $res['data'];

    $models = [];
    foreach ($rows as $row) {
        if (is_string($row)) {
            $id = $row; $name = $row; $pricing = [];
        } elseif (is_array($row)) {
            $id = (string)($row['id'] ?? $row['model'] ?? $row['name'] ?? '');
            $name = (string)($row['name'] ?? $id);
            $pricing = is_array($row['pricing'] ?? null) ? $row['pricing'] : [];
        } else continue;
        if ($id === '') continue;

        $prompt = (string)($pricing['prompt'] ?? '');
        $completion = (string)($pricing['completion'] ?? '');
        $isFree = substr($id, -5) === ':free' || stripos($id, 'free') !== false || (mspro_ai304_price_zero($prompt) && mspro_ai304_price_zero($completion));
        $hasPricing = $prompt !== '' || $completion !== '';

        $models[] = [
            'id' => $id,
            'name' => $name ?: $id,
            'availability' => $isFree ? 'free' : ($hasPricing ? 'paid' : 'provider_catalog'),
            'selectable' => $isFree || !$hasPricing,
            'requires_key' => true,
            'context_length' => (int)($row['context_length'] ?? 0),
            'input_price' => $prompt !== '' ? $prompt : ($isFree ? '0' : 'provider/account dependent'),
            'output_price' => $completion !== '' ? $completion : ($isFree ? '0' : 'provider/account dependent'),
            'limit' => isset($row['context_length']) ? 'Context: ' . (int)$row['context_length'] : 'Provider/account dependent',
            'description' => substr((string)($row['description'] ?? 'Model returned by opencode.ai-compatible /models endpoint.'), 0, 220),
        ];
    }

    if (!$models) return ['ok' => false, 'models' => mspro_ai304_opencode_ai_static_models(), 'error' => 'opencode.ai /models returned no readable model list. Static fallback loaded.', 'source' => 'opencode_ai_static_fallback_empty_models'];

    usort($models, fn(array $a, array $b): int => (($a['availability'] ?? '') === ($b['availability'] ?? '')) ? strcmp((string)$a['id'], (string)$b['id']) : ((($a['availability'] ?? '') === 'free') ? -1 : 1));
    return ['ok' => true, 'models' => $models, 'error' => null, 'source' => 'opencode_ai_models_api'];
}

function mspro_ai304_pick_live_model(string $provider, array $cfg): string
{
    if (!isset($cfg[$provider]) || !is_array($cfg[$provider])) return '';
    $default = trim((string)($cfg[$provider]['default_model'] ?? ''));
    if ($default !== '') return $default;
    $active = is_array($cfg[$provider]['active_models'] ?? null) ? $cfg[$provider]['active_models'] : [];
    return (string)($active[0] ?? '');
}

function mspro_ai304_live_ping_provider(string $provider, array $cfg): array
{
    if (!in_array($provider, ['qwen', 'openrouter', 'opencode_ai'], true)) {
        return ['ok' => false, 'model' => '', 'message' => 'Live ping unavailable for provider.', 'http_code' => 0, 'sent_mail_data' => false, 'tested_at' => date('c')];
    }

    $key = mspro_ai304_get_secret($provider);
    if ($key === '') {
        return ['ok' => false, 'model' => '', 'message' => 'No encrypted API key saved for ' . $provider . '.', 'http_code' => 0, 'sent_mail_data' => false, 'tested_at' => date('c')];
    }

    $model = mspro_ai304_pick_live_model($provider, $cfg);
    if ($model === '') {
        $model = $provider === 'qwen' ? 'qwen-plus' : ($provider === 'openrouter' ? 'openrouter/free' : 'deepseek-v4-flash-free');
    }

    if ($provider === 'qwen') {
        $base = rtrim((string)($cfg['qwen']['base_url'] ?? ''), '/');
        $timeout = (int)($cfg['qwen']['timeout_seconds'] ?? 20);
    } elseif ($provider === 'openrouter') {
        $base = rtrim((string)($cfg['openrouter']['base_url'] ?? 'https://openrouter.ai/api/v1'), '/');
        $timeout = (int)($cfg['openrouter']['timeout_seconds'] ?? 20);
    } else {
        $base = rtrim((string)($cfg['opencode_ai']['base_url'] ?? ''), '/');
        $timeout = (int)($cfg['opencode_ai']['timeout_seconds'] ?? 20);
    }

    if ($base === '' || strpos($base, '{WorkspaceId}') !== false) {
        return ['ok' => false, 'model' => $model, 'message' => 'Base URL is incomplete.', 'http_code' => 0, 'sent_mail_data' => false, 'tested_at' => date('c')];
    }

    $endpoint = $base . '/chat/completions';
    $payload = [
        'model' => $model,
        'messages' => [['role' => 'user', 'content' => 'Return OK only.']],
        'temperature' => 0,
        'max_tokens' => 8,
    ];

    $res = mspro_ai304_http_post_json($endpoint, $key, $payload, $timeout);
    $reply = '';
    if (is_array($res['data'] ?? null)) {
        $reply = (string)($res['data']['choices'][0]['message']['content'] ?? '');
    }

    return [
        'ok' => !empty($res['ok']),
        'model' => $model,
        'message' => !empty($res['ok']) ? ('Live ping OK. Reply: ' . substr(trim($reply), 0, 80)) : mspro_ai307_sanitize_provider_message((string)($res['error'] ?? 'Live ping failed')),
        'http_code' => (int)($res['http_code'] ?? 0),
        'tested_at' => date('c'),
        'sent_mail_data' => false,
        'prompt' => 'Return OK only.',
        'endpoint' => $endpoint,
    ];
}

function mspro_ai304_int_post(string $name, int $default, int $min, int $max): int
{
    $value = filter_input(INPUT_POST, $name, FILTER_VALIDATE_INT);
    if ($value === false || $value === null) return $default;
    return max($min, min($max, (int)$value));
}

function mspro_ai304_array_post(string $name): array
{
    $value = $_POST[$name] ?? [];
    if (!is_array($value)) return [];
    $out = [];
    foreach ($value as $item) {
        $id = trim(str_replace(["\0", "\r", "\n"], '', (string)$item));
        if ($id !== '') $out[] = substr($id, 0, 180);
    }
    return array_values(array_unique($out));
}

function mspro_ai304_selected(string $a, string $b): string { return $a === $b ? 'selected' : ''; }
function mspro_ai304_checked(bool $v): string { return $v ? 'checked' : ''; }

function mspro_ai304_model_catalog_for_provider(string $provider, array $catalog): array
{
    $default = mspro_ai304_default_catalog();
    return is_array($catalog[$provider] ?? null) ? $catalog[$provider] : ($default[$provider] ?? ['models' => []]);
}

function mspro_ai304_model_allowed_ids(string $provider, array $catalog): array
{
    $data = mspro_ai304_model_catalog_for_provider($provider, $catalog);
    $allowed = [];
    foreach ((array)($data['models'] ?? []) as $model) {
        if (!is_array($model) || empty($model['selectable'])) continue;
        $id = (string)($model['id'] ?? '');
        if ($id !== '') $allowed[$id] = true;
    }
    return $allowed;
}

function mspro_ai304_apply_provider_settings(array $cfg, string $provider): array
{
    $labels = mspro_ai304_provider_labels();
    if (!isset($labels[$provider])) $provider = 'qwen';

    $cfg['provider'] = $provider;
    $cfg['provider_label'] = $labels[$provider];
    $cfg['read_body'] = false;
    $cfg['enforcement'] = false;

    $cfg['data_mode'] = in_array((string)($_POST['data_mode'] ?? $cfg['data_mode'] ?? ''), ['masked_headers_only', 'full_headers_allowed'], true) ? (string)($_POST['data_mode'] ?? $cfg['data_mode']) : 'masked_headers_only';
    $cfg['decision_mode'] = in_array((string)($_POST['decision_mode'] ?? $cfg['decision_mode'] ?? ''), ['recommend_only', 'tag_preview', 'quarantine_preview'], true) ? (string)($_POST['decision_mode'] ?? $cfg['decision_mode']) : 'recommend_only';

    if ($provider === 'qwen') {
        $regions = mspro_ai304_qwen_regions();
        $region = (string)($_POST['qwen_region'] ?? ($cfg['qwen']['region'] ?? 'singapore_workspace'));
        if (!isset($regions[$region])) $region = 'singapore_workspace';
        $workspace = mspro_ai304_clean_workspace((string)($_POST['qwen_workspace_id'] ?? ($cfg['qwen']['workspace_id'] ?? '')));

        $cfg['qwen']['region'] = $region;
        $cfg['qwen']['region_label'] = (string)$regions[$region]['label'];
        $cfg['qwen']['workspace_id'] = $workspace;
        $cfg['qwen']['base_url'] = mspro_ai304_qwen_base($region, $workspace);
        $cfg['qwen']['default_model'] = trim((string)($_POST['qwen_default_model'] ?? ($cfg['qwen']['default_model'] ?? 'qwen-plus'))) ?: 'qwen-plus';
        $cfg['qwen']['daily_token_limit'] = mspro_ai304_int_post('qwen_daily_token_limit', (int)($cfg['qwen']['daily_token_limit'] ?? 50000), 1000, 1000000);
        $cfg['qwen']['max_headers_per_run'] = mspro_ai304_int_post('qwen_max_headers_per_run', (int)($cfg['qwen']['max_headers_per_run'] ?? 50), 1, 1000);
        $cfg['qwen']['timeout_seconds'] = mspro_ai304_int_post('qwen_timeout_seconds', (int)($cfg['qwen']['timeout_seconds'] ?? 20), 3, 120);
    } elseif ($provider === 'openrouter') {
        $cfg['openrouter']['base_url'] = mspro_ai304_safe_base((string)($_POST['openrouter_base_url'] ?? ($cfg['openrouter']['base_url'] ?? '')), 'https://openrouter.ai/api/v1');
        $cfg['openrouter']['default_model'] = trim((string)($_POST['openrouter_default_model'] ?? ($cfg['openrouter']['default_model'] ?? 'openrouter/free'))) ?: 'openrouter/free';
        $cfg['openrouter']['daily_token_limit'] = mspro_ai304_int_post('openrouter_daily_token_limit', (int)($cfg['openrouter']['daily_token_limit'] ?? 50000), 1000, 1000000);
        $cfg['openrouter']['max_headers_per_run'] = mspro_ai304_int_post('openrouter_max_headers_per_run', (int)($cfg['openrouter']['max_headers_per_run'] ?? 50), 1, 1000);
        $cfg['openrouter']['timeout_seconds'] = mspro_ai304_int_post('openrouter_timeout_seconds', (int)($cfg['openrouter']['timeout_seconds'] ?? 20), 3, 120);
    } elseif ($provider === 'opencode_ai') {
        $cfg['opencode_ai']['base_url'] = mspro_ai304_safe_base((string)($_POST['opencode_ai_base_url'] ?? ($cfg['opencode_ai']['base_url'] ?? '')), '');
        $cfg['opencode_ai']['default_model'] = trim((string)($_POST['opencode_ai_default_model'] ?? ($cfg['opencode_ai']['default_model'] ?? 'deepseek-v4-flash-free'))) ?: 'deepseek-v4-flash-free';
        $cfg['opencode_ai']['daily_token_limit'] = mspro_ai304_int_post('opencode_ai_daily_token_limit', (int)($cfg['opencode_ai']['daily_token_limit'] ?? 50000), 1000, 1000000);
        $cfg['opencode_ai']['max_headers_per_run'] = mspro_ai304_int_post('opencode_ai_max_headers_per_run', (int)($cfg['opencode_ai']['max_headers_per_run'] ?? 50), 1, 1000);
        $cfg['opencode_ai']['timeout_seconds'] = mspro_ai304_int_post('opencode_ai_timeout_seconds', (int)($cfg['opencode_ai']['timeout_seconds'] ?? 20), 3, 120);
    }

    $active = is_array($cfg['active_providers'] ?? null) ? $cfg['active_providers'] : [];
    $active = array_values(array_filter(array_unique(array_map('strval', $active)), fn(string $p): bool => isset($labels[$p])));

    if (!empty($_POST['active_agent'])) {
        if (!in_array($provider, $active, true)) $active[] = $provider;
    } else {
        $active = array_values(array_filter($active, fn(string $p): bool => $p !== $provider));
    }

    $cfg['active_providers'] = $active;
    $cfg['enabled'] = !empty($active);
    $cfg['external_calls'] = !empty($active);

    foreach (array_keys($labels) as $p) {
        $cfg[$p]['enabled'] = in_array($p, $active, true);
    }

    return $cfg;
}

function mspro_ai304_save_key_for_provider(string $provider): string
{
    if (!in_array($provider, ['qwen', 'openrouter', 'opencode_ai'], true)) return '';

    if (!empty($_POST['clear_' . $provider . '_key'])) {
        mspro_ai304_clear_secret($provider);
        return '';
    }

    $key = trim((string)($_POST[$provider . '_api_key'] ?? ''));
    if ($key !== '' && !mspro_ai304_save_secret($provider, $key)) {
        return 'Failed to save encrypted API key for ' . $provider . '.';
    }
    return '';
}


function mspro_ai307_sanitize_provider_message(string $message): string
{
    /*
     * Never show provider-returned API keys or Bearer values in UI/logs/config.
     */
    $message = preg_replace('/sk-[A-Za-z0-9_\-*]{8,}/', 'sk-***REDACTED***', $message);
    $message = preg_replace('/Bearer\s+[A-Za-z0-9_\-\.\*]{12,}/i', 'Bearer ***REDACTED***', $message);
    $message = preg_replace('/api[_-]?key\s*[:=]\s*[A-Za-z0-9_\-\.]{8,}/i', 'api_key=***REDACTED***', $message);
    return $message;
}

function mspro_ai307_sanitize_ping_result(array $ping): array
{
    if (isset($ping['message'])) {
        $ping['message'] = mspro_ai307_sanitize_provider_message((string)$ping['message']);
    }
    if (isset($ping['endpoint'])) {
        $ping['endpoint'] = (string)$ping['endpoint'];
    }
    $ping['sent_mail_data'] = false;
    return $ping;
}

function mspro_ai307_test_all_agents(array $cfg): array
{
    $labels = mspro_ai304_provider_labels();
    $providers = ['qwen', 'openrouter', 'opencode_ai'];

    $results = [];
    foreach ($providers as $provider) {
        $started = microtime(true);

        if (!isset($labels[$provider])) {
            continue;
        }

        $ping = mspro_ai304_live_ping_provider($provider, $cfg);
        $ping = mspro_ai307_sanitize_ping_result($ping);
        $ping['provider'] = $provider;
        $ping['provider_label'] = $labels[$provider];
        $ping['duration_ms'] = (int)round((microtime(true) - $started) * 1000);

        $results[$provider] = $ping;
    }

    $ok = 0;
    foreach ($results as $item) {
        if (!empty($item['ok'])) {
            $ok++;
        }
    }

    return [
        'tested_at' => date('c'),
        'ok_count' => $ok,
        'total_count' => count($results),
        'sent_mail_data' => false,
        'prompt' => 'Return OK only.',
        'results' => $results,
    ];
}



if (!function_exists('mspro_ai308_provider_list')) {
    function mspro_ai308_provider_list(): array
    {
        return [
            'qwen' => 'Alibaba Qwen',
            'openrouter' => 'OpenRouter',
            'opencode_ai' => 'opencode.ai',
        ];
    }
}

if (!function_exists('mspro_ai308_sanitize_message')) {
    function mspro_ai308_sanitize_message(string $message): string
    {
        $message = preg_replace('/sk-[A-Za-z0-9_\-*]{8,}/', 'sk-***REDACTED***', $message);
        $message = preg_replace('/Bearer\s+[A-Za-z0-9_\-\.\*]{12,}/i', 'Bearer ***REDACTED***', $message);
        $message = preg_replace('/api[_-]?key\s*[:=]\s*[A-Za-z0-9_\-\.]{8,}/i', 'api_key=***REDACTED***', $message);
        return $message;
    }
}

if (!function_exists('mspro_ai308_provider_base_url')) {
    function mspro_ai308_provider_base_url(string $provider, array $cfg): string
    {
        if ($provider === 'qwen') {
            return (string)($cfg['qwen']['base_url'] ?? '');
        }
        if ($provider === 'openrouter') {
            return (string)($cfg['openrouter']['base_url'] ?? '');
        }
        if ($provider === 'opencode_ai') {
            return (string)($cfg['opencode_ai']['base_url'] ?? '');
        }
        return '';
    }
}

if (!function_exists('mspro_ai308_test_all_agents')) {
    function mspro_ai308_test_all_agents(array $cfg): array
    {
        $providers = mspro_ai308_provider_list();
        $results = [];

        foreach ($providers as $provider => $label) {
            $started = microtime(true);

            if (!function_exists('mspro_ai304_live_ping_provider')) {
                $ping = [
                    'ok' => false,
                    'model' => '',
                    'message' => 'Live ping function is not available.',
                    'http_code' => 0,
                    'sent_mail_data' => false,
                    'tested_at' => date('c'),
                ];
            } else {
                $ping = mspro_ai304_live_ping_provider($provider, $cfg);
            }

            if (isset($ping['message'])) {
                $ping['message'] = mspro_ai308_sanitize_message((string)$ping['message']);
            }

            $ping['provider'] = $provider;
            $ping['provider_label'] = $label;
            $ping['duration_ms'] = (int)round((microtime(true) - $started) * 1000);
            $ping['sent_mail_data'] = false;

            $results[$provider] = $ping;
        }

        $ok = 0;
        foreach ($results as $result) {
            if (!empty($result['ok'])) {
                $ok++;
            }
        }

        return [
            'tested_at' => date('c'),
            'ok_count' => $ok,
            'total_count' => count($results),
            'sent_mail_data' => false,
            'prompt' => 'Return OK only.',
            'results' => $results,
        ];
    }
}

if (!function_exists('mspro_ai308_build_readiness')) {
    function mspro_ai308_build_readiness(array $cfg): array
    {
        $providers = mspro_ai308_provider_list();
        $items = [];
        $readyCount = 0;

        foreach ($providers as $provider => $label) {
            $issues = [];
            $baseUrl = trim(mspro_ai308_provider_base_url($provider, $cfg));
            $models = is_array($cfg[$provider]['active_models'] ?? null) ? $cfg[$provider]['active_models'] : [];
            $lastPing = is_array($cfg[$provider]['last_live_test'] ?? null) ? $cfg[$provider]['last_live_test'] : [];
            $lastPingOk = !empty($lastPing['ok']);

            $hasKey = function_exists('mspro_ai304_secret_exists') ? mspro_ai304_secret_exists($provider) : false;

            if (!$hasKey) {
                $issues[] = 'No encrypted API key saved';
            }

            if ($baseUrl === '') {
                $issues[] = 'Base URL is empty';
            }

            if ($provider === 'qwen' && strpos($baseUrl, '{WorkspaceId}') !== false) {
                $issues[] = 'Qwen Workspace ID/Base URL is incomplete';
            }

            if (!$models) {
                $issues[] = 'No selected models';
            }

            if (!$lastPingOk) {
                $msg = mspro_ai308_sanitize_message((string)($lastPing['message'] ?? 'No successful live ping yet'));
                $issues[] = 'Live ping not OK: ' . $msg;
            }

            $ready = empty($issues);
            if ($ready) {
                $readyCount++;
            }

            $items[$provider] = [
                'provider' => $provider,
                'provider_label' => $label,
                'ready' => $ready,
                'has_key' => $hasKey,
                'base_url' => $baseUrl,
                'selected_models' => $models,
                'selected_model_count' => count($models),
                'last_ping_ok' => $lastPingOk,
                'last_ping_model' => (string)($lastPing['model'] ?? ''),
                'last_ping_http_code' => (int)($lastPing['http_code'] ?? 0),
                'last_ping_tested_at' => (string)($lastPing['tested_at'] ?? ''),
                'issues' => $issues,
            ];
        }

        return [
            'generated_at' => date('c'),
            'ready_count' => $readyCount,
            'total_count' => count($items),
            'all_ready' => $readyCount === count($items) && count($items) > 0,
            'items' => $items,
            'mail_data_sent' => false,
        ];
    }
}


function mspro_ai304_handle_post(): string
{
    static $handled = false;
    static $result = '';
    if ($handled) return $result;
    $handled = true;

    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') return '';

    // AUTHORIZATION: this handler writes provider config + encrypted API keys as root, so it MUST enforce the
    // same root gate every other state-changing endpoint uses (the token below is only anti-CSRF, not authz).
    // Fail CLOSED — if the root gate isn't loaded (bootstrap missing), refuse rather than silently skipping authz.
    if (!function_exists('smpro_require_root')) { http_response_code(403); echo json_encode(['ok'=>false,'message'=>'Unauthorized']); exit; }
    smpro_require_root();

    $action = (string)($_POST['mspro_ai304_action'] ?? '');
    if ($action === '' && isset($_POST['mspro_ai304_token'])) $action = 'save_settings';
    if ($action === '') return '';

    if (!mspro_ai304_valid_token((string)($_POST['mspro_ai304_token'] ?? ''))) {
        $result = 'Security token expired. Refresh and try again.';
        return $result;
    }

    $cfg = mspro_ai304_load_config();
    $labels = mspro_ai304_provider_labels();
    $provider = (string)($_POST['provider'] ?? ($cfg['provider'] ?? 'qwen'));
    if (!isset($labels[$provider])) $provider = 'qwen';

    mspro_ai304_log('post_received', [
        'action' => $action,
        'provider' => $provider,
        'has_key_input' => trim((string)($_POST[$provider . '_api_key'] ?? '')) !== '',
        'active_agent' => !empty($_POST['active_agent']),
    ]);


    if ($action === 'test_all_agents' || $action === 'refresh_agent_readiness') {
        if ($action === 'test_all_agents') {
            $allTest = mspro_ai308_test_all_agents($cfg);

            foreach ((array)($allTest['results'] ?? []) as $testedProvider => $testedResult) {
                if (isset($cfg[$testedProvider]) && is_array($cfg[$testedProvider])) {
                    $cfg[$testedProvider]['last_live_test'] = $testedResult;
                }
            }

            $cfg['last_all_agents_test'] = $allTest;
        }

        $cfg['last_agent_readiness'] = mspro_ai308_build_readiness($cfg);
        mspro_ai304_write_json(mspro_ai304_config_path(), $cfg);

        if ($action === 'test_all_agents') {
            $result = 'All AI agents tested. Ready: '
                . (int)($cfg['last_agent_readiness']['ready_count'] ?? 0)
                . ' / '
                . (int)($cfg['last_agent_readiness']['total_count'] ?? 0)
                . '.';
        } else {
            $result = 'AI agent readiness refreshed. Ready: '
                . (int)($cfg['last_agent_readiness']['ready_count'] ?? 0)
                . ' / '
                . (int)($cfg['last_agent_readiness']['total_count'] ?? 0)
                . '.';
        }

        return $result;
    }

    if ($action === 'switch_provider') {
        $cfg['provider'] = $provider;
        $cfg['provider_label'] = $labels[$provider];
        $cfg['read_body'] = false;
        $cfg['enforcement'] = false;
        mspro_ai304_write_json(mspro_ai304_config_path(), $cfg);
        $result = 'Editing provider changed to ' . $labels[$provider] . '.';
        return $result;
    }

    $cfg = mspro_ai304_apply_provider_settings($cfg, $provider);

    $keyError = mspro_ai304_save_key_for_provider($provider);
    if ($keyError !== '') {
        $result = $keyError;
        return $result;
    }

    $catalog = mspro_ai304_load_catalog();

    if ($action === 'save_models') {
        $allowed = mspro_ai304_model_allowed_ids($provider, $catalog);
        $posted = mspro_ai304_array_post('active_models');
        $selected = array_values(array_filter($posted, fn(string $id): bool => isset($allowed[$id])));
        $cfg[$provider]['active_models'] = $selected;
        mspro_ai304_write_json(mspro_ai304_config_path(), $cfg);
        $result = 'Selected models saved for ' . $labels[$provider] . '.';
        return $result;
    }

    if ($action === 'test_provider') {
        if ($provider === 'openrouter') {
            $fetch = mspro_ai304_fetch_openrouter_models($cfg);
        } elseif ($provider === 'qwen') {
            $fetch = mspro_ai304_fetch_qwen_models($cfg);
        } else {
            $fetch = mspro_ai304_fetch_opencode_ai_models($cfg);
        }

        $catalog[$provider] = [
            'fetched_at' => date('c'),
            'source' => $fetch['source'],
            'models' => $fetch['models'],
            'error' => $fetch['error'],
        ];

        $cfg[$provider]['last_test'] = [
            'tested_at' => date('c'),
            'ok' => $fetch['ok'],
            'message' => $fetch['ok'] ? ($labels[$provider] . ' models fetched.') : (string)$fetch['error'],
            'model_count' => count($fetch['models']),
        ];

        mspro_ai304_write_json(mspro_ai304_catalog_path(), $catalog);
        mspro_ai304_write_json(mspro_ai304_config_path(), $cfg);

        $result = 'Provider tested/loaded. ' . count((array)$fetch['models']) . ' models are now available for ' . $labels[$provider] . '.';
        return $result;
    }


    if ($action === 'test_all_agents') {
        $allTest = mspro_ai307_test_all_agents($cfg);

        foreach (($allTest['results'] ?? []) as $testedProvider => $testedResult) {
            if (isset($cfg[$testedProvider]) && is_array($cfg[$testedProvider])) {
                $cfg[$testedProvider]['last_live_test'] = mspro_ai307_sanitize_ping_result($testedResult);
            }
        }

        $cfg['last_all_agents_test'] = $allTest;

        mspro_ai304_write_json(mspro_ai304_config_path(), $cfg);

        mspro_ai304_log('test_all_agents_result', [
            'ok_count' => (int)($allTest['ok_count'] ?? 0),
            'total_count' => (int)($allTest['total_count'] ?? 0),
            'sent_mail_data' => false,
            'results' => array_map(function ($item) {
                return [
                    'provider' => (string)($item['provider'] ?? ''),
                    'ok' => !empty($item['ok']),
                    'model' => (string)($item['model'] ?? ''),
                    'http_code' => (int)($item['http_code'] ?? 0),
                    'message' => mspro_ai307_sanitize_provider_message((string)($item['message'] ?? '')),
                    'sent_mail_data' => false,
                ];
            }, (array)($allTest['results'] ?? [])),
        ]);

        $result = 'All AI agents tested. OK: ' . (int)$allTest['ok_count'] . ' / ' . (int)$allTest['total_count'] . '.';
        return $result;
    }

    if ($action === 'live_ping') {
        $ping = mspro_ai304_live_ping_provider($provider, $cfg);
        $cfg[$provider]['last_live_test'] = $ping;
        mspro_ai304_write_json(mspro_ai304_config_path(), $cfg);
        mspro_ai304_log('live_ping_result', [
            'provider' => $provider,
            'ok' => !empty($ping['ok']),
            'model' => (string)($ping['model'] ?? ''),
            'http_code' => (int)($ping['http_code'] ?? 0),
            'message' => (string)($ping['message'] ?? ''),
            'sent_mail_data' => false,
        ]);

        $result = !empty($ping['ok'])
            ? ('Live API ping successful using ' . $labels[$provider] . ' model ' . (string)($ping['model'] ?? '') . '.')
            : ('Live API ping failed for ' . $labels[$provider] . ': ' . (string)($ping['message'] ?? 'Unknown error'));
        return $result;
    }

    mspro_ai304_write_json(mspro_ai304_config_path(), $cfg);
    $result = 'Provider settings saved for ' . $labels[$provider] . '.';
    return $result;
}

function mspro_ai304_badge(string $availability): string
{
    $class = 'neutral';
    if ($availability === 'free') $class = 'good';
    elseif (in_array($availability, ['free_quota_or_paid', 'available_or_quota', 'provider_catalog'], true)) $class = 'warn';
    elseif (in_array($availability, ['paid', 'paid_or_requires_key'], true)) $class = 'danger';
    return '<span class="ai304-badge ' . $class . '">' . mspro_ai304_e($availability) . '</span>';
}

function mspro_ai304_render_model_picker(string $provider, array $catalog, array $cfg): void
{
    $labels = mspro_ai304_provider_labels();
    $label = $labels[$provider] ?? $provider;
    $data = mspro_ai304_model_catalog_for_provider($provider, $catalog);
    $models = is_array($data['models'] ?? null) ? $data['models'] : [];
    $error = (string)($data['error'] ?? '');
    $active = is_array($cfg[$provider]['active_models'] ?? null) ? $cfg[$provider]['active_models'] : [];

    echo '<section class="panel ai304-models">';
    echo '<div class="panel-head"><div><h3>Models for ' . mspro_ai304_e($label) . '</h3><p class="muted">All available models are shown when API allows it. Free/allowed models are selectable.</p></div><span class="pill good">' . count($models) . ' models</span></div>';
    echo '<div class="ai304-catalog-meta"><span>Source: <code>' . mspro_ai304_e((string)($data['source'] ?? '-')) . '</code></span><span>Fetched: ' . mspro_ai304_e((string)($data['fetched_at'] ?? '-')) . '</span></div>';

    if ($error !== '') echo '<div class="ai304-warning">' . mspro_ai304_e($error) . '</div>';

    if (!$models) {
        echo '<div class="empty-state"><b>No models loaded yet.</b><span>Click Test Connection / Fetch Models.</span></div></section>';
        return;
    }

    echo '<form method="post" class="ai304-model-form">';
    echo '<input type="hidden" name="mspro_ai304_token" value="' . mspro_ai304_e(mspro_ai304_token()) . '">';
    echo '<input type="hidden" name="mspro_ai304_action" value="save_models">';
    echo '<input type="hidden" name="provider" value="' . mspro_ai304_e($provider) . '">';
    if (!empty($cfg[$provider]['enabled'])) {
        echo '<input type="hidden" name="active_agent" value="1">';
    }

    echo '<div class="ai304-model-list">';
    foreach ($models as $model) {
        if (!is_array($model)) continue;
        $id = (string)($model['id'] ?? '');
        if ($id === '') continue;

        $selectable = !empty($model['selectable']);
        $checked = in_array($id, $active, true) ? 'checked' : '';

        echo '<label class="ai304-model-card ' . ($selectable ? '' : 'disabled') . '">';
        echo '<input type="checkbox" name="active_models[]" value="' . mspro_ai304_e($id) . '" ' . $checked . ' ' . ($selectable ? '' : 'disabled') . '>';
        echo '<span class="ai304-model-title"><b>' . mspro_ai304_e($id) . '</b><em>' . mspro_ai304_e((string)($model['name'] ?? $id)) . '</em></span>';
        echo '<span class="ai304-model-badges">' . mspro_ai304_badge((string)($model['availability'] ?? 'unknown')) . '<small>' . (empty($model['requires_key']) ? 'No key required' : 'Requires key') . '</small></span>';
        echo '<span class="ai304-model-meta">';
        echo '<small>Context: ' . mspro_ai304_e((string)($model['context_length'] ?? 'unknown')) . '</small>';
        echo '<small>Input: ' . mspro_ai304_e((string)($model['input_price'] ?? '-')) . '</small>';
        echo '<small>Output: ' . mspro_ai304_e((string)($model['output_price'] ?? '-')) . '</small>';
        echo '<small>Limit: ' . mspro_ai304_e((string)($model['limit'] ?? 'not provided')) . '</small>';
        echo '</span>';
        echo '<p>' . mspro_ai304_e((string)($model['description'] ?? '')) . '</p>';
        echo '</label>';
    }
    echo '</div>';
    echo '<div class="ai304-footer"><button class="ops-btn primary" type="submit">Save Selected Models</button><span>Selections are saved only for ' . mspro_ai304_e($label) . '.</span></div>';
    echo '</form></section>';
}

function mspro_ai304_active_notice(array $cfg): string
{
    $labels = mspro_ai304_provider_labels();
    $activeProviders = is_array($cfg['active_providers'] ?? null) ? $cfg['active_providers'] : [];
    $parts = [];

    foreach ($activeProviders as $provider) {
        if (!isset($labels[$provider])) continue;
        $models = is_array($cfg[$provider]['active_models'] ?? null) ? $cfg[$provider]['active_models'] : [];
        $parts[] = $labels[$provider] . ' | models: ' . ($models ? implode(', ', $models) : 'no models selected');
    }

    if (!$parts) return 'No active AI agents. Select a provider, enable Active Agent, choose models, and save.';
    return 'Active AI Agents: ' . implode('  •  ', $parts);
}

function mspro_ai304_render_provider_fields(string $provider, array $cfg): void
{
    $q = is_array($cfg['qwen'] ?? null) ? $cfg['qwen'] : [];
    $op = is_array($cfg['openrouter'] ?? null) ? $cfg['openrouter'] : [];
    $oc = is_array($cfg['opencode_ai'] ?? null) ? $cfg['opencode_ai'] : [];
    $regions = mspro_ai304_qwen_regions();

    if ($provider === 'qwen') {
        echo '<section class="ai304-provider-card">';
        echo '<div class="ai304-provider-head"><h3>Alibaba Qwen ' . (mspro_ai304_secret_exists('qwen') ? '<span class="pill good">Encrypted key saved</span>' : '<span class="pill warn">No API key</span>') . '</h3><p>Only Qwen settings are open for editing now.</p></div>';
        echo '<div class="ai304-warning">Endpoint: ' . mspro_ai304_e((string)($q['base_url'] ?? '')) . '</div>';
        echo mspro_ai304_secret_status_html('qwen');
        echo '<div class="ai304-grid">';
        echo '<label><span>API Key</span><input type="password" name="qwen_api_key" placeholder="Saved key is hidden. Leave blank to keep, paste new key to replace"></label>';
        echo '<label><span>Clear Key</span><div class="ai304-check"><input type="checkbox" name="clear_qwen_key" value="1"><em>Remove encrypted key</em></div></label>';
        echo '<label><span>Default Model</span><input type="text" name="qwen_default_model" value="' . mspro_ai304_e((string)($q['default_model'] ?? 'qwen-plus')) . '"></label>';
        echo '<label><span>Region</span><select name="qwen_region" id="qwen_region">';
        foreach ($regions as $key => $info) {
            echo '<option value="' . mspro_ai304_e((string)$key) . '" data-template="' . mspro_ai304_e((string)$info['template']) . '" ' . mspro_ai304_selected((string)($q['region'] ?? 'singapore_workspace'), (string)$key) . '>' . mspro_ai304_e((string)$info['label']) . '</option>';
        }
        echo '</select></label>';
        echo '<label><span>Workspace ID</span><input type="text" name="qwen_workspace_id" id="qwen_workspace_id" value="' . mspro_ai304_e((string)($q['workspace_id'] ?? '')) . '" placeholder="Example: ws-xxxxxxxx"></label>';
        echo '<label><span>Generated Base URL</span><input type="text" readonly id="qwen_base_url_display" value="' . mspro_ai304_e((string)($q['base_url'] ?? '')) . '"></label>';
        echo '<label><span>Daily Token Limit</span><input type="number" name="qwen_daily_token_limit" value="' . (int)($q['daily_token_limit'] ?? 50000) . '"></label>';
        echo '<label><span>Max Headers Per Run</span><input type="number" name="qwen_max_headers_per_run" value="' . (int)($q['max_headers_per_run'] ?? 50) . '"></label>';
        echo '<label><span>Timeout Seconds</span><input type="number" name="qwen_timeout_seconds" value="' . (int)($q['timeout_seconds'] ?? 20) . '"></label>';
        echo '</div></section>';
        return;
    }

    if ($provider === 'openrouter') {
        echo '<section class="ai304-provider-card">';
        echo '<div class="ai304-provider-head"><h3>OpenRouter ' . (mspro_ai304_secret_exists('openrouter') ? '<span class="pill good">Encrypted key saved</span>' : '<span class="pill warn">No API key</span>') . '</h3><p>Only OpenRouter settings are open for editing now.</p></div>';
        echo mspro_ai304_secret_status_html('openrouter');
        echo '<div class="ai304-grid">';
        echo '<label><span>API Key</span><input type="password" name="openrouter_api_key" placeholder="Saved key is hidden. Leave blank to keep, paste new key to replace"></label>';
        echo '<label><span>Clear Key</span><div class="ai304-check"><input type="checkbox" name="clear_openrouter_key" value="1"><em>Remove encrypted key</em></div></label>';
        echo '<label><span>Base URL</span><input type="text" name="openrouter_base_url" value="' . mspro_ai304_e((string)($op['base_url'] ?? 'https://openrouter.ai/api/v1')) . '"></label>';
        echo '<label><span>Default Model</span><input type="text" name="openrouter_default_model" value="' . mspro_ai304_e((string)($op['default_model'] ?? 'openrouter/free')) . '"></label>';
        echo '<label><span>Daily Token Limit</span><input type="number" name="openrouter_daily_token_limit" value="' . (int)($op['daily_token_limit'] ?? 50000) . '"></label>';
        echo '<label><span>Max Headers Per Run</span><input type="number" name="openrouter_max_headers_per_run" value="' . (int)($op['max_headers_per_run'] ?? 50) . '"></label>';
        echo '<label><span>Timeout Seconds</span><input type="number" name="openrouter_timeout_seconds" value="' . (int)($op['timeout_seconds'] ?? 20) . '"></label>';
        echo '</div></section>';
        return;
    }

    echo '<section class="ai304-provider-card">';
    echo '<div class="ai304-provider-head"><h3>opencode.ai ' . (mspro_ai304_secret_exists('opencode_ai') ? '<span class="pill good">Encrypted key saved</span>' : '<span class="pill warn">No API key</span>') . '</h3><p>Only opencode.ai settings are open for editing now.</p></div>';
    echo '<div class="ai304-warning">Use Base URL https://opencode.ai/zen/v1. The plugin tests /models and /chat/completions only. No mail data is sent.</div>';
    echo mspro_ai304_secret_status_html('opencode_ai');
    echo '<div class="ai304-grid">';
    echo '<label><span>API Key</span><input type="password" name="opencode_ai_api_key" placeholder="Saved key is hidden. Leave blank to keep, paste new key to replace"></label>';
    echo '<label><span>Clear Key</span><div class="ai304-check"><input type="checkbox" name="clear_opencode_ai_key" value="1"><em>Remove encrypted key</em></div></label>';
    echo '<label><span>Base URL</span><input type="text" name="opencode_ai_base_url" value="' . mspro_ai304_e((string)($oc['base_url'] ?? '')) . '" placeholder="https://opencode.ai/zen/v1"></label>';
    echo '<label><span>Default Model</span><input type="text" name="opencode_ai_default_model" value="' . mspro_ai304_e((string)($oc['default_model'] ?? 'deepseek-v4-flash-free')) . '"></label>';
    echo '<label><span>Daily Token Limit</span><input type="number" name="opencode_ai_daily_token_limit" value="' . (int)($oc['daily_token_limit'] ?? 50000) . '"></label>';
    echo '<label><span>Max Headers Per Run</span><input type="number" name="opencode_ai_max_headers_per_run" value="' . (int)($oc['max_headers_per_run'] ?? 50) . '"></label>';
    echo '<label><span>Timeout Seconds</span><input type="number" name="opencode_ai_timeout_seconds" value="' . (int)($oc['timeout_seconds'] ?? 20) . '"></label>';
    echo '</div></section>';
}

function mspro_ai304_render_page(): void
{
    $msg = $GLOBALS['mspro_ai304_message']
        ?? $GLOBALS['mspro_ai29_message']
        ?? $GLOBALS['mspro_ai28_message']
        ?? $GLOBALS['mspro_ai26_message']
        ?? $GLOBALS['mspro_ai25_message']
        ?? $GLOBALS['mspro_ai_message']
        ?? '';

    $cfg = mspro_ai304_load_config();
    $catalog = mspro_ai304_load_catalog();
    $revision = mspro_ai304_read_json(mspro_ai304_revision_path(), ['revision_id' => '30.6.1']);
    $labels = mspro_ai304_provider_labels();

    $provider = (string)($cfg['provider'] ?? 'qwen');
    if (!isset($labels[$provider])) $provider = 'qwen';

    $activeProviders = is_array($cfg['active_providers'] ?? null) ? $cfg['active_providers'] : [];
    $currentModels = is_array($cfg[$provider]['active_models'] ?? null) ? $cfg[$provider]['active_models'] : [];
    $providerKey = mspro_ai304_secret_exists($provider);

    ?>
    <section class="panel ai304-banner">
        <div>
            <b>Revision #<?php echo mspro_ai304_e((string)($revision['revision_id'] ?? '30.6.1')); ?></b>
            <span>AI Providers — Qwen, OpenRouter, opencode.ai</span>
        </div>
        <span class="pill good">No mail enforcement</span>
    </section>

    <div class="ai304-active-line <?php echo $activeProviders ? 'good' : 'warn'; ?>">
        <?php echo mspro_ai304_e(mspro_ai304_active_notice($cfg)); ?>
    </div>


    <?php if (!empty($cfg['last_all_agents_test']) && is_array($cfg['last_all_agents_test'])): ?>
        <section class="panel ai307-test-panel">
            <div class="panel-head">
                <div>
                    <h3>Last All Agents Test</h3>
                    <p class="muted">Ping-only test. No mail data was sent.</p>
                </div>
                <span class="pill <?php echo ((int)($cfg['last_all_agents_test']['ok_count'] ?? 0) === (int)($cfg['last_all_agents_test']['total_count'] ?? 0) && (int)($cfg['last_all_agents_test']['total_count'] ?? 0) > 0) ? 'good' : 'warn'; ?>">
                    <?php echo (int)($cfg['last_all_agents_test']['ok_count'] ?? 0); ?> / <?php echo (int)($cfg['last_all_agents_test']['total_count'] ?? 0); ?> OK
                </span>
            </div>

            <div class="ai307-agent-results">
                <?php foreach ((array)($cfg['last_all_agents_test']['results'] ?? []) as $agentResult): ?>
                    <?php
                        $agentOk = !empty($agentResult['ok']);
                        $agentLabel = (string)($agentResult['provider_label'] ?? $agentResult['provider'] ?? 'Unknown');
                        $agentMsg = mspro_ai307_sanitize_provider_message((string)($agentResult['message'] ?? ''));
                    ?>
                    <article class="ai307-agent-card <?php echo $agentOk ? 'ok' : 'fail'; ?>">
                        <b><?php echo mspro_ai304_e($agentLabel); ?></b>
                        <span><?php echo $agentOk ? 'OK' : 'FAILED'; ?> · HTTP <?php echo (int)($agentResult['http_code'] ?? 0); ?> · Model: <?php echo mspro_ai304_e((string)($agentResult['model'] ?? '-')); ?></span>
                        <small><?php echo mspro_ai304_e($agentMsg); ?></small>
                    </article>
                <?php endforeach; ?>
            </div>
        </section>
    <?php endif; ?>



    <?php
        $ai308Readiness = is_array($cfg['last_agent_readiness'] ?? null)
            ? $cfg['last_agent_readiness']
            : mspro_ai308_build_readiness($cfg);
    ?>
    <section class="panel ai308-readiness-panel">
        <div class="panel-head">
            <div>
                <h3>AI Agents Readiness Gate</h3>
                <p class="muted">Checks API key, base URL, selected models, and last live ping. No mail data is sent.</p>
            </div>
            <span class="pill <?php echo !empty($ai308Readiness['all_ready']) ? 'good' : 'warn'; ?>">
                <?php echo (int)($ai308Readiness['ready_count'] ?? 0); ?> / <?php echo (int)($ai308Readiness['total_count'] ?? 0); ?> Ready
            </span>
        </div>

        <div class="ai308-agent-grid">
            <?php foreach ((array)($ai308Readiness['items'] ?? []) as $agent): ?>
                <?php
                    $agentReady = !empty($agent['ready']);
                    $issues = is_array($agent['issues'] ?? null) ? $agent['issues'] : [];
                ?>
                <article class="ai308-agent-card <?php echo $agentReady ? 'ready' : 'not-ready'; ?>">
                    <div class="ai308-agent-title">
                        <b><?php echo mspro_ai304_e((string)($agent['provider_label'] ?? $agent['provider'] ?? 'Unknown')); ?></b>
                        <span><?php echo $agentReady ? 'READY' : 'NOT READY'; ?></span>
                    </div>
                    <small>Key: <?php echo !empty($agent['has_key']) ? 'Saved' : 'Missing'; ?></small>
                    <small>Models: <?php echo (int)($agent['selected_model_count'] ?? 0); ?></small>
                    <small>Ping: <?php echo !empty($agent['last_ping_ok']) ? 'OK' : 'Not OK'; ?> · HTTP <?php echo (int)($agent['last_ping_http_code'] ?? 0); ?></small>
                    <?php if ($issues): ?>
                        <details>
                            <summary>Issues</summary>
                            <ul>
                                <?php foreach ($issues as $issue): ?>
                                    <li><?php echo mspro_ai304_e(mspro_ai308_sanitize_message((string)$issue)); ?></li>
                                <?php endforeach; ?>
                            </ul>
                        </details>
                    <?php endif; ?>
                </article>
            <?php endforeach; ?>
        </div>
    </section>


    <?php if ($msg !== ''): ?>
        <div class="alert action-alert"><?php echo mspro_ai304_e((string)$msg); ?></div>
    <?php endif; ?>

    <section class="cards-grid">
        <article class="stat-card">
            <div class="stat-label">Selected Provider</div>
            <div class="stat-value ai304-text"><?php echo mspro_ai304_e($labels[$provider]); ?></div>
            <div class="stat-hint">Only this provider editor is open</div>
        </article>
        <article class="stat-card">
            <div class="stat-label">Provider Key</div>
            <div class="stat-value ai304-text"><?php echo $providerKey ? 'Saved' : 'None'; ?></div>
            <div class="stat-hint">Encrypted vault</div>
        </article>
        <article class="stat-card">
            <div class="stat-label">Loaded Models</div>
            <div class="stat-value ai304-text"><?php echo count((array)(mspro_ai304_model_catalog_for_provider($provider, $catalog)['models'] ?? [])); ?></div>
            <div class="stat-hint">Current provider only</div>
        </article>
        <article class="stat-card">
            <div class="stat-label">Selected Models</div>
            <div class="stat-value ai304-text"><?php echo count($currentModels); ?></div>
            <div class="stat-hint">Current provider only</div>
        </article>
    </section>

    <form method="post" class="panel ai304-form">
        <input type="hidden" name="mspro_ai304_token" value="<?php echo mspro_ai304_e(mspro_ai304_token()); ?>">
        <input type="hidden" name="mspro_ai304_action" id="ai304_action" value="save_settings">

        <div class="panel-head">
            <div>
                <h3>Provider Editor</h3>
                <p class="muted">Changing the dropdown only switches the editor; it does not save settings or change Active Agent.</p>
            </div>
            <button class="ops-btn primary" type="submit" name="mspro_ai304_action" value="save_settings">Save Provider Settings</button>
        </div>

        <div class="ai304-grid">
            <label>
                <span>AI Provider</span>
                <select name="provider" id="ai304_provider">
                    <?php foreach ($labels as $key => $label): ?>
                        <option value="<?php echo mspro_ai304_e((string)$key); ?>" <?php echo mspro_ai304_selected($provider, (string)$key); ?>>
                            <?php echo mspro_ai304_e((string)$label); ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </label>

            <label>
                <span>Active Agent</span>
                <div class="ai304-check">
                    <input type="checkbox" name="active_agent" value="1" <?php echo mspro_ai304_checked(in_array($provider, $activeProviders, true)); ?>>
                    <em>Enable this provider as an active AI agent. Multiple providers can be active, but only one is edited at a time.</em>
                </div>
            </label>

            <label>
                <span>Data Mode</span>
                <select name="data_mode">
                    <option value="masked_headers_only" <?php echo mspro_ai304_selected((string)($cfg['data_mode'] ?? ''), 'masked_headers_only'); ?>>Masked Headers Only</option>
                    <option value="full_headers_allowed" <?php echo mspro_ai304_selected((string)($cfg['data_mode'] ?? ''), 'full_headers_allowed'); ?>>Full Headers Allowed Later</option>
                </select>
            </label>

            <label>
                <span>Decision Mode</span>
                <select name="decision_mode">
                    <option value="recommend_only" <?php echo mspro_ai304_selected((string)($cfg['decision_mode'] ?? ''), 'recommend_only'); ?>>Recommend Only</option>
                    <option value="tag_preview" <?php echo mspro_ai304_selected((string)($cfg['decision_mode'] ?? ''), 'tag_preview'); ?>>Tag Preview Only</option>
                    <option value="quarantine_preview" <?php echo mspro_ai304_selected((string)($cfg['decision_mode'] ?? ''), 'quarantine_preview'); ?>>Quarantine Preview Only</option>
                </select>
            </label>
        </div>

        <?php mspro_ai304_render_provider_fields($provider, $cfg); ?>

        <div class="ai304-actions">
            <button class="ops-btn primary" type="submit" name="mspro_ai304_action" value="save_settings">Save Provider Settings</button>
            <button class="ops-btn neutral" type="submit" name="mspro_ai304_action" value="test_provider">Test Connection / Fetch Models</button>
            <button class="ops-btn neutral ai304-live-btn" type="submit" name="mspro_ai304_action" value="live_ping">Test Live API Ping</button>
            <button class="ops-btn neutral ai308-refresh-btn" type="submit" name="mspro_ai304_action" value="refresh_agent_readiness">Refresh Readiness</button>
            <button class="ops-btn neutral ai307-test-all-btn" type="submit" name="mspro_ai304_action" value="test_all_agents">Test All 3 AI Agents</button>
            <span>No mail data is sent. Live ping sends only: Return OK only.</span>
        </div>
    </form>

    <?php mspro_ai304_render_model_picker($provider, $catalog, $cfg); ?>

    <script>
    (function(){
        var provider = document.getElementById('ai304_provider');
        var action = document.getElementById('ai304_action');

        if (provider) {
            provider.addEventListener('change', function(){
                if (action) action.value = 'switch_provider';
                provider.form.submit();
            });
        }

        var region = document.getElementById('qwen_region');
        var workspace = document.getElementById('qwen_workspace_id');
        var output = document.getElementById('qwen_base_url_display');

        function updateQwenBase(){
            if(!region || !workspace || !output) return;
            var opt = region.options[region.selectedIndex];
            var tpl = opt ? opt.getAttribute('data-template') : '';
            var ws = (workspace.value || '').trim();
            output.value = tpl.indexOf('{WorkspaceId}') >= 0 ? tpl.replace('{WorkspaceId}', ws || '{WorkspaceId}') : tpl;
        }

        if(region) region.addEventListener('change', updateQwenBase);
        if(workspace) workspace.addEventListener('input', updateQwenBase);
        updateQwenBase();
    })();
    </script>
    <?php
}

function mspro_ai304_render_full_page(): void
{
    if (!headers_sent()) header('Content-Type: text/html; charset=UTF-8');
    $GLOBALS['mspro_ai304_message'] = mspro_ai304_handle_post();
    ?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Safety Monitor Pro - AI Providers</title>
<link rel="stylesheet" href="assets/app.css?v=3081877622">
</head>
<body>
<main style="padding:18px">
<?php mspro_ai304_render_page(); ?>
</main>
</body>
</html><?php
}

/* Compatibility aliases */
function mspro_ai29_handle_post(): string { return mspro_ai304_handle_post(); }
function mspro_ai29_render_page(): void { mspro_ai304_render_page(); }
function mspro_ai29_render_full_page(): void { mspro_ai304_render_full_page(); }

function mspro_ai28_handle_post(): string { return mspro_ai304_handle_post(); }
function mspro_ai28_render_page(): void { mspro_ai304_render_page(); }
function mspro_ai28_render_full_page(): void { mspro_ai304_render_full_page(); }

function mspro_ai26_handle_post(): string { return mspro_ai304_handle_post(); }
function mspro_ai26_render_page(): void { mspro_ai304_render_page(); }
function mspro_ai26_render_full_page(): void { mspro_ai304_render_full_page(); }

function mspro_ai25_handle_post(): string { return mspro_ai304_handle_post(); }
function mspro_ai25_render_page(): void { mspro_ai304_render_page(); }

function mspro_ai_handle_post(): string { return mspro_ai304_handle_post(); }
function mspro_ai_render_page(): void { mspro_ai304_render_page(); }
