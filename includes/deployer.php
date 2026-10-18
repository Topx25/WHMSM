<?php
/**
 * deployer.php — is this address a CI / deployment pipeline (GitHub Actions, Bitbucket Pipelines, GitLab CI)?
 *
 * THE FALSE ALARM. A customer deploys from GitHub Actions. Every push runs on a fresh runner in Microsoft's
 * cloud, connects over SSH with the deploy KEY, and the foreign-login alert fired "[HIGH] 10 foreign successful
 * login(s): devuser @ <runner> (US) ×1, @ <runner> (US) ×1 ..." - nine addresses, one each, all of them
 * in GitHub's published runner ranges. Nothing was compromised; the operator was told to rotate keys.
 *
 * A pipeline looks exactly like what it is, when you look: a KEY (never a password), from a range the provider
 * publishes, one login per run, a different runner each time. So the providers' own range lists are fetched
 * (GitHub's api.github.com/meta, Atlassian's ip-ranges) and an address is named by its provider. That name is
 * for CLASSIFICATION only - the ranges are the whole of a public cloud and are never put into the firewall
 * allow-list, which is why this is not a provider in fwallow.php.
 *
 * What the callers do with the name: a key-based login from a named pipeline is a deployment, reported as such
 * (info), not as a compromise. A PASSWORD from one of these ranges is still a compromise - pipelines do not type
 * passwords. A key from an unknown foreign address is still reported, labelled as a key, because the question
 * then is "whose key is in authorized_keys".
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

if (!defined('SMPRO_DEPLOY_DIR'))  define('SMPRO_DEPLOY_DIR', SMPRO_VARLIB . '/deployers');
if (!defined('SMPRO_DEPLOY_TTL'))  define('SMPRO_DEPLOY_TTL', 7 * 86400);     // providers change ranges rarely; a week is plenty

/** The providers, with where their ranges are published. Static fallbacks are the documented core ranges only. */
function smpro_deploy_providers(): array {
    return [
        'github' => [
            'name'  => 'GitHub Actions',
            'fetch' => 'https://api.github.com/meta',
            'keys'  => ['actions', 'git', 'hooks'],                 // JSON members that hold CIDR lists
            'static'=> ['140.82.112.0/20', '143.55.64.0/20', '192.30.252.0/22', '185.199.108.0/22'],   // GitHub-owned git/hook ranges (runners are fetched)
        ],
        'bitbucket' => [
            'name'  => 'Bitbucket Pipelines',
            'fetch' => 'https://ip-ranges.atlassian.com/',
            'items' => 'items', 'cidr' => 'cidr', 'product' => 'product', 'product_match' => 'bitbucket',
            'static'=> ['34.199.54.113/32', '34.232.25.90/32', '34.232.119.183/32', '34.236.25.177/32', '35.171.175.212/32',
                        '52.54.90.98/32', '52.202.195.162/32', '52.203.14.55/32', '52.204.96.37/32', '34.218.156.209/32',
                        '34.218.168.212/32', '52.41.219.63/32', '35.155.178.254/32', '35.160.177.10/32', '34.216.18.129/32'],
        ],
        'gitlab' => [
            'name'  => 'GitLab CI (shared runners)',
            'fetch' => '',
            'static'=> ['34.74.90.64/28', '34.74.226.0/24'],         // documented gitlab.com shared-runner egress
        ],
    ];
}

function smpro_deploy_cache_file(string $key): string { return SMPRO_DEPLOY_DIR . '/' . $key . '.json'; }

/** Fetch one provider's published ranges. Returns the CIDR list, or [] when nothing could be fetched. */
function smpro_deploy_fetch(string $key): array {
    $p = smpro_deploy_providers()[$key] ?? null;
    if (!$p || $p['fetch'] === '') return [];
    $raw = function_exists('smpro_run') ? smpro_run('curl -fsS --max-time 12 -H ' . escapeshellarg('User-Agent: SafetyMonitorPro') . ' ' . escapeshellarg($p['fetch']), 15, ['stderr' => 'discard'])
                                        : (string)@shell_exec('timeout 15 curl -fsS --max-time 12 ' . escapeshellarg($p['fetch']) . ' 2>/dev/null');
    $j = json_decode((string)$raw, true);
    if (!is_array($j)) return [];
    $out = [];
    if (!empty($p['keys'])) {
        foreach ($p['keys'] as $k) foreach ((array)($j[$k] ?? []) as $c) if (is_string($c)) $out[] = $c;
    } elseif (!empty($p['items'])) {
        foreach ((array)($j[$p['items']] ?? []) as $it) {
            if (!is_array($it)) continue;
            $prods = array_map('strtolower', (array)($it[$p['product']] ?? []));
            if (!in_array(strtolower($p['product_match']), $prods, true)) continue;
            $c = (string)($it[$p['cidr']] ?? ''); if ($c !== '') $out[] = $c;
        }
    }
    return array_values(array_unique(array_filter($out, 'smpro_deploy_cidr_ok')));
}

function smpro_deploy_cidr_ok($c): bool {
    if (!is_string($c) || $c === '') return false;
    [$ip, $bits] = array_pad(explode('/', $c, 2), 2, '');
    if (filter_var($ip, FILTER_VALIDATE_IP) === false) return false;
    if ($bits === '') return true;
    return ctype_digit($bits) && (int)$bits <= (strpos($ip, ':') !== false ? 128 : 32);
}

/** Refresh every provider whose cache is older than the TTL. Cheap when fresh; called from the allow-list sync. */
function smpro_deploy_refresh(bool $force = false): array {
    @is_dir(SMPRO_DEPLOY_DIR) || @mkdir(SMPRO_DEPLOY_DIR, 0700, true);
    $did = [];
    foreach (smpro_deploy_providers() as $key => $p) {
        $f = smpro_deploy_cache_file($key);
        if (!$force && @is_file($f) && time() - (int)@filemtime($f) < SMPRO_DEPLOY_TTL) continue;
        $ranges = $p['fetch'] !== '' ? smpro_deploy_fetch($key) : [];
        if (!$ranges) { if (!@is_file($f)) { @file_put_contents($f, json_encode(['ranges' => $p['static'], 'source' => 'static', 'fetched_at' => 0])); $did[$key] = 'static'; } else { @touch($f); $did[$key] = 'fetch failed, kept previous'; } continue; }
        @file_put_contents($f . '.tmp', json_encode(['ranges' => array_values(array_unique(array_merge($ranges, $p['static']))), 'source' => 'fetched', 'fetched_at' => time()]));
        @rename($f . '.tmp', $f);
        $did[$key] = count($ranges) . ' ranges';
    }
    return $did;
}

/** The ranges we have for a provider: cache, else the static core. */
function smpro_deploy_ranges(string $key): array {
    // Memoised per cache-file version, not per process: a refresh that lands mid-process (or a test that writes
    // the cache after a first lookup) must be seen, or the old static core answers for a week.
    static $mem = [];
    $p = smpro_deploy_providers()[$key] ?? null;
    if (!$p) return [];
    $f = smpro_deploy_cache_file($key);
    $ver = @is_file($f) ? ((int)@filemtime($f) . ':' . (int)@filesize($f)) : 'static';
    if (isset($mem[$key]) && $mem[$key]['ver'] === $ver) return $mem[$key];
    $j = @is_file($f) ? json_decode((string)@file_get_contents($f), true) : null;
    $ranges = is_array($j) && !empty($j['ranges']) ? (array)$j['ranges'] : $p['static'];
    // Pre-split into [start, end] integers (IPv4) and a list of IPv6 CIDRs, so 7,000 ranges cost one binary search.
    $v4 = []; $v6 = [];
    foreach ($ranges as $c) {
        [$ip, $bits] = array_pad(explode('/', (string)$c, 2), 2, '');
        if (strpos($ip, ':') !== false) { $v6[] = (string)$c; continue; }
        $n = ip2long($ip); if ($n === false) continue;
        $b = $bits === '' ? 32 : (int)$bits;
        $mask = $b === 0 ? 0 : ((0xFFFFFFFF << (32 - $b)) & 0xFFFFFFFF);
        $start = $n & $mask; $v4[] = [$start, $start | (~$mask & 0xFFFFFFFF)];
    }
    usort($v4, fn($a, $b) => $a[0] <=> $b[0]);
    return $mem[$key] = ['v4' => $v4, 'v6' => $v6, 'n' => count($ranges), 'ver' => $ver];
}

/** Which deployment provider publishes this address. '' when none does. */
function smpro_deploy_provider(string $ip): string {
    if ($ip === '' || filter_var($ip, FILTER_VALIDATE_IP) === false) return '';
    $is6 = strpos($ip, ':') !== false;
    $n = $is6 ? 0 : ip2long($ip);
    foreach (smpro_deploy_providers() as $key => $p) {
        $r = smpro_deploy_ranges($key);
        if (!$is6) {
            $lo = 0; $hi = count($r['v4']) - 1; $hit = false;
            while ($lo <= $hi) {                                   // ranges may nest/overlap; find any containing one
                $mid = intdiv($lo + $hi, 2);
                if ($r['v4'][$mid][0] <= $n) { if ($r['v4'][$mid][1] >= $n) { $hit = true; break; } $lo = $mid + 1; } else $hi = $mid - 1;
            }
            if (!$hit) { for ($i = max(0, $hi - 64); $i <= min(count($r['v4']) - 1, $hi + 1); $i++) if ($r['v4'][$i][0] <= $n && $r['v4'][$i][1] >= $n) { $hit = true; break; } }
            if ($hit) return $p['name'];
        } else {
            foreach ($r['v6'] as $c) if (function_exists('smpro_ip_in_cidr') ? smpro_ip_in_cidr($ip, $c) : smpro_deploy_in6($ip, $c)) return $p['name'];
        }
    }
    return '';
}

function smpro_deploy_in6(string $ip, string $cidr): bool {
    [$net, $bits] = array_pad(explode('/', $cidr, 2), 2, '128');
    $a = @inet_pton($ip); $b = @inet_pton($net);
    if ($a === false || $b === false || strlen($a) !== 16 || strlen($b) !== 16) return false;
    $bits = (int)$bits; $bytes = intdiv($bits, 8); $rem = $bits % 8;
    if ($bytes && substr($a, 0, $bytes) !== substr($b, 0, $bytes)) return false;
    if ($rem === 0) return true;
    $m = (0xFF << (8 - $rem)) & 0xFF;
    return (ord($a[$bytes]) & $m) === (ord($b[$bytes]) & $m);
}

/**
 * Classify one accepted SSH login.
 *   method  'publickey' | 'password' | 'keyboard-interactive' | ''
 * Returns ['class' => 'deploy'|'key'|'password', 'provider' => name|'' ]
 *   deploy    a key from a named pipeline provider - a deployment, not a person
 *   key       a key from anywhere else - whose key is in authorized_keys?
 *   password  a typed password (or keyboard-interactive) - a person, or a compromise
 */
function smpro_deploy_classify(string $ip, string $method): array {
    $method = strtolower($method);
    if ($method !== 'publickey') return ['class' => 'password', 'provider' => ''];
    $pv = smpro_deploy_provider($ip);
    return ['class' => $pv !== '' ? 'deploy' : 'key', 'provider' => $pv];
}
