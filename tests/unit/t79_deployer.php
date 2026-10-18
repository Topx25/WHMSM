<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/deployer.php';
/**
 * t79_deployer.php — a CI pipeline deploying by key is a deployment, not a compromise.
 *
 * THE FALSE ALARM. "[HIGH] 10 foreign successful login(s)" - nine addresses, one login each, all in GitHub's
 * published Actions runner ranges, all by key. A customer pushed to GitHub; the operator was told to rotate keys.
 * Locked here: the provider is named from its published ranges, a key from it is a deployment, a PASSWORD from
 * it is still a compromise, a key from an unknown foreign address is still reported as a key, and the ranges are
 * for classification only - never the firewall allow-list.
 */
@is_dir(SMPRO_DEPLOY_DIR) || @mkdir(SMPRO_DEPLOY_DIR, 0700, true);
foreach (glob(SMPRO_DEPLOY_DIR . '/*.json') ?: [] as $f) @unlink($f);

/* ---------- U1: with no cache, the documented static ranges still classify ---------- */
is_eq(smpro_deploy_provider('34.74.90.70'), 'GitLab CI (shared runners)', 'U1: a GitLab shared-runner address is named from the static core');
is_eq(smpro_deploy_provider('140.82.112.5'), 'GitHub Actions', 'U1: a GitHub-owned address is named from the static core');
is_eq(smpro_deploy_provider('203.0.113.9'), '', 'U1: an address no provider publishes is nobody\'s');
is_eq(smpro_deploy_provider('not-an-ip'), '', 'U1: garbage is nobody\'s');

/* ---------- U2: a cache of fetched ranges (the real shape) is used, with a binary search over thousands ---------- */
$ranges = ['20.46.238.0/24', '48.214.54.0/24', '172.184.220.0/22', '20.57.223.0/24', '52.156.108.0/24', '2603:1030::/28'];
for ($i = 0; $i < 7000; $i++) $ranges[] = '10.' . intdiv($i, 256) . '.' . ($i % 256) . '.0/24';   // bulk, like the 7,306 real ones
file_put_contents(smpro_deploy_cache_file('github'), json_encode(['ranges' => $ranges, 'source' => 'fetched', 'fetched_at' => time()]));
// the in-process cache must be dropped for the new file to be read: call through a fresh classification set
$t0 = microtime(true);
is_eq(smpro_deploy_provider('20.46.238.66'), 'GitHub Actions', 'U2: the alert\'s first address is a GitHub Actions runner');
is_eq(smpro_deploy_provider('172.184.220.151'), 'GitHub Actions', 'U2: and one inside a /22');
is_eq(smpro_deploy_provider('10.3.7.200'), 'GitHub Actions', 'U2: a bulk range in the middle of 7,000 is found');
is_eq(smpro_deploy_provider('10.99.0.1'), '', 'U2: an address just outside every range is not');
is_eq(smpro_deploy_provider('2603:1030:abcd::1'), 'GitHub Actions', 'U2: IPv6 ranges match too');
for ($i = 0; $i < 2000; $i++) smpro_deploy_provider('10.' . ($i % 27) . '.' . ($i % 256) . '.9');
ok(microtime(true) - $t0 < 2.0, 'U2: 2,000 lookups over 7,000 ranges stay under two seconds (' . round(microtime(true) - $t0, 2) . 's)');

/* ---------- U3: the classification the alert acts on ---------- */
is_eq(smpro_deploy_classify('20.46.238.66', 'publickey'), ['class' => 'deploy', 'provider' => 'GitHub Actions'], 'U3: a key from a runner is a deployment');
is_eq(smpro_deploy_classify('20.46.238.66', 'password')['class'], 'password', 'U3: a PASSWORD from a runner range is still a password login - pipelines do not type passwords');
is_eq(smpro_deploy_classify('203.0.113.9', 'publickey')['class'], 'key', 'U3: a key from an unknown address is a key - whose key is in authorized_keys?');
is_eq(smpro_deploy_classify('203.0.113.9', 'keyboard-interactive')['class'], 'password', 'U3: keyboard-interactive is a typed secret');

/* ---------- U4: the alert tells deployments apart, and never allow-lists the ranges ---------- */
$ntf = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/notify.php'));
has($ntf, "if (\$cl['class'] === 'deploy') {", 'U4: a deployment leaves the foreign-login list');
has($ntf, "'deploy:' . md5(", 'U4: and is reported once per account+provider, as info');
has($ntf, "— by KEY", 'U4: a key login from elsewhere is labelled as a key');
has($ntf, "\$anyPassword ? 'high' : 'medium'", 'U4: an alert with no password login is medium, not high');
$fw = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/fwallow.php'));
hasnt($fw, "'github'", 'U4: GitHub is NOT a firewall allow-list provider - its runner ranges are a public cloud');
has($fw, 'smpro_deploy_refresh', 'U4: but its ranges are refreshed with the allow-list sync');

/* ---------- U5: fetch parsing, from the providers\' real shapes ---------- */
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/deployer.php'));
has($src, "'https://api.github.com/meta'", 'U5: GitHub\'s ranges come from its own meta endpoint');
has($src, "'product_match' => 'bitbucket'", 'U5: Atlassian\'s list is filtered to the Bitbucket product');
ok(smpro_deploy_cidr_ok('1.2.3.0/24') && !smpro_deploy_cidr_ok('1.2.3.0/40') && !smpro_deploy_cidr_ok('x/8'), 'U5: a fetched entry that is not a CIDR is dropped');
foreach (glob(SMPRO_DEPLOY_DIR . '/*.json') ?: [] as $f) @unlink($f);
