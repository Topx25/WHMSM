<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
if (!defined('SMPRO_VARLIB')) define('SMPRO_VARLIB', sys_get_temp_dir() . '/t139_varlib_' . getmypid());
require_once SMPRO_BASE . '/includes/botguard.php';
require_once SMPRO_BASE . '/includes/netkind.php';
require_once SMPRO_BASE . '/includes/siteshield.php';
/** t139 - Site Shield: a per-vhost include that refuses hosting / VPN networks, scanner tools and secret-file probes,
 *  lets the operator's own addresses through, is rendered from the plugin's lists (never from names in code), is
 *  installed only when it can be tested, and is put back on any refusal. */
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/siteshield.php'));
hasnt($src, '/home/', 'N1: no path from any server in the code');
hasnt($src, 'efadh', 'N1: no customer name');
has($src, "if (!\$ok) { foreach (\$paths as \$p) @unlink(\$p); smpro_ss_reload(true); return [false, 'Not installed, everything put back: ' . \$msg]; }", 'N2: a refused configtest removes the files and rebuilds again');
has($src, "if (function_exists('smpro_ctl_dry_run') && smpro_ctl_dry_run()) return [false, 'Dry-Run is on:", 'N3: Dry-Run installs nothing and says what it would have refused');
has($src, "if (!function_exists('smpro_nk_ready') || !smpro_nk_ready()) return [false,", 'N4: without the lists nothing is installed (a shield that refuses nothing is not a shield)');
has($src, "return (bool)preg_match('#^\\s*Include\\s+\"?' . preg_quote(\$std, '#') . '\"?#m', \$conf) && is_file(", 'N5: "live" is read from the generated httpd.conf, not from memory');

// the two patterns are one source for Bot Guard and the shield
ok(smpro_bg_scanner_ua('Mozilla/5.0 sqlmap/1.7'), 'P1: Bot Guard still recognises a scanner tool');
ok(!smpro_bg_scanner_ua('Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)'), 'P1: and not a phone');
is_eq(smpro_bg_classify_req('GET', '/shop/.env', 'Mozilla/5.0'), 'probe', 'P2: a secret-file probe is still a probe');
is_eq(smpro_bg_classify_req('GET', '/shop/index.php?route=product/category', 'Mozilla/5.0'), '', 'P2: a store page is not');
ok(strpos(smpro_bg_probe_re(), '"') === false && strpos(smpro_bg_scanner_ua_re(), '"') === false, 'P3: the patterns carry no double quote (they are quoted Apache arguments)');

// rendering
$prefixes = ['203.0.113.0/24', '198.51.100.0/25'];
$r = smpro_ss_render('shop.example', $prefixes, ['192.0.2.10']);
has($r, 'Require not ip 203.0.113.0/24', 'R1: every list prefix is refused');
has($r, 'Require not ip 198.51.100.0/25', 'R1: all of them');
has($r, "        Require ip 192.0.2.10\n", 'R2: the operator address passes before the refusals');
has($r, 'Require all granted', 'R3: everybody else is allowed');
has($r, 'Require not env smpro_ss_tool', 'R4: a scanner tool is refused by its User-Agent');
has($r, 'RewriteRule .* - [F,L]', 'R5: a secret-file probe is refused at once');
ok(preg_match('/^\s*<RequireAny>\s*$/m', $r) === 1 && preg_match('/<RequireAll>/', $r) === 1, 'R6: the allow of the operator wraps the refusals (RequireAny of ip / RequireAll)');
hasnt($r, 'Require not ip not-an-address', 'R7: nothing but prefixes is written as a prefix');
// the prefix reader accepts valid CIDR only
@mkdir(smpro_nk_dir(), 0700, true);
file_put_contents(smpro_nk_file('vpn'), "203.0.113.0/24\n<html>\n300.1.1.1/8\n198.51.100.0/33\n198.51.100.0/25\n");
file_put_contents(smpro_nk_file('hosting'), "192.0.2.0/24\n");
is_eq(smpro_ss_prefixes(), ['203.0.113.0/24', '198.51.100.0/25', '192.0.2.0/24'], 'L1: only valid IPv4 CIDR lines reach Apache');
// domain validation and the vhost record
ok(!smpro_ss_domain_ok('../../etc'), 'D1: a path is not a domain');
ok(!smpro_ss_domain_ok('shop'), 'D1: nor a bare word');
ok(smpro_ss_domain_ok('shop.example'), 'D1: a domain is');
$tmp = sys_get_temp_dir() . '/t139_ud_' . getmypid(); file_put_contents($tmp, "shop.example: acct==root==main==shop.example==/home/acct/public_html==10.0.0.1:81==10.0.0.1:444====0==ea-php82\nalias.example: acct==root==parked==shop.example==/home/acct/public_html==10.0.0.1:81==10.0.0.1:444====0==ea-php82\nsub.shop.example: acct==root==sub==shop.example==/home/acct/public_html/sub==10.0.0.1:81==10.0.0.1:444====0==ea-php82\n");
$lines = @file($tmp, FILE_IGNORE_NEW_LINES); $parsed = [];
foreach ($lines as $l) if (preg_match('/^([a-z0-9.-]+):\s*([a-z0-9_.-]+)==[^=]*==(main|addon|sub)==[^=]*==(\/[^=]*)==/i', $l, $m)) $parsed[$m[1]] = $m[3];
is_eq($parsed, ['shop.example' => 'main', 'sub.shop.example' => 'sub'], 'D2: main, addon and sub domains have a vhost; a parked name does not');
$p = smpro_ss_paths('shop.example', 'acct');
is_eq($p, ['/etc/apache2/conf.d/userdata/std/2_4/acct/shop.example/smpro-siteshield.conf', '/etc/apache2/conf.d/userdata/ssl/2_4/acct/shop.example/smpro-siteshield.conf'], 'D3: the include goes to both the plain and the TLS vhost');
// the worker
$tick = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/bin/geologin_tick.php'));
has($tick, "if (function_exists('smpro_ss_refresh')) { try { smpro_ss_refresh(); }", 'W1: the shields follow the lists from the worker');
has($tick, "smpro_nk_update(); smpro_nk_ensure_sets();", 'W2: right after the lists refresh');
@unlink($tmp); @exec('rm -rf ' . escapeshellarg(SMPRO_VARLIB));
// the page cache in front of Apache
$src2 = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/siteshield.php'));
has($src2, "[\$cok, \$cmsg] = smpro_ss_nginx_cache(\$user, true);", 'C1: shielding turns the account\'s nginx page cache off (a cached page would bypass the shield)');
has($src2, "if (\$cacheOff && !in_array(\$user, array_column(\$c['domains'], 'user'), true)) smpro_ss_nginx_cache(\$user, false);", 'C2: and resets it only when the account has no shielded domain left');
is_eq(smpro_ss_nginx_cache('../x', true), [true, 'no ea-nginx'], 'C3: an account name is a name, never a path');
