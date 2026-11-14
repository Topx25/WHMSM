<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
/**
 * t168 - the rest of the review: the last root-by-path writes inside account folders, the lock agreement with
 * the other products, replayed bridge events, the shared cloud-mail file, the deny list rewrite.
 */
$src = fn($p) => str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $p));

$sd = $src('includes/sdbulk.php');
has($sd, "return smpro_acct_put((string)\$pw['name'], \$d . '/' . \$name, \$content, 0644);", 'A1: the safe-write helper writes as the owner of the folder');
ok(strpos($sd, "\$h = @fopen(\$tmp, 'xb'); if (!\$h) return false;") === false, 'A2: ...and no longer creates the file as root');

$iv = $src('includes/investigate.php');
has($iv, "if (\$asAcct) { \$ok = smpro_acct_put(\$user, \$dest, (string)\$content, is_file(\$dest) ? 0 : 0644); }", 'B1: undo puts a file back as the account');
has($iv, "smpro_acct_get(\$user, (string)\$e['backup'], 67108864)", 'B2: a backup kept in the account folder is read as the account');
has($iv, "\$ok = smpro_acct_sh(\$uUser, '[ ! -e \"\$2\" ] && mv -- \"\$1\" \"\$2\"', [(string)\$e['to'], (string)\$e['from']], null, 120)['code'] === 0;", 'B3: an item renamed inside the home is moved back by the account');

$ph = $src('modules/php-harden.php');
has($ph, "if (\$accountRoots) smpro_ph_chattr_many('-i', \$mine(\$accountRoots));", 'C1: applying protection does not open a root another product locked');
has($ph, "smpro_ph_chattr_many('-i', \$mine(\$files));", 'C2: ...nor a file it locked');

$hg = $src('includes/hgbridge.php');
has($hg, "if (\$want === 'block' && \$ets > 0 && \$ets < time() - 3600) { \$want = 'report'; \$decision = 'stale'; }", 'D1: an event older than an hour is noted, not blocked on');

$gh = $src('includes/geohulk.php');
has($gh, 'function smpro_gh_cloudmail_unreadable(): bool {', 'E1: an unreadable shared file is told apart from an absent one');
has($gh, "&& !smpro_gh_cloudmail_unreadable()) {", 'E2: ...and is not overwritten');
has($gh, "if (smpro_gh_cloudmail_unreadable()) foreach (array_keys((array)(\$c['cloud_done'] ?? [])) as \$p) \$on[] = (string)\$p;", 'E3: ...and nothing already whitelisted is withdrawn on a guess');

$hp = $src('includes/helpers.php');
ok(strpos($hp, '$dl = function_exists(\'smpro_csf_deny_lock\') ? smpro_csf_deny_lock() : null;') !== false && strpos($hp, 'smpro_csf_deny_unlock($dl);') !== false, 'F1: unblock rewrites the deny list under the shared lock');
ok(strpos($hp, 'function smpro_fw_unblock_engines(string $ip): array {') !== false && strpos($hp, "smpro_fw_unblock_engines(\$ip) : [];") !== false, 'F2: unblock looks in every engine a block can land in');
is_eq(smpro_fw_unblock_engines('not-an-ip'), [], 'F3: ...and refuses anything that is not an address');
