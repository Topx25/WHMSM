<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/compcheck.php';
/**
 * t90_compcheck.php — Compromise Check: the version gate is exact, the doors are read from the right files, and
 * the page exists and is registered.
 */
/* ---------- U1: the version gate ---------- */
is_eq(smpro_cc_version_state('11.136.0.4')['ok'], false, 'U1: one build below the fix on its track is unpatched');
is_eq(smpro_cc_version_state('11.136.0.5')['ok'], true,  'U1: the fixed build is patched');
is_eq(smpro_cc_version_state('11.110.0.96')['ok'], false, 'U1: an older track below its own fix is unpatched');
is_eq(smpro_cc_version_state('11.110.0.97')['ok'], true,  'U1: and at its fix it is patched');
is_eq(smpro_cc_version_state('11.138.0.8')['ok'], true,  'U1: a track newer than every fixed track is patched (the production servers)');
is_eq(smpro_cc_version_state('11.84.0.10')['ok'], false, 'U1: a track older than the oldest fixed track is unpatched');
is_eq(smpro_cc_version_state('garbage')['ok'], null,     'U1: an unreadable version is unknown, not "ok"');
has(smpro_cc_version_state('11.136.0.4')['why'], 'update cPanel now', 'U1: the unpatched verdict says what to do');
/* ---------- U2: the doors are read from cPanel's own files ---------- */
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/compcheck.php'));
has($src, "'/etc/proftpd/' . \$u", 'U2: FTP sub-accounts from the account\'s proftpd file');
has($src, "preg_match('/^(root|admin|administrator|test|backup|support|cpanel|ftp|www|webmaster)@/i', \$login)", 'U2: a sub-account named like an administrator is flagged whatever its age (the "root@domain" case)');
has($src, "'/etc/valiases/' . \$dom", 'U2: forwarders from valiases');
has($src, "if (in_array(\$td, smpro_cc_domains_of(\$u), true)) continue;", 'U2: a forwarder inside the account\'s own domains is not a door');
has($src, "'/var/spool/cron/' . \$u", 'U2: cron from the spool');
has($src, "\$home . '/.ssh/authorized_keys'", 'U2: SSH keys from the account\'s home');
has($src, "\$home . '/.cpanel/contactinfo'", 'U2: the contact e-mail');
has($src, "'/var/cpanel/authn/api_tokens_v2/cpanel/' . \$u . '.json'", 'U2: API tokens from the file, not the API');
hasnt($src, 'uapi --user', 'U2: no per-account API call - a 1,300-account server must answer in seconds');
has($src, "if (microtime(true) - \$t0 > \$budgetSec) { \$partial = true; break; }", 'U2: and the scan is time-bounded and says when it is partial');
/* ---------- U3: server checks ---------- */
has($src, "whmapi1 cphulk_status", 'U3: cPHulk state');
has($src, "compromised_user_password_reset", 'U3: Imunify\'s compromised-user handling');
has($src, "/root/.ssh/authorized_keys", 'U3: root\'s keys');
has($src, "whmapi1 api_token_list", 'U3: root\'s API tokens');
has($src, "/var/cpanel/resellers", 'U3: resellers with everything');
/* ---------- U4: the page is registered and read-only ---------- */
$menu = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/menu.php'));
has($menu, "'id' => 'compromise-check'", 'U4: in the menu');
$mod = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/compromise-check.php'));
has($mod, 'smpro_require_root();', 'U4: root only');
has($mod, "smpro_require_valid_csrf('cc_fix')", 'U4: the page changes nothing without a CSRF token');
has($mod, 'CVE-2026-41940', 'U4: it says why the version matters');
/* ---------- U5: when a door was created comes from cPanel's access log, not from a file date ---------- */
// 65 of 90 FTP files on a real server shared one mtime (a server-wide rewrite) and every account looked as if it had
// just gained a sub-account. The creation is the API call cPanel logged, with the address that made it.
has($src, "execute/Ftp/add_ftp|execute/Email/add_pop", 'U5: the creation index reads the calls that create doors');
has($src, "function smpro_cc_mtime_is_rewrite(", 'U5: a file date shared by most accounts is recognised as a rewrite');
has($src, "\$sus || \$cr !== null || (!\$rewrite && \$mt >= \$since)", 'U5: an FTP sub-account is flagged by name, by a creation event, or by a file date that is NOT a rewrite');
has($src, "(routine unless nobody did it)", 'U5: a mailbox password change is not a door by itself');
has($src, "'Mailbox created'", 'U5: a mailbox created in the window is');
has($src, "(array)(\$j['tokens'] ?? [])", 'U5: the token file\'s real shape is read');
has($src, "reverse_trust_", 'U5: cPanel\'s own transfer tokens are told apart from the operator\'s');
/* ---------- U6: the second 2026 critical (account holder -> root) is gated too, with minor-version-aware compare ---------- */
is_eq(smpro_cc_version_state('11.138.0.1', 1)['ok'], false, 'U6: 11.138.0.1 is below the CVE-2026-65643 fix 11.138.0.2');
is_eq(smpro_cc_version_state('11.138.0.2', 1)['ok'], true,  'U6: 11.138.0.2 is the fix');
is_eq(smpro_cc_version_state('11.138.0.8', 1)['ok'], true,  'U6: 11.138.0.8 (the production servers) is past it');
is_eq(smpro_cc_version_state('11.136.0.36', 1)['ok'], false, 'U6: 11.136.0.36 is below its track fix 11.136.0.37');
is_eq(smpro_cc_version_state('11.138.1.0', 1)['ok'], true,  'U6: a higher minor on the same track counts as past the fix');
is_eq(smpro_cc_version_state('11.138.0.8', 0)['ok'], true,  'U6: and the first gate still reads the same version');
/* ---------- U7: the published post-compromise checklist items are all looked at ---------- */
has($src, "'/etc/ld.so.preload'", 'U7: ld.so.preload (WebPros item 1)');
has($src, "/etc/sudoers.d/*", 'U7: sudoers');
has($src, "getent group wheel sudo", 'U7: wheel/sudo membership');
has($src, "'/var/spool/cron/root', '/etc/crontab', '/etc/anacrontab'", 'U7: root and system cron');
has($src, "/etc/cron.{hourly,daily,weekly,monthly}/*", 'U7: the periodic cron folders');
has($src, "'/root/.bashrc', '/root/.bash_profile', '/root/.profile', '/etc/profile', '/etc/bashrc'", 'U7: shell start-up files');
has($src, "/usr/local/cpanel/base/unprotected/cpanel/main.tmpl", 'U7: the cPanel login template');
has($src, '*.sorry', 'U7: ransomware markers');
has($src, "ioc_checksessions_files.sh", 'U7: points at cPanel\'s own session IOC script instead of re-implementing it');
has($src, "ss -tlnpH", 'U7: public listeners');
has($src, "glob('/proc/[0-9]*')", 'U7: hidden processes (ps vs /proc)');
has($src, "if (strpos(basename(\$f), 'smpro-') === 0) continue;", 'U7: the product\'s own cron workers are not reported as suspicious');
$page2 = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/compromise-check.php'));
has($page2, "past both 2026 critical fixes", 'U7: the build tile speaks for both gates');
/* ---------- U8: every check and every door kind has a "what to do" ---------- */
foreach (['cve','cve2','cphulk','im_comp','rootkeys','roottok','uid0','resellers','sshd','preload','sudoers','syscron','shellrc','tmpl','sorry','ioc','listen','hidden','ftp','forwarder','cron','sshkey','contact','mailbox','token','shellrc_acct'] as $id)
    ok(strlen(smpro_cc_fix($id)) > 40, 'U8: what to do for ' . $id);
is_eq(smpro_cc_fix('nonsense'), '', 'U8: unknown id gives nothing, not a wrong advice');
$page3 = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/compromise-check.php'));
has($page3, "\$fx = \$c['status'] !== 'ok' ? smpro_cc_fix(\$c['id']) : ''", 'U8: shown on every non-OK server row');
has($page3, "\$fx = \$f['flag'] ? smpro_cc_fix(", 'U8: and on every flagged door');
