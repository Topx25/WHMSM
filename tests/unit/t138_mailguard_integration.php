<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
require_once SMPRO_BASE . '/includes/mailguard.php';
/** t138 - living beside MailGuard: one shared sender-block list, said truthfully on both screens; MailGuard's files are
 *  never findings; its Exim lock is honoured; its database is read only, and "could not read" is never "none". */
$mg = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/mailguard.php'));
$mb = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/mailblock.php'));
$lr = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/learn.php'));
$sh = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/shharden.php'));
$sp = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/spam-phishing.php'));

// read-only by construction
hasnt($mg, 'file_put_contents(SMPRO_MG', 'R1: nothing of MailGuard\'s is written');
hasnt($mg, 'unlink(', 'R1: nothing of MailGuard\'s is removed');
has($mg, "' -readonly -cmd '", 'R2: its database is opened read-only with a busy timeout');
hasnt($mg, '/home/', 'R3: no path from any server is written in the code');
hasnt($mg, '@efadh', 'R3: nor an address');

// the shared list, said truthfully
has($mb, "'detail' => 'Shares THIS list (' . SMPRO_MB_LIST . ')", 'L1: the layers table says MailGuard shares the very same list');
has($mb, "\$acl = \$mgRule ? smpro_mb_unsplice(", 'L2: with MailGuard\'s rule in place this plugin does not add a second deny for the same list');
has($mb, "MailGuard\\'s own Exim rule still consults the same list, so every address on it is still refused", 'L3: disabling here says that MailGuard still blocks');
has($mb, "\$lk = function_exists('smpro_mg_exim_lock') ? smpro_mg_exim_lock(90) : true;", 'L4: the Exim rebuild takes MailGuard\'s lock');
is_eq(substr_count($mb, 'smpro_mg_exim_unlock($lk)'), 2, 'L4: and releases it after install and after uninstall');
has($sp, 'MailGuard on this server', 'L5: the Spam & phishing page shows MailGuard\'s holds, throttles and verdicts');
has($sp, 'this is "unknown", not "none"', 'L6: an unreadable database is said as unknown');
has($sh, "smpro_sh_mk('MailGuard - outgoing-mail protection'", 'L7: Security Health has a MailGuard card');

// Learned Defense
has($lr, "if (function_exists('smpro_mg_trusted') && smpro_mg_trusted(\$p)) return;", 'D1: MailGuard\'s files are never findings');
has($lr, "Refused: this is MailGuard\\'s own file.", 'D2: nor quarantined');
has($lr, "Refused: a folder is reported, not quarantined", 'D3: a folder finding (MailGuard attributes mail to a folder) cannot be quarantined');
has($lr, "\$add(\$o['path'], \$ou, 'mailguard', 'MailGuard attributed outgoing mail to '", 'D4: what MailGuard attributed mail to becomes a finding');

// the trust test and the lists on a fixture
ok(smpro_mg_trusted('/opt/mailguard/whm/src/Enforcement/EximConfig.php'), 'T1: its code is trusted');
ok(smpro_mg_trusted('/var/lib/mailguard/mailguard.sqlite3'), 'T1: its state is trusted');
ok(smpro_mg_trusted(SMPRO_MG_HOOK), 'T1: its Exim rule is trusted');
ok(!smpro_mg_trusted('/opt/mailguardx/evil.php'), 'T2: a look-alike folder is not');
ok(!smpro_mg_trusted('/home/u/public_html/mailguard.php'), 'T2: nor a file merely named after it');
ok(!smpro_mg_trusted(''), 'T2: nor nothing');
is_eq(smpro_mg_list('../../etc/passwd.list'), [], 'T3: a list name is a name, never a path');
is_eq(smpro_mg_version() === '' || (bool)preg_match('/^[0-9]/', smpro_mg_version()), true, 'T4: a version is a version string or empty');
// the lock: without MailGuard it is a no-op handle, never null
$h = smpro_mg_exim_lock(1);
ok($h !== null, 'K1: without MailGuard the lock is a no-op handle, never a refusal');
smpro_mg_exim_unlock($h);
ok(true, 'K2: unlocking a no-op handle is harmless');
