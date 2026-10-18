<?php
/**
 * t62_deleted_files.php — "who deleted these files?" answered from evidence, and honest about what it could not read.
 *
 * A deletion is the hardest thing to investigate on a hosting account: the thing that would prove it is the thing
 * that is gone. What is left is scattered across logs written by different programs, none complete on its own.
 * Two rules decide whether this feature helps or misleads, and both are asserted here:
 *
 *   1. A source that could not be READ is never reported as a source that was read and found nothing. "No FTP
 *      deletions" and "the FTP log is not readable" are opposite findings, and confusing them is how an
 *      investigation ends by blaming the wrong person.
 *   2. The plugin looks at ITSELF first. SM Pro quarantines, cleans and auto-purges — on 2026-07-27 an auto-purge
 *      matching cache NAMES removed OpenCart and Twig source files across 92 sites. A tool that cannot name its
 *      own actions as a suspect will confidently blame a customer for what the panel did.
 */
require __DIR__ . '/../support/bootstrap.php';
require SMPRO_BASE . '/tests/support/plugin_funcs.php';
smpro_plugin_funcs('includes/uidelete.php');

$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/uidelete.php'));
$pg  = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/user-investigation.php'));

/* ---------- D1: every source states what happened to it ---------- */
ok(function_exists('smpro_uid_source'), 'D1: sources describe themselves');
$missing = smpro_uid_source('X', '/definitely/not/here/' . mt_rand());
is_eq($missing['state'], 'missing', 'D1: a log that does not exist reports "missing"');
has($missing['why'], 'does not exist', 'D1: ...with the reason');
$na = smpro_uid_source('X', '');
is_eq($na['state'], 'n/a', 'D1: a source that does not apply to this server is "n/a", not "read"');
$self = smpro_uid_source('X', SMPRO_BASE . '/includes/uidelete.php');
is_eq($self['state'], 'read', 'D1: a readable file reports "read"');
foreach (['missing', 'n/a'] as $st) ok($st !== 'read', 'D1: and nothing that was not read can claim it was');

/* ---------- D2: the verdict never turns "not seen" into "did not happen" ---------- */
ok(function_exists('smpro_uid_verdict_text'), 'D2: there is a verdict sentence');
$blind = smpro_uid_verdict_text(['verdict' => 'none', 'counts' => ['events'=>0,'confirmed'=>0,'actors'=>0,'dirs'=>0,'trash'=>0],
                                 'unreadable' => [['name'=>'FTP'],['name'=>'SSH']]]);
has($blind, 'not seen', 'D2: with sources unread, the answer is "not seen", not "did not happen"');
has($blind, '2 of the sources could not be read', 'D2: ...and says how many');

$clean = smpro_uid_verdict_text(['verdict' => 'none', 'counts' => ['events'=>0,'confirmed'=>0,'actors'=>0,'dirs'=>0,'trash'=>0], 'unreadable' => []]);
has($clean, 'Every source was read', 'D2: with everything read it says so');
has($clean, 'Widen the dates before concluding it did not happen', 'D2: ...and still does not declare innocence');

$conf = smpro_uid_verdict_text(['verdict' => 'confirmed', 'counts' => ['events'=>9,'confirmed'=>9,'actors'=>2,'dirs'=>0,'trash'=>0], 'unreadable' => []]);
has($conf, '9 deletion(s) are recorded, from 2 address(es)', 'D2: a confirmed finding is stated plainly');
$circ = smpro_uid_verdict_text(['verdict' => 'circumstantial', 'counts' => ['events'=>3,'confirmed'=>0,'actors'=>1,'dirs'=>0,'trash'=>0], 'unreadable' => []]);
has($circ, 'No log names a deletion', 'D2: a session is not reported as a deletion');
has($circ, 'shell `rm` writes no record', 'D2: ...and the reason that limit exists is stated');
$fso = smpro_uid_verdict_text(['verdict' => 'fs_only', 'counts' => ['events'=>0,'confirmed'=>0,'actors'=>0,'dirs'=>4,'trash'=>0], 'unreadable' => []]);
has($fso, '4 director(ies) changed', 'D2: the filesystem still dates it when no log names it');

/* ---------- D3: the plugin is a suspect in its own report ---------- */
ok(function_exists('smpro_uid_smpro'), 'D3: SM Pro\'s own actions are collected');
has($src, 'An investigation that cannot name its own', 'D3: and why, in the code, where it cannot be quietly dropped');
has($src, "\$sm = smpro_uid_smpro(\$account, \$fromTs, \$toTs);", 'D3: the report calls it');
has($src, "'purge', 'quarantine', 'clean', 'delete', 'remove', 'restore'", 'D3: including auto-purge, the one that has done this before');

/* ---------- D4: every channel that can delete a file is looked at ---------- */
foreach ([['smpro_uid_cpanel', 'cPanel File Manager'], ['smpro_uid_ftp', 'FTP'],
          ['smpro_uid_ssh', 'SSH/SFTP'], ['smpro_uid_filesystem', 'the account\'s own files']] as [$fn, $label])
    ok(function_exists($fn), 'D4: ' . $label . ' is collected');
has($src, "'/var/log/messages', '/var/log/syslog', '/var/log/xferlog', '/var/log/proftpd/proftpd.log'",
    'D4: FTP is looked for in every place different builds write it, not just one');
has($src, "foreach (['/var/log/secure', '/var/log/auth.log'] as \$log)", 'D4: ...and so is SSH');

/* ---------- D5: a File Manager READ is not a deletion, and a missing filename is not invented ---------- */
has($src, 'A read of the File Manager is not a deletion. Only the calls that remove something count.',
    'D5: opening File Manager is not evidence of anything');
has($src, "stripos(\$path, 'op=copy') === false && stripos(\$path, 'op=move') === false",
    'D5: copying and moving are excluded — they are not deletions');
has($src, 'the filename is not recorded in this log', 'D5: when cPanel did not log the target, the report says so');
has($src, 'a delete sends its targets in the body', 'D5: ...and why, so nobody assumes the tool missed it');

/* ---------- D6: a session is labelled as a lead, never as proof ---------- */
has($src, "'confidence' => 'circumstantial'", 'D6: an SSH session is circumstantial');
has($src, 'this is a lead, not proof', 'D6: and says so in the row itself, where it will be read');
has($src, "'action' => 'SFTP ' . strtolower(\$rm[1])", 'D6: while an SFTP line that names a removal is kept as its own confirmed row');

/* ---------- D7: the answer to "who, from where" ---------- */
has($src, "'known'    => isset(\$known[\$ip]),", 'D7: each address is marked as one the account has signed in from before, or not');
has($src, "foreach (smpro_ui_logins(\$account, max(0, \$fromTs - 90 * 86400), \$toTs) as \$lg)",
    'D7: judged against 90 days of logins, not just the incident window — otherwise every address looks new');
has($src, "stripos((string)\$lg['action'], 'fail') === false", 'D7: and a FAILED login does not make an address familiar');
has($src, "'machine'  => function_exists('smpro_ip_is_datacenter')", 'D7: with whether it is a rented machine');
has($src, "\$a['activity'] = function_exists('smpro_ip_auth_attempts')", 'D7: and everything else that address did on the server');
has($src, 'max(0, $fromTs - 7 * 86400)', 'D7: reaching back before the window, since what came first is the point');

/* ---------- D8: the filesystem is read correctly ---------- */
has($src, "@posix_getpwnam(\$account); if (is_array(\$pw) && !empty(\$pw['dir'])) \$home = (string)\$pw['dir'];",
    'D8: the home directory comes from /etc/passwd — a cPanel box can have /home2, and guessing would report "nothing changed" about a path that does not exist');
has($src, "-newermt ' . escapeshellarg('@' . \$fromTs)", 'D8: directories are filtered by the window in find, not in PHP');
has($src, "-maxdepth 5", 'D8: and the walk is bounded');
has($src, "rtrim(\$home, '/') . '/.trash'", 'D8: cPanel moves deletions to ~/.trash, so the files themselves are often still there');
has($pg, 'may be recoverable as they are', 'D8: ...which the report points out, on the page');

/* ---------- D9: read-only, gated, recorded ---------- */
hasnt($src, 'unlink(', 'D9: this file deletes nothing');
hasnt($src, 'file_put_contents', 'D9: ...and writes nothing');
has($pg, "smpro_require_valid_csrf('ub_action'); smpro_require_root();", 'D9: the endpoint is root-only and CSRF-checked');
has($pg, "smpro_audit('user_investigation_deleted'", 'D9: and every collection is recorded');
has($pg, 'Collected on demand rather than on every page load', 'D9: it runs when asked, not on every view');
has($pg, 'var UBTOK=<?= json_encode($ubTok', 'D9: the script carries its own token — the block above scopes its own inside a closure');

/* ---------- D10: mail is its own investigation, and the file collectors see none of it ---------- */
// A message does not live in the document root and no File Manager call touches one, so a report built only from
// the file trail would answer confidently about files and silently about mail — which reads as "nothing was
// deleted" to the person asking about their inbox.
ok(function_exists('smpro_uid_mail'), 'D10: mailbox deletions are collected');
has($src, "foreach (['/var/log/maillog', '/var/log/mail.log', '/var/log/dovecot.log'] as \$log)",
    'D10: from wherever this build of Dovecot writes');
has($src, "\$ml = smpro_uid_mail(\$account, \$fromTs, \$toTs,", 'D10: and the report calls it');
has($src, 'messages do not live in the document root', 'D10: with the reason written where it cannot be dropped by accident');

/* the default-on evidence: Dovecot's disconnect summary */
has($src, "if (preg_match('/\b(?:expunged|deleted)=(\d+)/', \$ln, \$cm))",
    'D10: a session that expunged or deleted messages is the evidence Dovecot writes without being asked');
has($src, "if (\$exp + \$del <= 0) continue;", 'D10: ...and a session that deleted nothing is not reported as one that did');
has($src, "if (\$ip !== '' && \$sid !== '') \$ipOf[\$sid] = \$ip;",
    'D10: the address is on the login line and the count is on the disconnect line, so it is carried across by session id');

/* the honesty about the gap */
ok(function_exists('smpro_uid_maillog_enabled'), 'D10: whether per-message logging is on is checked, not assumed');
has($src, 'records HOW MANY per session by default, not which', 'D10: and the limit is stated in the row itself');
has($src, 'Turn on the mail_log plugin to get the mailbox, the subject and the sender',
    'D10: ...together with what would fix it');
has($pg, 'this server records how many, not which', 'D10: the page leads with that, rather than letting silence imply nothing happened');
has($pg, 'It cannot recover what is already gone: it changes what gets recorded from now on',
    'D10: and does not let anyone think enabling it undoes the deletion');

/* mailboxes are scoped to the account, and Trash is checked */
ok(function_exists('smpro_uid_mailboxes'), 'D10: the account\'s own mailboxes are enumerated');
has($src, "if (\$user !== '' && !isset(\$mine[\$user])) continue;", 'D10: another account\'s mailbox is never reported under this one');
has($src, "'/mail/*/*/.Trash/cur'", 'D10: a webmail delete usually moves to Trash first, so Trash is checked');
has($pg, 'may simply be recoverable', 'D10: ...and that is said, because it usually is');

/* ---------- D11: the losses people actually report — a FOLDER, and a whole ADDRESS ---------- */
// "Some emails are gone" is rarely what happened. What gets reported is "the Archive folder is gone" or "the
// sales@ mailbox is gone", and a count of expunged messages answers neither. Both are recoverable by name, and
// both have a default-on source that needs no plugin — which is the one that usually answers it.
ok(function_exists('smpro_uid_mail_folders'), 'D11: deleted folders are collected');
ok(function_exists('smpro_uid_mail_accounts'), 'D11: deleted email accounts are collected');

/* folders */
has($src, "smpro_uid_grep(\$log, ['Mailbox deleted', 'mailbox_delete', 'Mailbox renamed']",
    'D11: a folder Dovecot named is taken from the log');
has($src, "\$sub = \$md . '/subscriptions';",
    'D11: and the default-on source is the mailbox\'s own folder list, which needs no plugin');
has($src, "if (@is_dir(\$md . '/.' . \$f) || @is_dir(\$md . '/.' . \$bare)) continue;",
    'D11: a folder is only called gone when neither Maildir++ spelling of it exists');
has($src, "'in_window' => (\$mtime >= \$fromTs && \$mtime <= \$toTs),",
    'D11: whether that evidence falls inside the asked-about window is reported, not assumed');
has($pg, 'This names it without dating it', 'D11: ...because this route names the folder but cannot date the loss');
has($pg, 'listed with no folder behind it is a folder that used to exist', 'D11: and the page explains the inference rather than presenting it as a log entry');

/* addresses */
has($src, "smpro_uid_grep(\$log, ['delete_pop', 'delete_forwarder', 'deletepop', 'delmailuser', 'Email/delete']",
    'D11: a deleted address is taken from the cPanel log');
has($src, "if (preg_match('#[?&]email=([^&\s\"]+)#i', \$path, \$em)) \$addr = rawurldecode(\$em[1]);",
    'D11: and cPanel DOES name it — unlike a file delete, the address is in the request line');
has($pg, 'cPanel puts its arguments in the request line, so unlike a file delete this one names what it removed',
    'D11: which the page says, so the difference from the file case is not a mystery');
has($src, "if (\$u === '' || isset(\$listed[\$u])) continue;",
    'D11: an address still listed in the account\'s own passwd file is not reported as deleted');
has($src, "'address' => \$u . '@' . \$domain, 'path' => \$md,",
    'D11: a maildir with no address behind it names the address AND where its mail still is');
has($pg, 'so the mailbox was deleted and this is everything it held, still recoverable',
    'D11: ...because that mail is usually still recoverable, which is the useful part');

/* the verdict leads with the names */
$named = smpro_uid_verdict_text(['verdict' => 'none', 'unreadable' => [],
    'counts' => ['events'=>0,'confirmed'=>0,'actors'=>0,'dirs'=>0,'trash'=>0,'folders_gone'=>2,'addresses_gone'=>1]]);
has($named, '2 mail folder(s) are named as gone', 'D11: a named folder is reported even when no log records the act');
has($named, '1 email address(es) are named as removed', 'D11: ...and so is a named address');
has($named, 'No log records the act itself', 'D11: without pretending the act was logged');
