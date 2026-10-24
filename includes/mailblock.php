<?php
/**
 * includes/mailblock.php - Blocked sender addresses (per-address OUTGOING mail block).
 *
 * WHAT IT DOES (plain terms): keeps a list of individual email addresses (or *@domain patterns)
 * that must NOT be able to SEND mail through this server. "Sending" = authenticated submission
 * (webmail / mail client / SMTP-AUTH) OR local injection (PHP mail(), the sendmail binary, cron).
 * It deliberately does NOT touch inbound delivery - mail arriving FROM those addresses TO your
 * users is unaffected (so blocking *@example.com never loses incoming mail from example.com).
 *
 * Enforced at TWO points, each guarded to the outgoing/submission direction only:
 *   1) Exim ACL, slot ACL_MAIL_PRE_BLOCK/custom_begin_mail_pre - a deny with `authenticated = *`,
 *      so it 550-rejects a blocked sender ONLY on an authenticated submission (compromised
 *      mailbox / webmail), and never on unauthenticated inbound delivery.
 *   2) cPanel system-filter custom option (sysfilter/options/smpro_blocked_senders, enabled via
 *      filter_smpro_blocked_senders=1 in /etc/exim.conf.localopts) - matches only when the message
 *      is LOCALLY injected ($sender_host_address empty) OR authenticated ($authenticated_id set),
 *      catching PHP mail()/sendmail; such mail is silently discarded ("=> discarded (system filter)").
 *      Inbound remote mail (non-empty host, unauthenticated) is never matched.
 *
 * Both read the SAME list file /etc/smpro_blocked_senders, which Exim reads live per message - so
 * ADDING/REMOVING an address is instant with NO Exim rebuild. Only INSTALL/UNINSTALL (writing or
 * removing the two rules) runs /scripts/buildeximconf. All of it is cPanel-supported customization
 * (survives Exim rebuilds/updates) and is fully reversible via smpro_mb_uninstall().
 */
if (!defined('SMPRO_BOOT')) { http_response_code(403); exit('forbidden'); }

define('SMPRO_MB_LIST',   '/etc/smpro_blocked_senders');
define('SMPRO_MB_ACL',    '/usr/local/cpanel/etc/exim/acls/ACL_MAIL_PRE_BLOCK/custom_begin_mail_pre');
define('SMPRO_MB_SF',     '/usr/local/cpanel/etc/exim/sysfilter/options/smpro_blocked_senders');
define('SMPRO_MB_LOPTS',  '/etc/exim.conf.localopts');
define('SMPRO_MB_EXIMC',  '/etc/exim.conf');
define('SMPRO_MB_SYSGEN', '/etc/cpanel_exim_system_filter');
define('SMPRO_MB_BEGIN',  '# SMPRO-BLOCKLIST BEGIN');
define('SMPRO_MB_END',    '# SMPRO-BLOCKLIST END');

/** ACL rule text (static - no user data). `authenticated = *` scopes it to submission, so inbound is untouched. */
function smpro_mb_acl_block(): string {
    return SMPRO_MB_BEGIN . " (managed by Safety Monitor Pro — per-address sender block; submission only)\n"
         . "deny\n"
         . "  authenticated = *\n"
         . "  condition = \${if exists{/etc/smpro_blocked_senders}{yes}{no}}\n"
         . "  senders = /etc/smpro_blocked_senders\n"
         . "  message = 550 5.7.1 Sender address blocked by the server administrator\n"
         . "  log_message = SMPRO blocked sender (submission): \$sender_address\n"
         . SMPRO_MB_END;
}
/** System-filter rule text. Only acts on locally-injected OR authenticated mail - never inbound remote delivery. */
/** UNION of sender-blocklist files SM Pro enforces: its own list PLUS any flat Exim-format list dropped into
 *  /etc/smpro_blocked_senders.d/. This is the "shared blocking" join point - cPanel, another plugin, or the
 *  admin can drop a one-address-per-line file there and SM Pro blocks those senders too. Only ABSOLUTE, plain
 *  file paths are returned; each is exists-guarded in the filter so a file appearing/vanishing never errors Exim.
 *  Baked at build time - a newly added source is picked up on the next install/repair (the add path runs it). */
function smpro_mb_union_lists(): array {
    $files = [SMPRO_MB_LIST];
    foreach (glob('/etc/smpro_blocked_senders.d/*') ?: [] as $f) {
        if (@is_file($f) && !@is_link($f) && preg_match('#^/etc/smpro_blocked_senders\.d/[A-Za-z0-9._-]+$#', $f)) $files[] = $f;
    }
    return array_values(array_unique($files));
}
function smpro_mb_sf_block(): string {
    // OR the sender-match across every union list, each guarded by exists{} so a missing file is skipped, never
    // an Exim error. Then AND with the auth/local guard (only authenticated submission or locally-injected mail),
    // exactly as before. Logically: (sender in ANY list) AND (authenticated OR no sending host).
    $terms = [];
    foreach (smpro_mb_union_lists() as $f)
        $terms[] = 'and{{exists{' . $f . '}}{match_address{$sender_address}{' . $f . '}}}';
    $match = count($terms) === 1 ? $terms[0] : 'or{{' . implode('}{', $terms) . '}}';
    $cond  = 'and{{' . $match . '}{or{{def:authenticated_id}{eq{$sender_host_address}{}}}}}';
    return "# SMPRO per-address sender block (managed by Safety Monitor Pro)\n"
         . "# Acts ONLY on locally-injected (sendmail/PHP mail(), empty \$sender_host_address) or authenticated\n"
         . "# submission — never on inbound remote delivery, so incoming mail is unaffected.\n"
         . "# Enforces the UNION of /etc/smpro_blocked_senders and any /etc/smpro_blocked_senders.d/* list (shared\n"
         . "# blocking: other tools or the admin can drop a flat one-address-per-line list there).\n"
         . "if \"\${if " . $cond . "{Y}{N}}\" is \"Y\"\n"
         . "then\n"
         . "  seen finish\n"
         . "endif";
}

/**
 * Normalize + validate one entry. Returns [ok(bool), value(string), why(string)].
 * Allowed, case-folded forms only:  user@domain.tld  |  *@domain.tld  |  domain.tld (-> *@domain.tld).
 * Whitespace inside is REJECTED (never silently altered). Catastrophic patterns are hard-refused.
 */
function smpro_mb_norm_entry(string $raw): array {
    $e = strtolower(trim($raw));
    if ($e === '')                 return [false, '', 'empty'];
    if (preg_match('/\s/', $e))    return [false, '', 'contains a space — enter one address per line'];
    if (strlen($e) > 254)          return [false, '', 'too long'];
    if (preg_match('/[^a-z0-9._%+\-@*]/', $e)) return [false, '', 'contains characters that are not allowed in an email address'];
    if (in_array($e, ['*', '@', '*@', '*@*', '@*'], true))
        return [false, '', 'that pattern would block ALL mail — refused'];

    $reAddr = '/^[a-z0-9](?:[a-z0-9._%+\-]*[a-z0-9])?@(?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.)+[a-z]{2,}$/';
    $reWild = '/^\*@(?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.)+[a-z]{2,}$/';
    $reDom  = '/^(?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.)+[a-z]{2,}$/';
    if (preg_match($reAddr, $e))      $val = $e;
    elseif (preg_match($reWild, $e))  $val = $e;
    elseif (preg_match($reDom, $e))   $val = '*@' . $e;
    else return [false, '', 'not a valid email address, *@domain, or domain'];

    // never let a wildcard cover the server's own system-mail identities
    $host = strtolower(trim((string)@php_uname('n')));
    if ($val === '*@localhost' || $val === '*@localhost.localdomain')
        return [false, '', 'refused: localhost — blocking it would break system mail'];
    if ($host !== '' && $val === '*@' . $host)
        return [false, '', 'refused: that is the server\'s own hostname — blocking it would break system mail'];
    return [true, $val, ''];
}

/** Detect OTHER mail-security layers on the server so the admin sees every blocking mechanism in one place,
 *  not just SM Pro's. These tools block DIFFERENT things (SM Pro = specific sender addresses; OSM/MailGuard =
 *  per-account outbound RATE; cPanel = per-domain filters + incoming-domain blocks) - there is no single shared
 *  list, so this is an awareness view, not a merge. Every path/signal here was verified on a real cPanel box;
 *  detection is by presence only (READ-ONLY), never by guessing a format we'd have to parse. */
function smpro_mb_other_layers(): array {
    $L = [];
    // OSM (MailShield / OutSpam Monitor) - Python log-watcher; per-account outbound-rate actions (freeze/discard/
    // suspend). Mode lives in osm-shield.conf (report_only vs enforcing).
    if (@is_dir('/etc/osm-shield') || @is_dir('/etc/osm-cls')) {
        $mode = '';
        $conf = (string)@file_get_contents('/etc/osm-shield/osm-shield.conf');
        if (preg_match('/^\s*mode\s*=\s*(\S+)/mi', $conf, $m)) $mode = strtolower($m[1]);
        $L[] = ['key' => 'osm', 'name' => 'OSM MailShield', 'kind' => 'Outbound rate / account',
                'active' => ($mode !== '' && $mode !== 'report_only'),
                'detail' => 'Per-account outbound spam rate limiting' . ($mode !== '' ? ' (mode: ' . $mode . ')' : '') . '. Blocks compromised accounts, not individual senders.'];
    }
    // MailGuard - outgoing-mail protection. It reads AND writes this very list and places its own Exim rule for it,
    // so an address blocked on either product's screen is blocked by both; its holds and throttles are shown below.
    if (function_exists('smpro_mg_present') && smpro_mg_present()) {
        $hook = smpro_mg_hook_present();
        $L[] = ['key' => 'mailguard', 'name' => 'MailGuard', 'kind' => 'Outgoing mail / shared list',
                'active' => true,
                'detail' => 'Shares THIS list (' . SMPRO_MB_LIST . '): an address added on either screen is blocked by both products. '
                          . ($hook ? 'MailGuard\'s own Exim rule also consults the list, so disabling enforcement here alone does not unblock anyone.' : 'Its Exim rule for the list is not in place; this plugin\'s rules do the blocking.')
                          . ' Its account throttles, mailbox holds and verdicts are its own and are shown here read-only.'];
    } elseif (@is_dir('/etc/mailguard')) {
        $L[] = ['key' => 'mailguard', 'name' => 'MailGuard', 'kind' => 'Mail protection plugin', 'active' => false, 'detail' => 'MailGuard\'s configuration folder exists but the product is not installed.'];
    }
    // cPanel blocked incoming email domains (WHM › Mail).
    $bd = '/etc/blocked_incoming_email_domains';
    if (@is_file($bd)) {
        $n = 0; foreach (@file($bd, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $ln) if (($ln = trim($ln)) !== '' && $ln[0] !== '#') $n++;
        if ($n > 0) $L[] = ['key' => 'cpanel_bd', 'name' => 'cPanel blocked domains', 'kind' => 'Incoming domains',
                'active' => true, 'detail' => $n . ' incoming sender-domain(s) blocked server-wide (WHM › Mail). Inbound axis — different from SM Pro\'s outbound-submission block.'];
    }
    // cPanel per-domain email filters (users' own "block this sender" rules).
    $vf = 0; foreach (glob('/etc/vfilters/*') ?: [] as $f) if (@is_file($f) && (int)@filesize($f) > 0) $vf++;
    if ($vf > 0) $L[] = ['key' => 'cpanel_vf', 'name' => 'cPanel email filters', 'kind' => 'Per-domain filters',
                'active' => true, 'detail' => $vf . ' domain(s) have account/domain-level email filters (/etc/vfilters). Set by users per domain.'];
    // Imunify email protection, if the agent is installed.
    if (@is_executable('/usr/bin/imunify360-agent'))
        $L[] = ['key' => 'imunify', 'name' => 'Imunify360', 'kind' => 'Malware / email',
                'active' => true, 'detail' => 'Malware scanning + proactive defense (includes outbound-email abuse detection).'];
    return $L;
}

/** Read the current list (normalized, deduped, sorted) - read-only, for display. */
function smpro_mb_read(): array {
    $raw = @file_get_contents(SMPRO_MB_LIST);
    if ($raw === false) return [];
    $out = [];
    foreach (explode("\n", $raw) as $ln) {
        $ln = trim($ln);
        if ($ln === '' || $ln[0] === '#') continue;
        $out[strtolower($ln)] = true;
    }
    $list = array_keys($out); sort($list);
    return $list;
}

/**
 * Atomic read-modify-write under a single exclusive lock (no lost-update race).
 * $fn receives the current list (array) and returns the new list. Returns [ok, msg, newList].
 */
function smpro_mb_mutate(callable $fn): array {
    $fp = @fopen(SMPRO_MB_LIST, 'c+');
    if ($fp === false) return [false, 'Cannot open ' . SMPRO_MB_LIST . ' (need root).', []];
    if (!@flock($fp, LOCK_EX)) { @fclose($fp); return [false, 'List file is busy — try again.', []]; }
    $raw = (string) stream_get_contents($fp);
    $cur = [];
    foreach (explode("\n", $raw) as $ln) { $ln = trim($ln); if ($ln !== '' && $ln[0] !== '#') $cur[strtolower($ln)] = true; }
    $new = $fn(array_keys($cur));
    $new = array_values(array_unique(array_filter(array_map('strtolower', array_map('trim', (array)$new)), 'strlen')));
    sort($new);
    @rewind($fp); @ftruncate($fp, 0);
    $w = @fwrite($fp, $new ? (implode("\n", $new) . "\n") : '');
    @fflush($fp); @flock($fp, LOCK_UN); @fclose($fp); @chmod(SMPRO_MB_LIST, 0644);
    if ($w === false) return [false, 'Write failed on ' . SMPRO_MB_LIST . '.', []];
    return [true, 'saved', $new];
}

/** Which enforcement layers are LIVE in the generated Exim config. Two independent layers:
 *   'sf'  - the Exim SYSTEM FILTER (/etc/cpanel_exim_system_filter). This is the PRIMARY layer: it stops a
 *           blocked sender on BOTH authenticated submission AND local injection (PHP mail()/sendmail), which is
 *           the entire scope of this feature. When this is live, blocking works.
 *   'acl' - an acl_smtp_mail deny that additionally returns an SMTP-time 550 for the authenticated case. Purely
 *           additive. It cannot merge on some cPanel layouts: a custom deny placed in exim.conf.local's
 *           @BEGINACL@ section is only attributed to acl_smtp_mail if it follows an `acl_smtp_mail:` header
 *           line (per Cpanel::Exim::Config::check_acls_for_content), and cPanel's stock @BEGINACL@ is empty, so
 *           a bare deny is dropped. Its absence must therefore NOT be reported as "blocking failed". */
function smpro_mb_layers(): array {
    // GROUND TRUTH is the GENERATED system filter: if /etc/cpanel_exim_system_filter contains our list-path
    // directive, Exim is enforcing it, full stop. Grep the LIST PATH (a real directive) rather than our comment
    // markers - some cPanel builds strip comments when merging. Do NOT also require filter_smpro_blocked_senders=1
    // in exim.conf.localopts: cPanel enables sysfilter option files BY DEFAULT (localopts only OVERRIDES), so the
    // rule merges and enforces with no localopts line at all - requiring it reported "not installed" while blocked
    // senders were actively being discarded, and made every add re-run a full install + exim rebuild.
    $sf  = strpos((string)@file_get_contents(SMPRO_MB_SYSGEN), SMPRO_MB_LIST) !== false;
    $acl = strpos((string)@file_get_contents(SMPRO_MB_EXIMC), SMPRO_MB_LIST) !== false;
    return ['sf' => $sf, 'acl' => $acl];
}
/** Enforcement is active whenever the system filter (the layer that covers every blocking case) is live. */
function smpro_mb_installed(): bool {
    return smpro_mb_layers()['sf'];
}

/** Splice a marker-delimited block into content (preserve other custom content). Markers must be at line start. */
function smpro_mb_splice(string $content, string $block): string {
    $content = preg_replace('/(?:^|\n)[ \t]*' . preg_quote(SMPRO_MB_BEGIN, '/') . '.*?' . preg_quote(SMPRO_MB_END, '/') . '[ \t]*(?=\n|$)/s', "\n", $content);
    $content = trim((string)$content, "\n");
    return ($content === '' ? '' : $content . "\n\n") . $block . "\n";
}
/** Remove our marker-delimited block, keeping other custom content. */
function smpro_mb_unsplice(string $content): string {
    $content = preg_replace('/(?:^|\n)[ \t]*' . preg_quote(SMPRO_MB_BEGIN, '/') . '.*?' . preg_quote(SMPRO_MB_END, '/') . '[ \t]*(?=\n|$)/s', "\n", $content);
    return ltrim((string)$content, "\n");
}

/** Install (or repair) enforcement + rebuild Exim once. Idempotent. Returns [ok(bool), msg(string), rebuilt(bool)]. */
function smpro_mb_install(): array {
    if (!is_file(SMPRO_MB_LIST)) { @file_put_contents(SMPRO_MB_LIST, ''); @chmod(SMPRO_MB_LIST, 0644); }

    if (!is_dir(dirname(SMPRO_MB_ACL))) return [false, 'This does not look like a cPanel server (missing ' . dirname(SMPRO_MB_ACL) . ').', false];
    // MailGuard's rule for the same list already refuses these senders at SMTP time: a second deny would be the same
    // verdict twice. This plugin's own rule is then left out (and removed if an earlier build placed it).
    $mgRule = function_exists('smpro_mg_hook_present') && smpro_mg_hook_present();
    $acl = $mgRule ? smpro_mb_unsplice((string)@file_get_contents(SMPRO_MB_ACL)) : smpro_mb_splice((string)@file_get_contents(SMPRO_MB_ACL), smpro_mb_acl_block());
    if (@file_put_contents(SMPRO_MB_ACL, $acl) === false) return [false, 'Cannot write the Exim ACL slot (' . SMPRO_MB_ACL . ').', false];

    if (!is_dir(dirname(SMPRO_MB_SF))) return [false, 'Missing ' . dirname(SMPRO_MB_SF) . ' (cPanel Exim sysfilter dir).', false];
    if (@file_put_contents(SMPRO_MB_SF, smpro_mb_sf_block() . "\n") === false) return [false, 'Cannot write the system-filter option (' . SMPRO_MB_SF . ').', false];

    $lopts = (string)@file_get_contents(SMPRO_MB_LOPTS);
    // GUARD: if the file exists with content but read came back empty (transient error), ABORT - never overwrite
    // exim.conf.localopts with only our one line (that would drop every other Exim option, incl. DKIM/SPF/etc.).
    if ($lopts === '' && is_file(SMPRO_MB_LOPTS) && (int)@filesize(SMPRO_MB_LOPTS) > 0)
        return [false, 'Could not read ' . SMPRO_MB_LOPTS . ' — aborting so your other Exim options are not clobbered. Please retry.', false];
    if (preg_match('/^filter_smpro_blocked_senders=/m', $lopts) === 1)
        $lopts = preg_replace('/^filter_smpro_blocked_senders=.*$/m', 'filter_smpro_blocked_senders=1', $lopts);
    else
        $lopts = rtrim($lopts, "\n") . "\nfilter_smpro_blocked_senders=1\n";
    if (@file_put_contents(SMPRO_MB_LOPTS, $lopts) === false) return [false, 'Cannot update ' . SMPRO_MB_LOPTS . '.', false];

    // NOTE: earlier builds ALSO spliced the deny block into /etc/exim.conf.local's @BEGINACL@ section as a
    // "second merge path". That was REMOVED - verified against cPanel 11.136 source: @BEGINACL@ content is
    // emitted VERBATIM right after `begin acl`, before any named ACL, so a bare `deny` there is invalid Exim
    // syntax that makes buildeximconf fail validation and refuse to install - poisoning EVERY later rebuild
    // (cPanel updates, any WHM Exim change) until the file is hand-edited. It also never actually blocked
    // anything (0 refs in the generated config in live tests). Enforcement is the system filter (covers auth
    // submission AND local injection); the additive SMTP-time 550 belongs in the supported acls/ slot only.
    // HEAL: if a previous version spliced our block into exim.conf.local, strip it now so this rebuild (and every
    // future one) is clean again. Runs on every install/repair and on every add (smpro_mb_add calls install).
    $lcl = '/etc/exim.conf.local';
    if (@is_file($lcl)) {
        $cur = (string)@file_get_contents($lcl);
        if ($cur !== '' && strpos($cur, SMPRO_MB_LIST) !== false) {
            @copy($lcl, $lcl . '.smpro-bak-' . date('Ymd-His'));
            $clean = smpro_mb_unsplice($cur);
            if ($clean !== '' && $clean !== $cur) @file_put_contents($lcl, $clean);
        }
    }

    $build = '/scripts/buildeximconf';
    if (!is_executable($build)) return [false, 'Saved the rules, but ' . $build . ' is not available to activate them.', false];
    // MailGuard rebuilds Exim too; the two take turns through its lock, never run at once.
    $lk = function_exists('smpro_mg_exim_lock') ? smpro_mg_exim_lock(90) : true;
    if ($lk === null) return [false, 'Saved the rules, but MailGuard is rebuilding Exim right now; try again in a minute.', false];
    $out = (string)@shell_exec('timeout 180 ' . escapeshellarg($build) . ' 2>&1');
    if (function_exists('smpro_mg_exim_unlock')) smpro_mg_exim_unlock($lk);

    // verify via the real directive path (comment-strip-proof - see smpro_mb_layers)
    $L = smpro_mb_layers();
    // The system filter is the layer that actually blocks (auth submission AND local scripts). If it is live,
    // enforcement is active - whether or not the additive SMTP-rejection ACL merged. Only a MISSING system
    // filter is a real failure. (Before, a non-merging ACL raised a scary warning that read as "blocking broke"
    // even though blocked senders were, in fact, being stopped - exactly what confused admins on servers whose
    // cPanel Exim layout drops a headerless custom deny.)
    if ($L['sf'] && $L['acl'])
        return [true, 'Enforcement is fully active — blocked addresses are rejected at submission time (SMTP 550) and stopped by the system filter for local scripts too. Incoming mail is unaffected.', true];
    if ($L['sf'])
        return [true, 'Enforcement is active — blocked addresses can no longer send: the Exim system filter stops their mail whether it comes from authenticated submission/webmail or a local script (PHP mail()). The optional SMTP-time rejection ACL could not be merged into this server\'s generated Exim config (some cPanel builds structure custom ACLs differently) — this does NOT change whether blocked senders are stopped; it only decides whether they get an SMTP 550 or a silent drop. Incoming mail is unaffected. (The "SMTP Mail protection" line in the build output is cPanel reporting THIS SERVER\'S SMTP-Restrictions setting — unrelated to this feature.)', true];
    // The primary layer itself did not merge - this is the genuine failure to surface.
    return [false, 'Exim rebuilt OK, but the system-filter rule was not merged into ' . basename(SMPRO_MB_SYSGEN) . ', so enforcement is NOT active yet. Your blocklist is saved; please retry — if it persists, check that ' . SMPRO_MB_LOPTS . ' contains filter_smpro_blocked_senders=1 and rebuild. Last output: ' . trim(mb_substr($out, -200)), true];
}

/** Uninstall enforcement (remove both rules, keep the list) + rebuild. Returns [ok, msg]. */
function smpro_mb_uninstall(): array {
    if (is_file(SMPRO_MB_ACL)) @file_put_contents(SMPRO_MB_ACL, smpro_mb_unsplice((string)@file_get_contents(SMPRO_MB_ACL)));
    // also remove it from the Advanced-Editor file when that is the merge path in use (see install)
    $lcl = '/etc/exim.conf.local';
    if (@is_file($lcl)) {
        $cur = (string)@file_get_contents($lcl);
        if ($cur !== '' && strpos($cur, SMPRO_MB_LIST) !== false) {
            @copy($lcl, $lcl . '.smpro-bak-' . date('Ymd-His'));
            $clean = smpro_mb_unsplice($cur);
            if ($clean !== '' && $clean !== $cur) @file_put_contents($lcl, $clean);
        }
    }
    @unlink(SMPRO_MB_SF);
    $lopts = (string)@file_get_contents(SMPRO_MB_LOPTS);
    if (preg_match('/^filter_smpro_blocked_senders=/m', $lopts) === 1) {
        $lopts = preg_replace('/^filter_smpro_blocked_senders=.*$/m', 'filter_smpro_blocked_senders=0', $lopts);
        @file_put_contents(SMPRO_MB_LOPTS, $lopts);
    }
    $build = '/scripts/buildeximconf';
    $lk = function_exists('smpro_mg_exim_lock') ? smpro_mg_exim_lock(90) : true;
    if ($lk === null) return [false, 'MailGuard is rebuilding Exim right now; try again in a minute.'];
    if (is_executable($build)) @shell_exec('timeout 180 ' . escapeshellarg($build) . ' 2>&1');
    if (function_exists('smpro_mg_exim_unlock')) smpro_mg_exim_unlock($lk);
    $stillAcl = strpos((string)@file_get_contents(SMPRO_MB_EXIMC), SMPRO_MB_LIST) !== false;
    $stillSf  = strpos((string)@file_get_contents(SMPRO_MB_SYSGEN), SMPRO_MB_LIST) !== false;
    if (!$stillAcl && !$stillSf) return [true, 'Enforcement disabled — the block rules were removed from Exim. Your list is kept for later.'];
    // MailGuard's own rule consults the same list: this plugin's rules are gone, the senders are still refused by it.
    if (!$stillSf && function_exists('smpro_mg_hook_present') && smpro_mg_hook_present())
        return [true, 'This plugin\'s rules were removed, but MailGuard\'s own Exim rule still consults the same list, so every address on it is still refused. Disable the shared list in MailGuard as well to unblock them.'];
    return [false, 'Tried to disable, but the rules are still present after the Exim rebuild.'];
}

/** Add one address (installs enforcement if needed). Returns [ok,msg,entry,count,installed]. */
function smpro_mb_add(string $raw): array {
    [$ok, $val, $why] = smpro_mb_norm_entry($raw);
    if (!$ok) return ['ok' => false, 'msg' => 'Not added: ' . $why . '.'];
    $already = false;
    [$w, $wm, $new] = smpro_mb_mutate(function ($cur) use ($val, &$already) {
        if (in_array($val, $cur, true)) { $already = true; return $cur; }
        $cur[] = $val; return $cur;
    });
    if (!$w) return ['ok' => false, 'msg' => $wm];
    if ($already) return ['ok' => true, 'msg' => $val . ' is already on the block list.', 'entry' => $val, 'count' => count($new), 'installed' => smpro_mb_installed()];
    $installed = smpro_mb_installed(); $note = '';
    if (!$installed) { $r = smpro_mb_install(); $installed = $r[0]; $note = ' ' . $r[1]; }
    return ['ok' => true, 'entry' => $val, 'count' => count($new), 'installed' => $installed,
            'msg' => $val . ' added — it can no longer send mail through this server.' . $note];
}

/** Remove one address. Returns [ok,msg,count]. */
function smpro_mb_remove(string $raw): array {
    $e = strtolower(trim($raw)); $removed = false;
    [$w, $wm, $new] = smpro_mb_mutate(function ($cur) use ($e, &$removed) {
        $n = array_values(array_filter($cur, fn($x) => $x !== $e));
        $removed = count($n) !== count($cur);
        return $n;
    });
    if (!$w) return ['ok' => false, 'msg' => $wm];
    return ['ok' => true, 'count' => count($new),
            'msg' => $removed ? ($e . ' removed — it can send mail again.') : ($e . ' was not on the list.')];
}

/** Snapshot for the UI (read-only, fast). */
function smpro_mb_status(): array {
    return ['installed' => smpro_mb_installed(), 'entries' => smpro_mb_read()];
}
