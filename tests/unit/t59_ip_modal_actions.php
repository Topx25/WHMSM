<?php
/**
 * t59_ip_modal_actions.php — the IP dialog must not make protecting an attacker the easiest thing on it.
 *
 * Seen on a live panel (2026-09-12): a Google Cloud address with 9 failed webmail logins, already blocked. Because
 * it was blocked the Block button was hidden, and the ONE remaining button was "Add to Allowlist" — green, primary,
 * one click, no confirmation. Allow-listing is permanent and outranks every later decision: the firewall, lfd and
 * this plugin all stop acting on that address however it behaves afterwards. There was no Unblock on the dialog at
 * all, so the cheap, reversible correction was missing and the expensive, irreversible one was the tempting one.
 *
 * The same dialog printed "No attacks recorded for this IP in the database." directly above those nine failures —
 * the page disproving itself, because the database holds ModSecurity WEB attacks and the failures come from the
 * auth logs.
 */
require __DIR__ . '/../support/bootstrap.php';

$js = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/layout.php'));
$im = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/intrusion-monitor.php'));

/* ---------- M1: the reversible correction exists ---------- */
has($js, "smproIpModalAction(\\'unblock\\',", 'M1: the dialog offers Unblock');
has($js, '>Unblock</button>', 'M1: ...as a real button on it');
has($im, "(\$_POST['im_action'] ?? '') === 'unblock'", 'M1: ...and the server actually has that action');
has($im, "\$r = smpro_csf_do('unblock', \$ip);", 'M1: through the verified helper, which reports ok only when the address really left csf.deny');
has($im, "smpro_audit('intrusion_unblock'", 'M1: recorded, with the actor');
has($im, "\$__im_ajax_actions = ['block','allow','unblock',", 'M1: registered as a JSON action — otherwise an expired token returns HTML and the dialog says "Request failed" for no reason');

/* ---------- M2: allow-listing an address with a record against it is not one click ---------- */
has($js, 'window.smproIpAllowConfirm=function(ip,against,nFail,nAttacks){', 'M2: the allow button goes through a check');
has($js, "if(against>0){", 'M2: ...which only fires when there IS something against the address');
has($js, 'Adding it to the allow-list is permanent and it wins over every later decision', 'M2: and the dialog states the consequence, not just "are you sure"');
has($js, 'however it behaves from now on', 'M2: ...including that it covers future behaviour');
has($js, "what.push(nFail+' failed login attempt'", 'M2: the warning names what this server actually saw');
has($js, "var nFail = (d.login_summary && d.login_summary.failed) || 0;",
    'M2: counted from the server-side summary, not from the visible rows — that list is capped and a cap would shrink the number the warning rests on');

/* ---------- M3: on an address with a record, it stops being the primary action ---------- */
has($js, 'var risky = against > 0;', 'M3: the button knows whether this address has a record');
has($js, "(risky?' style=\"background:transparent;color:#b45309;border:1px solid rgba(180,83,9,.45)\"':'')",
    'M3: and is demoted from the green primary when it does');
has($js, "(risky?'&#9888; Add to Allowlist anyway':'Add to Allowlist')", 'M3: ...and says "anyway", so the choice reads as a choice');

/* ---------- M4: an empty record says which record was searched ---------- */
hasnt($js, 'No attacks recorded for this IP in the database.</div>', 'M4: the sentence that read as "this address is clean" is gone');
has($js, 'this covers ModSecurity web attacks only', 'M4: it now says what was searched');
has($js, 'read from the server\\\'s auth logs, not from here', 'M4: ...and where the login attempts below actually come from');
