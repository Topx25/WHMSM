<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/geologin.php';
/**
 * t74_foreign_allowance.php — a customer who lives abroad is not a compromise.
 *
 * THE INCIDENT. The foreign-login alert had no allowance of any kind. A mailbox whose owner lives in Türkiye and
 * one whose owner lives in Australia were reported every week as successful foreign sign-ins — five logins, one
 * address, one country, webmail. That is what a person looks like, not what an attacker looks like: the
 * attackers in the same report used a different address every time, across several countries, all of them
 * hosting providers.
 *
 * And nothing could clear it. Resetting the password does not stop the owner signing in from Türkiye the next
 * day, so the alert returns naming the same account, for ever. An alert that cannot be cleared by doing what it
 * asks is the fastest way to teach an operator to ignore it — and to ignore the real one underneath it, which in
 * the same report was three accounts signing in from ONE address in Poland.
 *
 * The allowance is Country Login Lock's existing per-account country list, not a second list. Two allow-lists
 * that can disagree is a bug waiting for the day they do: the account the report calls compromised would be the
 * account the lock quietly lets through.
 */

/* ---------- U1: the allowance resolves per account, falling back to the server list ---------- */
$cfg = ['countries' => ['EG', 'SA'], 'per_account' => ['shopone' => ['TR'], 'info@example.test' => ['AU']]];
is_eq(smpro_gl_allowed_for('nobody', $cfg),  ['EG', 'SA'], 'U1: an account with no entry gets the server list');
is_eq(smpro_gl_allowed_for('shopone', $cfg), ['TR'],       'U1: an account with an entry gets its own');

/* ---------- U2: a MAILBOX can have one too — the "@" must survive ---------- */
// It did not. The name was cleaned with a rule that stripped '@', so info@example.test was stored and looked up
// as "infoexample.test" — a key matching no account and no mailbox anywhere else in the product, and one an
// operator cannot recognise in the list they are editing.
is_eq(smpro_gl_allowed_for('info@example.test', $cfg), ['AU'], 'U2: a mailbox allowance is found by its real name');
$saved = smpro_gl_cfg_save([]);                       // exercise the cleaner the config file goes through
ok(is_array($saved), 'U2: the config still loads');
$clean = (new ReflectionFunction('smpro_gl_allowed_for'))->getFileName();
$src   = str_replace(chr(13), '', (string)file_get_contents($clean));
has($src, "preg_replace('/[^a-zA-Z0-9._@-]/'", 'U2: the cleaner keeps @ where identities are normalised');
hasnt($src, "preg_replace('/[^a-zA-Z0-9._-]/', '', \$account)", 'U2: and the old stripping rule is gone');

/* ---------- U3: the alert consults it, and consults THE SAME helper ---------- */
$intr = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/intrusion.php'));
has($intr, 'smpro_gl_allowed_for((string)$account, $glCfg)',
    'U3: the foreign-login alert asks the lock what this account is allowed');
has($intr, 'NO RESET CAN EVER MAKE THEM ONE',
    'U3: with the reason an un-clearable alert is the thing being removed');
has($intr, 'Two allow-lists that can disagree',
    'U3: and why it is not a second list of its own');

// the skip must happen BEFORE the event is recorded, or it is counted and then hidden inconsistently
$posAllow = strpos($intr, 'smpro_gl_allowed_for((string)$account, $glCfg)');
$posSeen  = strpos($intr, "\$seen[\$account]['cc'][\$g['cc']] = true;");
ok($posAllow !== false && $posSeen !== false && $posAllow < $posSeen,
   'U3: an allowed country is skipped before it can feed the travel-anomaly count too');

/* ---------- U4: only the named country is allowed, not the account ---------- */
// An allowance is "this person signs in from there", not "stop watching this account". A login from anywhere
// else must still be reported, or the allowance becomes a way to make an account invisible.
$allowed = smpro_gl_allowed_for('shopone', $cfg);
ok(in_array('TR', $allowed, true),  'U4: the allowed country passes');
ok(!in_array('PL', $allowed, true), 'U4: a different country is still a finding for the same account');
ok(!in_array('US', $allowed, true), 'U4: and so is every other one');

/* ---------- U5: an empty allowance never means "allow everything" ---------- */
$none = ['countries' => [], 'per_account' => []];
is_eq(smpro_gl_allowed_for('anyone', $none), [], 'U5: no configuration yields no allowance');
// in_array against an empty list is false, so nothing is skipped — the alert still reports. Locked here because
// the opposite (empty = allow all) would silently switch the whole detector off on a fresh install.
ok(!in_array('TR', smpro_gl_allowed_for('anyone', $none), true),
   'U5: which means nothing is skipped — an unconfigured server still reports');

/* ---------- U6: the lock's SERVER countries are home for the foreign-login alert ---------- */
// Two lists disagreed on a production server: the lock allowed EG, SA, AU; Intrusion Monitor's home region said
// EG and SA. A customer in Australia signed in exactly as the lock permits, and the alert called it a leaked
// credential - every week, and nothing could clear it because the sign-in was allowed and would happen again.
require_once SMPRO_BASE . '/includes/intrusion.php';
$intrSrc = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/intrusion.php'));
has($intrSrc, 'smpro_im_lock_regions()', 'U6: trusted regions include the lock\'s countries');
ok(function_exists('smpro_im_lock_regions'), 'U6: the resolver exists');
$lockCfgFile = SMPRO_VARLIB . '/geologin.json';
@is_dir(SMPRO_VARLIB) || @mkdir(SMPRO_VARLIB, 0700, true);
smpro_gl_cfg_save(['countries' => ['EG', 'SA', 'AU'], 'per_account' => []]);
ok(in_array('AU', smpro_im_lock_regions(), true), 'U6: a country the lock accepts is a lock region');
ok(in_array('AU', smpro_im_trusted_regions(), true), 'U6: and therefore trusted - not "outside the home region"');
ok(!in_array('PL', smpro_im_trusted_regions(), true), 'U6: a country the lock does not accept is still foreign');
$ntf = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/notify.php'));
has($ntf, 'smpro_im_home_regions_label(true)', 'U6: the alert text names the same set it judged against');
