<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/georeport.php';
/**
 * t69_threat_state.php — "the file exists" is not "there is malware there".
 *
 * The compromised-accounts report counted a detection as still on disk whenever the file was present. On a live
 * server that reported 44 accounts as still infected when NONE of them were: 34 were a vendor JavaScript library
 * the scanner had already cleaned and put back, byte-identical across all 34, and 10 were files that had been
 * truncated to zero bytes. An empty file cannot execute, and a file whose contents no longer match what was
 * flagged is not what was flagged.
 *
 * The count measured existence and was read as danger — the same failure this product exists to prevent, told
 * the other way round: not a check that could not run reported as clean, but a check that found nothing
 * dangerous reported as an emergency.
 */
$d = sys_get_temp_dir();
$empty = $d . '/smpro_t69_empty_' . getmypid();
$real  = $d . '/smpro_t69_real_'  . getmypid();
file_put_contents($empty, '');
file_put_contents($real, 'the flagged payload');
$h = hash_file('sha256', $real);
$sz = strlen('the flagged payload');

/* ---------- U1: every outcome is named, not inferred from a number ---------- */
is_eq(smpro_gr_threat_state($real,  $h,          $sz), 'live',    'U1: unchanged since it was flagged = live');
is_eq(smpro_gr_threat_state($empty, 'abc',       10),  'emptied', 'U1: zero bytes = emptied — it cannot execute');
is_eq(smpro_gr_threat_state($real,  'deadbeef',  $sz), 'changed', 'U1: a different hash = cleaned or replaced');
is_eq(smpro_gr_threat_state($real,  $h,          999), 'changed', 'U1: a different size = cleaned, without paying for a hash');
is_eq(smpro_gr_threat_state($real,  '',          0),   'unknown', 'U1: nothing recorded to compare against');
is_eq(smpro_gr_threat_state($d . '/no_such_file_t69', $h, 5), 'gone', 'U1: absent = gone');
is_eq(smpro_gr_threat_state('', $h, 5), 'gone', 'U1: an empty path is not a threat');

/* ---------- U2: only what is genuinely still running counts as live ---------- */
// 'unknown' counts too, deliberately: a present, non-empty file the scanner gave no hash for has not been shown
// to be safe, and this is the one place in the product where the unproven case must NOT be waved through.
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/georeport.php'));
has($src, "\$live  = (\$state === 'live' || \$state === 'unknown');",
    'U2: live means live or unproven — nothing else');
hasnt($src, "\$live = \$file !== '' && @is_file(\$file);", 'U2: existence alone no longer decides it');

/* ---------- U3: the sentence says which, so a count never needs interpreting ---------- */
has($src, 'function smpro_gr_state_words', 'U3: the outcome is put into words');
is_eq(smpro_gr_state_words(['emptied' => 10]), '10 emptied', 'U3: an emptied file is called emptied');
is_eq(smpro_gr_state_words(['changed' => 34]), '34 cleaned or replaced', 'U3: a cleaned one is called cleaned');
is_eq(smpro_gr_state_words([]), 'nothing found on disk', 'U3: and nothing is called nothing');
has($src, 'still live on disk', 'U3: the live wording is unambiguous');

/* ---------- U4: hashing is not paid for when the size already answers ---------- */
$i = strpos($src, 'function smpro_gr_threat_state');
$body = substr($src, $i, 1400);
$iSize = strpos($body, "if (\$recordedSize > 0 && \$size !== \$recordedSize) return 'changed';");
$iHash = strpos($body, "hash_file('sha256'");
ok($iSize !== false && $iHash !== false && $iSize < $iHash,
   'U4: size is compared before hashing — a server with thousands of detections cannot hash them all');

/* ---------- U5: an account with nothing live still appears ---------- */
// It was under someone else's control; something put that file there, and whatever did still has whatever it
// used to get in. The password still has to change. What changes is the urgency, not the listing.
has($src, 'Both need the password changed', 'U5: the reason a cleaned account still needs a reset is recorded');

@unlink($empty); @unlink($real);
