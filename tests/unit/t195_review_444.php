<?php
require __DIR__ . '/../support/bootstrap.php';
/**
 * t195 - reports-center conflated CC_ALLOW (full trust, skips LFD) with CC_ALLOW_FILTER (country-only, keeps LFD):
 * it grepped both into one string and, when an IP's country was in neither, told the operator to add the country
 * to CC_ALLOW - the riskier one, which turns off EVERY firewall check for that whole nation. Now it reads each
 * separately and recommends CC_ALLOW_FILTER.
 */
$src = fn($p) => str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $p));
$rc = $src('modules/reports-center.php');

has($rc, "\$ccAllow  = trim(smpro_rc_logcmd(\"grep -E '^CC_ALLOW *=' /etc/csf/csf.conf 2>/dev/null\"));", 'A1: CC_ALLOW is read on its own');
has($rc, "\$ccFilter = trim(smpro_rc_logcmd(\"grep -E '^CC_ALLOW_FILTER *=' /etc/csf/csf.conf 2>/dev/null\"));", 'A2: CC_ALLOW_FILTER is read on its own');
has($rc, "while CC_ALLOW_FILTER only exempts it from", 'A3: the comment states the distinction (CC_ALLOW skips LFD, filter keeps it)');
has($rc, 'Filtered allow" (CC_ALLOW_FILTER)', 'A4: the fix recommends the SAFER Filtered allow');
has($rc, 'Avoid "Full allow" (CC_ALLOW) unless you mean to skip ALL firewall checks', 'A5: and warns against Full allow');
ok(strpos($rc, "to Firewall → Country Block-Prevention (CC_ALLOW) so it is never blocked again.") === false, 'A6: the old "add to CC_ALLOW" wording is gone');

// coverage still matches when EITHER list names the country, and not when neither does
$country = 'EG';
$ctryRe = '/\b' . preg_quote($country, '/') . '\b/i';
is_eq((bool)preg_match($ctryRe, trim('CC_ALLOW = "AU,EG,SA"' . ' ' . 'CC_ALLOW_FILTER = ""')), true, 'B1: covered when CC_ALLOW names it');
is_eq((bool)preg_match($ctryRe, trim('CC_ALLOW = ""' . ' ' . 'CC_ALLOW_FILTER = "EG,SA"')), true, 'B2: covered when the FILTER names it');
is_eq((bool)preg_match($ctryRe, trim('CC_ALLOW = "AU,SA"' . ' ' . 'CC_ALLOW_FILTER = "DE"')), false, 'B3: NOT covered when neither names it');
// a country that only appears as a substring of another token is not a match (word boundary)
is_eq((bool)preg_match('/\bSA\b/i', 'CC_ALLOW = "USA,BR"'), false, 'B4: SA does not match inside USA (word boundary)');
