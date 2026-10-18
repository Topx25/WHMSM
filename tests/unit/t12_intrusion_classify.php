<?php
require __DIR__ . '/../support/bootstrap.php';
/**
 * t12_intrusion_classify.php — pure classification / matching helpers in includes/intrusion.php
 *   U30 smpro_im_classify       — ordered needle -> label; first-match wins; default label
 *   U31 smpro_im_sev_rank       — severity word -> numeric rank; default
 *   U32 smpro_im_exploit_kind   — classify LABEL -> exploit bool
 *   U33 smpro_in_cidr_match     — v4/v6 CIDR + exact match + mixed-family
 *   U34 smpro_im_subnet24 / smpro_im_path_of / smpro_im_is_secret_probe
 *
 * intrusion.php loads standalone (only function/const defs after the SMPRO_BOOT guard).
 * All targets here are deterministic (string/array in -> value out), no exec/network/CSF.
 */
require SMPRO_BASE . '/includes/intrusion.php';

/* ================= U30 smpro_im_classify ================= */
// each branch hits its own label (source: lines 205-217)
is_eq(smpro_im_classify('SQL injection detected'), 'SQL Injection', 'classify: sql injection -> SQL Injection');
is_eq(smpro_im_classify('blocked sqli payload'),   'SQL Injection', 'classify: sqli needle');
is_eq(smpro_im_classify('UNION SELECT 1,2,3'),     'SQL Injection', 'classify: union select (case-insensitive)');
is_eq(smpro_im_classify('attack-sqli'),            'SQL Injection', 'classify: attack-sqli tag');
is_eq(smpro_im_classify('Reflected XSS attempt'),  'XSS', 'classify: xss');
is_eq(smpro_im_classify('cross-site scripting'),   'XSS', 'classify: cross-site scripting');
is_eq(smpro_im_classify('os command injection'),   'Command Injection / RCE', 'classify: command injection -> RCE');
is_eq(smpro_im_classify('RCE attempt'),            'Command Injection / RCE', 'classify: rce needle');
is_eq(smpro_im_classify('remote file inclusion'),  'Remote File Inclusion', 'classify: rfi (full phrase)');
is_eq(smpro_im_classify('attack-rfi'),             'Remote File Inclusion', 'classify: attack-rfi tag');
is_eq(smpro_im_classify('path traversal blocked'), 'Path Traversal / LFI', 'classify: path traversal');
is_eq(smpro_im_classify('GET /a/../../etc'),       'Path Traversal / LFI', 'classify: ../ literal -> traversal');
is_eq(smpro_im_classify('lfi include'),            'Path Traversal / LFI', 'classify: lfi needle');
is_eq(smpro_im_classify('access to .env file'),    'Sensitive File Access', 'classify: .env -> sensitive file');
is_eq(smpro_im_classify('probing wp-config'),      'Sensitive File Access', 'classify: wp-config');
is_eq(smpro_im_classify('php object injection'),   'PHP Injection', 'classify: php object -> PHP Injection');
is_eq(smpro_im_classify('deserialization'),        'PHP Injection', 'classify: deserial needle');
is_eq(smpro_im_classify('sqlmap user agent'),      'Scanner / Recon', 'classify: sqlmap -> scanner');
is_eq(smpro_im_classify('nikto scan'),             'Scanner / Recon', 'classify: nikto -> scanner');
is_eq(smpro_im_classify('invalid request line'),   'Protocol Violation', 'classify: invalid request -> protocol');
is_eq(smpro_im_classify('malformed header'),       'Protocol Violation', 'classify: malformed -> protocol');
is_eq(smpro_im_classify('brute attempt'),          'Brute Force / Auth', 'classify: brute -> auth');
is_eq(smpro_im_classify('failed authentication'),  'Brute Force / Auth', 'classify: authentication -> auth');
is_eq(smpro_im_classify('webshell uploaded'),      'Malicious Upload', 'classify: webshell -> upload');
is_eq(smpro_im_classify('backdoor planted'),       'Malicious Upload', 'classify: backdoor -> upload');
is_eq(smpro_im_classify('session fixation'),       'Session Attack', 'classify: fixation -> session');
is_eq(smpro_im_classify('nothing recognizable'),   'WAF Block (other)', 'classify: no match -> default label');
is_eq(smpro_im_classify(''),                       'WAF Block (other)', 'classify: empty -> default label');

// ORDERING / first-match-wins (security-relevant): sqli is checked before traversal (line 205 before 209)
is_eq(smpro_im_classify('sqli with ../ traversal'), 'SQL Injection',
      'classify: sqli+traversal -> SQL Injection (first match wins)');
// xss is checked before rce -> a string with both yields XSS
is_eq(smpro_im_classify('xss and rce combined'), 'XSS',
      'classify: xss+rce -> XSS (xss checked first)');
// ../ (traversal, line 209) is checked before .env (sensitive, line 210)
is_eq(smpro_im_classify('../ and .env both present'), 'Path Traversal / LFI',
      'classify: ../ + .env -> Path Traversal (traversal checked first)');
// 'login' substring lands in Brute Force / Auth (line 214)
is_eq(smpro_im_classify('GET /wp-login.php'), 'Brute Force / Auth', 'classify: login substring -> auth');
// FIXED: 'rce' is now matched with \brce\b, so "brute force" (which contains "rce" inside "force")
// is NO LONGER misclassified as RCE — it correctly falls through to Brute Force / Auth.
is_eq(smpro_im_classify('brute force on form'), 'Brute Force / Auth',
      'classify: "brute force" -> Brute Force/Auth (\brce\b no longer trips on "force" — bug fixed)');
is_eq(smpro_im_classify('attempted rce via shell'), 'Command Injection / RCE',
      'classify: a real " rce " token still -> Command Injection / RCE');

/* ================= U31 smpro_im_sev_rank ================= */
// ranks from line 219: critical=5,error=4,warning=3,notice=2,info=1; default ?? 2
is_eq(smpro_im_sev_rank('CRITICAL'), 5, 'sev_rank: CRITICAL -> 5 (case-insensitive)');
is_eq(smpro_im_sev_rank('critical'), 5, 'sev_rank: critical -> 5');
is_eq(smpro_im_sev_rank('error'),    4, 'sev_rank: error -> 4');
is_eq(smpro_im_sev_rank('Warning'),  3, 'sev_rank: warning -> 3');
is_eq(smpro_im_sev_rank('NOTICE'),   2, 'sev_rank: notice -> 2');
is_eq(smpro_im_sev_rank('info'),     1, 'sev_rank: info -> 1');
is_eq(smpro_im_sev_rank('bogus'),    2, 'sev_rank: unknown word -> default 2');
is_eq(smpro_im_sev_rank(''),         2, 'sev_rank: empty -> default 2');
is_eq(smpro_im_sev_rank(null),       2, 'sev_rank: null -> default 2 (cast to "")');

/* ================= U32 smpro_im_exploit_kind ================= */
// takes a classify LABEL; strict in_array against exploit labels (line 222)
ok(smpro_im_exploit_kind('SQL Injection'),            'exploit_kind: SQL Injection -> true');
ok(smpro_im_exploit_kind('Command Injection / RCE'),  'exploit_kind: RCE -> true');
ok(smpro_im_exploit_kind('Remote File Inclusion'),    'exploit_kind: RFI -> true');
ok(smpro_im_exploit_kind('Path Traversal / LFI'),     'exploit_kind: LFI -> true');
ok(smpro_im_exploit_kind('PHP Injection'),            'exploit_kind: PHP Injection -> true');
ok(smpro_im_exploit_kind('Malicious Upload'),         'exploit_kind: Malicious Upload -> true');
nok(smpro_im_exploit_kind('Scanner / Recon'),         'exploit_kind: Scanner -> false');
nok(smpro_im_exploit_kind('XSS'),                     'exploit_kind: XSS -> false');
nok(smpro_im_exploit_kind('WAF Block (other)'),       'exploit_kind: WAF other -> false');
nok(smpro_im_exploit_kind('Brute Force / Auth'),      'exploit_kind: Brute Force -> false');
nok(smpro_im_exploit_kind('Session Attack'),          'exploit_kind: Session Attack -> false');
nok(smpro_im_exploit_kind(''),                        'exploit_kind: empty -> false');
nok(smpro_im_exploit_kind('sqli'),                    'exploit_kind: needle (not a label) -> false');

/* ================= U33 smpro_in_cidr_match ================= */
// no slash -> exact string equality (line 457)
ok(smpro_in_cidr_match('1.2.3.4', '1.2.3.4'),   'cidr: exact v4 no-slash match');
nok(smpro_in_cidr_match('1.2.3.4', '1.2.3.5'),  'cidr: exact v4 no-slash mismatch');
// v4 in-range
ok(smpro_in_cidr_match('192.168.1.55', '192.168.1.0/24'),  'cidr: v4 inside /24');
nok(smpro_in_cidr_match('192.168.2.55', '192.168.1.0/24'), 'cidr: v4 outside /24');
ok(smpro_in_cidr_match('10.0.0.1', '10.0.0.1/32'),         'cidr: v4 /32 exact host');
nok(smpro_in_cidr_match('10.0.0.2', '10.0.0.1/32'),        'cidr: v4 /32 different host');
// /0 -> mask 0 -> matches everything (line 462)
ok(smpro_in_cidr_match('8.8.8.8', '0.0.0.0/0'),  'cidr: v4 /0 matches anything');
// out-of-range bits (line 461) -> false
nok(smpro_in_cidr_match('1.2.3.4', '1.2.3.4/33'), 'cidr: v4 bits>32 -> false');
// v6 /32 + /128 (lines 466-473)
ok(smpro_in_cidr_match('2001:db8::1', '2001:db8::/32'),         'cidr: v6 inside /32');
nok(smpro_in_cidr_match('2001:db9::1', '2001:db8::/32'),        'cidr: v6 outside /32');
ok(smpro_in_cidr_match('2001:db8::1', '2001:db8::1/128'),       'cidr: v6 /128 exact');
nok(smpro_in_cidr_match('2001:db8::2', '2001:db8::1/128'),      'cidr: v6 /128 different');
ok(smpro_in_cidr_match('2001:db8::abcd', '2001:db8::/0'),       'cidr: v6 /0 (rem==0 whole==0) -> true');
nok(smpro_in_cidr_match('2001:db8::1', '2001:db8::/129'),       'cidr: v6 bits>128 -> false');
// mixed family -> false (line 475)
nok(smpro_in_cidr_match('1.2.3.4', '2001:db8::/32'),  'cidr: v4 ip vs v6 net -> false');
nok(smpro_in_cidr_match('2001:db8::1', '1.2.3.0/24'), 'cidr: v6 ip vs v4 net -> false');

/* ================= U34a smpro_im_subnet24 ================= */
// line 606: ^(\d+\.\d+\.\d+)\.\d+$ -> first 3 octets + .0/24
is_eq(smpro_im_subnet24('1.2.3.4'),       '1.2.3.0/24',   'subnet24: dotted-quad -> /24');
is_eq(smpro_im_subnet24('192.168.10.200'),'192.168.10.0/24','subnet24: another quad');
is_eq(smpro_im_subnet24('2001:db8::1'),   '',             'subnet24: v6 -> empty');
is_eq(smpro_im_subnet24(''),              '',             'subnet24: empty -> empty');
is_eq(smpro_im_subnet24('not.an.ip'),     '',             'subnet24: non-numeric -> empty');

/* ================= U34b smpro_im_path_of ================= */
// line 605: parse_url PATH; falls back to full uri when path empty
is_eq(smpro_im_path_of('/wp-login.php?a=1'), '/wp-login.php', 'path_of: strips query');
is_eq(smpro_im_path_of('http://h/x/y.php?q=1#f'), '/x/y.php', 'path_of: full URL -> path only');
is_eq(smpro_im_path_of('/just/a/path'), '/just/a/path', 'path_of: bare path unchanged');
is_eq(smpro_im_path_of(''), '', 'path_of: empty -> empty (fallback to uri)');
// a query-only string has no path -> falls back to the original string
is_eq(smpro_im_path_of('?only=query'), '?only=query', 'path_of: no path -> returns original uri');

/* ================= U34c smpro_im_is_secret_probe ================= */
// line 830: lowercases, substring needle list
ok(smpro_im_is_secret_probe('/.env'),                 'secret_probe: /.env -> true');
ok(smpro_im_is_secret_probe('/.git/config'),          'secret_probe: /.git/config -> true');
ok(smpro_im_is_secret_probe('/.aws/credentials'),     'secret_probe: /.aws/credentials -> true');
ok(smpro_im_is_secret_probe('/.SSH/id_rsa'),          'secret_probe: case-insensitive (/.SSH/) -> true');
ok(smpro_im_is_secret_probe('/path/to/.env'),         'secret_probe: needle anywhere in path -> true');
ok(smpro_im_is_secret_probe('/.htpasswd'),            'secret_probe: /.htpasswd -> true');
nok(smpro_im_is_secret_probe('/index.php'),           'secret_probe: /index.php -> false');
nok(smpro_im_is_secret_probe('/about/team'),          'secret_probe: normal path -> false');
nok(smpro_im_is_secret_probe(''),                     'secret_probe: empty -> false');

/* ================= U35 smpro_im_is_self_attack — self-test vs real local compromise =================
 * A real incident's alert was a FALSE POSITIVE: Really Simple SSL requests
 * /wp-content/uploads/code-execution.php FROM THE SERVER'S OWN IP to prove uploads can't run PHP, and the
 * filename trips the Malicious-Upload heuristic. The fix whitelists that self-test ONLY from the server's own
 * IP — an external attacker dropping the same file must still flag, and a real self-origin exploit must too.
 */
if (!function_exists('smpro_is_server_ip'))  { function smpro_is_server_ip($ip){ return $ip === '203.0.113.10'; } }
if (!function_exists('smpro_ip_is_external')) { function smpro_ip_is_external($ip){ return strpos($ip,'127.')!==0 && $ip!=='::1' && strpos($ip,'10.')!==0; } }

// the false positive: RSSSL self-test from the server's own IP -> NOT a self-attack
nok(smpro_im_is_self_attack('203.0.113.10', 'Malicious Upload', '/wp-content/uploads/code-execution.php'),
    'self-attack: RSSSL uploads self-test from server IP is NOT flagged');
nok(smpro_im_is_self_attack('203.0.113.10', 'Malicious Upload', '/wp-content/plugins/really-simple-ssl/ssl-test-page.php'),
    'self-attack: RSSSL ssl-test-page from server IP is NOT flagged');
// wp-cron from server IP -> benign (pre-existing rule, still holds)
nok(smpro_im_is_self_attack('203.0.113.10', 'Malicious Upload', '/wp-cron.php?doing_wp_cron=123'),
    'self-attack: wp-cron from server IP is NOT flagged');
// SAME probe path from an EXTERNAL attacker -> STILL a real exploit-class hit (not whitelisted)
ok(smpro_im_is_self_attack('198.51.100.20', 'Malicious Upload', '/wp-content/uploads/code-execution.php') === false,
    'self-attack: external IP is not a SELF source at all (returns false by definition), but is not whitelisted as benign');
// a genuine local compromise: server IP POSTing a real webshell upload elsewhere -> MUST still flag
ok(smpro_im_is_self_attack('203.0.113.10', 'Malicious Upload', '/wp-content/uploads/evil-shell.php'),
   'self-attack: a real upload from the server IP (not a known self-test) IS still flagged');
// generic WAF noise from the server IP -> not an exploit kind -> not flagged
nok(smpro_im_is_self_attack('203.0.113.10', 'WAF Block (other)', '/xmlrpc.php'),
    'self-attack: generic WAF noise from server IP is NOT flagged (exploit-kind gate)');
