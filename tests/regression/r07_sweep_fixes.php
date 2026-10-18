<?php
/**
 * r07_sweep_fixes.php — locks the adversarial-sweep fixes (siblings of the original 6 bug classes):
 *   #1 smpro_ip_is_datacenter — word-boundary match (SERVER/COLO no longer match inside OBSERVER/COLOMBIA)
 *   #2 smpro_im_classify       — word-boundary for sqli/xss/rce/rfi/lfi/shell/login/brute/session
 *   smpro_path_safe            — the shared symlink/scope guard used by the delete/backup/rewrite fixes (#6/#7/#8/#9/#10)
 */
require __DIR__ . '/../support/bootstrap.php';
require SMPRO_BASE . '/includes/helpers.php';     // ip_is_datacenter + smpro_path_safe
require SMPRO_BASE . '/includes/intrusion.php';   // im_classify

/* ---------- #1 datacenter keyword word-boundary ---------- */
is_eq(smpro_ip_is_datacenter(['provider' => 'OBSERVER MEDIA NETWORKS', 'asn' => 'AS12345']), false, '#1 "OBSERVER..." NOT datacenter (SERVER no longer matches inside the word)');
is_eq(smpro_ip_is_datacenter(['provider' => 'TELECOM COLOMBIA', 'asn' => 'AS9999']), false, '#1 "COLOMBIA" NOT datacenter (COLO substring fixed)');
is_eq(smpro_ip_is_datacenter(['provider' => 'Vodafone Egypt', 'asn' => 'AS24835']), false, '#1 residential telecom NOT datacenter');
is_eq(smpro_ip_is_datacenter(['provider' => 'OVH SAS', 'asn' => 'AS16276']), true, '#1 OVH still datacenter');
is_eq(smpro_ip_is_datacenter(['provider' => 'Hetzner Online GmbH', 'asn' => 'AS24940']), true, '#1 Hetzner still datacenter');
is_eq(smpro_ip_is_datacenter(['provider' => 'DigitalOcean, LLC', 'asn' => 'AS14061']), true, '#1 DigitalOcean still datacenter');
is_eq(smpro_ip_is_datacenter(['provider' => 'Contabo GmbH', 'asn' => 'AS51167']), true, '#1 Contabo still datacenter');
is_eq(smpro_ip_is_datacenter(['provider' => 'some VPS hosting', 'asn' => '']), true, '#1 standalone "VPS" word still datacenter');

/* ---------- #2 classifier word-boundary ---------- */
isnt_eq(smpro_im_classify('PowerShell remoting health-check rule'), 'Malicious Upload', '#2 "PowerShell" NOT Malicious Upload (shell no longer matches inside powershell)');
isnt_eq(smpro_im_classify('mysqli driver connection warning'), 'SQL Injection', '#2 "mysqli" NOT SQL Injection (sqli substring fixed)');
isnt_eq(smpro_im_classify('Gulfintel reputation feed note'), 'Path Traversal / LFI', '#2 "Gulfintel" NOT LFI (lfi substring fixed)');
is_eq(smpro_im_classify('Webshell backdoor upload detected'), 'Malicious Upload', '#2 real webshell still Malicious Upload');
is_eq(smpro_im_classify('LFI attempt /etc/passwd'), 'Path Traversal / LFI', '#2 real "LFI" token still classified');
is_eq(smpro_im_classify('brute force on the form'), 'Brute Force / Auth', '#2 "brute force" still Brute Force/Auth (not RCE)');
is_eq(smpro_im_classify('attempted rce via injection'), 'Command Injection / RCE', '#2 real " rce " token still RCE');
is_eq(smpro_im_classify('GET /wp-login.php'), 'Brute Force / Auth', '#2 wp-login still Brute Force/Auth (\\blogin\\b matches)');

/* ---------- smpro_path_safe — the symlink/scope guard ---------- */
$d = SMPRO_VARLIB . '/pf'; @mkdir($d, 0700, true);
file_put_contents($d . '/real.php', 'x');
@symlink('/etc/hostname', $d . '/evil.php');        // symlink pointing OUTSIDE the allowed root
@symlink('/etc', $d . '/etclnk');                   // symlinked directory component

isnt_eq(smpro_path_safe($d . '/real.php', [$d]), '', 'path_safe: real regular file under allowed root -> resolved path');
is_eq(smpro_path_safe($d . '/evil.php', [$d]), '', 'path_safe: symlink target -> refused (is_link)');
is_eq(smpro_path_safe($d . '/etclnk/hostname', [$d]), '', 'path_safe: file via a symlinked dir resolves outside -> refused');
is_eq(smpro_path_safe('/etc/passwd', ['/home/bob']), '', 'path_safe: path outside the allowed prefix -> refused');
is_eq(smpro_path_safe($d . '/does-not-exist', [$d]), '', 'path_safe: nonexistent path -> refused');
is_eq(smpro_path_safe('', [$d]), '', 'path_safe: empty -> refused');
