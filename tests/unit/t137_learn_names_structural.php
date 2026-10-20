<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
if (!defined('SMPRO_VARLIB')) define('SMPRO_VARLIB', sys_get_temp_dir() . '/t137_varlib_' . getmypid());
require_once SMPRO_BASE . '/includes/learn.php';
/** t137 - Learned Defense, three things one planted "cgi-bin" taught: a rare file NAME is a lesson (the folders above
 *  it change from site to site, the name does not), an .htaccess that turns an odd extension into a CGI program is a
 *  finding, and a native executable inside a web folder is a finding - the last two need no lesson at all. */
$src = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/learn.php'));
has($src, "if (smpro_lr_name_rare(\$name)) \$ids[] = smpro_lr_lesson_add(\$L, 'name', \$name,", 'N1: the file name is learned only when rare');
has($src, "'docblock', 'name']; }", 'N2: a name carries no path, so it is shared');
has($src, "foreach (smpro_lr_structural(\$root) as [\$p, \$why]) \$add(\$p, \$user, 'structural', \$why);", 'N3: the hunt runs the structural checks on every site');
hasnt($src, 'wh1z', 'N4: no tool name from the incident is written in the engine');
hasnt($src, 'ALFA', 'N4: nor another');

// names: common ones are never lessons, whatever the server looks like
ok(!smpro_lr_name_rare('index.php'), 'R1: index.php is never a name lesson');
ok(!smpro_lr_name_rare('functions.php'), 'R1: nor functions.php');
ok(!smpro_lr_name_rare('a.php'), 'R2: a name too short to mean anything is not a lesson');
ok(!smpro_lr_name_rare('README'), 'R2: nor one without an extension');

// the structural checks on a fixture site
$site = sys_get_temp_dir() . '/t137_site_' . getmypid(); @mkdir("$site/cgi-bin", 0755, true); @mkdir("$site/shop/cgi-bin", 0755, true); @mkdir("$site/vendor/x", 0755, true);
file_put_contents("$site/cgi-bin/.htaccess", "Options +ExecCGI\nAddHandler cgi-script .cgi .pl\n");                       // what a cgi-bin is for
file_put_contents("$site/shop/cgi-bin/.htaccess", "Options FollowSymLinks ExecCGI\nAddType application/x-httpd-cgi .ss\nAddHandler cgi-script .ss\nAddHandler cgi-script .pl\n");
file_put_contents("$site/shop/.htaccess", "RewriteEngine On\nRewriteRule ^x$ index.php [L]\n");
$elf = "\x7fELF" . str_repeat("\0", 60) . str_repeat('A', 8192);
file_put_contents("$site/shop/cgi-bin/exp-cr", $elf);
file_put_contents("$site/vendor/x/wkhtmltopdf", $elf);                                                                  // a library's own binary: not a finding
file_put_contents("$site/shop/logo.png", "\x89PNG" . str_repeat('B', 8192));
$f = smpro_lr_structural($site);
$paths = array_column($f, 0); $whys = array_column($f, 1);
ok(in_array("$site/shop/cgi-bin/.htaccess", $paths, true), 'H1: an .htaccess that makes .ss run as CGI is a finding');
ok(!in_array("$site/cgi-bin/.htaccess", $paths, true), 'H2: the ordinary cgi-bin .htaccess (.cgi .pl) is not');
ok(!in_array("$site/shop/.htaccess", $paths, true), 'H2: nor a rewrite-only .htaccess');
$i = array_search("$site/shop/cgi-bin/.htaccess", $paths, true);
ok($i !== false && strpos($whys[$i], '.ss') !== false, 'H3: the finding names the disguised extension');
ok(in_array("$site/shop/cgi-bin/exp-cr", $paths, true), 'E1: a native executable in a web folder is a finding');
ok(!in_array("$site/vendor/x/wkhtmltopdf", $paths, true), 'E2: a binary under vendor/ is not');
ok(!in_array("$site/shop/logo.png", $paths, true), 'E3: an image is not');
file_put_contents("$site/shop/cgi-bin/sym", $elf); @unlink("$site/shop/cgi-bin/sym"); @symlink("$site/shop/cgi-bin/exp-cr", "$site/shop/cgi-bin/sym");
ok(!in_array("$site/shop/cgi-bin/sym", smpro_lr_structural($site) ? array_column(smpro_lr_structural($site), 0) : [], true), 'E4: a symlink is never a finding on its own');

@exec('rm -rf ' . escapeshellarg($site) . ' ' . escapeshellarg(SMPRO_VARLIB));
