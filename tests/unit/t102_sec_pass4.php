<?php
require __DIR__ . '/../support/bootstrap.php';
/** t102 - security pass 4: PHP Harden never follows a .htaccess link, quarantine refuses links, Safety Lock answers are O_EXCL, fx_file confined, NUL pipelines. */
$ph = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/php-harden.php'));
has($ph, "if (is_link(\$ht) || is_link(rtrim(\$dir, '/'))) return", 'U1: apply refuses a linked .htaccess');
has($ph, "\$tmp = \$ht . '.smpro-' . bin2hex(random_bytes(6)); \$fh = @fopen(\$tmp, 'xb');", 'U1: apply writes through an O_EXCL temp');
hasnt($ph, "@file_put_contents(\$ht, \$content, LOCK_EX); @chmod(\$ht, 0644);", 'U1: the in-place write is gone');
has($ph, "if (is_file(\$src) && !is_link(\$src))", 'U1: backup skips links');
$im = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/intrusion.php'));
has($im, "if (is_link(\$file) || !is_file(\$file)) return null;", 'U2: quarantine refuses a link');
has($im, "(\$ls['mode'] & 0170000) !== 0100000", 'U2: quarantine insists on a regular file by lstat');
hasnt($im, "@file_put_contents(\$file, \"<?php /* quarantined by smpro Intrusion Monitor */", 'U2: the stub is not written into the path by name');
$sq = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/spqueue.php'));
has($sq, "\$tmp = \$p . '.' . bin2hex(random_bytes(4)) . '.tmp'; \$fh = @fopen(\$tmp, 'xb');", 'U3: the answer is written O_EXCL then renamed');
hasnt($sq, "if (is_link(\$p)) { @unlink(\$p); }", 'U3: the unlink-then-write race is gone');
$fa = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/forensics-audit.php'));
has($fa, "smpro_path_safe(\$fxFile, [smpro_user_home(\$fxUser)])", 'U4: fx_file goes through smpro_path_safe');
has($fa, "-name '.htaccess' -print0 2>/dev/null | head -z -n 20000", 'U5: .htaccess sweep is NUL-delimited');
has($fa, "| xargs -0 -r grep -HnEi", 'U5: ...and xargs reads NUL');
$ub = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/forensics-upload-breach.php'));
has($ub, "-print0 2>/dev/null | head -z -n 4000", 'U5: upload-breach sweep is NUL-delimited');
has($ub, "| xargs -0 -r grep -lEa", 'U5: ...and xargs reads NUL');
hasnt($fa . $ub, 'xargs -r -d', 'U5: no newline-delimited xargs left in the two sweeps');
