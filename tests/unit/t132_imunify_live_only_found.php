<?php
require __DIR__ . '/../support/bootstrap.php';
/** t132 - "currently malicious" means Imunify status "found" only: rows Imunify already cleaned (cleanup_done /
 *  cleanup_removed) keep a file on disk, cleaned in place or emptied, and must not raise the critical alert. Account
 *  homes are recognised under any /homeN root, not only /home. */
$nt = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/notify.php'));
has($nt, "if ((\$r['status'] ?? 'found') !== 'found') continue;", 'A1: the alert counts only rows Imunify still lists as found');
hasnt($nt, "strpos(\$p, '/home/') === 0 && !@is_file(\$p)", 'A2: the gone-file test is not limited to /home');
$m = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/imunify360-reports.php'));
has($m, "\$imLive = function (\$r) { if ((\$r['status'] ?? 'found') !== 'found') return false;", 'R1: the page headline counts found rows only');
has($m, "\$exists = \$isFile && \$inHome && !\$imCleaned && @is_file(\$path);", 'R2: an already-cleaned file is not offered for delete');
has($m, "preg_match('#^/home[0-9]*/([^/]+)/.+#', \$file, \$m)", 'R3: delete works for accounts under /home2, /home3 …');
has($m, "if(!/^\\/home[0-9]*\\//.test(path))", 'R4: the browser check agrees');
has($m, "smpro_path_safe(\$file, [smpro_user_home(\$acct)])", 'R5: the file must still resolve inside that account home');
