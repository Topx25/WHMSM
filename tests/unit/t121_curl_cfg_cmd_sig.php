<?php
require __DIR__ . '/../support/bootstrap.php';
/** t121 - the shell-curl fallback keeps secrets out of argv; a signed per-server command is verified. */
$r = fn($f) => str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/' . $f));
$h = $r('includes/helpers.php');
hasnt($h, "foreach (\$headers as \$hh) \$cmd .= ' -H ' . escapeshellarg(\$hh);", 'L8: no header on the curl command line');
hasnt($h, "\$cmd .= ' --data-binary ' . escapeshellarg((string)\$body);", 'L8: no body on the curl command line');
has($h, "\$cmd .= ' --config ' . escapeshellarg(\$cf);", 'L8: ...they go through a 0600 config file');
has($h, "if (\$cf !== '') @unlink(\$cf);", 'L8: ...removed right after the call');
$u = $r('includes/update.php');
has($u, "@openssl_verify(\$id . '|' . \$name . '|' . \$args, \$sig, \$pk, OPENSSL_ALGO_SHA256) !== 1", 'L9: a carried signature is verified against the offline key');
has($u, "smpro_audit('update_cmd_bad_sig'", 'L9: a forged one is audited and dropped');
