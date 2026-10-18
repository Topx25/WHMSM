<?php
$f='/opt/aitech-license-server/public/index.php'; $s=file_get_contents($f);
if ($s===false){fwrite(STDERR,"read fail\n");exit(1);}
if (strpos($s,'auth_otp.php')!==false){echo "already wired\n";exit(0);}
$anchor="\$__panelExt = __DIR__ . '/panel_ext.php';\nif (is_file(\$__panelExt)) {\n    require_once \$__panelExt;\n    if (function_exists('pext_route') && pext_route(\$path)) { exit; }\n}";
$inject=$anchor."\n\n".
"\$__authOtp = __DIR__ . '/auth_otp.php';\n".
"if (is_file(\$__authOtp)) {\n".
"    require_once \$__authOtp;\n".
"    if (function_exists('authotp_route') && authotp_route(\$path)) { exit; }\n".
"}";
$n=str_replace($anchor,$inject,$s,$c);
if($c!==1){fwrite(STDERR,"anchor matched $c (expected 1)\n");exit(2);}
file_put_contents($f,$n); echo "wired authotp dispatch\n";
