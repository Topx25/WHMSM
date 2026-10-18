<?php
$f='/opt/aitech-license-server/public/index.php'; $s=file_get_contents($f);
if($s===false){fwrite(STDERR,"read fail\n");exit(1);}
$changed=0;
// 1) include+dispatch mailer.php BEFORE auth_otp.php
if(strpos($s,'mailer.php')===false){
  $anchor="\$__authOtp = __DIR__ . '/auth_otp.php';";
  $inject="\$__mailer = __DIR__ . '/mailer.php';\n".
          "if (is_file(\$__mailer)) {\n".
          "    require_once \$__mailer;\n".
          "    if (function_exists('mailer_route') && mailer_route(\$path)) { exit; }\n".
          "}\n\n".$anchor;
  $n=str_replace($anchor,$inject,$s,$c);
  if($c!==1){fwrite(STDERR,"mailer dispatch anchor matched $c\n");exit(2);}
  $s=$n; $changed++;
}
// 2) nav link after Logs
if(strpos($s,'/settings/smtp')===false){
  $a="echo '<a href=\"/logs\">Logs</a>';";
  $b=$a."\n        echo '<a href=\"/settings/smtp\">SMTP</a>';";
  $n=str_replace($a,$b,$s,$c);
  if($c!==1){fwrite(STDERR,"nav anchor matched $c\n");exit(3);}
  $s=$n; $changed++;
}
file_put_contents($f,$s);
echo "patched ($changed edits)\n";
