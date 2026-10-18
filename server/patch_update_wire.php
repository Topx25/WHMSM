<?php
$f='/opt/aitech-license-server/public/index.php'; $s=file_get_contents($f);
if(strpos($s,'update_ext.php')!==false){echo "already wired\n";exit(0);}
$a="require_once __DIR__ . '/download_ext.php';";
$b=$a."\n".
   "require_once __DIR__ . '/update_ext.php';\n".
   "if (\$path === '/api/version' && (\$_SERVER['REQUEST_METHOD'] ?? '') === 'POST') { api_version(); }\n".
   "if (\$path === '/api/update'  && (\$_SERVER['REQUEST_METHOD'] ?? '') === 'POST') { api_update(); }";
$n=str_replace($a,$b,$s,$c);
if($c!==1){fwrite(STDERR,"anchor matched $c\n");exit(2);}
file_put_contents($f,$n); echo "wired /api/version + /api/update\n";
