<?php
if (PHP_SAPI!=='cli') exit("cli only\n");
$idx='/opt/aitech-license-server/public/index.php';
$arc='/opt/aitech-license-server/_archive_backups_20260617'; @mkdir($arc,0700,true);
$s=file_get_contents($idx);
if (strpos($s,'releases_ext.php')!==false){ echo "already wired\n"; exit; }
copy($idx,$arc.'/index.php.bak_releases_'.date('Ymd_His'));
$log=[];
$nav="        echo '<a href=\"/servers\">Servers</a>';";
if(strpos($s,$nav)!==false) $s=str_replace($nav,$nav."\n        echo '<a href=\"/releases\">Releases</a>';",$s); else $log[]='nav-NF';
$req="    require_once __DIR__ . '/servers_ext.php';\n    require_once __DIR__ . '/plans_ext.php';";
if(strpos($s,$req)!==false) $s=str_replace($req,$req."\n    require_once __DIR__ . '/releases_ext.php';",$s); else $log[]='require-NF';
$rt="    if (function_exists('splan_route') && splan_route(\$path)) { exit; }";
if(strpos($s,$rt)!==false) $s=str_replace($rt,$rt."\n    if (function_exists('rel_route') && rel_route(\$path)) { exit; }",$s); else $log[]='route-NF';
file_put_contents($idx,$s);
$lint=shell_exec('php -l '.escapeshellarg($idx).' 2>&1');
if(strpos((string)$lint,'No syntax errors')===false){ $bk=glob($arc.'/index.php.bak_releases_*'); copy(end($bk),$idx); echo "LINT FAIL reverted: ".trim($lint)."\n"; exit(1); }
echo "PATCHED ".($log?implode(',',$log):'(all anchors ok)')."\n";
