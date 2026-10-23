<?php
require __DIR__ . '/../support/bootstrap.php';
require_once SMPRO_BASE . '/includes/helpers.php';
if (!defined('SMPRO_VARLIB')) define('SMPRO_VARLIB', sys_get_temp_dir() . '/t151_varlib_' . getmypid());
require_once SMPRO_BASE . '/includes/learn.php';
/** t151 - beta369: a kept (quarantined) file is CHECKED before it may go back - the lessons, the code, ClamAV when
 *  present - and the page says what was found; a file that looks malicious is not restored unless the operator
 *  insists, and a forced restore is never remembered as safe. The page is one set of folding sections behind the
 *  shared navigator. */
$ln = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/includes/learn.php'));
$pg = str_replace(chr(13), '', (string)file_get_contents(SMPRO_BASE . '/modules/learned-defense.php'));

// A. the verdict itself, on real kept copies
$qd = smpro_lr_dir('quarantine/acct1');
$mk = function (string $name, string $body) use ($qd): string { $p = $qd . '/20261023-120000-' . substr(sha1($name), 0, 12) . '-' . $name; file_put_contents($p, $body); return $p; };
$shell = $mk('wp-cache.php', '<?php' . "\n" . 'if (isset($_POST["cmd"])) { system($_POST["cmd"]); }' . "\n");
$v = smpro_lr_verdict($shell);
is_eq($v['verdict'], 'malicious', 'A1: commands taken from the web request = malicious');
ok(count(array_filter($v['signs'], fn($s) => strpos($s, 'runs system commands taken from the web request') !== false)) === 1, 'A2: ...and the sign names what it does');
$ico = $mk('favicon.ico', "<?php\necho 'hello';\n");
is_eq(smpro_lr_verdict($ico)['verdict'], 'malicious', 'A3: PHP inside a file named as an image = malicious');
$loader = $mk('loader.php', "<?php\n/* cache */\n@eval(base64_decode('aGVsbG8='));\n");
$v = smpro_lr_verdict($loader);
is_eq($v['verdict'], 'malicious', 'A4: a file that only runs a payload = malicious');
ok(in_array('the file does nothing but run a payload', $v['signs'], true), 'A5: ...named');
$plain = $mk('readme.html', "<html><body><h1>Shop</h1><p>Welcome to our store.</p></body></html>\n");
$v = smpro_lr_verdict($plain);
is_eq($v['verdict'], 'clean', 'A6: plain HTML = no sign found');
is_eq($v['signs'], [], 'A7: ...no signs');
is_eq($v['sha'], hash('sha256', file_get_contents($plain)), 'A8: the verdict is bound to the bytes it judged');
ok(in_array($v['clam'], ['not installed', 'clean', 'did not finish'], true), 'A9: ClamAV is reported as a named opinion (' . $v['clam'] . ')');
$soft = $mk('tool.php', "<?php\n\$x = 'abc';\n\$f = create_function('', \$x);\n");
is_eq(smpro_lr_verdict($soft)['verdict'], 'suspicious', 'A10: a single risky function without the combination = worth a look, not malicious');
is_eq(smpro_lr_verdict('/etc/passwd')['verdict'], 'unknown', 'A11: a path outside the store is never judged (unknown, not clean)');
is_eq(smpro_lr_verdict($qd . '/does-not-exist.php')['verdict'], 'unknown', 'A12: a missing copy is unknown, never clean');
// a hash lesson confirmed on this server makes the exact file malicious whatever the code looks like
$L = []; $sha = hash('sha256', file_get_contents($plain));
smpro_lr_lesson_add($L, 'hash', $sha . ':' . filesize($plain), 'test', ['path' => '/home/acct1/public_html/readme.html', 'sha' => $sha, 'at' => time(), 'source' => 'test']);
smpro_lr_save('lessons', $L);
$v = smpro_lr_verdict($plain);
is_eq($v['verdict'], 'malicious', 'A13: the exact file of a confirmed incident = malicious even when the code reads clean');
ok(in_array('the exact file of an incident confirmed on this server', $v['signs'], true), 'A14: ...and says so');
smpro_lr_save('lessons', []);

// B. the verdict travels with the store row, and Restore reads it
$jf = smpro_lr_dir() . '/quarantine.jsonl';
$row = fn($kept, $orig) => json_encode(['at' => time(), 'orig' => $orig, 'kept' => $kept, 'sha' => hash('sha256', file_get_contents($kept)), 'size' => filesize($kept), 'mode' => 0644, 'uid' => 0, 'gid' => 0, 'mtime' => time(), 'source' => 'operator', 'restored' => 0], JSON_UNESCAPED_SLASHES);
file_put_contents($jf, $row($shell, '/home/acct1/public_html/wp-cache.php') . "\n" . $row($plain, '/home/acct1/public_html/readme.html') . "\n");
is_eq(smpro_lr_verdict_of(smpro_lr_quarantined()[0]), null, 'B1: unchecked row = null, never a guess');
[$n, $bad] = smpro_lr_verdict_all(30);
is_eq([$n, $bad], [2, 1], 'B2: Check all judges every unchecked row and counts the malicious ones');
$rows = smpro_lr_quarantined(); $byKept = []; foreach ($rows as $r) $byKept[$r['kept']] = $r;
is_eq(smpro_lr_verdict_of($byKept[$shell])['verdict'], 'malicious', 'B3: ...the verdict is on the row');
is_eq(smpro_lr_verdict_all(30), [0, 0], 'B4: a second pass finds nothing waiting');
$r = smpro_lr_restore($shell);
is_eq($r['ok'], false, 'B5: Restore REFUSES a file that looks malicious');
has($r['msg'], 'NOT restored - this file looks malicious', 'B6: ...and says so, with the reason');
has($r['msg'], 'tick "I understand the risk"', 'B7: ...and how to insist');
has($ln, "if (\$v['verdict'] === 'unknown' && !\$force) return ['ok' => false, 'msg' => 'NOT restored - the kept copy could not be checked", 'B8: a copy that could not be checked is not restored silently either');
has($ln, "\$against = \$v['verdict'] !== 'clean';", 'B9: anything but clean is a restore against the check');
has($ln, "if (\$against) return ['ok' => true, 'msg' => 'Put back AGAINST the check (' . \$v['verdict'] . '). It is NOT remembered as safe", 'B10: ...which is never remembered as safe');
has($ln, "smpro_audit('learn_restore', ['path' => \$hit['orig'], 'sha256' => (string)(\$hit['sha'] ?? ''), 'verdict' => \$v['verdict'], 'forced' => \$against]);", 'B11: every restore is audited with its verdict');
has($ln, "if (\$v === null) { \$v = smpro_lr_verdict(\$kept); smpro_lr_verdict_save(\$kept, \$v); }", 'B12: Restore checks an unchecked file first');
// peek never leaves the store and is bounded
ok(strpos(smpro_lr_peek($shell), 'system(') !== false, 'B13: View shows the kept copy');
is_eq(smpro_lr_peek('/etc/passwd'), '', 'B14: ...only from inside the store');
$big = $mk('big.txt', str_repeat("line\n", 5000)); $pk = smpro_lr_peek($big);
ok(strlen($pk) < 7000 && substr($pk, -3) === '…', 'B15: ...and bounded');

// C. the page
has($pg, "case 'restore':   \$r = smpro_lr_restore((string)(\$_POST['kept'] ?? ''), !empty(\$_POST['ack']));", 'C1: Restore carries the acknowledgement');
has($pg, "case 'verdict':", 'C2: Check one');
has($pg, "case 'verdict_all': [\$n, \$bad] = smpro_lr_verdict_all(50);", 'C3: Check all, time-bounded');
has($pg, "case 'peek':", 'C4: View');
has($pg, 'Do not restore them: putting one back re-infects the site.', 'C5: the warning on the store when a kept file looks malicious');
has($pg, 'I understand the risk', 'C6: the acknowledgement tick');
has($pg, "<button class=\"btn btn-xs <?= \$k === 'malicious' ? 'btn-danger' : 'btn-ghost' ?>\" type=\"submit\"<?= \$risky ? ' disabled' : '' ?>>", 'C7: Restore is disarmed on a risky row until the tick');
has($pg, "if(b) b.disabled=!c.checked;", 'C8: ...the tick arms it');
has($pg, "'This file LOOKS MALICIOUS: ' . smpro_h(implode('; ', \$v['signs'])) . '. Putting it back re-infects the site and it will NOT be remembered as safe. Restore it anyway?'", 'C9: the confirm repeats the verdict');
has($pg, 'why it was taken:', 'C10: every row says why the file was taken');
has($pg, 'data-nopage="1"', 'C11: the store table filters itself (no shared pager on top)');
has($pg, '<nav class="fw-nav" id="ldNav" data-keep-open="1">', 'C12: the shared navigator, sections open on first visit');
has($pg, "var KEY='smpro:learned-defense:open', HSEL='.smpro-main .card > .ld-head', PFX='ld'", 'C13: one fold engine, remembered per section');
has($pg, 'if(!card||!card.id||th.classList.contains(\'fw-toggle\')) return;   /* the flash card has no id: never folded */', 'C14: the flash message is never folded away');
foreach (['findings', 'ld-store', 'ld-lessons', 'ld-tools'] as $id) has($pg, 'id="' . $id . '"', 'C15: section ' . $id);
has($pg, 'data-go="ld-store"', 'C16: the store tile opens the store');
hasnt($pg, 'class="ld-two"', 'C17: the old two-column layout is gone');
hasnt($pg, 'data-confirm="Put this file back where it was, and remember it as not malicious?"', 'C18: the old unconditional Restore is gone');

// D. the quarantine that put a file in the store taught lessons FROM it; they must not judge the same file
$own = $mk('own.html', "<html><body><p>Plain page of the customer.</p></body></html>
"); $osha = hash('sha256', file_get_contents($own));
file_put_contents($jf, $row($own, '/home/acct1/public_html/own.html') . "
", FILE_APPEND);
$L = smpro_lr_lessons();
smpro_lr_lesson_add($L, 'hash', $osha . ':' . filesize($own), 'self', ['path' => '/home/acct1/public_html/own.html', 'sha' => $osha, 'at' => time(), 'source' => 'quarantine']);
smpro_lr_lesson_add($L, 'hash', $osha . ':' . filesize($own), 'self', ['path' => '/home/acct1/public_html/own.html', 'sha' => $osha, 'at' => time(), 'source' => 'relearn']);
smpro_lr_save('lessons', $L);
is_eq(smpro_lr_verdict($own)['verdict'], 'clean', 'D1: a hash lesson whose only incidents are this file own quarantine / relearn does not make it malicious');
$L = smpro_lr_lessons();
smpro_lr_lesson_add($L, 'hash', $osha . ':' . filesize($own), 'self', ['path' => '/home/acct2/public_html/own.html', 'sha' => $osha, 'at' => time(), 'source' => 'quarantine']);
smpro_lr_save('lessons', $L);
is_eq(smpro_lr_verdict($own)['verdict'], 'clean', 'D2: ...nor one more quarantine of it elsewhere (one bulk selection of copies is one decision)');
$L = smpro_lr_lessons();
foreach (['acct3', 'acct4'] as $a) smpro_lr_lesson_add($L, 'hash', $osha . ':' . filesize($own), 'self', ['path' => '/home/' . $a . '/public_html/own.html', 'sha' => $osha, 'at' => time(), 'source' => 'quarantine']);
smpro_lr_save('lessons', $L);
$v = smpro_lr_verdict($own);
is_eq($v['verdict'], 'malicious', 'D2b: ...but the same file quarantined at three other places is a pattern, and counts');
ok(in_array('the same file was quarantined at 3 other places', $v['signs'], true), 'D2c: ...said as what it is, not as a "confirmed incident"');
$L = smpro_lr_lessons();
smpro_lr_lesson_add($L, 'hash', $osha . ':' . filesize($own), 'self', ['path' => '/home/acct9/public_html/own.html', 'sha' => $osha, 'at' => time(), 'source' => 'imunify cleanup']);
smpro_lr_save('lessons', $L);
ok(in_array('the exact file of an incident confirmed on this server', smpro_lr_verdict($own)['signs'], true), 'D2d: an incident that was not a quarantine (Imunify, a delete, a taught folder) is a confirmed one');
has($ln, "if (\$strong !== '') \$r['signs'][] = (strpos(\$strong, 'a ') === 0 ? \$strong : 'code that ' . \$strong);", 'D3: a sign reads as a sentence');
