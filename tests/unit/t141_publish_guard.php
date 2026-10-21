<?php
require __DIR__ . '/../support/bootstrap.php';
/** t141 - a version number is a promise about bytes. Two builds of the same source are never byte-identical, so a
 *  rebuild after a publish leaves a tarball that passes its own receipt and would quietly replace what licensees
 *  already took: same version, different build, and no way afterwards to say which one a server runs. */
$p = SMPRO_BASE . '/packaging/PUBLISH.sh';
if (!is_file($p)) { tap_skip('t141 publish guard', 'packaging/PUBLISH.sh is not in this tree (the lab copy carries no build scripts)'); return; }
$s = str_replace(chr(13), '', (string)file_get_contents($p));
has($s, 'REFUSING: $VER is already served from $HOST with DIFFERENT bytes.', 'G1: publishing different bytes under a version already served is refused');
has($s, 'if [ -n "$SERVED" ] && [ "$SERVED" != "$SHA" ]; then', 'G2: the refusal compares what the server serves with what is about to be sent');
has($s, 'exit 1', 'G3: and it stops, rather than warning and carrying on');
// the check must read the version the server actually serves for THIS channel, not assume it
has($s, '[ \\"\\$(cat \'$VFILE\' 2>/dev/null | tr -d \'[:space:]\')\\" = \'$VER\' ]', 'G4: the comparison only applies when the server is serving this very version');
// an identical re-upload (repairing a partial publish) must still be allowed
$i = strpos($s, 'if [ -n "$SERVED" ]');
$cond = substr($s, $i, 120);
has($cond, '"$SERVED" != "$SHA"', 'G5: identical bytes are still allowed through, so a partial upload can be repaired');
// and the guard must run BEFORE anything is uploaded
$iGuard = strpos($s, 'REFUSING: $VER is already served');
$iUp = strpos($s, 'echo "publishing $VER to $CHANNEL on $HOST');
ok($iGuard !== false && $iUp !== false && $iGuard < $iUp, 'G6: the refusal happens before the upload starts');
hasnt($s, "\r", 'G7: the publish script stays LF (it is executed by a shell)');
