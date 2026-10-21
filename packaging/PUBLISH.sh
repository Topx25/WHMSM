#!/usr/bin/env bash
# Publish a built release.   Usage:  ./PUBLISH.sh <version> [--stable]     e.g. ./PUBLISH.sh 1.1.5
#
# BETA IS THE DEFAULT, AND STABLE NEEDS ASKING FOR.
#
# This script used to write BOTH channel pointers on every run: one command, and every licensee on the stable
# channel was moved onto whatever had just been built. the release rules say in two places that stable moves only on the
# owner's explicit word and that an agent never moves it alone — and the script made obeying that impossible,
# because there was no way to publish a beta WITHOUT also moving stable. Nine beta builds went to stable that way
# before anybody noticed, and the only reason nobody was hurt is that the channels already pointed at the same
# build.
#
# A rule the tooling cannot express is not a rule. So the default publishes the beta channel only, and stable
# waits for --stable.
#
# This replaced four near-identical PUBLISH-<version>.sh scripts. They were the hazard: every one of them still
# ran, and the tarball each referred to was still on disk, so running an old one by mistake would have quietly
# REPLACED stable with an older release — a downgrade for every licensee, reported as a successful publish.
# One script, one argument, and the version can no longer be stale by accident.
#
# Before publishing, check the release really is newer than what stable serves. That check is enforced below:
# publishing an older version requires --rollback, so a downgrade has to be something you meant.
set -euo pipefail

VER="${1:-}"
if [ -z "$VER" ] || [ "$VER" = "-h" ] || [ "$VER" = "--help" ]; then
  echo "usage: $0 <version> [--stable] [--rollback]"
  echo "  e.g. $0 1.1.5                    publish to the BETA channel (the default)"
  echo "       $0 1.1.5 --stable           ALSO move every licensee on stable onto it"
  echo "       $0 1.1.3 --stable --rollback deliberately put an OLDER release back on stable"
  exit 2
fi
case "$VER" in
  *[!0-9.a-zA-Z-]*) echo "refusing: '$VER' does not look like a version."; exit 2 ;;
esac
ALLOW_DOWNGRADE=0
PUBLISH_STABLE=0
for arg in "${@:2}"; do
  case "$arg" in
    --rollback) ALLOW_DOWNGRADE=1 ;;
    --stable)   PUBLISH_STABLE=1 ;;
    *) echo "refusing: unknown option '$arg'"; exit 2 ;;
  esac
done
CHANNEL="beta"
[ "$PUBLISH_STABLE" -eq 1 ] && CHANNEL="beta+STABLE"


KEY="${SMPRO_LIC_KEY:-$HOME/.ssh/cpanel_audit_178_63_134_16}"
HOST="${SMPRO_LIC_HOST:-136.243.211.154}"
DIR="/opt/aitech-license-server/releases"

TGZ="smpro-$VER.tar.gz"
SIG="$TGZ.sig"
NOTES="smpro-$VER.RELEASE-NOTES.txt"
RECEIPT="smpro-$VER.gate.json"

for f in "$TGZ" "$SIG" "$NOTES" "$RECEIPT"; do
  [[ -f "$f" ]] || { echo "missing: $f"; exit 1; }
done

# The gate must have passed for THIS artifact. A build made with the gate overridden records lab=overridden and
# is refused here — stable is not the place to find out the suite was skipped.
LAB="$(php -r 'echo json_decode(file_get_contents($argv[1]),true)["lab"] ?? "";' "$RECEIPT")"
SHA="$(php -r 'echo json_decode(file_get_contents($argv[1]),true)["sha256"] ?? "";' "$RECEIPT")"
[[ "$LAB" == "green" ]] || { echo "receipt says lab=$LAB — refusing to publish."; exit 1; }

LOCAL="$(sha256sum "$TGZ" | cut -d' ' -f1)"
[[ "$LOCAL" == "$SHA" ]] || { echo "the tarball does not match its receipt — refusing."; exit 1; }
echo "receipt ok: lab=green  sha=$SHA"

# Refuse a silent downgrade. `sort -V` puts the two versions in order; if the one being published is not the
# later of the two, this is a rollback and must be asked for by name.
# The guard runs against the channel actually being written. A beta that goes backwards is a downgrade for
# everybody testing on beta, which is a smaller blast radius than stable and still not something to do by accident.
VFILE="VERSION_BETA"; WHAT="beta"
if [ "$PUBLISH_STABLE" -eq 1 ]; then VFILE="VERSION"; WHAT="stable"; fi
CUR="$(ssh -i "$KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=30 "root@$HOST" "cat '$DIR/$VFILE' 2>/dev/null" || true)"
CUR="$(printf '%s' "$CUR" | tr -d '[:space:]')"
if [ -n "$CUR" ] && [ "$CUR" != "$VER" ]; then
  NEWER="$(printf '%s
%s
' "$CUR" "$VER" | sort -V | tail -1)"
  if [ "$NEWER" != "$VER" ] && [ "$ALLOW_DOWNGRADE" -ne 1 ]; then
    echo "REFUSING: $WHAT currently serves $CUR, and $VER is older."
    echo "          Publishing it would downgrade every licensee on that channel. If that is what you want, pass --rollback."
    exit 1
  fi
  [ "$ALLOW_DOWNGRADE" -eq 1 ] && echo "ROLLBACK: $WHAT serves $CUR, deliberately going back to $VER."
fi
echo "$WHAT now: ${CUR:-unknown}  ->  publishing: $VER"
if [ "$PUBLISH_STABLE" -eq 1 ]; then
  echo
  echo "  *** --stable given: this moves EVERY licensee on the stable channel onto $VER. ***"
  echo
fi

# A version number is a promise about bytes. Two builds of the same source are not byte-identical (timestamps, the
# obfuscator's ordering), so a rebuild after a publish leaves a local tarball that passes its own receipt and would
# silently replace what licensees already took - same version, different bytes, and no way afterwards to say which
# one a server is running. Refuse that. Re-publishing the IDENTICAL bytes (to repair a partial upload) still works.
SERVED="$(ssh -i "$KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=45 "root@$HOST" \
  "cd '$DIR' 2>/dev/null && [ \"\$(cat '$VFILE' 2>/dev/null | tr -d '[:space:]')\" = '$VER' ] && sha256sum '$TGZ' 2>/dev/null | cut -d' ' -f1" 2>/dev/null | tr -d '[:space:]')"
if [ -n "$SERVED" ] && [ "$SERVED" != "$SHA" ]; then
  echo "REFUSING: $VER is already served from $HOST with DIFFERENT bytes."
  echo "          served: $SERVED"
  echo "          local : $SHA"
  echo "          The local tarball was rebuilt after that publish. Cut a new version number instead;"
  echo "          never let one version mean two different builds. (To re-upload the served build, fetch it"
  echo "          back into packaging/ first.)"
  exit 1
fi

echo "publishing $VER to $CHANNEL on $HOST …"
tar cf - "$TGZ" "$SIG" "$NOTES" | ssh -i "$KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=45 \
  -o ServerAliveInterval=10 "root@$HOST" "
set -e
cd '$DIR'
tar xf -
a=\$(sha256sum '$TGZ' | cut -d' ' -f1)
if [ \"\$a\" != '$SHA' ]; then echo 'HASH MISMATCH AFTER UPLOAD'; exit 1; fi

PUBLISH_STABLE='$PUBLISH_STABLE'

# Keep what stable is serving today, so a rollback is a copy rather than a rebuild.
# Only when it is a DIFFERENT release. Re-publishing the version already on stable (to repair a partial upload,
# or to re-push a rebuilt package) used to copy it over smpro-prev — which threw away the one release you would
# roll back TO and replaced it with the one you are rolling back FROM. The rollback target then pointed at the
# same build as stable, and nobody would find that out until the rollback was needed.
if [ \"\$PUBLISH_STABLE\" = '1' ]; then
  if [ \"\$(cat VERSION 2>/dev/null | tr -d '[:space:]')\" != '$VER' ]; then
    [ -f smpro-latest.tar.gz ] && cp -f smpro-latest.tar.gz smpro-prev.tar.gz
    [ -f smpro-latest.tar.gz.sig ] && cp -f smpro-latest.tar.gz.sig smpro-prev.tar.gz.sig
    [ -f VERSION ] && cp -f VERSION VERSION.prev
  else
    echo \"re-publishing the same version — rollback target left at \$(cat VERSION.prev 2>/dev/null)\"
  fi

  cp -f '$TGZ' smpro-latest.tar.gz
  cp -f '$SIG'  smpro-latest.tar.gz.sig
  echo '$VER' > VERSION
fi

# The BETA payload moves with its version file. Writing the version alone is what left the cPanel-user channel
# saying beta193 while the tarball was still beta191: a box on the beta channel downloaded, installed and
# reported beta191 over and over, while the panel offered beta193 and the update looked like it kept failing. A
# version file that promises a payload the channel does not carry is worse than having no beta channel at all.
# This channel had the same gap; it only never bit because beta files here were copied by hand each time.
cp -f '$TGZ' smpro-beta.tar.gz
cp -f '$SIG'  smpro-beta.tar.gz.sig
echo '$VER' > VERSION_BETA
# The notes follow the channel they belong to. This wrote only NOTES_STABLE.txt, and the licence server serves
# NOTES_BETA.txt to the beta channel — so the beta notes were last written on 9 September for beta190 and sat
# there unchanged through thirty-nine releases, while NOTES_STABLE.txt filled up with notes whose own first line
# said it was for the beta channel. Both channels described a release nobody was running.
cp -f '$NOTES' NOTES_BETA.txt
if [ \"\$PUBLISH_STABLE\" = '1' ]; then cp -f '$NOTES' NOTES_STABLE.txt; fi

echo \"served : \$(sha256sum smpro-beta.tar.gz | cut -d' ' -f1)\"
echo \"BETA   : \$(cat VERSION_BETA)\"
if [ \"\$PUBLISH_STABLE\" = '1' ]; then
  echo \"STABLE : \$(cat VERSION)\"
  echo \"rollback: cp -f smpro-prev.tar.gz smpro-latest.tar.gz && cp -f VERSION.prev VERSION\"
else
  echo \"STABLE : \$(cat VERSION 2>/dev/null) (UNTOUCHED - pass --stable to move it)\"
fi
"

# Publish the readable source to the private repository. Never fails the release.
bash "$(dirname "$0")/push-source.sh" "$VER" || echo "source push did not complete (the release itself is fine)"
