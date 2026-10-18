#!/bin/bash
# push-source.sh <version> — commit and push the readable source after a successful release publish.
# Never force-pushes. Refuses (and says why) when the tree carries a private key, a release artifact,
# or an assistant reference. A failure here never fails the release itself (PUBLISH.sh ignores our exit code).
set -u
V="${1:-unversioned}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT" || exit 1
LOG="$ROOT/.git/push-source.log"
log() { echo "$(date '+%F %T') $*" | tee -a "$LOG"; }

git rev-parse --is-inside-work-tree >/dev/null 2>&1 || { log "not a git repo - skipped"; exit 0; }
git add -A
if git diff --cached --quiet; then log "$V: nothing new to push"; exit 0; fi

# 1) guards: nothing sensitive or assistant-related may go out
bad=0
if git diff --cached -U0 | grep -E '^\+.*-----BEGIN [A-Z ]*PRIVATE KEY-----' >/dev/null; then log "REFUSED: a private key is in the change"; bad=1; fi
if git diff --cached --name-only | grep -E '(^|/)(_obf|_obf_src|_obf_out|_pkg)/|\.(tar\.gz|sig)$|\.gate\.json$|RELEASE-NOTES|(^|/)C[L]AUDE[.]md$' >/dev/null; then log "REFUSED: a build artifact or assistant file is in the change"; bad=1; fi
if git diff --cached -U0 | grep -E '^\+.*(C[L]AUDE[.]md|Co-Author[e]d-By|Generated with [[]?C[l]aude|c[l]aude[.]com/c[l]aude-code)' >/dev/null; then log "REFUSED: an assistant reference is in the change"; bad=1; fi
if [ "$bad" = 1 ]; then git reset -q; log "$V: not pushed - fix the change and publish again"; exit 1; fi

# 2) commit (no assistant trailer) and push, never forced
git -c user.name="SM Pro" -c user.email="noreply@topx25.local" commit -q -m "SM Pro source $V

Source of Safety Monitor Pro at release $V. Build output, packages, signatures and keys are not part of the repository." \
  || { log "$V: commit failed"; exit 1; }
if timeout 300 git push -q origin HEAD:main 2>>"$LOG"; then
  log "$V: pushed $(git rev-parse --short HEAD) to origin/main"
else
  log "$V: push FAILED (commit kept locally; it will go with the next release)"; exit 1
fi
