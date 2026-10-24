#!/usr/bin/env bash
#
# obfuscate-and-package.sh - reproducible YAK Pro obfuscated release build of Safety Monitor Pro.
#
# Produces packaging/smpro-<VERSION>.tar.gz with the SAME layout the license server serves:
#   smpro-<VER>/install.sh
#   smpro-<VER>/README.md
#   smpro-<VER>/smpro/<obfuscated plugin>
#
# What it does:
#   1. obfuscates every .php with YAK Pro (string-scramble + control-flow; names PRESERVED because the
#      plugin dispatches by string - see smpro.cnf), 2. STRIPS the leaked "Obfuscated by YAK Pro" banner
#      (only the custom "protected build" comment remains - no obfuscator name shipped), 3. copies the
#      bash wrapper index.cgi as-is, 4. verifies (php -l on every file, no "yak" leak, gate is obfuscated),
#      5. packages with install.sh/README from the previous release.
#
# Usage: ./build/obfuscate-and-package.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"                       # plugin source root (smprov1_build)
YAK="${YAK:-$ROOT/../smpro_tools/yakpro-po}"
CNF="${CNF:-$ROOT/../smpro_tools/smpro.cnf}"
# Read the FULL SMPRO_VERSION value (incl. any -betaN.N suffix), not just the numeric X.Y.Z - the update/downgrade
# guard uses version_compare which understands beta suffixes, so betas must keep theirs end-to-end.
VER="$(sed -nE "s/.*SMPRO_VERSION',[[:space:]]*'([^']+)'.*/\1/p" "$ROOT/includes/defines.php" | head -1)"
[ -n "$VER" ] || { echo "ERROR: could not read SMPRO_VERSION"; exit 1; }
[ -f "$YAK/yakpro-po.php" ] || { echo "ERROR: yakpro-po not found at $YAK"; exit 1; }

# ═══════════════════════════════════════════════════════════════════════════════════════════════
#  RELEASE GATE 0 - the hermetic test lab MUST be GREEN against the EXACT source being packaged.
#  Principle: "every fixed bug becomes automatic protection in every build." A signed release tarball
#  cannot be born unless the full lab passes. The lab runs on the TEST box (ea-php82 + sandbox + the
#  physical production lockout) - it cannot run here on Windows and it cannot run on production, so the gate
#  ships the source to the lab and runs it there. Hard by default; emergency override is loud + recorded.
# ═══════════════════════════════════════════════════════════════════════════════════════════════
GATE_HOST="${SMPRO_LAB_HOST:-167.233.29.168}"
GATE_KEY="${SMPRO_LAB_KEY:-$HOME/.ssh/cpanel_audit_178_63_134_16}"
GATE_PORT="${SMPRO_LAB_PORT:-22}"
GATE_SRC="${SMPRO_LAB_SRC:-/opt/smpro-testlab/src}"
GATE_PHP="${SMPRO_LAB_PHP:-/opt/cpanel/ea-php82/root/usr/bin/php}"
GATE_SSH=(ssh -i "$GATE_KEY" -p "$GATE_PORT" -o StrictHostKeyChecking=no -o ConnectTimeout=15)
GATE_SUMMARY=""; GATE_STATE=""

run_release_gate() {
  echo "── RELEASE GATE: syncing source to lab ($GATE_HOST) + running full hermetic suite ──"
  # 0. EMPTY the lab source first. tar extraction OVERLAYS: it writes what the archive holds and leaves
  #    everything else in place, so any file that ever landed there stays forever. That bit us on 2026-08-23,
  #    when three test files from a different working copy sat in the directory and failed every build - but the
  #    dangerous direction is the opposite one: a stale MODULE left behind is tested and reported green while the
  #    tarball being packaged never contained it. The gate must prove the source it is about to ship, and only
  #    that, so the directory is rebuilt from nothing on every run.
  #    The path is checked before the delete: it must be an absolute path under /opt/smpro-testlab, so a mistyped
  #    or empty SMPRO_LAB_SRC can never turn this into a wipe of something else. Note /opt/smpro-testlab/samples
  #    sits OUTSIDE src and is deliberately preserved - it holds large fixtures that are expensive to re-fetch.
  case "$GATE_SRC" in
    /opt/smpro-testlab/src|/opt/smpro-testlab/src/*) : ;;
    *) echo "GATE ERROR: refusing to clean '$GATE_SRC' - it is not under /opt/smpro-testlab/src."; return 1 ;;
  esac
  if ! "${GATE_SSH[@]}" "root@$GATE_HOST" "rm -rf -- '$GATE_SRC' && mkdir -p '$GATE_SRC'"; then
    echo "GATE ERROR: could not prepare a clean source directory on the lab ($GATE_HOST:$GATE_SRC)."
    return 1
  fi
  # 1. push the EXACT source-to-be-packaged to the lab (raw set the build ships + tests/lang/assets)
  if ! tar czf - -C "$ROOT" index.cgi index.php includes modules bin cpuser lang assets tests packaging/install.sh 2>/dev/null \
       | "${GATE_SSH[@]}" "root@$GATE_HOST" "tar xzf - -C '$GATE_SRC'"; then
    echo "GATE ERROR: could not deploy source to lab ($GATE_HOST:$GATE_SRC) — is the TEST box reachable?"
    return 1
  fi
  # 1b. PROVE the lab received the whole tree before trusting anything it says about it.
  #     On 2026-08-30 a run reported 35 failures out of 94 assertions - out of 1693 - because the suite started
  #     against a tree that was still arriving. That reads exactly like a broken build, and the same source came
  #     back green seconds later. A partial tree is not a red build; it is nothing having been tested, and the two
  #     must never print the same. Compared as path+size over every file, so a truncated file is caught too, not
  #     just a missing one.
  local localMan remoteMan
  localMan="$(cd "$ROOT" && find index.cgi index.php includes modules bin cpuser lang assets tests packaging/install.sh -type f -print0 2>/dev/null               | xargs -0 stat -c '%n %s' 2>/dev/null | LC_ALL=C sort | sha256sum | cut -d' ' -f1)"
  remoteMan="$("${GATE_SSH[@]}" "root@$GATE_HOST" "cd '$GATE_SRC' && find index.cgi index.php includes modules bin cpuser lang assets tests packaging/install.sh -type f -print0 2>/dev/null | xargs -0 stat -c '%n %s' 2>/dev/null | LC_ALL=C sort | sha256sum | cut -d' ' -f1" 2>/dev/null)"
  if [ -z "$remoteMan" ] || [ "$localMan" != "$remoteMan" ]; then
    echo "GATE ERROR: the source on the lab does not match what was sent — the tree arrived incomplete, so"
    echo "            NOTHING was tested. This is not a red build. Re-run; if it repeats, check the link to"
    echo "            $GATE_HOST."
    echo "            sent:     ${localMan:-<could not compute>}"
    echo "            received: ${remoteMan:-<could not read>}"
    return 1
  fi

  # 2. run the lab; exit 0 == GREEN (run.php: exit non-zero on any fail/crash/timeout/plan-mismatch)
  # The suite's OWN exit code is carried back in a sentinel line rather than read from ssh. ssh reports its own
  # failures as 255, so a dropped connection arrived here indistinguishable from a test run that failed - and the
  # gate announced "the test lab is RED", sending the reader to hunt for a broken test that did not exist. A run
  # that could not happen and a run that failed are different facts and now print differently. stderr is kept for
  # the same reason: it holds the sentence saying which of the two occurred.
  local out rc suiteRc
  out="$("${GATE_SSH[@]}" "root@$GATE_HOST" "$GATE_PHP '$GATE_SRC/tests/smpro_test.php'; echo \"__SMPRO_SUITE_RC__=\$?\"" 2>&1)"; rc=$?
  suiteRc="$(printf '%s\n' "$out" | sed -n 's/^__SMPRO_SUITE_RC__=\([0-9]\{1,\}\)$/\1/p' | tail -1)"
  GATE_SUMMARY="$(printf '%s\n' "$out" | sed 's/\x1b\[[0-9;]*m//g' | grep -E 'assertions:' | tail -1)"
  printf '%s\n' "$out" | sed 's/\x1b\[[0-9;]*m//g' | grep -v '^__SMPRO_SUITE_RC__=' | tail -3
  if [ -z "$suiteRc" ]; then
    echo "GATE ERROR: the suite never reported a result (ssh exit $rc) - the lab was NOT reached, so nothing was"
    echo "            tested. This is not a red build: no test failed, none ran. Check $GATE_HOST is reachable."
    return 1
  fi
  if [ "$suiteRc" -ne 0 ]; then echo "GATE FAIL: the test lab is RED (suite exit $suiteRc) - refusing to build a release."; return 1; fi
  echo "GATE PASS: lab GREEN — $GATE_SUMMARY"
  return 0
}

if [ "${SMPRO_GATE_OVERRIDE:-0}" = "1" ]; then
  echo
  echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
  echo "!! SMPRO_GATE_OVERRIDE=1 — BUILDING WITHOUT THE TEST-LAB GATE.               !!"
  echo "!! This release will NOT be proven green. Emergency/offline use ONLY.         !!"
  echo "!! The gate receipt will record lab=overridden so promote can refuse it.      !!"
  echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
  echo
  GATE_SUMMARY="OVERRIDDEN (lab not run)"; GATE_STATE="overridden"
else
  run_release_gate || { echo; echo "BUILD ABORTED by release gate. Fix the lab, or set SMPRO_GATE_OVERRIDE=1 to force (not recommended)."; exit 8; }
  GATE_STATE="green"
fi

WORK="$ROOT/_obf"; SRC="$WORK/src"; STAGE="$WORK/stage"; PKG="$WORK/pkg"
echo "Building obfuscated release smpro-$VER"
rm -rf "$WORK"; mkdir -p "$SRC" "$PKG"

# 1. stage the php-bearing trees (index.cgi is bash -> copied later, not obfuscated)
# The account-side detection file is derived from includes/phstack.php. Regenerated here so a release can never
# carry a copy that drifted from the source it was generated from.
if [ -f "$ROOT/build/gen-cpuser-stack.php" ]; then
  php "$ROOT/build/gen-cpuser-stack.php" || { echo "ERROR: could not generate cpuser/stack.php"; exit 2; }
fi

cp -r "$ROOT/index.php" "$ROOT/includes" "$ROOT/modules" "$ROOT/bin" "$SRC/"
# cpuser/ is the account-side page cPanel serves - Safety Lock. It is part of THIS product and is staged like
# everything else so it is obfuscated and signed with the rest. It used to be built into a SEPARATE package on a
# separate channel, which meant a server running the account-side plugin could not take a WHM release at all: the
# release genuinely did not contain Safety Lock, so installing it would have removed working protection. The
# edition guard that refused those installs was right; the package was what was wrong.
[ -d "$ROOT/cpuser" ] && cp -r "$ROOT/cpuser" "$SRC/"

# 2. obfuscate (creates $STAGE/yakpro-po mirroring $SRC)
# memory_limit raised: the PHP-Parser AST for the largest modules (spam-phishing.php etc.) exceeds the 128M default.
php -d memory_limit=1024M "$YAK/yakpro-po.php" --config-file "$CNF" "$SRC" -o "$STAGE" >/dev/null
OBF="$STAGE/yakpro-po/obfuscated"
[ -f "$OBF/index.php" ] || { echo "ERROR: obfuscation produced no output"; exit 2; }

# 3. strip the YAK Pro banner block (keep the custom 'protected build' comment)
while IFS= read -r -d '' f; do
  perl -0777 -i -pe 's{/\*.*?Obfuscated by YAK Pro.*?\*/\s*}{}s' "$f"
done < <(find "$OBF" -name '*.php' -print0)

# 4. copy non-php as-is + recreate the (empty) asset/lang dirs the loader expects
cp "$ROOT/index.cgi" "$OBF/"
mkdir -p "$OBF/assets" "$OBF/lang"

# 4b. signed integrity manifest - hashes the FINAL shipped files + signs with the OFFLINE key.
#     The plugin verifies it in-process with the embedded public key (Protected Mode on tamper).
PRIV="${PRIV:-$HOME/smpro_keys/smpro_update_private.pem}"
[ -f "$PRIV" ] || { echo "ERROR: private key not found: $PRIV"; exit 6; }
php "$HERE/gen-manifest.php" "$OBF" "$PRIV" "$VER"
[ -f "$OBF/integrity.json" ] || { echo "ERROR: integrity manifest not generated"; exit 6; }

# 5. verify
echo ">> php -l on every obfuscated file"
while IFS= read -r -d '' f; do
  php -l "$f" >/dev/null 2>&1 || { echo "LINT FAIL: $f"; php -l "$f"; exit 3; }
done < <(find "$OBF" -name '*.php' -print0)

# Match the ACTUAL banner words - NOT bare "yak" (random goto labels like "evyak" are false positives).
echo ">> no obfuscator-name leak"
if grep -rlE 'YAK Pro|yakpro-po|Obfuscated by' "$OBF" >/dev/null 2>&1; then
  echo "!! obfuscator banner found:"; grep -rlE 'YAK Pro|yakpro-po|Obfuscated by' "$OBF"; exit 4
fi

# YAK Pro keeps function/const NAMES readable on purpose (the plugin dispatches by string), so the
# real "is it obfuscated" signal is scrambled string literals (\xNN) + control-flow (goto), NOT missing
# names. Require both in the gate file; also require the original plaintext docblock to be GONE.
echo ">> gate must be obfuscated (scrambled strings + control-flow present, plaintext docblock gone)"
if ! grep -qsE '\\x[0-9a-fA-F]{2}' "$OBF/includes/license.php" || ! grep -qs 'goto ' "$OBF/includes/license.php"; then
  echo "!! license.php does not look obfuscated (no hex strings / goto)"; exit 5
fi
if grep -qs 'Talks to the AITECH_LICENSE server' "$OBF/includes/license.php"; then
  echo "!! plaintext docblock still present in license.php"; exit 5
fi

# Constructs that reach a variable by its NAME AT RUNTIME. The obfuscator renames variables but leaves the
# strings naming them untouched, so compact()/extract()/$$var keep asking for names that no longer exist. They
# do not error - compact() just returns an empty array - so the built plugin renders blank rows while the test
# suite, which runs on the source, stays green. This shipped: Database Health counted five problems and showed
# five empty boxes. Comments are stripped by obfuscation, so a hit here is a hit in real code.
echo ">> no name-at-runtime variable access in the obfuscated output"
# --include=*.php: the bundled cpulimit binary contains these byte sequences by chance.
if grep -rnE --include='*.php' 'compact[[:space:]]*\(|extract[[:space:]]*\(|\$\$[A-Za-z_]' "$OBF" >/dev/null 2>&1; then
  echo "!! compact()/extract()/\$\$var survived into the build — obfuscation renames variables but not these"
  echo "   name strings, so they silently resolve to nothing. Write the array out key by key instead:"
  grep -rnE --include='*.php' 'compact[[:space:]]*\(|extract[[:space:]]*\(|\$\$[A-Za-z_]' "$OBF" | head -20
  exit 6
fi

# A resale product may not carry one operator's world: no server name, no customer account, no public IP outside
# the vendor allow-list, no email, no "home country" default. This ran as a one-off audit on 2026-09-06 and found
# a fresh install still defaulting its home region to two specific countries, and fixtures with real customer
# accounts and the production server's own IP. A rule that is only checked by hand is a hope; this makes it a
# gate. build/hardcode-allow.txt lists the vendors that MAY be named. Runs on the SOURCE tree (identities in a
# comment are stripped by obfuscation anyway, so the source is the honest place to look).
echo ">> no CR line endings in shell-executed files (a CRLF shebang = cpsrvd 500 on every WHM page; shipped in 1.1.8)"
for f in "$ROOT/index.cgi" "$ROOT/packaging/install.sh" "$ROOT/packaging/uninstall.sh" "$ROOT"/bin/*.sh; do
  [ -f "$f" ] || continue
  if grep -q $'\r' "$f"; then echo "FAIL: $f has CR line endings - run dos2unix / save as LF"; exit 9; fi
done
# JS SYNTAX GATE - every inline <script> in modules/ and includes/ must parse (beta294 shipped a page whose whole
# script was dead because of one bare line break inside a string; nothing at build time noticed).
if command -v node >/dev/null 2>&1; then
  node "$ROOT/build/jscheck.js" "$ROOT" || { echo "BUILD ABORTED: an inline script does not parse (see above)"; exit 8; }
else
  echo "!! node not found — the inline-JS syntax gate CANNOT RUN; refusing to build rather than skipping the check"; exit 8
fi
echo ">> no hardcoded identities / market defaults in shipped source"
# Pick an interpreter that actually EXECUTES: on Windows, "python3" can be a Store alias that prints an install
# hint and exits non-zero - which, read as a gate failure, would announce a leak that nobody planted. So each
# candidate must run a no-op first, and the gate's own exit code is the ONLY thing that means "leak" (6).
PYBIN=""
for c in python3 python; do
  if command -v "$c" >/dev/null 2>&1 && "$c" -c "pass" >/dev/null 2>&1; then PYBIN="$c"; break; fi
done
if [ -z "$PYBIN" ]; then echo "!! no working python — the hardcode gate CANNOT RUN; refusing to build rather than skipping the check"; exit 7; fi
PYTHONIOENCODING=utf-8 "$PYBIN" "$ROOT/build/hardcode-gate.py"; hc=$?
if [ "$hc" -eq 6 ]; then echo "BUILD ABORTED: shipped source names a real identity or a market default (see above)."; exit 7; fi
if [ "$hc" -ne 0 ]; then echo "BUILD ABORTED: the hardcode gate could not run (exit $hc) — nothing was checked; this is not a leak, fix the gate."; exit 7; fi

# 6. package: smpro-<VER>/{install.sh,README.md,smpro/...}
DEST="$PKG/smpro-$VER"; mkdir -p "$DEST/smpro"
cp -r "$OBF/." "$DEST/smpro/"
# The icon is not PHP, so obfuscation never saw it - without this the cPanel entry has no icon.
if [ -d "$ROOT/cpuser" ]; then
  mkdir -p "$DEST/smpro/cpuser"
  find "$ROOT/cpuser" -maxdepth 1 -type f ! -name '*.php' -exec cp -f {} "$DEST/smpro/cpuser/" \;
fi
# Ship install.sh / README.md / uninstall.sh from SOURCE CONTROL (never from a prior tarball) so the root-run
# installer always matches the current source - otherwise security fixes to the installer silently never ship,
# and each release inherits the previous (stale) installer. Hard-fail if a source file is missing.
for f in install.sh README.md uninstall.sh; do
  [ -f "$ROOT/packaging/$f" ] || { echo "ERROR: packaging/$f missing from source — cannot build"; exit 7; }
  cp "$ROOT/packaging/$f" "$DEST/"
done
tar czf "$ROOT/packaging/smpro-$VER.tar.gz" -C "$PKG" "smpro-$VER"
echo
echo "DONE: packaging/smpro-$VER.tar.gz"
echo "  files: $(tar tzf "$ROOT/packaging/smpro-$VER.tar.gz" | wc -l)"

# 7. ALWAYS sign the release tarball (offline key) so the .sig can never be forgotten before publishing.
PRIV="${PRIV:-$HOME/smpro_keys/smpro_update_private.pem}"
if [ -f "$HERE/sign-release.sh" ] && [ -f "$PRIV" ]; then
  echo; bash "$HERE/sign-release.sh" "$ROOT/packaging/smpro-$VER.tar.gz" "$PRIV" "${PUB:-$HOME/smpro_keys/smpro_update_public.pem}"
else
  echo "WARNING: release NOT signed (sign-release.sh or private key missing) — sign before publishing!"
fi

# 8. GATE RECEIPT - provenance that THIS exact tarball passed the lab + obf-lint. The promote step
#    (build/gate-check.sh) refuses to publish any tarball whose receipt is missing, not-green, or whose
#    sha256 does not match - so a hand-rolled or untested tarball can never reach customers.
SHA="$(sha256sum "$ROOT/packaging/smpro-$VER.tar.gz" | awk '{print $1}')"
cat > "$ROOT/packaging/smpro-$VER.gate.json" << JSON
{
  "version": "$VER",
  "tarball": "smpro-$VER.tar.gz",
  "sha256": "$SHA",
  "lab": "$GATE_STATE",
  "lab_summary": "$GATE_SUMMARY",
  "obf_lint": "pass",
  "built_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "build_host": "$(hostname 2>/dev/null || echo unknown)"
}
JSON
echo "Gate receipt: packaging/smpro-$VER.gate.json (lab=$GATE_STATE)"
