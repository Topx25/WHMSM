#!/bin/bash
# Applies server/apply_signed_refusals.php on the licence server (backup + lint inside the script).
# Local settings (release host + key) come from ~/.smpro-build.env.
set -e
. "$HOME/.smpro-build.env"
HERE="$(cd "$(dirname "$0")" && pwd)"
tr -d '\r' < "$HERE/apply_signed_refusals.php" | ssh -i "$SMPRO_LIC_KEY" "root@$SMPRO_LIC_HOST" 'cat > /root/sr_apply.php && php /root/sr_apply.php; rm -f /root/sr_apply.php'
