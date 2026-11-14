#!/bin/bash
# Puts server/install-remote.sh in place as the public first-install script. The old one is kept under _backups.
# Local settings (release host + key) come from ~/.smpro-build.env.
set -e
. "$HOME/.smpro-build.env"
HERE="$(cd "$(dirname "$0")" && pwd)"
tr -d '\r' < "$HERE/install-remote.sh" | ssh -i "$SMPRO_LIC_KEY" "root@$SMPRO_LIC_HOST" 'P=/opt/aitech-license-server/public; B=/opt/aitech-license-server/_backups/install_$(date +%Y%m%d_%H%M%S); mkdir -p $B && cp -a $P/install.sh $B/ && cat > $P/install.sh.new && bash -n $P/install.sh.new && chown --reference=$P/install.sh $P/install.sh.new && chmod --reference=$P/install.sh $P/install.sh.new && mv -f $P/install.sh.new $P/install.sh && echo "deployed; backup $B"'
