#!/bin/bash
# Generate rnsd config from environment variables and exec rnsd.
set -e

CONFIG_DIR="/etc/rnsd"
mkdir -p "$CONFIG_DIR"

IFAC_LINE=""
if [ -n "$RNSD_IFAC_NETNAME" ]; then
    IFAC_LINE="
    networkname = $RNSD_IFAC_NETNAME"
fi

cat > "$CONFIG_DIR/config" <<EOF
[reticulum]
  enable_transport = yes
  share_instance = ${RNSD_SHARE_INSTANCE:-no}

[logging]
  loglevel = ${RNSD_LOGLEVEL:-5}

[interfaces]

  [[TCP Server Interface]]
    type = TCPServerInterface
    enabled = yes
    listen_ip = 0.0.0.0
    listen_port = ${RNSD_PORT:-4242}${IFAC_LINE}
EOF

exec rnsd --config "$CONFIG_DIR"
