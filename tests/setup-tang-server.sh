#!/usr/bin/env bash
# setup-tang-server.sh — Set up a Tang server for testing Clevis auto-unlock.
#
# Usage: sudo ./tests/setup-tang-server.sh [--port PORT] [--remove]
#
# Run this on a separate Debian VM (not the OMV system under test).  It
# installs tang, listens on PORT (default 80), makes sure signing keys exist
# and prints the TANG_URL and key thumbprint to use with test-rpc.sh:
#
#   sudo TANG_URL=http://<this-vm>:<port> ./tests/test-rpc.sh
#
# --remove stops tang, purges the package and deletes its keys.

set -euo pipefail

PORT=80
REMOVE=0

while [ $# -gt 0 ]; do
    case "$1" in
        --port)   PORT=${2:?--port needs a value}; shift 2 ;;
        --remove) REMOVE=1; shift ;;
        -h|--help) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "Must be run as root." >&2
    exit 1
fi
if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
    echo "Invalid port: $PORT" >&2
    exit 1
fi

DROPIN_DIR=/etc/systemd/system/tangd.socket.d
DROPIN=$DROPIN_DIR/port.conf
KEY_DIR=/var/lib/tang

if [ "$REMOVE" -eq 1 ]; then
    systemctl disable --now tangd.socket >/dev/null 2>&1 || true
    rm -f "$DROPIN"
    rmdir "$DROPIN_DIR" 2>/dev/null || true
    systemctl daemon-reload
    DEBIAN_FRONTEND=noninteractive apt-get purge -y tang
    rm -rf "$KEY_DIR"
    echo "Tang removed."
    exit 0
fi

echo "» Installing tang and curl ..."
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq tang curl jq >/dev/null

# tangd.socket listens on port 80 by default; override it if asked.
if [ "$PORT" -ne 80 ]; then
    echo "» Setting tangd.socket to listen on port $PORT ..."
    mkdir -p "$DROPIN_DIR"
    cat > "$DROPIN" <<EOF
[Socket]
ListenStream=
ListenStream=$PORT
EOF
else
    rm -f "$DROPIN"
fi
systemctl daemon-reload

# Tang creates its keys on first request, but generate them up front so the
# thumbprint can be printed now.
if ! ls "$KEY_DIR"/*.jwk >/dev/null 2>&1; then
    echo "» Generating signing and exchange keys ..."
    mkdir -p "$KEY_DIR"
    keygen=$(dpkg -L tang | grep '/tangd-keygen$' | head -1 || true)
    if [ -n "$keygen" ]; then
        "$keygen" "$KEY_DIR"
        chown -R _tang:_tang "$KEY_DIR" 2>/dev/null || true
    fi
fi

echo "» Enabling tangd.socket ..."
systemctl enable tangd.socket >/dev/null 2>&1
systemctl restart tangd.socket

# Verify the server answers with an advertisement.
echo "» Checking http://localhost:$PORT/adv ..."
if ! curl -fsS "http://localhost:$PORT/adv" | jq -e .payload >/dev/null; then
    echo "Tang did not return an advertisement on port $PORT." >&2
    systemctl status tangd.socket --no-pager >&2 || true
    exit 1
fi

THP=$(tang-show-keys "$PORT" 2>/dev/null | head -1 || true)
IP=$(hostname -I | awk '{ print $1 }')
URL="http://$IP"
[ "$PORT" -ne 80 ] && URL="$URL:$PORT"

cat <<EOF

Tang server is running.

  URL:         $URL
  Thumbprint:  ${THP:-<unknown; run tang-show-keys $PORT>}

On the OMV system:

  sudo TANG_URL=$URL ./tests/test-rpc.sh

In the web UI, use the URL above as "Tang server URL" and optionally the
thumbprint as "Tang key thumbprint".

If a firewall is active on this VM, allow TCP port $PORT.
To simulate the Tang server being unreachable: systemctl stop tangd.socket
EOF
