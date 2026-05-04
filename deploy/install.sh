#!/bin/bash
# Installs the Goloom WG transport-proxy server as a systemd service.
#
# Run from the directory that contains:
#   - goloom-wg-server                (the binary; see ../README.md to build)
#   - goloom-wg-server.yaml           (config — copy goloom-wg-server.yaml.example)
#   - deploy/goloom-wg-server.service (systemd unit; this script copies it)
#
# Prereqs:
#   - WireGuard kernel module + wg-quick (apt install wireguard)
#   - At least one wg interface (typically /etc/wireguard/wg0.conf) up
#     so the unit's `Requires=wg-quick@wg0.service` is satisfied
#   - net.ipv4.ip_forward=1 in /etc/sysctl.conf
#   - iptables MASQUERADE for the per-inbound subnets you intend to route

set -euo pipefail

INSTALL_DIR="/opt/goloom"
SERVICE_NAME="goloom-wg-server"
BINARY="goloom-wg-server"
CONFIG="goloom-wg-server.yaml"

echo "=== ${SERVICE_NAME} installer ==="

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: run as root"
    exit 1
fi

mkdir -p "${INSTALL_DIR}"

if [ -f "${BINARY}" ]; then
    cp "${BINARY}" "${INSTALL_DIR}/${BINARY}"
    chmod +x "${INSTALL_DIR}/${BINARY}"
    echo "  binary → ${INSTALL_DIR}/${BINARY}"
else
    echo "ERROR: ${BINARY} not found in current directory."
    echo "       Build it from the repo root: go build -o ${BINARY} ./cmd/goloom-wg-server"
    exit 1
fi

if [ ! -f "${INSTALL_DIR}/${CONFIG}" ]; then
    if [ -f "${CONFIG}" ]; then
        cp "${CONFIG}" "${INSTALL_DIR}/${CONFIG}"
        echo "  config → ${INSTALL_DIR}/${CONFIG}"
    else
        echo "WARN:   no ${CONFIG} found in current directory."
        echo "        Copy goloom-wg-server.yaml.example, edit, place at ${INSTALL_DIR}/${CONFIG}."
    fi
else
    echo "  config exists, skipping"
fi

cp "deploy/${SERVICE_NAME}.service" "/etc/systemd/system/${SERVICE_NAME}.service"
systemctl daemon-reload
systemctl enable "${SERVICE_NAME}"
echo "  systemd unit installed and enabled"

echo ""
echo "=== Done ==="
echo "  Edit config:   nano ${INSTALL_DIR}/${CONFIG}"
echo "  Start:         systemctl start ${SERVICE_NAME}"
echo "  Logs:          journalctl -u ${SERVICE_NAME} -f"
echo "  Status:        systemctl status ${SERVICE_NAME}"
echo "  Admin panel:   https://<this-host>:9443  (port from yaml)"
