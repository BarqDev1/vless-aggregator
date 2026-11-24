#!/usr/bin/env bash
set -euo pipefail

# Idempotent installer for Oracle Cloud Always Free (Ubuntu 22.04/24.04, ARM64 & x86_64)

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Run as root: sudo bash deploy/oracle/install.sh" >&2
  exit 1
fi

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DATA_DIR="/var/lib/vpn-aggregator"
ENV_FILE="/etc/vpn-aggregator.env"
SERVICE_FILE="/etc/systemd/system/vpn-aggregator.service"
XRAY_VERSION="v26.7.28"

ARCH="$(uname -m)"
case "$ARCH" in
  aarch64|arm64)
    PKG_ARCHIVE="Xray-linux-arm64-v8a.zip"
    PKG_CHECKSUM="f5698bb218ada3b4022db26fafc39601c5f53b46b19eb76c9616325985807501"
    ;;
  x86_64|amd64)
    PKG_ARCHIVE="Xray-linux-64.zip"
    PKG_CHECKSUM="8195d909f1109b8f3d99eefe401a3c451d7bf4af71f24d3815420f77e5dd2a40"
    ;;
  *)
    echo "Unsupported CPU architecture: $ARCH" >&2
    exit 1
    ;;
esac

echo "[1/6] Installing system packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends python3 python3-venv python3-pip curl git unzip ca-certificates openssl

echo "[2/6] Installing Xray-core ${XRAY_VERSION} (${ARCH})..."
if [[ ! -x /usr/local/bin/xray ]] || ! /usr/local/bin/xray version 2>/dev/null | grep -q "${XRAY_VERSION#v}"; then
  TMP_DIR="$(mktemp -d)"
  trap 'rm -rf "$TMP_DIR"' EXIT
  curl -fsSL -o "${TMP_DIR}/xray.zip" "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/${PKG_ARCHIVE}"
  echo "${PKG_CHECKSUM}  ${TMP_DIR}/xray.zip" | sha256sum -c -
  unzip -q "${TMP_DIR}/xray.zip" -d "${TMP_DIR}/xray"
  install -m 0755 "${TMP_DIR}/xray/xray" /usr/local/bin/xray
fi

echo "[3/6] Creating service user and data directories..."
if ! id -u aggregator >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin aggregator
fi
mkdir -p "${DATA_DIR}/state" "${DATA_DIR}/cache"
chown -R aggregator:aggregator "${DATA_DIR}"

echo "[4/6] Setting up Python virtualenv..."
if [[ ! -d "${APP_DIR}/.venv" ]]; then
  python3 -m venv "${APP_DIR}/.venv"
fi
"${APP_DIR}/.venv/bin/pip" install --quiet --upgrade pip
"${APP_DIR}/.venv/bin/pip" install --quiet -r "${APP_DIR}/requirements.lock"
chown -R aggregator:aggregator "${APP_DIR}"

echo "[5/6] Writing ${ENV_FILE} (if missing)..."
if [[ ! -f "${ENV_FILE}" ]]; then
  GENERATED_KEY="$(openssl rand -hex 24)"
  cat > "${ENV_FILE}" <<EOF
SUB_KEY=${GENERATED_KEY}
PUBLIC_BASE_URL=
HOST=0.0.0.0
PORT=8080
UPDATE_INTERVAL_MINUTES=15
RUN_ON_STARTUP=1
RATE_LIMIT_PER_MINUTE=60
TRUST_X_FORWARDED_FOR=0

PYTHONPATH=${APP_DIR}/src
XRAY_BIN=/usr/local/bin/xray
SOURCES_FILE=${APP_DIR}/config/sources.txt
VLESS_OUTPUT=${DATA_DIR}/vless_universal.txt
HY2_OUTPUT=${DATA_DIR}/hysteria2.txt
ALL_OUTPUT=${DATA_DIR}/all_universal.txt
STATS_OUTPUT=${DATA_DIR}/state/stats.json
META_FILE=${DATA_DIR}/state/meta.json
HISTORY_FILE=${DATA_DIR}/state/history.json
NODE_HISTORY_FILE=${DATA_DIR}/state/node_history.json
SOURCE_HEALTH_FILE=${DATA_DIR}/state/source_health.json
SOURCE_CACHE_FILE=${DATA_DIR}/state/source_cache.json
RU_GEOIP_CACHE_FILE=${DATA_DIR}/cache/ru_geoip_cache.json

CONCURRENCY=120
DNS_CONCURRENCY=64
FETCH_CONCURRENCY=20
E2E_VERIFY=1
E2E_CONCURRENCY=48
E2E_BATCH_SIZE=32
E2E_TIMEOUT=8.0
E2E_CACHE_MINUTES=45
E2E_FAILURE_CACHE_MINUTES=15
ONLY_RU_IPS=1
NODE_MIN_RECENT_SUCCESS=1
MAX_PER_ENDPOINT=6
PUBLISH_PER_ENDPOINT=2
MAX_PER_SUBNET=6
MAX_PER_DOMAIN=10
MIN_ALIVE=10
EOF
  chmod 0600 "${ENV_FILE}"
  chown aggregator:aggregator "${ENV_FILE}"
fi

echo "[6/6] Installing and starting systemd service..."
cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=VPN Aggregator Server (Oracle Cloud Edition)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=aggregator
Group=aggregator
WorkingDirectory=${APP_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=${APP_DIR}/.venv/bin/python -m vpn_aggregator.server
Restart=always
RestartSec=5
LimitNOFILE=65535
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=${DATA_DIR}

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now vpn-aggregator
sleep 2
systemctl --no-pager status vpn-aggregator || true

SUB_KEY_VAL="$(grep '^SUB_KEY=' "${ENV_FILE}" | cut -d= -f2-)"
echo ""
echo "=== Setup complete ==="
echo "Health check: curl http://127.0.0.1:8080/health"
echo "All subs URL: http://<ORACLE_PUBLIC_IP>:8080/${SUB_KEY_VAL}/all"
echo "Base64 URL:   http://<ORACLE_PUBLIC_IP>:8080/${SUB_KEY_VAL}/all/base64"
echo ""
echo "IMPORTANT for Oracle Cloud Ubuntu: open port 8080 (or 80/443 with Caddy) in BOTH:"
echo "  1. Oracle Cloud Console -> VCN -> Subnet -> Security List (Ingress Rule)"
echo "  2. Ubuntu host iptables (Oracle images block ports by default!):"
echo "     sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 8080 -j ACCEPT && sudo netfilter-persistent save"
