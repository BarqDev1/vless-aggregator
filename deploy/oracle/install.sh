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
HY2_VERSION="app/v2.14.0"

ARCH="$(uname -m)"
case "$ARCH" in
  aarch64|arm64)
    PKG_ARCHIVE="Xray-linux-arm64-v8a.zip"
    PKG_CHECKSUM="f5698bb218ada3b4022db26fafc39601c5f53b46b19eb76c9616325985807501"
    HY2_ARCHIVE="hysteria-linux-arm64"
    HY2_CHECKSUM="e7c52241299fe85aba11e9d36e85d8d88ddbb5799ac0e33d272219d20e313bab"
    ;;
  x86_64|amd64)
    PKG_ARCHIVE="Xray-linux-64.zip"
    PKG_CHECKSUM="8195d909f1109b8f3d99eefe401a3c451d7bf4af71f24d3815420f77e5dd2a40"
    HY2_ARCHIVE="hysteria-linux-amd64"
    HY2_CHECKSUM="fc25edff9948708cb00a4ff01f3bccde677660aca050133bb1ad46c6860362d2"
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

echo "[2/6] Installing Xray-core ${XRAY_VERSION} & Hysteria ${HY2_VERSION} (${ARCH})..."
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
if [[ ! -x /usr/local/bin/xray ]] || ! /usr/local/bin/xray version 2>/dev/null | grep -q "${XRAY_VERSION#v}"; then
  curl -fsSL -o "${TMP_DIR}/xray.zip" "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/${PKG_ARCHIVE}"
  echo "${PKG_CHECKSUM}  ${TMP_DIR}/xray.zip" | sha256sum -c -
  unzip -q "${TMP_DIR}/xray.zip" -d "${TMP_DIR}/xray"
  install -m 0755 "${TMP_DIR}/xray/xray" /usr/local/bin/xray
fi
if [[ ! -x /usr/local/bin/hysteria ]] || ! /usr/local/bin/hysteria version 2>/dev/null | grep -q "v2.14.0"; then
  curl -fsSL -o "${TMP_DIR}/hysteria" "https://github.com/HyNetworks/hysteria/releases/download/${HY2_VERSION}/${HY2_ARCHIVE}"
  echo "${HY2_CHECKSUM}  ${TMP_DIR}/hysteria" | sha256sum -c -
  install -m 0755 "${TMP_DIR}/hysteria" /usr/local/bin/hysteria
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
  GENERATED_VALUE="$(openssl rand -hex 24)"
  cat > "${ENV_FILE}" <<EOF
SUB_KEY=${GENERATED_VALUE}
PUBLIC_BASE_URL=
HOST=0.0.0.0
PORT=8080
UPDATE_INTERVAL_MINUTES=15
RUN_ON_STARTUP=1
RATE_LIMIT_PER_MINUTE=60
TRUST_X_FORWARDED_FOR=0

PYTHONPATH=${APP_DIR}/src
XRAY_BIN=/usr/local/bin/xray
HY2_BIN=/usr/local/bin/hysteria
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
E2E_SPEEDTEST_BYTES=131072
E2E_MIN_SPEED_KBPS=256
E2E_CACHE_MINUTES=45
E2E_FAILURE_CACHE_MINUTES=15
ONLY_RU_IPS=1
REJECT_RU_EXIT=1
FILTER_POISONED_SNI=1
RU_ENTRY_PROXY=
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

echo ""
echo "=== Setup complete ==="
echo "Health check: curl http://127.0.0.1:8080/health"
echo "Read your SUB_KEY from ${ENV_FILE} (chmod 0600)."
