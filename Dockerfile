FROM python:3.12-slim

ARG XRAY_VERSION=v26.7.28
ARG HY2_VERSION=app/v2.14.0
ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git unzip \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    arch="${TARGETARCH:-$(dpkg --print-architecture)}"; \
    case "$arch" in \
        amd64|x86_64) \
            pkg_asset="Xray-linux-64.zip"; \
            pkg_checksum="8195d909f1109b8f3d99eefe401a3c451d7bf4af71f24d3815420f77e5dd2a40"; \
            hy2_asset="hysteria-linux-amd64"; \
            hy2_sum="fc25edff9948708cb00a4ff01f3bccde677660aca050133bb1ad46c6860362d2" ;; \
        arm64|aarch64) \
            pkg_asset="Xray-linux-arm64-v8a.zip"; \
            pkg_checksum="f5698bb218ada3b4022db26fafc39601c5f53b46b19eb76c9616325985807501"; \
            hy2_asset="hysteria-linux-arm64"; \
            hy2_sum="e7c52241299fe85aba11e9d36e85d8d88ddbb5799ac0e33d272219d20e313bab" ;; \
        *) echo "Unsupported architecture: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/xray.zip "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/${pkg_asset}"; \
    echo "${pkg_checksum}  /tmp/xray.zip" | sha256sum -c -; \
    unzip -q /tmp/xray.zip -d /tmp/xray; \
    install -m 0755 /tmp/xray/xray /usr/local/bin/xray; \
    rm -rf /tmp/xray /tmp/xray.zip; \
    /usr/local/bin/xray version; \
    curl -fsSL -o /tmp/hysteria "https://github.com/HyNetworks/hysteria/releases/download/${HY2_VERSION}/${hy2_asset}"; \
    echo "${hy2_sum}  /tmp/hysteria" | sha256sum -c -; \
    install -m 0755 /tmp/hysteria /usr/local/bin/hysteria; \
    rm -f /tmp/hysteria; \
    /usr/local/bin/hysteria version

WORKDIR /app

COPY requirements.lock .
RUN pip install --no-cache-dir -r requirements.lock

COPY src/ ./src/
COPY config/ ./config/

RUN useradd --system --create-home --uid 10001 aggregator \
    && mkdir -p /data/state /data/cache \
    && chown -R aggregator:aggregator /app /data

USER aggregator

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    XRAY_BIN=/usr/local/bin/xray \
    HY2_BIN=/usr/local/bin/hysteria \
    VLESS_OUTPUT=/data/vless_universal.txt \
    HY2_OUTPUT=/data/hysteria2.txt \
    ALL_OUTPUT=/data/all_universal.txt \
    STATS_OUTPUT=/data/state/stats.json \
    META_FILE=/data/state/meta.json \
    HISTORY_FILE=/data/state/history.json \
    NODE_HISTORY_FILE=/data/state/node_history.json \
    SOURCE_HEALTH_FILE=/data/state/source_health.json \
    SOURCE_CACHE_FILE=/data/state/source_cache.json \
    RU_GEOIP_CACHE_FILE=/data/cache/ru_geoip_cache.json \
    E2E_VERIFY=1 \
    ONLY_RU_IPS=1 \
    REJECT_RU_EXIT=1 \
    FILTER_POISONED_SNI=1 \
    E2E_SPEEDTEST_BYTES=131072 \
    E2E_MIN_SPEED_KBPS=256 \
    HOST=0.0.0.0 \
    PORT=8080

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/health >/dev/null || exit 1

CMD ["python", "-m", "vpn_aggregator.server"]
