FROM python:3.12-slim

ARG XRAY_VERSION=v26.7.28
ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git unzip \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    arch="${TARGETARCH:-$(dpkg --print-architecture)}"; \
    case "$arch" in \
        amd64|x86_64) \
            asset="Xray-linux-64.zip"; \
            sha256="8195d909f1109b8f3d99eefe401a3c451d7bf4af71f24d3815420f77e5dd2a40" ;; \
        arm64|aarch64) \
            asset="Xray-linux-arm64-v8a.zip"; \
            sha256="f5698bb218ada3b4022db26fafc39601c5f53b46b19eb76c9616325985807501" ;; \
        *) echo "Unsupported architecture: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/xray.zip "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/${asset}"; \
    echo "${sha256}  /tmp/xray.zip" | sha256sum -c -; \
    unzip -q /tmp/xray.zip -d /tmp/xray; \
    install -m 0755 /tmp/xray/xray /usr/local/bin/xray; \
    rm -rf /tmp/xray /tmp/xray.zip; \
    /usr/local/bin/xray version

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
    HOST=0.0.0.0 \
    PORT=8080

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/health >/dev/null || exit 1

CMD ["python", "-m", "vpn_aggregator.server"]
