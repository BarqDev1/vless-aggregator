"""End-to-end verification of VPN nodes through real proxy clients (Xray v26 + Hysteria v2)."""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
from typing import Dict, List, Optional, Tuple

from . import quality

SUCCESS_STATUSES = {"200", "204"}
RETRY_STATUSES = {"400", "403", "404", "451"}
TARGETS = (
    "http://www.gstatic.com/generate_204",
    "http://connectivitycheck.gstatic.com/generate_204",
)
XRAY_TRANSPORTS = {"tcp", "raw", "ws", "grpc", "xhttp", "splithttp", "httpupgrade", "http", "h2"}


class E2ERuntimeError(RuntimeError):
    """Raised when the configured e2e binaries are missing or unusable."""


def _q(node: dict, key: str, default: str = "") -> str:
    qs = node.get("query") or {}
    for k, values in qs.items():
        if k.lower() == key.lower() and values:
            return values[0]
    return default


def _sni(node: dict) -> str:
    return node.get("sni") or node["host"]


def _normalize_numbers(value):
    """Xray rejects JSON floats where integers/ranges are expected."""
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, dict):
        return {key: _normalize_numbers(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_normalize_numbers(item) for item in value]
    return value


def _xray_stream(node: dict, dialer_proxy: Optional[str] = None) -> Optional[dict]:
    transport = (_q(node, "type") or "tcp").lower()
    if transport not in XRAY_TRANSPORTS:
        return None

    network = {"raw": "tcp", "h2": "http", "splithttp": "xhttp"}.get(transport, transport)
    security = (_q(node, "security") or "none").lower()
    if security not in {"none", "tls", "reality"}:
        return None
    if network == "tcp" and (_q(node, "headerType") or "none").lower() not in {"", "none"}:
        return None

    stream: Dict[str, object] = {"network": network, "security": security}
    if security == "tls":
        tls: Dict[str, object] = {"serverName": _sni(node)}
        if node.get("tls_cert_sha256"):
            tls["pinnedPeerCertSha256"] = node["tls_cert_sha256"]
        if fp := _q(node, "fp"):
            tls["fingerprint"] = fp
        if alpn := _q(node, "alpn"):
            tls["alpn"] = [item for item in alpn.split(",") if item]
        stream["tlsSettings"] = tls
    elif security == "reality":
        public_key = _q(node, "pbk")
        if not public_key or len(public_key) > 128 or not all(ch.isalnum() or ch in "-_+/=" for ch in public_key):
            return None
        short_id = _q(node, "sid")
        if short_id and (len(short_id) > 16 or len(short_id) % 2 != 0 or not all(ch in "0123456789abcdefABCDEF" for ch in short_id)):
            return None
        reality: Dict[str, object] = {
            "serverName": _sni(node),
            "fingerprint": _q(node, "fp") or "chrome",
            "publicKey": public_key,
            "spiderX": _q(node, "spx") or "/",
        }
        if short_id:
            reality["shortId"] = short_id
        stream["realitySettings"] = reality

    if network == "ws":
        stream["wsSettings"] = {
            "path": _q(node, "path") or "/",
            "headers": {"Host": _q(node, "host") or _sni(node)},
        }
    elif network == "grpc":
        service_name = _q(node, "serviceName") or _q(node, "path").lstrip("/")
        stream["grpcSettings"] = {"serviceName": service_name}
    elif network == "xhttp":
        xhttp: Dict[str, object] = {
            "path": _q(node, "path") or "/",
            "host": _q(node, "host") or _sni(node),
            "mode": _q(node, "mode") or "auto",
        }
        if extra := _q(node, "extra"):
            try:
                xhttp["extra"] = _normalize_numbers(json.loads(extra))
            except (TypeError, ValueError):
                pass
        stream["xhttpSettings"] = xhttp
    elif network == "httpupgrade":
        stream["httpupgradeSettings"] = {
            "path": _q(node, "path") or "/",
            "host": _q(node, "host") or _sni(node),
        }
    elif network == "http":
        hosts = _q(node, "host") or _sni(node)
        stream["httpSettings"] = {
            "path": _q(node, "path") or "/",
            "host": [item for item in hosts.split(",") if item],
        }

    if dialer_proxy:
        stream["sockopt"] = {"dialerProxy": dialer_proxy}
    return stream


def build_xray_config(
    node: dict,
    listen_port: int,
    *,
    ru_entry_proxy: Optional[str] = None,
) -> Optional[dict]:
    """Builds an Xray config with an HTTP inbound and a single outbound (plus optional RU dialerProxy)."""
    inbound = {"listen": "127.0.0.1", "port": listen_port, "protocol": "http", "settings": {"timeout": 0}}
    proxy_uri = ru_entry_proxy if ru_entry_proxy is not None else os.getenv("RU_ENTRY_PROXY", "")
    upstream = quality.build_upstream_proxy_outbound(proxy_uri, tag="ru-entry")
    dialer_tag = "ru-entry" if upstream else None

    if node.get("scheme") == "hysteria2":
        certificate = node.get("tls_cert_sha256")
        if not certificate:
            return None
        obfs_type = _q(node, "obfs").strip().lower()
        stream_hy2: Dict[str, object] = {
            "network": "hysteria",
            "security": "tls",
            "tlsSettings": {"serverName": _sni(node), "pinnedPeerCertSha256": certificate},
            "hysteriaSettings": {"version": 2, "auth": node["credential"]},
        }
        if obfs_type == "salamander":
            obfs_pw = _q(node, "obfs-password")
            if not obfs_pw:
                return None
            stream_hy2["udpmasks"] = [{"type": "salamander", "settings": {"password": obfs_pw}}]
        elif obfs_type and obfs_type != "none":
            return None
        if dialer_tag:
            stream_hy2["sockopt"] = {"dialerProxy": dialer_tag}

        hy2_outbound: Dict[str, object] = {
            "protocol": "hysteria",
            "settings": {"version": 2, "address": node["host"], "port": node["port"]},
            "streamSettings": stream_hy2,
        }
        outbounds = [hy2_outbound, upstream] if upstream else [hy2_outbound]
        return {"log": {"loglevel": "error"}, "inbounds": [inbound], "outbounds": outbounds}

    if node.get("scheme") not in ("vless", "trojan"):
        return None
    stream = _xray_stream(node, dialer_proxy=dialer_tag)
    if not stream:
        return None

    if node["scheme"] == "vless":
        user: Dict[str, object] = {"id": node["credential"], "encryption": "none"}
        if flow := _q(node, "flow"):
            user["flow"] = flow
        outbound: Dict[str, object] = {
            "protocol": "vless",
            "settings": {"vnext": [{"address": node["host"], "port": node["port"], "users": [user]}]},
            "streamSettings": stream,
        }
    else:
        outbound = {
            "protocol": "trojan",
            "settings": {"servers": [{"address": node["host"], "port": node["port"], "password": node["credential"]}]},
            "streamSettings": stream,
        }

    outbounds = [outbound, upstream] if upstream else [outbound]
    return {"log": {"loglevel": "error"}, "inbounds": [inbound], "outbounds": outbounds}


def _free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


def _wait_for_port(port: int, process: subprocess.Popen, timeout: float = 3.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.15):
                return True
        except OSError:
            time.sleep(0.08)
    return False


def _curl_through_proxy(port: int, timeout: float, node: Optional[dict] = None) -> Tuple[str, Optional[float]]:
    """Returns (http_status, latency_ms) using HTTPS trace + 204 fallback."""
    only_ru = quality._env_bool("ONLY_RU_IPS", True)
    reject_ru_exit = quality._env_bool("REJECT_RU_EXIT", only_ru)
    for trace_url in quality.TRACE_TARGETS:
        started = time.perf_counter()
        cmd = ["curl", "-fsSL", "--max-filesize", "8192", "-m", str(timeout), "-x", f"http://127.0.0.1:{port}", trace_url]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 3)
        except (OSError, subprocess.TimeoutExpired):
            break
        if res.returncode == 0 and ("ip=" in res.stdout or "loc=" in res.stdout):
            trace = quality.parse_trace_body(res.stdout)
            loc = (trace.get("loc") or "").upper()
            if reject_ru_exit and loc == "RU":
                if node is not None:
                    node["e2e_fail_reason"] = "ru_exit"
                return "403", None
            if node is not None and len(loc) == 2 and loc.isalpha() and loc != "XX":
                node["exit_country"] = loc
            return "200", round((time.perf_counter() - started) * 1000, 1)

    for target in TARGETS:
        started = time.perf_counter()
        cmd = ["curl", "-s", "-o", os.devnull, "-w", "%{http_code}", "-m", str(timeout), "-x", f"http://127.0.0.1:{port}", target]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 3)
        except (OSError, subprocess.TimeoutExpired):
            return "", None

        status = result.stdout.strip()
        if status in SUCCESS_STATUSES:
            return status, round((time.perf_counter() - started) * 1000, 1)
        if status in RETRY_STATUSES:
            continue
        return status, None
    return "403", None


def verify_one(node: dict, xray_bin: str, timeout: float = 7.0) -> Tuple[str, Optional[float]]:
    """Runs one node through a real client. Returns (status, latency_ms)."""
    port = _free_port()
    config = build_xray_config(node, port)
    if config is None:
        return "unsupported", None

    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = os.path.join(tmpdir, "config.json")
        with open(config_path, "w", encoding="utf-8") as handle:
            json.dump(config, handle)

        process = subprocess.Popen(
            [xray_bin, "run", "-c", config_path],
            cwd=tmpdir,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            if not _wait_for_port(port, process):
                return "failed", None
            status, latency = _curl_through_proxy(port, timeout, node=node)
            return ("verified", latency) if status in SUCCESS_STATUSES else ("failed", None)
        finally:
            process.kill()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass


def _require_binary(path: str, name: str) -> str:
    resolved = path if os.path.isabs(path) else shutil.which(path)
    if not resolved or not os.path.isfile(resolved):
        raise E2ERuntimeError(f"{name} binary not found: {path}")
    return resolved


def ensure_binaries(xray_bin: str = "xray") -> str:
    """Validates the Xray binary and returns its resolved path."""
    return _require_binary(xray_bin, "Xray")


async def verify_nodes(
    nodes: List[dict],
    xray_bin: str = "xray",
    concurrency: int = 6,
    timeout: float = 7.0,
    hy2_bin: Optional[str] = None,
) -> List[Tuple[dict, str, Optional[float]]]:
    """Verifies nodes concurrently via native Hysteria2 (if available) + batched Xray."""
    from . import batch_e2e, hy2_e2e

    resolved_hy2 = hy2_e2e.find_hy2_binary(hy2_bin if hy2_bin is not None else os.getenv("HY2_BIN", "hysteria"))
    if not resolved_hy2 or not any(n.get("scheme") == "hysteria2" for n in nodes):
        return await batch_e2e.verify_nodes_batched(nodes, xray_bin=xray_bin, concurrency=concurrency, timeout=timeout)

    xray_indexed = [(i, n) for i, n in enumerate(nodes) if n.get("scheme") != "hysteria2"]
    hy2_indexed = [(i, n) for i, n in enumerate(nodes) if n.get("scheme") == "hysteria2"]

    merged: Dict[int, Tuple[dict, str, Optional[float]]] = {}
    if xray_indexed:
        xray_res = await batch_e2e.verify_nodes_batched(
            [n for _, n in xray_indexed], xray_bin=xray_bin, concurrency=concurrency, timeout=timeout
        )
        for (idx, _), item in zip(xray_indexed, xray_res, strict=True):
            merged[idx] = item

    hy2_res = await hy2_e2e.verify_hy2_nodes(
        [n for _, n in hy2_indexed], hy2_bin=resolved_hy2, concurrency=min(16, max(4, concurrency // 2)), timeout=timeout
    )
    for (idx, _), item in zip(hy2_indexed, hy2_res, strict=True):
        merged[idx] = item

    return [merged[i] for i in range(len(nodes))]
