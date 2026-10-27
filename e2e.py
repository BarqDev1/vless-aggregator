"""End-to-end verification of VPN nodes through real proxy clients.

Protocol-level checks only prove that a port answers. This module starts a
real Xray client (VLESS, Trojan and Hysteria2), routes an HTTP request through
it and accepts the node only if the request succeeds.

Xray is pinned to a modern v26 release: `allowInsecure` is gone, so TLS nodes
are either CA-valid or pinned with `pinnedPeerCertSha256` (`pcs` in links).
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
from typing import Dict, List, Optional, Tuple

SUCCESS_STATUSES = {"200", "204"}
RETRY_STATUSES = {"400", "403", "404", "451"}
TARGETS = (
    "http://www.gstatic.com/generate_204",
    "http://connectivitycheck.gstatic.com/generate_204",
)

# Transports supported by Xray-core 25.3.6 outbounds.
XRAY_TRANSPORTS = {"tcp", "raw", "ws", "grpc", "xhttp", "splithttp", "httpupgrade", "http", "h2"}


class E2ERuntimeError(RuntimeError):
    """Raised when the configured e2e binaries are missing or unusable."""


def _q(node: dict, key: str, default: str = "") -> str:
    values = node.get("query", {}).get(key) or [default]
    return values[0]


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


def _xray_stream(node: dict) -> Optional[dict]:
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
        fingerprint = _q(node, "fp")
        if fingerprint:
            tls["fingerprint"] = fingerprint
        alpn = _q(node, "alpn")
        if alpn:
            tls["alpn"] = [item for item in alpn.split(",") if item]
        stream["tlsSettings"] = tls
    elif security == "reality":
        public_key = _q(node, "pbk")
        if not public_key:
            return None
        reality: Dict[str, object] = {
            "serverName": _sni(node),
            "fingerprint": _q(node, "fp") or "chrome",
            "publicKey": public_key,
            "spiderX": _q(node, "spx") or "/",
        }
        short_id = _q(node, "sid")
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
        if not service_name:
            return None
        stream["grpcSettings"] = {"serviceName": service_name}
    elif network == "xhttp":
        xhttp: Dict[str, object] = {
            "path": _q(node, "path") or "/",
            "host": _q(node, "host") or _sni(node),
            "mode": _q(node, "mode") or "auto",
        }
        extra = _q(node, "extra")
        if extra:
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

    return stream


def build_xray_config(node: dict, listen_port: int) -> Optional[dict]:
    """Builds an Xray config with an HTTP inbound and a single outbound."""
    inbound = {
        "listen": "127.0.0.1",
        "port": listen_port,
        "protocol": "http",
        "settings": {"timeout": 0},
    }

    if node.get("scheme") == "hysteria2":
        certificate = node.get("tls_cert_sha256")
        if not certificate:
            return None
        outbound: Dict[str, object] = {
            "protocol": "hysteria",
            "settings": {
                "version": 2,
                "address": node["host"],
                "port": node["port"],
            },
            "streamSettings": {
                "network": "hysteria",
                "security": "tls",
                "tlsSettings": {
                    "serverName": _sni(node),
                    "pinnedPeerCertSha256": certificate,
                },
                "hysteriaSettings": {
                    "version": 2,
                    "auth": node["credential"],
                },
            },
        }
        return {
            "log": {"loglevel": "error"},
            "inbounds": [inbound],
            "outbounds": [outbound],
        }

    if node.get("scheme") not in ("vless", "trojan"):
        return None
    stream = _xray_stream(node)
    if not stream:
        return None

    if node["scheme"] == "vless":
        user: Dict[str, object] = {"id": node["credential"], "encryption": "none"}
        flow = _q(node, "flow")
        if flow:
            user["flow"] = flow
        outbound: Dict[str, object] = {
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": node["host"],
                        "port": node["port"],
                        "users": [user],
                    }
                ]
            },
            "streamSettings": stream,
        }
    else:
        outbound = {
            "protocol": "trojan",
            "settings": {
                "servers": [
                    {
                        "address": node["host"],
                        "port": node["port"],
                        "password": node["credential"],
                    }
                ]
            },
            "streamSettings": stream,
        }

    return {
        "log": {"loglevel": "error"},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": listen_port,
                "protocol": "http",
                "settings": {"timeout": 0},
            }
        ],
        "outbounds": [outbound],
    }


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


def _curl_through_proxy(port: int, timeout: float) -> Tuple[str, Optional[float]]:
    """Returns (http_status, latency_ms). Empty status means curl failed."""
    for target in TARGETS:
        started = time.perf_counter()
        try:
            result = subprocess.run(
                [
                    "curl",
                    "-s",
                    "-o",
                    os.devnull,
                    "-w",
                    "%{http_code}",
                    "-m",
                    str(timeout),
                    "-x",
                    f"http://127.0.0.1:{port}",
                    target,
                ],
                capture_output=True,
                text=True,
                timeout=timeout + 3,
            )
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
            status, latency = _curl_through_proxy(port, timeout)
            if status in SUCCESS_STATUSES:
                return "verified", latency
            return "failed", None
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
) -> List[Tuple[dict, str, Optional[float]]]:
    """Verifies nodes concurrently and annotates each node with its e2e status."""
    xray_bin = _require_binary(xray_bin, "Xray")
    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def run(node: dict) -> Tuple[dict, str, Optional[float]]:
        async with semaphore:
            status, latency = await asyncio.to_thread(verify_one, node, xray_bin, timeout)
            node["e2e"] = status
            if latency is not None:
                node["e2e_ms"] = latency
            return node, status, latency

    return list(await asyncio.gather(*[run(node) for node in nodes]))
