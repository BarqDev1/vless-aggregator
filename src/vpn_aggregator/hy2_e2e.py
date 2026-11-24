"""Native Hysteria2 end-to-end verification using the official `hysteria` v2 client."""

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

import aiohttp

from . import quality


def _q(node: dict, key: str, default: str = "") -> str:
    qs = node.get("query") or {}
    for k, values in qs.items():
        if k.lower() == key.lower() and values:
            return values[0]
    return default


def find_hy2_binary(hy2_bin: str = "hysteria") -> Optional[str]:
    """Returns the resolved `hysteria` v2 client binary path if installed, else None."""
    if not hy2_bin:
        return None
    resolved = hy2_bin if os.path.isabs(hy2_bin) else shutil.which(hy2_bin)
    if resolved and os.path.isfile(resolved) and os.access(resolved, os.X_OK):
        return resolved
    return None


def _format_server_addr(node: dict) -> str:
    host = node["host"]
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    mport = _q(node, "mport").strip()
    if mport:
        normalized_mport = mport.replace(":", "-")
        return f"{host}:{node['port']},{normalized_mport}"
    return f"{host}:{node['port']}"


def build_hy2_client_config(node: dict, listen_port: int) -> Optional[dict]:
    """Builds an official Hysteria v2 client JSON config with pinSHA256, mport, and salamander."""
    if node.get("scheme") != "hysteria2":
        return None
    certificate = node.get("tls_cert_sha256")
    if not certificate:
        return None

    sni = node.get("sni") or node["host"]
    cfg: Dict[str, object] = {
        "server": _format_server_addr(node),
        "lazy": True,
        "tls": {
            "sni": sni,
            "insecure": True,
            "pinSHA256": certificate,
        },
        "http": {
            "listen": f"127.0.0.1:{listen_port}",
        },
    }
    if node.get("credential"):
        cfg["auth"] = node["credential"]

    obfs_type = _q(node, "obfs").strip().lower()
    if obfs_type == "salamander":
        obfs_password = _q(node, "obfs-password")
        if not obfs_password:
            return None
        cfg["obfs"] = {
            "type": "salamander",
            "salamander": {"password": obfs_password},
        }
    elif obfs_type and obfs_type != "none":
        return None

    return cfg


def _free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


async def _wait_for_port_async(port: int, process: subprocess.Popen, timeout: float = 3.5) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", port), timeout=0.2
            )
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=0.2)
            except Exception:
                pass
            return True
        except Exception:
            await asyncio.sleep(0.06)
    return False


def _terminate_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    process.kill()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass


async def _verify_single_hy2(
    node: dict,
    hy2_bin: str,
    timeout: float,
    session: aiohttp.ClientSession,
    worker_sem: asyncio.Semaphore,
    probe_sem: asyncio.Semaphore,
) -> Tuple[dict, str, Optional[float]]:
    async with worker_sem:
        port = _free_port()
        cfg = build_hy2_client_config(node, port)
        if cfg is None:
            node["e2e"] = "unsupported"
            return node, "unsupported", None

        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "hy2.json")
            with open(cfg_path, "w", encoding="utf-8") as handle:
                json.dump(cfg, handle)

            process = subprocess.Popen(
                [hy2_bin, "client", "--disable-update-check", "-c", cfg_path],
                cwd=tmpdir,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                if not await _wait_for_port_async(port, process):
                    node["e2e"] = "failed"
                    node["e2e_fail_reason"] = "startup_failed"
                    return node, "failed", None

                status, latency, meta = await quality.probe_proxy_quality(
                    session, f"http://127.0.0.1:{port}", timeout, probe_sem
                )
                node["e2e"] = status
                if latency is not None:
                    node["e2e_ms"] = latency
                if meta.get("exit_country"):
                    node["exit_country"] = meta["exit_country"]
                if meta.get("speed_kbps") is not None:
                    node["speed_kbps"] = meta["speed_kbps"]
                if meta.get("fail_reason"):
                    node["e2e_fail_reason"] = meta["fail_reason"]
                return node, status, latency
            finally:
                _terminate_process(process)


async def verify_hy2_nodes(
    nodes: List[dict],
    hy2_bin: str = "hysteria",
    concurrency: int = 12,
    timeout: float = 8.0,
) -> List[Tuple[dict, str, Optional[float]]]:
    """Verifies Hysteria2 nodes concurrently using the official `hysteria` v2 client."""
    resolved = find_hy2_binary(hy2_bin)
    if not resolved:
        raise RuntimeError(f"Hysteria2 binary not found: {hy2_bin}")
    if not nodes:
        return []

    workers = max(1, min(16, concurrency))
    worker_sem = asyncio.Semaphore(workers)
    probe_sem = asyncio.Semaphore(workers)

    connector = aiohttp.TCPConnector(limit=max(16, workers * 2))
    async with aiohttp.ClientSession(connector=connector, auto_decompress=False) as session:
        return list(
            await asyncio.gather(
                *[
                    _verify_single_hy2(node, resolved, timeout, session, worker_sem, probe_sem)
                    for node in nodes
                ]
            )
        )
