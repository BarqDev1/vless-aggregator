"""Batched multi-inbound Xray E2E verification for high-throughput servers.

Runs up to `E2E_BATCH_SIZE` nodes through a single Xray process using dedicated
HTTP inbound -> outbound routing pairs and native async aiohttp proxy probes.
Automatically falls back to per-node verification if a batch process fails.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import tempfile
import time
from typing import Dict, List, Optional, Tuple

import aiohttp

from . import e2e

DEFAULT_BATCH_SIZE = max(1, int(os.getenv("E2E_BATCH_SIZE", "32")))


def _allocate_free_ports(count: int) -> List[int]:
    """Allocates `count` distinct ephemeral localhost TCP ports simultaneously."""
    sockets: List[socket.socket] = []
    ports: List[int] = []
    try:
        for _ in range(count):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(("127.0.0.1", 0))
            ports.append(int(sock.getsockname()[1]))
            sockets.append(sock)
        return ports
    finally:
        for sock in sockets:
            sock.close()


def build_batch_xray_config(items: List[Tuple[int, dict, int]]) -> dict:
    """Combines multiple single-outbound configs into one routed Xray config."""
    inbounds = []
    outbounds = []
    rules = []
    for idx, single_config, port in items:
        in_tag = f"in-{idx}"
        out_tag = f"out-{idx}"
        inbounds.append(
            {
                "tag": in_tag,
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "http",
                "settings": {"timeout": 0},
            }
        )
        outbound = dict(single_config["outbounds"][0])
        outbound["tag"] = out_tag
        outbounds.append(outbound)
        rules.append({"type": "field", "inboundTag": [in_tag], "outboundTag": out_tag})

    return {
        "log": {"loglevel": "error"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    }


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
            await asyncio.sleep(0.08)
    return False


async def _probe_via_http_proxy(
    session: aiohttp.ClientSession,
    port: int,
    timeout: float,
    semaphore: asyncio.Semaphore,
) -> Tuple[str, Optional[float]]:
    proxy_url = f"http://127.0.0.1:{port}"
    async with semaphore:
        for target in e2e.TARGETS:
            started = time.perf_counter()
            try:
                async with session.get(
                    target,
                    proxy=proxy_url,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    allow_redirects=False,
                ) as resp:
                    status = str(resp.status)
                    if status in e2e.SUCCESS_STATUSES:
                        return "verified", round((time.perf_counter() - started) * 1000, 1)
                    if status in e2e.RETRY_STATUSES:
                        continue
                    return "failed", None
            except Exception:
                return "failed", None
        return "failed", None


def _terminate_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    process.kill()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass


async def _verify_chunk(
    chunk: List[Tuple[int, dict, dict]],
    xray_bin: str,
    timeout: float,
    session: aiohttp.ClientSession,
    batch_sem: asyncio.Semaphore,
    probe_sem: asyncio.Semaphore,
) -> List[Tuple[int, str, Optional[float]]]:
    async with batch_sem:
        ports = _allocate_free_ports(len(chunk))
        batch_items = [(idx, single_cfg, port) for (idx, _, single_cfg), port in zip(chunk, ports, strict=True)]
        config = build_batch_xray_config(batch_items)

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = os.path.join(tmpdir, "batch_config.json")
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
                ready = await _wait_for_port_async(ports[0], process)
                if not ready:
                    _terminate_process(process)

                    async def _fallback(idx: int, node: dict) -> Tuple[int, str, Optional[float]]:
                        async with probe_sem:
                            status, latency = await asyncio.to_thread(
                                e2e.verify_one, node, xray_bin, timeout
                            )
                            return idx, status, latency

                    return list(
                        await asyncio.gather(*[_fallback(idx, node) for idx, node, _ in chunk])
                    )

                probes = await asyncio.gather(
                    *[
                        _probe_via_http_proxy(session, port, timeout, probe_sem)
                        for port in ports
                    ]
                )
                return [
                    (idx, status, latency)
                    for (idx, _, _), (status, latency) in zip(chunk, probes, strict=True)
                ]
            finally:
                _terminate_process(process)


async def verify_nodes_batched(
    nodes: List[dict],
    xray_bin: str = "xray",
    concurrency: int = 16,
    timeout: float = 8.0,
    batch_size: Optional[int] = None,
) -> List[Tuple[dict, str, Optional[float]]]:
    """Verifies nodes in batches through Xray and annotates each node with e2e status."""
    xray_bin = e2e.ensure_binaries(xray_bin)
    if not nodes:
        return []

    size = max(1, batch_size if batch_size is not None else DEFAULT_BATCH_SIZE)
    results_map: Dict[int, Tuple[str, Optional[float]]] = {}
    supported: List[Tuple[int, dict, dict]] = []

    for idx, node in enumerate(nodes):
        cfg = e2e.build_xray_config(node, 1080)
        if cfg is None:
            results_map[idx] = ("unsupported", None)
        else:
            supported.append((idx, node, cfg))

    if supported:
        chunks = [supported[i : i + size] for i in range(0, len(supported), size)]
        batch_workers = max(1, min(4, (concurrency + size - 1) // size + 1))
        batch_sem = asyncio.Semaphore(batch_workers)
        probe_sem = asyncio.Semaphore(max(1, concurrency))

        connector = aiohttp.TCPConnector(limit=max(32, concurrency * 2))
        async with aiohttp.ClientSession(connector=connector) as session:
            chunk_results = await asyncio.gather(
                *[
                    _verify_chunk(chunk, xray_bin, timeout, session, batch_sem, probe_sem)
                    for chunk in chunks
                ]
            )
        for batch in chunk_results:
            for idx, status, latency in batch:
                results_map[idx] = (status, latency)

    ordered: List[Tuple[dict, str, Optional[float]]] = []
    for idx, node in enumerate(nodes):
        status, latency = results_map[idx]
        node["e2e"] = status
        if latency is not None:
            node["e2e_ms"] = latency
        ordered.append((node, status, latency))
    return ordered
