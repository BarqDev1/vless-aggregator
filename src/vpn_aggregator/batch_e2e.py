"""Batched multi-inbound Xray E2E verification for high-throughput servers.

Runs up to `E2E_BATCH_SIZE` nodes through a single Xray process using dedicated
HTTP inbound -> outbound routing pairs and native async quality probes (exit-IP
trace + optional download speedtest). Falls back to per-node verification if a
batch process fails to start.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import tempfile
import time
from typing import Dict, List, Optional, Tuple, Union

import aiohttp

from . import e2e, quality

DEFAULT_BATCH_SIZE = max(1, int(os.getenv("E2E_BATCH_SIZE", "32")))
ProbeResult = Union[Tuple[str, Optional[float]], Tuple[str, Optional[float], Dict[str, object]]]


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


def build_batch_xray_config(
    items: List[Tuple[int, dict, int]],
    *,
    ru_entry_proxy: Optional[str] = None,
) -> dict:
    """Combines multiple single-outbound configs into one routed Xray config."""
    inbounds = []
    outbounds = []
    rules = []
    shared_upstream: Optional[dict] = None

    proxy_uri = ru_entry_proxy if ru_entry_proxy is not None else os.getenv("RU_ENTRY_PROXY", "")
    if proxy_uri:
        shared_upstream = quality.build_upstream_proxy_outbound(proxy_uri, tag="ru-entry")

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
        if shared_upstream is not None:
            stream = dict(outbound.get("streamSettings") or {})
            stream["sockopt"] = {"dialerProxy": "ru-entry"}
            outbound["streamSettings"] = stream
        outbounds.append(outbound)
        rules.append({"type": "field", "inboundTag": [in_tag], "outboundTag": out_tag})

    if shared_upstream is not None:
        outbounds.append(shared_upstream)

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
) -> ProbeResult:
    return await quality.probe_proxy_quality(
        session, f"http://127.0.0.1:{port}", timeout, semaphore
    )


def _unpack_probe(result: ProbeResult) -> Tuple[str, Optional[float], Dict[str, object]]:
    if len(result) == 3:
        return result[0], result[1], result[2]
    return result[0], result[1], {}


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
) -> List[Tuple[int, str, Optional[float], Dict[str, object]]]:
    async with batch_sem:
        ports = _allocate_free_ports(len(chunk))
        batch_items = [
            (idx, single_cfg, port)
            for (idx, _, single_cfg), port in zip(chunk, ports, strict=True)
        ]
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

                    async def _fallback(
                        idx: int, node: dict
                    ) -> Tuple[int, str, Optional[float], Dict[str, object]]:
                        async with probe_sem:
                            status, latency = await asyncio.to_thread(
                                e2e.verify_one, node, xray_bin, timeout
                            )
                            return idx, status, latency, {}

                    return list(
                        await asyncio.gather(*[_fallback(idx, node) for idx, node, _ in chunk])
                    )

                probes = await asyncio.gather(
                    *[
                        _probe_via_http_proxy(session, port, timeout, probe_sem)
                        for port in ports
                    ]
                )
                unpacked: List[Tuple[int, str, Optional[float], Dict[str, object]]] = []
                for (idx, _, _), raw_probe in zip(chunk, probes, strict=True):
                    status, latency, meta = _unpack_probe(raw_probe)
                    unpacked.append((idx, status, latency, meta))
                return unpacked
            finally:
                _terminate_process(process)


async def verify_nodes_batched(
    nodes: List[dict],
    xray_bin: str = "xray",
    concurrency: int = 16,
    timeout: float = 8.0,
    batch_size: Optional[int] = None,
) -> List[Tuple[dict, str, Optional[float]]]:
    """Verifies nodes in batches through Xray and annotates each node with e2e status & quality."""
    xray_bin = e2e.ensure_binaries(xray_bin)
    if not nodes:
        return []

    size = max(1, batch_size if batch_size is not None else DEFAULT_BATCH_SIZE)
    results_map: Dict[int, Tuple[str, Optional[float], Dict[str, object]]] = {}
    supported: List[Tuple[int, dict, dict]] = []

    for idx, node in enumerate(nodes):
        cfg = e2e.build_xray_config(node, 1080)
        if cfg is None:
            results_map[idx] = ("unsupported", None, {})
        else:
            supported.append((idx, node, cfg))

    if supported:
        chunks = [supported[i : i + size] for i in range(0, len(supported), size)]
        batch_workers = max(1, min(4, (concurrency + size - 1) // size + 1))
        batch_sem = asyncio.Semaphore(batch_workers)
        probe_sem = asyncio.Semaphore(max(1, concurrency))

        connector = aiohttp.TCPConnector(limit=max(32, concurrency * 2))
        async with aiohttp.ClientSession(connector=connector, auto_decompress=False) as session:
            chunk_results = await asyncio.gather(
                *[
                    _verify_chunk(chunk, xray_bin, timeout, session, batch_sem, probe_sem)
                    for chunk in chunks
                ]
            )
        for batch in chunk_results:
            for idx, status, latency, meta in batch:
                results_map[idx] = (status, latency, meta)

    ordered: List[Tuple[dict, str, Optional[float]]] = []
    for idx, node in enumerate(nodes):
        status, latency, meta = results_map[idx]
        node["e2e"] = status
        if latency is not None:
            node["e2e_ms"] = latency
        if meta.get("exit_country"):
            node["exit_country"] = meta["exit_country"]
        if meta.get("speed_kbps") is not None:
            node["speed_kbps"] = meta["speed_kbps"]
        if meta.get("fail_reason"):
            node["e2e_fail_reason"] = meta["fail_reason"]
        ordered.append((node, status, latency))
    return ordered
