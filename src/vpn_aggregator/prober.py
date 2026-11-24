"""Protocol-level TCP/QUIC reachability probes, TLS certificate pinning, and endpoint diversity caps."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
import ssl
import time
from contextlib import suppress
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives import serialization

try:
    from aioquic.asyncio.client import connect as quic_connect
    from aioquic.quic.configuration import QuicConfiguration

    HAS_AIOQUIC = True
except ImportError:  # pragma: no cover
    quic_connect = None  # type: ignore[assignment]
    QuicConfiguration = None  # type: ignore[misc,assignment]
    HAS_AIOQUIC = False


class _DropAioquicNoise(logging.Filter):
    """QUIC handshake attempts are expected to fail; aioquic logs them at INFO/ERROR."""

    def filter(self, record: logging.LogRecord) -> bool:
        noisy = ("aioquic", "quic", "http3")
        if record.name.startswith(noisy):
            return False
        msg = record.getMessage()
        if record.name == "asyncio" and (
            "shielded future" in msg or "Future exception was never retrieved" in msg
        ):
            return False
        return True


MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "com.au", "net.au", "org.au", "co.jp", "ne.jp",
    "or.jp", "co.kr", "or.kr", "com.br", "com.tr", "co.in", "com.cn", "com.tw",
    "com.sg", "co.id", "co.nz", "co.za", "com.mx", "com.ar", "com.hk", "com.my",
    "com.ph", "com.vn", "co.th",
}


async def check_tcp(node: dict, timeout: float) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(node["host"], node["port"]), timeout=timeout
        )
        writer.close()
        with suppress(Exception):
            await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
        return True
    except Exception:
        return False


async def check_quic(node: dict, timeout: float) -> bool:
    """Completes a QUIC v1 handshake (ALPN h3) and pins the peer leaf certificate."""
    if not HAS_AIOQUIC:
        return False

    host, port = node["host"], node["port"]
    config = QuicConfiguration(is_client=True, alpn_protocols=["h3"], verify_mode=ssl.CERT_NONE)
    config.server_name = node["sni"] or node["host"]

    try:
        async with asyncio.timeout(timeout):
            async with quic_connect(host, port, configuration=config) as protocol:
                if node.get("scheme") == "hysteria2":
                    try:
                        certificate = protocol._quic.tls._peer_certificate
                        if certificate is not None:
                            der = certificate.public_bytes(serialization.Encoding.DER)
                            node["tls_mode"] = "pinned"
                            node["tls_cert_sha256"] = hashlib.sha256(der).hexdigest()
                    except Exception:
                        pass
                return True
    except Exception:
        return False


async def probe_node(
    node: dict,
    timeout: Optional[float] = None,
    *,
    tcp_timeout: float = 3.0,
    quic_timeout: float = 5.0,
    check_tcp_fn=None,
    check_quic_fn=None,
) -> Optional[float]:
    """Returns handshake latency in milliseconds when the node answers."""
    started = time.perf_counter()
    tcp_fn = check_tcp_fn or check_tcp
    quic_fn = check_quic_fn or check_quic
    if node["transport"] == "udp":
        alive = await quic_fn(node, timeout if timeout is not None else quic_timeout)
    else:
        alive = await tcp_fn(node, timeout if timeout is not None else tcp_timeout)
    if not alive:
        return None
    return round((time.perf_counter() - started) * 1000, 1)


async def check_connectivity(
    node: dict,
    timeout: Optional[float] = None,
    **kwargs,
) -> bool:
    """Checks protocol-level reachability of a single node (one attempt)."""
    return await probe_node(node, timeout, **kwargs) is not None


async def inspect_tls(node: dict, timeout: float = 6.0) -> Tuple[Optional[str], Optional[str]]:
    """Classifies a TLS node as CA-valid or self-signed (returns its cert hash)."""
    if node.get("security") != "tls":
        return None, None

    sni = node.get("sni") or node["host"]

    for attempt in range(2):
        try:
            context = ssl.create_default_context()
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(node["host"], node["port"], ssl=context, server_hostname=sni),
                timeout=timeout,
            )
            writer.close()
            with suppress(Exception):
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
            return "valid", None
        except (ssl.SSLError, ssl.CertificateError):
            break
        except Exception:
            if attempt == 0:
                await asyncio.sleep(0.3)
                continue
            break

    for attempt in range(2):
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(node["host"], node["port"], ssl=context, server_hostname=sni),
                timeout=timeout,
            )
            ssl_object = writer.get_extra_info("ssl_object")
            certificate = ssl_object.getpeercert(binary_form=True) if ssl_object else None
            writer.close()
            with suppress(Exception):
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
            if certificate:
                return "pinned", hashlib.sha256(certificate).hexdigest()
        except Exception:
            if attempt == 0:
                await asyncio.sleep(0.3)
                continue
    return None, None


async def inspect_tls_batch(
    fresh_nodes: List[dict],
    semaphore: asyncio.Semaphore,
    *,
    inspect_fn=None,
) -> Tuple[List[dict], Dict[str, int]]:
    """Inspects TLS certificates for VLESS/Trojan TLS candidates and drops broken ones."""
    fn = inspect_fn or inspect_tls
    tls_nodes = [
        n for n in fresh_nodes if n["scheme"] in ("vless", "trojan") and n.get("security") == "tls"
    ]
    tls_status = {"valid": 0, "pinned": 0, "failed": 0}
    if not tls_nodes:
        return fresh_nodes, tls_status

    async def _run_one(target: dict) -> Tuple[Optional[str], Optional[str]]:
        async with semaphore:
            return await fn(target)

    checks = await asyncio.gather(*[_run_one(n) for n in tls_nodes])
    tls_ids = {id(n) for n in tls_nodes}
    kept: List[dict] = []
    for node, (mode, fp) in zip(tls_nodes, checks, strict=True):
        node["tls_mode"], node["tls_cert_sha256"] = mode, fp
        if mode is None:
            tls_status["failed"] += 1
        else:
            tls_status[mode] += 1
            kept.append(node)
    return [n for n in fresh_nodes if id(n) not in tls_ids] + kept, tls_status


async def verify_node(
    node: dict,
    semaphore: asyncio.Semaphore,
    *,
    attempts: int = 2,
    probe_fn=None,
) -> Optional[float]:
    """Checks a node with retries, limited by the shared semaphore."""
    fn = probe_fn or probe_node
    async with semaphore:
        for attempt in range(1, attempts + 1):
            latency = await fn(node)
            if latency is not None:
                node["latency_ms"] = latency
                return latency
            if attempt < attempts:
                await asyncio.sleep(0.4 * attempt)
        return None


async def probe_nodes_dedup(
    nodes: List[dict],
    semaphore: asyncio.Semaphore,
    *,
    verify_fn=None,
) -> Tuple[List[dict], List[dict]]:
    """Probes each unique (transport, host, port, quic_sni) once and fans out results."""
    fn = verify_fn or verify_node
    groups: Dict[Tuple[str, str, int, str], List[dict]] = {}
    for node in nodes:
        sni_key = (node["sni"] or node["host"]).lower() if node["transport"] == "udp" else ""
        key = (node["transport"], node["host"].lower(), node["port"], sni_key)
        groups.setdefault(key, []).append(node)

    reps = [group[0] for group in groups.values()]
    latencies = await asyncio.gather(*[fn(rep, semaphore) for rep in reps])

    reachable_nodes: List[dict] = []
    unreachable_nodes: List[dict] = []
    for group, rep, latency in zip(groups.values(), reps, latencies, strict=True):
        if latency is None:
            unreachable_nodes.extend(group)
            continue
        for node in group:
            node["latency_ms"] = latency
            if rep.get("tls_cert_sha256") and not node.get("tls_cert_sha256"):
                node["tls_mode"] = rep.get("tls_mode")
                node["tls_cert_sha256"] = rep["tls_cert_sha256"]
            reachable_nodes.append(node)
    return reachable_nodes, unreachable_nodes


def _subnet_key(node: dict) -> Optional[str]:
    try:
        address = ipaddress.ip_address(node["host"])
    except ValueError:
        return None
    prefix = 24 if address.version == 4 else 48
    return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))


def _domain_key(node: dict) -> Optional[str]:
    host = node["host"].lower().rstrip(".")
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    labels = host.split(".")
    if len(labels) < 2:
        return host
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _cap_by_key(nodes: List[dict], key_fn, limit: int) -> Tuple[List[dict], int]:
    kept: List[dict] = []
    counts: Dict[object, int] = {}
    for node in nodes:
        key = key_fn(node)
        if key is None:
            kept.append(node)
            continue
        if counts.get(key, 0) >= limit:
            continue
        counts[key] = counts.get(key, 0) + 1
        kept.append(node)
    return kept, len(nodes) - len(kept)


def cap_per_endpoint(nodes: List[dict], limit: int = 6) -> List[dict]:
    """Keeps a few alternative credentials per server to avoid subscription spam."""
    capped, _ = _cap_by_key(
        nodes,
        lambda n: (n["scheme"], n["host"].lower(), n["port"], n["sni"].lower()),
        limit,
    )
    return capped


def cap_published_endpoints(nodes: List[dict], limit: int = 2) -> Tuple[List[dict], int]:
    """Publishes up to `limit` (usually fastest) variants per host:port."""
    return _cap_by_key(
        nodes,
        lambda n: (n["scheme"], n["host"].lower(), n["port"]),
        limit,
    )


def cap_diversity(
    nodes: List[dict],
    *,
    max_per_subnet: int = 6,
    max_per_domain: int = 10,
) -> Tuple[List[dict], Dict[str, int]]:
    """Limits repeated subnets and registrable domains after verification."""
    kept, subnet_removed = _cap_by_key(nodes, _subnet_key, max_per_subnet)
    kept, domain_removed = _cap_by_key(kept, _domain_key, max_per_domain)
    return kept, {"subnet": subnet_removed, "domain": domain_removed}


def cap_for_diversity(
    nodes: List[dict],
    *,
    max_per_endpoint: int = 6,
    max_per_subnet: int = 6,
    max_per_domain: int = 10,
) -> Tuple[List[dict], Dict[str, int]]:
    """Limits repeated endpoints, subnets and registrable domains."""
    kept, endpoint_removed = _cap_by_key(
        nodes,
        lambda n: (n["scheme"], n["host"].lower(), n["port"], n["sni"].lower()),
        max_per_endpoint,
    )
    kept, diversity = cap_diversity(
        kept, max_per_subnet=max_per_subnet, max_per_domain=max_per_domain
    )
    return kept, {"endpoint": endpoint_removed, **diversity}
