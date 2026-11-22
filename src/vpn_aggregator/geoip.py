"""Russian IP (GeoIP + RIPE NCC) filtering and async DNS resolution.

Combines GeoLite2-derived RU CIDR lists with the official RIPE NCC RU
allocation list, caches merged CIDRs locally and checks both literal IPs
and DNS-resolved domain addresses using O(log N) binary search.
"""

from __future__ import annotations

import asyncio
import bisect
import ipaddress
import json
import logging
import os
import socket
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple, Union

import aiohttp

logger = logging.getLogger("aggregator")

RIPE_RU_URL = "https://stat.ripe.net/data/country-resource-list/data.json?resource=ru"
GEOIP_RU_URLS = (
    "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/ru.txt",
    "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/ru.list",
)
CACHE_MAX_AGE_HOURS = 24.0
MAX_GEOIP_BYTES = 10 * 1024 * 1024

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


class GeoIPRuntimeError(RuntimeError):
    """Raised when no RU IP ranges can be loaded from upstream or cache."""


def _parse_ip(value: str) -> Optional[IPAddress]:
    cleaned = value.strip().split("%", 1)[0]
    if not cleaned:
        return None
    try:
        return ipaddress.ip_address(cleaned)
    except ValueError:
        return None


def is_global_ip(value: str) -> bool:
    """Returns True only for publicly routable unicast IP addresses."""
    addr = _parse_ip(value)
    return bool(addr is not None and addr.is_global)


def _split_and_collapse(
    cidrs: Iterable[str],
) -> Tuple[List[ipaddress.IPv4Network], List[ipaddress.IPv6Network]]:
    v4_nets: List[ipaddress.IPv4Network] = []
    v6_nets: List[ipaddress.IPv6Network] = []
    for raw in cidrs:
        text = raw.strip()
        if not text:
            continue
        try:
            net = ipaddress.ip_network(text, strict=False)
        except ValueError:
            continue
        if isinstance(net, ipaddress.IPv4Network):
            v4_nets.append(net)
        else:
            v6_nets.append(net)
    return list(ipaddress.collapse_addresses(v4_nets)), list(ipaddress.collapse_addresses(v6_nets))


class RuIpMatcher:
    """Fast O(log N) membership checker for collapsed IPv4/IPv6 CIDR ranges."""

    def __init__(self, v4: List[Tuple[int, int]], v6: List[Tuple[int, int]]) -> None:
        self._v4_starts, self._v4_ends = [s for s, _ in v4], [e for _, e in v4]
        self._v6_starts, self._v6_ends = [s for s, _ in v6], [e for _, e in v6]

    @classmethod
    def from_cidrs(cls, cidrs: Iterable[str]) -> "RuIpMatcher":
        v4_nets, v6_nets = _split_and_collapse(cidrs)
        return cls(
            [(int(n.network_address), int(n.broadcast_address)) for n in v4_nets],
            [(int(n.network_address), int(n.broadcast_address)) for n in v6_nets],
        )

    @property
    def size_v4(self) -> int:
        return len(self._v4_starts)

    @property
    def size_v6(self) -> int:
        return len(self._v6_starts)

    @property
    def is_empty(self) -> bool:
        return not self._v4_starts and not self._v6_starts

    def contains(self, ip_str: str) -> bool:
        addr = _parse_ip(ip_str)
        if addr is None or not addr.is_global:
            return False
        value = int(addr)
        starts, ends = (
            (self._v4_starts, self._v4_ends)
            if addr.version == 4
            else (self._v6_starts, self._v6_ends)
        )
        idx = bisect.bisect_right(starts, value) - 1
        return idx >= 0 and value <= ends[idx]


def parse_cidr_text(text: str) -> List[str]:
    """Extracts normalized IPv4/IPv6 CIDR strings from plain-text lists."""
    cidrs: List[str] = []
    for line in text.splitlines():
        item = line.strip()
        if not item or item.startswith("#"):
            continue
        try:
            cidrs.append(str(ipaddress.ip_network(item, strict=False)))
        except ValueError:
            continue
    return cidrs


def parse_ripe_ru_payload(payload: dict) -> List[str]:
    """Extracts IPv4/IPv6 CIDRs from a RIPEstat country-resource-list JSON."""
    resources = payload.get("data", {}).get("resources", {})
    if not isinstance(resources, dict):
        return []

    cidrs: List[str] = []
    for raw in resources.get("ipv4") or []:
        if not isinstance(raw, str):
            continue
        item = raw.strip()
        try:
            if "-" in item:
                start_s, end_s = item.split("-", 1)
                nets = ipaddress.summarize_address_range(
                    ipaddress.IPv4Address(start_s.strip()),
                    ipaddress.IPv4Address(end_s.strip()),
                )
                cidrs.extend(str(net) for net in nets)
            else:
                cidrs.append(str(ipaddress.IPv4Network(item, strict=False)))
        except ValueError:
            continue

    for raw in resources.get("ipv6") or []:
        if not isinstance(raw, str):
            continue
        try:
            cidrs.append(str(ipaddress.IPv6Network(raw.strip(), strict=False)))
        except ValueError:
            continue

    return cidrs


def _load_cache(cache_path: str) -> Tuple[Optional[datetime], List[str]]:
    try:
        with open(cache_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (FileNotFoundError, ValueError, OSError):
        return None, []
    if not isinstance(data, dict) or not isinstance(data.get("cidrs"), list):
        return None, []
    cidrs = [item for item in data["cidrs"] if isinstance(item, str)]
    updated_raw = data.get("updated_at")
    updated_at: Optional[datetime] = None
    if isinstance(updated_raw, str) and updated_raw:
        try:
            parsed = datetime.fromisoformat(updated_raw.replace("Z", "+00:00"))
            updated_at = parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            updated_at = None
    return updated_at, cidrs


def _save_cache(cache_path: str, cidrs: List[str], now: datetime) -> None:
    Path(cache_path).parent.mkdir(parents=True, exist_ok=True)
    tmp = f"{cache_path}.tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump({"updated_at": now.isoformat(timespec="seconds"), "cidrs": cidrs}, handle)
    os.replace(tmp, cache_path)


async def _fetch_text(session: aiohttp.ClientSession, url: str, timeout: float) -> Optional[str]:
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
            if resp.status != 200:
                logger.warning(f"Failed to fetch RU GeoIP source {url}: HTTP {resp.status}")
                return None
            chunks: List[bytes] = []
            total = 0
            async for chunk in resp.content.iter_chunked(65536):
                total += len(chunk)
                if total > MAX_GEOIP_BYTES:
                    logger.warning(f"RU GeoIP source {url} exceeds {MAX_GEOIP_BYTES} bytes; skipping")
                    return None
                chunks.append(chunk)
            return b"".join(chunks).decode(resp.charset or "utf-8", errors="ignore")
    except Exception as exc:
        logger.warning(f"Error fetching RU GeoIP source {url}: {type(exc).__name__}: {exc}")
        return None


def _collapse_cidrs(cidrs: Iterable[str]) -> List[str]:
    v4_nets, v6_nets = _split_and_collapse(cidrs)
    return [str(net) for net in v4_nets] + [str(net) for net in v6_nets]


async def load_ru_matcher(
    session: aiohttp.ClientSession,
    cache_path: str,
    now: Optional[datetime] = None,
    timeout: float = 20.0,
    max_age_hours: float = CACHE_MAX_AGE_HOURS,
) -> RuIpMatcher:
    """Loads merged RU IPv4/IPv6 ranges from fresh cache or upstream sources."""
    now = now or datetime.now(timezone.utc)
    cached_at, cached_cidrs = _load_cache(cache_path)
    if cached_at and cached_cidrs and (now - cached_at) <= timedelta(hours=max_age_hours):
        matcher = RuIpMatcher.from_cidrs(cached_cidrs)
        if not matcher.is_empty:
            logger.info(
                f"Loaded RU GeoIP ranges from cache: {matcher.size_v4} IPv4, {matcher.size_v6} IPv6"
            )
            return matcher

    collected: List[str] = []

    for url in GEOIP_RU_URLS:
        text = await _fetch_text(session, url, timeout)
        if text:
            parsed = parse_cidr_text(text)
            if parsed:
                collected.extend(parsed)
                logger.info(f"Loaded {len(parsed)} RU CIDRs from {url}")
                break

    ripe_text = await _fetch_text(session, RIPE_RU_URL, timeout)
    if ripe_text:
        try:
            ripe_cidrs = parse_ripe_ru_payload(json.loads(ripe_text))
        except ValueError:
            ripe_cidrs = []
        if ripe_cidrs:
            collected.extend(ripe_cidrs)
            logger.info(f"Loaded {len(ripe_cidrs)} RU CIDRs from RIPE NCC")

    if collected:
        merged = _collapse_cidrs(collected)
        matcher = RuIpMatcher.from_cidrs(merged)
        if not matcher.is_empty:
            try:
                _save_cache(cache_path, merged, now)
            except OSError as exc:
                logger.warning(f"Could not write RU GeoIP cache {cache_path}: {exc}")
            logger.info(
                f"RU GeoIP matcher ready: {matcher.size_v4} IPv4, {matcher.size_v6} IPv6 ranges"
            )
            return matcher

    if cached_cidrs:
        matcher = RuIpMatcher.from_cidrs(cached_cidrs)
        if not matcher.is_empty:
            logger.warning(
                "Failed to refresh RU GeoIP lists; falling back to stale cache "
                f"({matcher.size_v4} IPv4, {matcher.size_v6} IPv6 ranges)."
            )
            return matcher

    raise GeoIPRuntimeError("Unable to load RU IP ranges from upstream sources or cache")


async def resolve_host_ips(host: str, timeout: float = 5.0) -> List[str]:
    """Resolves a hostname to sorted unique IP strings, or returns [host] for IP literals."""
    addr = _parse_ip(host)
    if addr is not None:
        return [str(addr)]

    try:
        infos = await asyncio.wait_for(
            asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM),
            timeout=timeout,
        )
    except Exception:
        return []

    ips = {
        str(parsed)
        for info in infos
        if info[4] and isinstance(info[4][0], str) and (parsed := _parse_ip(info[4][0])) is not None
    }
    return sorted(ips)


async def filter_ru_nodes(
    nodes: List[dict],
    matcher: RuIpMatcher,
    concurrency: int = 32,
    timeout: float = 5.0,
) -> Tuple[List[dict], Dict[str, int]]:
    """Keeps only nodes whose literal or DNS-resolved public IPs are all in Russia."""
    unique_hosts = sorted({node["host"].strip().lower() for node in nodes})
    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def resolve_limited(host: str) -> Tuple[str, List[str]]:
        async with semaphore:
            return host, await resolve_host_ips(host, timeout=timeout)

    dns_map = dict(await asyncio.gather(*[resolve_limited(host) for host in unique_hosts]))

    kept: List[dict] = []
    stats = {
        "checked": len(nodes),
        "kept": 0,
        "non_ru": 0,
        "unresolved": 0,
        "non_public": 0,
        "unique_hosts": len(unique_hosts),
    }

    for node in nodes:
        ips = dns_map.get(node["host"].strip().lower(), [])
        if not ips:
            stats["unresolved"] += 1
            continue
        public_ips = [ip for ip in ips if is_global_ip(ip)]
        if not public_ips:
            stats["non_public"] += 1
            continue
        if all(matcher.contains(ip) for ip in public_ips):
            node["resolved_ips"] = public_ips
            kept.append(node)
            stats["kept"] += 1
        else:
            stats["non_ru"] += 1

    return kept, stats
