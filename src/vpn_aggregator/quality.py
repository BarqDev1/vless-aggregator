"""Proxy quality probing (exit-IP trace, bandwidth mini-speedtest), TSPU scoring, and RU entry proxy chaining."""

from __future__ import annotations

import asyncio
import os
import time
import urllib.parse
from typing import Dict, Optional, Tuple

import aiohttp

MAX_TRACE_BYTES = 8192
TRACE_TARGETS = (
    "https://1.1.1.1/cdn-cgi/trace",
    "https://www.cloudflare.com/cdn-cgi/trace",
)
FALLBACK_204_TARGETS = (
    "https://cp.cloudflare.com/generate_204",
    "https://www.gstatic.com/generate_204",
)
PROBE_HEADERS = {"Accept-Encoding": "identity"}
SUCCESS_STATUSES = {"200", "204"}
RETRY_STATUSES = {"400", "403", "404", "429", "451", "500", "502", "503"}

# Domains blocked or throttled at the TLS ClientHello SNI layer by Russian TSPU.
POISONED_SNI_SUFFIXES = (
    "instagram.com",
    "facebook.com",
    "fbcdn.net",
    "twitter.com",
    "x.com",
    "youtube.com",
    "googlevideo.com",
    "ytimg.com",
    "torproject.org",
    "rutracker.org",
    "proton.me",
    "protonvpn.com",
    "ntc.party",
    "amnezia.org",
)

# Russian domestic/CDN domains commonly permitted under mobile/ISP whitelists.
RU_WHITELIST_SNI_SUFFIXES = (
    "yandex.ru",
    "ya.ru",
    "yandex.net",
    "yastatic.net",
    "vk.com",
    "userapi.com",
    "vkuser.net",
    "mail.ru",
    "imgsmail.ru",
    "ozon.ru",
    "ozone.ru",
    "wb.ru",
    "wildberries.ru",
    "x5.ru",
    "sberbank.ru",
    "gosuslugi.ru",
    "rutube.ru",
    "avito.ru",
    "2gis.ru",
    "kaspersky.com",
    "rzd.ru",
    "tbank.ru",
    "tinkoff.ru",
    "alfabank.ru",
    "mts.ru",
    "megafon.ru",
    "beeline.ru",
    "rostelecom.ru",
    "dzen.ru",
    "kinopoisk.ru",
    "ok.ru",
)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _matches_suffix(host: str, suffixes: Tuple[str, ...]) -> bool:
    clean = host.strip().lower().rstrip(".")
    if not clean:
        return False
    return any(clean == s or clean.endswith("." + s) for s in suffixes)


def is_poisoned_sni(node: dict) -> bool:
    """Returns True when the node's TLS/Reality SNI uses a domain blocked by TSPU."""
    sni = (node.get("sni") or "").strip().lower()
    return _matches_suffix(sni, POISONED_SNI_SUFFIXES)


def tspu_score(node: dict) -> int:
    """Estimates TSPU/DPI resilience in RU (0..30 bonus points)."""
    if is_poisoned_sni(node):
        return 0

    score = 0
    scheme = node.get("scheme", "")
    security = (node.get("security") or "").lower()
    sni = (node.get("sni") or "").strip().lower()
    qs = node.get("query") or {}
    transport = ((qs.get("type") or ["tcp"])[0] or "tcp").lower()
    flow = ((qs.get("flow") or [""])[0] or "").lower()

    if security == "reality":
        score += 10
        if _matches_suffix(sni, RU_WHITELIST_SNI_SUFFIXES):
            score += 10
    elif scheme == "hysteria2":
        score += 6
        obfs = ((qs.get("obfs") or [""])[0] or "").lower()
        mport = ((qs.get("mport") or [""])[0] or "").strip()
        if obfs == "salamander":
            score += 8
        if mport:
            score += 6

    if transport in ("xhttp", "splithttp", "grpc"):
        score += 8
    elif flow == "xtls-rprx-vision":
        score += 6

    return min(30, score)


def build_upstream_proxy_outbound(proxy_uri: str, tag: str = "ru-entry") -> Optional[dict]:
    """Builds an Xray outbound for `RU_ENTRY_PROXY` (`socks5://` or `http://`) to probe from inside RU."""
    raw = (proxy_uri or "").strip()
    if not raw:
        return None
    parsed = urllib.parse.urlsplit(raw)
    scheme = parsed.scheme.lower()
    if scheme not in ("socks5", "socks5h", "socks", "http"):
        return None
    host = parsed.hostname
    port = parsed.port
    if not host or not port or not (0 < port < 65536):
        return None

    protocol = "socks" if scheme.startswith("socks") else "http"
    server: Dict[str, object] = {"address": host, "port": port}
    if parsed.username:
        user_entry: Dict[str, str] = {"user": urllib.parse.unquote(parsed.username)}
        user_entry["pass"] = urllib.parse.unquote(parsed.password or "")
        server["users"] = [user_entry]

    return {
        "tag": tag,
        "protocol": protocol,
        "settings": {"servers": [server]},
    }


def parse_trace_body(body: str) -> Dict[str, str]:
    """Parses Cloudflare `/cdn-cgi/trace` key=value lines."""
    fields: Dict[str, str] = {}
    for line in body.splitlines():
        key, sep, value = line.strip().partition("=")
        if sep and key:
            fields[key.strip()] = value.strip()
    return fields


async def _measure_speed_kbps(
    session: aiohttp.ClientSession,
    proxy_url: str,
    target_bytes: int,
    timeout: float,
) -> Optional[float]:
    url = f"https://speed.cloudflare.com/__down?bytes={target_bytes}"
    started = time.perf_counter()
    read_bytes = 0
    try:
        async with session.get(
            url,
            proxy=proxy_url,
            headers=PROBE_HEADERS,
            timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=False,
        ) as resp:
            if resp.status != 200:
                return None
            async for chunk in resp.content.iter_chunked(32768):
                read_bytes += len(chunk)
                if read_bytes >= target_bytes:
                    break
    except Exception:
        return None

    elapsed = max(time.perf_counter() - started, 1e-4)
    if read_bytes < min(16384, target_bytes):
        return None
    return round((read_bytes * 8.0 / 1000.0) / elapsed, 1)


async def probe_proxy_quality(
    session: aiohttp.ClientSession,
    proxy_url: str,
    timeout: float,
    semaphore: asyncio.Semaphore,
    *,
    reject_ru_exit: Optional[bool] = None,
    speedtest_bytes: Optional[int] = None,
    min_speed_kbps: Optional[float] = None,
    strict_speedtest: Optional[bool] = None,
) -> Tuple[str, Optional[float], Dict[str, object]]:
    """Verifies proxy connectivity, exit country (`loc`), and optional download throughput."""
    if reject_ru_exit is None:
        only_ru = _env_bool("ONLY_RU_IPS", True)
        reject_ru_exit = _env_bool("REJECT_RU_EXIT", only_ru)
    if speedtest_bytes is None:
        speedtest_bytes = max(0, int(os.getenv("E2E_SPEEDTEST_BYTES", "131072")))
    if min_speed_kbps is None:
        min_speed_kbps = max(0.0, float(os.getenv("E2E_MIN_SPEED_KBPS", "256")))
    if strict_speedtest is None:
        strict_speedtest = _env_bool("E2E_STRICT_SPEEDTEST", False)

    async with semaphore:
        latency_ms: Optional[float] = None
        exit_country: Optional[str] = None

        for target in TRACE_TARGETS:
            started = time.perf_counter()
            try:
                async with session.get(
                    target,
                    proxy=proxy_url,
                    headers=PROBE_HEADERS,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    allow_redirects=False,
                ) as resp:
                    status = str(resp.status)
                    if status == "200":
                        chunks = []
                        read_len = 0
                        too_large = False
                        async for chunk in resp.content.iter_chunked(4096):
                            read_len += len(chunk)
                            if read_len > MAX_TRACE_BYTES:
                                too_large = True
                                break
                            chunks.append(chunk)
                        if too_large:
                            return "failed", None, {"fail_reason": "oversized_trace"}
                        text = b"".join(chunks).decode("utf-8", errors="ignore")
                        trace = parse_trace_body(text)
                        if "ip" in trace or "loc" in trace:
                            latency_ms = round((time.perf_counter() - started) * 1000, 1)
                            loc = (trace.get("loc") or "").upper()
                            if len(loc) == 2 and loc.isalpha() and loc != "XX":
                                exit_country = loc
                            break
                    if status in RETRY_STATUSES:
                        continue
            except Exception:
                break

        if latency_ms is None:
            for target in FALLBACK_204_TARGETS:
                started = time.perf_counter()
                try:
                    async with session.get(
                        target,
                        proxy=proxy_url,
                        headers=PROBE_HEADERS,
                        timeout=aiohttp.ClientTimeout(total=timeout),
                        allow_redirects=False,
                    ) as resp:
                        status = str(resp.status)
                        if status in SUCCESS_STATUSES:
                            latency_ms = round((time.perf_counter() - started) * 1000, 1)
                            break
                        if status in RETRY_STATUSES:
                            continue
                        return "failed", None, {"fail_reason": "http_status"}
                except Exception:
                    return "failed", None, {"fail_reason": "unreachable"}

        if latency_ms is None:
            return "failed", None, {"fail_reason": "unreachable"}

        if reject_ru_exit and exit_country == "RU":
            return "failed", None, {"fail_reason": "ru_exit", "exit_country": "RU"}

        meta: Dict[str, object] = {}
        if exit_country:
            meta["exit_country"] = exit_country

        if speedtest_bytes > 0:
            speed_timeout = max(timeout, 6.0)
            speed_kbps = await _measure_speed_kbps(session, proxy_url, speedtest_bytes, speed_timeout)
            if speed_kbps is not None:
                meta["speed_kbps"] = speed_kbps
                if min_speed_kbps > 0 and speed_kbps < min_speed_kbps:
                    meta["fail_reason"] = "slow"
                    return "failed", None, meta
            elif strict_speedtest:
                meta["fail_reason"] = "speedtest_failed"
                return "failed", None, meta

        return "verified", latency_ms, meta
