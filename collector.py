#!/usr/bin/env python3
"""
Multi-Protocol VPN Aggregator & Connectivity Checker.

Collects VLESS, Trojan and Hysteria2 configs from HTTP(S) subscriptions and
Git repositories, validates them, removes exact duplicates, checks protocol
level reachability and writes normalized subscription files.

VMess and Shadowsocks are intentionally not supported: VMess is excluded by
project policy, Shadowsocks is unreliable behind TSPU.

Exit codes:
    0 - success
    1 - output guard triggered (previous subscription files are kept intact)
    2 - no usable sources / no nodes parsed
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import html
import ipaddress
import json
import logging
import os
import re
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse
from contextlib import suppress
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Tuple

import aiohttp

try:  # Hysteria2 runs over QUIC; without aioquic we cannot check it honestly.
    from aioquic.asyncio.client import connect as quic_connect
    from aioquic.quic.configuration import QuicConfiguration

    HAS_AIOQUIC = True
except ImportError:  # pragma: no cover - exercised only without the dependency
    quic_connect = None
    QuicConfiguration = None
    HAS_AIOQUIC = False


SOURCES_FILE = os.getenv("SOURCES_FILE", "sources.txt")
VLESS_OUTPUT = os.getenv("VLESS_OUTPUT", "vless_universal.txt")
HY2_OUTPUT = os.getenv("HY2_OUTPUT", "hysteria2.txt")
ALL_OUTPUT = os.getenv("ALL_OUTPUT", "all_universal.txt")
STATS_OUTPUT = os.getenv("STATS_OUTPUT", "stats.json")

TIMEOUT = float(os.getenv("PING_TIMEOUT", "3.0"))
QUIC_TIMEOUT = float(os.getenv("QUIC_TIMEOUT", "5.0"))
CHECK_ATTEMPTS = max(1, int(os.getenv("CHECK_ATTEMPTS", "2")))
MAX_CONCURRENT_PINGS = int(os.getenv("CONCURRENCY", "60"))
FETCH_TIMEOUT = float(os.getenv("FETCH_TIMEOUT", "20.0"))
FETCH_ATTEMPTS = max(1, int(os.getenv("FETCH_ATTEMPTS", "3")))
MAX_SOURCE_BYTES = int(os.getenv("MAX_SOURCE_BYTES", str(5 * 1024 * 1024)))
MAX_GIT_FILE_BYTES = int(os.getenv("MAX_GIT_FILE_BYTES", str(2 * 1024 * 1024)))
MAX_GIT_FILES = int(os.getenv("MAX_GIT_FILES", "2000"))

MIN_ALIVE = int(os.getenv("MIN_ALIVE", "10"))
MAX_DROP_RATIO = float(os.getenv("MAX_DROP_RATIO", "0.5"))
MAX_PER_ENDPOINT = max(1, int(os.getenv("MAX_PER_ENDPOINT", "3")))
MAX_REMARK_LEN = int(os.getenv("MAX_REMARK_LEN", "120"))

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
    ),
    "Accept": "*/*",
}

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("aggregator")
logging.getLogger("aioquic").setLevel(logging.CRITICAL)
logging.getLogger("aiohttp").setLevel(logging.WARNING)


class _DropAioquicNoise(logging.Filter):
    """QUIC handshake attempts are expected to fail; aioquic logs them at INFO/ERROR."""

    def filter(self, record: logging.LogRecord) -> bool:
        noisy = ("aioquic", "quic", "http3")
        if record.name.startswith(noisy):
            return False
        # aioquic cancels handshakes on timeout; asyncio reports the shielded future.
        if record.name == "asyncio" and "shielded future" in record.getMessage():
            return False
        return True


for _handler in logging.getLogger().handlers:
    _handler.addFilter(_DropAioquicNoise())

FLAG_REGEX = re.compile(r"[\U0001F1E6-\U0001F1FF]{2}")
COUNTRY_CODE_REGEX = re.compile(r"(?:^|[\s\[(_\-|])([A-Z]{2})(?:[\s\])_\-|.,;:]|$)")
SCHEME_ALIASES = {"hy2": "hysteria2"}
SUPPORTED_SCHEMES = ("vless", "trojan", "hysteria2")
SUPPORTED_PREFIXES = tuple(f"{s}://" for s in ("vless", "trojan", "hysteria2", "hy2"))

# Protocols that are deliberately excluded from this aggregator.
EXCLUDED_PREFIXES = ("vmess://", "ss://", "ssr://", "tuic://")

LINK_REGEX = re.compile(r"(?:vless|trojan|hysteria2|hy2)://[^\s\"'<>\\]+", re.IGNORECASE)
UUID_REGEX = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
INVISIBLE_REGEX = re.compile(r"[\x00-\x1f\x7f\u200b-\u200f\u202a-\u202e\ufeff]")
HOST_LABEL_REGEX = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?$")

COUNTRY_CODES = {
    "AE", "AM", "AR", "AT", "AU", "BE", "BG", "BR", "BY", "CA", "CH", "CY",
    "CZ", "DE", "DK", "EE", "ES", "FI", "FR", "GB", "GE", "GR", "HK", "HR",
    "HU", "ID", "IE", "IL", "IN", "IS", "IT", "JP", "KR", "KZ", "LT", "LU",
    "LV", "MD", "ME", "MT", "MX", "MY", "NL", "NO", "NZ", "PH", "PL", "PT",
    "RO", "RS", "RU", "SE", "SG", "SI", "SK", "TH", "TR", "TW", "UA", "US",
    "VN", "ZA",
}


class GuardError(RuntimeError):
    """Raised when the fresh output looks dangerously small."""


def code_to_flag(code: str) -> str:
    """Converts a two-letter ISO country code (e.g. 'RU') to a flag emoji."""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code.upper())


def sanitize_remark(remark: str) -> str:
    """Removes control/zero-width characters and normalizes whitespace."""
    remark = INVISIBLE_REGEX.sub(" ", remark)
    remark = re.sub(r"\s+", " ", remark).strip()
    return remark[:MAX_REMARK_LEN].strip()


def _valid_host(host: str) -> bool:
    if not host or len(host) > 253:
        return False
    if any(ch.isspace() or ord(ch) < 33 for ch in host):
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    labels = host.rstrip(".").split(".")
    return all(HOST_LABEL_REGEX.fullmatch(label) for label in labels)


def _split_userinfo(rest: str) -> List[Tuple[str, str]]:
    """Returns candidate (userinfo, host_query) splits.

    Standard URIs have a single '@'; some sources put a raw '@' inside the
    password or inside a query value, so try the first and the last separator.
    """
    candidates: List[Tuple[str, str]] = []
    first = rest.partition("@")
    if first[1]:
        candidates.append((first[0], first[2]))
    last = rest.rpartition("@")
    if last[1] and (not candidates or last[0] != candidates[0][0]):
        candidates.append((last[0], last[2]))
    if not candidates:
        return [("", rest)]
    return candidates


def _parse_host_port(host_port: str) -> Optional[Tuple[str, int]]:
    """Returns (host, port) or None. Port 0 means 'use the protocol default'."""
    host_port = host_port.rstrip("/")
    if not host_port:
        return None

    if host_port.startswith("["):
        end = host_port.find("]")
        if end < 0:
            return None
        host = host_port[1:end]
        remainder = host_port[end + 1 :]
        if remainder.startswith(":"):
            port_str = remainder[1:]
        elif remainder:
            return None
        else:
            port_str = ""
    else:
        if host_port.count(":") > 1:
            return None  # unbracketed IPv6
        host, sep, port_str = host_port.partition(":")
        if not sep:
            port_str = ""

    if port_str:
        if not port_str.isdigit():
            return None
        port = int(port_str)
        if not 0 < port < 65536:
            return None
        return host, port
    return host, 0


def parse_vpn_link(link: str) -> Optional[dict]:
    """Parses and validates a supported VPN URI into structured fields."""
    link = link.strip()
    if not link or len(link) > 8192:
        return None

    scheme, sep, rest = link.partition("://")
    scheme = scheme.lower()
    if not sep or scheme not in ("vless", "trojan", "hysteria2", "hy2"):
        return None

    canonical = SCHEME_ALIASES.get(scheme, scheme)
    url_part, _, raw_remark = rest.partition("#")
    remark = sanitize_remark(urllib.parse.unquote(raw_remark))

    parsed: Optional[Tuple[str, str, Tuple[str, int]]] = None
    for raw_userinfo, host_query in _split_userinfo(url_part):
        candidate_userinfo = urllib.parse.unquote(raw_userinfo).strip()
        candidate_host_port, _, candidate_query = host_query.partition("?")
        candidate_host = _parse_host_port(candidate_host_port)
        if candidate_host and _valid_host(candidate_host[0]):
            parsed = (candidate_userinfo, candidate_query, candidate_host)
            break
    if not parsed:
        return None

    userinfo, raw_query, parsed_host = parsed
    host, port = parsed_host

    default_port = 8443 if canonical == "hysteria2" else 443
    port = port or default_port
    if not 0 < port < 65536:
        return None

    qs = urllib.parse.parse_qs(raw_query, keep_blank_values=True)
    sni = (qs.get("sni") or qs.get("host") or [""])[0].strip()

    if canonical == "vless":
        if not UUID_REGEX.match(userinfo):
            return None
        if (qs.get("security") or [""])[0].lower() == "reality" and not (qs.get("pbk") or [""])[0]:
            return None
    elif canonical == "trojan":
        if not userinfo:
            return None
    # Hysteria2 auth is optional, so an empty userinfo is valid.

    flag = _detect_flag(remark)
    if not flag:
        flag = "🌐"
    elif flag not in remark:
        remark = sanitize_remark(f"{flag} {remark}")

    key = _dedup_key(canonical, host, port, userinfo, sni, qs)
    return {
        "scheme": canonical,
        "link": link,
        "host": host,
        "port": port,
        "sni": sni,
        "flag": flag,
        "remark": remark or "🌐",
        "transport": "udp" if canonical == "hysteria2" else "tcp",
        "credential": userinfo,
        "query": qs,
        "dedup_key": key,
    }


def _detect_flag(remark: str) -> Optional[str]:
    flag_match = FLAG_REGEX.search(remark)
    if flag_match:
        return flag_match.group(0)
    code_match = COUNTRY_CODE_REGEX.search(remark)
    if code_match and code_match.group(1) in COUNTRY_CODES:
        return code_to_flag(code_match.group(1))
    return None


def _dedup_key(
    scheme: str,
    host: str,
    port: int,
    credential: str,
    sni: str,
    qs: Dict[str, List[str]],
) -> str:
    """Identity of a config: endpoint + credentials + every transport parameter."""
    query = urllib.parse.urlencode(sorted((k, v) for k, values in qs.items() for v in values))
    return "|".join(
        [
            scheme,
            host.lower(),
            str(port),
            credential,
            (sni or "").lower(),
            query,
        ]
    )


async def check_connectivity(node: dict, timeout: Optional[float] = None) -> bool:
    """Checks protocol-level reachability of a single node (one attempt)."""
    host, port = node["host"], node["port"]
    if node["transport"] == "udp":
        return await _check_quic(node, timeout if timeout is not None else QUIC_TIMEOUT)

    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout or TIMEOUT
        )
        writer.close()
        with suppress(Exception):
            await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
        return True
    except Exception:
        return False


async def _check_quic(node: dict, timeout: float) -> bool:
    """Completes a QUIC v1 handshake (ALPN h3) with the Hysteria2 endpoint."""
    if not HAS_AIOQUIC:
        return False

    host, port = node["host"], node["port"]
    config = QuicConfiguration(is_client=True, alpn_protocols=["h3"], verify_mode=ssl.CERT_NONE)
    config.server_name = node["sni"] or node["host"]

    try:
        async with asyncio.timeout(timeout):
            async with quic_connect(host, port, configuration=config):
                return True
    except Exception:
        return False


async def verify_node(node: dict, semaphore: asyncio.Semaphore) -> bool:
    """Checks a node with retries, limited by the shared semaphore."""
    async with semaphore:
        for attempt in range(1, CHECK_ATTEMPTS + 1):
            if await check_connectivity(node):
                return True
            if attempt < CHECK_ATTEMPTS:
                await asyncio.sleep(0.4 * attempt)
        return False


def _clean_git_url(repo_url: str) -> str:
    url = repo_url[4:] if repo_url.startswith("git+") else repo_url
    url = url.strip()
    if not url.startswith(("https://", "http://")):
        raise ValueError(f"unsupported git URL: {repo_url}")
    if not url.endswith(".git") and ("gitlab.com" in url or "github.com" in url):
        url = url.rstrip("/") + ".git"
    return url


def _clone_git_repo(repo_url: str) -> List[str]:
    """Clones a Git repository and recursively extracts links from text files."""
    try:
        clean_url = _clean_git_url(repo_url)
    except ValueError as exc:
        logger.warning(str(exc))
        return []

    configs: List[str] = []
    files_read = 0
    with tempfile.TemporaryDirectory() as tmpdir:
        res = subprocess.run(
            ["git", "clone", "--depth", "1", "--single-branch", "--no-tags", "--quiet", clean_url, tmpdir],
            capture_output=True,
            text=True,
            timeout=90,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
        if res.returncode != 0:
            logger.warning(f"Failed to clone {clean_url}: {res.stderr.strip()[:160]}")
            return []

        for root, dirs, files in os.walk(tmpdir):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d != "__pycache__"]
            for fname in sorted(files):
                if not fname.lower().endswith((".txt", ".md", ".yaml", ".yml")):
                    continue
                if files_read >= MAX_GIT_FILES:
                    logger.warning(f"Git source {clean_url}: file limit reached ({MAX_GIT_FILES})")
                    break
                fpath = os.path.join(root, fname)
                try:
                    if os.path.getsize(fpath) > MAX_GIT_FILE_BYTES:
                        continue
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        text = f.read(MAX_GIT_FILE_BYTES)
                except OSError:
                    continue
                files_read += 1
                configs.extend(extract_links(text))
            if files_read >= MAX_GIT_FILES:
                break

    logger.info(f" -> Found {len(configs)} configs from Git repo: {clean_url}")
    return configs


def _decode_base64(text: str) -> Optional[str]:
    compact = re.sub(r"\s+", "", text)
    if not compact or len(compact) < 16:
        return None
    padded = compact + "=" * (-len(compact) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = decoder(padded)
            decoded = raw.decode("utf-8", errors="ignore")
        except (binascii.Error, ValueError):
            continue
        if "://" in decoded:
            return decoded
    return None


def extract_links(body: str) -> List[str]:
    """Extracts supported links from raw text or a base64 subscription body."""
    body = body.strip()
    if not body:
        return []

    links = LINK_REGEX.findall(body)
    if not links:
        decoded = _decode_base64(body)
        if decoded:
            links = LINK_REGEX.findall(decoded)

    cleaned: List[str] = []
    seen = set()
    for link in links:
        # Some sources embed links in HTML/markdown attributes ("&amp;").
        link = html.unescape(link).strip().rstrip(",;")
        if link in seen:
            continue
        seen.add(link)
        cleaned.append(link)
    return cleaned


def _looks_like_html(body: str) -> bool:
    head = body[:1024].lower()
    return "<html" in head or "<!doctype html" in head


async def _fetch_once(session: aiohttp.ClientSession, url: str) -> Tuple[bool, str]:
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=FETCH_TIMEOUT)) as resp:
            if resp.status != 200:
                retryable = resp.status == 429 or resp.status >= 500
                logger.warning(f"Failed to fetch {url}: HTTP {resp.status}")
                return retryable, ""
            raw = await resp.content.read(MAX_SOURCE_BYTES + 1)
            if len(raw) > MAX_SOURCE_BYTES:
                logger.warning(f"Source {url} exceeds {MAX_SOURCE_BYTES} bytes; truncating")
                raw = raw[:MAX_SOURCE_BYTES]
            return True, raw.decode(resp.charset or "utf-8", errors="ignore")
    except Exception as exc:
        logger.warning(f"Error fetching {url}: {type(exc).__name__}: {exc}")
        return True, ""


async def fetch_source(session: aiohttp.ClientSession, url: str) -> List[str]:
    """Fetches a URL with retries and extracts supported links."""
    url = url.strip()
    if not url or url.startswith("#"):
        return []

    if url.startswith("git+") or (url.endswith(".git") and ("gitlab.com" in url or "github.com" in url)):
        logger.info(f"Cloning Git source: {url}")
        return await asyncio.to_thread(_clone_git_repo, url)

    logger.info(f"Downloading source: {url}")
    body = ""
    for attempt in range(1, FETCH_ATTEMPTS + 1):
        retryable, body = await _fetch_once(session, url)
        if body:
            break
        if not retryable or attempt == FETCH_ATTEMPTS:
            break
        await asyncio.sleep(min(2 ** attempt, 8))

    if not body:
        return []

    if _looks_like_html(body) and not LINK_REGEX.search(body):
        logger.warning(f"Skipping HTML page from {url}")
        return []

    configs = extract_links(body)
    logger.info(f" -> Found {len(configs)} configs from {url}")
    return configs


def format_link(node: dict) -> str:
    """Rebuilds the link with a standardized, URL-encoded remark."""
    base_link = node["link"].partition("#")[0]
    return f"{base_link}#{urllib.parse.quote(node['remark'], safe='')}"


def read_previous_count(path: str) -> int:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return sum(1 for line in f if line.strip())
    except FileNotFoundError:
        return 0


def enforce_guard(alive: int, previous: int, min_alive: int = MIN_ALIVE, max_drop: float = MAX_DROP_RATIO) -> None:
    """Refuses to publish an empty or collapsed subscription."""
    if alive < min_alive:
        raise GuardError(f"only {alive} alive nodes (< MIN_ALIVE={min_alive})")
    if previous and alive < previous * (1 - max_drop):
        raise GuardError(
            f"alive nodes dropped from {previous} to {alive} "
            f"(> {int(max_drop * 100)}% loss)"
        )


def cap_per_endpoint(nodes: List[dict], limit: int = MAX_PER_ENDPOINT) -> List[dict]:
    """Keeps a few alternative credentials per server to avoid subscription spam."""
    capped: List[dict] = []
    counts: Dict[tuple, int] = {}
    for node in nodes:
        endpoint = (node["scheme"], node["host"].lower(), node["port"], node["sni"].lower())
        if counts.get(endpoint, 0) >= limit:
            continue
        counts[endpoint] = counts.get(endpoint, 0) + 1
        capped.append(node)
    return capped


def write_atomic(path: str, lines: Iterable[str]) -> None:
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    os.replace(tmp, path)


def write_json_atomic(path: str, payload: dict) -> None:
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp, path)


def _load_sources(path: str) -> List[str]:
    if not os.path.exists(path):
        logger.error(f"Sources file '{path}' not found!")
        return []
    with open(path, "r", encoding="utf-8") as f:
        urls = [
            line.strip()
            for line in f
            if line.strip() and not line.strip().startswith("#")
        ]
    # Preserve order while removing duplicates.
    return list(dict.fromkeys(urls))


async def main() -> int:
    started = time.monotonic()
    source_urls = _load_sources(SOURCES_FILE)
    if not source_urls:
        logger.error("No usable sources found.")
        return 2

    if not HAS_AIOQUIC:
        logger.error("aioquic is not installed: Hysteria2 nodes cannot be verified and will be dropped.")
    logger.info(f"Loaded {len(source_urls)} sources to process.")

    fetch_sem = asyncio.Semaphore(8)
    all_raw_links: List[str] = []
    fetched_ok = 0

    async with aiohttp.ClientSession(headers=DEFAULT_HEADERS) as session:
        async def fetch_limited(url: str) -> List[str]:
            async with fetch_sem:
                return await fetch_source(session, url)

        results = await asyncio.gather(*[fetch_limited(u) for u in source_urls])
    for result in results:
        if result:
            fetched_ok += 1
            all_raw_links.extend(result)

    logger.info(f"Total raw links collected: {len(all_raw_links)} (sources with data: {fetched_ok})")
    if not all_raw_links:
        logger.error("No links collected from any source; keeping previous files.")
        return 2

    seen_keys = set()
    parsed_nodes: List[dict] = []
    rejected = 0
    for raw in all_raw_links:
        parsed = parse_vpn_link(raw)
        if not parsed or parsed["dedup_key"] in seen_keys:
            if not parsed:
                rejected += 1
            continue
        seen_keys.add(parsed["dedup_key"])
        parsed_nodes.append(parsed)

    logger.info(f"Unique valid nodes: {len(parsed_nodes)} (rejected invalid: {rejected})")
    if not parsed_nodes:
        logger.error("No valid nodes parsed; keeping previous files.")
        return 2

    candidates = cap_per_endpoint(parsed_nodes)
    capped = len(parsed_nodes) - len(candidates)
    logger.info(
        f"Candidates after endpoint cap: {len(candidates)} "
        f"(skipped {capped} duplicate endpoints, MAX_PER_ENDPOINT={MAX_PER_ENDPOINT})"
    )

    protocol_counts: Dict[str, int] = {}
    for node in candidates:
        protocol_counts[node["scheme"]] = protocol_counts.get(node["scheme"], 0) + 1
    logger.info("Candidate protocols: " + ", ".join(f"{k.upper()}={v}" for k, v in sorted(protocol_counts.items())))

    semaphore = asyncio.Semaphore(MAX_CONCURRENT_PINGS)
    logger.info(f"Checking reachability (workers={MAX_CONCURRENT_PINGS})...")
    check_results = await asyncio.gather(
        *[verify_node(node, semaphore) for node in candidates]
    )

    alive_nodes = [node for node, is_alive in zip(candidates, check_results, strict=True) if is_alive]
    reachable = len(alive_nodes)

    alive_counts: Dict[str, int] = {}
    country_counts: Dict[str, int] = {}
    for node in alive_nodes:
        proto = node["scheme"]
        alive_counts[proto] = alive_counts.get(proto, 0) + 1
        country_counts[node["flag"]] = country_counts.get(node["flag"], 0) + 1

    logger.info(f"✅ Total alive nodes: {reachable} / {len(candidates)} checked")
    for proto, count in sorted(alive_counts.items(), key=lambda item: -item[1]):
        logger.info(f"  {proto.upper()}: {count}")
    logger.info("Top countries:")
    for flag, count in sorted(country_counts.items(), key=lambda item: -item[1])[:8]:
        logger.info(f"  {flag}: {count}")

    previous_total = read_previous_count(ALL_OUTPUT)
    try:
        enforce_guard(len(alive_nodes), previous_total)
    except GuardError as exc:
        logger.error(f"Output guard triggered: {exc}. Previous files are kept unchanged.")
        return 1

    vless_lines = [format_link(n) for n in alive_nodes if n["scheme"] == "vless"]
    hy2_lines = [format_link(n) for n in alive_nodes if n["scheme"] == "hysteria2"]
    all_lines = [format_link(n) for n in alive_nodes]

    write_atomic(VLESS_OUTPUT, vless_lines)
    write_atomic(HY2_OUTPUT, hy2_lines)
    write_atomic(ALL_OUTPUT, all_lines)
    logger.info(f"Exported {len(vless_lines)} VLESS nodes -> {VLESS_OUTPUT}")
    logger.info(f"Exported {len(hy2_lines)} Hysteria2 nodes -> {HY2_OUTPUT}")
    logger.info(f"Exported {len(all_lines)} all-protocol nodes -> {ALL_OUTPUT}")

    elapsed = round(time.monotonic() - started, 1)
    write_json_atomic(
        STATS_OUTPUT,
        {
            "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "duration_sec": elapsed,
            "sources_total": len(source_urls),
            "sources_with_data": fetched_ok,
            "raw_links": len(all_raw_links),
            "unique_valid": len(parsed_nodes),
            "candidates_after_cap": len(candidates),
            "rejected_invalid": rejected,
            "reachable": reachable,
            "capped_by_endpoint": capped,
            "alive": len(alive_nodes),
            "alive_by_protocol": dict(sorted(alive_counts.items())),
            "top_countries": dict(sorted(country_counts.items(), key=lambda item: -item[1])[:15]),
            "previous_total": previous_total,
            "checks": {
                "vless": "tcp_connect",
                "trojan": "tcp_connect",
                "hysteria2": "quic_v1_handshake_h3" if HAS_AIOQUIC else "unverified",
            },
        },
    )
    logger.info(f"Wrote run statistics -> {STATS_OUTPUT} ({elapsed}s)")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
