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
import hashlib
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
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, List, Optional, Tuple

import aiohttp
from cryptography.hazmat.primitives import serialization

import e2e

try:  # Hysteria2 runs over QUIC; without aioquic we cannot check it honestly.
    from aioquic.asyncio.client import connect as quic_connect
    from aioquic.quic.configuration import QuicConfiguration

    HAS_AIOQUIC = True
except ImportError:  # pragma: no cover - exercised only without the dependency
    quic_connect = None  # type: ignore[assignment]
    QuicConfiguration = None  # type: ignore[misc,assignment]
    HAS_AIOQUIC = False


SOURCES_FILE = os.getenv("SOURCES_FILE", "sources.txt")
VLESS_OUTPUT = os.getenv("VLESS_OUTPUT", "vless_universal.txt")
HY2_OUTPUT = os.getenv("HY2_OUTPUT", "hysteria2.txt")
ALL_OUTPUT = os.getenv("ALL_OUTPUT", "all_universal.txt")
STATS_OUTPUT = os.getenv("STATS_OUTPUT", "stats.json")
SOURCE_HEALTH_FILE = os.getenv("SOURCE_HEALTH_FILE", "source_health.json")
NODE_HISTORY_FILE = os.getenv("NODE_HISTORY_FILE", "node_history.json")
HISTORY_FILE = os.getenv("HISTORY_FILE", "history.json")
META_FILE = os.getenv("META_FILE", "meta.json")

PROFILE_TITLE = os.getenv("PROFILE_TITLE", "BarqDev Multi-Protocol VPN")
SUPPORT_URL = os.getenv(
    "SUPPORT_URL", "https://github.com/BarqDev1/vless-aggregator/issues"
)
PROFILE_UPDATE_INTERVAL = int(os.getenv("PROFILE_UPDATE_INTERVAL", "1"))
HOME_URL = os.getenv("HOME_URL", "https://github.com/BarqDev1/vless-aggregator")

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
MAX_PER_SUBNET = max(1, int(os.getenv("MAX_PER_SUBNET", "3")))
MAX_PER_DOMAIN = max(1, int(os.getenv("MAX_PER_DOMAIN", "10")))
MAX_REMARK_LEN = int(os.getenv("MAX_REMARK_LEN", "120"))

NODE_MIN_RECENT_SUCCESS = max(1, int(os.getenv("NODE_MIN_RECENT_SUCCESS", "2")))
NODE_RECENT_WINDOW = max(1, int(os.getenv("NODE_RECENT_WINDOW", "3")))
NODE_HISTORY_TTL_DAYS = max(1, int(os.getenv("NODE_HISTORY_TTL_DAYS", "30")))
MAX_NODE_HISTORY = max(100, int(os.getenv("MAX_NODE_HISTORY", "10000")))
HISTORY_MAX_RUNS = max(24, int(os.getenv("HISTORY_MAX_RUNS", "720")))

PROTOCOL_MIN_ALIVE = max(1, int(os.getenv("PROTOCOL_MIN_ALIVE", "3")))
PROTOCOL_MAX_DROP = float(os.getenv("PROTOCOL_MAX_DROP", "0.7"))

SOURCE_FAILURE_THRESHOLD = max(1, int(os.getenv("SOURCE_FAILURE_THRESHOLD", "3")))
SOURCE_QUARANTINE_HOURS = float(os.getenv("SOURCE_QUARANTINE_HOURS", "24"))

E2E_VERIFY = os.getenv("E2E_VERIFY", "0").strip().lower() in {"1", "true", "yes", "on"}
E2E_CONCURRENCY = max(1, int(os.getenv("E2E_CONCURRENCY", "6")))
E2E_TIMEOUT = float(os.getenv("E2E_TIMEOUT", "7.0"))
XRAY_BIN = os.getenv("XRAY_BIN", "xray")
BASELINE_RESET = os.getenv("BASELINE_RESET", "0").strip().lower() in {"1", "true", "yes", "on"}

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
    security = (qs.get("security") or [""])[0].lower()
    if canonical == "hysteria2":
        pinned = (qs.get("pinSHA256") or qs.get("pinsha256") or [""])[0].strip()
    else:
        pinned = (qs.get("pcs") or [""])[0].strip() if security == "tls" else ""

    if canonical == "vless":
        if not UUID_REGEX.match(userinfo):
            return None
        # New Xray-core refuses plaintext VLESS to public addresses, so only
        # TLS or Reality nodes are usable in modern clients (INCY, v2rayN, ...).
        if security not in ("tls", "reality"):
            return None
        if security == "reality" and not (qs.get("pbk") or [""])[0]:
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
        "security": security,
        "flag": flag,
        "remark": remark or "🌐",
        "transport": "udp" if canonical == "hysteria2" else "tcp",
        "credential": userinfo,
        "query": qs,
        "tls_mode": "pinned" if pinned else None,
        "tls_cert_sha256": pinned or None,
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


async def _check_tcp(node: dict, timeout: float) -> bool:
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


async def check_connectivity(node: dict, timeout: Optional[float] = None) -> bool:
    """Checks protocol-level reachability of a single node (one attempt)."""
    return await probe_node(node, timeout) is not None


async def probe_node(node: dict, timeout: Optional[float] = None) -> Optional[float]:
    """Returns handshake latency in milliseconds when the node answers."""
    started = time.perf_counter()
    if node["transport"] == "udp":
        alive = await _check_quic(node, timeout if timeout is not None else QUIC_TIMEOUT)
    else:
        alive = await _check_tcp(node, timeout if timeout is not None else TIMEOUT)
    if not alive:
        return None
    return round((time.perf_counter() - started) * 1000, 1)


async def _check_quic(node: dict, timeout: float) -> bool:
    """Completes a QUIC v1 handshake (ALPN h3) with the Hysteria2 endpoint."""
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


async def inspect_tls(node: dict, timeout: float = 6.0) -> Tuple[Optional[str], Optional[str]]:
    """Classifies a TLS node as CA-valid or self-signed (returns its cert hash).

    Modern Xray-core removed `allowInsecure`, so subscriptions must either use
    a CA-valid certificate or pin the leaf certificate with `pcs`.
    """
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


async def verify_node(node: dict, semaphore: asyncio.Semaphore) -> Optional[float]:
    """Checks a node with retries, limited by the shared semaphore."""
    async with semaphore:
        for attempt in range(1, CHECK_ATTEMPTS + 1):
            latency = await probe_node(node)
            if latency is not None:
                node["latency_ms"] = latency
                return latency
            if attempt < CHECK_ATTEMPTS:
                await asyncio.sleep(0.4 * attempt)
        return None


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
    """Rebuilds the link, removing deprecated TLS flags and adding `pcs`.

    New Xray-core (and INCY v3.7.9+) reject `allowInsecure`/`insecure`:
    - CA-valid TLS nodes need neither flag;
    - self-signed TLS nodes are pinned with `pcs=<sha256>`;
    - Reality works without insecure flags;
    - Hysteria2 keeps its own `insecure` parameter.
    """
    base_link = node["link"].partition("#")[0]
    scheme, _, rest = base_link.partition("://")
    location, separator, query = rest.partition("?")
    pairs = urllib.parse.parse_qsl(query, keep_blank_values=True) if separator else []

    if node["scheme"] in ("vless", "trojan"):
        pairs = [
            (key, value)
            for key, value in pairs
            if key.lower() not in ("insecure", "allowinsecure", "pcs")
        ]
        if node.get("security") == "tls" and node.get("tls_cert_sha256"):
            pairs.append(("pcs", node["tls_cert_sha256"]))
    else:
        pairs = [
            (key, value)
            for key, value in pairs
            if key.lower() not in ("insecure", "allowinsecure", "pinsha256", "pcs")
        ]
        if node.get("tls_cert_sha256"):
            pairs.append(("pinSHA256", node["tls_cert_sha256"]))

    rebuilt = f"{scheme}://{location}"
    if pairs:
        rebuilt += "?" + urllib.parse.urlencode(pairs)
    return f"{rebuilt}#{urllib.parse.quote(node['remark'], safe='')}"


def read_previous_count(path: str) -> int:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return sum(1 for line in f if line.strip())
    except FileNotFoundError:
        return 0


def load_previous_stats(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, ValueError, OSError):
        return {}


def enforce_guard(
    alive: int,
    previous: int,
    min_alive: int = MIN_ALIVE,
    max_drop: float = MAX_DROP_RATIO,
    protocol_counts: Optional[Dict[str, int]] = None,
    previous_protocols: Optional[Dict[str, int]] = None,
    protocol_min: int = PROTOCOL_MIN_ALIVE,
    protocol_max_drop: float = PROTOCOL_MAX_DROP,
    allow_baseline_reset: bool = False,
) -> None:
    """Refuses to publish an empty, collapsed or protocol-degraded subscription."""
    if alive < min_alive:
        raise GuardError(f"only {alive} alive nodes (< MIN_ALIVE={min_alive})")

    if allow_baseline_reset:
        return

    if previous and alive < previous * (1 - max_drop):
        raise GuardError(
            f"alive nodes dropped from {previous} to {alive} "
            f"(> {int(max_drop * 100)}% loss)"
        )

    for protocol, previous_count in (previous_protocols or {}).items():
        if previous_count < protocol_min:
            continue
        current = (protocol_counts or {}).get(protocol, 0)
        if current == 0:
            raise GuardError(f"{protocol} disappeared completely (was {previous_count})")
        if current < previous_count * (1 - protocol_max_drop):
            raise GuardError(
                f"{protocol} dropped from {previous_count} to {current} "
                f"(> {int(protocol_max_drop * 100)}% loss)"
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


MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "com.au", "net.au", "org.au", "co.jp", "ne.jp",
    "or.jp", "co.kr", "or.kr", "com.br", "com.tr", "co.in", "com.cn", "com.tw",
    "com.sg", "co.id", "co.nz", "co.za", "com.mx", "com.ar", "com.hk", "com.my",
    "com.ph", "com.vn", "co.th",
}


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
    counts: Dict[str, int] = {}
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


def cap_for_diversity(nodes: List[dict]) -> Tuple[List[dict], Dict[str, int]]:
    """Limits repeated endpoints, subnets and registrable domains."""
    kept, endpoint_removed = _cap_by_key(
        nodes,
        lambda n: (n["scheme"], n["host"].lower(), n["port"], n["sni"].lower()),
        MAX_PER_ENDPOINT,
    )
    kept, diversity = cap_diversity(kept)
    return kept, {"endpoint": endpoint_removed, **diversity}


def cap_diversity(nodes: List[dict]) -> Tuple[List[dict], Dict[str, int]]:
    """Limits repeated subnets and registrable domains after verification."""
    kept, subnet_removed = _cap_by_key(nodes, _subnet_key, MAX_PER_SUBNET)
    kept, domain_removed = _cap_by_key(kept, _domain_key, MAX_PER_DOMAIN)
    return kept, {"subnet": subnet_removed, "domain": domain_removed}


def load_source_health(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        if isinstance(data, dict) and isinstance(data.get("sources"), dict):
            return data
    except (FileNotFoundError, ValueError, OSError):
        pass
    return {"updated_at": None, "sources": {}}


def _parse_datetime(value: object) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def select_active_sources(urls: List[str], health: dict, now: datetime) -> Tuple[List[str], List[str]]:
    active: List[str] = []
    skipped: List[str] = []
    for url in urls:
        entry = health.get("sources", {}).get(url, {})
        until = _parse_datetime(entry.get("quarantined_until"))
        if until and until > now:
            skipped.append(url)
        else:
            active.append(url)
    return active, skipped


def update_source_health(health: dict, urls: List[str], source_stats: Dict[str, dict], now: datetime) -> dict:
    """Updates consecutive failure counters and quarantines useless sources."""
    old_sources = health.get("sources", {})
    sources: Dict[str, dict] = {}
    for url in urls:
        old = old_sources.get(url, {})
        stat = source_stats.get(url, {})
        if stat.get("active") is False:
            sources[url] = old
            continue

        failures = int(old.get("consecutive_failures", 0))
        raw = int(stat.get("raw", 0))
        unique = int(stat.get("unique", 0))
        alive = int(stat.get("alive", 0))

        if alive > 0:
            failures = 0
            quarantined_until = None
        else:
            failures += 1
            quarantined_until = old.get("quarantined_until")
            if failures >= SOURCE_FAILURE_THRESHOLD:
                quarantined_until = (now + timedelta(hours=SOURCE_QUARANTINE_HOURS)).isoformat(
                    timespec="seconds"
                )

        sources[url] = {
            "consecutive_failures": failures,
            "last_raw": raw,
            "last_unique": unique,
            "last_alive": alive,
            "last_checked_at": now.isoformat(timespec="seconds"),
            "quarantined_until": quarantined_until,
        }

    return {"updated_at": now.isoformat(timespec="seconds"), "sources": sources}


def node_history_id(node: dict) -> str:
    """Stable, non-reversible ID for node history (credentials are not stored)."""
    return hashlib.sha256(node["dedup_key"].encode("utf-8")).hexdigest()[:32]


def load_history_list(path: str) -> List[dict]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return [entry for entry in data if isinstance(entry, dict)] if isinstance(data, list) else []
    except (FileNotFoundError, ValueError, OSError):
        return []


def load_node_history(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        if isinstance(data, dict) and isinstance(data.get("nodes"), dict):
            return data
    except (FileNotFoundError, ValueError, OSError):
        pass
    return {"updated_at": None, "nodes": {}}


def update_node_history(
    state: dict,
    tested_nodes: List[dict],
    verified_nodes: List[dict],
    now: datetime,
) -> Tuple[dict, set, Dict[str, int]]:
    """Implements the 2-of-3 stability policy and returns publishable node IDs."""
    raw_nodes = state.get("nodes")
    old_nodes: Dict[str, dict] = raw_nodes if isinstance(raw_nodes, dict) else {}
    nodes: Dict[str, dict] = {str(key): dict(value) for key, value in old_nodes.items()}
    bootstrap = not nodes

    tested_ids = {node_history_id(node) for node in tested_nodes}
    verified_ids = {node_history_id(node) for node in verified_nodes}
    timestamp = now.isoformat(timespec="seconds")

    for node in verified_nodes:
        node_id = node_history_id(node)
        entry = nodes.setdefault(
            node_id,
            {"recent": [], "successes": 0, "failures": 0, "first_seen": timestamp},
        )
        recent = [True, True] if bootstrap else [*entry.get("recent", []), True]
        entry["recent"] = recent[-NODE_RECENT_WINDOW:]
        entry["successes"] = int(entry.get("successes", 0)) + 1
        entry["last_seen"] = timestamp
        entry["last_success"] = timestamp
        nodes[node_id] = entry

    for node_id in tested_ids - verified_ids:
        failed_entry = nodes.get(node_id)
        if failed_entry is None:
            continue
        failed_entry["recent"] = [*failed_entry.get("recent", []), False][-NODE_RECENT_WINDOW:]
        failed_entry["failures"] = int(failed_entry.get("failures", 0)) + 1
        failed_entry["last_seen"] = timestamp

    cutoff = now - timedelta(days=NODE_HISTORY_TTL_DAYS)
    pruned = 0
    for node_id, entry in list(nodes.items()):
        last_seen = _parse_datetime(entry.get("last_seen"))
        if last_seen and last_seen < cutoff:
            del nodes[node_id]
            pruned += 1

    if len(nodes) > MAX_NODE_HISTORY:
        newest = sorted(
            nodes.items(),
            key=lambda item: item[1].get("last_seen") or "",
            reverse=True,
        )[:MAX_NODE_HISTORY]
        pruned += len(nodes) - len(newest)
        nodes = dict(newest)

    eligible: set = set()
    for node_id in verified_ids:
        entry = nodes.get(node_id, {})
        recent = entry.get("recent", [])[-NODE_RECENT_WINDOW:]
        if sum(bool(result) for result in recent) >= NODE_MIN_RECENT_SUCCESS:
            eligible.add(node_id)

    stats = {
        "tracked": len(nodes),
        "bootstrap": int(bootstrap),
        "verified": len(verified_ids),
        "eligible": len(eligible),
        "held_back": len(verified_ids - eligible),
        "pruned": pruned,
    }
    return {"updated_at": timestamp, "nodes": nodes}, eligible, stats


def build_meta(alive_counts: Dict[str, int], total: int, now: datetime) -> dict:
    raw_base = (
        "https://raw.githubusercontent.com/"
        f"{os.getenv('GITHUB_REPOSITORY', 'BarqDev1/vless-aggregator')}/main"
    )
    return {
        "profile_title": PROFILE_TITLE,
        "profile_update_interval": PROFILE_UPDATE_INTERVAL,
        "support_url": SUPPORT_URL,
        "home_url": HOME_URL,
        "subscription_userinfo": None,
        "updated_at": now.isoformat(timespec="seconds"),
        "counts": {"total": total, **dict(sorted(alive_counts.items()))},
        "subscriptions": {
            "all": f"{raw_base}/all_universal.txt",
            "vless": f"{raw_base}/vless_universal.txt",
            "hysteria2": f"{raw_base}/hysteria2.txt",
        },
    }


def _percentile(values: List[float], quantile: float) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((quantile / 100) * (len(ordered) - 1))))
    return round(ordered[index], 1)


def latency_summary(nodes: List[dict]) -> Dict[str, float]:
    values: List[float] = []
    for node in nodes:
        value = node.get("e2e_ms") if node.get("e2e_ms") is not None else node.get("latency_ms")
        if isinstance(value, (int, float)):
            values.append(float(value))
    if not values:
        return {}
    return {
        "p50": _percentile(values, 50) or 0.0,
        "p90": _percentile(values, 90) or 0.0,
        "min": round(min(values), 1),
        "max": round(max(values), 1),
    }


def write_atomic(path: str, lines: Iterable[str]) -> None:
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    os.replace(tmp, path)


def write_json_atomic(path: str, payload) -> None:
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
    now = datetime.now(timezone.utc)

    source_urls = _load_sources(SOURCES_FILE)
    if not source_urls:
        logger.error("No usable sources found.")
        return 2

    xray_bin = XRAY_BIN
    if E2E_VERIFY:
        try:
            xray_bin = e2e.ensure_binaries(XRAY_BIN)
        except e2e.E2ERuntimeError as exc:
            logger.error(f"E2E verification is enabled but unusable: {exc}")
            return 2

    if not HAS_AIOQUIC:
        logger.error("aioquic is not installed: Hysteria2 nodes cannot be verified and will be dropped.")

    health = load_source_health(SOURCE_HEALTH_FILE)
    active_urls, skipped_urls = select_active_sources(source_urls, health, now)
    if not active_urls:
        logger.warning("All sources are quarantined; retrying all sources once.")
        active_urls = list(source_urls)
        skipped_urls = []
    active_set = set(active_urls)
    logger.info(
        f"Loaded {len(source_urls)} sources: {len(active_urls)} active, "
        f"{len(skipped_urls)} quarantined."
    )

    fetch_sem = asyncio.Semaphore(8)
    async with aiohttp.ClientSession(headers=DEFAULT_HEADERS) as session:
        async def fetch_limited(url: str) -> Tuple[str, List[str]]:
            async with fetch_sem:
                return url, await fetch_source(session, url)

        results = await asyncio.gather(*[fetch_limited(url) for url in active_urls])

    raw_by_source: Dict[str, int] = {url: 0 for url in source_urls}
    fetched_ok = 0
    for url, links in results:
        raw_by_source[url] = len(links)
        if links:
            fetched_ok += 1

    raw_total = sum(raw_by_source.values())
    logger.info(f"Total raw links collected: {raw_total} (sources with data: {fetched_ok})")
    if not raw_total:
        logger.error("No links collected from any source; keeping previous files.")
        return 2

    by_key: Dict[str, dict] = {}
    rejected = 0
    for url, links in results:
        for raw in links:
            parsed = parse_vpn_link(raw)
            if not parsed:
                rejected += 1
                continue
            existing = by_key.get(parsed["dedup_key"])
            if existing:
                existing["sources"].add(url)
                continue
            parsed["sources"] = {url}
            parsed["latency_ms"] = None
            parsed["e2e"] = "disabled"
            by_key[parsed["dedup_key"]] = parsed

    parsed_nodes = list(by_key.values())
    logger.info(f"Unique valid nodes: {len(parsed_nodes)} (rejected invalid: {rejected})")
    if not parsed_nodes:
        logger.error("No valid nodes parsed; keeping previous files.")
        return 2

    unique_by_source: Dict[str, int] = {url: 0 for url in source_urls}
    for node in parsed_nodes:
        for url in node["sources"]:
            unique_by_source[url] = unique_by_source.get(url, 0) + 1

    candidates = cap_per_endpoint(parsed_nodes)
    cap_counts = {
        "endpoint": len(parsed_nodes) - len(candidates),
        "subnet": 0,
        "domain": 0,
    }
    logger.info(
        f"Candidates after endpoint cap: {len(candidates)} "
        f"(removed endpoint duplicates: {cap_counts['endpoint']})"
    )

    candidate_protocols: Dict[str, int] = {}
    for node in candidates:
        candidate_protocols[node["scheme"]] = candidate_protocols.get(node["scheme"], 0) + 1
    logger.info(
        "Candidate protocols: "
        + ", ".join(f"{key.upper()}={value}" for key, value in sorted(candidate_protocols.items()))
    )

    semaphore = asyncio.Semaphore(MAX_CONCURRENT_PINGS)
    logger.info(f"Checking reachability (workers={MAX_CONCURRENT_PINGS})...")
    check_results = await asyncio.gather(
        *[verify_node(node, semaphore) for node in candidates]
    )
    alive_nodes = [
        node
        for node, latency in zip(candidates, check_results, strict=True)
        if latency is not None
    ]
    reachable = len(alive_nodes)
    logger.info(f"Protocol-level reachable nodes: {reachable} / {len(candidates)}")

    tls_nodes = [
        node
        for node in alive_nodes
        if node["scheme"] in ("vless", "trojan") and node.get("security") == "tls"
    ]
    tls_status = {"valid": 0, "pinned": 0, "failed": 0}
    if tls_nodes:
        logger.info(f"Inspecting TLS certificates ({len(tls_nodes)} nodes)...")
        tls_checks = await asyncio.gather(*[inspect_tls(node) for node in tls_nodes])
        tls_ids = {id(node) for node in tls_nodes}
        kept_tls: List[dict] = []
        for node, (mode, fingerprint) in zip(tls_nodes, tls_checks, strict=True):
            node["tls_mode"] = mode
            node["tls_cert_sha256"] = fingerprint
            if mode is None:
                tls_status["failed"] += 1
                continue
            tls_status[mode] += 1
            kept_tls.append(node)
        alive_nodes = [node for node in alive_nodes if id(node) not in tls_ids] + kept_tls
        logger.info(
            f"TLS certificates: CA-valid={tls_status['valid']}, "
            f"pinned={tls_status['pinned']}, failed={tls_status['failed']}"
        )

    hy2_without_pin = [
        node
        for node in alive_nodes
        if node["scheme"] == "hysteria2" and not node.get("tls_cert_sha256")
    ]
    if hy2_without_pin:
        logger.info(f"Dropping {len(hy2_without_pin)} Hysteria2 nodes without a certificate pin")
        alive_nodes = [node for node in alive_nodes if node not in hy2_without_pin]

    e2e_status = {
        "enabled": E2E_VERIFY,
        "verified": 0,
        "failed": 0,
        "unsupported": 0,
        "duration_sec": 0.0,
    }
    if E2E_VERIFY and alive_nodes:
        logger.info(
            f"Running end-to-end verification (workers={E2E_CONCURRENCY}, timeout={E2E_TIMEOUT}s)..."
        )
        e2e_started = time.monotonic()
        try:
            e2e_results = await e2e.verify_nodes(
                alive_nodes,
                xray_bin=xray_bin,
                concurrency=E2E_CONCURRENCY,
                timeout=E2E_TIMEOUT,
            )
        except e2e.E2ERuntimeError as exc:
            logger.error(f"E2E verification failed to run: {exc}")
            return 2

        e2e_status["duration_sec"] = round(time.monotonic() - e2e_started, 1)
        for key in ("verified", "failed", "unsupported"):
            e2e_status[key] = sum(1 for _, status, _ in e2e_results if status == key)
        alive_nodes = [node for node in alive_nodes if node.get("e2e") != "failed"]
        logger.info(
            f"E2E verified: {e2e_status['verified']}, failed: {e2e_status['failed']}, "
            f"unsupported: {e2e_status['unsupported']} ({e2e_status['duration_sec']}s)"
        )

    node_history, eligible_ids, stability_stats = update_node_history(
        load_node_history(NODE_HISTORY_FILE), candidates, alive_nodes, now
    )
    if stability_stats["held_back"]:
        logger.info(
            f"Stability filter: {stability_stats['held_back']} verified nodes held back "
            f"(need {NODE_MIN_RECENT_SUCCESS}/{NODE_RECENT_WINDOW} successes)."
        )
    alive_nodes = [
        node for node in alive_nodes if node_history_id(node) in eligible_ids
    ]

    alive_nodes, diversity_removed = cap_diversity(alive_nodes)
    cap_counts.update(diversity_removed)
    if diversity_removed["subnet"] or diversity_removed["domain"]:
        logger.info(
            "Diversity caps after verification: "
            f"removed subnet={diversity_removed['subnet']}, "
            f"domain={diversity_removed['domain']}"
        )

    def latency_value(node: dict) -> Optional[float]:
        if E2E_VERIFY and node.get("e2e") == "verified" and node.get("e2e_ms") is not None:
            return node["e2e_ms"]
        return node.get("latency_ms")

    alive_nodes.sort(key=lambda node: (latency_value(node) is None, latency_value(node) or 0))

    alive_counts: Dict[str, int] = {}
    country_counts: Dict[str, int] = {}
    alive_by_source: Dict[str, int] = {url: 0 for url in source_urls}
    for node in alive_nodes:
        protocol = node["scheme"]
        alive_counts[protocol] = alive_counts.get(protocol, 0) + 1
        country_counts[node["flag"]] = country_counts.get(node["flag"], 0) + 1
        for url in node["sources"]:
            alive_by_source[url] = alive_by_source.get(url, 0) + 1

    logger.info(f"✅ Total published nodes: {len(alive_nodes)} / {len(candidates)} checked")
    for protocol, count in sorted(alive_counts.items(), key=lambda item: -item[1]):
        logger.info(f"  {protocol.upper()}: {count}")
    logger.info("Top countries:")
    for flag, count in sorted(country_counts.items(), key=lambda item: -item[1])[:8]:
        logger.info(f"  {flag}: {count}")

    source_stats: Dict[str, dict] = {}
    for url in source_urls:
        entry = health.get("sources", {}).get(url, {})
        active = url in active_set
        if active:
            raw_count = int(raw_by_source.get(url, 0))
            unique_count = int(unique_by_source.get(url, 0))
            alive_count = int(alive_by_source.get(url, 0))
        else:
            raw_count = int(entry.get("last_raw", 0))
            unique_count = int(entry.get("last_unique", 0))
            alive_count = int(entry.get("last_alive", 0))
        source_stats[url] = {
            "active": active,
            "raw": raw_count,
            "unique": unique_count,
            "alive": alive_count,
            "yield": round(alive_count / raw_count, 3) if raw_count else 0.0,
            "quarantined": bool(
                (until := _parse_datetime(entry.get("quarantined_until"))) and until > now
            ),
        }

    previous_stats = load_previous_stats(STATS_OUTPUT)
    previous_total = int(previous_stats.get("alive") or read_previous_count(ALL_OUTPUT))
    previous_protocols = previous_stats.get("alive_by_protocol") or {}
    baseline_reset = BASELINE_RESET or (
        E2E_VERIFY and not previous_stats.get("e2e_enabled", False)
    )
    if BASELINE_RESET:
        logger.warning(
            "BASELINE_RESET=1: total and per-protocol drop guards are skipped for this run."
        )
    elif baseline_reset:
        logger.info(
            "First E2E run: total/protocol drop guard is skipped to establish a new baseline."
        )

    try:
        enforce_guard(
            len(alive_nodes),
            previous_total,
            protocol_counts=alive_counts,
            previous_protocols=previous_protocols,
            allow_baseline_reset=baseline_reset,
        )
    except GuardError as exc:
        logger.error(f"Output guard triggered: {exc}. Previous files are kept unchanged.")
        return 1

    vless_lines = [format_link(node) for node in alive_nodes if node["scheme"] == "vless"]
    hy2_lines = [format_link(node) for node in alive_nodes if node["scheme"] == "hysteria2"]
    all_lines = [format_link(node) for node in alive_nodes]

    write_atomic(VLESS_OUTPUT, vless_lines)
    write_atomic(HY2_OUTPUT, hy2_lines)
    write_atomic(ALL_OUTPUT, all_lines)
    logger.info(f"Exported {len(vless_lines)} VLESS nodes -> {VLESS_OUTPUT}")
    logger.info(f"Exported {len(hy2_lines)} Hysteria2 nodes -> {HY2_OUTPUT}")
    logger.info(f"Exported {len(all_lines)} all-protocol nodes -> {ALL_OUTPUT}")

    elapsed = round(time.monotonic() - started, 1)
    overall_latency = latency_summary(alive_nodes)
    write_json_atomic(
        STATS_OUTPUT,
        {
            "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "duration_sec": elapsed,
            "e2e_enabled": E2E_VERIFY,
            "sources_total": len(source_urls),
            "sources_active": len(active_urls),
            "sources_skipped_quarantined": len(skipped_urls),
            "sources_with_data": fetched_ok,
            "raw_links": raw_total,
            "unique_valid": len(parsed_nodes),
            "candidates_after_cap": len(candidates),
            "capped_by_endpoint": cap_counts["endpoint"],
            "capped_by_subnet": cap_counts["subnet"],
            "capped_by_domain": cap_counts["domain"],
            "rejected_invalid": rejected,
            "reachable": reachable,
            "tls_inspection": tls_status,
            "hysteria2_pinned": sum(
                1
                for node in alive_nodes
                if node["scheme"] == "hysteria2" and node.get("tls_cert_sha256")
            ),
            "e2e": e2e_status,
            "alive": len(alive_nodes),
            "alive_by_protocol": dict(sorted(alive_counts.items())),
            "top_countries": dict(sorted(country_counts.items(), key=lambda item: -item[1])[:15]),
            "latency_ms": overall_latency,
            "latency_by_protocol": {
                protocol: latency_summary([node for node in alive_nodes if node["scheme"] == protocol])
                for protocol in sorted(alive_counts)
            },
            "previous_total": previous_total,
            "baseline_reset": baseline_reset,
            "stability": stability_stats,
            "source_stats": source_stats,
            "checks": {
                "vless": "xray_e2e" if E2E_VERIFY else "tcp_connect",
                "trojan": "xray_e2e" if E2E_VERIFY else "tcp_connect",
                "hysteria2": (
                    "xray_hysteria2_e2e"
                    if E2E_VERIFY
                    else ("quic_v1_handshake_h3" if HAS_AIOQUIC else "unverified")
                ),
            },
        },
    )
    new_health = update_source_health(health, source_urls, source_stats, now)
    write_json_atomic(SOURCE_HEALTH_FILE, new_health)

    history_entries = load_history_list(HISTORY_FILE)
    history_entries.append(
        {
            "timestamp": now.isoformat(timespec="seconds"),
            "alive": len(alive_nodes),
            "protocols": dict(sorted(alive_counts.items())),
            "delta": len(alive_nodes) - previous_total,
            "reachable": reachable,
            "e2e_verified": e2e_status["verified"],
            "e2e_failed": e2e_status["failed"],
            "latency_p50": overall_latency.get("p50"),
            "sources_active": len(active_urls),
            "sources_quarantined": len(skipped_urls),
            "held_back": stability_stats["held_back"],
        }
    )
    history_entries = history_entries[-HISTORY_MAX_RUNS:]
    write_json_atomic(HISTORY_FILE, history_entries)
    write_json_atomic(NODE_HISTORY_FILE, node_history)
    write_json_atomic(META_FILE, build_meta(alive_counts, len(alive_nodes), now))

    logger.info(f"Wrote run statistics -> {STATS_OUTPUT} ({elapsed}s)")
    logger.info(f"Wrote source health -> {SOURCE_HEALTH_FILE}")
    logger.info(f"Wrote node history -> {NODE_HISTORY_FILE}")
    logger.info(f"Wrote run history -> {HISTORY_FILE}")
    logger.info(f"Wrote subscription metadata -> {META_FILE}")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
