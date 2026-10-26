#!/usr/bin/env python3
"""
Multi-Protocol VPN Aggregator & Connectivity Checker.
Downloads VLESS, Trojan, and Hysteria2 configs from multiple sources,
including direct Git repositories (GitLab/GitHub) and raw HTTP/HTTPS URLs.
(VMess is explicitly excluded per configuration).
"""

import asyncio
import base64
import logging
import os
import re
import socket
import subprocess
import tempfile
import urllib.parse
from typing import Dict, List, Optional, Tuple

import aiohttp

SOURCES_FILE = os.getenv("SOURCES_FILE", "sources.txt")
VLESS_OUTPUT = os.getenv("VLESS_OUTPUT", "vless_universal.txt")
HY2_OUTPUT = os.getenv("HY2_OUTPUT", "hysteria2.txt")
ALL_OUTPUT = os.getenv("ALL_OUTPUT", "all_universal.txt")

TIMEOUT = float(os.getenv("PING_TIMEOUT", "3.0"))
MAX_CONCURRENT_PINGS = int(os.getenv("CONCURRENCY", "60"))
FETCH_TIMEOUT = float(os.getenv("FETCH_TIMEOUT", "20.0"))

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
    )
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("aggregator")

FLAG_REGEX = re.compile(r"[\U0001F1E6-\U0001F1FF]{2}")
COUNTRY_CODE_REGEX = re.compile(
    r"(?:^|[\s\[\(_\-\|])([A-Z]{2})(?:[\s\]\)_0-9\-\|]|$)"
)
# VMess is explicitly excluded
SUPPORTED_PREFIXES = (
    "vless://", "trojan://", "hysteria2://", "hy2://", "tuic://", "ss://"
)


def code_to_flag(code: str) -> str:
    """Converts a two-letter ISO country code (e.g. 'RU') to a flag emoji."""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code.upper())


def parse_vpn_link(link: str) -> Optional[dict]:
    """Parses any supported VPN URI into structured fields."""
    link = link.strip()
    if not any(link.startswith(p) for p in SUPPORTED_PREFIXES):
        return None

    try:
        scheme, _, rest = link.partition("://")
        scheme = scheme.lower()

        url_part, _, raw_remark = rest.partition("#")
        remark = urllib.parse.unquote(raw_remark).strip()

        user_info, _, host_query = url_part.partition("@")
        if not host_query:
            return None

        host_port, _, raw_query = host_query.partition("?")
        if not host_port:
            return None

        if host_port.startswith("["):
            host_end = host_port.find("]")
            host = host_port[1:host_end]
            port_str = host_port[host_end + 1 :].lstrip(":")
        else:
            host, _, port_str = host_port.partition(":")

        port = int(port_str) if port_str.isdigit() else (8443 if "hy" in scheme else 443)

        qs = urllib.parse.parse_qs(raw_query)
        sni = qs.get("sni", [""])[0] or qs.get("host", [""])[0]

        transport = "udp" if scheme in ("hysteria2", "hy2", "tuic") else "tcp"
        return _build_node(scheme, link, host, port, sni, remark, transport)
    except Exception:
        return None


def _build_node(scheme: str, link: str, host: str, port: int, sni: str, remark: str, transport: str) -> Optional[dict]:
    if not host or not port:
        return None

    flag_match = FLAG_REGEX.search(remark)
    flag = flag_match.group(0) if flag_match else None

    if not flag:
        cc_match = COUNTRY_CODE_REGEX.search(remark)
        if cc_match:
            candidate = cc_match.group(1)
            if candidate in {
                "RU", "DE", "NL", "US", "GB", "FR", "SG", "JP", "TR",
                "FI", "SE", "PL", "AT", "CH", "IT", "ES", "CA", "HK",
                "BG", "EE", "LT", "LV", "KZ", "BY", "UA", "RO", "CZ",
            }:
                flag = code_to_flag(candidate)
                remark = f"{flag} {remark}"

    if not flag:
        flag = "🌐"

    dedup_key = f"{scheme}:{host.lower()}:{port}:{sni.lower()}"
    return {
        "scheme": scheme,
        "link": link,
        "host": host,
        "port": port,
        "sni": sni,
        "flag": flag,
        "remark": remark,
        "transport": transport,
        "dedup_key": dedup_key,
    }


async def check_connectivity(node: dict, timeout: float = TIMEOUT) -> bool:
    """Verifies reachability via TCP connect or UDP resolution/routing."""
    host, port, transport = node["host"], node["port"], node["transport"]
    if transport == "tcp":
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False
    else:
        try:
            loop = asyncio.get_running_loop()
            infos = await asyncio.wait_for(
                loop.getaddrinfo(host, port, family=socket.AF_UNSPEC, type=socket.SOCK_DGRAM),
                timeout=timeout,
            )
            if not infos:
                return False
            family, socktype, proto, _, sockaddr = infos[0]
            s = socket.socket(family, socktype, proto)
            s.setblocking(False)
            s.connect(sockaddr)
            s.close()
            return True
        except Exception:
            return False


def _clone_git_repo(repo_url: str) -> List[str]:
    """Clones a Git repository to read all .txt configs directly without rate limits."""
    clean_url = repo_url[4:] if repo_url.startswith("git+") else repo_url
    if not clean_url.endswith(".git") and ("gitlab.com" in clean_url or "github.com" in clean_url):
        clean_url = clean_url.rstrip("/") + ".git"

    configs = []
    with tempfile.TemporaryDirectory() as tmpdir:
        res = subprocess.run(
            ["git", "clone", "--depth", "1", clean_url, tmpdir],
            capture_output=True,
            text=True,
            timeout=40,
        )
        if res.returncode != 0:
            logger.warning(f"Failed to clone {clean_url}: {res.stderr.strip()[:100]}")
            return []

        for fname in os.listdir(tmpdir):
            if fname.endswith(".txt") and ("WHITE" in fname or "Vless" in fname or "all" in fname.lower()):
                fpath = os.path.join(tmpdir, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        lines = [l.strip() for l in f if any(l.strip().startswith(p) for p in SUPPORTED_PREFIXES)]
                        configs.extend(lines)
                except Exception:
                    pass
    logger.info(f" -> Found {len(configs)} configs from Git repo: {clean_url}")
    return configs


async def fetch_source(session: aiohttp.ClientSession, url: str) -> List[str]:
    """Fetches a URL, extracting raw lines or cloning Git repos directly."""
    url = url.strip()
    if not url or url.startswith("#"):
        return []

    # Handle Git repositories directly
    if url.startswith("git+") or (url.endswith(".git") and ("gitlab.com" in url or "github.com" in url)):
        logger.info(f"Cloning Git source: {url}")
        return await asyncio.to_thread(_clone_git_repo, url)

    logger.info(f"Downloading source: {url}")
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=FETCH_TIMEOUT)) as resp:
            if resp.status != 200:
                logger.warning(f"Failed to fetch {url}: HTTP {resp.status}")
                return []
            body = (await resp.text()).strip()

        if any(p in body for p in SUPPORTED_PREFIXES):
            lines = [l.strip() for l in body.splitlines() if l.strip()]
        else:
            try:
                pad = len(body) % 4
                padded = body + ("=" * ((4 - pad) % 4)) if pad else body
                decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
                lines = [l.strip() for l in decoded.splitlines() if l.strip()]
            except Exception:
                lines = [l.strip() for l in body.splitlines() if l.strip()]

        configs = [l for l in lines if any(l.startswith(p) for p in SUPPORTED_PREFIXES)]
        logger.info(f" -> Found {len(configs)} configs from {url}")
        return configs
    except Exception as e:
        logger.error(f"Error fetching {url}: {e}")
        return []


def format_link(node: dict) -> str:
    """Rebuilds the link with a standardized, URL-encoded remark."""
    base_link = node["link"].split("#")[0]
    return f"{base_link}#{urllib.parse.quote(node['remark'])}"


async def main():
    if not os.path.exists(SOURCES_FILE):
        logger.error(f"Sources file '{SOURCES_FILE}' not found!")
        return

    with open(SOURCES_FILE, "r", encoding="utf-8") as f:
        source_urls = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

    if not source_urls:
        logger.warning("No URLs found in sources.txt.")
        return

    logger.info(f"Loaded {len(source_urls)} sources to process.")

    all_raw_links: List[str] = []
    async with aiohttp.ClientSession(headers=DEFAULT_HEADERS) as session:
        tasks = [fetch_source(session, u) for u in source_urls]
        results = await asyncio.gather(*tasks)
        for r in results:
            all_raw_links.extend(r)

    logger.info(f"Total raw links collected: {len(all_raw_links)}")

    seen_keys = set()
    parsed_nodes: List[dict] = []
    for raw in all_raw_links:
        parsed = parse_vpn_link(raw)
        if not parsed or parsed["dedup_key"] in seen_keys:
            continue
        seen_keys.add(parsed["dedup_key"])
        parsed_nodes.append(parsed)

    logger.info(f"Unique nodes to check: {len(parsed_nodes)}")

    semaphore = asyncio.Semaphore(MAX_CONCURRENT_PINGS)

    async def verify(node: dict) -> Tuple[dict, bool]:
        async with semaphore:
            alive = await check_connectivity(node)
            return node, alive

    logger.info(f"Checking reachability (workers={MAX_CONCURRENT_PINGS})...")
    check_results = await asyncio.gather(*[verify(n) for n in parsed_nodes])

    alive_nodes: List[dict] = []
    protocol_counts: Dict[str, int] = {}
    country_counts: Dict[str, int] = {}

    for node, is_alive in check_results:
        if is_alive:
            alive_nodes.append(node)
            proto = node["scheme"]
            flag = node["flag"]
            protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
            country_counts[flag] = country_counts.get(flag, 0) + 1

    logger.info(f"✅ Total alive nodes: {len(alive_nodes)} / {len(parsed_nodes)}")
    logger.info("Protocols:")
    for proto, cnt in sorted(protocol_counts.items(), key=lambda x: -x[1]):
        logger.info(f"  {proto.upper()}: {cnt}")
    logger.info("Top Countries:")
    for flag, cnt in sorted(country_counts.items(), key=lambda x: -x[1])[:8]:
        logger.info(f"  {flag}: {cnt}")

    # 1. Export VLESS
    vless_nodes = [format_link(n) for n in alive_nodes if n["scheme"] == "vless"]
    with open(VLESS_OUTPUT, "w", encoding="utf-8") as f:
        f.write("\n".join(vless_nodes) + "\n")
    logger.info(f"Exported {len(vless_nodes)} VLESS nodes -> {VLESS_OUTPUT}")

    # 2. Export Hysteria 2
    hy2_nodes = [format_link(n) for n in alive_nodes if n["scheme"] in ("hysteria2", "hy2")]
    with open(HY2_OUTPUT, "w", encoding="utf-8") as f:
        f.write("\n".join(hy2_nodes) + "\n")
    logger.info(f"Exported {len(hy2_nodes)} Hysteria2 nodes -> {HY2_OUTPUT}")

    # 3. Export All Universal
    all_nodes = [format_link(n) for n in alive_nodes]
    with open(ALL_OUTPUT, "w", encoding="utf-8") as f:
        f.write("\n".join(all_nodes) + "\n")
    logger.info(f"Exported {len(all_nodes)} All-protocol nodes -> {ALL_OUTPUT}")


if __name__ == "__main__":
    asyncio.run(main())
