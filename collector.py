#!/usr/bin/env python3
"""
VLESS Aggregator & Connectivity Checker.
Downloads VLESS configs from multiple sources, deduplicates,
verifies TCP connectivity, standardizes country tags, and exports a unified list.
"""

import asyncio
import base64
import logging
import os
import re
import urllib.parse
from typing import Dict, List, Optional, Tuple

import aiohttp

SOURCES_FILE = os.getenv("SOURCES_FILE", "sources.txt")
OUTPUT_FILE = os.getenv("OUTPUT_FILE", "vless_universal.txt")
TCP_TIMEOUT = float(os.getenv("TCP_TIMEOUT", "3.0"))
MAX_CONCURRENT_PINGS = int(os.getenv("CONCURRENCY", "50"))
FETCH_TIMEOUT = float(os.getenv("FETCH_TIMEOUT", "20.0"))

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


def code_to_flag(code: str) -> str:
    """Converts a two-letter ISO country code (e.g. 'RU') to a flag emoji."""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code.upper())


def parse_vless(link: str) -> Optional[dict]:
    """Parses a vless:// URI into structured fields."""
    link = link.strip()
    if not link.startswith("vless://"):
        return None

    try:
        url_part, _, raw_remark = link[8:].partition("#")
        remark = urllib.parse.unquote(raw_remark).strip()

        user_info, _, host_query = url_part.partition("@")
        if not user_info or not host_query:
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

        port = int(port_str) if port_str.isdigit() else 443

        qs = urllib.parse.parse_qs(raw_query)
        sni = ""
        if "sni" in qs:
            sni = qs["sni"][0]
        elif "host" in qs:
            sni = qs["host"][0]

        # Extract or infer country flag
        flag_match = FLAG_REGEX.search(remark)
        flag = flag_match.group(0) if flag_match else None

        if not flag:
            cc_match = COUNTRY_CODE_REGEX.search(remark)
            if cc_match:
                candidate = cc_match.group(1)
                if candidate in {
                    "RU", "DE", "NL", "US", "GB", "FR", "SG", "JP", "TR",
                    "FI", "SE", "PL", "AT", "CH", "IT", "ES", "CA", "HK",
                }:
                    flag = code_to_flag(candidate)
                    remark = f"{flag} {remark}"

        if not flag:
            flag = "🌐"

        # Dedup key by host, port, and SNI
        dedup_key = f"{host.lower()}:{port}:{sni.lower()}"

        return {
            "link": link,
            "host": host,
            "port": port,
            "uuid": user_info,
            "sni": sni,
            "flag": flag,
            "remark": remark,
            "dedup_key": dedup_key,
        }
    except Exception:
        return None


async def check_tcp(host: str, port: int, timeout: float = TCP_TIMEOUT) -> bool:
    """Tests TCP connectivity to the given host and port."""
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


async def fetch_source(
    session: aiohttp.ClientSession, url: str
) -> List[str]:
    """Fetches a URL and extracts lines, handling base64 or raw text."""
    url = url.strip()
    if not url or url.startswith("#"):
        return []

    logger.info(f"Downloading source: {url}")
    try:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=FETCH_TIMEOUT)
        ) as resp:
            if resp.status != 200:
                logger.warning(f"Failed to fetch {url}: HTTP {resp.status}")
                return []
            body = (await resp.text()).strip()

        # If it already contains vless://, it's plain text
        if "vless://" in body:
            lines = [l.strip() for l in body.splitlines() if l.strip()]
        else:
            # Try base64 decoding for base64 subscription URLs
            try:
                pad = len(body) % 4
                padded = body + ("=" * ((4 - pad) % 4)) if pad else body
                decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
                lines = [l.strip() for l in decoded.splitlines() if l.strip()]
            except Exception:
                lines = [l.strip() for l in body.splitlines() if l.strip()]

        vless_lines = [l for l in lines if l.startswith("vless://")]
        logger.info(f" -> Found {len(vless_lines)} VLESS links from {url}")
        return vless_lines
    except Exception as e:
        logger.error(f"Error fetching {url}: {e}")
        return []


async def main():
    if not os.path.exists(SOURCES_FILE):
        logger.error(f"Sources file '{SOURCES_FILE}' not found!")
        return

    with open(SOURCES_FILE, "r", encoding="utf-8") as f:
        source_urls = [
            line.strip()
            for line in f
            if line.strip() and not line.strip().startswith("#")
        ]

    if not source_urls:
        logger.warning("No URLs found in sources.txt.")
        return

    logger.info(f"Loaded {len(source_urls)} sources to process.")

    all_raw_links: List[str] = []
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_source(session, u) for u in source_urls]
        results = await asyncio.gather(*tasks)
        for r in results:
            all_raw_links.extend(r)

    logger.info(f"Total raw links collected: {len(all_raw_links)}")

    # Deduplication & Parsing
    seen_keys = set()
    parsed_nodes: List[dict] = []

    for raw in all_raw_links:
        parsed = parse_vless(raw)
        if not parsed:
            continue
        if parsed["dedup_key"] in seen_keys:
            continue
        seen_keys.add(parsed["dedup_key"])
        parsed_nodes.append(parsed)

    logger.info(f"Unique nodes to check: {len(parsed_nodes)}")

    # TCP Connectivity Check
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_PINGS)

    async def verify_node(node: dict) -> Tuple[dict, bool]:
        async with semaphore:
            alive = await check_tcp(node["host"], node["port"])
            return node, alive

    logger.info(
        f"Checking TCP reachability (timeout={TCP_TIMEOUT}s, workers={MAX_CONCURRENT_PINGS})..."
    )
    check_tasks = [verify_node(n) for n in parsed_nodes]
    check_results = await asyncio.gather(*check_tasks)

    alive_nodes: List[dict] = []
    country_counts: Dict[str, int] = {}

    for node, is_alive in check_results:
        if is_alive:
            alive_nodes.append(node)
            flag = node["flag"]
            country_counts[flag] = country_counts.get(flag, 0) + 1

    logger.info(f"Alive nodes: {len(alive_nodes)} / {len(parsed_nodes)}")
    for flag, count in sorted(country_counts.items(), key=lambda x: -x[1]):
        logger.info(f"  {flag} : {count} alive nodes")

    # Export to output file
    # Ensure remark formatting with flag
    output_lines = []
    for node in alive_nodes:
        # Re-attach updated remark if flag was added
        base_link = node["link"].split("#")[0]
        output_lines.append(f"{base_link}#{urllib.parse.quote(node['remark'])}")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(output_lines) + "\n")

    logger.info(f"✅ Successfully written {len(output_lines)} nodes to {OUTPUT_FILE}")


if __name__ == "__main__":
    asyncio.run(main())
