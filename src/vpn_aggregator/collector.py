#!/usr/bin/env python3
"""Multi-Protocol VPN Aggregator & Connectivity Checker (orchestrator & public facade)."""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import aiohttp

from . import e2e, exporter, geoip, hy2_e2e, parser, prober, quality, sources

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _p(*parts: str) -> str:
    return str(PROJECT_ROOT.joinpath(*parts))

def _flag(name: str, default: str = "0") -> bool:
    return os.getenv(name, default).strip().lower() in {"1", "true", "yes", "on"}

SOURCES_FILE = os.getenv("SOURCES_FILE", _p("config", "sources.txt"))
VLESS_OUTPUT = os.getenv("VLESS_OUTPUT", _p("vless_universal.txt"))
HY2_OUTPUT = os.getenv("HY2_OUTPUT", _p("hysteria2.txt"))
ALL_OUTPUT = os.getenv("ALL_OUTPUT", _p("all_universal.txt"))
STATS_OUTPUT = os.getenv("STATS_OUTPUT", _p("state", "stats.json"))
SOURCE_HEALTH_FILE = os.getenv("SOURCE_HEALTH_FILE", _p("state", "source_health.json"))
SOURCE_CACHE_FILE = os.getenv("SOURCE_CACHE_FILE", _p("state", "source_cache.json"))
NODE_HISTORY_FILE = os.getenv("NODE_HISTORY_FILE", _p("state", "node_history.json"))
HISTORY_FILE = os.getenv("HISTORY_FILE", _p("state", "history.json"))
META_FILE = os.getenv("META_FILE", _p("state", "meta.json"))
RU_GEOIP_CACHE_FILE = os.getenv("RU_GEOIP_CACHE_FILE", _p(".cache", "ru_geoip_cache.json"))

PROFILE_TITLE = os.getenv("PROFILE_TITLE", "BarqDev Multi-Protocol VPN")
SUPPORT_URL = os.getenv("SUPPORT_URL", "https://github.com/BarqDev1/vless-aggregator/issues")
PROFILE_UPDATE_INTERVAL = float(os.getenv("PROFILE_UPDATE_INTERVAL", "0.5"))
HOME_URL = os.getenv("HOME_URL", "https://github.com/BarqDev1/vless-aggregator")
TIMEOUT = float(os.getenv("PING_TIMEOUT", "3.0"))
QUIC_TIMEOUT = float(os.getenv("QUIC_TIMEOUT", "5.0"))
CHECK_ATTEMPTS = max(1, int(os.getenv("CHECK_ATTEMPTS", "2")))
MAX_CONCURRENT_PINGS = int(os.getenv("CONCURRENCY", "60"))
FETCH_CONCURRENCY = max(1, int(os.getenv("FETCH_CONCURRENCY", "16")))
FETCH_TIMEOUT = float(os.getenv("FETCH_TIMEOUT", "20.0"))
FETCH_ATTEMPTS = max(1, int(os.getenv("FETCH_ATTEMPTS", "3")))
MAX_SOURCE_BYTES = int(os.getenv("MAX_SOURCE_BYTES", str(5 * 1024 * 1024)))
MAX_GIT_FILE_BYTES = int(os.getenv("MAX_GIT_FILE_BYTES", str(2 * 1024 * 1024)))
MAX_GIT_FILES = int(os.getenv("MAX_GIT_FILES", "2000"))
MIN_ALIVE = int(os.getenv("MIN_ALIVE", "10"))
MAX_DROP_RATIO = float(os.getenv("MAX_DROP_RATIO", "0.5"))
MAX_PER_ENDPOINT = max(1, int(os.getenv("MAX_PER_ENDPOINT", "6")))
PUBLISH_PER_ENDPOINT = max(1, int(os.getenv("PUBLISH_PER_ENDPOINT", "2")))
MAX_PER_SUBNET = max(1, int(os.getenv("MAX_PER_SUBNET", "6")))
MAX_PER_DOMAIN = max(1, int(os.getenv("MAX_PER_DOMAIN", "10")))
MAX_REMARK_LEN = int(os.getenv("MAX_REMARK_LEN", "120"))

E2E_VERIFY = _flag("E2E_VERIFY", "0")
NODE_MIN_RECENT_SUCCESS = max(1, int(os.getenv("NODE_MIN_RECENT_SUCCESS", "1" if E2E_VERIFY else "2")))
NODE_RECENT_WINDOW = max(1, int(os.getenv("NODE_RECENT_WINDOW", "3")))
NODE_HISTORY_TTL_DAYS = max(1, int(os.getenv("NODE_HISTORY_TTL_DAYS", "30")))
MAX_NODE_HISTORY = max(100, int(os.getenv("MAX_NODE_HISTORY", "10000")))
HISTORY_MAX_RUNS = max(24, int(os.getenv("HISTORY_MAX_RUNS", "1440")))
E2E_CACHE_MINUTES = max(0.0, float(os.getenv("E2E_CACHE_MINUTES", "60")))
E2E_FAILURE_CACHE_MINUTES = max(0.0, float(os.getenv("E2E_FAILURE_CACHE_MINUTES", "15")))
PROTOCOL_MIN_ALIVE = max(1, int(os.getenv("PROTOCOL_MIN_ALIVE", "3")))
PROTOCOL_MAX_DROP = float(os.getenv("PROTOCOL_MAX_DROP", "0.7"))
SOURCE_FAILURE_THRESHOLD = max(1, int(os.getenv("SOURCE_FAILURE_THRESHOLD", "5")))
SOURCE_QUARANTINE_HOURS = float(os.getenv("SOURCE_QUARANTINE_HOURS", "2"))
E2E_CONCURRENCY = max(1, int(os.getenv("E2E_CONCURRENCY", "16")))
E2E_TIMEOUT = float(os.getenv("E2E_TIMEOUT", "8.0"))
XRAY_BIN = os.getenv("XRAY_BIN", "xray")
HY2_BIN = os.getenv("HY2_BIN", "hysteria")
BASELINE_RESET = _flag("BASELINE_RESET", "0")
ONLY_RU_IPS = _flag("ONLY_RU_IPS", "1")
REJECT_RU_EXIT = _flag("REJECT_RU_EXIT", "1" if ONLY_RU_IPS else "0")
FILTER_POISONED_SNI = _flag("FILTER_POISONED_SNI", "1")
DNS_CONCURRENCY = max(1, int(os.getenv("DNS_CONCURRENCY", "32")))
DNS_TIMEOUT = float(os.getenv("DNS_TIMEOUT", "5.0"))
DEFAULT_HEADERS = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36", "Accept": "*/*"}

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper(), format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger("aggregator")
logging.getLogger("aioquic").setLevel(logging.CRITICAL)
logging.getLogger("aiohttp").setLevel(logging.WARNING)
for _h in logging.getLogger().handlers:
    _h.addFilter(prober._DropAioquicNoise())

# Public facade re-exports for backward compatibility.
COUNTRY_CODES, EXCLUDED_PREFIXES, LINK_REGEX = parser.COUNTRY_CODES, parser.EXCLUDED_PREFIXES, parser.LINK_REGEX
SUPPORTED_PREFIXES, SUPPORTED_SCHEMES, UUID_REGEX = parser.SUPPORTED_PREFIXES, parser.SUPPORTED_SCHEMES, parser.UUID_REGEX
code_to_flag, sanitize_remark, parse_vpn_link = parser.code_to_flag, parser.sanitize_remark, parser.parse_vpn_link
extract_links, format_link, _dedup_key = parser.extract_links, parser.format_link, parser._dedup_key
HAS_AIOQUIC, inspect_tls = prober.HAS_AIOQUIC, prober.inspect_tls
_domain_key, _subnet_key = prober._domain_key, prober._subnet_key
_check_tcp, _check_quic = prober.check_tcp, prober.check_quic
_clean_git_url, _header_value = sources._clean_git_url, sources._header_value
_parse_datetime, _load_sources = sources.parse_datetime, sources.load_sources
load_source_cache, load_source_health, select_active_sources = sources.load_source_cache, sources.load_source_health, sources.select_active_sources
GuardError, node_history_id = exporter.GuardError, exporter.node_history_id
load_history_list, load_node_history = exporter.load_history_list, exporter.load_node_history
load_previous_stats, read_previous_count = exporter.load_previous_stats, exporter.read_previous_count
latency_summary, speed_summary, rank_node_key = exporter.latency_summary, exporter.speed_summary, exporter.rank_node_key
write_atomic, write_json_atomic = exporter.write_atomic, exporter.write_json_atomic
_reexport_types = (timedelta,)


def _clone_git_repo(repo_url: str) -> List[str]:
    return sources.clone_git_repo(repo_url, max_git_files=MAX_GIT_FILES, max_git_file_bytes=MAX_GIT_FILE_BYTES)

async def _fetch_once(session: aiohttp.ClientSession, url: str, cache_entry: Optional[dict] = None) -> Tuple[bool, str, int, Dict[str, str]]:
    return await sources.fetch_once(session, url, cache_entry, fetch_timeout=FETCH_TIMEOUT, max_source_bytes=MAX_SOURCE_BYTES)

async def fetch_source(session: aiohttp.ClientSession, url: str, cache_entry: Optional[dict] = None) -> Tuple[List[str], Optional[dict]]:
    return await sources.fetch_source(session, url, cache_entry, fetch_attempts=FETCH_ATTEMPTS, fetch_once_fn=_fetch_once, clone_git_fn=_clone_git_repo)

async def probe_node(node: dict, timeout: Optional[float] = None) -> Optional[float]:
    return await prober.probe_node(node, timeout, tcp_timeout=TIMEOUT, quic_timeout=QUIC_TIMEOUT, check_tcp_fn=_check_tcp, check_quic_fn=_check_quic)

async def check_connectivity(node: dict, timeout: Optional[float] = None) -> bool:
    return await probe_node(node, timeout) is not None

async def verify_node(node: dict, semaphore: asyncio.Semaphore) -> Optional[float]:
    return await prober.verify_node(node, semaphore, attempts=CHECK_ATTEMPTS, probe_fn=probe_node)

async def probe_nodes_dedup(nodes: List[dict], semaphore: asyncio.Semaphore) -> Tuple[List[dict], List[dict]]:
    return await prober.probe_nodes_dedup(nodes, semaphore, verify_fn=verify_node)

def cap_per_endpoint(nodes: List[dict], limit: Optional[int] = None) -> List[dict]:
    return prober.cap_per_endpoint(nodes, MAX_PER_ENDPOINT if limit is None else limit)

def cap_published_endpoints(nodes: List[dict]) -> Tuple[List[dict], int]:
    return prober.cap_published_endpoints(nodes, PUBLISH_PER_ENDPOINT)

def cap_diversity(nodes: List[dict]) -> Tuple[List[dict], Dict[str, int]]:
    return prober.cap_diversity(nodes, max_per_subnet=MAX_PER_SUBNET, max_per_domain=MAX_PER_DOMAIN)

def cap_for_diversity(nodes: List[dict]) -> Tuple[List[dict], Dict[str, int]]:
    return prober.cap_for_diversity(nodes, max_per_endpoint=MAX_PER_ENDPOINT, max_per_subnet=MAX_PER_SUBNET, max_per_domain=MAX_PER_DOMAIN)

def update_source_health(health: dict, urls: List[str], source_stats: Dict[str, dict], now: datetime) -> dict:
    return sources.update_source_health(health, urls, source_stats, now, failure_threshold=SOURCE_FAILURE_THRESHOLD, quarantine_hours=SOURCE_QUARANTINE_HOURS)

def _e2e_cache_status(entry: dict, now: datetime, compatible: bool = True) -> str:
    return exporter.e2e_cache_status(entry, now, compatible, cache_minutes=E2E_CACHE_MINUTES, failure_cache_minutes=E2E_FAILURE_CACHE_MINUTES)

def _cache_is_fresh(entry: dict, now: datetime) -> bool:
    return exporter.cache_is_fresh(entry, now, cache_minutes=E2E_CACHE_MINUTES, failure_cache_minutes=E2E_FAILURE_CACHE_MINUTES)

def enforce_guard(alive: int, previous: int, min_alive: int = MIN_ALIVE, max_drop: float = MAX_DROP_RATIO, protocol_counts: Optional[Dict[str, int]] = None, previous_protocols: Optional[Dict[str, int]] = None, protocol_min: int = PROTOCOL_MIN_ALIVE, protocol_max_drop: float = PROTOCOL_MAX_DROP, allow_baseline_reset: bool = False) -> None:
    exporter.enforce_guard(alive, previous, min_alive=min_alive, max_drop=max_drop, protocol_counts=protocol_counts, previous_protocols=previous_protocols, protocol_min=protocol_min, protocol_max_drop=protocol_max_drop, allow_baseline_reset=allow_baseline_reset)

def update_node_history(state: dict, tested_nodes: List[dict], verified_nodes: List[dict], now: datetime) -> Tuple[dict, set, Dict[str, object]]:
    return exporter.update_node_history(state, tested_nodes, verified_nodes, now, recent_window=NODE_RECENT_WINDOW, min_recent_success=NODE_MIN_RECENT_SUCCESS, ttl_days=NODE_HISTORY_TTL_DAYS, max_entries=MAX_NODE_HISTORY)

def build_meta(alive_counts: Dict[str, int], total: int, now: datetime) -> dict:
    return exporter.build_meta(alive_counts, total, now, profile_title=PROFILE_TITLE, profile_update_interval=PROFILE_UPDATE_INTERVAL, support_url=SUPPORT_URL, home_url=HOME_URL)


async def main() -> int:
    started, now = time.monotonic(), datetime.now(timezone.utc)
    source_urls = _load_sources(SOURCES_FILE)
    if not source_urls:
        return 2
    xray_bin = XRAY_BIN
    if E2E_VERIFY:
        try:
            xray_bin = e2e.ensure_binaries(XRAY_BIN)
        except e2e.E2ERuntimeError as exc:
            logger.error(f"E2E verification unusable: {exc}")
            return 2

    health = load_source_health(SOURCE_HEALTH_FILE)
    node_history_state = load_node_history(NODE_HISTORY_FILE)
    active_urls, skipped_urls = select_active_sources(source_urls, health, now)
    if not active_urls:
        active_urls, skipped_urls = list(source_urls), []
    active_set = set(active_urls)
    source_cache = load_source_cache(SOURCE_CACHE_FILE)
    fetch_sem = asyncio.Semaphore(FETCH_CONCURRENCY)

    async with aiohttp.ClientSession(headers=DEFAULT_HEADERS) as session:
        async def _fetch_lim(u: str) -> Tuple[str, List[str], Optional[dict]]:
            async with fetch_sem:
                links, entry = await fetch_source(session, u, source_cache.get("sources", {}).get(u))
                return u, links, entry

        results = await asyncio.gather(*[_fetch_lim(u) for u in active_urls])

    raw_by_source: Dict[str, int] = {u: 0 for u in source_urls}
    fetched_ok = 0
    cached_sources = {u: e for u, e in source_cache.get("sources", {}).items() if u in set(source_urls)}
    for url, links, entry in results:
        raw_by_source[url] = len(links)
        fetched_ok += int(bool(links))
        if entry:
            cached_sources[url] = entry
    raw_total = sum(raw_by_source.values())
    if not raw_total:
        return 2

    by_key: Dict[str, dict] = {}
    rejected, poisoned_sni = 0, 0
    for url, links, _ in results:
        for raw in links:
            parsed = parse_vpn_link(raw, MAX_REMARK_LEN)
            if not parsed:
                rejected += 1
            elif FILTER_POISONED_SNI and quality.is_poisoned_sni(parsed):
                poisoned_sni += 1
            elif existing := by_key.get(parsed["dedup_key"]):
                existing["sources"].add(url)
            else:
                parsed.update({"sources": {url}, "latency_ms": None, "e2e": "disabled"})
                by_key[parsed["dedup_key"]] = parsed

    parsed_nodes = list(by_key.values())
    logger.info(f"Raw: {raw_total}, unique valid: {len(parsed_nodes)} (rejected: {rejected}, poisoned_sni: {poisoned_sni})")
    if not parsed_nodes:
        return 2

    ru_filter_stats: Dict[str, int] = {}
    if ONLY_RU_IPS:
        try:
            async with aiohttp.ClientSession(headers=DEFAULT_HEADERS) as geo_session:
                ru_matcher = await geoip.load_ru_matcher(geo_session, RU_GEOIP_CACHE_FILE, now=now, timeout=FETCH_TIMEOUT)
        except geoip.GeoIPRuntimeError as exc:
            logger.error(f"RU IP filter unavailable: {exc}")
            return 2
        parsed_nodes, ru_filter_stats = await geoip.filter_ru_nodes(parsed_nodes, ru_matcher, concurrency=DNS_CONCURRENCY, timeout=DNS_TIMEOUT)
        if not parsed_nodes:
            return 2

    unique_by_source: Dict[str, int] = {u: 0 for u in source_urls}
    for n in parsed_nodes:
        for u in n["sources"]:
            unique_by_source[u] = unique_by_source.get(u, 0) + 1

    semaphore = asyncio.Semaphore(MAX_CONCURRENT_PINGS)
    reachable_all, unreachable_nodes = await probe_nodes_dedup(parsed_nodes, semaphore)
    candidates = cap_per_endpoint(reachable_all)
    cap_counts = {"endpoint": len(reachable_all) - len(candidates), "subnet": 0, "domain": 0}
    tested_nodes = unreachable_nodes + candidates

    cached_nodes, fresh_nodes, cached_failures = [], [], 0
    history_nodes = node_history_state.get("nodes", {})
    for node in candidates:
        entry = history_nodes.get(node_history_id(node), {})
        tls_mode, cert = entry.get("tls_mode"), entry.get("tls_cert_sha256")
        compat = (tls_mode in ("valid", "pinned") and (tls_mode != "pinned" or bool(cert))) if node.get("security") == "tls" else True
        if node["scheme"] == "hysteria2":
            compat = compat and bool(cert)
        if REJECT_RU_EXIT and entry.get("exit_country") == "RU":
            compat = False
        st = _e2e_cache_status(entry, now, compat) if E2E_VERIFY else "fresh"
        if st == "success":
            node.update({"e2e": "cached", "e2e_ms": entry.get("last_e2e_ms"), "last_verified_at": entry.get("last_verified_at"), "last_e2e_at": entry.get("last_e2e_at"), "last_e2e_ok": True, "tls_mode": tls_mode, "tls_cert_sha256": cert, "exit_country": entry.get("exit_country"), "ema_kbps": entry.get("ema_kbps")})
            cached_nodes.append(node)
        elif st == "failed":
            cached_failures += 1
            node.update({"e2e": "cached_failed", "last_e2e_at": entry.get("last_e2e_at"), "last_e2e_ok": False})
        else:
            fresh_nodes.append(node)

    fresh_nodes, tls_status = await prober.inspect_tls_batch(fresh_nodes, semaphore, inspect_fn=inspect_tls)
    fresh_nodes = [n for n in fresh_nodes if not (n["scheme"] == "hysteria2" and not n.get("tls_cert_sha256"))]
    native_hy2 = bool(hy2_e2e.find_hy2_binary(HY2_BIN))
    e2e_status: Dict[str, object] = {"enabled": E2E_VERIFY, "cached": len(cached_nodes), "cached_failed": cached_failures, "verified": 0, "failed": 0, "unsupported": 0, "ru_exit_rejected": 0, "slow_rejected": 0, "duration_sec": 0.0}
    if E2E_VERIFY and fresh_nodes:
        t0 = time.monotonic()
        try:
            e2e_res = await e2e.verify_nodes(fresh_nodes, xray_bin=xray_bin, concurrency=E2E_CONCURRENCY, timeout=E2E_TIMEOUT, hy2_bin=HY2_BIN)
        except e2e.E2ERuntimeError as exc:
            logger.error(f"E2E verification failed: {exc}")
            return 2
        e2e_status["duration_sec"] = round(time.monotonic() - t0, 1)
        ts = now.isoformat(timespec="seconds")
        for n, st, _ in e2e_res:
            e2e_status[st] = int(e2e_status.get(st, 0)) + 1
            if n.get("e2e_fail_reason") == "ru_exit":
                e2e_status["ru_exit_rejected"] = int(e2e_status["ru_exit_rejected"]) + 1
            elif n.get("e2e_fail_reason") == "slow":
                e2e_status["slow_rejected"] = int(e2e_status["slow_rejected"]) + 1
            if st in ("verified", "failed"):
                n["last_e2e_at"], n["last_e2e_ok"] = ts, (st == "verified")
            if st == "verified":
                n["last_verified_at"] = ts
        fresh_nodes = [n for n in fresh_nodes if n.get("e2e") != "failed"]
        logger.info(f"E2E fresh: ok={e2e_status['verified']}, fail={e2e_status['failed']} (ru_exit={e2e_status['ru_exit_rejected']}, slow={e2e_status['slow_rejected']}) in {e2e_status['duration_sec']}s")

    verified_nodes = cached_nodes + fresh_nodes
    prev_stats = load_previous_stats(STATS_OUTPUT)
    prev_total = int(prev_stats.get("alive") or read_previous_count(ALL_OUTPUT))
    prev_protos = {p: c for p, c in (prev_stats.get("alive_by_protocol") or {}).items() if p in SUPPORTED_SCHEMES}
    node_history, eligible_ids, stability_stats = update_node_history(node_history_state, tested_nodes, verified_nodes, now)
    alive_nodes = [n for n in verified_nodes if node_history_id(n) in eligible_ids]
    if prev_total and len(alive_nodes) < prev_total * (1 - MAX_DROP_RATIO) and len(verified_nodes) >= prev_total * (1 - MAX_DROP_RATIO):
        alive_nodes, stability_stats["bypassed"], stability_stats["held_back"] = list(verified_nodes), True, 0

    alive_nodes.sort(key=lambda n: rank_node_key(n, e2e_enabled=E2E_VERIFY))
    alive_nodes, pub_removed = cap_published_endpoints(alive_nodes)
    alive_nodes, div_removed = cap_diversity(alive_nodes)
    cap_counts.update({"published_endpoint": pub_removed, **div_removed})

    alive_counts, country_counts, exit_countries = {}, {}, {}
    alive_by_source: Dict[str, int] = {u: 0 for u in source_urls}
    for n in alive_nodes:
        alive_counts[n["scheme"]] = alive_counts.get(n["scheme"], 0) + 1
        country_counts[n["flag"]] = country_counts.get(n["flag"], 0) + 1
        if cc := n.get("exit_country"):
            exit_countries[cc] = exit_countries.get(cc, 0) + 1
        for u in n["sources"]:
            alive_by_source[u] = alive_by_source.get(u, 0) + 1

    source_stats = {u: {"active": (act := u in active_set), "raw": (rc := int(raw_by_source.get(u, 0)) if act else int((ent := health.get("sources", {}).get(u, {})).get("last_raw", 0))), "unique": int(unique_by_source.get(u, 0)) if act else int(ent.get("last_unique", 0)), "alive": (ac := int(alive_by_source.get(u, 0)) if act else int(ent.get("last_alive", 0))), "yield": round(ac / rc, 3) if rc else 0.0, "quarantined": bool((until := _parse_datetime(health.get("sources", {}).get(u, {}).get("quarantined_until"))) and until > now)} for u in source_urls}
    overall_latency, overall_speed = latency_summary(alive_nodes), speed_summary(alive_nodes)
    write_json_atomic(SOURCE_HEALTH_FILE, update_source_health(health, source_urls, source_stats, now))
    write_json_atomic(SOURCE_CACHE_FILE, {"updated_at": now.isoformat(timespec="seconds"), "sources": cached_sources})
    hist = [*load_history_list(HISTORY_FILE), {"timestamp": now.isoformat(timespec="seconds"), "alive": len(alive_nodes), "protocols": dict(sorted(alive_counts.items())), "delta": len(alive_nodes) - prev_total, "reachable": len(candidates), "e2e_verified": e2e_status["verified"], "e2e_cached": e2e_status["cached"], "e2e_cached_failed": e2e_status["cached_failed"], "e2e_failed": e2e_status["failed"], "latency_p50": overall_latency.get("p50"), "speed_kbps_p50": overall_speed.get("p50"), "sources_active": len(active_urls), "sources_quarantined": len(skipped_urls), "held_back": stability_stats["held_back"]}][-HISTORY_MAX_RUNS:]
    write_json_atomic(HISTORY_FILE, hist)
    write_json_atomic(NODE_HISTORY_FILE, node_history)

    baseline_reset = BASELINE_RESET or (E2E_VERIFY and not prev_stats.get("e2e_enabled", False)) or (ONLY_RU_IPS and not prev_stats.get("only_ru_ips", False))
    guard_reset = baseline_reset or (bool(prev_total) and len(verified_nodes) >= prev_total * (1 - MAX_DROP_RATIO) and len(alive_nodes) < prev_total * (1 - MAX_DROP_RATIO))
    try:
        enforce_guard(len(alive_nodes), prev_total, protocol_counts=alive_counts, previous_protocols=prev_protos, allow_baseline_reset=guard_reset)
        if alive_counts.get("vless", 0) == 0:
            raise GuardError("no vless nodes available for dedicated output")
    except GuardError as exc:
        logger.error(f"Output guard triggered: {exc}. Previous files kept.")
        return 1

    write_atomic(VLESS_OUTPUT, [format_link(n) for n in alive_nodes if n["scheme"] == "vless"])
    write_atomic(HY2_OUTPUT, [format_link(n) for n in alive_nodes if n["scheme"] == "hysteria2"])
    write_atomic(ALL_OUTPUT, [format_link(n) for n in alive_nodes])
    write_json_atomic(META_FILE, build_meta(alive_counts, len(alive_nodes), now))
    elapsed = round(time.monotonic() - started, 1)
    hy2_check = ("hysteria2_native_e2e" if native_hy2 else "xray_hysteria2_e2e") if E2E_VERIFY else ("quic_v1_handshake_h3" if HAS_AIOQUIC else "unverified")
    write_json_atomic(STATS_OUTPUT, {"updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "duration_sec": elapsed, "e2e_enabled": E2E_VERIFY, "only_ru_ips": ONLY_RU_IPS, "reject_ru_exit": REJECT_RU_EXIT, "ru_entry_proxy_enabled": bool(os.getenv("RU_ENTRY_PROXY", "").strip()), "ru_ip_filter": ru_filter_stats, "sources_total": len(source_urls), "sources_active": len(active_urls), "sources_skipped_quarantined": len(skipped_urls), "sources_with_data": fetched_ok, "raw_links": raw_total, "unique_valid": len(parsed_nodes), "poisoned_sni_rejected": poisoned_sni, "candidates_after_cap": len(candidates), "capped_by_endpoint": cap_counts["endpoint"], "capped_by_published_endpoint": cap_counts.get("published_endpoint", 0), "capped_by_subnet": cap_counts["subnet"], "capped_by_domain": cap_counts["domain"], "rejected_invalid": rejected, "reachable": len(candidates), "tls_inspection": tls_status, "hysteria2_pinned": sum(1 for n in alive_nodes if n["scheme"] == "hysteria2" and n.get("tls_cert_sha256")), "e2e": e2e_status, "alive": len(alive_nodes), "alive_by_protocol": dict(sorted(alive_counts.items())), "top_countries": dict(sorted(country_counts.items(), key=lambda i: -i[1])[:15]), "exit_countries": dict(sorted(exit_countries.items(), key=lambda i: -i[1])[:15]), "latency_ms": overall_latency, "speed_kbps": overall_speed, "latency_by_protocol": {p: latency_summary([n for n in alive_nodes if n["scheme"] == p]) for p in sorted(alive_counts)}, "previous_total": prev_total, "baseline_reset": baseline_reset, "stability": stability_stats, "source_stats": source_stats, "checks": {"vless": "xray_e2e" if E2E_VERIFY else "tcp_connect", "trojan": "xray_e2e" if E2E_VERIFY else "tcp_connect", "hysteria2": hy2_check}})
    logger.info(f"✅ Published {len(alive_nodes)} nodes ({elapsed}s)")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
