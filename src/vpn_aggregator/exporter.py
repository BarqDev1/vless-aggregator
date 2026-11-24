"""Output guard, node stability history, quality ranking, metadata, and atomic writers."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Optional, Tuple

from .quality import tspu_score
from .sources import parse_datetime


class GuardError(RuntimeError):
    """Raised when the fresh output looks dangerously small."""


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
    min_alive: int = 10,
    max_drop: float = 0.5,
    protocol_counts: Optional[Dict[str, int]] = None,
    previous_protocols: Optional[Dict[str, int]] = None,
    protocol_min: int = 3,
    protocol_max_drop: float = 0.7,
    allow_baseline_reset: bool = False,
) -> None:
    """Refuses to publish an empty, collapsed or protocol-degraded subscription."""
    if alive < min_alive:
        raise GuardError(f"only {alive} alive nodes (< MIN_ALIVE={min_alive})")
    if allow_baseline_reset:
        return
    if previous and alive < previous * (1 - max_drop):
        raise GuardError(f"alive nodes dropped from {previous} to {alive} (> {int(max_drop * 100)}% loss)")

    for protocol, previous_count in (previous_protocols or {}).items():
        if previous_count <= 0:
            continue
        current = (protocol_counts or {}).get(protocol, 0)
        if current == 0 and (previous_count >= protocol_min or protocol == "vless"):
            raise GuardError(f"{protocol} disappeared completely (was {previous_count})")
        if previous_count >= protocol_min and current < previous_count * (1 - protocol_max_drop):
            raise GuardError(f"{protocol} dropped from {previous_count} to {current} (> {int(protocol_max_drop * 100)}% loss)")


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


def e2e_cache_status(
    entry: dict,
    now: datetime,
    compatible: bool = True,
    *,
    cache_minutes: float = 60.0,
    failure_cache_minutes: float = 15.0,
) -> str:
    last_attempt = parse_datetime(entry.get("last_e2e_at"))
    if not last_attempt or last_attempt > now:
        return "fresh"
    ok = bool(entry.get("last_e2e_ok"))
    ttl = cache_minutes if ok else failure_cache_minutes
    if ttl <= 0 or (now - last_attempt).total_seconds() > ttl * 60:
        return "fresh"
    if ok and compatible:
        return "success"
    return "failed" if not ok else "fresh"


def cache_is_fresh(
    entry: dict,
    now: datetime,
    *,
    cache_minutes: float = 60.0,
    failure_cache_minutes: float = 15.0,
) -> bool:
    return e2e_cache_status(entry, now, cache_minutes=cache_minutes, failure_cache_minutes=failure_cache_minutes) == "success"


def update_node_history(
    state: dict,
    tested_nodes: List[dict],
    verified_nodes: List[dict],
    now: datetime,
    *,
    recent_window: int = 3,
    min_recent_success: int = 2,
    ttl_days: int = 30,
    max_entries: int = 10000,
) -> Tuple[dict, set, Dict[str, object]]:
    """Implements the stability policy, EMA latency/throughput tracking, and pruning."""
    raw_nodes = state.get("nodes")
    old_nodes: Dict[str, dict] = raw_nodes if isinstance(raw_nodes, dict) else {}
    nodes: Dict[str, dict] = {str(key): dict(value) for key, value in old_nodes.items()}
    bootstrap = not nodes

    tested_ids = {node_history_id(node) for node in tested_nodes}
    verified_ids = {node_history_id(node) for node in verified_nodes}
    timestamp = now.isoformat(timespec="seconds")

    for node in verified_nodes:
        node_id = node_history_id(node)
        entry = nodes.setdefault(node_id, {"recent": [], "successes": 0, "failures": 0, "first_seen": timestamp})
        recent = [True, True] if bootstrap else [*entry.get("recent", []), True]
        entry["recent"] = recent[-recent_window:]
        entry["successes"] = int(entry.get("successes", 0)) + 1
        entry["streak"] = int(entry.get("streak", 0)) + 1
        entry["last_seen"] = timestamp
        entry["last_success"] = timestamp

        sample_ms = node.get("e2e_ms") if node.get("e2e_ms") is not None else node.get("latency_ms")
        if isinstance(sample_ms, (int, float)):
            prev_ema = entry.get("ema_ms")
            entry["ema_ms"] = round(0.6 * float(sample_ms) + 0.4 * float(prev_ema), 1) if isinstance(prev_ema, (int, float)) else round(float(sample_ms), 1)
            node["ema_ms"] = entry["ema_ms"]

        sample_kbps = node.get("speed_kbps")
        if isinstance(sample_kbps, (int, float)) and sample_kbps > 0:
            prev_kbps = entry.get("ema_kbps")
            entry["ema_kbps"] = round(0.6 * float(sample_kbps) + 0.4 * float(prev_kbps), 1) if isinstance(prev_kbps, (int, float)) and prev_kbps > 0 else round(float(sample_kbps), 1)
            node["ema_kbps"] = entry["ema_kbps"]
        elif isinstance(entry.get("ema_kbps"), (int, float)):
            node["ema_kbps"] = entry["ema_kbps"]

        if node.get("exit_country"):
            entry["exit_country"] = node["exit_country"]
        elif entry.get("exit_country"):
            node["exit_country"] = entry["exit_country"]

        node["streak"] = entry["streak"]
        if node.get("last_verified_at"):
            entry["last_verified_at"] = node["last_verified_at"]
        else:
            entry.pop("last_verified_at", None)
        if node.get("e2e") in ("verified", "cached"):
            entry["last_e2e_at"] = node.get("last_e2e_at") or node.get("last_verified_at") or timestamp
            entry["last_e2e_ok"] = True
            entry["last_e2e_ms"] = node.get("e2e_ms")
        else:
            for k in ("last_e2e_at", "last_e2e_ok", "last_e2e_ms"):
                entry.pop(k, None)
        entry["tls_mode"] = node.get("tls_mode")
        entry["tls_cert_sha256"] = node.get("tls_cert_sha256")
        nodes[node_id] = entry

    tested_map = {node_history_id(node): node for node in tested_nodes}
    for node_id in tested_ids - verified_ids:
        failed_entry = nodes.get(node_id)
        if failed_entry is None:
            continue
        failed_node = tested_map.get(node_id, {})
        failed_entry["recent"] = [*failed_entry.get("recent", []), False][-recent_window:]
        failed_entry["failures"] = int(failed_entry.get("failures", 0)) + 1
        failed_entry["streak"] = 0
        failed_entry["last_seen"] = timestamp
        failed_entry.pop("last_verified_at", None)
        if failed_node.get("last_e2e_at") and failed_node.get("e2e") in ("failed", "cached_failed"):
            failed_entry["last_e2e_at"] = failed_node["last_e2e_at"]
            failed_entry["last_e2e_ok"] = False
        else:
            failed_entry.pop("last_e2e_at", None)
            failed_entry.pop("last_e2e_ok", None)

    cutoff = now - timedelta(days=ttl_days)
    pruned = 0
    for node_id, entry in list(nodes.items()):
        last_seen = parse_datetime(entry.get("last_seen"))
        if last_seen and last_seen < cutoff:
            del nodes[node_id]
            pruned += 1

    if len(nodes) > max_entries:
        newest = sorted(nodes.items(), key=lambda item: item[1].get("last_seen") or "", reverse=True)[:max_entries]
        pruned += len(nodes) - len(newest)
        nodes = dict(newest)

    eligible = {
        node_id
        for node_id in verified_ids
        if sum(bool(r) for r in nodes.get(node_id, {}).get("recent", [])[-recent_window:]) >= min_recent_success
    }
    stats: Dict[str, object] = {
        "tracked": len(nodes),
        "bootstrap": int(bootstrap),
        "verified": len(verified_ids),
        "eligible": len(eligible),
        "held_back": len(verified_ids - eligible),
        "pruned": pruned,
    }
    return {"updated_at": timestamp, "nodes": nodes}, eligible, stats


def rank_node_key(node: dict, *, e2e_enabled: bool = True) -> Tuple[bool, float]:
    """Computes effective lower-is-better score combining latency, speed, streak, and TSPU resilience."""
    base = node.get("ema_ms")
    if base is None:
        base = node.get("e2e_ms") if (e2e_enabled and node.get("e2e") in ("verified", "cached") and node.get("e2e_ms") is not None) else node.get("latency_ms")
    if base is None:
        return True, 0.0

    effective = float(base)
    if int(node.get("streak") or 0) >= 3:
        effective *= 0.85

    kbps = node.get("ema_kbps") or node.get("speed_kbps")
    if isinstance(kbps, (int, float)) and kbps > 0:
        if kbps >= 8000:
            effective *= 0.78
        elif kbps >= 3000:
            effective *= 0.88
        elif kbps < 600:
            effective *= 1.25

    bonus = tspu_score(node)
    if bonus > 0:
        effective *= max(0.82, 1.0 - (bonus / 200.0))
    if node.get("exit_country") and node.get("exit_country") != "RU":
        effective *= 0.95
    return False, round(effective, 2)


def build_meta(
    alive_counts: Dict[str, int],
    total: int,
    now: datetime,
    *,
    profile_title: str = "BarqDev Multi-Protocol VPN",
    profile_update_interval: float = 0.5,
    support_url: str = "https://github.com/BarqDev1/vless-aggregator/issues",
    home_url: str = "https://github.com/BarqDev1/vless-aggregator",
) -> dict:
    public_base = os.getenv("PUBLIC_BASE_URL", "").strip().rstrip("/")
    sub_key = os.getenv("SUB_KEY", "").strip("/")
    if public_base:
        prefix = f"{public_base}/{sub_key}" if sub_key else public_base
        subscriptions = {"all": f"{prefix}/all", "vless": f"{prefix}/vless", "hysteria2": f"{prefix}/hy2"}
    else:
        raw_base = f"https://raw.githubusercontent.com/{os.getenv('GITHUB_REPOSITORY', 'BarqDev1/vless-aggregator')}/main"
        subscriptions = {
            "all": f"{raw_base}/all_universal.txt",
            "vless": f"{raw_base}/vless_universal.txt",
            "hysteria2": f"{raw_base}/hysteria2.txt",
        }
    return {
        "profile_title": profile_title,
        "profile_update_interval": profile_update_interval,
        "support_url": support_url,
        "home_url": home_url,
        "subscription_userinfo": None,
        "updated_at": now.isoformat(timespec="seconds"),
        "counts": {"total": total, **dict(sorted(alive_counts.items()))},
        "subscriptions": subscriptions,
    }


def _percentile(values: List[float], quantile: float) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((quantile / 100) * (len(ordered) - 1))))
    return round(ordered[index], 1)


def latency_summary(nodes: List[dict]) -> Dict[str, float]:
    values = [
        float(v)
        for n in nodes
        if isinstance((v := n.get("e2e_ms") if n.get("e2e_ms") is not None else n.get("latency_ms")), (int, float))
    ]
    if not values:
        return {}
    return {"p50": _percentile(values, 50) or 0.0, "p90": _percentile(values, 90) or 0.0, "min": round(min(values), 1), "max": round(max(values), 1)}


def speed_summary(nodes: List[dict]) -> Dict[str, float]:
    values = [
        float(v)
        for n in nodes
        if isinstance((v := n.get("ema_kbps") if n.get("ema_kbps") is not None else n.get("speed_kbps")), (int, float)) and v > 0
    ]
    if not values:
        return {}
    return {"p50": _percentile(values, 50) or 0.0, "p90": _percentile(values, 90) or 0.0, "min": round(min(values), 1), "max": round(max(values), 1)}


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
