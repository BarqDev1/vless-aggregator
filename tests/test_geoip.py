import asyncio
import json
from datetime import datetime, timedelta, timezone

import pytest

from vpn_aggregator import geoip


def test_matcher_checks_ipv4_and_ipv6_ranges():
    matcher = geoip.RuIpMatcher.from_cidrs(
        [
            "78.159.240.0/20",
            "188.72.103.0/24",
            "2a02:6b8::/32",
        ]
    )
    assert matcher.contains("78.159.250.107")
    assert matcher.contains("188.72.103.4")
    assert matcher.contains("2a02:6b8::1")
    assert not matcher.contains("104.21.60.73")
    assert not matcher.contains("2606:4700::1")


def test_matcher_rejects_private_and_loopback_ips():
    matcher = geoip.RuIpMatcher.from_cidrs(["0.0.0.0/0", "::/0"])
    assert not matcher.contains("127.0.0.1")
    assert not matcher.contains("10.0.0.1")
    assert not matcher.contains("192.168.1.1")
    assert not matcher.contains("::1")
    assert not matcher.contains("not-an-ip")
    assert matcher.contains("78.159.250.107")


def test_parse_cidr_text_ignores_comments_and_invalid():
    text = "# header\n\n78.159.240.0/20\ninvalid-line\n2a02:6b8::/32\n"
    assert geoip.parse_cidr_text(text) == ["78.159.240.0/20", "2a02:6b8::/32"]


def test_parse_ripe_ru_payload_handles_ranges_and_cidrs():
    payload = {
        "data": {
            "resources": {
                "ipv4": ["188.72.103.0-188.72.103.255", "95.163.209.0/24", "bad"],
                "ipv6": ["2a02:6b8::/32", "bad"],
            }
        }
    }
    cidrs = geoip.parse_ripe_ru_payload(payload)
    assert "188.72.103.0/24" in cidrs
    assert "95.163.209.0/24" in cidrs
    assert "2a02:6b8::/32" in cidrs


def test_filter_ru_nodes_resolves_domains_and_drops_non_ru(monkeypatch):
    matcher = geoip.RuIpMatcher.from_cidrs(["78.159.240.0/20", "95.163.209.0/24"])

    fake_dns = {
        "78.159.250.107": ["78.159.250.107"],
        "ru.example": ["95.163.209.247"],
        "mixed.example": ["95.163.209.247", "104.21.60.73"],
        "us.example": ["104.21.60.73"],
        "dead.example": [],
        "local.example": ["127.0.0.1"],
    }
    calls = []

    async def fake_resolve(host: str, timeout: float = 5.0):
        calls.append(host)
        return fake_dns[host]

    monkeypatch.setattr(geoip, "resolve_host_ips", fake_resolve)

    nodes = [
        {"host": "78.159.250.107"},
        {"host": "ru.example"},
        {"host": "RU.EXAMPLE"},
        {"host": "mixed.example"},
        {"host": "us.example"},
        {"host": "dead.example"},
        {"host": "local.example"},
    ]

    kept, stats = asyncio.run(geoip.filter_ru_nodes(nodes, matcher))
    assert [n["host"] for n in kept] == ["78.159.250.107", "ru.example", "RU.EXAMPLE"]
    assert kept[1]["resolved_ips"] == ["95.163.209.247"]
    assert stats == {
        "checked": 7,
        "kept": 3,
        "non_ru": 2,
        "unresolved": 1,
        "non_public": 1,
        "unique_hosts": 6,
    }
    assert calls.count("ru.example") == 1


def test_load_ru_matcher_uses_fresh_cache_without_network(tmp_path):
    now = datetime(2026, 11, 22, 12, 0, tzinfo=timezone.utc)
    cache = tmp_path / "ru_cache.json"
    cache.write_text(
        json.dumps(
            {
                "updated_at": (now - timedelta(hours=1)).isoformat(),
                "cidrs": ["78.159.240.0/20"],
            }
        ),
        encoding="utf-8",
    )

    matcher = asyncio.run(geoip.load_ru_matcher(None, str(cache), now=now))  # type: ignore[arg-type]
    assert matcher.contains("78.159.250.107")
    assert not matcher.contains("1.1.1.1")


def test_load_ru_matcher_falls_back_to_stale_cache_on_network_error(tmp_path, monkeypatch):
    now = datetime(2026, 11, 22, 12, 0, tzinfo=timezone.utc)
    cache = tmp_path / "ru_cache.json"
    cache.write_text(
        json.dumps(
            {
                "updated_at": (now - timedelta(days=3)).isoformat(),
                "cidrs": ["78.159.240.0/20"],
            }
        ),
        encoding="utf-8",
    )

    async def fail_fetch(session, url, timeout):
        return None

    monkeypatch.setattr(geoip, "_fetch_text", fail_fetch)
    matcher = asyncio.run(geoip.load_ru_matcher(None, str(cache), now=now))  # type: ignore[arg-type]
    assert matcher.contains("78.159.250.107")


def test_load_ru_matcher_fails_closed_without_cache_or_network(tmp_path, monkeypatch):
    async def fail_fetch(session, url, timeout):
        return None

    monkeypatch.setattr(geoip, "_fetch_text", fail_fetch)
    with pytest.raises(geoip.GeoIPRuntimeError):
        asyncio.run(geoip.load_ru_matcher(None, str(tmp_path / "missing.json")))  # type: ignore[arg-type]


def test_resolve_host_ips_returns_literal_ip_without_dns():
    assert asyncio.run(geoip.resolve_host_ips("78.159.250.107")) == ["78.159.250.107"]
    assert asyncio.run(geoip.resolve_host_ips("2a02:6b8::1")) == ["2a02:6b8::1"]
