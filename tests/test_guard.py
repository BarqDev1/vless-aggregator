import json
import os

import pytest

import collector as c


def test_guard_passes_normal_run():
    c.enforce_guard(80, 100, min_alive=10, max_drop=0.5)


def test_guard_blocks_collapse():
    with pytest.raises(c.GuardError):
        c.enforce_guard(40, 100, min_alive=10, max_drop=0.5)


def test_guard_blocks_empty_run():
    with pytest.raises(c.GuardError):
        c.enforce_guard(0, 0, min_alive=10, max_drop=0.5)


def test_guard_allows_first_run():
    c.enforce_guard(10, 0, min_alive=10, max_drop=0.5)


def test_read_previous_count(tmp_path):
    path = tmp_path / "all.txt"
    assert c.read_previous_count(str(path)) == 0
    path.write_text("vless://a\n\nvless://b\n", encoding="utf-8")
    assert c.read_previous_count(str(path)) == 2


def test_write_atomic(tmp_path):
    path = tmp_path / "out.txt"
    path.write_text("old\n", encoding="utf-8")
    c.write_atomic(str(path), ["a", "b"])
    assert path.read_text(encoding="utf-8") == "a\nb\n"
    assert not os.path.exists(f"{path}.tmp")


def test_write_json_atomic(tmp_path):
    path = tmp_path / "stats.json"
    c.write_json_atomic(str(path), {"alive": 2, "flag": "🇷🇺"})
    assert json.loads(path.read_text(encoding="utf-8")) == {"alive": 2, "flag": "🇷🇺"}
    assert not os.path.exists(f"{path}.tmp")


def _node(host="1.2.3.4", port=443, sni="example.com", credential="a"):
    return {
        "scheme": "vless",
        "host": host,
        "port": port,
        "sni": sni,
        "credential": credential,
    }


def test_endpoint_cap_limits_credentials_per_server():
    nodes = [_node(credential=f"uuid-{i}") for i in range(5)]
    capped = c.cap_per_endpoint(nodes, limit=3)
    assert len(capped) == 3
    assert [node["credential"] for node in capped] == ["uuid-0", "uuid-1", "uuid-2"]


def test_endpoint_cap_keeps_distinct_endpoints():
    nodes = [
        _node(credential="a"),
        _node(credential="b"),
        _node(sni="other.example", credential="c"),
        _node(host="5.6.7.8", credential="d"),
        _node(port=8443, credential="e"),
    ]
    assert len(c.cap_per_endpoint(nodes, limit=1)) == 4


def test_published_endpoint_cap_removes_credential_copies(monkeypatch):
    monkeypatch.setattr(c, "PUBLISH_PER_ENDPOINT", 1)
    nodes = [_node(credential=f"uuid-{i}") for i in range(3)]
    kept, removed = c.cap_published_endpoints(nodes)
    assert len(kept) == 1
    assert removed == 2


def test_guard_protocol_disappeared():
    with pytest.raises(c.GuardError):
        c.enforce_guard(
            50,
            50,
            protocol_counts={"vless": 50},
            previous_protocols={"vless": 50, "hysteria2": 10},
        )


def test_guard_protocol_large_drop():
    with pytest.raises(c.GuardError):
        c.enforce_guard(
            100,
            100,
            protocol_counts={"vless": 20},
            previous_protocols={"vless": 100},
        )
    c.enforce_guard(
        100,
        100,
        protocol_counts={"vless": 40},
        previous_protocols={"vless": 100},
    )


def test_guard_baseline_reset_skips_drop_checks():
    c.enforce_guard(
        5,
        500,
        min_alive=1,
        protocol_counts={"hysteria2": 0},
        previous_protocols={"hysteria2": 10},
        allow_baseline_reset=True,
    )


def test_cap_for_diversity_limits_subnet(monkeypatch):
    monkeypatch.setattr(c, "MAX_PER_ENDPOINT", 10)
    monkeypatch.setattr(c, "MAX_PER_SUBNET", 1)
    monkeypatch.setattr(c, "MAX_PER_DOMAIN", 10)
    nodes = [_node(host="10.0.0.1"), _node(host="10.0.0.2")]
    kept, removed = c.cap_for_diversity(nodes)
    assert len(kept) == 1
    assert removed["subnet"] == 1


def test_domain_key_handles_multi_label_suffixes():
    assert c._domain_key({"host": "a.b.example.co.uk"}) == "example.co.uk"
    assert c._domain_key({"host": "x.example.com"}) == "example.com"
    assert c._domain_key({"host": "1.2.3.4"}) is None


def test_source_health_quarantines_after_threshold(monkeypatch):
    monkeypatch.setattr(c, "SOURCE_FAILURE_THRESHOLD", 3)
    monkeypatch.setattr(c, "SOURCE_QUARANTINE_HOURS", 24)
    now = c.datetime(2026, 1, 1, tzinfo=c.timezone.utc)
    health = {"sources": {}}
    stat = {"u": {"raw": 10, "unique": 5, "alive": 0, "active": True}}

    for _ in range(2):
        health = c.update_source_health(health, ["u"], stat, now)
    assert health["sources"]["u"]["consecutive_failures"] == 2
    assert health["sources"]["u"]["quarantined_until"] is None

    health = c.update_source_health(health, ["u"], stat, now)
    assert health["sources"]["u"]["consecutive_failures"] == 3
    assert health["sources"]["u"]["quarantined_until"] is not None

    active, skipped = c.select_active_sources(["u"], health, now + c.timedelta(hours=1))
    assert active == []
    assert skipped == ["u"]

    active, skipped = c.select_active_sources(["u"], health, now + c.timedelta(hours=25))
    assert active == ["u"]
    assert skipped == []


def test_source_health_recovery_resets_failures():
    now = c.datetime(2026, 1, 1, tzinfo=c.timezone.utc)
    health = {
        "sources": {
            "u": {"consecutive_failures": 3, "quarantined_until": now.isoformat()},
        }
    }
    health = c.update_source_health(
        health, ["u"], {"u": {"raw": 10, "unique": 5, "alive": 2, "active": True}}, now
    )
    assert health["sources"]["u"]["consecutive_failures"] == 0
    assert health["sources"]["u"]["quarantined_until"] is None


def test_source_health_preserves_skipped_source():
    now = c.datetime(2026, 1, 1, tzinfo=c.timezone.utc)
    old = {"consecutive_failures": 3, "quarantined_until": now.isoformat(), "last_alive": 1}
    health = {"sources": {"u": old}}
    updated = c.update_source_health(
        health, ["u"], {"u": {"active": False}}, now
    )
    assert updated["sources"]["u"] == old


def test_latency_summary():
    nodes = [
        {"latency_ms": 100.0},
        {"latency_ms": 200.0},
        {"e2e_ms": 300.0, "e2e": "verified"},
    ]
    summary = c.latency_summary(nodes)
    assert summary["min"] == 100.0
    assert summary["max"] == 300.0
    assert summary["p50"] in (200.0, 300.0)
