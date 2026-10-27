from datetime import timedelta

from vpn_aggregator import collector as c


def _node(key: str) -> dict:
    return {"dedup_key": key}


def test_node_history_bootstrap_publishes_current_nodes():
    now = c.datetime(2026, 1, 1, tzinfo=c.timezone.utc)
    node = _node("a")
    state, eligible, stats = c.update_node_history({"nodes": {}}, [node], [node], now)
    assert stats["bootstrap"] == 1
    assert stats["held_back"] == 0
    assert c.node_history_id(node) in eligible


def test_new_node_needs_two_recent_successes():
    now = c.datetime(2026, 1, 1, tzinfo=c.timezone.utc)
    node = _node("new")
    state, eligible, stats = c.update_node_history({"nodes": {}}, [node], [node], now)
    # Bootstrap treats the first observation as trusted.
    assert c.node_history_id(node) in eligible

    state = {
        "nodes": {
            "seed": {"recent": [True], "last_seen": now.isoformat(timespec="seconds")}
        }
    }
    state, eligible, stats = c.update_node_history(state, [node], [node], now)
    assert stats["held_back"] == 1
    assert c.node_history_id(node) not in eligible

    state, eligible, stats = c.update_node_history(state, [node], [node], now + timedelta(hours=1))
    assert c.node_history_id(node) in eligible


def test_existing_node_survives_one_failure_in_window():
    now = c.datetime(2026, 1, 1, tzinfo=c.timezone.utc)
    node = _node("stable")
    state = {"nodes": {}}
    state, _, _ = c.update_node_history(state, [node], [node], now)
    state, _, _ = c.update_node_history(state, [node], [node], now + timedelta(hours=1))

    state, eligible, _ = c.update_node_history(
        state, [node], [], now + timedelta(hours=2)
    )
    assert c.node_history_id(node) not in eligible
    entry = state["nodes"][c.node_history_id(node)]
    assert entry["recent"][-1] is False

    state, eligible, _ = c.update_node_history(
        state, [node], [node], now + timedelta(hours=3)
    )
    assert c.node_history_id(node) in eligible


def test_node_history_prunes_old_entries():
    now = c.datetime(2026, 1, 1, tzinfo=c.timezone.utc)
    old = (now - timedelta(days=c.NODE_HISTORY_TTL_DAYS + 1)).isoformat()
    state = {"nodes": {"deadbeef": {"recent": [True], "last_seen": old}}}
    updated, eligible, stats = c.update_node_history(state, [], [], now)
    assert "deadbeef" not in updated["nodes"]
    assert stats["pruned"] == 1
    assert eligible == set()


def test_meta_contains_subscription_metadata():
    now = c.datetime(2026, 1, 1, tzinfo=c.timezone.utc)
    meta = c.build_meta({"vless": 3, "trojan": 1}, 4, now)
    assert meta["profile_title"]
    assert meta["profile_update_interval"] == c.PROFILE_UPDATE_INTERVAL
    assert meta["support_url"].startswith("https://")
    assert meta["counts"] == {"total": 4, "trojan": 1, "vless": 3}
    assert set(meta["subscriptions"]) == {"all", "vless", "hysteria2"}


def test_e2e_cache_freshness(monkeypatch):
    now = c.datetime(2026, 1, 1, 12, 0, tzinfo=c.timezone.utc)
    monkeypatch.setattr(c, "E2E_CACHE_MINUTES", 60)
    monkeypatch.setattr(c, "E2E_FAILURE_CACHE_MINUTES", 15)
    recent = {
        "last_e2e_at": (now - timedelta(minutes=30)).isoformat(),
        "last_e2e_ok": True,
    }
    stale = {
        "last_e2e_at": (now - timedelta(minutes=90)).isoformat(),
        "last_e2e_ok": True,
    }
    recent_failure = {
        "last_e2e_at": (now - timedelta(minutes=5)).isoformat(),
        "last_e2e_ok": False,
    }
    old_failure = {
        "last_e2e_at": (now - timedelta(minutes=30)).isoformat(),
        "last_e2e_ok": False,
    }
    assert c._cache_is_fresh(recent, now)
    assert not c._cache_is_fresh(stale, now)
    assert c._e2e_cache_status(recent_failure, now) == "failed"
    assert c._e2e_cache_status(old_failure, now) == "fresh"
    assert not c._cache_is_fresh({}, now)


def test_node_history_stores_verification_cache():
    now = c.datetime(2026, 1, 1, tzinfo=c.timezone.utc)
    node = _node("cache-me")
    node.update(
        {
            "e2e": "verified",
            "last_verified_at": now.isoformat(timespec="seconds"),
            "last_e2e_at": now.isoformat(timespec="seconds"),
            "last_e2e_ok": True,
            "e2e_ms": 123.4,
            "tls_mode": "pinned",
            "tls_cert_sha256": "abc123",
        }
    )
    state, _, _ = c.update_node_history({"nodes": {}}, [node], [node], now)
    entry = state["nodes"][c.node_history_id(node)]
    assert entry["last_verified_at"] == node["last_verified_at"]
    assert entry["last_e2e_at"] == node["last_e2e_at"]
    assert entry["last_e2e_ok"] is True
    assert entry["last_e2e_ms"] == 123.4
    assert entry["tls_mode"] == "pinned"
    assert entry["tls_cert_sha256"] == "abc123"


def test_node_history_clears_cache_on_failure():
    now = c.datetime(2026, 1, 1, tzinfo=c.timezone.utc)
    node = _node("cache-me")
    node["last_verified_at"] = now.isoformat(timespec="seconds")
    state, _, _ = c.update_node_history({"nodes": {}}, [node], [node], now)
    state, _, _ = c.update_node_history(state, [node], [], now + timedelta(hours=1))
    entry = state["nodes"][c.node_history_id(node)]
    assert "last_verified_at" not in entry


def test_history_list_loader_ignores_invalid(tmp_path):
    path = tmp_path / "history.json"
    path.write_text('{"not": "a list"}', encoding="utf-8")
    assert c.load_history_list(str(path)) == []
    path.write_text('[{"alive": 1}, "junk"]', encoding="utf-8")
    assert c.load_history_list(str(path)) == [{"alive": 1}]


def test_header_value_is_case_insensitive():
    headers = {"Etag": "abc", "Last-Modified": "today"}
    assert c._header_value(headers, "ETag") == "abc"
    assert c._header_value(headers, "etag") == "abc"
    assert c._header_value(headers, "missing") is None


def test_source_cache_loader(tmp_path):
    path = tmp_path / "source_cache.json"
    assert c.load_source_cache(str(path)) == {"updated_at": None, "sources": {}}
    path.write_text('{"sources": {"u": {"etag": "x"}}}', encoding="utf-8")
    assert c.load_source_cache(str(path))["sources"]["u"]["etag"] == "x"
