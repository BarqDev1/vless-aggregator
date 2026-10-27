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
    assert meta["profile_update_interval"] == 0.5
    assert meta["support_url"].startswith("https://")
    assert meta["counts"] == {"total": 4, "trojan": 1, "vless": 3}
    assert set(meta["subscriptions"]) == {"all", "vless", "hysteria2"}


def test_history_list_loader_ignores_invalid(tmp_path):
    path = tmp_path / "history.json"
    path.write_text('{"not": "a list"}', encoding="utf-8")
    assert c.load_history_list(str(path)) == []
    path.write_text('[{"alive": 1}, "junk"]', encoding="utf-8")
    assert c.load_history_list(str(path)) == [{"alive": 1}]
