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
