import asyncio
import json
from pathlib import Path

from vpn_aggregator import collector as c

ROOT = Path(__file__).resolve().parents[1]
VLESS = ROOT / "vless_universal.txt"
HY2 = ROOT / "hysteria2.txt"
SS = ROOT / "shadowsocks.txt"
ALL = ROOT / "all_universal.txt"
STATS = ROOT / "state" / "stats.json"


def _lines(path: Path):
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_output_files_exist():
    for path in (VLESS, HY2, SS, ALL):
        assert path.is_file(), f"missing {path.name}"
        assert _lines(path), f"empty {path.name}"


def test_every_exported_line_is_valid():
    for path in (VLESS, HY2, SS, ALL):
        for line in _lines(path):
            node = c.parse_vpn_link(line)
            assert node is not None, f"invalid link in {path.name}: {line[:100]}"
            assert node["scheme"] in c.SUPPORTED_SCHEMES
            assert node["remark"], f"empty remark in {path.name}"
            assert node["flag"]


def test_excluded_protocols_are_absent():
    for path in (VLESS, HY2, SS, ALL):
        for line in _lines(path):
            assert not line.startswith(c.EXCLUDED_PREFIXES), f"excluded protocol in {path.name}"


def test_outputs_are_split_by_protocol():
    assert all(line.startswith("vless://") for line in _lines(VLESS))
    assert all(line.startswith(("hysteria2://", "hy2://")) for line in _lines(HY2))
    assert all(line.startswith("ss://") for line in _lines(SS))
    assert all(line.startswith(c.SUPPORTED_PREFIXES) for line in _lines(ALL))


def test_all_output_is_a_superset_of_protocol_files():
    all_lines = set(_lines(ALL))
    assert set(_lines(VLESS)) <= all_lines
    assert set(_lines(HY2)) <= all_lines
    assert set(_lines(SS)) <= all_lines


def test_no_exact_duplicates_in_all_output():
    keys = [c.parse_vpn_link(line)["dedup_key"] for line in _lines(ALL)]
    assert len(keys) == len(set(keys))


def test_stats_match_exported_data():
    if not STATS.is_file():
        return
    stats = json.loads(STATS.read_text(encoding="utf-8"))
    assert stats["alive"] == len(_lines(ALL))
    protocols = {}
    for line in _lines(ALL):
        node = c.parse_vpn_link(line)
        protocols[node["scheme"]] = protocols.get(node["scheme"], 0) + 1
    assert stats["alive_by_protocol"] == protocols


def test_modern_xray_compatible_tls_links():
    # Xray-core >= 26 rejects allowInsecure/insecure and plaintext VLESS.
    for line in _lines(ALL):
        node = c.parse_vpn_link(line)
        params = {key.lower(): values for key, values in node["query"].items()}
        assert "insecure" not in params
        assert "allowinsecure" not in params
        if node["scheme"] == "vless":
            assert node["security"] in ("tls", "reality")
        if node["scheme"] == "hysteria2":
            assert "pinsha256" in params
        if "pcs" in params:
            assert all(
                len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)
                for value in params["pcs"]
            )
        if "pinsha256" in params:
            assert all(
                len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)
                for value in params["pinsha256"]
            )


def test_udp_uses_quic_check(monkeypatch):
    called = {}

    async def fake_quic(node, timeout):
        called["node"] = node
        return True

    monkeypatch.setattr(c, "_check_quic", fake_quic)
    node = {"host": "example.com", "port": 443, "sni": "example.com", "transport": "udp"}
    assert asyncio.run(c.check_connectivity(node)) is True
    assert called["node"] is node
