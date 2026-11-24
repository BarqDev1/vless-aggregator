import asyncio

from vpn_aggregator import batch_e2e, e2e
from vpn_aggregator import collector as c


def _vless_node(host: str = "1.2.3.4", port: int = 443) -> dict:
    node = c.parse_vpn_link(
        f"vless://11111111-1111-1111-1111-111111111111@{host}:{port}"
        "?encryption=none&security=reality&pbk=public-key&sni=example.com&type=tcp#node"
    )
    assert node is not None
    return node


def test_allocate_free_ports_returns_distinct_ports():
    ports = batch_e2e._allocate_free_ports(6)
    assert len(ports) == 6
    assert len(set(ports)) == 6
    assert all(1024 <= p <= 65535 for p in ports)


def test_build_batch_xray_config_maps_inbounds_to_outbounds():
    n1 = _vless_node("1.1.1.1", 443)
    n2 = _vless_node("2.2.2.2", 8443)
    cfg1 = e2e.build_xray_config(n1, 10001)
    cfg2 = e2e.build_xray_config(n2, 10002)
    assert cfg1 is not None and cfg2 is not None

    batch_cfg = batch_e2e.build_batch_xray_config([(0, cfg1, 20001), (1, cfg2, 20002)])
    assert [ib["tag"] for ib in batch_cfg["inbounds"]] == ["in-0", "in-1"]
    assert [ib["port"] for ib in batch_cfg["inbounds"]] == [20001, 20002]
    assert [ob["tag"] for ob in batch_cfg["outbounds"]] == ["out-0", "out-1"]
    assert batch_cfg["routing"]["rules"] == [
        {"type": "field", "inboundTag": ["in-0"], "outboundTag": "out-0"},
        {"type": "field", "inboundTag": ["in-1"], "outboundTag": "out-1"},
    ]


def test_verify_nodes_batched_handles_unsupported_and_probes(monkeypatch, tmp_path):
    fake_xray = tmp_path / "xray"
    fake_xray.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")

    class _FakeProc:
        def poll(self):
            return None

        def kill(self):
            return None

        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr(batch_e2e.subprocess, "Popen", lambda *a, **kw: _FakeProc())

    async def fake_wait(port, proc, timeout=3.5):
        return True

    async def fake_probe(session, port, timeout, sem):
        return ("verified", 55.5) if port % 2 == 0 else ("failed", None)

    monkeypatch.setattr(batch_e2e, "_wait_for_port_async", fake_wait)
    monkeypatch.setattr(batch_e2e, "_probe_via_http_proxy", fake_probe)
    monkeypatch.setattr(batch_e2e, "_allocate_free_ports", lambda count: [30000 + i for i in range(count)])

    n_ok = _vless_node("1.1.1.1", 443)
    n_fail = _vless_node("2.2.2.2", 443)
    n_bad = _vless_node("3.3.3.3", 443)
    n_bad["query"]["type"] = ["quic"]

    results = asyncio.run(
        batch_e2e.verify_nodes_batched(
            [n_ok, n_fail, n_bad], xray_bin=str(fake_xray), concurrency=4, timeout=3.0, batch_size=8
        )
    )
    assert [(r[1], r[2]) for r in results] == [
        ("verified", 55.5),
        ("failed", None),
        ("unsupported", None),
    ]
    assert n_ok["e2e"] == "verified"
    assert n_ok["e2e_ms"] == 55.5
    assert n_bad["e2e"] == "unsupported"


def test_verify_nodes_batched_falls_back_to_single_on_batch_start_failure(monkeypatch, tmp_path):
    fake_xray = tmp_path / "xray"
    fake_xray.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")

    class _DeadProc:
        def poll(self):
            return 1

        def kill(self):
            return None

        def wait(self, timeout=None):
            return 1

    monkeypatch.setattr(batch_e2e.subprocess, "Popen", lambda *a, **kw: _DeadProc())

    async def fake_wait(port, proc, timeout=3.5):
        return False

    fallback_calls = []

    def fake_verify_one(node, xray_bin, timeout):
        fallback_calls.append(node["host"])
        return "verified", 88.0

    monkeypatch.setattr(batch_e2e, "_wait_for_port_async", fake_wait)
    monkeypatch.setattr(e2e, "verify_one", fake_verify_one)

    nodes = [_vless_node("10.0.0.1", 443), _vless_node("10.0.0.2", 443)]
    results = asyncio.run(
        batch_e2e.verify_nodes_batched(nodes, xray_bin=str(fake_xray), batch_size=2)
    )
    assert fallback_calls == ["10.0.0.1", "10.0.0.2"]
    assert all(status == "verified" and lat == 88.0 for _, status, lat in results)
