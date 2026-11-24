import asyncio
from datetime import datetime, timezone

from vpn_aggregator import batch_e2e, e2e, exporter, hy2_e2e, parser, quality

UUID = "11111111-1111-1111-1111-111111111111"


def test_poisoned_sni_and_tspu_scoring():
    poisoned = parser.parse_vpn_link(
        f"vless://{UUID}@1.2.3.4:443?security=reality&pbk=abc&sni=www.instagram.com&type=tcp#bad"
    )
    whitelist = parser.parse_vpn_link(
        f"vless://{UUID}@1.2.3.4:443?security=reality&pbk=abc&sni=ads.x5.ru&type=xhttp&flow=xtls-rprx-vision#good"
    )
    plain_tls = parser.parse_vpn_link(
        f"vless://{UUID}@1.2.3.4:443?security=tls&sni=cdn.example.org&type=ws#mid"
    )
    assert poisoned and whitelist and plain_tls
    assert quality.is_poisoned_sni(poisoned) is True
    assert quality.tspu_score(poisoned) == 0
    assert quality.is_poisoned_sni(whitelist) is False
    assert quality.tspu_score(whitelist) >= 25
    assert quality.tspu_score(whitelist) > quality.tspu_score(plain_tls)


def test_ru_entry_proxy_chaining_in_single_and_batch_xray():
    node = parser.parse_vpn_link(
        f"vless://{UUID}@78.159.250.107:443?security=reality&pbk=abc&sni=ya.ru&type=tcp#ru"
    )
    assert node is not None

    single = e2e.build_xray_config(
        node, 10808, ru_entry_proxy="socks5://alice:s3cr3t@198.51.100.10:1080"
    )
    assert single is not None
    assert len(single["outbounds"]) == 2
    assert single["outbounds"][0]["streamSettings"]["sockopt"] == {"dialerProxy": "ru-entry"}
    assert single["outbounds"][1]["tag"] == "ru-entry"
    assert single["outbounds"][1]["protocol"] == "socks"
    assert single["outbounds"][1]["settings"]["servers"][0]["users"][0]["user"] == "alice"

    base_cfg = e2e.build_xray_config(node, 10809, ru_entry_proxy="")
    assert base_cfg is not None
    batched = batch_e2e.build_batch_xray_config(
        [(0, base_cfg, 20001)], ru_entry_proxy="http://198.51.100.10:8080"
    )
    assert batched["outbounds"][0]["streamSettings"]["sockopt"] == {"dialerProxy": "ru-entry"}
    assert batched["outbounds"][-1]["tag"] == "ru-entry"
    assert batched["outbounds"][-1]["protocol"] == "http"

    assert quality.build_upstream_proxy_outbound("ftp://bad:21") is None


def test_probe_proxy_quality_rejects_ru_exit_and_slow_nodes():
    class _FakeContent:
        def __init__(self, data: bytes):
            self._data = data

        async def iter_chunked(self, size: int):
            yield self._data

    class _FakeResp:
        def __init__(self, status: int, body: str = "", raw: bytes = b""):
            self.status = status
            self._body = body
            self.content = _FakeContent(raw if raw else body.encode("utf-8"))

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

    class _FakeSession:
        def __init__(self, loc: str, speed_bytes: bytes = b"x" * 65536):
            self.loc = loc
            self.speed_bytes = speed_bytes

        def get(self, url, proxy=None, headers=None, timeout=None, allow_redirects=False):
            if "cdn-cgi/trace" in url:
                assert url.startswith("https://")
                return _FakeResp(200, body=f"ip=203.0.113.5\nloc={self.loc}\n")
            if "speed.cloudflare.com" in url:
                return _FakeResp(200, raw=self.speed_bytes)
            return _FakeResp(204)

    sem = asyncio.Semaphore(4)
    st_ru, lat_ru, meta_ru = asyncio.run(
        quality.probe_proxy_quality(
            _FakeSession("RU"), "http://127.0.0.1:9999", 5.0, sem, reject_ru_exit=True, speedtest_bytes=0
        )
    )
    assert st_ru == "failed" and lat_ru is None
    assert meta_ru["fail_reason"] == "ru_exit"

    st_nl, lat_nl, meta_nl = asyncio.run(
        quality.probe_proxy_quality(
            _FakeSession("NL", b"x" * 131072),
            "http://127.0.0.1:9999",
            5.0,
            sem,
            reject_ru_exit=True,
            speedtest_bytes=131072,
            min_speed_kbps=10.0,
        )
    )
    assert st_nl == "verified" and lat_nl is not None
    assert meta_nl["exit_country"] == "NL"
    assert meta_nl["speed_kbps"] > 10.0

    st_slow, _, meta_slow = asyncio.run(
        quality.probe_proxy_quality(
            _FakeSession("DE", b"x" * 32768),
            "http://127.0.0.1:9999",
            5.0,
            sem,
            reject_ru_exit=True,
            speedtest_bytes=32768,
            min_speed_kbps=999_999_999.0,
        )
    )
    assert st_slow == "failed"
    assert meta_slow["fail_reason"] == "slow"

    class _BombSession:
        def get(self, url, proxy=None, headers=None, timeout=None, allow_redirects=False):
            return _FakeResp(200, raw=b"A" * 16384)

    st_bomb, _, meta_bomb = asyncio.run(
        quality.probe_proxy_quality(_BombSession(), "http://127.0.0.1:9999", 5.0, sem, speedtest_bytes=0)
    )
    assert st_bomb == "failed"
    assert meta_bomb["fail_reason"] == "oversized_trace"

    bad_sid = parser.parse_vpn_link(
        f"vless://{UUID}@1.2.3.4:443?security=reality&pbk=abc&sni=ya.ru&sid=not_hex#bad"
    )
    assert bad_sid is not None
    assert e2e.build_xray_config(bad_sid, 10808) is None


def test_hy2_client_config_supports_salamander_mport_and_ipv6():
    node = parser.parse_vpn_link(
        "hysteria2://secret@[2001:db8::1]:443"
        "?sni=hy2.example.com&obfs=salamander&obfs-password=sally&mport=20000:30000#hy2"
    )
    assert node is not None
    node["tls_cert_sha256"] = "a" * 64
    cfg = hy2_e2e.build_hy2_client_config(node, 18080)
    assert cfg is not None
    assert cfg["server"] == "[2001:db8::1]:443,20000-30000"
    assert cfg["auth"] == "secret"
    assert cfg["tls"] == {"sni": "hy2.example.com", "insecure": True, "pinSHA256": "a" * 64}
    assert cfg["obfs"] == {"type": "salamander", "salamander": {"password": "sally"}}
    assert cfg["http"] == {"listen": "127.0.0.1:18080"}

    xray_fallback = e2e.build_xray_config(node, 18081, ru_entry_proxy="")
    assert xray_fallback is not None
    assert xray_fallback["outbounds"][0]["streamSettings"]["udpmasks"] == [
        {"type": "salamander", "settings": {"password": "sally"}}
    ]


def test_e2e_dispatches_hy2_to_native_binary_and_preserves_order(monkeypatch, tmp_path):
    fake_xray = tmp_path / "xray"
    fake_hy2 = tmp_path / "hysteria"
    fake_xray.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_hy2.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_xray.chmod(0o755)
    fake_hy2.chmod(0o755)

    vless_node = parser.parse_vpn_link(
        f"vless://{UUID}@1.1.1.1:443?security=reality&pbk=abc&sni=ya.ru&type=tcp#v"
    )
    hy2_node = parser.parse_vpn_link("hysteria2://pw@2.2.2.2:443?sni=ya.ru#h")
    assert vless_node and hy2_node
    hy2_node["tls_cert_sha256"] = "b" * 64

    async def fake_batch(nodes, xray_bin="xray", concurrency=16, timeout=8.0):
        for n in nodes:
            n["e2e"], n["e2e_ms"], n["exit_country"] = "verified", 80.0, "FI"
        return [(n, "verified", 80.0) for n in nodes]

    async def fake_hy2_verify(nodes, hy2_bin="hysteria", concurrency=8, timeout=8.0):
        for n in nodes:
            n["e2e"], n["e2e_ms"], n["exit_country"], n["speed_kbps"] = "verified", 45.0, "NL", 12000.0
        return [(n, "verified", 45.0) for n in nodes]

    monkeypatch.setattr(batch_e2e, "verify_nodes_batched", fake_batch)
    monkeypatch.setattr(hy2_e2e, "verify_hy2_nodes", fake_hy2_verify)

    res = asyncio.run(
        e2e.verify_nodes(
            [hy2_node, vless_node],
            xray_bin=str(fake_xray),
            hy2_bin=str(fake_hy2),
            concurrency=8,
            timeout=5.0,
        )
    )
    assert [item[0]["scheme"] for item in res] == ["hysteria2", "vless"]
    assert hy2_node["exit_country"] == "NL"
    assert vless_node["exit_country"] == "FI"


def test_ranking_prefers_fast_resilient_foreign_exit_nodes():
    now = datetime(2026, 11, 24, tzinfo=timezone.utc)
    fast = parser.parse_vpn_link(
        f"vless://{UUID}@1.1.1.1:443?security=reality&pbk=abc&sni=ads.x5.ru&type=xhttp#fast"
    )
    choked = parser.parse_vpn_link(
        f"vless://{UUID}@2.2.2.2:443?security=tls&sni=example.org&type=tcp#choked"
    )
    assert fast and choked
    fast.update({"e2e": "verified", "e2e_ms": 120.0, "speed_kbps": 15000.0, "exit_country": "NL"})
    choked.update({"e2e": "verified", "e2e_ms": 110.0, "speed_kbps": 350.0, "exit_country": "NL"})

    state, _, _ = exporter.update_node_history({"nodes": {}}, [fast, choked], [fast, choked], now)
    assert exporter.rank_node_key(fast) < exporter.rank_node_key(choked)
    summary = exporter.speed_summary([fast, choked])
    assert summary["min"] == 350.0 and summary["max"] == 15000.0
