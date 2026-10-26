import pytest

import collector as c
import e2e


def _vless(extra: str) -> dict:
    link = (
        "vless://11111111-1111-1111-1111-111111111111@example.com:443"
        f"?encryption=none&security=reality&pbk=public-key&sni=example.com&{extra}#node"
    )
    node = c.parse_vpn_link(link)
    assert node is not None
    return node


def test_xray_reality_tcp_config():
    node = _vless("type=tcp&flow=xtls-rprx-vision&fp=chrome&sid=abcd")
    config = e2e.build_xray_config(node, 1080)
    assert config is not None
    stream = config["outbounds"][0]["streamSettings"]
    assert stream["network"] == "tcp"
    assert stream["security"] == "reality"
    assert stream["realitySettings"]["publicKey"] == "public-key"
    assert config["outbounds"][0]["settings"]["vnext"][0]["users"][0]["flow"] == "xtls-rprx-vision"


def test_xray_xhttp_config():
    node = _vless("type=xhttp&path=%2Fapi&host=cdn.example.com&mode=packet-up")
    config = e2e.build_xray_config(node, 1080)
    assert config is not None
    settings = config["outbounds"][0]["streamSettings"]["xhttpSettings"]
    assert settings["path"] == "/api"
    assert settings["host"] == "cdn.example.com"
    assert settings["mode"] == "packet-up"


def test_xray_trojan_ws_config():
    node = c.parse_vpn_link(
        "trojan://secret@example.com:8443?security=tls&type=ws&path=%2Fws"
        "&host=cdn.example.com&sni=example.com#node"
    )
    assert node is not None
    config = e2e.build_xray_config(node, 1080)
    assert config is not None
    outbound = config["outbounds"][0]
    assert outbound["protocol"] == "trojan"
    assert outbound["streamSettings"]["wsSettings"]["path"] == "/ws"
    assert outbound["streamSettings"]["tlsSettings"]["allowInsecure"] is True


def test_singbox_hysteria2_config():
    node = c.parse_vpn_link(
        "hysteria2://pass@example.com:443?sni=example.com&obfs=salamander"
        "&obfs-password=obfs-pass#node"
    )
    assert node is not None
    config = e2e.build_singbox_config(node, 1080)
    assert config is not None
    outbound = config["outbounds"][0]
    assert outbound["type"] == "hysteria2"
    assert outbound["tls"]["server_name"] == "example.com"
    assert outbound["obfs"] == {"type": "salamander", "password": "obfs-pass"}


def test_unsupported_transport_returns_none():
    node = _vless("type=quic")
    assert e2e.build_xray_config(node, 1080) is None


def test_builders_are_protocol_specific():
    hy2 = c.parse_vpn_link("hysteria2://pass@example.com:443?sni=example.com")
    vless = _vless("type=tcp")
    assert e2e.build_xray_config(hy2, 1080) is None
    assert e2e.build_singbox_config(vless, 1080) is None


def test_ensure_binaries_rejects_missing(tmp_path):
    with pytest.raises(e2e.E2ERuntimeError):
        e2e.ensure_binaries(str(tmp_path / "missing-xray"), str(tmp_path / "missing-singbox"))
