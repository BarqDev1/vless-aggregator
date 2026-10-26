import base64

import collector as c

UUID = "11111111-1111-1111-1111-111111111111"
VLESS = (
    f"vless://{UUID}@1.2.3.4:443"
    "?encryption=none&security=reality&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB"
    "&sni=example.com&type=tcp&flow=xtls-rprx-vision"
    "#%F0%9F%87%A9%F0%9F%87%AA%20Germany"
)
TROJAN = "trojan://secret@example.com:8443?security=tls&sni=example.com#NL%20node"
HY2 = "hysteria2://auth@example.com:443?sni=example.com&insecure=1#Japan"


def test_parse_vless():
    node = c.parse_vpn_link(VLESS)
    assert node is not None
    assert node["scheme"] == "vless"
    assert node["host"] == "1.2.3.4"
    assert node["port"] == 443
    assert node["sni"] == "example.com"
    assert node["flag"] == "🇩🇪"
    assert node["transport"] == "tcp"


def test_parse_trojan_default_port():
    node = c.parse_vpn_link(TROJAN)
    assert node is not None
    assert node["scheme"] == "trojan"
    assert node["port"] == 8443


def test_parse_hy2_alias_is_canonical():
    alias = c.parse_vpn_link("hy2://auth@example.com:8443?sni=example.com")
    canonical = c.parse_vpn_link("hysteria2://auth@example.com:8443?sni=example.com")
    assert alias["scheme"] == canonical["scheme"] == "hysteria2"
    assert alias["dedup_key"] == canonical["dedup_key"]
    assert alias["transport"] == "udp"


def test_parse_hy2_without_auth():
    node = c.parse_vpn_link("hysteria2://example.com:443?sni=example.com")
    assert node is not None
    assert node["host"] == "example.com"
    assert node["port"] == 443


def test_parse_ipv6():
    node = c.parse_vpn_link(f"vless://{UUID}@[2001:db8::1]:8443?security=tls&sni=example.com")
    assert node is not None
    assert node["host"] == "2001:db8::1"
    assert node["port"] == 8443


def test_password_with_at_sign():
    node = c.parse_vpn_link("trojan://p@ss@example.com:443?sni=example.com")
    assert node is not None
    assert node["credential"] == "p@ss"
    assert node["host"] == "example.com"


def test_rejects_invalid_uuid():
    assert c.parse_vpn_link("vless://not-a-uuid@1.2.3.4:443?security=tls") is None


def test_rejects_reality_without_pbk():
    link = f"vless://{UUID}@1.2.3.4:443?security=reality&sni=example.com"
    assert c.parse_vpn_link(link) is None


def test_rejects_trojan_without_password():
    assert c.parse_vpn_link("trojan://@example.com:443") is None


def test_rejects_bad_ports():
    assert c.parse_vpn_link(f"vless://{UUID}@1.2.3.4:0?security=tls") is None
    assert c.parse_vpn_link(f"vless://{UUID}@1.2.3.4:70000?security=tls") is None
    assert c.parse_vpn_link(f"vless://{UUID}@1.2.3.4:abc?security=tls") is None


def test_rejects_unsupported_and_junk():
    assert c.parse_vpn_link("vmess://eyJhZGQiOiIxLjIuMy40In0=") is None
    assert c.parse_vpn_link("ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388") is None
    assert c.parse_vpn_link("vless://") is None
    assert c.parse_vpn_link("vless://،") is None
    assert c.parse_vpn_link("vless://uuid@bad host:443") is None


def test_sanitizes_remark():
    node = c.parse_vpn_link(f"vless://{UUID}@1.2.3.4:443?security=tls#US%20%0A%20node%E2%80%8B")
    assert node is not None
    assert "\n" not in node["remark"]
    assert "\u200b" not in node["remark"]
    assert node["flag"] == "🇺🇸"
    assert node["remark"].startswith("🇺🇸")


def test_format_link_encodes_remark():
    node = c.parse_vpn_link(VLESS)
    formatted = c.format_link(node)
    assert "#" in formatted
    assert " " not in formatted
    assert formatted.split("#", 1)[1].startswith("%F0%9F%87%A9")


def test_extract_raw_links():
    body = (
        "comments\n"
        f"{VLESS}\n"
        f"{TROJAN}\n"
        "vmess://eyJhZGQiOiIxLjIuMy40In0=\n"
        f"{HY2}\n"
    )
    links = c.extract_links(body)
    assert len(links) == 3
    assert links[0].startswith("vless://")
    assert links[1].startswith("trojan://")
    assert links[2].startswith("hysteria2://")


def test_extract_base64_links():
    raw = f"{VLESS}\n{TROJAN}\n".encode()
    body = base64.b64encode(raw).decode()
    links = c.extract_links(body)
    assert len(links) == 2
    assert links[0].startswith("vless://")


def test_extract_unescapes_html_entities():
    body = f'<a href="{VLESS.replace("&", "&amp;")}">node</a>'
    links = c.extract_links(body)
    assert len(links) == 1
    node = c.parse_vpn_link(links[0])
    assert node is not None
    assert node["sni"] == "example.com"


def test_extract_deduplicates_within_source():
    links = c.extract_links(f"{VLESS}\n{VLESS}\n")
    assert len(links) == 1


def test_extract_ignores_html_error_page():
    assert c.extract_links("<html><body>404 not found</body></html>") == []


def test_dedup_keeps_distinct_configs():
    same_uuid_other_transport = VLESS.replace("type=tcp", "type=ws")
    first = c.parse_vpn_link(VLESS)
    second = c.parse_vpn_link(same_uuid_other_transport)
    assert first["dedup_key"] != second["dedup_key"]

    other_uuid = VLESS.replace(UUID, "22222222-2222-2222-2222-222222222222")
    third = c.parse_vpn_link(other_uuid)
    assert first["dedup_key"] != third["dedup_key"]


def test_clean_git_url():
    assert c._clean_git_url("git+https://gitlab.com/a/b") == "https://gitlab.com/a/b.git"
    assert c._clean_git_url("https://github.com/a/b.git") == "https://github.com/a/b.git"
    try:
        c._clean_git_url("file:///etc/passwd")
    except ValueError:
        pass
    else:
        raise AssertionError("non-http git URL must be rejected")
