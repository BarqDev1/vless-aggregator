"""URI parsing, semantic deduplication, link extraction, and canonical formatting."""

from __future__ import annotations

import base64
import binascii
import html
import ipaddress
import os
import re
import urllib.parse
from typing import Dict, List, Optional, Tuple

MAX_REMARK_LEN = int(os.getenv("MAX_REMARK_LEN", "120"))

FLAG_REGEX = re.compile(r"[\U0001F1E6-\U0001F1FF]{2}")
COUNTRY_CODE_REGEX = re.compile(r"(?:^|[\s\[(_\-|])([A-Z]{2})(?:[\s\])_\-|.,;:]|$)")
SCHEME_ALIASES = {"hy2": "hysteria2"}
SUPPORTED_SCHEMES = ("vless", "trojan", "hysteria2")
SUPPORTED_PREFIXES = tuple(f"{s}://" for s in ("vless", "trojan", "hysteria2", "hy2"))
EXCLUDED_PREFIXES = ("vmess://", "ss://", "ssr://", "tuic://")

LINK_REGEX = re.compile(r"(?<![A-Za-z0-9])(?:vless|trojan|hysteria2|hy2)://[^\s\"'<>\\]+", re.IGNORECASE)
UUID_REGEX = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
INVISIBLE_REGEX = re.compile(r"[\x00-\x1f\x7f\u200b-\u200f\u202a-\u202e\ufeff]")
HOST_LABEL_REGEX = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?$")

COUNTRY_CODES = {
    "AE", "AM", "AR", "AT", "AU", "BE", "BG", "BR", "BY", "CA", "CH", "CY",
    "CZ", "DE", "DK", "EE", "ES", "FI", "FR", "GB", "GE", "GR", "HK", "HR",
    "HU", "ID", "IE", "IL", "IN", "IS", "IT", "JP", "KR", "KZ", "LT", "LU",
    "LV", "MD", "ME", "MT", "MX", "MY", "NL", "NO", "NZ", "PH", "PL", "PT",
    "RO", "RS", "RU", "SE", "SG", "SI", "SK", "TH", "TR", "TW", "UA", "US",
    "VN", "ZA",
}

_IGNORED_DEDUP_PARAMS = {"fp", "packetencoding", "insecure", "allowinsecure"}
_TYPE_ALIASES = {"": "tcp", "raw": "tcp", "h2": "http", "splithttp": "xhttp"}


def code_to_flag(code: str) -> str:
    """Converts a two-letter ISO country code (e.g. 'RU') to a flag emoji."""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code.upper())


def sanitize_remark(remark: str, max_len: int = MAX_REMARK_LEN) -> str:
    """Removes control/zero-width characters and normalizes whitespace."""
    remark = INVISIBLE_REGEX.sub(" ", remark)
    remark = re.sub(r"\s+", " ", remark).strip()
    return remark[:max_len].strip()


def _valid_host(host: str) -> bool:
    if not host or len(host) > 253:
        return False
    if any(ch.isspace() or ord(ch) < 33 for ch in host):
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    labels = host.rstrip(".").split(".")
    return all(HOST_LABEL_REGEX.fullmatch(label) for label in labels)


def _split_userinfo(rest: str) -> List[Tuple[str, str]]:
    """Returns candidate (userinfo, host_query) splits."""
    candidates: List[Tuple[str, str]] = []
    first = rest.partition("@")
    if first[1]:
        candidates.append((first[0], first[2]))
    last = rest.rpartition("@")
    if last[1] and (not candidates or last[0] != candidates[0][0]):
        candidates.append((last[0], last[2]))
    if not candidates:
        return [("", rest)]
    return candidates


def _parse_host_port(host_port: str) -> Optional[Tuple[str, int]]:
    """Returns (host, port) or None. Port 0 means 'use the protocol default'."""
    host_port = host_port.rstrip("/")
    if not host_port:
        return None

    if host_port.startswith("["):
        end = host_port.find("]")
        if end < 0:
            return None
        host = host_port[1:end]
        remainder = host_port[end + 1 :]
        if remainder.startswith(":"):
            port_str = remainder[1:]
        elif remainder:
            return None
        else:
            port_str = ""
    else:
        if host_port.count(":") > 1:
            return None
        host, sep, port_str = host_port.partition(":")
        if not sep:
            port_str = ""

    if port_str:
        if not port_str.isdigit():
            return None
        port = int(port_str)
        if not 0 < port < 65536:
            return None
        return host, port
    return host, 0


def _detect_flag(remark: str) -> Optional[str]:
    flag_match = FLAG_REGEX.search(remark)
    if flag_match:
        return flag_match.group(0)
    code_match = COUNTRY_CODE_REGEX.search(remark)
    if code_match and code_match.group(1) in COUNTRY_CODES:
        return code_to_flag(code_match.group(1))
    return None


def _dedup_key(
    scheme: str,
    host: str,
    port: int,
    credential: str,
    sni: str,
    qs: Dict[str, List[str]],
) -> str:
    """Semantic identity of a config, ignoring cosmetic fingerprint/default params."""
    norm_cred = credential.lower() if scheme == "vless" else credential
    raw_type = ""
    for key, values in qs.items():
        if key.lower() == "type" and values:
            raw_type = values[0].strip().lower()
            break
    canon_type = _TYPE_ALIASES.get(raw_type, raw_type)

    normalized_pairs: List[Tuple[str, str]] = []
    if scheme in ("vless", "trojan"):
        normalized_pairs.append(("type", canon_type))

    for key, values in qs.items():
        lk = key.lower()
        if lk in _IGNORED_DEDUP_PARAMS or lk == "type":
            continue
        for value in values:
            if value == "":
                continue
            lv = value.lower()
            if lk == "encryption" and lv == "none":
                continue
            if lk == "spx" and value == "/":
                continue
            if lk == "headertype" and lv == "none":
                continue
            if lk == "mode" and (
                (canon_type == "grpc" and lv == "gun")
                or (canon_type != "grpc" and lv == "auto")
            ):
                continue
            normalized_pairs.append((lk, value))

    query = urllib.parse.urlencode(sorted(normalized_pairs))
    return "|".join(
        [
            scheme,
            host.lower(),
            str(port),
            norm_cred,
            (sni or "").lower(),
            query,
        ]
    )


def parse_vpn_link(link: str, max_remark_len: int = MAX_REMARK_LEN) -> Optional[dict]:
    """Parses and validates a supported VPN URI into structured fields."""
    link = link.strip()
    if not link or len(link) > 8192:
        return None

    scheme, sep, rest = link.partition("://")
    scheme = scheme.lower()
    if not sep or scheme not in ("vless", "trojan", "hysteria2", "hy2"):
        return None

    canonical = SCHEME_ALIASES.get(scheme, scheme)
    url_part, _, raw_remark = rest.partition("#")
    remark = sanitize_remark(urllib.parse.unquote(raw_remark), max_remark_len)

    parsed: Optional[Tuple[str, str, Tuple[str, int]]] = None
    for raw_userinfo, host_query in _split_userinfo(url_part):
        candidate_userinfo = urllib.parse.unquote(raw_userinfo).strip()
        candidate_host_port, _, candidate_query = host_query.partition("?")
        candidate_host = _parse_host_port(candidate_host_port)
        if candidate_host and _valid_host(candidate_host[0]):
            parsed = (candidate_userinfo, candidate_query, candidate_host)
            break
    if not parsed:
        return None

    userinfo, raw_query, parsed_host = parsed
    host, port = parsed_host

    default_port = 8443 if canonical == "hysteria2" else 443
    port = port or default_port
    if not 0 < port < 65536:
        return None

    qs = urllib.parse.parse_qs(raw_query, keep_blank_values=True)
    sni = (qs.get("sni") or qs.get("host") or [""])[0].strip()
    security = (qs.get("security") or [""])[0].lower()
    if canonical == "hysteria2":
        pinned = (qs.get("pinSHA256") or qs.get("pinsha256") or [""])[0].strip()
    else:
        pinned = (qs.get("pcs") or [""])[0].strip() if security == "tls" else ""

    if canonical == "vless":
        if not UUID_REGEX.match(userinfo):
            return None
        if security not in ("tls", "reality"):
            return None
        if security == "reality" and not (qs.get("pbk") or [""])[0]:
            return None
    elif canonical == "trojan":
        if not userinfo:
            return None

    flag = _detect_flag(remark)
    if not flag:
        flag = "🌐"
    elif flag not in remark:
        remark = sanitize_remark(f"{flag} {remark}", max_remark_len)

    key = _dedup_key(canonical, host, port, userinfo, sni, qs)
    return {
        "scheme": canonical,
        "link": link,
        "host": host,
        "port": port,
        "sni": sni,
        "security": security,
        "flag": flag,
        "remark": remark or "🌐",
        "transport": "udp" if canonical == "hysteria2" else "tcp",
        "credential": userinfo,
        "query": qs,
        "tls_mode": "pinned" if pinned else None,
        "tls_cert_sha256": pinned or None,
        "dedup_key": key,
    }


def _decode_base64(text: str) -> Optional[str]:
    compact = re.sub(r"\s+", "", text)
    if not compact or len(compact) < 16:
        return None
    padded = compact + "=" * (-len(compact) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = decoder(padded)
            decoded = raw.decode("utf-8", errors="ignore")
        except (binascii.Error, ValueError):
            continue
        if "://" in decoded:
            return decoded
    return None


def extract_links(body: str) -> List[str]:
    """Extracts supported links from raw text or a base64 subscription body."""
    body = body.strip()
    if not body:
        return []

    links = LINK_REGEX.findall(body)
    if not links:
        decoded = _decode_base64(body)
        if decoded:
            links = LINK_REGEX.findall(decoded)

    cleaned: List[str] = []
    seen = set()
    for link in links:
        link = html.unescape(link).strip().rstrip(",;")
        if link in seen:
            continue
        seen.add(link)
        cleaned.append(link)
    return cleaned


def format_link(node: dict) -> str:
    """Rebuilds the link, removing deprecated TLS flags and adding `pcs`/`pinSHA256`."""
    base_link = node["link"].partition("#")[0]
    _, _, rest = base_link.partition("://")
    location, separator, query = rest.partition("?")
    pairs = urllib.parse.parse_qsl(query, keep_blank_values=True) if separator else []

    if node["scheme"] in ("vless", "trojan"):
        pairs = [
            (key, value)
            for key, value in pairs
            if key.lower() not in ("insecure", "allowinsecure", "pcs")
        ]
        if node.get("security") == "tls" and node.get("tls_cert_sha256"):
            pairs.append(("pcs", node["tls_cert_sha256"]))
    else:
        pairs = [
            (key, value)
            for key, value in pairs
            if key.lower() not in ("insecure", "allowinsecure", "pinsha256", "pcs")
        ]
        if node.get("tls_cert_sha256"):
            pairs.append(("pinSHA256", node["tls_cert_sha256"]))

    rebuilt = f"{node['scheme']}://{location}"
    if pairs:
        rebuilt += "?" + urllib.parse.urlencode(pairs)
    return f"{rebuilt}#{urllib.parse.quote(node['remark'], safe='')}"
