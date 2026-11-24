import asyncio
import base64
import json

import aiohttp
import pytest
from aiohttp import web

from vpn_aggregator import server


def test_create_app_rejects_missing_or_short_sub_key():
    with pytest.raises(ValueError):
        server.create_app(sub_key="", allow_public_subs=False, enable_scheduler=False)
    with pytest.raises(ValueError):
        server.create_app(sub_key="too-short", allow_public_subs=False, enable_scheduler=False)


def test_rate_limiter_enforces_limit_and_evicts():
    limiter = server.SlidingWindowRateLimiter(limit_per_minute=2, window_seconds=60.0, max_ips=64)
    assert limiter.allow("1.2.3.4", now=10.0) is True
    assert limiter.allow("1.2.3.4", now=20.0) is True
    assert limiter.allow("1.2.3.4", now=30.0) is False
    assert limiter.allow("1.2.3.4", now=71.0) is True


async def _with_server(app, fn):
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]  # type: ignore[union-attr]
    base = f"http://127.0.0.1:{port}"
    try:
        async with aiohttp.ClientSession() as client:
            await fn(client, base)
    finally:
        await runner.cleanup()


def test_server_endpoints_security_and_refresh(tmp_path):
    all_file = tmp_path / "all.txt"
    vless_file = tmp_path / "vless.txt"
    hy2_file = tmp_path / "hy2.txt"
    stats_file = tmp_path / "stats.json"
    meta_file = tmp_path / "meta.json"
    history_file = tmp_path / "history.json"

    all_file.write_text("vless://abc\nhysteria2://def\n", encoding="utf-8")
    vless_file.write_text("vless://abc\n", encoding="utf-8")
    hy2_file.write_text("hysteria2://def\n", encoding="utf-8")
    stats_file.write_text(json.dumps({"alive": 2, "updated_at": "2026-11-24T00:00:00Z"}), encoding="utf-8")
    meta_file.write_text(json.dumps({"counts": {"total": 2}}), encoding="utf-8")
    history_file.write_text(json.dumps([{"alive": 2}]), encoding="utf-8")

    refresh_calls = []

    async def fake_collect():
        refresh_calls.append(1)
        return 0

    key = "a" * 24
    app = server.create_app(
        sub_key=key,
        allow_public_subs=False,
        rate_limit_per_minute=20,
        enable_scheduler=False,
        run_collector_fn=fake_collect,
        file_paths={
            "all": str(all_file),
            "vless": str(vless_file),
            "hy2": str(hy2_file),
            "stats": str(stats_file),
            "meta": str(meta_file),
            "history": str(history_file),
        },
    )

    async def run_checks(client: aiohttp.ClientSession, base: str):
        async with client.get(f"{base}/health") as resp:
            assert resp.status == 200
            data = await resp.json()
            assert data["status"] == "ok"
            assert data["alive"] == 2
            assert "Content-Security-Policy" in resp.headers
            assert resp.headers["X-Content-Type-Options"] == "nosniff"
            assert resp.headers["X-Frame-Options"] == "DENY"

        async with client.get(f"{base}/wrong-key-value-123/all") as resp:
            assert resp.status == 404

        async with client.get(f"{base}/.env") as resp:
            assert resp.status == 404
        async with client.get(f"{base}/{key}/.git") as resp:
            assert resp.status == 404

        async with client.get(f"{base}/{key}/all") as resp:
            assert resp.status == 200
            assert await resp.text() == "vless://abc\nhysteria2://def\n"
            assert "profile-title" in resp.headers
            assert "profile-update-interval" in resp.headers

        async with client.get(f"{base}/{key}/all/base64") as resp:
            assert resp.status == 200
            decoded = base64.b64decode(await resp.text()).decode("utf-8")
            assert decoded == "vless://abc\nhysteria2://def\n"

        async with client.get(f"{base}/{key}/vless?format=base64") as resp:
            assert resp.status == 200
            assert base64.b64decode(await resp.text()).decode("utf-8") == "vless://abc\n"

        async with client.get(f"{base}/{key}/stats") as resp:
            assert resp.status == 200
            assert (await resp.json())["alive"] == 2

        async with client.post(f"{base}/{key}/refresh") as resp:
            assert resp.status == 202
            assert (await resp.json())["status"] == "scheduled"
        await asyncio.sleep(0.05)
        assert len(refresh_calls) == 1

        async with client.post(f"{base}/{key}/refresh") as resp:
            assert resp.status == 429

    asyncio.run(_with_server(app, run_checks))


def test_server_rate_limits_excessive_requests(tmp_path):
    app = server.create_app(
        sub_key="a" * 24,
        rate_limit_per_minute=2,
        enable_scheduler=False,
        file_paths={"stats": str(tmp_path / "missing.json")},
    )

    async def run_checks(client: aiohttp.ClientSession, base: str):
        assert (await client.get(f"{base}/health")).status == 200
        assert (await client.get(f"{base}/health")).status == 200
        assert (await client.get(f"{base}/health")).status == 429

    asyncio.run(_with_server(app, run_checks))
