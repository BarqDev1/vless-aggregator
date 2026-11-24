"""Production HTTP subscription server and background update daemon.

Serves raw and Base64 subscription endpoints with native VPN client headers,
strict security headers, constant-time path key verification and bounded per-IP
rate limiting, while periodically refreshing nodes via `collector.main()`.
"""

from __future__ import annotations

import asyncio
import base64
import hmac
import json
import logging
import os
import time
from collections import deque
from contextlib import suppress
from pathlib import Path
from typing import Any, Awaitable, Callable, Deque, Dict, Optional

from aiohttp import web

from . import collector

logger = logging.getLogger("aggregator.server")

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Frame-Options": "DENY",
}


class SlidingWindowRateLimiter:
    """Bounded in-memory per-IP sliding-window rate limiter."""

    def __init__(
        self,
        limit_per_minute: int = 60,
        window_seconds: float = 60.0,
        max_ips: int = 4096,
    ) -> None:
        self.limit = max(1, limit_per_minute)
        self.window = max(1.0, window_seconds)
        self.max_ips = max(64, max_ips)
        self._hits: Dict[str, Deque[float]] = {}

    def allow(self, ip: str, now: Optional[float] = None) -> bool:
        ts = time.monotonic() if now is None else now
        cutoff = ts - self.window
        bucket = self._hits.get(ip)
        if bucket is None:
            if len(self._hits) >= self.max_ips:
                oldest_ip = next(iter(self._hits))
                self._hits.pop(oldest_ip, None)
            bucket = deque()
            self._hits[ip] = bucket
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()
        if len(bucket) >= self.limit:
            return False
        bucket.append(ts)
        return True


def _extract_client_ip(request: web.Request, trust_xff: bool) -> str:
    if trust_xff:
        forwarded = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        if forwarded:
            return forwarded
    return request.remote or "unknown"


def _read_text_file(path: str) -> Optional[str]:
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError:
        return None


def _read_json_safe(path: str) -> Any:
    raw = _read_text_file(path)
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return None


def _subscription_headers() -> Dict[str, str]:
    return {
        "cache-control": "no-store",
        "profile-title": collector.PROFILE_TITLE,
        "profile-update-interval": str(collector.PROFILE_UPDATE_INTERVAL),
        "support-url": collector.SUPPORT_URL,
        "profile-web-page-url": collector.HOME_URL,
    }


def _authorized_key(candidate: str, expected_key: str, allow_public: bool) -> bool:
    if allow_public and not expected_key:
        return candidate in ("", "public")
    if not expected_key:
        return False
    return hmac.compare_digest(candidate.encode("utf-8"), expected_key.encode("utf-8"))


def create_app(
    *,
    sub_key: Optional[str] = None,
    allow_public_subs: Optional[bool] = None,
    update_interval_minutes: Optional[float] = None,
    run_on_startup: Optional[bool] = None,
    rate_limit_per_minute: Optional[int] = None,
    trust_xff: Optional[bool] = None,
    file_paths: Optional[Dict[str, str]] = None,
    run_collector_fn: Optional[Callable[[], Awaitable[int]]] = None,
    enable_scheduler: bool = True,
) -> web.Application:
    """Creates the configured aiohttp web application."""
    resolved_key = (os.getenv("SUB_KEY", "") if sub_key is None else sub_key).strip()
    resolved_public = (
        os.getenv("ALLOW_PUBLIC_SUBS", "0").strip().lower() in {"1", "true", "yes", "on"}
        if allow_public_subs is None
        else allow_public_subs
    )
    if not resolved_public and len(resolved_key) < 16:
        raise ValueError(
            "SUB_KEY must be at least 16 characters (or set ALLOW_PUBLIC_SUBS=1 explicitly)"
        )

    interval_min = (
        max(1.0, float(os.getenv("UPDATE_INTERVAL_MINUTES", "15")))
        if update_interval_minutes is None
        else max(0.05, float(update_interval_minutes))
    )
    startup_run = (
        os.getenv("RUN_ON_STARTUP", "1").strip().lower() in {"1", "true", "yes", "on"}
        if run_on_startup is None
        else run_on_startup
    )
    rate_limit = (
        max(1, int(os.getenv("RATE_LIMIT_PER_MINUTE", "60")))
        if rate_limit_per_minute is None
        else max(1, rate_limit_per_minute)
    )
    use_xff = (
        os.getenv("TRUST_X_FORWARDED_FOR", "0").strip().lower() in {"1", "true", "yes", "on"}
        if trust_xff is None
        else trust_xff
    )
    paths = {
        "all": collector.ALL_OUTPUT,
        "vless": collector.VLESS_OUTPUT,
        "hy2": collector.HY2_OUTPUT,
        "stats": collector.STATS_OUTPUT,
        "meta": collector.META_FILE,
        "history": collector.HISTORY_FILE,
        **(file_paths or {}),
    }
    collect_fn = run_collector_fn or collector.main

    limiter = SlidingWindowRateLimiter(limit_per_minute=rate_limit)
    collect_lock = asyncio.Lock()
    state: Dict[str, Any] = {
        "last_exit_code": None,
        "last_run_finished_at": None,
        "last_manual_refresh": 0.0,
        "scheduler_task": None,
        "refresh_task": None,
    }

    async def _execute_collection() -> int:
        if collect_lock.locked():
            return -1
        async with collect_lock:
            try:
                code = int(await collect_fn())
            except Exception as exc:
                logger.exception(f"Collector run failed: {exc}")
                code = 1
            state["last_exit_code"] = code
            state["last_run_finished_at"] = time.time()
            return code

    @web.middleware
    async def security_middleware(
        request: web.Request,
        handler: Callable[[web.Request], Awaitable[web.StreamResponse]],
    ) -> web.StreamResponse:
        segments = [seg for seg in request.path.split("/") if seg]
        if any(seg.startswith(".") for seg in segments):
            resp: web.StreamResponse = web.Response(text="Not found\n", status=404)
        else:
            ip = _extract_client_ip(request, use_xff)
            if not limiter.allow(ip):
                resp = web.Response(text="Too many requests\n", status=429)
            else:
                try:
                    resp = await handler(request)
                except web.HTTPException as exc:
                    resp = exc
        for hdr, val in SECURITY_HEADERS.items():
            resp.headers.setdefault(hdr, val)
        return resp

    async def handle_health(_request: web.Request) -> web.Response:
        stats = _read_json_safe(paths["stats"])
        payload = {
            "status": "ok",
            "alive": stats.get("alive") if isinstance(stats, dict) else None,
            "updated_at": stats.get("updated_at") if isinstance(stats, dict) else None,
            "running": collect_lock.locked(),
            "last_exit_code": state["last_exit_code"],
        }
        return web.json_response(payload)

    def _require_auth(request: web.Request) -> Optional[web.Response]:
        key = request.match_info.get("key", "")
        if not _authorized_key(key, resolved_key, resolved_public):
            return web.Response(text="Not found\n", status=404)
        return None

    async def handle_subscription(request: web.Request) -> web.Response:
        denied = _require_auth(request)
        if denied is not None:
            return denied
        kind = request.match_info.get("kind", "")
        if kind not in ("all", "vless", "hy2"):
            return web.Response(text="Not found\n", status=404)
        content = _read_text_file(paths[kind])
        if content is None:
            return web.Response(text="Subscription not generated yet\n", status=503)

        want_b64 = (
            request.match_info.get("encoding") == "base64"
            or request.query.get("format", "").lower() == "base64"
            or request.query.get("base64", "") in ("1", "true", "yes")
        )
        body = (
            base64.b64encode(content.encode("utf-8")).decode("ascii")
            if want_b64
            else content
        )
        return web.Response(
            text=body,
            content_type="text/plain",
            charset="utf-8",
            headers=_subscription_headers(),
        )

    async def handle_json_resource(request: web.Request) -> web.Response:
        denied = _require_auth(request)
        if denied is not None:
            return denied
        kind = request.match_info.get("kind", "")
        if kind not in ("stats", "meta", "history"):
            return web.Response(text="Not found\n", status=404)
        raw = _read_text_file(paths[kind])
        if raw is None:
            return web.Response(text="Not found\n", status=404)
        return web.Response(
            text=raw,
            content_type="application/json",
            charset="utf-8",
            headers={"cache-control": "no-store"},
        )

    async def handle_refresh(request: web.Request) -> web.Response:
        denied = _require_auth(request)
        if denied is not None:
            return denied
        if collect_lock.locked():
            return web.json_response({"status": "already_running"}, status=202)
        now = time.monotonic()
        if now - float(state["last_manual_refresh"]) < 60.0:
            return web.json_response({"status": "cooldown"}, status=429)
        state["last_manual_refresh"] = now
        state["refresh_task"] = asyncio.create_task(_execute_collection())
        return web.json_response({"status": "scheduled"}, status=202)

    async def _scheduler_loop() -> None:
        if startup_run:
            await _execute_collection()
        while True:
            await asyncio.sleep(interval_min * 60.0)
            await _execute_collection()

    async def _on_startup(_app: web.Application) -> None:
        if enable_scheduler:
            state["scheduler_task"] = asyncio.create_task(_scheduler_loop())

    async def _on_cleanup(_app: web.Application) -> None:
        for task_key in ("scheduler_task", "refresh_task"):
            task = state.get(task_key)
            if task is not None and not task.done():
                task.cancel()
                with suppress(asyncio.CancelledError):
                    await task

    app = web.Application(middlewares=[security_middleware])
    app.on_startup.append(_on_startup)
    app.on_cleanup.append(_on_cleanup)
    app.router.add_get("/health", handle_health)
    app.router.add_get("/{key}/{kind:all|vless|hy2}", handle_subscription)
    app.router.add_get("/{key}/{kind:all|vless|hy2}/{encoding:base64}", handle_subscription)
    app.router.add_get("/{key}/{kind:stats|meta|history}", handle_json_resource)
    app.router.add_post("/{key}/refresh", handle_refresh)
    return app


def main() -> None:
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8080"))
    app = create_app()
    logger.info(f"Starting VPN Aggregator server on {host}:{port}")
    web.run_app(app, host=host, port=port, access_log=None)


if __name__ == "__main__":
    main()
