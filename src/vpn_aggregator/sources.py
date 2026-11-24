"""Subscription source fetching, Git shallow-clone extraction, caching, and quarantine."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

import aiohttp

from .parser import LINK_REGEX, extract_links

logger = logging.getLogger("aggregator")


def parse_datetime(value: object) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _clean_git_url(repo_url: str) -> str:
    url = repo_url[4:] if repo_url.startswith("git+") else repo_url
    url = url.strip()
    if not url.startswith(("https://", "http://")):
        raise ValueError(f"unsupported git URL: {repo_url}")
    if not url.endswith(".git") and ("gitlab.com" in url or "github.com" in url):
        url = url.rstrip("/") + ".git"
    return url


def clone_git_repo(
    repo_url: str,
    *,
    max_git_files: int = 2000,
    max_git_file_bytes: int = 2 * 1024 * 1024,
) -> List[str]:
    """Clones a Git repository and recursively extracts links from text files."""
    try:
        clean_url = _clean_git_url(repo_url)
    except ValueError as exc:
        logger.warning(str(exc))
        return []

    configs: List[str] = []
    files_read = 0
    with tempfile.TemporaryDirectory() as tmpdir:
        res = subprocess.run(
            ["git", "clone", "--depth", "1", "--single-branch", "--no-tags", "--quiet", clean_url, tmpdir],
            capture_output=True,
            text=True,
            timeout=90,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
        if res.returncode != 0:
            logger.warning(f"Failed to clone {clean_url}: {res.stderr.strip()[:160]}")
            return []

        for root, dirs, files in os.walk(tmpdir):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d != "__pycache__"]
            for fname in sorted(files):
                if not fname.lower().endswith((".txt", ".md", ".yaml", ".yml")):
                    continue
                if files_read >= max_git_files:
                    logger.warning(f"Git source {clean_url}: file limit reached ({max_git_files})")
                    break
                fpath = os.path.join(root, fname)
                try:
                    if os.path.getsize(fpath) > max_git_file_bytes:
                        continue
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        text = f.read(max_git_file_bytes)
                except OSError:
                    continue
                files_read += 1
                configs.extend(extract_links(text))
            if files_read >= max_git_files:
                break

    logger.info(f" -> Found {len(configs)} configs from Git repo: {clean_url}")
    return configs


def _looks_like_html(body: str) -> bool:
    head = body[:1024].lower()
    return "<html" in head or "<!doctype html" in head


def _header_value(headers: Dict[str, str], name: str) -> Optional[str]:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


async def fetch_once(
    session: aiohttp.ClientSession,
    url: str,
    cache_entry: Optional[dict] = None,
    *,
    fetch_timeout: float = 20.0,
    max_source_bytes: int = 5 * 1024 * 1024,
) -> Tuple[bool, str, int, Dict[str, str]]:
    headers: Dict[str, str] = {}
    if cache_entry:
        etag = _header_value(cache_entry, "etag")
        last_modified = _header_value(cache_entry, "last_modified")
        if etag:
            headers["If-None-Match"] = etag
        if last_modified:
            headers["If-Modified-Since"] = last_modified

    try:
        async with session.get(
            url,
            headers=headers or None,
            timeout=aiohttp.ClientTimeout(total=fetch_timeout),
        ) as resp:
            if resp.status == 304:
                return False, "", 304, dict(resp.headers)
            if resp.status != 200:
                retryable = resp.status == 429 or resp.status >= 500
                logger.warning(f"Failed to fetch {url}: HTTP {resp.status}")
                return retryable, "", resp.status, {}
            chunks: List[bytes] = []
            total = 0
            truncated = False
            async for chunk in resp.content.iter_chunked(65536):
                remaining = max_source_bytes - total
                if len(chunk) > remaining:
                    chunks.append(chunk[:remaining])
                    truncated = True
                    break
                chunks.append(chunk)
                total += len(chunk)
            if truncated:
                logger.warning(f"Source {url} exceeds {max_source_bytes} bytes; truncating")
            raw = b"".join(chunks)
            return True, raw.decode(resp.charset or "utf-8", errors="ignore"), 200, dict(resp.headers)
    except Exception as exc:
        logger.warning(f"Error fetching {url}: {type(exc).__name__}: {exc}")
        return True, "", 0, {}


async def fetch_source(
    session: aiohttp.ClientSession,
    url: str,
    cache_entry: Optional[dict] = None,
    *,
    fetch_attempts: int = 3,
    fetch_timeout: float = 20.0,
    max_source_bytes: int = 5 * 1024 * 1024,
    max_git_files: int = 2000,
    max_git_file_bytes: int = 2 * 1024 * 1024,
    fetch_once_fn=None,
    clone_git_fn=None,
) -> Tuple[List[str], Optional[dict]]:
    """Fetches a URL with retries, conditional caching and link extraction."""
    url = url.strip()
    if not url or url.startswith("#"):
        return [], None

    if url.startswith("git+") or (url.endswith(".git") and ("gitlab.com" in url or "github.com" in url)):
        logger.info(f"Cloning Git source: {url}")
        if clone_git_fn is not None:
            return await asyncio.to_thread(clone_git_fn, url), None
        return await asyncio.to_thread(
            clone_git_repo,
            url,
            max_git_files=max_git_files,
            max_git_file_bytes=max_git_file_bytes,
        ), None

    logger.info(f"Downloading source: {url}")
    cached_links = cache_entry.get("links", []) if cache_entry else []
    body = ""
    response_headers: Dict[str, str] = {}
    status = 0

    for attempt in range(1, fetch_attempts + 1):
        if fetch_once_fn is not None:
            retryable, body, status, response_headers = await fetch_once_fn(
                session, url, cache_entry if attempt == 1 else None
            )
        else:
            retryable, body, status, response_headers = await fetch_once(
                session,
                url,
                cache_entry if attempt == 1 else None,
                fetch_timeout=fetch_timeout,
                max_source_bytes=max_source_bytes,
            )
        if status == 304 and cached_links:
            logger.info(f" -> Not modified, using cached links ({len(cached_links)})")
            updated = dict(cache_entry or {})
            updated["fetched_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            return list(cached_links), updated
        if status == 304:
            continue
        if body:
            break
        if not retryable or attempt == fetch_attempts:
            break
        await asyncio.sleep(min(2 ** attempt, 8))

    if not body:
        if cached_links:
            logger.warning(f"Fetch failed for {url}; using {len(cached_links)} cached links")
            return list(cached_links), cache_entry
        return [], None

    if _looks_like_html(body) and not LINK_REGEX.search(body):
        logger.warning(f"Skipping HTML page from {url}")
        return [], None

    configs = extract_links(body)
    entry = {
        "etag": _header_value(response_headers, "ETag"),
        "last_modified": _header_value(response_headers, "Last-Modified"),
        "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "links": configs,
    }
    logger.info(f" -> Found {len(configs)} configs from {url}")
    return configs, entry


def load_sources(path: str) -> List[str]:
    if not os.path.exists(path):
        logger.error(f"Sources file '{path}' not found!")
        return []
    with open(path, "r", encoding="utf-8") as f:
        urls = [
            line.strip()
            for line in f
            if line.strip() and not line.strip().startswith("#")
        ]
    return list(dict.fromkeys(urls))


def load_source_health(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        if isinstance(data, dict) and isinstance(data.get("sources"), dict):
            return data
    except (FileNotFoundError, ValueError, OSError):
        pass
    return {"updated_at": None, "sources": {}}


def load_source_cache(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        if isinstance(data, dict) and isinstance(data.get("sources"), dict):
            return data
    except (FileNotFoundError, ValueError, OSError):
        pass
    return {"updated_at": None, "sources": {}}


def select_active_sources(urls: List[str], health: dict, now: datetime) -> Tuple[List[str], List[str]]:
    active: List[str] = []
    skipped: List[str] = []
    for url in urls:
        entry = health.get("sources", {}).get(url, {})
        until = parse_datetime(entry.get("quarantined_until"))
        if until and until > now:
            skipped.append(url)
        else:
            active.append(url)
    return active, skipped


def update_source_health(
    health: dict,
    urls: List[str],
    source_stats: Dict[str, dict],
    now: datetime,
    *,
    failure_threshold: int = 5,
    quarantine_hours: float = 2.0,
) -> dict:
    """Updates consecutive failure counters and quarantines useless sources."""
    old_sources = health.get("sources", {})
    sources: Dict[str, dict] = {}
    for url in urls:
        old = old_sources.get(url, {})
        stat = source_stats.get(url, {})
        if stat.get("active") is False:
            sources[url] = old
            continue

        failures = int(old.get("consecutive_failures", 0))
        raw = int(stat.get("raw", 0))
        unique = int(stat.get("unique", 0))
        alive = int(stat.get("alive", 0))

        if alive > 0:
            failures = 0
            quarantined_until = None
        else:
            failures += 1
            quarantined_until = old.get("quarantined_until")
            if failures >= failure_threshold:
                quarantined_until = (now + timedelta(hours=quarantine_hours)).isoformat(
                    timespec="seconds"
                )

        sources[url] = {
            "consecutive_failures": failures,
            "last_raw": raw,
            "last_unique": unique,
            "last_alive": alive,
            "last_checked_at": now.isoformat(timespec="seconds"),
            "quarantined_until": quarantined_until,
        }

    return {"updated_at": now.isoformat(timespec="seconds"), "sources": sources}
