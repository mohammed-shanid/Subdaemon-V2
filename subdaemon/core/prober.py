"""
SubDaemon v2 — HTTP Prober
───────────────────────────
Probes confirmed DNS hits for HTTP/HTTPS services.
Only runs AFTER DNS resolution — no wasted HTTP calls.

Design:
  • aiohttp for true async (falls back to requests via executor)
  • HEAD-first, GET on failure
  • Captures: status, title, server header, redirect chain, TLS info
  • Virtual host fuzzing support
"""

from __future__ import annotations

import asyncio
import logging
import random
import re
import ssl
import time
from dataclasses import dataclass, field
from typing import Optional

from subdaemon.config.defaults import (
    HTTP_MAX_REDIRECTS,
    HTTP_TIMEOUT,
    USER_AGENTS,
    VALID_STATUS_CODES,
)

logger = logging.getLogger("subdaemon.prober")


# ─── Data Structures ──────────────────────────────────────────────────────────

@dataclass
class ProbeResult:
    hostname:       str
    url:            str
    status:         Optional[int]       = None
    title:          Optional[str]       = None
    server:         Optional[str]       = None
    content_length: Optional[int]       = None
    redirect_to:    Optional[str]       = None
    technologies:   list[str]           = field(default_factory=list)
    tls_subject:    Optional[str]       = None
    response_time:  float               = 0.0
    error:          Optional[str]       = None

    @property
    def alive(self) -> bool:
        return self.status is not None and self.status in VALID_STATUS_CODES

    @property
    def protocol(self) -> str:
        return "https" if self.url.startswith("https") else "http"

    def __str__(self) -> str:
        parts = [f"[{self.status}]", self.url]
        if self.title:
            parts.append(f'"{self.title}"')
        if self.server:
            parts.append(f"({self.server})")
        if self.response_time:
            parts.append(f"{self.response_time:.2f}s")
        return " ".join(parts)


# ─── Tech Fingerprinting ──────────────────────────────────────────────────────

_TECH_SIGNATURES = {
    "nginx":      [("server", r"nginx")],
    "apache":     [("server", r"apache")],
    "cloudflare": [("server", r"cloudflare"), ("cf-ray", r".")],
    "iis":        [("server", r"Microsoft-IIS")],
    "fastly":     [("x-served-by", r"cache-"), ("x-cache", r"HIT")],
    "wordpress":  [("x-powered-by", r"PHP"), ("link", r"wp-json")],
    "django":     [("x-frame-options", r"SAMEORIGIN"), ("x-content-type-options", r".")],
    "express":    [("x-powered-by", r"Express")],
}

def _fingerprint(headers: dict) -> list[str]:
    found = []
    lowered = {k.lower(): v for k, v in headers.items()}
    for tech, sigs in _TECH_SIGNATURES.items():
        for header_name, pattern in sigs:
            val = lowered.get(header_name, "")
            if val and re.search(pattern, val, re.IGNORECASE):
                found.append(tech)
                break
    return found


def _extract_title(html: str) -> Optional[str]:
    match = re.search(r"<title[^>]*>([^<]{1,200})</title>", html, re.IGNORECASE | re.DOTALL)
    if match:
        return " ".join(match.group(1).split())[:120]
    return None


def _random_ua() -> str:
    return random.choice(USER_AGENTS)


# ─── Backend: aiohttp ─────────────────────────────────────────────────────────

class _AiohttpProber:
    """True async HTTP probing — best performance."""

    def __init__(self, verify_ssl: bool, timeout: int):
        import aiohttp
        self._aiohttp   = aiohttp
        self._verify    = verify_ssl
        self._timeout   = aiohttp.ClientTimeout(total=timeout)
        self._connector = None

    def _get_connector(self):
        if self._connector is None or self._connector.closed:
            ssl_ctx = ssl.create_default_context() if self._verify else False
            self._connector = self._aiohttp.TCPConnector(
                ssl=ssl_ctx,
                limit=200,
                limit_per_host=5,
                enable_cleanup_closed=True,
            )
        return self._connector

    async def probe(self, url: str) -> tuple[Optional[int], dict, str]:
        headers = {"User-Agent": _random_ua(), "Accept": "text/html,*/*;q=0.8"}
        body = ""
        resp_headers = {}

        async with self._aiohttp.ClientSession(
            connector=self._get_connector(),
            connector_owner=False,
            timeout=self._timeout,
        ) as session:
            # Try HEAD first
            try:
                async with session.head(
                    url,
                    headers=headers,
                    allow_redirects=True,
                    max_redirects=HTTP_MAX_REDIRECTS,
                ) as resp:
                    if resp.status in VALID_STATUS_CODES:
                        return resp.status, dict(resp.headers), ""
            except Exception:
                pass

            # Fallback to GET
            try:
                async with session.get(
                    url,
                    headers=headers,
                    allow_redirects=True,
                    max_redirects=HTTP_MAX_REDIRECTS,
                ) as resp:
                    try:
                        body = await resp.text(errors="replace", limit=1024 * 64)
                    except Exception:
                        body = ""
                    return resp.status, dict(resp.headers), body
            except Exception as e:
                raise

    async def close(self):
        if self._connector and not self._connector.closed:
            await self._connector.close()


# ─── Backend: requests (sync via executor) ────────────────────────────────────

class _RequestsProber:
    """Sync requests wrapped in executor — always available."""

    def __init__(self, verify_ssl: bool, timeout: int):
        import requests
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry

        self._session = requests.Session()
        retry = Retry(total=1, backoff_factor=0.2, status_forcelist=[429, 503])
        adapter = HTTPAdapter(max_retries=retry, pool_connections=50, pool_maxsize=100)
        self._session.mount("http://", adapter)
        self._session.mount("https://", adapter)
        self._verify   = verify_ssl
        self._timeout  = timeout

    def _probe_sync(self, url: str) -> tuple[Optional[int], dict, str]:
        headers = {"User-Agent": _random_ua(), "Accept": "text/html,*/*;q=0.8"}

        # HEAD first
        try:
            r = self._session.head(
                url, headers=headers, timeout=self._timeout,
                verify=self._verify, allow_redirects=True
            )
            if r.status_code in VALID_STATUS_CODES:
                return r.status_code, dict(r.headers), ""
        except Exception:
            pass

        # GET fallback
        try:
            r = self._session.get(
                url, headers=headers, timeout=self._timeout,
                verify=self._verify, allow_redirects=True,
                stream=True
            )
            body = ""
            try:
                body = r.text[:65536]
            except Exception:
                pass
            return r.status_code, dict(r.headers), body
        except Exception as e:
            raise

    async def probe(self, url: str) -> tuple[Optional[int], dict, str]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._probe_sync, url)

    async def close(self):
        self._session.close()


# ─── Prober ───────────────────────────────────────────────────────────────────

def _pick_backend(verify_ssl: bool, timeout: int):
    try:
        import aiohttp  # noqa: F401
        logger.info("HTTP backend: aiohttp (async, fastest)")
        return _AiohttpProber(verify_ssl, timeout)
    except ImportError:
        logger.info("HTTP backend: requests (sync via executor)")
        return _RequestsProber(verify_ssl, timeout)


class Prober:
    """
    Async HTTP/HTTPS prober.

    Probes a hostname on both HTTPS and HTTP, returns the best ProbeResult.
    Captures tech fingerprints, page title, TLS info automatically.

    Usage:
        prober = Prober()
        result = await prober.probe_host("api.example.com")
        await prober.close()
    """

    def __init__(self, verify_ssl: bool = False, timeout: int = HTTP_TIMEOUT):
        self._backend   = _pick_backend(verify_ssl, timeout)
        self._semaphore = asyncio.Semaphore(200)   # max concurrent HTTP probes

    async def _probe_url(self, hostname: str, protocol: str) -> Optional[ProbeResult]:
        url = f"{protocol}://{hostname}"
        start = time.monotonic()

        try:
            async with self._semaphore:
                status, headers, body = await self._backend.probe(url)
        except Exception as e:
            logger.debug(f"HTTP error {url}: {e}")
            return None

        elapsed = time.monotonic() - start

        if status is None:
            return None

        result = ProbeResult(
            hostname=hostname,
            url=url,
            status=status,
            server=headers.get("server") or headers.get("Server"),
            content_length=int(headers.get("content-length", 0) or 0),
            redirect_to=headers.get("location") or headers.get("Location"),
            technologies=_fingerprint(headers),
            response_time=elapsed,
        )

        if body:
            result.title = _extract_title(body)

        # TLS subject from URL (rough)
        if protocol == "https":
            result.tls_subject = hostname

        return result

    async def probe_host(self, hostname: str) -> Optional[ProbeResult]:
        """
        Probe a hostname on HTTPS then HTTP.
        Returns the first successful ProbeResult, or None.
        """
        for protocol in ("https", "http"):
            result = await self._probe_url(hostname, protocol)
            if result and result.alive:
                return result
        return None

    async def probe_batch(
        self,
        hostnames: list[str],
        concurrency: int = 100,
    ):
        """
        Probe a list of hostnames concurrently.
        Yields ProbeResult (or None) as each completes.
        """
        semaphore = asyncio.Semaphore(concurrency)

        async def _bounded(h: str):
            async with semaphore:
                return await self.probe_host(h)

        tasks = [asyncio.create_task(_bounded(h)) for h in hostnames]
        for coro in asyncio.as_completed(tasks):
            yield await coro

    async def close(self):
        await self._backend.close()
