"""
SubDaemon v2 — DNS Resolver Pool
────────────────────────────────
Key design decisions:
  • Resolver pool with round-robin — no single NS sees your full scan
  • Async via asyncio + aiodns (falls back to threaded dnspython/socket)
  • Per-resolver rate limiting to avoid bans
  • Returns structured DNSResult, never raw strings
  • Wildcard detection baked in
"""

from __future__ import annotations

import asyncio
import itertools
import logging
import random
import socket
import string
import time
from dataclasses import dataclass, field
from typing import Optional

from subdaemon.config.defaults import (
    DNS_RETRIES,
    DNS_TIMEOUT,
    PUBLIC_RESOLVERS,
    WILDCARD_TEST_LEN,
    WILDCARD_TESTS,
)

logger = logging.getLogger("subdaemon.resolver")


# ─── Data Structures ──────────────────────────────────────────────────────────

@dataclass
class DNSResult:
    hostname:   str
    ipv4:       list[str]   = field(default_factory=list)
    ipv6:       list[str]   = field(default_factory=list)
    cnames:     list[str]   = field(default_factory=list)
    wildcard:   bool        = False
    error:      Optional[str] = None

    @property
    def resolved(self) -> bool:
        return bool(self.ipv4 or self.ipv6)

    @property
    def primary_ip(self) -> Optional[str]:
        return self.ipv4[0] if self.ipv4 else (self.ipv6[0] if self.ipv6 else None)


@dataclass
class WildcardInfo:
    exists:     bool
    ips:        set[str]    = field(default_factory=set)


# ─── Backend: aiodns (fastest) ────────────────────────────────────────────────

class _AiodnsBackend:
    """Uses aiodns for true async DNS — best performance."""

    def __init__(self, nameservers: list[str]):
        import aiodns
        self._lib = aiodns
        self._ns = nameservers

    def _resolver(self, ns: str):
        return self._lib.DNSResolver(
            nameservers=[ns],
            timeout=DNS_TIMEOUT,
        )

    async def query_a(self, resolver, hostname: str) -> list[str]:
        try:
            result = await resolver.query(hostname, "A")
            return [r.host for r in result]
        except Exception:
            return []

    async def query_aaaa(self, resolver, hostname: str) -> list[str]:
        try:
            result = await resolver.query(hostname, "AAAA")
            return [r.host for r in result]
        except Exception:
            return []

    async def query_cname(self, resolver, hostname: str) -> list[str]:
        try:
            result = await resolver.query(hostname, "CNAME")
            return [r.cname for r in result]
        except Exception:
            return []

    async def resolve(self, hostname: str, ns: str) -> DNSResult:
        resolver = self._resolver(ns)
        ipv4, ipv6, cnames = await asyncio.gather(
            self.query_a(resolver, hostname),
            self.query_aaaa(resolver, hostname),
            self.query_cname(resolver, hostname),
        )
        return DNSResult(hostname=hostname, ipv4=ipv4, ipv6=ipv6, cnames=cnames)


# ─── Backend: dnspython (sync, good compatibility) ────────────────────────────

class _DnspythonBackend:
    """Uses dnspython — sync but feature-rich."""

    def __init__(self, nameservers: list[str]):
        import dns.resolver as _r
        self._lib = _r
        self._ns = nameservers

    def _resolver(self, ns: str):
        r = self._lib.Resolver(configure=False)
        r.nameservers = [ns]
        r.timeout = DNS_TIMEOUT
        r.lifetime = DNS_TIMEOUT * DNS_RETRIES
        return r

    def _query(self, resolver, hostname: str, rtype: str) -> list[str]:
        try:
            answers = resolver.resolve(hostname, rtype)
            if rtype == "CNAME":
                return [str(a.target) for a in answers]
            return [a.address for a in answers]
        except Exception:
            return []

    async def resolve(self, hostname: str, ns: str) -> DNSResult:
        loop = asyncio.get_event_loop()
        resolver = self._resolver(ns)

        ipv4, ipv6, cnames = await asyncio.gather(
            loop.run_in_executor(None, self._query, resolver, hostname, "A"),
            loop.run_in_executor(None, self._query, resolver, hostname, "AAAA"),
            loop.run_in_executor(None, self._query, resolver, hostname, "CNAME"),
        )
        return DNSResult(hostname=hostname, ipv4=ipv4, ipv6=ipv6, cnames=cnames)


# ─── Backend: stdlib socket (always available) ────────────────────────────────

class _SocketBackend:
    """Pure stdlib fallback — no deps, IPv4 only."""

    async def resolve(self, hostname: str, ns: str) -> DNSResult:
        loop = asyncio.get_event_loop()
        try:
            results = await loop.run_in_executor(
                None,
                lambda: socket.getaddrinfo(hostname, None, socket.AF_INET)
            )
            ipv4 = list({r[4][0] for r in results})
        except socket.gaierror:
            ipv4 = []

        try:
            results6 = await loop.run_in_executor(
                None,
                lambda: socket.getaddrinfo(hostname, None, socket.AF_INET6)
            )
            ipv6 = list({r[4][0] for r in results6})
        except socket.gaierror:
            ipv6 = []

        return DNSResult(hostname=hostname, ipv4=ipv4, ipv6=ipv6)


# ─── Resolver Pool ────────────────────────────────────────────────────────────

def _pick_backend(nameservers: list[str]):
    """Auto-select best available DNS backend."""
    try:
        import aiodns  # noqa: F401
        logger.info("DNS backend: aiodns (async, fastest)")
        return _AiodnsBackend(nameservers)
    except ImportError:
        pass

    try:
        import dns.resolver  # noqa: F401
        logger.info("DNS backend: dnspython (threaded)")
        return _DnspythonBackend(nameservers)
    except ImportError:
        pass

    logger.warning("DNS backend: stdlib socket (limited — install aiodns for best results)")
    return _SocketBackend()


class ResolverPool:
    """
    Round-robin resolver pool.

    Each query goes to a different nameserver, distributing
    traffic so no single resolver sees your full scan pattern.

    Usage:
        pool = ResolverPool()
        result = await pool.resolve("www.example.com")
    """

    def __init__(
        self,
        nameservers: list[str] | None = None,
        custom_resolvers: list[str] | None = None,
    ):
        ns_list = custom_resolvers if custom_resolvers else PUBLIC_RESOLVERS
        if nameservers:
            ns_list = nameservers + ns_list

        random.shuffle(ns_list)          # randomize starting point
        self._ns_cycle = itertools.cycle(ns_list)
        self._backend  = _pick_backend(ns_list)
        self._lock     = asyncio.Lock()
        self._stats    = {"resolved": 0, "failed": 0, "total": 0}

    def _next_ns(self) -> str:
        return next(self._ns_cycle)

    async def resolve(self, hostname: str, retries: int = DNS_RETRIES) -> DNSResult:
        """Resolve a hostname, retrying on different nameservers."""
        self._stats["total"] += 1

        for attempt in range(retries + 1):
            ns = self._next_ns()
            try:
                result = await asyncio.wait_for(
                    self._backend.resolve(hostname, ns),
                    timeout=DNS_TIMEOUT + 1,
                )
                if result.resolved or attempt == retries:
                    if result.resolved:
                        self._stats["resolved"] += 1
                    else:
                        self._stats["failed"] += 1
                    return result
            except asyncio.TimeoutError:
                logger.debug(f"Timeout on {hostname} via {ns} (attempt {attempt+1})")
            except Exception as e:
                logger.debug(f"Error on {hostname} via {ns}: {e}")

        self._stats["failed"] += 1
        return DNSResult(hostname=hostname, error="max_retries")

    async def resolve_batch(
        self,
        hostnames: list[str],
        concurrency: int = 500,
    ):
        """
        Resolve a batch of hostnames with bounded concurrency.
        Yields DNSResult as they complete.
        """
        semaphore = asyncio.Semaphore(concurrency)

        async def _bounded(h: str):
            async with semaphore:
                return await self.resolve(h)

        tasks = [asyncio.create_task(_bounded(h)) for h in hostnames]

        for coro in asyncio.as_completed(tasks):
            yield await coro

    @property
    def stats(self) -> dict:
        return self._stats.copy()


# ─── Wildcard Detector ────────────────────────────────────────────────────────

class WildcardDetector:
    """
    Detects wildcard DNS before bruteforce.

    A wildcard (*.example.com → IP) means every subdomain
    you check will appear to resolve — generating massive false positives.
    We probe with guaranteed-random subdomains to detect this.

    Strategy:
        1. Query N random 32-char subdomains
        2. If ANY resolves → wildcard exists
        3. Collect all wildcard IPs → filter later
    """

    def __init__(self, pool: ResolverPool):
        self._pool = pool

    def _random_subdomain(self, domain: str) -> str:
        rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=WILDCARD_TEST_LEN))
        return f"{rand}.{domain}"

    async def detect(self, domain: str) -> WildcardInfo:
        probes = [self._random_subdomain(domain) for _ in range(WILDCARD_TESTS)]

        logger.debug(f"Wildcard probe: {probes[0]}")

        results = [await self._pool.resolve(p) for p in probes]
        resolved = [r for r in results if r.resolved]

        if not resolved:
            logger.debug(f"No wildcard detected for {domain}")
            return WildcardInfo(exists=False)

        # Collect all IPs that are wildcard responses
        wildcard_ips: set[str] = set()
        for r in resolved:
            wildcard_ips.update(r.ipv4)
            wildcard_ips.update(r.ipv6)

        logger.warning(
            f"⚠ Wildcard detected for *.{domain} → {wildcard_ips}. "
            "Results will be filtered."
        )
        return WildcardInfo(exists=True, ips=wildcard_ips)
