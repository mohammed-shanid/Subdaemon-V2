"""
SubDaemon v2 — Core Engine
────────────────────────────
The engine is the ONLY orchestrator.
It does NO logic itself — it wires components together.

Pipeline:
  Sources → dedup queue → DNS resolver pool (wildcard-filtered)
          → [optional] HTTP prober → OutputManager

Everything is async. The engine supports:
  - DNS-only mode (fastest)
  - Full mode (DNS + HTTP probe)
  - Passive-only (no bruteforce)
  - Resume from checkpoint
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from subdaemon.core.resolver  import ResolverPool, WildcardDetector, WildcardInfo
from subdaemon.core.prober    import Prober
from subdaemon.sources.sources import BaseSource, PermutationSource
from subdaemon.output.writer  import Finding, OutputManager, Checkpoint

logger = logging.getLogger("subdaemon.engine")


# ─── Scan Config ──────────────────────────────────────────────────────────────

@dataclass
class ScanConfig:
    domain:          str
    sources:         list[BaseSource]
    output:          OutputManager
    dns_concurrency: int             = 500
    http_concurrency:int             = 100
    dns_only:        bool            = False
    delay:           float           = 0.0
    verbose:         bool            = False
    resume:          bool            = False
    checkpoint_path: str             = ".subdaemon_checkpoint.json"
    custom_resolvers:list[str]       = field(default_factory=list)


# ─── Stats ────────────────────────────────────────────────────────────────────

@dataclass
class ScanStats:
    start_time:    float = field(default_factory=time.monotonic)
    total_queued:  int   = 0
    dns_checked:   int   = 0
    dns_resolved:  int   = 0
    wildcard_hits: int   = 0
    http_probed:   int   = 0
    found:         int   = 0
    errors:        int   = 0

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.start_time

    @property
    def rate(self) -> float:
        e = self.elapsed
        return self.dns_checked / e if e > 0 else 0.0

    def __str__(self) -> str:
        return (
            f"Queued:{self.total_queued} | "
            f"DNS:{self.dns_checked} | "
            f"Resolved:{self.dns_resolved} | "
            f"Found:{self.found} | "
            f"Rate:{self.rate:.0f}/s | "
            f"Elapsed:{self.elapsed:.1f}s"
        )


# ─── Engine ───────────────────────────────────────────────────────────────────

class Engine:
    """
    The main scan engine.

    Responsibilities:
      - Collect subdomains from all sources (deduped)
      - Detect wildcards before starting
      - Resolve DNS with pool (skip wildcard IPs)
      - Optionally probe HTTP
      - Stream results to OutputManager
      - Save checkpoint for resume

    Usage:
        engine = Engine(config)
        await engine.run()
    """

    def __init__(self, config: ScanConfig):
        self._cfg      = config
        self._stats    = ScanStats()
        self._seen:    set[str] = set()          # dedup across all sources
        self._found:   list[str] = []            # confirmed subdomains (for permutation)
        self._pool     = ResolverPool(
            custom_resolvers=config.custom_resolvers or None
        )
        self._prober   = Prober() if not config.dns_only else None
        self._wildcard: WildcardInfo | None = None
        self._checkpoint = Checkpoint(config.checkpoint_path) if config.resume else None
        self._queue:   asyncio.Queue[str | None] = asyncio.Queue(maxsize=10000)
        self._display_callback = None           # injected by CLI

    def set_display_callback(self, cb):
        """CLI injects a callback to update the live display."""
        self._display_callback = cb

    # ── Phase 1: Wildcard Detection ───────────────────────────────────────────

    async def _detect_wildcard(self) -> WildcardInfo:
        detector = WildcardDetector(self._pool)
        info = await detector.detect(self._cfg.domain)
        self._wildcard = info
        return info

    # ── Phase 2: Source Collection ────────────────────────────────────────────

    async def _collect_sources(self) -> list[str]:
        """
        Run all sources concurrently, collect into deduplicated list.
        Returns list of subdomain prefixes (not FQDNs).
        """
        all_subs: set[str] = set()

        # Load checkpoint if resuming
        already_checked: set[str] = set()
        if self._checkpoint:
            already_checked = await self._checkpoint.load()

        async def _drain_source(source: BaseSource):
            try:
                async for sub in source.stream(self._cfg.domain):
                    fqdn = f"{sub}.{self._cfg.domain}"
                    if fqdn not in already_checked:
                        all_subs.add(sub)
            except Exception as e:
                logger.error(f"Source {source.name} failed: {e}")

        # Run non-permutation sources concurrently
        regular = [s for s in self._cfg.sources if not isinstance(s, PermutationSource)]
        perm    = [s for s in self._cfg.sources if isinstance(s, PermutationSource)]

        await asyncio.gather(*[_drain_source(s) for s in regular])

        # If permutation source exists, seed it with what we found passively
        for p in perm:
            p.set_known(list(all_subs))
            await _drain_source(p)

        logger.info(f"Total unique subdomains to check: {len(all_subs)}")
        self._stats.total_queued = len(all_subs)
        return list(all_subs)

    # ── Phase 3: DNS Resolution ───────────────────────────────────────────────

    async def _resolve_worker(self, sub: str):
        """Resolve one subdomain. Core inner loop."""
        fqdn = f"{sub}.{self._cfg.domain}"

        if self._cfg.delay > 0:
            await asyncio.sleep(self._cfg.delay)

        result = await self._pool.resolve(fqdn)
        self._stats.dns_checked += 1

        if self._checkpoint:
            await self._checkpoint.mark_checked(fqdn)

        if not result.resolved:
            return

        # Wildcard filter: if all IPs are wildcard IPs → skip
        if self._wildcard and self._wildcard.exists:
            result_ips = set(result.ipv4 + result.ipv6)
            if result_ips and result_ips.issubset(self._wildcard.ips):
                self._stats.wildcard_hits += 1
                logger.debug(f"Wildcard filtered: {fqdn}")
                return

        self._stats.dns_resolved += 1
        logger.debug(f"Resolved: {fqdn} → {result.primary_ip}")

        # Build finding
        finding = Finding.from_dns(result, source="dns")

        # HTTP probe
        if not self._cfg.dns_only and self._prober:
            probe = await self._prober.probe_host(fqdn)
            self._stats.http_probed += 1
            if probe and probe.alive:
                finding.enrich_http(probe)
            elif not probe:
                # HTTP failed but DNS confirmed — still record
                pass

        self._stats.found += 1
        self._found.append(sub)
        await self._cfg.output.record(finding)

        if self._display_callback:
            self._display_callback(finding, self._stats)

    async def _run_dns_phase(self, subdomains: list[str]):
        """Resolve all subdomains with bounded concurrency."""
        semaphore = asyncio.Semaphore(self._cfg.dns_concurrency)

        async def _bounded(sub: str):
            async with semaphore:
                try:
                    await self._resolve_worker(sub)
                except Exception as e:
                    self._stats.errors += 1
                    logger.debug(f"Worker error for {sub}: {e}")

        tasks = [asyncio.create_task(_bounded(sub)) for sub in subdomains]
        await asyncio.gather(*tasks)

    # ── Main Run ──────────────────────────────────────────────────────────────

    async def run(self) -> ScanStats:
        """
        Execute the full scan pipeline.
        Returns ScanStats when complete.
        """
        logger.info(f"Starting scan: {self._cfg.domain}")

        await self._cfg.output.open()

        try:
            # Phase 1: Wildcard detection
            logger.info("Phase 1/3: Wildcard detection...")
            wc = await self._detect_wildcard()
            if wc.exists:
                logger.warning(f"Wildcard active — false positives will be filtered")

            # Phase 2: Source collection
            logger.info("Phase 2/3: Collecting subdomains from sources...")
            subdomains = await self._collect_sources()

            if not subdomains:
                logger.warning("No subdomains to check!")
                return self._stats

            # Phase 3: Resolution (+ HTTP probe)
            mode = "DNS-only" if self._cfg.dns_only else "DNS + HTTP"
            logger.info(f"Phase 3/3: Resolving {len(subdomains)} subdomains [{mode}]...")
            await self._run_dns_phase(subdomains)

        except asyncio.CancelledError:
            logger.warning("Scan cancelled — saving partial results")
        finally:
            if self._checkpoint:
                await self._checkpoint.close()
            await self._cfg.output.close()
            if self._prober:
                await self._prober.close()

        logger.info(f"Scan complete. {self._stats}")
        return self._stats
