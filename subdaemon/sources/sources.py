"""
SubDaemon v2 — Subdomain Sources
──────────────────────────────────
All sources yield plain subdomain strings into a shared async queue.
The engine doesn't care where a subdomain came from.

Sources implemented:
  1. BruteforceSource  — wordlist-based
  2. PassiveSource     — crt.sh Certificate Transparency logs
  3. WaybackSource     — Wayback Machine CDX API
  4. PermutationSource — mutation of known subdomains (altdns-style)
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import urllib.request
import urllib.error
from abc import ABC, abstractmethod
from pathlib import Path
from typing import AsyncGenerator

from subdaemon.config.defaults import (
    CRT_SH_URL,
    MUTATION_PREFIXES,
    MUTATION_SUFFIXES,
    WAYBACK_URL,
)

logger = logging.getLogger("subdaemon.sources")


# ─── Base ─────────────────────────────────────────────────────────────────────

class BaseSource(ABC):
    """All sources implement this interface."""

    name: str = "base"

    @abstractmethod
    async def stream(self, domain: str) -> AsyncGenerator[str, None]:
        """Yield subdomains (without the root domain) or FQDNs."""
        ...

    def _clean(self, sub: str, domain: str) -> str | None:
        """Normalize a subdomain entry. Returns None if invalid."""
        sub = sub.strip().lower()

        # If it's an FQDN, strip the domain part
        if sub.endswith(f".{domain}"):
            sub = sub[: -(len(domain) + 1)]
        elif sub == domain:
            return None

        # Strip wildcards
        sub = sub.lstrip("*.")

        # Basic validity
        if not sub or "." in sub and not all(
            re.match(r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$", part)
            for part in sub.split(".")
        ):
            return None

        return sub


# ─── 1. Bruteforce ────────────────────────────────────────────────────────────

class BruteforceSource(BaseSource):
    """
    Reads a wordlist file and streams subdomains.
    Deduplicates, strips comments, handles blank lines.
    """

    name = "bruteforce"

    def __init__(self, wordlist_path: str):
        self._path = Path(wordlist_path)

    async def stream(self, domain: str) -> AsyncGenerator[str, None]:
        if not self._path.exists():
            raise FileNotFoundError(f"Wordlist not found: {self._path}")

        seen: set[str] = set()
        loop = asyncio.get_event_loop()

        def _read():
            words = []
            with open(self._path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip().lower()
                    if not line or line.startswith("#"):
                        continue
                    words.append(line)
            return words

        words = await loop.run_in_executor(None, _read)
        logger.info(f"[bruteforce] Loaded {len(words)} words from {self._path}")

        for word in words:
            cleaned = self._clean(word, domain)
            if cleaned and cleaned not in seen:
                seen.add(cleaned)
                yield cleaned


# ─── 2. Passive: Certificate Transparency (crt.sh) ───────────────────────────

class PassiveSource(BaseSource):
    """
    Queries crt.sh for SSL certificates issued for *.domain.
    No DNS, no HTTP to target — completely passive.
    """

    name = "crt.sh"

    def __init__(self, timeout: int = 15):
        self._timeout = timeout

    def _fetch_crtsh(self, domain: str) -> list[str]:
        url = CRT_SH_URL.format(domain=domain)
        try:
            req = urllib.request.Request(
                url,
                headers={"Accept": "application/json", "User-Agent": "subdaemon/2.0"},
            )
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                data = json.loads(resp.read().decode())
                names = set()
                for entry in data:
                    for name in entry.get("name_value", "").split("\n"):
                        names.add(name.strip())
                return list(names)
        except urllib.error.HTTPError as e:
            logger.warning(f"[crt.sh] HTTP {e.code} for {domain}")
            return []
        except Exception as e:
            logger.warning(f"[crt.sh] Failed: {e}")
            return []

    async def stream(self, domain: str) -> AsyncGenerator[str, None]:
        loop = asyncio.get_event_loop()
        logger.info(f"[crt.sh] Querying certificate transparency for {domain}")
        names = await loop.run_in_executor(None, self._fetch_crtsh, domain)
        logger.info(f"[crt.sh] Got {len(names)} raw entries")

        seen: set[str] = set()
        for name in names:
            cleaned = self._clean(name, domain)
            if cleaned and cleaned not in seen:
                seen.add(cleaned)
                yield cleaned


# ─── 3. Passive: Wayback Machine ─────────────────────────────────────────────

class WaybackSource(BaseSource):
    """
    Queries the Wayback Machine CDX API for archived URLs.
    Extracts subdomains from URL hostnames — completely passive.
    """

    name = "wayback"

    def __init__(self, timeout: int = 30):
        self._timeout = timeout

    def _fetch_wayback(self, domain: str) -> list[str]:
        url = WAYBACK_URL.format(domain=domain)
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "subdaemon/2.0"},
            )
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                text = resp.read().decode(errors="ignore")
                # Extract hostnames from URLs
                hostnames = re.findall(
                    r"https?://([a-z0-9\-\.]+\." + re.escape(domain) + r")",
                    text,
                    re.IGNORECASE,
                )
                return list(set(hostnames))
        except Exception as e:
            logger.warning(f"[wayback] Failed: {e}")
            return []

    async def stream(self, domain: str) -> AsyncGenerator[str, None]:
        loop = asyncio.get_event_loop()
        logger.info(f"[wayback] Querying Wayback Machine for {domain}")
        hostnames = await loop.run_in_executor(None, self._fetch_wayback, domain)
        logger.info(f"[wayback] Got {len(hostnames)} raw entries")

        seen: set[str] = set()
        for hostname in hostnames:
            # Strip root domain to get subdomain prefix
            if hostname.endswith(f".{domain}"):
                sub = hostname[: -(len(domain) + 1)]
                cleaned = self._clean(sub, domain)
                if cleaned and cleaned not in seen:
                    seen.add(cleaned)
                    yield cleaned


# ─── 4. Permutation ───────────────────────────────────────────────────────────

class PermutationSource(BaseSource):
    """
    Generates mutations of known/discovered subdomains.
    Run this AFTER passive sources have seeded some results.

    Mutations:
      - dev.api → staging.api, prod.api, api-dev, api-prod
      - v1.example → v2.example
      - Prefix/suffix injection
    """

    name = "permutation"

    def __init__(self, known_subdomains: list[str] | None = None):
        self._known = known_subdomains or []

    def set_known(self, known: list[str]):
        self._known = known

    def _generate(self, sub: str) -> set[str]:
        mutations: set[str] = set()

        # Add all prefixes
        for prefix in MUTATION_PREFIXES:
            mutations.add(f"{prefix}.{sub}")
            mutations.add(f"{prefix}-{sub}")

        # Add all suffixes
        for suffix in MUTATION_SUFFIXES:
            mutations.add(f"{sub}{suffix}")

        # Number increments: api1 → api2, api3
        if re.search(r"\d+$", sub):
            base, num = re.match(r"^(.*?)(\d+)$", sub).groups()
            for i in range(1, 6):
                mutations.add(f"{base}{i}")

        return mutations

    async def stream(self, domain: str) -> AsyncGenerator[str, None]:
        if not self._known:
            logger.debug("[permutation] No known subdomains to permute")
            return

        logger.info(f"[permutation] Generating mutations for {len(self._known)} known subdomains")
        seen: set[str] = set(self._known)

        for sub in self._known:
            for mutation in self._generate(sub):
                if mutation not in seen:
                    seen.add(mutation)
                    yield mutation


# ─── Source Registry ──────────────────────────────────────────────────────────

def build_sources(
    wordlist:    str | None      = None,
    passive:     bool            = True,
    wayback:     bool            = False,
    permutation: bool            = False,
    known:       list[str] | None = None,
) -> list[BaseSource]:
    """
    Build the list of sources to use for a scan.
    Called by the engine based on CLI flags.
    """
    sources: list[BaseSource] = []

    if wordlist:
        sources.append(BruteforceSource(wordlist))

    if passive:
        sources.append(PassiveSource())

    if wayback:
        sources.append(WaybackSource())

    if permutation:
        perm = PermutationSource(known or [])
        sources.append(perm)

    return sources
