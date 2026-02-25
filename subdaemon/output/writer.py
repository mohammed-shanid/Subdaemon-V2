"""
SubDaemon v2 — Output System
──────────────────────────────
Streaming writers — results are written AS they are discovered,
not buffered until the end. No data loss on Ctrl+C.

Formats: txt, json, csv
Checkpoint: JSON file for scan resume
"""

from __future__ import annotations

import asyncio
import csv
import json
import logging
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional, TextIO

from subdaemon.core.resolver import DNSResult
from subdaemon.core.prober  import ProbeResult

logger = logging.getLogger("subdaemon.output")


# ─── Finding (unified result object) ─────────────────────────────────────────

@dataclass
class Finding:
    """One confirmed subdomain finding."""
    hostname:       str
    ipv4:           list[str]           = field(default_factory=list)
    ipv6:           list[str]           = field(default_factory=list)
    cnames:         list[str]           = field(default_factory=list)
    http_status:    Optional[int]       = None
    http_url:       Optional[str]       = None
    title:          Optional[str]       = None
    server:         Optional[str]       = None
    technologies:   list[str]           = field(default_factory=list)
    response_time:  float               = 0.0
    wildcard:       bool                = False
    source:         str                 = "unknown"
    timestamp:      float               = field(default_factory=time.time)

    @classmethod
    def from_dns(cls, dns: DNSResult, source: str = "dns") -> "Finding":
        return cls(
            hostname    = dns.hostname,
            ipv4        = dns.ipv4,
            ipv6        = dns.ipv6,
            cnames      = dns.cnames,
            wildcard    = dns.wildcard,
            source      = source,
        )

    def enrich_http(self, probe: ProbeResult) -> "Finding":
        self.http_status   = probe.status
        self.http_url      = probe.url
        self.title         = probe.title
        self.server        = probe.server
        self.technologies  = probe.technologies
        self.response_time = probe.response_time
        return self

    def to_dict(self) -> dict:
        return asdict(self)

    def to_csv_row(self) -> list:
        return [
            self.hostname,
            ",".join(self.ipv4),
            ",".join(self.ipv6),
            ",".join(self.cnames),
            self.http_status or "",
            self.http_url or "",
            self.title or "",
            self.server or "",
            ",".join(self.technologies),
            f"{self.response_time:.3f}",
            self.source,
        ]

    CSV_HEADERS = [
        "hostname", "ipv4", "ipv6", "cnames",
        "http_status", "http_url", "title", "server",
        "technologies", "response_time", "source",
    ]

    def __str__(self) -> str:
        parts = [self.hostname]
        if self.ipv4:
            parts.append(f"[{', '.join(self.ipv4)}]")
        if self.http_status:
            parts.append(f"HTTP:{self.http_status}")
        if self.title:
            parts.append(f'"{self.title}"')
        return " ".join(parts)


# ─── Writers ──────────────────────────────────────────────────────────────────

class StreamingWriter:
    """
    Base streaming writer.
    Opens file once, writes each finding immediately.
    Thread-safe via asyncio lock.
    """

    def __init__(self, path: Path):
        self._path  = path
        self._lock  = asyncio.Lock()
        self._fh:   Optional[TextIO] = None
        self._count = 0

    async def open(self):
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self._path, "w", encoding="utf-8", buffering=1)
        await self._write_header()

    async def _write_header(self):
        pass  # Override in subclasses

    async def write(self, finding: Finding):
        async with self._lock:
            await self._write_finding(finding)
            self._count += 1
            if hasattr(self._fh, "flush"):
                self._fh.flush()

    async def _write_finding(self, finding: Finding):
        raise NotImplementedError

    async def close(self):
        if self._fh:
            await self._write_footer()
            self._fh.close()
            self._fh = None

    async def _write_footer(self):
        pass

    @property
    def count(self) -> int:
        return self._count


class TxtWriter(StreamingWriter):
    """Plain text — one FQDN per line."""

    async def _write_finding(self, finding: Finding):
        self._fh.write(f"{finding.hostname}\n")


class VerboseTxtWriter(StreamingWriter):
    """Verbose text with IPs and HTTP info."""

    async def _write_finding(self, finding: Finding):
        line = str(finding)
        self._fh.write(f"{line}\n")


class JsonWriter(StreamingWriter):
    """
    JSON output — writes a JSON array (opens/closes brackets).
    Each finding is a valid JSON object.
    """

    def __init__(self, path: Path):
        super().__init__(path)
        self._first = True

    async def _write_header(self):
        self._fh.write("[\n")

    async def _write_finding(self, finding: Finding):
        if not self._first:
            self._fh.write(",\n")
        json.dump(finding.to_dict(), self._fh, indent=2)
        self._first = False

    async def _write_footer(self):
        self._fh.write("\n]\n")


class CsvWriter(StreamingWriter):
    """CSV output with all fields."""

    def __init__(self, path: Path):
        super().__init__(path)
        self._writer = None

    async def open(self):
        await super().open()

    async def _write_header(self):
        self._writer = csv.writer(self._fh)
        self._writer.writerow(Finding.CSV_HEADERS)

    async def _write_finding(self, finding: Finding):
        self._writer.writerow(finding.to_csv_row())


# ─── Output Manager ───────────────────────────────────────────────────────────

class OutputManager:
    """
    Manages multiple simultaneous output writers.
    Single call to .record() writes to all open formats.

    Usage:
        mgr = OutputManager("results/scan1", formats=["txt", "json", "csv"])
        await mgr.open()
        await mgr.record(finding)
        await mgr.close()
        print(mgr.summary())
    """

    FORMAT_MAP = {
        "txt":          TxtWriter,
        "txt-verbose":  VerboseTxtWriter,
        "json":         JsonWriter,
        "csv":          CsvWriter,
    }

    def __init__(self, base_path: str, formats: list[str] | None = None):
        self._base     = Path(base_path)
        self._formats  = formats or ["txt"]
        self._writers: list[StreamingWriter] = []
        self._findings: list[Finding] = []
        self._lock     = asyncio.Lock()

    def _ext(self, fmt: str) -> str:
        ext_map = {"txt": "txt", "txt-verbose": "txt", "json": "json", "csv": "csv"}
        return ext_map.get(fmt, fmt)

    async def open(self):
        for fmt in self._formats:
            cls = self.FORMAT_MAP.get(fmt)
            if not cls:
                logger.warning(f"Unknown output format: {fmt}")
                continue
            ext  = self._ext(fmt)
            path = self._base.with_suffix(f".{ext}") if len(self._formats) == 1 else \
                   Path(f"{self._base}_{fmt}.{ext}")
            writer = cls(path)
            await writer.open()
            self._writers.append(writer)
            logger.debug(f"Opened output: {path}")

    async def record(self, finding: Finding):
        async with self._lock:
            self._findings.append(finding)
        for writer in self._writers:
            await writer.write(finding)

    async def close(self):
        for writer in self._writers:
            await writer.close()

    @property
    def findings(self) -> list[Finding]:
        return list(self._findings)

    @property
    def count(self) -> int:
        return len(self._findings)

    def summary(self) -> str:
        lines = [f"Total findings: {self.count}"]
        for w in self._writers:
            lines.append(f"  → {w._path} ({w.count} entries)")
        return "\n".join(lines)


# ─── Checkpoint (Resume) ──────────────────────────────────────────────────────

class Checkpoint:
    """
    Persists scan progress to disk.
    On resume, skips already-checked subdomains.
    """

    def __init__(self, path: str):
        self._path     = Path(path)
        self._checked: set[str] = set()
        self._lock     = asyncio.Lock()

    async def load(self) -> set[str]:
        if not self._path.exists():
            return set()
        try:
            data = json.loads(self._path.read_text())
            self._checked = set(data.get("checked", []))
            logger.info(f"Resumed: {len(self._checked)} already checked")
            return self._checked
        except Exception as e:
            logger.warning(f"Failed to load checkpoint: {e}")
            return set()

    async def mark_checked(self, hostname: str):
        async with self._lock:
            self._checked.add(hostname)

    async def save(self):
        async with self._lock:
            data = {"checked": list(self._checked), "saved_at": time.time()}
            self._path.write_text(json.dumps(data, indent=2))

    async def close(self):
        await self.save()
        logger.debug(f"Checkpoint saved: {self._path}")
