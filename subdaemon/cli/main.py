"""
SubDaemon v2 — CLI Entry Point
────────────────────────────────
This file ONLY:
  1. Parses arguments
  2. Wires components (sources, output, engine, display)
  3. Runs the async engine
  4. Exits cleanly

No logic here. All logic is in core/.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from subdaemon.config.defaults import (
    DEFAULT_DELAY, DEFAULT_OUTPUT, DEFAULT_THREADS,
    MAX_THREADS, CHECKPOINT_FILE,
)
from subdaemon.core.engine    import Engine, ScanConfig
from subdaemon.sources.sources import build_sources
from subdaemon.output.writer   import OutputManager
from subdaemon.cli.display     import make_display


# ─── Version ──────────────────────────────────────────────────────────────────

__version__ = "2.0.0"


# ─── Argument Parser ──────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="subdaemon",
        description="SubDaemon v2 — Async Subdomain Enumeration Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Fast DNS-only (passive + bruteforce)
  subdaemon example.com -w wordlist.txt --dns-only

  # Full scan with HTTP probing
  subdaemon example.com -w wordlist.txt -t 200

  # Passive only (no wordlist, CT logs + wayback)
  subdaemon example.com --passive --wayback

  # All sources, JSON output, resume if interrupted
  subdaemon example.com -w wordlist.txt --passive --wayback --permute \\
            -o results/scan -f json --resume

  # Custom resolvers, max speed
  subdaemon example.com -w wordlist.txt -t 500 \\
            --resolvers 1.1.1.1,8.8.8.8

GitHub: https://github.com/mohammed-shanid/subdeamon
        """,
    )

    # ── Target ──
    p.add_argument("domain", nargs="?", help="Target domain (e.g. example.com)")

    # ── Sources ──
    src = p.add_argument_group("Source Options")
    src.add_argument("-w", "--wordlist",
        help="Path to subdomain wordlist")
    src.add_argument("--passive", action="store_true", default=True,
        help="Query crt.sh CT logs (default: on)")
    src.add_argument("--no-passive", dest="passive", action="store_false",
        help="Disable passive CT log source")
    src.add_argument("--wayback", action="store_true",
        help="Query Wayback Machine CDX API")
    src.add_argument("--permute", action="store_true",
        help="Generate mutations from discovered subdomains")

    # ── Output ──
    out = p.add_argument_group("Output Options")
    out.add_argument("-o", "--output", default=DEFAULT_OUTPUT,
        help=f"Output base path (default: {DEFAULT_OUTPUT})")
    out.add_argument("-f", "--format", dest="formats",
        default="txt", metavar="FMT",
        help="Output format(s): txt,json,csv (comma-separated, default: txt)")

    # ── Performance ──
    perf = p.add_argument_group("Performance Options")
    perf.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS,
        metavar="N",
        help=f"DNS concurrency (default: {DEFAULT_THREADS}, max: {MAX_THREADS})")
    perf.add_argument("--http-threads", type=int, default=100,
        metavar="N", help="HTTP probe concurrency (default: 100)")
    perf.add_argument("-T", "--timeout", type=int, default=6,
        metavar="SEC", help="HTTP timeout in seconds (default: 6)")
    perf.add_argument("--delay", type=float, default=DEFAULT_DELAY,
        metavar="SEC", help="Delay between DNS queries (default: 0, stealth: 0.5+)")

    # ── DNS ──
    dns = p.add_argument_group("DNS Options")
    dns.add_argument("--dns-only", action="store_true",
        help="DNS resolution only, skip HTTP probing (fastest)")
    dns.add_argument("--resolvers", metavar="IPs",
        help="Custom resolvers (comma-separated IPs), prepended to pool")
    dns.add_argument("--verify-ssl", action="store_true",
        help="Verify SSL certificates (default: off)")

    # ── Resume ──
    res = p.add_argument_group("Resume Options")
    res.add_argument("--resume", action="store_true",
        help="Resume interrupted scan from checkpoint")
    res.add_argument("--checkpoint", default=CHECKPOINT_FILE,
        help=f"Checkpoint file path (default: {CHECKPOINT_FILE})")

    # ── Display ──
    disp = p.add_argument_group("Display Options")
    disp.add_argument("-v", "--verbose", action="store_true",
        help="Verbose debug logging")
    disp.add_argument("-q", "--quiet", action="store_true",
        help="Suppress all output except findings")
    disp.add_argument("--no-color", action="store_true",
        help="Disable colored output")

    # ── Meta ──
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    return p


# ─── Validation ───────────────────────────────────────────────────────────────

def validate(args: argparse.Namespace) -> list[str]:
    errors = []

    if not args.domain:
        errors.append("Target domain is required")

    if not args.wordlist and not args.passive and not args.wayback:
        errors.append("At least one source is required: -w wordlist, --passive, or --wayback")

    if args.wordlist and not Path(args.wordlist).exists():
        errors.append(f"Wordlist not found: {args.wordlist}")

    if not (1 <= args.threads <= MAX_THREADS):
        errors.append(f"Threads must be 1–{MAX_THREADS}, got {args.threads}")

    if args.delay < 0:
        errors.append(f"Delay cannot be negative")

    return errors


# ─── Main ─────────────────────────────────────────────────────────────────────

async def _run(args: argparse.Namespace):
    # Logging
    level = logging.DEBUG if args.verbose else (logging.ERROR if args.quiet else logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    # Parse formats
    formats = [f.strip() for f in args.formats.split(",")]

    # Custom resolvers
    custom_resolvers = []
    if args.resolvers:
        custom_resolvers = [r.strip() for r in args.resolvers.split(",")]

    # Build components
    sources = build_sources(
        wordlist    = args.wordlist,
        passive     = args.passive,
        wayback     = args.wayback,
        permutation = args.permute,
    )

    output_mgr = OutputManager(
        base_path = args.output,
        formats   = formats,
    )

    display = make_display(
        domain   = args.domain,
        quiet    = args.quiet,
        no_color = args.no_color,
    )

    # Config
    cfg = ScanConfig(
        domain           = args.domain,
        sources          = sources,
        output           = output_mgr,
        dns_concurrency  = args.threads,
        http_concurrency = args.http_threads,
        dns_only         = args.dns_only,
        delay            = args.delay,
        verbose          = args.verbose,
        resume           = args.resume,
        checkpoint_path  = args.checkpoint,
        custom_resolvers = custom_resolvers,
    )

    # Wire display callback into engine
    engine = Engine(cfg)
    engine.set_display_callback(display.update)

    display.start()

    try:
        stats = await engine.run()
        display.print_summary(stats)
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted. Partial results saved.")
        sys.exit(130)

    sys.exit(0 if stats.found > 0 else 1)


def main():
    parser = build_parser()
    args   = parser.parse_args()

    # Show help if no domain
    if not args.domain:
        parser.print_help()
        sys.exit(0)

    # Validate
    errors = validate(args)
    if errors:
        for e in errors:
            print(f"[✗] {e}", file=sys.stderr)
        sys.exit(2)

    # Run
    try:
        asyncio.run(_run(args))
    except KeyboardInterrupt:
        print("\n[!] Aborted.")
        sys.exit(130)


if __name__ == "__main__":
    main()
