"""
SubDaemon v2 — Default Configuration
All tuneable constants live here. Nothing hardcoded elsewhere.
"""

# ─── DNS ──────────────────────────────────────────────────────────────────────

# Public resolver pool — round-robin to avoid fingerprinting
PUBLIC_RESOLVERS = [
    "1.1.1.1",       # Cloudflare
    "1.0.0.1",       # Cloudflare secondary
    "8.8.8.8",       # Google
    "8.8.4.4",       # Google secondary
    "9.9.9.9",       # Quad9
    "149.112.112.112",# Quad9 secondary
    "208.67.222.222", # OpenDNS
    "208.67.220.220", # OpenDNS secondary
    "64.6.64.6",      # Verisign
    "77.88.8.8",      # Yandex
    "94.140.14.14",   # AdGuard
    "185.228.168.9",  # CleanBrowsing
]

DNS_TIMEOUT        = 3.0    # seconds per query
DNS_RETRIES        = 2      # retries on timeout
WILDCARD_TEST_LEN  = 32     # random subdomain length for wildcard detection
WILDCARD_TESTS     = 3      # how many random probes before declaring wildcard

# ─── HTTP ─────────────────────────────────────────────────────────────────────

HTTP_TIMEOUT       = 6      # seconds
HTTP_MAX_REDIRECTS = 5
HTTP_POOL_SIZE     = 100

VALID_STATUS_CODES = {
    200, 201, 204,
    301, 302, 303, 307, 308,
    401, 403,
    405,
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Edge/124.0.0.0 Safari/537.36",
]

# ─── CONCURRENCY ──────────────────────────────────────────────────────────────

DEFAULT_THREADS    = 100
MAX_THREADS        = 800
DEFAULT_DELAY      = 0.0    # seconds between submitting tasks (not per-thread)

# ─── SOURCES ──────────────────────────────────────────────────────────────────

CRT_SH_URL         = "https://crt.sh/?q=%.{domain}&output=json"
WAYBACK_URL        = "http://web.archive.org/cdx/search/cdx?url=*.{domain}&output=text&fl=original&collapse=urlkey"

# ─── OUTPUT ───────────────────────────────────────────────────────────────────

DEFAULT_OUTPUT     = "subdaemon_results"   # extension added by formatter
CHECKPOINT_FILE    = ".subdaemon_checkpoint.json"
RESULTS_DIR        = "subdaemon_output"

# ─── PERMUTATION ──────────────────────────────────────────────────────────────

MUTATION_PREFIXES  = ["dev", "staging", "prod", "api", "test", "beta",
                      "v1", "v2", "old", "new", "admin", "internal"]
MUTATION_SUFFIXES  = ["-dev", "-staging", "-prod", "-api", "-test",
                      "-beta", "-v1", "-v2", "-old", "-new"]
