"""
Central config for IOC Enricher.
API keys are read from environment variables so nothing sensitive
ever gets hardcoded or committed to git.

Set them like:
    export ABUSEIPDB_API_KEY="xxx"
    export VT_API_KEY="xxx"
    export SHODAN_API_KEY="xxx"
    export OTX_API_KEY="xxx"
"""

import os
from pathlib import Path

# --- API Keys (None if not set -> that source is skipped gracefully) ---
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")

# --- Cache settings ---
CACHE_DIR = Path.home() / ".ioc_enricher_cache"
CACHE_TTL_HOURS = 12  # how long before we re-query a source for the same IOC

# --- HTTP settings ---
REQUEST_TIMEOUT = 15  # seconds per API call

# --- Logging ---
# Set to a path (e.g. "logs/ioc_enricher.jsonl") to enable structured JSON
# file logging in addition to console output. None disables file logging.
LOG_FILE = os.getenv("IOC_ENRICHER_LOG_FILE")

# --- Retry / backoff tuning ---
# Tests set IOC_ENRICHER_FAST_RETRY=1 (see conftest.py) to shrink these to
# near-zero so the suite doesn't spend real wall-clock time retrying mocks.
_fast_retry = os.getenv("IOC_ENRICHER_FAST_RETRY") == "1"
RETRY_ATTEMPTS = 2 if _fast_retry else 3
RETRY_MIN_WAIT = 0.01 if _fast_retry else 1
RETRY_MAX_WAIT = 0.02 if _fast_retry else 10

# --- Scoring config ---
# Path to the YAML file holding source weights + verdict thresholds.
# Lets scoring be retuned without touching code. See scoring.yaml for format.
SCORING_CONFIG_PATH = os.getenv(
    "IOC_ENRICHER_SCORING_CONFIG",
    str(Path(__file__).parent / "scoring.yaml"),
)

# --- Batch mode ---
# How many IOCs to enrich concurrently in --batch mode. Per-source rate
# limiters (see reliability.py) are shared and global, so this doesn't
# bypass them — it just controls how many IOCs are "in flight" at once,
# which keeps memory/connection usage sane on large batch files.
BATCH_CONCURRENCY = int(os.getenv("IOC_ENRICHER_BATCH_CONCURRENCY", "8"))

# --- Cache backend ---
# "file" (default): one JSON file per cached entry, simplest, fine for
#   normal single-analyst use.
# "sqlite": single SQLite db, better for high-volume/batch use since it
#   avoids thousands of small files and supports proper concurrent access.
CACHE_BACKEND = os.getenv("IOC_ENRICHER_CACHE_BACKEND", "file")
SQLITE_CACHE_PATH = os.getenv(
    "IOC_ENRICHER_SQLITE_CACHE_PATH",
    str(Path.home() / ".ioc_enricher_cache.db"),
)

# --- Allowlist ---
# Known-benign IPs/domains (public DNS resolvers, major CDNs) that get
# force-marked CLEAN regardless of what threat-intel sources report.
# See allowlist.txt and allowlist.py for details on why this exists.
ALLOWLIST_PATH = os.getenv(
    "IOC_ENRICHER_ALLOWLIST",
    str(Path(__file__).parent / "allowlist.txt"),
)
