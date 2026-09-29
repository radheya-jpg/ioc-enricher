"""
Loads the allowlist and checks whether a given IOC matches it.

Domains match subdomains (an entry for "google.com" also covers
"mail.google.com"). IPs must match exactly. Hashes are never
allowlisted — a specific file being known-good isn't the same kind
of durable judgment as "this is Google's infrastructure."
"""

from __future__ import annotations

import config
from logger import get_logger

log = get_logger("allowlist")

_cache: set | None = None


def _load() -> set:
    path = config.ALLOWLIST_PATH
    entries = set()
    try:
        with open(path) as f:
            for line in f:
                line = line.strip().lower()
                if not line or line.startswith("#"):
                    continue
                entries.add(line)
        log.debug("loaded allowlist", extra={"path": path, "entries": len(entries)})
    except FileNotFoundError:
        log.warning("allowlist file not found, allowlist disabled", extra={"path": path})
    return entries


def _get_entries() -> set:
    global _cache
    if _cache is None:
        _cache = _load()
    return _cache


def reload():
    """Re-reads the allowlist file from disk. Call after editing it
    without restarting a long-running process."""
    global _cache
    _cache = _load()


def is_allowlisted(ioc: str, ioc_type) -> bool:
    entries = _get_entries()
    ioc_lower = ioc.strip().lower()

    ioc_type_str = str(getattr(ioc_type, "value", ioc_type))

    if ioc_type_str == "ipv4":
        return ioc_lower in entries

    if ioc_type_str == "domain":
        # exact match, or the IOC is a subdomain of an allowlisted domain
        if ioc_lower in entries:
            return True
        return any(ioc_lower.endswith("." + entry) for entry in entries)

    return False  # hashes are never allowlisted
