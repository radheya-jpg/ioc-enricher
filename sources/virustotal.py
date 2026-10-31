"""
VirusTotal source. Handles IPs, domains, and file hashes (MD5/SHA1/SHA256).
Free tier: 4 requests/min, 500/day. Docs: https://developers.virustotal.com/reference

Confidence mapping (v2): based on the NUMBER of engines that flag the
indicator, not the share of all engines. VirusTotal runs ~90 engines and most
never flag anything, so a ratio (10 flagged / 92 = 0.11) badly understates a
strong signal. Suspicious verdicts count half. The count is passed through a
saturating curve:

    detections:   0     1     2     3     5     10    20
    confidence:  0.00  0.18  0.33  0.45  0.63  0.86  0.98

A source only reports malicious=True when it would call the indicator bad
itself (MIN_DETECTIONS_TO_FLAG engines or more). A single engine hit is a
common false positive and must not count as an independent "flag" when the
scorer applies its corroboration bonus.
"""

import math

import httpx
import config
import cache
from logger import get_logger
from reliability import with_reliability
from ioc_type import IOCType, is_hash

SOURCE_NAME = "VirusTotal"
log = get_logger("sources.virustotal")

# Bump when the mapping below changes: cached results from older versions are ignored.
RESULT_VERSION = 2
MIN_DETECTIONS_TO_FLAG = 3
DETECTION_SCALE = 5.0  # larger = needs more engines to reach high confidence


def _endpoint_for(ioc: str, ioc_type: str) -> str:
    base = "https://www.virustotal.com/api/v3"
    if ioc_type == IOCType.IPV4:
        return f"{base}/ip_addresses/{ioc}"
    if ioc_type == IOCType.DOMAIN:
        return f"{base}/domains/{ioc}"
    if is_hash(ioc_type):
        return f"{base}/files/{ioc}"
    return ""


def _to_result(stats: dict) -> dict:
    """Pure function: VirusTotal last_analysis_stats -> normalized result."""
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values()) or 1
    detections = malicious + 0.5 * suspicious
    confidence = 1 - math.exp(-detections / DETECTION_SCALE)

    return {
        "source": SOURCE_NAME,
        "skipped": False,
        "error": None,
        "malicious": detections >= MIN_DETECTIONS_TO_FLAG,
        "confidence": round(confidence, 2),
        "summary": f"{malicious} malicious / {suspicious} suspicious / {total} vendors",
        "raw": stats,
        "_v": RESULT_VERSION,
    }


@with_reliability(SOURCE_NAME)
async def check(client: httpx.AsyncClient, ioc: str, ioc_type: str) -> dict:
    url = _endpoint_for(ioc, ioc_type)
    if not url:
        return {"source": SOURCE_NAME, "skipped": True, "reason": "unsupported IOC type"}

    if not config.VT_API_KEY:
        return {"source": SOURCE_NAME, "skipped": True, "reason": "no API key configured"}

    cached = cache.get(SOURCE_NAME, ioc)
    if cached and cached.get("_v") == RESULT_VERSION:
        cached["from_cache"] = True
        log.debug("cache hit", extra={"ioc": ioc})
        return cached

    headers = {"x-apikey": config.VT_API_KEY}

    log.debug("calling API", extra={"ioc": ioc})
    resp = await client.get(url, headers=headers, timeout=config.REQUEST_TIMEOUT)

    if resp.status_code == 404:
        result = {
            "source": SOURCE_NAME, "skipped": False, "error": None,
            "malicious": False, "confidence": 0.0,
            "summary": "Not found in VirusTotal (no history)", "raw": {},
            "_v": RESULT_VERSION,
        }
        cache.set(SOURCE_NAME, ioc, result)
        return result

    resp.raise_for_status()  # lets 429/5xx propagate to the retry decorator
    stats = resp.json()["data"]["attributes"].get("last_analysis_stats", {})

    result = _to_result(stats)
    cache.set(SOURCE_NAME, ioc, result)
    return result
