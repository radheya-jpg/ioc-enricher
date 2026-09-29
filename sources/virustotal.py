"""
VirusTotal source. Handles IPs, domains, and file hashes (MD5/SHA1/SHA256).
Free tier: 4 requests/min, 500/day. Docs: https://developers.virustotal.com/reference
"""

import httpx
import config
import cache
from logger import get_logger
from reliability import with_reliability
from ioc_type import IOCType, is_hash

SOURCE_NAME = "VirusTotal"
log = get_logger("sources.virustotal")


def _endpoint_for(ioc: str, ioc_type: str) -> str:
    base = "https://www.virustotal.com/api/v3"
    if ioc_type == IOCType.IPV4:
        return f"{base}/ip_addresses/{ioc}"
    if ioc_type == IOCType.DOMAIN:
        return f"{base}/domains/{ioc}"
    if is_hash(ioc_type):
        return f"{base}/files/{ioc}"
    return ""


@with_reliability(SOURCE_NAME)
async def check(client: httpx.AsyncClient, ioc: str, ioc_type: str) -> dict:
    url = _endpoint_for(ioc, ioc_type)
    if not url:
        return {"source": SOURCE_NAME, "skipped": True, "reason": "unsupported IOC type"}

    if not config.VT_API_KEY:
        return {"source": SOURCE_NAME, "skipped": True, "reason": "no API key configured"}

    cached = cache.get(SOURCE_NAME, ioc)
    if cached:
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
        }
        cache.set(SOURCE_NAME, ioc, result)
        return result

    resp.raise_for_status()  # lets 429/5xx propagate to the retry decorator
    attrs = resp.json()["data"]["attributes"]
    stats = attrs.get("last_analysis_stats", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values()) or 1
    bad_ratio = (malicious + suspicious) / total

    result = {
        "source": SOURCE_NAME,
        "skipped": False,
        "error": None,
        "malicious": malicious > 0,
        "confidence": round(bad_ratio, 2),
        "summary": f"{malicious} malicious / {suspicious} suspicious / {total} vendors",
        "raw": stats,
    }
    cache.set(SOURCE_NAME, ioc, result)
    return result
