"""
AbuseIPDB source. Only handles IPv4 lookups.
Free tier: 1000 checks/day. Docs: https://docs.abuseipdb.com/
"""

import httpx
import config
import cache
from logger import get_logger
from reliability import with_reliability

SOURCE_NAME = "AbuseIPDB"
log = get_logger("sources.abuseipdb")


@with_reliability(SOURCE_NAME)
async def check(client: httpx.AsyncClient, ioc: str, ioc_type: str) -> dict:
    if ioc_type != "ipv4":
        return {"source": SOURCE_NAME, "skipped": True, "reason": "not an IPv4 address"}

    if not config.ABUSEIPDB_API_KEY:
        return {"source": SOURCE_NAME, "skipped": True, "reason": "no API key configured"}

    cached = cache.get(SOURCE_NAME, ioc)
    if cached:
        cached["from_cache"] = True
        log.debug("cache hit", extra={"ioc": ioc})
        return cached

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ioc, "maxAgeInDays": "90"}

    log.debug("calling API", extra={"ioc": ioc})
    resp = await client.get(url, headers=headers, params=params, timeout=config.REQUEST_TIMEOUT)
    resp.raise_for_status()  # lets 429/5xx propagate to the retry decorator
    data = resp.json()["data"]

    score = data.get("abuseConfidenceScore", 0)
    result = {
        "source": SOURCE_NAME,
        "skipped": False,
        "error": None,
        "malicious": score >= 50,
        "confidence": score / 100,
        "summary": f"Abuse confidence {score}%, {data.get('totalReports', 0)} reports",
        "raw": data,
    }
    cache.set(SOURCE_NAME, ioc, result)
    return result
