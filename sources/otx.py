"""
AlienVault OTX source. Handles IPs, domains, and hashes via pulse data
(community-reported threat intel). Free API key, generous limits.
Docs: https://otx.alienvault.com/api
"""

import httpx
import config
import cache
from logger import get_logger
from reliability import with_reliability
from ioc_type import IOCType, is_hash

SOURCE_NAME = "OTX"
log = get_logger("sources.otx")


def _endpoint_for(ioc: str, ioc_type: str) -> str:
    base = "https://otx.alienvault.com/api/v1/indicators"
    if ioc_type == IOCType.IPV4:
        return f"{base}/IPv4/{ioc}/general"
    if ioc_type == IOCType.DOMAIN:
        return f"{base}/domain/{ioc}/general"
    if is_hash(ioc_type):
        return f"{base}/file/{ioc}/general"
    return ""


@with_reliability(SOURCE_NAME)
async def check(client: httpx.AsyncClient, ioc: str, ioc_type: str) -> dict:
    url = _endpoint_for(ioc, ioc_type)
    if not url:
        return {"source": SOURCE_NAME, "skipped": True, "reason": "unsupported IOC type"}

    if not config.OTX_API_KEY:
        return {"source": SOURCE_NAME, "skipped": True, "reason": "no API key configured"}

    cached = cache.get(SOURCE_NAME, ioc)
    if cached:
        cached["from_cache"] = True
        log.debug("cache hit", extra={"ioc": ioc})
        return cached

    headers = {"X-OTX-API-KEY": config.OTX_API_KEY}

    log.debug("calling API", extra={"ioc": ioc})
    resp = await client.get(url, headers=headers, timeout=config.REQUEST_TIMEOUT)
    resp.raise_for_status()  # lets 429/5xx propagate to the retry decorator
    data = resp.json()

    pulse_count = data.get("pulse_info", {}).get("count", 0)

    result = {
        "source": SOURCE_NAME,
        "skipped": False,
        "error": None,
        "malicious": pulse_count > 0,
        "confidence": min(pulse_count / 10, 1.0),
        "summary": f"Referenced in {pulse_count} threat intel pulses",
        "raw": {"pulse_count": pulse_count},
    }
    cache.set(SOURCE_NAME, ioc, result)
    return result
