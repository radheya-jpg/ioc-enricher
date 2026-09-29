"""
Shodan source. IP-only — shows what's exposed on the host (open ports,
banners, known vulns). Shodan doesn't give a "malicious" verdict itself,
so we treat "lots of exposed services / known CVEs" as a risk signal.
Free tier requires a Shodan account (Membership, ~$1 one-time) for API access.
"""

import httpx
import config
import cache
from logger import get_logger
from reliability import with_reliability

SOURCE_NAME = "Shodan"
log = get_logger("sources.shodan")


@with_reliability(SOURCE_NAME)
async def check(client: httpx.AsyncClient, ioc: str, ioc_type: str) -> dict:
    if ioc_type != "ipv4":
        return {"source": SOURCE_NAME, "skipped": True, "reason": "not an IPv4 address"}

    if not config.SHODAN_API_KEY:
        return {"source": SOURCE_NAME, "skipped": True, "reason": "no API key configured"}

    cached = cache.get(SOURCE_NAME, ioc)
    if cached:
        cached["from_cache"] = True
        log.debug("cache hit", extra={"ioc": ioc})
        return cached

    url = f"https://api.shodan.io/shodan/host/{ioc}"
    params = {"key": config.SHODAN_API_KEY}

    log.debug("calling API", extra={"ioc": ioc})
    resp = await client.get(url, params=params, timeout=config.REQUEST_TIMEOUT)

    if resp.status_code == 404:
        result = {
            "source": SOURCE_NAME, "skipped": False, "error": None,
            "malicious": False, "confidence": 0.0,
            "summary": "No Shodan data (host not indexed)", "raw": {},
        }
        cache.set(SOURCE_NAME, ioc, result)
        return result

    resp.raise_for_status()  # lets 429/5xx propagate to the retry decorator
    data = resp.json()

    ports = data.get("ports", [])
    vulns = data.get("vulns", [])
    risky = bool(vulns) or len(ports) >= 8

    result = {
        "source": SOURCE_NAME,
        "skipped": False,
        "error": None,
        "malicious": risky,
        "confidence": 0.6 if risky else 0.1,
        "summary": f"{len(ports)} open ports, {len(vulns)} known CVEs",
        "raw": {"ports": ports, "vulns": list(vulns)},
    }
    cache.set(SOURCE_NAME, ioc, result)
    return result
