"""
Shodan source. IP-only — shows what's exposed on the host (open ports,
banners, known vulns). Shodan doesn't give a "malicious" verdict itself.
Free tier requires a Shodan account (Membership, ~$1 one-time) for API access.

Confidence mapping (v2). Open ports and CVEs describe how EXPOSED a host is,
not whether it is hostile: a legitimate, unpatched web server has both. So:

  * exposure alone gives a small confidence (0.1 up to 0.4) and is NEVER
    reported as malicious=True. That matters because the scorer counts every
    malicious=True source toward its corroboration bonus, and a vulnerable
    server must not look like an independent "flag".
  * Shodan's own tags "malware" or "compromised" are a real signal: confidence
    0.9 and malicious=True.

Tags are read defensively: if a response has none, only the exposure rule applies.
"""

import httpx
import config
import cache
from logger import get_logger
from reliability import with_reliability

SOURCE_NAME = "Shodan"
log = get_logger("sources.shodan")

# Bump when the mapping below changes: cached results from older versions are ignored.
RESULT_VERSION = 2
STRONG_TAGS = {"malware", "compromised"}


def _to_result(data: dict) -> dict:
    """Pure function: Shodan host response -> normalized result."""
    ports = data.get("ports", []) or []
    vulns = data.get("vulns", []) or []
    tags = sorted({str(t).lower() for t in (data.get("tags") or [])})
    strong = sorted(set(tags) & STRONG_TAGS)

    if strong:
        confidence, malicious = 0.9, True
    else:
        confidence = 0.1 + 0.05 * min(len(vulns), 4) + (0.1 if len(ports) >= 8 else 0.0)
        malicious = False

    summary = f"{len(ports)} open ports, {len(vulns)} known CVEs"
    if tags:
        summary += f", tags: {', '.join(tags)}"

    return {
        "source": SOURCE_NAME,
        "skipped": False,
        "error": None,
        "malicious": malicious,
        "confidence": round(confidence, 2),
        "summary": summary,
        "raw": {"ports": ports, "vulns": list(vulns), "tags": tags},
        "_v": RESULT_VERSION,
    }


@with_reliability(SOURCE_NAME)
async def check(client: httpx.AsyncClient, ioc: str, ioc_type: str) -> dict:
    if ioc_type != "ipv4":
        return {"source": SOURCE_NAME, "skipped": True, "reason": "not an IPv4 address"}

    if not config.SHODAN_API_KEY:
        return {"source": SOURCE_NAME, "skipped": True, "reason": "no API key configured"}

    cached = cache.get(SOURCE_NAME, ioc)
    if cached and cached.get("_v") == RESULT_VERSION:
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
            "_v": RESULT_VERSION,
        }
        cache.set(SOURCE_NAME, ioc, result)
        return result

    resp.raise_for_status()  # lets 429/5xx propagate to the retry decorator

    result = _to_result(resp.json())
    cache.set(SOURCE_NAME, ioc, result)
    return result
