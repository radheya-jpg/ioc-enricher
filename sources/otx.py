"""
AlienVault OTX source. Handles IPs, domains, and hashes via pulse data
(community-reported threat intel). Free API key, generous limits.
Docs: https://otx.alienvault.com/api

Confidence mapping (v2). A pulse count measures how often an indicator is
MENTIONED, not how often it is malicious: widely used infrastructure (CDNs,
resolvers, Tor exit nodes) collects mentions simply by being popular. So:

  * pulses attributed to a malware family, adversary or ATT&CK technique count
    fully; plain mentions count 0.2 each, but plain mentions can contribute at
    most MENTION_EVIDENCE_CAP in total, so a domain mentioned in thousands of
    pulses (example.com, big CDNs) can never look malicious from mentions alone
  * evidence passes through a saturating curve (no more "10 pulses = 1.0")
  * if OTX's own validation data marks the indicator as whitelisted / a top
    domain, confidence is capped at 0.1 and it is never flagged

malicious=True only when this source would call the indicator bad itself
(confidence >= 0.5), so mere mentions do not count as an independent flag in
the scorer's corroboration bonus.

The attribution fields (adversary, malware_families, attack_ids) are read
defensively: if a response does not contain them, every pulse counts as a plain
mention and the source simply behaves more cautiously.
"""

import math

import httpx
import config
import cache
from logger import get_logger
from reliability import with_reliability
from ioc_type import IOCType, is_hash

SOURCE_NAME = "OTX"
log = get_logger("sources.otx")

# Bump when the mapping below changes: cached results from older versions are ignored.
RESULT_VERSION = 3
MENTION_WEIGHT = 0.2
MENTION_EVIDENCE_CAP = 3.0  # plain mentions alone give at most ~0.31 confidence
EVIDENCE_SCALE = 8.0
FLAG_CONFIDENCE = 0.5
WHITELIST_CAP = 0.1


def _endpoint_for(ioc: str, ioc_type: str) -> str:
    base = "https://otx.alienvault.com/api/v1/indicators"
    if ioc_type == IOCType.IPV4:
        return f"{base}/IPv4/{ioc}/general"
    if ioc_type == IOCType.DOMAIN:
        return f"{base}/domain/{ioc}/general"
    if is_hash(ioc_type):
        return f"{base}/file/{ioc}/general"
    return ""


def _is_whitelisted(data: dict) -> bool:
    for entry in data.get("validation") or []:
        if isinstance(entry, dict):
            text = " ".join(str(entry.get(k, "")) for k in ("source", "name", "message"))
        else:
            text = str(entry)
        text = text.lower()
        if "whitelist" in text or "alexa" in text:
            return True
    return False


def _to_result(data: dict) -> dict:
    """Pure function: OTX 'general' response -> normalized result."""
    info = data.get("pulse_info") or {}
    pulses = info.get("pulses") or []
    count = info.get("count", len(pulses)) or 0

    attributed = sum(
        1 for p in pulses
        if isinstance(p, dict) and (p.get("adversary") or p.get("malware_families") or p.get("attack_ids"))
    )
    attributed = min(attributed, count)
    mentions = count - attributed

    evidence = attributed + min(MENTION_WEIGHT * mentions, MENTION_EVIDENCE_CAP)
    confidence = 1 - math.exp(-evidence / EVIDENCE_SCALE)

    whitelisted = _is_whitelisted(data)
    if whitelisted:
        confidence = min(confidence, WHITELIST_CAP)

    summary = f"Referenced in {count} threat intel pulses ({attributed} attributed to a malware family or adversary)"
    if whitelisted:
        summary += "; OTX lists it as whitelisted / a top domain"

    return {
        "source": SOURCE_NAME,
        "skipped": False,
        "error": None,
        "malicious": (not whitelisted) and confidence >= FLAG_CONFIDENCE,
        "confidence": round(confidence, 2),
        "summary": summary,
        "raw": {"pulse_count": count, "attributed_pulses": attributed, "whitelisted": whitelisted},
        "_v": RESULT_VERSION,
    }


@with_reliability(SOURCE_NAME)
async def check(client: httpx.AsyncClient, ioc: str, ioc_type: str) -> dict:
    url = _endpoint_for(ioc, ioc_type)
    if not url:
        return {"source": SOURCE_NAME, "skipped": True, "reason": "unsupported IOC type"}

    if not config.OTX_API_KEY:
        return {"source": SOURCE_NAME, "skipped": True, "reason": "no API key configured"}

    cached = cache.get(SOURCE_NAME, ioc)
    if cached and cached.get("_v") == RESULT_VERSION:
        cached["from_cache"] = True
        log.debug("cache hit", extra={"ioc": ioc})
        return cached

    headers = {"X-OTX-API-KEY": config.OTX_API_KEY}

    log.debug("calling API", extra={"ioc": ioc})
    resp = await client.get(url, headers=headers, timeout=config.REQUEST_TIMEOUT)
    resp.raise_for_status()  # lets 429/5xx propagate to the retry decorator

    result = _to_result(resp.json())
    cache.set(SOURCE_NAME, ioc, result)
    return result