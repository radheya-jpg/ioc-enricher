#!/usr/bin/env python
"""
Splunk streaming command: enrich indicators inline from the search bar.

    ... | stats count by src_ip | iocenrich field=src_ip

Adds these fields to each result (prefix is configurable, default "ioc_"):
    ioc_verdict, ioc_score, ioc_confidence, ioc_type, ioc_flagged_by,
    ioc_sources, ioc_sources_used, ioc_adjustments, ioc_detail

Private / loopback / reserved IPs are not looked up (verdict NOT_ROUTABLE):
threat-intel sources know nothing about 192.168.x.x, so spending a rate-limited
API call on them is wasted. Distinct values are enriched once, and at most
`limit` distinct values per search, because free API tiers are slow
(VirusTotal allows about 4 requests per minute).
"""

import asyncio
import ipaddress
import os
import sys

# Vendored dependencies (splunk-sdk, httpx, the enricher itself ...) live in ../lib
APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(APP_DIR, "lib"))

# config.py reads these at import time. pip does not install data files, so point
# the enricher at the copies that ship inside this app (an explicit env var wins).
os.environ.setdefault("IOC_ENRICHER_SCORING_CONFIG", os.path.join(APP_DIR, "default", "scoring.yaml"))
os.environ.setdefault("IOC_ENRICHER_ALLOWLIST", os.path.join(APP_DIR, "default", "allowlist.txt"))

from splunklib.searchcommands import (  # noqa: E402
    Configuration, Option, StreamingCommand, dispatch, validators,
)

MAX_CONCURRENCY = 4  # the per-source token buckets in reliability.py do the real pacing

OUTPUT_FIELDS = ("verdict", "score", "confidence", "type", "flagged_by", "sources",
                 "sources_used", "adjustments", "allowlisted", "detail")


async def enrich_one(client, ioc: str) -> dict:
    """Adapter onto the enricher pipeline (enrich.enrich_one): classify, allowlist
    check, concurrent source checks, scoring. Returns the scorer's verdict dict
    plus the IOC type and a flat per-source summary."""
    from enrich import enrich_one as pipeline  # imported lazily so errors surface per IOC

    _, ioc_type, _results, verdict = await pipeline(client, ioc)
    out = dict(verdict)
    out["type"] = str(getattr(ioc_type, "value", ioc_type))
    out["sources"] = [f"{c['source']}={c['confidence']}" for c in verdict.get("contributions", [])]
    return out


def _is_routable(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return True  # not an IP address (domain or hash): let the pipeline decide


async def _enrich_all(iocs):
    import httpx

    sem = asyncio.Semaphore(MAX_CONCURRENCY)

    async with httpx.AsyncClient() as client:
        async def run(ioc):
            async with sem:
                if not _is_routable(ioc):
                    return ioc, {"verdict": "NOT_ROUTABLE",
                                 "detail": "private or reserved address, not looked up"}
                try:
                    return ioc, await enrich_one(client, ioc)
                except Exception as exc:  # one bad IOC must not kill the whole search
                    return ioc, {"verdict": "ERROR", "detail": f"{type(exc).__name__}: {exc}"}

        return dict(await asyncio.gather(*(run(i) for i in iocs)))


@Configuration(local=True)  # run on the search head only, never on indexers
class IOCEnrichCommand(StreamingCommand):
    field = Option(require=True, validate=validators.Fieldname(),
                   doc="Field holding the IOC (IPv4, domain or hash).")
    prefix = Option(default="ioc_",
                    validate=validators.Match("prefix", r"^[A-Za-z_][A-Za-z0-9_]*$"),
                    doc="Prefix for the output fields.")
    limit = Option(default=25, validate=validators.Integer(minimum=1, maximum=500),
                   doc="Maximum distinct IOCs to look up per search.")

    def stream(self, records):
        try:  # JSON log file if IOC_ENRICHER_LOG_FILE is set; warnings go to search.log
            import logger as enricher_logging
            enricher_logging.configure()
        except Exception:
            pass

        records = list(records)
        values = {str(r[self.field]).strip() for r in records if r.get(self.field)}
        ordered = sorted(values)
        to_lookup, over_limit = ordered[: self.limit], ordered[self.limit:]

        if over_limit:
            self.write_warning(
                f"{len(ordered)} distinct values; enriching the first {self.limit}. "
                "Narrow the search (for example '| sort -count | head 10') or raise limit=."
            )

        results = asyncio.run(_enrich_all(to_lookup)) if to_lookup else {}
        for value in over_limit:
            results[value] = {"verdict": "SKIPPED_LIMIT",
                              "detail": f"over limit={self.limit} for this search"}

        for record in records:
            res = results.get(str(record.get(self.field, "")).strip())
            if res:
                for key in OUTPUT_FIELDS:
                    if res.get(key) not in (None, [], ""):
                        record[self.prefix + key] = res[key]
            yield record


if __name__ == "__main__":
    dispatch(IOCEnrichCommand, sys.argv, sys.stdin, sys.stdout, __name__)
