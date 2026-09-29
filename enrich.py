#!/usr/bin/env python3
"""
IOC Enricher — check an IP, domain, or file hash against multiple
threat intel sources at once and get back a single combined verdict.

Usage:
    python enrich.py 8.8.8.8
    python enrich.py evil-domain.com --json
    python enrich.py <sha256hash> --json > report.json
    python enrich.py --batch iocs.txt
    python enrich.py --batch iocs.txt --csv results.csv
"""

from __future__ import annotations
import asyncio
import csv
import sys
import click
import httpx

import config
from ioc_type import classify, IOCType
import scorer
import allowlist
import report as report_mod
import logger as logger_mod
from sources import abuseipdb, virustotal, shodan, otx

ALL_SOURCES = [abuseipdb, virustotal, shodan, otx]
log = logger_mod.get_logger("enrich")


async def enrich_one(client: httpx.AsyncClient, ioc: str):
    ioc_type = classify(ioc)
    log.info("enriching IOC", extra={"ioc": ioc, "ioc_type": str(getattr(ioc_type, "value", ioc_type))})

    if ioc_type == IOCType.UNKNOWN:
        log.warning("could not classify IOC", extra={"ioc": ioc})
        return ioc, ioc_type, [], {
            "verdict": "UNKNOWN", "score": 0.0, "sources_used": 0,
            "sources_total": 0, "detail": "Could not classify input as IP, domain, or hash.",
        }

    if allowlist.is_allowlisted(ioc, ioc_type):
        log.info("IOC is allowlisted, skipping source checks", extra={"ioc": ioc})
        return ioc, ioc_type, [], {
            "verdict": "CLEAN", "score": 0.0, "sources_used": 0, "sources_total": 0,
            "flagged_by": [], "allowlisted": True,
            "detail": "Allowlisted known-benign infrastructure — source checks skipped.",
        }

    # fan out to every source concurrently — this is the whole point
    tasks = [src.check(client, ioc, ioc_type) for src in ALL_SOURCES]
    results = await asyncio.gather(*tasks)

    verdict = scorer.score(results)
    log.info("verdict reached", extra={"ioc": ioc, "verdict": verdict["verdict"], "score": verdict["score"]})
    return ioc, ioc_type, results, verdict


async def _enrich_bounded(client: httpx.AsyncClient, ioc: str, semaphore: asyncio.Semaphore):
    """Wraps enrich_one with a concurrency limit. Per-source rate limiters
    are global/shared regardless of this limit — this just caps how many
    IOCs are in flight at once, keeping connection/memory usage sane on
    large batch files."""
    async with semaphore:
        return await enrich_one(client, ioc)


def _write_csv_summary(path: str, rows: list[tuple]):
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["ioc", "ioc_type", "verdict", "score", "sources_used", "sources_total", "flagged_by"])
        for ioc, ioc_type, results, verdict in rows:
            writer.writerow([
                ioc,
                str(getattr(ioc_type, "value", ioc_type)),
                verdict["verdict"],
                verdict["score"],
                verdict.get("sources_used", 0),
                verdict.get("sources_total", 0),
                ";".join(verdict.get("flagged_by", []) or []),
            ])
    log.info("wrote CSV summary", extra={"path": path, "rows": len(rows)})


async def run(iocs: list[str], as_json: bool, csv_path: str = None):
    semaphore = asyncio.Semaphore(config.BATCH_CONCURRENCY)

    async with httpx.AsyncClient() as client:
        tasks = [_enrich_bounded(client, ioc, semaphore) for ioc in iocs]
        # gather preserves input order regardless of completion order,
        # so output (and any CSV) lines up with the input file line-for-line
        all_results = await asyncio.gather(*tasks)

    for ioc, ioc_type, results, verdict in all_results:
        if as_json:
            print(report_mod.to_json(ioc, ioc_type, results, verdict))
        else:
            report_mod.print_report(ioc, ioc_type, results, verdict)

    if csv_path:
        _write_csv_summary(csv_path, all_results)


@click.command()
@click.argument("ioc", required=False)
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON instead of a table.")
@click.option("--batch", type=click.Path(exists=True), help="Path to a text file, one IOC per line.")
@click.option("--csv", "csv_path", type=click.Path(), help="Write a CSV summary (one row per IOC). Most useful with --batch.")
@click.option("--verbose", is_flag=True, help="Show debug-level logs on stderr (API calls, cache hits, retries).")
@click.option("--log-file", type=click.Path(), help="Write structured JSON logs to this file (all levels).")
def main(ioc, as_json, batch, csv_path, verbose, log_file):
    """Check IOC (an IP / domain / hash) against multiple threat intel sources."""
    logger_mod.configure(verbose=verbose, log_file=log_file)

    if not ioc and not batch:
        click.echo("Usage: enrich.py <ioc> [--json] | --batch <file> [--csv results.csv]")
        sys.exit(1)

    if batch:
        with open(batch) as f:
            iocs = [line.strip() for line in f if line.strip()]
    else:
        iocs = [ioc]

    asyncio.run(run(iocs, as_json, csv_path))


if __name__ == "__main__":
    main()
