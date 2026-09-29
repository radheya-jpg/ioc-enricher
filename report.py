"""
Formats the final enrichment result for humans (rich table) or
machines (JSON), so the tool can be used interactively or piped
into other scripts / Splunk / SIEMs.
"""

from __future__ import annotations


import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

VERDICT_COLORS = {
    "MALICIOUS": "bold red",
    "SUSPICIOUS": "bold yellow",
    "CLEAN": "bold green",
    "UNKNOWN": "bold white",
}


def print_report(ioc: str, ioc_type: str, results: list[dict], verdict: dict):
    color = VERDICT_COLORS.get(verdict["verdict"], "white")

    console.print()
    console.print(Panel.fit(
        f"[{color}]{verdict['verdict']}[/{color}]  (score: {verdict['score']})\n"
        f"{verdict['detail']}",
        title=f"{ioc}  [{getattr(ioc_type, 'value', ioc_type)}]",
        border_style=color.split()[-1],
    ))

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Source")
    table.add_column("Status")
    table.add_column("Malicious?")
    table.add_column("Confidence")
    table.add_column("Summary")

    for r in results:
        source = r["source"]
        if r.get("skipped"):
            table.add_row(source, "skipped", "-", "-", r.get("reason", ""))
        elif r.get("error"):
            table.add_row(source, "[red]error[/red]", "-", "-", r["error"])
        else:
            mal = "[red]YES[/red]" if r["malicious"] else "[green]no[/green]"
            cached_tag = " (cached)" if r.get("from_cache") else ""
            table.add_row(
                source, f"ok{cached_tag}", mal,
                f"{r['confidence']:.2f}", r.get("summary", ""),
            )

    console.print(table)
    console.print()


def to_json(ioc: str, ioc_type: str, results: list[dict], verdict: dict) -> str:
    payload = {
        "ioc": ioc,
        "ioc_type": getattr(ioc_type, "value", ioc_type),
        "verdict": verdict,
        "sources": results,
    }
    return json.dumps(payload, indent=2, default=str)
