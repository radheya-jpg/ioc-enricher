# IOC Enricher

A Python command-line tool that takes one Indicator of Compromise (IP address, domain, URL or file hash), asks several public threat intelligence services about it, and combines their answers into a single score and verdict. It can also be used inside Splunk as a custom search command.

Mini Project (BSC4PR05A), B.Sc. Computer Science (Cybersecurity Honours), MIT World Peace University, Pune, 2026-27.

**Authors:** Radheya Shahane and Zawiya Anant

## Why

Analysts normally check one indicator by opening several portals by hand and comparing the answers in their heads. This is slow, and two analysts can reach different conclusions from the same data. IOC Enricher does the lookups together and applies written, adjustable scoring rules so the result is consistent.

## Features

- Automatic indicator type detection (IP, domain, URL, hash), no flags needed
- Queries VirusTotal, AlienVault OTX, Shodan and AbuseIPDB; a source without an API key is skipped and labelled
- Weighted scoring with weights, thresholds, type weights, a corroboration bonus and a strong-signal floor kept in `scoring.yaml`
- Verdicts: `CLEAN`, `suspicious`, `MALICIOUS`, `NOT_ROUTABLE` (private addresses)
- Colour terminal output with a verdict panel and a per-source table
- Retry with back-off, caching, and one JSON log line per run
- Splunk search command: `| iocenrich field=<name>`
- Evaluation script that prints precision, recall, F1, a threshold sweep and a source ablation over a labelled IOC set

## Project layout

| Module | Role |
|---|---|
| `enrich` | Orchestrates one lookup |
| `config` | Reads environment variables and YAML settings |
| `ioc_type` | Detects the indicator type |
| `sources/` | One module per threat intelligence service |
| `cache`, `reliability` | Caching, retries and back-off |
| `scorer` | Turns per-source confidence values into a score and verdict using `scoring.yaml` |
| `report` | Rich terminal output |
| `logger` | Appends JSON lines to the log file |

## Installation

Requires Python 3 and at least one API key. More keys mean more sources in the verdict.

```bash
git clone <repository-url>
cd <repository-folder>
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

Dependencies: httpx, click, rich, tenacity, PyYAML.

## Configuration

API keys are read from environment variables, never from source code.

```bash
export VT_API_KEY=<your-key-here>
export OTX_API_KEY=<your-key-here>
export SHODAN_API_KEY=<your-key-here>
```

Do not commit real keys. If a key is exposed anywhere, regenerate it.

## Usage

```bash
ioc-enrich 8.8.8.8
ioc-enrich evil-domain.com
ioc-enrich 44d88612fea8a8f36de82e1278abb02f
ioc-enrich --help
```

The output has a verdict panel (verdict, score, how many sources flagged the indicator) and a table with one row per source: status, the source's own opinion, confidence from 0.00 to 1.00, and a one-line summary. Do not over-trust a clean verdict that comes from a single source.

## Splunk

With the tool installed on the same host as Splunk, the enrichment is available as a search command:

```
| makeresults
| eval ioc=split("8.8.8.8,185.220.101.7,192.168.1.10,example.com", ",")
| mvexpand ioc
| iocenrich field=ioc
| table ioc ioc_verdict ioc_score ioc_confidence ioc_flagged_by ioc_sources ioc_adjustments
```

The JSON log file can be added as a monitored input to analyse verdicts over time.

## Scoring

Each source returns a confidence between 0 and 1. The scorer combines them with a weighted average, using source weights from `scoring.yaml`, then applies type weights, a corroboration bonus and a strong-signal floor. Thresholds in the same file map the score to a verdict. Edit `scoring.yaml` to change how much each source is trusted.

## Evaluation

On a small labelled set of 6 indicators (5 malicious, 1 benign), the current `scoring.yaml` gives precision 1.00, recall 1.00 and F1 1.00. This set is small, so treat the result as a sanity check and not as proof of general accuracy.

## Troubleshooting

| Symptom | What to do |
|---|---|
| `skipped: no API key configured` | Set that source's environment variable in the current terminal |
| `skipped: not an IPv4 address` | Expected for domains, URLs and hashes on IP-only sources |
| Slow run or repeated failures | Check the connection; a free-tier limit may have been reached |

## Limitations

Free-tier API rate limits apply, and the labelled evaluation set is small. See the project report for the full discussion and future enhancements.

## References

VirusTotal, AlienVault OTX, Shodan and AbuseIPDB API documentation; Splunk developer documentation on custom search commands; HTTPX documentation.
