# IOC Enricher — Setup

## 1. Install
```bash
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## 2. Get API keys (free tiers, use whichever you have)
- AbuseIPDB: https://www.abuseipdb.com/register
- VirusTotal: https://www.virustotal.com/gui/join-us
- Shodan: https://account.shodan.io/register
- OTX (AlienVault): https://otx.alienvault.com

## 3. Set keys as environment variables
```bash
export ABUSEIPDB_API_KEY="..."
export VT_API_KEY="..."
export SHODAN_API_KEY="..."
export OTX_API_KEY="..."
```
Only sources with a key set will run — the rest show as "skipped" gracefully.

## 4. Run it
```bash
python3 enrich.py 8.8.8.8
python3 enrich.py evil-domain.com --json
python3 enrich.py <hash> --json > report.json
python3 enrich.py --batch iocs.txt                        # one IOC per line, processed concurrently
python3 enrich.py --batch iocs.txt --csv results.csv       # + write a CSV summary
python3 enrich.py 8.8.8.8 --verbose                        # show debug logs (API calls, cache hits, retries) on stderr
python3 enrich.py 8.8.8.8 --log-file logs/enrich.jsonl     # structured JSON logs for SIEM ingestion
```

## Installing as a real CLI command
```bash
pip install -e .
ioc-enrich 8.8.8.8    # now works from anywhere, not just this folder
```

## Running with Docker
```bash
docker build -t ioc-enricher .
docker run --rm -e ABUSEIPDB_API_KEY="..." ioc-enricher 8.8.8.8
```

## Reliability features (built-in, no config needed)
- **Rate limiting**: each source is paced to stay within its free-tier limit automatically — you'll never get blocked for going too fast.
- **Retry with backoff**: transient failures (429 rate-limit, 5xx server errors, timeouts) are retried up to 3 times with exponential backoff. Non-transient errors (bad API key, malformed request) are NOT retried.
- **Circuit breaker**: if a source fails 5 times in a row, it's skipped for 60 seconds instead of being hammered further.

## Tuning the scoring (no code changes needed)
Edit `scoring.yaml` to change how much each source is trusted, or where the MALICIOUS/SUSPICIOUS thresholds sit:
```yaml
source_weights:
  VirusTotal: 1.2   # trust VT more
thresholds:
  malicious: 0.7
  suspicious: 0.35
```
If the file is missing or malformed, the tool falls back to safe built-in defaults and logs a warning — it never crashes on a bad config edit.

## Allowlist (prevents false positives on known-good infrastructure)
Community threat-intel feeds like OTX count how often something is *mentioned* in a threat report, not how often it's *actually* malicious — so popular infrastructure (public DNS resolvers, major CDNs) can get flagged SUSPICIOUS just for being widely used. `allowlist.txt` holds known-benign IPs/domains that skip source checks entirely and are force-marked CLEAN. Edit it to add your own trusted infrastructure:
```
# one IP or domain per line, comments start with #
8.8.8.8
your-internal-domain.com
```
Domain entries also match subdomains (`google.com` covers `mail.google.com`). Hashes are never allowlisted.

## Cache backend (for higher volume / batch use)
```bash
export IOC_ENRICHER_CACHE_BACKEND="sqlite"   # default is "file"
```
File backend (default) is fine for normal single-analyst use. SQLite is better for large batch runs — avoids creating thousands of tiny cache files and handles concurrent access more safely.

## Batch concurrency
```bash
export IOC_ENRICHER_BATCH_CONCURRENCY="8"    # default is 8
```
Controls how many IOCs are processed at once in `--batch` mode. Per-source rate limits are global regardless of this setting — it just bounds memory/connection usage on large batch files.

## 5. Run the test suite (no API keys needed — fully mocked)
```bash
python3 -m pytest -v
```
