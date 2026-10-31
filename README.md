# IOC Enricher for Splunk

Adds `| iocenrich field=<field>` to Splunk search, plus a sourcetype for the enricher JSON log.
Tested end to end through Splunk chunked protocol with stub sources; not yet tested inside a real Splunk instance.

## 1. Prepare the project (once)
- Use the patched `enrich.py` (passes the IOC type to the scorer, adds `--dump-dataset`).
- Use the patched `pyproject.toml`: `allowlist` was missing from `py-modules`, so an installed `ioc-enrich` would fail with ModuleNotFoundError.
- Copy your `scoring.yaml` (already in `default/`) and `allowlist.txt` next to each other in `default/`. pip does not install data files, and the command points the enricher at these copies.

## 2. Vendor dependencies into lib/
Splunk runs the command with its own bundled Python, so dependencies must ship inside the app.

    $SPLUNK_HOME/bin/splunk cmd python --version        # note the version, probably 3.9
    cd ioc_enricher
    pip install --target lib splunk-sdk
    pip install --target lib --python-version 3.9 --only-binary=:all: httpx click rich tenacity pyyaml
    pip install --target lib --no-deps /path/to/ioc-enricher   # folder containing pyproject.toml
    cp /path/to/ioc-enricher/allowlist.txt default/

Use the version printed on the first line for --python-version. Newer click and rich releases drop old Pythons.

## 3. API keys
Splunk child processes inherit the environment of splunkd. Add one NAME=value per line to
$SPLUNK_HOME/etc/splunk-launch.conf, then restart Splunk:

    ABUSEIPDB_API_KEY=...
    VT_API_KEY=...
    SHODAN_API_KEY=...
    OTX_API_KEY=...
    IOC_ENRICHER_LOG_FILE=/absolute/path/ioc_enricher.jsonl     # optional, for telemetry (step 6)

Do not commit keys. The cache lives in ~/.ioc_enricher_cache of the user running Splunk, which must be writable.

## 4. Install
Copy the ioc_enricher folder to $SPLUNK_HOME/etc/apps/ and restart Splunk. If a command fails, check the
search job inspector (search.log); per-IOC failures also show up as ioc_verdict=ERROR with the reason in ioc_detail.

## 5. Try it (no log data needed)

    | makeresults
    | eval ioc=split("8.8.8.8,185.220.101.7,192.168.1.10,example.com", ",")
    | mvexpand ioc
    | iocenrich field=ioc
    | table ioc ioc_verdict ioc_score ioc_confidence ioc_flagged_by ioc_sources ioc_adjustments

Real use:

    index=main sourcetype=access_combined
    | stats count by clientip
    | sort -count | head 10
    | iocenrich field=clientip
    | where ioc_verdict IN ("MALICIOUS","SUSPICIOUS")

Notes: private IPs return NOT_ROUTABLE without an API call; allowlisted values return CLEAN; at most limit=25
distinct values are looked up per search (VirusTotal free tier is about 4 requests per minute, and results are cached).

## 6. Enricher telemetry and history
Set IOC_ENRICHER_LOG_FILE, then add that file as a monitor input (Settings > Add Data > Monitor) with sourcetype
ioc_enricher:json. The pipeline already logs one "verdict reached" event per lookup (ioc, ioc_type, verdict, score,
confidence, flagged_by), so you get history for free:

    sourcetype=ioc_enricher:json message="verdict reached" | timechart count by verdict
    sourcetype=ioc_enricher:json message="verdict reached" verdict=MALICIOUS | stats count by ioc
    sourcetype=ioc_enricher:json message="circuit breaker opened" | timechart count by source
    sourcetype=ioc_enricher:json message="source call failed after retries" | stats count by source error

## 7. Tune the scoring with real data
    ioc-enrich --batch bad.txt  --label malicious --dump-dataset dataset.jsonl
    ioc-enrich --batch good.txt --label benign    --dump-dataset dataset.jsonl
    python evaluate.py dataset.jsonl

Allowlisted IOCs are skipped in the dump, so pick benign examples that are not on allowlist.txt.
Known-bad IPs from public blocklists are also what AbuseIPDB and VirusTotal learn from, so recall will look
better than it would on fresh indicators. Say so in the writeup.
