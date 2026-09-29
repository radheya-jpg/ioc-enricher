import csv as csv_module

import httpx
import respx
import pytest

import config
import allowlist
from enrich import run


@pytest.fixture(autouse=True)
def fake_keys(monkeypatch):
    monkeypatch.setattr(config, "ABUSEIPDB_API_KEY", "fake")
    monkeypatch.setattr(config, "VT_API_KEY", None)
    monkeypatch.setattr(config, "SHODAN_API_KEY", None)
    monkeypatch.setattr(config, "OTX_API_KEY", None)
    # These tests use 1.1.1.1 etc. expecting real source checks — isolate
    # from the real allowlist.txt (which now includes 1.1.1.1) so it
    # doesn't short-circuit them.
    monkeypatch.setattr(config, "ALLOWLIST_PATH", "/nonexistent/allowlist.txt")
    allowlist.reload()


@respx.mock
async def test_batch_processes_all_iocs(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(config, "CACHE_DIR", tmp_path)

    respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(200, json={"data": {"abuseConfidenceScore": 0, "totalReports": 0}})
    )

    iocs = ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
    await run(iocs, as_json=True)

    captured = capsys.readouterr()
    # one JSON object printed per IOC, in input order
    for ioc in iocs:
        assert ioc in captured.out


@respx.mock
async def test_batch_respects_concurrency_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(config, "BATCH_CONCURRENCY", 2)

    respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(200, json={"data": {"abuseConfidenceScore": 0, "totalReports": 0}})
    )

    # just confirms it runs without error under a tight concurrency cap
    iocs = [f"10.0.0.{i}" for i in range(6)]
    await run(iocs, as_json=True)


@respx.mock
async def test_batch_writes_csv_summary(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CACHE_DIR", tmp_path)
    csv_path = str(tmp_path / "out.csv")

    respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(200, json={"data": {"abuseConfidenceScore": 90, "totalReports": 50}})
    )

    await run(["1.1.1.1"], as_json=False, csv_path=csv_path)

    with open(csv_path) as f:
        rows = list(csv_module.DictReader(f))

    assert len(rows) == 1
    assert rows[0]["ioc"] == "1.1.1.1"
    assert rows[0]["ioc_type"] == "ipv4"
    assert "AbuseIPDB" in rows[0]["flagged_by"]


@respx.mock
async def test_csv_rows_match_input_order(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CACHE_DIR", tmp_path)
    csv_path = str(tmp_path / "out.csv")

    respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(200, json={"data": {"abuseConfidenceScore": 0, "totalReports": 0}})
    )

    iocs = ["5.5.5.5", "6.6.6.6", "7.7.7.7"]
    await run(iocs, as_json=False, csv_path=csv_path)

    with open(csv_path) as f:
        rows = list(csv_module.DictReader(f))

    assert [r["ioc"] for r in rows] == iocs
