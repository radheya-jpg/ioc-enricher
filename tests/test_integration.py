import httpx
import respx
import pytest

import config
import allowlist
from enrich import enrich_one


@pytest.fixture(autouse=True)
def fake_keys(monkeypatch):
    monkeypatch.setattr(config, "ABUSEIPDB_API_KEY", "fake")
    monkeypatch.setattr(config, "VT_API_KEY", "fake")
    monkeypatch.setattr(config, "SHODAN_API_KEY", "fake")
    monkeypatch.setattr(config, "OTX_API_KEY", "fake")
    # Isolate from the real allowlist.txt (which includes 8.8.8.8, used
    # below as a "clean but not allowlisted" test IP) — point at an empty
    # file so these tests exercise real source-checking, not the shortcut.
    monkeypatch.setattr(config, "ALLOWLIST_PATH", "/nonexistent/allowlist.txt")
    allowlist.reload()


@respx.mock
async def test_full_pipeline_malicious_ip(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CACHE_DIR", tmp_path)
    ip = "1.2.3.4"

    respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(200, json={
            "data": {"abuseConfidenceScore": 90, "totalReports": 100}
        })
    )
    respx.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}").mock(
        return_value=httpx.Response(200, json={
            "data": {"attributes": {"last_analysis_stats": {
                "malicious": 45, "suspicious": 5, "harmless": 5, "undetected": 5
            }}}
        })
    )
    respx.get(f"https://api.shodan.io/shodan/host/{ip}").mock(
        return_value=httpx.Response(200, json={"ports": [22, 445], "vulns": ["CVE-2020-0001"]})
    )
    respx.get(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general").mock(
        return_value=httpx.Response(200, json={"pulse_info": {"count": 8}})
    )

    async with httpx.AsyncClient() as client:
        ioc, ioc_type, results, verdict = await enrich_one(client, ip)

    assert ioc == ip
    assert len(results) == 4
    assert verdict["verdict"] == "MALICIOUS"
    assert verdict["sources_used"] == 4
    assert len(verdict["flagged_by"]) == 4


@respx.mock
async def test_full_pipeline_clean_ip(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CACHE_DIR", tmp_path)
    ip = "8.8.8.8"

    respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(200, json={"data": {"abuseConfidenceScore": 0, "totalReports": 0}})
    )
    respx.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}").mock(
        return_value=httpx.Response(200, json={
            "data": {"attributes": {"last_analysis_stats": {
                "malicious": 0, "suspicious": 0, "harmless": 90, "undetected": 5
            }}}
        })
    )
    respx.get(f"https://api.shodan.io/shodan/host/{ip}").mock(
        return_value=httpx.Response(200, json={"ports": [443], "vulns": []})
    )
    respx.get(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general").mock(
        return_value=httpx.Response(200, json={"pulse_info": {"count": 0}})
    )

    async with httpx.AsyncClient() as client:
        ioc, ioc_type, results, verdict = await enrich_one(client, ip)

    assert verdict["verdict"] == "CLEAN"
    assert verdict["flagged_by"] == []


async def test_unclassifiable_input_short_circuits():
    async with httpx.AsyncClient() as client:
        ioc, ioc_type, results, verdict = await enrich_one(client, "not-a-real-ioc!!")

    assert results == []
    assert verdict["verdict"] == "UNKNOWN"


async def test_allowlisted_ioc_skips_all_source_calls(tmp_path, monkeypatch):
    """No respx mocks are registered here on purpose — if the allowlist
    short-circuit didn't work, any actual HTTP call would raise, since
    respx has nothing mocked to answer it."""
    path = tmp_path / "allowlist.txt"
    path.write_text("9.9.9.9\n")
    monkeypatch.setattr(config, "ALLOWLIST_PATH", str(path))
    allowlist.reload()

    async with httpx.AsyncClient() as client:
        ioc, ioc_type, results, verdict = await enrich_one(client, "9.9.9.9")

    assert results == []  # no source calls were made at all
    assert verdict["verdict"] == "CLEAN"
    assert verdict.get("allowlisted") is True
