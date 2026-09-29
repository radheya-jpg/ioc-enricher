import httpx
import respx
import pytest

import config
from sources import abuseipdb


@pytest.fixture(autouse=True)
def fake_key(monkeypatch):
    monkeypatch.setattr(config, "ABUSEIPDB_API_KEY", "fake-key-for-tests")


@respx.mock
async def test_abuseipdb_flags_malicious_ip(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CACHE_DIR", tmp_path)  # isolate cache per test

    respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(200, json={
            "data": {"abuseConfidenceScore": 85, "totalReports": 42}
        })
    )

    async with httpx.AsyncClient() as client:
        result = await abuseipdb.check(client, "1.2.3.4", "ipv4")

    assert result["malicious"] is True
    assert result["confidence"] == 0.85
    assert "42 reports" in result["summary"]


@respx.mock
async def test_abuseipdb_clean_ip(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CACHE_DIR", tmp_path)

    respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(200, json={
            "data": {"abuseConfidenceScore": 0, "totalReports": 0}
        })
    )

    async with httpx.AsyncClient() as client:
        result = await abuseipdb.check(client, "8.8.8.8", "ipv4")

    assert result["malicious"] is False


async def test_abuseipdb_skips_non_ip():
    async with httpx.AsyncClient() as client:
        result = await abuseipdb.check(client, "example.com", "domain")
    assert result["skipped"] is True


async def test_abuseipdb_skips_without_key(monkeypatch):
    monkeypatch.setattr(config, "ABUSEIPDB_API_KEY", None)
    async with httpx.AsyncClient() as client:
        result = await abuseipdb.check(client, "1.2.3.4", "ipv4")
    assert result["skipped"] is True
    assert "API key" in result["reason"]


@respx.mock
async def test_abuseipdb_handles_http_error(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CACHE_DIR", tmp_path)

    respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(429)
    )

    async with httpx.AsyncClient() as client:
        result = await abuseipdb.check(client, "1.2.3.4", "ipv4")

    assert result["error"] is not None
