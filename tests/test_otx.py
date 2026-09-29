import httpx
import respx
import pytest

import config
from sources import otx


@pytest.fixture(autouse=True)
def fake_key(monkeypatch):
    monkeypatch.setattr(config, "OTX_API_KEY", "fake-key-for-tests")


@respx.mock
async def test_otx_flags_ip_with_pulses(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CACHE_DIR", tmp_path)

    respx.get("https://otx.alienvault.com/api/v1/indicators/IPv4/1.2.3.4/general").mock(
        return_value=httpx.Response(200, json={"pulse_info": {"count": 5}})
    )

    async with httpx.AsyncClient() as client:
        result = await otx.check(client, "1.2.3.4", "ipv4")

    assert result["malicious"] is True
    assert result["confidence"] == 0.5
    assert "5 threat intel pulses" in result["summary"]


@respx.mock
async def test_otx_domain_endpoint(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CACHE_DIR", tmp_path)

    respx.get("https://otx.alienvault.com/api/v1/indicators/domain/evil.com/general").mock(
        return_value=httpx.Response(200, json={"pulse_info": {"count": 0}})
    )

    async with httpx.AsyncClient() as client:
        result = await otx.check(client, "evil.com", "domain")

    assert result["malicious"] is False


@respx.mock
async def test_otx_hash_endpoint(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CACHE_DIR", tmp_path)
    fake_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85"

    respx.get(f"https://otx.alienvault.com/api/v1/indicators/file/{fake_hash}/general").mock(
        return_value=httpx.Response(200, json={"pulse_info": {"count": 12}})
    )

    async with httpx.AsyncClient() as client:
        result = await otx.check(client, fake_hash, "sha256")

    assert result["confidence"] == 1.0  # capped at 1.0 even though 12/10 > 1


async def test_otx_skips_without_key(monkeypatch):
    monkeypatch.setattr(config, "OTX_API_KEY", None)
    async with httpx.AsyncClient() as client:
        result = await otx.check(client, "1.2.3.4", "ipv4")
    assert result["skipped"] is True
