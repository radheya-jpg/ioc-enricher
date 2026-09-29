import httpx
import respx
import pytest

import config
from sources import virustotal


@pytest.fixture(autouse=True)
def fake_key(monkeypatch):
    monkeypatch.setattr(config, "VT_API_KEY", "fake-key-for-tests")


@respx.mock
async def test_vt_flags_malicious_hash(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CACHE_DIR", tmp_path)
    fake_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85"

    respx.get(f"https://www.virustotal.com/api/v3/files/{fake_hash}").mock(
        return_value=httpx.Response(200, json={
            "data": {"attributes": {"last_analysis_stats": {
                "malicious": 12, "suspicious": 3, "undetected": 55, "harmless": 0
            }}}
        })
    )

    async with httpx.AsyncClient() as client:
        result = await virustotal.check(client, fake_hash, "sha256")

    assert result["malicious"] is True
    assert result["confidence"] == round(15 / 70, 2)


@respx.mock
async def test_vt_404_means_no_history_not_malicious(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CACHE_DIR", tmp_path)

    respx.get("https://www.virustotal.com/api/v3/domains/example.com").mock(
        return_value=httpx.Response(404)
    )

    async with httpx.AsyncClient() as client:
        result = await virustotal.check(client, "example.com", "domain")

    assert result["malicious"] is False
    assert result["error"] is None


async def test_vt_skips_without_key(monkeypatch):
    monkeypatch.setattr(config, "VT_API_KEY", None)
    async with httpx.AsyncClient() as client:
        result = await virustotal.check(client, "8.8.8.8", "ipv4")
    assert result["skipped"] is True
