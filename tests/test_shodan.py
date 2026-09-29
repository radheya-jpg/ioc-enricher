import httpx
import respx
import pytest

import config
from sources import shodan


@pytest.fixture(autouse=True)
def fake_key(monkeypatch):
    monkeypatch.setattr(config, "SHODAN_API_KEY", "fake-key-for-tests")


@respx.mock
async def test_shodan_flags_host_with_known_cves(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CACHE_DIR", tmp_path)

    respx.get("https://api.shodan.io/shodan/host/1.2.3.4").mock(
        return_value=httpx.Response(200, json={
            "ports": [22, 80],
            "vulns": ["CVE-2021-1234"],
        })
    )

    async with httpx.AsyncClient() as client:
        result = await shodan.check(client, "1.2.3.4", "ipv4")

    assert result["malicious"] is True
    assert "1 known CVEs" in result["summary"]


@respx.mock
async def test_shodan_flags_large_attack_surface_without_cves(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CACHE_DIR", tmp_path)

    respx.get("https://api.shodan.io/shodan/host/1.2.3.4").mock(
        return_value=httpx.Response(200, json={
            "ports": list(range(8)),  # 8 open ports, no CVEs
            "vulns": [],
        })
    )

    async with httpx.AsyncClient() as client:
        result = await shodan.check(client, "1.2.3.4", "ipv4")

    assert result["malicious"] is True  # >= 8 ports triggers heuristic


@respx.mock
async def test_shodan_clean_host_low_exposure(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CACHE_DIR", tmp_path)

    respx.get("https://api.shodan.io/shodan/host/1.2.3.4").mock(
        return_value=httpx.Response(200, json={"ports": [443], "vulns": []})
    )

    async with httpx.AsyncClient() as client:
        result = await shodan.check(client, "1.2.3.4", "ipv4")

    assert result["malicious"] is False


@respx.mock
async def test_shodan_404_means_not_indexed(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CACHE_DIR", tmp_path)

    respx.get("https://api.shodan.io/shodan/host/1.2.3.4").mock(
        return_value=httpx.Response(404)
    )

    async with httpx.AsyncClient() as client:
        result = await shodan.check(client, "1.2.3.4", "ipv4")

    assert result["error"] is None
    assert result["malicious"] is False


async def test_shodan_skips_non_ip():
    async with httpx.AsyncClient() as client:
        result = await shodan.check(client, "example.com", "domain")
    assert result["skipped"] is True
