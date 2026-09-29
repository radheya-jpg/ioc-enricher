import time
import config
import cache


def test_cache_set_and_get_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CACHE_DIR", tmp_path)

    cache.set("TestSource", "1.2.3.4", {"malicious": True})
    result = cache.get("TestSource", "1.2.3.4")

    assert result == {"malicious": True}


def test_cache_miss_returns_none(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CACHE_DIR", tmp_path)
    assert cache.get("TestSource", "nonexistent-ioc") is None


def test_cache_expires_after_ttl(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(config, "CACHE_TTL_HOURS", 1)

    cache.set("TestSource", "1.2.3.4", {"malicious": True})

    # manually age the cache file past the TTL
    cache_file = list(tmp_path.glob("*.json"))[0]
    import json
    data = json.loads(cache_file.read_text())
    data["cached_at"] = time.time() - (2 * 3600)  # 2 hours ago
    cache_file.write_text(json.dumps(data))

    assert cache.get("TestSource", "1.2.3.4") is None


def test_different_iocs_dont_collide(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CACHE_DIR", tmp_path)

    cache.set("TestSource", "1.1.1.1", {"tag": "first"})
    cache.set("TestSource", "2.2.2.2", {"tag": "second"})

    assert cache.get("TestSource", "1.1.1.1") == {"tag": "first"}
    assert cache.get("TestSource", "2.2.2.2") == {"tag": "second"}
