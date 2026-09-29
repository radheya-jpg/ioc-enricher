import time
import config
import cache


def test_sqlite_set_and_get_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CACHE_BACKEND", "sqlite")
    monkeypatch.setattr(config, "SQLITE_CACHE_PATH", str(tmp_path / "test.db"))

    cache.set("TestSource", "1.2.3.4", {"malicious": True})
    result = cache.get("TestSource", "1.2.3.4")

    assert result == {"malicious": True}


def test_sqlite_cache_miss_returns_none(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CACHE_BACKEND", "sqlite")
    monkeypatch.setattr(config, "SQLITE_CACHE_PATH", str(tmp_path / "test.db"))

    assert cache.get("TestSource", "nonexistent") is None


def test_sqlite_cache_expires_after_ttl(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CACHE_BACKEND", "sqlite")
    monkeypatch.setattr(config, "SQLITE_CACHE_PATH", str(tmp_path / "test.db"))
    monkeypatch.setattr(config, "CACHE_TTL_HOURS", 1)

    cache.set("TestSource", "1.2.3.4", {"malicious": True})

    # manually age the row past the TTL
    import sqlite3
    conn = sqlite3.connect(str(tmp_path / "test.db"))
    conn.execute("UPDATE cache_entries SET cached_at = ?", (time.time() - 2 * 3600,))
    conn.commit()
    conn.close()

    assert cache.get("TestSource", "1.2.3.4") is None


def test_sqlite_overwrite_replaces_value(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CACHE_BACKEND", "sqlite")
    monkeypatch.setattr(config, "SQLITE_CACHE_PATH", str(tmp_path / "test.db"))

    cache.set("TestSource", "1.2.3.4", {"tag": "first"})
    cache.set("TestSource", "1.2.3.4", {"tag": "second"})

    assert cache.get("TestSource", "1.2.3.4") == {"tag": "second"}


def test_default_backend_is_file(tmp_path, monkeypatch):
    # sanity check: with no override, CACHE_BACKEND should be "file"
    # and existing file-based behavior should still work
    monkeypatch.setattr(config, "CACHE_DIR", tmp_path)
    cache.set("TestSource", "1.2.3.4", {"malicious": False})
    assert cache.get("TestSource", "1.2.3.4") == {"malicious": False}
