"""
Cache layer for source lookups, with two interchangeable backends:

- "file" (default): one JSON file per (source, ioc) pair. Simple,
  zero setup, fine for normal single-analyst use.
- "sqlite": single SQLite database. Avoids creating thousands of tiny
  files under high-volume/batch use, and handles concurrent access
  (e.g. multiple batch runs, or a future Splunk command invoked per
  search) more safely than flat files.

Selected via config.CACHE_BACKEND ("file" | "sqlite"). Callers use the
same get()/set() interface either way — the backend is an implementation
detail.
"""

import json
import time
import hashlib
import sqlite3
from pathlib import Path

import config


def _cache_key(source: str, ioc: str) -> str:
    raw = f"{source}:{ioc}".encode()
    return hashlib.sha256(raw).hexdigest()


# ---------------------------------------------------------------- file backend

def _file_get(source: str, ioc: str):
    config.CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path = config.CACHE_DIR / f"{_cache_key(source, ioc)}.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None

    age_hours = (time.time() - data["cached_at"]) / 3600
    if age_hours > config.CACHE_TTL_HOURS:
        return None
    return data["payload"]


def _file_set(source: str, ioc: str, payload: dict):
    config.CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path = config.CACHE_DIR / f"{_cache_key(source, ioc)}.json"
    data = {"cached_at": time.time(), "payload": payload}
    path.write_text(json.dumps(data))


# -------------------------------------------------------------- sqlite backend

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cache_entries (
    key TEXT PRIMARY KEY,
    cached_at REAL NOT NULL,
    payload TEXT NOT NULL
)
"""


def _sqlite_conn():
    path = Path(config.SQLITE_CACHE_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=10)
    conn.execute(_SCHEMA)
    return conn


def _sqlite_get(source: str, ioc: str):
    key = _cache_key(source, ioc)
    conn = _sqlite_conn()
    try:
        row = conn.execute(
            "SELECT cached_at, payload FROM cache_entries WHERE key = ?", (key,)
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        return None
    cached_at, payload_json = row
    age_hours = (time.time() - cached_at) / 3600
    if age_hours > config.CACHE_TTL_HOURS:
        return None
    try:
        return json.loads(payload_json)
    except json.JSONDecodeError:
        return None


def _sqlite_set(source: str, ioc: str, payload: dict):
    key = _cache_key(source, ioc)
    conn = _sqlite_conn()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO cache_entries (key, cached_at, payload) VALUES (?, ?, ?)",
            (key, time.time(), json.dumps(payload)),
        )
        conn.commit()
    finally:
        conn.close()


# ------------------------------------------------------------- public interface

def get(source: str, ioc: str):
    if config.CACHE_BACKEND == "sqlite":
        return _sqlite_get(source, ioc)
    return _file_get(source, ioc)


def set(source: str, ioc: str, payload: dict):
    if config.CACHE_BACKEND == "sqlite":
        return _sqlite_set(source, ioc, payload)
    return _file_set(source, ioc, payload)
