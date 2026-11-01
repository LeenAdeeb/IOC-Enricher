"""Tiny SQLite cache so repeated runs don't burn API quota."""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path


class Cache:
    def __init__(self, path: str | Path | None, ttl_hours: float = 24):
        self.ttl = ttl_hours * 3600
        self.enabled = path is not None
        if not self.enabled:
            return
        p = Path(path).expanduser()
        p.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(p)
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS cache (k TEXT PRIMARY KEY, ts REAL, v TEXT)"
        )

    def get(self, key: str):
        if not self.enabled:
            return None
        row = self.db.execute("SELECT ts, v FROM cache WHERE k=?", (key,)).fetchone()
        if row and time.time() - row[0] < self.ttl:
            return json.loads(row[1])
        return None

    def set(self, key: str, value) -> None:
        if not self.enabled:
            return
        self.db.execute(
            "INSERT OR REPLACE INTO cache VALUES (?,?,?)",
            (key, time.time(), json.dumps(value)),
        )
        self.db.commit()
