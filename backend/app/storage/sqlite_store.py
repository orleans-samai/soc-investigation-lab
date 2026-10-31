"""SQLite persistence: one document table, written incrementally inside transactions.

Each collection item is stored as a JSON document keyed by (collection, key). Only rows that changed
since the last save are written, so persisting after a new alert no longer rewrites every event.
WAL journaling gives crash safety; an unreadable database file is quarantined and replaced.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from contextlib import suppress
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ValidationError

from app.storage.json_store import LoadResult

log = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS documents (
    collection TEXT NOT NULL,
    key        TEXT NOT NULL,
    data       TEXT NOT NULL,
    PRIMARY KEY (collection, key)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS collection_meta (
    collection TEXT PRIMARY KEY,
    data       TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS schema_info (version INTEGER NOT NULL);
"""
SCHEMA_VERSION = 1


class SqliteDocumentStore:
    def __init__(self, path: Path):
        self.path = path
        self.recovered = False
        self._conn: sqlite3.Connection | None = None

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = self._open()
        return self._conn

    def _open(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            return self._connect()
        except sqlite3.DatabaseError as exc:
            target = self.path.with_name(f"{self.path.stem}.corrupt-{int(time.time())}{self.path.suffix}")
            log.error("%s is not a usable database (%s); moved to %s and starting empty", self.path.name, exc, target.name)
            with suppress(OSError):
                os.replace(self.path, target)
            self.recovered = True
            return self._connect()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.executescript(SCHEMA)
            if conn.execute("SELECT COUNT(*) FROM schema_info").fetchone()[0] == 0:
                conn.execute("INSERT INTO schema_info (version) VALUES (?)", (SCHEMA_VERSION,))
            conn.execute("SELECT COUNT(*) FROM documents").fetchone()
        except sqlite3.DatabaseError:
            conn.close()
            raise
        return conn

    def is_empty(self) -> bool:
        return self.conn.execute("SELECT 1 FROM documents LIMIT 1").fetchone() is None

    def load[T: BaseModel](self, collection: str, model: type[T]) -> LoadResult[T]:
        items: list[T] = []
        skipped = 0
        for (data,) in self.conn.execute("SELECT data FROM documents WHERE collection = ?", (collection,)):
            try:
                items.append(model.model_validate_json(data))
            except ValidationError:
                skipped += 1
        if skipped:
            log.warning("%s: skipped %d invalid records", collection, skipped)
        row = self.conn.execute("SELECT data FROM collection_meta WHERE collection = ?", (collection,)).fetchone()
        return LoadResult(items, json.loads(row[0]) if row else {}, skipped, False)

    def save(self, collection: str, upserts: dict[str, str], removed: set[str], meta: dict[str, Any]) -> None:
        conn = self.conn
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.executemany(
                "INSERT INTO documents (collection, key, data) VALUES (?, ?, ?) ON CONFLICT (collection, key) DO UPDATE SET data = excluded.data",
                [(collection, key, data) for key, data in upserts.items()],
            )
            conn.executemany("DELETE FROM documents WHERE collection = ? AND key = ?", [(collection, key) for key in removed])
            conn.execute(
                "INSERT INTO collection_meta (collection, data) VALUES (?, ?) ON CONFLICT (collection) DO UPDATE SET data = excluded.data",
                (collection, json.dumps(meta, default=str)),
            )
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None
