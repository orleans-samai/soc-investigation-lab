"""In-memory repositories with pluggable persistence (SQLite by default, JSON files optional).

Services only talk to these classes, never to files or SQL, so adding another backend (e.g.
PostgreSQL) means implementing ``_Backend`` without touching the rest of the code.

Items are often mutated in place by the services (``alert.status = ...``), so changes are found at
save time by comparing each item's serialized form with what was last persisted. Events never
change after ingestion, so only new event keys are written.
"""

from __future__ import annotations

import hashlib
import json
import logging
import shutil
import threading
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any, Literal, Protocol

from pydantic import BaseModel

from app.models.alerts import Alert, RuleOverride
from app.models.events import NormalizedEvent
from app.models.imports import ImportRecord
from app.models.incidents import Activity, Incident
from app.models.simulations import SimulationRun
from app.storage.json_store import JsonCollectionFile, LoadResult
from app.storage.sqlite_store import SqliteDocumentStore

log = logging.getLogger(__name__)
StorageKind = Literal["sqlite", "json"]


class _Backend(Protocol):
    recovered: set[str]

    def load[T: BaseModel](self, collection: str, model: type[T]) -> LoadResult[T]: ...

    def save(
        self, collection: str, items: dict[str, BaseModel], upserts: dict[str, str], removed: set[str], meta: dict[str, Any]
    ) -> None: ...


class JsonBackend:
    """One JSON file per collection, rewritten atomically whenever the collection changes."""

    def __init__(self, state_dir: Path):
        self.state_dir = state_dir
        self.recovered: set[str] = set()

    def _file(self, collection: str) -> JsonCollectionFile:
        return JsonCollectionFile(self.state_dir / f"{collection}.json", collection)

    def load(self, collection, model):
        result = self._file(collection).load(model)
        if result.recovered:
            self.recovered.add(collection)
        return result

    def save(self, collection, items, upserts, removed, meta):
        self._file(collection).save(list(items.values()), meta)


class SqliteBackend:
    """Rows are upserted/deleted individually inside one transaction per collection."""

    def __init__(self, state_dir: Path):
        self.db = SqliteDocumentStore(state_dir / "lab.db")
        self.recovered: set[str] = set()

    def load(self, collection, model):
        result = self.db.load(collection, model)
        if self.db.recovered:
            self.recovered.add("database")
        return result

    def save(self, collection, items, upserts, removed, meta):
        self.db.save(collection, upserts, removed, meta)


def _digest(data: str) -> str:
    return hashlib.blake2b(data.encode(), digest_size=16).hexdigest()


class Collection[T: BaseModel]:
    def __init__(self, backend: _Backend, name: str, model: type[T], key: Callable[[T], str] = lambda m: m.id, immutable: bool = False):
        self._backend = backend
        self.name = name
        self._model = model
        self._key = key
        self._immutable = immutable
        self._items: dict[str, T] = {}
        self._saved: dict[str, str] = {}  # key -> digest of the persisted version
        self._saved_meta = ""
        self.meta: dict[str, Any] = {}

    @property
    def recovered(self) -> bool:
        return self.name in self._backend.recovered or "database" in self._backend.recovered

    def load(self) -> None:
        result = self._backend.load(self.name, self._model)
        self._items = {self._key(item): item for item in result.items}
        self.meta = result.meta
        self._saved = {k: ("" if self._immutable else _digest(v.model_dump_json())) for k, v in self._items.items()}
        self._saved_meta = json.dumps(self.meta, sort_keys=True, default=str)

    def mark_all_unsaved(self) -> None:
        self._saved = {}
        self._saved_meta = ""

    def persist(self) -> None:
        upserts: dict[str, str] = {}
        for key, item in self._items.items():
            if self._immutable and key in self._saved:
                continue
            data = item.model_dump_json()
            if self._saved.get(key) != (digest := _digest(data)) or self._immutable:
                upserts[key] = data
                self._saved[key] = "" if self._immutable else digest
        removed = set(self._saved) - set(self._items)
        meta = json.dumps(self.meta, sort_keys=True, default=str)
        if not upserts and not removed and meta == self._saved_meta:
            return
        self._backend.save(self.name, self._items, upserts, removed, self.meta)
        for key in removed:
            del self._saved[key]
        self._saved_meta = meta

    def get(self, key: str) -> T | None:
        return self._items.get(key)

    def __contains__(self, key: str) -> bool:
        return key in self._items

    def __len__(self) -> int:
        return len(self._items)

    def all(self) -> list[T]:
        return list(self._items.values())

    def upsert(self, item: T) -> None:
        self._items[self._key(item)] = item

    def upsert_many(self, items: Iterable[T]) -> None:
        for item in items:
            self.upsert(item)

    def remove(self, key: str) -> None:
        self._items.pop(key, None)

    def clear(self) -> None:
        self._items.clear()
        self.meta = {}


class EventCollection(Collection[NormalizedEvent]):
    """Events are append-only; keep a time-sorted view cached for queries and the detection engine."""

    def __init__(self, backend: _Backend):
        super().__init__(backend, "events", NormalizedEvent, immutable=True)
        self._sorted: list[NormalizedEvent] | None = None

    def load(self) -> None:
        super().load()
        self._sorted = None

    def upsert(self, item: NormalizedEvent) -> None:
        super().upsert(item)
        self._sorted = None

    def remove(self, key: str) -> None:
        super().remove(key)
        self._sorted = None

    def clear(self) -> None:
        super().clear()
        self._sorted = None

    def sorted(self) -> list[NormalizedEvent]:
        if self._sorted is None:
            self._sorted = sorted(self._items.values(), key=lambda e: (e.timestamp, e.id))
        return self._sorted


class LabStore:
    def __init__(self, state_dir: Path, backend: StorageKind = "sqlite"):
        self.state_dir = state_dir
        self.backend_kind = backend
        self.lock = threading.RLock()
        self._backend: _Backend = SqliteBackend(state_dir) if backend == "sqlite" else JsonBackend(state_dir)
        b = self._backend
        self.events = EventCollection(b)
        self.alerts: Collection[Alert] = Collection(b, "alerts", Alert)
        self.incidents: Collection[Incident] = Collection(b, "incidents", Incident)
        self.activity: Collection[Activity] = Collection(b, "activity", Activity)
        self.imports: Collection[ImportRecord] = Collection(b, "imports", ImportRecord)
        self.simulation_runs: Collection[SimulationRun] = Collection(b, "simulation_runs", SimulationRun)
        self.rules: Collection[RuleOverride] = Collection(b, "rules", RuleOverride)
        self.migrated_from_json = False

    @property
    def collections(self) -> list[Collection[Any]]:
        return [self.events, self.alerts, self.incidents, self.activity, self.imports, self.simulation_runs, self.rules]

    @property
    def recovered_collections(self) -> list[str]:
        return sorted(self._backend.recovered)

    def load(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        if isinstance(self._backend, SqliteBackend) and self._backend.db.is_empty() and (self.state_dir / "events.json").exists():
            self._migrate_from_json()
            return
        for collection in self.collections:
            collection.load()

    def _migrate_from_json(self) -> None:
        """One-off upgrade: state written by the JSON backend is imported into SQLite, then archived."""
        json_backend = JsonBackend(self.state_dir)
        for collection in self.collections:
            result = json_backend.load(collection.name, collection._model)
            collection._items = {collection._key(item): item for item in result.items}
            collection.meta = result.meta
            collection.mark_all_unsaved()
        self.persist_all()
        archive = self.state_dir / "json-backup"
        archive.mkdir(exist_ok=True)
        for collection in self.collections:
            source = self.state_dir / f"{collection.name}.json"
            if source.exists():
                shutil.move(source, archive / source.name)
        self.migrated_from_json = True
        log.info("migrated JSON state to SQLite; originals kept in %s", archive)

    def is_initialized(self) -> bool:
        return bool(self.events.meta.get("initialized"))

    def clear(self) -> None:
        for collection in self.collections:
            collection.clear()

    def close(self) -> None:
        if isinstance(self._backend, SqliteBackend):
            self._backend.db.close()

    def persist_all(self) -> None:
        for collection in self.collections:
            collection.persist()
