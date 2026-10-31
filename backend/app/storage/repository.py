"""In-memory repositories backed by JSON files.

Services only talk to these classes, never to files directly, so swapping the backend for
SQLite/PostgreSQL later means re-implementing this module with the same method signatures.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from app.models.alerts import Alert, RuleOverride
from app.models.events import NormalizedEvent
from app.models.imports import ImportRecord
from app.models.incidents import Activity, Incident
from app.models.simulations import SimulationRun
from app.storage.json_store import JsonCollectionFile


class Collection[T: BaseModel]:
    def __init__(self, path: Path, name: str, model: type[T], key: Callable[[T], str] = lambda m: m.id):
        self._file = JsonCollectionFile(path, name)
        self._model = model
        self._key = key
        self._items: dict[str, T] = {}
        self.meta: dict[str, Any] = {}
        self.recovered = False

    def load(self) -> None:
        result = self._file.load(self._model)
        self._items = {self._key(item): item for item in result.items}
        self.meta = result.meta
        self.recovered = result.recovered

    def persist(self) -> None:
        self._file.save(list(self._items.values()), self.meta)

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

    def clear(self) -> None:
        self._items.clear()
        self.meta = {}


class EventCollection(Collection[NormalizedEvent]):
    """Events are append-mostly; keep a time-sorted view cached for queries and the detection engine."""

    def __init__(self, path: Path):
        super().__init__(path, "events", NormalizedEvent)
        self._sorted: list[NormalizedEvent] | None = None

    def load(self) -> None:
        super().load()
        self._sorted = None

    def upsert(self, item: NormalizedEvent) -> None:
        super().upsert(item)
        self._sorted = None

    def clear(self) -> None:
        super().clear()
        self._sorted = None

    def sorted(self) -> list[NormalizedEvent]:
        if self._sorted is None:
            self._sorted = sorted(self._items.values(), key=lambda e: (e.timestamp, e.id))
        return self._sorted


class LabStore:
    def __init__(self, state_dir: Path):
        self.state_dir = state_dir
        self.lock = threading.RLock()
        self.events = EventCollection(state_dir / "events.json")
        self.alerts: Collection[Alert] = Collection(state_dir / "alerts.json", "alerts", Alert)
        self.incidents: Collection[Incident] = Collection(state_dir / "incidents.json", "incidents", Incident)
        self.activity: Collection[Activity] = Collection(state_dir / "activity.json", "activity", Activity)
        self.imports: Collection[ImportRecord] = Collection(state_dir / "imports.json", "imports", ImportRecord)
        self.simulation_runs: Collection[SimulationRun] = Collection(state_dir / "simulation_runs.json", "simulation_runs", SimulationRun)
        self.rules: Collection[RuleOverride] = Collection(state_dir / "rules.json", "rules", RuleOverride)

    @property
    def collections(self) -> list[Collection[Any]]:
        return [self.events, self.alerts, self.incidents, self.activity, self.imports, self.simulation_runs, self.rules]

    def load(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        for collection in self.collections:
            collection.load()

    def is_initialized(self) -> bool:
        return bool(self.events.meta.get("initialized"))

    def clear(self) -> None:
        for collection in self.collections:
            collection.clear()

    def persist_all(self) -> None:
        for collection in self.collections:
            collection.persist()
