"""Crash-safe JSON persistence.

Each collection lives in its own file with an envelope::

    {"schema_version": 1, "collection": "alerts", "updated_at": "...", "meta": {...}, "items": [...]}

Writes go to a temporary file in the same directory, are fsync'ed, then atomically swapped in
with ``os.replace``. A reader therefore sees either the previous or the new file, never a partial one.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import time
from contextlib import suppress
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ValidationError

from app.models.common import utcnow

SCHEMA_VERSION = 1
log = logging.getLogger(__name__)


def atomic_write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, separators=(",", ":"))
            fh.flush()
            os.fsync(fh.fileno())
        _replace_with_retry(tmp_name, path)
    except BaseException:
        with suppress(FileNotFoundError):
            os.unlink(tmp_name)
        raise


def _replace_with_retry(src: str, dst: Path, attempts: int = 5) -> None:
    # On Windows, antivirus or indexers can briefly hold the destination open.
    for attempt in range(attempts):
        try:
            os.replace(src, dst)
            return
        except PermissionError:
            if attempt == attempts - 1:
                raise
            time.sleep(0.05 * (attempt + 1))


class LoadResult[T: BaseModel]:
    def __init__(self, items: list[T], meta: dict[str, Any], skipped: int, recovered: bool):
        self.items = items
        self.meta = meta
        self.skipped = skipped
        self.recovered = recovered


class JsonCollectionFile:
    def __init__(self, path: Path, collection: str):
        self.path = path
        self.collection = collection

    def exists(self) -> bool:
        return self.path.exists()

    def load[T: BaseModel](self, model: type[T]) -> LoadResult[T]:
        if not self.path.exists():
            return LoadResult([], {}, 0, False)
        try:
            with self.path.open(encoding="utf-8") as fh:
                envelope = json.load(fh)
            if not isinstance(envelope, dict) or not isinstance(envelope.get("items"), list):
                raise ValueError("missing 'items' list")
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
            self._quarantine(exc)
            return LoadResult([], {}, 0, True)

        items: list[T] = []
        skipped = 0
        for raw in envelope["items"]:
            try:
                items.append(model.model_validate(raw))
            except ValidationError:
                skipped += 1
        if skipped:
            log.warning("%s: skipped %d invalid records", self.path.name, skipped)
        return LoadResult(items, envelope.get("meta") or {}, skipped, False)

    def save(self, items: list[BaseModel], meta: dict[str, Any] | None = None) -> None:
        atomic_write_json(
            self.path,
            {
                "schema_version": SCHEMA_VERSION,
                "collection": self.collection,
                "updated_at": utcnow().isoformat(),
                "meta": meta or {},
                "items": [item.model_dump(mode="json") for item in items],
            },
        )

    def _quarantine(self, exc: Exception) -> None:
        target = self.path.with_name(f"{self.path.stem}.corrupt-{int(time.time())}{self.path.suffix}")
        log.error("%s is unreadable (%s); moved to %s and starting empty", self.path.name, exc, target.name)
        with suppress(OSError):
            os.replace(self.path, target)
