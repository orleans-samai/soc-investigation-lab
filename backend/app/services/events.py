"""Event search, filtering and export for the Log Explorer."""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from app.models.common import Page
from app.models.events import EventFacets, NormalizedEvent

SORTABLE = {"timestamp", "hostname", "username", "source_ip", "event_id", "event_source", "event_type", "event_action", "log_level"}
EXPORT_COLUMNS = [
    "id", "timestamp", "event_id", "event_source", "event_type", "event_action", "outcome", "log_level",
    "hostname", "username", "source_ip", "source_port", "destination_ip", "logon_type", "process_name",
    "command_line", "target_username", "group_name", "dataset", "message", "raw",
]  # fmt: skip


@dataclass
class EventFilter:
    q: str | None = None
    username: str | None = None
    source_ip: str | None = None
    hostname: str | None = None
    event_source: str | None = None
    event_type: str | None = None
    event_action: str | None = None
    log_level: str | None = None
    outcome: str | None = None
    dataset: str | None = None
    start: datetime | None = None
    end: datetime | None = None
    ids: set[str] | None = None

    def matches(self, e: NormalizedEvent) -> bool:
        if self.ids is not None and e.id not in self.ids:
            return False
        if self.start and e.timestamp < self.start:
            return False
        if self.end and e.timestamp > self.end:
            return False
        if self.username and self.username.lower() not in {e.username, e.target_username}:
            return False
        if self.source_ip and self.source_ip not in {e.source_ip, e.destination_ip}:
            return False
        if self.hostname and e.hostname != self.hostname.lower():
            return False
        for attr in ("event_source", "event_type", "event_action", "log_level", "outcome"):
            wanted = getattr(self, attr)
            if wanted and str(getattr(e, attr)) not in wanted.split(","):
                return False
        if self.dataset and not e.dataset.startswith(self.dataset):
            return False
        if self.q:
            haystack = " ".join(
                str(v) for v in (e.message, e.raw, e.username, e.hostname, e.source_ip, e.command_line, e.event_id, e.target_username) if v
            ).lower()
            if not all(term in haystack for term in self.q.lower().split()):
                return False
        return True


def filter_events(events: Iterable[NormalizedEvent], flt: EventFilter) -> list[NormalizedEvent]:
    return [e for e in events if flt.matches(e)]


def sort_events(events: list[NormalizedEvent], sort: str, order: str) -> list[NormalizedEvent]:
    field = sort if sort in SORTABLE else "timestamp"
    reverse = order != "asc"
    if field == "timestamp":
        return sorted(events, key=lambda e: (e.timestamp, e.id), reverse=reverse)
    present = [e for e in events if getattr(e, field) is not None]
    missing = [e for e in events if getattr(e, field) is None]
    return sorted(present, key=lambda e: (str(getattr(e, field)), e.timestamp), reverse=reverse) + missing


def paginate[T](items: list[T], page: int, page_size: int) -> Page[T]:
    page = max(page, 1)
    start = (page - 1) * page_size
    return Page(items=items[start : start + page_size], total=len(items), page=page, page_size=page_size)


def facets(events: list[NormalizedEvent]) -> EventFacets:
    def distinct(attr: str) -> list[str]:
        return sorted({str(getattr(e, attr)) for e in events if getattr(e, attr)})

    datasets = sorted({e.dataset.split(":")[0] if e.dataset.startswith("simulation:") else e.dataset for e in events})
    return EventFacets(
        hostnames=distinct("hostname"),
        usernames=distinct("username"),
        source_ips=distinct("source_ip"),
        event_sources=distinct("event_source"),
        event_types=distinct("event_type"),
        event_actions=distinct("event_action"),
        datasets=datasets,
    )


def export_csv(events: list[NormalizedEvent]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=EXPORT_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for event in events:
        row = event.model_dump(mode="json")
        # Neutralise spreadsheet formula injection in exported cells.
        writer.writerow({k: _csv_safe(row.get(k)) for k in EXPORT_COLUMNS})
    return buffer.getvalue()


def export_json(events: list[NormalizedEvent]) -> str:
    return json.dumps([e.model_dump(mode="json") for e in events], ensure_ascii=False, indent=1)


def _csv_safe(value: object) -> object:
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value
