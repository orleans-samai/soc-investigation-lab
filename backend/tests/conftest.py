from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.detection.base import DetectionContext
from app.detection.engine import DetectionEngine
from app.detection.inventory import Inventory
from app.detection.threat_intel import ThreatIntelFeed
from app.main import create_app
from app.models.events import EventSource, EventType, NormalizedEvent, Outcome

BACKEND = Path(__file__).resolve().parent.parent
T0 = datetime(2026, 10, 29, 15, 0, tzinfo=UTC)  # Thursday 12:00 in Sao Paulo (business hours)


@pytest.fixture(scope="session")
def inventory() -> Inventory:
    return Inventory.load(BACKEND / "data" / "inventory.json")


@pytest.fixture
def engine(inventory: Inventory) -> DetectionEngine:
    feed = ThreatIntelFeed.load(BACKEND / "data" / "threat_intel.json")
    return DetectionEngine(DetectionContext(inventory=inventory, timezone=ZoneInfo("America/Sao_Paulo"), threat_intel=feed))


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(state_dir=tmp_path / "state")


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    with TestClient(create_app(settings)) as c:
        yield c


_counter = 0


def ev(
    action: str,
    *,
    at: datetime | None = None,
    seconds: float = 0,
    source: EventSource = EventSource.windows_security,
    event_type: EventType = EventType.authentication,
    outcome: Outcome | None = None,
    **fields: Any,
) -> NormalizedEvent:
    """Build a normalized event directly (unit tests for rules don't need to go through parsers)."""
    global _counter
    _counter += 1
    if outcome is None:
        outcome = Outcome.failure if "failed" in action or "denied" in action else Outcome.success
    return NormalizedEvent(
        timestamp=(at or T0) + timedelta(seconds=seconds),
        event_source=source,
        event_type=event_type,
        event_action=action,
        outcome=outcome,
        raw=f"test-event-{_counter}",
        dataset="test",
        **fields,
    )


def rules_fired(engine: DetectionEngine, events: list[NormalizedEvent]) -> list[str]:
    return sorted({a.rule_id for a in engine.run(sorted(events, key=lambda e: e.timestamp))})
