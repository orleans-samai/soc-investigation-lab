from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Any

from pydantic import Field, field_validator

from app.models.common import ApiModel, UtcDatetime, utcnow


class EventSource(StrEnum):
    windows_security = "windows_security"
    windows_system = "windows_system"
    windows_powershell = "windows_powershell"
    linux_auth = "linux_auth"
    internal = "internal"


class EventType(StrEnum):
    authentication = "authentication"
    session = "session"
    account_management = "account_management"
    process = "process"
    privilege = "privilege"
    persistence = "persistence"
    audit = "audit"
    other = "other"


class LogLevel(StrEnum):
    info = "info"
    warning = "warning"
    error = "error"
    critical = "critical"


class Outcome(StrEnum):
    success = "success"
    failure = "failure"
    unknown = "unknown"


class NormalizedEvent(ApiModel):
    """The project's internal event schema. Every parser produces this shape."""

    id: str = ""
    timestamp: UtcDatetime
    ingested_at: UtcDatetime = Field(default_factory=utcnow)
    event_id: str | None = None
    event_source: EventSource
    event_type: EventType
    event_action: str
    outcome: Outcome = Outcome.unknown
    log_level: LogLevel = LogLevel.info
    hostname: str | None = None
    username: str | None = None
    domain: str | None = None
    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    logon_type: int | None = None
    process_name: str | None = None
    command_line: str | None = None
    parent_process: str | None = None
    target_username: str | None = None
    group_name: str | None = None
    message: str = ""
    raw: str
    dataset: str = "import"
    tags: list[str] = Field(default_factory=list)
    fields: dict[str, Any] = Field(default_factory=dict)

    @field_validator("hostname", "username", "target_username", mode="before")
    @classmethod
    def _lower(cls, value: Any) -> Any:
        if isinstance(value, str):
            value = value.strip()
            return value.lower() or None
        return value

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = compute_event_id(self.event_source, self.raw)


def compute_event_id(source: str, raw: str) -> str:
    """Deterministic id: the same raw record from the same source is always the same event.

    This is what prevents accidental duplication when a file is imported twice.
    """
    digest = hashlib.sha256(f"{source}\x1f{raw}".encode()).hexdigest()
    return f"evt_{digest[:16]}"


class EventFacets(ApiModel):
    hostnames: list[str]
    usernames: list[str]
    source_ips: list[str]
    event_sources: list[str]
    event_types: list[str]
    event_actions: list[str]
    datasets: list[str]
