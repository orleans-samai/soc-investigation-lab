from __future__ import annotations

from enum import StrEnum

from pydantic import Field

from app.models.common import ApiModel, MitreRef, Severity, UtcDatetime, utcnow


class IncidentStatus(StrEnum):
    new = "new"
    investigating = "investigating"
    contained = "contained"
    closed = "closed"


class Classification(StrEnum):
    undetermined = "undetermined"
    true_positive = "true_positive"
    benign_true_positive = "benign_true_positive"
    false_positive = "false_positive"


class Note(ApiModel):
    id: str
    author: str
    body: str
    created_at: UtcDatetime = Field(default_factory=utcnow)


class Incident(ApiModel):
    id: str
    title: str
    # Set once an analyst renames the incident, so automatic correlation stops retitling it.
    title_locked: bool = False
    summary: str
    severity: Severity
    status: IncidentStatus = IncidentStatus.new
    classification: Classification = Classification.undetermined
    assignee: str | None = None
    alert_ids: list[str] = Field(default_factory=list)
    entities: dict[str, list[str]] = Field(default_factory=dict)
    mitre: list[MitreRef] = Field(default_factory=list)
    first_seen: UtcDatetime
    last_seen: UtcDatetime
    notes: list[Note] = Field(default_factory=list)
    resolution: str | None = None
    # LGPD: the incident affected personal data (None = not assessed yet).
    personal_data: bool | None = None
    created_at: UtcDatetime = Field(default_factory=utcnow)
    updated_at: UtcDatetime = Field(default_factory=utcnow)
    acknowledged_at: UtcDatetime | None = None
    closed_at: UtcDatetime | None = None


class IncidentCreate(ApiModel):
    alert_ids: list[str] = Field(min_length=1)
    title: str | None = Field(default=None, max_length=200)


class IncidentUpdate(ApiModel):
    title: str | None = Field(default=None, min_length=3, max_length=200)
    status: IncidentStatus | None = None
    classification: Classification | None = None
    severity: Severity | None = None
    assignee: str | None = Field(default=None, max_length=80)
    resolution: str | None = Field(default=None, max_length=4000)
    personal_data: bool | None = None


class NoteCreate(ApiModel):
    body: str = Field(min_length=1, max_length=4000)
    author: str = Field(default="analyst", min_length=1, max_length=80)


class Activity(ApiModel):
    id: str
    timestamp: UtcDatetime = Field(default_factory=utcnow)
    actor: str
    action: str
    message: str
    target_type: str | None = None
    target_id: str | None = None
