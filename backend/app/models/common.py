from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated

from pydantic import AfterValidator, BaseModel, ConfigDict


def _ensure_utc(value: datetime) -> datetime:
    """Every timestamp in the lab is timezone-aware UTC. Naive datetimes are rejected upstream."""
    if value.tzinfo is None:
        raise ValueError("timestamp must include a timezone offset")
    return value.astimezone(UTC)


UtcDatetime = Annotated[datetime, AfterValidator(_ensure_utc)]


def utcnow() -> datetime:
    return datetime.now(UTC)


class Severity(StrEnum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @classmethod
    def max(cls, values: list[Severity]) -> Severity:
        return max(values, key=lambda s: s.rank) if values else cls.low


_SEVERITY_RANK = {Severity.low: 1, Severity.medium: 2, Severity.high: 3, Severity.critical: 4}


class ApiModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True, use_enum_values=False)


class MitreRef(ApiModel):
    technique_id: str
    technique: str
    tactic: str


class Page[T](ApiModel):
    items: list[T]
    total: int
    page: int
    page_size: int
