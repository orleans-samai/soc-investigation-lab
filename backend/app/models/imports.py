from __future__ import annotations

from enum import StrEnum

from pydantic import Field

from app.models.common import ApiModel, UtcDatetime, utcnow
from app.models.events import NormalizedEvent


class LogFormat(StrEnum):
    auto = "auto"
    windows_json = "windows_json"
    linux_ssh = "linux_ssh"
    normalized_json = "normalized_json"


class ParseIssue(ApiModel):
    line: int | None
    message: str
    excerpt: str = ""


class ImportRecord(ApiModel):
    id: str
    filename: str
    format: LogFormat
    size_bytes: int
    total_records: int
    parsed: int
    added: int
    duplicates: int
    skipped: int
    error_count: int
    alerts_created: int = 0
    created_at: UtcDatetime = Field(default_factory=utcnow)


class ImportReport(ApiModel):
    import_id: str | None
    filename: str
    format: LogFormat
    dry_run: bool
    size_bytes: int
    total_records: int
    parsed: int
    added: int
    duplicates: int
    skipped: int
    errors: list[ParseIssue]
    error_count: int
    first_timestamp: UtcDatetime | None
    last_timestamp: UtcDatetime | None
    preview: list[NormalizedEvent]
    alerts_created: int = 0
    incidents_touched: list[str] = Field(default_factory=list)
