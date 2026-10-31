from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, tzinfo
from typing import Any, Protocol
from zoneinfo import ZoneInfo

from app.models.events import NormalizedEvent
from app.models.imports import LogFormat, ParseIssue

MAX_LINE_LENGTH = 16_384
MAX_REPORTED_ERRORS = 200


class ParseError(ValueError):
    """Raised for a single record that cannot be parsed; becomes a ParseIssue in the report."""


@dataclass
class ParseOptions:
    dataset: str = "import"
    # Applied to timestamps that carry no offset (classic syslog, naive ISO strings).
    timezone: tzinfo = field(default_factory=lambda: ZoneInfo("UTC"))
    # Classic BSD syslog lines have no year; this is the year assumed (with rollover protection).
    year: int | None = None
    reference_time: datetime | None = None


@dataclass
class ParseResult:
    format: LogFormat
    events: list[NormalizedEvent] = field(default_factory=list)
    errors: list[ParseIssue] = field(default_factory=list)
    error_count: int = 0
    skipped: int = 0
    total_records: int = 0

    def add_error(self, line: int | None, message: str, excerpt: str = "") -> None:
        self.error_count += 1
        if len(self.errors) < MAX_REPORTED_ERRORS:
            self.errors.append(ParseIssue(line=line, message=message, excerpt=excerpt[:240]))


class LogParser(Protocol):
    format: LogFormat

    def parse(self, text: str, options: ParseOptions) -> ParseResult: ...


_FRACTION = re.compile(r"(\.\d{6})\d+")
_DOTNET_DATE = re.compile(r"^/Date\((-?\d+)\)/$")


def parse_timestamp(value: Any, default_tz: tzinfo) -> datetime:
    """Parse ISO-8601 (any precision, 'Z' or offset), epoch numbers and .NET ``/Date(ms)/`` strings."""
    if isinstance(value, int | float) and not isinstance(value, bool):
        seconds = value / 1000 if value > 1e11 else value
        return datetime.fromtimestamp(seconds, UTC)
    if not isinstance(value, str) or not value.strip():
        raise ParseError("missing or empty timestamp")
    text = value.strip()
    if match := _DOTNET_DATE.match(text):
        return datetime.fromtimestamp(int(match.group(1)) / 1000, UTC)
    text = _FRACTION.sub(r"\1", text.replace(" ", "T", 1) if "T" not in text else text)
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ParseError(f"invalid timestamp {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=default_tz)
    return parsed.astimezone(UTC)


def short_hostname(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip().split(".")[0].lower()


def iter_json_records(text: str) -> tuple[list[tuple[int | None, Any]], list[ParseIssue]]:
    """Accept a JSON array, an object wrapping a list, a single object, or NDJSON.

    Returns ``(line_or_index, record)`` pairs so errors can point at the right place.
    """
    stripped = text.strip()
    if not stripped:
        return [], [ParseIssue(line=None, message="file is empty")]
    try:
        document = json.loads(stripped)
    except json.JSONDecodeError:
        document = None
    else:
        if isinstance(document, list):
            return [(i + 1, rec) for i, rec in enumerate(document)], []
        if isinstance(document, dict):
            for key in ("events", "Events", "records", "Records", "items"):
                if isinstance(document.get(key), list):
                    return [(i + 1, rec) for i, rec in enumerate(document[key])], []
            return [(1, document)], []
        return [], [ParseIssue(line=None, message="JSON root must be an array or object")]

    # Fall back to newline-delimited JSON.
    records: list[tuple[int | None, Any]] = []
    issues: list[ParseIssue] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        if len(line) > MAX_LINE_LENGTH:
            issues.append(ParseIssue(line=number, message="line exceeds maximum length", excerpt=line[:120]))
            continue
        try:
            records.append((number, json.loads(line)))
        except json.JSONDecodeError as exc:
            issues.append(ParseIssue(line=number, message=f"invalid JSON: {exc.msg}", excerpt=line[:240]))
    return records, issues
