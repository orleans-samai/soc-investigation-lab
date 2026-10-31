from __future__ import annotations

import json

from app.models.imports import LogFormat
from app.parsers.base import ParseOptions, ParseResult
from app.parsers.linux import _BSD, _RFC3339, LinuxAuthParser
from app.parsers.normalized import NormalizedJsonParser
from app.parsers.windows import WindowsJsonParser

PARSERS = {
    LogFormat.windows_json: WindowsJsonParser(),
    LogFormat.linux_ssh: LinuxAuthParser(),
    LogFormat.normalized_json: NormalizedJsonParser(),
}


class UnsupportedFormatError(ValueError):
    pass


def detect_format(text: str, filename: str = "") -> LogFormat:
    """Best-effort sniffing based on content, falling back to the file extension."""
    first_line = next((line for line in text.splitlines() if line.strip()), "").strip()
    if not first_line:
        raise UnsupportedFormatError("file is empty")

    if first_line[0] in "[{":
        sample = _first_json_record(text)
        if isinstance(sample, dict):
            if "event_source" in sample and "event_action" in sample:
                return LogFormat.normalized_json
            if any(key in sample for key in ("EventID", "EventId", "Id", "event_id")):
                return LogFormat.windows_json
        raise UnsupportedFormatError(
            "JSON content does not look like Windows events (EventID) or normalized events (event_source/event_action)"
        )
    if _RFC3339.match(first_line) or _BSD.match(first_line):
        return LogFormat.linux_ssh
    if filename.lower().endswith((".log", ".txt")) or "auth" in filename.lower():
        return LogFormat.linux_ssh
    raise UnsupportedFormatError("unable to detect the log format; choose it explicitly")


def _first_json_record(text: str) -> object:
    stripped = text.strip()
    try:
        document = json.loads(stripped)
    except json.JSONDecodeError:
        try:
            return json.loads(stripped.splitlines()[0])
        except (json.JSONDecodeError, IndexError):
            return None
    if isinstance(document, list):
        return document[0] if document else None
    if isinstance(document, dict):
        for key in ("events", "Events", "records", "Records", "items"):
            if isinstance(document.get(key), list) and document[key]:
                return document[key][0]
    return document


def parse_text(text: str, fmt: LogFormat, options: ParseOptions, filename: str = "") -> ParseResult:
    if fmt == LogFormat.auto:
        fmt = detect_format(text, filename)
    return PARSERS[fmt].parse(text, options)


__all__ = ["PARSERS", "ParseOptions", "ParseResult", "UnsupportedFormatError", "detect_format", "parse_text"]
