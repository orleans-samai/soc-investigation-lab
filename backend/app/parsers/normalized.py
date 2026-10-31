from __future__ import annotations

import json

from pydantic import ValidationError

from app.models.events import NormalizedEvent
from app.models.imports import LogFormat
from app.parsers.base import ParseOptions, ParseResult, iter_json_records


def _summarize(exc: ValidationError) -> str:
    parts = []
    for err in exc.errors()[:3]:
        location = ".".join(str(p) for p in err["loc"]) or "record"
        parts.append(f"{location}: {err['msg']}")
    return "; ".join(parts)


class NormalizedJsonParser:
    """Events already in the lab's internal schema (for example, an export from the Log Explorer)."""

    format = LogFormat.normalized_json

    def parse(self, text: str, options: ParseOptions) -> ParseResult:
        result = ParseResult(format=self.format)
        records, issues = iter_json_records(text)
        for issue in issues:
            result.add_error(issue.line, issue.message, issue.excerpt)
        result.total_records = len(records) + len(issues)

        for position, record in records:
            if not isinstance(record, dict):
                result.add_error(position, "record is not a JSON object")
                continue
            # The id is always recomputed from the raw record so it cannot be spoofed to bypass dedup.
            payload = {k: v for k, v in record.items() if k not in {"id", "ingested_at"}}
            payload["dataset"] = options.dataset
            try:
                result.events.append(NormalizedEvent.model_validate(payload))
            except ValidationError as exc:
                result.add_error(position, _summarize(exc), json.dumps(record, default=str)[:240])
        return result
