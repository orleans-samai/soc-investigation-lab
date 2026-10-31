"""Local, offline threat-intelligence feed (indicators of compromise) used to enrich and detect."""

from __future__ import annotations

import ipaddress
import json
import re
from functools import cached_property
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field

from app.models.common import ApiModel, Severity

IndicatorType = Literal["ip", "domain", "url", "sha256"]
_URL = re.compile(r"https?://[^\s'\"<>)]+", re.IGNORECASE)


class Indicator(ApiModel):
    type: IndicatorType
    value: str
    threat: str
    severity: Severity
    confidence: int = Field(ge=0, le=100)
    first_seen: str | None = None


class ThreatIntelFeed(ApiModel):
    source: str
    updated: str | None = None
    indicators: list[Indicator]

    @classmethod
    def load(cls, path: Path) -> ThreatIntelFeed:
        if not path.exists():
            return cls(source="none", indicators=[])
        with path.open(encoding="utf-8") as fh:
            return cls.model_validate(json.load(fh))

    @cached_property
    def _index(self) -> dict[tuple[str, str], Indicator]:
        return {(i.type, i.value.lower()): i for i in self.indicators}

    def lookup(self, kind: str, value: str | None) -> Indicator | None:
        return self._index.get((kind, value.strip().lower())) if value else None


def urls_in(text: str | None) -> list[str]:
    return [u.rstrip("').;,") for u in _URL.findall(text or "")]


def host_of(url: str) -> str | None:
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def is_ip(value: str | None) -> bool:
    try:
        ipaddress.ip_address(value or "")
    except ValueError:
        return False
    return True
