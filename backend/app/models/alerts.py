from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import Field

from app.models.common import ApiModel, MitreRef, Severity, UtcDatetime, utcnow


class AlertStatus(StrEnum):
    new = "new"
    investigating = "investigating"
    # Closed states: the detection was correct and malicious / correct but benign / wrong.
    resolved = "resolved"
    benign = "benign"
    false_positive = "false_positive"

    @property
    def is_closed(self) -> bool:
        return self in (AlertStatus.resolved, AlertStatus.benign, AlertStatus.false_positive)


class Evidence(ApiModel):
    label: str
    value: str


class Alert(ApiModel):
    id: str
    fingerprint: str
    rule_id: str
    rule_name: str
    description: str
    severity: Severity
    # Time of the event that made the rule fire (simulated clock).
    timestamp: UtcDatetime
    # First event of the activity cluster; timestamp - first_seen = time to detect.
    first_seen: UtcDatetime
    hostname: str | None = None
    username: str | None = None
    source_ip: str | None = None
    event_ids: list[str]
    event_count: int
    reason: str
    evidence: list[Evidence] = Field(default_factory=list)
    mitre: list[MitreRef] = Field(default_factory=list)
    fp_hints: list[str] = Field(default_factory=list)
    status: AlertStatus = AlertStatus.new
    incident_id: str | None = None
    analyst_note: str | None = None
    created_at: UtcDatetime = Field(default_factory=utcnow)
    updated_at: UtcDatetime = Field(default_factory=utcnow)


class AlertUpdate(ApiModel):
    status: AlertStatus | None = None
    analyst_note: str | None = Field(default=None, max_length=4000)


class RuleParam(ApiModel):
    name: str
    label: str
    value: int
    min: int
    max: int
    unit: str = ""


class RuleOverride(ApiModel):
    """Analyst changes to a built-in rule, persisted separately from the rule code."""

    id: str
    enabled: bool = True
    params: dict[str, int] = Field(default_factory=dict)


class CustomRuleRecord(ApiModel):
    """An analyst-written Sigma rule as stored; it is compiled into the engine at startup."""

    id: str
    source: str
    created_at: UtcDatetime = Field(default_factory=utcnow)
    updated_at: UtcDatetime = Field(default_factory=utcnow)


class SigmaRuleRequest(ApiModel):
    source: str = Field(min_length=1, max_length=64_000)


class RuleInfo(ApiModel):
    id: str
    name: str
    description: str
    severity: Severity
    rule_type: str
    data_sources: list[str]
    mitre: list[MitreRef]
    enabled: bool
    params: list[RuleParam]
    logic: str
    false_positives: list[str]
    response: list[str]
    custom: bool = False
    source: str | None = None
    alert_count: int = 0
    last_triggered: UtcDatetime | None = None


class RuleUpdate(ApiModel):
    enabled: bool | None = None
    params: dict[str, int] | None = None


class BacktestRequest(ApiModel):
    params: dict[str, int] = Field(default_factory=dict)


class BacktestResult(ApiModel):
    rule_id: str
    params: dict[str, int]
    alert_count: int
    current_alert_count: int
    sample: list[dict[str, Any]]
