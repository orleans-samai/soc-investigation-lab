"""Building blocks shared by every detection rule."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import Counter, defaultdict
from collections.abc import Callable, Hashable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from app.detection.inventory import Inventory
from app.detection.threat_intel import ThreatIntelFeed
from app.models.alerts import RuleParam
from app.models.common import MitreRef, Severity
from app.models.events import NormalizedEvent

# Accounts that are never meaningful as "the user" behind an activity.
NON_HUMAN_ACCOUNTS = {"-", "system", "local service", "network service", "anonymous logon", "dwm-1", "umfd-0"}


@dataclass(frozen=True)
class ParamSpec:
    name: str
    label: str
    default: int
    min: int
    max: int
    unit: str = ""


@dataclass
class DetectionContext:
    inventory: Inventory
    timezone: ZoneInfo
    business_hours: tuple[int, int] = (7, 20)
    threat_intel: ThreatIntelFeed | None = None

    def local(self, at: datetime) -> datetime:
        return at.astimezone(self.timezone)

    def is_business_hours(self, at: datetime) -> bool:
        local = self.local(at)
        start, end = self.business_hours
        return local.weekday() < 5 and start <= local.hour < end


@dataclass
class AlertDraft:
    rule: Rule
    group_key: str
    events: list[NormalizedEvent]
    trigger: NormalizedEvent
    reason: str
    severity: Severity | None = None
    evidence: list[tuple[str, str]] = field(default_factory=list)
    extra_mitre: list[MitreRef] = field(default_factory=list)
    fp_hints: list[str] = field(default_factory=list)
    hostname: str | None = None
    username: str | None = None
    source_ip: str | None = None

    @property
    def fingerprint(self) -> str:
        # Anchored on the first event of the cluster so re-running detection on a growing
        # dataset updates the same alert instead of creating a duplicate.
        return f"{self.rule.id}|{self.group_key}|{self.events[0].id}"


class Rule(ABC):
    id: str
    name: str
    description: str
    severity: Severity
    rule_type: str  # threshold | correlation | single_event | behavioral
    data_sources: list[str]
    mitre: list[MitreRef]
    params: list[ParamSpec] = []
    logic: str
    false_positives: list[str]
    response: list[str]
    # True for analyst-authored rules (Sigma); built-in rules ship with the lab.
    custom: bool = False

    def defaults(self) -> dict[str, int]:
        return {p.name: p.default for p in self.params}

    def resolve_params(self, overrides: dict[str, int] | None) -> dict[str, int]:
        values = self.defaults()
        for spec in self.params:
            if overrides and spec.name in overrides:
                values[spec.name] = max(spec.min, min(spec.max, int(overrides[spec.name])))
        return values

    def param_models(self, overrides: dict[str, int] | None = None) -> list[RuleParam]:
        values = self.resolve_params(overrides)
        return [RuleParam(name=p.name, label=p.label, value=values[p.name], min=p.min, max=p.max, unit=p.unit) for p in self.params]

    @abstractmethod
    def evaluate(self, events: list[NormalizedEvent], ctx: DetectionContext, params: dict[str, int]) -> list[AlertDraft]:
        """Return alert drafts for the (time-sorted) events."""


def mitre(technique_id: str, technique: str, tactic: str) -> MitreRef:
    return MitreRef(technique_id=technique_id, technique=technique, tactic=tactic)


def is_human_account(username: str | None) -> bool:
    return bool(username) and username not in NON_HUMAN_ACCOUNTS and not username.endswith("$")


def group_by[K: Hashable](events: Iterable[NormalizedEvent], key: Callable[[NormalizedEvent], K | None]) -> dict[K, list[NormalizedEvent]]:
    groups: dict[K, list[NormalizedEvent]] = defaultdict(list)
    for event in events:
        k = key(event)
        if k is not None:
            groups[k].append(event)
    return groups


def sessionize(events: list[NormalizedEvent], gap: timedelta) -> list[list[NormalizedEvent]]:
    """Split a time-sorted list wherever two consecutive events are more than ``gap`` apart."""
    sessions: list[list[NormalizedEvent]] = []
    for event in events:
        if sessions and event.timestamp - sessions[-1][-1].timestamp <= gap:
            sessions[-1].append(event)
        else:
            sessions.append([event])
    return sessions


@dataclass
class Burst:
    events: list[NormalizedEvent]
    trigger: NormalizedEvent
    peak: int


def threshold_bursts(
    events: list[NormalizedEvent],
    window: timedelta,
    threshold: int,
    distinct: Callable[[NormalizedEvent], Hashable] | None = None,
) -> list[Burst]:
    """Find activity bursts where ``threshold`` events (or distinct values) occur within ``window``.

    Events are first grouped into sessions (gaps <= window). Inside each session a sliding window
    looks for the first point where the threshold is crossed; that event becomes the trigger and the
    whole session is attached to the alert as context.
    """
    bursts: list[Burst] = []
    for session in sessionize(events, window):
        left = 0
        counts: Counter[Hashable] = Counter()
        trigger: NormalizedEvent | None = None
        peak = 0
        for right, event in enumerate(session):
            counts[distinct(event) if distinct else right] += 1
            while session[right].timestamp - session[left].timestamp > window:
                old = distinct(session[left]) if distinct else left
                counts[old] -= 1
                if counts[old] <= 0:
                    del counts[old]
                left += 1
            size = len(counts)
            peak = max(peak, size)
            if trigger is None and size >= threshold:
                trigger = event
        if trigger is not None:
            bursts.append(Burst(events=session, trigger=trigger, peak=peak))
    return bursts


def cluster_by_time(events: list[NormalizedEvent], window: timedelta) -> list[list[NormalizedEvent]]:
    """Group repeated single-event detections (same entity) that happen close together."""
    clusters: list[list[NormalizedEvent]] = []
    for event in events:
        if clusters and event.timestamp - clusters[-1][0].timestamp <= window:
            clusters[-1].append(event)
        else:
            clusters.append([event])
    return clusters


def fmt_duration(delta: timedelta) -> str:
    seconds = int(delta.total_seconds())
    if seconds < 60:
        return f"{seconds}s"
    minutes, seconds = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {seconds:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes:02d}m"


def top(values: Iterable[str | None], n: int = 5) -> list[tuple[str, int]]:
    return Counter(v for v in values if v).most_common(n)
