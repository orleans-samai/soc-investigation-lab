"""Scenario authoring: turn real (imported) log events into a replayable scenario with an answer key.

The analyst selects events with a Log Explorer query. The events become ``normalized_json`` steps with
their original relative timing; every replay gets fresh timestamps and fresh event ids, so the same
scenario can be run many times (by the author or by anyone the JSON file is shared with).

Anonymization replaces account names, host names and IP addresses everywhere in the event, including
the raw text, with stable pseudonyms (documentation IP ranges, ``user01``, ``host01``). It is a help,
not a guarantee: the author still reviews the preview before sharing.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Literal

from pydantic import Field

from app.models.common import ApiModel, Severity
from app.models.events import NormalizedEvent
from app.models.simulations import ChallengeQuestion, Scenario, ScenarioStep
from app.services import query as query_service
from app.services.lab import LabService
from app.simulation.scenarios import escape

MAX_SCENARIO_EVENTS = 500
MAX_SPAN_SECONDS = 7 * 24 * 3600
KEEP_ACCOUNTS = {"root", "administrator", "admin", "system", "guest", "-", "anonymous logon", "local service", "network service"}
_SLUG = re.compile(r"[^a-z0-9]+")


class AuthoringError(ValueError):
    pass


class ScenarioDraft(ApiModel):
    query: str = Field(min_length=1, max_length=2000)
    name: str = Field(min_length=3, max_length=120)
    summary: str = Field(default="", max_length=600)
    narrative: str = Field(default="", max_length=4000)
    category: str = Field(default="Custom", max_length=60)
    level: Literal["N1", "N2", "N3"] = "N1"
    verdict: Literal["malicious", "benign", "false_positive"] = "malicious"
    anonymize: bool = True
    challenge: list[ChallengeQuestion] = Field(default_factory=list)


class Pseudonyms:
    def __init__(self) -> None:
        self.users: dict[str, str] = {}
        self.hosts: dict[str, str] = {}
        self.ips: dict[str, str] = {}

    def user(self, name: str | None) -> str | None:
        if not name or name.lower() in KEEP_ACCOUNTS or name.endswith("$"):
            return name
        return self.users.setdefault(name.lower(), f"user{len(self.users) + 1:02d}")

    def host(self, name: str | None) -> str | None:
        if not name:
            return name
        return self.hosts.setdefault(name.lower(), f"host{len(self.hosts) + 1:02d}")

    def ip(self, value: str | None) -> str | None:
        if not value:
            return value
        try:
            addr = ipaddress.ip_address(value)
        except ValueError:
            return value
        if addr.is_loopback or addr.is_unspecified:
            return value
        if value not in self.ips:
            n = len(self.ips) + 1
            # Private stays private, public becomes a documentation range (RFC 5737), so rules behave the same.
            self.ips[value] = f"10.99.{n // 250}.{n % 250 + 1}" if addr.is_private else f"203.0.113.{n % 254 + 1}"
        return self.ips[value]

    def table(self) -> list[dict[str, str]]:
        rows = [{"kind": "account", "original": k, "pseudonym": v} for k, v in self.users.items()]
        rows += [{"kind": "host", "original": k, "pseudonym": v} for k, v in self.hosts.items()]
        rows += [{"kind": "ip", "original": k, "pseudonym": v} for k, v in self.ips.items()]
        return rows

    def scrub(self, value: Any) -> Any:
        """Replace every known original in free text, longest first so 'ws-01.corp' wins over 'ws-01'."""
        if isinstance(value, dict):
            return {k: self.scrub(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.scrub(v) for v in value]
        if not isinstance(value, str):
            return value
        pairs = [(o, p, r"(?<![\w.-])", r"(?![\w-])") for o, p in {**self.users, **self.hosts}.items()]
        pairs += [(o, p, r"(?<![\d.])", r"(?!\d)") for o, p in self.ips.items()]
        for original, pseudonym, before, after in sorted(pairs, key=lambda x: -len(x[0])):
            value = re.sub(before + re.escape(original) + after, pseudonym, value, flags=re.IGNORECASE)
        return value


def select_events(lab: LabService, query: str) -> list[NormalizedEvent]:
    try:
        parsed = query_service.parse(query)
        if parsed.stats_by:
            raise AuthoringError("use a query that returns events (no '| stats')")
        events = [e for e in lab.store.events.sorted() if parsed.predicate(e)]
    except query_service.QueryError as exc:
        raise AuthoringError(str(exc)) from exc
    if not events:
        raise AuthoringError("the query matched no events")
    if len(events) > MAX_SCENARIO_EVENTS:
        raise AuthoringError(f"the query matched {len(events)} events; narrow it to at most {MAX_SCENARIO_EVENTS}")
    if (events[-1].timestamp - events[0].timestamp).total_seconds() > MAX_SPAN_SECONDS:
        raise AuthoringError("the selected events span more than 7 days; narrow the time range")
    return events


def _record(event: NormalizedEvent, names: Pseudonyms | None) -> dict[str, Any]:
    record = event.model_dump(mode="json", exclude={"id", "ingested_at", "dataset", "timestamp"}, exclude_none=True)
    if names is not None:
        for attr in ("username", "target_username"):
            if attr in record:
                record[attr] = names.user(record[attr])
        if "hostname" in record:
            record["hostname"] = names.host(record["hostname"])
        for attr in ("source_ip", "destination_ip"):
            if attr in record:
                record[attr] = names.ip(record[attr])
    return record


def build_scenario(lab: LabService, draft: ScenarioDraft) -> tuple[Scenario, list[dict[str, str]]]:
    events = select_events(lab, draft.query)
    names = Pseudonyms() if draft.anonymize else None
    records = [_record(e, names) for e in events]
    if names is not None:  # Second pass: now every original is known, scrub free text everywhere.
        records = [names.scrub(r) for r in records]

    start = events[0].timestamp
    steps = []
    for event, record in zip(events, records, strict=True):
        record = {k: (escape(v) if isinstance(v, str) else _escape_all(v)) for k, v in record.items()}
        record["timestamp"] = "{ts}"
        # The replay marker keeps every run's raw text (and so its event id) unique.
        record["raw"] = "[replay {ts}] " + record.get("raw", "")
        steps.append(ScenarioStep(format="normalized_json", offset_seconds=int((event.timestamp - start).total_seconds()), record=record))

    slug = _SLUG.sub("-", draft.name.lower()).strip("-")[:48] or "scenario"
    scenario_id = f"custom-{slug}"
    n = 2
    while scenario_id in lab.scenarios and lab.scenarios[scenario_id].origin == "builtin":
        scenario_id, n = f"custom-{slug}-{n}", n + 1

    preview_scenario = Scenario(
        id=scenario_id,
        name=draft.name,
        summary=draft.summary or f"Replay of {len(events)} events selected with: {draft.query}",
        narrative=draft.narrative or draft.summary or "Scenario built from real log data in the lab.",
        category=draft.category,
        level=draft.level,
        expected_severity=Severity.low,
        expected_rules=[],
        benign=draft.verdict != "malicious",
        verdict=draft.verdict,
        tags=["Custom", "Anonymized"] if draft.anonymize else ["Custom"],
        mitre=[],
        hosts=sorted({str(r.get("hostname")) for r in records if r.get("hostname")})[:20],
        learning_objectives=["Investigate activity reconstructed from real log data."],
        investigation_questions=[q.question for q in draft.challenge],
        steps=steps,
        challenge=draft.challenge,
        origin="custom",
    )
    return _with_answer_key(lab, preview_scenario), names.table() if names else []


def _escape_all(value: Any) -> Any:
    if isinstance(value, str):
        return escape(value)
    if isinstance(value, dict):
        return {k: _escape_all(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_escape_all(v) for v in value]
    return value


def _with_answer_key(lab: LabService, scenario: Scenario) -> Scenario:
    """Fill expected rules / severity / MITRE by replaying the scenario through the engine (rules as tuned now)."""
    import random

    from app.simulation.baseline import ANCHOR
    from app.simulation.scenarios import choose_start, render

    suite = lab.regression_suite
    rendered = render(scenario, choose_start(scenario, ANCHOR, random.Random(1), lab.timezone), 1, dataset="authoring")
    ids = {e.id for e in rendered.events}
    combined = sorted(suite.baseline + rendered.events, key=lambda e: (e.timestamp, e.id))
    alerts = [a for a in lab.engine.run(combined, lab.rule_config()) if ids & set(a.event_ids)]
    scenario.expected_rules = sorted({a.rule_id for a in alerts})
    scenario.expected_severity = Severity.max([a.severity for a in alerts]) if alerts else Severity.low
    scenario.mitre = sorted({m.technique_id for a in alerts for m in a.mitre})
    return scenario
