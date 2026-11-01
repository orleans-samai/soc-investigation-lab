"""The detection engine: normalized events in, structured alerts out.

It is a pure function of (events, rule configuration, inventory). It does not know about storage,
HTTP or the UI, which is what makes it straightforward to unit-test and to backtest rule tuning.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass

from app.detection.base import AlertDraft, DetectionContext, Rule
from app.detection.rules import builtin_rules
from app.models.alerts import Alert, Evidence
from app.models.common import MitreRef
from app.models.events import NormalizedEvent

log = logging.getLogger(__name__)
MAX_EVENTS_PER_ALERT = 500


@dataclass
class RuleConfig:
    enabled: bool = True
    params: dict[str, int] | None = None


class DetectionEngine:
    def __init__(self, context: DetectionContext, rules: list[Rule] | None = None):
        self.context = context
        self._builtin = rules or builtin_rules()
        self.rules = list(self._builtin)
        self._by_id = {rule.id: rule for rule in self.rules}

    def set_custom_rules(self, custom: list[Rule]) -> None:
        """Replace the analyst-authored rules; built-in rules are always kept."""
        self.rules = sorted(self._builtin + custom, key=lambda r: r.id)
        self._by_id = {rule.id: rule for rule in self.rules}

    def rule(self, rule_id: str) -> Rule | None:
        return self._by_id.get(rule_id)

    def run(self, events: list[NormalizedEvent], config: dict[str, RuleConfig] | None = None) -> list[Alert]:
        """Evaluate every enabled rule over ``events`` (must be sorted by timestamp)."""
        config = config or {}
        alerts: list[Alert] = []
        for rule in self.rules:
            rule_config = config.get(rule.id, RuleConfig())
            if not rule_config.enabled:
                continue
            alerts.extend(self.run_rule(rule, events, rule_config.params))
        alerts.sort(key=lambda a: (a.timestamp, a.id))
        return alerts

    def run_rule(self, rule: Rule, events: list[NormalizedEvent], overrides: dict[str, int] | None = None) -> list[Alert]:
        params = rule.resolve_params(overrides)
        try:
            drafts = rule.evaluate(events, self.context, params)
        except Exception:  # A broken rule must never take the whole pipeline down.
            log.exception("rule %s failed", rule.id)
            return []
        return [self._to_alert(draft) for draft in drafts]

    @staticmethod
    def _to_alert(draft: AlertDraft) -> Alert:
        rule = draft.rule
        events = sorted({e.id: e for e in draft.events}.values(), key=lambda e: (e.timestamp, e.id))
        fingerprint = draft.fingerprint
        mitre: list[MitreRef] = list(rule.mitre)
        for extra in draft.extra_mitre:
            if extra.technique_id not in {m.technique_id for m in mitre}:
                mitre.append(extra)
        return Alert(
            id="alr_" + hashlib.sha1(fingerprint.encode()).hexdigest()[:12],
            fingerprint=fingerprint,
            rule_id=rule.id,
            rule_name=rule.name,
            description=rule.description,
            severity=draft.severity or rule.severity,
            timestamp=draft.trigger.timestamp,
            first_seen=events[0].timestamp,
            hostname=draft.hostname,
            username=draft.username,
            source_ip=draft.source_ip,
            event_ids=[e.id for e in events][:MAX_EVENTS_PER_ALERT],
            event_count=len(events),
            reason=draft.reason,
            evidence=[Evidence(label=label, value=value) for label, value in draft.evidence],
            mitre=mitre,
            fp_hints=draft.fp_hints,
        )
