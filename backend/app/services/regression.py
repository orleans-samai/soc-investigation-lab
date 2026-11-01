"""Detection regression testing: does a rule change still catch every attack, and how much noise does it remove?

Every scenario is rendered with fixed seeds on top of the baseline week, then evaluated twice: with the
rule configuration currently in force ("before") and with the candidate changes applied ("after").
Nothing is written to the lab; this is the detection-engineering equivalent of running the test suite
before merging.
"""

from __future__ import annotations

import random
from collections import Counter
from functools import cached_property

from pydantic import Field

from app.detection.engine import RuleConfig
from app.models.common import ApiModel, UtcDatetime, utcnow
from app.models.events import NormalizedEvent
from app.services.lab import LabService
from app.simulation.baseline import ANCHOR
from app.simulation.scenarios import choose_start, render

SEEDS = (1, 99)


class RuleChange(ApiModel):
    enabled: bool | None = None
    params: dict[str, int] = Field(default_factory=dict)


class RegressionRequest(ApiModel):
    changes: dict[str, RuleChange] = Field(default_factory=dict)


class ScenarioOutcome(ApiModel):
    scenario_id: str
    name: str
    verdict: str
    origin: str
    expected_rules: list[str]
    # Expected rules that failed to fire in at least one seed.
    missed_before: list[str]
    missed_after: list[str]
    alerts_before: int
    alerts_after: int
    # detected | missed | regressed | fixed (attacks); noise_reduced | noise_added | unchanged (benign)
    status: str


class BaselineRule(ApiModel):
    rule_id: str
    before: int
    after: int


class RegressionSummary(ApiModel):
    attack_scenarios: int
    detected_before: int
    detected_after: int
    regressions: int
    fixes: int
    noise_before: int
    noise_after: int


class RegressionReport(ApiModel):
    generated_at: UtcDatetime = Field(default_factory=utcnow)
    seeds: list[int]
    changes: dict[str, RuleChange]
    passed: bool
    summary: RegressionSummary
    scenarios: list[ScenarioOutcome]
    baseline: list[BaselineRule]


class RegressionSuite:
    """Rendered test corpus, built once per lab (scenarios are deterministic for a given seed)."""

    def __init__(self, lab: LabService):
        self.lab = lab
        self._rendered: dict[tuple[str, int], list[NormalizedEvent]] = {}

    @cached_property
    def baseline(self) -> list[NormalizedEvent]:
        return sorted(self.lab._load_seed(), key=lambda e: (e.timestamp, e.id))

    def scenario_events(self, scenario_id: str, seed: int) -> list[NormalizedEvent]:
        key = (scenario_id, seed)
        if key not in self._rendered:
            scenario = self.lab.scenarios[scenario_id]
            start = choose_start(scenario, ANCHOR, random.Random(seed), self.lab.timezone)
            self._rendered[key] = render(scenario, start, seed, dataset=f"regression:{scenario_id}").events
        return self._rendered[key]

    def forget(self, scenario_id: str) -> None:
        for key in [k for k in self._rendered if k[0] == scenario_id]:
            del self._rendered[key]


def candidate_config(current: dict[str, RuleConfig], changes: dict[str, RuleChange]) -> dict[str, RuleConfig]:
    config = {rule_id: RuleConfig(enabled=c.enabled, params=dict(c.params or {})) for rule_id, c in current.items()}
    for rule_id, change in changes.items():
        base = config.get(rule_id, RuleConfig())
        config[rule_id] = RuleConfig(
            enabled=base.enabled if change.enabled is None else change.enabled,
            params={**(base.params or {}), **change.params},
        )
    return config


def run_regression(lab: LabService, suite: RegressionSuite, changes: dict[str, RuleChange]) -> RegressionReport:
    engine = lab.engine
    before_config = lab.rule_config()
    after_config = candidate_config(before_config, changes)
    changed = {rule_id for rule_id in changes if engine.rule(rule_id)}

    def evaluate(events: list[NormalizedEvent]):
        """Alerts with the current config, and with the candidate (only changed rules are re-run)."""
        before = engine.run(events, before_config)
        after = [a for a in before if a.rule_id not in changed]
        for rule_id in changed:
            cfg = after_config[rule_id]
            if cfg.enabled:
                after.extend(engine.run_rule(engine.rule(rule_id), events, cfg.params))
        return before, after

    base_before, base_after = evaluate(suite.baseline)
    base_ids = {a.id for a in base_before} | {a.id for a in base_after}
    count_before = Counter(a.rule_id for a in base_before)
    count_after = Counter(a.rule_id for a in base_after)
    baseline_rows = [
        BaselineRule(rule_id=r, before=count_before[r], after=count_after[r]) for r in sorted(set(count_before) | set(count_after))
    ]

    outcomes: list[ScenarioOutcome] = []
    for scenario in lab.scenarios.values():
        missed_before: set[str] = set()
        missed_after: set[str] = set()
        alerts_before = alerts_after = 0
        for seed in SEEDS:
            scenario_events = suite.scenario_events(scenario.id, seed)
            ids = {e.id for e in scenario_events}
            events = sorted(suite.baseline + scenario_events, key=lambda e: (e.timestamp, e.id))
            before, after = evaluate(events)
            # Only alerts that involve the scenario's own events count towards it.
            hit_before = [a for a in before if a.id not in base_ids and ids & set(a.event_ids)]
            hit_after = [a for a in after if a.id not in base_ids and ids & set(a.event_ids)]
            alerts_before += len(hit_before)
            alerts_after += len(hit_after)
            missed_before |= set(scenario.expected_rules) - {a.rule_id for a in hit_before}
            missed_after |= set(scenario.expected_rules) - {a.rule_id for a in hit_after}

        malicious = scenario.expected_verdict == "malicious"
        if malicious:
            status = {
                (False, False): "detected",
                (False, True): "regressed",
                (True, False): "fixed",
                (True, True): "missed",
            }[(bool(missed_before), bool(missed_after))]
        else:
            status = "noise_reduced" if alerts_after < alerts_before else "noise_added" if alerts_after > alerts_before else "unchanged"
        outcomes.append(
            ScenarioOutcome(
                scenario_id=scenario.id,
                name=scenario.name,
                verdict=scenario.expected_verdict,
                origin=scenario.origin,
                expected_rules=scenario.expected_rules,
                missed_before=sorted(missed_before),
                missed_after=sorted(missed_after),
                alerts_before=alerts_before,
                alerts_after=alerts_after,
                status=status,
            )
        )

    attacks = [o for o in outcomes if o.verdict == "malicious"]
    benign = [o for o in outcomes if o.verdict != "malicious"]
    summary = RegressionSummary(
        attack_scenarios=len(attacks),
        detected_before=sum(1 for o in attacks if not o.missed_before),
        detected_after=sum(1 for o in attacks if not o.missed_after),
        regressions=sum(1 for o in attacks if o.status == "regressed"),
        fixes=sum(1 for o in attacks if o.status == "fixed"),
        noise_before=len(base_before) + sum(o.alerts_before for o in benign),
        noise_after=len(base_after) + sum(o.alerts_after for o in benign),
    )
    order = {"regressed": 0, "missed": 1, "noise_added": 2, "fixed": 3, "noise_reduced": 4, "detected": 5, "unchanged": 6}
    return RegressionReport(
        seeds=list(SEEDS),
        changes=changes,
        passed=summary.regressions == 0,
        summary=summary,
        scenarios=sorted(outcomes, key=lambda o: (order[o.status], o.name)),
        baseline=baseline_rows,
    )
