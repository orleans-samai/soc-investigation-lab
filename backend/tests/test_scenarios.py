"""Detection validation: every simulated attack must trigger exactly the rules it is designed to exercise."""

from __future__ import annotations

import random
from collections import Counter
from zoneinfo import ZoneInfo

import pytest

from app.config import get_settings
from app.simulation.baseline import ANCHOR, generate_baseline
from app.simulation.scenarios import choose_start, load_scenarios, render

SCENARIOS = load_scenarios(get_settings().scenarios_dir)
TZ = ZoneInfo("America/Sao_Paulo")


@pytest.fixture(scope="module")
def baseline():
    return generate_baseline()


def test_baseline_is_deterministic_and_mostly_quiet(engine, baseline):
    assert [e.id for e in baseline] == [e.id for e in generate_baseline()]
    assert all(e.timestamp <= ANCHOR for e in baseline)
    fired = Counter(a.rule_id for a in engine.run(baseline))
    # Exactly the two organic stories baked into the baseline.
    assert fired == Counter({"LAB-005": 2, "LAB-001": 1})


@pytest.mark.parametrize("scenario_id", sorted(SCENARIOS))
@pytest.mark.parametrize("seed", [1, 99])
def test_scenario_triggers_expected_rules(engine, baseline, scenario_id, seed):
    scenario = SCENARIOS[scenario_id]
    start = choose_start(scenario, ANCHOR, random.Random(seed), TZ)
    rendered = render(scenario, start, seed, dataset="test")
    assert rendered.events, "scenario produced no events"
    ids = {e.id for e in rendered.events}
    alerts = engine.run(sorted(baseline + rendered.events, key=lambda e: (e.timestamp, e.id)))
    fired = {a.rule_id for a in alerts if ids & set(a.event_ids)}
    assert fired == set(scenario.expected_rules)
    highest = max((a.severity for a in alerts if ids & set(a.event_ids)), key=lambda s: s.rank)
    assert highest == scenario.expected_severity


def test_scenarios_cover_every_rule(engine):
    covered = {r for s in SCENARIOS.values() for r in s.expected_rules}
    assert covered == {rule.id for rule in engine.rules}


def test_after_hours_scenario_starts_at_night():
    scenario = SCENARIOS["after-hours-maintenance"]
    start = choose_start(scenario, ANCHOR, random.Random(3), TZ).astimezone(TZ)
    assert (start.hour, start.minute // 10) == (1, 4)
