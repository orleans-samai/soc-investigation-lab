"""Controlled incident simulation.

Scenarios are JSON templates of *raw* log lines / Windows records. A run renders them with concrete
timestamps and variables, then pushes the raw text through the same parsers used for file imports,
so the whole pipeline (raw log -> normalized event -> detection -> alert -> incident) is exercised.
"""

from __future__ import annotations

import json
import random
import re
from dataclasses import dataclass
from datetime import datetime, time, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from app.models.events import NormalizedEvent
from app.models.imports import LogFormat
from app.models.simulations import Scenario
from app.parsers import PARSERS, ParseOptions

_PLACEHOLDER = re.compile(r"\{(\w+)\}")


class ScenarioError(ValueError):
    pass


def load_scenarios(directory: Path) -> dict[str, Scenario]:
    scenarios: dict[str, Scenario] = {}
    for path in sorted(directory.glob("*.json")):
        with path.open(encoding="utf-8") as fh:
            scenario = Scenario.model_validate(json.load(fh))
        if scenario.id in scenarios:
            raise ScenarioError(f"duplicate scenario id {scenario.id}")
        scenarios[scenario.id] = scenario
    return scenarios


def estimate_events(scenario: Scenario) -> int:
    return sum(step.repeat for step in scenario.steps)


@dataclass
class RenderedScenario:
    events: list[NormalizedEvent]
    variables: dict[str, Any]
    start: datetime
    end: datetime


def _substitute(value: Any, variables: dict[str, Any]) -> Any:
    if isinstance(value, str):

        def repl(match: re.Match[str]) -> str:
            name = match.group(1)
            if name not in variables:
                raise ScenarioError(f"unknown placeholder {{{name}}}")
            return str(variables[name])

        return _PLACEHOLDER.sub(repl, value)
    if isinstance(value, dict):
        return {k: _substitute(v, variables) for k, v in value.items()}
    if isinstance(value, list):
        return [_substitute(v, variables) for v in value]
    return value


def _format_ts(ts: datetime, fmt: str) -> str:
    if fmt == LogFormat.windows_json:
        return f"{ts:%Y-%m-%dT%H:%M:%S.%f}0Z"  # Windows emits 7 fractional digits.
    return ts.isoformat(timespec="microseconds")


def choose_start(scenario: Scenario, clock: datetime, rng: random.Random, tz: ZoneInfo) -> datetime:
    # Leave a realistic quiet gap after the latest activity so independent runs don't overlap.
    start = clock + timedelta(minutes=rng.randint(45, 120), seconds=rng.randint(0, 59))
    if scenario.time_of_day_local:
        hour, minute = (int(x) for x in scenario.time_of_day_local.split(":"))
        local = start.astimezone(tz)
        candidate = datetime.combine(local.date(), time(hour, minute), tz)
        if candidate < local:
            candidate += timedelta(days=1)
        start = candidate.astimezone(ZoneInfo("UTC")) + timedelta(seconds=rng.randint(0, 300))
    return start


def render(scenario: Scenario, start: datetime, seed: int, dataset: str) -> RenderedScenario:
    rng = random.Random(seed)
    variables = {name: rng.choice(options) for name, options in scenario.variables.items()}

    raw: dict[str, list[tuple[datetime, Any]]] = {}
    for step in scenario.steps:
        moment = start + timedelta(seconds=step.offset_seconds)
        for i in range(step.repeat):
            if i:
                low, high = step.interval_seconds
                moment += timedelta(seconds=rng.uniform(low, high))
            jittered = moment + timedelta(milliseconds=rng.randint(0, 999))
            values = dict(variables)
            values["i"] = i
            values["ts"] = _format_ts(jittered, step.format)
            for name, options in step.cycle.items():
                values[name] = options[i % len(options)]
            for name, (low, high) in step.random_int.items():
                values[name] = rng.randint(low, high)
            if step.line is not None:
                payload: Any = _substitute(step.line, values)
            elif step.record is not None:
                payload = _substitute(step.record, values)
            else:
                raise ScenarioError(f"step in {scenario.id} has neither 'line' nor 'record'")
            raw.setdefault(step.format, []).append((jittered, payload))

    events: list[NormalizedEvent] = []
    options = ParseOptions(dataset=dataset)
    for fmt, items in raw.items():
        items.sort(key=lambda item: item[0])
        if fmt == LogFormat.linux_ssh:
            text = "\n".join(str(payload) for _, payload in items)
        else:
            text = json.dumps([payload for _, payload in items])
        result = PARSERS[LogFormat(fmt)].parse(text, options)
        if result.error_count:
            first = result.errors[0]
            raise ScenarioError(f"scenario {scenario.id} produced unparseable data (line {first.line}: {first.message})")
        events.extend(result.events)

    events.sort(key=lambda e: e.timestamp)
    end = events[-1].timestamp if events else start
    return RenderedScenario(events=events, variables=variables, start=start, end=end)
