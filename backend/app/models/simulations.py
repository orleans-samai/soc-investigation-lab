from __future__ import annotations

from typing import Any, Literal

from pydantic import Field

from app.models.common import ApiModel, Severity, UtcDatetime, utcnow


class ScenarioStep(ApiModel):
    format: str
    offset_seconds: int = 0
    repeat: int = Field(default=1, ge=1, le=500)
    interval_seconds: tuple[int, int] = (1, 1)
    cycle: dict[str, list[Any]] = Field(default_factory=dict)
    random_int: dict[str, tuple[int, int]] = Field(default_factory=dict)
    line: str | None = None
    record: dict[str, Any] | None = None


class ScenarioMaintenance(ApiModel):
    description: str
    usernames: list[str]
    hosts: list[str]
    duration_minutes: int = Field(default=60, ge=1, le=24 * 60)


class ChallengeQuestion(ApiModel):
    """A question the analyst answers from the evidence. Answers may reference run variables ({attacker_ip})."""

    id: str
    question: str
    kind: Literal["text", "choice"] = "text"
    options: list[str] = Field(default_factory=list)
    answers: list[str] = Field(min_length=1)
    points: int = Field(default=25, ge=1, le=100)
    hint: str
    explanation: str


class Scenario(ApiModel):
    id: str
    name: str
    summary: str
    narrative: str
    category: str
    level: str
    expected_severity: Severity
    expected_rules: list[str]
    benign: bool = False
    # Force the run to start at this local wall-clock time ("HH:MM"), e.g. for after-hours scenarios.
    time_of_day_local: str | None = Field(default=None, pattern=r"^\d{2}:\d{2}$")
    # Registers an approved change ticket covering the run, so analysts can find the justification.
    maintenance_window: ScenarioMaintenance | None = None
    mitre: list[str]
    hosts: list[str]
    learning_objectives: list[str]
    investigation_questions: list[str]
    variables: dict[str, list[Any]] = Field(default_factory=dict)
    steps: list[ScenarioStep]
    challenge: list[ChallengeQuestion] = Field(default_factory=list)


class ScenarioSummary(ApiModel):
    id: str
    name: str
    summary: str
    narrative: str
    category: str
    level: str
    expected_severity: Severity
    expected_rules: list[str]
    benign: bool
    mitre: list[str]
    hosts: list[str]
    learning_objectives: list[str]
    investigation_questions: list[str]
    event_estimate: int
    challenge_points: int = 0
    run_count: int = 0
    last_run_id: str | None = None


class SimulationRequest(ApiModel):
    scenario_id: str
    seed: int | None = Field(default=None, ge=0, le=2**31)


class ChallengeAttempt(ApiModel):
    hints_used: list[str] = Field(default_factory=list)
    answers: dict[str, str] = Field(default_factory=dict)
    results: dict[str, bool] = Field(default_factory=dict)
    score: int = 0
    max_score: int = 0
    submitted_at: UtcDatetime | None = None


class ChallengeSubmission(ApiModel):
    answers: dict[str, str] = Field(default_factory=dict)


class HintRequest(ApiModel):
    question_id: str


class SimulationRun(ApiModel):
    id: str
    scenario_id: str
    scenario_name: str
    seed: int
    benign: bool = False
    simulated_start: UtcDatetime
    simulated_end: UtcDatetime
    executed_at: UtcDatetime = Field(default_factory=utcnow)
    event_count: int
    event_ids: list[str]
    alert_ids: list[str]
    incident_ids: list[str]
    expected_rules: list[str]
    triggered_rules: list[str]
    missed_rules: list[str]
    unexpected_rules: list[str]
    variables: dict[str, Any] = Field(default_factory=dict)
    challenge: ChallengeAttempt = Field(default_factory=lambda: ChallengeAttempt())

    @property
    def fully_detected(self) -> bool:
        return not self.missed_rules
