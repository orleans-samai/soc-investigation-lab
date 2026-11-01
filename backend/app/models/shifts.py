from __future__ import annotations

from typing import Literal

from pydantic import Field

from app.models.common import ApiModel, UtcDatetime, utcnow

Verdict = Literal["malicious", "benign", "false_positive"]


class ShiftItem(ApiModel):
    alert_id: str
    run_id: str
    scenario_id: str
    # Ground truth, never sent to the client before the shift ends.
    truth: Verdict
    verdict: Verdict | None = None
    note: str | None = None
    decided_at: UtcDatetime | None = None
    seconds_to_decide: int | None = None
    accuracy_points: int = 0
    speed_points: int = 0
    note_points: int = 0
    feedback: str | None = None


class ShiftScore(ApiModel):
    total: int
    accuracy: int
    speed: int
    documentation: int
    decided: int
    correct: int
    missed_attacks: int
    wasted_escalations: int


class Shift(ApiModel):
    id: str
    started_at: UtcDatetime = Field(default_factory=utcnow)
    duration_minutes: int
    ends_at: UtcDatetime
    status: Literal["active", "finished"] = "active"
    finished_at: UtcDatetime | None = None
    scenario_ids: list[str]
    items: list[ShiftItem]
    score: ShiftScore | None = None


class ShiftStart(ApiModel):
    duration_minutes: int = Field(default=20, ge=5, le=120)
    seed: int | None = Field(default=None, ge=0, le=2**31)


class ShiftDecision(ApiModel):
    verdict: Verdict
    note: str = Field(default="", max_length=4000)
