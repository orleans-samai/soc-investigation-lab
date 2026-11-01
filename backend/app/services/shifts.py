"""Shift mode: a timed alert queue that mixes real attacks with benign activity and false positives.

The analyst triages every alert (malicious / benign / false positive) with a short justification, against
a clock. The score rewards, in this order: never letting an attack through, closing noise correctly,
working the queue by severity, and writing notes another analyst could verify.
"""

from __future__ import annotations

import random
import uuid
from datetime import timedelta
from typing import Any

from app.models.alerts import Alert, AlertStatus
from app.models.common import Severity, utcnow
from app.models.shifts import Shift, ShiftDecision, ShiftItem, ShiftScore
from app.services.ingestion import run_simulation
from app.services.lab import LabService

ATTACKS_PER_SHIFT = 2
NOISE_PER_SHIFT = 2
# Seconds from shift start within which an alert of this severity should be triaged.
SLA_SECONDS = {Severity.critical: 180, Severity.high: 300, Severity.medium: 600, Severity.low: 900}
ACCURACY_POINTS, SPEED_POINTS, NOTE_POINTS = 6, 2, 2
ITEM_POINTS = ACCURACY_POINTS + SPEED_POINTS + NOTE_POINTS
VERDICT_STATUS = {"malicious": AlertStatus.investigating, "benign": AlertStatus.benign, "false_positive": AlertStatus.false_positive}
LABELS = {"malicious": "malicious", "benign": "benign true positive", "false_positive": "false positive"}


class ShiftError(ValueError):
    pass


def start_shift(lab: LabService, duration_minutes: int, seed: int | None) -> Shift:
    rng = random.Random(seed if seed is not None else random.SystemRandom().randrange(1, 2**31))
    builtin = [s for s in lab.scenarios.values() if s.origin == "builtin" and s.expected_rules]
    attacks = [s for s in builtin if s.expected_verdict == "malicious"]
    noise = [s for s in builtin if s.expected_verdict != "malicious"]
    if not attacks or not noise:
        raise ShiftError("the lab needs both attack and benign scenarios to run a shift")
    chosen = rng.sample(attacks, min(ATTACKS_PER_SHIFT, len(attacks))) + rng.sample(noise, min(NOISE_PER_SHIFT, len(noise)))
    rng.shuffle(chosen)

    with lab.store.lock:
        if any(s.status == "active" for s in lab.store.shifts.all()):
            raise ShiftError("a shift is already in progress; finish it first")
        items: list[ShiftItem] = []
        seen: set[str] = set()
        for scenario in chosen:
            run = run_simulation(lab, scenario.id, rng.randrange(1, 2**31))
            for alert_id in run.alert_ids:
                if alert_id in seen:
                    continue
                seen.add(alert_id)
                items.append(ShiftItem(alert_id=alert_id, run_id=run.id, scenario_id=scenario.id, truth=scenario.expected_verdict))
        started = utcnow()
        shift = Shift(
            id="shf_" + uuid.uuid4().hex[:8],
            started_at=started,
            duration_minutes=duration_minutes,
            ends_at=started + timedelta(minutes=duration_minutes),
            scenario_ids=[s.id for s in chosen],
            items=items,
        )
        lab.store.shifts.upsert(shift)
        lab.log(
            "analyst",
            "shift.started",
            f"Shift {shift.id} started: {len(items)} alerts in the queue, {duration_minutes} min",
            "shift",
            shift.id,
        )
        lab.store.persist_all()
    return shift


def _note_points(note: str | None, alert: Alert | None) -> int:
    text = (note or "").strip()
    if len(text) < 10:
        return 0
    entities = [v for v in (alert.username, alert.hostname, alert.source_ip) if v] if alert else []
    if len(text) >= 25 and any(v.lower() in text.lower() for v in entities):
        return NOTE_POINTS
    return NOTE_POINTS // 2


def _grade(item: ShiftItem) -> tuple[int, str]:
    if item.verdict is None:
        if item.truth == "malicious":
            return 0, "Not triaged before the end of the shift: an attack was left in the queue."
        return 0, "Not triaged before the end of the shift."
    if item.verdict == item.truth:
        return ACCURACY_POINTS, f"Correct: {LABELS[item.truth]}."
    if item.truth == "malicious":
        return 0, f"Missed attack: closed as {LABELS[item.verdict]} but this alert was part of a real intrusion."
    if item.verdict == "malicious":
        return 2, f"Unnecessary escalation: the activity was a {LABELS[item.truth]}."
    return 4, f"Not malicious, but this was a {LABELS[item.truth]} rather than a {LABELS[item.verdict]}."


def decide(lab: LabService, shift: Shift, alert_id: str, body: ShiftDecision) -> ShiftItem:
    if shift.status != "active":
        raise ShiftError("the shift has ended")
    item = next((i for i in shift.items if i.alert_id == alert_id), None)
    if item is None:
        raise ShiftError(f"alert {alert_id} is not in this shift's queue")
    with lab.store.lock:
        now = utcnow()
        item.verdict = body.verdict
        item.note = body.note.strip() or None
        item.decided_at = now
        item.seconds_to_decide = int((now - shift.started_at).total_seconds())
        alert = lab.store.alerts.get(alert_id)
        if alert is not None:
            alert.status = VERDICT_STATUS[body.verdict]
            if item.note:
                alert.analyst_note = item.note
            alert.updated_at = now
            lab.log("analyst", "alert.updated", f"{alert.rule_name} ({alert.id}): triaged as {LABELS[body.verdict]} during shift {shift.id}",
                    "alert", alert.id)  # fmt: skip
        lab.store.shifts.upsert(shift)
        if all(i.verdict for i in shift.items):
            finish(lab, shift)
        lab.store.persist_all()
    return item


def finish(lab: LabService, shift: Shift) -> Shift:
    if shift.status == "finished":
        return shift
    with lab.store.lock:
        for item in shift.items:
            alert = lab.store.alerts.get(item.alert_id)
            item.accuracy_points, item.feedback = _grade(item)
            item.speed_points = 0
            if item.verdict and item.seconds_to_decide is not None and item.accuracy_points:
                sla = SLA_SECONDS[alert.severity] if alert else 600
                item.speed_points = SPEED_POINTS if item.seconds_to_decide <= sla else 1 if item.seconds_to_decide <= 2 * sla else 0
            item.note_points = _note_points(item.note, alert) if item.verdict else 0
        n = len(shift.items) or 1
        accuracy = sum(i.accuracy_points for i in shift.items)
        speed = sum(i.speed_points for i in shift.items)
        notes = sum(i.note_points for i in shift.items)
        shift.score = ShiftScore(
            total=round(100 * (accuracy + speed + notes) / (n * ITEM_POINTS)),
            accuracy=round(100 * accuracy / (n * ACCURACY_POINTS)),
            speed=round(100 * speed / (n * SPEED_POINTS)),
            documentation=round(100 * notes / (n * NOTE_POINTS)),
            decided=sum(1 for i in shift.items if i.verdict),
            correct=sum(1 for i in shift.items if i.verdict == i.truth),
            missed_attacks=sum(1 for i in shift.items if i.truth == "malicious" and i.verdict != "malicious"),
            wasted_escalations=sum(1 for i in shift.items if i.truth != "malicious" and i.verdict == "malicious"),
        )
        shift.status = "finished"
        shift.finished_at = utcnow()
        lab.store.shifts.upsert(shift)
        lab.log("analyst", "shift.finished", f"Shift {shift.id} finished: score {shift.score.total}/100, "
                f"{shift.score.missed_attacks} missed attacks", "shift", shift.id)  # fmt: skip
        lab.store.persist_all()
    return shift


def expire_if_due(lab: LabService, shift: Shift) -> Shift:
    if shift.status == "active" and utcnow() >= shift.ends_at:
        return finish(lab, shift)
    return shift


def view(lab: LabService, shift: Shift) -> dict[str, Any]:
    finished = shift.status == "finished"
    queue = []
    for item in shift.items:
        alert = lab.store.alerts.get(item.alert_id)
        entry: dict[str, Any] = {
            "alert_id": item.alert_id,
            "verdict": item.verdict,
            "note": item.note,
            "seconds_to_decide": item.seconds_to_decide,
            "sla_seconds": SLA_SECONDS[alert.severity] if alert else None,
            "alert": alert,
        }
        if finished:
            scenario = lab.scenarios.get(item.scenario_id)
            entry |= {
                "truth": item.truth,
                "scenario_id": item.scenario_id,
                "scenario_name": scenario.name if scenario else item.scenario_id,
                "run_id": item.run_id,
                "accuracy_points": item.accuracy_points,
                "speed_points": item.speed_points,
                "note_points": item.note_points,
                "feedback": item.feedback,
            }
        queue.append(entry)
    queue.sort(key=lambda e: (e["alert"].timestamp if e["alert"] else shift.started_at, e["alert_id"]))
    return {
        "id": shift.id,
        "status": shift.status,
        "started_at": shift.started_at,
        "ends_at": shift.ends_at,
        "finished_at": shift.finished_at,
        "duration_minutes": shift.duration_minutes,
        "now": utcnow(),
        "score": shift.score,
        "max_points_per_alert": {"accuracy": ACCURACY_POINTS, "speed": SPEED_POINTS, "note": NOTE_POINTS},
        "queue": queue,
    }
