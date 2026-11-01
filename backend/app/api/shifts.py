"""Shift mode: a timed triage queue mixing attacks, benign activity and false positives."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.api.deps import Lab
from app.models.shifts import Shift, ShiftDecision, ShiftStart
from app.services import shifts as shift_service
from app.simulation.scenarios import ScenarioError

router = APIRouter(tags=["shifts"])


def _require_shift(lab, shift_id: str) -> Shift:
    shift = lab.store.shifts.get(shift_id)
    if shift is None:
        raise HTTPException(404, f"shift {shift_id} not found")
    return shift_service.expire_if_due(lab, shift)


@router.get("/shifts")
def list_shifts(lab: Lab):
    shifts = sorted(lab.store.shifts.all(), key=lambda s: s.started_at, reverse=True)
    return [
        {"id": s.id, "status": shift_service.expire_if_due(lab, s).status, "started_at": s.started_at, "ends_at": s.ends_at,
         "duration_minutes": s.duration_minutes, "alerts": len(s.items), "score": s.score}
        for s in shifts
    ]  # fmt: skip


@router.post("/shifts", status_code=201)
def start_shift(lab: Lab, body: ShiftStart):
    try:
        shift = shift_service.start_shift(lab, body.duration_minutes, body.seed)
    except shift_service.ShiftError as exc:
        raise HTTPException(409, str(exc)) from exc
    except ScenarioError as exc:
        raise HTTPException(500, f"scenario error: {exc}") from exc
    return shift_service.view(lab, shift)


@router.get("/shifts/{shift_id}")
def get_shift(lab: Lab, shift_id: str):
    return shift_service.view(lab, _require_shift(lab, shift_id))


@router.post("/shifts/{shift_id}/alerts/{alert_id}")
def decide(lab: Lab, shift_id: str, alert_id: str, body: ShiftDecision):
    shift = _require_shift(lab, shift_id)
    try:
        shift_service.decide(lab, shift, alert_id, body)
    except shift_service.ShiftError as exc:
        raise HTTPException(409, str(exc)) from exc
    return shift_service.view(lab, shift)


@router.post("/shifts/{shift_id}/finish")
def finish(lab: Lab, shift_id: str):
    shift = _require_shift(lab, shift_id)
    return shift_service.view(lab, shift_service.finish(lab, shift))
