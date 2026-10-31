from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Request

from app.models.alerts import Alert
from app.models.incidents import Incident
from app.services.lab import LabService


def get_lab(request: Request) -> LabService:
    return request.app.state.lab


Lab = Annotated[LabService, Depends(get_lab)]


def require_alert(lab: LabService, alert_id: str) -> Alert:
    alert = lab.store.alerts.get(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"alert {alert_id} not found")
    return alert


def require_incident(lab: LabService, incident_id: str) -> Incident:
    incident = lab.store.incidents.get(incident_id.upper())
    if incident is None:
        raise HTTPException(status_code=404, detail=f"incident {incident_id} not found")
    return incident
