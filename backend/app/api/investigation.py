"""Incidents, entities, reports, dashboard, metrics, search and lab administration."""

from __future__ import annotations

import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import PlainTextResponse

from app import __version__
from app.api.deps import Lab, require_alert, require_incident
from app.models.common import Page, Severity, utcnow
from app.models.incidents import Activity, Incident, IncidentCreate, IncidentStatus, IncidentUpdate, Note, NoteCreate
from app.services import analytics, entities, reports
from app.services.events import paginate

router = APIRouter()


# ---------------------------------------------------------------- incidents
@router.get("/incidents", response_model=Page[Incident], tags=["incidents"])
def list_incidents(
    lab: Lab,
    q: str | None = None,
    status: str | None = None,
    severity: str | None = None,
    classification: str | None = None,
    sort: Literal["updated", "severity", "first_seen", "id"] = "updated",
    order: Literal["asc", "desc"] = "desc",
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=200)] = 25,
):
    def keep(i: Incident) -> bool:
        if status and i.status.value not in status.split(","):
            return False
        if severity and i.severity.value not in severity.split(","):
            return False
        if classification and i.classification.value not in classification.split(","):
            return False
        if q:
            text = " ".join([i.id, i.title, i.summary, i.assignee or "", *sum(i.entities.values(), [])]).lower()
            return all(t in text for t in q.lower().split())
        return True

    keys = {
        "updated": lambda i: i.updated_at,
        "severity": lambda i: (i.severity.rank, i.last_seen),
        "first_seen": lambda i: i.first_seen,
        "id": lambda i: i.id,
    }
    items = sorted((i for i in lab.store.incidents.all() if keep(i)), key=keys[sort], reverse=order == "desc")
    return paginate(items, page, page_size)


@router.post("/incidents", response_model=Incident, status_code=201, tags=["incidents"])
def create_incident(lab: Lab, body: IncidentCreate):
    with lab.store.lock:
        alerts = [require_alert(lab, a) for a in dict.fromkeys(body.alert_ids)]
        taken = [a.id for a in alerts if a.incident_id]
        if taken:
            raise HTTPException(409, f"alerts already belong to an incident: {', '.join(taken)}")
        incident = lab.create_incident(alerts, actor="analyst", title=body.title)
        lab.store.persist_all()
        return incident


@router.get("/incidents/{incident_id}", tags=["incidents"])
def get_incident(lab: Lab, incident_id: str):
    incident = require_incident(lab, incident_id)
    alerts = lab.incident_alerts(incident)
    ids = {eid for a in alerts for eid in a.event_ids}
    events = [e for e in lab.store.events.sorted() if e.id in ids]
    activity = sorted((a for a in lab.store.activity.all() if a.target_id == incident.id), key=lambda a: a.timestamp, reverse=True)
    rules = {a.rule_id: lab.engine.rule(a.rule_id) for a in alerts}
    return {
        "incident": incident,
        "alerts": alerts,
        "events": events,
        "activity": activity,
        "playbook": [
            {"rule_id": rid, "rule_name": r.name, "steps": r.response, "false_positives": r.false_positives}
            for rid, r in rules.items()
            if r
        ],  # fmt: skip
    }


@router.patch("/incidents/{incident_id}", response_model=Incident, tags=["incidents"])
def update_incident(lab: Lab, incident_id: str, body: IncidentUpdate):
    with lab.store.lock:
        incident = require_incident(lab, incident_id)
        changes: list[str] = []
        if body.title and body.title != incident.title:
            incident.title = body.title.strip()
            changes.append("title updated")
        if body.assignee is not None and body.assignee != incident.assignee:
            incident.assignee = body.assignee.strip() or None
            changes.append(f"assigned to {incident.assignee or 'nobody'}")
        if body.severity and body.severity != incident.severity:
            changes.append(f"severity {incident.severity.value} -> {body.severity.value}")
            incident.severity = body.severity
        if body.resolution is not None:
            incident.resolution = body.resolution.strip() or None
            changes.append("resolution recorded")
        target_status = body.status or incident.status
        if target_status == IncidentStatus.closed and incident.status != IncidentStatus.closed:
            classification = body.classification or incident.classification
            if classification.value == "undetermined":
                raise HTTPException(422, "set a classification before closing the incident")
            if not (incident.resolution or "").strip():
                raise HTTPException(422, "document the resolution before closing the incident")
        if body.status and body.status != incident.status or (body.classification and body.classification != incident.classification):
            if body.status and body.status != incident.status:
                changes.append(f"status {incident.status.value} -> {body.status.value}")
            if body.classification and body.classification != incident.classification:
                changes.append(f"classified as {body.classification.value}")
            lab.apply_incident_status(incident, target_status, body.classification)
        if changes:
            incident.updated_at = utcnow()
            lab.log(incident.assignee or "analyst", "incident.updated", f"{incident.id}: {'; '.join(changes)}", "incident", incident.id)
            lab.store.persist_all()
        return incident


@router.post("/incidents/{incident_id}/notes", response_model=Incident, status_code=201, tags=["incidents"])
def add_note(lab: Lab, incident_id: str, body: NoteCreate):
    with lab.store.lock:
        incident = require_incident(lab, incident_id)
        incident.notes.append(Note(id="note_" + uuid.uuid4().hex[:10], author=body.author.strip(), body=body.body.strip()))
        incident.updated_at = utcnow()
        if incident.status == IncidentStatus.new:
            lab.apply_incident_status(incident, IncidentStatus.investigating, None)
        lab.log(body.author, "incident.note", f"Note added to {incident.id}", "incident", incident.id)
        lab.store.persist_all()
        return incident


@router.get("/incidents/{incident_id}/report", tags=["reports"])
def incident_report(lab: Lab, incident_id: str):
    return reports.build_report(lab, require_incident(lab, incident_id))


@router.get("/incidents/{incident_id}/report.md", response_class=PlainTextResponse, tags=["reports"])
def incident_report_markdown(lab: Lab, incident_id: str):
    incident = require_incident(lab, incident_id)
    body = reports.report_markdown(reports.build_report(lab, incident))
    return PlainTextResponse(
        body, media_type="text/markdown", headers={"Content-Disposition": f'attachment; filename="{incident.id}-report.md"'}
    )


# ---------------------------------------------------------------- entities & search
@router.get("/entities/{kind}/{value}", tags=["investigation"])
def entity_profile(lab: Lab, kind: str, value: str):
    try:
        return entities.profile(lab, kind, value)
    except entities.UnknownEntityError as exc:
        raise HTTPException(404, str(exc)) from exc


@router.get("/search", tags=["investigation"])
def search(lab: Lab, q: Annotated[str, Query(min_length=2, max_length=120)]):
    term = q.strip().lower()
    incidents = [
        i for i in lab.store.incidents.all()
        if term in f"{i.id} {i.title} {' '.join(sum(i.entities.values(), []))}".lower()
    ][:6]  # fmt: skip
    alerts = [
        a for a in sorted(lab.store.alerts.all(), key=lambda a: a.timestamp, reverse=True)
        if term in f"{a.id} {a.rule_id} {a.rule_name} {a.hostname} {a.username} {a.source_ip}".lower()
    ][:6]  # fmt: skip
    events = [
        e for e in reversed(lab.store.events.sorted())
        if term in f"{e.message} {e.username} {e.hostname} {e.source_ip} {e.event_id}".lower()
    ][:6]  # fmt: skip
    entity_hits: list[dict[str, str]] = []
    for e in lab.store.events.sorted():
        for kind, value in (("user", e.username), ("host", e.hostname), ("ip", e.source_ip)):
            if value and term in value.lower() and {"kind": kind, "value": value} not in entity_hits:
                entity_hits.append({"kind": kind, "value": value})
        if len(entity_hits) >= 8:
            break
    return {"incidents": incidents, "alerts": alerts, "events": events, "entities": entity_hits}


# ---------------------------------------------------------------- dashboards
@router.get("/dashboard", tags=["analytics"])
def dashboard(
    lab: Lab,
    range: Literal["24h", "7d", "30d", "all"] = "7d",
    severity: str | None = None,
    host: str | None = None,
    status: str | None = None,
):
    with lab.store.lock:
        return analytics.dashboard(lab, range, severity, host, status)


@router.get("/metrics", tags=["analytics"])
def detection_metrics(lab: Lab):
    with lab.store.lock:
        return analytics.metrics(lab)


@router.get("/mitre", tags=["analytics"])
def mitre_matrix(lab: Lab):
    return analytics.mitre_matrix(lab)


@router.get("/activity", response_model=list[Activity], tags=["analytics"])
def activity(lab: Lab, limit: Annotated[int, Query(ge=1, le=500)] = 50):
    return sorted(lab.store.activity.all(), key=lambda a: a.timestamp, reverse=True)[:limit]


# ---------------------------------------------------------------- system
@router.get("/system/status", tags=["system"])
def system_status(lab: Lab):
    store = lab.store
    return {
        "version": __version__,
        "mode": "simulation",
        "mode_label": "Simulation Mode - all telemetry is synthetic",
        "organization": lab.inventory.organization,
        "clock": lab.clock(),
        "timezone": lab.settings.lab_timezone,
        "business_hours": [lab.settings.business_hours_start, lab.settings.business_hours_end],
        "counts": {
            "events": len(store.events),
            "alerts": len(store.alerts),
            "incidents": len(store.incidents),
            "open_incidents": sum(1 for i in store.incidents.all() if i.status != IncidentStatus.closed),
            "rules": len(lab.engine.rules),
            "rules_enabled": sum(1 for r in lab.engine.rules if lab.rule_override(r.id).enabled),
            "scenarios": len(lab.scenarios),
            "simulation_runs": len(store.simulation_runs),
            "imports": len(store.imports),
        },
        "storage": {
            "backend": "json-files",
            "recovered_collections": [c._file.collection for c in store.collections if c.recovered],
        },
        "limits": {"max_upload_mb": lab.settings.max_upload_mb, "max_import_lines": lab.settings.max_import_lines},
        "severities": [s.value for s in Severity],
    }


@router.get("/system/inventory", tags=["system"])
def inventory(lab: Lab):
    return lab.inventory


@router.post("/system/reset", tags=["system"])
def reset_lab(lab: Lab, confirm: Annotated[str, Query(description="Must be 'RESET'")] = ""):
    if confirm != "RESET":
        raise HTTPException(400, "pass confirm=RESET to wipe all investigation state and reload the seed dataset")
    lab.reset()
    return {"status": "reset", "events": len(lab.store.events), "alerts": len(lab.store.alerts)}
