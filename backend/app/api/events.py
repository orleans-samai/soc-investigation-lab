from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import Response

from app.api.deps import Lab
from app.models.common import Page
from app.models.events import EventFacets, NormalizedEvent
from app.models.imports import ImportRecord, ImportReport, LogFormat
from app.services import events as event_service
from app.services.ingestion import ImportRejectedError, import_file

router = APIRouter(tags=["events"])
EXPORT_LIMIT = 50_000


def _filter(
    q: str | None = None,
    username: str | None = None,
    source_ip: str | None = None,
    hostname: str | None = None,
    event_source: str | None = None,
    event_type: str | None = None,
    event_action: str | None = None,
    log_level: str | None = None,
    outcome: str | None = None,
    dataset: str | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    ids: str | None = None,
) -> event_service.EventFilter:
    if (start and start.tzinfo is None) or (end and end.tzinfo is None):
        raise HTTPException(422, "start/end must include a timezone offset (e.g. 2026-10-30T12:00:00Z)")
    return event_service.EventFilter(
        q=q, username=username, source_ip=source_ip, hostname=hostname, event_source=event_source, event_type=event_type,
        event_action=event_action, log_level=log_level, outcome=outcome, dataset=dataset, start=start, end=end,
        ids=set(ids.split(",")) if ids else None,
    )  # fmt: skip


Filter = Annotated[event_service.EventFilter, Depends(_filter)]


@router.get("/events", response_model=Page[NormalizedEvent])
def list_events(
    lab: Lab,
    flt: Filter,
    sort: str = "timestamp",
    order: Literal["asc", "desc"] = "desc",
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=500)] = 50,
):
    with lab.store.lock:
        events = event_service.filter_events(lab.store.events.sorted(), flt)
    return event_service.paginate(event_service.sort_events(events, sort, order), page, page_size)


@router.get("/events/facets", response_model=EventFacets)
def event_facets(lab: Lab):
    return event_service.facets(lab.store.events.sorted())


@router.get("/events/export")
def export_events(lab: Lab, flt: Filter, format: Literal["csv", "json"] = "csv"):
    events = event_service.filter_events(lab.store.events.sorted(), flt)[-EXPORT_LIMIT:]
    if format == "json":
        body, media = event_service.export_json(events), "application/json"
    else:
        body, media = event_service.export_csv(events), "text/csv"
    filename = f"soc-lab-events-{len(events)}.{format}"
    return Response(body, media_type=media, headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@router.get("/events/{event_id}", response_model=NormalizedEvent)
def get_event(lab: Lab, event_id: str):
    event = lab.store.events.get(event_id)
    if event is None:
        raise HTTPException(404, f"event {event_id} not found")
    return event


@router.get("/events/{event_id}/context")
def event_context(lab: Lab, event_id: str):
    """Alerts that reference the event, plus the neighbouring events on the same host."""
    event = lab.store.events.get(event_id)
    if event is None:
        raise HTTPException(404, f"event {event_id} not found")
    alerts = [a for a in lab.store.alerts.all() if event_id in a.event_ids]
    host_events = [e for e in lab.store.events.sorted() if e.hostname == event.hostname]
    index = next((i for i, e in enumerate(host_events) if e.id == event_id), 0)
    return {"alerts": alerts, "surrounding": host_events[max(0, index - 5) : index + 6]}


@router.post("/imports", response_model=ImportReport)
async def upload_logs(
    lab: Lab,
    file: Annotated[UploadFile, File(description="Log file (JSON, NDJSON or auth.log text)")],
    format: Annotated[LogFormat, Form()] = LogFormat.auto,
    timezone: Annotated[str, Form(max_length=64)] = "UTC",
    year: Annotated[int | None, Form(ge=1990, le=2100)] = None,
    dry_run: Annotated[bool, Form()] = True,
):
    limit = lab.settings.max_upload_bytes
    content = await file.read(limit + 1)
    if len(content) > limit:
        raise HTTPException(413, f"file exceeds the {lab.settings.max_upload_mb:g} MB limit")
    if not content.strip():
        raise HTTPException(422, "file is empty")
    try:
        return import_file(lab, content, file.filename or "upload", format, timezone, year, dry_run)
    except ImportRejectedError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.get("/imports", response_model=list[ImportRecord])
def list_imports(lab: Lab):
    return sorted(lab.store.imports.all(), key=lambda r: r.created_at, reverse=True)
