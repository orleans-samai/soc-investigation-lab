"""Core orchestration: ingestion -> detection -> correlation -> persistence.

All state-changing operations go through ``LabService`` while holding ``store.lock`` so concurrent
API requests can never interleave half-applied changes.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from app.config import Settings
from app.detection.base import DetectionContext
from app.detection.engine import DetectionEngine, RuleConfig
from app.detection.inventory import Inventory, MaintenanceWindow
from app.detection.mitre import MitreCatalog
from app.models.alerts import Alert, AlertStatus, RuleOverride
from app.models.common import MitreRef, Severity, utcnow
from app.models.events import NormalizedEvent
from app.models.incidents import Activity, Classification, Incident, IncidentStatus
from app.simulation.baseline import generate_baseline
from app.simulation.scenarios import load_scenarios
from app.storage.repository import LabStore

log = logging.getLogger(__name__)

MAX_ACTIVITY = 500
# Alerts sharing an account or source IP are merged into the same open incident within this window...
ENTITY_CORRELATION_WINDOW = timedelta(hours=2)
# ...and alerts on the same host within this (shorter) window.
HOST_CORRELATION_WINDOW = timedelta(minutes=20)
# Below this severity an alert only joins an existing incident; it never opens one on its own.
AUTO_INCIDENT_MIN_SEVERITY = Severity.high


@dataclass
class IngestResult:
    added: list[NormalizedEvent] = field(default_factory=list)
    duplicates: int = 0


@dataclass
class DetectionResult:
    new_alerts: list[Alert] = field(default_factory=list)
    updated_alerts: list[Alert] = field(default_factory=list)
    incidents: list[str] = field(default_factory=list)


def alert_entities(alert: Alert) -> dict[str, set[str]]:
    return {
        "users": {alert.username} if alert.username else set(),
        "hosts": {alert.hostname} if alert.hostname else set(),
        "ips": {alert.source_ip} if alert.source_ip else set(),
    }


class LabService:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.timezone = ZoneInfo(settings.lab_timezone)
        self.inventory = Inventory.load(settings.data_dir / "inventory.json")
        self._static_windows = list(self.inventory.maintenance_windows)
        self.context = DetectionContext(
            inventory=self.inventory,
            timezone=self.timezone,
            business_hours=(settings.business_hours_start, settings.business_hours_end),
        )
        self.engine = DetectionEngine(self.context)
        self.mitre = MitreCatalog.load(settings.data_dir / "mitre_attack.json")
        self.scenarios = load_scenarios(settings.scenarios_dir)
        self.store = LabStore(settings.state_dir)

    # ------------------------------------------------------------------ lifecycle
    def startup(self) -> None:
        with self.store.lock:
            self.store.load()
            self._sync_maintenance_windows()
            if not self.store.is_initialized():
                self.reset()

    def reset(self) -> None:
        """Restore the lab to the seed dataset (all analyst work is discarded)."""
        with self.store.lock:
            self.store.clear()
            self._sync_maintenance_windows()
            events = self._load_seed()
            self.ingest(events)
            self.store.events.meta["initialized"] = True
            self.store.events.meta["seed_events"] = len(events)
            self.log("system", "lab.reset", f"Lab initialized with {len(events)} baseline events")
            result = self.detect()
            self.log("system", "detection.run", f"Initial detection produced {len(result.new_alerts)} alerts")
            self.store.persist_all()

    def _load_seed(self) -> list[NormalizedEvent]:
        path = self.settings.seed_dir / "baseline_events.json"
        if path.exists():
            with path.open(encoding="utf-8") as fh:
                return [NormalizedEvent.model_validate(e) for e in json.load(fh)["events"]]
        log.warning("seed file missing; generating baseline in memory")
        return generate_baseline()

    def _sync_maintenance_windows(self) -> None:
        dynamic = [MaintenanceWindow.model_validate(w) for w in self.store.simulation_runs.meta.get("maintenance_windows", [])]
        self.inventory.maintenance_windows = self._static_windows + dynamic

    def add_maintenance_window(self, window: MaintenanceWindow) -> None:
        stored = self.store.simulation_runs.meta.setdefault("maintenance_windows", [])
        stored.append(window.model_dump(mode="json"))
        self._sync_maintenance_windows()

    # ------------------------------------------------------------------ helpers
    def clock(self) -> datetime:
        """The simulated 'now': the timestamp of the most recent event in the lab."""
        events = self.store.events.sorted()
        return events[-1].timestamp if events else utcnow()

    def log(self, actor: str, action: str, message: str, target_type: str | None = None, target_id: str | None = None) -> Activity:
        entry = Activity(
            id="act_" + uuid.uuid4().hex[:12], actor=actor, action=action, message=message, target_type=target_type, target_id=target_id
        )
        self.store.activity.upsert(entry)
        items = self.store.activity.all()
        if len(items) > MAX_ACTIVITY:
            for old in sorted(items, key=lambda a: a.timestamp)[: len(items) - MAX_ACTIVITY]:
                self.store.activity._items.pop(old.id, None)
        return entry

    def rule_config(self) -> dict[str, RuleConfig]:
        return {o.id: RuleConfig(enabled=o.enabled, params=o.params) for o in self.store.rules.all()}

    def rule_override(self, rule_id: str) -> RuleOverride:
        return self.store.rules.get(rule_id) or RuleOverride(id=rule_id)

    # ------------------------------------------------------------------ pipeline
    def ingest(self, events: list[NormalizedEvent]) -> IngestResult:
        result = IngestResult()
        with self.store.lock:
            seen: set[str] = set()
            for event in events:
                if event.id in self.store.events or event.id in seen:
                    result.duplicates += 1
                    continue
                seen.add(event.id)
                self.store.events.upsert(event)
                result.added.append(event)
        return result

    def detect(self) -> DetectionResult:
        """Run every enabled rule over all events, upsert alerts and correlate new ones into incidents."""
        result = DetectionResult()
        with self.store.lock:
            for alert in self.engine.run(self.store.events.sorted(), self.rule_config()):
                existing = self.store.alerts.get(alert.id)
                if existing is None:
                    self.store.alerts.upsert(alert)
                    result.new_alerts.append(alert)
                elif existing.event_ids != alert.event_ids:
                    # The activity grew (more events in the same burst): refresh the facts, keep analyst state.
                    existing.event_ids = alert.event_ids
                    existing.event_count = alert.event_count
                    existing.evidence = alert.evidence
                    existing.reason = alert.reason
                    existing.severity = Severity.max([existing.severity, alert.severity])
                    existing.updated_at = utcnow()
                    result.updated_alerts.append(existing)
            result.incidents = self.correlate(result.new_alerts)
        return result

    # ------------------------------------------------------------------ incidents
    def correlate(self, alerts: list[Alert]) -> list[str]:
        touched: list[str] = []
        for alert in sorted(alerts, key=lambda a: (a.timestamp, -a.severity.rank)):
            incident = self._find_incident_for(alert)
            if incident is not None:
                self._attach(incident, [alert])
            elif alert.severity.rank >= AUTO_INCIDENT_MIN_SEVERITY.rank:
                incident = self.create_incident([alert], actor="system")
                # Pull in earlier lower-severity alerts about the same entities (e.g. the account
                # creation that preceded a privileged group change).
                strays = [
                    a for a in self.store.alerts.all() if a.incident_id is None and not a.status.is_closed and self._matches(incident, a)
                ]
                if strays:
                    self._attach(incident, strays)
            else:
                continue
            if incident.id not in touched:
                touched.append(incident.id)
        return touched

    def _matches(self, incident: Incident, alert: Alert) -> bool:
        entities = alert_entities(alert)
        delta = min(abs(alert.timestamp - incident.last_seen), abs(alert.timestamp - incident.first_seen))
        if alert.first_seen <= incident.last_seen and alert.timestamp >= incident.first_seen:
            delta = timedelta(0)
        shared_identity = bool(entities["users"] & set(incident.entities.get("users", []))) or bool(
            entities["ips"] & set(incident.entities.get("ips", []))
        )
        shared_host = bool(entities["hosts"] & set(incident.entities.get("hosts", [])))
        return (shared_identity and delta <= ENTITY_CORRELATION_WINDOW) or (shared_host and delta <= HOST_CORRELATION_WINDOW)

    def _find_incident_for(self, alert: Alert) -> Incident | None:
        candidates = [i for i in self.store.incidents.all() if i.status != IncidentStatus.closed and self._matches(i, alert)]
        return max(candidates, key=lambda i: i.last_seen) if candidates else None

    def _next_incident_id(self) -> str:
        seq = int(self.store.incidents.meta.get("seq", 0)) + 1
        self.store.incidents.meta["seq"] = seq
        return f"INC-{seq:04d}"

    def create_incident(self, alerts: list[Alert], actor: str = "analyst", title: str | None = None) -> Incident:
        lead = min(alerts, key=lambda a: (-a.severity.rank, a.timestamp))  # earliest of the most severe
        incident = Incident(
            id=self._next_incident_id(),
            title=title or "",
            summary="",
            severity=lead.severity,
            first_seen=min(a.first_seen for a in alerts),
            last_seen=max(a.timestamp for a in alerts),
        )
        incident.entities = {"users": [], "hosts": [], "ips": []}
        self.store.incidents.upsert(incident)
        self._attach(incident, alerts, auto_title=title is None)
        verb = "opened automatically" if actor == "system" else "created"
        self.log(actor, "incident.created", f"{incident.id} {verb}: {incident.title}", "incident", incident.id)
        return incident

    def _attach(self, incident: Incident, alerts: list[Alert], auto_title: bool | None = None) -> None:
        for alert in alerts:
            if alert.id not in incident.alert_ids:
                incident.alert_ids.append(alert.id)
            alert.incident_id = incident.id
            if incident.status in (IncidentStatus.investigating, IncidentStatus.contained) and alert.status == AlertStatus.new:
                alert.status = AlertStatus.investigating
        self.refresh_incident(incident, auto_title=incident.status == IncidentStatus.new if auto_title is None else auto_title)

    def incident_alerts(self, incident: Incident) -> list[Alert]:
        alerts = [self.store.alerts.get(a) for a in incident.alert_ids]
        return sorted((a for a in alerts if a), key=lambda a: a.timestamp)

    def refresh_incident(self, incident: Incident, auto_title: bool = True) -> None:
        alerts = self.incident_alerts(incident)
        if not alerts:
            return
        lead = min(alerts, key=lambda a: (-a.severity.rank, a.timestamp))  # earliest of the most severe
        users: set[str] = set()
        hosts: set[str] = set()
        ips: set[str] = set()
        mitre: dict[str, MitreRef] = {}
        for alert in alerts:
            entities = alert_entities(alert)
            users |= entities["users"]
            hosts |= entities["hosts"]
            ips |= entities["ips"]
            for ref in alert.mitre:
                mitre.setdefault(ref.technique_id, ref)
        incident.entities = {"users": sorted(users), "hosts": sorted(hosts), "ips": sorted(ips)}
        incident.mitre = list(mitre.values())
        incident.first_seen = min(a.first_seen for a in alerts)
        incident.last_seen = max(a.timestamp for a in alerts)
        incident.severity = Severity.max([incident.severity, *[a.severity for a in alerts]])
        if auto_title:
            subject = lead.username or lead.source_ip or lead.hostname or "unknown entity"
            where = f" on {lead.hostname}" if lead.hostname and lead.hostname != subject else ""
            incident.title = f"{lead.rule_name}: {subject}{where}"
        tactics = sorted({m.tactic for m in incident.mitre})
        incident.summary = (
            f"{len(alerts)} correlated alert{'s' if len(alerts) != 1 else ''} between "
            f"{incident.first_seen:%Y-%m-%d %H:%M} and {incident.last_seen:%H:%M} UTC"
            + (f" involving {', '.join(sorted(hosts))}" if hosts else "")
            + (f"; accounts: {', '.join(sorted(users))}" if users else "")
            + (f"; sources: {', '.join(sorted(ips))}" if ips else "")
            + f". Highest severity: {incident.severity.value} ({lead.rule_name})."
            + (f" ATT&CK tactics: {', '.join(tactics)}." if tactics else "")
        )
        incident.updated_at = utcnow()

    def apply_incident_status(self, incident: Incident, status: IncidentStatus, classification: Classification | None) -> None:
        now = utcnow()
        if status != IncidentStatus.new and incident.acknowledged_at is None:
            incident.acknowledged_at = now
        incident.status = status
        if classification is not None:
            incident.classification = classification
        if status == IncidentStatus.closed:
            incident.closed_at = now
            closed_as = {
                Classification.true_positive: AlertStatus.resolved,
                Classification.benign_true_positive: AlertStatus.benign,
                Classification.false_positive: AlertStatus.false_positive,
            }.get(incident.classification, AlertStatus.resolved)
            for alert in self.incident_alerts(incident):
                if not alert.status.is_closed:
                    alert.status = closed_as
                    alert.updated_at = now
        else:
            incident.closed_at = None
            for alert in self.incident_alerts(incident):
                if alert.status == AlertStatus.new and status != IncidentStatus.new:
                    alert.status = AlertStatus.investigating
                    alert.updated_at = now
