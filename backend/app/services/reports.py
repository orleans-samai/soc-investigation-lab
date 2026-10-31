"""Incident investigation reports (structured JSON + Markdown)."""

from __future__ import annotations

import re
from datetime import timedelta
from typing import Any

from app.detection.rules.endpoint import decode_powershell
from app.models.common import utcnow
from app.models.incidents import Incident
from app.services.lab import LabService

_URL = re.compile(r"https?://[^\s'\"<>)]+", re.IGNORECASE)
_EXE = re.compile(r"[A-Za-z]:\\[^\s'\"<>|]+?\.(?:exe|dll|ps1|bat|vbs|msi|bin)|%\w+%\\[^\s'\"<>|]+?\.(?:exe|dll|ps1)", re.IGNORECASE)

CLASSIFICATION_LABEL = {
    "undetermined": "Undetermined",
    "true_positive": "True positive (malicious)",
    "benign_true_positive": "Benign true positive",
    "false_positive": "False positive",
}


def _duration(delta: timedelta | None) -> str | None:
    if delta is None:
        return None
    seconds = int(delta.total_seconds())
    hours, rem = divmod(seconds, 3600)
    minutes, secs = divmod(rem, 60)
    return f"{hours}h {minutes:02d}m {secs:02d}s" if hours else f"{minutes}m {secs:02d}s"


def build_report(lab: LabService, incident: Incident, analyst: str = "SOC Analyst") -> dict[str, Any]:
    alerts = lab.incident_alerts(incident)
    event_ids = {eid for a in alerts for eid in a.event_ids}
    events = [e for e in lab.store.events.sorted() if e.id in event_ids]

    timeline: list[dict[str, Any]] = []
    for e in events[:250]:
        timeline.append({"timestamp": e.timestamp, "kind": "event", "title": e.message or e.event_action, "event_id": e.event_id,
                         "host": e.hostname, "user": e.username, "ip": e.source_ip, "ref": e.id})  # fmt: skip
    for a in alerts:
        timeline.append({"timestamp": a.timestamp, "kind": "alert", "title": f"[{a.rule_id}] {a.rule_name}", "severity": a.severity,
                         "detail": a.reason, "host": a.hostname, "user": a.username, "ip": a.source_ip, "ref": a.id})  # fmt: skip
    timeline.sort(key=lambda t: (t["timestamp"], t["kind"] == "alert"))

    iocs: dict[tuple[str, str], str] = {}
    for e in events:
        if e.source_ip and not lab.inventory.is_internal(e.source_ip):
            geo = lab.inventory.geo_for(e.source_ip)
            iocs.setdefault(("ip", e.source_ip), f"external source ({geo.reputation}, {geo.organization})" if geo else "external source")
        if e.event_action == "user_created" and e.target_username:
            iocs.setdefault(("account", e.target_username), f"account created on {e.hostname}")
        if e.fields.get("task_name"):
            iocs.setdefault(("scheduled_task", str(e.fields["task_name"])), f"created on {e.hostname}")
        if e.fields.get("service_name"):
            iocs.setdefault(("service", str(e.fields["service_name"])), f"installed on {e.hostname}")
        text = " ".join(filter(None, [e.command_line, decode_powershell(e.command_line)]))
        for url in _URL.findall(text):
            iocs.setdefault(("url", url.rstrip("').;")), f"referenced by {e.process_name or 'process'} on {e.hostname}")
        for path in _EXE.findall(text):
            if "\\windows\\system32\\" not in path.lower() and "program files" not in path.lower():
                iocs.setdefault(("file", path), f"seen on {e.hostname}")

    recommendations: list[str] = []
    for a in alerts:
        rule = lab.engine.rule(a.rule_id)
        for step in rule.response if rule else []:
            if step not in recommendations:
                recommendations.append(step)

    hosts = [
        {"hostname": h, **(lab.inventory.asset(h).model_dump() if lab.inventory.asset(h) else {})}
        for h in incident.entities.get("hosts", [])
    ]
    users = [
        {
            "username": u,
            **(lab.inventory.identity(u).model_dump() if lab.inventory.identity(u) else {"display_name": "Unknown / not in inventory"}),
        }
        for u in incident.entities.get("users", [])
    ]
    ips = []
    for ip in incident.entities.get("ips", []):
        geo = lab.inventory.geo_for(ip)
        ips.append({"ip": ip, "internal": lab.inventory.is_internal(ip), "reputation": geo.reputation if geo else None,
                    "organization": geo.organization if geo else None})  # fmt: skip

    tactics = sorted({m.tactic for m in incident.mitre})
    # Time from the first malicious event of the incident to the first alert it produced.
    detection_delay = min(a.timestamp for a in alerts) - incident.first_seen if alerts else None
    summary = (
        f"Between {incident.first_seen:%Y-%m-%d %H:%M} and {incident.last_seen:%H:%M} UTC the SOC Investigation Lab detected "
        f"{len(alerts)} related alert(s) ({', '.join(sorted({a.rule_name for a in alerts}))}). "
        f"The activity maps to the ATT&CK tactic(s) {', '.join(tactics) or 'n/a'} and affected "
        f"{len(hosts)} host(s) and {len(users)} account(s). "
        f"Current status: {incident.status.value}; classification: {CLASSIFICATION_LABEL[incident.classification.value]}."
    )
    if incident.resolution:
        summary += f" Resolution: {incident.resolution}"

    return {
        "generated_at": utcnow(),
        "analyst": incident.assignee or analyst,
        "environment": "Simulation Mode - synthetic data generated by SOC Investigation Lab",
        "incident": incident,
        "classification_label": CLASSIFICATION_LABEL[incident.classification.value],
        "executive_summary": summary,
        "scope": {"hosts": hosts, "users": users, "ips": ips},
        "metrics": {
            "event_count": len(events),
            "alert_count": len(alerts),
            "time_to_detect": _duration(detection_delay),
            "time_to_acknowledge": _duration(incident.acknowledged_at - incident.created_at) if incident.acknowledged_at else None,
            "time_to_close": _duration(incident.closed_at - incident.created_at) if incident.closed_at else None,
        },
        "detections": alerts,
        "timeline": timeline,
        "iocs": [{"type": t, "value": v, "context": c} for (t, v), c in iocs.items()],
        "evidence": [
            {"event_ref": e.id, "timestamp": e.timestamp, "source": e.event_source, "event_id": e.event_id, "raw": e.raw}
            for e in events[:30]
        ],
        "recommendations": recommendations,
        "notes": incident.notes,
    }


def report_markdown(report: dict[str, Any]) -> str:
    inc: Incident = report["incident"]
    lines = [
        f"# Incident Report - {inc.id}: {inc.title}",
        "",
        f"> {report['environment']}",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Severity | {inc.severity.value.upper()} |",
        f"| Status | {inc.status.value} |",
        f"| Classification | {report['classification_label']} |",
        f"| Analyst | {report['analyst']} |",
        f"| First seen (UTC) | {inc.first_seen:%Y-%m-%d %H:%M:%S} |",
        f"| Last seen (UTC) | {inc.last_seen:%Y-%m-%d %H:%M:%S} |",
        f"| Time to detect | {report['metrics']['time_to_detect'] or 'n/a'} |",
        f"| Time to acknowledge | {report['metrics']['time_to_acknowledge'] or 'n/a'} |",
        f"| Time to close | {report['metrics']['time_to_close'] or 'n/a'} |",
        f"| Report generated | {report['generated_at']:%Y-%m-%d %H:%M} UTC |",
        "",
        "## 1. Executive summary",
        "",
        report["executive_summary"],
        "",
        "## 2. Scope",
        "",
        "**Hosts:** " + (", ".join(f"{h['hostname']} ({h.get('role', 'unknown role')})" for h in report["scope"]["hosts"]) or "none"),
        "",
        "**Accounts:** " + (", ".join(f"{u['username']} ({u.get('display_name')})" for u in report["scope"]["users"]) or "none"),
        "",
        "**Source addresses:** "
        + (
            ", ".join(f"{i['ip']} ({'internal' if i['internal'] else i.get('reputation') or 'external'})" for i in report["scope"]["ips"])
            or "none"
        ),
        "",
        "## 3. Detections",
        "",
        "| Time (UTC) | Rule | Severity | ATT&CK | Reason |",
        "|---|---|---|---|---|",
    ]
    for a in report["detections"]:
        techniques = ", ".join(m.technique_id for m in a.mitre)
        lines.append(f"| {a.timestamp:%H:%M:%S} | {a.rule_id} {a.rule_name} | {a.severity.value} | {techniques} | {a.reason} |")
    lines += ["", "## 4. MITRE ATT&CK mapping", ""]
    for m in inc.mitre:
        lines.append(f"- **{m.technique_id}** {m.technique} - _{m.tactic}_")
    lines += ["", "## 5. Timeline", "", "| Time (UTC) | Type | Description |", "|---|---|---|"]
    for t in report["timeline"][:120]:
        label = "ALERT" if t["kind"] == "alert" else (t.get("event_id") or "event")
        lines.append(f"| {t['timestamp']:%Y-%m-%d %H:%M:%S} | {label} | {str(t['title']).replace('|', '/')} |")
    lines += ["", "## 6. Indicators of compromise", ""]
    if report["iocs"]:
        lines += ["| Type | Value | Context |", "|---|---|---|"]
        lines += [f"| {i['type']} | `{i['value']}` | {i['context']} |" for i in report["iocs"]]
    else:
        lines.append("No external indicators identified.")
    lines += ["", "## 7. Evidence (raw logs)", ""]
    for ev in report["evidence"][:15]:
        lines += [f"`{ev['timestamp']:%Y-%m-%d %H:%M:%S}` {ev['source']} {ev['event_id'] or ''}", "```", ev["raw"][:1500], "```"]
    lines += ["", "## 8. Recommendations", ""]
    lines += [f"{n}. {r}" for n, r in enumerate(report["recommendations"], 1)] or ["None."]
    lines += ["", "## 9. Analyst notes", ""]
    if report["notes"]:
        lines += [f"- **{n.created_at:%Y-%m-%d %H:%M} {n.author}:** {n.body}" for n in report["notes"]]
    else:
        lines.append("No notes recorded.")
    if inc.resolution:
        lines += ["", "## 10. Resolution", "", inc.resolution]
    return "\n".join(lines) + "\n"
