"""Entity profiles: everything the lab knows about a user, host or IP address."""

from __future__ import annotations

import ipaddress
from collections import Counter
from typing import Any

from app.models.events import NormalizedEvent
from app.services.lab import LabService

KINDS = {"user", "host", "ip"}


class UnknownEntityError(LookupError):
    pass


def _matches(kind: str, value: str, e: NormalizedEvent) -> bool:
    if kind == "user":
        return value in (e.username, e.target_username)
    if kind == "host":
        return e.hostname == value
    return value in (e.source_ip, e.destination_ip)


def profile(lab: LabService, kind: str, value: str) -> dict[str, Any]:
    if kind not in KINDS:
        raise UnknownEntityError(kind)
    value = value.strip().lower() if kind != "ip" else value.strip()
    events = [e for e in lab.store.events.sorted() if _matches(kind, value, e)]
    alerts = sorted(
        (a for a in lab.store.alerts.all() if value in {"user": [a.username], "host": [a.hostname], "ip": [a.source_ip]}[kind]),
        key=lambda a: a.timestamp,
        reverse=True,
    )
    incident_key = {"user": "users", "host": "hosts", "ip": "ips"}[kind]
    incidents = sorted(
        (i for i in lab.store.incidents.all() if value in i.entities.get(incident_key, [])), key=lambda i: i.last_seen, reverse=True
    )
    if not events and not alerts and not incidents and not _known(lab, kind, value):
        raise UnknownEntityError(f"{kind} {value} not found")

    auth = [e for e in events if e.event_type == "authentication"]
    result: dict[str, Any] = {
        "kind": kind,
        "value": value,
        "event_count": len(events),
        "first_seen": events[0].timestamp if events else None,
        "last_seen": events[-1].timestamp if events else None,
        "auth_success": sum(1 for e in auth if e.outcome == "success"),
        "auth_failure": sum(1 for e in auth if e.outcome == "failure"),
        "actions": [{"name": k, "count": v} for k, v in Counter(e.event_action for e in events).most_common(8)],
        "alerts": alerts[:25],
        "incidents": incidents[:10],
        "recent_events": list(reversed(events[-15:])),
    }
    if kind == "user":
        identity = lab.inventory.identity(value)
        result["identity"] = identity
        result["related"] = {
            "hosts": _top(e.hostname for e in events),
            "source_ips": _top(e.source_ip for e in events),
        }
    elif kind == "host":
        result["asset"] = lab.inventory.asset(value)
        result["related"] = {
            "users": _top(e.username for e in events),
            "source_ips": _top(e.source_ip for e in events),
        }
    else:
        geo = lab.inventory.geo_for(value)
        asset = lab.inventory.asset_by_ip(value)
        result["network"] = {
            "internal": lab.inventory.is_internal(value),
            "asset": asset,
            "geo": geo,
            "note": "Geolocation and reputation are synthetic: the lab only uses RFC 5737 documentation ranges.",
        }
        result["related"] = {
            "users": _top(e.username for e in events),
            "hosts": _top(e.hostname for e in events),
        }
    return result


def _known(lab: LabService, kind: str, value: str) -> bool:
    if kind == "user":
        return lab.inventory.identity(value) is not None
    if kind == "host":
        return lab.inventory.asset(value) is not None
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _top(values) -> list[dict[str, Any]]:
    return [{"value": v, "count": c} for v, c in Counter(v for v in values if v).most_common(8)]
