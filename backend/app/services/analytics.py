"""Read-only aggregations: dashboard, detection metrics and ATT&CK coverage."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta
from statistics import mean
from typing import Any

from app.models.alerts import Alert, AlertStatus
from app.models.common import Severity
from app.models.incidents import IncidentStatus
from app.services.lab import LabService

RANGES = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}
SEVERITIES = [s.value for s in Severity]


def resolve_range(lab: LabService, range_key: str) -> tuple[datetime, datetime]:
    end = lab.clock()
    if range_key in RANGES:
        return end - RANGES[range_key], end
    events = lab.store.events.sorted()
    return (events[0].timestamp if events else end), end


def _bucket_size(span: timedelta) -> timedelta:
    for size in (timedelta(hours=1), timedelta(hours=3), timedelta(hours=6), timedelta(days=1)):
        if span / size <= 60:
            return size
    return timedelta(days=7)


def _floor(ts: datetime, size: timedelta) -> datetime:
    epoch = datetime(1970, 1, 1, tzinfo=ts.tzinfo)
    return epoch + ((ts - epoch) // size) * size


def dashboard(lab: LabService, range_key: str, severity: str | None, host: str | None, status: str | None) -> dict[str, Any]:
    start, end = resolve_range(lab, range_key)
    store = lab.store
    events = [e for e in store.events.sorted() if start <= e.timestamp <= end and (not host or e.hostname == host)]

    def alert_ok(a: Alert) -> bool:
        return (
            start <= a.timestamp <= end
            and (not severity or a.severity.value in severity.split(","))
            and (not host or a.hostname == host)
            and (not status or a.status.value in status.split(","))
        )

    alerts = sorted((a for a in store.alerts.all() if alert_ok(a)), key=lambda a: a.timestamp, reverse=True)
    incidents = [
        i for i in store.incidents.all()
        if (not host or host in i.entities.get("hosts", [])) and (not severity or i.severity.value in severity.split(","))
    ]  # fmt: skip

    size = _bucket_size(end - start)
    buckets: dict[datetime, dict[str, Any]] = {}
    cursor = _floor(start, size)
    while cursor <= end:
        buckets[cursor] = {"bucket": cursor, "events": 0, "failures": 0, "alerts": 0}
        cursor += size
    for e in events:
        b = buckets.get(_floor(e.timestamp, size))
        if b:
            b["events"] += 1
            if e.outcome == "failure":
                b["failures"] += 1
    for a in alerts:
        b = buckets.get(_floor(a.timestamp, size))
        if b:
            b["alerts"] += 1

    host_events = Counter(e.hostname for e in events if e.hostname)
    host_alerts = Counter(a.hostname for a in alerts if a.hostname)
    ip_events = Counter(e.source_ip for e in events if e.source_ip)
    ip_failures = Counter(e.source_ip for e in events if e.source_ip and e.outcome == "failure")
    rule_counts = Counter(a.rule_id for a in alerts)

    def ip_row(ip: str) -> dict[str, Any]:
        geo = lab.inventory.geo_for(ip)
        return {
            "ip": ip,
            "events": ip_events[ip],
            "failures": ip_failures[ip],
            "internal": lab.inventory.is_internal(ip),
            "reputation": geo.reputation if geo else ("internal" if lab.inventory.is_internal(ip) else "unknown"),
        }

    top_ips = sorted(ip_events, key=lambda ip: (ip_failures[ip], ip_events[ip]), reverse=True)[:8]
    open_alerts = [a for a in store.alerts.all() if not a.status.is_closed]
    return {
        "clock": end,
        "range": range_key,
        "start": start,
        "end": end,
        "bucket_seconds": int(size.total_seconds()),
        "kpis": {
            "events_total": len(store.events),
            "events_in_range": len(events),
            "events_last_24h": sum(1 for e in store.events.sorted() if e.timestamp >= end - timedelta(hours=24)),
            "alerts_in_range": len(alerts),
            "alerts_open": len(open_alerts),
            "alerts_unassigned": sum(1 for a in open_alerts if a.incident_id is None),
            "critical_open": sum(1 for a in open_alerts if a.severity == Severity.critical),
            "incidents_new": sum(1 for i in incidents if i.status == IncidentStatus.new),
            "incidents_investigating": sum(1 for i in incidents if i.status in (IncidentStatus.investigating, IncidentStatus.contained)),
            "incidents_closed": sum(1 for i in incidents if i.status == IncidentStatus.closed),
        },
        "timeline": list(buckets.values()),
        "severity": [{"severity": s, "count": sum(1 for a in alerts if a.severity.value == s)} for s in SEVERITIES],
        "top_rules": [
            {"rule_id": rid, "rule_name": lab.engine.rule(rid).name if lab.engine.rule(rid) else rid, "count": count}
            for rid, count in rule_counts.most_common(6)
        ],
        "top_hosts": [
            {
                "hostname": h,
                "events": host_events[h],
                "alerts": host_alerts[h],
                "role": (lab.inventory.asset(h).role if lab.inventory.asset(h) else None),
            }
            for h in sorted(set(host_events) | set(host_alerts), key=lambda h: (host_alerts[h], host_events[h]), reverse=True)[:8]
        ],
        "top_source_ips": [ip_row(ip) for ip in top_ips],
        "event_sources": [{"source": s, "count": c} for s, c in Counter(str(e.event_source) for e in events).most_common()],
        "recent_alerts": alerts[:8],
        "recent_activity": sorted(store.activity.all(), key=lambda a: a.timestamp, reverse=True)[:12],
    }


def _seconds(delta: timedelta) -> float:
    return delta.total_seconds()


def metrics(lab: LabService) -> dict[str, Any]:
    alerts = lab.store.alerts.all()
    incidents = lab.store.incidents.all()
    by_rule: dict[str, list[Alert]] = defaultdict(list)
    for a in alerts:
        by_rule[a.rule_id].append(a)

    def outcome_counts(items: list[Alert]) -> dict[str, int]:
        c = Counter(a.status for a in items)
        return {
            "true_positive": c[AlertStatus.resolved],
            "benign": c[AlertStatus.benign],
            "false_positive": c[AlertStatus.false_positive],
            "open": c[AlertStatus.new] + c[AlertStatus.investigating],
        }

    def precision(counts: dict[str, int]) -> float | None:
        decided = counts["true_positive"] + counts["false_positive"]
        return round(counts["true_positive"] / decided, 3) if decided else None

    rules = []
    for rule in lab.engine.rules:
        items = by_rule.get(rule.id, [])
        counts = outcome_counts(items)
        rules.append(
            {
                "rule_id": rule.id,
                "rule_name": rule.name,
                "severity": rule.severity,
                "enabled": lab.rule_override(rule.id).enabled,
                "alerts": len(items),
                **counts,
                "precision": precision(counts),
                "mean_time_to_detect_seconds": round(mean(_seconds(a.timestamp - a.first_seen) for a in items), 1) if items else None,
            }
        )

    overall = outcome_counts(alerts)
    acknowledged = [i for i in incidents if i.acknowledged_at]
    closed = [i for i in incidents if i.closed_at]

    per_day: dict[str, Counter[str]] = defaultdict(Counter)
    events = lab.store.events.sorted()
    if events:
        # One bar per day of telemetry, including quiet days, so gaps are visible instead of collapsed.
        day = events[0].timestamp.astimezone(lab.timezone).date()
        last = events[-1].timestamp.astimezone(lab.timezone).date()
        while day <= last:
            per_day[day.isoformat()] = Counter()
            day += timedelta(days=1)
    for a in alerts:
        per_day[a.timestamp.astimezone(lab.timezone).date().isoformat()][a.severity.value] += 1

    runs = lab.store.simulation_runs.all()
    per_scenario = []
    for scenario in lab.scenarios.values():
        scenario_runs = sorted((r for r in runs if r.scenario_id == scenario.id), key=lambda r: r.executed_at)
        per_scenario.append(
            {
                "scenario_id": scenario.id,
                "name": scenario.name,
                "runs": len(scenario_runs),
                "detected_runs": sum(1 for r in scenario_runs if not r.missed_rules),
                "last_missed": scenario_runs[-1].missed_rules if scenario_runs else [],
                "expected_rules": scenario.expected_rules,
            }
        )
    executed = [s for s in per_scenario if s["runs"]]
    techniques = {m.technique_id for r in lab.engine.rules for m in r.mitre}

    return {
        "overall": {
            "alerts": len(alerts),
            **overall,
            "precision": precision(overall),
            "false_positive_rate": round(overall["false_positive"] / decided, 3) if (decided := len(alerts) - overall["open"]) else None,
            "mean_time_to_detect_seconds": round(mean(_seconds(a.timestamp - a.first_seen) for a in alerts), 1) if alerts else None,
            "incidents": len(incidents),
            "incidents_closed": len(closed),
            "mean_time_to_acknowledge_seconds": round(mean(_seconds(i.acknowledged_at - i.created_at) for i in acknowledged), 1)
            if acknowledged
            else None,
            "mean_time_to_resolve_seconds": round(mean(_seconds(i.closed_at - i.created_at) for i in closed), 1) if closed else None,
        },
        "rules": rules,
        "alerts_per_day": [{"date": day, **{s: counts[s] for s in SEVERITIES}} for day, counts in sorted(per_day.items())],
        "classification": [{"classification": c, "count": n} for c, n in Counter(i.classification.value for i in incidents).most_common()],
        "simulation": {
            "runs": len(runs),
            "fully_detected_runs": sum(1 for r in runs if not r.missed_rules),
            "scenarios_executed": len(executed),
            "scenarios_total": len(per_scenario),
            "scenarios_fully_detected": sum(1 for s in executed if s["detected_runs"] == s["runs"]),
            "per_scenario": per_scenario,
            "challenges_completed": len(graded := [r.challenge for r in runs if r.challenge.submitted_at]),
            "challenge_average_pct": round(100 * sum(a.score for a in graded) / sum(a.max_score for a in graded), 1)
            if graded and sum(a.max_score for a in graded)
            else None,
        },
        "mitre": {
            "techniques_covered": len(techniques),
            "techniques_in_catalog": len(lab.mitre.techniques),
            "techniques_detected": len({m.technique_id for a in alerts for m in a.mitre}),
        },
        "shifts": [
            {"id": s.id, "started_at": s.started_at, "alerts": len(s.items), **s.score.model_dump()}
            for s in sorted(lab.store.shifts.all(), key=lambda s: s.started_at)
            if s.score
        ],
        "last_regression": lab.store.rules.meta.get("last_regression"),
    }


def mitre_matrix(lab: LabService) -> dict[str, Any]:
    rules_by_technique: dict[str, list[str]] = defaultdict(list)
    for rule in lab.engine.rules:
        for ref in rule.mitre:
            rules_by_technique[ref.technique_id].append(rule.id)
    # Extra techniques a rule can add dynamically (e.g. PowerShell obfuscation).
    for tid, rid in (("T1027", "LAB-009"), ("T1105", "LAB-009"), ("T1003.001", "LAB-009")):
        if rid not in rules_by_technique[tid]:
            rules_by_technique[tid].append(rid)
    alerts_by_technique: Counter[str] = Counter()
    open_by_technique: Counter[str] = Counter()
    for alert in lab.store.alerts.all():
        for ref in alert.mitre:
            alerts_by_technique[ref.technique_id] += 1
            if not alert.status.is_closed:
                open_by_technique[ref.technique_id] += 1

    tactics = []
    for tactic in lab.mitre.tactics:
        techniques = [
            {
                "id": t.id,
                "name": t.name,
                "url": t.url,
                "rules": rules_by_technique.get(t.id, []),
                "alerts": alerts_by_technique[t.id],
                "open_alerts": open_by_technique[t.id],
            }
            for t in lab.mitre.techniques
            if tactic.name in t.tactics
        ]
        tactics.append({"id": tactic.id, "name": tactic.name, "techniques": techniques})
    covered = {t.id for t in lab.mitre.techniques if rules_by_technique.get(t.id)}
    return {
        "source": lab.mitre.source,
        "tactics": tactics,
        "summary": {
            "techniques": len(lab.mitre.techniques),
            "covered": len(covered),
            "detected": sum(1 for t in lab.mitre.techniques if alerts_by_technique[t.id]),
            "coverage_pct": round(100 * len(covered) / max(1, len(lab.mitre.techniques)), 1),
        },
    }
