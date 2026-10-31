"""Alerts, detection rules and simulations."""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import PlainTextResponse

from app.api.deps import Lab, require_alert
from app.detection import sigma
from app.models.alerts import Alert, AlertStatus, AlertUpdate, BacktestRequest, BacktestResult, RuleInfo, RuleUpdate
from app.models.common import Page, Severity, utcnow
from app.models.simulations import ChallengeSubmission, HintRequest, ScenarioSummary, SimulationRequest, SimulationRun
from app.services import challenge
from app.services.events import paginate
from app.services.ingestion import run_simulation
from app.simulation.scenarios import ScenarioError, estimate_events

router = APIRouter(tags=["detection"])

ALERT_SORT = {
    "timestamp": lambda a: a.timestamp,
    "severity": lambda a: (a.severity.rank, a.timestamp),
    "rule": lambda a: (a.rule_id, a.timestamp),
    "host": lambda a: (a.hostname or "", a.timestamp),
    "status": lambda a: (a.status.value, a.timestamp),
}


@router.get("/alerts", response_model=Page[Alert])
def list_alerts(
    lab: Lab,
    q: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    rule_id: str | None = None,
    hostname: str | None = None,
    username: str | None = None,
    source_ip: str | None = None,
    incident: Literal["any", "unassigned", "assigned"] = "any",
    sort: Literal["timestamp", "severity", "rule", "host", "status"] = "timestamp",
    order: Literal["asc", "desc"] = "desc",
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=200)] = 25,
):
    def keep(a: Alert) -> bool:
        if severity and a.severity.value not in severity.split(","):
            return False
        if status and a.status.value not in status.split(","):
            return False
        if rule_id and a.rule_id not in rule_id.split(","):
            return False
        if hostname and a.hostname != hostname.lower():
            return False
        if username and a.username != username.lower():
            return False
        if source_ip and a.source_ip != source_ip:
            return False
        if incident == "unassigned" and a.incident_id:
            return False
        if incident == "assigned" and not a.incident_id:
            return False
        if q:
            text = " ".join(
                filter(None, [a.id, a.rule_id, a.rule_name, a.reason, a.hostname, a.username, a.source_ip, a.incident_id])
            ).lower()
            return all(t in text for t in q.lower().split())
        return True

    alerts = sorted((a for a in lab.store.alerts.all() if keep(a)), key=ALERT_SORT[sort], reverse=order == "desc")
    return paginate(alerts, page, page_size)


@router.get("/alerts/{alert_id}")
def get_alert(lab: Lab, alert_id: str):
    alert = require_alert(lab, alert_id)
    ids = set(alert.event_ids)
    events = [e for e in lab.store.events.sorted() if e.id in ids]
    rule = lab.engine.rule(alert.rule_id)
    return {
        "alert": alert,
        "events": events,
        "rule": {"id": rule.id, "logic": rule.logic, "false_positives": rule.false_positives, "response": rule.response} if rule else None,
        "incident": lab.store.incidents.get(alert.incident_id) if alert.incident_id else None,
    }


@router.patch("/alerts/{alert_id}", response_model=Alert)
def update_alert(lab: Lab, alert_id: str, body: AlertUpdate):
    with lab.store.lock:
        alert = require_alert(lab, alert_id)
        changes = []
        if body.status and body.status != alert.status:
            changes.append(f"status {alert.status.value} -> {body.status.value}")
            alert.status = body.status
        if body.analyst_note is not None and body.analyst_note != alert.analyst_note:
            alert.analyst_note = body.analyst_note.strip() or None
            changes.append("note updated")
        if changes:
            alert.updated_at = utcnow()
            lab.log("analyst", "alert.updated", f"{alert.rule_name} ({alert.id}): {', '.join(changes)}", "alert", alert.id)
            lab.store.persist_all()
        return alert


@router.post("/detection/run")
def rerun_detection(lab: Lab):
    with lab.store.lock:
        result = lab.detect()
        lab.log("analyst", "detection.run", f"Detection re-run: {len(result.new_alerts)} new, {len(result.updated_alerts)} updated alerts")
        lab.store.persist_all()
    return {"new_alerts": len(result.new_alerts), "updated_alerts": len(result.updated_alerts), "incidents": result.incidents}


# ---------------------------------------------------------------- rules
def _rule_info(lab, rule) -> RuleInfo:
    override = lab.rule_override(rule.id)
    alerts = [a for a in lab.store.alerts.all() if a.rule_id == rule.id]
    params = rule.resolve_params(override.params)
    return RuleInfo(
        id=rule.id,
        name=rule.name,
        description=rule.description,
        severity=rule.severity,
        rule_type=rule.rule_type,
        data_sources=rule.data_sources,
        mitre=rule.mitre,
        enabled=override.enabled,
        params=rule.param_models(override.params),
        logic=rule.logic.format(**params) if params else rule.logic,
        false_positives=rule.false_positives,
        response=rule.response,
        alert_count=len(alerts),
        last_triggered=max((a.timestamp for a in alerts), default=None),
    )


def _require_rule(lab, rule_id: str):
    rule = lab.engine.rule(rule_id.upper())
    if rule is None:
        raise HTTPException(404, f"rule {rule_id} not found")
    return rule


@router.get("/rules", response_model=list[RuleInfo])
def list_rules(lab: Lab):
    return [_rule_info(lab, r) for r in lab.engine.rules]


def _sigma_docs(lab, rule) -> list[dict]:
    params = rule.resolve_params(lab.rule_override(rule.id).params)
    return sigma.rule_documents(rule, params, lab.context.threat_intel)


@router.get("/rules/sigma.yml", response_class=PlainTextResponse)
def export_sigma(lab: Lab):
    """Every rule as Sigma YAML (multi-document), using the current tuned parameters."""
    docs = [doc for rule in lab.engine.rules for doc in _sigma_docs(lab, rule)]
    body = sigma.to_yaml(docs, "SOC Investigation Lab - detection rules exported as Sigma (https://sigmahq.io)")
    return PlainTextResponse(
        body, media_type="application/yaml", headers={"Content-Disposition": 'attachment; filename="soc-lab-sigma-rules.yml"'}
    )


@router.get("/rules/{rule_id}/sigma", response_class=PlainTextResponse)
def rule_sigma(lab: Lab, rule_id: str):
    rule = _require_rule(lab, rule_id)
    body = sigma.to_yaml(_sigma_docs(lab, rule), f"{rule.id} {rule.name}")
    return PlainTextResponse(body, media_type="application/yaml", headers={"Content-Disposition": f'inline; filename="{rule.id}.yml"'})


@router.get("/rules/{rule_id}", response_model=RuleInfo)
def get_rule(lab: Lab, rule_id: str):
    return _rule_info(lab, _require_rule(lab, rule_id))


def _validate_params(rule, params: dict[str, int]) -> None:
    specs = {p.name: p for p in rule.params}
    for name, value in params.items():
        spec = specs.get(name)
        if spec is None:
            raise HTTPException(422, f"unknown parameter '{name}' for {rule.id}")
        if not spec.min <= value <= spec.max:
            raise HTTPException(422, f"'{name}' must be between {spec.min} and {spec.max}")


@router.patch("/rules/{rule_id}", response_model=RuleInfo)
def update_rule(lab: Lab, rule_id: str, body: RuleUpdate):
    rule = _require_rule(lab, rule_id)
    with lab.store.lock:
        override = lab.rule_override(rule.id)
        messages = []
        if body.enabled is not None and body.enabled != override.enabled:
            override.enabled = body.enabled
            messages.append("enabled" if body.enabled else "disabled")
        if body.params:
            _validate_params(rule, body.params)
            override.params = {**override.params, **body.params}
            messages.append("tuned " + ", ".join(f"{k}={v}" for k, v in body.params.items()))
        lab.store.rules.upsert(override)
        if messages:
            lab.log("analyst", "rule.updated", f"{rule.id} {rule.name}: {'; '.join(messages)}", "rule", rule.id)
        lab.store.persist_all()
    return _rule_info(lab, rule)


@router.post("/rules/{rule_id}/backtest", response_model=BacktestResult)
def backtest_rule(lab: Lab, rule_id: str, body: BacktestRequest):
    """Run one rule with candidate parameters over all stored events without persisting anything."""
    rule = _require_rule(lab, rule_id)
    _validate_params(rule, body.params)
    params = {**lab.rule_override(rule.id).params, **body.params}
    alerts = lab.engine.run_rule(rule, lab.store.events.sorted(), params)
    return BacktestResult(
        rule_id=rule.id,
        params=rule.resolve_params(params),
        alert_count=len(alerts),
        current_alert_count=sum(1 for a in lab.store.alerts.all() if a.rule_id == rule.id),
        sample=[
            {"timestamp": a.timestamp, "severity": a.severity, "hostname": a.hostname, "username": a.username,
             "source_ip": a.source_ip, "reason": a.reason, "existing": a.id in lab.store.alerts}
            for a in sorted(alerts, key=lambda a: a.timestamp, reverse=True)[:10]
        ],
    )  # fmt: skip


# ---------------------------------------------------------------- simulations
@router.get("/simulations/scenarios", response_model=list[ScenarioSummary])
def list_scenarios(lab: Lab):
    runs = sorted(lab.store.simulation_runs.all(), key=lambda r: r.executed_at)
    summaries = []
    for s in lab.scenarios.values():
        mine = [r for r in runs if r.scenario_id == s.id]
        summaries.append(
            ScenarioSummary(
                **s.model_dump(
                    include=set(ScenarioSummary.model_fields) - {"event_estimate", "challenge_points", "run_count", "last_run_id"}
                ),
                event_estimate=estimate_events(s),
                challenge_points=sum(q.points for q in s.challenge),
                run_count=len(mine),
                last_run_id=mine[-1].id if mine else None,
            )
        )
    return summaries


@router.post("/simulations/run")
def simulate(lab: Lab, body: SimulationRequest):
    if body.scenario_id not in lab.scenarios:
        raise HTTPException(404, f"scenario {body.scenario_id} not found")
    try:
        run = run_simulation(lab, body.scenario_id, body.seed)
    except ScenarioError as exc:
        raise HTTPException(500, f"scenario error: {exc}") from exc
    return _run_detail(lab, run)


@router.get("/simulations/runs", response_model=list[SimulationRun])
def list_runs(lab: Lab):
    return sorted(lab.store.simulation_runs.all(), key=lambda r: r.executed_at, reverse=True)


@router.get("/simulations/runs/{run_id}")
def get_run(lab: Lab, run_id: str):
    run = lab.store.simulation_runs.get(run_id)
    if run is None:
        raise HTTPException(404, f"simulation run {run_id} not found")
    return _run_detail(lab, run)


def _require_run(lab, run_id: str) -> SimulationRun:
    run = lab.store.simulation_runs.get(run_id)
    if run is None:
        raise HTTPException(404, f"simulation run {run_id} not found")
    if run.scenario_id not in lab.scenarios:
        raise HTTPException(404, f"scenario {run.scenario_id} no longer exists")
    return run


@router.get("/simulations/runs/{run_id}/challenge")
def get_challenge(lab: Lab, run_id: str):
    run = _require_run(lab, run_id)
    return challenge.view(lab.scenarios[run.scenario_id], run)


@router.post("/simulations/runs/{run_id}/challenge/hint")
def challenge_hint(lab: Lab, run_id: str, body: HintRequest):
    run = _require_run(lab, run_id)
    try:
        return challenge.use_hint(lab, lab.scenarios[run.scenario_id], run, body.question_id)
    except challenge.ChallengeError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.post("/simulations/runs/{run_id}/challenge")
def submit_challenge(lab: Lab, run_id: str, body: ChallengeSubmission):
    run = _require_run(lab, run_id)
    try:
        return challenge.submit(lab, lab.scenarios[run.scenario_id], run, body.answers)
    except challenge.ChallengeError as exc:
        raise HTTPException(409, str(exc)) from exc


def _run_detail(lab, run: SimulationRun) -> dict:
    alerts = [a for a in (lab.store.alerts.get(i) for i in run.alert_ids) if a]
    ids = set(run.event_ids)
    return {
        "run": run,
        "alerts": sorted(alerts, key=lambda a: (-a.severity.rank, a.timestamp)),
        "incidents": [i for i in (lab.store.incidents.get(x) for x in run.incident_ids) if i],
        "events": [e for e in lab.store.events.sorted() if e.id in ids][:200],
        "highest_severity": Severity.max([a.severity for a in alerts]) if alerts else None,
        "open_alerts": sum(1 for a in alerts if a.status == AlertStatus.new),
    }
