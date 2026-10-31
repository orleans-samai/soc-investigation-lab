from __future__ import annotations

import json

import pytest

AUTH_LOG = (
    "\n".join(
        f"Oct 31 03:10:{i * 5:02d} bastion-01 sshd[{4000 + i}]: Failed password for root from 203.0.113.200 port {50000 + i} ssh2"
        for i in range(10)
    )
    + "\nthis line is garbage\n"
)


def upload(client, content: str | bytes, name="auth.log", dry_run=False, **form):
    data = {"dry_run": str(dry_run).lower(), "timezone": "UTC", "year": "2026", **form}
    payload = content.encode() if isinstance(content, str) else content
    return client.post("/api/imports", data=data, files={"file": (name, payload, "text/plain")})


def test_bootstrap_loads_seed_and_runs_detection(client):
    status = client.get("/api/system/status").json()
    assert status["mode"] == "simulation"
    assert status["counts"]["events"] > 900 and status["counts"]["alerts"] == 3 and status["counts"]["incidents"] == 1
    dashboard = client.get("/api/dashboard", params={"range": "7d"}).json()
    assert dashboard["kpis"]["events_in_range"] == status["counts"]["events"]
    assert sum(b["events"] for b in dashboard["timeline"]) == dashboard["kpis"]["events_in_range"]


def test_import_preview_commit_and_duplicate_protection(client):
    preview = upload(client, AUTH_LOG, dry_run=True).json()
    assert preview["dry_run"] and preview["format"] == "linux_ssh"
    assert (preview["parsed"], preview["added"], preview["error_count"]) == (10, 10, 1)
    assert preview["errors"][0]["line"] == 11
    assert client.get("/api/system/status").json()["counts"]["imports"] == 0, "dry run must not persist"

    committed = upload(client, AUTH_LOG).json()
    assert committed["added"] == 10 and committed["alerts_created"] >= 1 and committed["incidents_touched"]

    again = upload(client, AUTH_LOG).json()
    assert (again["added"], again["duplicates"]) == (0, 10)

    events = client.get("/api/events", params={"source_ip": "203.0.113.200"}).json()
    assert events["total"] == 10 and events["items"][0]["raw"].startswith("Oct 31")


def test_import_rejections(client):
    assert upload(client, b"\x00\x01binary").status_code == 422
    assert upload(client, '{"foo": 1}', name="x.json").status_code == 422
    assert upload(client, "   ").status_code == 422
    assert upload(client, "a" * (5 * 1024 * 1024 + 10)).status_code == 413


def test_simulation_creates_alerts_and_incident(client):
    response = client.post("/api/simulations/run", json={"scenario_id": "powershell-download-cradle", "seed": 7})
    body = response.json()
    assert response.status_code == 200
    assert body["run"]["missed_rules"] == [] and body["highest_severity"] == "critical"
    incident_id = body["run"]["incident_ids"][0]
    detail = client.get(f"/api/incidents/{incident_id}").json()
    assert {a["rule_id"] for a in detail["alerts"]} == {"LAB-009", "LAB-010", "LAB-016", "LAB-017"}
    assert detail["playbook"]

    report = client.get(f"/api/incidents/{incident_id}/report").json()
    assert any(i["type"] == "url" and "203.0.113.80" in i["value"] for i in report["iocs"])
    markdown = client.get(f"/api/incidents/{incident_id}/report.md")
    assert markdown.headers["content-type"].startswith("text/markdown") and "## 6. Indicators of compromise" in markdown.text
    assert client.post("/api/simulations/run", json={"scenario_id": "nope"}).status_code == 404


def test_incident_workflow_requires_documentation(client):
    incident_id = client.get("/api/incidents").json()["items"][0]["id"]
    assert client.patch(f"/api/incidents/{incident_id}", json={"status": "closed"}).status_code == 422
    client.post(f"/api/incidents/{incident_id}/notes", json={"body": "Source is a known malicious VPS.", "author": "ana"})
    assert client.get(f"/api/incidents/{incident_id}").json()["incident"]["status"] == "investigating"

    closed = client.patch(
        f"/api/incidents/{incident_id}",
        json={"status": "closed", "classification": "true_positive", "resolution": "IP blocked, no successful logon."},
    )
    assert closed.status_code == 200 and closed.json()["closed_at"]
    alerts = client.get("/api/alerts", params={"q": incident_id}).json()["items"]
    assert alerts and all(a["status"] == "resolved" for a in alerts)
    metrics = client.get("/api/metrics").json()
    assert metrics["overall"]["true_positive"] >= 1 and metrics["overall"]["mean_time_to_resolve_seconds"] is not None


def test_alert_triage_and_escalation(client):
    unassigned = client.get("/api/alerts", params={"incident": "unassigned"}).json()["items"]
    assert unassigned, "baseline contains medium alerts waiting for triage"
    alert_id = unassigned[0]["id"]
    updated = client.patch(f"/api/alerts/{alert_id}", json={"status": "false_positive", "analyst_note": "CHG-2041"}).json()
    assert updated["status"] == "false_positive"
    other = unassigned[1]["id"]
    created = client.post("/api/incidents", json={"alert_ids": [other], "title": "Escalated off-hours logon"})
    assert created.status_code == 201 and created.json()["title"] == "Escalated off-hours logon"
    assert client.post("/api/incidents", json={"alert_ids": [other]}).status_code == 409


def test_rules_toggle_tune_and_backtest(client):
    assert client.patch("/api/rules/LAB-001", json={"params": {"threshold": 1000}}).status_code == 422
    assert client.patch("/api/rules/LAB-001", json={"params": {"bogus": 1}}).status_code == 422
    tuned = client.patch("/api/rules/LAB-001", json={"enabled": False, "params": {"threshold": 20}}).json()
    assert tuned["enabled"] is False and tuned["params"][0]["value"] == 20 and "count >= 20" in tuned["logic"]
    loose = client.post("/api/rules/LAB-001/backtest", json={"params": {"threshold": 3}}).json()
    strict = client.post("/api/rules/LAB-001/backtest", json={"params": {"threshold": 50}}).json()
    assert loose["alert_count"] > strict["alert_count"]


def test_export_neutralises_formulas(client):
    line = "2026-10-30T10:00:00Z web-01 sudo: alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND==cmd|' /C calc'!A0"
    upload(client, line)
    csv_text = client.get("/api/events/export", params={"username": "alice", "format": "csv"}).text
    assert "'=cmd" in csv_text
    as_json = client.get("/api/events/export", params={"username": "alice", "format": "json"}).json()
    assert as_json[0]["command_line"].startswith("=cmd")


def test_entities_search_and_mitre(client):
    user = client.get("/api/entities/user/adm.roliveira").json()
    assert user["identity"]["privileged"] and user["alerts"]
    assert client.get("/api/entities/ip/198.51.100.23").json()["network"]["geo"]["reputation"] == "suspicious"
    assert client.get("/api/entities/user/nobody-here").status_code == 404
    assert client.get("/api/entities/planet/x").status_code == 404
    assert client.get("/api/search", params={"q": "bastion"}).json()["entities"]
    mitre = client.get("/api/mitre").json()
    assert mitre["summary"]["covered"] >= 15 and mitre["tactics"][0]["name"] == "Initial Access"


def test_reset_requires_confirmation_and_restores_seed(client):
    client.post("/api/simulations/run", json={"scenario_id": "lateral-movement-service"})
    assert client.post("/api/system/reset").status_code == 400
    assert client.post("/api/system/reset", params={"confirm": "RESET"}).json()["alerts"] == 3
    assert client.get("/api/simulations/runs").json() == []


@pytest.mark.parametrize("backend", ["sqlite", "json"])
def test_state_survives_restart(tmp_path, backend):
    from fastapi.testclient import TestClient

    from app.config import Settings
    from app.main import create_app

    settings = Settings(state_dir=tmp_path / "state", storage_backend=backend)
    with TestClient(create_app(settings)) as c:
        run = c.post("/api/simulations/run", json={"scenario_id": "linux-backdoor-account", "seed": 5}).json()["run"]
        c.patch("/api/rules/LAB-001", json={"enabled": False})
    with TestClient(create_app(settings)) as c:
        assert c.get(f"/api/simulations/runs/{run['id']}").status_code == 200
        assert next(r for r in c.get("/api/rules").json() if r["id"] == "LAB-001")["enabled"] is False
        assert c.get("/api/system/status").json()["storage"]["backend"] == backend
    if backend == "json":
        assert json.loads((settings.state_dir / "events.json").read_text(encoding="utf-8"))["schema_version"] == 1
    else:
        assert (settings.state_dir / "lab.db").exists() and not (settings.state_dir / "events.json").exists()


def test_challenge_mode_scoring(client):
    run = client.post("/api/simulations/run", json={"scenario_id": "ssh-bruteforce-compromise", "seed": 11}).json()["run"]
    url = f"/api/simulations/runs/{run['id']}/challenge"
    view = client.get(url).json()
    assert view["max_score"] == 100 and not view["submitted"]
    assert all("expected" not in q and q["hint"] is None for q in view["questions"]), "answers must not leak before submission"

    hinted = client.post(f"{url}/hint", json={"question_id": "account"}).json()
    assert next(q for q in hinted["questions"] if q["id"] == "account")["hint"]

    answers = {
        "source_ip": f"  {run['variables']['attacker_ip']} ",  # whitespace is tolerated
        "account": "deploy",
        "next_step": "Run commands as root with sudo",
        "classification": "False positive",  # wrong on purpose
    }
    result = client.post(url, json={"answers": answers}).json()
    assert result["submitted"] and result["score"] == 25 + 12 + 25  # hint halves 'account'
    wrong = next(q for q in result["questions"] if q["id"] == "classification")
    assert wrong["correct"] is False and wrong["expected"] == "True positive"
    assert client.post(url, json={"answers": answers}).status_code == 409
    assert client.get("/api/metrics").json()["simulation"]["challenges_completed"] == 1
