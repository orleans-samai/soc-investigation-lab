"""The purple-team loop: regression testing, custom Sigma rules, scenarios from real logs and shift mode."""

from __future__ import annotations

from datetime import timedelta

import pytest

from app.detection.sigma_rules import SigmaError, SigmaRule
from app.models.events import EventSource, EventType, Outcome
from app.services import shifts as shift_service
from tests.conftest import T0, ev, rules_fired

# ---------------------------------------------------------------- LAB-018 (PIX account takeover)


def bank(action: str, seconds: float, device: str, ip: str = "192.0.2.10", user: str = "cli.teste", **fields):
    event_type = {"pix_transfer": EventType.transaction, "payee_added": EventType.account_management}.get(action, EventType.authentication)
    return ev(
        action,
        seconds=seconds,
        source=EventSource.application,
        event_type=event_type,
        outcome=Outcome.failure if action == "login_failed" else Outcome.success,
        username=user,
        hostname="ib-portal",
        source_ip=ip,
        fields={"device_id": device, **fields},
    )


def takeover(amount: int = 4800, new_device: str = "dev-evil", minutes_to_transfer: int = 5):
    return [
        bank("login_success", 0, "dev-home"),
        bank("login_success", 3600, new_device, ip="203.0.113.9"),
        bank("payee_added", 3660, new_device, ip="203.0.113.9", recipient_key="mule@x.example"),
        bank(
            "pix_transfer",
            3600 + minutes_to_transfer * 60,
            new_device,
            ip="203.0.113.9",
            amount=str(amount),
            recipient_key="mule@x.example",
        ),
    ]


class TestPixTakeover:
    def test_fires_on_new_device_change_and_transfer(self, engine):
        alerts = [a for a in engine.run(takeover()) if a.rule_id == "LAB-018"]
        assert len(alerts) == 1
        assert alerts[0].source_ip == "203.0.113.9" and "R$ 4.800,00" in alerts[0].reason

    def test_known_device_small_amount_or_slow_transfer_are_quiet(self, engine):
        assert "LAB-018" not in rules_fired(engine, takeover(new_device="dev-home"))
        assert "LAB-018" not in rules_fired(engine, takeover(amount=200))
        assert "LAB-018" not in rules_fired(engine, takeover(minutes_to_transfer=90))

    def test_first_login_ever_has_no_history_to_compare(self, engine):
        assert "LAB-018" not in rules_fired(engine, takeover()[1:])

    def test_large_total_is_critical(self, engine):
        (alert,) = [a for a in engine.run(takeover(amount=50_000)) if a.rule_id == "LAB-018"]
        assert alert.severity.value == "critical"


# ---------------------------------------------------------------- custom Sigma rules
ENCODED_PS = """
title: Encoded PowerShell
id: 4b0c3a3e-0000-4000-8000-000000000001
logsource: {product: windows, category: process_creation}
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: [' -enc ', ' -EncodedCommand ']
  filter_admin:
    User: adm.roliveira
  condition: selection and not filter_admin
level: high
tags: [attack.execution, attack.t1059.001]
"""

BRUTE = """
title: Failed logon
logsource: {product: windows, service: security}
detection:
  selection: {EventID: 4625}
  condition: selection
---
title: Brute force (custom)
correlation:
  type: event_count
  rules: [failed]
  group-by: [TargetUserName]
  timespan: 5m
  condition: {gte: 4}
level: medium
"""


def proc(command: str, user: str = "j.silva", seconds: float = 0):
    return ev(
        "process_created",
        seconds=seconds,
        source=EventSource.windows_sysmon,
        event_type=EventType.process,
        hostname="ws-fin-01",
        username=user,
        process_name="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line=command,
        event_id="1",
    )


class TestSigmaRules:
    def test_selection_modifiers_filters_and_mitre(self, engine):
        rule = SigmaRule("CUS-001", ENCODED_PS, lambda t: ("PowerShell", "Execution") if t == "T1059.001" else None)
        assert rule.severity.value == "high" and rule.mitre[0].technique_id == "T1059.001"
        assert rule.matches(proc("powershell.exe -NoP -enc SQBFAFgA"))
        assert not rule.matches(proc("powershell.exe -enc SQBFAFgA", user="adm.roliveira"))
        assert not rule.matches(proc("powershell.exe Get-Date"))
        drafts = rule.evaluate([proc("powershell -enc AAA", seconds=i) for i in range(3)], engine.context, {})
        assert len(drafts) == 1 and len(drafts[0].events) == 3

    def test_event_count_correlation_becomes_tunable_threshold(self, engine):
        rule = SigmaRule("CUS-002", BRUTE)
        assert rule.rule_type == "threshold" and rule.defaults() == {"threshold": 4, "window_minutes": 5}
        failures = [ev("logon_failed", seconds=i * 10, username="m.santos", event_id="4625") for i in range(5)]
        assert len(rule.evaluate(failures, engine.context, rule.defaults())) == 1
        assert rule.evaluate(failures, engine.context, {"threshold": 6, "window_minutes": 5}) == []

    @pytest.mark.parametrize(
        ("source", "message"),
        [
            ("title: x\nlogsource: {product: windows}\ndetection: {sel: {EventID: 1}, condition: sel and other}", "unknown selection"),
            ("title: x\nlogsource: {product: macos}\ndetection: {sel: {EventID: 1}, condition: sel}", "not available"),
            ("title: x\nlogsource: {product: windows}\ndetection: {sel: {Image|base64: a}, condition: sel}", "not supported"),
            ("title: x\nlogsource: {product: windows}\ndetection: {sel: {EventID: 1}, condition: sel | count() > 5}", "correlation"),
            ("title: [unclosed", "invalid YAML"),
        ],
    )
    def test_clear_errors(self, source, message):
        with pytest.raises(SigmaError, match=message):
            SigmaRule("CUS-X", source)

    def test_exported_builtin_rule_round_trips(self, client):
        exported = client.get("/api/rules/LAB-002/sigma").text
        preview = client.post("/api/rules/custom/validate", json={"source": exported}).json()
        assert preview["rule"]["rule_type"] == "threshold" and preview["matched_events"] > 0

    def test_custom_rule_lifecycle(self, client):
        created = client.post("/api/rules/custom", json={"source": ENCODED_PS})
        assert created.status_code == 201
        rule = created.json()
        assert rule["id"] == "CUS-001" and rule["custom"] and rule["source"] == ENCODED_PS
        assert any(r["id"] == "CUS-001" for r in client.get("/api/rules").json())
        assert "Encoded PowerShell" in client.get("/api/rules/CUS-001/sigma").text
        assert client.patch("/api/rules/CUS-001", json={"enabled": False}).json()["enabled"] is False
        bad = client.put("/api/rules/custom/CUS-001", json={"source": "title: x"})
        assert bad.status_code == 422
        assert client.delete("/api/rules/custom/CUS-001").status_code == 204
        assert client.get("/api/rules/CUS-001").status_code == 404

    def test_custom_rules_survive_restart_and_reset(self, settings):
        from fastapi.testclient import TestClient

        from app.main import create_app

        with TestClient(create_app(settings)) as c:
            c.post("/api/rules/custom", json={"source": ENCODED_PS})
            c.post("/api/system/reset?confirm=RESET")
        with TestClient(create_app(settings)) as c:
            assert c.get("/api/rules/CUS-001").json()["name"] == "Encoded PowerShell"


# ---------------------------------------------------------------- regression testing
class TestRegression:
    def test_current_rules_detect_every_attack(self, client):
        report = client.post("/api/detection/regression", json={}).json()
        s = report["summary"]
        assert report["passed"] and s["regressions"] == 0
        assert s["detected_before"] == s["detected_after"] == s["attack_scenarios"] >= 8
        assert {o["status"] for o in report["scenarios"]} <= {"detected", "unchanged"}

    def test_detuning_a_rule_is_reported_as_regression(self, client):
        report = client.post("/api/detection/regression", json={"changes": {"LAB-001": {"params": {"threshold": 100}}}}).json()
        assert not report["passed"]
        regressed = {o["scenario_id"] for o in report["scenarios"] if o["status"] == "regressed"}
        assert "ssh-bruteforce-compromise" in regressed
        assert {"LAB-001"} <= {r for o in report["scenarios"] for r in o["missed_after"]}

    def test_disabling_a_noisy_rule_shows_noise_reduction_and_lost_coverage(self, client):
        report = client.post("/api/detection/regression", json={"changes": {"LAB-002": {"enabled": False}}}).json()
        statuses = {o["scenario_id"]: o["status"] for o in report["scenarios"]}
        assert statuses["forgotten-password"] == "noise_reduced"
        assert statuses["windows-password-spray"] == "regressed"
        assert report["summary"]["noise_after"] < report["summary"]["noise_before"]

    def test_invalid_change_is_rejected(self, client):
        assert client.post("/api/detection/regression", json={"changes": {"LAB-001": {"params": {"threshold": 0}}}}).status_code == 422
        assert client.post("/api/detection/regression", json={"changes": {"LAB-999": {"enabled": False}}}).status_code == 404

    def test_regression_never_writes_lab_state(self, client):
        before = client.get("/api/system/status").json()["counts"]
        client.post("/api/detection/regression", json={"changes": {"LAB-001": {"params": {"threshold": 3}}}})
        assert client.get("/api/system/status").json()["counts"] == before


# ---------------------------------------------------------------- scenarios from real logs
class TestAuthoring:
    QUERY = "event_action:logon_failed AND host:bastion-01"

    def test_preview_anonymizes_everywhere(self, client):
        body = {"query": self.QUERY, "name": "Bastion brute force replay", "verdict": "malicious", "anonymize": True}
        preview = client.post("/api/simulations/scenarios/preview", json=body).json()
        assert preview["event_count"] > 0
        kinds = {p["kind"] for p in preview["pseudonyms"]}
        assert {"host", "ip"} <= kinds
        originals = [p["original"] for p in preview["pseudonyms"] if p["kind"] in ("host", "ip")]
        text = str(preview["sample"]).lower()
        assert not any(o.lower() in text for o in originals)
        assert "LAB-001" in preview["scenario"]["expected_rules"]

    def test_pseudonyms_keep_internal_and_external_apart(self):
        from app.services.authoring import Pseudonyms

        names = Pseudonyms()
        assert names.ip("10.10.10.23").startswith("10.99.")
        assert names.ip("198.51.100.200").startswith("203.0.113.")  # documentation range = external attacker
        assert names.ip("127.0.0.1") == "127.0.0.1"

    def test_saved_scenario_runs_repeatedly_and_exports(self, client):
        body = {
            "query": self.QUERY,
            "name": "Bastion brute force replay",
            "anonymize": False,
            "challenge": [{"id": "ip", "question": "Attacker IP?", "answers": ["198.51.100.23"], "hint": "h", "explanation": "e"}],
        }
        created = client.post("/api/simulations/scenarios", json=body)
        assert created.status_code == 201
        summary = created.json()
        assert summary["origin"] == "custom" and summary["challenge_points"] == 25
        runs = [client.post("/api/simulations/run", json={"scenario_id": summary["id"], "seed": s}).json()["run"] for s in (1, 2)]
        assert all(r["event_count"] == runs[0]["event_count"] > 0 for r in runs)  # fresh ids each replay
        assert not runs[0]["missed_rules"]
        exported = client.get(f"/api/simulations/scenarios/{summary['id']}/export").json()
        client.delete(f"/api/simulations/scenarios/{summary['id']}")
        assert client.post("/api/simulations/scenarios/import", json=exported).status_code == 201

    def test_bad_queries_are_explained(self, client):
        base = {"name": "x scenario"}
        assert "no events" in client.post("/api/simulations/scenarios/preview", json={**base, "query": "host:nope"}).json()["detail"]
        stats = client.post("/api/simulations/scenarios/preview", json={**base, "query": "* | stats count by host"}).json()["detail"]
        assert "stats" in stats

    def test_builtin_scenarios_cannot_be_deleted(self, client):
        assert client.delete("/api/simulations/scenarios/pix-account-takeover").status_code == 409


# ---------------------------------------------------------------- shift mode
class TestShift:
    def test_full_shift_scoring(self, client):
        shift = client.post("/api/shifts", json={"duration_minutes": 20, "seed": 7}).json()
        assert shift["status"] == "active" and len(shift["queue"]) >= 4
        assert "truth" not in shift["queue"][0]  # ground truth stays hidden during the shift
        assert client.post("/api/shifts", json={}).status_code == 409  # one shift at a time

        # Answer from the server's ground truth, with a note naming the entity, to get a perfect shift.
        lab = client.app.state.lab
        truth = {i.alert_id: i.truth for i in lab.store.shifts.get(shift["id"]).items}
        for item in shift["queue"]:
            alert = item["alert"]
            entity = alert["username"] or alert["hostname"] or alert["source_ip"]
            note = f"Checked activity of {entity} against the timeline and context."
            view = client.post(f"/api/shifts/{shift['id']}/alerts/{alert['id']}", json={"verdict": truth[alert["id"]], "note": note}).json()
        assert view["status"] == "finished"  # deciding the last alert closes the shift
        assert view["score"]["total"] == 100 and view["score"]["missed_attacks"] == 0
        assert all(q["truth"] for q in view["queue"])
        statuses = {client.get(f"/api/alerts/{a}").json()["alert"]["status"] for a in truth}
        assert statuses <= {"investigating", "benign", "false_positive"}

    def test_closing_an_attack_as_noise_is_a_missed_attack(self, client):
        shift = client.post("/api/shifts", json={"seed": 3}).json()
        lab = client.app.state.lab
        items = lab.store.shifts.get(shift["id"]).items
        attack = next(i for i in items if i.truth == "malicious")
        client.post(f"/api/shifts/{shift['id']}/alerts/{attack.alert_id}", json={"verdict": "benign"})
        view = client.post(f"/api/shifts/{shift['id']}/finish").json()
        assert view["score"]["missed_attacks"] >= 1 and view["score"]["total"] < 20
        graded = next(q for q in view["queue"] if q["alert_id"] == attack.alert_id)
        assert graded["accuracy_points"] == 0 and "Missed attack" in graded["feedback"]
        assert client.post(f"/api/shifts/{shift['id']}/alerts/{attack.alert_id}", json={"verdict": "malicious"}).status_code == 409

    def test_shift_expires(self, client):
        shift = client.post("/api/shifts", json={"duration_minutes": 5}).json()
        lab = client.app.state.lab
        stored = lab.store.shifts.get(shift["id"])
        stored.ends_at = stored.started_at - timedelta(seconds=1)
        assert client.get(f"/api/shifts/{shift['id']}").json()["status"] == "finished"

    def test_grading_rules(self):
        from app.models.shifts import ShiftItem

        def grade(truth, verdict):
            return shift_service._grade(ShiftItem(alert_id="a", run_id="r", scenario_id="s", truth=truth, verdict=verdict))[0]

        assert grade("malicious", "malicious") == 6
        assert grade("malicious", "false_positive") == 0
        assert grade("benign", "malicious") == 2
        assert grade("benign", "false_positive") == 4


def test_t0_is_business_hours():
    assert T0.weekday() < 5


# ---------------------------------------------------------------- LGPD
def test_business_days_skip_weekends():
    from datetime import date

    from app.services.reports import add_business_days

    assert add_business_days(date(2026, 10, 30), 3) == date(2026, 11, 4)  # Friday -> Wednesday


def test_pix_incident_report_has_lgpd_section(client):
    run = client.post("/api/simulations/run", json={"scenario_id": "pix-account-takeover", "seed": 4}).json()
    incident_id = run["run"]["incident_ids"][0]
    report = client.get(f"/api/incidents/{incident_id}/report").json()
    assert report["lgpd"]["suggested"] and report["lgpd"]["personal_data"] is None
    client.patch(f"/api/incidents/{incident_id}", json={"personal_data": True})
    markdown = client.get(f"/api/incidents/{incident_id}/report.md").text
    assert "LGPD notification" in markdown and "3 business days" in markdown and "CD/ANPD" in markdown
    metrics = client.get("/api/metrics").json()
    assert "shifts" in metrics and "last_regression" in metrics
