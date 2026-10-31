from __future__ import annotations

import json
from datetime import UTC, datetime
from zoneinfo import ZoneInfo

import pytest

from app.models.imports import LogFormat
from app.parsers import ParseOptions, UnsupportedFormatError, detect_format, parse_text
from app.parsers.base import parse_timestamp
from app.parsers.linux import LinuxAuthParser
from app.parsers.normalized import NormalizedJsonParser
from app.parsers.windows import WindowsJsonParser

OPTS = ParseOptions(dataset="test")


def win(event_id: int, **data):
    return {"EventID": event_id, "TimeCreated": "2026-10-30T14:02:11.1234567Z", "Computer": "DC-01.corp.lab", "EventData": data}


class TestTimestamps:
    def test_windows_seven_digit_fraction_and_z(self):
        assert parse_timestamp("2026-10-30T14:02:11.1234567Z", UTC) == datetime(2026, 10, 30, 14, 2, 11, 123456, tzinfo=UTC)

    def test_offset_is_converted_to_utc(self):
        assert parse_timestamp("2026-10-30T11:00:00-03:00", UTC).hour == 14

    def test_naive_uses_default_timezone(self):
        assert parse_timestamp("2026-10-30 11:00:00", ZoneInfo("America/Sao_Paulo")).hour == 14

    def test_dotnet_date(self):
        assert parse_timestamp("/Date(1793455200000)/", UTC).year == 2026

    def test_garbage(self):
        with pytest.raises(ValueError):
            parse_timestamp("yesterday", UTC)


class TestWindowsParser:
    def test_failed_logon_maps_fields(self):
        record = win(4625, TargetUserName="J.Silva", TargetDomainName="CORP", IpAddress="10.10.10.21", IpPort="51000",
                     LogonType="3", SubStatus="0xc000006a")  # fmt: skip
        result = WindowsJsonParser().parse(json.dumps([record]), OPTS)
        assert result.error_count == 0
        e = result.events[0]
        assert (e.event_action, e.outcome, e.username, e.hostname, e.source_ip, e.logon_type) == (
            "logon_failed", "failure", "j.silva", "dc-01", "10.10.10.21", 3
        )  # fmt: skip
        assert e.fields["failure_reason"] == "bad password"
        assert json.loads(e.raw)["EventID"] == 4625, "raw record must be preserved"

    def test_group_membership_extracts_member_cn(self):
        record = win(4732, SubjectUserName="adm.x", TargetUserName="Administrators", MemberName="CN=evil,CN=Users,DC=corp,DC=lab")
        e = WindowsJsonParser().parse(json.dumps(record), OPTS).events[0]
        assert (e.event_action, e.group_name, e.target_username, e.username) == ("group_member_added", "Administrators", "evil", "adm.x")

    def test_scheduled_task_command_extracted(self):
        xml = "<Task><Actions><Exec><Command>C:\\Temp\\a.exe</Command><Arguments>-x</Arguments></Exec></Actions></Task>"
        e = WindowsJsonParser().parse(json.dumps(win(4698, SubjectUserName="u", TaskName="\\T", TaskContent=xml)), OPTS).events[0]
        assert e.command_line == "C:\\Temp\\a.exe -x"

    def test_unsupported_event_id_is_skipped_not_error(self):
        result = WindowsJsonParser().parse(json.dumps([win(5156)]), OPTS)
        assert (result.skipped, result.error_count, len(result.events)) == (1, 0, 0)

    def test_errors_are_reported_per_ndjson_line(self):
        text = "\n".join([json.dumps(win(4624, TargetUserName="a")), "{not json", json.dumps({"Computer": "x"})])
        result = WindowsJsonParser().parse(text, OPTS)
        assert len(result.events) == 1
        assert [(i.line, i.message.split(":")[0]) for i in result.errors] == [(2, "invalid JSON"), (3, "missing EventID")]

    def test_missing_hostname_is_an_error(self):
        result = WindowsJsonParser().parse(json.dumps({"EventID": 4624, "TimeCreated": "2026-10-30T00:00:00Z"}), OPTS)
        assert result.error_count == 1

    def test_ids_are_deterministic(self):
        text = json.dumps([win(4624, TargetUserName="a")])
        assert WindowsJsonParser().parse(text, OPTS).events[0].id == WindowsJsonParser().parse(text, OPTS).events[0].id


class TestLinuxParser:
    def test_bsd_header_uses_year_and_timezone(self):
        options = ParseOptions(timezone=ZoneInfo("America/Sao_Paulo"), year=2026)
        line = "Oct 30 11:02:11 bastion-01 sshd[2211]: Failed password for invalid user admin from 203.0.113.9 port 4123 ssh2"
        e = LinuxAuthParser().parse(line, options).events[0]
        assert e.timestamp == datetime(2026, 10, 30, 14, 2, 11, tzinfo=UTC)
        assert (e.event_action, e.username, e.source_ip, e.source_port, e.hostname) == (
            "logon_failed",
            "admin",
            "203.0.113.9",
            4123,
            "bastion-01",
        )
        assert "invalid_user" in e.tags

    def test_bsd_year_rollover(self):
        options = ParseOptions(reference_time=datetime(2027, 1, 2, tzinfo=UTC))
        e = LinuxAuthParser().parse("Dec 31 23:00:00 h sshd[1]: Accepted password for a from 10.0.0.1 port 1 ssh2", options).events[0]
        assert e.timestamp.year == 2026

    @pytest.mark.parametrize(
        ("message", "action", "user"),
        [
            ("sshd[1]: Accepted publickey for deploy from 10.10.2.15 port 5000 ssh2: ED25519 SHA256:x", "logon_success", "deploy"),
            ("sudo:   bob : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash", "sudo_denied", "bob"),
            ("sudo: alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/id", "sudo_command", "alice"),
            ("useradd[9]: new user: name=backdoor, UID=1003, GID=1003, home=/home/backdoor, shell=/bin/bash", "user_created", None),
            ("usermod[9]: add 'backdoor' to group 'sudo'", "group_member_added", None),
            ("CRON[5]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)", "cron_session", "root"),
            ("sshd[1]: Connection closed by authenticating user root 203.0.113.5 port 52814 [preauth]", "connection_closed", "root"),
        ],
    )
    def test_supported_messages(self, message, action, user):
        e = LinuxAuthParser().parse(f"2026-10-30T14:00:00+00:00 web-01 {message}", OPTS).events[0]
        assert (e.event_action, e.username) == (action, user)

    def test_unknown_program_skipped_and_garbage_reported(self):
        text = "2026-10-30T14:00:00Z web-01 kernel: something\nthis is not a log line\n\n"
        result = LinuxAuthParser().parse(text, OPTS)
        assert (result.skipped, result.error_count, result.errors[0].line) == (1, 1, 2)

    def test_shell_content_is_never_executed(self, tmp_path):
        marker = tmp_path / "pwned"
        line = f"2026-10-30T14:00:00Z web-01 sudo: x : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=$(touch {marker})"
        e = LinuxAuthParser().parse(line, OPTS).events[0]
        assert e.command_line == f"$(touch {marker})"
        assert not marker.exists()


class TestNormalizedParser:
    def test_validation_errors_and_id_recomputed(self):
        good = {"id": "evt_spoofed", "timestamp": "2026-10-30T14:00:00Z", "event_source": "internal", "event_type": "other",
                "event_action": "x", "raw": "r"}  # fmt: skip
        bad = {"timestamp": "2026-10-30T14:00:00", "event_source": "nope", "event_action": "x", "raw": "r"}
        result = NormalizedJsonParser().parse(json.dumps([good, bad]), OPTS)
        assert len(result.events) == 1 and result.events[0].id != "evt_spoofed"
        assert result.error_count == 1 and "event_source" in result.errors[0].message


class TestFormatDetection:
    def test_detects_each_format(self):
        assert detect_format(json.dumps([win(4624)])) == LogFormat.windows_json
        assert detect_format(json.dumps([{"event_source": "x", "event_action": "y"}])) == LogFormat.normalized_json
        assert detect_format("Oct 30 11:02:11 h sshd[1]: hi") == LogFormat.linux_ssh

    def test_rejects_unknown(self):
        with pytest.raises(UnsupportedFormatError):
            detect_format('{"hello": "world"}')
        with pytest.raises(UnsupportedFormatError):
            detect_format("just some text")

    def test_parse_text_auto(self):
        result = parse_text("2026-10-30T14:00:00Z web-01 sshd[1]: Accepted password for a from 10.0.0.1 port 1 ssh2", LogFormat.auto, OPTS)
        assert result.format == LogFormat.linux_ssh and len(result.events) == 1
