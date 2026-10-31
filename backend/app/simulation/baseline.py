"""Deterministic generator for the baseline dataset (a week of normal corporate activity).

The baseline is generated as raw Windows records / auth.log lines and parsed with the real parsers,
then stored as normalized JSON in ``data/seed/baseline_events.json``. Regenerate with::

    python -m scripts.generate_seed
"""

from __future__ import annotations

import json
import random
from datetime import datetime, time, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from app.models.events import NormalizedEvent
from app.models.imports import LogFormat
from app.parsers import PARSERS, ParseOptions

UTC = ZoneInfo("UTC")
LAB_TZ = ZoneInfo("America/Sao_Paulo")
# The simulated "now" of the seed dataset. Scenario runs continue the clock from here.
ANCHOR = datetime(2026, 10, 30, 21, 0, tzinfo=UTC)
DAYS = 7

EMPLOYEES = [
    # username, workstation, workstation ip, uses ERP
    ("j.silva", "WS-FIN-01", "10.10.10.21", True),
    ("m.santos", "WS-HR-02", "10.10.10.22", True),
    ("a.costa", "WS-DEV-03", "10.10.10.23", False),
    ("r.oliveira", "WS-IT-04", "10.10.10.24", False),
    ("l.pereira", "WS-SALES-05", "10.10.10.25", True),
    ("c.souza", "WS-OPS-06", "10.10.10.26", True),
]
DAILY_APPS = [
    ("C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "OUTLOOK.EXE"),
    ("C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", "msedge.exe --profile-directory=Default"),
    ("C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE", "EXCEL.EXE"),
    ("C:\\Windows\\System32\\notepad.exe", "notepad.exe"),
    ("C:\\Program Files\\Microsoft VS Code\\Code.exe", "Code.exe"),
]
LINUX_HOSTS = ["bastion-01", "web-01", "db-01", "ci-01"]
NOISE_USERS = ["root", "admin", "ubuntu", "test", "oracle", "postgres", "user", "pi", "ftpuser", "guest"]


class _Builder:
    def __init__(self, seed: int):
        self.rng = random.Random(seed)
        self.windows: list[dict[str, Any]] = []
        self.linux: list[tuple[datetime, str]] = []

    # -- helpers -------------------------------------------------------------------------------
    def jitter(self, ts: datetime, seconds: int = 0) -> datetime:
        return ts + timedelta(seconds=self.rng.randint(0, seconds), milliseconds=self.rng.randint(0, 999))

    def win(self, event_id: int, ts: datetime, computer: str, data: dict[str, Any], channel: str = "Security", **extra: Any) -> None:
        record = {
            "EventID": event_id,
            "TimeCreated": f"{ts.astimezone(UTC):%Y-%m-%dT%H:%M:%S.%f}0Z",
            "Computer": f"{computer}.corp.lab",
            "Channel": channel,
            "Provider": "Microsoft-Windows-Security-Auditing" if channel == "Security" else "Service Control Manager",
            "Level": "Information",
            "EventData": data,
        }
        record.update(extra)
        self.windows.append(record)

    def logon(
        self, ts: datetime, computer: str, user: str, logon_type: int, ip: str | None, workstation: str, package: str = "Kerberos"
    ) -> None:
        self.win(
            4624,
            ts,
            computer,
            {
                "TargetUserName": user,
                "TargetDomainName": "CORP",
                "LogonType": str(logon_type),
                "IpAddress": ip or "-",
                "IpPort": str(self.rng.randint(49152, 65535)) if ip else "0",
                "WorkstationName": workstation,
                "AuthenticationPackageName": package,
            },
        )

    def logon_failed(self, ts: datetime, computer: str, user: str, logon_type: int, ip: str | None, workstation: str) -> None:
        self.win(
            4625,
            ts,
            computer,
            {
                "TargetUserName": user,
                "TargetDomainName": "CORP",
                "LogonType": str(logon_type),
                "IpAddress": ip or "-",
                "IpPort": "0",
                "WorkstationName": workstation,
                "Status": "0xc000006d",
                "SubStatus": "0xc000006a",
            },
        )

    def process(self, ts: datetime, computer: str, user: str, path: str, command: str, parent: str = "C:\\Windows\\explorer.exe") -> None:
        self.win(
            4688,
            ts,
            computer,
            {
                "SubjectUserName": user,
                "SubjectDomainName": "CORP",
                "NewProcessName": path,
                "CommandLine": command,
                "ParentProcessName": parent,
            },
        )

    def syslog(self, ts: datetime, host: str, program: str, message: str, pid: int | None = None) -> None:
        pid = pid if pid is not None else self.rng.randint(1000, 65000)
        self.linux.append((ts, f"{ts.astimezone(UTC).isoformat(timespec='microseconds')} {host} {program}[{pid}]: {message}"))

    def ssh_session(self, ts: datetime, host: str, user: str, ip: str, method: str = "publickey", minutes: int = 20) -> None:
        pid = self.rng.randint(1000, 65000)
        port = self.rng.randint(32768, 60999)
        suffix = " ssh2: ED25519 SHA256:lab" + str(self.rng.randint(100000, 999999)) if method == "publickey" else " ssh2"
        self.syslog(ts, host, "sshd", f"Accepted {method} for {user} from {ip} port {port}{suffix}", pid)
        self.syslog(
            ts + timedelta(milliseconds=40),
            host,
            "sshd",
            f"pam_unix(sshd:session): session opened for user {user}(uid=1001) by (uid=0)",
            pid,
        )
        end = ts + timedelta(minutes=minutes, seconds=self.rng.randint(0, 600))
        self.syslog(end, host, "sshd", f"pam_unix(sshd:session): session closed for user {user}", pid)

    def sudo(self, ts: datetime, host: str, user: str, command: str, pwd: str = "/home") -> None:
        self.syslog(ts, host, "sudo", f"{user} : TTY=pts/0 ; PWD={pwd} ; USER=root ; COMMAND={command}")

    # -- day generators ------------------------------------------------------------------------
    def workday(self, day: datetime) -> None:
        def at(hour: int, minute: int = 0) -> datetime:
            return datetime.combine(day.date(), time(hour, minute), LAB_TZ)

        for user, ws, ip, erp in EMPLOYEES:
            arrival = self.jitter(at(8), 90 * 60)
            if self.rng.random() < 0.25:  # a mistyped password in the morning: normal noise
                for k in range(self.rng.randint(1, 2)):
                    self.logon_failed(arrival - timedelta(seconds=30 - k * 8), ws, user, 2, None, ws)
            self.logon(arrival, ws, user, 2, None, ws)
            for _ in range(self.rng.randint(2, 4)):
                self.logon(self.jitter(arrival, 8 * 3600), "DC-01", user, 3, ip, ws)
            for _ in range(self.rng.randint(1, 3)):
                self.logon(self.jitter(arrival + timedelta(minutes=20), 7 * 3600), "FS-01", user, 3, ip, ws)
            if erp:
                self.logon(self.jitter(arrival + timedelta(hours=1), 6 * 3600), "APP-01", user, 3, ip, ws)
            for path, cmd in self.rng.sample(DAILY_APPS[:4] if user != "a.costa" else DAILY_APPS, k=3):
                self.process(self.jitter(arrival + timedelta(minutes=2), 5 * 3600), ws, user, path, cmd)
            departure = self.jitter(at(17), 2 * 3600)
            self.win(4634, departure, ws, {"TargetUserName": user, "TargetDomainName": "CORP", "LogonType": "2"})

        # IT administration with the dedicated admin account, during business hours.
        for host in self.rng.sample(["DC-01", "FS-01", "APP-01"], k=2):
            self.logon(self.jitter(at(10), 6 * 3600), host, "adm.roliveira", 3, "10.10.10.24", "WS-IT-04")
        if self.rng.random() < 0.5:
            ts = self.jitter(at(14), 3 * 3600)
            self.logon(ts, "APP-01", "adm.roliveira", 10, "10.10.10.24", "WS-IT-04")
            self.win(
                4672,
                ts + timedelta(seconds=1),
                "APP-01",
                {"SubjectUserName": "adm.roliveira", "SubjectDomainName": "CORP", "PrivilegeList": "SeBackupPrivilege SeDebugPrivilege"},
            )

        # Linux administration and development.
        self.ssh_session(self.jitter(at(9, 30), 3600), "bastion-01", "r.oliveira", "10.10.10.24")
        for _ in range(self.rng.randint(1, 3)):
            ts = self.jitter(at(10), 6 * 3600)
            host = self.rng.choice(["db-01", "web-01"])
            self.ssh_session(ts, host, "r.oliveira", "10.10.2.5")
            self.sudo(
                ts + timedelta(minutes=2),
                host,
                "r.oliveira",
                self.rng.choice(
                    [
                        "/usr/bin/systemctl status postgresql",
                        "/usr/bin/apt list --upgradable",
                        "/usr/bin/journalctl -u nginx --since today",
                        "/usr/bin/systemctl reload nginx",
                        "/usr/bin/df -h",
                    ]
                ),
            )
        for _ in range(self.rng.randint(1, 2)):
            self.ssh_session(self.jitter(at(9), 8 * 3600), self.rng.choice(["web-01", "ci-01"]), "a.costa", "10.10.10.23")

    def everyday(self, day: datetime) -> None:
        def at(hour: int, minute: int = 0) -> datetime:
            return datetime.combine(day.date(), time(hour, minute), LAB_TZ)

        # Nightly backup job (service account, network logons: expected off-hours activity).
        backup = self.jitter(at(2), 600)
        self.logon(backup, "FS-01", "svc_backup", 5, None, "FS-01")
        self.logon(backup + timedelta(minutes=3), "APP-01", "svc_backup", 3, "10.10.1.20", "FS-01")

        # CI deployments.
        for _ in range(self.rng.randint(1, 3)):
            ts = self.jitter(at(10), 9 * 3600)
            self.ssh_session(ts, "web-01", "deploy", "10.10.2.15", minutes=1)
            self.sudo(ts + timedelta(seconds=30), "web-01", "deploy", "/usr/bin/systemctl reload app", "/srv/app")

        # Cron on every Linux host.
        for host in LINUX_HOSTS:
            for hour in (0, 6, 12, 18):
                ts = at(hour, 17)
                pid = self.rng.randint(1000, 65000)
                self.syslog(ts, host, "CRON", "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)", pid)
                self.syslog(ts + timedelta(seconds=2), host, "CRON", "pam_unix(cron:session): session closed for user root", pid)

        # Internet background noise on exposed hosts: short, low-volume scans (below thresholds).
        for _ in range(self.rng.randint(3, 6)):
            host = self.rng.choice(["bastion-01", "web-01"])
            ip = f"{self.rng.choice(['203.0.113', '198.51.100'])}.{self.rng.randint(2, 254)}"
            ts = self.jitter(at(0), 23 * 3600)
            for k in range(self.rng.randint(1, 4)):
                user = self.rng.choice(NOISE_USERS)
                pid = self.rng.randint(1000, 65000)
                port = self.rng.randint(32768, 60999)
                moment = ts + timedelta(seconds=k * self.rng.randint(3, 15))
                prefix = "" if user == "root" else "invalid user "
                if prefix:
                    self.syslog(moment, host, "sshd", f"Invalid user {user} from {ip} port {port}", pid)
                self.syslog(
                    moment + timedelta(seconds=2), host, "sshd", f"Failed password for {prefix}{user} from {ip} port {port} ssh2", pid
                )
                self.syslog(
                    moment + timedelta(seconds=3),
                    host,
                    "sshd",
                    f"Connection closed by {'authenticating' if not prefix else 'invalid'} user {user} {ip} port {port} [preauth]",
                    pid,
                )

    def organic_incidents(self) -> None:
        # 1) Real SSH brute force against the bastion three days ago, no success.
        start = datetime(2026, 10, 27, 23, 10, tzinfo=LAB_TZ)
        ip = "198.51.100.23"
        users = ["root", "root", "admin", "root", "ubuntu", "root", "oracle", "root"]
        moment = start
        for k in range(40):
            moment += timedelta(seconds=self.rng.uniform(3, 8))
            user = users[k % len(users)]
            prefix = "" if user == "root" else "invalid user "
            self.syslog(
                moment, "bastion-01", "sshd", f"Failed password for {prefix}{user} from {ip} port {self.rng.randint(32768, 60999)} ssh2"
            )

        # 2) Approved after-hours patching (CHG-2041): fires LAB-005, should be closed as benign.
        for computer, local in (("DC-01", time(1, 12)), ("FS-01", time(1, 48))):
            ts = datetime.combine(datetime(2026, 10, 26).date(), local, LAB_TZ)
            self.logon(ts, computer, "adm.roliveira", 10, "10.10.10.24", "WS-IT-04")
            self.win(
                4672,
                ts + timedelta(seconds=1),
                computer,
                {"SubjectUserName": "adm.roliveira", "SubjectDomainName": "CORP", "PrivilegeList": "SeBackupPrivilege SeRestorePrivilege"},
            )
            self.process(
                ts + timedelta(minutes=3),
                computer,
                "adm.roliveira",
                "C:\\Windows\\System32\\wusa.exe",
                "wusa.exe C:\\Patches\\windows-kb-update-x64.msu /quiet /norestart",
            )
            self.win(
                4634,
                ts + timedelta(minutes=25),
                computer,
                {"TargetUserName": "adm.roliveira", "TargetDomainName": "CORP", "LogonType": "10"},
            )


def generate_baseline(seed: int = 2026, anchor: datetime = ANCHOR, days: int = DAYS) -> list[NormalizedEvent]:
    builder = _Builder(seed)
    start_day = (anchor - timedelta(days=days)).astimezone(LAB_TZ)
    for offset in range(days + 1):
        day = start_day + timedelta(days=offset)
        if day.weekday() < 5:
            builder.workday(day)
        builder.everyday(day)
    builder.organic_incidents()

    options = ParseOptions(dataset="baseline")
    events: list[NormalizedEvent] = []
    window_start = anchor - timedelta(days=days)
    result = PARSERS[LogFormat.windows_json].parse(json.dumps(builder.windows), options)
    linux = "\n".join(line for _, line in sorted(builder.linux))
    result_linux = PARSERS[LogFormat.linux_ssh].parse(linux, options)
    for res in (result, result_linux):
        if res.error_count:
            raise RuntimeError(f"baseline generator produced invalid data: {res.errors[:3]}")
        events.extend(res.events)
    events = [e for e in events if window_start <= e.timestamp <= anchor]
    for event in events:
        event.ingested_at = anchor
    unique = {e.id: e for e in events}
    return sorted(unique.values(), key=lambda e: (e.timestamp, e.id))
