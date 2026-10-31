"""Endpoint detections: execution, persistence and defense evasion on Windows hosts."""

from __future__ import annotations

import base64
import binascii
import re
from datetime import timedelta

from app.detection.base import AlertDraft, ParamSpec, Rule, cluster_by_time, group_by, mitre
from app.models.common import Severity
from app.models.events import NormalizedEvent

# Each indicator is a category: matching several categories is what makes a command suspicious.
POWERSHELL_INDICATORS: dict[str, re.Pattern[str]] = {
    "encoded command": re.compile(r"\s-(?:e|ec|en|enc|enco|encodedcommand)\s+[A-Za-z0-9+/=]{16,}", re.IGNORECASE),
    "download cradle": re.compile(
        r"downloadstring|downloadfile|downloaddata|invoke-webrequest|\biwr\b|net\.webclient|start-bitstransfer|invoke-restmethod",
        re.IGNORECASE,
    ),
    "in-memory execution": re.compile(r"\biex\b|invoke-expression|\[scriptblock\]::create", re.IGNORECASE),
    "hidden window": re.compile(r"-w(?:indowstyle)?\s+h(?:idden)?\b", re.IGNORECASE),
    "policy bypass": re.compile(r"-ex(?:ecutionpolicy)?\s+bypass|-nop\b|-noprofile", re.IGNORECASE),
    "base64 decoding": re.compile(r"frombase64string", re.IGNORECASE),
    "AMSI tampering": re.compile(r"amsiutils|amsiinitfailed|amsi\.dll", re.IGNORECASE),
    "credential tooling": re.compile(r"mimikatz|sekurlsa|invoke-mimikatz|lsass", re.IGNORECASE),
}
_ENCODED_ARG = re.compile(r"\s-(?:e|ec|en|enc|enco|encodedcommand)\s+([A-Za-z0-9+/=]{16,})", re.IGNORECASE)

SUSPICIOUS_PATHS = re.compile(
    r"\\(?:temp|tmp|appdata|users\\public|programdata|perflogs)\\|%temp%|cmd(?:\.exe)?\s+/c|powershell|pwsh|rundll32|regsvr32|mshta",
    re.IGNORECASE,
)


def decode_powershell(command: str | None) -> str | None:
    """Decode a -EncodedCommand argument (UTF-16LE base64) for the analyst. The text is never executed."""
    match = _ENCODED_ARG.search(command or "")
    if not match:
        return None
    try:
        return base64.b64decode(match.group(1), validate=True).decode("utf-16-le", errors="replace")[:2000]
    except (binascii.Error, ValueError):
        return None


def powershell_indicators(text: str) -> list[str]:
    return [name for name, pattern in POWERSHELL_INDICATORS.items() if pattern.search(text)]


def _is_powershell(e: NormalizedEvent) -> bool:
    if e.event_action == "powershell_script_block":
        return True
    name = (e.process_name or "").lower()
    return e.event_action == "process_created" and name.endswith(("powershell.exe", "pwsh.exe"))


class SuspiciousPowerShell(Rule):
    id = "LAB-009"
    name = "Suspicious PowerShell Execution"
    description = "PowerShell launched with obfuscation, download or in-memory execution techniques."
    severity = Severity.high
    rule_type = "behavioral"
    data_sources = ["windows_security", "windows_powershell"]
    mitre = [mitre("T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution")]
    params = [ParamSpec("min_indicators", "Minimum indicator categories", 2, 1, 6)]
    logic = (
        "(event_id = 4688 AND process_name ends with powershell.exe) OR event_id = 4104\n"
        "| score = count of indicator categories matched in command_line\n"
        "|   (encoded command, download cradle, IEX, hidden window, bypass, AMSI, credential tooling)\n"
        "| alert when score >= {min_indicators}"
    )
    false_positives = [
        "Software deployment / RMM tools that wrap scripts in -EncodedCommand.",
        "Administrators bootstrapping package managers (e.g. iwr ... | iex).",
    ]
    response = [
        "Decode and review the full command / script block.",
        "Check for network connections and files written by the process.",
        "Isolate the host if a payload was downloaded or executed in memory.",
    ]

    def evaluate(self, events, ctx, params):
        candidates: list[tuple[NormalizedEvent, list[str], str | None]] = []
        for event in events:
            if not _is_powershell(event) or not event.command_line:
                continue
            decoded = decode_powershell(event.command_line)
            indicators = powershell_indicators(event.command_line + "\n" + (decoded or ""))
            if len(indicators) >= params["min_indicators"]:
                candidates.append((event, indicators, decoded))

        drafts = []
        by_entity = group_by(candidates, lambda c: (c[0].hostname, c[0].username))  # type: ignore[arg-type,return-value]
        for (host, user), group in by_entity.items():
            events_only = [c[0] for c in group]
            for cluster in cluster_by_time(events_only, timedelta(minutes=10)):
                details = [c for c in group if c[0] in cluster]
                indicators = sorted({i for c in details for i in c[1]})
                decoded = next((c[2] for c in details if c[2]), None)
                extra = []
                if "encoded command" in indicators or "base64 decoding" in indicators:
                    extra.append(mitre("T1027", "Obfuscated Files or Information", "Defense Evasion"))
                if "download cradle" in indicators:
                    extra.append(mitre("T1105", "Ingress Tool Transfer", "Command and Control"))
                if "credential tooling" in indicators:
                    extra.append(mitre("T1003.001", "OS Credential Dumping: LSASS Memory", "Credential Access"))
                evidence = [
                    ("Indicators", ", ".join(indicators)),
                    ("Command line", (cluster[0].command_line or "")[:500]),
                    ("Parent process", cluster[0].parent_process or "n/a"),
                ]
                if decoded:
                    evidence.append(("Decoded -EncodedCommand", decoded))
                drafts.append(
                    AlertDraft(
                        rule=self,
                        group_key=f"{host}|{user}",
                        events=cluster,
                        trigger=cluster[0],
                        severity=Severity.critical if len(indicators) >= 4 else None,
                        reason=f"PowerShell on {host} by {user} matched {len(indicators)} suspicious indicator categories: {', '.join(indicators)}.",
                        evidence=evidence,
                        extra_mitre=extra,
                        hostname=host,
                        username=user,
                    )
                )
        return drafts


class AuditLogCleared(Rule):
    id = "LAB-010"
    name = "Security Audit Log Cleared"
    description = "The Windows Security event log was cleared (event 1102)."
    severity = Severity.critical
    rule_type = "single_event"
    data_sources = ["windows_security"]
    mitre = [mitre("T1070.001", "Indicator Removal: Clear Windows Event Logs", "Defense Evasion")]
    params = []
    logic = "event_id = 1102"
    false_positives = ["Rare: decommissioning or re-imaging a host. Should always be backed by a change ticket."]
    response = [
        "Treat as anti-forensics until proven otherwise.",
        "Recover logs from the SIEM/forwarder for the period before the clear.",
        "Investigate every session of the account that cleared the log.",
    ]

    def evaluate(self, events, ctx, params):
        drafts = []
        for event in (e for e in events if e.event_action == "audit_log_cleared"):
            drafts.append(
                AlertDraft(
                    rule=self,
                    group_key=event.hostname or "?",
                    events=[event],
                    trigger=event,
                    reason=f"Security log on {event.hostname} cleared by {event.username or 'unknown'}.",
                    evidence=[("Host", event.hostname or "?"), ("Cleared by", event.username or "?")],
                    hostname=event.hostname,
                    username=event.username,
                )
            )
        return drafts


class _PersistenceRule(Rule):
    action: str

    def _describe(self, event: NormalizedEvent) -> tuple[str, list[tuple[str, str]]]:
        raise NotImplementedError

    def evaluate(self, events, ctx, params):
        drafts = []
        for event in (e for e in events if e.event_action == self.action):
            command = event.command_line or ""
            suspicious = bool(SUSPICIOUS_PATHS.search(command))
            reason, evidence = self._describe(event)
            evidence.append(("Suspicious location / interpreter", "yes" if suspicious else "no"))
            hints = []
            change = ctx.inventory.maintenance_window(event.username, event.hostname, event.timestamp)
            if change:
                hints.append(f"Inside approved change {change.id}.")
            if not suspicious:
                hints.append("Binary path looks like a standard install location.")
            drafts.append(
                AlertDraft(
                    rule=self,
                    group_key=f"{event.hostname}|{event.fields.get('task_name') or event.fields.get('service_name')}",
                    events=[event],
                    trigger=event,
                    severity=Severity.high if suspicious else None,
                    reason=reason,
                    evidence=evidence,
                    fp_hints=hints,
                    hostname=event.hostname,
                    username=event.username,
                )
            )
        return drafts


class ScheduledTaskCreated(_PersistenceRule):
    id = "LAB-011"
    name = "Scheduled Task Created"
    description = "A scheduled task was registered; severity rises when it runs an interpreter or a binary from a user-writable path."
    severity = Severity.medium
    rule_type = "single_event"
    data_sources = ["windows_security"]
    mitre = [mitre("T1053.005", "Scheduled Task/Job: Scheduled Task", "Persistence")]
    params = []
    action = "scheduled_task_created"
    logic = "event_id = 4698\n| severity = high if task command matches temp/appdata/public paths or cmd/powershell/rundll32/mshta"
    false_positives = ["Software installers and updaters that register maintenance tasks."]
    response = [
        "Review the task action, trigger and author.",
        "Collect the referenced binary/script and check its hash reputation.",
        "Delete the task and the payload if malicious; hunt for the same task name on other hosts.",
    ]

    def _describe(self, event):
        task = event.fields.get("task_name", "?")
        return (
            f"Scheduled task {task} created on {event.hostname} by {event.username or 'unknown'}.",
            [("Task", str(task)), ("Action", event.command_line or "n/a"), ("Author", event.username or "?")],
        )


class ServiceInstalled(_PersistenceRule):
    id = "LAB-012"
    name = "New Service Installed"
    description = "A new Windows service was installed (7045/4697); common for persistence and remote execution tools."
    severity = Severity.medium
    rule_type = "single_event"
    data_sources = ["windows_system", "windows_security"]
    mitre = [mitre("T1543.003", "Create or Modify System Process: Windows Service", "Persistence")]
    params = []
    action = "service_installed"
    logic = "event_id in (7045, 4697)\n| severity = high if image path is user-writable or launches an interpreter"
    false_positives = ["Legitimate software installation or agent upgrades."]
    response = [
        "Verify the service binary signature and hash.",
        "Correlate with remote logons to the host just before the install (PsExec-like behaviour).",
        "Stop and remove the service if unauthorized.",
    ]

    def _describe(self, event):
        service = event.fields.get("service_name", "?")
        return (
            f"Service {service} installed on {event.hostname}.",
            [
                ("Service", str(service)),
                ("Image path", event.command_line or "n/a"),
                ("Runs as", str(event.fields.get("service_account") or "n/a")),
            ],
        )
