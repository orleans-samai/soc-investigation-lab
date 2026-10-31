"""Detections that rely on process lineage and process access (Sysmon and 4688)."""

from __future__ import annotations

from datetime import timedelta

from app.detection.base import AlertDraft, Rule, cluster_by_time, group_by, mitre
from app.models.common import Severity


def _base(path: str | None) -> str:
    return (path or "").replace("/", "\\").rsplit("\\", 1)[-1].lower()


# Access masks that allow reading LSASS memory (PROCESS_VM_READ combinations used by dumpers / mimikatz).
LSASS_DUMP_ACCESS = {"0x1010", "0x1410", "0x1438", "0x143a", "0x1f0fff", "0x1f1fff", "0x1f3fff", "0x1fffff", "0x40"}
LSASS_ALLOWED_SOURCES = {"msmpeng.exe", "csrss.exe", "wininit.exe", "services.exe", "lsm.exe", "svchost.exe", "wmiprvse.exe", "mrt.exe"}


class LsassMemoryAccess(Rule):
    id = "LAB-015"
    name = "LSASS Memory Access"
    description = "A non-system process opened lsass.exe with rights that allow reading its memory (credential dumping)."
    severity = Severity.critical
    rule_type = "behavioral"
    data_sources = ["windows_sysmon"]
    mitre = [mitre("T1003.001", "OS Credential Dumping: LSASS Memory", "Credential Access")]
    params = []
    logic = (
        "event_source = windows_sysmon AND event_id = 10 AND fields.target_image ends with lsass.exe\n"
        "| where fields.granted_access in (0x1010, 0x1410, 0x1438, 0x143a, 0x1fffff, ...)\n"
        "| where process_name not in (MsMpEng.exe, csrss.exe, wininit.exe, services.exe, svchost.exe, ...)"
    )
    false_positives = [
        "EDR / antivirus products and backup agents that legitimately read LSASS (allow-list them by signed path).",
        "Administrators running diagnostic tools such as Process Explorer.",
    ]
    response = [
        "Isolate the host immediately: credentials of every account logged on to it must be considered stolen.",
        "Collect the dumping binary and any dump file written to disk (Sysmon 11).",
        "Reset passwords and revoke tickets for accounts with sessions on the host; hunt for their reuse elsewhere.",
    ]

    def evaluate(self, events, ctx, params):
        relevant = [
            e
            for e in events
            if e.event_action == "process_access"
            and _base(e.fields.get("target_image")) == "lsass.exe"
            and str(e.fields.get("granted_access", "")).lower() in LSASS_DUMP_ACCESS
            and _base(e.process_name) not in LSASS_ALLOWED_SOURCES
        ]
        drafts = []
        for (host, process), group in group_by(relevant, lambda e: (e.hostname, _base(e.process_name))).items():
            for cluster in cluster_by_time(group, timedelta(minutes=10)):
                first = cluster[0]
                drafts.append(
                    AlertDraft(
                        rule=self,
                        group_key=f"{host}|{process}",
                        events=cluster,
                        trigger=first,
                        reason=f"{first.process_name} opened lsass.exe on {host} with access {first.fields.get('granted_access')}.",
                        evidence=[
                            ("Source process", first.process_name or "?"),
                            ("Granted access", str(first.fields.get("granted_access"))),
                            ("Account", first.username or "?"),
                            ("Call trace", str(first.fields.get("call_trace") or "n/a")[:200]),
                        ],
                        hostname=host,
                        username=first.username,
                    )
                )
        return drafts


OFFICE_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "mspub.exe", "onenote.exe"}
SCRIPT_CHILDREN = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
}  # fmt: skip


class OfficeSpawnsShell(Rule):
    id = "LAB-017"
    name = "Office Application Spawned a Shell"
    description = "An Office application started a command interpreter or LOLBin, typical of malicious macros."
    severity = Severity.high
    rule_type = "single_event"
    data_sources = ["windows_security", "windows_sysmon"]
    mitre = [mitre("T1204.002", "User Execution: Malicious File", "Execution")]
    params = []
    logic = (
        "event_action = process_created (4688 / Sysmon 1)\n"
        "| where parent_process in (WINWORD, EXCEL, POWERPNT, OUTLOOK, ...)\n"
        "|   AND process_name in (powershell, cmd, wscript, cscript, mshta, rundll32, regsvr32, certutil, bitsadmin)"
    )
    false_positives = ["Legacy business macros or add-ins that call scripts (they should be signed and documented)."]
    response = [
        "Identify the document that was opened and where it came from (mail, download, share).",
        "Review the child process command line and everything it spawned or downloaded.",
        "Quarantine the document organisation-wide and block macros in files from the internet (Mark of the Web).",
    ]

    def evaluate(self, events, ctx, params):
        drafts = []
        for e in events:
            if (
                e.event_action != "process_created"
                or _base(e.parent_process) not in OFFICE_PARENTS
                or _base(e.process_name) not in SCRIPT_CHILDREN
            ):
                continue
            drafts.append(
                AlertDraft(
                    rule=self,
                    group_key=f"{e.hostname}|{_base(e.parent_process)}|{_base(e.process_name)}",
                    events=[e],
                    trigger=e,
                    reason=f"{_base(e.parent_process)} started {_base(e.process_name)} on {e.hostname} as {e.username}.",
                    evidence=[
                        ("Parent", e.parent_process or "?"),
                        ("Child", e.process_name or "?"),
                        ("Command line", (e.command_line or "")[:500]),
                    ],
                    hostname=e.hostname,
                    username=e.username,
                )
            )
        return drafts
