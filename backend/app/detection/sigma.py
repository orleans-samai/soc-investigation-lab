"""Export the lab's detection rules as Sigma (https://sigmahq.io) YAML.

Single-event logic becomes a regular Sigma rule; thresholds become Sigma v2 *correlation* rules
(event_count / value_count / temporal_ordered) that reference the base rule by name. The exported
values reflect the rule's current (possibly tuned) parameters. A few behaviours have no Sigma
equivalent (time-of-day, inventory lookups); those are stated in the rule's ``falsepositives``/notes.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any

import yaml

from app.detection.base import Rule
from app.detection.threat_intel import ThreatIntelFeed

NAMESPACE = uuid.UUID("6b1f4e8e-8a1d-4c49-9d6e-50c1ab0a5e11")
AUTHOR = "SOC Investigation Lab"
DATE = "2026-10-31"

WIN_SECURITY = {"product": "windows", "service": "security"}
WIN_SYSTEM = {"product": "windows", "service": "system"}
PROCESS_CREATION = {"product": "windows", "category": "process_creation"}
PROCESS_ACCESS = {"product": "windows", "category": "process_access"}
LINUX_SSHD = {"product": "linux", "service": "sshd"}
LINUX_AUTH = {"product": "linux", "service": "auth"}

PRIVILEGED_GROUPS = ["Administrators", "Domain Admins", "Enterprise Admins", "Schema Admins", "Backup Operators"]


def _uuid(name: str) -> str:
    return str(uuid.uuid5(NAMESPACE, name))


def _tags(rule: Rule) -> list[str]:
    tags = {f"attack.{m.tactic.lower().replace(' ', '-')}" for m in rule.mitre}
    return sorted(tags) + [f"attack.{m.technique_id.lower()}" for m in rule.mitre]


def _level(rule: Rule) -> str:
    return rule.severity.value


def _name(rule: Rule, name: str) -> str:
    # Sigma names must be unique across a rule set; correlations reference them.
    return f"{rule.id.lower().replace('-', '')}_{name.removeprefix('soclab_')}"


def _base(
    rule: Rule, name: str, title: str, logsource: dict, detection: dict, fields: list[str] | None = None, extra: dict | None = None
) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "title": title,
        "id": _uuid(f"{rule.id}:{name}"),
        "name": _name(rule, name),
        "status": "experimental",
        "description": f"{rule.description} (SOC Investigation Lab {rule.id})",
        "author": AUTHOR,
        "date": DATE,
        "tags": _tags(rule),
        "logsource": logsource,
        "detection": detection,
        "falsepositives": rule.false_positives,
        "level": _level(rule),
    }
    if fields:
        doc["fields"] = fields
    if extra:
        doc.update(extra)
    return doc


def _correlation(
    rule: Rule, name: str, kind: str, rules: list[str], group_by: list[str], timespan_min: int, condition: dict, title: str
) -> dict[str, Any]:
    return {
        "title": title,
        "id": _uuid(f"{rule.id}:{name}"),
        "name": _name(rule, name),
        "status": "experimental",
        "author": AUTHOR,
        "date": DATE,
        "correlation": {
            "type": kind,
            "rules": rules,
            "group-by": group_by,
            "timespan": f"{timespan_min}m",
            **({"condition": condition} if condition else {}),
        },
        "tags": _tags(rule),
        "level": _level(rule),
    }


Builder = Callable[[Rule, dict[str, int], ThreatIntelFeed | None], list[dict[str, Any]]]


def _ssh_brute(rule, p, _):
    base = _base(
        rule,
        "soclab_ssh_failed_password",
        "SSH Failed Password",
        LINUX_SSHD,
        {"keywords": ["Failed password for"], "condition": "keywords"},
    )
    return [
        base,
        _correlation(
            rule,
            "soclab_ssh_brute_force",
            "event_count",
            [base["name"]],
            ["src_ip", "host"],
            p["window_minutes"],
            {"gte": p["threshold"]},
            rule.name,
        ),  # fmt: skip
    ]


def _win_failed_logon(rule):
    return _base(
        rule,
        "soclab_windows_failed_logon",
        "Windows Failed Logon",
        WIN_SECURITY,
        {
            "selection": {"EventID": 4625},
            "filter_machine": {"TargetUserName|endswith": "$"},
            "condition": "selection and not filter_machine",
        },
        ["TargetUserName", "IpAddress", "SubStatus", "WorkstationName"],
    )


def _win_brute(rule, p, _):
    base = _win_failed_logon(rule)
    return [
        base,
        _correlation(
            rule,
            "soclab_windows_brute_force",
            "event_count",
            [base["name"]],
            ["TargetUserName"],
            p["window_minutes"],
            {"gte": p["threshold"]},
            rule.name,
        ),
    ]


def _spray(rule, p, _):
    base = _win_failed_logon(rule)
    return [
        base,
        _correlation(
            rule,
            "soclab_password_spraying",
            "value_count",
            [base["name"]],
            ["IpAddress"],
            p["window_minutes"],
            {"field": "TargetUserName", "gte": p["distinct_users"]},
            rule.name,
        ),  # fmt: skip
    ]


def _success_after_failures(rule, p, _):
    failed = _win_failed_logon(rule)
    success = _base(rule, "soclab_windows_successful_logon", "Windows Successful Network Logon", WIN_SECURITY,
                    {"selection": {"EventID": 4624, "LogonType": [3, 10]}, "condition": "selection"}, ["TargetUserName", "IpAddress"])  # fmt: skip
    many = _correlation(rule, "soclab_many_failures_from_ip", "event_count", [failed["name"]], ["IpAddress"], p["lookback_minutes"],
                        {"gte": p["min_failures"]}, "Many Failed Logons From One Source")  # fmt: skip
    ordered = _correlation(rule, "soclab_success_after_failures", "temporal_ordered", [many["name"], success["name"]], ["IpAddress"],
                           p["lookback_minutes"], {}, rule.name)  # fmt: skip
    return [failed, success, many, ordered]


def _off_hours(rule, p, _):
    return [
        _base(
            rule,
            "soclab_privileged_interactive_logon",
            "Privileged Interactive Logon (evaluate outside business hours)",
            WIN_SECURITY,
            {"selection": {"EventID": 4624, "LogonType": [2, 10, 11], "TargetUserName|startswith": "adm."}, "condition": "selection"},
            ["TargetUserName", "IpAddress", "WorkstationName"],
            {
                "notes": [
                    f"Alert only outside {p['business_start']:02d}:00-{p['business_end']:02d}:00 local time or on weekends; "
                    "Sigma cannot express time-of-day, apply it in the SIEM query or a pipeline."
                ]
            },  # fmt: skip
        )
    ]


def _root_ssh(rule, p, _):
    return [
        _base(
            rule,
            "soclab_root_ssh_login",
            rule.name,
            LINUX_SSHD,
            {"keywords": ["Accepted password for root from", "Accepted publickey for root from"], "condition": "keywords"},
        )
    ]


def _account_created(rule, p, _):
    return [
        _base(
            rule,
            "soclab_windows_user_created",
            "Windows User Account Created",
            WIN_SECURITY,
            {"selection": {"EventID": 4720}, "condition": "selection"},
            ["SubjectUserName", "TargetUserName"],
        ),  # fmt: skip
        _base(
            rule,
            "soclab_linux_user_created",
            "Linux User Account Created",
            LINUX_AUTH,
            {"keywords": ["useradd", "new user: name="], "condition": "all of keywords"},
        ),
    ]


def _privileged_group(rule, p, _):
    return [
        _base(
            rule,
            "soclab_windows_privileged_group_add",
            "Member Added to Privileged Windows Group",
            WIN_SECURITY,
            {"selection": {"EventID": [4728, 4732, 4756], "TargetUserName": PRIVILEGED_GROUPS}, "condition": "selection"},
            ["SubjectUserName", "MemberName", "TargetUserName"],
        ),  # fmt: skip
        _base(
            rule,
            "soclab_linux_sudo_group_add",
            "User Added to sudo/wheel Group",
            LINUX_AUTH,
            {"keywords": ["to group 'sudo'", "to group 'wheel'", "to group sudo", "to group wheel"], "condition": "keywords"},
        ),  # fmt: skip
    ]


def _powershell(rule, p, _):
    return [
        _base(
            rule,
            "soclab_suspicious_powershell",
            rule.name,
            PROCESS_CREATION,
            {
                "selection_img": {"Image|endswith": ["\\powershell.exe", "\\pwsh.exe"]},
                "selection_encoded": {"CommandLine|contains": [" -enc ", " -e ", " -EncodedCommand ", "FromBase64String"]},
                "selection_download": {
                    "CommandLine|contains": ["DownloadString", "DownloadFile", "Invoke-WebRequest", "Net.WebClient", "iwr "]
                },
                "selection_exec": {
                    "CommandLine|contains": ["IEX", "Invoke-Expression", "-w hidden", "-WindowStyle Hidden", "-nop", "Bypass"]
                },
                "condition": "selection_img and (selection_encoded or (selection_download and selection_exec))",
            },
            ["CommandLine", "ParentImage", "User"],
            {
                "notes": [
                    f"The lab engine scores indicator categories and requires >= {p['min_indicators']}; this Sigma form approximates it."
                ]
            },
        )
    ]


def _log_cleared(rule, p, _):
    return [
        _base(
            rule,
            "soclab_security_log_cleared",
            rule.name,
            WIN_SECURITY,
            {"selection": {"EventID": 1102}, "condition": "selection"},
            ["SubjectUserName"],
        )
    ]


def _scheduled_task(rule, p, _):
    return [_base(rule, "soclab_scheduled_task_created", rule.name, WIN_SECURITY, {"selection": {"EventID": 4698}, "condition": "selection"},
                  ["SubjectUserName", "TaskName", "TaskContent"])]  # fmt: skip


def _service(rule, p, _):
    return [_base(rule, "soclab_service_installed", rule.name, WIN_SYSTEM,
                  {"selection": {"Provider_Name": "Service Control Manager", "EventID": 7045}, "condition": "selection"},
                  ["ServiceName", "ImagePath", "AccountName"])]  # fmt: skip


def _lateral(rule, p, _):
    base = _base(rule, "soclab_remote_logon", "Remote Logon (Network or RDP)", WIN_SECURITY,
                 {"selection": {"EventID": 4624, "LogonType": [3, 10]}, "filter_machine": {"TargetUserName|endswith": "$"},
                  "condition": "selection and not filter_machine"}, ["TargetUserName", "IpAddress", "Computer"])  # fmt: skip
    return [
        base,
        _correlation(
            rule,
            "soclab_lateral_movement",
            "value_count",
            [base["name"]],
            ["TargetUserName"],
            p["window_minutes"],
            {"field": "Computer", "gte": p["distinct_hosts"]},
            rule.name,
        ),  # fmt: skip
    ]


def _sudo(rule, p, _):
    return [_base(rule, "soclab_sudo_not_in_sudoers", rule.name, {"product": "linux", "service": "sudo"},
                  {"keywords": ["user NOT in sudoers", f"{p['max_failed_attempts']} incorrect password attempts"], "condition": "keywords"})]  # fmt: skip


def _lsass(rule, p, _):
    return [
        _base(
            rule,
            "soclab_lsass_memory_access",
            rule.name,
            PROCESS_ACCESS,
            {
                "selection": {
                    "TargetImage|endswith": "\\lsass.exe",
                    "GrantedAccess": ["0x1010", "0x1410", "0x1438", "0x143a", "0x1f0fff", "0x1f1fff", "0x1f3fff", "0x1fffff", "0x40"],
                },
                "filter_system": {
                    "SourceImage|endswith": [
                        "\\MsMpEng.exe",
                        "\\csrss.exe",
                        "\\wininit.exe",
                        "\\services.exe",
                        "\\svchost.exe",
                        "\\wmiprvse.exe",
                    ]
                },
                "condition": "selection and not filter_system",
            },
            ["SourceImage", "GrantedAccess", "SourceUser", "CallTrace"],
        )
    ]


def _intel(rule, p, feed):
    by_type: dict[str, list[str]] = {}
    for indicator in feed.indicators if feed else []:
        by_type.setdefault(indicator.type, []).append(indicator.value)
    docs = []
    if by_type.get("ip") or by_type.get("domain"):
        detection: dict[str, Any] = {}
        if by_type.get("ip"):
            detection["selection_ip"] = {"DestinationIp": by_type["ip"]}
        if by_type.get("domain"):
            detection["selection_domain"] = {"DestinationHostname|endswith": by_type["domain"]}
        detection["condition"] = "1 of selection_*"
        docs.append(
            _base(
                rule,
                "soclab_ti_network_indicator",
                "Connection to Threat Intel Indicator",
                {"product": "windows", "category": "network_connection"},
                detection,
            )
        )
    if by_type.get("domain"):
        docs.append(_base(rule, "soclab_ti_dns_indicator", "DNS Query for Threat Intel Domain", {"product": "windows", "category": "dns_query"},
                          {"selection": {"QueryName|endswith": by_type["domain"]}, "condition": "selection"}))  # fmt: skip
    if by_type.get("sha256"):
        docs.append(_base(rule, "soclab_ti_file_hash", "Process With Threat Intel Hash", PROCESS_CREATION,
                          {"selection": {"Hashes|contains": [f"SHA256={h.upper()}" for h in by_type["sha256"]]}, "condition": "selection"}))  # fmt: skip
    return docs


def _office(rule, p, _):
    return [
        _base(
            rule,
            "soclab_office_spawns_shell",
            rule.name,
            PROCESS_CREATION,
            {
                "selection_parent": {
                    "ParentImage|endswith": [
                        "\\WINWORD.EXE",
                        "\\EXCEL.EXE",
                        "\\POWERPNT.EXE",
                        "\\OUTLOOK.EXE",
                        "\\MSACCESS.EXE",
                        "\\MSPUB.EXE",
                        "\\ONENOTE.EXE",
                    ]
                },
                "selection_child": {
                    "Image|endswith": [
                        "\\powershell.exe",
                        "\\pwsh.exe",
                        "\\cmd.exe",
                        "\\wscript.exe",
                        "\\cscript.exe",
                        "\\mshta.exe",
                        "\\rundll32.exe",
                        "\\regsvr32.exe",
                        "\\certutil.exe",
                        "\\bitsadmin.exe",
                    ]  # fmt: skip
                },
                "condition": "selection_parent and selection_child",
            },
            ["ParentImage", "Image", "CommandLine", "User"],
        )
    ]


BUILDERS: dict[str, Builder] = {
    "LAB-001": _ssh_brute,
    "LAB-002": _win_brute,
    "LAB-003": _spray,
    "LAB-004": _success_after_failures,
    "LAB-005": _off_hours,
    "LAB-006": _root_ssh,
    "LAB-007": _account_created,
    "LAB-008": _privileged_group,
    "LAB-009": _powershell,
    "LAB-010": _log_cleared,
    "LAB-011": _scheduled_task,
    "LAB-012": _service,
    "LAB-013": _lateral,
    "LAB-014": _sudo,
    "LAB-015": _lsass,
    "LAB-016": _intel,
    "LAB-017": _office,
}


def rule_documents(rule: Rule, params: dict[str, int], feed: ThreatIntelFeed | None) -> list[dict[str, Any]]:
    builder = BUILDERS.get(rule.id)
    return builder(rule, params, feed) if builder else []


def to_yaml(documents: list[dict[str, Any]], header: str | None = None) -> str:
    body = yaml.safe_dump_all(documents, sort_keys=False, allow_unicode=True, width=140, default_flow_style=False)
    return (f"# {header}\n" if header else "") + body
