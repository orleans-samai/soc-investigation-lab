"""Windows event parser for structured JSON exports.

Accepts the shape produced by ``Get-WinEvent ... | ConvertTo-Json`` style exports and simplified
Winlogbeat-like records::

    {"EventID": 4625, "TimeCreated": "2026-10-30T14:02:11.123Z", "Computer": "DC-01.corp.lab",
     "Channel": "Security", "EventData": {"TargetUserName": "j.silva", "IpAddress": "10.10.10.21", ...}}
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from app.models.events import EventSource, EventType, LogLevel, NormalizedEvent, Outcome
from app.models.imports import LogFormat
from app.parsers.base import ParseError, ParseOptions, ParseResult, iter_json_records, parse_timestamp, short_hostname

LOGON_TYPES = {
    2: "Interactive",
    3: "Network",
    4: "Batch",
    5: "Service",
    7: "Unlock",
    8: "NetworkCleartext",
    9: "NewCredentials",
    10: "RemoteInteractive (RDP)",
    11: "CachedInteractive",
}

FAILURE_STATUS = {
    "0xc000006a": "bad password",
    "0xc0000064": "user does not exist",
    "0xc0000234": "account locked out",
    "0xc0000072": "account disabled",
    "0xc000006f": "outside authorized hours",
    "0xc0000071": "password expired",
    "0xc0000193": "account expired",
}

_EMPTY = {"", "-", "null", "none", "n/a"}
_MEMBER_CN = re.compile(r"CN=([^,]+)", re.IGNORECASE)
_TASK_COMMAND = re.compile(r"<Command>(.*?)</Command>(?:\s*<Arguments>(.*?)</Arguments>)?", re.IGNORECASE | re.DOTALL)


def _clean(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return None if text.lower() in _EMPTY else text


def _int(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _ip(value: Any) -> str | None:
    text = _clean(value)
    if text and text.startswith("::ffff:"):
        text = text[7:]
    return text


def _split_account(value: Any) -> tuple[str | None, str | None]:
    text = _clean(value)
    if not text:
        return None, None
    if "\\" in text:
        domain, user = text.split("\\", 1)
        return user, domain
    return text, None


@dataclass
class Mapping:
    source: EventSource
    event_type: EventType
    action: str
    outcome: Outcome
    level: LogLevel
    describe: Callable[[dict[str, Any], NormalizedEvent], str]


def _logon_desc(d: dict[str, Any], e: NormalizedEvent) -> str:
    kind = LOGON_TYPES.get(e.logon_type or 0, f"type {e.logon_type}")
    origin = f" from {e.source_ip}" if e.source_ip else ""
    return f"Account {e.username} logged on to {e.hostname} ({kind}){origin}"


def _logon_failed_desc(d: dict[str, Any], e: NormalizedEvent) -> str:
    reason = FAILURE_STATUS.get(str(d.get("SubStatus", "")).lower()) or FAILURE_STATUS.get(
        str(d.get("Status", "")).lower(), "unknown reason"
    )
    origin = f" from {e.source_ip}" if e.source_ip else ""
    return f"Failed logon for {e.username} on {e.hostname}{origin}: {reason}"


MAPPINGS: dict[int, Mapping] = {
    4624: Mapping(EventSource.windows_security, EventType.authentication, "logon_success", Outcome.success, LogLevel.info, _logon_desc),
    4625: Mapping(
        EventSource.windows_security, EventType.authentication, "logon_failed", Outcome.failure, LogLevel.warning, _logon_failed_desc
    ),
    4634: Mapping(
        EventSource.windows_security,
        EventType.session,
        "logoff",
        Outcome.success,
        LogLevel.info,
        lambda d, e: f"Account {e.username} logged off from {e.hostname}",
    ),
    4672: Mapping(
        EventSource.windows_security,
        EventType.privilege,
        "special_privileges_assigned",
        Outcome.success,
        LogLevel.info,
        lambda d, e: f"Special privileges assigned to new logon of {e.username} on {e.hostname}",
    ),
    4688: Mapping(
        EventSource.windows_security,
        EventType.process,
        "process_created",
        Outcome.success,
        LogLevel.info,
        lambda d, e: f"{e.username} started {e.process_name} on {e.hostname}",
    ),
    4698: Mapping(
        EventSource.windows_security,
        EventType.persistence,
        "scheduled_task_created",
        Outcome.success,
        LogLevel.warning,
        lambda d, e: f"{e.username} created scheduled task {e.fields.get('task_name')} on {e.hostname}",
    ),
    4697: Mapping(
        EventSource.windows_security,
        EventType.persistence,
        "service_installed",
        Outcome.success,
        LogLevel.warning,
        lambda d, e: f"Service {e.fields.get('service_name')} installed on {e.hostname}",
    ),
    4720: Mapping(
        EventSource.windows_security,
        EventType.account_management,
        "user_created",
        Outcome.success,
        LogLevel.warning,
        lambda d, e: f"{e.username} created user account {e.target_username} on {e.hostname}",
    ),
    4722: Mapping(
        EventSource.windows_security,
        EventType.account_management,
        "user_enabled",
        Outcome.success,
        LogLevel.info,
        lambda d, e: f"{e.username} enabled account {e.target_username}",
    ),
    4724: Mapping(
        EventSource.windows_security,
        EventType.account_management,
        "password_reset",
        Outcome.success,
        LogLevel.info,
        lambda d, e: f"{e.username} reset the password of {e.target_username}",
    ),
    4726: Mapping(
        EventSource.windows_security,
        EventType.account_management,
        "user_deleted",
        Outcome.success,
        LogLevel.warning,
        lambda d, e: f"{e.username} deleted account {e.target_username}",
    ),
    4728: Mapping(
        EventSource.windows_security,
        EventType.account_management,
        "group_member_added",
        Outcome.success,
        LogLevel.warning,
        lambda d, e: f"{e.username} added {e.target_username} to global group {e.group_name}",
    ),
    4732: Mapping(
        EventSource.windows_security,
        EventType.account_management,
        "group_member_added",
        Outcome.success,
        LogLevel.warning,
        lambda d, e: f"{e.username} added {e.target_username} to local group {e.group_name}",
    ),
    4756: Mapping(
        EventSource.windows_security,
        EventType.account_management,
        "group_member_added",
        Outcome.success,
        LogLevel.warning,
        lambda d, e: f"{e.username} added {e.target_username} to universal group {e.group_name}",
    ),
    4740: Mapping(
        EventSource.windows_security,
        EventType.account_management,
        "account_locked",
        Outcome.failure,
        LogLevel.warning,
        lambda d, e: f"Account {e.target_username} was locked out (caller {e.fields.get('caller_computer') or 'unknown'})",
    ),
    1102: Mapping(
        EventSource.windows_security,
        EventType.audit,
        "audit_log_cleared",
        Outcome.success,
        LogLevel.critical,
        lambda d, e: f"Security audit log cleared on {e.hostname} by {e.username}",
    ),
    4104: Mapping(
        EventSource.windows_powershell,
        EventType.process,
        "powershell_script_block",
        Outcome.success,
        LogLevel.info,
        lambda d, e: f"PowerShell script block executed on {e.hostname}",
    ),
    7045: Mapping(
        EventSource.windows_system,
        EventType.persistence,
        "service_installed",
        Outcome.success,
        LogLevel.warning,
        lambda d, e: f"Service {e.fields.get('service_name')} installed on {e.hostname}",
    ),
}


def _basename(path: str | None) -> str:
    return (path or "?").replace("/", "\\").rsplit("\\", 1)[-1]


# Sysmon (Microsoft-Windows-Sysmon/Operational) reuses small event ids, so it is selected by channel/provider.
SYSMON_MAPPINGS: dict[int, Mapping] = {
    1: Mapping(
        EventSource.windows_sysmon,
        EventType.process,
        "process_created",
        Outcome.success,
        LogLevel.info,
        lambda d, e: f"{e.username} started {_basename(e.process_name)} on {e.hostname} (parent {_basename(e.parent_process)})",
    ),
    3: Mapping(
        EventSource.windows_sysmon,
        EventType.network,
        "network_connection",
        Outcome.success,
        LogLevel.info,
        lambda d, e: (
            f"{_basename(e.process_name)} on {e.hostname} connected to {e.fields.get('destination_hostname') or e.destination_ip}:{e.destination_port}"
        ),
    ),
    10: Mapping(
        EventSource.windows_sysmon,
        EventType.process,
        "process_access",
        Outcome.success,
        LogLevel.warning,
        lambda d, e: (
            f"{_basename(e.process_name)} opened {_basename(e.fields.get('target_image'))} on {e.hostname} (access {e.fields.get('granted_access')})"
        ),
    ),
    11: Mapping(
        EventSource.windows_sysmon,
        EventType.file,
        "file_created",
        Outcome.success,
        LogLevel.info,
        lambda d, e: f"{_basename(e.process_name)} created {e.fields.get('target_filename')} on {e.hostname}",
    ),
    22: Mapping(
        EventSource.windows_sysmon,
        EventType.network,
        "dns_query",
        Outcome.success,
        LogLevel.info,
        lambda d, e: f"{_basename(e.process_name)} on {e.hostname} resolved {e.fields.get('query_name')}",
    ),
}
_HASH = re.compile(r"(MD5|SHA1|SHA256|IMPHASH)=([0-9A-Fa-f]+)")


def _first(record: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in record and record[key] not in (None, ""):
            return record[key]
    return None


class WindowsJsonParser:
    format = LogFormat.windows_json

    def parse(self, text: str, options: ParseOptions) -> ParseResult:
        result = ParseResult(format=self.format)
        records, issues = iter_json_records(text)
        for issue in issues:
            result.add_error(issue.line, issue.message, issue.excerpt)
        result.total_records = len(records) + len(issues)

        for position, record in records:
            try:
                event = self.parse_record(record, options)
            except ParseError as exc:
                result.add_error(position, str(exc), json.dumps(record, default=str)[:240])
                continue
            if event is None:
                result.skipped += 1
                continue
            result.events.append(event)
        return result

    def parse_record(self, record: Any, options: ParseOptions) -> NormalizedEvent | None:
        if not isinstance(record, dict):
            raise ParseError("record is not a JSON object")
        event_id = _int(_first(record, "EventID", "EventId", "Id", "event_id"))
        if event_id is None:
            raise ParseError("missing EventID")
        origin = f"{record.get('Channel') or ''} {record.get('Provider') or ''}".lower()
        sysmon = "sysmon" in origin
        mapping = SYSMON_MAPPINGS.get(event_id) if sysmon else MAPPINGS.get(event_id)
        if mapping is None:
            return None  # Valid Windows record, but not an event the lab models: counted as skipped.

        timestamp = parse_timestamp(_first(record, "TimeCreated", "@timestamp", "TimeGenerated", "timestamp"), options.timezone)
        hostname = short_hostname(_first(record, "Computer", "MachineName", "hostname", "host"))
        if not hostname:
            raise ParseError("missing Computer/hostname")

        data = record.get("EventData") or record.get("event_data") or {}
        if not isinstance(data, dict):
            raise ParseError("EventData must be an object")

        fields: dict[str, Any] = {"channel": _clean(record.get("Channel")), "provider": _clean(record.get("Provider"))}
        username = domain = target = group = None
        source_ip = _ip(data.get("IpAddress"))
        source_port = _int(data.get("IpPort"))
        logon_type = _int(data.get("LogonType"))
        process = command = parent = None
        destination_ip = destination_port = None

        if sysmon:
            username, domain = _split_account(data.get("User") or data.get("SourceUser") or _first(record, "UserId", "User"))
            process = _clean(data.get("Image") or data.get("SourceImage"))
            for algo, digest in _HASH.findall(str(data.get("Hashes") or "")):
                fields[algo.lower()] = digest.lower()
            if event_id == 1:
                command = _clean(data.get("CommandLine"))
                parent = _clean(data.get("ParentImage"))
            elif event_id == 3:
                source_ip, source_port = _ip(data.get("SourceIp")), _int(data.get("SourcePort"))
                destination_ip, destination_port = _ip(data.get("DestinationIp")), _int(data.get("DestinationPort"))
                fields["destination_hostname"] = _clean(data.get("DestinationHostname"))
                fields["protocol"] = _clean(data.get("Protocol"))
            elif event_id == 10:
                fields["target_image"] = _clean(data.get("TargetImage"))
                fields["granted_access"] = _clean(data.get("GrantedAccess"))
                fields["call_trace"] = _clean(data.get("CallTrace"))
            elif event_id == 11:
                fields["target_filename"] = _clean(data.get("TargetFilename"))
            elif event_id == 22:
                fields["query_name"] = _clean(data.get("QueryName"))
                fields["query_results"] = _clean(data.get("QueryResults"))
        elif event_id in (4624, 4625, 4634, 4672):
            username, domain = _clean(data.get("TargetUserName")), _clean(data.get("TargetDomainName"))
            if event_id == 4672:
                username, domain = _clean(data.get("SubjectUserName")), _clean(data.get("SubjectDomainName"))
            fields["workstation"] = _clean(data.get("WorkstationName"))
            if event_id == 4625:
                fields["status"] = _clean(data.get("Status"))
                fields["sub_status"] = _clean(data.get("SubStatus"))
                fields["failure_reason"] = FAILURE_STATUS.get(str(data.get("SubStatus", "")).lower())
            if logon_type is not None:
                fields["logon_type_name"] = LOGON_TYPES.get(logon_type)
        elif event_id == 4688:
            username, domain = _clean(data.get("SubjectUserName")), _clean(data.get("SubjectDomainName"))
            process = _clean(data.get("NewProcessName"))
            command = _clean(data.get("CommandLine"))
            parent = _clean(data.get("ParentProcessName"))
        elif event_id == 4104:
            username, domain = _split_account(_first(record, "UserId", "User") or data.get("UserName"))
            command = _clean(data.get("ScriptBlockText"))
            process = "powershell.exe"
            fields["script_block_id"] = _clean(data.get("ScriptBlockId"))
        elif event_id in (4720, 4722, 4724, 4726, 4740):
            username, domain = _clean(data.get("SubjectUserName")), _clean(data.get("SubjectDomainName"))
            target = _clean(data.get("TargetUserName"))
            if event_id == 4740:
                fields["caller_computer"] = _clean(data.get("TargetDomainName"))
        elif event_id in (4728, 4732, 4756):
            username, domain = _clean(data.get("SubjectUserName")), _clean(data.get("SubjectDomainName"))
            group = _clean(data.get("TargetUserName"))
            member = _clean(data.get("MemberName"))
            match = _MEMBER_CN.search(member or "")
            target = match.group(1) if match else member or _clean(data.get("MemberSid"))
        elif event_id == 4698:
            username, domain = _clean(data.get("SubjectUserName")), _clean(data.get("SubjectDomainName"))
            fields["task_name"] = _clean(data.get("TaskName"))
            match = _TASK_COMMAND.search(str(data.get("TaskContent") or ""))
            if match:
                command = " ".join(part.strip() for part in match.groups() if part)
                process = match.group(1).strip()
        elif event_id in (7045, 4697):
            username, domain = _split_account(_first(record, "UserId", "User") or data.get("SubjectUserName"))
            fields["service_name"] = _clean(data.get("ServiceName"))
            fields["service_account"] = _clean(data.get("AccountName") or data.get("ServiceAccount"))
            command = _clean(data.get("ImagePath") or data.get("ServiceFileName"))
            process = command
        elif event_id == 1102:
            username, domain = _clean(data.get("SubjectUserName")), _clean(data.get("SubjectDomainName"))

        event = NormalizedEvent(
            timestamp=timestamp,
            event_id=str(event_id),
            event_source=mapping.source,
            event_type=mapping.event_type,
            event_action=mapping.action,
            outcome=mapping.outcome,
            log_level=mapping.level,
            hostname=hostname,
            username=username,
            domain=domain.lower() if domain else None,
            source_ip=source_ip,
            source_port=source_port,
            destination_ip=destination_ip,
            destination_port=destination_port,
            logon_type=logon_type,
            process_name=process,
            command_line=command,
            parent_process=parent,
            target_username=target,
            group_name=group,
            raw=json.dumps(record, sort_keys=True, ensure_ascii=False, default=str),
            dataset=options.dataset,
            fields={k: v for k, v in fields.items() if v is not None},
        )
        event.message = mapping.describe(data, event)
        return event
