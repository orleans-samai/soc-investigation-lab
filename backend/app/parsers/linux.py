"""Linux auth log parser (``/var/log/auth.log`` / ``/var/log/secure``).

Supports both header styles emitted by rsyslog:

* classic BSD:      ``Oct 30 14:02:11 bastion-01 sshd[2211]: Failed password for root from 203.0.113.9 port 4123 ssh2``
* high precision:   ``2026-10-30T14:02:11.000000+00:00 bastion-01 sshd[2211]: ...``

Lines are only ever matched with regular expressions; nothing in the file is executed or evaluated.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from app.models.events import EventSource, EventType, LogLevel, NormalizedEvent, Outcome
from app.models.imports import LogFormat
from app.parsers.base import MAX_LINE_LENGTH, ParseError, ParseOptions, ParseResult, parse_timestamp, short_hostname

_RFC3339 = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+(?P<prog>[\w\-./()]+?)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$"
)
_BSD = re.compile(
    r"^(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<prog>[\w\-./()]+?)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$"
)
_MONTHS = {m: i for i, m in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}

SUPPORTED_PROGRAMS = {"sshd", "sudo", "su", "useradd", "usermod", "gpasswd", "groupadd", "cron", "systemd-logind"}


@dataclass
class Pattern:
    regex: re.Pattern[str]
    event_type: EventType
    action: str
    outcome: Outcome
    level: LogLevel
    describe: Callable[[dict[str, Any], str], str]


def P(
    regex: str, event_type: EventType, action: str, outcome: Outcome, level: LogLevel, describe: Callable[[dict[str, Any], str], str]
) -> Pattern:  # noqa: E501
    return Pattern(re.compile(regex), event_type, action, outcome, level, describe)


AUTH, SESSION, ACCOUNT, PRIV = EventType.authentication, EventType.session, EventType.account_management, EventType.privilege
OK, FAIL = Outcome.success, Outcome.failure
INFO, WARN = LogLevel.info, LogLevel.warning

PATTERNS: dict[str, list[Pattern]] = {
    "sshd": [
        P(
            r"^Failed (?P<method>password|publickey|keyboard-interactive/pam|none) for (?P<invalid>invalid user )?(?P<user>\S*) from (?P<ip>[\da-fA-F.:]+) port (?P<port>\d+)",
            AUTH,
            "logon_failed",
            FAIL,
            WARN,
            lambda g, h: f"SSH {g['method']} authentication failed for {g['user'] or '(empty)'} from {g['ip']}",
        ),
        P(
            r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[\da-fA-F.:]+) port (?P<port>\d+)",
            AUTH,
            "logon_success",
            OK,
            INFO,
            lambda g, h: f"SSH login accepted for {g['user']} from {g['ip']} ({g['method']})",
        ),
        P(
            r"^Invalid user (?P<user>\S*) from (?P<ip>[\da-fA-F.:]+)(?: port (?P<port>\d+))?",
            AUTH,
            "invalid_user",
            FAIL,
            WARN,
            lambda g, h: f"SSH connection for non-existent user {g['user'] or '(empty)'} from {g['ip']}",
        ),
        P(
            r"^error: maximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\da-fA-F.:]+) port (?P<port>\d+)",
            AUTH,
            "max_auth_exceeded",
            FAIL,
            WARN,
            lambda g, h: f"Maximum SSH authentication attempts exceeded for {g['user']} from {g['ip']}",
        ),
        P(
            r"^pam_unix\(sshd:auth\): authentication failure;.*?rhost=(?P<ip>\S*)(?:\s+user=(?P<user>\S+))?",
            AUTH,
            "pam_auth_failure",
            FAIL,
            INFO,
            lambda g, h: f"PAM authentication failure for {g.get('user') or 'unknown'} from {g['ip']}",
        ),
        P(
            r"^pam_unix\(sshd:session\): session opened for user (?P<user>[^\s(]+)",
            SESSION,
            "session_opened",
            OK,
            INFO,
            lambda g, h: f"SSH session opened for {g['user']} on {h}",
        ),
        P(
            r"^pam_unix\(sshd:session\): session closed for user (?P<user>[^\s(]+)",
            SESSION,
            "session_closed",
            OK,
            INFO,
            lambda g, h: f"SSH session closed for {g['user']} on {h}",
        ),
        P(
            r"^(?:Connection closed|Disconnected from) (?:by )?(?:authenticating user |invalid user |user )?(?P<user>[^\s\d][^\s]*)? ?(?P<ip>[\da-fA-F.:]+) port (?P<port>\d+)",
            SESSION,
            "connection_closed",
            OK,
            INFO,
            lambda g, h: f"SSH connection from {g['ip']} closed",
        ),
    ],
    "sudo": [
        P(
            r"^\s*(?P<user>\S+) : user NOT in sudoers ; TTY=(?P<tty>\S+) ; PWD=(?P<pwd>\S+) ; USER=(?P<target>\S+) ; COMMAND=(?P<cmd>.*)$",
            PRIV,
            "sudo_denied",
            FAIL,
            WARN,
            lambda g, h: f"{g['user']} is not in sudoers and tried to run '{g['cmd']}' as {g['target']}",
        ),
        P(
            r"^\s*(?P<user>\S+) : (?P<attempts>\d+) incorrect password attempts? ; TTY=(?P<tty>\S+) ; PWD=(?P<pwd>\S+) ; USER=(?P<target>\S+) ; COMMAND=(?P<cmd>.*)$",
            PRIV,
            "sudo_auth_failed",
            FAIL,
            WARN,
            lambda g, h: f"{g['user']} failed sudo authentication {g['attempts']} times",
        ),
        P(
            r"^\s*(?P<user>\S+) : TTY=(?P<tty>\S+) ; PWD=(?P<pwd>\S+) ; USER=(?P<target>\S+) ; COMMAND=(?P<cmd>.*)$",
            PRIV,
            "sudo_command",
            OK,
            INFO,
            lambda g, h: f"{g['user']} ran '{g['cmd']}' as {g['target']} via sudo",
        ),
        P(
            r"^pam_unix\(sudo:auth\): authentication failure;.*?ruser=(?P<user>\S*)",
            PRIV,
            "sudo_pam_failure",
            FAIL,
            INFO,
            lambda g, h: f"PAM sudo authentication failure for {g['user'] or 'unknown'}",
        ),
        P(
            r"^pam_unix\(sudo:session\): session (?P<state>opened|closed) for user (?P<target>[^\s(]+)",
            SESSION,
            "sudo_session",
            OK,
            INFO,
            lambda g, h: f"sudo session {g['state']} for {g['target']}",
        ),
    ],
    "su": [
        P(
            r"^FAILED SU \(to (?P<target>\S+)\) (?P<user>\S+) on",
            PRIV,
            "su_failed",
            FAIL,
            WARN,
            lambda g, h: f"{g['user']} failed to switch user to {g['target']}",
        ),
        P(
            r"^pam_unix\(su(?:-l)?:session\): session opened for user (?P<target>[^\s(]+).*? by (?P<user>[^\s(]+)",
            PRIV,
            "su_session",
            OK,
            INFO,
            lambda g, h: f"{g['user']} switched user to {g['target']}",
        ),
    ],
    "useradd": [
        P(
            r"^new user: name=(?P<target>[^,]+), UID=(?P<uid>\d+)",
            ACCOUNT,
            "user_created",
            OK,
            WARN,
            lambda g, h: f"Local user {g['target']} (UID {g['uid']}) created on {h}",
        ),
    ],
    "usermod": [
        P(
            r"^add '(?P<target>[^']+)' to group '(?P<group>[^']+)'",
            ACCOUNT,
            "group_member_added",
            OK,
            WARN,
            lambda g, h: f"{g['target']} added to group {g['group']} on {h}",
        ),
    ],
    "gpasswd": [
        P(
            r"^user (?P<target>\S+) added by (?P<user>\S+) to group (?P<group>\S+)",
            ACCOUNT,
            "group_member_added",
            OK,
            WARN,
            lambda g, h: f"{g['user']} added {g['target']} to group {g['group']} on {h}",
        ),
    ],
    "groupadd": [
        P(
            r"^group added to /etc/group: name=(?P<group>[^,]+)",
            ACCOUNT,
            "group_created",
            OK,
            INFO,
            lambda g, h: f"Group {g['group']} created on {h}",
        ),
    ],
    "cron": [
        P(
            r"^pam_unix\(cron:session\): session (?P<state>opened|closed) for user (?P<user>[^\s(]+)",
            SESSION,
            "cron_session",
            OK,
            INFO,
            lambda g, h: f"cron session {g['state']} for {g['user']}",
        ),
    ],
    "systemd-logind": [
        P(
            r"^New session (?P<session>\S+) of user (?P<user>[^\s.]+)",
            SESSION,
            "session_opened",
            OK,
            INFO,
            lambda g, h: f"New login session {g['session']} for {g['user']}",
        ),
    ],
}


class LinuxAuthParser:
    format = LogFormat.linux_ssh

    def parse(self, text: str, options: ParseOptions) -> ParseResult:
        result = ParseResult(format=self.format)
        for number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            result.total_records += 1
            if len(line) > MAX_LINE_LENGTH:
                result.add_error(number, "line exceeds maximum length", line[:120])
                continue
            try:
                event = self.parse_line(line.rstrip("\r"), options)
            except ParseError as exc:
                result.add_error(number, str(exc), line)
                continue
            if event is None:
                result.skipped += 1
            else:
                result.events.append(event)
        return result

    def parse_line(self, line: str, options: ParseOptions) -> NormalizedEvent | None:
        header = _RFC3339.match(line)
        if header:
            timestamp = parse_timestamp(header["ts"], options.timezone)
        else:
            header = _BSD.match(line)
            if not header:
                raise ParseError("line does not match a supported syslog header")
            timestamp = self._bsd_timestamp(header, options)

        program = header["prog"].lower()
        program = "cron" if program.startswith("cron") else program
        if program not in SUPPORTED_PROGRAMS:
            return None
        hostname = short_hostname(header["host"])
        message = header["msg"].strip()

        for pattern in PATTERNS.get(program, []):
            match = pattern.regex.search(message)
            if not match:
                continue
            groups = {k: v for k, v in match.groupdict().items()}
            fields: dict[str, Any] = {"program": program}
            if header["pid"]:
                fields["pid"] = int(header["pid"])
            for key in ("method", "tty", "pwd", "uid", "attempts", "session", "state"):
                if groups.get(key):
                    fields[key] = groups[key]
            if groups.get("invalid"):
                fields["invalid_user"] = True
            event = NormalizedEvent(
                timestamp=timestamp,
                event_id=f"{program}:{pattern.action}",
                event_source=EventSource.linux_auth,
                event_type=pattern.event_type,
                event_action=pattern.action,
                outcome=pattern.outcome,
                log_level=pattern.level,
                hostname=hostname,
                username=groups.get("user") or None,
                source_ip=groups.get("ip") or None,
                source_port=int(groups["port"]) if groups.get("port") else None,
                destination_port=22 if program == "sshd" and groups.get("ip") else None,
                target_username=groups.get("target"),
                group_name=groups.get("group"),
                command_line=groups.get("cmd"),
                process_name=program,
                message=pattern.describe(groups, hostname or "?"),
                raw=line,
                dataset=options.dataset,
                fields=fields,
            )
            if pattern.action == "logon_failed" and fields.get("invalid_user"):
                event.tags.append("invalid_user")
            return event
        return None

    @staticmethod
    def _bsd_timestamp(header: re.Match[str], options: ParseOptions) -> datetime:
        reference = options.reference_time or datetime.now(UTC)
        year = options.year or reference.astimezone(options.timezone).year
        hour, minute, second = (int(x) for x in header["time"].split(":"))
        try:
            local = datetime(year, _MONTHS[header["mon"]], int(header["day"]), hour, minute, second, tzinfo=options.timezone)
        except ValueError as exc:
            raise ParseError(f"invalid date: {exc}") from exc
        # Syslog has no year: a December line read in January belongs to the previous year.
        if options.year is None and local - reference > timedelta(days=2):
            local = local.replace(year=year - 1)
        return local.astimezone(UTC)
