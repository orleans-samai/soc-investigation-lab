"""Authentication-centric detections: brute force, spraying, suspicious logons, lateral movement."""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from app.detection.base import (
    AlertDraft,
    DetectionContext,
    ParamSpec,
    Rule,
    cluster_by_time,
    fmt_duration,
    group_by,
    is_human_account,
    mitre,
    threshold_bursts,
    top,
)
from app.models.common import Severity
from app.models.events import EventSource, NormalizedEvent

INTERACTIVE_LOGON_TYPES = {2, 10, 11}
REMOTE_LOGON_TYPES = {3, 10}
# Built-in (root/Administrator) and service accounts are covered by dedicated rules.
PERSONAL_ACCOUNT_TYPES = {"human", "admin"}


def _failed(e: NormalizedEvent) -> bool:
    return e.event_action == "logon_failed"


def _external_hint(ctx: DetectionContext, ip: str | None) -> list[str]:
    if ctx.inventory.is_internal(ip):
        asset = ctx.inventory.asset_by_ip(ip)
        where = f" ({asset.hostname}, {asset.role})" if asset else ""
        return [f"Source {ip} is on the internal network{where}: check for a misconfigured script, saved credential or scanner."]
    return []


class SshBruteForce(Rule):
    id = "LAB-001"
    name = "SSH Brute Force"
    description = "High volume of failed SSH authentications from a single source against one host."
    severity = Severity.high
    rule_type = "threshold"
    data_sources = ["linux_auth"]
    mitre = [mitre("T1110.001", "Brute Force: Password Guessing", "Credential Access")]
    params = [
        ParamSpec("threshold", "Failed attempts", 8, 3, 100),
        ParamSpec("window_minutes", "Time window", 5, 1, 60, "min"),
    ]
    logic = (
        "event_source = linux_auth AND event_action = logon_failed\n"
        "| group by source_ip, hostname\n"
        "| alert when count >= {threshold} within {window_minutes} min"
    )
    false_positives = [
        "Automation or monitoring with an expired key/password retrying in a loop.",
        "Internal vulnerability scanners performing authenticated checks.",
    ]
    response = [
        "Check whether any login from the same source succeeded (see LAB-004).",
        "Block the source IP at the perimeter firewall / fail2ban.",
        "Disable password authentication on internet-facing SSH; require keys + MFA.",
        "Review targeted accounts for weak or default passwords.",
    ]

    def evaluate(self, events, ctx, params):
        window = timedelta(minutes=params["window_minutes"])
        relevant = (e for e in events if e.event_source == EventSource.linux_auth and _failed(e) and e.source_ip)
        drafts = []
        for (ip, host), group in group_by(relevant, lambda e: (e.source_ip, e.hostname)).items():
            for burst in threshold_bursts(group, window, params["threshold"]):
                users = top((e.username for e in burst.events), 6)
                geo = ctx.inventory.geo_for(ip)
                evidence = [
                    ("Failed attempts", str(len(burst.events))),
                    ("Peak within window", f"{burst.peak} in {params['window_minutes']} min"),
                    ("Duration", fmt_duration(burst.events[-1].timestamp - burst.events[0].timestamp)),
                    ("Targeted accounts", ", ".join(f"{u} ({c})" for u, c in users)),
                    ("Invalid usernames", str(sum(1 for e in burst.events if "invalid_user" in e.tags))),
                ]
                if geo:
                    evidence.append(("Source reputation", f"{geo.reputation} - {geo.organization} ({geo.country})"))
                drafts.append(
                    AlertDraft(
                        rule=self,
                        group_key=f"{ip}|{host}",
                        events=burst.events,
                        trigger=burst.trigger,
                        reason=(
                            f"{len(burst.events)} failed SSH logins from {ip} against {host}; "
                            f"threshold of {params['threshold']} in {params['window_minutes']} min crossed at "
                            f"{burst.trigger.timestamp:%H:%M:%S} UTC."
                        ),
                        evidence=evidence,
                        fp_hints=_external_hint(ctx, ip),
                        hostname=host,
                        username=users[0][0] if users else None,
                        source_ip=ip,
                    )
                )
        return drafts


class WindowsBruteForce(Rule):
    id = "LAB-002"
    name = "Windows Account Brute Force"
    description = "Repeated failed Windows logons (4625) for the same account in a short period."
    severity = Severity.medium
    rule_type = "threshold"
    data_sources = ["windows_security"]
    mitre = [mitre("T1110.001", "Brute Force: Password Guessing", "Credential Access")]
    params = [
        ParamSpec("threshold", "Failed attempts", 6, 3, 100),
        ParamSpec("window_minutes", "Time window", 5, 1, 60, "min"),
    ]
    logic = (
        "event_id = 4625\n"
        "| group by username\n"
        "| alert when count >= {threshold} within {window_minutes} min\n"
        "| severity = high if account is privileged"
    )
    false_positives = [
        "User with a stale password cached on a phone or mapped drive after a password change.",
        "Service configured with an old password after rotation.",
    ]
    response = [
        "Contact the account owner to confirm whether they were typing the password.",
        "Check for account lockout (4740) and the calling workstation.",
        "If unexpected, reset the password and review sign-ins after the burst.",
    ]

    def evaluate(self, events, ctx, params):
        window = timedelta(minutes=params["window_minutes"])
        relevant = (e for e in events if e.event_source == EventSource.windows_security and _failed(e) and is_human_account(e.username))
        lockouts = [e for e in events if e.event_action == "account_locked"]
        drafts = []
        for user, group in group_by(relevant, lambda e: e.username).items():
            for burst in threshold_bursts(group, window, params["threshold"]):
                privileged = ctx.inventory.is_privileged(user)
                sources = top((e.source_ip for e in burst.events), 3)
                start, end = burst.events[0].timestamp, burst.events[-1].timestamp + window
                locked = [e for e in lockouts if e.target_username == user and start <= e.timestamp <= end]
                evidence = [
                    ("Failed attempts", str(len(burst.events))),
                    ("Hosts", ", ".join(sorted({e.hostname or "?" for e in burst.events}))),
                    ("Sources", ", ".join(f"{ip} ({c})" for ip, c in sources) or "n/a"),
                    ("Failure reasons", ", ".join(sorted({e.fields.get("failure_reason") or "unknown" for e in burst.events}))),
                    ("Account locked out", "yes" if locked else "no"),
                    ("Privileged account", "yes" if privileged else "no"),
                ]
                hints = []
                if all(ctx.inventory.is_internal(e.source_ip) for e in burst.events):
                    hints.append("All attempts come from internal hosts: a stale cached credential is a common benign cause.")
                drafts.append(
                    AlertDraft(
                        rule=self,
                        group_key=user,
                        events=burst.events + locked,
                        trigger=burst.trigger,
                        severity=Severity.high if privileged else None,
                        reason=f"{len(burst.events)} failed logons for {user} within {fmt_duration(burst.events[-1].timestamp - burst.events[0].timestamp)}.",
                        evidence=evidence,
                        fp_hints=hints,
                        hostname=burst.trigger.hostname,
                        username=user,
                        source_ip=sources[0][0] if sources else None,
                    )
                )
        return drafts


class PasswordSpraying(Rule):
    id = "LAB-003"
    name = "Password Spraying"
    description = "One source fails authentication against many different accounts, with few attempts per account."
    severity = Severity.high
    rule_type = "threshold"
    data_sources = ["windows_security", "linux_auth"]
    mitre = [mitre("T1110.003", "Brute Force: Password Spraying", "Credential Access")]
    params = [
        ParamSpec("distinct_users", "Distinct accounts", 5, 3, 100),
        ParamSpec("window_minutes", "Time window", 15, 1, 120, "min"),
        ParamSpec("max_attempts_per_user", "Max attempts per account", 3, 1, 20),
    ]
    logic = (
        "event_action = logon_failed\n"
        "| group by source_ip\n"
        "| alert when distinct(username) >= {distinct_users} within {window_minutes} min\n"
        "|   AND avg attempts per account <= {max_attempts_per_user}"
    )
    false_positives = [
        "Shared kiosk or VDI gateway where many users mistype passwords (source is the gateway).",
        "Identity provider or proxy that forwards authentications from a single IP.",
    ]
    response = [
        "Identify any account that later authenticated successfully from the same source.",
        "Force password reset for successful targets and enforce MFA.",
        "Block the source and hunt for the same pattern from adjacent IPs.",
    ]

    def evaluate(self, events, ctx, params):
        window = timedelta(minutes=params["window_minutes"])
        relevant = (e for e in events if _failed(e) and e.source_ip and e.username)
        drafts = []
        for ip, group in group_by(relevant, lambda e: e.source_ip).items():
            for burst in threshold_bursts(group, window, params["distinct_users"], distinct=lambda e: e.username):
                users = {e.username for e in burst.events}
                per_user = len(burst.events) / len(users)
                if per_user > params["max_attempts_per_user"]:
                    continue  # This is a brute force against a few accounts, handled by LAB-001/002.
                hosts = sorted({e.hostname or "?" for e in burst.events})
                drafts.append(
                    AlertDraft(
                        rule=self,
                        group_key=ip,
                        events=burst.events,
                        trigger=burst.trigger,
                        reason=(f"{ip} failed against {len(users)} different accounts ({per_user:.1f} attempts per account on average)."),
                        evidence=[
                            ("Distinct accounts", str(len(users))),
                            ("Total attempts", str(len(burst.events))),
                            ("Attempts per account", f"{per_user:.1f}"),
                            ("Accounts", ", ".join(sorted(users)[:12])),
                            ("Target hosts", ", ".join(hosts)),
                        ],
                        fp_hints=_external_hint(ctx, ip),
                        hostname=hosts[0] if len(hosts) == 1 else burst.trigger.hostname,
                        username=None,
                        source_ip=ip,
                    )
                )
        return drafts


class SuccessAfterFailures(Rule):
    id = "LAB-004"
    name = "Successful Login After Brute Force"
    description = "A source that generated many failed logons subsequently authenticated successfully."
    severity = Severity.critical
    rule_type = "correlation"
    data_sources = ["windows_security", "linux_auth"]
    mitre = [
        mitre("T1110", "Brute Force", "Credential Access"),
        mitre("T1078", "Valid Accounts", "Initial Access"),
    ]
    params = [
        ParamSpec("min_failures", "Prior failures", 5, 2, 100),
        ParamSpec("lookback_minutes", "Lookback", 30, 5, 240, "min"),
    ]
    logic = (
        "event_action = logon_success AS s\n"
        "| join event_action = logon_failed AS f ON f.source_ip = s.source_ip\n"
        "|   WHERE f.timestamp in [s.timestamp - {lookback_minutes} min, s.timestamp]\n"
        "| alert when count(f) >= {min_failures}"
    )
    false_positives = ["User who forgot the password and eventually typed it correctly from a shared NAT address."]
    response = [
        "Treat the account as compromised: disable or reset credentials and revoke sessions/keys.",
        "Isolate the destination host and collect volatile evidence.",
        "Review everything the account did after the successful login (process, sudo, account changes).",
    ]

    def evaluate(self, events, ctx, params):
        lookback = timedelta(minutes=params["lookback_minutes"])
        failures = group_by((e for e in events if _failed(e) and e.source_ip), lambda e: e.source_ip)
        successes = group_by((e for e in events if e.event_action == "logon_success" and e.source_ip in failures), lambda e: e.source_ip)
        drafts = []
        for ip, wins in successes.items():
            fails = failures[ip]
            for cluster in cluster_by_time(wins, timedelta(hours=1)):
                first = cluster[0]
                prior = [f for f in fails if first.timestamp - lookback <= f.timestamp <= first.timestamp]
                if len(prior) < params["min_failures"]:
                    continue
                gap = first.timestamp - prior[-1].timestamp
                drafts.append(
                    AlertDraft(
                        rule=self,
                        group_key=f"{ip}|{first.username}",
                        events=prior + cluster,
                        trigger=first,
                        reason=(
                            f"{first.username} logged on to {first.hostname} from {ip} {fmt_duration(gap)} after "
                            f"{len(prior)} failed attempts from the same source."
                        ),
                        evidence=[
                            ("Compromised account", first.username or "?"),
                            ("Destination host", first.hostname or "?"),
                            ("Failures before success", str(len(prior))),
                            ("Time from last failure to success", fmt_duration(gap)),
                            ("Authentication method", str(first.fields.get("method") or first.fields.get("logon_type_name") or "n/a")),
                            ("Successful logons in cluster", str(len(cluster))),
                        ],
                        fp_hints=_external_hint(ctx, ip),
                        hostname=first.hostname,
                        username=first.username,
                        source_ip=ip,
                    )
                )
        return drafts


class PrivilegedOffHoursLogon(Rule):
    id = "LAB-005"
    name = "Privileged Logon Outside Business Hours"
    description = "Interactive logon by a privileged account outside business hours or on a weekend."
    severity = Severity.medium
    rule_type = "behavioral"
    data_sources = ["windows_security", "linux_auth"]
    mitre = [mitre("T1078", "Valid Accounts", "Initial Access")]
    params = [
        ParamSpec("business_start", "Business hours start", 7, 0, 23, "h"),
        ParamSpec("business_end", "Business hours end", 20, 1, 24, "h"),
    ]
    logic = (
        "event_action = logon_success AND identity.privileged = true AND identity.type in (human, admin)\n"
        "| where logon_type in (2, 10, 11) OR event_source = linux_auth\n"
        "| where local_time.hour not in [{business_start}, {business_end}) OR weekend"
    )
    false_positives = [
        "Planned maintenance or patching windows (check the change calendar).",
        "On-call administrators responding to an outage.",
    ]
    response = [
        "Check the change calendar and on-call schedule.",
        "Contact the administrator through an out-of-band channel to confirm.",
        "If unconfirmed, review the session activity and reset the credential.",
    ]

    def evaluate(self, events, ctx, params):
        start, end = params["business_start"], params["business_end"]

        def off_hours(e: NormalizedEvent) -> bool:
            local = ctx.local(e.timestamp)
            return local.weekday() >= 5 or not (start <= local.hour < end)

        relevant = [
            e
            for e in events
            if e.event_action == "logon_success"
            and ctx.inventory.is_privileged(e.username)
            and ctx.inventory.identity(e.username).type in PERSONAL_ACCOUNT_TYPES
            and (e.event_source == EventSource.linux_auth or e.logon_type in INTERACTIVE_LOGON_TYPES)
            and off_hours(e)
        ]
        drafts = []
        for (user, host), group in group_by(relevant, lambda e: (e.username, e.hostname)).items():
            for cluster in cluster_by_time(group, timedelta(hours=1)):
                first = cluster[0]
                local = ctx.local(first.timestamp)
                hints = []
                change = ctx.inventory.maintenance_window(user, host, first.timestamp)
                if change:
                    hints.append(f"Inside approved change {change.id}: {change.description}.")
                if ctx.inventory.is_internal(first.source_ip):
                    hints.append("Logon originates from the internal network.")
                drafts.append(
                    AlertDraft(
                        rule=self,
                        group_key=f"{user}|{host}",
                        events=cluster,
                        trigger=first,
                        reason=f"Privileged account {user} logged on to {host} at {local:%a %H:%M} local time ({ctx.timezone.key}).",
                        evidence=[
                            ("Local time", f"{local:%Y-%m-%d %H:%M} ({ctx.timezone.key})"),
                            ("Business hours", f"{start:02d}:00-{end:02d}:00, Mon-Fri"),
                            ("Logon type", str(first.fields.get("logon_type_name") or first.fields.get("method") or "n/a")),
                            ("Source", first.source_ip or "local console"),
                            ("Logons in cluster", str(len(cluster))),
                        ],
                        fp_hints=hints,
                        hostname=host,
                        username=user,
                        source_ip=first.source_ip,
                    )
                )
        return drafts


class RootSshLogin(Rule):
    id = "LAB-006"
    name = "Direct Root SSH Login"
    description = "Successful SSH authentication directly as root, bypassing individual accountability."
    severity = Severity.high
    rule_type = "single_event"
    data_sources = ["linux_auth"]
    mitre = [mitre("T1078.003", "Valid Accounts: Local Accounts", "Privilege Escalation")]
    params = []
    logic = "event_source = linux_auth AND event_action = logon_success AND username = root"
    false_positives = ["Break-glass access during an incident when named accounts are unavailable."]
    response = [
        "Confirm whether a break-glass procedure was invoked.",
        "Set PermitRootLogin no and require named accounts + sudo.",
        "If unexpected, rotate root credentials/keys and review commands executed.",
    ]

    def evaluate(self, events, ctx, params):
        relevant = (
            e for e in events if e.event_source == EventSource.linux_auth and e.event_action == "logon_success" and e.username == "root"
        )
        drafts = []
        for (host, ip), group in group_by(relevant, lambda e: (e.hostname, e.source_ip)).items():
            for cluster in cluster_by_time(group, timedelta(minutes=30)):
                first = cluster[0]
                drafts.append(
                    AlertDraft(
                        rule=self,
                        group_key=f"{host}|{ip}",
                        events=cluster,
                        trigger=first,
                        reason=f"root logged on to {host} over SSH from {ip}.",
                        evidence=[
                            ("Method", str(first.fields.get("method", "n/a"))),
                            ("Source", ip or "?"),
                            ("Internal source", "yes" if ctx.inventory.is_internal(ip) else "no"),
                        ],
                        fp_hints=_external_hint(ctx, ip),
                        hostname=host,
                        username="root",
                        source_ip=ip,
                    )
                )
        return drafts


class LateralMovement(Rule):
    id = "LAB-013"
    name = "Lateral Movement: Logons to Multiple Hosts"
    description = "The same account performs network or RDP logons to many distinct hosts in a short time."
    severity = Severity.high
    rule_type = "threshold"
    data_sources = ["windows_security"]
    mitre = [
        mitre("T1021.002", "Remote Services: SMB/Windows Admin Shares", "Lateral Movement"),
        mitre("T1021.001", "Remote Services: Remote Desktop Protocol", "Lateral Movement"),
    ]
    params = [
        ParamSpec("distinct_hosts", "Distinct hosts", 3, 2, 50),
        ParamSpec("window_minutes", "Time window", 10, 1, 120, "min"),
    ]
    logic = (
        "event_id = 4624 AND logon_type in (3, 10) AND asset.role != 'Domain Controller'\n"
        "| group by username\n"
        "| alert when distinct(hostname) >= {distinct_hosts} within {window_minutes} min"
    )
    false_positives = [
        "Backup, inventory or deployment service accounts that touch many servers by design.",
        "Administrators performing mass maintenance.",
    ]
    response = [
        "Map the source host(s) of the logons and check if it is already compromised.",
        "Look for service installs (LAB-012) or scheduled tasks (LAB-011) on the destinations.",
        "Disable the account and isolate affected hosts if the activity is unexplained.",
    ]

    def evaluate(self, events, ctx, params):
        window = timedelta(minutes=params["window_minutes"])
        relevant = (
            e
            for e in events
            if e.event_action == "logon_success"
            and e.event_source == EventSource.windows_security
            and e.logon_type in REMOTE_LOGON_TYPES
            and is_human_account(e.username)
            and "domain controller" not in ((ctx.inventory.asset(e.hostname) or _NoAsset).role.lower())
        )
        drafts = []
        for user, group in group_by(relevant, lambda e: e.username).items():
            for burst in threshold_bursts(group, window, params["distinct_hosts"], distinct=lambda e: e.hostname):
                hosts = sorted({e.hostname or "?" for e in burst.events})
                sources = sorted({e.source_ip for e in burst.events if e.source_ip})
                hints = []
                if ctx.inventory.is_service_account(user):
                    hints.append(f"{user} is a service account; check whether this matches its normal job schedule.")
                by_type: dict[str, int] = defaultdict(int)
                for e in burst.events:
                    by_type[str(e.fields.get("logon_type_name", e.logon_type))] += 1
                drafts.append(
                    AlertDraft(
                        rule=self,
                        group_key=user,
                        events=burst.events,
                        trigger=burst.trigger,
                        reason=f"{user} logged on to {len(hosts)} hosts ({', '.join(hosts)}) within {params['window_minutes']} min.",
                        evidence=[
                            ("Destination hosts", ", ".join(hosts)),
                            ("Source addresses", ", ".join(sources) or "n/a"),
                            ("Logon types", ", ".join(f"{k} ({v})" for k, v in by_type.items())),
                        ],
                        fp_hints=hints,
                        hostname=burst.trigger.hostname,
                        username=user,
                        source_ip=sources[0] if len(sources) == 1 else None,
                    )
                )
        return drafts


class _NoAssetType:
    role = ""


_NoAsset = _NoAssetType()
