"""Account manipulation and privilege escalation detections."""

from __future__ import annotations

from datetime import timedelta

from app.detection.base import AlertDraft, ParamSpec, Rule, cluster_by_time, group_by, mitre
from app.models.common import Severity
from app.models.events import EventSource


class AccountCreated(Rule):
    id = "LAB-007"
    name = "New Account Created"
    description = "A new local or domain user account was created."
    severity = Severity.medium
    rule_type = "single_event"
    data_sources = ["windows_security", "linux_auth"]
    mitre = [mitre("T1136.001", "Create Account: Local Account", "Persistence")]
    params = []
    logic = "event_action = user_created   (Windows 4720, Linux useradd)"
    false_positives = ["Regular onboarding performed by the IT team (match against HR/onboarding tickets)."]
    response = [
        "Find the onboarding or change ticket that justifies the account.",
        "Check who created it and from which session.",
        "If unjustified, disable the account and review its group memberships and logons.",
    ]

    def evaluate(self, events, ctx, params):
        drafts = []
        for event in (e for e in events if e.event_action == "user_created"):
            actor = event.username or "unknown actor"
            hints = []
            actor_identity = ctx.inventory.identity(event.username)
            if ctx.is_business_hours(event.timestamp) and actor_identity and actor_identity.department == "IT":
                hints.append(f"Created by IT staff ({actor}) during business hours: confirm a matching onboarding ticket.")
            change = ctx.inventory.maintenance_window(event.username, event.hostname, event.timestamp)
            if change:
                hints.append(f"Inside approved change {change.id}.")
            drafts.append(
                AlertDraft(
                    rule=self,
                    group_key=f"{event.hostname}|{event.target_username}",
                    events=[event],
                    trigger=event,
                    reason=f"Account '{event.target_username}' was created on {event.hostname} by {actor}.",
                    evidence=[
                        ("New account", event.target_username or "?"),
                        ("Created by", actor),
                        ("Host", event.hostname or "?"),
                        ("Within business hours", "yes" if ctx.is_business_hours(event.timestamp) else "no"),
                    ],
                    fp_hints=hints,
                    hostname=event.hostname,
                    username=event.target_username,
                    source_ip=event.source_ip,
                )
            )
        return drafts


class PrivilegedGroupAddition(Rule):
    id = "LAB-008"
    name = "User Added to Privileged Group"
    description = "An account was added to an administrative group (Administrators, Domain Admins, sudo...)."
    severity = Severity.high
    rule_type = "correlation"
    data_sources = ["windows_security", "linux_auth"]
    mitre = [mitre("T1098", "Account Manipulation", "Persistence")]
    params = [ParamSpec("recent_account_hours", "Escalate if account created within", 24, 1, 168, "h")]
    logic = (
        "event_action = group_member_added AND group_name IN privileged_groups\n"
        "| severity = critical if target account was created within {recent_account_hours} h"
    )
    false_positives = ["Approved access request for a new administrator."]
    response = [
        "Validate the access request / change ticket.",
        "Remove the membership if not approved and investigate the actor's session.",
        "Review privileged group changes across all hosts for the same period.",
    ]

    def evaluate(self, events, ctx, params):
        recent = timedelta(hours=params["recent_account_hours"])
        created = {}
        for e in events:
            if e.event_action == "user_created" and e.target_username:
                created.setdefault(e.target_username, e)
        drafts = []
        for event in events:
            if event.event_action != "group_member_added" or not ctx.inventory.is_privileged_group(event.group_name):
                continue
            target = event.target_username
            creation = created.get(target or "")
            new_account = creation is not None and timedelta(0) <= event.timestamp - creation.timestamp <= recent
            related = [creation, event] if new_account and creation else [event]
            hints = []
            change = ctx.inventory.maintenance_window(event.username, event.hostname, event.timestamp)
            if change:
                hints.append(f"Inside approved change {change.id}.")
            evidence = [
                ("Group", event.group_name or "?"),
                ("Member added", target or "?"),
                ("Changed by", event.username or "?"),
                ("Host", event.hostname or "?"),
            ]
            if new_account and creation:
                minutes = int((event.timestamp - creation.timestamp).total_seconds() // 60)
                evidence.append(("Account age at elevation", f"{minutes} min (created by {creation.username})"))
            drafts.append(
                AlertDraft(
                    rule=self,
                    group_key=f"{event.hostname}|{event.group_name}|{target}",
                    events=related,
                    trigger=event,
                    severity=Severity.critical if new_account else None,
                    reason=(
                        f"'{target}' was added to privileged group '{event.group_name}' on {event.hostname} by {event.username or 'unknown'}"
                        + (" shortly after the account was created." if new_account else ".")
                    ),
                    evidence=evidence,
                    fp_hints=hints,
                    hostname=event.hostname,
                    username=target,
                    source_ip=event.source_ip,
                )
            )
        return drafts


class SudoAbuse(Rule):
    id = "LAB-014"
    name = "Sudo Privilege Escalation Attempt"
    description = "A user not allowed to use sudo tried to run privileged commands, or failed sudo authentication repeatedly."
    severity = Severity.medium
    rule_type = "threshold"
    data_sources = ["linux_auth"]
    mitre = [mitre("T1548.003", "Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "Privilege Escalation")]
    params = [ParamSpec("max_failed_attempts", "Failed sudo password attempts", 3, 1, 20)]
    logic = (
        "event_source = linux_auth AND (event_action = sudo_denied\n"
        "  OR (event_action = sudo_auth_failed AND attempts >= {max_failed_attempts}))\n"
        "| group by username, hostname within 30 min"
    )
    false_positives = ["New team member who has not yet been granted sudo rights."]
    response = [
        "Ask the user what they were trying to do and review the commands attempted.",
        "If the account is shared or was recently compromised, reset it and review its SSH keys.",
    ]

    def evaluate(self, events, ctx, params):
        def suspicious(e):
            if e.event_source != EventSource.linux_auth:
                return False
            if e.event_action == "sudo_denied":
                return True
            return e.event_action == "sudo_auth_failed" and int(e.fields.get("attempts", 0)) >= params["max_failed_attempts"]

        drafts = []
        for (user, host), group in group_by((e for e in events if suspicious(e)), lambda e: (e.username, e.hostname)).items():
            for cluster in cluster_by_time(group, timedelta(minutes=30)):
                first = cluster[0]
                commands = sorted({e.command_line for e in cluster if e.command_line})
                drafts.append(
                    AlertDraft(
                        rule=self,
                        group_key=f"{user}|{host}",
                        events=cluster,
                        trigger=first,
                        reason=f"{user} attempted privileged commands on {host} without authorization ({len(cluster)} events).",
                        evidence=[
                            ("Commands attempted", " | ".join(commands)[:400] or "n/a"),
                            ("Events", str(len(cluster))),
                        ],
                        hostname=host,
                        username=user,
                    )
                )
        return drafts
