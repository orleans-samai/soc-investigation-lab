"""Detections over business-application audit logs (internet banking, PIX)."""

from __future__ import annotations

from datetime import timedelta

from app.detection.base import AlertDraft, ParamSpec, Rule, group_by, mitre
from app.models.common import Severity
from app.models.events import EventSource

ACCOUNT_CHANGES = {"contact_changed", "pix_key_registered", "payee_added"}


def _amount(value: object) -> float:
    try:
        return float(str(value).replace(",", "."))
    except ValueError:
        return 0.0


def _brl(value: float) -> str:
    # 12345.6 -> "R$ 12.345,60"
    return "R$ " + f"{value:,.2f}".replace(",", "_").replace(".", ",").replace("_", ".")


def _mask(key: str | None) -> str:
    if not key:
        return "?"
    return key if len(key) <= 6 else key[:3] + "***" + key[-3:]


class PixAccountTakeover(Rule):
    id = "LAB-018"
    name = "Account Takeover Followed by PIX Transfer"
    description = (
        "A banking customer signed in from a device never seen for that account, changed contact data or registered a "
        "new PIX key / payee, and moved money shortly after."
    )
    severity = Severity.high
    rule_type = "correlation"
    data_sources = ["application"]
    mitre = [
        mitre("T1078", "Valid Accounts", "Initial Access"),
        mitre("T1098", "Account Manipulation", "Persistence"),
        mitre("T1657", "Financial Theft", "Impact"),
    ]
    params = [
        ParamSpec("window_minutes", "Login-to-transfer window", 30, 5, 240, "min"),
        ParamSpec("min_amount", "Minimum transfer", 1000, 50, 1_000_000, "BRL"),
    ]
    logic = (
        "event_source = application AND event_action = login_success AS l\n"
        "| where l.fields.device_id not in (devices previously used by l.username)\n"
        "| followed by event_action in (contact_changed, pix_key_registered, payee_added) AS c\n"
        "| followed by event_action = pix_transfer AND fields.amount >= {min_amount} AS t\n"
        "|   within {window_minutes} min of l, same username"
    )
    false_positives = [
        "Customer replaced or reset the phone and paid someone new on the same day (look for a step-up or call-centre "
        "identity verification just before the login).",
        "Joint account holders sharing credentials from their own devices.",
    ]
    response = [
        "Block outgoing PIX for the account and request MED (Mecanismo Especial de Devolução) for the transfers.",
        "Revoke the new device's sessions, reset the credentials and contact the customer on a verified channel.",
        "Hunt for the same source IP / device across other customers (credential stuffing campaigns hit many accounts).",
        "Customer personal data was accessed by a third party: assess LGPD notification to ANPD and the data subject.",
    ]

    def evaluate(self, events, ctx, params):
        window = timedelta(minutes=params["window_minutes"])
        app_events = [e for e in events if e.event_source == EventSource.application and e.username]
        drafts = []
        for user, timeline in group_by(app_events, lambda e: e.username).items():
            known: set[str] = set()
            for i, login in enumerate(timeline):
                if login.event_action != "login_success":
                    continue
                device = str(login.fields.get("device_id") or "")
                is_new = bool(known) and device not in known
                if device:
                    known.add(device)
                if not is_new:
                    continue
                after = [e for e in timeline[i + 1 :] if e.timestamp - login.timestamp <= window]
                changes = [e for e in after if e.event_action in ACCOUNT_CHANGES]
                transfers = [
                    e
                    for e in after
                    if e.event_action == "pix_transfer"
                    and _amount(e.fields.get("amount")) >= params["min_amount"]
                    and changes
                    and e.timestamp >= changes[0].timestamp
                ]
                if not transfers:
                    continue
                failures = [e for e in timeline[:i] if e.event_action == "login_failed" and login.timestamp - e.timestamp <= window]
                total = sum(_amount(t.fields.get("amount")) for t in transfers)
                trigger = transfers[0]
                drafts.append(
                    AlertDraft(
                        rule=self,
                        group_key=f"{user}|{device}",
                        events=failures + [login] + changes + transfers,
                        trigger=trigger,
                        severity=Severity.critical if total >= params["min_amount"] * 10 else None,
                        reason=(
                            f"{user} signed in from new device {device} ({login.source_ip}), "
                            f"{'/'.join(sorted({c.event_action for c in changes}))} and sent {_brl(total)} in "
                            f"{len(transfers)} PIX transfer(s) within {int((trigger.timestamp - login.timestamp).total_seconds() // 60)} min."
                        ),
                        evidence=[
                            ("Customer", user),
                            ("New device", f"{device} ({login.fields.get('user_agent') or 'unknown agent'})"),
                            ("Known devices", ", ".join(sorted(known - {device})) or "none"),
                            ("Source IP", login.source_ip or "?"),
                            ("Failed logins before", str(len(failures))),
                            ("Account changes", ", ".join(c.event_action for c in changes)),
                            ("PIX total", _brl(total)),
                            ("Recipient keys", ", ".join(sorted({_mask(t.fields.get("recipient_key")) for t in transfers}))),
                        ],
                        fp_hints=[
                            "Check for an identity_verified event (call centre / branch) shortly before the new-device login.",
                        ],
                        hostname=login.hostname,
                        username=user,
                        source_ip=login.source_ip,
                    )
                )
        return drafts
