"""Detections driven by the local threat-intelligence feed."""

from __future__ import annotations

from datetime import timedelta

from app.detection.base import AlertDraft, Rule, cluster_by_time, group_by, mitre
from app.detection.threat_intel import Indicator, host_of, is_ip, urls_in
from app.models.common import Severity
from app.models.events import NormalizedEvent


def observables(event: NormalizedEvent) -> list[tuple[str, str, str]]:
    """(indicator type, value, where it was found) for everything in the event worth looking up."""
    found: list[tuple[str, str, str]] = []
    for attr in ("source_ip", "destination_ip"):
        if getattr(event, attr):
            found.append(("ip", getattr(event, attr), attr))
    for key in ("query_name", "destination_hostname"):
        if event.fields.get(key):
            found.append(("domain", str(event.fields[key]), f"fields.{key}"))
    if event.fields.get("sha256"):
        found.append(("sha256", str(event.fields["sha256"]), "fields.sha256"))
    for url in urls_in(event.command_line):
        found.append(("url", url, "command_line"))
        host = host_of(url)
        if host:
            found.append(("ip" if is_ip(host) else "domain", host, "command_line URL"))
    return found


class ThreatIntelMatch(Rule):
    id = "LAB-016"
    name = "Threat Intelligence Indicator Match"
    description = "An event references an IP, domain, URL or file hash listed in the threat-intelligence feed."
    severity = Severity.high
    rule_type = "enrichment"
    data_sources = ["windows_security", "windows_sysmon", "windows_powershell", "linux_auth"]
    mitre = [mitre("T1071", "Application Layer Protocol", "Command and Control")]
    params = []
    logic = (
        "for each event: extract source/destination IP, DNS query, destination hostname,\n"
        "  URLs (and their hosts) in command_line, SHA256 hash\n"
        "| lookup threat_intel on (type, value)\n"
        "| severity = indicator severity; one alert per indicator and host per hour"
    )
    false_positives = [
        "Stale indicators: infrastructure is re-used or re-assigned after a campaign ends.",
        "Low-confidence feed entries (shared hosting, CDNs, Tor exit nodes used by legitimate users).",
    ]
    response = [
        "Confirm the match in the raw event and check the indicator's confidence and age.",
        "Block the indicator at the firewall / proxy / EDR and search for it across all hosts.",
        "Investigate the process and account that produced the event on the affected host.",
    ]

    def evaluate(self, events, ctx, params):
        feed = ctx.threat_intel
        if feed is None or not feed.indicators:
            return []
        hits: list[tuple[NormalizedEvent, Indicator, str]] = []
        for event in events:
            seen: set[str] = set()
            for kind, value, where in observables(event):
                indicator = feed.lookup(kind, value)
                if indicator and indicator.value not in seen:
                    seen.add(indicator.value)
                    hits.append((event, indicator, where))

        drafts = []
        for (value, host), group in group_by(hits, lambda h: (h[1].value.lower(), h[0].hostname)).items():  # type: ignore[arg-type,return-value]
            events_only = [h[0] for h in group]
            for cluster in cluster_by_time(events_only, timedelta(hours=1)):
                indicator, where = next((h[1], h[2]) for h in group if h[0] is cluster[0])
                first = cluster[0]
                hints = []
                if indicator.confidence < 70:
                    hints.append(f"Indicator confidence is only {indicator.confidence}%: verify before acting on it.")
                drafts.append(
                    AlertDraft(
                        rule=self,
                        group_key=f"{value}|{host}",
                        events=cluster,
                        trigger=first,
                        severity=indicator.severity,
                        reason=f"{host} produced {len(cluster)} event(s) referencing {indicator.type} {indicator.value}: {indicator.threat}.",
                        evidence=[
                            ("Indicator", f"{indicator.type}: {indicator.value}"),
                            ("Threat", indicator.threat),
                            ("Confidence", f"{indicator.confidence}%"),
                            ("First seen in feed", indicator.first_seen or "n/a"),
                            ("Matched in", where),
                            ("Feed", feed.source),
                        ],
                        fp_hints=hints,
                        hostname=host,
                        username=first.username,
                        source_ip=first.source_ip if first.source_ip and not ctx.inventory.is_internal(first.source_ip) else None,
                    )
                )
        return drafts
