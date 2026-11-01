"""Run analyst-written Sigma rules (https://sigmahq.io) inside the lab's detection engine.

Supported subset, enough for the rules SOC analysts write day to day:

* ``logsource`` with product / service / category (mapped to the lab's event sources);
* selections as maps (AND), lists of maps (OR) and keyword lists (search over raw + message);
* modifiers ``contains``, ``startswith``, ``endswith``, ``all``, ``re``, ``cidr``, ``exists``, ``gt/gte/lt/lte``,
  ``cased``; ``*`` and ``?`` wildcards; ``null`` for "field absent";
* conditions with ``and``, ``or``, ``not``, parentheses, ``1 of x*``, ``all of x*``, ``1 of them``;
* Sigma v2 ``event_count`` and ``value_count`` correlations (with ``group-by``, ``timespan`` and ``gte``),
  which become tunable threshold parameters, exactly like the built-in rules.

Field names follow Windows/Sigma conventions (``Image``, ``TargetUserName``, ``IpAddress``...) and are
resolved against the normalized event, then against ``fields`` (raw EventData, snake_case).
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from collections.abc import Callable
from datetime import timedelta
from typing import Any

import yaml

from app.detection.base import AlertDraft, ParamSpec, Rule, cluster_by_time, group_by, threshold_bursts
from app.models.common import MitreRef, Severity
from app.models.events import EventSource, NormalizedEvent

MAX_YAML_BYTES = 64_000
LEVELS = {
    "informational": Severity.low,
    "low": Severity.low,
    "medium": Severity.medium,
    "high": Severity.high,
    "critical": Severity.critical,
}
MODIFIERS = {"contains", "startswith", "endswith", "all", "re", "cidr", "exists", "gt", "gte", "lt", "lte", "cased", "i", "m", "s"}

ALIASES: dict[str, list[str]] = {
    "eventid": ["event_id"],
    "image": ["process_name"],
    "sourceimage": ["process_name"],
    "newprocessname": ["process_name"],
    "commandline": ["command_line"],
    "scriptblocktext": ["command_line"],
    "parentimage": ["parent_process"],
    "user": ["username"],
    "subjectusername": ["username"],
    "targetusername": ["target_username", "username"],
    "ipaddress": ["source_ip"],
    "sourceip": ["source_ip"],
    "src_ip": ["source_ip"],
    "destinationip": ["destination_ip"],
    "dst_ip": ["destination_ip"],
    "sourceport": ["source_port"],
    "ipport": ["source_port"],
    "destinationport": ["destination_port"],
    "computer": ["hostname"],
    "computername": ["hostname"],
    "host": ["hostname"],
    "workstationname": ["fields.workstation"],
    "logontype": ["logon_type"],
    "groupname": ["group_name"],
    "substatus": ["fields.sub_status"],
    "status": ["fields.status"],
    "servicename": ["fields.service_name"],
    "taskname": ["fields.task_name"],
    "queryname": ["fields.query_name"],
    "targetimage": ["fields.target_image"],
    "grantedaccess": ["fields.granted_access"],
    "targetfilename": ["fields.target_filename"],
    "calltrace": ["fields.call_trace"],
    "hashes": ["fields.hashes", "fields.sha256"],
    "action": ["event_action"],
}
NORMALIZED_FIELDS = set(NormalizedEvent.model_fields) - {"fields", "tags"}

CATEGORY_ACTIONS = {
    "process_creation": {"process_created"},
    "process_access": {"process_access"},
    "file_event": {"file_created"},
    "dns_query": {"dns_query"},
    "dns": {"dns_query"},
    "network_connection": {"network_connection"},
}
SERVICE_SOURCES = {
    "security": {EventSource.windows_security},
    "system": {EventSource.windows_system},
    "powershell": {EventSource.windows_powershell},
    "powershell-classic": {EventSource.windows_powershell},
    "sysmon": {EventSource.windows_sysmon},
}


class SigmaError(ValueError):
    pass


def _snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def resolve(event: NormalizedEvent, field: str) -> Any:
    candidates = ALIASES.get(field.lower(), []) + [field, _snake(field), f"fields.{field}", f"fields.{_snake(field)}"]
    for candidate in candidates:
        if candidate.startswith("fields."):
            value = event.fields.get(candidate[7:])
        elif candidate in NORMALIZED_FIELDS:
            value = getattr(event, candidate)
        else:
            continue
        if value not in (None, ""):
            return value.value if hasattr(value, "value") else value
    return None


# ---------------------------------------------------------------- value matching
def _value_matcher(value: Any, modifiers: set[str]) -> Callable[[Any], bool]:
    cased = "cased" in modifiers

    def norm(v: Any) -> str:
        s = str(v)
        return s if cased else s.lower()

    if "exists" in modifiers:
        want = bool(value)
        return lambda actual: (actual is not None) == want
    if value is None:
        return lambda actual: actual is None
    for op, fn in (("gte", float.__ge__), ("gt", float.__gt__), ("lte", float.__le__), ("lt", float.__lt__)):
        if op in modifiers:
            limit = float(value)

            def numeric(actual: Any, fn=fn, limit=limit) -> bool:
                try:
                    return actual is not None and fn(float(actual), limit)
                except (TypeError, ValueError):
                    return False

            return numeric
    if "cidr" in modifiers:
        try:
            network = ipaddress.ip_network(str(value), strict=False)
        except ValueError as exc:
            raise SigmaError(f"invalid CIDR {value!r}") from exc

        def in_network(actual: Any) -> bool:
            try:
                return actual is not None and ipaddress.ip_address(str(actual)) in network
            except ValueError:
                return False

        return in_network
    if "re" in modifiers:
        try:
            pattern = re.compile(str(value), 0 if cased else re.IGNORECASE)
        except re.error as exc:
            raise SigmaError(f"invalid regular expression {value!r}: {exc}") from exc
        return lambda actual: actual is not None and bool(pattern.search(str(actual)))

    target = norm(value)
    if "contains" in modifiers:
        return lambda actual: actual is not None and target in norm(actual)
    if "startswith" in modifiers:
        return lambda actual: actual is not None and norm(actual).startswith(target)
    if "endswith" in modifiers:
        return lambda actual: actual is not None and norm(actual).endswith(target)
    if isinstance(value, str) and ("*" in value or "?" in value):
        pattern = re.compile(fnmatch.translate(value), 0 if cased else re.IGNORECASE)
        return lambda actual: actual is not None and bool(pattern.match(str(actual)))
    return lambda actual: actual is not None and norm(actual) == target


def _field_matcher(key: str, value: Any) -> Callable[[NormalizedEvent], bool]:
    field, *mods = key.split("|")
    modifiers = set(mods)
    unknown = modifiers - MODIFIERS
    if unknown:
        raise SigmaError(f"modifier(s) not supported: {', '.join(sorted(unknown))}")
    values = value if isinstance(value, list) else [value]
    if not values:
        raise SigmaError(f"field {field} has an empty value list")
    matchers = [_value_matcher(v, modifiers) for v in values]
    combine = all if "all" in modifiers else any
    return lambda event: combine(m(resolve(event, field)) for m in matchers)


def _keyword_matcher(words: list[Any]) -> Callable[[NormalizedEvent], bool]:
    lowered = [str(w).lower() for w in words]
    return lambda event: any(w in event.raw.lower() or w in event.message.lower() for w in lowered)


def _selection(name: str, body: Any) -> Callable[[NormalizedEvent], bool]:
    if isinstance(body, dict):
        if not body:
            raise SigmaError(f"selection '{name}' is empty")
        parts = [_field_matcher(k, v) for k, v in body.items()]
        return lambda event: all(p(event) for p in parts)
    if isinstance(body, list) and body and all(isinstance(item, dict) for item in body):
        alternatives = [_selection(name, item) for item in body]
        return lambda event: any(a(event) for a in alternatives)
    if isinstance(body, list | str | int) and body != []:
        return _keyword_matcher(body if isinstance(body, list) else [body])
    raise SigmaError(f"selection '{name}' must be a map, a list of maps or a list of keywords")


# ---------------------------------------------------------------- condition parsing
_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*]+)")


def _tokenize(condition: str) -> list[str]:
    tokens, pos = [], 0
    while pos < len(condition):
        match = _TOKEN.match(condition, pos)
        if not match:
            if condition[pos:].strip().startswith("|"):
                raise SigmaError("pipe aggregations ('| count() ...') are deprecated in Sigma; use a correlation rule instead")
            raise SigmaError(f"cannot parse condition near {condition[pos : pos + 20]!r}")
        tokens.append(match.group(1))
        pos = match.end()
    return tokens


def compile_condition(condition: str, selections: dict[str, Callable[[NormalizedEvent], bool]]):
    tokens = _tokenize(condition)
    pos = 0

    def peek() -> str | None:
        return tokens[pos].lower() if pos < len(tokens) else None

    def take() -> str:
        nonlocal pos
        if pos >= len(tokens):
            raise SigmaError("condition ends unexpectedly")
        pos += 1
        return tokens[pos - 1]

    def names(pattern: str) -> list[str]:
        found = list(selections) if pattern.lower() == "them" else [n for n in selections if fnmatch.fnmatchcase(n, pattern)]
        if not found:
            raise SigmaError(f"'{pattern}' does not match any selection")
        return found

    def factor():
        token = peek()
        if token == "not":
            take()
            inner = factor()
            return lambda e: not inner(e)
        if token == "(":
            take()
            inner = expr()
            if take() != ")":
                raise SigmaError("missing ')' in condition")
            return inner
        word = take()
        if peek() == "of":
            take()
            group = [selections[n] for n in names(take())]
            if word.lower() == "all":
                return lambda e: all(s(e) for s in group)
            if word.isdigit():
                need = int(word)
                return lambda e: sum(1 for s in group if s(e)) >= need
            raise SigmaError(f"expected '1 of' or 'all of', got '{word} of'")
        if word not in selections:
            raise SigmaError(f"condition references unknown selection '{word}'")
        return selections[word]

    def term():
        parts = [factor()]
        while peek() == "and":
            take()
            parts.append(factor())
        return parts[0] if len(parts) == 1 else (lambda e: all(p(e) for p in parts))

    def expr():
        parts = [term()]
        while peek() == "or":
            take()
            parts.append(term())
        return parts[0] if len(parts) == 1 else (lambda e: any(p(e) for p in parts))

    result = expr()
    if pos != len(tokens):
        raise SigmaError(f"unexpected '{tokens[pos]}' in condition")
    return result


# ---------------------------------------------------------------- rule documents
def _logsource(logsource: dict[str, Any]) -> tuple[set[EventSource] | None, set[str] | None, str]:
    product = str(logsource.get("product", "")).lower()
    service = str(logsource.get("service", "")).lower()
    category = str(logsource.get("category", "")).lower()
    actions = CATEGORY_ACTIONS.get(category)
    if category and actions is None:
        raise SigmaError(f"logsource category '{category}' is not available in the lab")
    if product == "linux":
        sources = {EventSource.linux_auth}
    elif product in {"application", "internet_banking", "webapp"}:
        sources = {EventSource.application}
    elif product == "windows":
        if service:
            if service not in SERVICE_SOURCES:
                raise SigmaError(f"logsource service '{service}' is not available in the lab")
            sources = SERVICE_SOURCES[service]
        elif actions:
            sources = {EventSource.windows_sysmon, EventSource.windows_security}
        else:
            sources = {s for s in EventSource if s.value.startswith("windows")}
    elif not product:
        sources = None
    else:
        raise SigmaError(f"logsource product '{product}' is not available in the lab (use windows, linux or application)")
    label = "/".join(x for x in (product, service, category) if x) or "any"
    return sources, actions, label


def _timespan_minutes(value: Any) -> int:
    match = re.fullmatch(r"(\d+)([smhd])", str(value).strip())
    if not match:
        raise SigmaError(f"invalid timespan {value!r} (use e.g. 5m, 1h)")
    amount, unit = int(match.group(1)), match.group(2)
    minutes = {"s": amount / 60, "m": amount, "h": amount * 60, "d": amount * 1440}[unit]
    return max(1, min(1440, round(minutes)))


def _mitre(tags: list[str], lookup: Callable[[str], tuple[str, str] | None]) -> list[MitreRef]:
    refs = []
    for tag in tags:
        match = re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", str(tag).lower())
        if match:
            technique_id = match.group(1).upper()
            name, tactic = lookup(technique_id) or (technique_id, "Unknown")
            refs.append(MitreRef(technique_id=technique_id, technique=name, tactic=tactic))
    return refs


class SigmaRule(Rule):
    """A detection compiled from analyst-written Sigma YAML."""

    rule_type = "single_event"
    custom = True

    def __init__(self, rule_id: str, source: str, mitre_lookup: Callable[[str], tuple[str, str] | None] = lambda _: None):
        if len(source.encode()) > MAX_YAML_BYTES:
            raise SigmaError(f"rule is larger than {MAX_YAML_BYTES // 1000} kB")
        try:
            docs = [d for d in yaml.safe_load_all(source) if d is not None]
        except yaml.YAMLError as exc:
            raise SigmaError(f"invalid YAML: {exc}") from exc
        if not docs or not all(isinstance(d, dict) for d in docs):
            raise SigmaError("expected one or more YAML mappings (Sigma rule documents)")
        bases = [d for d in docs if "detection" in d]
        correlations = [d for d in docs if "correlation" in d]
        if len(bases) != 1:
            raise SigmaError("the file must contain exactly one detection rule (plus an optional correlation)")
        if len(correlations) > 1:
            raise SigmaError("only one correlation per file is supported")
        base = bases[0]

        self.id = rule_id
        self.source = source
        self.name = str((correlations[0] if correlations else base).get("title") or base.get("title") or "Untitled Sigma rule")[:120]
        self.description = str(base.get("description") or self.name)[:600]
        level = str((correlations[0] if correlations else base).get("level") or base.get("level") or "medium").lower()
        if level not in LEVELS:
            raise SigmaError(f"unknown level '{level}'")
        self.severity = LEVELS[level]
        tags = [str(t) for t in (base.get("tags") or [])]
        self.mitre = _mitre(tags, mitre_lookup)
        self.false_positives = [str(x) for x in (base.get("falsepositives") or [])] or ["Not documented in the rule."]
        self.response = ["Review the matching events and the entity's surrounding activity."]
        self.sigma_id = str(base.get("id") or "")

        logsource = base.get("logsource") or {}
        if not isinstance(logsource, dict):
            raise SigmaError("logsource must be a map")
        self._sources, self._actions, source_label = _logsource(logsource)
        self.data_sources = sorted(s.value for s in self._sources) if self._sources else ["any"]

        detection = base.get("detection")
        if not isinstance(detection, dict) or "condition" not in detection:
            raise SigmaError("detection must be a map with a 'condition'")
        condition = detection["condition"]
        if isinstance(condition, list):
            condition = " or ".join(f"({c})" for c in condition)
        selections = {name: _selection(name, body) for name, body in detection.items() if name != "condition"}
        if not selections:
            raise SigmaError("detection has no selections")
        self._match = compile_condition(str(condition), selections)

        self._group_by: list[str] = []
        self._distinct: str | None = None
        self.params = []
        logic = f"logsource {source_label}\n| where {condition}"
        if correlations:
            corr = correlations[0]["correlation"] or {}
            kind = corr.get("type")
            if kind not in {"event_count", "value_count"}:
                raise SigmaError(f"correlation type '{kind}' is not supported (use event_count or value_count)")
            cond = corr.get("condition") or {}
            if "gte" not in cond and "gt" not in cond:
                raise SigmaError("correlation condition must use gte or gt")
            threshold = int(cond["gte"]) if "gte" in cond else int(cond["gt"]) + 1
            self._group_by = [str(g) for g in (corr.get("group-by") or [])]
            if kind == "value_count":
                if not cond.get("field"):
                    raise SigmaError("value_count needs condition.field")
                self._distinct = str(cond["field"])
            window = _timespan_minutes(corr.get("timespan", "5m"))
            self.rule_type = "threshold"
            self.params = [
                ParamSpec("threshold", "Distinct values" if self._distinct else "Matching events", threshold, 1, 10_000),
                ParamSpec("window_minutes", "Time window", window, 1, 1440, "min"),
            ]
            counted = f"count(distinct {self._distinct})" if self._distinct else "count"
            logic += (
                f"\n| group by {', '.join(self._group_by) or 'all'}\n| alert when {counted} >= {{threshold}} within {{window_minutes}} min"
            )
        self.logic = logic

    def matches(self, event: NormalizedEvent) -> bool:
        if self._sources is not None and event.event_source not in self._sources:
            return False
        if self._actions is not None and event.event_action not in self._actions:
            return False
        return self._match(event)

    def evaluate(self, events, ctx, params):
        matched = [e for e in events if self.matches(e)]
        drafts: list[AlertDraft] = []
        if not self.params:
            for (host, user), group in group_by(matched, lambda e: (e.hostname or "-", e.username or "-")).items():
                for cluster in cluster_by_time(group, timedelta(minutes=10)):
                    first = cluster[0]
                    drafts.append(self._draft(f"{host}|{user}", cluster, first, f"{len(cluster)} matching event(s) on {host}"))
            return drafts

        window = timedelta(minutes=params["window_minutes"])
        distinct = (lambda e: resolve(e, self._distinct)) if self._distinct else None
        keyed = group_by(matched, lambda e: tuple(str(resolve(e, f)) for f in self._group_by))
        for key, group in keyed.items():
            for burst in threshold_bursts(group, window, params["threshold"], distinct=distinct):
                label = ", ".join(f"{f}={v}" for f, v in zip(self._group_by, key, strict=True)) or "all events"
                what = f"{burst.peak} distinct {self._distinct}" if self._distinct else f"{len(burst.events)} matching events"
                drafts.append(self._draft("|".join(key) or "all", burst.events, burst.trigger, f"{what} for {label}"))
        return drafts

    def _draft(self, group_key: str, events: list[NormalizedEvent], trigger: NormalizedEvent, summary: str) -> AlertDraft:
        return AlertDraft(
            rule=self,
            group_key=group_key,
            events=events,
            trigger=trigger,
            reason=f"{self.name}: {summary}.",
            evidence=[
                ("Matching events", str(len(events))),
                ("Hosts", ", ".join(sorted({e.hostname or "?" for e in events}))[:200]),
                ("Accounts", ", ".join(sorted({e.username for e in events if e.username}))[:200] or "n/a"),
                ("First match", trigger.message[:200] or trigger.event_action),
            ],
            hostname=trigger.hostname,
            username=trigger.username,
            source_ip=trigger.source_ip,
        )
