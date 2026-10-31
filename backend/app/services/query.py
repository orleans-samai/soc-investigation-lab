"""A small search language for the Log Explorer, in the spirit of KQL / SPL.

    outcome:failure AND host:bastion-01 | stats count by source_ip | sort -count | head 10
    action:logon_success NOT ip:10.10.* | sort timestamp
    cmd:*powershell* (user:j.silva OR user:a.costa)
    logon_type>=3 "invalid user"

Grammar (case-insensitive keywords):

    query   := expr? ("|" pipe)*
    expr    := and ("OR" and)*
    and     := unary (["AND"] unary)*
    unary   := ("NOT" | "-") unary | "(" expr ")" | term
    term    := FIELD OP VALUE | VALUE            (a bare VALUE is free text)
    OP      := ":" | "=" | "!=" | ">" | ">=" | "<" | "<="
    pipe    := "stats count by" FIELD ("," FIELD)* | "sort" ["-"]FIELD | "head" N

``:``/``=`` compare case-insensitively and accept ``*`` wildcards. Nothing is evaluated as code: the
query is tokenized and turned into Python predicates over event attributes.
"""

from __future__ import annotations

import fnmatch
import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.models.events import NormalizedEvent

MAX_QUERY_LENGTH = 1000
ALIASES = {
    "user": "username",
    "host": "hostname",
    "src": "source_ip",
    "src_ip": "source_ip",
    "dst": "destination_ip",
    "action": "event_action",
    "source": "event_source",
    "type": "event_type",
    "level": "log_level",
    "cmd": "command_line",
    "process": "process_name",
    "parent": "parent_process",
    "target": "target_username",
    "group": "group_name",
    "id": "event_id",
}
FIELDS = set(NormalizedEvent.model_fields) - {"fields", "tags"} | {"ip", "tag"}
FREE_TEXT_FIELDS = ("message", "raw", "username", "hostname", "source_ip", "command_line", "event_id", "target_username")

_TOKEN = re.compile(
    r"""\s*(?:
        (?P<str>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')
      | (?P<op>!=|>=|<=|[:=<>])
      | (?P<punct>[()|,])
      | (?P<word>[^\s()|,:=<>!"']+)
    )""",
    re.VERBOSE,
)

Predicate = Callable[[NormalizedEvent], bool]


class QueryError(ValueError):
    def __init__(self, message: str, position: int | None = None):
        super().__init__(message if position is None else f"{message} (at character {position + 1})")
        self.position = position


@dataclass
class Token:
    kind: str  # str | op | punct | word | end
    value: str
    pos: int


@dataclass
class Query:
    predicate: Predicate
    stats_by: list[str] | None = None
    sort: tuple[str, bool] | None = None  # field, descending
    head: int | None = None
    fields_used: set[str] = field(default_factory=set)


def tokenize(text: str) -> list[Token]:
    tokens: list[Token] = []
    pos = 0
    text = text.rstrip()
    while pos < len(text):
        match = _TOKEN.match(text, pos)
        if not match or match.end() == pos:
            raise QueryError(f"unexpected character {text[pos]!r}", pos)
        kind = match.lastgroup or "word"
        value = match.group(kind)
        if kind == "str":
            value = re.sub(r"\\(.)", r"\1", value[1:-1])
        tokens.append(Token(kind, value, match.start(kind)))
        pos = match.end()
    tokens.append(Token("end", "", len(text)))
    return tokens


def resolve_field(name: str, pos: int) -> str:
    key = ALIASES.get(name.lower(), name.lower())
    if key.startswith("fields."):
        return key
    if key not in FIELDS:
        raise QueryError(f"unknown field '{name}'", pos)
    return key


def field_values(event: NormalizedEvent, name: str) -> list[Any]:
    if name == "ip":
        return [event.source_ip, event.destination_ip]
    if name == "tag":
        return list(event.tags)
    if name.startswith("fields."):
        return [event.fields.get(name[7:])]
    value = getattr(event, name)
    return [value.value if hasattr(value, "value") and not isinstance(value, datetime) else value]


def _compare(actual: Any, op: str, expected: str) -> bool:
    if actual is None:
        return op == "!=" and expected != ""
    if op in (":", "=", "!="):
        text = actual.isoformat() if isinstance(actual, datetime) else str(actual)
        hit = (
            fnmatch.fnmatchcase(text.lower(), expected.lower()) if "*" in expected or "?" in expected else text.lower() == expected.lower()
        )
        return not hit if op == "!=" else hit
    # Ordering comparisons: numbers numerically, timestamps chronologically, otherwise as text.
    try:
        if isinstance(actual, datetime):
            left: Any = actual
            right: Any = datetime.fromisoformat(expected.replace("Z", "+00:00"))
            if right.tzinfo is None:
                raise QueryError(f"timestamp '{expected}' needs a timezone, e.g. 2026-10-30T12:00:00Z")
        elif isinstance(actual, int | float):
            left, right = actual, float(expected)
        else:
            left, right = str(actual).lower(), expected.lower()
    except ValueError as exc:
        raise QueryError(f"cannot compare with '{expected}'") from exc
    return {">": left > right, ">=": left >= right, "<": left < right, "<=": left <= right}[op]


class _Parser:
    def __init__(self, tokens: list[Token]):
        self.tokens = tokens
        self.i = 0
        self.fields_used: set[str] = set()

    @property
    def tok(self) -> Token:
        return self.tokens[self.i]

    def keyword(self, *words: str) -> bool:
        return self.tok.kind == "word" and self.tok.value.upper() in words

    def take(self) -> Token:
        token = self.tokens[self.i]
        self.i += 1
        return token

    def expect_word(self, what: str) -> Token:
        if self.tok.kind not in ("word", "str"):
            raise QueryError(f"expected {what}", self.tok.pos)
        return self.take()

    def parse(self) -> Query:
        predicate: Predicate = lambda e: True  # noqa: E731
        if not (self.tok.kind == "end" or (self.tok.kind == "punct" and self.tok.value == "|")):
            predicate = self.expr()
        query = Query(predicate=predicate)
        while self.tok.kind == "punct" and self.tok.value == "|":
            self.take()
            self.pipe(query)
        if self.tok.kind != "end":
            raise QueryError(f"unexpected '{self.tok.value}'", self.tok.pos)
        query.fields_used = self.fields_used
        return query

    def expr(self) -> Predicate:
        parts = [self.conj()]
        while self.keyword("OR"):
            self.take()
            parts.append(self.conj())
        return parts[0] if len(parts) == 1 else (lambda e: any(p(e) for p in parts))

    def conj(self) -> Predicate:
        parts = [self.unary()]
        while True:
            if self.keyword("AND"):
                self.take()
            elif self.tok.kind == "end" or self.keyword("OR") or (self.tok.kind == "punct" and self.tok.value in ")|"):
                break
            parts.append(self.unary())
        return parts[0] if len(parts) == 1 else (lambda e: all(p(e) for p in parts))

    def unary(self) -> Predicate:
        if self.keyword("NOT") or (self.tok.kind == "word" and self.tok.value == "-"):
            self.take()
            inner = self.unary()
            return lambda e: not inner(e)
        if self.tok.kind == "word" and self.tok.value.startswith("-") and len(self.tok.value) > 1:
            token = self.take()
            self.tokens.insert(self.i, Token("word", token.value[1:], token.pos + 1))
            inner = self.unary()
            return lambda e: not inner(e)
        if self.tok.kind == "punct" and self.tok.value == "(":
            start = self.take().pos
            inner = self.expr()
            if not (self.tok.kind == "punct" and self.tok.value == ")"):
                raise QueryError("missing ')'", start)
            self.take()
            return inner
        return self.term()

    def term(self) -> Predicate:
        token = self.expect_word("a search term")
        if self.tok.kind == "op" and token.kind == "word":
            name = resolve_field(token.value, token.pos)
            op = self.take().value
            value = self.expect_word(f"a value after '{op}'").value
            self.fields_used.add(name)
            return lambda e: (
                any(_compare(v, op, value) for v in field_values(e, name))
                if op != "!="
                else all(_compare(v, op, value) for v in field_values(e, name))
            )
        needle = token.value.lower().replace("*", "")
        return lambda e: any(needle in str(getattr(e, f) or "").lower() for f in FREE_TEXT_FIELDS)

    def pipe(self, query: Query) -> None:
        start = self.tok.pos
        if self.keyword("STATS"):
            self.take()
            if not self.keyword("COUNT"):
                raise QueryError("only 'stats count by <field>' is supported", self.tok.pos)
            self.take()
            if not self.keyword("BY"):
                raise QueryError("expected 'by' after 'stats count'", self.tok.pos)
            self.take()
            fields = [resolve_field(self.expect_word("a field").value, start)]
            while self.tok.kind == "punct" and self.tok.value == ",":
                self.take()
                fields.append(resolve_field(self.expect_word("a field").value, start))
            query.stats_by = fields
        elif self.keyword("SORT"):
            self.take()
            raw = self.expect_word("a field to sort by").value
            descending = raw.startswith("-")
            name = raw.lstrip("-+")
            if name.lower() != "count":
                name = resolve_field(name, start)
            if self.keyword("DESC", "ASC"):
                descending = self.take().value.upper() == "DESC"
            query.sort = (name.lower() if name.lower() == "count" else name, descending)
        elif self.keyword("HEAD", "LIMIT"):
            self.take()
            value = self.expect_word("a number").value
            if not value.isdigit() or not 0 < int(value) <= 10_000:
                raise QueryError("head expects a number between 1 and 10000", start)
            query.head = int(value)
        else:
            raise QueryError("unknown command after '|' (use stats, sort or head)", start)


def parse(text: str) -> Query:
    if len(text) > MAX_QUERY_LENGTH:
        raise QueryError(f"query longer than {MAX_QUERY_LENGTH} characters")
    return _Parser(tokenize(text)).parse()


@dataclass
class QueryResult:
    mode: str  # events | stats
    events: list[NormalizedEvent] = field(default_factory=list)
    columns: list[str] = field(default_factory=list)
    rows: list[dict[str, Any]] = field(default_factory=list)
    scanned: int = 0


def _sort_key(value: Any) -> tuple[int, Any]:
    if value is None:
        return (1, "")
    return (0, value if isinstance(value, int | float | datetime) else str(value).lower())


def execute(query: Query, events: list[NormalizedEvent]) -> QueryResult:
    matched = [e for e in events if query.predicate(e)]
    if query.stats_by:
        counts: Counter[tuple[Any, ...]] = Counter(tuple(field_values(e, f)[0] for f in query.stats_by) for e in matched)
        rows = [{**dict(zip(query.stats_by, key, strict=True)), "count": n} for key, n in counts.items()]
        sort_field, descending = query.sort or ("count", True)
        if sort_field not in (*query.stats_by, "count"):
            raise QueryError(f"after stats you can only sort by count or {', '.join(query.stats_by)}")
        rows.sort(key=lambda r: _sort_key(r.get(sort_field)), reverse=descending)
        return QueryResult("stats", columns=[*query.stats_by, "count"], rows=rows[: query.head or None], scanned=len(events))

    sort_field, descending = query.sort or ("timestamp", True)
    if sort_field == "count":
        raise QueryError("'sort count' needs a 'stats count by' first")
    matched.sort(key=lambda e: _sort_key(field_values(e, sort_field)[0]), reverse=descending)
    return QueryResult("events", events=matched[: query.head or None], scanned=len(events))
