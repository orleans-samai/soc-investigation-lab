from __future__ import annotations

import pytest

from app.models.events import EventSource
from app.services.query import QueryError, execute, parse
from tests.conftest import ev

LINUX = EventSource.linux_auth
EVENTS = sorted(
    [
        *(ev("logon_failed", seconds=i, source=LINUX, hostname="bastion-01", username="root", source_ip="203.0.113.5") for i in range(5)),
        *(
            ev("logon_failed", seconds=10 + i, source=LINUX, hostname="bastion-01", username="admin", source_ip="198.51.100.7")
            for i in range(2)
        ),
        ev("logon_success", seconds=30, hostname="dc-01", username="j.silva", source_ip="10.10.10.21", logon_type=3),
        ev("process_created", seconds=40, hostname="ws-fin-01", username="j.silva", command_line="powershell -enc AAAA", logon_type=None),
    ],
    key=lambda e: e.timestamp,
)


def run(q: str):
    return execute(parse(q), EVENTS)


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("", 9),
        ("outcome:failure", 7),
        ("outcome:failure AND user:root", 5),
        ("user:root OR user:admin", 7),
        ("outcome:failure NOT ip:203.0.113.*", 2),
        ("outcome:failure -user:root", 2),
        ("(host:dc-01 OR host:ws-fin-01) user:j.silva", 2),
        ("cmd:*powershell*", 1),
        ("logon_type>=3", 1),
        ("user!=root outcome:failure", 2),
        ('"powershell -enc"', 1),
        ("action:LOGON_SUCCESS", 1),
        ("source:linux_auth | head 3", 3),
        ('timestamp>="2026-10-29T15:00:20Z"', 2),
    ],
)
def test_filters(query, expected):
    assert len(run(query).events) == expected


def test_stats_and_sort():
    result = run("outcome:failure | stats count by source_ip")
    assert result.mode == "stats" and result.columns == ["source_ip", "count"]
    assert result.rows[0] == {"source_ip": "203.0.113.5", "count": 5}
    assert run("outcome:failure | stats count by source_ip | sort count").rows[0]["count"] == 2
    assert [e.username for e in run("user:* | sort username | head 1").events] == ["admin"]


@pytest.mark.parametrize(
    "query",
    [
        "user:",
        "colour:red",
        "(user:root",
        "| frobnicate",
        "x | stats sum by user",
        "| head 0",
        "timestamp>yesterday",
        "| sort count",
        "a ! b",
    ],
)
def test_errors_are_reported(query):
    with pytest.raises(QueryError):
        run(query)


def test_query_endpoint(client):
    body = client.get("/api/events/query", params={"q": "outcome:failure host:bastion-01 | stats count by source_ip | head 3"}).json()
    assert body["mode"] == "stats" and len(body["rows"]) <= 3 and body["rows"][0]["count"] >= body["rows"][-1]["count"]
    events = client.get("/api/events/query", params={"q": "action:logon_success user:adm.roliveira", "page_size": 5}).json()
    assert events["mode"] == "events" and events["total"] > 0 and len(events["items"]) <= 5
    error = client.get("/api/events/query", params={"q": "nosuchfield:1"})
    assert error.status_code == 400 and "unknown field" in error.json()["detail"]
    exported = client.get("/api/events/export", params={"query": "user:adm.roliveira", "format": "json"}).json()
    assert exported and all(e["username"] == "adm.roliveira" or e["target_username"] == "adm.roliveira" for e in exported)
