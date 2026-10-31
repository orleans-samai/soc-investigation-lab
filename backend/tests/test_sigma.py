from __future__ import annotations

import yaml

from app.detection import sigma
from app.detection.threat_intel import ThreatIntelFeed
from tests.conftest import BACKEND


def test_every_rule_exports_valid_sigma(engine):
    feed = ThreatIntelFeed.load(BACKEND / "data" / "threat_intel.json")
    ids, names = set(), set()
    for rule in engine.rules:
        docs = sigma.rule_documents(rule, rule.defaults(), feed)
        assert docs, f"{rule.id} has no Sigma export"
        parsed = list(yaml.safe_load_all(sigma.to_yaml(docs)))
        for doc in parsed:
            assert doc["id"] not in ids
            ids.add(doc["id"])
            assert doc["name"] not in names
            names.add(doc["name"])
            assert doc["level"] in {"low", "medium", "high", "critical"}
            assert any(t.startswith("attack.t") for t in doc["tags"])
            if "correlation" in doc:
                assert set(doc["correlation"]["rules"]) <= names, "correlations must reference rules defined before them"
            else:
                assert doc["logsource"] and "condition" in doc["detection"]


def test_export_uses_tuned_parameters(client):
    client.patch("/api/rules/LAB-001", json={"params": {"threshold": 15}})
    docs = list(yaml.safe_load_all(client.get("/api/rules/LAB-001/sigma").text))
    assert docs[1]["correlation"] == {
        "type": "event_count",
        "rules": ["lab001_ssh_failed_password"],
        "group-by": ["src_ip", "host"],
        "timespan": "5m",
        "condition": {"gte": 15},
    }
    bundle = client.get("/api/rules/sigma.yml")
    assert bundle.headers["content-disposition"].startswith("attachment") and len(list(yaml.safe_load_all(bundle.text))) > 17
