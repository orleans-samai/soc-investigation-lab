from __future__ import annotations

import json

from app.models.incidents import Activity
from app.storage.json_store import JsonCollectionFile, atomic_write_json


def test_atomic_write_leaves_no_temp_files(tmp_path):
    target = tmp_path / "data.json"
    atomic_write_json(target, {"a": 1})
    atomic_write_json(target, {"a": 2})
    assert json.loads(target.read_text()) == {"a": 2}
    assert [p.name for p in tmp_path.iterdir()] == ["data.json"]


def test_roundtrip_with_envelope(tmp_path):
    file = JsonCollectionFile(tmp_path / "activity.json", "activity")
    file.save([Activity(id="1", actor="a", action="x", message="m")], {"seq": 3})
    envelope = json.loads((tmp_path / "activity.json").read_text())
    assert envelope["schema_version"] == 1 and envelope["collection"] == "activity"
    loaded = file.load(Activity)
    assert loaded.items[0].id == "1" and loaded.meta == {"seq": 3} and not loaded.recovered


def test_corrupt_file_is_quarantined(tmp_path):
    path = tmp_path / "alerts.json"
    path.write_text('{"items": [ truncated')
    loaded = JsonCollectionFile(path, "alerts").load(Activity)
    assert loaded.recovered and loaded.items == []
    assert not path.exists()
    assert any(p.name.startswith("alerts.corrupt-") for p in tmp_path.iterdir())


def test_invalid_records_are_skipped(tmp_path):
    path = tmp_path / "activity.json"
    path.write_text(json.dumps({"items": [{"id": "ok", "actor": "a", "action": "x", "message": "m"}, {"id": "broken"}]}))
    loaded = JsonCollectionFile(path, "activity").load(Activity)
    assert [a.id for a in loaded.items] == ["ok"] and loaded.skipped == 1
