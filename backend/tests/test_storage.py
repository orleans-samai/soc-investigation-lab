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


def test_sqlite_writes_only_changed_rows(tmp_path, monkeypatch):
    from app.models.incidents import Activity
    from app.storage.repository import LabStore

    store = LabStore(tmp_path, "sqlite")
    store.load()
    for i in range(3):
        store.activity.upsert(Activity(id=f"a{i}", actor="x", action="y", message=f"m{i}"))
    store.persist_all()

    written: list[int] = []
    original = store._backend.db.save
    monkeypatch.setattr(store._backend.db, "save", lambda c, up, rm, meta: (written.append(len(up) + len(rm)), original(c, up, rm, meta)))
    store.activity.get("a1").message = "edited in place"  # services mutate objects directly
    store.activity.remove("a2")
    store.persist_all()
    assert written == [2]  # one update + one delete; untouched collections and rows are skipped

    reloaded = LabStore(tmp_path, "sqlite")
    reloaded.load()
    assert sorted(a.message for a in reloaded.activity.all()) == ["edited in place", "m0"]
    store.close()
    reloaded.close()


def test_corrupt_database_is_quarantined(tmp_path):
    from app.storage.repository import LabStore

    (tmp_path / "lab.db").write_bytes(b"this is not sqlite" * 100)
    store = LabStore(tmp_path, "sqlite")
    store.load()
    assert store.recovered_collections == ["database"] and len(store.events) == 0
    assert any(p.name.startswith("lab.corrupt-") for p in tmp_path.iterdir())
    store.close()


def test_json_state_is_migrated_to_sqlite(tmp_path):
    from app.models.incidents import Activity
    from app.storage.repository import LabStore

    legacy = LabStore(tmp_path, "json")
    legacy.load()
    legacy.activity.upsert(Activity(id="old", actor="x", action="y", message="from json"))
    legacy.events.meta["initialized"] = True
    legacy.persist_all()

    store = LabStore(tmp_path, "sqlite")
    store.load()
    assert store.migrated_from_json and store.is_initialized() and store.activity.get("old").message == "from json"
    assert (tmp_path / "json-backup" / "activity.json").exists() and not (tmp_path / "activity.json").exists()
    store.close()
