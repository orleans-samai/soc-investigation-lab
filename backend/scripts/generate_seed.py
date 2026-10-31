"""Regenerate data/seed/baseline_events.json (deterministic). Run from backend/: python -m scripts.generate_seed"""

from __future__ import annotations

from app.config import get_settings
from app.simulation.baseline import ANCHOR, generate_baseline
from app.storage.json_store import atomic_write_json


def main() -> None:
    settings = get_settings()
    events = generate_baseline()
    target = settings.seed_dir / "baseline_events.json"
    atomic_write_json(
        target,
        {
            "description": "Synthetic baseline: one week of normal activity for the fictional Lab Corp, plus two organic detections.",
            "anchor": ANCHOR.isoformat(),
            "events": [e.model_dump(mode="json") for e in events],
        },
    )
    print(f"wrote {len(events)} events to {target}")


if __name__ == "__main__":
    main()
