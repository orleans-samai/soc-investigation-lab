from __future__ import annotations

import json
from pathlib import Path

from app.models.common import ApiModel


class Tactic(ApiModel):
    id: str
    name: str


class Technique(ApiModel):
    id: str
    name: str
    tactics: list[str]

    @property
    def url(self) -> str:
        return "https://attack.mitre.org/techniques/" + self.id.replace(".", "/") + "/"


class MitreCatalog(ApiModel):
    source: str
    tactics: list[Tactic]
    techniques: list[Technique]

    @classmethod
    def load(cls, path: Path) -> MitreCatalog:
        with path.open(encoding="utf-8") as fh:
            return cls.model_validate(json.load(fh))

    def technique(self, technique_id: str) -> Technique | None:
        return next((t for t in self.techniques if t.id == technique_id), None)
