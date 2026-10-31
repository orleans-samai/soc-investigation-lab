"""Runtime configuration loaded from environment variables (prefix ``SOCLAB_``)."""

from __future__ import annotations

import os
import sys
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

# In a PyInstaller bundle the package and its data files live under sys._MEIPASS.
BACKEND_ROOT = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
FROZEN = getattr(sys, "frozen", False)


def _default_state_dir() -> Path:
    if not FROZEN:
        return BACKEND_ROOT / "state"
    # Installed builds must never write next to the executable (e.g. Program Files).
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    else:
        base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return base / "soc-investigation-lab" / "state"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SOCLAB_", env_file=".env", extra="ignore")

    app_name: str = "SOC Investigation Lab"
    environment: str = "development"

    # Read-only reference data shipped with the project (seed events, scenarios, MITRE, inventory).
    data_dir: Path = BACKEND_ROOT / "data"
    # Mutable lab state (events, alerts, incidents...). Safe to delete: it is rebuilt from the seed.
    state_dir: Path = _default_state_dir()
    # Optional: exported Next.js UI (frontend/out) served at "/" so the app runs from a single origin.
    static_dir: Path | None = None

    # Timezone used to evaluate "business hours" and to interpret syslog lines without an offset.
    lab_timezone: str = "America/Sao_Paulo"
    business_hours_start: int = 7
    business_hours_end: int = 20

    max_upload_mb: float = 5.0
    max_import_lines: int = 50_000

    cors_origins: list[str] = ["http://localhost:3000", "http://127.0.0.1:3000"]

    @property
    def seed_dir(self) -> Path:
        return self.data_dir / "seed"

    @property
    def scenarios_dir(self) -> Path:
        return self.data_dir / "scenarios"

    @property
    def max_upload_bytes(self) -> int:
        return int(self.max_upload_mb * 1024 * 1024)


@lru_cache
def get_settings() -> Settings:
    return Settings()
