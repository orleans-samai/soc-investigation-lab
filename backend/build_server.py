"""Bundle the backend into a self-contained executable folder with PyInstaller.

Run from backend/ with the project's virtualenv:  python build_server.py
Output: backend/dist/soclab-server/soclab-server(.exe)
PyInstaller cannot cross-compile: build on Windows for Windows and on Linux for Linux.
"""

from __future__ import annotations

import os
from pathlib import Path

import PyInstaller.__main__

HERE = Path(__file__).resolve().parent


def main() -> None:
    PyInstaller.__main__.run(
        [
            str(HERE / "soclab_server.py"),
            "--name=soclab-server",
            "--onedir",  # faster start-up than --onefile (no unpacking on every launch)
            "--noconfirm",
            "--clean",
            f"--distpath={HERE / 'dist'}",
            f"--workpath={HERE / 'build'}",
            f"--specpath={HERE / 'build'}",
            f"--add-data={HERE / 'data'}{os.pathsep}data",
            "--collect-submodules=uvicorn",
            "--collect-submodules=app",
            "--collect-data=tzdata",  # Windows has no system zoneinfo database
            "--exclude-module=pytest",
            "--exclude-module=tkinter",
        ]
    )


if __name__ == "__main__":
    main()
