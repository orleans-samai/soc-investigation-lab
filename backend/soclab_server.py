"""Standalone server entry point (used by the desktop app and the PyInstaller bundle).

soclab-server --port 47321 --state-dir <dir> --static-dir <frontend/out> [--open-browser]
"""

from __future__ import annotations

import argparse
import os
import socket
import threading
import webbrowser


def free_port(preferred: int, host: str) -> int:
    for port in (preferred, 0):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind((host, port))
            except OSError:
                continue
            return sock.getsockname()[1]
    raise RuntimeError("no free TCP port available")


def main() -> None:
    parser = argparse.ArgumentParser(prog="soclab-server", description="SOC Investigation Lab server")
    parser.add_argument("--host", default="127.0.0.1", help="interface to bind (keep 127.0.0.1: the lab has no authentication)")
    parser.add_argument("--port", type=int, default=47321)
    parser.add_argument("--state-dir", help="where lab state is written (default: per-user data directory)")
    parser.add_argument("--static-dir", help="exported UI to serve at / (frontend/out)")
    parser.add_argument("--open-browser", action="store_true", help="open the UI in the default browser once ready")
    args = parser.parse_args()

    # Settings are read from the environment, so set overrides before importing the app.
    if args.state_dir:
        os.environ["SOCLAB_STATE_DIR"] = args.state_dir
    if args.static_dir:
        os.environ["SOCLAB_STATIC_DIR"] = args.static_dir

    import uvicorn

    from app.config import Settings
    from app.main import create_app

    port = free_port(args.port, args.host)
    url = f"http://{args.host}:{port}/"
    if args.open_browser:
        threading.Timer(1.5, webbrowser.open, args=(url,)).start()
    # Machine-readable line the desktop shell waits for.
    print(f"SOCLAB_LISTENING {url}", flush=True)
    uvicorn.run(create_app(Settings()), host=args.host, port=port, log_level="info", access_log=False)


if __name__ == "__main__":
    main()
