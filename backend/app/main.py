from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app import __version__
from app.api import detection, events, investigation, shifts
from app.config import Settings, get_settings
from app.services.lab import LabService

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        lab = LabService(settings)
        lab.startup()
        app.state.lab = lab
        yield
        with lab.store.lock:
            lab.store.persist_all()
            lab.store.close()

    app = FastAPI(
        title="SOC Investigation Lab API",
        version=__version__,
        description=(
            "Security Operations & Incident Investigation Simulator. Ingests Windows/Linux logs, normalizes them, "
            "runs a rule-based detection engine mapped to MITRE ATT&CK, correlates alerts into incidents and "
            "produces investigation reports. **All data is synthetic (Simulation Mode).**"
        ),
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["GET", "POST", "PATCH"],
        allow_headers=["*"],
    )
    for module in (events, detection, investigation, shifts):
        app.include_router(module.router, prefix="/api")

    @app.get("/api/health", tags=["system"])
    def health():
        return {"status": "ok", "version": __version__}

    if settings.static_dir:
        if not (settings.static_dir / "index.html").is_file():
            raise RuntimeError(f"static_dir {settings.static_dir} does not contain an exported UI (index.html)")
        # Mounted last so /api and /docs keep priority; html=True serves <route>/index.html and 404.html.
        app.mount("/", StaticFiles(directory=settings.static_dir, html=True), name="ui")

    return app


app = create_app()
