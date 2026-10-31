"""File imports and simulation runs: the two ways new telemetry enters the lab."""

from __future__ import annotations

import random
import re
import uuid
from datetime import timedelta
from pathlib import PurePath
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from app.detection.inventory import MaintenanceWindow
from app.models.imports import ImportRecord, ImportReport, LogFormat
from app.models.simulations import SimulationRun
from app.parsers import ParseOptions, UnsupportedFormatError, detect_format, parse_text
from app.services.lab import LabService
from app.simulation.scenarios import choose_start, render


class ImportRejectedError(ValueError):
    pass


def _safe_name(filename: str) -> str:
    name = PurePath(filename or "upload").name
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)[:80] or "upload"


def decode_upload(content: bytes, max_lines: int) -> str:
    if b"\x00" in content[:8192]:
        raise ImportRejectedError("file looks binary (contains NUL bytes); only UTF-8 text logs are accepted")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ImportRejectedError(f"file is not valid UTF-8 (byte offset {exc.start})") from exc
    if text.count("\n") > max_lines:
        raise ImportRejectedError(f"file has more than {max_lines} lines")
    return text


def import_file(
    lab: LabService,
    content: bytes,
    filename: str,
    fmt: LogFormat,
    timezone: str,
    year: int | None,
    dry_run: bool,
) -> ImportReport:
    name = _safe_name(filename)
    text = decode_upload(content, lab.settings.max_import_lines)
    try:
        tz = ZoneInfo(timezone)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ImportRejectedError(f"unknown timezone {timezone!r}") from exc
    try:
        resolved = detect_format(text, name) if fmt == LogFormat.auto else fmt
    except UnsupportedFormatError as exc:
        raise ImportRejectedError(str(exc)) from exc

    import_id = "imp_" + uuid.uuid4().hex[:10]
    options = ParseOptions(dataset=f"import:{name}", timezone=tz, year=year, reference_time=lab.clock())
    result = parse_text(text, resolved, options, name)

    unique = {}
    duplicates = 0
    with lab.store.lock:
        for event in result.events:
            if event.id in unique or event.id in lab.store.events:
                duplicates += 1
            else:
                unique[event.id] = event
        timestamps = sorted(e.timestamp for e in result.events)
        report = ImportReport(
            import_id=None if dry_run else import_id,
            filename=name,
            format=resolved,
            dry_run=dry_run,
            size_bytes=len(content),
            total_records=result.total_records,
            parsed=len(result.events),
            added=len(unique),
            duplicates=duplicates,
            skipped=result.skipped,
            errors=result.errors,
            error_count=result.error_count,
            first_timestamp=timestamps[0] if timestamps else None,
            last_timestamp=timestamps[-1] if timestamps else None,
            preview=list(unique.values())[:25] or result.events[:25],
        )
        if dry_run or not unique:
            return report

        lab.ingest(list(unique.values()))
        detection = lab.detect()
        report.alerts_created = len(detection.new_alerts)
        report.incidents_touched = detection.incidents
        lab.store.imports.upsert(
            ImportRecord(
                id=import_id,
                filename=name,
                format=resolved,
                size_bytes=len(content),
                total_records=result.total_records,
                parsed=len(result.events),
                added=len(unique),
                duplicates=duplicates,
                skipped=result.skipped,
                error_count=result.error_count,
                alerts_created=len(detection.new_alerts),
            )
        )
        lab.log(
            "analyst",
            "import.committed",
            f"Imported {len(unique)} events from {name} ({resolved.value}); {len(detection.new_alerts)} new alerts",
            "import",
            import_id,
        )
        lab.store.persist_all()
    return report


def run_simulation(lab: LabService, scenario_id: str, seed: int | None) -> SimulationRun:
    scenario = lab.scenarios[scenario_id]
    seed = seed if seed is not None else random.SystemRandom().randrange(1, 2**31)
    rng = random.Random(seed)
    with lab.store.lock:
        start = choose_start(scenario, lab.clock(), rng, lab.timezone)
        run_id = "sim_" + uuid.uuid4().hex[:8]
        rendered = render(scenario, start, seed, dataset=f"simulation:{run_id}")
        if scenario.maintenance_window:
            mw = scenario.maintenance_window
            rendered.variables["change_id"] = f"CHG-{rng.randint(2100, 2999)}"
            lab.add_maintenance_window(
                MaintenanceWindow(
                    id=rendered.variables["change_id"],
                    description=mw.description,
                    usernames=mw.usernames,
                    hosts=mw.hosts,
                    start=start - timedelta(minutes=15),
                    end=start + timedelta(minutes=mw.duration_minutes),
                )
            )
        ingest = lab.ingest(rendered.events)
        detection = lab.detect()
        run_events = {e.id for e in ingest.added}
        related = [a for a in detection.new_alerts + detection.updated_alerts if run_events & set(a.event_ids)]
        triggered = sorted({a.rule_id for a in related})
        incident_ids = sorted({a.incident_id for a in related if a.incident_id})
        run = SimulationRun(
            id=run_id,
            scenario_id=scenario.id,
            scenario_name=scenario.name,
            seed=seed,
            benign=scenario.benign,
            simulated_start=rendered.start,
            simulated_end=rendered.end,
            event_count=len(ingest.added),
            event_ids=[e.id for e in ingest.added],
            alert_ids=[a.id for a in related],
            incident_ids=incident_ids,
            expected_rules=scenario.expected_rules,
            triggered_rules=triggered,
            missed_rules=sorted(set(scenario.expected_rules) - set(triggered)),
            unexpected_rules=sorted(set(triggered) - set(scenario.expected_rules)),
            variables=rendered.variables,
        )
        lab.store.simulation_runs.upsert(run)
        outcome = "all expected detections fired" if not run.missed_rules else f"missed {', '.join(run.missed_rules)}"
        lab.log("analyst", "simulation.run", f"Ran scenario '{scenario.name}' ({len(ingest.added)} events, {len(related)} alerts): {outcome}",
                "simulation", run_id)  # fmt: skip
        lab.store.persist_all()
    return run
