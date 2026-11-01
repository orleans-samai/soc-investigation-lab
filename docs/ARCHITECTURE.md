# Architecture

## Data flow

```mermaid
flowchart LR
    subgraph Sources
        A1[Windows JSON<br/>4624, 4625, 4688, 4720...]
        A2[Linux auth.log<br/>sshd, sudo, useradd...]
        A3[Normalized JSON]
        A4[Simulation scenarios<br/>raw log templates]
    end
    A1 & A2 & A3 --> P[Parsers<br/>app/parsers]
    A4 -->|rendered raw logs| P
    P -->|NormalizedEvent<br/>deterministic id = sha256 source+raw| S[(Event store)]
    S --> E[Detection engine<br/>app/detection]
    INV[Asset & identity<br/>inventory] --> E
    E -->|Alert<br/>fingerprint-based id| C[Correlation<br/>app/services/lab.py]
    C --> I[(Incidents)]
    I --> R[Reports<br/>JSON / Markdown]
    S & I & E --> API[FastAPI /api]
    API --> UI[Next.js UI]
```

1. **Ingestion** - files (`POST /api/imports`) and simulations both end up as raw text that goes through the *same* parsers.
   Parsers only use regular expressions and `json.loads`; nothing in a file is ever evaluated or executed.
2. **Normalization** - every source maps to `NormalizedEvent` (`backend/app/models/events.py`). The raw record is preserved
   verbatim. The event id is `sha256(source + raw)`, so re-importing the same file cannot create duplicates.
3. **Detection** - `DetectionEngine.run(events, config)` evaluates every enabled rule over the time-sorted events. Rules are
   stateless and return `AlertDraft`s; the engine turns them into `Alert`s whose id is derived from
   `rule_id | group key | first event id`. Re-running detection therefore *updates* an alert when its burst grows instead of
   duplicating it, and analyst state (status, notes) is kept.
4. **Correlation** - new alerts join an open incident when they share an account or source IP within 2 h, or the same host
   within 20 min. High/critical alerts open incidents automatically; medium/low alerts wait in the triage queue (or join an
   incident that already exists), which mirrors a real N1 workflow.
5. **Investigation & reporting** - incidents carry entities, ATT&CK techniques, notes, classification and resolution. Closing
   requires both a classification and a written resolution. Reports are generated on demand from the stored state.

## Backend layout

| Path | Responsibility |
|---|---|
| `app/models/` | Pydantic models - the API contract and the persisted schema |
| `app/parsers/` | Windows JSON, Linux auth.log and normalized parsers + format detection |
| `app/detection/` | Rule base classes, the 18 built-in rules, the Sigma compiler for custom rules (`sigma_rules.py`), the engine, inventory, threat-intel feed, Sigma export and MITRE catalog |
| `app/simulation/` | Scenario rendering and the deterministic baseline generator |
| `app/services/` | Orchestration (`lab.py`), queries, analytics, entities, reports, ingestion, regression testing, shift mode, scenario authoring |
| `app/storage/` | SQLite and JSON persistence behind in-memory repositories |
| `app/api/` | FastAPI routers (OpenAPI at `/docs`) |
| `data/` | Read-only reference data: seed events, scenarios, inventory, ATT&CK subset |

## The purple-team loop

Three services close the loop between investigating and fixing detections. None of them has its own engine: they reuse the
parsers, the scenario renderer and `DetectionEngine`, so what they report is what the lab would actually do.

* **Regression testing** (`services/regression.py`, `POST /api/detection/regression`). Every scenario is rendered with fixed seeds
  (1 and 99) on top of the baseline week, then evaluated with the rule configuration in force and with the candidate changes.
  Only the changed rules are re-run for the candidate. Attack scenarios are graded `detected / regressed / fixed / missed`, benign
  ones `noise_reduced / noise_added / unchanged`, and baseline alerts per rule are compared. The gate fails on any regression.
  Nothing is written to the lab; rendered scenarios are cached per lab instance.
* **Custom Sigma rules** (`detection/sigma_rules.py`, `/api/rules/custom`). Sigma YAML is compiled into a `SigmaRule` that
  subclasses `Rule`, so it is tuned, toggled, backtested, regression-tested and exported like a built-in rule. An
  `event_count`/`value_count` correlation becomes the `threshold` and `window_minutes` parameters. Field names are resolved through an
  alias table (Windows/Sigma names to normalized fields), then `fields` (raw EventData in snake_case).
* **Shift mode** (`services/shifts.py`, `/api/shifts`). Starting a shift runs two attack and two noise scenarios through the normal
  simulation path and queues their alerts. Ground truth (`Scenario.expected_verdict`) never leaves the server until the shift
  ends. Each alert scores accuracy (6), speed against a severity SLA (2) and note quality (2).
* **Scenario authoring** (`services/authoring.py`, `/api/simulations/scenarios`). A Log Explorer query selects up to 500 events,
  which become `normalized_json` steps with their original relative offsets. Literal braces are escaped (`{{ }}`) so only `{ts}` is
  substituted, and each replay prefixes the raw text with its timestamp so event ids stay unique. Optional anonymization maps
  accounts, hosts and IPs to stable pseudonyms in every field, including the raw text. The answer key (expected rules, severity,
  ATT&CK) comes from replaying the draft through the engine.

Authored content (custom rules and scenarios) is stored in its own collections and survives a lab reset.

## Persistence

* Default backend: **SQLite** (`state/lab.db`, WAL journal). Each collection item is a JSON document keyed by
  (collection, key). On save, only rows whose serialized form changed since the last save are written, in one transaction
  per collection; events are append-only, so only new event ids are inserted.
* Alternative backend: one JSON file per collection (`SOCLAB_STORAGE_BACKEND=json`), written temp file -> fsync -> `os.replace`.
* State written by the JSON backend is migrated into SQLite automatically on first start (originals kept in `state/json-backup/`).
* Unreadable files or databases are quarantined (`*.corrupt-<ts>`) and the lab starts clean; the status endpoint reports it.
* All mutations go through `LabService` while holding one re-entrant lock. Services only use `LabStore`/`Collection`
  methods, so a PostgreSQL backend means implementing the small `_Backend` protocol in `app/storage/repository.py`.

## Time model

All timestamps are stored and displayed in UTC. The **simulation clock** is the timestamp of the most recent event; dashboard
ranges ("last 24h") are relative to it, so the seed dataset always looks "live". Business-hours rules evaluate local time in
`SOCLAB_LAB_TIMEZONE` (default `America/Sao_Paulo`). Classic syslog lines (no year, no offset) are interpreted with the year and
timezone chosen at import, with year-rollover protection.

## Frontend

Next.js App Router (all pages are client components fed by SWR). The Next server proxies `/api/*` to FastAPI, so the browser
talks to a single origin. Design tokens live in `src/app/globals.css` (dark theme first, light theme mirrored); severity colours
are reserved for severity, and chart colours were validated for colour-vision deficiency in both themes.

## Desktop distribution

```mermaid
flowchart LR
    E[Electron main process<br/>desktop/main.js] -->|spawn, 127.0.0.1:47321| S[soclab-server<br/>PyInstaller bundle]
    S -->|serves| UI[Exported Next.js UI<br/>resources/web]
    S -->|/api| API[FastAPI]
    S -->|writes| D[(userData/state)]
    E -->|BrowserWindow| UI
```

* `NEXT_OUTPUT=export` builds the UI as static files; detail pages use `?id=` so no Node.js server is needed.
* `backend/soclab_server.py` is the bundle's entry point: it picks a free port, prints `SOCLAB_LISTENING <url>`, and runs
  uvicorn with `SOCLAB_STATIC_DIR` mounted at `/` (after `/api` and `/docs`).
* Electron waits for `/api/health`, then loads the URL. External links open in the system browser; the server is killed
  when the app quits. Lab state lives in the per-user data folder, never in the install directory.
* `.github/workflows/release.yml` builds on `windows-latest` and `ubuntu-latest` (PyInstaller cannot cross-compile),
  smoke-tests the bundled server, and attaches the NSIS installer, AppImage and .deb to a GitHub Release.

## Security considerations

* Uploads: size limit, line limit, UTF-8 only, NUL-byte rejection, per-line errors, no execution of content.
* CSV export neutralises spreadsheet formula injection (`=`, `+`, `-`, `@` prefixes).
* PowerShell `-EncodedCommand` payloads are decoded *as text* for the analyst, never run.
* Destructive operations (lab reset) require an explicit confirmation token and a confirmation dialog.
* Containers run as non-root users; ports are bound to `127.0.0.1` in Compose.
* No authentication: the MVP is a single-user local lab. Do not expose it to a network.
