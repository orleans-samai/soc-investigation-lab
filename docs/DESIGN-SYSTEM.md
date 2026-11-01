# Design system

The interface of SOC Investigation Lab follows one idea, the **signal chain**: telemetry becomes detections, detections
become incidents, incidents end as documented decisions. That sequence is the product's thesis, so it is also the main
visual device: the Overview opens with it, the simulation result repeats it, and the navigation is ordered by it.

Everything else stays quiet so the chain, the data and the severity levels carry the page.

Source of truth: `frontend/src/app/globals.css` (tokens) and `frontend/src/components/` (components).

## Tokens

Components use **semantic tokens only** (`bg-surface`, `text-muted`, `border-border`...). Raw hex values live in
`globals.css` and nowhere else; a light theme mirrors every dark value.

### Colour

| Token | Dark | Light | Use |
|---|---|---|---|
| `background` | `#0f1216` | `#f3f5f8` | Page. Graphite with a blue cast, not void black |
| `surface` | `#151920` | `#ffffff` | Panels, sidebar, table body |
| `surface-2` | `#1b2029` | `#eef1f5` | Hover, selected rows, inset areas |
| `elevated` | `#212733` | `#ffffff` | Menus, dialogs, active segment |
| `border` / `border-strong` | `#252b36` / `#343c4a` | `#dde2ea` / `#c6cdd8` | Dividers / controls and nodes |
| `foreground` / `muted` / `subtle` | `#e4e8ee` / `#9da6b5` / `#7b8596` | `#12161d` / `#535d6e` / `#66707f` | Ink, secondary text, meta |
| `primary` | `#7aa2ff` | `#2557c9` | Text-safe blue: links, active icons, focus ring |
| `action` / `action-hover` | `#3a6ce0` / `#4a7bee` | `#2557c9` / `#1e49ad` | Solid blue behind white text (primary button only) |
| `critical` `high` `medium` `low` | `#f25a5e` `#f2913f` `#e2b53e` `#8794aa` | `#cc2f35` `#c25e10` `#946c00` `#5f6b7f` | Severity, and nothing else |
| `success` | `#46b985` | `#1e8150` | Successful outcome, benign verdict |
| `chart-1` / `chart-2` | `#3987e5` / `#d55181` | `#2a78d6` / `#e87ba4` | Two-series charts (CVD-validated pair). `chart-2` = failures / true positives |

Rules:

* Severity colours never decorate. A count of alerts is ink, not orange.
* Text wears text tokens. Colour sits in a notch, dot or bar next to the label.
* Tints have three levels only: `/8` wash, `/14` fill, `/30` outline.
* The hatched `hatch` utility marks synthetic data and is used once: the Simulation indicator.

### Type

| Role | Face | Where |
|---|---|---|
| Interface | IBM Plex Sans 400/500/600 | Everything by default |
| Display | IBM Plex Sans Condensed 600 | Page and record titles, signal-chain figures, stat values. Never body text |
| Data and labels | IBM Plex Mono 400/500 | IDs, IPs, timestamps, counts, column heads, `eyebrow` labels |

Fonts ship with the app (`@fontsource`), so the desktop build works offline.

Seven sizes, defined in `@theme`: `text-2xs` 11 · `text-xs` 12 · `text-sm` 13 (default) · `text-base` 14 · `text-lg` 16 ·
`text-xl` 22 · `text-2xl` 32. Arbitrary sizes (`text-[13px]`) are not allowed.

`eyebrow` (utility): mono, 11 px, uppercase, `0.06em` tracking, `subtle`. Used for section names, table column heads and
stage names. It replaced 16 copies of the same class string.

### Shape and depth

* Radius: `rounded-sm` 3 px (chips), `rounded-md` 5 px (controls, panels), `rounded-lg` 7 px (dialogs), `rounded-full` (dots).
* Elevation: `shadow-raised` (selected segment) and `shadow-overlay` (menus, dialogs, sheets). Panels sit flat on a border.
* Spacing follows Tailwind's 4 px scale; panels use 16 px (`p-4`) inside and 16 px (`gap-4`) between.
* Z order: content < sticky header (`z-20`) < sidebar (`z-30`) < overlay (`z-40`) < dialog and tooltip (`z-50`).

## Components

| Component | File | Use | Don't |
|---|---|---|---|
| `SignalChain` | `soc/signal-chain.tsx` | The four-stage pipeline with conversions and composition bars. `compact` for in-panel use | Generic KPI rows: use `Stat` |
| `SeverityBadge` | `soc/badges.tsx` | Severity of an alert, rule or incident. Coloured notch + mono label; critical gets a wash | Anything that isn't severity |
| `StatusBadge` | `soc/badges.tsx` | Workflow state. Shape encodes progress: ring = new, half = in progress, disc = decided | Severity |
| `Tag` | `soc/badges.tsx` | Neutral metadata (category, level, technique) | Status or severity |
| `Button` | `ui/button.tsx` | `primary` (one per view), `secondary`, `ghost`, `outline`, `danger` | A link that navigates without acting: use `Link` |
| `Panel` + `PanelHeader` | `ui/primitives.tsx` | The only container surface | Nested panels |
| `PageHeader` | `soc/common.tsx` | Title (display face) + one-sentence description + page actions | Marketing copy |
| `Stat` | `soc/common.tsx` | Single figure with an eyebrow label | The Overview, which uses the chain |
| `tableCls` + `SortHeader` | `soc/common.tsx` | Every data table; heads use the eyebrow voice | Ad-hoc table styling |
| `Segmented` | `soc/common.tsx` | 2-4 mutually exclusive views (time range, mode) | More than four options: use `Select` |
| `EmptyState` / `ErrorState` | `soc/common.tsx` | Tell the user what to do next | Apologies or vague errors |
| `Term` | `soc/common.tsx` | Dotted-underline glossary tooltip for SOC jargon | Decoration |

## Navigation

The sidebar lists the pipeline stages in data-flow order, joined by a wire: **1 Ingest → 2 Detect → 3 Respond → 4 Report**,
with live counts (events, enabled rules, open alerts, open incidents). The numbers match the stage numbers on the
Overview's signal chain. Overview sits above the chain; lab maintenance (activity log, settings) sits at the bottom.

## Motion

One orchestrated moment: the signal-chain stages arrive left to right (70 ms stagger, 220 ms). Everything else is a
100-150 ms colour transition. `prefers-reduced-motion` disables all of it.

## Writing

Sentence case everywhere ("Detection rules", not "Detection Rules"). Page descriptions are one sentence about what the
user can do on the page. Buttons say what happens ("Run a scenario", "Close incident"), errors say what to fix.

## Migration log (this redesign)

* 13 font sizes → 7; 5 radii → 4; 8 tint levels → 3; 6 ad-hoc shadows → 2 tokens.
* Geist replaced by IBM Plex Sans / Condensed / Mono.
* `SeverityBadge` and `StatusBadge` redrawn; `Tag` no longer fills.
* KPI grid on the Overview replaced by `SignalChain`; the simulation result reuses it (`compact`).
* Primary button moved from `bg-primary` to the `action` token so blue text and blue fills can differ in contrast.

## Purple-team surfaces (differentiation release)

* **Regression report** (`soc/regression-report.tsx`) - the gate verdict sits first (one line, `success` or `critical` wash), then
  four before/after figures, then the per-scenario table. A change is shown as `before → after` with the old value struck through;
  the new value turns `success` only when it moved in the good direction (more attacks, less noise). A failed gate is the one
  non-severity use of `critical`, the same as destructive buttons: it means "this would let an attack through".
* **Shift** (`app/shift/page.tsx`) - the countdown is the page's only display-size figure; it turns `critical` in the last minute.
  The queue reuses the rules list pattern (selected row = inset primary bar). Verdicts are three large radio cards, not a select,
  because the choice is the whole task.
* **Sigma editor** and **scenario builder** open as sheets (`max-w-3xl`) from the page that owns the data, validate before they
  save (the save button stays disabled until a dry-run/preview succeeds) and show errors inline in a `critical/8` box, not as toasts.
