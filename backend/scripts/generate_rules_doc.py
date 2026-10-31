"""Regenerate docs/DETECTION_RULES.md from the rule classes. Run from backend/: python -m scripts.generate_rules_doc"""

from __future__ import annotations

from app.config import BACKEND_ROOT, get_settings
from app.detection.rules import builtin_rules
from app.simulation.scenarios import load_scenarios


def main() -> None:
    rules = builtin_rules()
    covered: dict[str, list[str]] = {}
    for scenario in load_scenarios(get_settings().scenarios_dir).values():
        for rule_id in scenario.expected_rules:
            covered.setdefault(rule_id, []).append(scenario.id)

    lines = [
        "# Detection Rules",
        "",
        "> Generated from the rule classes in `backend/app/detection/rules/` (`python -m scripts.generate_rules_doc`).",
        "> The code is the source of truth. Every rule can also be exported as Sigma YAML from the Detection Rules page",
        "> or `GET /api/rules/{id}/sigma`.",
        "",
        "Rules are pure functions of (events, parameters, inventory, threat-intel feed): no I/O and no global state. Each one",
        "has unit tests in `backend/tests/` and an end-to-end validation in `backend/tests/test_scenarios.py`.",
        "",
        "| ID | Rule | Type | Default severity | MITRE ATT&CK | Validated by scenario |",
        "|---|---|---|---|---|---|",
    ]
    for r in rules:
        techniques = ", ".join(m.technique_id for m in r.mitre)
        scenarios = ", ".join(f"`{s}`" for s in covered.get(r.id, []))
        lines.append(f"| {r.id} | {r.name} | {r.rule_type} | {r.severity.value} | {techniques} | {scenarios} |")

    for r in rules:
        params = r.defaults()
        attack = "; ".join(
            f"[{m.technique_id}](https://attack.mitre.org/techniques/{m.technique_id.replace('.', '/')}/) {m.technique} ({m.tactic})"
            for m in r.mitre
        )
        lines += [
            "",
            f"## {r.id} - {r.name}",
            "",
            r.description,
            "",
            f"- **Type:** {r.rule_type}  ",
            f"- **Data sources:** {', '.join(r.data_sources)}  ",
            f"- **Severity:** {r.severity.value}  ",
            f"- **ATT&CK:** {attack}",
            "",
        ]
        if r.params:
            lines += ["**Tunable parameters**", "", "| Parameter | Default | Range |", "|---|---|---|"]
            lines += [f"| {p.label} (`{p.name}`) | {p.default}{(' ' + p.unit) if p.unit else ''} | {p.min}-{p.max} |" for p in r.params]
            lines.append("")
        lines += ["**Logic**", "", "```text", r.logic.format(**params) if params else r.logic, "```", "", "**Known false positives**", ""]
        lines += [f"- {fp}" for fp in r.false_positives]
        lines += ["", "**Response**", ""]
        lines += [f"{i}. {step}" for i, step in enumerate(r.response, 1)]

    target = BACKEND_ROOT.parent / "docs" / "DETECTION_RULES.md"
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {target} ({len(rules)} rules)")


if __name__ == "__main__":
    main()
