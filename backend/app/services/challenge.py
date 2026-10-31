"""Challenge mode: the analyst answers investigation questions about a simulation run and gets a score.

Answers are checked server-side; expected answers are only revealed after submission. Using a hint
halves the points of that question.
"""

from __future__ import annotations

import re
from typing import Any

from app.models.common import utcnow
from app.models.simulations import ChallengeQuestion, Scenario, SimulationRun
from app.services.lab import LabService

_PLACEHOLDER = re.compile(r"\{(\w+)\}")


class ChallengeError(ValueError):
    pass


def normalize(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().strip("'\"`").rstrip(".")).lower()


def render(text: str, variables: dict[str, Any]) -> str:
    return _PLACEHOLDER.sub(lambda m: str(variables.get(m.group(1), m.group(0))), text)


def expected_answers(question: ChallengeQuestion, variables: dict[str, Any]) -> list[str]:
    return [render(a, variables) for a in question.answers]


def points_for(question: ChallengeQuestion, hint_used: bool) -> int:
    return question.points // 2 if hint_used else question.points


def view(scenario: Scenario, run: SimulationRun) -> dict[str, Any]:
    attempt = run.challenge
    submitted = attempt.submitted_at is not None
    questions = []
    for q in scenario.challenge:
        hint_used = q.id in attempt.hints_used
        item: dict[str, Any] = {
            "id": q.id,
            "question": q.question,
            "kind": q.kind,
            "options": q.options,
            "points": q.points,
            "hint_used": hint_used,
            "hint": q.hint if hint_used or submitted else None,
        }
        if submitted:
            item |= {
                "answer": attempt.answers.get(q.id, ""),
                "correct": attempt.results.get(q.id, False),
                "expected": expected_answers(q, run.variables)[0],
                "explanation": render(q.explanation, run.variables),
                "earned": points_for(q, hint_used) if attempt.results.get(q.id) else 0,
            }
        questions.append(item)
    return {
        "run_id": run.id,
        "scenario_id": scenario.id,
        "submitted": submitted,
        "submitted_at": attempt.submitted_at,
        "score": attempt.score,
        "max_score": sum(q.points for q in scenario.challenge),
        "questions": questions,
    }


def use_hint(lab: LabService, scenario: Scenario, run: SimulationRun, question_id: str) -> dict[str, Any]:
    if not any(q.id == question_id for q in scenario.challenge):
        raise ChallengeError(f"unknown question {question_id}")
    with lab.store.lock:
        if run.challenge.submitted_at is None and question_id not in run.challenge.hints_used:
            run.challenge.hints_used.append(question_id)
            lab.store.simulation_runs.upsert(run)
            lab.store.simulation_runs.persist()
    return view(scenario, run)


def submit(lab: LabService, scenario: Scenario, run: SimulationRun, answers: dict[str, str]) -> dict[str, Any]:
    if not scenario.challenge:
        raise ChallengeError("this scenario has no challenge")
    with lab.store.lock:
        attempt = run.challenge
        if attempt.submitted_at is not None:
            raise ChallengeError("answers for this run were already submitted - run the scenario again for a new attempt")
        score = 0
        for q in scenario.challenge:
            given = (answers.get(q.id) or "")[:300]
            correct = bool(given) and normalize(given) in {normalize(a) for a in expected_answers(q, run.variables)}
            attempt.answers[q.id] = given
            attempt.results[q.id] = correct
            if correct:
                score += points_for(q, q.id in attempt.hints_used)
        attempt.score = score
        attempt.max_score = sum(q.points for q in scenario.challenge)
        attempt.submitted_at = utcnow()
        lab.store.simulation_runs.upsert(run)
        lab.log(
            "analyst",
            "challenge.submitted",
            f"Challenge '{scenario.name}': {score}/{attempt.max_score} points ({sum(attempt.results.values())}/{len(scenario.challenge)} correct)",
            "simulation",
            run.id,
        )
        lab.store.persist_all()
    return view(scenario, run)
