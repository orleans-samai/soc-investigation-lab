"use client";

import { CheckCircle2, Lightbulb, Send, Trophy, XCircle } from "lucide-react";
import * as React from "react";
import { toast } from "sonner";
import useSWR from "swr";

import { Button } from "@/components/ui/button";
import { Input, Panel, PanelHeader, Skeleton } from "@/components/ui/primitives";
import { post } from "@/lib/api";
import type { ChallengeView } from "@/lib/types";
import { cn } from "@/lib/utils";

function scoreTone(pct: number) {
  if (pct >= 80) return "text-success";
  if (pct >= 50) return "text-medium";
  return "text-critical";
}

/** Investigation challenge for one simulation run: answer from the evidence, hints cost half the points. */
export function ChallengePanel({ runId }: { runId: string }) {
  const url = `/simulations/runs/${runId}/challenge`;
  const { data, mutate } = useSWR<ChallengeView>(url);
  const [answers, setAnswers] = React.useState<Record<string, string>>({});
  const [busy, setBusy] = React.useState(false);

  if (!data) return <Skeleton className="h-64 w-full" />;
  if (!data.questions.length) return null;
  const pct = data.max_score ? Math.round((data.score / data.max_score) * 100) : 0;
  const unanswered = data.questions.filter((q) => !(answers[q.id] ?? "").trim()).length;

  async function hint(questionId: string) {
    try {
      await mutate(await post<ChallengeView>(`${url}/hint`, { question_id: questionId }), { revalidate: false });
    } catch (e) {
      toast.error((e as Error).message);
    }
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const result = await post<ChallengeView>(url, { answers });
      await mutate(result, { revalidate: false });
      toast.success(`Challenge scored: ${result.score}/${result.max_score} points`);
    } catch (err) {
      toast.error((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Panel>
      <PanelHeader
        title={
          <span className="inline-flex items-center gap-1.5">
            <Trophy className="size-3.5 text-medium" /> Investigation challenge
          </span>
        }
        description={data.submitted ? "Answers checked - expected answers and explanations below" : "Answer from the evidence in the alerts, incident and Log Explorer. A hint halves that question's points."}
        actions={
          data.submitted && (
            <span className={cn("font-mono text-lg font-semibold tabular-nums", scoreTone(pct))}>
              {data.score}/{data.max_score}
            </span>
          )
        }
      />
      <form onSubmit={submit} className="divide-y divide-border">
        {data.questions.map((q, i) => (
          <fieldset key={q.id} className="space-y-2 px-4 py-3.5" disabled={data.submitted}>
            <legend className="flex w-full items-start gap-2 text-[13px] font-medium">
              <span className="font-mono text-xs text-subtle">{i + 1}.</span>
              <span className="flex-1">{q.question}</span>
              {data.submitted ? (
                q.correct ? (
                  <span className="inline-flex shrink-0 items-center gap-1 text-xs text-success">
                    <CheckCircle2 className="size-3.5" /> +{q.earned}
                  </span>
                ) : (
                  <span className="inline-flex shrink-0 items-center gap-1 text-xs text-critical">
                    <XCircle className="size-3.5" /> 0
                  </span>
                )
              ) : (
                <span className="shrink-0 text-[11px] font-normal text-subtle">{q.hint_used ? `${q.points / 2} pts (hint used)` : `${q.points} pts`}</span>
              )}
            </legend>

            {data.submitted ? (
              <div className="space-y-1.5 pl-5 text-[13px]">
                <p className="text-muted">
                  Your answer: <span className={cn("font-medium", q.correct ? "text-success" : "text-critical")}>{q.answer || "(blank)"}</span>
                  {!q.correct && (
                    <>
                      {" "}
                      · expected: <span className="font-medium text-foreground">{q.expected}</span>
                    </>
                  )}
                </p>
                <p className="text-xs leading-relaxed text-muted">{q.explanation}</p>
              </div>
            ) : (
              <div className="space-y-2 pl-5">
                {q.kind === "choice" ? (
                  <div role="radiogroup" aria-label={q.question} className="grid gap-1.5 sm:grid-cols-2">
                    {q.options.map((opt) => (
                      <label
                        key={opt}
                        className={cn(
                          "flex cursor-pointer items-center gap-2 rounded-md border border-border px-2.5 py-1.5 text-[13px] hover:bg-surface-2",
                          answers[q.id] === opt && "border-primary/60 bg-primary/8",
                        )}
                      >
                        <input
                          type="radio"
                          name={q.id}
                          value={opt}
                          checked={answers[q.id] === opt}
                          onChange={() => setAnswers((a) => ({ ...a, [q.id]: opt }))}
                          className="accent-[var(--primary)]"
                        />
                        {opt}
                      </label>
                    ))}
                  </div>
                ) : (
                  <Input
                    value={answers[q.id] ?? ""}
                    onChange={(e) => setAnswers((a) => ({ ...a, [q.id]: e.target.value }))}
                    placeholder="Type your answer"
                    aria-label={q.question}
                    maxLength={300}
                    className="block max-w-sm"
                  />
                )}
                {q.hint ? (
                  <p className="flex items-start gap-1.5 text-xs text-medium">
                    <Lightbulb className="mt-0.5 size-3 shrink-0" /> {q.hint}
                  </p>
                ) : (
                  <button type="button" onClick={() => hint(q.id)} className="inline-flex items-center gap-1 text-xs text-subtle hover:text-medium">
                    <Lightbulb className="size-3" /> Show hint (-50%)
                  </button>
                )}
              </div>
            )}
          </fieldset>
        ))}
        {!data.submitted && (
          <div className="flex items-center justify-between gap-3 px-4 py-3">
            <span className="text-xs text-subtle">{unanswered ? `${unanswered} question(s) unanswered` : "All questions answered"} · one attempt per run</span>
            <Button type="submit" variant="primary" loading={busy}>
              <Send /> Submit answers
            </Button>
          </div>
        )}
      </form>
    </Panel>
  );
}
