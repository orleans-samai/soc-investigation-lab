"use client";

import { Eye, Plus, Save, Trash2 } from "lucide-react";
import { useRouter } from "next/navigation";
import * as React from "react";
import { toast } from "sonner";

import { SeverityBadge, Tag } from "@/components/soc/badges";
import { CodeBlock, KeyValue, Segmented, tableCls } from "@/components/soc/common";
import { Button } from "@/components/ui/button";
import { SheetContent } from "@/components/ui/overlays";
import { Input, Label, Switch, Textarea } from "@/components/ui/primitives";
import { post } from "@/lib/api";
import type { ScenarioPreview, ScenarioSummary, Verdict } from "@/lib/types";
import { cn, formatDuration } from "@/lib/utils";

interface Question {
  question: string;
  answer: string;
  points: number;
}

/**
 * Turns the events matched by a Log Explorer query into a replayable scenario with an answer key. The engine
 * fills in the expected detections; the author adds the questions.
 */
export function ScenarioBuilder({ query, onClose }: { query: string; onClose: () => void }) {
  const router = useRouter();
  const [name, setName] = React.useState("");
  const [summary, setSummary] = React.useState("");
  const [verdict, setVerdict] = React.useState<Verdict>("malicious");
  const [level, setLevel] = React.useState<"N1" | "N2" | "N3">("N1");
  const [anonymize, setAnonymize] = React.useState(true);
  const [questions, setQuestions] = React.useState<Question[]>([]);
  const [preview, setPreview] = React.useState<ScenarioPreview | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [busy, setBusy] = React.useState<"preview" | "save" | null>(null);

  const body = () => ({
    query,
    name: name.trim(),
    summary: summary.trim(),
    verdict,
    level,
    anonymize,
    challenge: questions
      .filter((q) => q.question.trim() && q.answer.trim())
      .map((q, i) => ({
        id: `q${i + 1}`,
        question: q.question.trim(),
        answers: q.answer.split("|").map((a) => a.trim()).filter(Boolean),
        points: q.points,
        hint: "Go back to the events of the scenario in the Log Explorer.",
        explanation: `Expected: ${q.answer.split("|")[0].trim()}.`,
      })),
  });

  async function act(kind: "preview" | "save") {
    setBusy(kind);
    try {
      if (kind === "preview") {
        setPreview(await post<ScenarioPreview>("/simulations/scenarios/preview", body()));
      } else {
        const saved = await post<ScenarioSummary>("/simulations/scenarios", body());
        toast.success(`Scenario "${saved.name}" saved`);
        onClose();
        router.push(`/simulations?scenario=${saved.id}`);
      }
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(null);
    }
  }

  const changed = () => setPreview(null);
  const valid = name.trim().length >= 3;

  return (
    <SheetContent title="Save as scenario" description="Replay these events as a training scenario, with an answer key" className="max-w-3xl">
      <div className="grid gap-4 p-5">
        <CodeBlock label="Events selected by">{query}</CodeBlock>
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="space-y-1.5 sm:col-span-2">
            <Label htmlFor="sc-name">Name</Label>
            <Input id="sc-name" value={name} onChange={(e) => (setName(e.target.value), changed())} placeholder="e.g. VPN brute force from our March incident" />
          </div>
          <div className="space-y-1.5 sm:col-span-2">
            <Label htmlFor="sc-summary">What happened (shown to the trainee)</Label>
            <Textarea id="sc-summary" rows={2} value={summary} onChange={(e) => (setSummary(e.target.value), changed())} />
          </div>
          <div className="space-y-1.5">
            <span className="block text-xs font-medium text-muted">Ground truth</span>
            <Segmented
              aria-label="Ground truth"
              value={verdict}
              onChange={(v) => (setVerdict(v), changed())}
              options={[
                { value: "malicious", label: "Malicious" },
                { value: "benign", label: "Benign" },
                { value: "false_positive", label: "False positive" },
              ]}
            />
          </div>
          <div className="space-y-1.5">
            <span className="block text-xs font-medium text-muted">Level</span>
            <Segmented aria-label="Level" value={level} onChange={setLevel} options={["N1", "N2", "N3"].map((v) => ({ value: v as "N1", label: v }))} />
          </div>
          <label className="flex items-start gap-3 rounded-md border border-border bg-surface p-3 sm:col-span-2">
            <Switch checked={anonymize} onCheckedChange={(v) => (setAnonymize(v), changed())} aria-label="Anonymize" className="mt-0.5" />
            <span className="text-sm">
              <span className="font-medium">Anonymize accounts, hosts and IPs</span>
              <span className="block text-xs text-muted">
                Replaced everywhere, including the raw text, with stable pseudonyms (user01, host01, documentation IP ranges). Review the preview before
                sharing: free-text secrets are not detected.
              </span>
            </span>
          </label>
        </div>

        <section>
          <div className="mb-2 flex items-center justify-between">
            <h3 className="eyebrow">Challenge questions (optional)</h3>
            <Button size="sm" variant="ghost" disabled={questions.length >= 6} onClick={() => setQuestions((q) => [...q, { question: "", answer: "", points: 25 }])}>
              <Plus /> Add question
            </Button>
          </div>
          {questions.length === 0 && <p className="text-xs text-muted">Without questions the scenario is still scored on detection and can feed shift mode.</p>}
          <div className="space-y-2">
            {questions.map((q, i) => (
              <div key={i} className="grid gap-2 rounded-md border border-border p-2 sm:grid-cols-[1fr_12rem_5rem_auto]">
                <Input aria-label={`Question ${i + 1}`} placeholder="Question" value={q.question} onChange={(e) => setQuestions((all) => all.map((x, j) => (j === i ? { ...x, question: e.target.value } : x)))} />
                <Input aria-label={`Answer ${i + 1}`} placeholder="Answer (a|b for variants)" className="font-mono text-xs" value={q.answer} onChange={(e) => setQuestions((all) => all.map((x, j) => (j === i ? { ...x, answer: e.target.value } : x)))} />
                <Input aria-label={`Points ${i + 1}`} type="number" min={1} max={100} value={q.points} onChange={(e) => setQuestions((all) => all.map((x, j) => (j === i ? { ...x, points: e.target.valueAsNumber || 1 } : x)))} />
                <Button size="icon" variant="ghost" aria-label={`Remove question ${i + 1}`} onClick={() => setQuestions((all) => all.filter((_, j) => j !== i))}>
                  <Trash2 />
                </Button>
              </div>
            ))}
          </div>
          {anonymize && questions.length > 0 && <p className="mt-1.5 text-2xs text-subtle">Write answers with the pseudonyms shown in the preview, not the original values.</p>}
        </section>

        {error && (
          <p role="alert" className="rounded-md border border-critical/30 bg-critical/8 px-3 py-2 text-sm">
            {error}
          </p>
        )}
        <div className="flex flex-wrap gap-2">
          <Button disabled={!valid} loading={busy === "preview"} onClick={() => act("preview")}>
            <Eye /> Preview
          </Button>
          <Button variant="primary" disabled={!valid || !preview} loading={busy === "save"} onClick={() => act("save")} title={preview ? undefined : "Preview first"}>
            <Save /> Save scenario
          </Button>
        </div>

        {preview && (
          <section aria-label="Scenario preview" className="space-y-3 rounded-md border border-border bg-surface p-4">
            <KeyValue
              items={[
                ["Events", `${preview.event_count} over ${formatDuration(preview.duration_seconds)}`],
                [
                  "Answer key",
                  preview.scenario.expected_rules.length ? (
                    <span className="flex flex-wrap items-center gap-1.5">
                      <SeverityBadge severity={preview.scenario.expected_severity} />
                      {preview.scenario.expected_rules.map((r) => (
                        <Tag key={r} mono>
                          {r}
                        </Tag>
                      ))}
                    </span>
                  ) : (
                    "No rule fires on these events: a pure investigation scenario (or a detection gap to fix)."
                  ),
                ],
                ["Hosts", preview.scenario.hosts.join(", ") || "-"],
              ]}
            />
            {preview.pseudonyms.length > 0 && (
              <div className="max-h-56 overflow-auto rounded-md border border-border">
                <table className={tableCls.table}>
                  <thead className={tableCls.head}>
                    <tr>
                      <th className={tableCls.th}>Kind</th>
                      <th className={tableCls.th}>Original</th>
                      <th className={tableCls.th}>Pseudonym</th>
                    </tr>
                  </thead>
                  <tbody>
                    {preview.pseudonyms.map((p) => (
                      <tr key={`${p.kind}-${p.original}`} className={tableCls.row}>
                        <td className={cn(tableCls.td, "text-xs text-muted")}>{p.kind}</td>
                        <td className={cn(tableCls.td, "font-mono text-xs")}>{p.original}</td>
                        <td className={cn(tableCls.td, "font-mono text-xs")}>{p.pseudonym}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {preview.sample[0] && <CodeBlock label="First event as stored in the scenario">{JSON.stringify(preview.sample[0], null, 2)}</CodeBlock>}
          </section>
        )}
      </div>
    </SheetContent>
  );
}
