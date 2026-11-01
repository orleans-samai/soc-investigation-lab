"use client";

import { ExternalLink, Flag, Play, Timer } from "lucide-react";
import Link from "next/link";
import * as React from "react";
import { toast } from "sonner";
import useSWR from "swr";

import { SeverityBadge, Tag } from "@/components/soc/badges";
import { EmptyState, KeyValue, PageHeader, Segmented, Stat, tableCls, Term } from "@/components/soc/common";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/overlays";
import { Label, Panel, PanelHeader, Skeleton, Textarea } from "@/components/ui/primitives";
import { post } from "@/lib/api";
import { alertHref } from "@/lib/routes";
import type { ShiftQueueItem, ShiftSummary, ShiftView, Verdict } from "@/lib/types";
import { cn, formatTs, relative } from "@/lib/utils";

const VERDICTS: { value: Verdict; label: string; hint: string }[] = [
  { value: "malicious", label: "Malicious", hint: "Escalate: part of a real attack" },
  { value: "benign", label: "Benign", hint: "Rule was right, activity was authorised" },
  { value: "false_positive", label: "False positive", hint: "Rule matched something it should not" },
];
const VERDICT_LABEL: Record<Verdict, string> = { malicious: "Malicious", benign: "Benign", false_positive: "False positive" };

function clock(seconds: number) {
  const s = Math.max(0, Math.floor(seconds));
  return `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;
}

/** Seconds left on the shift, ticking locally; the server clock offset is applied once per payload. */
function useCountdown(shift: ShiftView | undefined) {
  const [now, setNow] = React.useState(() => Date.now());
  const offset = React.useMemo(() => (shift ? new Date(shift.now).getTime() - Date.now() : 0), [shift]);
  React.useEffect(() => {
    if (shift?.status !== "active") return;
    const id = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(id);
  }, [shift?.status]);
  if (!shift) return 0;
  return (new Date(shift.ends_at).getTime() - (now + offset)) / 1000;
}

function Start({ history, onStarted }: { history: ShiftSummary[]; onStarted: (s: ShiftView) => void }) {
  const [minutes, setMinutes] = React.useState<"10" | "20" | "30">("20");
  const [busy, setBusy] = React.useState(false);
  const finished = history.filter((s) => s.score);
  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,7fr)_minmax(0,5fr)]">
      <Panel>
        <PanelHeader title="Start a shift" description="Two attacks and two noise scenarios are injected now; their alerts land in one queue." />
        <div className="space-y-4 p-4">
          <ul className="space-y-2 text-sm text-muted">
            <li>
              Every alert needs a verdict: <strong className="text-foreground">malicious</strong>, <Term name="Benign true positive">benign</Term> or{" "}
              <Term name="False positive">false positive</Term>, plus a note another analyst could verify.
            </li>
            <li>
              The queue mixes real intrusions with authorised activity and plain noise, like a Monday morning SOC. That is the point:{" "}
              <Term name="Alert fatigue">alert fatigue</Term> is how attacks get closed by mistake.
            </li>
            <li>You can pivot to the alert, its events and the incident at any time. The clock keeps running.</li>
          </ul>
          <KeyValue
            items={[
              ["Accuracy (60%)", "Closing an attack as benign or false positive scores zero for that alert"],
              ["Speed (20%)", "Within SLA from shift start: critical 3 min, high 5, medium 10, low 15"],
              ["Notes (20%)", "At least 25 characters naming the account, host or IP you checked"],
            ]}
          />
          <div className="flex flex-wrap items-end gap-3 border-t border-border pt-4">
            <div className="space-y-1.5">
              <span className="block text-xs font-medium text-muted">Duration</span>
              <Segmented
                aria-label="Shift duration"
                value={minutes}
                onChange={setMinutes}
                options={[
                  { value: "10", label: "10 min" },
                  { value: "20", label: "20 min" },
                  { value: "30", label: "30 min" },
                ]}
              />
            </div>
            <Button
              variant="primary"
              size="lg"
              loading={busy}
              onClick={async () => {
                setBusy(true);
                try {
                  onStarted(await post<ShiftView>("/shifts", { duration_minutes: Number(minutes) }));
                } catch (e) {
                  toast.error((e as Error).message);
                } finally {
                  setBusy(false);
                }
              }}
            >
              <Play /> Start shift
            </Button>
          </div>
        </div>
      </Panel>
      <Panel className="h-fit overflow-hidden">
        <PanelHeader title="Previous shifts" description={finished.length ? `Best score ${Math.max(...finished.map((s) => s.score!.total))}/100` : undefined} />
        {finished.length === 0 ? (
          <p className="p-4 text-sm text-muted">No shift completed yet.</p>
        ) : (
          <table className={tableCls.table}>
            <thead className={tableCls.head}>
              <tr>
                <th className={tableCls.th}>Started</th>
                <th className={cn(tableCls.th, "text-right")}>Score</th>
                <th className={cn(tableCls.th, "text-right")}>Missed attacks</th>
              </tr>
            </thead>
            <tbody>
              {finished.slice(0, 8).map((s) => (
                <tr key={s.id} className={tableCls.row}>
                  <td className={tableCls.td}>
                    <Link href={`/shift?id=${s.id}`} className="text-primary hover:underline">
                      {relative(s.started_at)}
                    </Link>
                    <span className="ml-2 text-2xs text-subtle">{s.alerts} alerts</span>
                  </td>
                  <td className={cn(tableCls.td, "text-right font-mono tabular-nums")}>{s.score!.total}</td>
                  <td className={cn(tableCls.td, "text-right font-mono tabular-nums")}>{s.score!.missed_attacks}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  );
}

function Triage({ shift, item, onDecided }: { shift: ShiftView; item: ShiftQueueItem; onDecided: (s: ShiftView) => void }) {
  const [verdict, setVerdict] = React.useState<Verdict | null>(item.verdict);
  const [note, setNote] = React.useState(item.note ?? "");
  const [busy, setBusy] = React.useState(false);
  const a = item.alert;
  return (
    <Panel>
      <PanelHeader
        title={
          <span className="flex items-center gap-2">
            <SeverityBadge severity={a.severity} /> {a.rule_name}
          </span>
        }
        description={`${a.rule_id} · ${formatTs(a.timestamp)} · ${a.event_count} event(s)`}
        actions={
          <Button asChild size="sm" variant="ghost">
            <Link href={alertHref(a.id)} target="_blank">
              Investigate <ExternalLink />
            </Link>
          </Button>
        }
      />
      <div className="space-y-4 p-4">
        <p className="text-sm leading-relaxed">{a.reason}</p>
        <KeyValue items={a.evidence.map((e) => [e.label, <span key={e.label} className="font-mono text-xs [overflow-wrap:anywhere]">{e.value}</span>])} />
        {a.fp_hints.length > 0 && (
          <div className="rounded-md border border-border bg-surface-2/60 p-3 text-xs text-muted">
            <span className="eyebrow">Context</span>
            <ul className="mt-1 list-disc space-y-0.5 pl-4">
              {a.fp_hints.map((h) => (
                <li key={h}>{h}</li>
              ))}
            </ul>
          </div>
        )}
        <fieldset className="space-y-2">
          <legend className="mb-1.5 text-xs font-medium text-muted">Verdict</legend>
          <div role="radiogroup" aria-label="Verdict" className="grid gap-2 sm:grid-cols-3">
            {VERDICTS.map((v) => (
              <button
                key={v.value}
                role="radio"
                aria-checked={verdict === v.value}
                onClick={() => setVerdict(v.value)}
                className={cn(
                  "flex flex-col items-start justify-start rounded-md border border-border bg-surface px-3 py-2 text-left transition-colors hover:border-border-strong",
                  verdict === v.value && "border-primary bg-primary/8 shadow-[inset_0_0_0_1px_var(--primary)]",
                )}
              >
                <span className="block text-sm font-medium">{v.label}</span>
                <span className="block text-2xs text-subtle">{v.hint}</span>
              </button>
            ))}
          </div>
        </fieldset>
        <div className="space-y-1.5">
          <Label htmlFor="shift-note">Justification</Label>
          <Textarea
            id="shift-note"
            value={note}
            onChange={(e) => setNote(e.target.value)}
            rows={3}
            placeholder={`What did you check? e.g. "${a.username ?? a.hostname ?? "account"} ... confirmed by ..."`}
          />
        </div>
        <div className="flex items-center justify-between gap-2">
          <span className="text-2xs text-subtle">SLA for {a.severity}: {clock(item.sla_seconds ?? 0)} from shift start</span>
          <Button
            variant="primary"
            disabled={!verdict}
            loading={busy}
            onClick={async () => {
              setBusy(true);
              try {
                onDecided(await post<ShiftView>(`/shifts/${shift.id}/alerts/${a.id}`, { verdict, note }));
              } catch (e) {
                toast.error((e as Error).message);
              } finally {
                setBusy(false);
              }
            }}
          >
            {item.verdict ? "Update verdict" : "Submit verdict"}
          </Button>
        </div>
      </div>
    </Panel>
  );
}

function Active({ shift, onChange }: { shift: ShiftView; onChange: (s: ShiftView) => void }) {
  const left = useCountdown(shift);
  const [selectedId, setSelectedId] = React.useState<string | null>(null);
  const pending = shift.queue.filter((q) => !q.verdict);
  const selected = shift.queue.find((q) => q.alert_id === selectedId) ?? pending[0] ?? shift.queue[0];
  const expired = left <= 0;

  React.useEffect(() => {
    if (expired) post<ShiftView>(`/shifts/${shift.id}/finish`).then(onChange, () => undefined);
  }, [expired, shift.id, onChange]);

  return (
    <div className="space-y-4">
      <Panel className="flex flex-wrap items-center gap-x-6 gap-y-3 px-4 py-3">
        <div className="flex items-center gap-2" role="timer" aria-label="Time left in shift">
          <Timer className="size-4 text-subtle" />
          <span className={cn("font-display text-2xl font-semibold tabular-nums", left < 60 && "text-critical")}>{clock(left)}</span>
        </div>
        <div className="min-w-40 flex-1">
          <div className="flex justify-between text-2xs text-subtle">
            <span className="eyebrow">Queue</span>
            <span className="font-mono">
              {shift.queue.length - pending.length}/{shift.queue.length} triaged
            </span>
          </div>
          <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-surface-2">
            <div className="h-full bg-primary transition-[width]" style={{ width: `${(100 * (shift.queue.length - pending.length)) / shift.queue.length}%` }} />
          </div>
        </div>
        <ConfirmDialog
          trigger={
            <Button>
              <Flag /> End shift
            </Button>
          }
          title="End the shift now?"
          description={`${pending.length} alert(s) are still in the queue. Untriaged attacks count as missed.`}
          confirmLabel="End shift"
          destructive={pending.length > 0}
          onConfirm={async () => onChange(await post<ShiftView>(`/shifts/${shift.id}/finish`))}
        />
      </Panel>
      <div className="grid gap-4 xl:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
        <Panel className="h-fit overflow-hidden">
          <PanelHeader title="Alert queue" description="In arrival order. Work it by severity." />
          <ul className="divide-y divide-border">
            {shift.queue.map((q) => (
              <li key={q.alert_id}>
                <button
                  onClick={() => setSelectedId(q.alert_id)}
                  aria-current={selected?.alert_id === q.alert_id}
                  className={cn(
                    "flex w-full items-center gap-3 px-4 py-2.5 text-left transition-colors hover:bg-surface-2",
                    selected?.alert_id === q.alert_id && "bg-surface-2 shadow-[inset_2px_0_0_var(--primary)]",
                    q.verdict && "opacity-60",
                  )}
                >
                  <span className="w-[4.75rem] shrink-0">
                    <SeverityBadge severity={q.alert.severity} />
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm font-medium">{q.alert.rule_name}</span>
                    <span className="block truncate font-mono text-2xs text-subtle">
                      {[q.alert.username, q.alert.hostname, q.alert.source_ip].filter(Boolean).join(" · ") || q.alert.rule_id}
                    </span>
                  </span>
                  {q.verdict ? <Tag>{VERDICT_LABEL[q.verdict]}</Tag> : <span className="font-mono text-2xs text-subtle" title="Alert time (simulated clock, UTC)">{formatTs(q.alert.timestamp, { date: false, seconds: false })}</span>}
                </button>
              </li>
            ))}
          </ul>
        </Panel>
        {selected && <Triage key={selected.alert_id} shift={shift} item={selected} onDecided={onChange} />}
      </div>
    </div>
  );
}

function Results({ shift, onNew }: { shift: ShiftView; onNew: () => void }) {
  const s = shift.score!;
  return (
    <div className="space-y-4">
      <Panel className="grid grid-cols-2 gap-px overflow-hidden bg-border sm:grid-cols-3 xl:grid-cols-6">
        <Stat label="Shift score" value={`${s.total}/100`} tone={s.missed_attacks ? undefined : "success"} hint={`${s.correct}/${shift.queue.length} verdicts right`} />
        <Stat label="Accuracy" value={`${s.accuracy}%`} hint={`${s.decided} triaged`} />
        <Stat label="Speed" value={`${s.speed}%`} hint="Within severity SLA" />
        <Stat label="Notes" value={`${s.documentation}%`} hint="Verifiable justifications" />
        <Stat label="Missed attacks" value={s.missed_attacks} tone={s.missed_attacks ? "critical" : undefined} hint="Closed or left in queue" />
        <Stat label="Wasted escalations" value={s.wasted_escalations} hint="Noise sent to incident response" />
      </Panel>
      <Panel className="overflow-hidden">
        <PanelHeader
          title="Debrief"
          description={`Shift of ${shift.duration_minutes} min, ended ${relative(shift.finished_at)}`}
          actions={
            <Button variant="primary" onClick={onNew}>
              <Play /> New shift
            </Button>
          }
        />
        <div className="overflow-x-auto">
          <table className={tableCls.table}>
            <thead className={tableCls.head}>
              <tr>
                <th className={tableCls.th}>Alert</th>
                <th className={tableCls.th}>Your verdict</th>
                <th className={tableCls.th}>Truth</th>
                <th className={cn(tableCls.th, "text-right")}>Points</th>
                <th className={tableCls.th}>Feedback</th>
              </tr>
            </thead>
            <tbody>
              {shift.queue.map((q) => {
                const right = q.verdict === q.truth;
                return (
                  <tr key={q.alert_id} className={tableCls.row}>
                    <td className={cn(tableCls.td, "min-w-56")}>
                      <Link href={alertHref(q.alert_id)} className="flex items-center gap-2 hover:underline">
                        <SeverityBadge severity={q.alert.severity} /> <span className="truncate">{q.alert.rule_name}</span>
                      </Link>
                      <span className="mt-0.5 block text-2xs text-subtle">{q.scenario_name}</span>
                    </td>
                    <td className={cn(tableCls.td, "whitespace-nowrap")}>{q.verdict ? VERDICT_LABEL[q.verdict] : <span className="text-subtle">not triaged</span>}</td>
                    <td className={cn(tableCls.td, "whitespace-nowrap")}>
                      <span className="inline-flex items-center gap-1.5">
                        <span className={cn("size-1.5 rounded-full", right ? "bg-success" : q.truth === "malicious" ? "bg-critical" : "bg-medium")} aria-hidden />
                        {q.truth && VERDICT_LABEL[q.truth]}
                      </span>
                    </td>
                    <td className={cn(tableCls.td, "text-right font-mono text-xs tabular-nums")}>
                      {(q.accuracy_points ?? 0) + (q.speed_points ?? 0) + (q.note_points ?? 0)}/
                      {shift.max_points_per_alert.accuracy + shift.max_points_per_alert.speed + shift.max_points_per_alert.note}
                    </td>
                    <td className={cn(tableCls.td, "min-w-64 text-xs text-muted")}>{q.feedback}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}

function ShiftPageInner() {
  const { data: history, mutate: refreshHistory } = useSWR<ShiftSummary[]>("/shifts");
  const [requested, setRequested] = React.useState<string | null>(null);
  React.useEffect(() => setRequested(new URLSearchParams(window.location.search).get("id")), []);
  const current = requested ?? history?.find((s) => s.status === "active")?.id ?? null;
  const { data: shift, mutate } = useSWR<ShiftView>(current ? `/shifts/${current}` : null);

  const update = React.useCallback(
    (next: ShiftView) => {
      setRequested(next.id);
      mutate(next, { revalidate: false });
      refreshHistory();
    },
    [mutate, refreshHistory],
  );

  return (
    <>
      <PageHeader
        title="Shift"
        description="A timed queue of real attacks mixed with authorised activity and noise. Triage every alert before the clock runs out."
      />
      {!history || (current && !shift) ? (
        <Skeleton className="h-96 w-full" />
      ) : !shift ? (
        <Start history={history} onStarted={update} />
      ) : shift.status === "active" ? (
        <Active shift={shift} onChange={update} />
      ) : shift.score ? (
        <Results
          shift={shift}
          onNew={() => {
            setRequested(null);
            window.history.replaceState(null, "", "/shift/");
            mutate(undefined, { revalidate: false });
          }}
        />
      ) : (
        <EmptyState icon={Flag} title="Shift not found" description="Start a new shift from the Shift page." />
      )}
    </>
  );
}

export default function ShiftPage() {
  return <ShiftPageInner />;
}
