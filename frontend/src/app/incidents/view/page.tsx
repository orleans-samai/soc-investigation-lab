"use client";

import { ArrowLeft, CheckCircle2, FileText, Globe2, Lock, Monitor, Pencil, Play, RotateCcw, ShieldAlert, User } from "lucide-react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import * as React from "react";
import { toast } from "sonner";
import useSWR from "swr";

import { CLASSIFICATION_LABEL, ClassificationText, SeverityBadge, SeverityDot, StatusBadge } from "@/components/soc/badges";
import { ErrorState, KeyValue, MitreChip, Term } from "@/components/soc/common";
import { EntityLink, useInvestigation } from "@/components/soc/investigation-context";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, Select } from "@/components/ui/overlays";
import { Input, Label, Panel, PanelHeader, Skeleton, Tabs, TabsContent, TabsList, TabsTrigger, Textarea } from "@/components/ui/primitives";
import { patch, post } from "@/lib/api";
import type { Activity, Alert, Classification, Incident, IncidentStatus, NormalizedEvent, Severity } from "@/lib/types";
import { cn, formatDuration, formatTs, relative } from "@/lib/utils";
import { alertHref, reportHref } from "@/lib/routes";

interface IncidentDetail {
  incident: Incident;
  alerts: Alert[];
  events: NormalizedEvent[];
  activity: Activity[];
  playbook: { rule_id: string; rule_name: string; steps: string[]; false_positives: string[] }[];
}

type TimelineEntry = { ts: string; kind: "alert"; alert: Alert } | { ts: string; kind: "event"; event: NormalizedEvent };

function Timeline({ alerts, events }: { alerts: Alert[]; events: NormalizedEvent[] }) {
  const { openEvent } = useInvestigation();
  const [onlyKey, setOnlyKey] = React.useState(true);
  // Collapse runs of identical failures (same action and source) to their first and last occurrence.
  const sameRun = (a?: NormalizedEvent, b?: NormalizedEvent) =>
    !!a && !!b && a.outcome === "failure" && b.outcome === "failure" && a.event_action === b.event_action && a.source_ip === b.source_ip;
  const hidden = new Map<string, number>();
  const visible = events.filter((e, i) => {
    if (!onlyKey || !sameRun(events[i - 1], e) || !sameRun(e, events[i + 1])) return true;
    let start = i;
    while (sameRun(events[start - 1], events[start])) start--;
    hidden.set(events[start].id, (hidden.get(events[start].id) ?? 0) + 1);
    return false;
  });
  const entries: TimelineEntry[] = [
    ...alerts.map((a) => ({ ts: a.timestamp, kind: "alert" as const, alert: a })),
    ...visible.map((e) => ({ ts: e.timestamp, kind: "event" as const, event: e })),
  ].sort((a, b) => a.ts.localeCompare(b.ts) || (a.kind === "alert" ? 1 : -1));

  return (
    <div>
      <div className="flex items-center justify-between border-b border-border px-4 py-2 text-xs text-muted">
        <span>
          {events.length} events · {alerts.length} alerts, oldest first
        </span>
        <label className="flex cursor-pointer items-center gap-2">
          <input type="checkbox" checked={onlyKey} onChange={(e) => setOnlyKey(e.target.checked)} className="size-3.5 accent-[var(--primary)]" />
          Collapse repeated failures
        </label>
      </div>
      <ol className="relative max-h-[640px] overflow-y-auto px-4 py-3">
        <span className="absolute bottom-3 left-[27px] top-3 w-px bg-border" aria-hidden />
        {entries.map((entry, i) =>
          entry.kind === "alert" ? (
            <li key={`a${entry.alert.id}`} className="relative my-2 flex gap-3">
              <span className="z-10 mt-2.5 flex size-[22px] shrink-0 items-center justify-center rounded-full border border-border-strong bg-elevated">
                <SeverityDot severity={entry.alert.severity} className="size-2.5" />
              </span>
              <Link href={alertHref(entry.alert.id)} className="block min-w-0 flex-1 rounded-md border border-border-strong bg-surface-2 px-3 py-2 hover:border-primary/50">
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={entry.alert.severity} />
                  <span className="text-[13px] font-semibold">{entry.alert.rule_name}</span>
                  <span className="ml-auto font-mono text-[11px] text-subtle">{formatTs(entry.ts)}</span>
                </div>
                <p className="mt-1 text-xs text-muted">{entry.alert.reason}</p>
              </Link>
            </li>
          ) : (
            <li key={`e${entry.event.id}${i}`} className="relative flex gap-3">
              <span className="z-10 mt-[9px] flex w-[22px] shrink-0 justify-center">
                <span className={cn("size-1.5 rounded-full", entry.event.outcome === "failure" ? "bg-high" : "bg-subtle")} />
              </span>
              <button onClick={() => openEvent(entry.event.id)} className="flex min-w-0 flex-1 items-baseline gap-3 rounded px-1.5 py-1 text-left text-xs hover:bg-surface-2">
                <span className="shrink-0 font-mono text-subtle">{formatTs(entry.ts, { date: false })}</span>
                <span className="shrink-0 font-mono text-[11px] text-muted">{entry.event.hostname}</span>
                <span className={cn("truncate", entry.event.outcome === "failure" ? "text-high" : "text-foreground/90")}>{entry.event.message || entry.event.event_action}</span>
                {hidden.get(entry.event.id) && (
                  <span className="ml-auto shrink-0 rounded bg-surface-2 px-1.5 text-[11px] text-muted">+{hidden.get(entry.event.id)} similar</span>
                )}
              </button>
            </li>
          ),
        )}
      </ol>
    </div>
  );
}

function CloseDialog({ incident, open, onOpenChange, onDone }: { incident: Incident; open: boolean; onOpenChange: (o: boolean) => void; onDone: () => void }) {
  const [classification, setClassification] = React.useState<Classification>(incident.classification === "undetermined" ? "true_positive" : incident.classification);
  const [resolution, setResolution] = React.useState(incident.resolution ?? "");
  const [busy, setBusy] = React.useState(false);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      await patch(`/incidents/${incident.id}`, { status: "closed", classification, resolution });
      toast.success(`${incident.id} closed as ${CLASSIFICATION_LABEL[classification].toLowerCase()}`);
      onOpenChange(false);
      onDone();
    } catch (err) {
      toast.error((err as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent title={`Close ${incident.id}`} description="Closing requires a classification and a documented resolution. Linked alerts are closed accordingly.">
        <form onSubmit={submit} className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="classification">Classification</Label>
            <Select
              aria-label="Classification"
              className="w-full"
              value={classification}
              onValueChange={(v) => setClassification(v as Classification)}
              options={[
                { value: "true_positive", label: "True positive - malicious or unauthorised" },
                { value: "benign_true_positive", label: "Benign true positive - authorised activity" },
                { value: "false_positive", label: "False positive - detection logic was wrong" },
              ]}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="resolution">Resolution & justification</Label>
            <Textarea
              id="resolution"
              required
              minLength={10}
              value={resolution}
              onChange={(e) => setResolution(e.target.value)}
              placeholder="What happened, evidence that supports the decision, containment actions taken, tuning recommended..."
              className="min-h-32"
            />
          </div>
          <div className="flex justify-end gap-2">
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" loading={busy} disabled={resolution.trim().length < 10}>
              <Lock /> Close incident
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function IncidentPage() {
  const id = useSearchParams().get("id") ?? "";
  const { data, error, mutate } = useSWR<IncidentDetail>(id ? `/incidents/${id}` : null);
  const [closing, setClosing] = React.useState(false);
  const [note, setNote] = React.useState("");
  const [author, setAuthor] = React.useState("analyst");
  const [busy, setBusy] = React.useState(false);
  const [titleDraft, setTitleDraft] = React.useState<string | null>(null);

  if (!id) return <ErrorState error={new Error("No record id in the URL.")} />;
  if (error) return <ErrorState error={error} retry={() => mutate()} />;
  if (!data) return <Skeleton className="h-[70vh] w-full" />;
  const { incident, alerts, events, activity, playbook } = data;

  async function update(body: Partial<{ status: IncidentStatus; severity: Severity; assignee: string; title: string }>, message: string) {
    setBusy(true);
    try {
      await patch(`/incidents/${incident.id}`, body);
      toast.success(message);
      mutate();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function addNote(e: React.FormEvent) {
    e.preventDefault();
    if (!note.trim()) return;
    try {
      await post(`/incidents/${incident.id}/notes`, { body: note, author: author || "analyst" });
      setNote("");
      toast.success("Note added");
      mutate();
    } catch (err) {
      toast.error((err as Error).message);
    }
  }

  const closed = incident.status === "closed";
  const entityGroups: [string, "user" | "host" | "ip", string[], React.ElementType][] = [
    ["Accounts", "user", incident.entities.users ?? [], User],
    ["Hosts", "host", incident.entities.hosts ?? [], Monitor],
    ["Source IPs", "ip", incident.entities.ips ?? [], Globe2],
  ];

  return (
    <>
      <Link href="/incidents" className="mb-3 inline-flex items-center gap-1 text-xs text-muted hover:text-foreground">
        <ArrowLeft className="size-3.5" /> Incidents
      </Link>
      <div className="mb-5 flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-xs text-muted">{incident.id}</span>
            <SeverityBadge severity={incident.severity} />
            <StatusBadge status={incident.status} />
            <ClassificationText value={incident.classification} />
          </div>
          {titleDraft === null ? (
            <div className="group mt-2 flex items-start gap-1.5">
              <h1 className="text-xl font-semibold tracking-tight">{incident.title}</h1>
              <Button variant="ghost" size="icon-sm" className="opacity-60 group-hover:opacity-100" aria-label="Edit title" onClick={() => setTitleDraft(incident.title)}>
                <Pencil />
              </Button>
            </div>
          ) : (
            <form
              className="mt-2 flex max-w-3xl items-center gap-2"
              onSubmit={async (e) => {
                e.preventDefault();
                await update({ title: titleDraft.trim() }, "Title updated");
                setTitleDraft(null);
              }}
            >
              <Input autoFocus value={titleDraft} onChange={(e) => setTitleDraft(e.target.value)} minLength={3} maxLength={200} aria-label="Incident title" className="h-9 text-base font-semibold" onKeyDown={(e) => e.key === "Escape" && setTitleDraft(null)} />
              <Button type="submit" variant="primary" disabled={titleDraft.trim().length < 3} loading={busy}>
                Save
              </Button>
              <Button type="button" variant="ghost" onClick={() => setTitleDraft(null)}>
                Cancel
              </Button>
            </form>
          )}
          <p className="mt-1 max-w-4xl text-[13px] leading-relaxed text-muted">{incident.summary}</p>
        </div>
        <div className="flex shrink-0 flex-wrap gap-2">
          {incident.status === "new" && (
            <Button variant="primary" loading={busy} onClick={() => update({ status: "investigating" }, "Investigation started")}>
              <Play /> Start investigation
            </Button>
          )}
          {incident.status === "investigating" && (
            <Button loading={busy} onClick={() => update({ status: "contained" }, "Incident marked as contained")}>
              <ShieldAlert /> Mark contained
            </Button>
          )}
          {!closed ? (
            <Button variant={incident.status === "new" ? "secondary" : "primary"} onClick={() => setClosing(true)}>
              <CheckCircle2 /> Close incident
            </Button>
          ) : (
            <Button loading={busy} onClick={() => update({ status: "investigating" }, "Incident reopened")}>
              <RotateCcw /> Reopen
            </Button>
          )}
          <Button asChild>
            <Link href={reportHref(incident.id)}>
              <FileText /> Report
            </Link>
          </Button>
        </div>
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Panel className="overflow-hidden xl:col-span-2">
          <Tabs defaultValue="timeline">
            <TabsList className="bg-surface">
              <TabsTrigger value="timeline">Timeline</TabsTrigger>
              <TabsTrigger value="alerts">Alerts ({alerts.length})</TabsTrigger>
              <TabsTrigger value="notes">Notes ({incident.notes.length})</TabsTrigger>
              <TabsTrigger value="playbook">Playbook</TabsTrigger>
              <TabsTrigger value="activity">Activity</TabsTrigger>
            </TabsList>
            <TabsContent value="timeline">
              <Timeline alerts={alerts} events={events} />
            </TabsContent>
            <TabsContent value="alerts" className="divide-y divide-border">
              {alerts.map((a) => (
                <Link key={a.id} href={alertHref(a.id)} className="flex flex-col gap-1 px-4 py-3 hover:bg-surface-2 sm:flex-row sm:items-center sm:gap-3">
                  <SeverityBadge severity={a.severity} />
                  <div className="min-w-0 flex-1">
                    <div className="text-[13px] font-medium">
                      {a.rule_name} <span className="ml-1 font-mono text-[11px] text-subtle">{a.rule_id}</span>
                    </div>
                    <p className="truncate text-xs text-muted">{a.reason}</p>
                  </div>
                  <span className="font-mono text-[11px] text-subtle">{formatTs(a.timestamp)}</span>
                  <StatusBadge status={a.status} />
                </Link>
              ))}
            </TabsContent>
            <TabsContent value="notes" className="p-4">
              {!closed && (
                <form onSubmit={addNote} className="mb-5 space-y-2">
                  <Textarea value={note} onChange={(e) => setNote(e.target.value)} placeholder="Findings, hypotheses, actions taken, people contacted..." aria-label="New note" maxLength={4000} />
                  <div className="flex items-center justify-end gap-2">
                    <Input value={author} onChange={(e) => setAuthor(e.target.value)} className="w-40" aria-label="Author" placeholder="Author" maxLength={80} />
                    <Button type="submit" size="md" variant="primary" disabled={!note.trim()}>
                      Add note
                    </Button>
                  </div>
                </form>
              )}
              {incident.notes.length === 0 ? (
                <p className="text-xs text-muted">No notes yet. Investigation notes become part of the final report.</p>
              ) : (
                <ol className="space-y-3">
                  {[...incident.notes].reverse().map((n) => (
                    <li key={n.id} className="rounded-md border border-border bg-surface-2/50 p-3">
                      <div className="mb-1 text-xs text-subtle">
                        <span className="font-medium text-muted">{n.author}</span> · {formatTs(n.created_at, { seconds: false })} UTC
                      </div>
                      <p className="whitespace-pre-wrap text-[13px] leading-relaxed">{n.body}</p>
                    </li>
                  ))}
                </ol>
              )}
              {incident.resolution && (
                <div className="mt-4 rounded-md border border-success/30 bg-success/6 p-3">
                  <div className="mb-1 text-xs font-medium text-success">Resolution</div>
                  <p className="whitespace-pre-wrap text-[13px]">{incident.resolution}</p>
                </div>
              )}
            </TabsContent>
            <TabsContent value="playbook" className="divide-y divide-border">
              {playbook.map((p) => (
                <div key={p.rule_id} className="p-4">
                  <h3 className="text-[13px] font-semibold">
                    {p.rule_name} <span className="font-mono text-[11px] font-normal text-subtle">{p.rule_id}</span>
                  </h3>
                  <ol className="mt-2 list-decimal space-y-1 pl-5 text-[13px] text-muted">
                    {p.steps.map((s) => (
                      <li key={s}>{s}</li>
                    ))}
                  </ol>
                  <p className="mt-2 text-xs text-subtle">Benign causes to rule out: {p.false_positives.join(" ")}</p>
                </div>
              ))}
            </TabsContent>
            <TabsContent value="activity" className="divide-y divide-border">
              {activity.map((a) => (
                <div key={a.id} className="flex gap-3 px-4 py-2.5 text-[13px]">
                  <span className="w-28 shrink-0 text-xs text-subtle">{relative(a.timestamp)}</span>
                  <span className="text-muted">
                    <span className="text-foreground">{a.actor}</span> - {a.message}
                  </span>
                </div>
              ))}
            </TabsContent>
          </Tabs>
        </Panel>

        <div className="min-w-0 space-y-4">
          <Panel>
            <PanelHeader title="Details" />
            <div className="space-y-3 p-4">
              <KeyValue
                items={[
                  ["First activity", `${formatTs(incident.first_seen)} UTC`],
                  ["Last activity", `${formatTs(incident.last_seen)} UTC`],
                  ["Created", relative(incident.created_at)],
                  [<Term key="a" name="MTTA">Acknowledged</Term>, incident.acknowledged_at ? `after ${formatDuration((+new Date(incident.acknowledged_at) - +new Date(incident.created_at)) / 1000)}` : "Not yet"],
                  [<Term key="r" name="MTTR">Closed</Term>, incident.closed_at ? `after ${formatDuration((+new Date(incident.closed_at) - +new Date(incident.created_at)) / 1000)}` : "Open"],
                  ["Events", events.length],
                ]}
              />
              <div className="grid grid-cols-2 gap-2 border-t border-border pt-3">
                <div className="space-y-1">
                  <Label>Severity</Label>
                  <Select
                    aria-label="Severity"
                    size="sm"
                    className="w-full"
                    value={incident.severity}
                    onValueChange={(v) => update({ severity: v as Severity }, `Severity set to ${v}`)}
                    options={["critical", "high", "medium", "low"].map((s) => ({ value: s, label: <span className="capitalize">{s}</span> }))}
                  />
                </div>
                <div className="space-y-1">
                  <Label htmlFor="assignee">Assignee</Label>
                  <Input
                    id="assignee"
                    defaultValue={incident.assignee ?? ""}
                    placeholder="Unassigned"
                    className="h-7"
                    maxLength={80}
                    onBlur={(e) => e.target.value !== (incident.assignee ?? "") && update({ assignee: e.target.value }, "Assignee updated")}
                    onKeyDown={(e) => e.key === "Enter" && (e.target as HTMLInputElement).blur()}
                  />
                </div>
              </div>
            </div>
          </Panel>
          <Panel>
            <PanelHeader title="Entities" description="Click to open the entity profile" />
            <div className="space-y-3 p-4">
              {entityGroups.map(([label, kind, values, Icon]) => (
                <div key={label}>
                  <div className="mb-1 flex items-center gap-1.5 text-xs text-subtle">
                    <Icon className="size-3" /> {label}
                  </div>
                  {values.length ? (
                    <div className="flex flex-wrap gap-1.5">
                      {values.map((v) => (
                        <span key={v} className="rounded border border-border bg-surface-2 px-2 py-0.5 text-xs">
                          <EntityLink kind={kind} value={v} plain />
                        </span>
                      ))}
                    </div>
                  ) : (
                    <span className="text-xs text-subtle">None</span>
                  )}
                </div>
              ))}
            </div>
          </Panel>
          <Panel>
            <PanelHeader title={<Term name="MITRE ATT&CK">MITRE ATT&CK</Term>} description="Techniques observed across the correlated alerts" />
            <ul className="space-y-1.5 p-4">
              {incident.mitre.map((m) => (
                <li key={m.technique_id} className="flex items-center gap-2 text-xs">
                  <MitreChip refItem={m} compact />
                  <span className="truncate text-muted">{m.technique}</span>
                  <span className="ml-auto shrink-0 text-subtle">{m.tactic}</span>
                </li>
              ))}
            </ul>
          </Panel>
        </div>
      </div>
      <CloseDialog incident={incident} open={closing} onOpenChange={setClosing} onDone={() => mutate()} />
    </>
  );
}

export default function Page() {
  return (
    <React.Suspense fallback={<Skeleton className="h-[70vh] w-full" />}>
      <IncidentPage />
    </React.Suspense>
  );
}
