"use client";

import { ArrowLeft, Check, ChevronDown, Lightbulb, ShieldCheck, ShieldPlus } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import * as React from "react";
import { toast } from "sonner";
import useSWR from "swr";

import { SeverityBadge, StatusBadge } from "@/components/soc/badges";
import { CodeBlock, ErrorState, KeyValue, MitreChip, tableCls, Term } from "@/components/soc/common";
import { EntityLink, useInvestigation } from "@/components/soc/investigation-context";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/overlays";
import { Panel, PanelHeader, Skeleton, Textarea } from "@/components/ui/primitives";
import { patch, post } from "@/lib/api";
import type { Alert, AlertStatus, Incident, NormalizedEvent } from "@/lib/types";
import { cn, formatDuration, formatTs } from "@/lib/utils";
import { incidentHref } from "@/lib/routes";

interface AlertDetail {
  alert: Alert;
  events: NormalizedEvent[];
  rule: { id: string; logic: string; false_positives: string[]; response: string[] } | null;
  incident: Incident | null;
}

const STATUS_ACTIONS: { status: AlertStatus; label: string; hint: string }[] = [
  { status: "investigating", label: "Mark as investigating", hint: "You are working on it" },
  { status: "resolved", label: "Close: true positive", hint: "Malicious / unauthorised activity" },
  { status: "benign", label: "Close: benign true positive", hint: "Rule was right, activity authorised" },
  { status: "false_positive", label: "Close: false positive", hint: "Rule matched the wrong thing" },
  { status: "new", label: "Reopen", hint: "Back to the queue" },
];

function AlertDetailPage() {
  const id = useSearchParams().get("id") ?? "";
  const router = useRouter();
  const { openEvent } = useInvestigation();
  const { data, error, mutate } = useSWR<AlertDetail>(id ? `/alerts/${id}` : null);
  const [note, setNote] = React.useState<string | null>(null);
  const [saving, setSaving] = React.useState(false);

  if (!id) return <ErrorState error={new Error("No record id in the URL.")} />;
  if (error) return <ErrorState error={error} retry={() => mutate()} />;
  if (!data) return <Skeleton className="h-[70vh] w-full" />;
  const { alert, events, rule, incident } = data;
  const noteValue = note ?? alert.analyst_note ?? "";

  async function update(body: Partial<Pick<Alert, "status" | "analyst_note">>, message: string) {
    setSaving(true);
    try {
      await patch(`/alerts/${alert.id}`, body);
      toast.success(message);
      await mutate();
      setNote(null);
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setSaving(false);
    }
  }

  async function escalate() {
    try {
      const created = await post<Incident>("/incidents", { alert_ids: [alert.id] });
      toast.success(`Escalated to ${created.id}`);
      router.push(incidentHref(created.id));
    } catch (e) {
      toast.error((e as Error).message);
    }
  }

  return (
    <>
      <Link href="/alerts" className="mb-3 inline-flex items-center gap-1 text-xs text-muted hover:text-foreground">
        <ArrowLeft className="size-3.5" /> Alert queue
      </Link>
      <div className="mb-5 flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={alert.severity} />
            <StatusBadge status={alert.status} />
            <span className="font-mono text-xs text-subtle">{alert.id}</span>
          </div>
          <h1 className="mt-2 font-display text-xl font-semibold tracking-[-0.01em]">{alert.rule_name}</h1>
          <p className="mt-1 max-w-3xl text-sm text-muted">{alert.description}</p>
        </div>
        <div className="flex shrink-0 flex-wrap gap-2">
          {incident ? (
            <Button asChild variant="primary">
              <Link href={incidentHref(incident.id)}>
                <ShieldCheck /> Open {incident.id}
              </Link>
            </Button>
          ) : (
            <Button variant="primary" onClick={escalate}>
              <ShieldPlus /> Escalate to incident
            </Button>
          )}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button loading={saving}>
                Set status <ChevronDown />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-64">
              <DropdownMenuLabel>Triage decision</DropdownMenuLabel>
              {STATUS_ACTIONS.map((a, i) => (
                <React.Fragment key={a.status}>
                  {i === 4 && <DropdownMenuSeparator />}
                  <DropdownMenuItem disabled={alert.status === a.status} onSelect={() => update({ status: a.status }, `Alert marked: ${a.label.toLowerCase()}`)} className="h-auto py-1.5">
                    {alert.status === a.status ? <Check /> : <span className="size-3.5" />}
                    <span>
                      <span className="block">{a.label}</span>
                      <span className="block text-2xs text-subtle">{a.hint}</span>
                    </span>
                  </DropdownMenuItem>
                </React.Fragment>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <div className="min-w-0 space-y-4 xl:col-span-2">
          <Panel>
            <PanelHeader title="Why this alert fired" />
            <div className="space-y-4 p-4">
              <p className="text-sm leading-relaxed">{alert.reason}</p>
              <KeyValue items={alert.evidence.map((e) => [e.label, e.label.toLowerCase().includes("command") || e.label.startsWith("Decoded") ? <code className="break-all font-mono text-xs">{e.value}</code> : e.value])} />
            </div>
          </Panel>

          {alert.fp_hints.length > 0 && (
            <div className="flex gap-3 rounded-lg border border-medium/30 bg-medium/8 p-4">
              <Lightbulb className="mt-0.5 size-4 shrink-0 text-medium" />
              <div>
                <h3 className="text-sm font-semibold">Possible <Term name="False positive">false-positive</Term> indicators</h3>
                <ul className="mt-1 list-disc space-y-0.5 pl-4 text-sm text-muted">
                  {alert.fp_hints.map((h) => (
                    <li key={h}>{h}</li>
                  ))}
                </ul>
              </div>
            </div>
          )}

          <Panel className="overflow-hidden">
            <PanelHeader
              title={`Related events (${alert.event_count})`}
              description="The records the rule evaluated. Open one for its raw log."
              actions={
                <Button asChild size="sm" variant="ghost">
                  <Link href={`/events?ids=${alert.event_ids.join(",")}`}>Open in Log Explorer</Link>
                </Button>
              }
            />
            <div className="max-h-[420px] overflow-auto">
              <table className={tableCls.table}>
                <thead className={tableCls.head}>
                  <tr>
                    <th className={tableCls.th}>Time (UTC)</th>
                    <th className={tableCls.th}>
                      <Term name="Event ID">Event</Term>
                    </th>
                    <th className={tableCls.th}>Message</th>
                    <th className={cn(tableCls.th, "hidden md:table-cell")}>Source IP</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((e) => (
                    <tr key={e.id} className={cn(tableCls.row, "cursor-pointer")} onClick={() => openEvent(e.id)}>
                      <td className={cn(tableCls.td, "whitespace-nowrap font-mono text-xs text-muted")}>{formatTs(e.timestamp)}</td>
                      <td className={cn(tableCls.td, "font-mono text-xs")}>{e.event_id}</td>
                      <td className={cn(tableCls.td, "max-w-md truncate", e.outcome === "failure" && "text-high")}>{e.message}</td>
                      <td className={cn(tableCls.td, "hidden md:table-cell")}>
                        <EntityLink kind="ip" value={e.source_ip} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>

          {rule && (
            <Panel>
              <PanelHeader title="Detection logic" description={`${rule.id} - pseudo-query of what the engine evaluates`} actions={<Button asChild size="sm" variant="ghost"><Link href={`/rules?rule=${rule.id}`}>Tune rule</Link></Button>} />
              <div className="p-4">
                <CodeBlock>{rule.logic}</CodeBlock>
              </div>
            </Panel>
          )}
        </div>

        <div className="min-w-0 space-y-4">
          <Panel>
            <PanelHeader title="Details" />
            <div className="p-4">
              <KeyValue
                items={[
                  ["Rule", <span key="r" className="font-mono text-xs">{alert.rule_id}</span>],
                  ["Fired at", `${formatTs(alert.timestamp)} UTC`],
                  ["First event", `${formatTs(alert.first_seen)} UTC`],
                  [<Term key="m" name="MTTD">Time to detect</Term>, formatDuration((new Date(alert.timestamp).getTime() - new Date(alert.first_seen).getTime()) / 1000)],
                  ["Host", <EntityLink key="h" kind="host" value={alert.hostname} />],
                  ["User", <EntityLink key="u" kind="user" value={alert.username} />],
                  ["Source IP", <EntityLink key="i" kind="ip" value={alert.source_ip} />],
                  ["Incident", incident ? <Link key="inc" href={incidentHref(incident.id)} className="text-primary hover:underline">{incident.id}</Link> : "Not escalated"],
                ]}
              />
            </div>
          </Panel>
          <Panel>
            <PanelHeader title={<Term name="MITRE ATT&CK">MITRE ATT&CK</Term>} />
            <div className="flex flex-wrap gap-1.5 p-4">
              {alert.mitre.map((m) => (
                <MitreChip key={m.technique_id} refItem={m} />
              ))}
            </div>
          </Panel>
          <Panel>
            <PanelHeader title="Analyst note" description="Document the evidence behind your triage decision" />
            <div className="space-y-2 p-4">
              <Textarea value={noteValue} onChange={(e) => setNote(e.target.value)} placeholder="e.g. Source matches change CHG-2041; confirmed with the administrator." aria-label="Analyst note" maxLength={4000} />
              <div className="flex justify-end">
                <Button size="sm" disabled={note === null || note === (alert.analyst_note ?? "")} loading={saving} onClick={() => update({ analyst_note: noteValue }, "Note saved")}>
                  Save note
                </Button>
              </div>
            </div>
          </Panel>
          {rule && (
            <Panel>
              <PanelHeader title="Response playbook" />
              <ol className="list-decimal space-y-1.5 p-4 pl-8 text-sm text-muted">
                {rule.response.map((s) => (
                  <li key={s}>{s}</li>
                ))}
              </ol>
              <div className="border-t border-border p-4">
                <h3 className="mb-1.5 text-xs font-medium text-subtle">Known benign causes</h3>
                <ul className="list-disc space-y-1 pl-4 text-sm text-muted">
                  {rule.false_positives.map((s) => (
                    <li key={s}>{s}</li>
                  ))}
                </ul>
              </div>
            </Panel>
          )}
        </div>
      </div>
    </>
  );
}

export default function Page() {
  return (
    <React.Suspense fallback={<Skeleton className="h-[70vh] w-full" />}>
      <AlertDetailPage />
    </React.Suspense>
  );
}
