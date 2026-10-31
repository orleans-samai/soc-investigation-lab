"use client";

import { ArrowRight, BellRing, Check, CircleDashed, FileCode2, FlaskConical, Layers, Play, ShieldCheck, X } from "lucide-react";
import { motion, useReducedMotion } from "motion/react";
import Link from "next/link";
import * as React from "react";
import { toast } from "sonner";
import useSWR from "swr";

import { SeverityBadge, StatusBadge, Tag } from "@/components/soc/badges";
import { EmptyState, PageHeader, tableCls } from "@/components/soc/common";
import { useInvestigation } from "@/components/soc/investigation-context";
import { Button } from "@/components/ui/button";
import { Input, Label, Panel, PanelHeader, Skeleton } from "@/components/ui/primitives";
import { post } from "@/lib/api";
import type { ScenarioSummary, SimulationDetail, SimulationRun } from "@/lib/types";
import { useUrlState } from "@/lib/use-url-state";
import { cn, formatTs, relative } from "@/lib/utils";
import { alertHref, incidentHref } from "@/lib/routes";

function Pipeline({ detail }: { detail: SimulationDetail }) {
  const reduce = useReducedMotion();
  const { run, alerts, incidents } = detail;
  const stages = [
    { icon: FileCode2, label: "Raw logs generated", value: run.event_count, note: "Windows JSON / auth.log lines" },
    { icon: Layers, label: "Normalized events", value: run.event_count, note: "Parsed by the import parsers" },
    { icon: BellRing, label: "Alerts raised", value: alerts.length, note: `${run.triggered_rules.length} rule(s) fired` },
    { icon: ShieldCheck, label: incidents.length ? "Incident" : "Incident", value: incidents.length, note: incidents.length ? incidents.map((i) => i.id).join(", ") : "Below auto-incident severity" },
  ];
  return (
    <ol className="grid gap-2 sm:grid-cols-4" aria-label="Detection pipeline">
      {stages.map((s, i) => (
        <motion.li
          key={s.label}
          initial={reduce ? false : { opacity: 0, y: 4 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: reduce ? 0 : i * 0.08, duration: 0.18 }}
          className="relative rounded-md border border-border bg-surface-2/60 px-3 py-2.5"
        >
          <div className="flex items-center gap-1.5 text-[11px] text-muted">
            <s.icon className="size-3.5 text-primary" /> {s.label}
          </div>
          <div className="mt-1 font-mono text-xl tabular-nums">{s.value}</div>
          <div className="truncate text-[11px] text-subtle">{s.note}</div>
          {i < stages.length - 1 && <ArrowRight className="absolute -right-2.5 top-1/2 z-10 hidden size-3.5 -translate-y-1/2 text-subtle sm:block" aria-hidden />}
        </motion.li>
      ))}
    </ol>
  );
}

function RunResult({ runId }: { runId: string }) {
  const { data } = useSWR<SimulationDetail>(`/simulations/runs/${runId}`);
  const { openEvent } = useInvestigation();
  if (!data) return <Skeleton className="h-64 w-full" />;
  const { run, alerts, incidents, events } = data;
  const allRules = [...new Set([...run.expected_rules, ...run.triggered_rules])].sort();
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2 text-xs text-muted">
        <span className="font-mono">{run.id}</span>· seed <span className="font-mono">{run.seed}</span>· simulated {formatTs(run.simulated_start, { seconds: false })} -{" "}
        {formatTs(run.simulated_end, { date: false, seconds: false })} UTC
        {run.missed_rules.length === 0 ? <Tag className="text-success">all expected detections fired</Tag> : <Tag className="text-critical">missed {run.missed_rules.join(", ")}</Tag>}
      </div>
      <Pipeline detail={data} />

      <div className="grid gap-4 lg:grid-cols-2">
        <div>
          <h4 className="mb-2 text-xs font-medium uppercase tracking-wide text-subtle">Detection validation</h4>
          <ul className="divide-y divide-border rounded-md border border-border">
            {allRules.map((rid) => {
              const expected = run.expected_rules.includes(rid);
              const fired = run.triggered_rules.includes(rid);
              return (
                <li key={rid} className="flex items-center gap-2 px-3 py-1.5 text-[13px]">
                  {fired ? <Check className="size-3.5 text-success" /> : <X className="size-3.5 text-critical" />}
                  <span className="font-mono text-xs">{rid}</span>
                  <span className="truncate text-muted">{alerts.find((a) => a.rule_id === rid)?.rule_name ?? ""}</span>
                  <span className="ml-auto text-[11px] text-subtle">{expected ? (fired ? "expected · fired" : "expected · MISSED") : "unexpected"}</span>
                </li>
              );
            })}
          </ul>
        </div>
        <div>
          <h4 className="mb-2 text-xs font-medium uppercase tracking-wide text-subtle">Alerts & incident</h4>
          <ul className="divide-y divide-border rounded-md border border-border">
            {alerts.map((a) => (
              <li key={a.id}>
                <Link href={alertHref(a.id)} className="flex items-center gap-2 px-3 py-1.5 text-[13px] hover:bg-surface-2">
                  <SeverityBadge severity={a.severity} />
                  <span className="truncate">{a.rule_name}</span>
                  <StatusBadge status={a.status} className="ml-auto" />
                </Link>
              </li>
            ))}
          </ul>
          {incidents.map((i) => (
            <Button key={i.id} asChild variant="primary" className="mt-2 w-full">
              <Link href={incidentHref(i.id)}>
                Investigate {i.id} <ArrowRight />
              </Link>
            </Button>
          ))}
          {!incidents.length && alerts.length > 0 && (
            <Button asChild className="mt-2 w-full">
              <Link href={alertHref(alerts[0].id)}>Triage the alert</Link>
            </Button>
          )}
        </div>
      </div>

      <div>
        <h4 className="mb-2 text-xs font-medium uppercase tracking-wide text-subtle">Generated raw logs (first 6)</h4>
        <div className="space-y-1">
          {events.slice(0, 6).map((e) => (
            <button key={e.id} onClick={() => openEvent(e.id)} className="block w-full rounded border border-border bg-background px-2.5 py-1.5 text-left hover:border-primary/40">
              <code className="block truncate font-mono text-[11px] text-foreground/85">{e.raw}</code>
            </button>
          ))}
        </div>
        <Link href={`/events?dataset=simulation:${run.id}`} className="mt-2 inline-block text-xs text-primary hover:underline">
          All {run.event_count} events in the Log Explorer
        </Link>
      </div>
    </div>
  );
}

function Simulations() {
  const [f, set] = useUrlState({ scenario: "", run: "" });
  const { data: scenarios, mutate } = useSWR<ScenarioSummary[]>("/simulations/scenarios");
  const { data: runs, mutate: mutateRuns } = useSWR<SimulationRun[]>("/simulations/runs");
  const [seed, setSeed] = React.useState("");
  const [running, setRunning] = React.useState(false);
  const selected = scenarios?.find((s) => s.id === f.scenario) ?? scenarios?.[0];
  const runId = f.run || selected?.last_run_id || "";

  async function execute() {
    if (!selected) return;
    setRunning(true);
    try {
      const detail = await post<SimulationDetail>("/simulations/run", { scenario_id: selected.id, seed: seed ? Number(seed) : undefined });
      const ok = detail.run.missed_rules.length === 0;
      toast[ok ? "success" : "warning"](
        `${detail.run.event_count} events injected · ${detail.alerts.length} alert(s)${detail.incidents.length ? ` · ${detail.incidents[0].id}` : ""}`,
      );
      await Promise.all([mutate(), mutateRuns()]);
      set({ scenario: selected.id, run: detail.run.id });
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setRunning(false);
    }
  }

  return (
    <>
      <PageHeader
        title="Incident Simulations"
        description="Controlled, synthetic attack scenarios. Each run renders raw Windows/Linux logs, pushes them through the real parsers and detection engine, and checks which rules fired against the ones the scenario is designed to trigger."
      />
      <div className="grid gap-4 xl:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
        <Panel className="h-fit overflow-hidden">
          <PanelHeader title="Scenarios" description="Synthetic data only - no real systems are touched" />
          <ul className="divide-y divide-border">
            {!scenarios &&
              Array.from({ length: 6 }).map((_, i) => (
                <li key={i} className="p-3">
                  <Skeleton className="h-12 w-full" />
                </li>
              ))}
            {scenarios?.map((s) => (
              <li key={s.id}>
                <button
                  onClick={() => set({ scenario: s.id, run: "" })}
                  aria-current={selected?.id === s.id}
                  className={cn("flex w-full gap-3 px-4 py-3 text-left transition-colors hover:bg-surface-2", selected?.id === s.id && "bg-surface-2 shadow-[inset_2px_0_0_var(--primary)]")}
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="truncate text-[13px] font-medium">{s.name}</span>
                    </div>
                    <div className="mt-1 flex flex-wrap items-center gap-1.5">
                      <SeverityBadge severity={s.expected_severity} />
                      <Tag>{s.category}</Tag>
                      <Tag>{s.level}</Tag>
                      {s.benign && <Tag className="text-success">benign</Tag>}
                    </div>
                  </div>
                  <div className="shrink-0 text-right text-[11px] text-subtle">
                    {s.run_count ? `${s.run_count} run${s.run_count > 1 ? "s" : ""}` : "not run"}
                  </div>
                </button>
              </li>
            ))}
          </ul>
        </Panel>

        {selected ? (
          <div className="space-y-4">
            <Panel>
              <PanelHeader
                title={selected.name}
                description={`${selected.category} · ${selected.level} · ~${selected.event_estimate} events · hosts: ${selected.hosts.join(", ")}`}
                actions={
                  <div className="flex items-end gap-2">
                    <div className="hidden sm:block">
                      <Label htmlFor="seed" className="sr-only">
                        Seed
                      </Label>
                      <Input id="seed" value={seed} onChange={(e) => setSeed(e.target.value.replace(/\D/g, "").slice(0, 9))} placeholder="seed (random)" className="h-8 w-28 font-mono text-xs" title="Optional seed for a reproducible run" />
                    </div>
                    <Button variant="primary" loading={running} onClick={execute}>
                      <Play /> Run scenario
                    </Button>
                  </div>
                }
              />
              <div className="grid gap-5 p-4 lg:grid-cols-2">
                <div className="space-y-3">
                  <p className="text-[13px] leading-relaxed">{selected.narrative}</p>
                  <div className="flex flex-wrap gap-1.5">
                    {selected.mitre.map((t) => (
                      <a key={t} href={`https://attack.mitre.org/techniques/${t.replace(".", "/")}/`} target="_blank" rel="noreferrer noopener">
                        <Tag mono className="hover:text-foreground">
                          {t}
                        </Tag>
                      </a>
                    ))}
                  </div>
                  <div className="text-xs text-muted">
                    Designed to trigger:{" "}
                    {selected.expected_rules.map((r) => (
                      <Link key={r} href={`/rules?rule=${r}`} className="mr-1.5 font-mono text-primary hover:underline">
                        {r}
                      </Link>
                    ))}
                  </div>
                </div>
                <div className="space-y-3">
                  <div>
                    <h4 className="mb-1 text-xs font-medium uppercase tracking-wide text-subtle">Learning objectives</h4>
                    <ul className="list-disc space-y-0.5 pl-4 text-[13px] text-muted">
                      {selected.learning_objectives.map((o) => (
                        <li key={o}>{o}</li>
                      ))}
                    </ul>
                  </div>
                  <div>
                    <h4 className="mb-1 text-xs font-medium uppercase tracking-wide text-subtle">Questions to answer in your investigation</h4>
                    <ol className="list-decimal space-y-0.5 pl-4 text-[13px] text-muted">
                      {selected.investigation_questions.map((q) => (
                        <li key={q}>{q}</li>
                      ))}
                    </ol>
                  </div>
                </div>
              </div>
            </Panel>
            <Panel>
              <PanelHeader title={runId ? "Run result" : "No runs yet"} description={runId ? "From raw log to documented incident" : undefined} />
              <div className="p-4">
                {runId ? (
                  <RunResult key={runId} runId={runId} />
                ) : (
                  <EmptyState icon={FlaskConical} title="Run this scenario to see the pipeline" description="Events are appended after the current simulation clock, so each run is a new, independent occurrence." />
                )}
              </div>
            </Panel>
          </div>
        ) : (
          <Skeleton className="h-96 w-full" />
        )}
      </div>

      <Panel className="mt-4 overflow-hidden">
        <PanelHeader title="Run history" />
        {runs?.length ? (
          <div className="overflow-x-auto">
            <table className={tableCls.table}>
              <thead className={tableCls.head}>
                <tr>
                  <th className={tableCls.th}>Scenario</th>
                  <th className={tableCls.th}>Simulated time (UTC)</th>
                  <th className={tableCls.th}>Events</th>
                  <th className={tableCls.th}>Detection</th>
                  <th className={tableCls.th}>Incident</th>
                  <th className={tableCls.th}>Executed</th>
                </tr>
              </thead>
              <tbody>
                {runs.map((r) => (
                  <tr key={r.id} className={cn(tableCls.row, "cursor-pointer")} onClick={() => set({ scenario: r.scenario_id, run: r.id })}>
                    <td className={tableCls.td}>{r.scenario_name}</td>
                    <td className={cn(tableCls.td, "font-mono text-xs text-muted")}>{formatTs(r.simulated_start, { seconds: false })}</td>
                    <td className={cn(tableCls.td, "font-mono text-xs")}>{r.event_count}</td>
                    <td className={tableCls.td}>
                      {r.missed_rules.length ? (
                        <span className="inline-flex items-center gap-1 text-xs text-critical">
                          <CircleDashed className="size-3" /> missed {r.missed_rules.join(", ")}
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-xs text-success">
                          <Check className="size-3" /> {r.triggered_rules.length}/{r.expected_rules.length} rules
                        </span>
                      )}
                    </td>
                    <td className={tableCls.td}>
                      {r.incident_ids.map((i) => (
                        <Link key={i} href={incidentHref(i)} onClick={(e) => e.stopPropagation()} className="mr-1.5 font-mono text-xs text-primary hover:underline">
                          {i}
                        </Link>
                      ))}
                      {!r.incident_ids.length && <span className="text-xs text-subtle">-</span>}
                    </td>
                    <td className={cn(tableCls.td, "text-xs text-muted")}>{relative(r.executed_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="px-4 py-6 text-center text-xs text-muted">No simulations executed yet.</p>
        )}
      </Panel>
    </>
  );
}

export default function SimulationsPage() {
  return (
    <React.Suspense fallback={<Skeleton className="h-96 w-full" />}>
      <Simulations />
    </React.Suspense>
  );
}
