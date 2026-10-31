"use client";

import Link from "next/link";
import useSWR from "swr";

import { CLASSIFICATION_LABEL, SeverityBadge, SEVERITY_ORDER } from "@/components/soc/badges";
import { Legend, SEVERITY_COLOR, TimeBars } from "@/components/soc/charts";
import { PageHeader, Stat, tableCls, Term } from "@/components/soc/common";
import { Panel, PanelHeader, Skeleton } from "@/components/ui/primitives";
import type { Metrics } from "@/lib/types";
import { cn, formatDuration, formatShortDate } from "@/lib/utils";

const pct = (v: number | null | undefined) => (v === null || v === undefined ? "-" : `${Math.round(v * 100)}%`);

export default function MetricsPage() {
  const { data: m } = useSWR<Metrics>("/metrics", { refreshInterval: 30000 });

  return (
    <>
      <PageHeader
        title="Detection Metrics"
        description={
          <>
            How well detection and response are performing. <Term name="Precision">Precision</Term> and false-positive rate come from analyst decisions, so close
            alerts and incidents to make them meaningful. Response times use wall-clock time; detection delay uses the simulated event timeline.
          </>
        }
      />
      {!m ? (
        <Skeleton className="h-[70vh] w-full" />
      ) : (
        <div className="space-y-4">
          <Panel className="grid grid-cols-2 gap-px overflow-hidden bg-border sm:grid-cols-3 xl:grid-cols-6">
            <Stat label={<Term name="Precision">Precision</Term>} value={pct(m.overall.precision)} hint={`${m.overall.true_positive} TP / ${m.overall.false_positive} FP decided`} tone="primary" />
            <Stat label="False-positive rate" value={pct(m.overall.false_positive_rate)} hint={`${m.overall.benign} benign, ${m.overall.open} still open`} />
            <Stat label={<Term name="MTTD">Mean time to detect</Term>} value={formatDuration(m.overall.mean_time_to_detect_seconds)} hint="First event to alert" />
            <Stat label={<Term name="MTTA">Mean time to acknowledge</Term>} value={formatDuration(m.overall.mean_time_to_acknowledge_seconds)} hint="Incident created to triage" />
            <Stat label={<Term name="MTTR">Mean time to resolve</Term>} value={formatDuration(m.overall.mean_time_to_resolve_seconds)} hint={`${m.overall.incidents_closed}/${m.overall.incidents} incidents closed`} />
            <Stat label="Scenario coverage" value={`${m.simulation.scenarios_fully_detected}/${m.simulation.scenarios_executed || 0}`} hint={`${m.simulation.scenarios_total} scenarios available`} tone="success" />
          </Panel>

          <div className="grid gap-4 xl:grid-cols-3">
            <Panel className="xl:col-span-2">
              <PanelHeader
                title="Alerts per day by severity"
                description="Lab timezone"
                actions={<Legend items={SEVERITY_ORDER.map((s) => ({ label: s, color: SEVERITY_COLOR[s] }))} />}
              />
              <div className="p-4">
                <TimeBars
                  ariaLabel="Alerts per day by severity"
                  data={m.alerts_per_day}
                  xKey="date"
                  tickFormatter={(v) => formatShortDate(`${v}T12:00:00Z`)}
                  keys={[...SEVERITY_ORDER].reverse().map((s) => ({ key: s, label: s, color: SEVERITY_COLOR[s] }))}
                />
              </div>
            </Panel>
            <Panel>
              <PanelHeader title="Incident outcomes" />
              <ul className="divide-y divide-border">
                {m.classification.map((c) => (
                  <li key={c.classification} className="flex items-center justify-between px-4 py-2.5 text-[13px]">
                    <Term name={CLASSIFICATION_LABEL[c.classification].replace("Undetermined", "")}>{CLASSIFICATION_LABEL[c.classification]}</Term>
                    <span className="font-mono tabular-nums">{c.count}</span>
                  </li>
                ))}
              </ul>
              <div className="border-t border-border p-4 text-xs text-muted">
                <Term name="MITRE ATT&CK">ATT&CK</Term>: {m.mitre.techniques_covered} techniques covered by rules, {m.mitre.techniques_detected} observed in alerts.{" "}
                <Link href="/mitre" className="text-primary hover:underline">
                  Matrix
                </Link>
              </div>
            </Panel>
          </div>

          <Panel className="overflow-hidden">
            <PanelHeader title="Per-rule performance" description="Use this to decide which rules need tuning (low precision) or more coverage" />
            <div className="overflow-x-auto">
              <table className={tableCls.table}>
                <thead className={tableCls.head}>
                  <tr>
                    <th className={tableCls.th}>Rule</th>
                    <th className={tableCls.th}>Severity</th>
                    <th className={cn(tableCls.th, "text-right")}>Alerts</th>
                    <th className={cn(tableCls.th, "text-right")}>Open</th>
                    <th className={cn(tableCls.th, "text-right")}>TP</th>
                    <th className={cn(tableCls.th, "text-right")}>Benign</th>
                    <th className={cn(tableCls.th, "text-right")}>FP</th>
                    <th className={cn(tableCls.th, "w-40")}>Precision</th>
                    <th className={cn(tableCls.th, "text-right")}>Avg. time to detect</th>
                  </tr>
                </thead>
                <tbody>
                  {m.rules.map((r) => (
                    <tr key={r.rule_id} className={cn(tableCls.row, !r.enabled && "opacity-55")}>
                      <td className={tableCls.td}>
                        <Link href={`/rules?rule=${r.rule_id}`} className="hover:text-primary">
                          <span className="mr-2 font-mono text-[11px] text-subtle">{r.rule_id}</span>
                          {r.rule_name}
                        </Link>
                      </td>
                      <td className={tableCls.td}>
                        <SeverityBadge severity={r.severity} />
                      </td>
                      {[r.alerts, r.open, r.true_positive, r.benign, r.false_positive].map((v, i) => (
                        <td key={i} className={cn(tableCls.td, "text-right font-mono text-xs tabular-nums", !v && "text-subtle")}>
                          {v}
                        </td>
                      ))}
                      <td className={tableCls.td}>
                        {r.precision === null ? (
                          <span className="text-xs text-subtle">no decisions</span>
                        ) : (
                          <div className="flex items-center gap-2">
                            <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-surface-2">
                              <div className="h-full rounded-full bg-primary" style={{ width: `${r.precision * 100}%` }} />
                            </div>
                            <span className="w-9 text-right font-mono text-xs tabular-nums">{pct(r.precision)}</span>
                          </div>
                        )}
                      </td>
                      <td className={cn(tableCls.td, "text-right font-mono text-xs text-muted")}>{formatDuration(r.mean_time_to_detect_seconds)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>

          <Panel className="overflow-hidden">
            <PanelHeader
              title="Simulation detection coverage"
              description="Did every scenario trigger the rules it was designed to exercise?"
              actions={
                <span className="text-xs text-muted">
                  Challenges: {m.simulation.challenges_completed} completed
                  {m.simulation.challenge_average_pct !== null && <> · avg score {m.simulation.challenge_average_pct}%</>}
                </span>
              }
            />
            <div className="overflow-x-auto">
              <table className={tableCls.table}>
                <thead className={tableCls.head}>
                  <tr>
                    <th className={tableCls.th}>Scenario</th>
                    <th className={tableCls.th}>Expected rules</th>
                    <th className={cn(tableCls.th, "text-right")}>Runs</th>
                    <th className={cn(tableCls.th, "text-right")}>Fully detected</th>
                    <th className={tableCls.th}>Last result</th>
                  </tr>
                </thead>
                <tbody>
                  {m.simulation.per_scenario.map((s) => (
                    <tr key={s.scenario_id} className={tableCls.row}>
                      <td className={tableCls.td}>
                        <Link href={`/simulations?scenario=${s.scenario_id}`} className="hover:text-primary">
                          {s.name}
                        </Link>
                      </td>
                      <td className={cn(tableCls.td, "font-mono text-xs text-muted")}>{s.expected_rules.join(", ")}</td>
                      <td className={cn(tableCls.td, "text-right font-mono text-xs")}>{s.runs}</td>
                      <td className={cn(tableCls.td, "text-right font-mono text-xs")}>{s.detected_runs}</td>
                      <td className={cn(tableCls.td, "text-xs")}>
                        {!s.runs ? <span className="text-subtle">not run</span> : s.last_missed.length ? <span className="text-critical">missed {s.last_missed.join(", ")}</span> : <span className="text-success">all detected</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>
        </div>
      )}
    </>
  );
}
