"use client";

import { ArrowRight, BellRing, CircleCheck, FlaskConical, History } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import * as React from "react";
import useSWR from "swr";

import { SEVERITY_ORDER, SeverityBadge, StatusBadge } from "@/components/soc/badges";
import { Legend, RankedBars, SERIES, TimeBars } from "@/components/soc/charts";
import { EmptyState, ErrorState, PageHeader, Segmented, tableCls, Term } from "@/components/soc/common";
import { EntityLink } from "@/components/soc/investigation-context";
import { SignalChain, type ChainStage } from "@/components/soc/signal-chain";
import { Button } from "@/components/ui/button";
import { Select } from "@/components/ui/overlays";
import { Panel, PanelHeader, Skeleton } from "@/components/ui/primitives";
import { qs } from "@/lib/api";
import { alertHref } from "@/lib/routes";
import type { Alert, Dashboard, EventFacets, Metrics, Severity } from "@/lib/types";
import { cn, formatShortDate, formatTs, nf, relative } from "@/lib/utils";

type Range = "24h" | "7d" | "30d" | "all";

const RANGE_LABEL: Record<Range, string> = { "24h": "last 24 hours", "7d": "last 7 days", "30d": "last 30 days", all: "whole dataset" };
const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };

function perUnit(numerator: number, denominator: number, noun: string) {
  if (!numerator || !denominator) return undefined;
  return `1 per ${nf.format(Math.round(denominator / numerator))} ${noun}`;
}

function buildChain(d: Dashboard, m: Metrics | undefined): ChainStage[] {
  const failures = d.timeline.reduce((sum, b) => sum + b.failures, 0);
  const k = d.kpis;
  const open = k.incidents_new + k.incidents_investigating;
  const decided = m ? m.overall.true_positive + m.overall.benign + m.overall.false_positive : undefined;
  return [
    {
      stage: 1,
      name: "Telemetry",
      value: k.events_in_range,
      caption: "events",
      detail: `${nf.format(k.events_last_24h)} in the last 24 h`,
      href: "/events",
      segments: [
        { label: "Failed authentications", value: failures, color: SERIES.secondary },
        { label: "Other", value: k.events_in_range - failures, color: SERIES.primary },
      ],
    },
    {
      stage: 2,
      name: "Detections",
      value: k.alerts_in_range,
      caption: "alerts",
      conversion: perUnit(k.alerts_in_range, k.events_in_range, "events"),
      detail: `${nf.format(k.alerts_unassigned)} awaiting triage`,
      href: "/alerts",
      segments: SEVERITY_ORDER.map((sev) => ({ label: sev[0].toUpperCase() + sev.slice(1), value: d.severity.find((s) => s.severity === sev)?.count ?? 0, color: `var(--sev-${sev})` })),
    },
    {
      stage: 3,
      name: "Incidents",
      value: open,
      caption: "open",
      conversion: k.alerts_in_range ? `${nf.format(open + k.incidents_closed)} from ${nf.format(k.alerts_in_range)} alerts` : undefined,
      detail: `${nf.format(k.incidents_new)} not yet acknowledged`,
      href: "/incidents",
      segments: [
        { label: "New", value: k.incidents_new, color: "var(--primary)" },
        { label: "In progress", value: k.incidents_investigating, color: "var(--muted)" },
        { label: "Closed", value: k.incidents_closed, color: "var(--border-strong)" },
      ],
    },
    {
      stage: 4,
      name: "Decisions",
      value: decided,
      caption: "alerts closed with a verdict",
      detail: m?.overall.precision !== null && m?.overall.precision !== undefined ? `Precision ${Math.round(m.overall.precision * 100)}%` : "No verdicts yet",
      href: "/metrics",
      segments: m
        ? [
            { label: "True positive", value: m.overall.true_positive, color: SERIES.secondary },
            { label: "Benign", value: m.overall.benign, color: "var(--success)" },
            { label: "False positive", value: m.overall.false_positive, color: "var(--subtle)" },
          ]
        : undefined,
    },
  ];
}

function AttentionList({ alerts, clock }: { alerts: Alert[]; clock: Date }) {
  const open = alerts
    .filter((a) => a.status === "new" || a.status === "investigating")
    .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || b.timestamp.localeCompare(a.timestamp))
    .slice(0, 6);
  if (!open.length) return <EmptyState icon={CircleCheck} title="Nothing waiting" description="Every alert in this window has a verdict." className="py-10" />;
  return (
    <ul className="divide-y divide-border">
      {open.map((a) => (
        <li key={a.id}>
          <Link href={alertHref(a.id)} className="flex items-start gap-3 px-4 py-3 transition-colors hover:bg-surface-2">
            <SeverityBadge severity={a.severity} className="mt-px w-[5.25rem]" />
            <span className="min-w-0 flex-1">
              <span className="block truncate text-sm font-medium">{a.rule_name}</span>
              <span className="block truncate text-xs text-subtle">
                {[a.hostname, a.username ?? a.source_ip].filter(Boolean).join(" · ")}
              </span>
            </span>
            <span className="shrink-0 font-mono text-2xs text-subtle">{relative(a.timestamp, clock)}</span>
          </Link>
        </li>
      ))}
    </ul>
  );
}

export default function OverviewPage() {
  const router = useRouter();
  const [range, setRange] = React.useState<Range>("7d");
  const [severity, setSeverity] = React.useState("all");
  const [host, setHost] = React.useState("all");
  const [status, setStatus] = React.useState("all");
  const params = qs({ range, severity: severity === "all" ? null : severity, host: host === "all" ? null : host, status: status === "all" ? null : status });
  const { data, error, mutate, isLoading } = useSWR<Dashboard>(`/dashboard${params}`, { refreshInterval: 20000, keepPreviousData: true });
  const { data: metrics } = useSWR<Metrics>("/metrics", { refreshInterval: 30000 });
  const { data: facets } = useSWR<EventFacets>("/events/facets");

  const clock = data ? new Date(data.clock) : new Date();
  const hourly = (data?.bucket_seconds ?? 3600) < 86400;
  const tick = (v: string) => {
    if (!hourly) return formatShortDate(v);
    const time = formatTs(v, { date: false, seconds: false });
    return range === "24h" ? time : `${formatShortDate(v)} ${time}`;
  };
  const timeline = (data?.timeline ?? []).map((b) => ({ ...b, other: b.events - b.failures }));
  const filtered = severity !== "all" || host !== "all" || status !== "all";

  return (
    <>
      <PageHeader
        title="Overview"
        description={
          <>
            {RANGE_LABEL[range][0].toUpperCase() + RANGE_LABEL[range].slice(1)} of lab telemetry, up to the <Term name="Simulation clock">simulation clock</Term>.
          </>
        }
        actions={
          <>
            <Segmented
              aria-label="Time range"
              value={range}
              onChange={setRange}
              options={[
                { value: "24h", label: "24h" },
                { value: "7d", label: "7d" },
                { value: "30d", label: "30d" },
                { value: "all", label: "All" },
              ]}
            />
            <Button asChild variant="primary">
              <Link href="/simulations">
                <FlaskConical /> Run a scenario
              </Link>
            </Button>
          </>
        }
      />

      {error ? (
        <Panel>
          <ErrorState error={error} retry={() => mutate()} />
        </Panel>
      ) : (
        <div className={cn("space-y-4 transition-opacity", isLoading && data && "opacity-60")}>
          {data ? <SignalChain stages={buildChain(data, metrics)} /> : <Skeleton className="h-44 w-full" />}

          <div className="flex flex-wrap items-center gap-2 pt-2">
            <span className="eyebrow mr-1">Filter</span>
            <Select
              aria-label="Severity filter"
              size="sm"
              className="w-36"
              value={severity}
              onValueChange={setSeverity}
              options={[{ value: "all", label: "All severities" }, ...["critical", "high", "medium", "low"].map((s) => ({ value: s, label: <span className="capitalize">{s}</span> }))]}
            />
            <Select
              aria-label="Host filter"
              size="sm"
              className="w-40"
              value={host}
              onValueChange={setHost}
              options={[{ value: "all", label: "All hosts" }, ...(facets?.hostnames ?? []).map((h) => ({ value: h, label: h }))]}
            />
            <Select
              aria-label="Alert status filter"
              size="sm"
              className="w-44"
              value={status}
              onValueChange={setStatus}
              options={[
                { value: "all", label: "Any alert status" },
                { value: "new", label: "New" },
                { value: "investigating", label: "Investigating" },
                { value: "resolved", label: "True positive" },
                { value: "benign,false_positive", label: "Benign / false positive" },
              ]}
            />
            {filtered && (
              <Button size="sm" variant="ghost" onClick={() => (setSeverity("all"), setHost("all"), setStatus("all"))}>
                Clear filters
              </Button>
            )}
            {data && (
              <span className="ml-auto font-mono text-2xs text-subtle">
                {formatTs(data.start, { seconds: false })} → {formatTs(data.end, { seconds: false })} UTC
              </span>
            )}
          </div>

          <div className="grid gap-4 xl:grid-cols-3">
            <Panel className="xl:col-span-2">
              <PanelHeader
                title="Event activity"
                description="Events per time bucket"
                actions={<Legend items={[{ label: "Other events", color: SERIES.primary }, { label: "Failed authentications", color: SERIES.secondary }]} />}
              />
              <div className="p-4">
                {data ? (
                  <TimeBars
                    ariaLabel="Events over time"
                    data={timeline}
                    xKey="bucket"
                    tickFormatter={tick}
                    labelFormatter={(v) => `${formatTs(v, { seconds: false })} UTC`}
                    keys={[
                      { key: "other", label: "Other events", color: SERIES.primary },
                      { key: "failures", label: "Failed authentications", color: SERIES.secondary },
                    ]}
                  />
                ) : (
                  <Skeleton className="h-[220px] w-full" />
                )}
              </div>
            </Panel>
            <Panel>
              <PanelHeader
                title="Needs attention"
                description="Open alerts, most severe first"
                actions={
                  <Button asChild size="sm" variant="ghost">
                    <Link href="/alerts">
                      Queue <ArrowRight />
                    </Link>
                  </Button>
                }
              />
              {data ? <AttentionList alerts={data.recent_alerts} clock={clock} /> : <Skeleton className="m-4 h-48" />}
            </Panel>
          </div>

          <div className="grid gap-4 xl:grid-cols-3">
            <Panel className="overflow-hidden xl:col-span-2">
              <PanelHeader title="Latest detections" />
              {data && data.recent_alerts.length === 0 ? (
                <EmptyState icon={BellRing} title="No detections in this window" description="Widen the time range or run a scenario." />
              ) : (
                <div className="overflow-x-auto">
                  <table className={tableCls.table}>
                    <thead className={tableCls.head}>
                      <tr>
                        <th className={tableCls.th}>Severity</th>
                        <th className={tableCls.th}>Rule</th>
                        <th className={cn(tableCls.th, "hidden md:table-cell")}>Host</th>
                        <th className={cn(tableCls.th, "hidden md:table-cell")}>Entity</th>
                        <th className={tableCls.th}>Time (UTC)</th>
                        <th className={tableCls.th}>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(data?.recent_alerts ?? []).map((a) => (
                        <tr key={a.id} className={cn(tableCls.row, "cursor-pointer")} onClick={() => router.push(alertHref(a.id))}>
                          <td className={tableCls.td}>
                            <SeverityBadge severity={a.severity} />
                          </td>
                          <td className={cn(tableCls.td, "min-w-48")}>
                            <Link href={alertHref(a.id)} className="font-medium hover:text-primary" onClick={(e) => e.stopPropagation()}>
                              {a.rule_name}
                            </Link>
                            <div className="font-mono text-2xs text-subtle">{a.rule_id}</div>
                          </td>
                          <td className={cn(tableCls.td, "hidden md:table-cell")}>
                            <EntityLink kind="host" value={a.hostname} />
                          </td>
                          <td className={cn(tableCls.td, "hidden md:table-cell")}>
                            {a.username ? <EntityLink kind="user" value={a.username} /> : <EntityLink kind="ip" value={a.source_ip} />}
                          </td>
                          <td className={cn(tableCls.td, "whitespace-nowrap font-mono text-xs text-muted")}>{formatTs(a.timestamp, { seconds: false })}</td>
                          <td className={tableCls.td}>
                            <StatusBadge status={a.status} />
                          </td>
                        </tr>
                      ))}
                      {!data &&
                        Array.from({ length: 5 }).map((_, i) => (
                          <tr key={i}>
                            <td colSpan={6} className="px-3 py-2">
                              <Skeleton className="h-6 w-full" />
                            </td>
                          </tr>
                        ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Panel>
            <Panel>
              <PanelHeader title="Rules that fired" description="In this window" />
              <div className="p-4">
                {data?.top_rules.length ? (
                  <RankedBars
                    rows={data.top_rules.map((r) => ({
                      key: r.rule_id,
                      label: (
                        <Link href={`/alerts?rule_id=${r.rule_id}&status=`} className="hover:text-primary">
                          <span className="mr-1.5 font-mono text-2xs text-subtle">{r.rule_id}</span>
                          {r.rule_name}
                        </Link>
                      ),
                      value: r.count,
                    }))}
                  />
                ) : data ? (
                  <p className="text-xs text-muted">No rule fired in this window.</p>
                ) : (
                  <Skeleton className="h-40 w-full" />
                )}
              </div>
            </Panel>
          </div>

          <div className="grid gap-4 lg:grid-cols-2 xl:grid-cols-3">
            <Panel>
              <PanelHeader title="Hosts" description="Most alerts, then most events" />
              <div className="p-4">
                {data ? (
                  <RankedBars
                    rows={data.top_hosts.map((h) => ({
                      key: h.hostname,
                      label: (
                        <span className="flex items-center gap-2">
                          <EntityLink kind="host" value={h.hostname} />
                          <span className="truncate text-2xs text-subtle">{h.role}</span>
                        </span>
                      ),
                      value: h.events,
                      meta: h.alerts ? <span className="font-mono text-2xs text-foreground">{h.alerts} alert{h.alerts === 1 ? "" : "s"}</span> : null,
                    }))}
                  />
                ) : (
                  <Skeleton className="h-48 w-full" />
                )}
              </div>
            </Panel>
            <Panel>
              <PanelHeader title="Source addresses" description="Most failed authentications" />
              <div className="p-4">
                {data ? (
                  <RankedBars
                    color={SERIES.secondary}
                    rows={data.top_source_ips.map((ip) => ({
                      key: ip.ip,
                      label: <EntityLink kind="ip" value={ip.ip} />,
                      value: ip.failures,
                      meta: (
                        <span className={cn("font-mono text-2xs", ip.reputation === "malicious" ? "text-critical" : "text-subtle")}>
                          {ip.internal ? "internal" : ip.reputation}
                        </span>
                      ),
                    }))}
                  />
                ) : (
                  <Skeleton className="h-48 w-full" />
                )}
              </div>
            </Panel>
            <Panel className="lg:col-span-2 xl:col-span-1">
              <PanelHeader
                title="Shift log"
                description="What changed in the lab"
                actions={
                  <Button asChild size="sm" variant="ghost">
                    <Link href="/activity">
                      <History /> All
                    </Link>
                  </Button>
                }
              />
              <ol className="divide-y divide-border">
                {(data?.recent_activity ?? []).slice(0, 7).map((a) => (
                  <li key={a.id} className="grid grid-cols-[4.5rem_1fr] gap-3 px-4 py-2.5">
                    <span className="pt-px font-mono text-2xs text-subtle">{relative(a.timestamp)}</span>
                    <span className="min-w-0 text-sm leading-snug">
                      {a.message}
                      <span className="mt-0.5 block font-mono text-2xs text-subtle">{a.actor}</span>
                    </span>
                  </li>
                ))}
              </ol>
            </Panel>
          </div>
        </div>
      )}
    </>
  );
}
