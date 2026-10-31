"use client";

import { ArrowRight, BellRing, FlaskConical, History } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import * as React from "react";
import useSWR from "swr";

import { SeverityBadge, StatusBadge, Tag } from "@/components/soc/badges";
import { Legend, RankedBars, SERIES, SeverityBreakdown, TimeBars } from "@/components/soc/charts";
import { EmptyState, ErrorState, PageHeader, Segmented, Stat, tableCls, Term } from "@/components/soc/common";
import { EntityLink } from "@/components/soc/investigation-context";
import { Button } from "@/components/ui/button";
import { Select } from "@/components/ui/overlays";
import { Panel, PanelHeader, Skeleton } from "@/components/ui/primitives";
import { qs } from "@/lib/api";
import type { Dashboard, EventFacets } from "@/lib/types";
import { cn, formatShortDate, formatTs, relative } from "@/lib/utils";
import { alertHref } from "@/lib/routes";

type Range = "24h" | "7d" | "30d" | "all";

export default function DashboardPage() {
  const router = useRouter();
  const [range, setRange] = React.useState<Range>("7d");
  const [severity, setSeverity] = React.useState("all");
  const [host, setHost] = React.useState("all");
  const [status, setStatus] = React.useState("all");
  const params = qs({ range, severity: severity === "all" ? null : severity, host: host === "all" ? null : host, status: status === "all" ? null : status });
  const { data, error, mutate, isLoading } = useSWR<Dashboard>(`/dashboard${params}`, { refreshInterval: 20000, keepPreviousData: true });
  const { data: facets } = useSWR<EventFacets>("/events/facets");

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
        title="Security Overview"
        description={
          <>
            Live view of the lab environment. Every number below is computed by the backend from the loaded datasets - nothing is
            randomly generated. Ranges are relative to the <Term name="Simulation clock">simulation clock</Term>.
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
                <FlaskConical /> Run simulation
              </Link>
            </Button>
          </>
        }
      />

      <div className="mb-4 flex flex-wrap items-center gap-2">
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
          className="w-40"
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
        {data && <span className="ml-auto text-xs text-subtle">Window: {formatTs(data.start, { seconds: false })} - {formatTs(data.end, { seconds: false })} UTC</span>}
      </div>

      {error ? (
        <Panel>
          <ErrorState error={error} retry={() => mutate()} />
        </Panel>
      ) : (
        <div className={cn("space-y-4 transition-opacity", isLoading && data && "opacity-60")}>
          <Panel className="grid grid-cols-2 gap-px overflow-hidden bg-border sm:grid-cols-4 xl:grid-cols-8">
            {data ? (
              <>
                <Stat label="Events processed" value={data.kpis.events_total} hint="All datasets" href="/events" />
                <Stat label="Events, last 24h" value={data.kpis.events_last_24h} hint="Simulated time" />
                <Stat label="Alerts in range" value={data.kpis.alerts_in_range} hint={`${range === "all" ? "All time" : `Last ${range}`}`} href="/alerts" />
                <Stat label="Awaiting triage" value={data.kpis.alerts_unassigned} hint="Open, no incident" tone={data.kpis.alerts_unassigned ? "primary" : undefined} href="/alerts?incident=unassigned&status=new" />
                <Stat label="Critical open" value={data.kpis.critical_open} hint="Alerts" tone={data.kpis.critical_open ? "critical" : undefined} href="/alerts?severity=critical&status=new,investigating" />
                <Stat label="Incidents open" value={data.kpis.incidents_new} hint="Status new" tone={data.kpis.incidents_new ? "high" : undefined} href="/incidents?status=new" />
                <Stat label="Investigating" value={data.kpis.incidents_investigating} hint="Incl. contained" href="/incidents?status=investigating,contained" />
                <Stat label="Incidents closed" value={data.kpis.incidents_closed} hint="With documented decision" tone={data.kpis.incidents_closed ? "success" : undefined} href="/incidents?status=closed" />
              </>
            ) : (
              Array.from({ length: 8 }).map((_, i) => (
                <div key={i} className="bg-surface px-4 py-3.5">
                  <Skeleton className="h-3 w-20" />
                  <Skeleton className="mt-2 h-6 w-14" />
                </div>
              ))
            )}
          </Panel>

          <div className="grid gap-4 xl:grid-cols-3">
            <Panel className="xl:col-span-2">
              <PanelHeader
                title="Event activity"
                description="Events ingested per time bucket; failed authentications highlighted"
                actions={<Legend items={[{ label: "Other events", color: SERIES.primary }, { label: "Failures", color: SERIES.secondary }]} />}
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
                      { key: "failures", label: "Failures", color: SERIES.secondary },
                    ]}
                  />
                ) : (
                  <Skeleton className="h-[220px] w-full" />
                )}
              </div>
            </Panel>
            <Panel>
              <PanelHeader title="Alerts by severity" description="Click a severity to open the filtered queue" />
              <div className="p-4">
                {data ? (
                  <SeverityBreakdown data={data.severity} onSelect={(s) => router.push(`/alerts?severity=${s}`)} />
                ) : (
                  <Skeleton className="h-40 w-full" />
                )}
              </div>
            </Panel>
          </div>

          <div className="grid gap-4 xl:grid-cols-3">
            <Panel className="overflow-hidden xl:col-span-2">
              <PanelHeader
                title="Recent alerts"
                actions={
                  <Button asChild size="sm" variant="ghost">
                    <Link href="/alerts">
                      Alert queue <ArrowRight />
                    </Link>
                  </Button>
                }
              />
              {data && data.recent_alerts.length === 0 ? (
                <EmptyState icon={BellRing} title="No alerts in this window" description="Widen the time range or run a simulation to generate detections." />
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
                          <td className={tableCls.td}>
                            <Link href={alertHref(a.id)} className="font-medium hover:text-primary" onClick={(e) => e.stopPropagation()}>
                              {a.rule_name}
                            </Link>
                            <div className="font-mono text-[11px] text-subtle">{a.rule_id}</div>
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
              <PanelHeader title="Top triggered rules" />
              <div className="p-4">
                {data?.top_rules.length ? (
                  <RankedBars
                    rows={data.top_rules.map((r) => ({
                      key: r.rule_id,
                      label: (
                        <Link href={`/alerts?rule_id=${r.rule_id}`} className="hover:text-primary">
                          <span className="mr-1.5 font-mono text-[11px] text-subtle">{r.rule_id}</span>
                          {r.rule_name}
                        </Link>
                      ),
                      value: r.count,
                    }))}
                  />
                ) : data ? (
                  <p className="text-xs text-muted">No rules triggered in this window.</p>
                ) : (
                  <Skeleton className="h-40 w-full" />
                )}
              </div>
            </Panel>
          </div>

          <div className="grid gap-4 lg:grid-cols-2 xl:grid-cols-3">
            <Panel>
              <PanelHeader title="Most active hosts" description="Ranked by alerts, then events" />
              <div className="p-4">
                {data ? (
                  <RankedBars
                    rows={data.top_hosts.map((h) => ({
                      key: h.hostname,
                      label: (
                        <span className="flex items-center gap-2">
                          <EntityLink kind="host" value={h.hostname} />
                          <span className="truncate text-[11px] text-subtle">{h.role}</span>
                        </span>
                      ),
                      value: h.events,
                      meta: h.alerts ? <Tag className="text-high">{h.alerts} alerts</Tag> : null,
                    }))}
                  />
                ) : (
                  <Skeleton className="h-48 w-full" />
                )}
              </div>
            </Panel>
            <Panel>
              <PanelHeader title="Top source IPs" description="Ranked by failed authentications" />
              <div className="p-4">
                {data ? (
                  <RankedBars
                    color={SERIES.secondary}
                    rows={data.top_source_ips.map((ip) => ({
                      key: ip.ip,
                      label: <EntityLink kind="ip" value={ip.ip} />,
                      value: ip.failures,
                      meta: (
                        <Tag className={cn(ip.reputation === "malicious" && "text-critical", ip.reputation === "suspicious" && "text-high")}>
                          {ip.internal ? "internal" : ip.reputation}
                        </Tag>
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
                title="Investigation activity"
                actions={
                  <Button asChild size="sm" variant="ghost">
                    <Link href="/activity">
                      <History /> All
                    </Link>
                  </Button>
                }
              />
              <ol className="divide-y divide-border">
                {(data?.recent_activity ?? []).slice(0, 8).map((a) => (
                  <li key={a.id} className="flex gap-3 px-4 py-2.5">
                    <span className={cn("mt-1.5 size-1.5 shrink-0 rounded-full", a.actor === "system" ? "bg-subtle" : "bg-primary")} aria-hidden />
                    <div className="min-w-0">
                      <p className="text-[13px] leading-snug text-foreground">{a.message}</p>
                      <p className="mt-0.5 text-[11px] text-subtle">
                        {a.actor} · {relative(a.timestamp)}
                      </p>
                    </div>
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
