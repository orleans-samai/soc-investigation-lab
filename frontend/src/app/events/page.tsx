"use client";

import { Download, FileJson, ScrollText, Search, Upload, X } from "lucide-react";
import Link from "next/link";
import * as React from "react";
import useSWR from "swr";

import { EmptyState, ErrorState, PageHeader, Pagination, Segmented, SortHeader, tableCls, Term } from "@/components/soc/common";
import { EntityLink, useInvestigation } from "@/components/soc/investigation-context";
import { drillDown, QueryBar } from "@/components/soc/query-bar";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger, Select } from "@/components/ui/overlays";
import { Input, Label, Panel, Skeleton } from "@/components/ui/primitives";
import { qs } from "@/lib/api";
import type { EventFacets, NormalizedEvent, Page } from "@/lib/types";
import { useUrlState } from "@/lib/use-url-state";
import { cn, formatTs, nf } from "@/lib/utils";

const DEFAULTS = {
  q: "",
  username: "",
  source_ip: "",
  hostname: "",
  event_source: "",
  event_type: "",
  outcome: "",
  log_level: "",
  dataset: "",
  start: "",
  end: "",
  ids: "",
  sort: "timestamp",
  order: "desc",
  page: "1",
  view: "normalized",
  mode: "filters",
  query: "",
};

type QueryResponse =
  | (Page<NormalizedEvent> & { mode: "events"; scanned: number })
  | { mode: "stats"; columns: string[]; rows: Record<string, string | number | null>[]; total: number; scanned: number };

const LEVEL_STYLE: Record<string, string> = {
  info: "text-subtle",
  warning: "text-medium",
  error: "text-high",
  critical: "text-critical",
};

// <input type="datetime-local"> has no timezone; the explorer treats it as UTC, like every timestamp shown.
const toInput = (iso: string) => (iso ? iso.slice(0, 16) : "");
const fromInput = (v: string) => (v ? `${v}:00Z` : "");

function FacetSelect({ label, value, options, onChange, width = "w-40" }: { label: string; value: string; options: string[]; onChange: (v: string) => void; width?: string }) {
  return (
    <Select
      aria-label={label}
      size="sm"
      className={width}
      value={value || "all"}
      onValueChange={(v) => onChange(v === "all" ? "" : v)}
      options={[{ value: "all", label: `Any ${label.toLowerCase()}` }, ...options.map((o) => ({ value: o, label: o }))]}
    />
  );
}

function StatsTable({
  columns,
  rows,
  onDrill,
}: {
  columns: string[];
  rows: Record<string, string | number | null>[];
  onDrill: (row: Record<string, string | number | null>) => void;
}) {
  if (!rows.length) return <EmptyState icon={ScrollText} title="No events match the query" />;
  const max = Math.max(...rows.map((r) => Number(r.count)));
  return (
    <div className="overflow-x-auto">
      <table className={tableCls.table}>
        <thead className={tableCls.head}>
          <tr>
            {columns.map((c) => (
              <th key={c} className={cn(tableCls.th, c === "count" && "w-64")}>
                {c}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i} tabIndex={0} title="Drill down into these events" onKeyDown={(e) => e.key === "Enter" && onDrill(row)} onClick={() => onDrill(row)} className={cn(tableCls.row, "cursor-pointer")}>
              {columns.map((c) =>
                c === "count" ? (
                  <td key={c} className="px-3 py-1.5">
                    <div className="flex items-center gap-2">
                      <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-surface-2">
                        <div className="h-full rounded-full bg-[var(--chart-1)]" style={{ width: `${(Number(row.count) / max) * 100}%` }} />
                      </div>
                      <span className="w-12 text-right font-mono text-xs tabular-nums">{nf.format(Number(row.count))}</span>
                    </div>
                  </td>
                ) : (
                  <td key={c} className="px-3 py-1.5 font-mono text-xs">
                    {row[c] ?? <span className="text-subtle">(empty)</span>}
                  </td>
                ),
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Explorer() {
  const [f, set, reset] = useUrlState(DEFAULTS);
  const { openEvent } = useInvestigation();
  const [search, setSearch] = React.useState(f.q);
  React.useEffect(() => {
    const t = setTimeout(() => search !== f.q && set({ q: search }), 300);
    return () => clearTimeout(t);
  }, [search, f.q, set]);

  const { view, mode, query: dsl, ...filters } = f;
  const queryMode = mode === "query";
  const filterQuery = { ...filters, sort: undefined, order: undefined, page: undefined };
  const filtered = useSWR<Page<NormalizedEvent>>(queryMode ? null : `/events${qs({ ...filters, page_size: 50 })}`, { keepPreviousData: true });
  const searched = useSWR<QueryResponse>(queryMode ? `/events/query${qs({ q: dsl, page: f.page, page_size: 50 })}` : null, { keepPreviousData: true });
  const data = queryMode ? (searched.data?.mode === "events" ? searched.data : undefined) : filtered.data;
  const stats = queryMode && searched.data?.mode === "stats" ? searched.data : undefined;
  const { error, mutate, isLoading } = queryMode ? searched : filtered;
  const exportParams = queryMode ? { query: dsl } : filterQuery;
  const { data: facets } = useSWR<EventFacets>("/events/facets");
  // In query mode the sort lives in the query itself ("| sort -field"), so headers rewrite that pipe.
  const querySort = /\|\s*sort\s+(-?)(\w+)/i.exec(dsl);
  const sortField = queryMode ? (querySort?.[2] ?? "timestamp") : f.sort;
  const order = (queryMode ? (querySort ? (querySort[1] ? "desc" : "asc") : "desc") : f.order) as "asc" | "desc";
  const onSort = (field: string) => {
    const nextOrder = sortField === field && order === "desc" ? "asc" : "desc";
    if (!queryMode) return set({ sort: field, order: nextOrder });
    const base = dsl.replace(/\|\s*sort\s+\S+(\s+(asc|desc))?/gi, "").trim();
    set({ query: `${base} | sort ${nextOrder === "desc" ? "-" : ""}${field}`.trim() });
  };
  const active = Object.entries(filterQuery).filter(([, v]) => v);

  return (
    <>
      <PageHeader
        title="Log Explorer"
        description={
          <>
            Search every ingested record. Each row keeps its <Term name="Raw log">raw log</Term> and the <Term name="Normalized fields">normalized fields</Term> the
            detection engine uses.
          </>
        }
        actions={
          <>
            <Button asChild>
              <Link href="/import">
                <Upload /> Import logs
              </Link>
            </Button>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button disabled={!data?.total}>
                  <Download /> Export {data ? nf.format(Math.min(data.total, 50000)) : ""}
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem asChild>
                  <a href={`/api/events/export${qs({ ...exportParams, format: "csv" })}`} download>
                    <Download /> CSV (current results)
                  </a>
                </DropdownMenuItem>
                <DropdownMenuItem asChild>
                  <a href={`/api/events/export${qs({ ...exportParams, format: "json" })}`} download>
                    <FileJson /> JSON, normalized schema
                  </a>
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </>
        }
      />

      <div className="mb-2 flex items-center gap-3">
        <Segmented
          aria-label="Search mode"
          value={queryMode ? "query" : "filters"}
          onChange={(v) => set({ mode: v, page: "1" })}
          options={[
            { value: "filters", label: "Filters" },
            { value: "query", label: "Query language" },
          ]}
        />
        {queryMode && <span className="text-xs text-subtle">KQL/SPL-style search with aggregations</span>}
      </div>

      {queryMode && (
        <Panel className="mb-3 p-3">
          <QueryBar
            value={dsl}
            onRun={(q) => set({ query: q, page: "1" })}
            matched={searched.data?.total}
            scanned={searched.data?.scanned}
          />
        </Panel>
      )}

      <Panel className={cn("mb-3 p-3", queryMode && "hidden")}>
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative min-w-60 flex-1">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-subtle" />
            <Input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder='Free text across message, raw log, command line... e.g. "failed root"'
              className="pl-8"
              aria-label="Search events"
            />
          </div>
          <Segmented
            aria-label="View"
            value={view as "normalized" | "raw"}
            onChange={(v) => set({ view: v })}
            options={[
              { value: "normalized", label: "Normalized" },
              { value: "raw", label: "Raw" },
            ]}
          />
        </div>
        <div className="mt-2 flex flex-wrap items-end gap-2">
          <Input value={f.username} onChange={(e) => set({ username: e.target.value })} placeholder="User" className="h-7 w-32" aria-label="Filter by user" />
          <Input value={f.source_ip} onChange={(e) => set({ source_ip: e.target.value })} placeholder="IP address" className="h-7 w-36 font-mono text-xs" aria-label="Filter by IP" />
          <FacetSelect label="Host" value={f.hostname} options={facets?.hostnames ?? []} onChange={(v) => set({ hostname: v })} width="w-36" />
          <FacetSelect label="Source" value={f.event_source} options={facets?.event_sources ?? []} onChange={(v) => set({ event_source: v })} width="w-44" />
          <FacetSelect label="Type" value={f.event_type} options={facets?.event_types ?? []} onChange={(v) => set({ event_type: v })} />
          <FacetSelect label="Outcome" value={f.outcome} options={["success", "failure", "unknown"]} onChange={(v) => set({ outcome: v })} width="w-36" />
          <FacetSelect label="Level" value={f.log_level} options={["info", "warning", "error", "critical"]} onChange={(v) => set({ log_level: v })} width="w-32" />
          <FacetSelect label="Dataset" value={f.dataset} options={facets?.datasets ?? []} onChange={(v) => set({ dataset: v })} width="w-44" />
          <div className="flex items-center gap-1.5">
            <Label htmlFor="start" className="sr-only">
              From (UTC)
            </Label>
            <Input id="start" type="datetime-local" value={toInput(f.start)} onChange={(e) => set({ start: fromInput(e.target.value) })} className="h-7 w-44 text-xs" title="From (UTC)" />
            <span className="text-xs text-subtle">to</span>
            <Label htmlFor="end" className="sr-only">
              To (UTC)
            </Label>
            <Input id="end" type="datetime-local" value={toInput(f.end)} onChange={(e) => set({ end: fromInput(e.target.value) })} className="h-7 w-44 text-xs" title="To (UTC)" />
            <span className="text-[11px] text-subtle">UTC</span>
          </div>
          {active.length > 0 && (
            <Button size="sm" variant="ghost" onClick={() => (setSearch(""), reset())}>
              <X /> Clear {active.length} filter{active.length > 1 ? "s" : ""}
            </Button>
          )}
        </div>
        {f.ids && <p className="mt-2 text-xs text-medium">Showing {f.ids.split(",").length} events linked to an alert.</p>}
      </Panel>

      <Panel className="overflow-hidden">
        {error ? (
          queryMode ? (
            <div role="alert" className="px-4 py-6 text-[13px]">
              <span className="font-medium text-critical">Query error: </span>
              <span className="text-muted">{error.message}</span>
            </div>
          ) : (
            <ErrorState error={error} retry={() => mutate()} />
          )
        ) : stats ? (
          <StatsTable
            columns={stats.columns}
            rows={stats.rows}
            onDrill={(row) => set({ query: drillDown(dsl, row, stats.columns), page: "1" })}
          />
        ) : data?.total === 0 ? (
          <EmptyState icon={ScrollText} title="No events match" description="Relax the filters, or import a log file to add data." />
        ) : (
          <>
            <div className={cn("overflow-x-auto", isLoading && data && "opacity-60")}>
              <table className={tableCls.table}>
                <thead className={tableCls.head}>
                  <tr>
                    <SortHeader label="Timestamp (UTC)" field="timestamp" sort={sortField} order={order} onSort={onSort} />
                    {view === "raw" ? (
                      <>
                        <SortHeader label="Source" field="event_source" sort={sortField} order={order} onSort={onSort} />
                        <th className={tableCls.th}>Raw log</th>
                      </>
                    ) : (
                      <>
                        <SortHeader label="Event ID" field="event_id" sort={sortField} order={order} onSort={onSort} />
                        <SortHeader label="Action" field="event_action" sort={sortField} order={order} onSort={onSort} className="hidden md:table-cell" />
                        <SortHeader label="Host" field="hostname" sort={sortField} order={order} onSort={onSort} />
                        <SortHeader label="User" field="username" sort={sortField} order={order} onSort={onSort} className="hidden md:table-cell" />
                        <SortHeader label="Source IP" field="source_ip" sort={sortField} order={order} onSort={onSort} className="hidden lg:table-cell" />
                        <SortHeader label="Level" field="log_level" sort={sortField} order={order} onSort={onSort} className="hidden lg:table-cell" />
                        <th className={cn(tableCls.th, "hidden xl:table-cell")}>Message</th>
                      </>
                    )}
                  </tr>
                </thead>
                <tbody>
                  {!data &&
                    Array.from({ length: 12 }).map((_, i) => (
                      <tr key={i}>
                        <td colSpan={8} className="px-3 py-1.5">
                          <Skeleton className="h-6 w-full" />
                        </td>
                      </tr>
                    ))}
                  {data?.items.map((e) => (
                    <tr
                      key={e.id}
                      tabIndex={0}
                      onKeyDown={(ev) => ev.key === "Enter" && openEvent(e.id)}
                      onClick={() => openEvent(e.id)}
                      className={cn(tableCls.row, "cursor-pointer focus-visible:bg-surface-2 focus-visible:outline-none")}
                    >
                      <td className="h-9 whitespace-nowrap px-3 font-mono text-xs text-muted">{formatTs(e.timestamp)}</td>
                      {view === "raw" ? (
                        <>
                          <td className="whitespace-nowrap px-3 text-xs text-muted">{e.event_source}</td>
                          <td className="max-w-0 px-3">
                            <code className="block truncate font-mono text-[12px] text-foreground/85">{e.raw}</code>
                          </td>
                        </>
                      ) : (
                        <>
                          <td className="px-3 font-mono text-xs">{e.event_id}</td>
                          <td className={cn("hidden px-3 text-xs md:table-cell", e.outcome === "failure" && "text-high")}>{e.event_action}</td>
                          <td className="px-3">
                            <EntityLink kind="host" value={e.hostname} plain />
                          </td>
                          <td className="hidden px-3 md:table-cell">
                            <EntityLink kind="user" value={e.username} plain />
                          </td>
                          <td className="hidden px-3 lg:table-cell">
                            <EntityLink kind="ip" value={e.source_ip} plain />
                          </td>
                          <td className={cn("hidden px-3 text-xs lg:table-cell", LEVEL_STYLE[e.log_level])}>{e.log_level}</td>
                          <td className="hidden max-w-0 px-3 xl:table-cell">
                            <span className="block truncate text-xs text-muted">{e.message}</span>
                          </td>
                        </>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {data && <Pagination page={data.page} pageSize={data.page_size} total={data.total} onPage={(p) => set({ page: String(p) })} />}
          </>
        )}
      </Panel>
    </>
  );
}

export default function EventsPage() {
  return (
    <React.Suspense fallback={<Skeleton className="h-96 w-full" />}>
      <Explorer />
    </React.Suspense>
  );
}
