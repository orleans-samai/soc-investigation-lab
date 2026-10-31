"use client";

import { BellRing, Search, ShieldPlus, X } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import * as React from "react";
import { toast } from "sonner";
import useSWR from "swr";

import { SeverityBadge, StatusBadge } from "@/components/soc/badges";
import { EmptyState, ErrorState, PageHeader, Pagination, SortHeader, tableCls } from "@/components/soc/common";
import { EntityLink } from "@/components/soc/investigation-context";
import { Button } from "@/components/ui/button";
import { Select } from "@/components/ui/overlays";
import { Input, Panel, Skeleton } from "@/components/ui/primitives";
import { patch, post, qs } from "@/lib/api";
import type { Alert, Incident, Page, RuleInfo } from "@/lib/types";
import { useUrlState } from "@/lib/use-url-state";
import { cn, formatTs } from "@/lib/utils";
import { alertHref, incidentHref } from "@/lib/routes";

const DEFAULTS = { q: "", severity: "", status: "new,investigating", rule_id: "", incident: "any", sort: "timestamp", order: "desc", page: "1" };

function AlertQueue() {
  const router = useRouter();
  const [f, set, reset] = useUrlState(DEFAULTS);
  const [search, setSearch] = React.useState(f.q);
  const [selected, setSelected] = React.useState<Set<string>>(new Set());
  React.useEffect(() => setSearch(f.q), [f.q]);
  React.useEffect(() => {
    const t = setTimeout(() => search !== f.q && set({ q: search }), 300);
    return () => clearTimeout(t);
  }, [search, f.q, set]);

  const key = `/alerts${qs({ ...f, page_size: 25 })}`;
  const { data, error, mutate, isLoading } = useSWR<Page<Alert>>(key, { keepPreviousData: true });
  const { data: rules } = useSWR<RuleInfo[]>("/rules");

  const onSort = (field: string) => set({ sort: field, order: f.sort === field && f.order === "desc" ? "asc" : "desc" });
  const toggle = (id: string) =>
    setSelected((s) => {
      const n = new Set(s);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });
  const items = data?.items ?? [];
  const allSelected = items.length > 0 && items.every((a) => selected.has(a.id));

  async function bulkStatus(status: "false_positive" | "investigating") {
    await Promise.all([...selected].map((id) => patch(`/alerts/${id}`, { status })));
    toast.success(`${selected.size} alert(s) marked as ${status.replace("_", " ")}`);
    setSelected(new Set());
    mutate();
  }

  async function escalate() {
    const ids = [...selected];
    const taken = items.filter((a) => selected.has(a.id) && a.incident_id);
    if (taken.length) {
      toast.error(`${taken.length} selected alert(s) already belong to an incident`);
      return;
    }
    try {
      const incident = await post<Incident>("/incidents", { alert_ids: ids });
      toast.success(`${incident.id} created from ${ids.length} alert(s)`);
      router.push(incidentHref(incident.id));
    } catch (e) {
      toast.error((e as Error).message);
    }
  }

  const filtersActive = JSON.stringify({ ...f, page: "1", sort: "", order: "" }) !== JSON.stringify({ ...DEFAULTS, sort: "", order: "" });

  return (
    <>
      <PageHeader
        title="Alert queue"
        description="Escalate each alert to an incident, or close it with a verdict and a note."
      />

      <div className="mb-3 flex flex-wrap items-center gap-2">
        <div className="relative w-full sm:w-72">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-subtle" />
          <Input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search rule, host, user, IP, ID..." className="pl-8" aria-label="Search alerts" />
        </div>
        <Select
          aria-label="Severity"
          size="sm"
          className="w-36"
          value={f.severity || "all"}
          onValueChange={(v) => set({ severity: v === "all" ? "" : v })}
          options={[{ value: "all", label: "All severities" }, { value: "critical,high", label: "Critical + High" }, ...["critical", "high", "medium", "low"].map((s) => ({ value: s, label: <span className="capitalize">{s}</span> }))]}
        />
        <Select
          aria-label="Status"
          size="sm"
          className="w-40"
          value={f.status || "all"}
          onValueChange={(v) => set({ status: v === "all" ? "" : v })}
          options={[
            { value: "new,investigating", label: "Open" },
            { value: "new", label: "New" },
            { value: "investigating", label: "Investigating" },
            { value: "resolved", label: "True positive" },
            { value: "benign", label: "Benign" },
            { value: "false_positive", label: "False positive" },
            { value: "all", label: "Any status" },
          ]}
        />
        <Select
          aria-label="Rule"
          size="sm"
          className="w-56"
          value={f.rule_id || "all"}
          onValueChange={(v) => set({ rule_id: v === "all" ? "" : v })}
          options={[{ value: "all", label: "All rules" }, ...(rules ?? []).map((r) => ({ value: r.id, label: `${r.id} ${r.name}` }))]}
        />
        <Select
          aria-label="Incident assignment"
          size="sm"
          className="w-40"
          value={f.incident}
          onValueChange={(v) => set({ incident: v })}
          options={[
            { value: "any", label: "Any incident" },
            { value: "unassigned", label: "Not in incident" },
            { value: "assigned", label: "In an incident" },
          ]}
        />
        {filtersActive && (
          <Button size="sm" variant="ghost" onClick={reset}>
            <X /> Reset
          </Button>
        )}
      </div>

      {selected.size > 0 && (
        <div className="mb-3 flex flex-wrap items-center gap-2 rounded-md border border-primary/30 bg-primary/8 px-3 py-2 text-sm">
          <span className="font-medium">{selected.size} selected</span>
          <Button size="sm" variant="primary" onClick={escalate}>
            <ShieldPlus /> Create incident
          </Button>
          <Button size="sm" onClick={() => bulkStatus("investigating")}>
            Mark investigating
          </Button>
          <Button size="sm" onClick={() => bulkStatus("false_positive")}>
            Close as false positive
          </Button>
          <Button size="sm" variant="ghost" onClick={() => setSelected(new Set())}>
            Clear
          </Button>
        </div>
      )}

      <Panel className="overflow-hidden">
        {error ? (
          <ErrorState error={error} retry={() => mutate()} />
        ) : data && data.total === 0 ? (
          <EmptyState
            icon={BellRing}
            title="No alerts match these filters"
            description="Set status to Any status, or run a scenario to produce new detections."
            action={
              <Button asChild size="sm">
                <Link href="/simulations">Open simulations</Link>
              </Button>
            }
          />
        ) : (
          <>
            <div className={cn("overflow-x-auto", isLoading && data && "opacity-60")}>
              <table className={tableCls.table}>
                <thead className={tableCls.head}>
                  <tr>
                    <th className="w-9 pl-3">
                      <input
                        type="checkbox"
                        aria-label="Select all alerts on this page"
                        checked={allSelected}
                        onChange={() => setSelected(allSelected ? new Set() : new Set(items.map((a) => a.id)))}
                        className="size-3.5 accent-[var(--primary)]"
                      />
                    </th>
                    <SortHeader label="Severity" field="severity" sort={f.sort} order={f.order as "asc" | "desc"} onSort={onSort} />
                    <SortHeader label="Rule / reason" field="rule" sort={f.sort} order={f.order as "asc" | "desc"} onSort={onSort} />
                    <SortHeader label="Host" field="host" sort={f.sort} order={f.order as "asc" | "desc"} onSort={onSort} className="hidden lg:table-cell" />
                    <th className={cn(tableCls.th, "hidden lg:table-cell")}>User / source</th>
                    <SortHeader label="Time (UTC)" field="timestamp" sort={f.sort} order={f.order as "asc" | "desc"} onSort={onSort} />
                    <th className={cn(tableCls.th, "hidden md:table-cell")}>Incident</th>
                    <SortHeader label="Status" field="status" sort={f.sort} order={f.order as "asc" | "desc"} onSort={onSort} />
                  </tr>
                </thead>
                <tbody>
                  {!data &&
                    Array.from({ length: 8 }).map((_, i) => (
                      <tr key={i}>
                        <td colSpan={8} className="px-3 py-2">
                          <Skeleton className="h-8 w-full" />
                        </td>
                      </tr>
                    ))}
                  {items.map((a) => (
                    <tr key={a.id} className={cn(tableCls.row, "cursor-pointer", selected.has(a.id) && "bg-primary/8")} onClick={() => router.push(alertHref(a.id))}>
                      <td className="pl-3" onClick={(e) => e.stopPropagation()}>
                        <input
                          type="checkbox"
                          aria-label={`Select alert ${a.id}`}
                          checked={selected.has(a.id)}
                          onChange={() => toggle(a.id)}
                          className="size-3.5 accent-[var(--primary)]"
                        />
                      </td>
                      <td className={tableCls.td}>
                        <SeverityBadge severity={a.severity} />
                      </td>
                      <td className={cn(tableCls.td, "max-w-[420px] py-2")}>
                        <Link href={alertHref(a.id)} onClick={(e) => e.stopPropagation()} className="font-medium hover:text-primary">
                          {a.rule_name}
                        </Link>
                        <span className="ml-2 font-mono text-2xs text-subtle">{a.rule_id}</span>
                        <p className="truncate text-xs text-muted">{a.reason}</p>
                      </td>
                      <td className={cn(tableCls.td, "hidden lg:table-cell")}>
                        <EntityLink kind="host" value={a.hostname} />
                      </td>
                      <td className={cn(tableCls.td, "hidden lg:table-cell")}>
                        <div className="flex flex-col gap-0.5">
                          {a.username && <EntityLink kind="user" value={a.username} />}
                          {a.source_ip && <EntityLink kind="ip" value={a.source_ip} />}
                          {!a.username && !a.source_ip && <span className="text-subtle">-</span>}
                        </div>
                      </td>
                      <td className={cn(tableCls.td, "whitespace-nowrap font-mono text-xs text-muted")}>{formatTs(a.timestamp)}</td>
                      <td className={cn(tableCls.td, "hidden md:table-cell")}>
                        {a.incident_id ? (
                          <Link href={incidentHref(a.incident_id)} onClick={(e) => e.stopPropagation()} className="font-mono text-xs text-primary hover:underline">
                            {a.incident_id}
                          </Link>
                        ) : (
                          <span className="text-xs text-subtle">-</span>
                        )}
                      </td>
                      <td className={tableCls.td}>
                        <StatusBadge status={a.status} />
                      </td>
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

export default function AlertsPage() {
  return (
    <React.Suspense fallback={<Skeleton className="h-96 w-full" />}>
      <AlertQueue />
    </React.Suspense>
  );
}
