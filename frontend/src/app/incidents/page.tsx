"use client";

import { Search, ShieldCheck, X } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import * as React from "react";
import useSWR from "swr";

import { ClassificationText, SeverityBadge, StatusBadge } from "@/components/soc/badges";
import { EmptyState, ErrorState, PageHeader, Pagination, Segmented, SortHeader, tableCls } from "@/components/soc/common";
import { Button } from "@/components/ui/button";
import { Select } from "@/components/ui/overlays";
import { Input, Panel, Skeleton } from "@/components/ui/primitives";
import { qs } from "@/lib/api";
import type { Incident, Page } from "@/lib/types";
import { useUrlState } from "@/lib/use-url-state";
import { cn, formatTs, relative } from "@/lib/utils";
import { incidentHref } from "@/lib/routes";

const DEFAULTS = { q: "", status: "", severity: "", sort: "updated", order: "desc", page: "1" };

function IncidentList() {
  const router = useRouter();
  const [f, set, reset] = useUrlState(DEFAULTS);
  const [search, setSearch] = React.useState(f.q);
  React.useEffect(() => {
    const t = setTimeout(() => search !== f.q && set({ q: search }), 300);
    return () => clearTimeout(t);
  }, [search, f.q, set]);
  const { data, error, mutate } = useSWR<Page<Incident>>(`/incidents${qs({ ...f, page_size: 25 })}`, { keepPreviousData: true });
  const onSort = (field: string) => set({ sort: field, order: f.sort === field && f.order === "desc" ? "asc" : "desc" });
  const order = f.order as "asc" | "desc";

  return (
    <>
      <PageHeader
        title="Incidents"
        description="Alerts that share an account, source address or host are grouped here. High and critical alerts open one automatically."
      />
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <Segmented
          aria-label="Status"
          value={(f.status || "all") as string}
          onChange={(v) => set({ status: v === "all" ? "" : v })}
          options={[
            { value: "all", label: "All" },
            { value: "new", label: "New" },
            { value: "investigating,contained", label: "In progress" },
            { value: "closed", label: "Closed" },
          ]}
        />
        <div className="relative w-full sm:w-64">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-subtle" />
          <Input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="ID, title, user, host, IP..." className="pl-8" aria-label="Search incidents" />
        </div>
        <Select
          aria-label="Severity"
          size="sm"
          className="w-36"
          value={f.severity || "all"}
          onValueChange={(v) => set({ severity: v === "all" ? "" : v })}
          options={[{ value: "all", label: "All severities" }, ...["critical", "high", "medium", "low"].map((s) => ({ value: s, label: <span className="capitalize">{s}</span> }))]}
        />
        {(f.q || f.status || f.severity) && (
          <Button size="sm" variant="ghost" onClick={() => (setSearch(""), reset())}>
            <X /> Reset
          </Button>
        )}
      </div>

      <Panel className="overflow-hidden">
        {error ? (
          <ErrorState error={error} retry={() => mutate()} />
        ) : data?.total === 0 ? (
          <EmptyState icon={ShieldCheck} title="No incidents match" description="Run a simulation or escalate an alert to create one." action={<Button asChild size="sm"><Link href="/simulations">Open simulations</Link></Button>} />
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className={tableCls.table}>
                <thead className={tableCls.head}>
                  <tr>
                    <SortHeader label="ID" field="id" sort={f.sort} order={order} onSort={onSort} />
                    <SortHeader label="Severity" field="severity" sort={f.sort} order={order} onSort={onSort} />
                    <th className={tableCls.th}>Title</th>
                    <th className={cn(tableCls.th, "hidden xl:table-cell")}>Entities</th>
                    <th className={tableCls.th}>Status</th>
                    <th className={cn(tableCls.th, "hidden md:table-cell")}>Classification</th>
                    <SortHeader label="First seen (UTC)" field="first_seen" sort={f.sort} order={order} onSort={onSort} className="hidden lg:table-cell" />
                    <SortHeader label="Updated" field="updated" sort={f.sort} order={order} onSort={onSort} className="hidden md:table-cell" />
                  </tr>
                </thead>
                <tbody>
                  {!data &&
                    Array.from({ length: 6 }).map((_, i) => (
                      <tr key={i}>
                        <td colSpan={8} className="px-3 py-2">
                          <Skeleton className="h-8 w-full" />
                        </td>
                      </tr>
                    ))}
                  {data?.items.map((i) => (
                    <tr key={i.id} className={cn(tableCls.row, "cursor-pointer")} onClick={() => router.push(incidentHref(i.id))}>
                      <td className={cn(tableCls.td, "font-mono text-xs text-muted")}>{i.id}</td>
                      <td className={tableCls.td}>
                        <SeverityBadge severity={i.severity} />
                      </td>
                      <td className={cn(tableCls.td, "max-w-[380px] py-2")}>
                        <Link href={incidentHref(i.id)} onClick={(e) => e.stopPropagation()} className="font-medium hover:text-primary">
                          {i.title}
                        </Link>
                        <p className="text-xs text-muted">
                          {i.alert_ids.length} alert{i.alert_ids.length === 1 ? "" : "s"} · {i.mitre.length} ATT&CK technique{i.mitre.length === 1 ? "" : "s"}
                          {i.assignee && <> · {i.assignee}</>}
                        </p>
                      </td>
                      <td className={cn(tableCls.td, "hidden max-w-[260px] truncate text-xs text-muted xl:table-cell")}>
                        {[...(i.entities.hosts ?? []), ...(i.entities.users ?? []), ...(i.entities.ips ?? [])].join(", ")}
                      </td>
                      <td className={tableCls.td}>
                        <StatusBadge status={i.status} />
                      </td>
                      <td className={cn(tableCls.td, "hidden md:table-cell")}>
                        <ClassificationText value={i.classification} />
                      </td>
                      <td className={cn(tableCls.td, "hidden whitespace-nowrap font-mono text-xs text-muted lg:table-cell")}>{formatTs(i.first_seen, { seconds: false })}</td>
                      <td className={cn(tableCls.td, "hidden whitespace-nowrap text-xs text-muted md:table-cell")}>{relative(i.updated_at)}</td>
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

export default function IncidentsPage() {
  return (
    <React.Suspense fallback={<Skeleton className="h-96 w-full" />}>
      <IncidentList />
    </React.Suspense>
  );
}
