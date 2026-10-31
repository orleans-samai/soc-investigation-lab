"use client";

import { FileText } from "lucide-react";
import Link from "next/link";
import useSWR from "swr";

import { ClassificationText, SeverityBadge, StatusBadge } from "@/components/soc/badges";
import { EmptyState, PageHeader, tableCls } from "@/components/soc/common";
import { Button } from "@/components/ui/button";
import { Panel, Skeleton } from "@/components/ui/primitives";
import type { Incident, Page } from "@/lib/types";
import { cn, formatTs } from "@/lib/utils";
import { reportHref } from "@/lib/routes";

export default function ReportsPage() {
  const { data } = useSWR<Page<Incident>>("/incidents?page_size=200&sort=updated");
  return (
    <>
      <PageHeader
        title="Reports"
        description="One technical report per incident. Export as Markdown or JSON, or print to PDF."
      />
      <Panel className="overflow-hidden">
        {!data ? (
          <Skeleton className="h-64 w-full" />
        ) : data.total === 0 ? (
          <EmptyState icon={FileText} title="No incidents to report on yet" description="Reports come from incidents. Run a scenario to create one." />
        ) : (
          <div className="overflow-x-auto">
            <table className={tableCls.table}>
              <thead className={tableCls.head}>
                <tr>
                  <th className={tableCls.th}>Incident</th>
                  <th className={tableCls.th}>Severity</th>
                  <th className={tableCls.th}>Status</th>
                  <th className={cn(tableCls.th, "hidden md:table-cell")}>Classification</th>
                  <th className={cn(tableCls.th, "hidden lg:table-cell")}>Period (UTC)</th>
                  <th className={tableCls.th}>
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((i) => (
                  <tr key={i.id} className={tableCls.row}>
                    <td className={cn(tableCls.td, "py-2")}>
                      <span className="mr-2 font-mono text-xs text-muted">{i.id}</span>
                      <span className="font-medium">{i.title}</span>
                    </td>
                    <td className={tableCls.td}>
                      <SeverityBadge severity={i.severity} />
                    </td>
                    <td className={tableCls.td}>
                      <StatusBadge status={i.status} />
                    </td>
                    <td className={cn(tableCls.td, "hidden md:table-cell")}>
                      <ClassificationText value={i.classification} />
                    </td>
                    <td className={cn(tableCls.td, "hidden whitespace-nowrap font-mono text-xs text-muted lg:table-cell")}>
                      {formatTs(i.first_seen, { seconds: false })} - {formatTs(i.last_seen, { date: false, seconds: false })}
                    </td>
                    <td className={cn(tableCls.td, "text-right")}>
                      <div className="flex justify-end gap-1">
                        <Button asChild size="sm">
                          <Link href={reportHref(i.id)}>View report</Link>
                        </Button>
                        <Button asChild size="sm" variant="ghost">
                          <a href={`/api/incidents/${i.id}/report.md`} download>
                            .md
                          </a>
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </>
  );
}
