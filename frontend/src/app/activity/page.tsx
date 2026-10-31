"use client";

import Link from "next/link";
import useSWR from "swr";

import { PageHeader } from "@/components/soc/common";
import { Panel, Skeleton } from "@/components/ui/primitives";
import type { Activity } from "@/lib/types";
import { cn, formatTs, relative } from "@/lib/utils";
import { alertHref, incidentHref } from "@/lib/routes";

const TARGET_HREF: Record<string, (id: string) => string> = {
  incident: (id) => incidentHref(id),
  alert: (id) => alertHref(id),
  rule: (id) => `/rules?rule=${id}`,
  simulation: (id) => `/simulations?run=${id}`,
};

export default function ActivityPage() {
  const { data } = useSWR<Activity[]>("/activity?limit=300", { refreshInterval: 15000 });
  return (
    <>
      <PageHeader title="Activity Log" description="Audit trail of everything that changed in the lab: detections, simulations, imports, triage decisions and incident updates." />
      <Panel className="overflow-hidden">
        {!data ? (
          <Skeleton className="h-96 w-full" />
        ) : (
          <ol className="divide-y divide-border">
            {data.map((a) => {
              const href = a.target_type && a.target_id ? TARGET_HREF[a.target_type]?.(a.target_id) : undefined;
              return (
                <li key={a.id} className="flex flex-col gap-1 px-4 py-2.5 sm:flex-row sm:items-baseline sm:gap-4">
                  <span className="w-40 shrink-0 font-mono text-xs text-subtle" title={relative(a.timestamp)}>
                    {formatTs(a.timestamp)}
                  </span>
                  <span className={cn("w-20 shrink-0 text-xs", a.actor === "system" ? "text-subtle" : "text-primary")}>{a.actor}</span>
                  <span className="w-36 shrink-0 font-mono text-[11px] text-muted">{a.action}</span>
                  <span className="min-w-0 text-[13px]">
                    {href ? (
                      <Link href={href} className="hover:text-primary">
                        {a.message}
                      </Link>
                    ) : (
                      a.message
                    )}
                  </span>
                </li>
              );
            })}
          </ol>
        )}
      </Panel>
      <p className="mt-2 text-xs text-subtle">Activity timestamps are wall-clock time (when the action happened), not simulated time.</p>
    </>
  );
}
