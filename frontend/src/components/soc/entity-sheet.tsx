"use client";

import { ShieldAlert } from "lucide-react";
import Link from "next/link";
import useSWR from "swr";

import { SeverityBadge, StatusBadge, Tag } from "@/components/soc/badges";
import { EmptyState, KeyValue } from "@/components/soc/common";
import { EntityLink, useInvestigation } from "@/components/soc/investigation-context";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent } from "@/components/ui/overlays";
import { Skeleton } from "@/components/ui/primitives";
import { ApiError, qs } from "@/lib/api";
import type { EntityProfile } from "@/lib/types";
import { cn, formatTs, nf } from "@/lib/utils";
import { alertHref } from "@/lib/routes";

type Target = { kind: "user" | "host" | "ip"; value: string } | null;

const TITLE = { user: "Account", host: "Host", ip: "IP address" };

export function EntitySheet({ target, onOpenChange }: { target: Target; onOpenChange: (open: boolean) => void }) {
  const { data, error } = useSWR<EntityProfile>(target ? `/entities/${target.kind}/${encodeURIComponent(target.value)}` : null);
  const { openEvent } = useInvestigation();
  const filterParam = target ? { user: { username: target.value }, host: { hostname: target.value }, ip: { source_ip: target.value } }[target.kind] : {};

  return (
    <Sheet open={!!target} onOpenChange={onOpenChange}>
      <SheetContent
        title={target ? `${TITLE[target.kind]} · ${target.value}` : ""}
        description="Entity profile built from all events, alerts and incidents in the lab"
        actions={
          target && (
            <Button asChild size="sm" variant="secondary" onClick={() => onOpenChange(false)}>
              <Link href={`/events${qs(filterParam)}`}>Open in Log Explorer</Link>
            </Button>
          )
        }
      >
        {error ? (
          <EmptyState
            icon={ShieldAlert}
            title={error instanceof ApiError && error.status === 404 ? "No activity recorded for this entity" : "Could not load entity"}
            description={error.message}
          />
        ) : !data ? (
          <div className="space-y-3 p-5">
            <Skeleton className="h-16 w-full" />
            <Skeleton className="h-40 w-full" />
          </div>
        ) : (
          <div className="space-y-6 p-5">
            <div className="grid grid-cols-2 gap-px overflow-hidden rounded-lg border border-border bg-border sm:grid-cols-4">
              {[
                ["Events", nf.format(data.event_count)],
                ["Auth success", nf.format(data.auth_success)],
                ["Auth failures", nf.format(data.auth_failure)],
                ["Alerts", nf.format(data.alerts.length)],
              ].map(([label, value]) => (
                <div key={label} className="bg-surface px-3 py-2.5">
                  <div className="text-2xs text-muted">{label}</div>
                  <div className={cn("mt-1 font-mono text-lg tabular-nums", label === "Auth failures" && Number(value) > 0 && "text-high")}>{value}</div>
                </div>
              ))}
            </div>

            <section>
              <h3 className="mb-2 eyebrow">Context</h3>
              {data.kind === "user" && (
                <KeyValue
                  items={[
                    ["Display name", data.identity?.display_name ?? "Not in identity inventory"],
                    ["Department", data.identity?.department],
                    ["Title", data.identity?.title],
                    ["Account type", data.identity?.type],
                    ["Privileged", data.identity ? (data.identity.privileged ? <Tag className="text-high">privileged</Tag> : "no") : null],
                    ["Workstation", data.identity?.workstation && <EntityLink kind="host" value={data.identity.workstation} />],
                  ]}
                />
              )}
              {data.kind === "host" && (
                <KeyValue
                  items={[
                    ["Role", data.asset?.role ?? "Not in asset inventory"],
                    ["Operating system", data.asset?.os],
                    ["IP address", data.asset?.ip && <EntityLink kind="ip" value={data.asset.ip} />],
                    ["Public IP", data.asset?.public_ip],
                    ["Criticality", data.asset?.criticality],
                    ["Owner", data.asset?.owner],
                  ]}
                />
              )}
              {data.kind === "ip" && data.network && (
                <>
                  <KeyValue
                    items={[
                      ["Network", data.network.internal ? "Internal (10.10.0.0/16)" : "External"],
                      ["Asset", data.network.asset ? <EntityLink kind="host" value={data.network.asset.hostname} /> : null],
                      ["Reputation", data.network.geo?.reputation && <Tag className={data.network.geo.reputation === "malicious" ? "text-critical" : ""}>{data.network.geo.reputation}</Tag>],
                      ["Organization", data.network.geo ? `${data.network.geo.organization} (${data.network.geo.asn})` : null],
                      ["Location", data.network.geo ? `${data.network.geo.city}, ${data.network.geo.country}` : null],
                    ]}
                  />
                  {!data.network.internal && <p className="mt-2 text-2xs text-subtle">{data.network.note}</p>}
                </>
              )}
              <KeyValue className="mt-1.5" items={[["First seen", formatTs(data.first_seen)], ["Last seen", formatTs(data.last_seen)]]} />
            </section>

            {Object.entries(data.related).map(([group, values]) =>
              values.length ? (
                <section key={group}>
                  <h3 className="mb-2 eyebrow">Related {group.replace("_", " ")}</h3>
                  <div className="flex flex-wrap gap-1.5">
                    {values.map((v) => (
                      <span key={v.value} className="inline-flex items-center gap-1.5 rounded-sm border border-border bg-surface px-2 py-1 text-xs">
                        <EntityLink kind={group === "users" ? "user" : group === "hosts" ? "host" : "ip"} value={v.value} plain />
                        <span className="tabular-nums text-subtle">{v.count}</span>
                      </span>
                    ))}
                  </div>
                </section>
              ) : null,
            )}

            <section>
              <h3 className="mb-2 eyebrow">Alerts</h3>
              {data.alerts.length === 0 ? (
                <p className="text-xs text-muted">No alerts involve this entity.</p>
              ) : (
                <ul className="divide-y divide-border rounded-md border border-border">
                  {data.alerts.slice(0, 10).map((a) => (
                    <li key={a.id}>
                      <Link href={alertHref(a.id)} onClick={() => onOpenChange(false)} className="flex items-center gap-2 px-3 py-2 text-sm hover:bg-surface-2">
                        <SeverityBadge severity={a.severity} />
                        <span className="truncate">{a.rule_name}</span>
                        <span className="ml-auto shrink-0 font-mono text-2xs text-subtle">{formatTs(a.timestamp, { seconds: false })}</span>
                        <StatusBadge status={a.status} />
                      </Link>
                    </li>
                  ))}
                </ul>
              )}
            </section>

            <section>
              <h3 className="mb-2 eyebrow">Recent events</h3>
              <ol className="divide-y divide-border rounded-md border border-border">
                {data.recent_events.map((e) => (
                  <li key={e.id}>
                    <button onClick={() => openEvent(e.id)} className="flex w-full items-baseline gap-3 px-3 py-1.5 text-left text-xs hover:bg-surface-2">
                      <span className="shrink-0 font-mono text-subtle">{formatTs(e.timestamp)}</span>
                      <span className={cn("truncate", e.outcome === "failure" && "text-high")}>{e.message || e.event_action}</span>
                    </button>
                  </li>
                ))}
              </ol>
            </section>
          </div>
        )}
      </SheetContent>
    </Sheet>
  );
}
