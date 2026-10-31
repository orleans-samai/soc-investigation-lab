"use client";

import Link from "next/link";
import useSWR from "swr";

import { SeverityBadge, Tag } from "@/components/soc/badges";
import { CodeBlock, KeyValue, Term } from "@/components/soc/common";
import { EntityLink, useInvestigation } from "@/components/soc/investigation-context";
import { Sheet, SheetContent } from "@/components/ui/overlays";
import { Skeleton, Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/primitives";
import type { Alert, NormalizedEvent } from "@/lib/types";
import { cn, formatTs, humanize } from "@/lib/utils";
import { alertHref } from "@/lib/routes";

export function EventFields({ event }: { event: NormalizedEvent }) {
  const items: [React.ReactNode, React.ReactNode][] = [
    ["timestamp", <span key="t" className="font-mono text-xs">{formatTs(event.timestamp)} UTC</span>],
    [<Term key="e" name="Event ID">event_id</Term>, event.event_id],
    ["event_source", event.event_source],
    ["event_type", event.event_type],
    ["event_action", event.event_action],
    ["outcome", event.outcome],
    ["log_level", event.log_level],
    ["hostname", <EntityLink key="h" kind="host" value={event.hostname} />],
    ["username", <EntityLink key="u" kind="user" value={event.username} />],
    ["domain", event.domain],
    ["source_ip", <EntityLink key="s" kind="ip" value={event.source_ip} />],
    ["source_port", event.source_port],
    ["destination_ip", event.destination_ip],
    ["destination_port", event.destination_port],
    [<Term key="l" name="Logon type">logon_type</Term>, event.logon_type],
    ["process_name", event.process_name],
    ["parent_process", event.parent_process],
    ["command_line", event.command_line && <code className="break-all font-mono text-xs">{event.command_line}</code>],
    ["target_username", event.target_username && <EntityLink kind="user" value={event.target_username} />],
    ["group_name", event.group_name],
    ["dataset", event.dataset],
    ["ingested_at", formatTs(event.ingested_at)],
  ];
  const extra = Object.entries(event.fields ?? {}).map(([k, v]) => [`fields.${k}`, String(v)] as [string, string]);
  return <KeyValue items={[...items, ...extra].filter(([, v]) => v !== null && v !== undefined && v !== "")} />;
}

export function EventSheet({ eventId, onOpenChange }: { eventId: string | null; onOpenChange: (open: boolean) => void }) {
  const { data: event } = useSWR<NormalizedEvent>(eventId ? `/events/${eventId}` : null);
  const { data: context } = useSWR<{ alerts: Alert[]; surrounding: NormalizedEvent[] }>(eventId ? `/events/${eventId}/context` : null);
  const { openEvent } = useInvestigation();

  return (
    <Sheet open={!!eventId} onOpenChange={onOpenChange}>
      <SheetContent
        title={event ? event.message || humanize(event.event_action) : "Event"}
        description={event ? `${event.id} · ${event.event_source} · ${formatTs(event.timestamp)} UTC` : eventId ?? ""}
      >
        {!event ? (
          <div className="space-y-2 p-5">
            <Skeleton className="h-4 w-1/2" />
            <Skeleton className="h-40 w-full" />
          </div>
        ) : (
          <Tabs defaultValue="fields">
            <TabsList className="bg-surface px-4">
              <TabsTrigger value="fields">
                <Term name="Normalized fields">Normalized</Term>
              </TabsTrigger>
              <TabsTrigger value="raw">
                <Term name="Raw log">Raw</Term>
              </TabsTrigger>
              <TabsTrigger value="context">Context {context ? `(${context.alerts.length})` : ""}</TabsTrigger>
            </TabsList>
            <TabsContent value="fields" className="p-5">
              {event.tags.length > 0 && (
                <div className="mb-3 flex gap-1.5">
                  {event.tags.map((t) => (
                    <Tag key={t}>{t}</Tag>
                  ))}
                </div>
              )}
              <EventFields event={event} />
            </TabsContent>
            <TabsContent value="raw" className="space-y-3 p-5">
              <p className="text-xs text-muted">Exactly as received by the parser. Preserved for evidence; never executed.</p>
              <CodeBlock>{event.raw}</CodeBlock>
              <CodeBlock label="Normalized JSON">{JSON.stringify(event, null, 2)}</CodeBlock>
            </TabsContent>
            <TabsContent value="context" className="space-y-5 p-5">
              <div>
                <h3 className="mb-2 eyebrow">Alerts referencing this event</h3>
                {context?.alerts.length ? (
                  <ul className="space-y-1.5">
                    {context.alerts.map((a) => (
                      <li key={a.id}>
                        <Link href={alertHref(a.id)} className="flex items-center gap-2 rounded-md border border-border px-3 py-2 text-sm hover:bg-surface-2">
                          <SeverityBadge severity={a.severity} />
                          <span className="font-medium">{a.rule_name}</span>
                          <span className="ml-auto font-mono text-2xs text-subtle">{a.rule_id}</span>
                        </Link>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-xs text-muted">No detection rule used this event.</p>
                )}
              </div>
              <div>
                <h3 className="mb-2 eyebrow">Surrounding events on {event.hostname}</h3>
                <ol className="divide-y divide-border rounded-md border border-border">
                  {context?.surrounding.map((e) => (
                    <li key={e.id}>
                      <button
                        onClick={() => openEvent(e.id)}
                        className={cn("flex w-full items-baseline gap-3 px-3 py-1.5 text-left text-xs hover:bg-surface-2", e.id === event.id && "bg-primary/8")}
                      >
                        <span className="shrink-0 font-mono text-subtle">{formatTs(e.timestamp, { date: false })}</span>
                        <span className={cn("truncate", e.outcome === "failure" && "text-high")}>{e.message || e.event_action}</span>
                      </button>
                    </li>
                  ))}
                </ol>
              </div>
            </TabsContent>
          </Tabs>
        )}
      </SheetContent>
    </Sheet>
  );
}
