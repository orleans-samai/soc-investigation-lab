"use client";

import { Command } from "cmdk";
import { Globe2, Monitor, ScrollText, Search, ShieldCheck, User } from "lucide-react";
import { useRouter } from "next/navigation";
import * as React from "react";
import useSWR from "swr";

import { ALL_NAV } from "@/components/shell/nav";
import { SeverityDot } from "@/components/soc/badges";
import { useInvestigation } from "@/components/soc/investigation-context";
import { Dialog, DialogContent } from "@/components/ui/overlays";
import { Kbd } from "@/components/ui/primitives";
import type { Alert, Incident, NormalizedEvent } from "@/lib/types";
import { formatTs } from "@/lib/utils";
import { alertHref, incidentHref } from "@/lib/routes";

interface SearchResult {
  incidents: Incident[];
  alerts: Alert[];
  events: NormalizedEvent[];
  entities: { kind: "user" | "host" | "ip"; value: string }[];
}

const ENTITY_ICON = { user: User, host: Monitor, ip: Globe2 };
const item = "flex h-8 cursor-pointer items-center gap-2.5 rounded px-2 text-[13px] data-[selected=true]:bg-surface-2 [&_svg]:size-3.5 [&_svg]:text-subtle";
const heading = "[&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5 [&_[cmdk-group-heading]]:text-[11px] [&_[cmdk-group-heading]]:font-medium [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-wide [&_[cmdk-group-heading]]:text-subtle";

export function CommandMenu() {
  const [open, setOpen] = React.useState(false);
  const [query, setQuery] = React.useState("");
  const [debounced, setDebounced] = React.useState("");
  const router = useRouter();
  const { openEntity, openEvent } = useInvestigation();

  React.useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.key === "k" && (e.metaKey || e.ctrlKey)) || (e.key === "/" && !/input|textarea|select/i.test((e.target as HTMLElement).tagName))) {
        e.preventDefault();
        setOpen((o) => !o);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  React.useEffect(() => {
    const t = setTimeout(() => setDebounced(query.trim()), 180);
    return () => clearTimeout(t);
  }, [query]);

  const { data, isLoading } = useSWR<SearchResult>(debounced.length >= 2 ? `/search?q=${encodeURIComponent(debounced)}` : null, {
    keepPreviousData: true,
  });

  const go = (fn: () => void) => {
    setOpen(false);
    setQuery("");
    fn();
  };

  return (
    <>
      <button
        onClick={() => setOpen(true)}
        className="flex h-8 w-full max-w-sm items-center gap-2 rounded-md border border-border bg-surface px-2.5 text-[13px] text-subtle transition-colors hover:border-border-strong hover:text-muted"
      >
        <Search className="size-3.5" />
        <span className="flex-1 truncate text-left">Search events, alerts, incidents, IPs...</span>
        <Kbd className="hidden sm:inline-flex">Ctrl K</Kbd>
      </button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent title="Search" className="max-w-xl [&>div:last-child]:p-0">
          <Command shouldFilter={false} label="Global search" className={heading}>
            <div className="flex items-center gap-2 border-b border-border px-3">
              <Search className="size-4 text-subtle" />
              <Command.Input
                value={query}
                onValueChange={setQuery}
                autoFocus
                placeholder="Type an IP, user, host, rule or incident ID..."
                className="h-11 w-full bg-transparent text-sm outline-none placeholder:text-subtle"
              />
            </div>
            <Command.List className="max-h-[55vh] overflow-y-auto p-1.5">
              {debounced.length < 2 && (
                <Command.Group heading="Go to">
                  {ALL_NAV.map((n) => (
                    <Command.Item key={n.href} value={n.href} onSelect={() => go(() => router.push(n.href))} className={item}>
                      <n.icon />
                      {n.label}
                    </Command.Item>
                  ))}
                </Command.Group>
              )}
              {debounced.length >= 2 && !isLoading && data && Object.values(data).every((v) => v.length === 0) && (
                <Command.Empty className="px-3 py-8 text-center text-[13px] text-muted">No matches for &quot;{debounced}&quot;</Command.Empty>
              )}
              {!!data?.entities.length && debounced.length >= 2 && (
                <Command.Group heading="Entities">
                  {data.entities.map((e) => {
                    const Icon = ENTITY_ICON[e.kind];
                    return (
                      <Command.Item key={`${e.kind}:${e.value}`} value={`${e.kind}:${e.value}`} onSelect={() => go(() => openEntity(e.kind, e.value))} className={item}>
                        <Icon />
                        <span className={e.kind === "ip" ? "font-mono text-[12px]" : ""}>{e.value}</span>
                        <span className="ml-auto text-[11px] text-subtle">{e.kind}</span>
                      </Command.Item>
                    );
                  })}
                </Command.Group>
              )}
              {!!data?.incidents.length && debounced.length >= 2 && (
                <Command.Group heading="Incidents">
                  {data.incidents.map((i) => (
                    <Command.Item key={i.id} value={i.id} onSelect={() => go(() => router.push(incidentHref(i.id)))} className={item}>
                      <ShieldCheck />
                      <span className="font-mono text-[12px] text-muted">{i.id}</span>
                      <span className="truncate">{i.title}</span>
                    </Command.Item>
                  ))}
                </Command.Group>
              )}
              {!!data?.alerts.length && debounced.length >= 2 && (
                <Command.Group heading="Alerts">
                  {data.alerts.map((a) => (
                    <Command.Item key={a.id} value={a.id} onSelect={() => go(() => router.push(alertHref(a.id)))} className={item}>
                      <SeverityDot severity={a.severity} />
                      <span className="truncate">{a.rule_name}</span>
                      <span className="ml-auto shrink-0 font-mono text-[11px] text-subtle">{formatTs(a.timestamp, { seconds: false })}</span>
                    </Command.Item>
                  ))}
                </Command.Group>
              )}
              {!!data?.events.length && debounced.length >= 2 && (
                <Command.Group heading="Events">
                  {data.events.map((e) => (
                    <Command.Item key={e.id} value={e.id} onSelect={() => go(() => openEvent(e.id))} className={item}>
                      <ScrollText />
                      <span className="truncate">{e.message || e.event_action}</span>
                      <span className="ml-auto shrink-0 font-mono text-[11px] text-subtle">{formatTs(e.timestamp, { seconds: false })}</span>
                    </Command.Item>
                  ))}
                </Command.Group>
              )}
            </Command.List>
          </Command>
        </DialogContent>
      </Dialog>
    </>
  );
}
