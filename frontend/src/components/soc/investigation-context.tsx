"use client";

import { Globe2, Monitor, User } from "lucide-react";
import * as React from "react";

import { EntitySheet } from "@/components/soc/entity-sheet";
import { EventSheet } from "@/components/soc/event-sheet";
import { cn } from "@/lib/utils";

type EntityKind = "user" | "host" | "ip";
type Target = { type: "entity"; kind: EntityKind; value: string } | { type: "event"; id: string } | null;

const Ctx = React.createContext<{ openEntity: (kind: EntityKind, value: string) => void; openEvent: (id: string) => void }>({
  openEntity: () => undefined,
  openEvent: () => undefined,
});

/** Lets any component open the entity profile or the full event record in a side panel. */
export function InvestigationProvider({ children }: { children: React.ReactNode }) {
  const [target, setTarget] = React.useState<Target>(null);
  const value = React.useMemo(
    () => ({
      openEntity: (kind: EntityKind, v: string) => setTarget({ type: "entity", kind, value: v }),
      openEvent: (id: string) => setTarget({ type: "event", id }),
    }),
    [],
  );
  const close = (open: boolean) => !open && setTarget(null);
  return (
    <Ctx.Provider value={value}>
      {children}
      <EntitySheet target={target?.type === "entity" ? target : null} onOpenChange={close} />
      <EventSheet eventId={target?.type === "event" ? target.id : null} onOpenChange={close} />
    </Ctx.Provider>
  );
}

export const useInvestigation = () => React.useContext(Ctx);

const ICONS = { user: User, host: Monitor, ip: Globe2 };

export function EntityLink({ kind, value, className, plain }: { kind: EntityKind; value: string | null | undefined; className?: string; plain?: boolean }) {
  const { openEntity } = useInvestigation();
  if (!value) return <span className="text-subtle">-</span>;
  const Icon = ICONS[kind];
  return (
    <button
      type="button"
      onClick={(e) => {
        e.stopPropagation();
        openEntity(kind, value);
      }}
      title={`Investigate ${kind} ${value}`}
      className={cn(
        "inline-flex max-w-full items-center gap-1 rounded-sm text-left text-foreground underline-offset-2 hover:text-primary hover:underline",
        kind === "ip" && "font-mono text-xs",
        className,
      )}
    >
      {!plain && <Icon className="size-3 shrink-0 text-subtle" aria-hidden />}
      <span className="truncate">{value}</span>
    </button>
  );
}
