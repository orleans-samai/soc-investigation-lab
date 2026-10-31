"use client";

import { PanelLeftClose, PanelLeftOpen, Radar } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import useSWR from "swr";

import { NAV } from "@/components/shell/nav";
import { Tooltip } from "@/components/ui/primitives";
import type { SystemStatus } from "@/lib/types";
import { cn } from "@/lib/utils";

export function isActive(pathname: string, href: string) {
  return href === "/" ? pathname === "/" : pathname === href || pathname.startsWith(`${href}/`);
}

export function SidebarNav({ collapsed, onNavigate }: { collapsed: boolean; onNavigate?: () => void }) {
  const pathname = usePathname();
  const { data: status } = useSWR<SystemStatus>("/system/status", { refreshInterval: 15000 });
  const badges: Record<string, number | undefined> = {
    "/incidents": status?.counts.open_incidents,
  };

  return (
    <nav aria-label="Main" className="flex-1 space-y-4 overflow-y-auto px-2 py-3">
      {NAV.map((group) => (
        <div key={group.section}>
          {!collapsed && <div className="mb-1 px-2 text-[11px] font-medium uppercase tracking-wider text-subtle">{group.section}</div>}
          <ul className="space-y-px">
            {group.items.map((item) => {
              const active = isActive(pathname, item.href);
              const badge = badges[item.href];
              const link = (
                <Link
                  href={item.href}
                  onClick={onNavigate}
                  aria-current={active ? "page" : undefined}
                  className={cn(
                    "group relative flex h-8 items-center gap-2.5 rounded-md px-2 text-[13px] text-muted transition-colors hover:bg-surface-2 hover:text-foreground",
                    active && "bg-surface-2 font-medium text-foreground",
                    collapsed && "justify-center px-0",
                  )}
                >
                  {active && <span className="absolute inset-y-1.5 left-0 w-0.5 rounded-full bg-primary" aria-hidden />}
                  <item.icon className={cn("size-4 shrink-0", active ? "text-primary" : "text-subtle group-hover:text-muted")} />
                  {!collapsed && <span className="truncate">{item.label}</span>}
                  {!collapsed && !!badge && (
                    <span className="ml-auto rounded bg-surface px-1.5 font-mono text-[11px] tabular-nums text-muted ring-1 ring-border">{badge}</span>
                  )}
                </Link>
              );
              return (
                <li key={item.href}>
                  {collapsed ? (
                    <Tooltip content={item.label} side="right">
                      {link}
                    </Tooltip>
                  ) : (
                    link
                  )}
                </li>
              );
            })}
          </ul>
        </div>
      ))}
    </nav>
  );
}

export function Brand({ collapsed }: { collapsed: boolean }) {
  return (
    <Link href="/" className={cn("flex h-12 items-center gap-2.5 border-b border-border px-3.5", collapsed && "justify-center px-0")}>
      <span className="flex size-7 shrink-0 items-center justify-center rounded-md bg-primary/15 ring-1 ring-primary/30">
        <Radar className="size-4 text-primary" />
      </span>
      {!collapsed && (
        <span className="min-w-0 leading-tight">
          <span className="block truncate text-[13px] font-semibold">SOC Investigation Lab</span>
          <span className="block truncate text-[11px] text-subtle">Incident Simulator</span>
        </span>
      )}
    </Link>
  );
}

export function Sidebar({ collapsed, onToggle }: { collapsed: boolean; onToggle: () => void }) {
  return (
    <aside
      className={cn(
        "no-print fixed inset-y-0 left-0 z-30 hidden flex-col border-r border-border bg-surface transition-[width] duration-150 lg:flex",
        collapsed ? "w-14" : "w-56",
      )}
    >
      <Brand collapsed={collapsed} />
      <SidebarNav collapsed={collapsed} />
      <div className="border-t border-border p-2">
        <button
          onClick={onToggle}
          className={cn(
            "flex h-8 w-full items-center gap-2 rounded-md px-2 text-xs text-muted hover:bg-surface-2 hover:text-foreground",
            collapsed && "justify-center px-0",
          )}
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {collapsed ? <PanelLeftOpen className="size-4" /> : <PanelLeftClose className="size-4" />}
          {!collapsed && "Collapse"}
        </button>
      </div>
    </aside>
  );
}
