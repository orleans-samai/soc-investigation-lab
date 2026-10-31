"use client";

import { PanelLeftClose, PanelLeftOpen } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import useSWR from "swr";

import { LAB_NAV, NAV, OVERVIEW, type NavItem } from "@/components/shell/nav";
import { Tooltip } from "@/components/ui/primitives";
import type { SystemStatus } from "@/lib/types";
import { cn, nf } from "@/lib/utils";

export function isActive(pathname: string, href: string) {
  return href === "/" ? pathname === "/" : pathname === href || pathname.startsWith(`${href}/`);
}

/** Brand mark: four nodes on a wire, the last one filled - telemetry becoming a decision. */
export function ChainMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 28 12" className={className} aria-hidden>
      <line x1="3" y1="6" x2="25" y2="6" stroke="currentColor" strokeWidth="1.25" opacity="0.45" />
      {[3, 10.3, 17.6].map((x) => (
        <circle key={x} cx={x} cy="6" r="2.1" fill="var(--surface)" stroke="currentColor" strokeWidth="1.25" />
      ))}
      <circle cx="24.6" cy="6" r="3" fill="currentColor" />
    </svg>
  );
}

function NavLink({ item, collapsed, active, status, onNavigate }: { item: NavItem; collapsed: boolean; active: boolean; status?: SystemStatus; onNavigate?: () => void }) {
  const raw = status && item.count ? item.count(status) : undefined;
  const count = typeof raw === "number" ? nf.format(raw) : raw;
  const link = (
    <Link
      href={item.href}
      onClick={onNavigate}
      aria-current={active ? "page" : undefined}
      className={cn(
        "group flex h-8 items-center gap-2.5 rounded-md px-2 text-sm text-muted transition-colors hover:bg-surface-2 hover:text-foreground",
        active && "bg-surface-2 font-medium text-foreground",
        collapsed && "justify-center px-0",
      )}
    >
      <item.icon className={cn("size-4 shrink-0", active ? "text-primary" : "text-subtle group-hover:text-muted")} strokeWidth={1.75} />
      {!collapsed && <span className="truncate">{item.label}</span>}
      {!collapsed && count !== undefined && <span className="ml-auto font-mono text-2xs tabular-nums text-subtle">{count}</span>}
    </Link>
  );
  return collapsed ? (
    <Tooltip content={count !== undefined ? `${item.label} · ${count}` : item.label} side="right">
      {link}
    </Tooltip>
  ) : (
    link
  );
}

export function SidebarNav({ collapsed, onNavigate }: { collapsed: boolean; onNavigate?: () => void }) {
  const pathname = usePathname();
  const { data: status } = useSWR<SystemStatus>("/system/status", { refreshInterval: 15000 });
  const linkProps = (item: NavItem) => ({ item, collapsed, active: isActive(pathname, item.href), status, onNavigate });

  return (
    <nav aria-label="Main" className="flex flex-1 flex-col overflow-y-auto px-2 py-3">
      <NavLink {...linkProps(OVERVIEW)} />

      {/* The pipeline stages, in data-flow order, joined by a wire. */}
      <ol className={cn("mt-4 space-y-3", collapsed && "space-y-2 border-t border-border pt-2")}>
        {NAV.map((group, index) => (
          <li key={group.section} className="relative">
            {!collapsed && index < NAV.length - 1 && <span className="absolute bottom-[-14px] left-[15.5px] top-[18px] w-px bg-border-strong" aria-hidden />}
            {!collapsed && (
              <div className="mb-1 flex items-center gap-2 px-2">
                <span className="relative z-10 flex size-4 items-center justify-center rounded-full border border-border-strong bg-surface font-mono text-2xs leading-none text-muted">
                  {group.stage}
                </span>
                <span className="eyebrow">{group.section}</span>
              </div>
            )}
            <ul className={cn("space-y-px", !collapsed && "ml-6")}>
              {group.items.map((item) => (
                <li key={item.href}>
                  <NavLink {...linkProps(item)} />
                </li>
              ))}
            </ul>
          </li>
        ))}
      </ol>

      <ul className="mt-auto space-y-px border-t border-border pt-2">
        {LAB_NAV.map((item) => (
          <li key={item.href}>
            <NavLink {...linkProps(item)} />
          </li>
        ))}
      </ul>
    </nav>
  );
}

export function Brand({ collapsed }: { collapsed: boolean }) {
  return (
    <Link href="/" className={cn("flex h-12 items-center gap-2.5 border-b border-border px-3.5", collapsed && "justify-center px-0")} aria-label="SOC Investigation Lab - overview">
      <ChainMark className={cn("shrink-0 text-primary", collapsed ? "w-7" : "w-8")} />
      {!collapsed && (
        <span className="min-w-0 leading-none">
          <span className="block truncate font-display text-base font-semibold tracking-[-0.01em]">SOC Investigation Lab</span>
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
        collapsed ? "w-14" : "w-60",
      )}
    >
      <Brand collapsed={collapsed} />
      <SidebarNav collapsed={collapsed} />
      <div className="border-t border-border p-2">
        <button
          onClick={onToggle}
          className={cn(
            "flex h-8 w-full items-center gap-2 rounded-md px-2 text-xs text-subtle hover:bg-surface-2 hover:text-foreground",
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
