"use client";

import * as DialogPrimitive from "@radix-ui/react-dialog";
import { ChevronRight, Menu, Moon, Sun } from "lucide-react";
import Link from "next/link";
import { usePathname, useSearchParams } from "next/navigation";
import * as React from "react";
import useSWR from "swr";

import { CommandMenu } from "@/components/shell/command-menu";
import { ALL_NAV } from "@/components/shell/nav";
import { Brand, Sidebar, SidebarNav } from "@/components/shell/sidebar";
import { Term } from "@/components/soc/common";
import { Button } from "@/components/ui/button";
import { Tooltip } from "@/components/ui/primitives";
import type { SystemStatus } from "@/lib/types";
import { cn, formatTs } from "@/lib/utils";

const COLLAPSE_KEY = "soclab-sidebar-collapsed";
const THEME_KEY = "soclab-theme";

function readStorage(key: string): string | null {
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

function writeStorage(key: string, value: string) {
  try {
    window.localStorage.setItem(key, value);
  } catch {
    /* storage unavailable (private mode) - preference simply isn't remembered */
  }
}

function Breadcrumbs() {
  const pathname = usePathname();
  const recordId = useSearchParams().get("id");
  const parts = pathname.split("/").filter(Boolean);
  const crumbs = [{ href: "/", label: "SOC Lab" }];
  if (parts.length) {
    const section = ALL_NAV.find((n) => n.href === `/${parts[0]}`);
    crumbs.push({ href: `/${parts[0]}`, label: section?.label ?? parts[0] });
    if (parts[1]) crumbs.push({ href: pathname, label: parts[1] === "view" && recordId ? recordId : decodeURIComponent(parts[1]) });
  } else {
    crumbs.push({ href: "/", label: "Overview" });
  }
  return (
    <nav aria-label="Breadcrumb" className="hidden min-w-0 items-center gap-1 text-sm md:flex">
      {crumbs.map((c, i) => {
        const last = i === crumbs.length - 1;
        return (
          <React.Fragment key={c.href + i}>
            {i > 0 && <ChevronRight className="size-3.5 shrink-0 text-subtle" aria-hidden />}
            {last ? (
              <span aria-current="page" className="truncate font-medium text-foreground">
                {c.label}
              </span>
            ) : (
              <Link href={c.href} className="truncate text-muted hover:text-foreground">
                {c.label}
              </Link>
            )}
          </React.Fragment>
        );
      })}
    </nav>
  );
}

function SimulationBadge() {
  const { data } = useSWR<SystemStatus>("/system/status", { refreshInterval: 15000 });
  return (
    <Tooltip
      content={
        <span>
          {data?.mode_label ?? "Simulation Mode"}. <br />
          <Term name="Simulation clock">Simulated clock</Term>: {data ? `${formatTs(data.clock)} UTC` : "..."}
          <br />
          Business hours evaluated in {data?.timezone ?? "..."}.
        </span>
      }
      side="bottom"
    >
      {/* Hatched tape = synthetic data. The clock is the lab's "now", not the wall clock. */}
      <div tabIndex={0} role="status" className="flex h-7 items-stretch overflow-hidden rounded-md border border-medium/30 font-mono text-2xs" aria-label="Simulation mode, simulated clock">
        <span className="hatch flex items-center px-2 font-medium uppercase tracking-[0.06em] text-medium">Simulation</span>
        <span className="hidden items-center border-l border-medium/30 bg-surface px-2 tabular-nums text-muted xl:flex">
          {data ? `${formatTs(data.clock, { seconds: false })} UTC` : ""}
        </span>
      </div>
    </Tooltip>
  );
}

function ThemeToggle() {
  const [dark, setDark] = React.useState(true);
  React.useEffect(() => setDark(document.documentElement.classList.contains("dark")), []);
  const toggle = () => {
    const next = !dark;
    setDark(next);
    document.documentElement.classList.toggle("dark", next);
    writeStorage(THEME_KEY, next ? "dark" : "light");
  };
  return (
    <Tooltip content={dark ? "Switch to light theme" : "Switch to dark theme"} side="bottom">
      <Button variant="ghost" size="icon" onClick={toggle} aria-label="Toggle colour theme">
        {dark ? <Sun /> : <Moon />}
      </Button>
    </Tooltip>
  );
}

export function AppShell({ children }: { children: React.ReactNode }) {
  const [collapsed, setCollapsed] = React.useState(false);
  const [mobileOpen, setMobileOpen] = React.useState(false);
  React.useEffect(() => setCollapsed(readStorage(COLLAPSE_KEY) === "1"), []);
  const toggle = () =>
    setCollapsed((c) => {
      writeStorage(COLLAPSE_KEY, c ? "0" : "1");
      return !c;
    });

  return (
    <div className="min-h-dvh">
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-3 focus:top-3 focus:z-50 focus:rounded-sm focus:bg-action focus:px-3 focus:py-1.5 focus:text-white">
        Skip to content
      </a>
      <Sidebar collapsed={collapsed} onToggle={toggle} />

      <DialogPrimitive.Root open={mobileOpen} onOpenChange={setMobileOpen}>
        <DialogPrimitive.Portal>
          <DialogPrimitive.Overlay className="fixed inset-0 z-40 bg-black/50 lg:hidden" />
          <DialogPrimitive.Content className="fixed inset-y-0 left-0 z-50 flex w-64 flex-col border-r border-border bg-surface lg:hidden">
            <DialogPrimitive.Title className="sr-only">Navigation</DialogPrimitive.Title>
            <DialogPrimitive.Description className="sr-only">Main navigation</DialogPrimitive.Description>
            <Brand collapsed={false} />
            <SidebarNav collapsed={false} onNavigate={() => setMobileOpen(false)} />
          </DialogPrimitive.Content>
        </DialogPrimitive.Portal>
      </DialogPrimitive.Root>

      <div className={cn("flex min-h-dvh flex-col transition-[padding] duration-150", collapsed ? "lg:pl-14" : "lg:pl-60")}>
        <header className="no-print sticky top-0 z-20 flex h-12 items-center gap-3 border-b border-border bg-background/85 px-4 backdrop-blur supports-[backdrop-filter]:bg-background/70 lg:px-6">
          <Button variant="ghost" size="icon" className="lg:hidden" onClick={() => setMobileOpen(true)} aria-label="Open navigation">
            <Menu />
          </Button>
          <React.Suspense fallback={null}>
            <Breadcrumbs />
          </React.Suspense>
          <div className="ml-auto flex min-w-0 flex-1 items-center justify-end gap-2">
            <div className="hidden min-w-0 flex-1 justify-end sm:flex">
              <CommandMenu />
            </div>
            <SimulationBadge />
            <ThemeToggle />
          </div>
        </header>
        <main id="main" className="mx-auto w-full max-w-[1600px] flex-1 px-4 py-5 lg:px-6 lg:py-6">
          {children}
        </main>
      </div>
    </div>
  );
}
