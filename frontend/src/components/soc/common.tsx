"use client";

import { ArrowDown, ArrowUp, ArrowUpDown, ChevronLeft, ChevronRight, Copy, ExternalLink, type LucideIcon } from "lucide-react";
import Link from "next/link";
import * as React from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Tooltip } from "@/components/ui/primitives";
import { GLOSSARY } from "@/lib/glossary";
import type { MitreRef } from "@/lib/types";
import { cn, nf } from "@/lib/utils";

/* ----------------------------------------------------------------- page header */
export function PageHeader({
  title,
  description,
  actions,
  children,
}: {
  title: React.ReactNode;
  description?: React.ReactNode;
  actions?: React.ReactNode;
  children?: React.ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-col gap-3 border-b border-border pb-4 sm:flex-row sm:items-end sm:justify-between">
      <div className="min-w-0">
        <h1 className="font-display text-xl font-semibold tracking-[-0.01em] text-foreground">{title}</h1>
        {description && <p className="mt-1 max-w-2xl text-sm text-muted">{description}</p>}
        {children}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

/* ----------------------------------------------------------------- term with glossary tooltip */
export function Term({ name, children }: { name: keyof typeof GLOSSARY | string; children?: React.ReactNode }) {
  const text = GLOSSARY[name];
  if (!text) return <>{children ?? name}</>;
  return (
    <Tooltip content={text}>
      <span tabIndex={0} className="cursor-help underline decoration-subtle/60 decoration-dotted underline-offset-[3px]">
        {children ?? name}
      </span>
    </Tooltip>
  );
}

/* ----------------------------------------------------------------- empty state */
export function EmptyState({
  icon: Icon,
  title,
  description,
  action,
  className,
}: {
  icon: LucideIcon;
  title: string;
  description?: React.ReactNode;
  action?: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-col items-center justify-center px-6 py-12 text-center", className)}>
      <Icon className="mb-3 size-5 text-subtle" strokeWidth={1.5} />
      <p className="text-sm font-medium text-foreground">{title}</p>
      {description && <p className="mt-1 max-w-sm text-xs leading-relaxed text-muted">{description}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

export function ErrorState({ error, retry }: { error: Error; retry?: () => void }) {
  return (
    <div role="alert" className="flex flex-col items-center gap-2 px-6 py-10 text-center">
      <p className="text-sm font-medium text-critical">Could not load data</p>
      <p className="max-w-md text-xs text-muted">{error.message}</p>
      {retry && (
        <Button size="sm" variant="secondary" onClick={retry}>
          Retry
        </Button>
      )}
    </div>
  );
}

/* ----------------------------------------------------------------- stat */
export function Stat({
  label,
  value,
  hint,
  tone,
  href,
}: {
  label: React.ReactNode;
  value: number | string | null | undefined;
  hint?: React.ReactNode;
  tone?: "critical" | "high" | "success" | "primary";
  href?: string;
}) {
  const body = (
    <>
      <div className="eyebrow">{label}</div>
      <div
        className={cn(
          "mt-2 font-display text-xl font-semibold leading-none tabular-nums",
          tone === "critical" && "text-critical",
          tone === "high" && "text-high",
          tone === "success" && "text-success",
          tone === "primary" && "text-primary",
        )}
      >
        {value === null || value === undefined ? "-" : typeof value === "number" ? nf.format(value) : value}
      </div>
      {hint && <div className="mt-1.5 truncate text-2xs text-subtle">{hint}</div>}
    </>
  );
  const cls = "block min-w-0 bg-surface px-4 py-3.5";
  return href ? (
    <Link href={href} className={cn(cls, "transition-colors hover:bg-surface-2")}>
      {body}
    </Link>
  ) : (
    <div className={cls}>{body}</div>
  );
}

/* ----------------------------------------------------------------- key / value list */
export function KeyValue({ items, className }: { items: [React.ReactNode, React.ReactNode][]; className?: string }) {
  return (
    <dl className={cn("grid grid-cols-[minmax(110px,max-content)_1fr] gap-x-4 gap-y-1.5 text-sm", className)}>
      {items.map(([k, v], i) => (
        <React.Fragment key={i}>
          <dt className="text-muted">{k}</dt>
          <dd className="min-w-0 break-words text-foreground">{v ?? <span className="text-subtle">-</span>}</dd>
        </React.Fragment>
      ))}
    </dl>
  );
}

/* ----------------------------------------------------------------- code / raw log */
export function CodeBlock({ children, className, label }: { children: string; className?: string; label?: string }) {
  let text = children;
  try {
    if (text.trim().startsWith("{")) text = JSON.stringify(JSON.parse(text), null, 2);
  } catch {
    /* keep as-is */
  }
  return (
    <div className={cn("group relative rounded-md border border-border bg-background", className)}>
      {label && <div className="border-b border-border px-3 py-1.5 eyebrow">{label}</div>}
      <Button
        variant="ghost"
        size="icon-sm"
        className="absolute right-1.5 top-1.5 opacity-0 transition-opacity group-hover:opacity-100 focus-visible:opacity-100"
        aria-label="Copy to clipboard"
        onClick={() => navigator.clipboard.writeText(children).then(() => toast.success("Copied to clipboard"))}
      >
        <Copy />
      </Button>
      <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all p-3 font-mono text-xs leading-relaxed text-foreground/90">{text}</pre>
    </div>
  );
}

/* ----------------------------------------------------------------- MITRE chip */
export function MitreChip({ refItem, compact }: { refItem: MitreRef; compact?: boolean }) {
  return (
    <Tooltip content={`${refItem.tactic} - ${refItem.technique}`}>
      <a
        href={`https://attack.mitre.org/techniques/${refItem.technique_id.replace(".", "/")}/`}
        target="_blank"
        rel="noreferrer noopener"
        className="inline-flex h-5 items-center gap-1 rounded-sm border border-border bg-surface-2 px-1.5 font-mono text-2xs text-muted transition-colors hover:border-primary/30 hover:text-foreground"
      >
        {refItem.technique_id}
        {!compact && <span className="max-w-48 truncate font-sans">{refItem.technique.split(": ").pop()}</span>}
        <ExternalLink className="size-2.5 opacity-60" />
      </a>
    </Tooltip>
  );
}

/* ----------------------------------------------------------------- sortable table header */
export function SortHeader({
  label,
  field,
  sort,
  order,
  onSort,
  className,
}: {
  label: React.ReactNode;
  field: string;
  sort: string;
  order: "asc" | "desc";
  onSort: (field: string) => void;
  className?: string;
}) {
  const active = sort === field;
  const Icon = !active ? ArrowUpDown : order === "asc" ? ArrowUp : ArrowDown;
  return (
    <th className={cn("h-8 px-3 text-left align-middle font-medium", className)} aria-sort={active ? (order === "asc" ? "ascending" : "descending") : "none"}>
      <button
        type="button"
        onClick={() => onSort(field)}
        className={cn("inline-flex items-center gap-1 rounded-sm uppercase tracking-[inherit] hover:text-foreground", active && "text-foreground")}
      >
        {label}
        <Icon className={cn("size-3", !active && "opacity-40")} />
      </button>
    </th>
  );
}

export const tableCls = {
  table: "w-full border-collapse text-sm",
  // Column heads use the eyebrow voice so they never compete with the data.
  head: "sticky top-0 z-10 border-b border-border bg-surface font-mono text-2xs uppercase tracking-[0.06em] text-subtle",
  th: "h-8 px-3 text-left align-middle font-medium",
  row: "border-b border-border/70 transition-colors last:border-0 hover:bg-surface-2",
  td: "h-10 px-3 align-middle",
};

/* ----------------------------------------------------------------- pagination */
export function Pagination({
  page,
  pageSize,
  total,
  onPage,
}: {
  page: number;
  pageSize: number;
  total: number;
  onPage: (page: number) => void;
}) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const from = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const to = Math.min(total, page * pageSize);
  return (
    <div className="flex items-center justify-between gap-3 border-t border-border px-3 py-2 text-xs text-muted">
      <span className="tabular-nums">
        {nf.format(from)}-{nf.format(to)} of {nf.format(total)}
      </span>
      <div className="flex items-center gap-1">
        <Button variant="ghost" size="icon-sm" disabled={page <= 1} onClick={() => onPage(page - 1)} aria-label="Previous page">
          <ChevronLeft />
        </Button>
        <span className="tabular-nums">
          {page} / {pages}
        </span>
        <Button variant="ghost" size="icon-sm" disabled={page >= pages} onClick={() => onPage(page + 1)} aria-label="Next page">
          <ChevronRight />
        </Button>
      </div>
    </div>
  );
}

/* ----------------------------------------------------------------- filter chip group */
export function Segmented<T extends string>({
  value,
  onChange,
  options,
  "aria-label": ariaLabel,
}: {
  value: T;
  onChange: (value: T) => void;
  options: { value: T; label: React.ReactNode }[];
  "aria-label": string;
}) {
  return (
    <div role="radiogroup" aria-label={ariaLabel} className="inline-flex h-8 items-center rounded-md border border-border bg-surface p-0.5">
      {options.map((o) => (
        <button
          key={o.value}
          role="radio"
          aria-checked={value === o.value}
          onClick={() => onChange(o.value)}
          className={cn(
            "h-full rounded-sm px-2.5 text-xs font-medium text-muted transition-colors hover:text-foreground",
            value === o.value && "bg-elevated text-foreground shadow-raised",
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}
