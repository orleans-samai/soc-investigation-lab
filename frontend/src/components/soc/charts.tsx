"use client";

import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip as ChartTooltip,
  XAxis,
  YAxis,
  type TooltipContentProps,
} from "recharts";

import { SEVERITY_ORDER } from "@/components/soc/badges";
import type { Severity } from "@/lib/types";
import { nf } from "@/lib/utils";

// Validated (CVD-safe) series colours; severity colours are a status palette and always ship with labels.
export const SERIES = { primary: "var(--chart-1)", secondary: "var(--chart-2)" };
export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
};

const axis = { stroke: "var(--subtle)", fontSize: 11, tickLine: false, axisLine: false } as const;

type Row = Record<string, string | number>;

function TooltipCard({
  active,
  payload,
  label,
  formatLabel,
}: Partial<TooltipContentProps<number, string>> & { formatLabel?: (label: string) => string }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="min-w-36 rounded-md border border-border-strong bg-elevated px-3 py-2 text-xs shadow-overlay">
      <div className="mb-1.5 font-medium text-foreground">{formatLabel ? formatLabel(String(label)) : label}</div>
      {payload.map((p) => (
        <div key={String(p.dataKey)} className="flex items-center gap-2 py-0.5 text-muted">
          <span className="size-2 rounded-sm" style={{ background: p.color }} aria-hidden />
          <span className="flex-1">{p.name}</span>
          <span className="font-mono tabular-nums text-foreground">{nf.format(Number(p.value))}</span>
        </div>
      ))}
    </div>
  );
}

export function Legend({ items }: { items: { label: string; color: string }[] }) {
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-2xs text-muted">
      {items.map((i) => (
        <span key={i.label} className="inline-flex items-center gap-1.5">
          <span className="size-2 rounded-sm" style={{ background: i.color }} aria-hidden />
          {i.label}
        </span>
      ))}
    </div>
  );
}

/** Time-bucketed bars. Several keys are stacked; one axis only. */
export function TimeBars({
  data,
  keys,
  xKey,
  tickFormatter,
  labelFormatter,
  height = 220,
  ariaLabel,
}: {
  data: Row[];
  keys: { key: string; label: string; color: string }[];
  xKey: string;
  tickFormatter: (v: string) => string;
  labelFormatter?: (v: string) => string;
  height?: number;
  ariaLabel: string;
}) {
  return (
    <div style={{ height }} role="img" aria-label={ariaLabel}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 8, right: 4, bottom: 0, left: -18 }} barCategoryGap={2}>
          <CartesianGrid vertical={false} stroke="var(--chart-grid)" />
          <XAxis dataKey={xKey} {...axis} tickFormatter={tickFormatter} minTickGap={28} />
          <YAxis {...axis} allowDecimals={false} width={44} />
          <ChartTooltip
            cursor={{ fill: "var(--surface-2)", opacity: 0.6 }}
            content={(props) => <TooltipCard {...(props as TooltipContentProps<number, string>)} formatLabel={labelFormatter ?? tickFormatter} />}
          />
          {keys.map((k, i) => (
            <Bar
              key={k.key}
              dataKey={k.key}
              name={k.label}
              stackId="a"
              fill={k.color}
              stroke="var(--surface)"
              strokeWidth={keys.length > 1 ? 1 : 0}
              radius={i === keys.length - 1 ? [3, 3, 0, 0] : 0}
              maxBarSize={28}
              isAnimationActive={false}
            />
          ))}
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

/** Severity counts as a single horizontal stacked bar plus a labelled breakdown (identity never colour-only). */
export function SeverityBreakdown({ data, onSelect }: { data: { severity: Severity; count: number }[]; onSelect?: (s: Severity) => void }) {
  const total = data.reduce((s, d) => s + d.count, 0);
  const ordered = SEVERITY_ORDER.map((s) => data.find((d) => d.severity === s) ?? { severity: s, count: 0 });
  return (
    <div>
      <div className="flex h-2.5 w-full gap-0.5 overflow-hidden rounded-full bg-surface-2" role="img" aria-label="Alerts by severity">
        {total > 0 &&
          ordered
            .filter((d) => d.count)
            .map((d) => <div key={d.severity} style={{ width: `${(d.count / total) * 100}%`, background: SEVERITY_COLOR[d.severity] }} />)}
      </div>
      <ul className="mt-3 divide-y divide-border">
        {ordered.map((d) => (
          <li key={d.severity}>
            <button
              type="button"
              disabled={!onSelect}
              onClick={() => onSelect?.(d.severity)}
              className="flex w-full items-center gap-2.5 py-2 text-left text-sm enabled:hover:text-foreground"
            >
              <span className="size-2 rounded-full" style={{ background: SEVERITY_COLOR[d.severity] }} aria-hidden />
              <span className="flex-1 capitalize text-muted">{d.severity}</span>
              <span className="font-mono tabular-nums text-foreground">{nf.format(d.count)}</span>
              <span className="w-10 text-right font-mono text-2xs tabular-nums text-subtle">{total ? Math.round((d.count / total) * 100) : 0}%</span>
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}

/** Ranked list with inline magnitude bars - easier to scan than a chart for top-N tables. */
export function RankedBars({
  rows,
  max,
  color = SERIES.primary,
}: {
  rows: { key: string; label: React.ReactNode; value: number; meta?: React.ReactNode }[];
  max?: number;
  color?: string;
}) {
  const top = max ?? Math.max(1, ...rows.map((r) => r.value));
  return (
    <ul className="space-y-2.5">
      {rows.map((r) => (
        <li key={r.key} className="text-sm">
          <div className="flex items-center gap-2">
            <div className="min-w-0 flex-1 truncate">{r.label}</div>
            {r.meta}
            <span className="w-12 text-right font-mono text-xs tabular-nums text-foreground">{nf.format(r.value)}</span>
          </div>
          <div className="mt-1 h-1 overflow-hidden rounded-full bg-surface-2">
            <div className="h-full rounded-full" style={{ width: `${(r.value / top) * 100}%`, background: color }} />
          </div>
        </li>
      ))}
    </ul>
  );
}
