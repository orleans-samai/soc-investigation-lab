import { cn, humanize } from "@/lib/utils";
import type { AlertStatus, Classification, IncidentStatus, Severity } from "@/lib/types";

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];

const SEVERITY_BAR: Record<Severity, string> = {
  critical: "bg-critical",
  high: "bg-high",
  medium: "bg-medium",
  low: "bg-low",
};

export function SeverityDot({ severity, className }: { severity: Severity; className?: string }) {
  return <span className={cn("inline-block size-2 shrink-0 rounded-full", SEVERITY_BAR[severity], className)} aria-hidden />;
}

/**
 * Severity chip: a coloured notch carries the level, the label stays in ink so it is readable on any
 * background and never relies on colour alone. Critical additionally gets a tinted wash.
 */
export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex h-5 shrink-0 items-stretch overflow-hidden rounded-sm border border-border bg-surface-2 font-mono text-2xs font-medium uppercase tracking-[0.05em] text-foreground",
        severity === "critical" && "border-critical/30 bg-critical/14",
        className,
      )}
    >
      <span className={cn("w-[3px]", SEVERITY_BAR[severity])} aria-hidden />
      <span className="flex items-center px-1.5">{severity}</span>
    </span>
  );
}

/* Status uses shape + text: an empty ring is untouched work, a full disc is a decision. */
const STATUS_SHAPE: Record<string, { fill: number; tone: string }> = {
  new: { fill: 0, tone: "text-primary" },
  investigating: { fill: 0.5, tone: "text-primary" },
  contained: { fill: 0.75, tone: "text-primary" },
  closed: { fill: 1, tone: "text-subtle" },
  resolved: { fill: 1, tone: "text-success" },
  benign: { fill: 1, tone: "text-subtle" },
  false_positive: { fill: 1, tone: "text-subtle" },
};

const STATUS_LABEL: Record<string, string> = {
  resolved: "True positive",
  benign: "Benign",
  false_positive: "False positive",
};

function StatusGlyph({ fill }: { fill: number }) {
  const r = 4.25;
  const angle = fill * 2 * Math.PI;
  const x = 6 + r * Math.sin(angle);
  const y = 6 - r * Math.cos(angle);
  return (
    <svg viewBox="0 0 12 12" className="size-3 shrink-0" aria-hidden>
      <circle cx="6" cy="6" r={r} fill="none" stroke="currentColor" strokeWidth="1.5" />
      {fill >= 1 ? (
        <circle cx="6" cy="6" r={r} fill="currentColor" />
      ) : fill > 0 ? (
        <path d={`M6 6 L6 ${6 - r} A${r} ${r} 0 ${fill > 0.5 ? 1 : 0} 1 ${x.toFixed(2)} ${y.toFixed(2)} Z`} fill="currentColor" />
      ) : null}
    </svg>
  );
}

export function StatusBadge({ status, className }: { status: AlertStatus | IncidentStatus; className?: string }) {
  const shape = STATUS_SHAPE[status] ?? STATUS_SHAPE.new;
  return (
    <span className={cn("inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap text-xs text-muted", className)}>
      <span className={shape.tone}>
        <StatusGlyph fill={shape.fill} />
      </span>
      {STATUS_LABEL[status] ?? humanize(status)}
    </span>
  );
}

const CLASSIFICATION_STYLE: Record<Classification, string> = {
  undetermined: "text-subtle",
  true_positive: "text-critical",
  benign_true_positive: "text-success",
  false_positive: "text-muted",
};

export const CLASSIFICATION_LABEL: Record<Classification, string> = {
  undetermined: "Undetermined",
  true_positive: "True positive",
  benign_true_positive: "Benign true positive",
  false_positive: "False positive",
};

export function ClassificationText({ value }: { value: Classification }) {
  return <span className={cn("text-xs font-medium", CLASSIFICATION_STYLE[value])}>{CLASSIFICATION_LABEL[value]}</span>;
}

/** Neutral metadata chip (category, level, tag). Not for severity or status. */
export function Tag({ children, className, mono }: { children: React.ReactNode; className?: string; mono?: boolean }) {
  return (
    <span
      className={cn(
        "inline-flex h-5 shrink-0 items-center rounded-sm border border-border px-1.5 text-2xs text-muted",
        mono && "font-mono",
        className,
      )}
    >
      {children}
    </span>
  );
}
