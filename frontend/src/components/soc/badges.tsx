import { cn, humanize } from "@/lib/utils";
import type { AlertStatus, Classification, IncidentStatus, Severity } from "@/lib/types";

const SEVERITY_STYLE: Record<Severity, string> = {
  critical: "text-critical bg-critical/12 border-critical/30",
  high: "text-high bg-high/12 border-high/30",
  medium: "text-medium bg-medium/12 border-medium/30",
  low: "text-low bg-low/12 border-low/30",
};

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];

export function SeverityDot({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <span
      className={cn("inline-block size-2 shrink-0 rounded-full", { critical: "bg-critical", high: "bg-high", medium: "bg-medium", low: "bg-low" }[severity], className)}
      aria-hidden
    />
  );
}

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex h-5 items-center gap-1.5 rounded border px-1.5 text-[11px] font-semibold uppercase tracking-wide",
        SEVERITY_STYLE[severity],
        className,
      )}
    >
      <SeverityDot severity={severity} />
      {severity}
    </span>
  );
}

const STATUS_STYLE: Record<string, string> = {
  new: "text-primary bg-primary/10 border-primary/25",
  investigating: "text-medium bg-medium/10 border-medium/25",
  contained: "text-high bg-high/10 border-high/25",
  closed: "text-muted bg-surface-2 border-border",
  resolved: "text-success bg-success/10 border-success/25",
  benign: "text-muted bg-surface-2 border-border-strong",
  false_positive: "text-muted bg-surface-2 border-border-strong",
};

const STATUS_LABEL: Record<string, string> = {
  resolved: "True positive",
  benign: "Benign",
  false_positive: "False positive",
};

export function StatusBadge({ status, className }: { status: AlertStatus | IncidentStatus; className?: string }) {
  return (
    <span className={cn("inline-flex h-5 items-center rounded border px-1.5 text-[11px] font-medium", STATUS_STYLE[status], className)}>
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

export function Tag({ children, className, mono }: { children: React.ReactNode; className?: string; mono?: boolean }) {
  return (
    <span
      className={cn(
        "inline-flex h-5 items-center rounded border border-border bg-surface-2 px-1.5 text-[11px] text-muted",
        mono && "font-mono",
        className,
      )}
    >
      {children}
    </span>
  );
}
