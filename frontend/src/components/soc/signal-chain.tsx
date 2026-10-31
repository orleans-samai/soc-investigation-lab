"use client";

import { motion, useReducedMotion } from "motion/react";
import Link from "next/link";
import * as React from "react";

import { Tooltip } from "@/components/ui/primitives";
import { cn, nf } from "@/lib/utils";

export interface ChainSegment {
  label: string;
  value: number;
  color: string;
}

export interface ChainStage {
  stage: number;
  name: string;
  value: number | null | undefined;
  caption: string;
  /** How this stage relates to the previous one ("1 per 57 events"). */
  conversion?: string;
  detail?: React.ReactNode;
  segments?: ChainSegment[];
  href?: string;
}

function Composition({ segments }: { segments: ChainSegment[] }) {
  const total = segments.reduce((sum, s) => sum + s.value, 0);
  return (
    <div className="mt-4">
      <div className="flex h-1.5 gap-px overflow-hidden rounded-full bg-surface-2" role="img" aria-label={segments.map((s) => `${s.label} ${s.value}`).join(", ")}>
        {total > 0 &&
          segments
            .filter((s) => s.value > 0)
            .map((s) => (
              <Tooltip key={s.label} content={`${s.label}: ${nf.format(s.value)}`}>
                <span style={{ width: `${(s.value / total) * 100}%`, background: s.color }} />
              </Tooltip>
            ))}
      </div>
      <ul className="mt-2 flex flex-wrap gap-x-3 gap-y-1">
        {segments.map((s) => (
          <li key={s.label} className="inline-flex items-center gap-1.5 text-2xs text-muted">
            <span className="size-1.5 rounded-full" style={{ background: s.color }} aria-hidden />
            {s.label}
            <span className="font-mono tabular-nums text-foreground">{nf.format(s.value)}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

/**
 * The lab's thesis as a single instrument: telemetry becomes detections, detections become
 * incidents, incidents end as documented decisions. Stage numbers match the navigation.
 */
export function SignalChain({ stages, className, compact }: { stages: ChainStage[]; className?: string; compact?: boolean }) {
  // One orchestrated moment: stages arrive left to right, like the signal moving downstream.
  const reduce = useReducedMotion();
  return (
    <ol className={cn("grid overflow-hidden rounded-md border border-border bg-surface", compact ? "grid-cols-2 md:grid-cols-4" : "sm:grid-cols-2 xl:grid-cols-4", className)} aria-label="Detection pipeline">
      {stages.map((s, i) => {
        const body = (
          <>
            <div className="flex items-center gap-2">
              <span className="flex size-4 items-center justify-center rounded-full border border-border-strong font-mono text-2xs leading-none text-muted">{s.stage}</span>
              <span className="eyebrow">{s.name}</span>
              {s.conversion && <span className="ml-auto font-mono text-2xs text-subtle">{s.conversion}</span>}
            </div>
            <div className="mt-3 flex items-baseline gap-2">
              <span className={cn("font-display font-semibold tabular-nums tracking-[-0.02em] text-foreground", compact ? "text-xl" : "text-2xl")}>
                {s.value === null || s.value === undefined ? "-" : nf.format(s.value)}
              </span>
              <span className="text-xs text-muted">{s.caption}</span>
            </div>
            {s.detail && <div className="mt-1 text-xs text-subtle">{s.detail}</div>}
            {s.segments && <Composition segments={s.segments} />}
          </>
        );
        return (
          <motion.li
            key={s.stage}
            initial={reduce ? false : { opacity: 0, x: -6 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: reduce ? 0 : i * 0.07, duration: 0.22, ease: "easeOut" }}
            className={cn(
              "relative border-border",
              compact
                ? cn("p-3", i % 2 === 1 && "border-l", i >= 2 && "border-t md:border-t-0", i > 0 && "md:border-l")
                : cn("p-4 sm:p-5", i > 0 && "border-t sm:border-t-0", i % 2 === 1 && "sm:border-l", i >= 2 && "sm:border-t xl:border-t-0", i > 0 && "xl:border-l"),
            )}
          >
            {/* Connector: the arrow sits on the shared border, pointing downstream. */}
            {i > 0 && (
              <span
                className={cn(
                  "absolute left-0 top-1/2 z-10 hidden size-4 -translate-x-1/2 -translate-y-1/2 items-center justify-center rounded-full border border-border-strong bg-surface text-subtle",
                  compact ? "md:flex" : "xl:flex",
                )}
                aria-hidden
              >
                <svg viewBox="0 0 8 8" className="size-2">
                  <path d="M2.5 1.5 5.5 4 2.5 6.5" fill="none" stroke="currentColor" strokeWidth="1.3" />
                </svg>
              </span>
            )}
            {s.href ? (
              <Link href={s.href} className="-m-1 block rounded-md p-1 transition-colors hover:bg-surface-2/60">
                {body}
              </Link>
            ) : (
              body
            )}
          </motion.li>
        );
      })}
    </ol>
  );
}
