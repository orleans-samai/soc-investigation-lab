"use client";

import Link from "next/link";
import useSWR from "swr";

import { PageHeader, Segmented, Term } from "@/components/soc/common";
import { Panel, Skeleton, Tooltip } from "@/components/ui/primitives";
import type { MitreMatrix } from "@/lib/types";
import { cn } from "@/lib/utils";
import * as React from "react";

type Mode = "all" | "covered" | "detected";

export default function MitrePage() {
  const { data } = useSWR<MitreMatrix>("/mitre");
  const [mode, setMode] = React.useState<Mode>("all");

  return (
    <>
      <PageHeader
        title="ATT&CK coverage"
        description={
          <>
            Which <Term name="MITRE ATT&CK">ATT&CK</Term> techniques a rule covers, and which have fired. Dashed cells are the detection backlog.
          </>
        }
        actions={
          <Segmented
            aria-label="Filter techniques"
            value={mode}
            onChange={setMode}
            options={[
              { value: "all", label: "All" },
              { value: "covered", label: "Covered" },
              { value: "detected", label: "Detected" },
            ]}
          />
        }
      />
      {data && (
        <div className="mb-4 grid grid-cols-2 gap-px overflow-hidden rounded-md border border-border bg-border sm:grid-cols-4">
          {[
            ["Techniques in view", data.summary.techniques],
            ["Covered by a rule", data.summary.covered],
            ["Coverage", `${data.summary.coverage_pct}%`],
            ["With alerts", data.summary.detected],
          ].map(([label, value]) => (
            <div key={label} className="bg-surface px-4 py-3">
              <div className="eyebrow">{label}</div>
              <div className="mt-2 font-display text-xl font-semibold tabular-nums">{value}</div>
            </div>
          ))}
        </div>
      )}
      <div className="mb-3 flex flex-wrap items-center gap-4 text-2xs text-muted">
        <span className="inline-flex items-center gap-1.5">
          <span className="size-3 rounded-sm border border-primary/30 bg-primary/30" /> Alerts observed
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="size-3 rounded-sm border border-border-strong bg-surface-2" /> Covered by a rule, no alerts
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="size-3 rounded-sm border border-dashed border-border-strong" /> Not covered (gap)
        </span>
      </div>
      {!data ? (
        <Skeleton className="h-[60vh] w-full" />
      ) : (
        <Panel className="overflow-x-auto p-3">
          <div className="grid min-w-[1100px] grid-cols-12 gap-2">
            {data.tactics.map((tactic) => {
              const techniques = tactic.techniques.filter((t) => mode === "all" || (mode === "covered" ? t.rules.length : t.alerts));
              return (
                <div key={tactic.id} className="min-w-0">
                  <div className="mb-2 border-b border-border pb-2">
                    <div className="truncate text-xs font-semibold" title={tactic.name}>
                      {tactic.name}
                    </div>
                    <div className="font-mono text-2xs text-subtle">
                      {tactic.id} · {tactic.techniques.filter((t) => t.rules.length).length}/{tactic.techniques.length}
                    </div>
                  </div>
                  <ul className="space-y-1.5">
                    {techniques.map((t) => {
                      const covered = t.rules.length > 0;
                      return (
                        <li key={t.id}>
                          <Tooltip
                            content={
                              <span>
                                <strong>{t.id}</strong> {t.name}
                                <br />
                                {covered ? `Rules: ${t.rules.join(", ")}` : "No rule covers this technique yet."}
                                {t.alerts > 0 && (
                                  <>
                                    <br />
                                    {t.alerts} alert(s), {t.open_alerts} open
                                  </>
                                )}
                              </span>
                            }
                          >
                            <a
                              href={t.alerts ? `/alerts?rule_id=${t.rules.join(",")}&status=` : t.url}
                              target={t.alerts ? undefined : "_blank"}
                              rel="noreferrer noopener"
                              className={cn(
                                "block rounded-md border px-2 py-1.5 text-2xs leading-snug transition-colors",
                                t.alerts > 0
                                  ? "border-primary/30 bg-primary/14 text-foreground hover:bg-primary/30"
                                  : covered
                                    ? "border-border-strong bg-surface-2 text-foreground/90 hover:border-subtle"
                                    : "border-dashed border-border-strong text-subtle hover:text-muted",
                              )}
                            >
                              <div className="font-mono text-2xs text-muted">{t.id}</div>
                              <div className="line-clamp-2">{t.name.split(": ").pop()}</div>
                              {t.alerts > 0 && <div className="mt-0.5 font-mono text-2xs text-primary">{t.alerts} alerts</div>}
                            </a>
                          </Tooltip>
                        </li>
                      );
                    })}
                  </ul>
                </div>
              );
            })}
          </div>
        </Panel>
      )}
      <p className="mt-3 text-xs text-subtle">
        {data?.source}. Technique pages open on attack.mitre.org. Tune coverage in <Link href="/rules" className="text-primary hover:underline">Detection Rules</Link>.
      </p>
    </>
  );
}
